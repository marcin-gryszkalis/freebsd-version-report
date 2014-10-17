#!/usr/bin/perl -w
use strict;
use warnings;
use Data::Dumper;

my %pkgng;
$pkgng{xxxhost} = 1;

my $debug = 0;

my $inifile = "config.ini";

my $rev = '0.1';

print STDERR "Version monitor rev $rev\n";

print STDERR "parsing configuration ($inifile)...\n";
my %cfg = ();
open(F, "<", $inifile) or die "cannot open $inifile ($!)\n";
while (<F>)
{
    chomp;

    next if /^[#;]/; # comments
    next if /^\s*$/; # empty

    my ($n, $v) = split(/\s*=\s*/, $_, 2);

    $cfg{$n} = exists $cfg{$n} ? "$cfg{$n}|$v" : $v;
}
close(F);

print STDERR "getting branches...\n";
my $onv = $cfg{newvers};
my %branch;
my %revmax;
FV: for my $fv (8..10) # freebsd5-9
{
    my $rev = 0;
    while (1)
    {
        my $nv = $onv;
        $nv =~ s/XXX/$fv.$rev/;
        my $t = `curl -f -s '$nv'`;
#        print STDERR "
        next FV if $? > 0;
        if ($t =~ m/.*BRANCH="RELEASE-(p\d+).*/)
        {
            $t = $1;
        }
        else
        {
            $t = 'X';
        }

        print "FreeBSD: $fv.$rev-$t\n";
        $branch{"$fv.$rev"} = $t;
        $revmax{$fv} = $rev;
        $rev++;
    }
}

print STDERR "getting index ($cfg{index})...\n";
my $idx;

my $idxname = $cfg{index};
$idxname  =~ s{.*/}{};

my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($idxname);
if (time() - $mtime > 60*60*4)
{
    unlink $idxname;
    `wget $cfg{index}`;
    `touch $idxname`;
    my $idxname0 = $idxname;
    $idxname =~ s/(.*)\.[^\.]+/$1/;
    unlink $idxname;
    `bzip2 -d -k $idxname0`;
}
else
{
    $idxname =~ s/(.*)\.[^\.]+/$1/;
}

print STDERR "reading index ($idxname)...\n";
open(F, $idxname) or die("cannot open file ($idxname): $!");
while (<F>)
{
    chomp;
    my @iline = split /\|/;
    $iline[0] =~ m/^(.*)-(.*)/;
    #print STDERR "$_ -- $1::$2\n";
    if ($2)
    {
        my $pname = $1;
        my $pver = $2;
        $iline[1] =~ s{/usr/ports/}{};
        $idx->{$iline[1]}->{name} = $pname;
        $idx->{$iline[1]}->{version} = $pver;
        print STDERR "INDEX $pname ($iline[1]) = $pver\n" if $debug;
    }
    else
    {
        print STDERR "cannot get version($_)\n";
    }
}
close(F);



print STDERR "getting audit ($cfg{audit})...\n";
my $audit;

$idxname = $cfg{audit};
$idxname  =~ s{.*/}{};

($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($idxname);
if (time() - $mtime > 60*60*4)
{
    unlink $idxname;
    `wget $cfg{audit}`;
    `touch $idxname`;
    my $idxname0 = $idxname;
    $idxname =~ s/(.*)\.[^\.]+/$1/;
    unlink $idxname;
    `tar -xjf $idxname0`;
}
else
{
    $idxname =~ s/(.*)\.[^\.]+/$1/;
}

print STDERR "reading audit ($idxname)...\n";
open(F, $idxname) or die("cannot open file ($idxname): $!");
while (<F>)
{
    chomp;
    next if /^#/;
    my @iline = split /\|/;
    $audit->{$iline[0]}->{url} = $iline[1];
    $audit->{$iline[0]}->{desc} = $iline[2];

#     $iline[0] =~ m/^(.*)-(.*)/;
#     #print STDERR "$1::$2\n";
#     if ($2)
#     {
#         my $pname = $1;
#         my $pver = $2;
#         $iline[1] =~ s{/usr/ports/}{};
#         $idx->{$iline[1]}->{name} = $pname;
#         $idx->{$iline[1]}->{version} = $pver;
#         print STDERR "INDEX $pname ($iline[1]) = $pver\n" if $debug;
#     }
#     else
#     {
#         print STDERR "cannot get version($_)\n";
#     }
}
close(F);


my @hosts = split/\|/, $cfg{host};
my @hostnames;
my $status;
my $installed;
my $baseversion;
for my $hh (@hosts)
{
    print STDERR "getting info from host[$hh]...\n";
    my ($name, $hostt) = split /\s+/, $hh;
    push(@hostnames, $name);
    my ($host, $port) = split /:/, $hostt;
    $port = 22 unless $port;

    my $hostver = `ssh -o VisualHostKey=no -p $port $host 'uname -r'`;
    $hostver =~ m/(\d+)\.(\d+)-[^-]+(-(p\d+))?/;
    $baseversion->{$name}->{version}=$1;
    $baseversion->{$name}->{revision}=$2;
    $baseversion->{$name}->{branch}=($4 || 'X');

    my $use_pkgng = (exists $pkgng{$name} || $baseversion->{$name}->{version} > 9) ? 1 : 0;
    $baseversion->{$name}->{pkgng} = $use_pkgng;

    my $pkg_info = $use_pkgng ? 'pkg info' : 'pkg_info';

    open (S, "ssh -o VisualHostKey=no -p $port $host '$pkg_info -ao'|") or die("cannot read from host");

    while (<S>)
    {
        chomp;

        my $pname;
        my $pver;
        
        if ($use_pkgng)
        {
            my @l = split/\s+/;
            $l[0] =~ m/(.*)-(.*)/;
            $pname = $1;
            $pver = $2;
            $status->{$name}->{$l[1]}->{name} = $pname;
            $status->{$name}->{$l[1]}->{version} = $pver;
            $installed->{$name}->{$pname} = 1;
            print STDERR "$name $pname ($l[1]) = $pver\n" if $debug;
            
        }
        else
        {

            m/Information for (.*)-(.*):/;
            if ($2)
            {
                $pname = $1;
                $pver = $2;
            }
            else
            {
                print STDERR "cannot get remote version($_)\n";
            }
    
            $_ = <S>; # br
            $_ = <S>; # Origin
            $_ = <S>; chomp;
            $status->{$name}->{$_}->{name} = $pname;
            $status->{$name}->{$_}->{version} = $pver;
            $installed->{$name}->{$pname} = 1;
            print STDERR "$name $pname ($_) = $pver\n" if $debug;
            $_ = <S>; #br
        }

    }
}


my $vulnerable;
my $vc = 0;
for my $hh (@hosts)
{
    print STDERR "getting vulnerability info from host[$hh]...\n";
    my ($name, $hostt) = split /\s+/, $hh;
    my ($host, $port) = split/:/, $hostt;
    $port = 22 unless $port;

    my $pkg_info = $baseversion->{$name}->{pkgng} ? 'pkg info' : 'pkg_info';

    my $lines;
    my $lc = 0;
    my $cc = 0;
    for (sort { $a cmp $b } keys %{$audit})
    {
        my @vv = split /[<>=]/;
        my $aud = $audit->{$_};

        #print STDERR "vulnerability test $name ($vv[0] against $_)\n";
        next unless exists $installed->{$name}->{$vv[0]};
#        print STDERR "vulnerability check prepare: $name ($vv[0] against $_)\n";
        print STDERR ".";
        my $l = "\"$_\" ";
        open (S, "ssh -o VisualHostKey=no -p $port $host '$pkg_info -E $l '|") or die("cannot read from host");

        while (<S>)
        {
            chomp;
            print STDERR "\n";
            print STDERR "vulnerable ($vc): $name ($_)\n";
            $vulnerable->{$name}->{$_} .= "<a href='$aud->{url}' title='$aud->{desc}'>[X]</a>";
            $vc++;
        }
        #$cc = ($cc + 1) % 20; # no of checks in one shot
        #$lc++ if ($cc == 0);
    }
    print STDERR "\n";
}

print STDERR Dumper $vulnerable if $debug;


print STDERR "generating report...\n";
my $cntok = 0;
my $cntrev = 0;
my $cntold = 0;
my $cntvul = 0;

my $table;
my $tablex = '';
my $tablev = '';
my $row = 0;
my $rowx = 0;



my $tr = "<tr class='header'><td></td>";
for (@hostnames)
{
    $tr .= "<td>$_</td>";
}
$tablev .= $tr;

$tr = "<tr><td>FreeBSD version</td>";
my $col = 0;
for (@hostnames)
{
    my $tdclass = "odd".($col % 2 ? "odd" : "even");
    my $vr = "$baseversion->{$_}->{version}.$baseversion->{$_}->{revision}";
    my $vrb = "$vr-$baseversion->{$_}->{branch}";
    if ($revmax{$baseversion->{$_}->{version}} ne $baseversion->{$_}->{revision})
    {
        $tr .= "<td class='$tdclass'><span class='vvul'>$vrb</span></td>";
    }
    elsif ($branch{$vr} ne $baseversion->{$_}->{branch})
    {
        $tr .= "<td class='$tdclass'><span class='vold'>$vrb</span></td>";
    }
    else
    {
        $tr .= "<td class='$tdclass'><span class='vok'>$vrb</span></td>";
    }
    $col++;
}
$tablev .= $tr;



for my $pkg (sort {$idx->{$a}->{name} cmp $idx->{$b}->{name} } keys %{$idx})
{
    # print STDERR "PKG($pkg)\n" if $debug;

    if ($row % 15 == 0)
    {
        $row++;
        my $tr = "<tr class='header'><td></td><td>INDEX</td>";
        for (@hostnames)
        {
            $tr .= "<td>$_</td>";
        }
        $tr .= "<td></td>";

        $table .= $tr;
        $tablex .= $tr if ($tablex eq ''); # only once
    }

    my $work = 0;
    for (@hostnames)
    {
        if (exists $status->{$_}->{$pkg})
        {
            $work = 1;
            last;
        }
    }
    next unless $work;
    $row++;

    my $tdclass = ($row % 2 ? "odd" : "even")."h";
    my $tr = "<tr>";
    $tr .= "<td class='$tdclass'>$idx->{$pkg}->{name}</td><td class='$tdclass'><span class='vidx'>$idx->{$pkg}->{version}</span></td>";

    my $tdclassx = ($rowx % 2 ? "odd" : "even")."h";
    my $trx = "<tr>";
    $trx .= "<td class='$tdclassx'>$idx->{$pkg}->{name}</td><td class='$tdclassx'><span class='vidx'>$idx->{$pkg}->{version}</span></td>";

    my $tx = 0;
    my $col = 0;
    for (@hostnames)
    {
        $col++;
        my $value = "&nbsp;";
        my $tdc = '';
        my $vul = undef;
        if (exists $status->{$_}->{$pkg})
        {
            my $pp = ($status->{$_}->{$pkg}->{name})."-".($status->{$_}->{$pkg}->{version});
            $pp =~ s{.*/}{};

            if (exists $vulnerable->{$_}->{$pp})
            {
                $tdc = "vvul";
                $cntvul++;
                $vul = $vulnerable->{$_}->{$pp};
                $tx = 1;
            }
            elsif ($status->{$_}->{$pkg}->{version} eq $idx->{$pkg}->{version})
            {
                $tdc = "vok";
                $cntok++;
            }
            else
            {
                my $v1 = $status->{$_}->{$pkg}->{version};
                my $v2 = $idx->{$pkg}->{version};
                $v1 =~ s/_\d+$//;
                $v2 =~ s/_\d+$//;

                if ($v1 eq $v2)
                {
                    $tdc = "vrev";
                    $cntrev++;
                }
                else
                {
                    $tdc = "vold";
                    $cntold++;
                    $vul = undef;
                }
            }

            $value = $status->{$_}->{$pkg}->{version};
        }
        
        my $tdclass = ($row % 2 ? "odd" : "even").($col % 2 ? "odd" : "even");
        $tr .= "<td class='$tdclass'><span class='$tdc'>$value</span>";
        $tr .= $vul if defined $vul;
        $tr .= "</td>";

        my $tdclassx = ($rowx % 2 ? "odd" : "even").($col % 2 ? "odd" : "even");
        $trx .= "<td class='$tdclassx'><span class='$tdc'>$value</span>";
        $trx .= $vul if defined $vul;
        $trx .= "</td>";
    }

    $tr .= "<td class='$tdclassx'>$idx->{$pkg}->{name}</td>";
    $trx .= "<td class='$tdclassx'>$idx->{$pkg}->{name}</td>";

    $table .= $tr;
    if ($tx)
    {
        $tablex .= $trx ;
        $rowx++;
    }

}



open(A, ">all-packages.txt");
for my $pkg (sort {$idx->{$a}->{name} cmp $idx->{$b}->{name} } keys %{$idx})
{
    my $tr = 0;
    for (@hostnames)
    {
        if (exists $status->{$_}->{$pkg})
        {
            $tr = 1;
            last;
        }
    }
    next unless $tr;
    print A "$pkg\n";
}
close(A);


open(H, ">status.html");
open(HEAD, "header.html");
while (<HEAD>) { print H $_ }
close(HEAD);
print H "
<span class='toplogo'>FreeBSD Package Version Monitor rev $rev</span><br><br>

<div style='text-align: left'>
    <span class='vok'>Ok: $cntok</span><br>
    <span class='vrev'>New revision: $cntrev</span><br>
    <span class='vold'>Outdated: $cntold</span><br>
    <span class='vvul'>Vulnerable: $cntvul</span><br>
</div>

<table>$tablev</table><br><br><br>
<table>$tablex</table><br>
<table>$table</table><br>
";

close(H);

exec "chromium status.html";

