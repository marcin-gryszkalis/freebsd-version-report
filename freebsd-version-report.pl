#!/usr/bin/perl -w
use strict;
use warnings;
use Data::Dumper;
use POSIX qw{strftime};

my $debug = 1;

my $inifile = $ARGV[0] // "freebsd-version-report.ini";

my $rev = '0.2';
my $godate = POSIX::strftime("%F %T", localtime);

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

my @hosts = split/\|/, $cfg{host};
my @hostnames;
my $status;
#my $installed;
my $baseversion;
my %branch;
my $vulnerable;
my $proxy;
for my $hh (@hosts)
{
    print STDERR "getting info from host[$hh]...\n";
    my ($name, $hostt) = split /\s+/, $hh;
    push(@hostnames, $name);

    $proxy = '';
    if ($hostt =~ m/!(\S+)/)
    {
        $proxy = "-o 'ProxyCommand=nc -X5 -x $1 \%h \%p'";
        $hostt =~ s/!.*//;
    }
    my ($host, $port) = split /:/, $hostt;
    $port = 22 unless $port;

    my $ssh = "ssh -o VisualHostKey=no $proxy -p $port $host";

    my $hostver = `$ssh 'freebsd-version'`; # 10.1-RELEASE-p3
    $hostver =~ m/(\d+)\.(\d+)-[^-]+(-(p\d+))?/;
    my $fv = $baseversion->{$name}->{version} = $1;
    my $rev = $baseversion->{$name}->{revision} = $2;
    $baseversion->{$name}->{branch}=($4 || 'X');

    if (not exists $branch{"$fv.$rev"})
    {
        print STDERR "checking branches...\n";
        my $onv = $cfg{newvers};
        my $nv = $onv;
        $nv =~ s/XXX/$fv.$rev/;

        my $t = `curl -f -s '$nv'`;
        # next FV if $? > 0; ### error case

        # BRANCH="RELEASE-p3"
        if ($t =~ m/.*BRANCH="RELEASE-(p\d+).*/)
        {
            $t = $1;
        }
        else
        {
            $t = 'X';
        }

        print STDERR "FreeBSD: $fv.$rev-$t\n";
        $branch{"$fv.$rev"} = $t;

    }

    open (my $pkgaudf, "$ssh 'sudo pkg audit -Fq'|") or die $!;
    # samba35-3.5.15
    # subversion-1.8.10_3
    while (<$pkgaudf>)
    {
        chomp;
        my $v = $_;

        open (my $pkgaudf2, "$ssh 'pkg audit $v'|") or die $!;
# phpMyAdmin-4.2.11 is vulnerable:
# phpMyAdmin -- XSS and DoS vulnerabilities
# CVE: CVE-2014-9219
# CVE: CVE-2014-9218
# WWW: http://portaudit.FreeBSD.org/c9c46fbf-7b83-11e4-a96e-6805ca0b3d42.html

# phpMyAdmin-4.2.11 is vulnerable:
# phpMyAdmin -- XSS and information disclosure vulnerabilities
# CVE: CVE-2014-8961
# CVE: CVE-2014-8960
# CVE: CVE-2014-8959
# CVE: CVE-2014-8958
# WWW: http://portaudit.FreeBSD.org/a5d4a82a-7153-11e4-88c7-6805ca0b3d42.html
        my $desc = '';
        while (<$pkgaudf2>)
        {
            chomp;
            if (/^\s*\S+\s--\s*(.*)/)
            {
                $desc = $1;
                next;
            }

            if (/^\s*WWW:\s*(\S+)/)
            {
                $vulnerable->{$name}->{$v} .= "<a href='$1' title='$desc'>[X]</a>";
            }

        }
    }

    open (S, "$ssh 'pkg info -ao'|") or die("cannot read from host");
    while (<S>)
    {
        chomp;

        my $pname;
        my $pver;

        my @l = split/\s+/;
        $l[0] =~ m/(.*)-(.*)/;
        $pname = $1;
        $pver = $2;
        $status->{$name}->{$l[1]}->{name} = $pname;
        $status->{$name}->{$l[1]}->{version} = $pver;
        #$installed->{$name}->{$pname} = 1;
        print STDERR "$name $pname ($l[1]) = $pver\n" if $debug;
    }

#    print Dumper $status;
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



my $tr = "<tr class='header'><td>&nbsp;</td><td>&nbsp;</td>";
for (@hostnames)
{
    $tr .= "<td>$_</td>";
}
$tr .= "<td>&nbsp;</td>";
$tablev .= $tr;

$tr = "<tr><td>FreeBSD version</td><td>&nbsp;</td>";
my $col = 0;
for (@hostnames)
{
    my $tdclass = "odd".($col % 2 ? "odd" : "even");
    my $vr = "$baseversion->{$_}->{version}.$baseversion->{$_}->{revision}";
    my $vrb = "$vr-$baseversion->{$_}->{branch}";
    if ($branch{$vr} ne $baseversion->{$_}->{branch})
    {
        $tr .= "<td class='$tdclass'><span class='vvul'>$vrb</span></td>";
    }
    # elsif ($revmax{$baseversion->{$_}->{version}} ne $baseversion->{$_}->{revision})
    # {
    #     $tr .= "<td class='$tdclass'><span class='vold'>$vrb</span></td>";
    # }
    else
    {
        $tr .= "<td class='$tdclass'><span class='vok'>$vrb</span></td>";
    }
    $col++;
}
$tr .= "<td>&nbsp;</td>";
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
        $tablex .= $tr if ($tablex eq ''); # only once in vuln-table
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
<div class='toplogo'>FreeBSD Package Version Monitor rev $rev</div>
<div class='title'>generated: $godate</div>
<br>

<div style='text-align: left'>
    <span class='vok'>Ok: $cntok</span><br>
    <span class='vrev'>New revision: $cntrev</span><br>
    <span class='vold'>Outdated: $cntold</span><br>
    <span class='vvul'>Vulnerable: $cntvul</span><br>
</div>

<table>
$tablev
$tablex
</table><br>
";

close(H);

exec "chromium status.html";

