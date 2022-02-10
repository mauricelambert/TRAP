#!/usr/bin/env perl

# TRAP - Tool for Regex Analysis with Perl
# 2022-01-26
# Maurice LAMBERT <mauricelambert434@gmail.com>
# https://github.com/mauricelambert/TRAP

###################
#    This file implements a forensic analyser based on regex.
#    Copyright (C) 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

package TRAP::Compare;

use v5.26;
use strict;
use Text::CSV qw( csv );

# use warnings;
# use Data::Dumper;

our $NAME            = "TRAP";
our $VERSION         = "0.0.1";
our $AUTHOR          = "Maurice Lambert";
our $MAINTAINER      = "Maurice Lambert";
our $AUTHOR_MAIL     = 'mauricelambert434@gmail.com';
our $MAINTAINER_MAIL = 'mauricelambert434@gmail.com';

our $DESCRIPTION = "This file implements a forensic analyser based on regex.";
our $URL         = "https://github.com/mauricelambert/$NAME";
our $LICENSE     = "GPL-3.0 License";
our $COPYRIGHT   = <<'EOF';

TRAP (Tool for Regex Analysis with Perl)  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

EOF

our $NAME_ARTS = <<'EOF';
____________________________________________
_|_____|____|____|_________|______|____|____
__|_____|_____|____|___|_______|____|____|__
\_      __/\____     \__/  _  \__\____  _  \
__|    |_|__|       _/_/  /_\  \__|     ___/
|_|    |____|    |   \/    |    \_|    |_|__
__|____|_|__|____|_  /\____|__  /_|____|__|_
___|_____|____|____\/___|_____\/____|____|__
__|_____|___|____|_______|___|_____|___|____

EOF

#pod =method get_targets_or_exit
#pod
#pod     get_targets_or_exit;
#pod
#pod This function returns a list
#pod of directories to be analysed,
#pod from default value or arguments.
#pod
#pod =cut

sub get_targets_or_exit {
    my @directories;

    if ($#ARGV < 0) {
        @directories = glob("TRAP_*");
    } else {
        @directories = @ARGV[1 .. $#ARGV];
    }

    if ($#directories < 0) {
        say "ERROR: no directory matching...\nPlease use valid glob syntax matching with directory.";
        exit 2;
    }

    return \@directories;
}

#pod =method analysis
#pod
#pod     analysis \@directories;
#pod
#pod This function analyses CSV report
#pod files to find matches and filenames.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - array] glob syntax of directory names.
#pod
#pod =back
#pod
#pod =cut

sub analysis {
    my ( $directories ) = @_;

    my %reports = ();
    my $report_data;

    foreach my $directory (@{$directories}) {
        foreach my $file (glob("$directory/*.csv")) {
            $report_data = csv (in => "$file", headers => "auto");
            foreach my $match (@{ $report_data }) {
                # say($match);
                # say($file);
                # say($directory);
                
                # $reports{%{$match}{"Match"}} = exists($reports{%{$match}{"Match"}}) ? $reports{%{$match}{"Match"}} : {}; # WORKING
                $reports{%{$match}{"Match"}} = $reports{%{$match}{"Match"}} // {} ;
                $reports{%{$match}{"Match"}}{%{$match}{"Filename"}} = 1;

                # $reports{%{$match}{"Match"}} = { %{$match}{"Filename"} => 1, %{$reports{%{$match}{"Match"}}} }; # NOT WORKING
                # say(Dumper(\%reports));
            }
        }
    }

    return \%reports;
}

#pod =method report
#pod
#pod     report \%reports;
#pod
#pod This function saves and prints
#pod matches with multiple filenames.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - hash] reports {match: {filename: 1}}.
#pod
#pod =back
#pod
#pod =cut

sub report {
    my ( $reports ) = @_;
    my %reports = %{$reports};

    my @files;
    my $str_files;
    my $length;

    open my $report, ">", "report.csv" || die "Can't open: report.csv: $!";
    my $csv = Text::CSV->new(
        {
            binary          => 1,
            sep_char        => ",",
            always_quote    => 1,
            quote_empty     => 1,
            # skip_empty_rows => 1
        }
    ) or die "Cannot use CSV: " . Text::CSV->error_diag();

    $csv->say(
        $report,
        ["file number", "files", "match"]
    ) or die "Can't write headers in report.csv: $!";

    for my $match (keys %reports) {
        @files = keys %{$reports{$match}};

        # say "$match -> @files";

        if ($#files > 0) {
            $str_files = join(", ", @files);
            $length = $#files + 1;
            say "[$length] $str_files : $match";

            $csv->say(
                $report,
                ["$length", "$str_files", "$match"]
            ) or die "Can't write line in report.csv: $!";
        }
    }

    close $report or die "Can't close report.csv: $!";
    return 0;
}

#pod =method main
#pod
#pod     main;
#pod
#pod This function launchs the script
#pod from the command line.
#pod
#pod =cut

sub main () {
    my $directories = get_targets_or_exit();
    my $reports = analysis($directories);
    return report($reports);
}

say $COPYRIGHT;
say $NAME_ARTS;
exit main();

__END__

=pod

=encoding UTF-8

=head1 TRAP

=head2 NAME

TRAP::Compare.
TRAP - Tool for Regex Analysis with Perl

=head2 VERSION

version 0.0.1

=head2 SYNOPSIS

=head3 Perl

    use TRAP::Compare;
    my @directories = ("TRAP_*", "report_*");
    my $reports = analysis \@directories;
    report($reports);

=head3 Command line

    ~# perl TRAP.pm -f "forensic_files*,other_files*"
    ~# perl TRAP/Compare.pm
    ~# perl TRAP/Compare.pm "custom_report_directories*" "second_report_directory*"

=head2 DESCRIPTION

=head3 TRAP

A forensic tool to extract some informations from files.

I created this tool following an investigation of an infected backup file.
This file was only part of a backup and it was necessary to identify the
server to which this piece of backup corresponded. I finally found the server
by analyzing the file, strings after strings. Some strings allowed the absolute
identification of the server. I chose to create this tool in order to avoid
long search to other people in a similar case.

It was also important to find out why the file was detected as infected. This tool
will allow you to identify certain payloads or abnormal elements on a server.

I make this tool in perl because it is pre-integrated on all Linux systems
and it is particularly optimized for regular expression.

=head3 TRAP::Compare

This file compare reports by filename and saves and prints matches with
multiple filenames.

=head2 REQUIREMENTS

=over 4

=item *

C<perl> - Perl (v5.26)

=item *

C<perl standard library> - Perl Standard Library

=back

Modules used:

=over 4

=item *

C<strict> - strict

=item *

C<Text::CSV> - Text::CSV

=back

=head2 INSTALLATION

    ~# git clone https://github.com/MauriceLambert/TRAP.git

=head2 METHODS

=head4 analysis

    use TRAP::Compare;
    my @directories = ("TRAP_*", "report_*");
    my $reports = analysis \@directories;
    report($reports);

This method returns a HASH of HASHES -> {match => {filename => 1}}.

=over 4

=item *

C<directories> - Array of glob syntax of report directories to be analysed.

=back

This method analyses reports to extract matches with multiple filenames.

=head2 OSNAMES

any

=head2 SCRIPT CATEGORIES

Forensic/Investigation

=head2 DOCUMENTATION

=over 4

=item *

L<https://mauricelambert.github.io/info/perl/code/TRAP_Compare.html>

=back

=head2 SUPPORT

=head4 Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/MauriceLambert/TRAP/issues>.
You will be notified automatically of any progress on your issue.

=head4 Source Code

This is open source software.  The code repository is available for
public review and contribution under the terms of the license.

L<https://github.com/MauriceLambert/TRAP>

  git clone https://github.com/MauriceLambert/TRAP.git

=head2 AUTHORS

=over 4

=item *

Maurice LAMBERT <mauricelambert434@gmail.com>

=back

=head2 COPYRIGHT AND LICENSE

TRAP  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

=over 4

=item *

L<https://www.gnu.org/licenses/> - Licensed under the GPL, version 3. (GPL-3.0 License)

=back

=cut


