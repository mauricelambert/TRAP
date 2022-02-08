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

package TRAP;

use v5.26;
use strict;
use JSON::PP;
use Text::CSV;
use Pod::Usage;
use Time::Piece;
use Getopt::Long;
use File::Basename;
use Term::ANSIColor;
use File::Map 'map_file';

# use warnings;
# use Data::Dumper;

our $NAME            = "TRAP";
our $VERSION         = "0.2.0";
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

our $HELP_MESSAGE = <<'EOF';

TRAP (Tool for Regex Analysis with Perl) version 0.2.0

usage: perl TRAP.pm [-h] [-c] [-d] (-f FILES | -t)

This program analyses Forensic files with regex to extract informations.

optional arguments:
  -h, --help            show this help message and exit
  -c, --no-color        Print without terminal colors (useful for stdout redirection)
  -d, --debug           Debug mode - enable logs (slower)
  -f FILES, --files FILES
                        The forensic files to be analysed (glob syntax, comma-separated values)
  -t, --test            Test mode (for development, to check regex)

EOF

*FILENAME = \( basename($0) );
our $FILENAME;

# my ($filenoext, $dirname, $extension) = fileparse($0);

# *DIRNAME = \($dirname);
# our $DIRNAME;

# *FILENOEXT = \($filenoext);
# our $FILENOEXT;

*SYSTEMDATE = \( localtime->strftime('%Y%m%d_%H%M%S') );
our $SYSTEMDATE;

*LOGFILENAME = \( $FILENAME . "_" . "$SYSTEMDATE.log.csv" );
our $LOGFILENAME;

my $colormode;
if ( grep { $_ eq "-c" or $_ eq "--no-color" } @ARGV ) {
    $colormode = '0';
}
else {
    $colormode = '1';
}

my $debugmode;
if ( grep { $_ eq "-d" or $_ eq "--debug" } @ARGV ) {
    $debugmode = '1';
}
else {
    $debugmode = '0';
}

*COLOR = \($colormode);
our $COLOR;

*DEBUG = \($debugmode);
our $DEBUG;

*GREEN = \( color('green') );
our $GREEN;
*CYAN = \( color('cyan') );
our $CYAN;
*MAGENTA = \( color('magenta') );
our $MAGENTA;
*YELLOW = \( color('yellow') );
our $YELLOW;
*BOLDBLUE = \( color('bold blue') );
our $BOLDBLUE;
*RESET = \( color('reset') );
our $RESET;
*BOLDRED = \( color('bold red') );
our $BOLDRED;

#pod =method log_debug
#pod
#pod     log_debug "My DEBUG message.";
#pod
#pod This function logs messages in DEBUG level.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The log message.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub log_debug {
    return 0 if !$DEBUG;

    my ( $message, $files_ref ) = @_;
    my ( $package, $filename, $line ) = caller;
    logging( $message, "DEBUG", "$package:$filename:$line", $files_ref );
    return 0;
}

#pod =method log_info
#pod
#pod     log_info "My INFO message.";
#pod
#pod This function logs messages in INFO level.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The log message.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub log_info {
    return 0 if !$DEBUG;

    my ( $message, $files_ref ) = @_;
    my ( $package, $filename, $line ) = caller;
    logging( $message, "INFO", "$package:$filename:$line", $files_ref );
    return 0;
}

#pod =method log_warning
#pod
#pod     log_warning "My WARNING message.";
#pod
#pod This function logs messages in WARNING level.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The log message.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub log_warning {
    return 0 if !$DEBUG;

    my ( $message, $files_ref ) = @_;
    my ( $package, $filename, $line ) = caller;
    logging( $message, "WARNING", "$package:$filename:$line", $files_ref );
    return 0;
}

#pod =method log_error
#pod
#pod     log_error "My ERROR message.";
#pod
#pod This function logs messages in ERROR level.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The log message.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub log_error {
    return 0 if !$DEBUG;

    my ( $message, $files_ref ) = @_;
    my ( $package, $filename, $line ) = caller;
    logging( $message, "ERROR", "$package:$filename:$line", $files_ref );
    return 0;
}

#pod =method log_critical
#pod
#pod     log_critical "My CRITICAL message.";
#pod
#pod This function logs messages in CRITICAL level.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The log message.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub log_critical {
    return 0 if !$DEBUG;

    my ( $message, $files_ref ) = @_;
    my ( $package, $filename, $line ) = caller;
    logging( $message, "CRITICAL", "$package:$filename:$line", $files_ref );
    return 0;
}

#pod =method logging
#pod
#pod     logging "My log message.", "DEBUG";
#pod     logging "My log message.", "ERROR", "script.pl:20";
#pod
#pod The logging function to log messages in CSV format.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] First argument is the message.
#pod =item *
#pod [REQUIRED - string] Second argument is the level.
#pod     Level should be:
#pod         - "DEBUG"    (10)
#pod         - "INFO"     (20)
#pod         - "WARNING"  (30)
#pod         - "ERROR"    (40)
#pod         - "CRITICAL" (50)
#pod =item *
#pod [REQUIRED - string] Last argument is the position.
#pod     Position should be: "<filename>:<line>"
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub logging {
    return 0 if !$DEBUG;

    my ( $message, $level, $localization, $files_ref ) = @_;

    my ( $package, $filename, $line ) = caller;
    $localization = "$package:$filename:$line" if !defined($localization);

    my $csv  = $files_ref->{'CSV'};
    my $file = $files_ref->{'log'};

    # date, level, filename, PID, process, filename:line, message
    $csv->say(
        $file,
        [
            localtime->strftime('%Y-%m-%d %T'),
            $level, $FILENAME, $$, $^X, $localization, $message
        ]
    ) or die "Can't write log in $LOGFILENAME: $!";

    return 0;
}

#pod =method init_log
#pod
#pod     init_log;
#pod
#pod This function initializes the CSV log file.
#pod
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub init_log {
    return 0 if !$DEBUG;

    my ($files_ref) = @_;

    my $csv  = $files_ref->{'CSV'};
    my $file = $files_ref->{'log'};

    $csv->say(
        $file,
        [
            "Date Time", "Log Level",    "Filename", "PID",
            "Process",   "Localization", "Log Message"
        ]
    ) or die "Can't write log in $LOGFILENAME: $!";
    return 0;
}

#pod =method log_and_die
#pod
#pod     log_and_die "My CRITICAL message";
#pod
#pod This function logs a CRITICAL message and die
#pod with the same message.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The log message.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" key.
#pod
#pod =back
#pod
#pod =cut

sub log_and_die {
    my ( $message, $files_ref ) = @_;
    log_critical "$message", $files_ref if !$DEBUG;
    die "$message";
}

#pod =method save_match
#pod
#pod     my %counter = (total => 0);
#pod     save_match \%counter, "myfile.bak", "IP", "8.8.8.8", 0, 7;
#pod
#pod This function saves a match found.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - hash] A hash containing counters.
#pod =item *
#pod [REQUIRED - hash] Files with "CSV" key.
#pod =item *
#pod [REQUIRED - string] The analysed filename.
#pod =item *
#pod [REQUIRED - string] The type of the match
#pod =item *
#pod [REQUIRED - string] The matching string.
#pod =item *
#pod [REQUIRED - integer] The starting position of the matching string.
#pod =item *
#pod [REQUIRED - integer] The ending position of the matching string.
#pod =back
#pod
#pod =cut

sub save_match {
    my ( $counter_ref, $files_ref, $file_analysed, $type, $match, $start, $end )
      = @_;

    my $csv  = $files_ref->{'CSV'};
    my $file = $files_ref->{$type};

    # say $files_ref;
    # say join(", ", keys %$files_ref);
    # say $csv;
    # say $file;

    if ( !defined($file) ) {
        my $filename = $NAME . "_$SYSTEMDATE/$type.csv";
        open $file, ">>:encoding(utf8)",
          "$filename" || log_and_die "Can't open: $filename: $!", $files_ref;

        $csv->say(
            $file,
            [
                "Date Time",
                "Counter total",
                "Counter $type",
                "Type",
                "Filename",
                "Start position",
                "End position",
                "Match"
            ]
        ) || log_and_die "Can't write: $filename: $!", $files_ref;
        log_debug( "$filename initialized", $files_ref );

        $files_ref->{$type} = $file;
    }

    log_debug( "Save match type $file_analysed ($start, $end)...", $files_ref );
    $csv->say(
        $file,
        [
            localtime->strftime('%Y-%m-%d %T'), $counter_ref->{'total'},
            $counter_ref->{$type},              "$type",
            "$file_analysed",                   "$start",
            "$end",                             "$match"
        ]
    ) || log_and_die "Can't write match type: $type: $!", $files_ref;
}

#pod =method process_match
#pod
#pod     my %counter = (total => 0);
#pod     process_match \%counter, "myfile.bak", "IP", "8.8.8.8", 0, 7;
#pod
#pod This function logs, prints and saves a matching
#pod string found. Counters are incremented here.
#pod Print in color mode or not is defined here.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - hash] A hash containing counters.
#pod =item *
#pod [REQUIRED - hash] Files with "CSV" key.
#pod =item *
#pod [REQUIRED - string] The analysed filename.
#pod =item *
#pod [REQUIRED - string] The type of the match
#pod =item *
#pod [REQUIRED - string] The matching string.
#pod =item *
#pod [REQUIRED - integer] The starting position of the matching string.
#pod =item *
#pod [REQUIRED - integer] The ending position of the matching string.
#pod =back
#pod
#pod =cut

sub process_match {
    my ( $counter_ref, $files_ref, $filename, $type, $match, $start, $end ) =
      @_;

    log_info( "Process new match ($type)...", $files_ref );

    log_debug( "Initialise/Increment counter...", $files_ref );
    my $total = $counter_ref->{'total'};
    my $total_field = $counter_ref->{$type} // 0;

    $total++;
    $total_field++;

    $end = 0 if !defined($end);

    log_debug( "Print information in the console....", $files_ref );
    if ($COLOR) {
        printf(
            "%s %s%.10X %s%.10X %s%.8d %s%.8d %s%-10s%s: %s%s%s\n",
            $filename, $CYAN,  $start,   $MAGENTA,     $end,
            $GREEN,    $total, $YELLOW,  $total_field, $BOLDBLUE,
            $type,     $RESET, $BOLDRED, $match,       $RESET
        );
    }
    else {
        printf( "%s %.10X %.10X %.8d %.8d %-10s: %s\n",
            $filename, $start, $end, $total, $total_field, $type, $match );
    }

    log_debug( "Set counter...", $files_ref );
    $counter_ref->{'total'} = $total;
    $counter_ref->{$type} = $total_field;

    save_match( $counter_ref, $files_ref, $filename, $type, $match, $start,
        $end );

    return;
}

#pod =method analysis
#pod
#pod     analysis "myfile.bak";
#pod
#pod This function analyses a file (perfoms
#pod regex on a Memory Map of the file content).
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - string] The analysed filename.
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" and "report" key.
#pod
#pod =back
#pod
#pod =cut

sub analysis {
    my ( $filename, $files_ref ) = @_;

    log_debug( "Start analyse on $filename. Defined fields name...",
        $files_ref );

    my $ip_field        = "IP";
    my $uu_field        = "UU";
    my $kb_field        = "KB";
    my $url_field       = "URL";
    my $gps_field       = "GPS";
    my $uuid_field      = "UUID";
    my $word_field      = "WORD";
    my $time_field      = "TIME";
    my $hash_field      = "HASH";
    my $path_field      = "PATH";
    my $phone_field     = 'PHONE';
    my $email_field     = '@EMAIL';
    my $domain_field    = "DOMAIN";
    my $base64_field    = "BASE64";
    my $base16_field    = "BASE16";
    my $urlencode_field = "URLENCODE";

    log_debug( "Initialise counter...", $files_ref );
    my %counter = ( total => 0, filename => $filename );
    my $counter_ref = \%counter;

    log_debug( "Memory map $filename...", $files_ref );
    map_file( my $map, $filename );

    log_debug( "Start research using regex...", $files_ref );

    log_debug( "Research IP...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $ip_field, $&, @-, @+ )
      while ( $map =~
/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/g
      );
    log_debug( "Research domain...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $domain_field, $&, @-,
        @+ )
      while (
        $map =~ /(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}/g );
    log_debug( "Research URL...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $url_field, $&, @-, @+ )
      while ( $map =~
m$((http|https)://)(www.)?[a-zA-Z0-9@:%._\+~#?&//=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%._\+~#?&//=]*)$g
      );
    log_debug( "Research base64...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $base64_field, $&, @-,
        @+ )
      while ( $map =~
        m$(?:[A-Za-z\d+/]{4}){10,}(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?$g );
    log_debug( "Research base16...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $base16_field, $&, @-,
        @+ )
      while ( $map =~
m$[0-9a-fA-F]{2}(?P<separator>[^0-9a-fA-F]?)([0-9a-fA-F]{2}(?P=separator)){3,}[0-9a-fA-F]{2}$g
      );
    log_debug( "Research email address...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $email_field, $&, @-,
        @+ )
      while ( $map =~
m$(?:(?!.*?[.]{2})[a-zA-Z0-9](?:[a-zA-Z0-9.+!%-]{1,64}|)|\"[a-zA-Z0-9.+!% -]{1,64}\")@[a-zA-Z0-9][a-zA-Z0-9.-]+(.[a-z]{2,}|.[0-9]{1,})$g
      );
    log_debug( "Research UUID...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $uuid_field, $&, @-,
        @+ )
      while ( $map =~
m$\{?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}?$g
      );
    log_debug( "Research URL encoding...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $urlencode_field, $&,
        @-, @+ )
      while ( $map =~
m$[-a-zA-Z0-9@:%._\+~#?&//=]*(%(25)?[0-9A-Fa-f]{2}){5,}[-a-zA-Z0-9@:%._\+~#?&//=]*$g
      );
    log_debug( "Research path...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $path_field, $&, @-,
        @+ )
      while (
        $map =~ m$(/|C:\\\\?|\.\.?(/|\\\\?))[\w .]+((/|\\\\?)[\w .]+)+$g );
    log_debug( "Research GPS...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $gps_field, $&, @-, @+ )
      while ( $map =~
m$([SNsn] )?-?[1-3]?[0-9]{1,2}(° ?|d ?|:|,|\.)-?[0-9]{1,7}('|m|:|[SNsn] ?,? ?|\.|′ ?|° ?|, ?)-?[0-9]{1,7}(\.|[SNsn],| |', [EWew] |″[SNsn] |″ [SNsn] |, ?)-?[0-9]{1,7}("(north|south), |"?[SNsn],? |:|E|° ?|d |[EWew])(-?[0-9]{1,2}(°|′ ?|:|\.|d)(-?[0-9]{1,7}(('|m|″ [EWew]|:|[EWew])(-?[0-9]{1,2}\.-?[0-9]{3}("(east|west)|"?[EWew])?)?)?)?)?$gi
      );
    log_debug( "Research hash...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $hash_field, $&, @-,
        @+ )
      while ( $map =~
m~([0-9a-fA-F]{32}([0-9a-fA-F]{8})?([0-9a-fA-F]{24})?([0-9a-fA-F]{64})?|$[0-9]+[a-zA-Z]*$[0-9\w/\.]+$[\w/\.]+)~g
      );
    log_debug( "Research phone numbers...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $phone_field, $&, @-,
        @+ )
      while ( $map =~
m$\+?\(?([0-9][- ]?)?(xx)?[0-9]{2,5}\)?(( – )?[- ]?\(?[0-9]{1,3}\)?[ 0-9]?)?( ?\(0\))?( – )?( ?/ ?)?[-\s\.]?\(?[0-9]{2,4}\)?( – )?[-\s\.]?[0-9]{2,6}( – )?[0-9]??([-\s\.]?[0-9]{2,4})*([-\s\.]?#?[0-9]{2,4})?(\s[0-9])?$g
      );
    log_debug( "Research UU encoding...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $uu_field, $&, @-, @+ )
      while ( $map =~ m~[-0-9A-Z)&:;<'%=>!*\$\]\.#,(+/@"]{61}~g );
    log_debug( "Research KB...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $kb_field, $&, @-, @+ )
      while ( $map =~ m~KB[0-9]{7}~g );
    log_debug( "Research word...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $word_field, $&, @-,
        @+ )
      while ( $map =~
m$[ -~]*(ID|HOST|SYSTEM|WINDOWS|LINUX|PASSWORD|USER|CERTIFICATE|COPYRIGHT)[ -~]{6,}$gi
      );
    log_debug( "Research time...", $files_ref );
    process_match( $counter_ref, $files_ref, $filename, $time_field, $&, @-,
        @+ )
      while ( $map =~
m$([0-9]{4}(-[0-9]{2}){2}T([0-9]{2}:){2}[0-9]{2}\.[0-9]+|([A-Z][a-z]{2}\s){2}\s[0-9]{1,2}\s([0-9]{2}:){2}[0-9]{2}\s[0-9]{4}|[0-9]{9,10}\.[0-9]+)$g
      );

    log_debug( "Write JSON report...", $files_ref );
    my $json   = encode_json($counter_ref);
    my $report = $files_ref->{'report'};
    say $report "$json" || log_and_die "Can't write: report.json: $!",
      $files_ref;
}

#pod =method test
#pod
#pod     test;
#pod
#pod This function tests the analysis function
#pod and regex quality.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - hash] Files with "log", "CSV" and "report" key.
#pod
#pod =back
#pod
#pod =cut

sub test {
    my ($files_ref) = @_;

    log_debug( "Enter in test mode...",        $files_ref );
    log_debug( "Defined and open filename...", $files_ref );
    my $filename = "test.txt";
    open( my $file, '>', $filename )
      or log_and_die "Can't open $filename $!", $files_ref;

    log_debug( "Write __DATA__ in $filename...", $files_ref );
    while ( my $line = <DATA> ) {
        say $file $line
          or log_and_die "Can't write $line in $filename $!", $files_ref;
    }

    # close $file;
    log_debug( "$filename closed.", $files_ref );

    analysis $filename, $files_ref;

    log_debug "Delete file created...", $files_ref;
    unlink($filename);
    return;
}

#pod =method parse_args
#pod
#pod     parse_args;
#pod
#pod This function parse command line
#pod arguments using GetOpt::Long.
#pod
#pod =cut

sub parse_args {

    # pod2usage(2) if !defined($ARGV[0]);
    pod2usage( -verbose => 1, -exitval => 2, -message => $HELP_MESSAGE )
      if !(
        grep {
                 $_ eq "-t"
              or $_ eq "--test"
              or $_ eq "-f"
              or $_ eq "--files"
              or $_ eq "-h"
              or $_ eq "--help"
        } @ARGV
      );

    GetOptions(
        't|test' => \
          my $test
        ,    # Test mode, create a text file with all the matching patterns.
        'f|files=s' => \
          my @files
        ,    # Glob syntax of the files to be analysed (comma-separated value).
        'c|no-color' => \my $color,    # Disabled color mode.
        'd|debug'    => \my $debug,    # Enabled debug mode (with logs, slower).
        'h|help'     => sub {
            pod2usage(
                -verbose => 1,
                -exitval => 1,
                -message => $HELP_MESSAGE
            );
        },
    ) or pod2usage( -verbose => 1, -exitval => 2, -message => $HELP_MESSAGE );

    @files = split( /,/, join( ',', @files ) );

    return ( $test, \@files );
}

#pod =method closefiles
#pod
#pod     closefiles;
#pod
#pod This function loop on files values
#pod to close all opened files.
#pod
#pod =over 4
#pod =item *
#pod [REQUIRED - hash] Files opened.
#pod
#pod =back
#pod
#pod =cut

sub closefiles {
    my ($files_ref) = @_;

    # delete $files_ref->{'CSV'};

    log_debug( "Close all files...", $files_ref );
    for my $file ( keys %$files_ref ) {

        # if (ref($file) eq "GLOB") {
        #     close $file;
        # }
        if ( $file ne "CSV" && $file ne "log" ) {
            close $files_ref->{$file};
        }
    }
}

#pod =method main
#pod
#pod     main;
#pod
#pod This function execute the file
#pod from the command line.
#pod
#pod =cut

sub main {
    open my $report, ">>", "report.json" || die "Can't open: report.json: $!";
    my $csv = Text::CSV->new(
        {
            binary          => 1,
            sep_char        => ",",
            always_quote    => 1,
            quote_empty     => 1,
            # skip_empty_rows => 1
        }
    ) or die "Cannot use CSV: " . Text::CSV->error_diag();

    my %files = (
        report => $report,
        CSV    => $csv,
    );

    if ($DEBUG) {
        open my $logfile, ">>:encoding(utf8)", "$LOGFILENAME"
          or die "Can't open log file: $LOGFILENAME: $!";
        $files{'log'} = $logfile;
    }

    my $files_ref = \%files;

    init_log($files_ref);
    log_debug( "Logging initialized. Parse arguments...", $files_ref );

    my ( $test, $file_lists_ref ) = parse_args;

    log_debug "Create directory report: " . $NAME . "_$SYSTEMDATE...",
      $files_ref;
    mkdir $NAME . "_$SYSTEMDATE"
      or log_critical "Can't create directory: " . $NAME . "_$SYSTEMDATE: $!"
      && die "Can't create directory: " . $NAME . "_$SYSTEMDATE: $!";

    if ( defined($test) ) {
        test $files_ref;
        log_debug( "End, exit code 0.", $files_ref );
        return 0;
    }

    log_debug "Loop on glob syntax list...", $files_ref;
    foreach my $globfiles ( @{$file_lists_ref} ) {
        log_debug "Get files from $globfiles glob syntax...", $files_ref;
        foreach my $file ( glob($globfiles) ) {
            log_debug "$file found from $globfiles", $files_ref;
            analysis $file, $files_ref;
        }
    }

    log_debug( "Close files", $files_ref );
    closefiles \%files;

    log_debug( "End, exit code 0.", $files_ref );
    close $files{"log"} if exists( $files{"log"} );
    return 0;
}

say "\n$COPYRIGHT";
say "$NAME_ARTS";
exit main();

__DATA__

===============
=    TESTS    =
===============

# IP
10.52.68.25
269.52.68.25
10.52.68.2555
10.52.68.26  

# Domain  
www.example.com

# Base16
001122334455667   # + 7
00:11:22:33:44:55 # MAC address
00112233445566778899aaAAbbBBccCCddDDeeEEffFF
00-11-22-33-44-55-66-77-88-99-aa-AA-bb-BB-cc-CC-dd-DD-ee-EE-ff-FF

# Base64
YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=

# Email
test@gmail.com

# Path
C:\\tmp\\tt.txt
/etc/sysctl.conf

# KB
KB4577586

# Word
HOST: d.abc.com
ID: 01/#{}[]&~^

# Time
1000000000.000000
Sun Sep  9 01:46:39 2001
2016-06-22T12:34:16.844423

# URL
http://example.com/test.pl?abc#def

# URL encoding (pourcent encoding) + double encoding
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%21%22%23%24%25%26%27%28%29%2A%2B%2C-./%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~%20%09%0A%0D%0B%0C
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%2521%2522%2523%2524%2525%2526%2527%2528%2529%252A%252B%252C-./%253A%253B%253C%253D%253E%253F%2540%255B%255C%255D%255E_%2560%257B%257C%257D~%2520%2509%250A%250D%250B%250C

# Hash
d41d8cd98f00b204e9800998ecf8427e
da39a3ee5e6b4b0d3255bfef95601890afd80709
$2y$10$VYf2VoR3lKZMV/qyioPFielCiybdE.rh1r0GGJ08tf2ivZUqqgDSa
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e

# UUID
79cdabf3-f4db-4657-be86-a8c2cc70b0ab

# GPS
50°4'17.698"north, 14°24'2.826"east
50°4'17.698"NORTH, 14°24'2.826"EAST
50d4m17.698N 14d24m2.826E
40:26:46N,79:56:55W
40:26:46.302N 79:56:55.903W
49°59'56.948"N, 15°48'22.989"E
50d4m17.698N 14d24m2.826E
49.9991522N, 15.8063858E
N 49° 59.94913', E 15° 48.38315'
40°26′47″N 79°58′36″W
40d 26′ 47″ N 79d 58′ 36″ W
40.446195N 79.948862W
40,446195° 79,948862°
40° 26.7717, -79° 56.93172
40.446195, -79.948862

# Email encoding (base16 regex)
=00=01=02=03=04=05=06=07=08=09
=0E=0F=10=11=12=13=14=15=16=17=18=19=1A=1B=1C=1D=1E=1F !"#$%&'()*+,-=
./0123456789:;<=3D>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuv=
wxyz{|}~=7F=80=81=82=83=84=85=86=87=88=89=8A=8B=8C=8D=8E=8F=90=91=92=93=94=
=95=96=97=98=99=9A=9B=9C=9D=9E=9F=A0=A1=A2=A3=A4=A5=A6=A7=A8=A9=AA=AB=AC=AD=
=AE=AF=B0=B1=B2=B3=B4=B5=B6=B7=B8=B9=BA=BB=BC=BD=BE=BF=C0=C1=C2=C3=C4=C5=C6=
=C7=C8=C9=CA=CB=CC=CD=CE=CF=D0=D1=D2=D3=D4=D5=D6=D7=D8=D9=DA=DB=DC=DD=DE=DF=
=E0=E1=E2=E3=E4=E5=E6=E7=E8=E9=EA=EB=EC=ED=EE=EF=F0=F1=F2=F3=F4=F5=F6=F7=F8=
=F9=FA=FB=FC=FD=FE=FF

# UU encoding
begin 666 -
M86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)3
M5%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"
M0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK
M;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W
M-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-
M3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V
M=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E
M9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=8
M65HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'
M2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P
M<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R
M,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%2
M4U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!
M0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ
M:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX
M-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,
M34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U
M=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D
M969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-45597
M6%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&
M1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO
M<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S
M,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!1
M4E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ
M04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI
M:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y
M.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+
M3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T
M=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C
M9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%56
M5UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%
M1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN
M;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T
M,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]0
M45)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY
M>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H
M:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP
M.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*
M2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S
M='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B
M8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U15
M5E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$
M149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM
M;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U
M-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/
M4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X
M>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G
M:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:
M,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)
M2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R
M<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A
M8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-4
M55976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#
M1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML
M;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V
M-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.
M3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W
M>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F
M9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA9
M6C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(
M24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q
M<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q
M86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)3
M5%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"
M0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK
M;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W
M-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-
M3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V
M=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E
M9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=8
M65HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'
M2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P
M<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R
M,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%2
M4U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!
M0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ
M:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX
M-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,
M34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U
M=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D
M969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-45597
M6%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&
M1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO
M<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S
M,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!1
M4E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ
M04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI
M:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y
M.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+
M3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T
M=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C
M9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%56
M5UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%
M1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN
M;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T
M,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]0
M45)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY
M>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H
M:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP
M.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*
M2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S
M='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B
M8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U15
M5E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$
M149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM
M;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U
M-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/
M4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X
M>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G
M:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:
M,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)
M2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R
M<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A
M8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-4
M55976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#
M1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML
M;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V
M-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.
M3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W
M>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q86)C9&5F
M9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)35%565UA9
M6C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"0T1%1D=(
M24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK;&UN;W!Q
M<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W-C4T,S(Q
M86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-3D]045)3
M5%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V=WAY>D%"
M0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E9F=H:6IK
M;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=865HP.3@W
M-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'2$E*2TQ-
M3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P<7)S='5V
M=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R,6%B8V1E
M9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%24U155E=8
M65HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!0D-$149'
M2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C%A8F-D969G:&EJ:VQM;F]P
M<7)S='5V=WAY>D%"0T1%1D=(24I+3$U.3U!14E-455976%E:,#DX-S8U-#,R
M,6%B8V1E9F=H:6IK;&UN;W!Q<G-T=79W>'EZ04)#1$5&1TA)2DM,34Y/4%%2
M4U155E=865HP.3@W-C4T,S(Q86)C9&5F9VAI:FML;6YO<'%R<W1U=G=X>7I!
C0D-$149'2$E*2TQ-3D]045)35%565UA96C Y.#<V-30S,C$

end

# Phone numbers
0 52 22 – 9 50 93 10
0 9754845789
0-9778545896
+33-1.23.45.67.89
+33(0) 123 456 789
+33 (0)123 45 67 89
+33 (0)1 2345-6789
+33(0) – 123456789
+49(0)121-79536 – 77
+49(0)2221-39938-113
+49 (0) 1739 906-44
+31(0)235256677
06442 / 38 93 02 3
042/ 88 17 890 0
(02852) 5996-0
+919367788755
8989829304
+16308520397
786-307-3615
1234567890
123-456-7890
123.456.7890
123 456 7890
(123) 456 7890
+447222555555
+44 7222 555 555
(0722) 5555555 #2222
0123456789
01 23 45 67 89
01.23.45.67.89
0123 45.67.89
0033 123-456-789
+33 – 123 456 789
(06442) 3933023
(042) 1818 87 9919
06442 / 3893023
06442/3839023
+49 221 549144 – 79
+49 221 – 542194 79
+49 (221) – 542944 79
+49 (173) 1799 806-44
0214154914479
02141 54 91 44 79
01517953677
+491517953677
015777953677
02162 – 54 91 44 79
(02162) 54 91 44 79
0936-4211235
89076543
010-12345678-1234
008618311006933
+8617888829981
19119255642
03595-259506
03592 245902
03598245785
9775876662
+91 9456211568
91 9857842356
919578965389
(12) 123 1234
(01512) 123 1234
(0xx12) 1234 1234
0732105432
1300333444
131313
+31235256677
023-5256677


__END__

=pod

=encoding UTF-8

=head1 TRAP

=head2 NAME

TRAP - Tool for Regex Analysis with Perl

=head2 VERSION

version 0.2.0

=head2 SYNOPSIS

=head3 Perl

    use TRAP;
    open my $report, ">>", "report.json";
    my $csv = Text::CSV->new ( { binary => 1, sep_char => "," } );
    my %files = (CSV => $csv, report => $report);
    analysis "myfile.bak", \%files;

=head3 Command line

    ~# perl TRAP.pm -h
    ~# perl TRAP.pm --help
    ~# perl TRAP.pm -t
    ~# ./TRAP.pm --test --debug --no-color
    ~# perl TRAP.pm -c -d -f *.txt,*.bak,*.bin
    ~# ./TRAP.pm --files *.txt,*.bak,*.bin

=head2 DESCRIPTION

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

C<JSON::PP> - JSON::PP

=item *

C<Text::CSV> - Text::CSV

=item *

C<Pod::Usage> - Pod::Usage

=item *

C<Time::Piece> - Time::Piece

=item *

C<Getopt::Long> - Getopt::Long

=item *

C<File::Basename> - File::Basename

=item *

C<Term::ANSIColor> - Term::ANSIColor

=item *

C<File::Map> - File::Map

=back

=head2 INSTALLATION

    ~# git clone https://github.com/MauriceLambert/TRAP.git

=head2 METHODS

=head4 analysis

    use TRAP;
    open my $report, ">>", "report.json";
    my $csv = Text::CSV->new ( { binary => 1, sep_char => "," } );
    my %files = (CSV => $csv, report => $report);
    analysis "myfile.bak", \%files;

This method does not return any values.

=over 4

=item *

C<filename> - The path and name of the file to be analysed.

=back

This method analyses a file and saves matches found in CSV files.

=head2 OSNAMES

any

=head2 SCRIPT CATEGORIES

Forensic/Investigation

=head2 DOCUMENTATION

=over 4

=item *

L<https://mauricelambert.github.io/info/perl/code/TRAP.html>

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


