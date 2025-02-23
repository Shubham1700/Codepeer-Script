# Codepeer-Script
a script utilizing the Codepeer Ada source code analyzer to identify runtime and logic errors. This script detects the author of the error and automatically sends an email notification, enhancing error resolution efficiency and improving code quality.


1.are_commits_exist Function:
Checks if two commits are valid or not.
2.generate_git_diff_command Function:
Generates differences between two commits.
Filters for .ads and .adb files.
3.generate_codepeer_report Function:
Generates the CodePeer report.
4.filter_csv_by_phrase Function:
Filters for range-check errors within the CSV.
5.check_and_write_errors Function:
Filters matches in diff.txt for changes in .ads and .adb files.
Writes these matches to codepeer_error.csv.

6.check_and_write_errors_with_author Function:
Extracts the author's name for specific line numbers in files.
Writes the information into codepeer_error_with_author.csv.
7.read_csv_and_send_emails Function:
Reads the filtered errors.
Emails the corresponding authors concerning the errors they have raised.
