############################################################################################################################################
#
# Author : MAHAJAN Shubham
#
# Description: This tool performs below actions
#               1. Extract diff with code changes
#                   (between topic branch and target branch or compares two different commits)
#               2. Read diff file to extract modified source filenames and line numbers
#               3. Run codepeer check only on the changed files range check errors and generate report
#               4. Parse codepeer report and only extract anomalies related to changes made by developer
#               5. Generate codepeer report as an artefact for developer to check for anomalies on changes made

#
# NOTE: For detailed documentation refer to GitLab Wiki page:
# https://alm.alstom.com/git/ErtmsTracksideApplicationSoftware/rbc/rbc/-/wikis/CI/Codepeer-Checker
#
# References:
#
# Command to extract diff:
# git diff --unified=0 <dev_branch/commit> <topic_branch/commit~> --ignore-blank-lines --output=diff.txt
#
# Command to do CodePeer analysis on code:
# gnatsas analyze -P rbc_appli.gpr --mode=deep --progress-bar=gnat-studio --no-gnat -- inspector --messages normal
#
# Command to generate CodePeer report:
# gnatsas report csv -P rbc_appli.gpr -o codepeer.csv
############################################################################################################################################

import os
import argparse
import csv
# Load rbc_common.py to use common utility functions
import importlib.util
import subprocess

#email generation libraries 
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl

path = os.path.normpath(os.path.dirname(os.path.abspath(__file__)) + "../../../../ci")
print(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("rbc_common", f"{path}\\rbc_common.py")
rbc_common = spec.loader.load_module()

# initialize global variables
rbc_root_dir = rbc_common.Get_Base_Directory()
local_base_path = os.getcwd()
path_filter = "*.ada *.adb *.ads"
diff_path = local_base_path + "\\diff.txt"
project_file_path = rbc_root_dir + r"\designer_test\integration\rbc_appli.gpr"
# list the codepeer errors that the script needs to consider; eg: errors_list_to_filter = ['range check', 'overflow check']
errors_list_to_filter = ['range check']

# email generation for identified authors
author_emails_list = []


paths_to_search = [
    "MooN",
    "src",
    "native_tools/src",
]

input_csv = 'codepeer_errors.csv'
output_csv = 'codepeer_errors_with_author.csv'

##########################
# Functions
##########################


# Run Gnat check and generate report
def generate_gnat_check_report():
    cur_dir = os.getcwd()
    local_report_path = cur_dir + r"\gnatcheck_report"
    project_file_path = rbc_root_dir + r"\designer_test\integration\rbc_appli.gpr"
    rules_file_path = cur_dir + r"\gnatcheck-rule-list.ref"

    gnatcheck_command = (
        "gnatcheck"
        + " --show-rule"
        + " -P "
        + project_file_path
        + " -o "
        + local_report_path
        + " -files=source_files_list.txt -rules -from="
        + rules_file_path
    )
    print("Gnat check command: ", gnatcheck_command)
    ReturnValue = os.system(gnatcheck_command)
    if ReturnValue > 1:
        print("Error during execution of Command:", gnatcheck_command)
        print("Exit code:", ReturnValue)
        if ReturnValue == 2:
            print(
                f"A tool failure was detected (in this case the results of the gnatcheck run cannot be trusted)"
            )
        elif ReturnValue == 3:
            print(f"No Ada source file was checked")
        elif ReturnValue == 4:
            print(f"Parameter of the rule -from option denotes a nonexistent file")
        elif ReturnValue == 5:
            print(
                f"The name of an unknown rule in a rule option or some problem with rule parameters"
            )
        elif ReturnValue == 6:
            print(f"Any other problem with specifying the rules to check")
        else:
            print("Undefined problem with Gnatcheck. Unknown errorcode")
        raise SystemExit(1)
    elif ReturnValue != 1:
        if not os.path.exists("gnatcheck_report"):
            print("Error during execution of Command:", gnatcheck_command)
            print("Exit code:", ReturnValue)
            raise SystemExit(1)


# Read report and only extract findings related to changes made
def parse_gnatcheck_report(changes_dict):
    report_file = open(r"gnatcheck_report", "r")
    anomaly_report_file = open(r"anomaly_report", "w")
    lines = report_file.readlines()

    # extract findings related to changes made from the Gnatcheck report
    # TODO:Improve performance of the algorithm
    for key in changes_dict:
        changed_ln_numbers = []
        matches = 0
        changed_ln_numbers = changes_dict.get(key)
        for line in lines:
            if ".adb" in line or ".ads" in line:
                if line.startswith(key):
                    violated_line_number = int(line.split(":")[1])
                    if violated_line_number in changed_ln_numbers:
                        matches = matches + 1
                        anomaly_report_file.write(line)

        print(
            "Analysed file: ",
            key,
            "from changes dictionary. No of matches: ",
            matches,
            changed_ln_numbers,
        )

    anomaly_report_file.truncate()
    report_file.close()
    anomaly_report_file.close()

    # Deliver the job verdict based on anomaly report
    file_size = os.path.getsize(r"anomaly_report")
    if file_size == 0:
        rbc_common.print_success("anomaly_checker.py: NO ANOMALIES FOUND")
        os.remove("anomaly_report")
    else:
        rbc_common.print_warning(
            f"Please check artifacts located in {os.path.dirname(__file__)}."
        )
        with open(r"anomaly_report") as file:
            for line in file:
                rbc_common.print_error(line)
        rbc_common.fail("Anomalies detected in the changes made!")

def commits_are_valid(sha1_1, sha1_2):
    try:
        # Use subprocess to execute Git commands
        # Check if the first commit exists
        subprocess.check_output(['git', 'cat-file', '-e', sha1_1])
        # Check if the second commit exists
        subprocess.check_output(['git', 'cat-file', '-e', sha1_2])
        # If both commits exist, return True
        return True
    except subprocess.CalledProcessError:
        # If any of the commands fail (commit does not exist), return False
        return False

def read_inputs_and_validate(commits):
    # Parse command line arguments  
    parser = argparse.ArgumentParser(
        description="Identifies selected codepeer errors from changes between two given Git commits",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        usage="""
Running codepeer_checker.py will identify selected codepeer errors from changes between two given Git commits. 
It accepts 2 git commits as input arguments.
        """,
    )
    parser.add_argument("-c1", "--commit1", help="First commit or chronologically older commit", required=True)
    parser.add_argument("-c2", "--commit2", help="Second commit or chronologically recent commit", required=True)
    args = parser.parse_args()
    print(args)
    if commits_are_valid(args.commit1, args.commit2):
        commits.append(args.commit1)
        commits.append(args.commit2)
        print ("Input arguments validated successfully")
        return True
    else:
        return False

def generate_git_diff_command(commit1, commit2, path_filter, output_path):
    git_command = f"git diff --unified=0 --ignore-blank-lines {commit1}..{commit2} --output={diff_path} -- {path_filter}"
    
    return git_command

def trim_file_path_in_dict_keys(changes_dict):
    new_dict = {}
    for key, value in changes_dict.items():
        key_parts = key.split("/")
        file_name_from_key = key_parts[-1]
        new_dict[file_name_from_key] = value
    return new_dict

def filter_csv_by_phrase(input_filename, output_filename, phrase, delimiter=','):
    """
    Filters a CSV file by a specified phrase in a specific column and writes the matching rows to a new CSV file.

    Args:
    input_filename (str): The name of the input CSV file.
    output_filename (str): The name of the output CSV file.
    phrase (str): The phrase to filter by.
    delimiter (str, optional): The delimiter used in the CSV file. Defaults to ','.
    """
    # Open the input file
    with open(input_filename, 'r', newline='') as input_file:
        reader = csv.DictReader(input_file, delimiter=delimiter)
        # Define fieldnames for the output CSV file
        fieldnames = reader.fieldnames
        # Open the output file
        with open(output_filename, 'w', newline='') as output_file:
            writer = csv.DictWriter(output_file, fieldnames=fieldnames)
            writer.writeheader()
            # Iterate over each row in the input file
            for row in reader:
                # Check if the specified phrase is in the 'kind' column
                if row['kind'] in phrase:
                    # filter codepeer errors that are only uncategorized. ignore if already annotated.
                    if 'uncategorized' in row['review_kind']:
                        # Write the row to the output file
                        writer.writerow(row)

    print(f"Filtered rows have been written to '{output_filename}'")

def check_and_write_errors(updated_dict, csv_file, output_file, column_name):

    def more_than_one_line_in_file(filename):
        with open(filename, 'r') as file:
            count = 0
            for line in file:
                count += 1
                if count > 1:
                    return True
        return False

    # Open the CSV file using csv.DictReader
    with open(csv_file, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        
        # Open the output CSV file for writing
        with open(output_file, 'w', newline='') as output_csv:
            writer = csv.writer(output_csv)
            # Write the header row
            writer.writerow(reader.fieldnames)
            
            # Iterate over the rows in the CSV file
            for row in reader:
                file_name = row[column_name]
                line_numbers = [int(num) for num in row['line'].split(',')] if row['line'] else []
                
                # Check if the file_name exists in the updated_dict
                if file_name in updated_dict:
                    # Get the line numbers associated with the file_name
                    updated_line_numbers = updated_dict[file_name]
                    
                    # Iterate over the line_numbers
                    for line_number in line_numbers:
                        # Check if the line_number exists in the updated line numbers
                        if line_number in updated_line_numbers:
                            # Write the row to the output CSV file
                            writer.writerow([row[field] for field in reader.fieldnames])
    
    # Deliver the job verdict based on generated report
    if not more_than_one_line_in_file(output_file):
        rbc_common.print_success("codepeer_checker.py: NO ERRORS FOUND")
        os.remove(output_file)
        raise SystemExit(0)
    else:
        rbc_common.print_warning(
            f"Please check artifacts located in {os.path.dirname(__file__)}."
        )
        rbc_common.print_warning("CodePeer ERRORS detected in the changes made!")

def generate_codepeer_report():
    codepeer_command = (
        "gnatsas analyze -P" 
        + project_file_path 
        #+ " --mode=deep --progress-bar=gnat-studio --no-gnat --inspector --messages normal"
        + " --mode=deep --progress-bar=gnat-studio --no-gnat --inspector"
    )                  
    ReturnValue = os.system(codepeer_command)
    if ReturnValue > 0:
        print("Error during execution of Command:", codepeer_command)
        print("Exit code:", ReturnValue)
        print ("Refer for error information: https://docs.adacore.com/live/wave/gnatsas/html/user_guide/cli_reference.html#exit-status")
        raise SystemExit(1)
    
    report_generation_command = (
        "gnatsas report csv -P" 
        + project_file_path 
        +" -o codepeer.csv"
    )
    ReturnValue = os.system(report_generation_command)
    if ReturnValue > 0:
        print("Error during execution of Command:", report_generation_command)
        print("Exit code:", ReturnValue)
        print ("Refer for error information: https://docs.adacore.com/live/wave/gnatsas/html/user_guide/cli_reference.html#exit-status")
        raise SystemExit(1)
    elif ReturnValue == 0:
        if not os.path.exists("codepeer.csv"):
            print("Unknown error during execution of Command: report not generated", report_generation_command)
            raise SystemExit(1)

def is_file_in_git_repo(file_path):
    """
    Checks if a file is tracked in the current Git repository.
    """
    try:
        git_check_command = f"git ls-files --error-unmatch {file_path}"
        subprocess.check_output(git_check_command.split())
        return True
    except subprocess.CalledProcessError:
        # File is outside the repository
        return False

def get_author_email(file_path, line_number):
    # Check if the file is within the repository
    if not is_file_in_git_repo(file_path):
        print(f"Warning: {file_path} is outside the repository.")
        return None

    git_blame_command = f"git blame -e -L {line_number},{line_number} {file_path}"
    print("# " + git_blame_command)
    try:
        output = subprocess.check_output(git_blame_command.split()).decode('utf-8').strip()
        author_email = output.split('<')[1].split('>')[0]
        return author_email
    except subprocess.CalledProcessError:
        print("Error during execution of GIT blame command")
        return None

def normalize_file_path(relative_path):
    """
    Converts the relative path in the CSV to an absolute path
    by stripping the '../../' and prepending the base directory (rbc_root_dir).
    """
    # Remove leading "../../" and prepend the rbc_root_dir
    stripped_path = relative_path.lstrip("../")
    absolute_path = os.path.join(rbc_root_dir, stripped_path)
    return os.path.normpath(absolute_path)

def check_and_write_errors_with_author(input_csv, output_csv):
    if not os.path.exists(input_csv):
        rbc_common.fail(f"Input CSV file '{input_csv}' does not exist.")

    with open(input_csv, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ['author_email']

        with open(output_csv, 'w', newline='') as output_csvfile:
            writer = csv.DictWriter(output_csvfile, fieldnames=fieldnames)
            writer.writeheader()
            os.chdir(rbc_root_dir)

            for row in reader:
                print(row['path'])
                
                # Convert the relative path to an absolute path
                file_path = normalize_file_path(row['path'])
                line_number = row['line']

                # Get author email or skip if the file is outside the repository
                author_email = get_author_email(file_path, line_number)
                row['author_email'] = author_email

                if author_email and author_email not in author_emails_list:
                    author_emails_list.append(author_email)
                writer.writerow(row)

                print(f"Processed: {file_path} lines {line_number}-{line_number} author_email: {author_email}")

    os.chdir(local_base_path)


def send_emails_to_identified_authors():

    """
    For Gmail host = 'smtp.gmail.com', port = 587
    For Yahoo host = 'smtp.mail.yahoo.com', port = 465 or port = 587
    For Outlook host = 'smtp-mail.outlook.com', port = 587
    """

    # host = 'smtp-mail.outlook.com'
    # port = 587

    # user = "mvsrinivasreddy@outlook.com"
    # password = "seenu450microsoft"
    # receivers = ", ".join(author_emails_list)
    # print (receivers)
    # subject = "Codepeer errors detected in your code changes. Please review"
    # body = """
    # Codepeer errors detected in your code changes. Please review the generated codepeer report and take necessary actions to resolve the issues.

    # Thanks!
    # """

    # message = f"""From: <{user}>
    # To: <{receivers}>
    # Subject: {subject}

    # {body}
    # """

    # #create smtp object for connection with the server
    # #connect to gmail's SMTP server with the port provided by google
    # conn = smtplib.SMTP(host, port)

    # #identify yourself to ESMPT server
    # conn.ehlo()

    # #For Security purpose
    # conn.starttls()
    # conn.ehlo()

    # #Login to the server
    # conn.login(user, password)
    # #print(conn.verify(receiver))

    # #Send Message
    # conn.sendmail(user, receivers, message)

    # #Close or Terminate the connection from the server
    # conn.quit()

    SMTP_SERVER = "smtp-mail.outlook.com"
    PORT = 587
    EMAIL = ("mvsrinivasreddy@outlook.com")
    PASSWORD = ("seenu450microsoft")

    subject = "CodePeer Checker Error Report"
    body = """
    Hello there,

    Please find the attached codepeer error report. Check the reported errors against your name and take necessary actions to resolve the issues. 

    Thanks!
    """
    receiver_email = ", ".join(author_emails_list)

    message = MIMEMultipart()
    message["From"] = EMAIL
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    filename = "codepeer_errors_with_author.csv"

    with open(filename, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())

    encoders.encode_base64(part)

    part.add_header(
        "Content-Disposition",
        f"attachment; filename= {filename}",
    )

    message.attach(part)
    text = message.as_string()

    #context = ssl.create_default_context()
    #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    with smtplib.SMTP(SMTP_SERVER, PORT) as server:
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, author_emails_list, text)

###########################
# Main Program
###########################
if __name__ == "__main__":
    
    # read command line arguments and validte inputs.
    commits=[]
    if not read_inputs_and_validate(commits):
        print("Invalid commits provided. Exiting...")
        SystemExit(1)
    # Generate git diff command
    git_diff_command = generate_git_diff_command(commits[0], commits[1], path_filter= path_filter, output_path=diff_path)
    print(git_diff_command)
    os.chdir(rbc_root_dir)

    # Clean up
    # rbc_common.clean_residues()
    
    # checkout the recent commit from the 2 commits so that the git diff linenumbers match
    # and git blame identifies the right authors
    return_code = os.system("git checkout " + commits[1])
    if return_code != 0:
        print("Error in checking out the commit!")
        raise SystemExit(1)

    # Run git diff command to extract the changes made between the two commits
    return_code = os.system(git_diff_command)
    if return_code != 0:
        print("Error in executing git diff command!")
        raise SystemExit(1)
    os.chdir(local_base_path)

    # Parse the git diff output to extract changed files and linenumbers
    changes_dict = rbc_common.parse_diff(diff_path)
    generate_codepeer_report()
    #print(changes_dict)
    updated_dict = trim_file_path_in_dict_keys(changes_dict)
    print(updated_dict)
    filter_csv_by_phrase('codepeer.csv', 'codepeer_filtered.csv', errors_list_to_filter)
    check_and_write_errors(updated_dict,'codepeer_filtered.csv','codepeer_errors.csv','basename')
    check_and_write_errors_with_author(input_csv, output_csv)
    print ("Emails will be sent to: ")
    print ( author_emails_list)
    send_emails_to_identified_authors()
