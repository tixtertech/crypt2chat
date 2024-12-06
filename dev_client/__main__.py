import argparse
import os

from dotenv import load_dotenv
from tabulate import tabulate

load_dotenv()
import sys
import urllib3
from colorama import Fore, Style
from dev_client.users import *
from dev_client.auth import *
from dev_client.messages import *

API_URL = os.getenv("API_URL")
ssl_verification = False if os.getenv("VERIFY_CERT") == "false" else True

if not ssl_verification:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def validate_arguments(namespace, *args):
    missing = [arg for arg in args if getattr(namespace, arg, None) is None]
    if missing:
        raise ValueError(f"The following arguments are missing: {', '.join(missing)}")


def sys_exit():
    print()
    input("Press enter to exit...")
    sys.exit()

def server_check():
    try:
        # Send request to server
        response = requests.get(f"{API_URL}/ping", verify=ssl_verification, timeout=10)

        # Check response
        if response.status_code == 200:
            print(Fore.GREEN + str(response.text) + Style.RESET_ALL)
        else:
            print(Fore.RED + str(response.text) + Style.RESET_ALL)
            sys_exit()

    except requests.Timeout:
        print(Fore.RED + "Server request timed out..." + Style.RESET_ALL)
        sys_exit()

    except requests.RequestException as e:
        print(Fore.RED + f"The server is currently unreachable..." + Style.RESET_ALL)
        sys_exit()

    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
        sys_exit()



if __name__ == "__main__":
    server_check()
    print()
    username = input("username: ")
    if username == "":
        print(Fore.YELLOW + "Operation canceled..." + Style.RESET_ALL)
        sys_exit()

    while True:
        password = input("password: ").encode()

        if password == b"":
            print(Fore.YELLOW + "Operation canceled..." + Style.RESET_ALL)
            sys_exit()
        try:
            diffie_helman = DiffieHelman(password=password, db_path=f"{os.getenv("CLIENT_DATABASES")}/{username}_keys.db")
            break
        except DiffieHelman.InvalidPasswordError:
            print(Fore.RED + "Wrong password... Try again." + Style.RESET_ALL + "\n")

    try:
        user_infos = get_user_infos(username=username)
        user_id = user_infos.get("user_id")
    except:
        user_id = register(username, diffie_helman)
    token = Token(user_id=user_id, diffie_helman=diffie_helman)
    messages = FinalMessages(b"",f"{os.getenv("CLIENT_DATABASES")}/{username}_messages.db")
    put_spk(token, user_id, diffie_helman)
    print()

    parser = argparse.ArgumentParser(description="Crypt2chat client for developers.")

    subparsers = parser.add_subparsers(dest="command", help="Available commands.")

    # Command to stop the client
    parser_exit = subparsers.add_parser("exit", help="Stop the client.")

    # Command to delete the current user's account
    parser_delete_acc = subparsers.add_parser("delete_acc", help="Delete the current user's account.")
    parser_delete_acc.add_argument("-y", "--yes", action="store_true", help="Confirm account deletion.")

    # Command to change the current user's username
    parser_change_usrn = subparsers.add_parser("change_usrn", help="Change the current user's username.")
    parser_change_usrn.add_argument("-usrn", "--username", type=str, required=True, help="New username.")
    parser_change_usrn.add_argument("-y", "--yes", action="store_true", help="Confirm username change.")

    # Command to send new pre-stored keys to the server
    parser_spk = subparsers.add_parser("put_spk", help="Send new pre-stored keys to the server.")

    # Command to retrieve all information about the current token
    parser_me = subparsers.add_parser("token", help="Retrieve information about the current token.")

    # Command to revoke the last token
    parser_revoke = subparsers.add_parser("revoke", help="Revoke the last token.")

    # Command to retrieve public information about a specific Crypt2chat user
    parser_user = subparsers.add_parser("user", help="Retrieve public information about a Crypt2chat user.")
    parser_user.add_argument("--id", type=str, help="Specify the user's ID.")
    parser_user.add_argument("--name", type=str, help="Specify the user's name.")

    # Command to retrieve the Crypt2chat users database
    parser_users = subparsers.add_parser("users", help="Retrieve the Crypt2chat user database.")
    parser_users.add_argument("--search", type=str, help="Search for specific users.")
    parser_users.add_argument("--since", type=str, help="Filter users created since a specified date.")
    parser_users.add_argument("--limit", type=int, help="Limit the number of users retrieved.")

    # Command to manage conversations
    parser_conv = subparsers.add_parser("conv", help="Manage conversations.")
    parser_conv.add_argument("--new", action="store_true", help="Create of the conversation")
    parser_conv.add_argument("--name", help="Name of the conversation")
    parser_conv.add_argument("-m", "--members", help="Add users by their IDs (format: id1;id2;...).")
    parser_conv.add_argument("-id", help="ID of the conversation.")
    parser_conv.add_argument("-p", "--print", help="Print all conversations or details of the conversation specified by the ID.")
    parser_conv.add_argument("-u", "--update", help="Update the parameters of a conversation.")
    parser_conv.add_argument("-e", "--exclude", help="Exclude users by their IDs (format: id1;id2;...).")
    parser_conv.add_argument("-a", "--add", help="Add users by their IDs (format: id1;id2;...).")
    parser_conv.add_argument("-rn", "--rename", action="store_true", help="Rename the specified conversation.")
    parser_conv.add_argument("-d", "--delete", action="store_true", help="Delete the conversation specified by the ID.")

    # Command to send a message
    parser_msg = subparsers.add_parser("msg", help="Send a message.")
    parser_msg.add_argument("-cid", "--conv_id", help="ID of the conversation.")
    parser_msg.add_argument("-c", "--content", type=str, help="Content of the message.")
    parser_msg.add_argument("-cf", "--content_file", type=str, help="File containing the message content.")

    while True:
        print()
        command = input(Fore.CYAN + user_id + Fore.RED + " $ " + Style.RESET_ALL)

        args_list = command.split()

        try:
            args = parser.parse_args(args_list)

            match args.command:

                case "exit":
                    break

                case "delete_acc":
                    if not args.yes:
                        if not input(Fore.RED + "This will delete your account. Are you sure you want to continue ? [y/n]: " + Style.RESET_ALL) == "y":
                            raise ValueError("Operation canceled...")

                    delete_account(token)
                    diffie_helman.destroy()
                    messages.destroy()
                    print(Fore.GREEN + "Success..." + Style.RESET_ALL)
                    break

                case "change_usrn":
                    raise NotImplementedError

                case "put_spk":
                    put_spk(token, user_id=user_id, diffie_helman=diffie_helman)
                    print(Fore.GREEN + "Success..." + Style.RESET_ALL)

                case "token":
                    print(token_info(token))

                case "user":
                    if args.id:
                        result = get_user_infos(user_id=args.id)
                    elif args.name:
                        result = get_user_infos(username=args.name)
                    else:
                        raise ValueError("specify an id or name")
                    for k, v in result.items():
                        print(Fore.YELLOW + k + Style.RESET_ALL + "\t" + v)

                case "users":
                    results = get_user(args.search, args.since, args.limit)
                    headers = ["user_id", "user_name", "authentication_key", "identity_key", "identity_sig", "since"]
                    print(f"{len(results)} result" if len(results) == 1 else f"{len(results)} results")
                    print(tabulate(results, headers=headers))

                case "conv":
                    if args.print:
                        if args.id:
                            print(messages.get_conversation_messages(args.id))
                        else:
                            print(messages.get_all())

                    elif args.new:
                        validate_arguments(args, 'name', 'members')
                        messages.add_conversation(args.name, args.members.split(";"), token)

                    elif args.delete:
                        validate_arguments(args, 'id')
                        if not input(Fore.RED + "This will delete this conversation. Are you sure you want to continue ? [y/n]: " + Style.RESET_ALL) == "y":
                            raise ValueError("Operation canceled...")
                        messages.delete_conversation(args.id, token)

                    elif args.add:
                        messages.add_members(args.id, args.add.split(";"), token)

                    elif args.exclude:
                        messages.exclude_members(args.id, args.exclude.split(";"), token)



        except SystemExit:
            time.sleep(0.5)

        except Exception as e:
            traceback.print_exc()

    sys_exit()