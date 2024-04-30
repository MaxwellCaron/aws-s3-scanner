import json

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion, CompleteEvent
from prompt_toolkit.document import Document
from rich.console import Console
from rich.progress import Progress, BarColumn, TransferSpeedColumn, DownloadColumn
from rich.prompt import Prompt

from main import File

# https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/builder/linpeas_parts/linpeas_base.sh
# ╠ ╣ ═ ╔ ╗ ╚ ╝ ║

console = Console()
BLACKLISTED_EXTENSIONS = [
    "ram", "3gp", "3gpp", "3g2", "3gpp2", "aac", "adts", "loas", "ass", "au",
    "snd", "mp3", "mp2", "opus", "aif", "aifc", "aiff", "ra", "wav", "avif",
    "bmp", "gif", "ief", "jpg", "jpe", "jpeg", "heic", "heif", "png", "svg",
    "tiff", "tif", "ico", "ras", "pnm", "pbm", "pgm", "ppm", "rgb", "xbm",
    "xpm", "xwd", "mp4", "mpeg", "m1v", "mpa", "mpe", "mpg", "mov", "qt",
    "webm", "avi", "movie", "mkv", "exe", "dll",
]
LS_STRING = '[cyan]║[/cyan] {:<11} {:<15} {:<6} {:<4}  {}'


class MyCompleter(Completer):
    def __init__(self, completions: list[str]):
        """
        Initialize the MyCompleter instance.

        :param completions: List of strings to prompt user
        """
        self.completions = completions

    def get_completions(self, document: Document, complete_event: CompleteEvent):
        """
        Generate completion suggestions based on the input document and complete event.

        :param document: Document object
        :param complete_event: Complete object
        """
        word_before_cursor = document.get_word_before_cursor()
        word_before_cursor_lower = word_before_cursor.lower()
        matches = [c for c in self.completions if c.lower().startswith(word_before_cursor_lower)]
        for m in matches:
            yield Completion(m, start_position=-len(word_before_cursor))


def download_prompt(readable_file_names: list[str]) -> list[str] | None:
    """
    Prompts a user asking if they would like to download any readable files in an S3 bucket.
    If the answer is "y", a prompt with auto-completion will appear.

    :param readable_file_names: List of file/folder names to prompt for auto-completion.
    :return: List of user's arguments if any, None otherwise
    """
    download_input = Prompt.ask("\nWould you like to download any of the readable files?", choices=["y", "n"],
                                default="n")

    if download_input == 'y':
        files = prompt("File(s): ", completer=MyCompleter(readable_file_names))
        return files.split()
    else:
        return


def get_progress_bar() -> Progress:
    """
    Creates and returns a stylized progress bar to be used for a file download.

    :return: Stylized progress bar
    """
    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn()
    )

    return progress


def print_title(text: str) -> None:
    title_len = len(text)
    max_title_len = 100
    side_len = int((max_title_len - title_len) / 2)

    left = f'[cyan]{"═" * side_len}╣'
    right = f'[cyan]╠{"═" * side_len}'

    top = f'[cyan]{" " * (len(left) - 7)}╔{"═" * (len(text) + 2)}╗\n'
    bottom = f'\n[cyan]{" " * (len(left) - 7)}╚{"═" * (len(text) + 2)}╝'

    console.print(f'\n{top}{left} [bold green]{text}[/bold green] {right}{bottom}')


def print_title1(text: str) -> None:
    console.print(f'\n[cyan]╔══════════╣ [bold magenta]{text}')


def print_title2(text: str) -> None:
    console.print(f'[cyan]║\n╠═════╣ [yellow]{text}')


def print_title3(text: str) -> None:
    console.print(f'[cyan]║\n╠══╣ [grey62]{text}')


def print_info(text: str, border: bool = True) -> None:
    console.print(f'[cyan]║\n║ [yellow][+] [green]{text}' if border else f'\n[yellow][+] [green]{text}')


def print_data(text: str | dict) -> None:
    data = (f'[cyan]║[/cyan] ' + str(json.dumps(text, indent=4, default=str))).split('\n')
    data_bordered: str = f'\n[cyan]║[/cyan] '.join(data)
    console.print(data_bordered, highlight=False)


def print_error(error: str, border: bool = False) -> None:
    console.print(f'[cyan]║[red] {error}' if border else f'[red]{error}')


def print_file_headers() -> None:
    console.print(LS_STRING.format("Size", "Last Modified", "Type", "Read", "File Name"))


def print_file(file: File) -> None:
    console.print(LS_STRING.
                  format(file.size,
                         file.last_modified,
                         file.type,
                         file.is_readable,
                         file.name),
                  highlight=False
                  )


if __name__ == '__main__':
    pass
