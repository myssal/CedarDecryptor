import sys
from pathlib import Path
import typer
from decryptor import Decryptor

app = typer.Typer(help="Decrypt all packages in the given folder")

@app.command()
def main(input_folder: str = typer.Argument(..., help="Path to yoo folder")):

    folder_path = Path(input_folder)
    if not folder_path.is_dir():
        typer.echo(f"Error: '{input_folder}' is not a valid folder.\n")
        typer.echo("Usage: python main.py <input_folder>")
        raise typer.Exit(code=1)

    decryptor1 = Decryptor(str(folder_path))
    decryptor1.process_packages()

if __name__ == "__main__":
    app()