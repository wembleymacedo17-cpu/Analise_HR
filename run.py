import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    # use_reloader=False impede o watchdog de reiniciar o Flask ao tocar nos arquivos do .venv
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=True,
        use_reloader=False,
    )