steps to implement and start streamlit:-
    - Create a Virtual Environment (here venv created); Command : cmd - python -m venv venv;  PowerShell - py -m venv venv;

    - To Activate the Virtual Environment created; Command : cmd - venv\Scripts\activate.bat ;  Already Created venv - venv\Scripts\activate ;  PowerShell - .\venv\Scripts\Activate.ps1; (if 'Activate.ps1' doesn't work in Powershell then run > Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process  )      

    - Install all the required packages; Command : pip install -r requirements.txt
                                                   python.exe -m pip install --upgrade pip
    
    - To Deactivate the Virtual Environment; Command : deactivate

    - Run > python app.py

NOTE : Run Cmd as admin then do the above steps in cmd.

same works for Linux - 