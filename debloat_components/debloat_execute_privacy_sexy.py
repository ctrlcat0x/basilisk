"""
Privacy.sexy Script Execution
Executes the privacy.sexy PowerShell script for enhanced privacy and security
"""

import os
import subprocess
from utilities.util_logger import logger
from utilities.util_powershell_handler import run_powershell_command
import tempfile


def main():
    """Execute the privacy.sexy script for comprehensive privacy and security hardening."""
    try:
        logger.info("Starting privacy.sexy script execution...")
        
        # Get the script path
        script_path = os.path.join(tempfile.gettempdir(), "basilisk", "privacy_sexy.ps1")
        
        if not os.path.exists(script_path):
            logger.error(f"privacy.sexy script not found at: {script_path}")
            return False
        
        logger.info(f"Executing privacy.sexy script: {script_path}")
        
        # Execute the privacy.sexy script
        # The script is designed to be run with elevated privileges
        command = f'powershell -ExecutionPolicy Bypass -File "{script_path}"'
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("privacy.sexy script executed successfully")
                logger.debug(f"Script output: {result.stdout}")
                return True
            else:
                logger.warning(f"privacy.sexy script completed with warnings (return code: {result.returncode})")
                logger.debug(f"Script output: {result.stdout}")
                logger.debug(f"Script errors: {result.stderr}")
                return True  # Still return True as some warnings are expected
                
        except subprocess.TimeoutExpired:
            logger.error("privacy.sexy script execution timed out after 10 minutes")
            return False
        except Exception as e:
            logger.error(f"Error executing privacy.sexy script: {e}")
            return False
            
    except Exception as e:
        logger.error(f"Error in privacy.sexy execution: {e}")
        return False


if __name__ == "__main__":
    main() 