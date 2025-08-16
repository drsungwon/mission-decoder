# ==============================================================================
# Encrypted Log Decryption Utility (v2.0)
# ------------------------------------------------------------------------------
# [프로그램 설명]
# 이 스크립트는 'mission-python' 프로젝트의 'utility.py'에 의해 생성된
# 암호화된 로그 파일(`log.encrypted`, `signature.encrypted` 등)을 복호화하는
# 교수/관리자용 도구입니다.
#
# 파일은 여러 개의 '청크(chunk)'가 연이어 붙어있는 형태로 구성되어 있습니다.
# 각 청크는 [암호화된 세션키][데이터 길이][암호화된 데이터] 구조를 가집니다.
# 이 스크립트는 파일을 순차적으로 읽으며 각 청크를 복호화하고, 이를 하나로 합쳐
# 최종 평문 텍스트 파일을 생성합니다.
#
# [사전 준비]
#   - Python 3.9+
#   - Poetry (의존성 관리 도구)
#   - 복호화를 위한 RSA 개인키 파일 (예: 'private_key.pem')
#
# [설치]
#   poetry install
#
# [사용 방법]
#   명령줄에서 아래 형식으로 실행합니다.
#   poetry run python -m mission_decoder.main [입력 파일] [개인키] [출력 파일]
#
# [예시]
#   poetry run python -m mission_decoder.main ./log.encrypted ./private_key.pem ./log.decrypted.txt
#
# ==============================================================================


# --- 1. 필수 모듈 임포트 ---

import sys
import os
import struct  # 바이너리 데이터를 다루기 위한 모듈 (데이터 길이를 바이트로 변환)
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding as aes_padding

# --- 2. 상수 정의 ---
# 이 값들은 암호화를 수행한 `crypto.py`의 값과 반드시 일치해야 합니다.

AES_KEY_SIZE = 32           # AES-256 사용 (32 바이트)
AES_IV_SIZE = 16            # AES 블록 크기와 동일한 16 바이트 IV
RSA_ENCRYPTED_KEY_SIZE = 256  # 2048비트 RSA 공개키로 암호화된 세션키의 크기 (2048 / 8)


# --- 3. 핵심 기능 함수 ---

def print_status(tag, message, is_error=False):
    """Cargo 스타일의 상태 메시지를 출력하는 헬퍼 함수입니다."""
    # 태그를 항상 9자리로 고정하고 중앙 정렬하여 출력 포맷을 맞춥니다.
    # 예: [  INFO   ], [  ERROR  ], [ SUCCESS ]
    formatted_tag = f"[{tag.upper():^9}]"
    
    # 에러 메시지는 표준 에러(stderr)로, 일반 메시지는 표준 출력(stdout)으로 보냅니다.
    stream = sys.stderr if is_error else sys.stdout
    print(f"{formatted_tag} {message}", file=stream)


def decrypt_chunk(rsa_encrypted_key: bytes, aes_encrypted_data: bytes, private_key) -> bytes | None:
    """
    하나의 암호화된 청크(chunk)를 받아 복호화합니다.
    이 함수는 하이브리드 암호화의 역순으로 동작합니다.

    Args:
        rsa_encrypted_key: RSA로 암호화된 세션키 (AES key + IV)
        aes_encrypted_data: AES로 암호화된 원본 데이터
        private_key: 복호화에 사용할 RSA 개인키 객체

    Returns:
        복호화된 원본 데이터(bytes), 실패 시 None
    """
    try:
        # 1단계: RSA 개인키로 암호화된 세션키(AES key + IV)를 복호화합니다.
        #       암호화 시 사용했던 OAEP 패딩 스킴을 동일하게 지정해야 합니다.
        decrypted_session_key = private_key.decrypt(
            rsa_encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 안전장치: 복호화된 세션키의 길이가 예상과 다른 경우, 오류 처리
        expected_len = AES_KEY_SIZE + AES_IV_SIZE
        if len(decrypted_session_key) != expected_len:
             print_status("error", f"복호화된 세션키의 길이가 올바르지 않습니다 (예상: {expected_len}, 실제: {len(decrypted_session_key)})", is_error=True)
             return None

        # 2단계: 복호화된 세션키를 실제 AES 키와 IV(Initialization Vector)로 분리합니다.
        aes_key = decrypted_session_key[:AES_KEY_SIZE]
        iv = decrypted_session_key[AES_KEY_SIZE:]
        
        # 3단계: 추출된 AES 키와 IV를 사용하여 암호화된 데이터를 복호화합니다.
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(aes_encrypted_data) + decryptor.finalize()
        
        # 4단계: 복호화된 데이터에서 PKCS7 패딩을 제거하여 원본 데이터를 복원합니다.
        #        암호화 시 추가했던 패딩을 제거하는 과정입니다.
        unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()
        return original_data
        
    except Exception as e:
        print_status("crypto", f"데이터 복호화 중 오류 발생: {e}", is_error=True)
        return None

def main(encrypted_log_path: str, private_key_path: str, output_path: str):
    """
    메인 실행 함수: 암호화된 로그 파일을 청크 단위로 읽고 복호화하여 결과 파일에 저장합니다.
    """
    print_status("info", "암호화된 로그 복호화 프로세스를 시작합니다...")
    print(f"{'':11}  - 입력 파일: {os.path.abspath(encrypted_log_path)}")
    print(f"{'':11}  - 개인키:    {os.path.abspath(private_key_path)}")
    print(f"{'':11}  - 출력 파일: {os.path.abspath(output_path)}\n")

    # --- 개인키 로딩 ---
    print_status("step 1", "개인키 파일을 로딩합니다...")
    try:
        # 개인키 파일을 바이너리 읽기('rb') 모드로 엽니다.
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  # 개인키가 암호로 보호되지 않았으므로 None
            )
        print_status("ok", "개인키 로딩 성공.")
    except FileNotFoundError:
        print_status("error", f"개인키 파일 '{private_key_path}'을(를) 찾을 수 없습니다.", is_error=True)
        return
    except Exception as e:
        print_status("error", f"개인키 파일을 읽는 중 문제가 발생했습니다: {e}", is_error=True)
        return

    # --- 로그 파일 처리 ---
    full_decrypted_log_bytes = b''  # 복호화된 모든 청크를 담을 바이트 버퍼
    chunk_count = 0
    
    print_status("step 2", f"'{encrypted_log_path}' 파일 처리를 시작합니다...")
    try:
        # 암호화된 로그 파일을 바이너리 읽기('rb') 모드로 엽니다.
        with open(encrypted_log_path, 'rb') as f:
            while True:
                # 1. 암호화된 세션키 (RSA 블록) 읽기
                rsa_block = f.read(RSA_ENCRYPTED_KEY_SIZE)
                if not rsa_block: # 파일의 끝에 도달하면 루프를 종료합니다.
                    break

                # 2. 데이터 길이 정보 (4바이트) 읽기
                len_block = f.read(4)
                if len(len_block) < 4:
                    print_status("error", f"청크 #{chunk_count + 1}의 데이터 길이 정보를 읽을 수 없습니다. 파일 손상 가능성이 있습니다.", is_error=True)
                    return
                
                # struct.unpack: 4바이트의 바이너리 데이터를 파이썬 정수형으로 변환합니다.
                # '>I'는 '빅엔디안, 부호 없는 4바이트 정수'를 의미합니다.
                aes_data_len = struct.unpack('>I', len_block)[0]
                
                # 3. 실제 암호화된 데이터 (AES 블록) 읽기
                aes_block = f.read(aes_data_len)
                if len(aes_block) != aes_data_len:
                    print_status("error", f"청크 #{chunk_count + 1}의 데이터가 불완전합니다. (예상 길이: {aes_data_len}, 실제 길이: {len(aes_block)})", is_error=True)
                    return
                
                chunk_count += 1
                print_status("...", f"청크 #{chunk_count} 복호화 중...")
                
                # 4. 읽어온 청크를 복호화합니다.
                decrypted_chunk = decrypt_chunk(rsa_block, aes_block, private_key)
                if decrypted_chunk is None:
                    print_status("error", f"로그 청크 #{chunk_count} 복호화에 실패했습니다. 프로세스를 중단합니다.", is_error=True)
                    return
                
                # 5. 복호화된 결과를 버퍼에 추가합니다.
                full_decrypted_log_bytes += decrypted_chunk
        
        # --- 결과 저장 ---
        if chunk_count > 0:
            print_status("step 3", f"'{output_path}' 파일에 결과를 저장합니다...")
            # 출력 경로의 디렉토리가 존재하지 않으면 생성합니다.
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # 복호화된 전체 바이트 데이터를 바이너리 쓰기('wb') 모드로 저장합니다.
            with open(output_path, "wb") as f_out:
                f_out.write(full_decrypted_log_bytes)
            
            print_status("success", f"총 {chunk_count}개의 청크를 성공적으로 복호화했습니다.")
        else:
            print_status("info", "암호화된 데이터가 없어 복호화를 진행하지 않았습니다.")

    except FileNotFoundError:
        print_status("error", f"암호화된 로그 파일 '{encrypted_log_path}'을(를) 찾을 수 없습니다.", is_error=True)
    except Exception as e:
        print_status("error", f"로그 파일 처리 중 예상치 못한 오류가 발생했습니다: {e}", is_error=True)


# --- 4. 프로그램 진입점 ---

# 이 스크립트가 'python main.py'처럼 직접 실행될 때만 아래 코드가 동작합니다.
if __name__ == "__main__":
    # 명령줄 인자의 개수를 확인합니다. (스크립트 이름 + 3개 인자 = 총 4개)
    if len(sys.argv) != 4:
        print("\n[ 사용법 오류 ]")
        print("  명령줄 인자가 올바르지 않습니다.")
        print("  올바른 형식: poetry run python -m mission_decoder.main [입력 파일] [개인키] [출력 파일]")
        print("\n[ 사용법 예시 ]")
        print("  poetry run python -m mission_decoder.main log.encrypted private_key.pem log.decrypted.txt")
        sys.exit(1) # 오류 코드(1)와 함께 프로그램을 종료합니다.

    # 명령줄 인자를 각각 변수에 할당합니다.
    encrypted_path, key_path, decrypted_path = sys.argv[1], sys.argv[2], sys.argv[3]
    # 메인 함수를 호출하여 실제 작업을 시작합니다.
    main(encrypted_path, key_path, decrypted_path)