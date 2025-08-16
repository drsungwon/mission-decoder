# ==============================================================================
# Encrypted Log Decryption Utility (v2.2 - Final)
# ------------------------------------------------------------------------------
# [프로그램 설명]
#   이 스크립트는 'mission-python' 프로젝트의 'utility.py'에 의해 생성된
#   암호화된 로그 파일(`log.encrypted`, `signature.encrypted` 등)을 복호화하는
#   교수/관리자용 도구입니다.
#
# [사용 방법]
#   명령줄에서 아래 형식으로 실행합니다. --help 플래그로 상세한 도움말을 볼 수 있습니다.
#   poetry run python -m mission_decoder.main [입력 파일] [개인키] [출력 파일]
#
# [예시]
#   poetry run python -m mission_decoder.main ./log.encrypted ./keys/private_key.pem ./log.decrypted.txt
#
# ==============================================================================


# --- 1. 필수 모듈 임포트 ---

import sys
import struct

# `argparse`: 명령줄 인자를 파싱하고, 도움말 메시지를 자동으로 생성하는 강력한 표준 라이브러리.
import argparse
# `pathlib.Path`: 파일 시스템 경로를 문자열이 아닌 객체로 다루어, 더 안전하고 직관적인 코드 작성을 돕는 표준 라이브러리.
from pathlib import Path

# --- `cryptography` 라이브러리 임포트 ---
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
# `RSAPrivateKey`: `private_key` 객체의 타입을 명확히 지정하기 위한 클래스. 코드의 가독성과 정적 분석에 도움을 줍니다.
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding as aes_padding

# --- 2. 상수 정의 ---
# 이 값들은 암호화를 수행한 'crypto.py'의 상수 값과 반드시 일치해야 복호화가 가능합니다.

AES_KEY_SIZE = 32           # AES-256 사용 (32 바이트)
AES_IV_SIZE = 16            # AES 블록 크기와 동일한 16 바이트 IV(Initialization Vector)
RSA_ENCRYPTED_KEY_SIZE = 256  # 2048비트 RSA 공개키로 암호화된 세션키의 크기 (2048 bits / 8 = 256 bytes)


# --- 3. 핵심 기능 함수 ---

def print_status(tag: str, message: str, is_error: bool = False):
    """
    Cargo 스타일의 상태 메시지를 출력하는 헬퍼 함수입니다.
    출력 포맷을 일관되게 유지하고, 에러 메시지를 별도로 관리합니다.
    """
    # 태그를 항상 9자리 너비로 만들고, 텍스트를 중앙에 정렬하여 시각적 통일성을 줍니다.
    # 예: '[  INFO   ]', '[  ERROR  ]', '[ SUCCESS ]'
    formatted_tag = f"[{tag.upper():^9}]"
    
    # 에러 메시지는 표준 에러 스트림(sys.stderr)으로, 일반 메시지는 표준 출력 스트림(sys.stdout)으로 보냅니다.
    # 이는 출력 리디렉션 시 오류와 일반 로그를 분리할 수 있게 해줍니다.
    stream = sys.stderr if is_error else sys.stdout
    print(f"{formatted_tag} {message}", file=stream)


def decrypt_chunk(rsa_encrypted_key: bytes, aes_encrypted_data: bytes, private_key: RSAPrivateKey) -> bytes | None:
    """
    하나의 암호화된 청크(chunk)를 받아 복호화합니다.
    이 함수는 하이브리드 암호화 과정의 정확한 역순으로 동작합니다.
    """
    try:
        # --- 1단계: RSA 개인키로 세션키(AES key + IV) 복호화 ---
        # 암호화 시 사용했던 `OAEP` 패딩 스킴과 동일한 설정을 사용해야 정확히 복호화됩니다.
        decrypted_session_key = private_key.decrypt(
            rsa_encrypted_key,
            rsa_padding.OAEP( mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None )
        )
        
        # --- 안전장치: 복호화된 세션키 길이 검증 ---
        expected_len = AES_KEY_SIZE + AES_IV_SIZE
        if len(decrypted_session_key) != expected_len:
             print_status("error", f"복호화된 세션키 길이가 올바르지 않습니다 (예상: {expected_len}, 실제: {len(decrypted_session_key)})", is_error=True)
             return None
        
        # --- 2단계: 복호화된 세션키를 AES 키와 IV로 분리 ---
        aes_key = decrypted_session_key[:AES_KEY_SIZE]
        iv = decrypted_session_key[AES_KEY_SIZE:] # AES_KEY_SIZE부터 끝까지
        
        # --- 3단계: AES 키와 IV를 사용하여 실제 데이터 복호화 ---
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(aes_encrypted_data) + decryptor.finalize()
        
        # --- 4단계: 복호화된 데이터에서 PKCS7 패딩 제거 ---
        # AES는 블록 단위 암호화이므로, 암호화 시 추가했던 패딩을 제거해야 원본 데이터를 얻을 수 있습니다.
        unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()
        return original_data
        
    except Exception as e:
        # 복호화 과정에서 발생하는 모든 예외(패딩 오류, 키 불일치 등)를 처리합니다.
        print_status("crypto", f"데이터 복호화 중 오류 발생: {e}", is_error=True)
        return None

def decrypt_and_save_log(encrypted_file: Path, private_key_file: Path, output_file: Path):
    """
    전체 복호화 프로세스를 총괄하는 메인 실행 함수입니다.
    암호화된 파일을 청크 단위로 읽고 복호화하여 최종 결과 파일에 저장합니다.
    """
    print_status("info", "암호화된 로그 복호화 프로세스를 시작합니다...")
    # `.resolve()`: 심볼릭 링크 등을 모두 해석한 '정규화된 절대 경로'를 반환하여, 경로를 명확하게 보여줍니다.
    print(f"{'':11}  - 입력 파일: {encrypted_file.resolve()}")
    print(f"{'':11}  - 개인키:    {private_key_file.resolve()}")
    print(f"{'':11}  - 출력 파일: {output_file.resolve()}\n")

    # --- 개인키 파일 로딩 ---
    print_status("step 1", f"개인키 파일 '{private_key_file.name}'을(를) 로딩합니다...")
    # `.exists()`: Path 객체를 사용하여 파일의 존재 여부를 간결하게 확인합니다.
    if not private_key_file.exists():
        print_status("error", f"개인키 파일을 찾을 수 없습니다: {private_key_file}", is_error=True)
        return

    try:
        # `.read_bytes()`: pathlib의 메서드로, 파일을 열고 바이너리 내용을 읽는 과정을 한 줄로 처리합니다.
        private_key = serialization.load_pem_private_key(private_key_file.read_bytes(), password=None)
        print_status("ok", "개인키 로딩 성공.")
    except Exception as e:
        print_status("error", f"개인키 파일을 읽는 중 문제가 발생했습니다: {e}", is_error=True)
        return

    # --- 로그 파일 처리 (읽기 -> 복호화 -> 병합) ---
    full_decrypted_log_bytes = b''  # 복호화된 모든 청크를 메모리에 순서대로 담을 바이트 버퍼
    chunk_count = 0
    
    print_status("step 2", f"'{encrypted_file.name}' 파일 처리를 시작합니다...")
    if not encrypted_file.exists():
        print_status("error", f"암호화된 로그 파일을 찾을 수 없습니다: {encrypted_file}", is_error=True)
        return

    try:
        # 암호화된 파일을 바이너리 읽기('rb') 모드로 엽니다.
        with open(encrypted_file, 'rb') as f:
            while True:
                # 1. RSA 블록(암호화된 세션키) 읽기
                rsa_block = f.read(RSA_ENCRYPTED_KEY_SIZE)
                if not rsa_block:  # `f.read()`는 파일의 끝에 도달하면 빈 바이트(b'')를 반환합니다.
                    break

                # 2. 데이터 길이 정보 읽기
                len_block = f.read(4)
                if len(len_block) < 4:
                    print_status("error", f"청크 #{chunk_count + 1}의 데이터 길이 정보가 손상되었습니다.", is_error=True)
                    return
                
                # `struct.unpack`: 4바이트의 바이너리 데이터를 파이썬 정수형으로 변환. '>I'는 '빅엔디안 부호 없는 4바이트 정수' 포맷.
                aes_data_len = struct.unpack('>I', len_block)[0]
                
                # 3. AES 블록(실제 암호화된 데이터) 읽기
                aes_block = f.read(aes_data_len)
                if len(aes_block) != aes_data_len: # 읽어온 데이터가 예상 길이보다 짧으면 파일이 손상된 것.
                    print_status("error", f"청크 #{chunk_count + 1}의 데이터가 불완전합니다. (예상: {aes_data_len}, 실제: {len(aes_block)})", is_error=True)
                    return
                
                chunk_count += 1
                print_status("...", f"청크 #{chunk_count} 복호화 중...")
                decrypted_chunk = decrypt_chunk(rsa_block, aes_block, private_key)
                
                if decrypted_chunk is None: # 청크 복호화에 실패하면 전체 프로세스를 중단.
                    print_status("error", f"로그 청크 #{chunk_count} 복호화에 실패했습니다. 프로세스를 중단합니다.", is_error=True)
                    return
                
                full_decrypted_log_bytes += decrypted_chunk
        
        # --- 결과 저장 ---
        if chunk_count > 0:
            print_status("step 3", f"'{output_file.name}' 파일에 결과를 저장합니다...")
            # `output_file.parent`: 파일 경로에서 디렉토리 부분만 나타내는 Path 객체 (e.g., /path/to/dir/)
            # `.mkdir(parents=True, exist_ok=True)`: 중간 경로의 모든 부모 디렉토리를 생성하며, 이미 존재해도 오류를 발생시키지 않음.
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # `.write_bytes()`: pathlib의 메서드로, 바이너리 데이터를 파일에 쓰는 과정을 한 줄로 안전하게 처리합니다.
            output_file.write_bytes(full_decrypted_log_bytes)
            
            print_status("success", f"총 {chunk_count}개의 청크를 성공적으로 복호화했습니다.")
        else:
            print_status("info", "암호화된 데이터가 없어 복호화를 진행하지 않았습니다.")

    except Exception as e:
        print_status("error", f"로그 파일 처리 중 예상치 못한 오류가 발생했습니다: {e}", is_error=True)


# --- 4. 프로그램 진입점 및 CLI 구성 ---
if __name__ == "__main__":
    # `ArgumentParser` 객체 생성. CLI 프로그램의 기본 정보를 설정합니다.
    parser = argparse.ArgumentParser(
        prog="mission-decoder",
        description="`mission-python` 프로젝트의 암호화된 로그 파일을 복호화합니다.",
        # `epilog`: 도움말 메시지의 맨 마지막에 표시될 텍스트. 주로 사용 예시를 보여주는 데 사용됩니다.
        epilog="사용 예시: poetry run python -m mission_decoder.main log.encrypted keys/private_key.pem log.decrypted.txt",
        formatter_class=argparse.RawTextHelpFormatter # 도움말 포맷을 좀 더 깔끔하게 유지합니다.
    )
    
    # 3개의 '위치 기반(positional)' 인자를 정의합니다. 사용자는 이 인자들을 순서대로 반드시 제공해야 합니다.
    # `type=Path`: argparse가 입력받은 문자열 경로를 자동으로 `pathlib.Path` 객체로 변환해줍니다.
    # `help`: `--help` 옵션을 사용했을 때 각 인자에 대해 보여줄 설명.
    parser.add_argument("input_file", type=Path, help="복호화할 암호화된 파일 경로")
    parser.add_argument("key_file", type=Path, help="복호화에 사용할 개인키 파일 경로")
    parser.add_argument("output_file", type=Path, help="복호화된 내용이 저장될 파일 경로")

    # `parser.parse_args()`: `sys.argv`를 분석하여 정의된 규칙에 맞게 인자를 파싱합니다.
    # 인자가 규칙에 맞지 않으면, argparse는 자동으로 오류 메시지와 함께 사용법을 출력하고 프로그램을 종료합니다.
    args = parser.parse_args()

    # 파싱이 성공적으로 완료되면, `args` 객체에 `input_file`, `key_file` 등의 속성으로 인자가 저장됩니다.
    # 이 인자들을 사용하여 메인 함수를 호출하고 복호화 프로세스를 시작합니다.
    decrypt_and_save_log(args.input_file, args.key_file, args.output_file)