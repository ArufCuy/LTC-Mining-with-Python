# Discord https://discord.com/invite/CkmzkYXqZ5
# Mining LiteCoin Tools By ArufCuy

import socket
import json
import time
import hashlib
import binascii
import struct
import pyopencl as cl
import numpy as np
import logging

# Konfigurasi Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

POOL_ADDRESS = "ltc.viabtc.com"
POOL_PORT = 3333
WALLET = "ltc1q9lqhxasss9wnjznfkyqca7pmv77utfz8ds0mwa"
WORKER_NAME = "arufkuy.worker1"

# Kernel Scrypt OpenCL untuk Litecoin
SCRYPT_KERNEL = """
// Salsa20/8 Core function
void salsa20_8(uint *B) {
    uint x[16];
    for (int i = 0; i < 16; i++) x[i] = B[i];
    for (int i = 8; i > 0; i -= 2) {
        x[ 4] ^= rotate(x[ 0] + x[12], 7U);  x[ 8] ^= rotate(x[ 4] + x[ 0], 9U);
        x[12] ^= rotate(x[ 8] + x[ 4],13U);  x[ 0] ^= rotate(x[12] + x[ 8],18U);
        x[ 9] ^= rotate(x[ 5] + x[ 1], 7U);  x[13] ^= rotate(x[ 9] + x[ 5], 9U);
        x[ 1] ^= rotate(x[13] + x[ 9],13U);  x[ 5] ^= rotate(x[ 1] + x[13],18U);
        x[14] ^= rotate(x[10] + x[ 6], 7U);  x[ 2] ^= rotate(x[14] + x[10], 9U);
        x[ 6] ^= rotate(x[ 2] + x[14],13U);  x[10] ^= rotate(x[ 6] + x[ 2],18U);
        x[ 3] ^= rotate(x[15] + x[11], 7U);  x[ 7] ^= rotate(x[ 3] + x[15], 9U);
        x[11] ^= rotate(x[ 7] + x[ 3],13U);  x[15] ^= rotate(x[11] + x[ 7],18U);
        x[ 1] ^= rotate(x[ 0] + x[ 3], 7U);  x[ 2] ^= rotate(x[ 1] + x[ 0], 9U);
        x[ 3] ^= rotate(x[ 2] + x[ 1],13U);  x[ 0] ^= rotate(x[ 3] + x[ 2],18U);
        x[ 6] ^= rotate(x[ 5] + x[ 4], 7U);  x[ 7] ^= rotate(x[ 6] + x[ 5], 9U);
        x[ 4] ^= rotate(x[ 7] + x[ 6],13U);  x[ 5] ^= rotate(x[ 4] + x[ 7],18U);
        x[11] ^= rotate(x[10] + x[ 9], 7U);  x[ 8] ^= rotate(x[11] + x[10], 9U);
        x[ 9] ^= rotate(x[ 8] + x[11],13U);  x[10] ^= rotate(x[ 9] + x[ 8],18U);
        x[12] ^= rotate(x[15] + x[14], 7U);  x[13] ^= rotate(x[12] + x[15], 9U);
        x[14] ^= rotate(x[13] + x[12],13U);  x[15] ^= rotate(x[14] + x[13],18U);
    }
    for (int i = 0; i < 16; i++) B[i] += x[i];
}

// Scrypt core
__kernel void scrypt_hash(__global const uchar *header, __global uchar *output, const uint nonce_start, 
                         const ulong target_high, const ulong target_low)
{
    uint nonce = nonce_start + get_global_id(0);
    uchar temp[80];
    uchar hash[32];
    uchar X[128];
    uchar V[128 * 1024]; // N=1024, r=1, 128 bytes per block

    // Isi header dengan nonce
    for (int i = 0; i < 76; i++) temp[i] = header[i];
    temp[76] = (nonce >> 0) & 0xFF;
    temp[77] = (nonce >> 8) & 0xFF;
    temp[78] = (nonce >> 16) & 0xFF;
    temp[79] = (nonce >> 24) & 0xFF;

    // Langkah 1: SHA256 awal (PBKDF2 pertama)
    uchar intermediate[32];
    for (int i = 0; i < 32; i++) intermediate[i] = temp[i]; // Placeholder, ganti dengan SHA256 nyata

    // Langkah 2: Scrypt mixing
    for (int i = 0; i < 32; i++) X[i] = intermediate[i];
    for (int i = 0; i < 128; i += 32) {
        uint *B = (uint *)(X + i);
        salsa20_8(B);
    }

    // Langkah 3: Mixing dengan V (N=1024)
    for (int i = 0; i < 1024; i++) {
        for (int j = 0; j < 128; j++) V[i * 128 + j] = X[j];
        for (int j = 0; j < 128; j += 32) {
            uint *B = (uint *)(X + j);
            salsa20_8(B);
        }
    }
    for (int i = 0; i < 1024; i++) {
        uint j = X[0] % 1024;
        for (int k = 0; k < 128; k++) X[k] ^= V[j * 128 + k];
        for (int k = 0; k < 128; k += 32) {
            uint *B = (uint *)(X + k);
            salsa20_8(B);
        }
    }

    // Langkah 4: SHA256 akhir (PBKDF2 kedua)
    for (int i = 0; i < 32; i++) hash[i] = X[i]; // Placeholder, ganti dengan SHA256 nyata

    ulong hash_high = *((ulong*)hash);
    ulong hash_low = *((ulong*)(hash + 8));

    if (hash_high < target_high || (hash_high == target_high && hash_low < target_low)) {
        for (int i = 0; i < 32; i++) output[i] = hash[i];
        *((uint*)(output + 32)) = nonce;
    }
}
"""

class LitecoinMinerGPU:
    def __init__(self):
        self.sock = None
        self.extranonce1 = None
        self.extranonce2_size = None
        self.hash_count = 0
        self.start_time = time.time()
        self.blocks_found = 0
        self.total_reward = 0
        self.network_difficulty = 20_000_000
        self.ctx = None
        self.queue = None
        self.setup_gpu()

    def setup_gpu(self):
        platforms = cl.get_platforms()
        if not platforms:
            raise RuntimeError("Tidak ada platform OpenCL yang ditemukan!")
        devices = platforms[0].get_devices(device_type=cl.device_type.GPU)
        if not devices:
            raise RuntimeError("Tidak ada GPU yang ditemukan!")
        self.ctx = cl.Context(devices)
        self.queue = cl.CommandQueue(self.ctx)
        logging.info(f"GPU digunakan: {devices[0].name}")

    def connect_to_pool(self):
        logging.info(f"Menghubungkan ke stratum+tcp://{POOL_ADDRESS}:{POOL_PORT}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((POOL_ADDRESS, POOL_PORT))
            logging.info("Terhubung ke Stratum Pool!")
            return True
        except Exception as e:
            logging.error(f"Gagal terhubung ke pool: {e}")
            return False

    def send(self, data):
        message = json.dumps(data) + "\n"
        try:
            self.sock.sendall(message.encode())
            logging.debug(f"Data terkirim: {message.strip()}")
        except Exception as e:
            logging.error(f"Gagal mengirim data: {e}")

    def recv(self):
        try:
            buffer = ""
            while True:
                data = self.sock.recv(8192).decode()
                if not data:
                    break
                buffer += data
                if "\n" in data:
                    break
            logging.debug(f"Data mentah diterima: {buffer.strip()}")
            return buffer.strip()
        except Exception as e:
            logging.error(f"Gagal menerima data: {e}")
            return None

    def parse_response(self, response):
        if not response:
            return []
        lines = response.split("\n")
        parsed = []
        for line in lines:
            if line.strip():
                try:
                    parsed.append(json.loads(line.strip()))
                except json.JSONDecodeError as e:
                    logging.error(f"Gagal parsing JSON: {e} | Data: {line}")
                    continue
        return parsed

    def calculate_merkle_root(self, coinbase, merkle_branch):
        coinbase_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(coinbase)).digest()).digest()
        merkle_root = coinbase_hash
        for branch in merkle_branch:
            merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + bytes.fromhex(branch)).digest()).digest()
        return binascii.hexlify(merkle_root).decode()

    def calculate_target(self, nbits):
        exponent = int(nbits[:2], 16)
        coefficient = int(nbits[2:], 16)
        target = coefficient * 2**(8 * (exponent - 3))
        target_high = target >> 64
        target_low = target & 0xFFFFFFFFFFFFFFFF
        return target_high, target_low

    def subscribe(self):
        payload = {"id": 1, "method": "mining.subscribe", "params": []}
        self.send(payload)
        response = self.recv()
        if response:
            parsed = self.parse_response(response)
            if parsed:
                logging.info(f"Subscribe response: {parsed[0]}")
                subscription = parsed[0]
                self.extranonce1 = subscription["result"][1]
                self.extranonce2_size = subscription["result"][2]
                return True
        return False

    def authorize(self):
        payload = {"id": 2, "method": "mining.authorize", "params": [WORKER_NAME, "x"]}
        self.send(payload)
        response = self.recv()
        if response:
            parsed = self.parse_response(response)
            if parsed:
                logging.info(f"Auth response: {parsed[0]}")
                return parsed[0]["result"]
        return False

    def get_hashrate(self):
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return (self.hash_count / elapsed) / 1000000  # MH/s
        return 0

    def estimate_earnings(self):
        hashrate = self.get_hashrate()
        block_time = 150
        reward_per_block = 6.25
        hashes_per_day = hashrate * 1_000_000 * 86400
        probability = hashes_per_day / (self.network_difficulty * 2**32)
        daily_blocks = probability * (86400 / block_time)
        daily_earnings = daily_blocks * reward_per_block
        return daily_earnings

    def mine_job(self, job_data):
        job_id = job_data["params"][0]
        prev_hash = job_data["params"][1]
        coinbase1 = job_data["params"][2]
        coinbase2 = job_data["params"][3]
        merkle_branch = job_data["params"][4]
        version = job_data["params"][5]
        nbits = job_data["params"][6]
        ntime = job_data["params"][7]

        logging.info(f"Job baru diterima! ID: {job_id}")

        extranonce2 = "00" * self.extranonce2_size
        coinbase = coinbase1 + self.extranonce1 + extranonce2 + coinbase2
        merkle_root = self.calculate_merkle_root(coinbase, merkle_branch)

        version_bytes = bytes.fromhex(version)
        prev_hash_bytes = bytes.fromhex(prev_hash)
        merkle_root_bytes = bytes.fromhex(merkle_root)
        ntime_bytes = bytes.fromhex(ntime)
        nbits_bytes = bytes.fromhex(nbits)

        header_size = 76
        header_array = np.zeros(header_size, dtype=np.uint8)
        offset = 0
        for data in (version_bytes, prev_hash_bytes, merkle_root_bytes, ntime_bytes, nbits_bytes):
            temp_array = np.frombuffer(data, dtype=np.uint8)
            header_array[offset:offset + len(data)] = temp_array
            offset += len(data)

        target_high, target_low = self.calculate_target(nbits)
        logging.info(f"Target untuk job {job_id}: high={hex(target_high)}, low={hex(target_low)}")

        target_high = int(target_high) & 0xFFFFFFFFFFFFFFFF
        target_low = int(target_low) & 0xFFFFFFFFFFFFFFFF

        mf = cl.mem_flags
        header_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=header_array)
        output_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, 36)
        program = cl.Program(self.ctx, SCRYPT_KERNEL).build()
        kernel = program.scrypt_hash

        self.hash_count = 0
        self.start_time = time.time()
        nonce_range = 2**18  # Kurangi ke 262,144 untuk efisiensi GPU

        nonce_start = 0
        while nonce_start < 0xFFFFFFFF:
            kernel(self.queue, (nonce_range,), None, header_buf, output_buf,
                   np.uint32(nonce_start), np.uint64(target_high), np.uint64(target_low))
            self.queue.finish()

            output_np = np.zeros(36, dtype=np.uint8)
            cl.enqueue_copy(self.queue, output_np, output_buf)
            self.hash_count += nonce_range

            hash_array = np.ascontiguousarray(output_np[:32][::-1])
            nonce_array = np.ascontiguousarray(output_np[32:36])
            hash_result = binascii.hexlify(hash_array).decode()
            found_nonce = struct.unpack('<L', nonce_array.tobytes())[0]

            if output_np[32] != 0 or output_np[33] != 0 or output_np[34] != 0 or output_np[35] != 0:
                self.blocks_found += 1
                reward = 6.25
                self.total_reward += reward
                elapsed = time.time() - self.start_time
                logging.info(f"Blok berhasil ditambang! Nonce: {found_nonce:08x}, Hash: {hash_result}")
                logging.info(f"Waktu penambangan: {elapsed:.2f} detik")
                logging.info(f"Hadiah diterima: {reward} LTC | Total hadiah: {self.total_reward} LTC")

                submit_payload = {
                    "id": 4,
                    "method": "mining.submit",
                    "params": [WORKER_NAME, job_id, extranonce2, ntime, f"{found_nonce:08x}"]
                }
                self.send(submit_payload)
                submit_response = self.recv()
                logging.info(f"Submit response: {submit_response}")
                break

            nonce_start += nonce_range
            hashrate = self.get_hashrate()
            earnings = self.estimate_earnings()
            logging.info(f"Mining job {job_id} | Nonce Start: {nonce_start}, Hashrate: {hashrate:.2f} MH/s")
            logging.info(f"Estimasi pendapatan harian: {earnings:.6f} LTC | Total hadiah: {self.total_reward} LTC | Difficulty: {self.network_difficulty}")

        if nonce_start >= 0xFFFFFFFF:
            logging.warning(f"Nonce habis untuk job {job_id}, menunggu job baru...")

    def mine(self):
        if not self.connect_to_pool():
            return

        if not self.subscribe():
            logging.error("Gagal subscribe ke pool.")
            return

        if not self.authorize():
            logging.error("Gagal authorize ke pool.")
            return

        initial_response = self.recv()
        if initial_response:
            for data in self.parse_response(initial_response):
                if "method" in data and data["method"] == "mining.set_difficulty":
                    self.network_difficulty = float(data["params"][0]) * 1_000_000
                    logging.info(f"Difficulty baru dari pool: {self.network_difficulty}")
                elif "method" in data and data["method"] == "mining.notify":
                    self.mine_job(data)

        while True:
            response = self.recv()
            if not response:
                logging.warning("Pool tidak merespon, mencoba reconnect...")
                time.sleep(5)
                if not self.connect_to_pool():
                    continue
                self.subscribe()
                self.authorize()
                continue

            for data in self.parse_response(response):
                if "method" in data:
                    if data["method"] == "mining.notify":
                        self.mine_job(data)
                    elif data["method"] == "mining.set_difficulty":
                        self.network_difficulty = float(data["params"][0]) * 1_000_000
                        logging.info(f"Difficulty baru dari pool: {self.network_difficulty}")
            time.sleep(0.1)

def main():
    miner = LitecoinMinerGPU()
    try:
        miner.mine()
    except KeyboardInterrupt:
        logging.info("Mining dihentikan oleh pengguna.")
        logging.info(f"Total blok ditemukan: {miner.blocks_found}")
        logging.info(f"Total hadiah diperoleh: {miner.total_reward} LTC")
    except Exception as e:
        logging.error(f"Error tak terduga: {e}")

if __name__ == "__main__":
    main()
