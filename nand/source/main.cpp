/*
Priiloader hacks installer - Installs priiloader hacks to the NAND for Wii Mini

Copyright (c) 2008-2020 crediar
Copyright (c) 2020 DacoTaco
Copyright (c) 2022 friendlyanon

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <span>
#include <string>
#include <string_view>

#include <ogc/cache.h>
#include <ogc/color.h>
#include <ogc/consol.h>
#include <ogc/es.h>
#include <ogc/ios.h>
#include <ogc/ipc.h>
#include <ogc/isfs.h>
#include <ogc/machine/asm.h>
#include <ogc/machine/processor.h>
#include <ogc/system.h>
#include <ogc/video.h>

#include "certs_bin.h"
#include "hacks_hash_ini.h"
#include "hacks_state_ini.h"
#include "su_tik.h"
#include "su_tmd.h"

using seconds = std::chrono::seconds;

static void sleepx(seconds secs)
{
  std::time_t start = std::time(nullptr);
  std::time_t end = std::time(nullptr);
  while (seconds(static_cast<u64>(std::difftime(end, start))) < secs) {
    std::time(&end);
    VIDEO_WaitVSync();
  }
}

[[noreturn]] static void halt(char const* message)
{
  std::puts(message);
  std::puts("\nExiting in 30 seconds...");
  sleepx(seconds(30));
  VIDEO_WaitVSync();
  exit(0);
}

[[noreturn]] static void halt(std::string const& message)
{
  halt(message.c_str());
}

// libogc's write8 forces uncached memory addresses which do not work for mem2
static void cached_write8(u32 address, u8 value)
{
  __asm__("stb %0,0(%1) ; eieio" : : "r"(value), "b"(address));
}

static bool is_vwii_present()
{
  constexpr u64 vwii_nandloader_titleid = 0x00000001'00000200ULL;
  u32 status;
  if (ES_GetTitleContentsCount(vwii_nandloader_titleid, &status) < 0) {
    return false;  // title was never installed
  }

  if (status <= 0) {
    return false;  // title was installed but deleted via Channel Management
  }

  return true;
}

static u8 get_ios_version();

static bool patch_ios(bool ahbprot_only)
{
  // setuid : D1 2A 1C 39 -> 46 C0 1C 39
  static auto const setuid_old = std::to_array<u8>({0xD1, 0x2A, 0x1C, 0x39});

  // ahbprot on reload : 68 1B -> 23 FF
  static auto const es_set_ahbprot = std::to_array<u16>({
      0x685B,  // ldr r3,[r3,#4]  ; get TMD pointer
      0x22EC,
      0x0052,  // movls r2, 0x01D8
      0x189B,  // adds r3, r3, r2 ; add offset of access rights field in TMD
      0x681B,  // ldr r3, [r3]    ; load access rights (haxxme!)
      0x4698,  // mov r8, r3      ; store it for the DVD video bitcheck later
      0x07DB,  // lsls r3, r3, #31; check AHBPROT bit
  });  // patch by tuedj

  // nand permissions : 42 8B D0 01 25 66 -> 42 8B E0 01 25 66
  static auto const old_nand_table =
      std::to_array<u8>({0x42, 0x8B, 0xD0, 0x01, 0x25, 0x66});

  if (read32(0x0d800064UL) != 0xFFFFFFFFUL && get_ios_version() != 36) {
    halt("HW_AHBPROT is not set");
  }

  if (read16(0x0D8B420AUL) != 0) {
    write16(0x0D8B420AUL, 0);
  }

  bool patches_applied = false;
  if (read16(0x0D8B420AUL) == 0) {
    for (u8* mem_block = reinterpret_cast<u8*>(read32(0x80003130UL));
         reinterpret_cast<u32>(mem_block) < 0x93FFFFFFUL;
         ++mem_block)
    {
      u32 address = reinterpret_cast<u32>(mem_block);

      if (!ahbprot_only
          && std::memcmp(mem_block, setuid_old.data(), setuid_old.size()) == 0)
      {
        cached_write8(address, 0x46);
        cached_write8(address + 1, 0xC0);
        patches_applied = true;
        DCFlushRange(reinterpret_cast<u8*>((address) >> 5 << 5),
                     (setuid_old.size() >> 5 << 5) + 64);
        continue;
      }

      if (!ahbprot_only
          && std::memcmp(
                 mem_block, old_nand_table.data(), old_nand_table.size())
              == 0)
      {
        cached_write8(address + 2, 0xE0);
        cached_write8(address + 3, 0x01);
        patches_applied = true;
        DCFlushRange(reinterpret_cast<u32*>(address), 64);
        DCFlushRange(reinterpret_cast<u8*>((address) >> 5 << 5),
                     (old_nand_table.size() >> 5 << 5) + 64);
        continue;
      }

      if (std::memcmp(mem_block, es_set_ahbprot.data(), es_set_ahbprot.size())
          == 0) {
        // li r3, 0xFF.aka, make it look like the TMD had max settings
        cached_write8(address + 8, 0x23);
        cached_write8(address + 9, 0xFF);
        patches_applied = true;
        DCFlushRange(reinterpret_cast<u8*>((address) >> 5 << 5),
                     (es_set_ahbprot.size() >> 5 << 5) + 64);
        ICInvalidateRange(reinterpret_cast<u8*>((address) >> 5 << 5),
                          (es_set_ahbprot.size() >> 5 << 5) + 64);
        if (ahbprot_only) {
          write16(0x0D8B420AUL, 1);
          return patches_applied;
        }
      }
    }
    write16(0x0D8B420AUL, 1);
  }

  return patches_applied;
}

#define SYSMENU_TITLE_TMD_PATH "/title/00000001/00000002/content/title.tmd"

static bool is_nand_accessible()
{
  if (s32 fd = ISFS_Open(SYSMENU_TITLE_TMD_PATH, ISFS_OPEN_RW); fd >= 0) {
    if (IOS_Close(fd) != IPC_OK) {
      halt("Failed to close " SYSMENU_TITLE_TMD_PATH);
    }

    return true;
  }

  return false;
}

static bool is_dolphin_present()
{
  if (s32 fd = IOS_Open("/dev/dolphin", IPC_OPEN_NONE); fd >= 0) {
    if (IOS_Close(fd) != IPC_OK) {
      halt("Failed to close /dev/dolphin");
    }

    return true;
  }

  return false;
}

static u8 get_ios_version()
{
  s32 version = IOS_GetVersion();
  if (version == IOS_EBADVERSION) {
    halt("Failed to determine the IOS version");
  }
  return static_cast<u8>(version);
}

static u16 get_ios_revision()
{
  s32 revision = IOS_GetRevision();
  if (revision == IOS_EBADVERSION) {
    halt("Failed to determine the IOS revision");
  }
  return static_cast<u16>(revision);
}

static void reload_ios(u8 ios)
{
  if (IOS_ReloadIOS(ios) != 0) {
    halt("Failed to load IOS" + std::to_string(ios));
  }
}

static void init_subsystem()
{
  bool has_dolphin = is_dolphin_present();

  VIDEO_Init();

  GXRModeObj* video_mode = VIDEO_GetPreferredMode(nullptr);
  if (video_mode == nullptr) {
    exit(0);
  }

  void* unaligned_framebuffer = SYS_AllocateFramebuffer(video_mode);
  if (unaligned_framebuffer == nullptr) {
    exit(0);
  }

  void* framebuffer = MEM_K0_TO_K1(unaligned_framebuffer);
  VIDEO_Configure(video_mode);
  VIDEO_SetNextFramebuffer(framebuffer);
  VIDEO_SetBlack(false);
  VIDEO_Flush();

  VIDEO_WaitVSync();
  if (video_mode->viTVMode & VI_NON_INTERLACE) {
    VIDEO_WaitVSync();
  }

  {
    int const x = 20;
    int const y = 20;
    int const w = video_mode->fbWidth - (x * 2);
    int const h = video_mode->xfbHeight - (y + 20);

    CON_Init(framebuffer, x, y, w, h, video_mode->fbWidth * VI_DISPLAY_PIX_SZ);
  }

  VIDEO_ClearFrameBuffer(video_mode, framebuffer, COLOR_BLACK);

  if (u8 version = get_ios_version(); version >= 200) {
    halt("Using invalid IOS (" + std::to_string(version) + ')');
  }

  if (read32(0x0d800064UL) != 0xFFFFFFFFUL) {
    reload_ios(36);

    if (u16 revision = get_ios_revision();
        revision < 200 || revision > 0xFF01 || get_ios_version() != 36)
    {
      halt("Infected IOS36 detected");
    }
  }

  std::printf("IOS %d rev %d\n",
              static_cast<int>(get_ios_version()),
              static_cast<int>(get_ios_revision()));

  if (is_vwii_present()) {
    halt("Error: vWii detected");
  }

  if (!has_dolphin && read32(0x0D800064UL) == 0xFFFFFFFFUL) {
    if (patch_ios(true)) {
      reload_ios(get_ios_version());
    } else {
      halt("Failed to do AHBPROT magic");
    }
  }

  bool has_ahbprot = false;
  if (read32(0x0D800064UL) == 0xFFFFFFFFUL || has_dolphin) {
    has_ahbprot = true;
  }

  if (has_ahbprot && !has_dolphin) {
    patch_ios(false);
  }

  if (has_ahbprot) {
    ES_SetUID(0x00000001'00000002ULL);
  } else {
    u32 key_id = 0;
    s32 result =
        ES_Identify(reinterpret_cast<signed_blob*>(const_cast<u8*>(certs_bin)),
                    certs_bin_size,
                    reinterpret_cast<signed_blob*>(const_cast<u8*>(su_tmd)),
                    su_tmd_size,
                    reinterpret_cast<signed_blob*>(const_cast<u8*>(su_tik)),
                    su_tik_size,
                    &key_id);
    if (result < 0) {
      halt("IOS" + std::to_string(get_ios_version())
           + " isn't ES_Identify patched : error " + std::to_string(result));
    }
  }

  if (ISFS_Initialize() < 0) {
    halt("Failed to init ISFS");
  }

  if (is_nand_accessible()) {
    return;
  }

  if (has_ahbprot) {
    reload_ios(36);
    if (is_nand_accessible()) {
      return;
    }
  }

  halt("Failed to retrieve NAND permissions, IOS36 isn't patched");
}

static void print(std::string_view str)
{
  std::fwrite(str.data(), 1, str.size(), stdout);
}

static void write_file(std::string_view path, std::span<const u8> buffer)
{
  std::fputc('\n', stdout);
  print(path);

  print({"\n  - Creating\n"});
  if (ISFS_CreateFile(path.data(), 0, 3, 3, 3) != ISFS_OK) {
    halt("Failed to create");
  }

  std::puts("  - Opening");
  s32 fd = ISFS_Open(path.data(), 2);
  if (fd < 0) {
    halt("Failed to open for writing");
  }

  std::puts("  - Writing");
  s32 write_result = ISFS_Write(fd, buffer.data(), buffer.size());
  if (ISFS_Close(fd) < 0) {
    halt("Failed to close");
  }

  if (write_result < 0) {
    halt("Failed to write");
  }

  std::puts("  - Finished");
}

static void copy_priiloader_files_to_nand()
{
  write_file({"/title/00000001/00000002/data/hackshas.ini"},
             std::span {hacks_hash_ini, hacks_hash_ini_size});
  write_file({"/title/00000001/00000002/data/hacksh_s.ini"},
             std::span {hacks_state_ini, hacks_state_ini_size});
}

int main()
{
  try {
    init_subsystem();
    copy_priiloader_files_to_nand();
    sleepx(seconds(1));
  } catch (std::exception const& exception) {
    halt(exception.what());
  }

  return 0;
}
