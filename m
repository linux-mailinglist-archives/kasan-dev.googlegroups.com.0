Return-Path: <kasan-dev+bncBAABBCOLRHEAMGQES3TL5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8113FC1CE2A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:05:47 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-37a0cc22ec1sf540221fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:05:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764747; cv=pass;
        d=google.com; s=arc-20240605;
        b=OvURL0VcH6758O48tGAAnblTyc6fudJowIaaUzXcG9SKaAf3IW4IGld475zzcwU8ww
         YoVMovyPWg1D47ovqdNGQWvJFAsYVFvvs9EatucSnEydKWTmKVGZuF1e9QX7gU5UfQMf
         gUPc7IQqRLKrI17qwW/BLtl30uVDc2iWauy/6hO1iQbEI9ijmo2w1lY/7N4bPyVXHPrc
         EAGZH4mruvtqRP0dIRk9ufRJ8NK8KB3sKUunoeo3fD9bJ58ALb2gCOmM/r7k8Nyi8li2
         izzu7NaqgLklzoR4Cv8cq0C0W355iz/jwre5IdaJFx1gnzXKG5zBWRw2Rbr1RCjIZcJj
         igQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=27f5fJllVFFgZt85RxTZwbLQlVSICJbmQgqvkt5DIxI=;
        fh=6ezWzJZwD6pvKrZiUP6uG0VTz7JqMoLWH1wJRsb5XiQ=;
        b=FnXjjwUD2kT3djsAvie/3uy/pP4YI3A/pDVDz591/kQWYC9EsdOIrMRipkqCIAr1FR
         takP6gkYurysjCG2IR9tgxwEfS7hpsuRQ/ndvUiVWpFJUe5DlwPV+WeUiUSi5sGK0HHi
         bzEzJWlOjwvBJpze8I4NDSJBHgN924nixf9oTmTSSOG1ru073x8WNAfnTO1oXM0RsZIT
         mPfrnHl8IxlIvWeuWUQsiKyeMhT4bFLvIgs0IVPLsUB/fZnj4pljr3U9kfFSYcuRc6+n
         OGeZbx0yw/zZhLeaLx0EYSH2GWavKi7niv70zUDkfetZHWGOyavJvy7GII6Xfq7CbkL8
         FApA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=AOyiR+rx;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764747; x=1762369547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=27f5fJllVFFgZt85RxTZwbLQlVSICJbmQgqvkt5DIxI=;
        b=LP4g0NUuxL81zmyodwxDI/tFlRkMGoQUAlC6alzLT9Ff69YijofhzROzGJmn/kkI0G
         WiqBoQaDLif/oIlgYilPkgdvlHHKbKD6NUhYvjbUP1XdePb+RkD8PmU1c6ZYAXDwd6Kt
         H2hsYzcK2iNnrl3wgCuSHor/3ID2RwzNmbNpEb+NFvvyhxtR7PxhXrk1wvozj9/4sbXB
         sqm8umlkBkO9y7n3LGu0+dp2rVqxGCGvtry6TcEhm1M0zLDoGEHO4nEMkltUeYKejlie
         Tjg0CRP/uAUsguiXdNkv2yNxwfKwInUOEcPgdG45Htrhnx/09Mxykp6ieJPgamcBAm5a
         z0tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764747; x=1762369547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=27f5fJllVFFgZt85RxTZwbLQlVSICJbmQgqvkt5DIxI=;
        b=NzUThacpit37dHUHVKWAE9lQrRD4FCGzH6hMznx+dFhi5fdy4TTxVzyC2dRJ1BLXHt
         UrceS+FE5LJ4RaBFYs5Q+OCk6I3e5GgNudWaTPI19pNr8N0LLukEbi7qFXGNayBzaRNZ
         tIyVIFGwv0YV3hBH17Uw7Cq6JpRvfJlL8Rb4UahBKYOYcqOMmztqWnQDSZULMaXehiCK
         a17jQj9klXnI0D1jz7AisHj+Esn276WyrBEwghn5cix0K3Ow62lnISftKVpCQi9RAjIn
         NtPCwWO9g/qXrZgkIyU3FJAA4RP+eZd3wHhuXcwInpFk//TS1rmiBFjVvw9MInLbHhWm
         9AVg==
X-Forwarded-Encrypted: i=2; AJvYcCWzQf/fuqDqLDAv4yqHfUVtMdATHvCLWNnnbxG7pPPsOHGHqhh4vHGFCeChHWRH/6+CYXcf9Q==@lfdr.de
X-Gm-Message-State: AOJu0YwE2j6mA88G3gBqdIIzmg3N926o5/YuF6uylgMJ7+/a1JyKlAj4
	7TsK+RM7HMEisUpH9a0i19XksBEDHLnApi6PtzyQZCGS/u9AghmXoBGm
X-Google-Smtp-Source: AGHT+IFGiL4uBaKHkvYPJZSHflx3udPImF0o5avslL1LNHjdP92PozXsb/t42heflfHETJO6nUHK2Q==
X-Received: by 2002:a05:6512:3b07:b0:592:fd1e:6f8a with SMTP id 2adb3069b0e04-59416e679fdmr151864e87.6.1761764746378;
        Wed, 29 Oct 2025 12:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YG+S70JCrlyq2ama5j+wnJs0kBgdxUV5PWM7jZ9FZvcg=="
Received: by 2002:ac2:5930:0:b0:55f:48d5:149d with SMTP id 2adb3069b0e04-59417655e17ls14214e87.2.-pod-prod-08-eu;
 Wed, 29 Oct 2025 12:05:44 -0700 (PDT)
X-Received: by 2002:a05:6512:3f1b:b0:591:eb05:c25c with SMTP id 2adb3069b0e04-59416e7dd30mr221225e87.17.1761764744050;
        Wed, 29 Oct 2025 12:05:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764744; cv=none;
        d=google.com; s=arc-20240605;
        b=dtIKephBdriFMIOIJPKhqCQbDoyjVQOC/wSX+SMlOg2LUnLm9jDUA6Wx3m4dVJz/5B
         oNtGOHSLlShI9Rtf0C2+XOojr5PZlLOOlLyJ45Fa5KS08Lpek9dHIQvfuucw4Ey0VoJh
         D63J0tBnIb2kXDzOUJic1gUtpnjoNAFUJP7MiYDgJ87roa48/IHNnH7lG+ayTxXd0GXl
         kCTfRBI5mIOOBVyXMoPuiw2zkwejpH0qfJI2fZ+LL5RRkvlaHLNdUBz3i8qMBD4FGwZL
         YzLOuHGAVUZd7eSDfG3OgTx2FEtvk5mpVqYqk7mS27/kUzUx9MVwRVfv4e7tU2T6u8me
         0Peg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=B6CFw+JSCNGBsZMvctblIxAviwt5E/Cc+YlSpcKbM2E=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=RqlxlQJ2qt5w81Weufyi9pa0WOqBuvhF7F+B5M3DiAmVTfsQkIiN9wmqKh3L8GRtgt
         HUT1hP861Zz3WgrfQrP1olWHhMqLEyCWYS6633PY/h6CBCASM9XZMLtkoTT6E0fw6+LR
         Pr3gkdscR2lv5h3MmKNWoULNTaflV0ce+hiorlIx+7G+aWQsNm/SGlQDo41wJy+s8wrz
         84xis2xfqZ0qXIDgADKsBbHXDcAfQv8tWHifX1VBI0nnTenyUCFUelMCaWsYQVmZI27Z
         hCKKREIsI0bVijoEU1AaZxeSG7DVswFUb4eu+PsdfXTsyernOX+N/RN4SBdyu6rfNWmv
         Dh7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=AOyiR+rx;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5930276e7e7si276864e87.2.2025.10.29.12.05.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:05:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Wed, 29 Oct 2025 19:05:27 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 00/18] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: b23693d0cf530e4c8a53771e64b6fdea3be223c5
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=AOyiR+rx;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

======= Introduction
The patchset aims to add a KASAN tag-based mode for the x86 architecture
with the help of the new CPU feature called Linear Address Masking
(LAM). Main improvement introduced by the series is 2x lower memory
usage compared to KASAN's generic mode, the only currently available
mode on x86. The tag based mode may also find errors that the generic
mode couldn't because of differences in how these modes operate.

======= How does KASAN' tag-based mode work?
When enabled, memory accesses and allocations are augmented by the
compiler during kernel compilation. Instrumentation functions are added
to each memory allocation and each pointer dereference.

The allocation related functions generate a random tag and save it in
two places: in shadow memory that maps to the allocated memory, and in
the top bits of the pointer that points to the allocated memory. Storing
the tag in the top of the pointer is possible because of Top-Byte Ignore
(TBI) on arm64 architecture and LAM on x86.

The access related functions are performing a comparison between the tag
stored in the pointer and the one stored in shadow memory. If the tags
don't match an out of bounds error must have occurred and so an error
report is generated.

The general idea for the tag-based mode is very well explained in the
series with the original implementation [1].

[1] https://lore.kernel.org/all/cover.1544099024.git.andreyknvl@google.com/

======= Differences summary compared to the arm64 tag-based mode
- Tag width:
	- Tag width influences the chance of a tag mismatch due to two
	  tags from different allocations having the same value. The
	  bigger the possible range of tag values the lower the chance
	  of that happening.
	- Shortening the tag width from 8 bits to 4, while it can help
	  with memory usage, it also increases the chance of not
	  reporting an error. 4 bit tags have a ~7% chance of a tag
	  mismatch.

- Address masking mechanism
	- TBI in arm64 allows for storing metadata in the top 8 bits of
	  the virtual address.
	- LAM in x86 allows storing tags in bits [62:57] of the pointer.
	  To maximize memory savings the tag width is reduced to bits
	  [60:57].

- Inline mode mismatch reporting
	- Arm64 inserts a BRK instruction to pass metadata about a tag
	  mismatch to the KASAN report.
	- On x86 the INT3 instruction is used for the same purpose.

======= Testing
Checked all the kunits for both software tags and generic KASAN after
making changes.

In generic mode the results were:

kasan: pass:59 fail:0 skip:13 total:72
Totals: pass:59 fail:0 skip:13 total:72
ok 1 kasan

and for software tags:

kasan: pass:63 fail:0 skip:9 total:72
Totals: pass:63 fail:0 skip:9 total:72
ok 1 kasan

======= Benchmarks [1]
All tests were ran on a Sierra Forest server platform. The only
differences between the tests were kernel options:
	- CONFIG_KASAN
	- CONFIG_KASAN_GENERIC
	- CONFIG_KASAN_SW_TAGS
	- CONFIG_KASAN_INLINE [1]
	- CONFIG_KASAN_OUTLINE

Boot time (until login prompt):
* 02:55 for clean kernel
* 05:42 / 06:32 for generic KASAN (inline/outline)
* 05:58 for tag-based KASAN (outline) [2]

Total memory usage (512GB present on the system - MemAvailable just
after boot):
* 12.56 GB for clean kernel
* 81.74 GB for generic KASAN
* 44.39 GB for tag-based KASAN

Kernel size:
* 14 MB for clean kernel
* 24.7 MB / 19.5 MB for generic KASAN (inline/outline)
* 27.1 MB / 18.1 MB for tag-based KASAN (inline/outline)

Work under load time comparison (compiling the mainline kernel) (200 cores):
*  62s for clean kernel
* 171s / 125s for generic KASAN (outline/inline)
* 145s for tag-based KASAN (outline) [2]

[1] Currently inline mode doesn't work on x86 due to things missing in
the compiler. I have written a patch for clang that seems to fix the
inline mode and I was able to boot and check that all patches regarding
the inline mode work as expected. My hope is to post the patch to LLVM
once this series is completed, and then make inline mode available in
the kernel config.

[2] While I was able to boot the inline tag-based kernel with my
compiler changes in a simulated environment, due to toolchain
difficulties I couldn't get it to boot on the machine I had access to.
Also boot time results from the simulation seem too good to be true, and
they're much too worse for the generic case to be believable. Therefore
I'm posting only results from the physical server platform.

======= Compilation
Clang was used to compile the series (make LLVM=1) since gcc doesn't
seem to have support for KASAN tag-based compiler instrumentation on
x86.

======= Dependencies
The base branch for the series is the mainline kernel, tag 6.18-rc3.

======= Previous versions
v5: https://lore.kernel.org/all/cover.1756151769.git.maciej.wieczor-retman@intel.com/
v4: https://lore.kernel.org/all/cover.1755004923.git.maciej.wieczor-retman@intel.com/
v3: https://lore.kernel.org/all/cover.1743772053.git.maciej.wieczor-retman@intel.com/
v2: https://lore.kernel.org/all/cover.1739866028.git.maciej.wieczor-retman@intel.com/
v1: https://lore.kernel.org/all/cover.1738686764.git.maciej.wieczor-retman@intel.com/

Changes v6:
- Initialize sw-tags only when LAM is available.
- Move inline mode to use UD1 instead of INT3
- Remove inline multishot patch.
- Fix the canonical check to work for user addresses too.
- Revise patch names and messages to align to tip tree rules.
- Fix vdso compilation issue.

Changes v5:
- Fix a bunch of arm64 compilation errors I didn't catch earlier.
  Thank You Ada for testing the series!
- Simplify the usage of the tag handling x86 functions (virt_to_page,
  phys_addr etc.).
- Remove within() and within_range() from the EXECMEM_ROX patch.

Changes v4:
- Revert x86 kasan_mem_to_shadow() scheme to the same on used in generic
  KASAN. Keep the arithmetic shift idea for the KASAN in general since
  it makes more sense for arm64 and in risc-v.
- Fix inline mode but leave it unavailable until a complementary
  compiler patch can be merged.
- Apply Dave Hansen's comments on series formatting, patch style and
  code simplifications.

Changes v3:
- Remove the runtime_const patch and setup a unified offset for both 5
  and 4 paging levels.
- Add a fix for inline mode on x86 tag-based KASAN. Add a handler for
  int3 that is generated on inline tag mismatches.
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion.
- Remove patches 2 and 3 since they related to risc-v and this series
  adds only x86 related things.
- Reorder __tag_*() functions so they're before arch_kasan_*(). Remove
  CONFIG_KASAN condition from __tag_set().

Changes v2:
- Split the series into one adding KASAN tag-based mode (this one) and
  another one that adds the dense mode to KASAN (will post later).
- Removed exporting kasan_poison() and used a wrapper instead in
  kasan_init_64.c
- Prepended series with 4 patches from the risc-v series and applied
  review comments to the first patch as the rest already are reviewed.

Maciej Wieczor-Retman (16):
  kasan: Unpoison pcpu chunks with base address tag
  kasan: Unpoison vms[area] addresses with a common tag
  kasan: Fix inline mode for x86 tag-based mode
  x86/kasan: Add arch specific kasan functions
  kasan: arm64: x86: Make special tags arch specific
  x86/mm: Reset tag for virtual to physical address conversions
  mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
  x86/mm: Physical address comparisons in fill_p*d/pte
  x86/kasan: KASAN raw shadow memory PTE init
  x86/mm: LAM compatible non-canonical definition
  x86/mm: LAM initialization
  x86: Minimal SLAB alignment
  x86/kasan: Handle UD1 for inline KASAN reports
  arm64: Unify software tag-based KASAN inline recovery path
  x86/kasan: Logical bit shift for kasan_mem_to_shadow
  x86/kasan: Make software tag-based kasan available

Samuel Holland (2):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: sw_tags: Support tag widths less than 8 bits

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
 Documentation/arch/x86/x86_64/mm.rst      |  6 +-
 MAINTAINERS                               |  4 +-
 arch/arm64/Kconfig                        | 10 ++--
 arch/arm64/include/asm/kasan-tags.h       | 14 +++++
 arch/arm64/include/asm/kasan.h            |  2 -
 arch/arm64/include/asm/memory.h           | 14 ++++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/kernel/traps.c                 | 17 +-----
 arch/arm64/mm/kasan_init.c                |  7 ++-
 arch/x86/Kconfig                          |  4 ++
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/bug.h                |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 +++
 arch/x86/include/asm/kasan.h              | 73 ++++++++++++++++++++++-
 arch/x86/include/asm/page.h               | 33 +++++++++-
 arch/x86/include/asm/page_64.h            |  1 +
 arch/x86/kernel/head_64.S                 |  3 +
 arch/x86/kernel/traps.c                   |  8 +++
 arch/x86/mm/Makefile                      |  2 +
 arch/x86/mm/init.c                        |  3 +
 arch/x86/mm/init_64.c                     | 11 ++--
 arch/x86/mm/kasan_init_64.c               | 24 +++++++-
 arch/x86/mm/kasan_inline.c                | 21 +++++++
 arch/x86/mm/physaddr.c                    |  2 +
 include/linux/kasan-tags.h                | 21 +++++--
 include/linux/kasan.h                     | 46 ++++++++++++--
 include/linux/mm.h                        |  6 +-
 include/linux/page-flags-layout.h         |  9 +--
 lib/Kconfig.kasan                         |  3 +-
 mm/execmem.c                              |  2 +-
 mm/kasan/report.c                         | 37 ++++++++++--
 mm/kasan/tags.c                           | 19 ++++++
 mm/vmalloc.c                              |  6 +-
 scripts/Makefile.kasan                    |  3 +
 scripts/gdb/linux/kasan.py                |  5 +-
 scripts/gdb/linux/mm.py                   |  5 +-
 38 files changed, 370 insertions(+), 75 deletions(-)
 mode change 100644 => 100755 Documentation/arch/arm64/kasan-offsets.sh
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h
 create mode 100644 arch/x86/mm/kasan_inline.c

-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1761763681.git.m.wieczorretman%40pm.me.
