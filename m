Return-Path: <kasan-dev+bncBAABBUG5STFQMGQEW3BY27A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BA86D1456F
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:26:42 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88fcbe2e351sf142371386d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:26:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238800; cv=pass;
        d=google.com; s=arc-20240605;
        b=HxcnP2vyY6AByjc4ebYlJ9n2+ja3mTJ2OVMzFrYxgcWy4BWORf9q4hfvDyW0g9j7iz
         dmKYguZqvDEX/z2iOcI0yYXZaKdWWNBzCBYO05wFMw6+31ZuSahhdea5Jy588gwTuOFD
         yBUHkcOmidHMk7T2T8Wzh6gUXFw1NxHPnPePzLq8kR7ZUSF67H9ONbT7UEMZwR7jb5tH
         cgHgIlo+uvjpDauoNjA2TLzQqxrxwVjl6FE76PuUoECJ7/iJuYtUQPfavst3L+f0kJ56
         bvIz7rT5D4T3Fk2bouhh7JwBBl+xQho9GEOyzosHoBbDhV4pURC4n2BHma+ArCytktf/
         A5Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=3Qk8k8OpvtyCoR0xUTO8imtUXG2JKM8YUQCYG/hdMOg=;
        fh=g263K+0jkIajpg3qhNugnFKuJE14nme+V6bzDaKbpj4=;
        b=ZzMaMh703UWjTHIFdUugm+Nu3e3O0U63hKrfcU0icF2U/aTN9nuH0ud/R2qw3zkEy4
         F29tLexwbGVUM4++8qorYKwGHkU37vpa9wXLq9FCuAURYI/5u9nzeMB1Dxw6mrwX2oAk
         YPu6ZLFppBCKZFSZaDFSVuvMyLU1T0Cy/PmHRU+vh8DEw0RLGqCoEF0Il7uYi6mrwqmb
         xDyVoGIK5HyHYG18czGyNcqzemys5/VayXzG8+HWAunY8V9oDKGsLykOuQfLoy47HUrD
         xycrT4EGp6fzWec4CsLGcW/WWKuXvW3N/ginxuAVtUBqPxC66E5UrdM4XBolk3DQfwSn
         pduQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=kply4xUI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238800; x=1768843600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3Qk8k8OpvtyCoR0xUTO8imtUXG2JKM8YUQCYG/hdMOg=;
        b=au3ANan7ckh2Z1gxKorR9d/904eJsFed+aasWVt/8RP3ctULQDozZCtHueHQyvXG9f
         TVnv/nFTNLUqnaOphwOUbb+51E1vvMYuUsdPWw+tMWLLvEwdv+SqJ6o7iOqDA2h/HVhO
         xdn6TpOcR9SCRxVQT8x1LfV4vBDkYSyK3AwNx9Q1J1Rs8U7u5LBPH74eppAQRB4GoSsH
         ebN2efZ9Y3FxvAEPnaSN6AICpP4G0b2WH+7i+8+RMqkexjbA1C1fJ8n0zJliOHjIpJLg
         7nTv1Mb5uIJ95+y40BQIZbYNQ3GqpT2eE3JpbeZAxPpVZMXXNJ4ZX9nogEvbR1Xn7FGa
         OnrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238800; x=1768843600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=3Qk8k8OpvtyCoR0xUTO8imtUXG2JKM8YUQCYG/hdMOg=;
        b=c0w3lQMJHP0pu7fLL4/PSJOWSrXF8EuwGfxx1tMLgcxJZ8gKjYMU5rYjhF+BwC4eGG
         0vSKD2pkhK2e0vBHv4NeI2VxyiMBw8N8yNaNXzIhZB8Ryz2yehrGT03+mPZ73yLuBwso
         OCsiWV2H2U7jfYJX7Get6v84gyso/vrSB9k14iML9/uIFFPLDM3gBdBG+zlA0Z42ZVA0
         ZQ3IDV8GizJomTTe+VXVaOMxU6/oY5KPEJT7f/yh3ncybIkUQIThgtrTswUOuxtm5IxD
         /UwjCG8p58xkBeUhFkahA+DyiG30k7s0qGwKguNADSpLhBX0I65hXoIhcT3nwxEuhcy6
         6BjA==
X-Forwarded-Encrypted: i=2; AJvYcCWTPg7+VtKbp2OxpMdSB5cyGdoCfdrqJhMnUh5EHCQcjJJxDTp6/XADSb/C1EMI5bARyhOUWA==@lfdr.de
X-Gm-Message-State: AOJu0YxAxgSonQ4j1iBgYpzQdv5mLSdMdzu+wb8dMvZ3hEyyt8syBpt6
	NnLav+SNw1SfXYtGlgMg2tpAcpvEUOYpba3kUICZw2gbqZeFS5cdbsSW
X-Google-Smtp-Source: AGHT+IEI2g99xAqoVDH+POWmaRU5y7wMsoB1uRd7nPlm6iJ/nANXNn72SMUNauzybQGqHZ+9Vv9Gsw==
X-Received: by 2002:a05:622a:1356:b0:4ed:e55b:767e with SMTP id d75a77b69052e-501397676d3mr2382551cf.15.1768238800465;
        Mon, 12 Jan 2026 09:26:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FSOmqDGWRBYXikyB0uLoJHiDoaETEJ7u8m2C4GFfm9WA=="
Received: by 2002:ac8:47d3:0:b0:4f1:83e4:6f59 with SMTP id d75a77b69052e-4ffb43f9497ls43177031cf.2.-pod-prod-00-us-canary;
 Mon, 12 Jan 2026 09:26:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXOxQQ5Y7g2aDg80zUfjZ3HbU8WCgrl8gvrGlnP4iIAjy6aMpEDRDg5dJ8b7Ft3WAvQsu1OalSNIvg=@googlegroups.com
X-Received: by 2002:a05:622a:28d:b0:4ff:a886:bc49 with SMTP id d75a77b69052e-5013966a94amr3346191cf.0.1768238799608;
        Mon, 12 Jan 2026 09:26:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238799; cv=none;
        d=google.com; s=arc-20240605;
        b=kaSZ2wEdiqFAxy5sjZAQMfQd+kBSCCCHTPuQ8DGgSaS6wG/xqLBRtF/9/gge4A+mOr
         o4+ITYiQMKE5PmAj4ScSJuhgPZLt6VTWQXsJBE9CDHbt/UaCPypjMMjhoQfXGpGz6CY4
         obZj4C6etwqRrJvML15iPw2xtuDJa2GPycj5/4PFJssQJYLLEn1haTzXgQnV0x1roko1
         geH9EwasizsCq1UtQ9wlSlkdq3NvyvR31pLy4hP7Y7k2RbnEfahRQxqPP7+oMgHunT3F
         A06Hqaf4p0QPlMNBOl7fBiXe1n/yDEO4aX33Jh5+xBOQcoGdnXvO3jGQ2iZrAcgaPPBi
         VpVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=MZLHOnEOyMbQ1BnCPqw/Rl/jRpv2IPlwroWlod1BlMw=;
        fh=5uKY3jKQAITqhhdBWfxwXfmLe9uHFeP0IaTBZeyIl7U=;
        b=VZkGuf9agSdxHO/P4bD0XQIYt+m8RRMVtSZqqsVlFTVeZJvj9zT70ByNb6j613ih3l
         nnuSUp0asEIByaIws/UIlhYcL7hM42+EuuVO6C+n8O5qGhsD03p5fkIyrh3QpoVx8ODN
         ItSPiU0QXRQycqmmMA8d38Eb3aviS1z7UQfGiiZNIfRTZ+H8UQLm7Ul+MFFJGBxd4aJ5
         bApq888+ZJIRi+N7ZLgCZ3oQG5+ZI2fZMqoLlCUDQpnUeFGg4QU4guTjGYtqPMQhikQ0
         JMIO6Oh4nGzo4My+Igj7ysy065HjvDvH037/TuKF2oonXapl8/DKdoEY1y2E8KV/2BWO
         F0lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=kply4xUI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89082d000a6si5056506d6.9.2026.01.12.09.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:26:39 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Mon, 12 Jan 2026 17:26:29 +0000
To: corbet@lwn.net, morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org, catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org, jackmanb@google.com, samuel.holland@sifive.com, glider@google.com, osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org, akpm@linux-foundation.org, Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com, thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com, axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com, bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com, urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com, andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org, vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com, samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com, surenb@google.com, anshuman.khandual@arm.com,
	smostafa@google.com, yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com, kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org, bp@alien8.de, ardb@kernel.org, justinstitt@google.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, x86@kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 30fd795ba3d87d5fa5bf659d16f56b67634e08f5
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=kply4xUI;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
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
	- Right now on x86 the INT3 instruction is used for the same
	  purpose. The attempt to move it over to use UD1 is already
	  implemented and tested but relies on another series that needs
	  merging first. Therefore this patch will be posted separately
	  once the dependency is satisfied by being merged upstream.

======= Testing
Checked all the kunits for both software tags and generic KASAN after
making changes.

In generic mode (both with these patches and without) the results were:

kasan: pass:61 fail:1 skip:14 total:76
Totals: pass:61 fail:1 skip:14 total:76
not ok 1 kasan

and for software tags:

kasan: pass:65 fail:1 skip:10 total:76
Totals: pass:65 fail:1 skip:10 total:76
not ok 1 kasan

At the time of testing the one failing case is also present on generic
mode without this patchset applied. This seems to point to something
else being at fault for the one case not passing. The test case in
question concerns strscpy() out of bounds error not getting caught.

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
The series is based on 6.19-rc5.

======= Previous versions
v7: https://lore.kernel.org/all/cover.1765386422.git.m.wieczorretman@pm.me/
v6: https://lore.kernel.org/all/cover.1761763681.git.m.wieczorretman@pm.me/
v5: https://lore.kernel.org/all/cover.1756151769.git.maciej.wieczor-retman@intel.com/
v4: https://lore.kernel.org/all/cover.1755004923.git.maciej.wieczor-retman@intel.com/
v3: https://lore.kernel.org/all/cover.1743772053.git.maciej.wieczor-retman@intel.com/
v2: https://lore.kernel.org/all/cover.1739866028.git.maciej.wieczor-retman@intel.com/
v1: https://lore.kernel.org/all/cover.1738686764.git.maciej.wieczor-retman@intel.com/

=== (two fixes patches were split off after v6) (merged into mm-unstable)
v1: https://lore.kernel.org/all/cover.1762267022.git.m.wieczorretman@pm.me/
v2: https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretman@pm.me/
v3: https://lore.kernel.org/all/cover.1764874575.git.m.wieczorretman@pm.me/
v4: https://lore.kernel.org/all/cover.1764945396.git.m.wieczorretman@pm.me/

Changes v8:
- Detached the UD1/INT3 inline patch from the series so the whole
  patchset can be merged without waiting on other dependency series. For
  now with lack of compiler support for the inline mode that patch
  didn't work anyway so this delay is not an issue.
- Rebased patches onto 6.19-rc5.
- Added acked-by tag to "kasan: arm64: x86: Make special tags arch
  specific".

Changes v7:
- Rebased the series onto Peter Zijlstra's "WARN() hackery" v2 patchset.
- Fix flipped memset arguments in "x86/kasan: KASAN raw shadow memory
  PTE init".
- Reorder tag width defines on arm64 to avoid redefinition warnings.
- Split off the pcpu unpoison patches into a separate fix oriented
  series.
- Redid the canonicality checks so it works for KVM too (didn't change
  the __canonical_address() function previously).
- A lot of fixes pointed out by Alexander in his great review:
	- Fixed "x86/mm: Physical address comparisons in fill_p*d/pte"
	- Merged "Support tag widths less than 8 bits" and "Make special
	  tags arch specific".
	- Added comments and extended patch messages for patches
	  "x86/kasan: Make software tag-based kasan available" and
	  "mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic",
	- Fixed KASAN_TAG_MASK definition order so all patches compile
	  individually.
	- Renamed kasan_inline.c to kasan_sw_tags.c.

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

Maciej Wieczor-Retman (12):
  kasan: Fix inline mode for x86 tag-based mode
  x86/kasan: Add arch specific kasan functions
  x86/mm: Reset tag for virtual to physical address conversions
  mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
  x86/mm: Physical address comparisons in fill_p*d/pte
  x86/kasan: KASAN raw shadow memory PTE init
  x86/mm: LAM compatible non-canonical definition
  x86/mm: LAM initialization
  x86: Minimal SLAB alignment
  arm64: Unify software tag-based KASAN inline recovery path
  x86/kasan: Logical bit shift for kasan_mem_to_shadow
  x86/kasan: Make software tag-based kasan available

Samuel Holland (2):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: arm64: x86: Make special tags arch specific

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
 Documentation/arch/x86/x86_64/mm.rst      |  6 ++-
 MAINTAINERS                               |  2 +-
 arch/arm64/Kconfig                        | 10 ++--
 arch/arm64/include/asm/kasan-tags.h       | 14 +++++
 arch/arm64/include/asm/kasan.h            |  2 -
 arch/arm64/include/asm/memory.h           | 14 ++++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/kernel/traps.c                 | 17 +------
 arch/arm64/mm/kasan_init.c                |  7 ++-
 arch/x86/Kconfig                          |  4 ++
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 ++++
 arch/x86/include/asm/kasan.h              | 62 ++++++++++++++++++++++-
 arch/x86/include/asm/page.h               | 23 ++++++++-
 arch/x86/include/asm/page_64.h            |  1 +
 arch/x86/kernel/head_64.S                 |  3 ++
 arch/x86/mm/init.c                        |  3 ++
 arch/x86/mm/init_64.c                     | 11 ++--
 arch/x86/mm/kasan_init_64.c               | 25 +++++++--
 arch/x86/mm/physaddr.c                    |  2 +
 include/linux/kasan-tags.h                | 21 ++++++--
 include/linux/kasan.h                     | 13 +++--
 include/linux/mm.h                        |  6 +--
 include/linux/mmzone.h                    |  2 +-
 include/linux/page-flags-layout.h         |  9 +---
 lib/Kconfig.kasan                         |  3 +-
 mm/execmem.c                              |  9 +++-
 mm/kasan/report.c                         | 37 ++++++++++++--
 mm/vmalloc.c                              |  7 ++-
 scripts/Makefile.kasan                    |  3 ++
 scripts/gdb/linux/kasan.py                |  5 +-
 scripts/gdb/linux/mm.py                   |  5 +-
 34 files changed, 277 insertions(+), 72 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1768233085.git.m.wieczorretman%40pm.me.
