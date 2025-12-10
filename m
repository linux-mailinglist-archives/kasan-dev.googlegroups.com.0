Return-Path: <kasan-dev+bncBAABBNW443EQMGQEM3QLW2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 381B8CB3A1E
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:30:32 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5942a78fbccsf4916433e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:30:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387831; cv=pass;
        d=google.com; s=arc-20240605;
        b=C22I0MXVqsRFdKAFvugZC5FjeeHNzBijQdUQgHON8kZX2QJJYkuPkCjVaGgqiTWuva
         iR558hPT2jkJoWREi7xGLv7bR6ZubuFmndaP5N7WTbsYQE/VBDrZy24pIBp7Fr9XgM8R
         vQrdCOJpyrvLR26MLL2BaSHt5yhJQW/HUnsxT+BWiKeNDSnv/SmN3WOq13NLRzvY82ZH
         79E5M/6Hbra4AApxgiCD4zKuoVqfyXL43Kkpvmc9N7zVXwoH780qu0TdhpO1KQR+Y75j
         2Q5XWBfCIYFro/NFi/TcJGdJCRXpYiKv/0eaC+BNbfeYEIr+9DNuG/W1bufXFMXUrM0W
         4MKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=J96M7gDIBBahrRw9k4X5Se3PaYAIO9El854KGk247uI=;
        fh=fd6jkrSoQV1gSqsNq2bKnsBVVOZom5AL09cSJHR/Sow=;
        b=EH/imSeQ9xSPTL5CmVG9PhU5o5qbxdK2aqTQ6Hcc45oVIUybCQRbxUDKDdlAoicpUC
         9NjCsI0cMTdblxDXyJXrNLHLGgsuMYiCYs8IhUawwnKsuAAcGUMjiUdDM8UFsITFBrpP
         VM0zOBBxkz1gN0VJW51eX0Izjjdgp/xpkfLlsZsO8dgAcJ3/bODQdv+wp11YXCnb8G2o
         QD3h/EOiL2ZbAoXFl6DgGfpxdSRPayot2GHcBM8Vlnh/HLwvExMVlCOBGCTxYQaK/0fH
         MSTcukk/Bb1qdV4ajHUZwXhvxcw5eoCJZgeYvFyYqvjF+y/SdnQe9PnyF0rxEW1zBhRj
         KLJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="lI8IFS/p";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387831; x=1765992631; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=J96M7gDIBBahrRw9k4X5Se3PaYAIO9El854KGk247uI=;
        b=dTcOds9IXIahAzjb/lEx78vnSEhMSNK3Q/VIUdQh3F+zB9VAvkQnwZzL7e2b+wvi5o
         vphY6lF4Dy2FJgZIfJbIDAQ5NxWHhS6h35WJyN2bfUZ0BmkX7VCBaQoTymBgFjbDx0wW
         mcZpEmAiPXIJGhSM4WckqXZ9dxo0IKb65jxVFS1837BqHXRlTJamT3wWxMujDBLVfK0w
         aBK3Kpr6fJAqzjGQaQ3eQqaWQiqs5dfsNUvnyNQIB3k3z5AYJMeD4lqTPV84LXFG5B9+
         bFA4ZjJm2RqiPNTTEriuCsDou9+8CofVnGNtNhlYgp6KwtnGJOBWIOWtvBWtMa8Q/7Px
         4TtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387831; x=1765992631;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J96M7gDIBBahrRw9k4X5Se3PaYAIO9El854KGk247uI=;
        b=xDFyPYqBTIfI0xtSJuG/sQ8ai00eQShgDKxkVqGp0AhqvQ2nlojui+lQUQFvrkByGo
         8Jvo6u71r+fQxHm56X4QQRh46VIDfUTUjPmilJRWQEUYNHT9wyWL/c4VgO8e02/K26Ff
         flC8Chue6TUkcQD493ayDdzaL198ISzUSgm2Q2MYlccuFuNXK6FVpGd1H3Qg5v4ow9r0
         2tz+FEk0EqvkO6E1rt5jiqHn89AHbH1mPCif8nLnue0SvSsrEhJfrGqH0egYBXrB5YSM
         b4Jp00abluTIqGlfH85zMxV3TOVvPWGUo0tWV+7HLi25qJpRjPuRwAIBn1bwxT/B6//j
         mXEA==
X-Forwarded-Encrypted: i=2; AJvYcCUGMLfc28Qs2xKQa8WV+N2tcTLrHm85rDyDSbablg77L57nEmatux9G9fGkicGu/CXBQJ8SzA==@lfdr.de
X-Gm-Message-State: AOJu0Yxoyidr1XF12AI3APjhaSK58+M+7cIrCxLUWSG77EuZJZmgVZXW
	AneELScf5965LVV7qeQ3LZbdpoasG/ooNBan+3bb3xJjnIp8OhcaEf0i
X-Google-Smtp-Source: AGHT+IGQI/rxfkFVKaFTib+b7NQizWXGHoUQQwBpPZWFZW9TEdEbOTVIKS+HY2m2RgwJcl0Sgjdb8w==
X-Received: by 2002:a05:6512:3991:b0:595:910c:8eea with SMTP id 2adb3069b0e04-598ee4dbed4mr1219386e87.32.1765387831342;
        Wed, 10 Dec 2025 09:30:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY/61AMAqB7ZTa1alT+u6XSJHjg+a+n1s51WACRjiULVg=="
Received: by 2002:ac2:4f06:0:b0:598:ef8f:67f0 with SMTP id 2adb3069b0e04-598ef8f69ffls295227e87.2.-pod-prod-01-eu;
 Wed, 10 Dec 2025 09:30:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUXhP2fKjGrzVlHmxa7NkY8UpyievjECwKsbRIXzvpPUJxmuhj56cjZoDmjmRMfCv1ASZI/TLnpZ50=@googlegroups.com
X-Received: by 2002:a05:6512:3d07:b0:594:55a3:c191 with SMTP id 2adb3069b0e04-598ee49d70bmr1205164e87.14.1765387829020;
        Wed, 10 Dec 2025 09:30:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387829; cv=none;
        d=google.com; s=arc-20240605;
        b=YkAkNHOsSZ2AjW1wzLAReTVVKuP14SZqUO0Y/iYjeeNyNttMDJq4/rnsMGQ50C3Rgj
         fUQGXl551ueqriEzKpIHA5Knb0TOiiEM+Ju71Ua3Nn1XpATcfwsQZjGA2Y/1tQoeAJZX
         YBzOO+1tvvZwvDm7SSyCs7oysNENhdQ0K+AZcEdOF7gZAEoHL8dO79OOv9hzu6bxN6B3
         Vk5MfIy2kTD3HvPyBIMe5/j0dzY6cOTqCT7HK2990gsWZ48krWnxBF+Us0mO47mQMf+A
         JeWHiBDfyCOUVRPy5UjEAPysBZBMdXRagRZ7LcQsLGnBQnF1HpdwonMFW8oV7RkZtHg6
         qxIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=Lmu9cRts0lCie4eBHValJXDUxi1lOhN4X7sXmk/mIFM=;
        fh=uZ0IYRsUVxE0+ontZZ9KeRjdygccU9aB6CeKVNZy/Eo=;
        b=IzVV7DGmbqmLnf4hf/b4Oyrrp7iBQql3Pr3J/VO29sh25rfz9RihVcdYTIagS8MS3s
         twp04DI8LCxR6YMUYAP5CDyuDYsnZz93v8vfi58E2CyA97QEtEie/P8xYBDToTpgfoXy
         j81prjvy3OCetUQGfGhe+E57MOksW+7UtEYMdHF17zZ3g5LShZVwxMdLfHYVfy2bZjZM
         6ynAcVUOktHQ+2ZJSq6JBivUMgl9inmFyU+v3jB6cDSJwl9X+yRUO4gYVFP9wS/cwefN
         7CYhBSnxAP9qOYqPabU3ReybLp5V46tWdwVe3LuYSZeKszZk2bOHljHW6uaLNfTeRDSY
         +PgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="lI8IFS/p";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106118.protonmail.ch (mail-106118.protonmail.ch. [79.135.106.118])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-598f2f37addsi625e87.2.2025.12.10.09.30.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:30:29 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) client-ip=79.135.106.118;
Date: Wed, 10 Dec 2025 17:30:23 +0000
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com
Subject: [PATCH v7 15/15] x86/kasan: Make software tag-based kasan available
Message-ID: <97b033941d8e146a71827cf31d4d0a12303bcc41.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5b69e1a241d582816c2acd4254c1d2042c7e7e69
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="lI8IFS/p";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

The value for sw_tags KASAN_SHADOW_OFFSET was calculated by rearranging
the formulas for KASAN_SHADOW_START and KASAN_SHADOW_END from
arch/x86/include/asm/kasan.h - the only prerequisites being
KASAN_SHADOW_SCALE_SHIFT of 4, and KASAN_SHADOW_END equal to the
one from KASAN generic mode.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
support is available.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v7:
- Add a paragraph to the patch message explaining how the various
  addresses and the KASAN_SHADOW_OFFSET were calculated.

Changelog v6:
- Don't enable KASAN if LAM is not supported.
- Move kasan_init_tags() to kasan_init_64.c to not clutter the setup.c
  file.
- Move the #ifdef for the KASAN scale shift here.
- Move the gdb code to patch "Use arithmetic shift for shadow
  computation".
- Return "depends on KASAN" line to Kconfig.
- Add the defer kasan config option so KASAN can be disabled on hardware
  that doesn't have LAM.

Changelog v4:
- Add x86 specific kasan_mem_to_shadow().
- Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
  KASAN_SHADOW_START/END.
- Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
- Disable inline and stack support when software tags are enabled on
  x86.

Changelog v3:
- Remove runtime_const from previous patch and merge the rest here.
- Move scale shift definition back to header file.
- Add new kasan offset for software tag based mode.
- Fix patch message typo 32 -> 16, and 16 -> 8.
- Update lib/Kconfig.kasan with x86 now having software tag-based
  support.

Changelog v2:
- Remove KASAN dense code.

 Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
 arch/x86/Kconfig                     | 4 ++++
 arch/x86/boot/compressed/misc.h      | 1 +
 arch/x86/include/asm/kasan.h         | 4 ++++
 arch/x86/mm/kasan_init_64.c          | 6 ++++++
 lib/Kconfig.kasan                    | 3 ++-
 6 files changed, 21 insertions(+), 3 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index a6cf05d51bd8..ccbdbb4cda36 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index a26dc3bad804..b5275e322061 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -67,6 +67,7 @@ config X86
 	select ARCH_CLOCKSOURCE_INIT
 	select ARCH_CONFIGURES_CPU_MITIGATIONS
 	select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
+	select ARCH_DISABLE_KASAN_INLINE	if X86_64 && KASAN_SW_TAGS
 	select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE && MIGRATION
 	select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
 	select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
@@ -196,6 +197,8 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
+	select ARCH_NEEDS_DEFER_KASAN		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -408,6 +411,7 @@ config AUDIT_ARCH
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN
+	default 0xeffffc0000000000 if KASAN_SW_TAGS
 	default 0xdffffc0000000000
 
 config HAVE_INTEL_TXT
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index db1048621ea2..ded92b439ada 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,7 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 395e133d551d..3fa63036c93c 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -7,6 +7,7 @@
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
+#ifdef CONFIG_KASAN_SW_TAGS
 /*
  * LLVM ABI for reporting tag mismatches in inline KASAN mode.
  * On x86 the UD1 instruction is used to carry metadata in the ECX register
@@ -24,7 +25,10 @@
 #define KASAN_ECX_WRITE		0x10
 #define KASAN_ECX_SIZE_MASK	0x0f
 #define KASAN_ECX_SIZE(ecx)	(1 << ((ecx) & KASAN_ECX_SIZE_MASK))
+#define KASAN_SHADOW_SCALE_SHIFT 4
+#else
 #define KASAN_SHADOW_SCALE_SHIFT 3
+#endif
 
 /*
  * Compiler uses shadow offset assuming that addresses start
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 7f5c11328ec1..3a5577341805 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -465,4 +465,10 @@ void __init kasan_init(void)
 
 	init_task.kasan_depth = 0;
 	kasan_init_generic();
+	pr_info("KernelAddressSanitizer initialized\n");
+
+	if (boot_cpu_has(X86_FEATURE_LAM))
+		kasan_init_sw_tags();
+	else
+		pr_info("KernelAddressSanitizer not initialized (sw-tags): hardware doesn't support LAM\n");
 }
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index a4bb610a7a6f..d13ea8da7bfd 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -112,7 +112,8 @@ config KASAN_SW_TAGS
 
 	  Requires GCC 11+ or Clang.
 
-	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
+	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
+	  that support Linear Address Masking.
 
 	  Consumes about 1/16th of available memory at kernel start and
 	  add an overhead of ~20% for dynamic allocations.
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/97b033941d8e146a71827cf31d4d0a12303bcc41.1765386422.git.m.wieczorretman%40pm.me.
