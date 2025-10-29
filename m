Return-Path: <kasan-dev+bncBAABB5HJRHEAMGQE6COJM3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 09D32C1D2A6
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:11:34 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-63c585eb47bsf164210a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:11:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768693; cv=pass;
        d=google.com; s=arc-20240605;
        b=BOfmPDBGZcwrYtR8fC8mfLbTm2/d+YnIte44mJSqa+8PJ7IHugLc2T4QoNT/l6XB4a
         l4pi1GqsIP3LdPoYaeCGi8jeuHcg0yjptiJ1g9TovsCXDIZun8KZg3Jf9YcaKWGeNgJp
         VEzYuITPRYeM2qBGElaJLQXhWrjTqca/wjEdDeMLveFqf18SZ5PMdXMm+IClkuUhs3c3
         I2Sgi7T1PDBHEsHLpR69RHQbC3DSnKMx78lo/h7rv0a3tswGs2Crs/dHhRBCq8P2x/s8
         SlHi/TDOnDYuLUWy19NOASIeEEZ02yCQdStkK1SJ9OcT749tJsi5RhZuxuw2TSgq6Ct5
         d7mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=ERgrRKWD6A7s8bqJJ9YfS7qCZ7iB7+xKvCxe2CyDVKI=;
        fh=jsolKaIXUIJCvEIFr7s/+gLxQpfe+OBhNeuvD+pOrWs=;
        b=KG7mLIracnzQgDDSw+r8SolNNaSJ7FMkRoRvCCfT6Rph3Gld2mMtVxJQlGiyy0UeaL
         OhurnhgGmrcTVU6BNXyiIUyCD7S7P19mj4vWX8AV2fj88hXiIEclyF8yXxRDLbGnHLhh
         bBZNjT7Y3qbdnBv5ACKi2JU5fSNbU/omvvljeUSgmQWl6JE5Zea0JSl4LJAXsrrnzmW+
         dDEuixJDpAprVJOqzngdiJob4/uv8JGznDunRDBzvpqsbp/sWuXWVgTQq33+1k13q7Um
         4Pw9Unir0nmwtTi3l7HAlS/xNu4OZHN1C2IsCBl2THeY5lJlrY7XcX/V5qB/srjM7sJh
         0Y7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=cXdMGkjY;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768693; x=1762373493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=ERgrRKWD6A7s8bqJJ9YfS7qCZ7iB7+xKvCxe2CyDVKI=;
        b=SRVfzoa/umkoIf3nV0OHm/6FquI9XhNRfnzmshPVYTIJytkSnHhlAf/QZFZvhuKVjs
         2frfcCkPHq8WYkDTRSUFBqZH/H00c06IMcmY26akF2WNejC0vOS3ugJUl6E4I32zbof9
         ty+1nhCv0zn707BPiZHd5Z3nv0PZWY1Jttxdxt7inybBj7U2ku85G2Pa4k0Qit4ptuqA
         9sWUgOqSrd9LDTK+4DGPYWY3Dxr5+/XGcNNFC5gWjdUj2hOHTBnrC/tloEolmrEapQkY
         TLPLdSFsLEZRz1zYUYnU6FEGc7vMUUVdrnIQrWQrKPDWZgoQPUb48zbkb8a/61woDWnt
         cEnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768693; x=1762373493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ERgrRKWD6A7s8bqJJ9YfS7qCZ7iB7+xKvCxe2CyDVKI=;
        b=u6prkzABOLjGFBDnIRtyoiIiRz6TvdBHSWzR9jLg9P8RTm8ynY2NP2HwkC74py5Sat
         jqX+1XbndBSTpsAbOgr8fOcvCXX9aAEFEiKJs3vQwQq03k0ePRCy5vcMLLbQjFoPFv4g
         JFmnnbhUpAmIvijOzMHeNJ4AEFjiY8DAl62iKDoB8sVRHlOq2Mh0LurPbD3xx0QQaOLD
         9a4ATEVzMD8X7qzLQip/QBlrUQUCqiwxt6pG3zLlAvdem60RWaE8+ryR7Qz5Nfefksla
         +qokzEgyhf1wfDG7M6pV3IQpys8os7+BtILAJW5uZpqCwbGSMazGjic54/mrszMn7ogK
         b9JA==
X-Forwarded-Encrypted: i=2; AJvYcCUaFCD5AHHN2Nx/tuw0DRa3BQXB03qK/ydOQ+hEotaxXHvyn/V+5JT8fJZpI++vcX1wZ83kbQ==@lfdr.de
X-Gm-Message-State: AOJu0YzYqUJm6BwBh/3uuajYhiaA/FLsrqGPTvC3vJkpbv4k2Eg9qxZF
	tDXxcGpnS9GOnld/5dPUuRrsL72MnQFszwDQERHMUmWnxbPW8ONszSA+
X-Google-Smtp-Source: AGHT+IGqaLauR+t6WrHr93JHN8SLhq4CJG5VIj7aujHEHQAEHktWpiGTl6aZWuF7dqeBmViI2lAbCA==
X-Received: by 2002:a50:c01e:0:b0:640:1bfb:66a2 with SMTP id 4fb4d7f45d1cf-6405e734a14mr536664a12.0.1761768693397;
        Wed, 29 Oct 2025 13:11:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bxSMMZ2BN7GP3HT82He7qNW63oXsXuLYGLO+O6HEhVVA=="
Received: by 2002:a05:6402:305c:20b0:63c:4828:e891 with SMTP id
 4fb4d7f45d1cf-6405fa5e704ls82470a12.2.-pod-prod-00-eu; Wed, 29 Oct 2025
 13:11:31 -0700 (PDT)
X-Received: by 2002:a05:6402:438e:b0:63b:fdf2:de76 with SMTP id 4fb4d7f45d1cf-6405efc4dfemr659280a12.15.1761768691155;
        Wed, 29 Oct 2025 13:11:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768691; cv=none;
        d=google.com; s=arc-20240605;
        b=Gxp4jLO3AnEeI/7+7Kwbkc7r3B3C/3wfyjxDiPq8l8PWcio1Es59mh1rjb/5TECTZE
         LJ/6LouZjF9IZod9morWUwkzFd9TvrJl7BggE8wtQYjyrtwjKeaevyuXQzU4lJsT/S+c
         EKVybQTJVdjnzz5kAx+DRPWk0cZpFR11mE1+rWEOemsTBPEo77cyxROx0oknGQMzEUw2
         1eLzpwHQco0fkmbe2Sz/cf1hPDVzu0LZf1x97xKiMPVEukbAlzgggvFU9eCiAUZr5IV2
         FIgg8oKyIoLAGvdOB5ZcZbBGlIROhw2IoFnL+QNZk/lR9CLPROoI8v88lXLC9DPhzbH0
         EI8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=801m/BDnq+4IDZrRjH01sT6fZRZq5h0m340QBaMU7xk=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=IAqQGEK88JWim/XucuxLLHor/ckhwxw9gCLrlWVmRSb4d924zklJ5O960hmNv9bwBx
         4CPrt73vWGnb3vKjpAP3YtV6c5G9Vw6vI40MZFb8h4XmL1U0bZEYIJZ78vvm/Vnfdn+i
         s3E8IP6qqLKfH7bioGf8wVxKQ0KX5JIeH9EWQXlfGDeWDd54jqlmGrt+sVCsXHU+aSa/
         5N41H4dtBi4YbTX/S1+GqxrRrgAqu49XQdLnrLLhrqDBiU/OK3i6fDWPpYCzpWkXjtR9
         3DxC7bEarZnLwcA69+4MqlA0oShaBHafcpLkzi1QgKFzyNGokN/Cq+2EIdjJWnRWTCgS
         trng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=cXdMGkjY;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e814b0616si223852a12.5.2025.10.29.13.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:11:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Wed, 29 Oct 2025 20:11:22 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 18/18] x86/kasan: Make software tag-based kasan available
Message-ID: <d98f04754c3f37f153493c13966c1e02852f551d.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: f951758d099748a231d1551fe212ba144d88e29b
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=cXdMGkjY;       spf=pass
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
support is available.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
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
 arch/x86/mm/kasan_init_64.c          | 5 +++++
 lib/Kconfig.kasan                    | 3 ++-
 6 files changed, 20 insertions(+), 3 deletions(-)

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
index fa3b616af03a..7c73a2688172 100644
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
@@ -406,6 +409,7 @@ config AUDIT_ARCH
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
index 2372397bc3e5..8320fffc71a1 100644
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
index e69b7210aaae..4a5a4a4d43db 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -465,4 +465,9 @@ void __init kasan_init(void)
 
 	init_task.kasan_depth = 0;
 	kasan_init_generic();
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
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d98f04754c3f37f153493c13966c1e02852f551d.1761763681.git.m.wieczorretman%40pm.me.
