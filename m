Return-Path: <kasan-dev+bncBCMIFTP47IJBBQHC6G2QMGQE4MTRF5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id A99A6951723
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:33 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e0be2c7c34dsf10005020276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625792; cv=pass;
        d=google.com; s=arc-20160816;
        b=vXrvoEhBRLTst/RLHau6cyebsFEGk2KMdB7iNH7pWlPS2OBCeQ2kY2aYSJEsW0FwXt
         9o86ItMCUHDsdxvAf1XWOxDeH8Nv1lPRcAtUpL2NIeUMIlp5NhjOesotEtDshgr35a8p
         yLBBJYTjnB8bce4einWb73N24KhTfRECW/nls1P3MvGwsIwE+l69GXqjAGqtSyXYngZF
         EzcEnvJPpN/4UHVzyN1WIG8DAV2ScHv454Xv1AuiTSDsGgJv7gGtiMnT6yqD//I7/p4v
         NTwfw9u3lJAOMt6749YeXmbZNUocl3QoVLiwwwGbdyx8qfekGQZ+2SxwYTCZY3GGETas
         dL7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dGq5j0ruJ63ZdcBWRsVOwuYA8/fluFq3RT3C49rNo8A=;
        fh=X8T02RPd/PK7mYybDjHvcqy/VV/fBJq17ClSPgyt7as=;
        b=qsS0QppgQE5mhTrMralUzFghZKJj1SDJFg8OezodG0O7t6ymfDuK2RE2RjA+DzdfFP
         JS8PvoP5fVBd/oCpgzjgQEaZsbI8txjYWce67kSj0DBxP6Lf2q+LvJc2hqTRV/1EhsfF
         IzYAGtGjtekpOAbeRuOwnPtEYvngK6f7dbV0/Xk+SQPERx/Wb8g8u4xVajhFkBadJZlw
         mzfs3nYQykw6pFTkJInD90S+YDUizDx/IDQC4tMFKQJ+GUpluGAapXadecr4FJ+mGKfW
         k2yEaY301+2OCKpDpQs7wLpq4kKKj+QjmRltGVr3/pJdLtZ6FW+zuuj2Z6y8lM1IzaYk
         6Idg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=b4AN25Ls;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625792; x=1724230592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dGq5j0ruJ63ZdcBWRsVOwuYA8/fluFq3RT3C49rNo8A=;
        b=dd2WP62T6nuimMeL8MVTB46s1yateWAc8emOe8bh4wys9s2cImwJ/Z2dnHSlXLv9PW
         oSCg/csDgxbA2eTqjOp0zwz4JQ9Kye6htE8eRUet62Aw6cmUH9ukaj5Wy8sSqKR1uYX+
         lUg/2TocSCMTbgFy1OEybobR6QqNgeeq11XjkIMiuR5gjDS15D5sOWxCMLBj72o+rvD0
         xMttwRlIPQkLew//Eh8S6s7b2f+nUOe26eZJmdwb54wzXyhQUuDaQP+y/+HVcqjpjZym
         KDqxj6zeluIt73lFugCCwdMJjns16SyRCu2TdRIi5/MhYoFD5X7tPlv5Zi5LnnYNgLzE
         7KWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625792; x=1724230592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dGq5j0ruJ63ZdcBWRsVOwuYA8/fluFq3RT3C49rNo8A=;
        b=KOK34XELTVSx2EFwGBgQkPe9rccWS9uyN2K3HfDBLKTLSq561g/JPrSnQ1jNg2uhqD
         pe9XACGbAOOEVhpNrNVpKZcuVcPw0nUkijsayH7WXFziCl35v+y7l8dOfxCBMYJuNxMa
         UyLGzeSOh62CNt5WgET9KHxT3ETIVS3xKRvUEhn+Sez/PYLBkBzaDGQ4EVJ7phr3SddL
         F31r+ldnMGq5bIuK+eIS26Ffp9czHbUeFaGV3bMW99XNAln1xzIjvHFm6GthRAV8Io2U
         kLPgdPwwR73idCQc4miL1FxgfV77O9kq2qA8BLMqJZL1+p5vHmH6k/gkTVDVxx5l3UYV
         zZ/g==
X-Forwarded-Encrypted: i=2; AJvYcCXQDWFmZRvF2DQVFxgIDloMqu96u0CB5szs+vE8NfbnCIt2DhsPaSBCaIE6zGEIssrR7YD1kg==@lfdr.de
X-Gm-Message-State: AOJu0Yxmlf4vyadhxB0CGpCfZ+4CahOLYXh3+qxlKhB368QNW8VNS5Zr
	3kRyM9NKefDhBAbTOSMsPJpKHjHDLyH2RKTGg3pUX1CahQt20SyE
X-Google-Smtp-Source: AGHT+IESisnzguwA4II0bVsm3Q1rZz+pHtoTaLaf6UizG9mfHvEpDl6B3muSwoxKwIlzYZn4prWsgw==
X-Received: by 2002:a05:6902:248c:b0:e08:6476:e27a with SMTP id 3f1490d57ef6-e1155ae4d4amr2205102276.28.1723625792540;
        Wed, 14 Aug 2024 01:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:154a:b0:e03:aded:7d3a with SMTP id
 3f1490d57ef6-e0e976cd2a8ls3595638276.1.-pod-prod-06-us; Wed, 14 Aug 2024
 01:56:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW46r4g4DbGnMTtH30zlEaBNgJdqbRV5fc3Y0/VGeQCHE9jyq6Ymo2vHCb1HS1ry7UD9kd/d2AvAf0=@googlegroups.com
X-Received: by 2002:a05:690c:3483:b0:63b:df6e:3f6d with SMTP id 00721157ae682-6ac9aa3e5d5mr20808687b3.37.1723625791672;
        Wed, 14 Aug 2024 01:56:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625791; cv=none;
        d=google.com; s=arc-20160816;
        b=DCJ1WwTPCJU9qe/P3jks7oL/FsgIKrtm5nAjlsC3xPwySDzVPUUYsja6YX8GEULW44
         o5rNXwfNkVuY66LFkoFJp1z5/80kE+vb4mFiFalbtdhf5OKOediq4/d/fOOl/68LMm05
         LkYPLz3mk5UA5wdwTqcmdAMfqK1TIs2tKy7QtA09CPUxe+Ki7SiEfr06F3tzmqqd6UBm
         AKLtUJb/x+Sfa+BbWSqPLQxs7ewxw1GuzN9IPddWHMKGpEtzHrFLgTAgnjxStAkV7bG+
         3wxgZTIe44HYak98zKt/0jWw94HMjJYMKaCGE9H9jHzzDgSFAdxG5sDsWcDv4CEMMiVU
         Q1PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xswnBLwHxJrHYsJkrECwj9jBmYSXx50wzmQACaoOJYE=;
        fh=Lhuymk9sIH8Uuvyut+80B7ccH3Icp+mY90+DDHUNWUo=;
        b=LW0AOVt3eVOk7RqtdFzV/Bo48D1G8wffpgseTXc8g0gTdrLFcIGHII2x4nsnRe9uQ0
         lkpudHsNfU/wSYeqC4z7zUBQqqahOKrZjN/wqIG74gaNMJivGSTmUyE/pe3zU8e9BcHT
         hh8BUVuos8XZs6QDwYqdg+oBDSgZBrKANPJUHRzfQBz8qa8dtRkZsZXcqnegV7ucu8p1
         5G+n5uHLS+a4acvsqqrP2dnn+mAE+JoVVySMladpj8PAMTHvgJLN2U8gVE4IxRp/pYQ3
         THcRIKnr6a+ZqFeWe5mdt7IS2aox5G7JEDXzvEzFXi7Iq6GYQk/TkwGSL8Hoj2WwaKsS
         Je8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=b4AN25Ls;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6a09a309efcsi4551117b3.0.2024.08.14.01.56.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-70f5ef740b7so5685910b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV26V1+tLSTxCp3G5wM1cNmhhJAA29LC4JdJRFHNf9mQtHv4Wi4M10x9jlXc5fzv8OqF5ifcm46yOs=@googlegroups.com
X-Received: by 2002:a05:6a20:9e4b:b0:1c4:bde5:174b with SMTP id adf61e73a8af0-1c8eaf7db28mr2708359637.41.1723625791103;
        Wed, 14 Aug 2024 01:56:31 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:30 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 6/7] riscv: Implement KASAN_SW_TAGS
Date: Wed, 14 Aug 2024 01:55:34 -0700
Message-ID: <20240814085618.968833-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=b4AN25Ls;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"
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

Implement support for software tag-based KASAN using the RISC-V pointer
masking extension, which supports 7 and/or 16-bit tags. This implemen-
tation uses 7-bit tags, so it is compatible with either hardware mode.

Pointer masking is an optional ISA extension, and it must be enabled
using an SBI call to firmware on each CPU. This SBI call must be made
very early in smp_callin(), as dereferencing any tagged pointers before
that point will crash the kernel. If the SBI call fails on the boot CPU,
then KASAN is globally disabled, and the kernel boots normally (unless
stack tagging is enabled). If the SBI call fails on any other CPU, that
CPU is excluded from the system.

When pointer masking is enabled for the kernel's privilege mode, it must
be more careful about accepting tagged pointers from userspace.
Normally, __access_ok() accepts tagged aliases of kernel memory as long
as the MSB is zero, since those addresses cannot be dereferenced -- they
will cause a page fault in the uaccess routines. But when the kernel is
using pointer masking, those addresses are dereferenceable, so
__access_ok() must specifically check the most-significant non-tag bit.

Pointer masking does not apply to the operands of fence instructions, so
software is responsible for untagging those addresses.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 Documentation/dev-tools/kasan.rst | 14 ++++---
 arch/riscv/Kconfig                |  4 +-
 arch/riscv/include/asm/cache.h    |  4 ++
 arch/riscv/include/asm/kasan.h    | 20 ++++++++++
 arch/riscv/include/asm/page.h     | 19 ++++++++--
 arch/riscv/include/asm/pgtable.h  |  6 +++
 arch/riscv/include/asm/tlbflush.h |  4 +-
 arch/riscv/kernel/setup.c         |  6 +++
 arch/riscv/kernel/smpboot.c       |  8 +++-
 arch/riscv/lib/Makefile           |  2 +
 arch/riscv/lib/kasan_sw_tags.S    | 61 +++++++++++++++++++++++++++++++
 arch/riscv/mm/kasan_init.c        | 30 ++++++++++++++-
 arch/riscv/mm/physaddr.c          |  4 ++
 13 files changed, 167 insertions(+), 15 deletions(-)
 create mode 100644 arch/riscv/lib/kasan_sw_tags.S

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index d7de44f5339d..6548aebac57f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,8 +22,8 @@ architectures, but it has significant performance and memory overheads.
 
 Software Tag-Based KASAN or SW_TAGS KASAN, enabled with CONFIG_KASAN_SW_TAGS,
 can be used for both debugging and dogfood testing, similar to userspace HWASan.
-This mode is only supported for arm64, but its moderate memory overhead allows
-using it for testing on memory-restricted devices with real workloads.
+This mode is only supported on arm64 and riscv, but its moderate memory overhead
+allows using it for testing on memory-restricted devices with real workloads.
 
 Hardware Tag-Based KASAN or HW_TAGS KASAN, enabled with CONFIG_KASAN_HW_TAGS,
 is the mode intended to be used as an in-field memory bug detector or as a
@@ -340,12 +340,14 @@ Software Tag-Based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
 Software Tag-Based KASAN uses a software memory tagging approach to checking
-access validity. It is currently only implemented for the arm64 architecture.
+access validity. It is currently only implemented for the arm64 and riscv
+architectures.
 
 Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
-to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
-to store memory tags associated with each 16-byte memory cell (therefore, it
-dedicates 1/16th of the kernel memory for shadow memory).
+or the pointer masking (Sspm) feature of RISC-V CPUs to store a pointer tag in
+the top byte of kernel pointers. It uses shadow memory to store memory tags
+associated with each 16-byte memory cell (therefore, it dedicates 1/16th of the
+kernel memory for shadow memory).
 
 On each memory allocation, Software Tag-Based KASAN generates a random tag, tags
 the allocated memory with this tag, and embeds the same tag into the returned
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 0f3cd7c3a436..b963f7cea3b8 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -117,6 +117,7 @@ config RISCV
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE if !XIP_KERNEL
 	select HAVE_ARCH_KASAN if MMU && 64BIT
+	select HAVE_ARCH_KASAN_SW_TAGS if MMU && 64BIT
 	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
 	select HAVE_ARCH_KFENCE if MMU && 64BIT
 	select HAVE_ARCH_KGDB if !XIP_KERNEL
@@ -277,7 +278,8 @@ config PAGE_OFFSET
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN_GENERIC
+	depends on KASAN
+	default 0xffffffff00000000 if KASAN_SW_TAGS
 	default 0xdfffffff00000000 if 64BIT
 	default 0xffffffff if 32BIT
 
diff --git a/arch/riscv/include/asm/cache.h b/arch/riscv/include/asm/cache.h
index 570e9d8acad1..232288a060c6 100644
--- a/arch/riscv/include/asm/cache.h
+++ b/arch/riscv/include/asm/cache.h
@@ -16,6 +16,10 @@
 #define ARCH_KMALLOC_MINALIGN	(8)
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#endif
+
 /*
  * RISC-V requires the stack pointer to be 16-byte aligned, so ensure that
  * the flat loader aligns it accordingly.
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
index a4e92ce9fa31..f6b378ba936d 100644
--- a/arch/riscv/include/asm/kasan.h
+++ b/arch/riscv/include/asm/kasan.h
@@ -25,7 +25,11 @@
  *      KASAN_SHADOW_OFFSET = KASAN_SHADOW_END -
  *                              (1ULL << (64 - KASAN_SHADOW_SCALE_SHIFT))
  */
+#if defined(CONFIG_KASAN_GENERIC)
 #define KASAN_SHADOW_SCALE_SHIFT	3
+#elif defined(CONFIG_KASAN_SW_TAGS)
+#define KASAN_SHADOW_SCALE_SHIFT	4
+#endif
 
 #define KASAN_SHADOW_SIZE	(UL(1) << ((VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
 /*
@@ -37,6 +41,14 @@
 
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_TAG_KERNEL	0x7f /* native kernel pointers tag */
+#endif
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
+
 void kasan_init(void);
 asmlinkage void kasan_early_init(void);
 void kasan_swapper_init(void);
@@ -48,5 +60,13 @@ void kasan_swapper_init(void);
 
 #endif /* CONFIG_KASAN */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+bool kasan_boot_cpu_enabled(void);
+int kasan_cpu_enable(void);
+#else
+static inline bool kasan_boot_cpu_enabled(void) { return false; }
+static inline int kasan_cpu_enable(void) { return 0; }
+#endif
+
 #endif
 #endif /* __ASM_KASAN_H */
diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 09d15567b0b8..d4f038466f1d 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -89,6 +89,16 @@ typedef struct page *pgtable_t;
 #define PTE_FMT "%08lx"
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define __tag_set(addr, tag)	((void *)((((u64)(addr) << 7) >> 7) | ((u64)(tag) << 57)))
+#define __tag_reset(addr)	((void *)((s64)((u64)(addr) << 7) >> 7))
+#define __tag_get(addr)		((u8)((u64)(addr) >> 57))
+#else
+#define __tag_set(addr, tag)	(addr)
+#define __tag_reset(addr)	(addr)
+#define __tag_get(addr)		0
+#endif
+
 #if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
 /*
  * We override this value as its generic definition uses __pa too early in
@@ -155,7 +165,7 @@ phys_addr_t linear_mapping_va_to_pa(unsigned long x);
 	})
 
 #define __va_to_pa_nodebug(x)	({						\
-	unsigned long _x = x;							\
+	unsigned long _x = (unsigned long)__tag_reset(x);			\
 	is_linear_mapping(_x) ?							\
 		linear_mapping_va_to_pa(_x) : kernel_mapping_va_to_pa(_x);	\
 	})
@@ -179,7 +189,10 @@ extern phys_addr_t __phys_addr_symbol(unsigned long x);
 #define pfn_to_virt(pfn)	(__va(pfn_to_phys(pfn)))
 
 #define virt_to_page(vaddr)	(pfn_to_page(virt_to_pfn(vaddr)))
-#define page_to_virt(page)	(pfn_to_virt(page_to_pfn(page)))
+#define page_to_virt(page)	({						\
+	__typeof__(page) __page = page;						\
+	__tag_set(pfn_to_virt(page_to_pfn(__page)), page_kasan_tag(__page));	\
+})
 
 #define page_to_phys(page)	(pfn_to_phys(page_to_pfn(page)))
 #define phys_to_page(paddr)	(pfn_to_page(phys_to_pfn(paddr)))
@@ -196,7 +209,7 @@ static __always_inline void *pfn_to_kaddr(unsigned long pfn)
 #endif /* __ASSEMBLY__ */
 
 #define virt_addr_valid(vaddr)	({						\
-	unsigned long _addr = (unsigned long)vaddr;				\
+	unsigned long _addr = (unsigned long)__tag_reset(vaddr);		\
 	(unsigned long)(_addr) >= PAGE_OFFSET && pfn_valid(virt_to_pfn(_addr));	\
 })
 
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 089f3c9f56a3..1b3bd1ff643a 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -910,7 +910,13 @@ static inline pte_t pte_swp_clear_exclusive(pte_t pte)
  */
 #ifdef CONFIG_64BIT
 #define TASK_SIZE_64	(PGDIR_SIZE * PTRS_PER_PGD / 2)
+/*
+ * When pointer masking is enabled for the kernel's privilege mode,
+ * __access_ok() must reject tagged aliases of kernel memory.
+ */
+#ifndef CONFIG_KASAN_SW_TAGS
 #define TASK_SIZE_MAX	LONG_MAX
+#endif
 
 #ifdef CONFIG_COMPAT
 #define TASK_SIZE_32	(_AC(0x80000000, UL) - PAGE_SIZE)
diff --git a/arch/riscv/include/asm/tlbflush.h b/arch/riscv/include/asm/tlbflush.h
index 72e559934952..68b3a85c6960 100644
--- a/arch/riscv/include/asm/tlbflush.h
+++ b/arch/riscv/include/asm/tlbflush.h
@@ -31,14 +31,14 @@ static inline void local_flush_tlb_all_asid(unsigned long asid)
 /* Flush one page from local TLB */
 static inline void local_flush_tlb_page(unsigned long addr)
 {
-	ALT_SFENCE_VMA_ADDR(addr);
+	ALT_SFENCE_VMA_ADDR(__tag_reset(addr));
 }
 
 static inline void local_flush_tlb_page_asid(unsigned long addr,
 					     unsigned long asid)
 {
 	if (asid != FLUSH_TLB_NO_ASID)
-		ALT_SFENCE_VMA_ADDR_ASID(addr, asid);
+		ALT_SFENCE_VMA_ADDR_ASID(__tag_reset(addr), asid);
 	else
 		local_flush_tlb_page(addr);
 }
diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index a2cde65b69e9..fdc72edc4857 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -299,6 +299,12 @@ void __init setup_arch(char **cmdline_p)
 	riscv_user_isa_enable();
 }
 
+void __init smp_prepare_boot_cpu(void)
+{
+	if (kasan_boot_cpu_enabled())
+		kasan_init_sw_tags();
+}
+
 bool arch_cpu_is_hotpluggable(int cpu)
 {
 	return cpu_has_hotplug(cpu);
diff --git a/arch/riscv/kernel/smpboot.c b/arch/riscv/kernel/smpboot.c
index 0f8f1c95ac38..a1cc555691b0 100644
--- a/arch/riscv/kernel/smpboot.c
+++ b/arch/riscv/kernel/smpboot.c
@@ -29,6 +29,7 @@
 #include <asm/cacheflush.h>
 #include <asm/cpu_ops.h>
 #include <asm/irq.h>
+#include <asm/kasan.h>
 #include <asm/mmu_context.h>
 #include <asm/numa.h>
 #include <asm/tlbflush.h>
@@ -210,7 +211,11 @@ void __init smp_cpus_done(unsigned int max_cpus)
 asmlinkage __visible void smp_callin(void)
 {
 	struct mm_struct *mm = &init_mm;
-	unsigned int curr_cpuid = smp_processor_id();
+	unsigned int curr_cpuid;
+
+	/* Must be called first, before referencing any dynamic allocations */
+	if (kasan_boot_cpu_enabled() && kasan_cpu_enable())
+		return;
 
 	if (has_vector()) {
 		/*
@@ -225,6 +230,7 @@ asmlinkage __visible void smp_callin(void)
 	mmgrab(mm);
 	current->active_mm = mm;
 
+	curr_cpuid = smp_processor_id();
 	store_cpu_topology(curr_cpuid);
 	notify_cpu_starting(curr_cpuid);
 
diff --git a/arch/riscv/lib/Makefile b/arch/riscv/lib/Makefile
index 8eec6b69a875..ae36616fe1f5 100644
--- a/arch/riscv/lib/Makefile
+++ b/arch/riscv/lib/Makefile
@@ -20,3 +20,5 @@ lib-$(CONFIG_RISCV_ISA_ZBC)	+= crc32.o
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 lib-$(CONFIG_RISCV_ISA_V)	+= xor.o
 lib-$(CONFIG_RISCV_ISA_V)	+= riscv_v_helpers.o
+
+obj-$(CONFIG_KASAN_SW_TAGS) += kasan_sw_tags.o
diff --git a/arch/riscv/lib/kasan_sw_tags.S b/arch/riscv/lib/kasan_sw_tags.S
new file mode 100644
index 000000000000..f7d3e0acba6a
--- /dev/null
+++ b/arch/riscv/lib/kasan_sw_tags.S
@@ -0,0 +1,61 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+/*
+ * Copyright (C) 2020 Google LLC
+ * Copyright (C) 2024 SiFive
+ */
+
+#include <linux/linkage.h>
+
+/*
+ * Report a tag mismatch detected by tag-based KASAN.
+ *
+ * A compiler-generated thunk calls this with a custom calling convention.
+ * Upon entry to this function, the following registers have been modified:
+ *
+ *   x1/ra:     clobbered by call to this function
+ *   x2/sp:     decremented by 256
+ *   x6/t1:     tag from shadow memory
+ *   x7/t2:     tag from pointer
+ *   x10/a0:    fault address
+ *   x11/a1:    fault description
+ *   x28/t3:    clobbered by thunk
+ *   x29/t4:    clobbered by thunk
+ *   x30/t5:    clobbered by thunk
+ *   x31/t6:    clobbered by thunk
+ *
+ * The caller has decremented the SP by 256 bytes, and stored the following
+ * registers in slots on the stack according to their number (sp + 8 * xN):
+ *
+ *   x1/ra:     return address to user code
+ *   x8/s0/fp:  saved value from user code
+ *   x10/a0:    saved value from user code
+ *   x11/a1:    saved value from user code
+ */
+SYM_CODE_START(__hwasan_tag_mismatch)
+	/* Store the remaining unclobbered caller-saved regs */
+	sd	t0, (8 *  5)(sp)
+	sd	a2, (8 * 12)(sp)
+	sd	a3, (8 * 13)(sp)
+	sd	a4, (8 * 14)(sp)
+	sd	a5, (8 * 15)(sp)
+	sd	a6, (8 * 16)(sp)
+	sd	a7, (8 * 17)(sp)
+
+	/* a0 and a1 are already set by the thunk */
+	ld	a2, (8 *  1)(sp)
+	call	kasan_tag_mismatch
+
+	ld	ra, (8 *  1)(sp)
+	ld	t0, (8 *  5)(sp)
+	ld	a0, (8 * 10)(sp)
+	ld	a1, (8 * 11)(sp)
+	ld	a2, (8 * 12)(sp)
+	ld	a3, (8 * 13)(sp)
+	ld	a4, (8 * 14)(sp)
+	ld	a5, (8 * 15)(sp)
+	ld	a6, (8 * 16)(sp)
+	ld	a7, (8 * 17)(sp)
+	addi	sp, sp, 256
+	ret
+SYM_CODE_END(__hwasan_tag_mismatch)
+EXPORT_SYMBOL(__hwasan_tag_mismatch)
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index c301c8d291d2..b247c56206c5 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -11,6 +11,10 @@
 #include <asm/fixmap.h>
 #include <asm/pgalloc.h>
 
+#ifdef CONFIG_KASAN_SW_TAGS
+static bool __kasan_boot_cpu_enabled __ro_after_init;
+#endif
+
 /*
  * Kasan shadow region must lie at a fixed address across sv39, sv48 and sv57
  * which is right before the kernel.
@@ -323,8 +327,11 @@ asmlinkage void __init kasan_early_init(void)
 {
 	uintptr_t i;
 
-	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
-		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
+			KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	else
+		BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);
 
 	for (i = 0; i < PTRS_PER_PTE; ++i)
 		set_pte(kasan_early_shadow_pte + i,
@@ -356,6 +363,8 @@ asmlinkage void __init kasan_early_init(void)
 				 KASAN_SHADOW_START, KASAN_SHADOW_END);
 
 	local_flush_tlb_all();
+
+	__kasan_boot_cpu_enabled = !kasan_cpu_enable();
 }
 
 void __init kasan_swapper_init(void)
@@ -534,3 +543,20 @@ void __init kasan_init(void)
 	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
 	local_flush_tlb_all();
 }
+
+#ifdef CONFIG_KASAN_SW_TAGS
+bool kasan_boot_cpu_enabled(void)
+{
+	return __kasan_boot_cpu_enabled;
+}
+
+int kasan_cpu_enable(void)
+{
+	struct sbiret ret;
+
+	/* sbi_fwft_set(POINTER_MASKING_PMLEN, 7, 0); */
+	ret = sbi_ecall(0x46574654, 0, 5, 7, 0, 0, 0, 0);
+
+	return sbi_err_map_linux_errno(ret.error);
+}
+#endif
diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
index 18706f457da7..6d1cf6ffd54e 100644
--- a/arch/riscv/mm/physaddr.c
+++ b/arch/riscv/mm/physaddr.c
@@ -8,6 +8,8 @@
 
 phys_addr_t __virt_to_phys(unsigned long x)
 {
+	x = __tag_reset(x);
+
 	/*
 	 * Boundary checking aginst the kernel linear mapping space.
 	 */
@@ -24,6 +26,8 @@ phys_addr_t __phys_addr_symbol(unsigned long x)
 	unsigned long kernel_start = kernel_map.virt_addr;
 	unsigned long kernel_end = kernel_start + kernel_map.size;
 
+	x = __tag_reset(x);
+
 	/*
 	 * Boundary checking aginst the kernel image mapping.
 	 * __pa_symbol should only be used on kernel symbol addresses.
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-7-samuel.holland%40sifive.com.
