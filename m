Return-Path: <kasan-dev+bncBDT2NE7U5UFRBZHJRSZAMGQEIKJFC7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 32B218C4EB0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 11:54:46 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-36c89052654sf68752395ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 02:54:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715680485; cv=pass;
        d=google.com; s=arc-20160816;
        b=PeXTc0FyC6XtWB8oQHao/ajjNMrpE/0mjnuTnnua8rFJU8BnGZYIbb7x0rYUEnXEzX
         Za2x04qgxlOhKwW89pRchijVrGCXTfOGmKn7ye/N2X9x7nBHbMHEcNAm8fKkMpzMzpNp
         410OgGjyusN8++P+33Sk/RhKtm3RUIdnw5GH0tLvm+VpEWi16jZC5kQ+8PU8xv7FtuSU
         DMdjEExjEaVPa7S4mDkKOzT0O5IvMLEtwTNt0W/fwKxrg5EaGwOePj5DHUOht54eVwag
         Hii9gwSju05FO+fuRLQ2bb7uCn0+9qA+M3305MsSrhnTDo0s4dsNXFxRBbHS/OKxxcRT
         ig6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=lNfCot2rs4S8BzuTO+cciUt02UdF2nN6cfKcHDPsNws=;
        fh=khclkN6JGljeNMVGOaPTL+lq1alXuvjfIHtpDXRhRJI=;
        b=dkYOC8yGcPj1D36TV/fZyGp6v44hcWoGq8cePf5fHcHWL0RU7cTcLdHqeFX9haKZRq
         7uSdOdcyCt/AK9avXweimYUWketHxaK31QXUKqejD/ZPc4bF8HC/77H/9dVM061A//gb
         dSBnmGtP8fYodtMpIPnkFFAyit2hESz/im1IlZCY8UsES1n3a8NYRd5fWg0RFcwCxwrl
         P7F150jxHEoAQx+FYaIvM4go6vKw+E3sUvJanmZHk5S1QhIUfyqKJhfPs1xPhowz7X1G
         BKEcu2fL1dJOgmgEd7BvG3+4JllwbRSCcBXPu35oC7aAn9pUo5P47rlLmzxlifOwnM09
         5fRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jTv9LLcT;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715680485; x=1716285285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lNfCot2rs4S8BzuTO+cciUt02UdF2nN6cfKcHDPsNws=;
        b=JrkZZOKBh9uiOUXQPJaZcMM+bD9JUNS8bZFj1AUP+iL5KmTVhHvGPyQxLsepHaO4vx
         83rCZcIuc7xjdRnwEK6mbY73QOQN3mUaiIhRvabmoaRAhSK+9Me43JuK3aesfBZ0qCYE
         Y0w/aa0uXY3xJUUwe3IoJn2YPiep3bvXbsY48+ZYTLhumNmg8dJzXtRsgakEZUqO7Se9
         Nt9IxN3LBfVBSDrIp+t02gOLbdGope+OT3igF+PHeppk+YtHkBucVO43z5DmV+B+QJVu
         VmfTk6Em7gAQvVeXFZ9r0WjMPmZt4wwQQjdWMI8Cilkp6wEIXDhvLJiPhNLYHgcGvt/D
         F0qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715680485; x=1716285285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lNfCot2rs4S8BzuTO+cciUt02UdF2nN6cfKcHDPsNws=;
        b=e7NYxJx0WRrj/QOSRHHkXFZhHHOWP4TKObquekW6QiMwF2JC/ow+rlsm8OCEITkt+0
         i/xT85sqA+5/BJfY6GmcLrr1yP8Nw/keETHtKUHExJ8CNdDaKChLlX4KTd8lyfOV9DyY
         29K1U0oxA5FiaVdQ6s4ypFcaDgYx15DbS4qOitGU3/3P+oTAwYypjdyjCW4+nWaRyZoI
         OWLqOweM/htnBBGVU5oTNp+SpGMOg/o/ukPtc7bZuuZzSGRr0vMAjVGXdi4CauAABcej
         ichWBrxoG37qU7NEpRRsL/pq+P6An6MZsIH48JNVxZz2AaVGr4QU1ZP2lGkdv2MdGw6O
         Z2tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUPyof64g+fTP8VYd2B3b6a2taINSP2EMxiFgvqlZRhuqotZGVFIBhTjyE8upHodw6ZyUJjpvZpdxLhSl2ETOFUWnaEFV2NA==
X-Gm-Message-State: AOJu0YwxFK9uhYl2QLKSkWgISCNyeKJyRDqJdskVyYnAbh9NRod12k4n
	Kx5XhiHSBIM3dme5/KluKLZvBsfh4GEPuIP5D9bJj7arqSfdCXyv
X-Google-Smtp-Source: AGHT+IF7CKRbAoDmMQut4hWqzGopw7iXMLHEUZNxqSg4YNrsGTh4BpGeIFLwK+A5XacC1LrdRid4tQ==
X-Received: by 2002:a05:6e02:1a49:b0:36d:a962:b19d with SMTP id e9e14a558f8ab-36da962b3d6mr27786225ab.14.1715680484486;
        Tue, 14 May 2024 02:54:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d9d:b0:36d:a927:3593 with SMTP id
 e9e14a558f8ab-36da9273754ls6217095ab.1.-pod-prod-09-us; Tue, 14 May 2024
 02:54:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsghqzEzoxgMkQDO5VKOqY3yeD9FnA5oRx+KwBE8QGgZCLQbcm8s3r08KaV3+pt6D0sRrz9g9Nwl8GpqsXEDIVp8UdybhbEnr/uA==
X-Received: by 2002:a92:ca08:0:b0:36c:11a0:9d62 with SMTP id e9e14a558f8ab-36cc1486327mr158165835ab.7.1715680483576;
        Tue, 14 May 2024 02:54:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715680483; cv=none;
        d=google.com; s=arc-20160816;
        b=L1LwrSdYu6vU1AUu4xB9toElpYLnOC0f1L0VLkWAXQNtaUJjyMqFukYjPXntDDyk0+
         OivcWHklnBE4puDPaIizzuQp6Auyksd3jKuJyjWcfkqVFj90/JLSybQGtO9zF5GaJ7l3
         uI169jEn+fEsOOH69ikPiHXqC2Rvo7mzU9bCp3yNIj/+tWxl/y5FrJ33EVcDRFIiQZOD
         nG+Xqmb4LxmaOJnH2glyrdi6dzeKiH9BcaQbMlktYtKsl9aU15TDMlV1Cat3u5DFxTnA
         bzJlE7yTGpaIespmyeSjehtQi6cLPTZXgjKyTMgR7pJ9hN85XZ4ZLkttKxV33uTzxPEK
         vWJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=r6wk4j6Y3ycl2nV4Dg4z8d02Nq2gzcm4qrwGHnkYfK8=;
        fh=VzOVdMhw4X6Pop50qdtU4gcRr0vN/MFDvrk+U4uouKk=;
        b=DKHr7GO+FNSnF2DZIKFyexcZhl0yWZjIMoV51KauCl+4kWTr1JOJ4KERRbRebPRTjd
         6TaRy5A980j4q03Bnw4YSEqM437UUuvhtPixwOZ/imHNYcNdA4tIdKfEHwxlJIp1ykg7
         EBaoDW/vOPVVlexsRV2bbKtwbMufYWTWZOnzNA1MUF8e3DGPSAV+tO32/FRiORYCLQ20
         rS9jfKJkZgGhgK6aN/8XBwhLd2RZba2viRzNMMwaQ/pGUOjMSQ7OzGBYaRxaaDRAKqFe
         g/jefRyV8kCVlgAiex4suJFKObhOOtkMogufCaEwkkpKoL4I9v/ibNWveBd9jdYIrCwK
         r5jQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jTv9LLcT;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-36cc657b584si6498075ab.1.2024.05.14.02.54.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 May 2024 02:54:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2AB04611DB;
	Tue, 14 May 2024 09:54:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 78A03C2BD10;
	Tue, 14 May 2024 09:54:41 +0000 (UTC)
From: Masahiro Yamada <masahiroy@kernel.org>
To: Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Masahiro Yamada <masahiroy@kernel.org>
Subject: [PATCH] ubsan: remove meaningless CONFIG_ARCH_HAS_UBSAN
Date: Tue, 14 May 2024 18:54:26 +0900
Message-Id: <20240514095427.541201-1-masahiroy@kernel.org>
X-Mailer: git-send-email 2.40.1
MIME-Version: 1.0
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jTv9LLcT;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

All architectures can enable UBSAN regardless of ARCH_HAS_UBSAN
because there is no "depends on ARCH_HAS_UBSAN" line.

Fixes: 918327e9b7ff ("ubsan: Remove CONFIG_UBSAN_SANITIZE_ALL")
Signed-off-by: Masahiro Yamada <masahiroy@kernel.org>
---

 MAINTAINERS          | 1 -
 arch/arm/Kconfig     | 1 -
 arch/arm64/Kconfig   | 1 -
 arch/mips/Kconfig    | 1 -
 arch/parisc/Kconfig  | 1 -
 arch/powerpc/Kconfig | 1 -
 arch/riscv/Kconfig   | 1 -
 arch/s390/Kconfig    | 1 -
 arch/x86/Kconfig     | 1 -
 lib/Kconfig.ubsan    | 3 ---
 10 files changed, 12 deletions(-)

diff --git a/MAINTAINERS b/MAINTAINERS
index ebf03f5f0619..01124115a991 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -22650,7 +22650,6 @@ F:	lib/Kconfig.ubsan
 F:	lib/test_ubsan.c
 F:	lib/ubsan.c
 F:	scripts/Makefile.ubsan
-K:	\bARCH_HAS_UBSAN\b
 
 UCLINUX (M68KNOMMU AND COLDFIRE)
 M:	Greg Ungerer <gerg@linux-m68k.org>
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index b14aed3a17ab..284103a56fbb 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -30,7 +30,6 @@ config ARM
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG if CPU_V7 || CPU_V7M || CPU_V6K
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_KEEP_MEMBLOCK
-	select ARCH_HAS_UBSAN
 	select ARCH_MIGHT_HAVE_PC_PARPORT
 	select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_OPTIONAL_KERNEL_RWX_DEFAULT if CPU_V7
diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 7b11c98b3e84..919f470338ed 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -107,7 +107,6 @@ config ARM64
 	select ARCH_WANT_LD_ORPHAN_WARN
 	select ARCH_WANTS_NO_INSTR
 	select ARCH_WANTS_THP_SWAP if ARM64_4K_PAGES
-	select ARCH_HAS_UBSAN
 	select ARM_AMBA
 	select ARM_ARCH_TIMER
 	select ARM_GIC
diff --git a/arch/mips/Kconfig b/arch/mips/Kconfig
index 516dc7022bd7..dd974ab9b4e0 100644
--- a/arch/mips/Kconfig
+++ b/arch/mips/Kconfig
@@ -15,7 +15,6 @@ config MIPS
 	select ARCH_HAS_STRNCPY_FROM_USER
 	select ARCH_HAS_STRNLEN_USER
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
-	select ARCH_HAS_UBSAN
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_KEEP_MEMBLOCK
 	select ARCH_USE_BUILTIN_BSWAP
diff --git a/arch/parisc/Kconfig b/arch/parisc/Kconfig
index daafeb20f993..afe348ed1202 100644
--- a/arch/parisc/Kconfig
+++ b/arch/parisc/Kconfig
@@ -13,7 +13,6 @@ config PARISC
 	select ARCH_HAS_ELF_RANDOMIZE
 	select ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_HAS_STRICT_MODULE_RWX
-	select ARCH_HAS_UBSAN
 	select ARCH_HAS_PTE_SPECIAL
 	select ARCH_NO_SG_CHAIN
 	select ARCH_SUPPORTS_HUGETLBFS if PA20
diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 1c4be3373686..185a24424f47 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -154,7 +154,6 @@ config PPC
 	select ARCH_HAS_SYSCALL_WRAPPER		if !SPU_BASE && !COMPAT
 	select ARCH_HAS_TICK_BROADCAST		if GENERIC_CLOCKEVENTS_BROADCAST
 	select ARCH_HAS_UACCESS_FLUSHCACHE
-	select ARCH_HAS_UBSAN
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG
 	select ARCH_KEEP_MEMBLOCK
 	select ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE	if PPC_RADIX_MMU
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index be09c8836d56..19ce88409c82 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -41,7 +41,6 @@ config RISCV
 	select ARCH_HAS_SYNC_CORE_BEFORE_USERMODE
 	select ARCH_HAS_SYSCALL_WRAPPER
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
-	select ARCH_HAS_UBSAN
 	select ARCH_HAS_VDSO_DATA
 	select ARCH_KEEP_MEMBLOCK if ACPI
 	select ARCH_OPTIONAL_KERNEL_RWX if ARCH_HAS_STRICT_KERNEL_RWX
diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 8f01ada6845e..789a5128af9a 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -83,7 +83,6 @@ config S390
 	select ARCH_HAS_STRICT_KERNEL_RWX
 	select ARCH_HAS_STRICT_MODULE_RWX
 	select ARCH_HAS_SYSCALL_WRAPPER
-	select ARCH_HAS_UBSAN
 	select ARCH_HAS_VDSO_DATA
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG
 	select ARCH_INLINE_READ_LOCK
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 4474bf32d0a4..2583d8beb3a2 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -100,7 +100,6 @@ config X86
 	select ARCH_HAS_STRICT_MODULE_RWX
 	select ARCH_HAS_SYNC_CORE_BEFORE_USERMODE
 	select ARCH_HAS_SYSCALL_WRAPPER
-	select ARCH_HAS_UBSAN
 	select ARCH_HAS_DEBUG_WX
 	select ARCH_HAS_ZONE_DMA_SET if EXPERT
 	select ARCH_HAVE_NMI_SAFE_CMPXCHG
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index e81e1ac4a919..0d53e085d4f2 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -1,7 +1,4 @@
 # SPDX-License-Identifier: GPL-2.0-only
-config ARCH_HAS_UBSAN
-	bool
-
 menuconfig UBSAN
 	bool "Undefined behaviour sanity checker"
 	help
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240514095427.541201-1-masahiroy%40kernel.org.
