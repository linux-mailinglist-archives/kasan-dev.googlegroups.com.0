Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDHYX7AQMGQEGK2GJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 12316AC1B03
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:42 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6f8c6ce05e0sf91033636d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975181; cv=pass;
        d=google.com; s=arc-20240605;
        b=RTFuUGf3NbRmooEtLSZVuCg1XtRgcD2qL4ImXpUof43kmO3mtAnNmNa5ESoGlc7+gC
         +/IrrNf7WVzpbBJR9luGwE7CDjtc83z73Uk4pth5UMEiqSiwXt8OLmApv2TlTLz0bLJV
         bc3/b7tZDeqDj+wV8NNorLHObn6uioi7ZgkKBfAVxXl+py7rBniAb4bhl1ZGffVmZCjW
         Texk8empJEqpR3ZUeMKmnXZOaRjnaP0VyVcfzbEK3gNQrH1qekL8mDPzEZpdVF4Wy+4u
         dfevyN4TZoCeLdvi2Vp8CkSQgFR/Mcgi/mIkwb4bbWPC+NT7hkRj57+ZAjsf/hWFkfvt
         5Q9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=PtSIGgv/iqmVDbrVNPlIgSH3WpJrpP6tsabOk92gkKE=;
        fh=0xv7LX/39x8gh+hZmzEEJCOF+RbxM/5A+C36LkWlCBE=;
        b=Vz/AwuEhnNiSk5ByCMokZrj5X/MMQwdZeU9Zgzj/1ICjnUR3Bou9pdbQd2YddiewQU
         aIGloAkbVjRrHJKoO25kIbO9SuscLF2aSFDg5oo9WztRuCm5VkjVpN33ACEOfOHQ5/zf
         1Pvo6rbPWEQVJTxUsZbrLy18Cae23MctoQaQJmW+TUClfPDK6himg+yT0a1yHThEXR1m
         yMtiTBu0S4p1guvml3Kjv8HAXcCiDHHZqYm51uTt1geTIMmvLStbzlDPD5JbYAGPz4IG
         5ODw1d1SDlJeRu5l9zfxvZkMSDKJ45HwH0+kUAKIuBCpd+OQbGHN3BaVSUYdsQGOLZA+
         QWbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BwShGNjl;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975181; x=1748579981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PtSIGgv/iqmVDbrVNPlIgSH3WpJrpP6tsabOk92gkKE=;
        b=e3tXE/028/W/4bx/tV8khJI6HOeVGVAFOOP36XVXDIl9XRQASr8VMb3rs2PAXgfNGW
         ByZ0LoZKLh7BI7307OoWoXOfF+S419WUD60BzGp+b9RwL5yQuACxLAjbzOi7reDjG1Zl
         SbuRZZWtSRAgpa91FxYu21gQAp5fFkuSXvO/eFUJkuz7xGXlTLba42gsZ9EQPrEhEz9x
         P5DzvRYyoG+3M6FcyaotqMEYary2DaOzS3AvvlHptexSLbOUtzpWE80FHM78R+AOWllX
         E8m8qhd16ApbzNQOTjTmhETKE8GjeFJ5vqnxK1WqvRdFreAtV8wLAjfK8pn8dSYpsGuL
         Gxdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975181; x=1748579981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PtSIGgv/iqmVDbrVNPlIgSH3WpJrpP6tsabOk92gkKE=;
        b=Lw2PAVzCxUAwJ7mGEYcTo47Rod1KDNZVtXbkA/4xj7ctftE5aKcXK300RmwsJnZxhE
         SErhGc1CHk0kNObOHT/uZmx69AqcJUbAJOxcMBz1gpZb7XkbIfkTV/ikb0uVVJhJXk+y
         h+Vo8hGABrHSY9i8mD9ZD85Kppksa+w20PYXAiMuETRaHIAMBDCSPxac05SYMNRHkFlc
         /SernGr9YhNH3fTWQmISCOFZvuAXcy6xfdZuxYccJypf09OTdOhYyl2JlxBqXLw8IShz
         c0+4HRmDZnaZyJfSj192oJ51BwMytjY9C0bfFtCfFLexz915RT8jueHe3kkZNf//k4UF
         XguA==
X-Forwarded-Encrypted: i=2; AJvYcCXwccAWVnk3sCoBkvSov+pLlHhvdI+nGTCuFahynnrmD6WtUtW+0gQUCAvXdV2/B0iVLQ+njA==@lfdr.de
X-Gm-Message-State: AOJu0Yz5Gr0Zf2Vqr73FHyr+2XUxGk89dQ13+LIMS58lZVAadzmNfrLp
	jSM1tbu9iWXUYRrSUltMWujRuDRrVTVJJ12hpWl83Xdgb397zwWNVOKI
X-Google-Smtp-Source: AGHT+IFOHcAedppDeLKp63RzsPhm77Ws8kvF6PZTY1prI+IQoN5VvT/CxQF76XCTYh6XCSWYhBzEUw==
X-Received: by 2002:a05:6214:250b:b0:6f9:2c6d:8568 with SMTP id 6a1803df08f44-6fa93aea61emr25532136d6.40.1747975180560;
        Thu, 22 May 2025 21:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGPu1ymoGyNVRP0eknezClQcu4ei9/v/M1K2CbYqtu96Q==
Received: by 2002:a05:6214:5853:b0:6f8:cdc5:aa9b with SMTP id
 6a1803df08f44-6f8cdc5b0e8ls29241826d6.0.-pod-prod-07-us; Thu, 22 May 2025
 21:39:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8WBDhOabderRwckI5RYkHi5v6o3xdkI/vwtwpbvy3CQ2wM/1/jdMxrm2ID6136yhuyKJqlaNeUDg=@googlegroups.com
X-Received: by 2002:a05:6122:a01:b0:52a:79fd:34bd with SMTP id 71dfb90a1353d-52f1fd070c0mr1340668e0c.4.1747975179558;
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975179; cv=none;
        d=google.com; s=arc-20240605;
        b=JEd9LQpR6dDRREJSXm6Y+LxXe4jrNm7vSN4SA3Qd0+u6l7yV5DHPv6fQ9aZvcMZSGt
         vN2Y6cmhSr63Plj7UL0mawL0ZFVVRX7gnj+qabyrxoqYQEBiZdH72JDNLaKLxFDWxUIK
         LQ0O3iATqwtcT9YIFbbokFRZSU0ZWigrJtS/v+0oMixrCFCpccjuIPhDU/LKz80W3V41
         NvZ+RHiy+z7/zBzI0vF40jLwnsQouEnYI8Hb7AX3LfBduJ0MGxfvVYjFqHApMFstlHPP
         zs4MbtLTMUvmrlTaEE2DzOZghoY8JZIwJs1iesDd/8FVL1vpiiIpHu23yJYY/djoJMcY
         moNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GtFEKgXXy7PevOGwDxDIYT3EbeE8i5sniziLu9c/oJA=;
        fh=OKNeOQKpZjs+CIN0HjzoB1LsP2aPYikHNR/QYibdeZA=;
        b=fEnA6vm+oAj5Se3cLhh3krqArdewvuHCkJ6ZjrKH22lT6Xa5zINQmw3GI8eq7aACkR
         unZS4+ICKZMdfWFIEeoy2E/MQTl+Nx2efMVHKyswkaBtaDIPSHBzQDFRiUnY9wueRn3T
         p4tDvYJMVErR7PLjHhFDZXzUcudY01X+p0T/q+YGTAMHcbTA3FOrnRYeBcDHHh/7dJn5
         vXih8i2LBYYzTPJ9b3X36sDc8CcDcEeMEDd23DPLmKv4OmesO1o/xtxrR8L6Sr2GtW2N
         +KZeM55VCvSXVeeo1cgu06ErRqKRpMxbV5/ojodVfo8+KbY1N6poBNIWrNOmUDSkLM6v
         i0bQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BwShGNjl;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52f24de72efsi6648e0c.0.2025.05.22.21.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A87805C6CC1;
	Fri, 23 May 2025 04:37:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 628DBC4CEE9;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	x86@kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 01/14] stackleak: Rename STACKLEAK to KSTACK_ERASE
Date: Thu, 22 May 2025 21:39:11 -0700
Message-Id: <20250523043935.2009972-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=36006; i=kees@kernel.org; h=from:subject; bh=9AkAkSKl9S4JaL8v+O2hS6MFbAfqao2mTLxrmw6SRmE=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v78bHbjqUCS/yZI1lJddPPsgl+Gs+Yd+zn2bvOBo+ 9zgHfccOkpZGMS4GGTFFFmC7NzjXDzetoe7z1WEmcPKBDKEgYtTACZi08Twz775WYHCrfbrKh63 bJpXGamk7NBMUTx1UO4483tJHp/1Bxh+s96ak5Lkmvj6g0dF6Yvt3k8/tc/kiGf13+I3P9Lf3Wc 6NwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BwShGNjl;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

In preparation for adding Clang sanitizer coverage stack depth tracking
that can support stack depth callbacks:

- Add the new top-level CONFIG_KSTACK_ERASE option which will be
  implemented either with the stackleak GCC plugin, or with the Clang
  stack depth callback support.
- Rename CONFIG_GCC_PLUGIN_STACKLEAK as needed to CONFIG_KSTACK_ERASE,
  but keep it for anything specific to the GCC plugin itself.
- Rename all exposed "STACKLEAK" names and files to "KSTACK_ERASE" (named
  for what it does rather than what it protects against), but leave as
  many of the internals alone as possible to avoid even more churn.

While here, also split "prev_lowest_stack" into CONFIG_KSTACK_ERASE_METRICS=
,
since that's the only place it is referenced from.

Suggested-by: Ingo Molnar <mingo@kernel.org>
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <x86@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-doc@vger.kernel.org>
Cc: <linux-arm-kernel@lists.infradead.org>
Cc: <kvmarm@lists.linux.dev>
Cc: <linux-riscv@lists.infradead.org>
Cc: <linux-s390@vger.kernel.org>
Cc: <linux-efi@vger.kernel.org>
Cc: <linux-hardening@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <linux-security-module@vger.kernel.org>
Cc: <linux-kselftest@vger.kernel.org>
---
 arch/Kconfig                                  |  4 +--
 arch/arm/Kconfig                              |  2 +-
 arch/arm64/Kconfig                            |  2 +-
 arch/riscv/Kconfig                            |  2 +-
 arch/s390/Kconfig                             |  2 +-
 arch/x86/Kconfig                              |  2 +-
 security/Kconfig.hardening                    | 36 ++++++++++---------
 arch/arm/boot/compressed/Makefile             |  2 +-
 arch/arm64/kernel/pi/Makefile                 |  2 +-
 arch/arm64/kvm/hyp/nvhe/Makefile              |  2 +-
 arch/riscv/kernel/pi/Makefile                 |  2 +-
 arch/riscv/purgatory/Makefile                 |  2 +-
 arch/x86/purgatory/Makefile                   |  2 +-
 drivers/firmware/efi/libstub/Makefile         |  8 ++---
 drivers/misc/lkdtm/Makefile                   |  2 +-
 kernel/Makefile                               | 10 +++---
 lib/Makefile                                  |  2 +-
 scripts/Makefile.gcc-plugins                  |  6 ++--
 Documentation/admin-guide/sysctl/kernel.rst   |  4 +--
 Documentation/arch/x86/x86_64/mm.rst          |  2 +-
 Documentation/security/self-protection.rst    |  2 +-
 .../zh_CN/security/self-protection.rst        |  2 +-
 arch/x86/entry/calling.h                      |  4 +--
 include/linux/{stackleak.h =3D> kstack_erase.h} | 18 +++++-----
 include/linux/sched.h                         |  4 ++-
 arch/arm/kernel/entry-common.S                |  2 +-
 arch/arm64/kernel/entry.S                     |  2 +-
 arch/riscv/kernel/entry.S                     |  2 +-
 arch/s390/kernel/entry.S                      |  2 +-
 .../lkdtm/{stackleak.c =3D> kstack_erase.c}     | 26 +++++++-------
 fs/proc/base.c                                |  6 ++--
 kernel/fork.c                                 |  2 +-
 kernel/{stackleak.c =3D> kstack_erase.c}        | 18 +++++-----
 tools/objtool/check.c                         |  2 +-
 tools/testing/selftests/lkdtm/config          |  2 +-
 MAINTAINERS                                   |  4 +--
 36 files changed, 100 insertions(+), 94 deletions(-)
 rename include/linux/{stackleak.h =3D> kstack_erase.h} (85%)
 rename drivers/misc/lkdtm/{stackleak.c =3D> kstack_erase.c} (89%)
 rename kernel/{stackleak.c =3D> kstack_erase.c} (90%)

diff --git a/arch/Kconfig b/arch/Kconfig
index a3308a220f86..4d1908f6f084 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -630,11 +630,11 @@ config SECCOMP_CACHE_DEBUG
=20
 	  If unsure, say N.
=20
-config HAVE_ARCH_STACKLEAK
+config HAVE_ARCH_KSTACK_ERASE
 	bool
 	help
 	  An architecture should select this if it has the code which
-	  fills the used part of the kernel stack with the STACKLEAK_POISON
+	  fills the used part of the kernel stack with the KSTACK_ERASE_POISON
 	  value before returning from system calls.
=20
 config HAVE_STACKPROTECTOR
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 3072731fe09c..cb0b2e2211ca 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -87,11 +87,11 @@ config ARM
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
 	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KSTACK_ERASE
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
 	select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
-	select HAVE_ARCH_STACKLEAK
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE if ARM_LPAE
diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 55fc331af337..e2a9e013b6a9 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -187,12 +187,12 @@ config ARM64
 	select HAVE_ARCH_KCSAN if EXPERT
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
+	select HAVE_ARCH_KSTACK_ERASE
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
 	select HAVE_ARCH_PREL32_RELOCATIONS
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-	select HAVE_ARCH_STACKLEAK
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index fbca724302ab..31792e0e0bf6 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -133,13 +133,13 @@ config RISCV
 	select HAVE_ARCH_KASAN if MMU && 64BIT
 	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
 	select HAVE_ARCH_KFENCE if MMU && 64BIT
+	select HAVE_ARCH_KSTACK_ERASE
 	select HAVE_ARCH_KGDB if !XIP_KERNEL
 	select HAVE_ARCH_KGDB_QXFER_PKT
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-	select HAVE_ARCH_STACKLEAK
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE if 64BIT && MMU
diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 0c16dc443e2f..a8e74ed8e3cc 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -176,10 +176,10 @@ config S390
 	select HAVE_ARCH_KCSAN
 	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
+	select HAVE_ARCH_KSTACK_ERASE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_SOFT_DIRTY
-	select HAVE_ARCH_STACKLEAK
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
 	select HAVE_ARCH_VMAP_STACK
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 340e5468980e..bc3708cad46b 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -204,13 +204,13 @@ config X86
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
+	select HAVE_ARCH_KSTACK_ERASE
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
 	select HAVE_ARCH_COMPAT_MMAP_BASES	if MMU && COMPAT
 	select HAVE_ARCH_PREL32_RELOCATIONS
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
-	select HAVE_ARCH_STACKLEAK
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD if X86_64
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index fd1238753cad..125b35e2ef0f 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -82,10 +82,10 @@ choice
=20
 endchoice
=20
-config GCC_PLUGIN_STACKLEAK
+config KSTACK_ERASE
 	bool "Poison kernel stack before returning from syscalls"
+	depends on HAVE_ARCH_KSTACK_ERASE
 	depends on GCC_PLUGINS
-	depends on HAVE_ARCH_STACKLEAK
 	help
 	  This option makes the kernel erase the kernel stack before
 	  returning from system calls. This has the effect of leaving
@@ -103,6 +103,10 @@ config GCC_PLUGIN_STACKLEAK
 	  are advised to test this feature on your expected workload before
 	  deploying it.
=20
+config GCC_PLUGIN_STACKLEAK
+	def_bool KSTACK_ERASE
+	depends on GCC_PLUGINS
+	help
 	  This plugin was ported from grsecurity/PaX. More information at:
 	   * https://grsecurity.net/
 	   * https://pax.grsecurity.net/
@@ -117,37 +121,37 @@ config GCC_PLUGIN_STACKLEAK_VERBOSE
 	  instrumented. This is useful for comparing coverage between
 	  builds.
=20
-config STACKLEAK_TRACK_MIN_SIZE
-	int "Minimum stack frame size of functions tracked by STACKLEAK"
+config KSTACK_ERASE_TRACK_MIN_SIZE
+	int "Minimum stack frame size of functions tracked by KSTACK_ERASE"
 	default 100
 	range 0 4096
-	depends on GCC_PLUGIN_STACKLEAK
+	depends on KSTACK_ERASE
 	help
-	  The STACKLEAK gcc plugin instruments the kernel code for tracking
+	  The KSTACK_ERASE option instruments the kernel code for tracking
 	  the lowest border of the kernel stack (and for some other purposes).
 	  It inserts the stackleak_track_stack() call for the functions with
 	  a stack frame size greater than or equal to this parameter.
 	  If unsure, leave the default value 100.
=20
-config STACKLEAK_METRICS
-	bool "Show STACKLEAK metrics in the /proc file system"
-	depends on GCC_PLUGIN_STACKLEAK
+config KSTACK_ERASE_METRICS
+	bool "Show KSTACK_ERASE metrics in the /proc file system"
+	depends on KSTACK_ERASE
 	depends on PROC_FS
 	help
-	  If this is set, STACKLEAK metrics for every task are available in
-	  the /proc file system. In particular, /proc/<pid>/stack_depth
+	  If this is set, KSTACK_ERASE metrics for every task are available
+	  in the /proc file system. In particular, /proc/<pid>/stack_depth
 	  shows the maximum kernel stack consumption for the current and
 	  previous syscalls. Although this information is not precise, it
-	  can be useful for estimating the STACKLEAK performance impact for
-	  your workloads.
+	  can be useful for estimating the KSTACK_ERASE performance impact
+	  for your workloads.
=20
-config STACKLEAK_RUNTIME_DISABLE
+config KSTACK_ERASE_RUNTIME_DISABLE
 	bool "Allow runtime disabling of kernel stack erasing"
-	depends on GCC_PLUGIN_STACKLEAK
+	depends on KSTACK_ERASE
 	help
 	  This option provides 'stack_erasing' sysctl, which can be used in
 	  runtime to control kernel stack erasing for kernels built with
-	  CONFIG_GCC_PLUGIN_STACKLEAK.
+	  CONFIG_KSTACK_ERASE.
=20
 config INIT_ON_ALLOC_DEFAULT_ON
 	bool "Enable heap memory zeroing on allocation by default"
diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/M=
akefile
index d61369b1eabe..f9075edfd773 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -9,7 +9,7 @@ OBJS		=3D
=20
 HEAD	=3D head.o
 OBJS	+=3D misc.o decompress.o
-CFLAGS_decompress.o +=3D $(DISABLE_STACKLEAK_PLUGIN)
+CFLAGS_decompress.o +=3D $(DISABLE_KSTACK_ERASE)
 ifeq ($(CONFIG_DEBUG_UNCOMPRESS),y)
 OBJS	+=3D debug.o
 AFLAGS_head.o +=3D -DDEBUG
diff --git a/arch/arm64/kernel/pi/Makefile b/arch/arm64/kernel/pi/Makefile
index 4d11a8c29181..f440bf57b1a5 100644
--- a/arch/arm64/kernel/pi/Makefile
+++ b/arch/arm64/kernel/pi/Makefile
@@ -2,7 +2,7 @@
 # Copyright 2022 Google LLC
=20
 KBUILD_CFLAGS	:=3D $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) -fpie \
-		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK_PLUGIN) \
+		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_KSTACK_ERASE) \
 		   $(DISABLE_LATENT_ENTROPY_PLUGIN) \
 		   $(call cc-option,-mbranch-protection=3Dnone) \
 		   -I$(srctree)/scripts/dtc/libfdt -fno-stack-protector \
diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Mak=
efile
index a76522d63c3e..0b0a68b663d4 100644
--- a/arch/arm64/kvm/hyp/nvhe/Makefile
+++ b/arch/arm64/kvm/hyp/nvhe/Makefile
@@ -12,7 +12,7 @@ asflags-y :=3D -D__KVM_NVHE_HYPERVISOR__ -D__DISABLE_EXPO=
RTS
 ccflags-y :=3D -D__KVM_NVHE_HYPERVISOR__ -D__DISABLE_EXPORTS -D__DISABLE_T=
RACE_MMIO__
 ccflags-y +=3D -fno-stack-protector	\
 	     -DDISABLE_BRANCH_PROFILING	\
-	     $(DISABLE_STACKLEAK_PLUGIN)
+	     $(DISABLE_KSTACK_ERASE)
=20
 hostprogs :=3D gen-hyprel
 HOST_EXTRACFLAGS +=3D -I$(objtree)/include
diff --git a/arch/riscv/kernel/pi/Makefile b/arch/riscv/kernel/pi/Makefile
index 81d69d45c06c..7dd15be69c90 100644
--- a/arch/riscv/kernel/pi/Makefile
+++ b/arch/riscv/kernel/pi/Makefile
@@ -2,7 +2,7 @@
 # This file was copied from arm64/kernel/pi/Makefile.
=20
 KBUILD_CFLAGS	:=3D $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) -fpie \
-		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK_PLUGIN) \
+		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_KSTACK_ERASE) \
 		   $(call cc-option,-mbranch-protection=3Dnone) \
 		   -I$(srctree)/scripts/dtc/libfdt -fno-stack-protector \
 		   -include $(srctree)/include/linux/hidden.h \
diff --git a/arch/riscv/purgatory/Makefile b/arch/riscv/purgatory/Makefile
index fb9c917c9b45..240592e3f5c2 100644
--- a/arch/riscv/purgatory/Makefile
+++ b/arch/riscv/purgatory/Makefile
@@ -53,7 +53,7 @@ targets +=3D purgatory.ro purgatory.chk
=20
 PURGATORY_CFLAGS_REMOVE :=3D -mcmodel=3Dkernel
 PURGATORY_CFLAGS :=3D -mcmodel=3Dmedany -ffreestanding -fno-zero-initializ=
ed-in-bss
-PURGATORY_CFLAGS +=3D $(DISABLE_STACKLEAK_PLUGIN) -DDISABLE_BRANCH_PROFILI=
NG
+PURGATORY_CFLAGS +=3D $(DISABLE_KSTACK_ERASE) -DDISABLE_BRANCH_PROFILING
 PURGATORY_CFLAGS +=3D -fno-stack-protector -g0
=20
 # Default KBUILD_CFLAGS can have -pg option set when FTRACE is enabled. Th=
at
diff --git a/arch/x86/purgatory/Makefile b/arch/x86/purgatory/Makefile
index ebdfd7b84feb..e0a607a14e7e 100644
--- a/arch/x86/purgatory/Makefile
+++ b/arch/x86/purgatory/Makefile
@@ -35,7 +35,7 @@ targets +=3D purgatory.ro purgatory.chk
 PURGATORY_CFLAGS_REMOVE :=3D -mcmodel=3Dkernel
 PURGATORY_CFLAGS :=3D -mcmodel=3Dsmall -ffreestanding -fno-zero-initialize=
d-in-bss -g0
 PURGATORY_CFLAGS +=3D -fpic -fvisibility=3Dhidden
-PURGATORY_CFLAGS +=3D $(DISABLE_STACKLEAK_PLUGIN) -DDISABLE_BRANCH_PROFILI=
NG
+PURGATORY_CFLAGS +=3D $(DISABLE_KSTACK_ERASE) -DDISABLE_BRANCH_PROFILING
 PURGATORY_CFLAGS +=3D -fno-stack-protector
=20
 # Default KBUILD_CFLAGS can have -pg option set when FTRACE is enabled. Th=
at
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/l=
ibstub/Makefile
index 6a0152858a2a..cdba14dde7d5 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -22,16 +22,16 @@ cflags-$(CONFIG_X86)		+=3D -m$(BITS) -D__KERNEL__ -std=
=3Dgnu11 \
=20
 # arm64 uses the full KBUILD_CFLAGS so it's necessary to explicitly
 # disable the stackleak plugin
-cflags-$(CONFIG_ARM64)		+=3D -fpie $(DISABLE_STACKLEAK_PLUGIN) \
+cflags-$(CONFIG_ARM64)		+=3D -fpie $(DISABLE_KSTACK_ERASE) \
 				   -fno-unwind-tables -fno-asynchronous-unwind-tables
 cflags-$(CONFIG_ARM)		+=3D -DEFI_HAVE_STRLEN -DEFI_HAVE_STRNLEN \
 				   -DEFI_HAVE_MEMCHR -DEFI_HAVE_STRRCHR \
 				   -DEFI_HAVE_STRCMP -fno-builtin -fpic \
 				   $(call cc-option,-mno-single-pic-base) \
-				   $(DISABLE_STACKLEAK_PLUGIN)
+				   $(DISABLE_KSTACK_ERASE)
 cflags-$(CONFIG_RISCV)		+=3D -fpic -DNO_ALTERNATIVE -mno-relax \
-				   $(DISABLE_STACKLEAK_PLUGIN)
-cflags-$(CONFIG_LOONGARCH)	+=3D -fpie $(DISABLE_STACKLEAK_PLUGIN)
+				   $(DISABLE_KSTACK_ERASE)
+cflags-$(CONFIG_LOONGARCH)	+=3D -fpie $(DISABLE_KSTACK_ERASE)
=20
 cflags-$(CONFIG_EFI_PARAMS_FROM_FDT)	+=3D -I$(srctree)/scripts/dtc/libfdt
=20
diff --git a/drivers/misc/lkdtm/Makefile b/drivers/misc/lkdtm/Makefile
index 39468bd27b85..03ebe33185f9 100644
--- a/drivers/misc/lkdtm/Makefile
+++ b/drivers/misc/lkdtm/Makefile
@@ -8,7 +8,7 @@ lkdtm-$(CONFIG_LKDTM)		+=3D perms.o
 lkdtm-$(CONFIG_LKDTM)		+=3D refcount.o
 lkdtm-$(CONFIG_LKDTM)		+=3D rodata_objcopy.o
 lkdtm-$(CONFIG_LKDTM)		+=3D usercopy.o
-lkdtm-$(CONFIG_LKDTM)		+=3D stackleak.o
+lkdtm-$(CONFIG_LKDTM)		+=3D kstack_erase.o
 lkdtm-$(CONFIG_LKDTM)		+=3D cfi.o
 lkdtm-$(CONFIG_LKDTM)		+=3D fortify.o
 lkdtm-$(CONFIG_PPC_64S_HASH_MMU)	+=3D powerpc.o
diff --git a/kernel/Makefile b/kernel/Makefile
index 32e80dd626af..e4f01f1d4d0c 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -139,11 +139,11 @@ obj-$(CONFIG_WATCH_QUEUE) +=3D watch_queue.o
 obj-$(CONFIG_RESOURCE_KUNIT_TEST) +=3D resource_kunit.o
 obj-$(CONFIG_SYSCTL_KUNIT_TEST) +=3D sysctl-test.o
=20
-CFLAGS_stackleak.o +=3D $(DISABLE_STACKLEAK_PLUGIN)
-obj-$(CONFIG_GCC_PLUGIN_STACKLEAK) +=3D stackleak.o
-KASAN_SANITIZE_stackleak.o :=3D n
-KCSAN_SANITIZE_stackleak.o :=3D n
-KCOV_INSTRUMENT_stackleak.o :=3D n
+CFLAGS_kstack_erase.o +=3D $(DISABLE_KSTACK_ERASE)
+obj-$(CONFIG_KSTACK_ERASE) +=3D kstack_erase.o
+KASAN_SANITIZE_kstack_erase.o :=3D n
+KCSAN_SANITIZE_kstack_erase.o :=3D n
+KCOV_INSTRUMENT_kstack_erase.o :=3D n
=20
 obj-$(CONFIG_SCF_TORTURE_TEST) +=3D scftorture.o
=20
diff --git a/lib/Makefile b/lib/Makefile
index c38582f187dd..632e69d25feb 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -337,7 +337,7 @@ obj-$(CONFIG_UBSAN) +=3D ubsan.o
 UBSAN_SANITIZE_ubsan.o :=3D n
 KASAN_SANITIZE_ubsan.o :=3D n
 KCSAN_SANITIZE_ubsan.o :=3D n
-CFLAGS_ubsan.o :=3D -fno-stack-protector $(DISABLE_STACKLEAK_PLUGIN)
+CFLAGS_ubsan.o :=3D -fno-stack-protector $(DISABLE_KSTACK_ERASE)
=20
 obj-$(CONFIG_SBITMAP) +=3D sbitmap.o
=20
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 435ab3f0ec44..28b8867c4e84 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -12,15 +12,15 @@ gcc-plugin-$(CONFIG_GCC_PLUGIN_STACKLEAK)	+=3D stacklea=
k_plugin.so
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
 		+=3D -DSTACKLEAK_PLUGIN
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+=3D -fplugin-arg-stackleak_plugin-track-min-size=3D$(CONFIG_STACKLEAK_T=
RACK_MIN_SIZE)
+		+=3D -fplugin-arg-stackleak_plugin-track-min-size=3D$(CONFIG_KSTACK_ERAS=
E_TRACK_MIN_SIZE)
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
 		+=3D -fplugin-arg-stackleak_plugin-arch=3D$(SRCARCH)
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE)	\
 		+=3D -fplugin-arg-stackleak_plugin-verbose
 ifdef CONFIG_GCC_PLUGIN_STACKLEAK
-    DISABLE_STACKLEAK_PLUGIN +=3D -fplugin-arg-stackleak_plugin-disable
+    DISABLE_KSTACK_ERASE +=3D -fplugin-arg-stackleak_plugin-disable
 endif
-export DISABLE_STACKLEAK_PLUGIN
+export DISABLE_KSTACK_ERASE
=20
 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/ad=
min-guide/sysctl/kernel.rst
index dd49a89a62d3..19224eeac1c2 100644
--- a/Documentation/admin-guide/sysctl/kernel.rst
+++ b/Documentation/admin-guide/sysctl/kernel.rst
@@ -1465,7 +1465,7 @@ stack_erasing
 =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
=20
 This parameter can be used to control kernel stack erasing at the end
-of syscalls for kernels built with ``CONFIG_GCC_PLUGIN_STACKLEAK``.
+of syscalls for kernels built with ``CONFIG_KSTACK_ERASE``.
=20
 That erasing reduces the information which kernel stack leak bugs
 can reveal and blocks some uninitialized stack variable attacks.
@@ -1473,7 +1473,7 @@ The tradeoff is the performance impact: on a single C=
PU system kernel
 compilation sees a 1% slowdown, other systems and workloads may vary.
=20
 =3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-0 Kernel stack erasing is disabled, STACKLEAK_METRICS are not updated.
+0 Kernel stack erasing is disabled, KSTACK_ERASE_METRICS are not updated.
 1 Kernel stack erasing is enabled (default), it is performed before
   returning to the userspace at the end of syscalls.
 =3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/=
x86_64/mm.rst
index f2db178b353f..a6cf05d51bd8 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -176,5 +176,5 @@ Be very careful vs. KASLR when changing anything here. =
The KASLR address
 range must not overlap with anything except the KASAN shadow area, which i=
s
 correct as KASAN disables KASLR.
=20
-For both 4- and 5-level layouts, the STACKLEAK_POISON value in the last 2M=
B
+For both 4- and 5-level layouts, the KSTACK_ERASE_POISON value in the last=
 2MB
 hole: ffffffffffff4111
diff --git a/Documentation/security/self-protection.rst b/Documentation/sec=
urity/self-protection.rst
index 910668e665cb..a32ca23c21b0 100644
--- a/Documentation/security/self-protection.rst
+++ b/Documentation/security/self-protection.rst
@@ -303,7 +303,7 @@ Memory poisoning
=20
 When releasing memory, it is best to poison the contents, to avoid reuse
 attacks that rely on the old contents of memory. E.g., clear stack on a
-syscall return (``CONFIG_GCC_PLUGIN_STACKLEAK``), wipe heap memory on a
+syscall return (``CONFIG_KSTACK_ERASE``), wipe heap memory on a
 free. This frustrates many uninitialized variable attacks, stack content
 exposures, heap content exposures, and use-after-free attacks.
=20
diff --git a/Documentation/translations/zh_CN/security/self-protection.rst =
b/Documentation/translations/zh_CN/security/self-protection.rst
index 3c8a68b1e1be..93de9cee5c1a 100644
--- a/Documentation/translations/zh_CN/security/self-protection.rst
+++ b/Documentation/translations/zh_CN/security/self-protection.rst
@@ -259,7 +259,7 @@ KALLSYSM=EF=BC=8C=E5=88=99=E4=BC=9A=E7=9B=B4=E6=8E=A5=
=E6=89=93=E5=8D=B0=E5=8E=9F=E5=A7=8B=E5=9C=B0=E5=9D=80=E3=80=82
 --------
=20
 =E5=9C=A8=E9=87=8A=E6=94=BE=E5=86=85=E5=AD=98=E6=97=B6=EF=BC=8C=E6=9C=80=
=E5=A5=BD=E5=AF=B9=E5=86=85=E5=AD=98=E5=86=85=E5=AE=B9=E8=BF=9B=E8=A1=8C=E6=
=B8=85=E9=99=A4=E5=A4=84=E7=90=86=EF=BC=8C=E4=BB=A5=E9=98=B2=E6=AD=A2=E6=94=
=BB=E5=87=BB=E8=80=85=E9=87=8D=E7=94=A8=E5=86=85=E5=AD=98=E4=B8=AD=E4=BB=A5=
=E5=89=8D
-=E7=9A=84=E5=86=85=E5=AE=B9=E3=80=82=E4=BE=8B=E5=A6=82=EF=BC=8C=E5=9C=A8=
=E7=B3=BB=E7=BB=9F=E8=B0=83=E7=94=A8=E8=BF=94=E5=9B=9E=E6=97=B6=E6=B8=85=E9=
=99=A4=E5=A0=86=E6=A0=88=EF=BC=88CONFIG_GCC_PLUGIN_STACKLEAK=EF=BC=89,
+=E7=9A=84=E5=86=85=E5=AE=B9=E3=80=82=E4=BE=8B=E5=A6=82=EF=BC=8C=E5=9C=A8=
=E7=B3=BB=E7=BB=9F=E8=B0=83=E7=94=A8=E8=BF=94=E5=9B=9E=E6=97=B6=E6=B8=85=E9=
=99=A4=E5=A0=86=E6=A0=88=EF=BC=88CONFIG_KSTACK_ERASE=EF=BC=89,
 =E5=9C=A8=E9=87=8A=E6=94=BE=E5=A0=86=E5=86=85=E5=AE=B9=E6=98=AF=E6=B8=85=
=E9=99=A4=E5=85=B6=E5=86=85=E5=AE=B9=E3=80=82=E8=BF=99=E6=9C=89=E5=8A=A9=E4=
=BA=8E=E9=98=B2=E6=AD=A2=E8=AE=B8=E5=A4=9A=E6=9C=AA=E5=88=9D=E5=A7=8B=E5=8C=
=96=E5=8F=98=E9=87=8F=E6=94=BB=E5=87=BB=E3=80=81=E5=A0=86=E6=A0=88=E5=86=85=
=E5=AE=B9
 =E6=B3=84=E9=9C=B2=E3=80=81=E5=A0=86=E5=86=85=E5=AE=B9=E6=B3=84=E9=9C=B2=
=E4=BB=A5=E5=8F=8A=E4=BD=BF=E7=94=A8=E5=90=8E=E9=87=8A=E6=94=BE=E6=94=BB=E5=
=87=BB=EF=BC=88user-after-free=EF=BC=89=E3=80=82
=20
diff --git a/arch/x86/entry/calling.h b/arch/x86/entry/calling.h
index d83236b96f22..94519688b007 100644
--- a/arch/x86/entry/calling.h
+++ b/arch/x86/entry/calling.h
@@ -369,7 +369,7 @@ For 32-bit we have the following conventions - kernel i=
s built with
 .endm
=20
 .macro STACKLEAK_ERASE_NOCLOBBER
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	PUSH_AND_CLEAR_REGS
 	call stackleak_erase
 	POP_REGS
@@ -388,7 +388,7 @@ For 32-bit we have the following conventions - kernel i=
s built with
 #endif /* !CONFIG_X86_64 */
=20
 .macro STACKLEAK_ERASE
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	call stackleak_erase
 #endif
 .endm
diff --git a/include/linux/stackleak.h b/include/linux/kstack_erase.h
similarity index 85%
rename from include/linux/stackleak.h
rename to include/linux/kstack_erase.h
index 3be2cb564710..4e432eefa4d0 100644
--- a/include/linux/stackleak.h
+++ b/include/linux/kstack_erase.h
@@ -1,6 +1,6 @@
 /* SPDX-License-Identifier: GPL-2.0 */
-#ifndef _LINUX_STACKLEAK_H
-#define _LINUX_STACKLEAK_H
+#ifndef _LINUX_KSTACK_ERASE_H
+#define _LINUX_KSTACK_ERASE_H
=20
 #include <linux/sched.h>
 #include <linux/sched/task_stack.h>
@@ -9,10 +9,10 @@
  * Check that the poison value points to the unused hole in the
  * virtual memory map for your platform.
  */
-#define STACKLEAK_POISON -0xBEEF
-#define STACKLEAK_SEARCH_DEPTH 128
+#define KSTACK_ERASE_POISON -0xBEEF
+#define KSTACK_ERASE_SEARCH_DEPTH 128
=20
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 #include <asm/stacktrace.h>
 #include <linux/linkage.h>
=20
@@ -50,7 +50,7 @@ stackleak_task_high_bound(const struct task_struct *tsk)
 static __always_inline unsigned long
 stackleak_find_top_of_poison(const unsigned long low, const unsigned long =
high)
 {
-	const unsigned int depth =3D STACKLEAK_SEARCH_DEPTH / sizeof(unsigned lon=
g);
+	const unsigned int depth =3D KSTACK_ERASE_SEARCH_DEPTH / sizeof(unsigned =
long);
 	unsigned int poison_count =3D 0;
 	unsigned long poison_high =3D high;
 	unsigned long sp =3D high;
@@ -58,7 +58,7 @@ stackleak_find_top_of_poison(const unsigned long low, con=
st unsigned long high)
 	while (sp > low && poison_count < depth) {
 		sp -=3D sizeof(unsigned long);
=20
-		if (*(unsigned long *)sp =3D=3D STACKLEAK_POISON) {
+		if (*(unsigned long *)sp =3D=3D KSTACK_ERASE_POISON) {
 			poison_count++;
 		} else {
 			poison_count =3D 0;
@@ -72,7 +72,7 @@ stackleak_find_top_of_poison(const unsigned long low, con=
st unsigned long high)
 static inline void stackleak_task_init(struct task_struct *t)
 {
 	t->lowest_stack =3D stackleak_task_low_bound(t);
-# ifdef CONFIG_STACKLEAK_METRICS
+# ifdef CONFIG_KSTACK_ERASE_METRICS
 	t->prev_lowest_stack =3D t->lowest_stack;
 # endif
 }
@@ -82,7 +82,7 @@ asmlinkage void noinstr stackleak_erase_on_task_stack(voi=
d);
 asmlinkage void noinstr stackleak_erase_off_task_stack(void);
 void __no_caller_saved_registers noinstr stackleak_track_stack(void);
=20
-#else /* !CONFIG_GCC_PLUGIN_STACKLEAK */
+#else /* !CONFIG_KSTACK_ERASE */
 static inline void stackleak_task_init(struct task_struct *t) { }
 #endif
=20
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 8c60a42f9d00..9051d9484393 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1606,8 +1606,10 @@ struct task_struct {
 	/* Used by BPF for per-TASK xdp storage */
 	struct bpf_net_context		*bpf_net_context;
=20
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	unsigned long			lowest_stack;
+#endif
+#ifdef CONFIG_KSTACK_ERASE_METRICS
 	unsigned long			prev_lowest_stack;
 #endif
=20
diff --git a/arch/arm/kernel/entry-common.S b/arch/arm/kernel/entry-common.=
S
index f379c852dcb7..88336a1292bb 100644
--- a/arch/arm/kernel/entry-common.S
+++ b/arch/arm/kernel/entry-common.S
@@ -119,7 +119,7 @@ no_work_pending:
=20
 	ct_user_enter save =3D 0
=20
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	bl	stackleak_erase_on_task_stack
 #endif
 	restore_user_regs fast =3D 0, offset =3D 0
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index 5ae2a34b50bd..67331437b2aa 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -614,7 +614,7 @@ SYM_CODE_END(ret_to_kernel)
 SYM_CODE_START_LOCAL(ret_to_user)
 	ldr	x19, [tsk, #TSK_TI_FLAGS]	// re-check for single-step
 	enable_step_tsk x19, x2
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	bl	stackleak_erase_on_task_stack
 #endif
 	kernel_exit 0
diff --git a/arch/riscv/kernel/entry.S b/arch/riscv/kernel/entry.S
index af514614404a..49e2344007c8 100644
--- a/arch/riscv/kernel/entry.S
+++ b/arch/riscv/kernel/entry.S
@@ -220,7 +220,7 @@ SYM_CODE_START_NOALIGN(ret_from_exception)
 #endif
 	bnez s0, 1f
=20
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	call	stackleak_erase_on_task_stack
 #endif
=20
diff --git a/arch/s390/kernel/entry.S b/arch/s390/kernel/entry.S
index 0f00f4b06d51..75b0fbb236d0 100644
--- a/arch/s390/kernel/entry.S
+++ b/arch/s390/kernel/entry.S
@@ -124,7 +124,7 @@ _LPP_OFFSET	=3D __LC_LPP
 #endif
=20
 	.macro STACKLEAK_ERASE
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_KSTACK_ERASE
 	brasl	%r14,stackleak_erase_on_task_stack
 #endif
 	.endm
diff --git a/drivers/misc/lkdtm/stackleak.c b/drivers/misc/lkdtm/kstack_era=
se.c
similarity index 89%
rename from drivers/misc/lkdtm/stackleak.c
rename to drivers/misc/lkdtm/kstack_erase.c
index f1d022160913..4fd9b0bfb874 100644
--- a/drivers/misc/lkdtm/stackleak.c
+++ b/drivers/misc/lkdtm/kstack_erase.c
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
  * This code tests that the current task stack is properly erased (filled
- * with STACKLEAK_POISON).
+ * with KSTACK_ERASE_POISON).
  *
  * Authors:
  *   Alexander Popov <alex.popov@linux.com>
@@ -9,9 +9,9 @@
  */
=20
 #include "lkdtm.h"
-#include <linux/stackleak.h>
+#include <linux/kstack_erase.h>
=20
-#if defined(CONFIG_GCC_PLUGIN_STACKLEAK)
+#if defined(CONFIG_KSTACK_ERASE)
 /*
  * Check that stackleak tracks the lowest stack pointer and erases the sta=
ck
  * below this as expected.
@@ -85,7 +85,7 @@ static void noinstr check_stackleak_irqoff(void)
 	while (poison_low > task_stack_low) {
 		poison_low -=3D sizeof(unsigned long);
=20
-		if (*(unsigned long *)poison_low =3D=3D STACKLEAK_POISON)
+		if (*(unsigned long *)poison_low =3D=3D KSTACK_ERASE_POISON)
 			continue;
=20
 		instrumentation_begin();
@@ -96,7 +96,7 @@ static void noinstr check_stackleak_irqoff(void)
 	}
=20
 	instrumentation_begin();
-	pr_info("stackleak stack usage:\n"
+	pr_info("kstack erase stack usage:\n"
 		"  high offset: %lu bytes\n"
 		"  current:     %lu bytes\n"
 		"  lowest:      %lu bytes\n"
@@ -121,7 +121,7 @@ static void noinstr check_stackleak_irqoff(void)
 	instrumentation_end();
 }
=20
-static void lkdtm_STACKLEAK_ERASING(void)
+static void lkdtm_KSTACK_ERASE(void)
 {
 	unsigned long flags;
=20
@@ -129,19 +129,19 @@ static void lkdtm_STACKLEAK_ERASING(void)
 	check_stackleak_irqoff();
 	local_irq_restore(flags);
 }
-#else /* defined(CONFIG_GCC_PLUGIN_STACKLEAK) */
-static void lkdtm_STACKLEAK_ERASING(void)
+#else /* defined(CONFIG_KSTACK_ERASE) */
+static void lkdtm_KSTACK_ERASE(void)
 {
-	if (IS_ENABLED(CONFIG_HAVE_ARCH_STACKLEAK)) {
-		pr_err("XFAIL: stackleak is not enabled (CONFIG_GCC_PLUGIN_STACKLEAK=3Dn=
)\n");
+	if (IS_ENABLED(CONFIG_HAVE_ARCH_KSTACK_ERASE)) {
+		pr_err("XFAIL: stackleak is not enabled (CONFIG_KSTACK_ERASE=3Dn)\n");
 	} else {
-		pr_err("XFAIL: stackleak is not supported on this arch (HAVE_ARCH_STACKL=
EAK=3Dn)\n");
+		pr_err("XFAIL: stackleak is not supported on this arch (HAVE_ARCH_KSTACK=
_ERASE=3Dn)\n");
 	}
 }
-#endif /* defined(CONFIG_GCC_PLUGIN_STACKLEAK) */
+#endif /* defined(CONFIG_KSTACK_ERASE) */
=20
 static struct crashtype crashtypes[] =3D {
-	CRASHTYPE(STACKLEAK_ERASING),
+	CRASHTYPE(KSTACK_ERASE),
 };
=20
 struct crashtype_category stackleak_crashtypes =3D {
diff --git a/fs/proc/base.c b/fs/proc/base.c
index c667702dc69b..be34612af8b6 100644
--- a/fs/proc/base.c
+++ b/fs/proc/base.c
@@ -3291,7 +3291,7 @@ static int proc_pid_ksm_stat(struct seq_file *m, stru=
ct pid_namespace *ns,
 }
 #endif /* CONFIG_KSM */
=20
-#ifdef CONFIG_STACKLEAK_METRICS
+#ifdef CONFIG_KSTACK_ERASE_METRICS
 static int proc_stack_depth(struct seq_file *m, struct pid_namespace *ns,
 				struct pid *pid, struct task_struct *task)
 {
@@ -3304,7 +3304,7 @@ static int proc_stack_depth(struct seq_file *m, struc=
t pid_namespace *ns,
 							prev_depth, depth);
 	return 0;
 }
-#endif /* CONFIG_STACKLEAK_METRICS */
+#endif /* CONFIG_KSTACK_ERASE_METRICS */
=20
 /*
  * Thread groups
@@ -3411,7 +3411,7 @@ static const struct pid_entry tgid_base_stuff[] =3D {
 #ifdef CONFIG_LIVEPATCH
 	ONE("patch_state",  S_IRUSR, proc_pid_patch_state),
 #endif
-#ifdef CONFIG_STACKLEAK_METRICS
+#ifdef CONFIG_KSTACK_ERASE_METRICS
 	ONE("stack_depth", S_IRUGO, proc_stack_depth),
 #endif
 #ifdef CONFIG_PROC_PID_ARCH_STATUS
diff --git a/kernel/fork.c b/kernel/fork.c
index 1ee8eb11f38b..1ec66911f6f6 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -93,7 +93,7 @@
 #include <linux/kcov.h>
 #include <linux/livepatch.h>
 #include <linux/thread_info.h>
-#include <linux/stackleak.h>
+#include <linux/kstack_erase.h>
 #include <linux/kasan.h>
 #include <linux/scs.h>
 #include <linux/io_uring.h>
diff --git a/kernel/stackleak.c b/kernel/kstack_erase.c
similarity index 90%
rename from kernel/stackleak.c
rename to kernel/kstack_erase.c
index bb65321761b4..201b846f8345 100644
--- a/kernel/stackleak.c
+++ b/kernel/kstack_erase.c
@@ -6,14 +6,14 @@
  *
  * Author: Alexander Popov <alex.popov@linux.com>
  *
- * STACKLEAK reduces the information which kernel stack leak bugs can
+ * KSTACK_ERASE reduces the information which kernel stack leak bugs can
  * reveal and blocks some uninitialized stack variable attacks.
  */
=20
-#include <linux/stackleak.h>
+#include <linux/kstack_erase.h>
 #include <linux/kprobes.h>
=20
-#ifdef CONFIG_STACKLEAK_RUNTIME_DISABLE
+#ifdef CONFIG_KSTACK_ERASE_RUNTIME_DISABLE
 #include <linux/jump_label.h>
 #include <linux/string_choices.h>
 #include <linux/sysctl.h>
@@ -68,7 +68,7 @@ late_initcall(stackleak_sysctls_init);
 #define skip_erasing()	static_branch_unlikely(&stack_erasing_bypass)
 #else
 #define skip_erasing()	false
-#endif /* CONFIG_STACKLEAK_RUNTIME_DISABLE */
+#endif /* CONFIG_KSTACK_ERASE_RUNTIME_DISABLE */
=20
 #ifndef __stackleak_poison
 static __always_inline void __stackleak_poison(unsigned long erase_low,
@@ -91,7 +91,7 @@ static __always_inline void __stackleak_erase(bool on_tas=
k_stack)
 	erase_low =3D stackleak_find_top_of_poison(task_stack_low,
 						 current->lowest_stack);
=20
-#ifdef CONFIG_STACKLEAK_METRICS
+#ifdef CONFIG_KSTACK_ERASE_METRICS
 	current->prev_lowest_stack =3D erase_low;
 #endif
=20
@@ -113,7 +113,7 @@ static __always_inline void __stackleak_erase(bool on_t=
ask_stack)
 	else
 		erase_high =3D task_stack_high;
=20
-	__stackleak_poison(erase_low, erase_high, STACKLEAK_POISON);
+	__stackleak_poison(erase_low, erase_high, KSTACK_ERASE_POISON);
=20
 	/* Reset the 'lowest_stack' value for the next syscall */
 	current->lowest_stack =3D task_stack_high;
@@ -161,11 +161,11 @@ void __used __no_caller_saved_registers noinstr stack=
leak_track_stack(void)
 	unsigned long sp =3D current_stack_pointer;
=20
 	/*
-	 * Having CONFIG_STACKLEAK_TRACK_MIN_SIZE larger than
-	 * STACKLEAK_SEARCH_DEPTH makes the poison search in
+	 * Having CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE larger than
+	 * KSTACK_ERASE_SEARCH_DEPTH makes the poison search in
 	 * stackleak_erase() unreliable. Let's prevent that.
 	 */
-	BUILD_BUG_ON(CONFIG_STACKLEAK_TRACK_MIN_SIZE > STACKLEAK_SEARCH_DEPTH);
+	BUILD_BUG_ON(CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE > KSTACK_ERASE_SEARCH_DEP=
TH);
=20
 	/* 'lowest_stack' should be aligned on the register width boundary */
 	sp =3D ALIGN(sp, sizeof(unsigned long));
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index b21b12ec88d9..31088a138bc9 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1191,7 +1191,7 @@ static const char *uaccess_safe_builtin[] =3D {
 	"__ubsan_handle_type_mismatch_v1",
 	"__ubsan_handle_shift_out_of_bounds",
 	"__ubsan_handle_load_invalid_value",
-	/* STACKLEAK */
+	/* KSTACK_ERASE */
 	"stackleak_track_stack",
 	/* TRACE_BRANCH_PROFILING */
 	"ftrace_likely_update",
diff --git a/tools/testing/selftests/lkdtm/config b/tools/testing/selftests=
/lkdtm/config
index 7afe05e8c4d7..bd09fdaf53e0 100644
--- a/tools/testing/selftests/lkdtm/config
+++ b/tools/testing/selftests/lkdtm/config
@@ -2,7 +2,7 @@ CONFIG_LKDTM=3Dy
 CONFIG_DEBUG_LIST=3Dy
 CONFIG_SLAB_FREELIST_HARDENED=3Dy
 CONFIG_FORTIFY_SOURCE=3Dy
-CONFIG_GCC_PLUGIN_STACKLEAK=3Dy
+CONFIG_KSTACK_ERASE=3Dy
 CONFIG_HARDENED_USERCOPY=3Dy
 CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=3Dy
 CONFIG_INIT_ON_FREE_DEFAULT_ON=3Dy
diff --git a/MAINTAINERS b/MAINTAINERS
index 79a8e2c73908..9f76b329fdb3 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9971,8 +9971,6 @@ L:	linux-hardening@vger.kernel.org
 S:	Maintained
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-ne=
xt/hardening
 F:	Documentation/kbuild/gcc-plugins.rst
-F:	include/linux/stackleak.h
-F:	kernel/stackleak.c
 F:	scripts/Makefile.gcc-plugins
 F:	scripts/gcc-plugins/
=20
@@ -13060,10 +13058,12 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/=
git/kees/linux.git for-next/har
 F:	Documentation/ABI/testing/sysfs-kernel-oops_count
 F:	Documentation/ABI/testing/sysfs-kernel-warn_count
 F:	arch/*/configs/hardening.config
+F:	include/linux/kstack_erase.h
 F:	include/linux/overflow.h
 F:	include/linux/randomize_kstack.h
 F:	include/linux/ucopysize.h
 F:	kernel/configs/hardening.config
+F:	kernel/kstack_erase.c
 F:	lib/tests/randstruct_kunit.c
 F:	lib/tests/usercopy_kunit.c
 F:	mm/usercopy.c
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250523043935.2009972-1-kees%40kernel.org.
