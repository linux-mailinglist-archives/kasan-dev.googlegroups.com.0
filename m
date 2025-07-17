Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYUM43BQMGQEXPFHJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 49E39B0973F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4ab3b89760bsf28456281cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794722; cv=pass;
        d=google.com; s=arc-20240605;
        b=dGqR/h/phGnkTV7MmrwRA79Tkv9VFRe0fofj/PTNNoywRAFwfObUQAXBn6dBumcDT6
         mWCa1I4dEC2ryJ4bVupvoI1/7b3gvO6aofH299Wt7fId28wGR0slvEr2cCycz8fKA98n
         a+GBERFc9i8/NQX+ZJkbR7iUeyKIXsQ5RGVCqH8DUAvoHVSAoN+MVS0vxtaPp5ogPj9p
         vZqtsGSn/W+eX8/kFBe91TGe1hUWoY9htJW/4J5MdAKjy8lyWlxlpov640YTm7l4thLI
         bkk33RVMzRUsYSZBkFhNFcwu7z/QMo/I9X4Jeep1voNKjARGuD+fsr3H2h3Q+kUWAKVx
         /sPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qEqEpwZ4syz06BtmdR0N5t452sEbcJ6O3m0ktJ2jI+0=;
        fh=O0dY0EjTJ+nqLB0UzD9STmemkOL5lBdru+WuPE9vpxw=;
        b=YCbYqV75qnerA6xY7oBDqYs7J2C2nlfZZB4qvO877n+m2ALKd9JtBSm8pvBSWIWyIj
         z6eWZeWRSAfr2pDLGymZGpdW6qUX4jJJ9AqLmIslCNiFg27ABVkw4iyuyZgU0LY70IY+
         K0rntAUbXde01EPsyVNVCFmNg2Ne52sCBhmE6Kjv2TKmGlrvUnS0TkcLxKYLBD8CwgbM
         d0pJ7fwyJ7d2oOBJ41KDLvxI4ldLCR/YtAHOy48QWTRIttBnmO/LT/DjX2vbGLIBczDx
         7IMP14irm/Uvzrzeq/LlMpGi91cSukjqqT8jRWtFJ5WeFGQ0EpiIZcNnxctqLoQbNbsi
         fSuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tk4wrPxY;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794722; x=1753399522; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qEqEpwZ4syz06BtmdR0N5t452sEbcJ6O3m0ktJ2jI+0=;
        b=v/0fYPl037jIO35DQ9G8JuQcA9vP71zrPd+VgbHn13bNDoJ3F4pMJ35uVJG0N/R4bV
         4h6XLWlp0VVbAQpbPmcPnBYmK5rfNgPZU0lgdyCv9CxAfkPpev1bL4nl2QXpPsqc420o
         ozmQWRXjCn7BIp6nxsPxIw8bg8gYpzJytWOUSM1LRNzsfFK2Zz3WaH7pzZ9CID+kNvBp
         Fd1B66js0BxHsfE0IVeV8gX3djB3xn4J6JGrgaIzGrURBpQQBLip9hzimLtuIjLkm3Rz
         HF8aZFrpyFgkzXANLZ/sAzKnZdV/9V3I/YtKL5tn/OHcH13Mfrnk4LYNvEtJuGqdSYBE
         Eijg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794722; x=1753399522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qEqEpwZ4syz06BtmdR0N5t452sEbcJ6O3m0ktJ2jI+0=;
        b=J0wn/TQqoo1GwJhoa86oCW55L22YMKvdLkQAHRXw4OPlgwN4QmR7gpkXam9aiP7jnW
         gwcqpCJYpVcrUi1Qf1tgv8C1T6GaM1Iwpv4wMqHA4sNI446/nA5PRBs6NqNLaBc4PvKl
         Bm4n4uypivkK32Lj7sg8uovrq5z76RV6WFkN2K0NUjc5OAznFKLgliGH4uDqoBw/aIq3
         D5fz7Q49fRO/P/dQqKrB2CrZ94f2n6Lc93gwT9Y9rQLc6ZQNwxs3LziNw8I3wXw6+YFR
         S3+LR7vGZR4wzdcwXIPs2APxMRn14OIAnfMYtfEgUld8zJ+k+inz5TnDI4MEIxf5Vrkj
         r8lQ==
X-Forwarded-Encrypted: i=2; AJvYcCUr3bG69vc57qDR9Xe5/xIIR7O/JhEFyaqoMgSz2spMIUFm0X0FgVGSMh3TJGB0oBWMw3yfoQ==@lfdr.de
X-Gm-Message-State: AOJu0YytzWC09O7Vh3rBlHzTbaaRFKe6B/GKN9cQGjnkiSJBElQGHjNB
	1HOEVzry9G4d+50r+cjHlqRHqp5EBsWBeZL04SssgaeuV6KgqnsbaGue
X-Google-Smtp-Source: AGHT+IHNkvj7gOCwEy91h857dIS3woO+w7eIz4G9K14vVOT1Q5WxkFDmG2G3SUC41B6698GEo44c9g==
X-Received: by 2002:ac8:5d13:0:b0:4a7:234e:6c00 with SMTP id d75a77b69052e-4ab93c4305emr131413141cf.2.1752794722561;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdyVwVErpY3pfeFXRTbrLSWKL/ZYq167b65Ltqym9XY2Q==
Received: by 2002:ac8:5d07:0:b0:4ab:9462:5bc0 with SMTP id d75a77b69052e-4aba1a20f84ls25303771cf.2.-pod-prod-06-us;
 Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVgY7+Jjzq/EmFrb5e3Hw99bi/H5Ge+/u07NlCwdzMKQzyC4iWU4eFX2vhvOfe0+qHNx15u/k9JSSY=@googlegroups.com
X-Received: by 2002:a05:620a:a49a:b0:7e3:4416:a894 with SMTP id af79cd13be357-7e34416b8dfmr981174685a.62.1752794721741;
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794721; cv=none;
        d=google.com; s=arc-20240605;
        b=OKaPWOBC7jHalQjNo8HBrZVHzvqKfw7qA1PywUi2nE/gqttzwFjSujF6JRfiFPUlh1
         8J3nNzJUMvfdeEDPBKculCgBkSxe9Lb5uIk2wzDap521KJnuZKgX4QlDkenrsMiaXxuw
         4vnqIgjDT3G2DV4r1OSpbUv0C28WwD0cglIwJLktkA9Zo7tFUD12aOoyEdIl007f7qtl
         X4NpFPyMNnHYNejD9CaPDQneYBY0dk+Ngt6Pd/dY0R/XdshryOZ1zZ9Yxz1ZudZEaVCJ
         ELSX0Fofvx2p8I7Aopto+OGc3fm8bz/HInq61prNaRrKf6RA2JxRhZmgZGAa9xsWOilp
         lWsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9DKEpDT6T1BPqsVAWrceXw4lPDKFraM5BnCzEwZS7U4=;
        fh=WZJkt84XCV/3zgKZFst2RvouTw0h4Uh5Z7o2zI50hss=;
        b=GfuFDSYYXLDFKqR/b4EPwCV7+fza76uj3erp5IDm6cOt+1iyc5KRUq/OXUGwC1ueCE
         r9eUTqLEg7L06HTdhbsfI2cerf5pjafsOuJqylDQOM6HFnG3Y98iYrEtLTTamRgLTdaU
         XRiKULGvRn/CpbnTxOVEy0ilUWgWW6dXz/PRsgOyz7RpObJkuH2Esmz8syNIo1hhepwq
         AJwN0dDqQsdyBPgzIHGzTHWbnfRdGMRoyXtmrrVsl+hrnTFKOgrOhDYzLB2gdqipyg6K
         FPdHByixKF/2hJ8BOWkKWPDpKKzrWe1ARv+ULpzSWpo90a+Yy5IoqaUCPRjkz2K/p+LE
         Yrow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tk4wrPxY;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e356c1cfa9si2154785a.3.2025.07.17.16.25.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 2E63C613FB;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EF6EC4CEF4;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	sparclinux@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
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
	linux-doc@vger.kernel.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 03/13] stackleak: Split KSTACK_ERASE_CFLAGS from GCC_PLUGINS_CFLAGS
Date: Thu, 17 Jul 2025 16:25:08 -0700
Message-Id: <20250717232519.2984886-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=8284; i=kees@kernel.org; h=from:subject; bh=AbRY71s+EYNiungngyC7ql9fgU96lmuco+up3sBxJKI=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbVFenPsnHmi0VJtRt3zfxZoThbLc+w/fuHDtsa1Lj DZvwOTHHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABfJYWQ4wpYXdVeFRXKb/qJP i6Mbvpg5Kx+RuNVw5v27mZmOGhf+MTLMt4uVMb7Dq+vSeDTycn9P5unzVarG7qGaH02nTeEQqeU DAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Tk4wrPxY;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

In preparation for Clang stack depth tracking for KSTACK_ERASE,
split the stackleak-specific cflags out of GCC_PLUGINS_CFLAGS into
KSTACK_ERASE_CFLAGS.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <x86@kernel.org>
Cc: <linux-arm-kernel@lists.infradead.org>
Cc: <sparclinux@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 Makefile                        |  1 +
 arch/arm/vdso/Makefile          |  2 +-
 arch/arm64/kernel/vdso/Makefile |  3 ++-
 arch/sparc/vdso/Makefile        |  3 ++-
 arch/x86/entry/vdso/Makefile    |  3 ++-
 scripts/Makefile.gcc-plugins    | 16 ++--------------
 scripts/Makefile.kstack_erase   | 15 +++++++++++++++
 MAINTAINERS                     |  2 ++
 8 files changed, 27 insertions(+), 18 deletions(-)
 create mode 100644 scripts/Makefile.kstack_erase

diff --git a/Makefile b/Makefile
index c18d8b64f0e6..d6c0287a061f 100644
--- a/Makefile
+++ b/Makefile
@@ -1092,6 +1092,7 @@ include-$(CONFIG_KMSAN)		+= scripts/Makefile.kmsan
 include-$(CONFIG_UBSAN)		+= scripts/Makefile.ubsan
 include-$(CONFIG_KCOV)		+= scripts/Makefile.kcov
 include-$(CONFIG_RANDSTRUCT)	+= scripts/Makefile.randstruct
+include-$(CONFIG_KSTACK_ERASE)	+= scripts/Makefile.kstack_erase
 include-$(CONFIG_AUTOFDO_CLANG)	+= scripts/Makefile.autofdo
 include-$(CONFIG_PROPELLER_CLANG)	+= scripts/Makefile.propeller
 include-$(CONFIG_GCC_PLUGINS)	+= scripts/Makefile.gcc-plugins
diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index cb044bfd145d..cf8cd39ab804 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -26,7 +26,7 @@ CPPFLAGS_vdso.lds += -P -C -U$(ARCH)
 CFLAGS_REMOVE_vdso.o = -pg
 
 # Force -O2 to avoid libgcc dependencies
-CFLAGS_REMOVE_vgettimeofday.o = -pg -Os $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS)
+CFLAGS_REMOVE_vgettimeofday.o = -pg -Os $(RANDSTRUCT_CFLAGS) $(KSTACK_ERASE_CFLAGS) $(GCC_PLUGINS_CFLAGS)
 ifeq ($(c-gettimeofday-y),)
 CFLAGS_vgettimeofday.o = -O2
 else
diff --git a/arch/arm64/kernel/vdso/Makefile b/arch/arm64/kernel/vdso/Makefile
index 5e27e46aa496..7dec05dd33b7 100644
--- a/arch/arm64/kernel/vdso/Makefile
+++ b/arch/arm64/kernel/vdso/Makefile
@@ -36,7 +36,8 @@ ccflags-y += -DDISABLE_BRANCH_PROFILING -DBUILD_VDSO
 # -Wmissing-prototypes and -Wmissing-declarations are removed from
 # the CFLAGS to make possible to build the kernel with CONFIG_WERROR enabled.
 CC_FLAGS_REMOVE_VDSO := $(CC_FLAGS_FTRACE) -Os $(CC_FLAGS_SCS) \
-			$(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) \
+			$(RANDSTRUCT_CFLAGS) $(KSTACK_ERASE_CFLAGS) \
+			$(GCC_PLUGINS_CFLAGS) \
 			$(CC_FLAGS_LTO) $(CC_FLAGS_CFI) \
 			-Wmissing-prototypes -Wmissing-declarations
 
diff --git a/arch/sparc/vdso/Makefile b/arch/sparc/vdso/Makefile
index fdc4a8f5a49c..683b2d408224 100644
--- a/arch/sparc/vdso/Makefile
+++ b/arch/sparc/vdso/Makefile
@@ -48,7 +48,7 @@ CFL := $(PROFILING) -mcmodel=medlow -fPIC -O2 -fasynchronous-unwind-tables -m64
 
 SPARC_REG_CFLAGS = -ffixed-g4 -ffixed-g5 $(call cc-option,-fcall-used-g5) $(call cc-option,-fcall-used-g7)
 
-$(vobjs): KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
+$(vobjs): KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS) $(KSTACK_ERASE_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
 
 #
 # vDSO code runs in userspace and -pg doesn't help with profiling anyway.
@@ -79,6 +79,7 @@ KBUILD_CFLAGS_32 := $(filter-out -m64,$(KBUILD_CFLAGS))
 KBUILD_CFLAGS_32 := $(filter-out -mcmodel=medlow,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -fno-pic,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RANDSTRUCT_CFLAGS),$(KBUILD_CFLAGS_32))
+KBUILD_CFLAGS_32 := $(filter-out $(KSTACK_ERASE_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(GCC_PLUGINS_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 += -m32 -msoft-float -fpic
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 54d3e9774d62..f247f5f5cb44 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -62,7 +62,7 @@ ifneq ($(RETPOLINE_VDSO_CFLAGS),)
 endif
 endif
 
-$(vobjs): KBUILD_CFLAGS := $(filter-out $(PADDING_CFLAGS) $(CC_FLAGS_LTO) $(CC_FLAGS_CFI) $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
+$(vobjs): KBUILD_CFLAGS := $(filter-out $(PADDING_CFLAGS) $(CC_FLAGS_LTO) $(CC_FLAGS_CFI) $(RANDSTRUCT_CFLAGS) $(KSTACK_ERASE_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
 $(vobjs): KBUILD_AFLAGS += -DBUILD_VDSO
 
 #
@@ -123,6 +123,7 @@ KBUILD_CFLAGS_32 := $(filter-out -mcmodel=kernel,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -fno-pic,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -mfentry,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RANDSTRUCT_CFLAGS),$(KBUILD_CFLAGS_32))
+KBUILD_CFLAGS_32 := $(filter-out $(KSTACK_ERASE_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(GCC_PLUGINS_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(CC_FLAGS_LTO),$(KBUILD_CFLAGS_32))
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 28b8867c4e84..b0e1423b09c2 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -8,20 +8,6 @@ ifdef CONFIG_GCC_PLUGIN_LATENT_ENTROPY
 endif
 export DISABLE_LATENT_ENTROPY_PLUGIN
 
-gcc-plugin-$(CONFIG_GCC_PLUGIN_STACKLEAK)	+= stackleak_plugin.so
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+= -DSTACKLEAK_PLUGIN
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+= -fplugin-arg-stackleak_plugin-track-min-size=$(CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE)
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+= -fplugin-arg-stackleak_plugin-arch=$(SRCARCH)
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE)	\
-		+= -fplugin-arg-stackleak_plugin-verbose
-ifdef CONFIG_GCC_PLUGIN_STACKLEAK
-    DISABLE_KSTACK_ERASE += -fplugin-arg-stackleak_plugin-disable
-endif
-export DISABLE_KSTACK_ERASE
-
 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
 GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -DGCC_PLUGINS
@@ -34,6 +20,8 @@ KBUILD_CFLAGS += $(GCC_PLUGINS_CFLAGS)
 # be included in GCC_PLUGIN so they can get built.
 gcc-plugin-external-$(CONFIG_GCC_PLUGIN_RANDSTRUCT)		\
 	+= randomize_layout_plugin.so
+gcc-plugin-external-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
+	+= stackleak_plugin.so
 
 # All enabled GCC plugins are collected here for building in
 # scripts/gcc-scripts/Makefile.
diff --git a/scripts/Makefile.kstack_erase b/scripts/Makefile.kstack_erase
new file mode 100644
index 000000000000..5223d3a35817
--- /dev/null
+++ b/scripts/Makefile.kstack_erase
@@ -0,0 +1,15 @@
+# SPDX-License-Identifier: GPL-2.0
+
+ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+kstack-erase-cflags-y += -fplugin=$(objtree)/scripts/gcc-plugins/stackleak_plugin.so
+kstack-erase-cflags-y += -fplugin-arg-stackleak_plugin-track-min-size=$(CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE)
+kstack-erase-cflags-y += -fplugin-arg-stackleak_plugin-arch=$(SRCARCH)
+kstack-erase-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE) += -fplugin-arg-stackleak_plugin-verbose
+DISABLE_KSTACK_ERASE := -fplugin-arg-stackleak_plugin-disable
+endif
+
+KSTACK_ERASE_CFLAGS   := $(kstack-erase-cflags-y)
+
+export STACKLEAK_CFLAGS DISABLE_KSTACK_ERASE
+
+KBUILD_CFLAGS += $(KSTACK_ERASE_CFLAGS)
diff --git a/MAINTAINERS b/MAINTAINERS
index 1d8067dd536d..cc7d7b779eb8 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13181,6 +13181,8 @@ F:	kernel/kstack_erase.c
 F:	lib/tests/randstruct_kunit.c
 F:	lib/tests/usercopy_kunit.c
 F:	mm/usercopy.c
+F:	scripts/Makefile.kstack_erase
+F:	scripts/Makefile.randstruct
 F:	security/Kconfig.hardening
 K:	\b(add|choose)_random_kstack_offset\b
 K:	\b__check_(object_size|heap_object)\b
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-3-kees%40kernel.org.
