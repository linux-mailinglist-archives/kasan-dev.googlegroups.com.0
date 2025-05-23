Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDHYX7AQMGQEGK2GJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 196BCAC1B04
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:42 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-476c2d1c582sf10060101cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975180; cv=pass;
        d=google.com; s=arc-20240605;
        b=gIZALEMAF6XYd4eVyGi0OgALOTflNdJGB9rD23tZxISDtKXOehNMlnBlvQg98xSnmb
         g2ZegZv93/PIbR4CuJY7DPfE+fYDGg7OLo1s7f1PAT52vGvXUrkktSIR6wMAqa7/03K0
         2/HGsO6jKNJpGLs/cMZVkrm8JX7LLOAi7IXkBij6/g5FK8y5iVPS4VfZ4NJ7kWhgGEYt
         1Zxf1/5qKrZkfME7GuYixrhurA9GHK1ZVRiCIJ+rwXwS+UBNJ7j2fa36ox9btFnry7sS
         ROnojsHdaMHZDsOLINb44jvoGYgIB2f+X/jsyfk04OkEZwBV2J48vfhEldpHFeq23xnx
         i8Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2qPJEt/80eZPLzZxChmWrhctHVvOFWU2CRmaaq8c+BA=;
        fh=mePKsw47qoGeP6oRxzu9fKHIEij0dYTsQNCtbgCTd5o=;
        b=S0jLypdVE/hugESK2HFJU9rk/Y+rSCsD3vkIDv0ZKXnaEmUhbg6AZCaLcaij6e7uAv
         59JS0CrLSjd7Snr/+q86MrbzaoJ+zU4rE6BdYWa6q/KfcAqdUti3bBbPP8M9nXDt/tnG
         HUBjt10QRdU3VIqXCMw4jwO2joxwYYqwh/ZCnbizxp0+JiFybTuVtJPCMzK/T6sAsKGe
         xfF74uNTquZpiCEQj+VC5v49+FTamWMncHeaUC5g6U6vWgk78EjnM8CxYyplx/WEQnRn
         H+Mr3MURH5F1moQUPGScn+sHleduzxPLzOx/pnvwcUM+7BBmLVcE3kr9QL+PBUY4eo8P
         CugQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CjCSBxXm;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975180; x=1748579980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2qPJEt/80eZPLzZxChmWrhctHVvOFWU2CRmaaq8c+BA=;
        b=fq5yoGK2malHNkAWfWydQGqjoREg2htrUFM2KmEbHf+GGRynMLUnNuS/BEmOPtSKHp
         V0NNz5n3XtScB7YRRGy7VwBKudT0FZqvsW33o3JFtYHVU4R9VVV8a96r9UPuBiqdT9jN
         N0EZ67MSXXnbOwpJMvPsr79Ag6kLHEmynYhW9lTzYEFzFufdYR4oPhgfwPZrdZD3NbxD
         wyhv4HbLylCbiFnlGMhmVn85ci4oju6EgqSyt5Z5r9tN/T3CDthBiWsEThCrxsr6V1bU
         KcyrU5GDfEEnneyznu+IX1aLHrW1GIm1hWDeiyr/G4DsL8AoyN+dl/m0hJuRUeSqQ7fi
         AfhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975180; x=1748579980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2qPJEt/80eZPLzZxChmWrhctHVvOFWU2CRmaaq8c+BA=;
        b=rqBEbiVQ5TaB8WWxaTgiWYa8GdwGVUOp/VFkvpIUOCtUUZ9ebkWT4hTLCiUSWcmsVz
         lAwJAipizcU1spdXidrm9MR//J0M9MQp7tCVXxlFAUw8KKvCs0T38Bv0PwvSg58Qkc+M
         r/Kx0fsSEJRD/kurV0PSGR7h9LC++z5W4SCc+CnQV81FdSLS5y2MpoMNCkpB36FlhaDK
         FeYx0IfO4A5ngMgj3JXF3gp0zcgpTzcipx+Gq5uHAAWdWsm21ncM5chWo1xqOdZ0K7EN
         dOMRO44iiuMC2hgkrxTLMBoEwpXHQmM/zKMzi4aBbLu3aOLw4HqbT9QfY70oNQgM6/vM
         jMGQ==
X-Forwarded-Encrypted: i=2; AJvYcCXGV/XtDudUj8y9Ysdz/VDg5xQZW/zb9USfU9WZnybAK0BcBqhZyJUkoo8oj8JsmBGVTpmJUg==@lfdr.de
X-Gm-Message-State: AOJu0Yx0utprwabC7qikqhybCElrwcv9AK3ekbcsAxnnr6vMG/w2SBeD
	lqWIyDMyS4IVCg7azkAy838ZFZZW6te09ojzY5W3MLadARMjqkkWm3KU
X-Google-Smtp-Source: AGHT+IH1jWaWsCFm2hfess6tmUXwJGSfPiQDNj8qwpBEcmQg3U78vyeNJZNyPyNKXVUH5rmv4YvB1A==
X-Received: by 2002:ac8:5fd6:0:b0:494:ac12:5cb8 with SMTP id d75a77b69052e-49dfce58886mr31318991cf.25.1747975180505;
        Thu, 22 May 2025 21:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEuNaUrz4Y4Xk2ooydLo6Fl4aXFg+Vw1BAsO6VogXmeOQ==
Received: by 2002:a05:622a:7713:b0:497:b054:a044 with SMTP id
 d75a77b69052e-497b054a312ls91902551cf.1.-pod-prod-00-us; Thu, 22 May 2025
 21:39:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXil3ET0xckoVM0aB5NwaGYmX4xF2FgaDlVdasCagdnLji4CS6ov7lk2t5Rj249omQWzf0A8v/MPBk=@googlegroups.com
X-Received: by 2002:a05:622a:90e:b0:48d:4887:9850 with SMTP id d75a77b69052e-49dfcf55d96mr37502981cf.19.1747975179628;
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975179; cv=none;
        d=google.com; s=arc-20240605;
        b=jC5cUp4fFnF/L+K+CIGka1tj912s09YACELcK7CZ+SLdarktuduK94ud3WCa73cbPB
         3Ww7YB2kWmmXei84A0yiJ3IDiyer9ckXTrkoVDuqAn1HUAX4mKgHk41WypnmtMREK9KS
         Bf8Aki8d3xEExDiMgKwYRcwz6pTz25iGEsTpg4U50w5uq5rrRDvVlyREs9P2nyNZLHM6
         1q4H28SlGDVMc7y47YKz245D90+DQU1Gw6fXmqEt7CthKSu59DgauPKk7ioQpXABnU+B
         nPk6suWLSPC+qq9kyGVoWXXIdFfi49fejgVBD69mu5NqadescRDLp+Tbw3VrIfs9Aj3v
         tA4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zJD+ACc+H0NLjlvdWHEkxM5n+92YJQxfFnkkbm9z+7Q=;
        fh=iqyaNv71WZ05ND5g9H2nycOZ8/KvMBm17gFrrdbmmto=;
        b=H/eUdLKidok1oygO2bBfclibFzkf7k4Bs4hPitNO6OnPhKnbabyb5RLjZrDJBlh6qW
         C3J9epsq1Y5/iMemzW72RpbNgl2pT9XhJlZ7BkOyDy0IDIFmIoKJDUUmM1NJGWHLlEPi
         QL2qwnOObW0mTZTq3pEFWc795ROak2Ct+HSpP8VgrKwwmnGUc58ycnHstgioFJFFFIt6
         0z6GUWZAxn6Lmaw34A2SGtJbk28nEFfyE5ojXmuUjEwwIhzdns5wTArllJi2mmJsqHWs
         XwSRNa3AZ9NiByXRBOYfjWKwOt5OSDZXiabfXN+zmTTknsBfnInhSvDXSp09jKm1xJOp
         A9QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CjCSBxXm;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-494ae409947si7147601cf.2.2025.05.22.21.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 978614A5E0;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68EEFC4AF0C;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	sparclinux@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
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
	linux-doc@vger.kernel.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 03/14] stackleak: Split KSTACK_ERASE_CFLAGS from GCC_PLUGINS_CFLAGS
Date: Thu, 22 May 2025 21:39:13 -0700
Message-Id: <20250523043935.2009972-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=8284; i=kees@kernel.org; h=from:subject; bh=eWRsrdfChO/6nxvZ/lswGVHEy8N01D610T/TBTk48qM=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/M4L5kqPDWsu/D37Zj0uE23tMv7z9xqLl0obbR+ wjWeMOQjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIlMvMvIcNd8c+86HffiN8rJ 6+ySOnSmXdo/9UVUUNSN5YdjJ+qlT2D4KxV5LlhZ/0ta26qZV/m37FOc21Y3qSawPO71I96NVns +MgMA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CjCSBxXm;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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
index 4bfac7e00d2b..4c9e4b5ec36c 100644
--- a/Makefile
+++ b/Makefile
@@ -1086,6 +1086,7 @@ include-$(CONFIG_KMSAN)		+= scripts/Makefile.kmsan
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
index 9f76b329fdb3..f4dcf3c0be8d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13067,6 +13067,8 @@ F:	kernel/kstack_erase.c
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-3-kees%40kernel.org.
