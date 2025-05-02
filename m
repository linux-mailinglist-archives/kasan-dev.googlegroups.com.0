Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDVN2TAAMGQEQO3UKSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id DE398AA79C2
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 21:01:35 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-476664bffbesf44862461cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 12:01:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746212494; cv=pass;
        d=google.com; s=arc-20240605;
        b=h4GiKgQvUsoFnOLaiUVJ3aTiEmX0zmUTcOD5JUkjDwAXTK7axtBfJQ0l3vobEgbGm+
         KPkteoAokcxyZSLhESQHWSGmGe6DKK56XfWz8otfuk3Q0/bJm2xwAvcZi6KXeM0Aa5aS
         lDynz5wS9f1NUCltpaAPexhVXR21Mjl44LkS27TknF9akbFtwMub3zoUHUwiSA+bCmPr
         6t0PXk4G0fpuC/qhTD8dyLZsaSW33hEudmkXrvG5HTcaMOt7xAJ14pam6qKE0vZyQVN8
         qqF1T9XF6PgSELo7Diz7eP29PcS3ZvKk/k4Txf2zNDKWaVuHBdAzMNGeojpFWZivYOfy
         Tllw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1pBHoHLHEZVGwWeKFjLsUW+bN+bGsgAq0kQ5S8EvOFw=;
        fh=P5aX66yHhOXUPyeUL2zAhd1RoxNMju+c0X4xS/7j8pU=;
        b=CP2REzfpMvP5kRdeauxLgLctHtYSC1s4ygD5jZcYhO7Pes2fq5vcOXM/4o3MiCWHf9
         1UUEutzfxURv3KqrdE7zCbe5EtpBg1Y7eMmkNhcipVkVHgE0oXmcze4zo0KOsMiIGI58
         UJACXlPHMe+eugQlaZ+swfPZiGu81TDi64ESLU8EmA6AbYlR6qrh4kXGUNP4ARFG+AAG
         bKJx1UOO+HwGF0/Co2U21nt9LI04HwPc94N/nSXcAeu/FM15kilzuYSBtW0TMS24vOIH
         Zcxrv1xyGRPi+yRtRjE17DvsuJDn+souAzQGySBDw1Cu365GqQosh+8eOM4Qgf4MK+OV
         gK7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XskH4lLH;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746212494; x=1746817294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1pBHoHLHEZVGwWeKFjLsUW+bN+bGsgAq0kQ5S8EvOFw=;
        b=EAvXk4slHBI6XITxeWuFH58TkisYvHZr0vGDzm8nlWeWWp+zCxpQaNyY5FggOHGRhy
         Vv/+V4HHzFCvBD8mEmUxwxjOakggDEBJcKlKI3PSx9NKpFixynUo2Yj+6AZv9aa48J7/
         v77PZYTp+A0yon78Rqm2vZRzPZeOD4SHyljJkLFuw9QHGg3pJNYIzLYrZDMcvur5shJh
         Xh5FtTOBzbkzEsJw0JMuvEWiNPEDjHdPzkwyYaqrUHLpT93qm1Mh60bSiPwjvObaqR8O
         wgD/r7gn4MdIrR43gZVacsywKJHSDHrA5gz3ntTJs86OHO2fkm3+yYjs3fHBIuverbhG
         2YKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746212494; x=1746817294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1pBHoHLHEZVGwWeKFjLsUW+bN+bGsgAq0kQ5S8EvOFw=;
        b=ZVjusLvX5+KUPL38R+qo/rvXsSl9G1hkvCQ9Y2PQo+14kR/K+k3LOvAwCMbWIunkyg
         YFD0PpEZrhuktIODmWsx8acjK1A3a1r10OxtkE4VS5IFUknUlhhXJWanxu6EYID7i/2b
         WPjH1YGHO7VhVlZBsaEydoATAUIoL7hHTTv2/SONJxkRvN9kAngb8gAlcvy2A9DXuEaC
         EMwMQDKjs9+ETRKzwTXFrFH+MscIjl5Ejmw25v2SwTtEat7lKMNlA6KD8TNMGm8YIZ4/
         NLEGY6oyGSWj6BaDjroj1LMsXMPuCmCTuJXk2nSOYpBXrfOHtLaxdzWZXuUbz3o3k3aW
         HlnA==
X-Forwarded-Encrypted: i=2; AJvYcCWBoJJRKN7UyPcY38Q+JTvttzkCBl0ntmc/y2t6uFrPISrlv8ZxQfmm+JBej13GjnDpkV/AsQ==@lfdr.de
X-Gm-Message-State: AOJu0YzZOlauHZYBc6UW8W/YDcdzncqT7TjSwJaFGCpDnfCq1vw2iS27
	RD5tenAKE6WLWiqoQGClSPXZElHXDbYtL8bS6rdrbeJ4rzEfjAd2
X-Google-Smtp-Source: AGHT+IElI1CWC9HVLu8bCinc7EcOK8UJ0H1nuL/OldKKuf8dGxSOeYAlhN0a1/hjA0ws8IDtDuSt4g==
X-Received: by 2002:a05:622a:4c07:b0:476:8296:17e5 with SMTP id d75a77b69052e-48c31353ea1mr58292001cf.17.1746212494508;
        Fri, 02 May 2025 12:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHBFWSYM13yxWbPDXu37qs0kD6myFAmTyWAj0bCoAAfgg==
Received: by 2002:a05:622a:a019:b0:481:d765:2e0e with SMTP id
 d75a77b69052e-48ad89b7041ls35597741cf.1.-pod-prod-07-us; Fri, 02 May 2025
 12:01:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLTbACASaCel19+d1NUBJmcM19VYma3Xm5MrWuwBVhKp9mkruOb011pi2eDKKqSDSwGsx+ThyKL/4=@googlegroups.com
X-Received: by 2002:a05:622a:4119:b0:477:e7c:a4c with SMTP id d75a77b69052e-48c32ac7c94mr68388171cf.39.1746212493568;
        Fri, 02 May 2025 12:01:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746212493; cv=none;
        d=google.com; s=arc-20240605;
        b=T+tHI/dvrw/+jIeSeSiPeWsH4hYOqtLp1C0L614Ny8Pbt2gt0rWRAX2fbDhZ2vVr1I
         jgizA6KEytXGRTPKFrVi3Vzft7IYNNSNUvzaXxMuaDbk+sllraei8BNbVPO7WVYpc2Zh
         I0rzT3Yqkfau6uizbQkBf9FKTU4SdM/GYU2N/2go7cruhrGAkBhvZ9a0YRwVdVp2rf1h
         7Lk9Wqvu7QRUNgxsiBffhwmZztKvhZuEH+ckae2jeBcN3gVWVYT+fNQFCIKBAGmv6QGL
         B5wJKVzENlsLeUBc60amh/lgDIPBFW4Ws4npag+oW1T8gdbIKrfs5yM0MJEjKNhP0hvC
         XrhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hX5wR39LjacC93Bmc78Vfzcvbkj+SUvbwoit1IycWNU=;
        fh=lh92C742Jj3nygrwO5Lq7z6EyFIw/1YWN8DCYAj+uaI=;
        b=g6ZI7y9W0BuKZQOrdDsaOTQDaqaTSjgLv1xGlAgvkoE9C2IfiyslzoxcmY/N95yNKa
         ZGjCf7TWgfSkojXzwRbQBeXnUO/wXekaYQu1pBHzugAJmVNf9W/L/mgf/LLB0umsKQkr
         1YFAw7DWWrYddrZ7kY4bY17KYlQUA2/LoyO+qMC+mBs3johVRyS5IeIbuAqTJKlQeOHA
         UYCMXKgDGg6/hHHjrMAujnsyJDmin2AkbmH2ut6ljyLhtOdDbvOAYmyW5uycJF0fMlNr
         HGnQ8uXgQJjY+WIpMytxn4UAY/nuk8rR5DRHgq77+T2ip/voS5LYB3Gbx8ySUayYbAxM
         AyAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XskH4lLH;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-48b9843811fsi1307951cf.4.2025.05.02.12.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 12:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CBBD55C5CAB;
	Fri,  2 May 2025 18:59:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 96854C4CEE4;
	Fri,  2 May 2025 19:01:32 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	sparclinux@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-doc@vger.kernel.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH RFC 3/4] stackleak: Split STACKLEAK_CFLAGS from GCC_PLUGINS_CFLAGS
Date: Fri,  2 May 2025 12:01:26 -0700
Message-Id: <20250502190129.246328-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502185834.work.560-kees@kernel.org>
References: <20250502185834.work.560-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=5846; i=kees@kernel.org; h=from:subject; bh=T23nG4j/t8R/0j3qoaqTnBegm1hE55sMCs8bEgkfkMg=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmiYm0985ZPL8tL9j7QeF5dfLXQKaEXKszinZxbNO7FG HvMXX2go5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCJlfxkZ7p7ujPW8PMHYrmTJ QnPBjkyu7pIXX6edPv1JZqlzjQPTHYY/HIvF3iRMfnLp6ZKpIo5GKTorNCf0GBx9eGzjYm2T6Ua OnAA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XskH4lLH;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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

In preparation for Clang stack depth tracking for stackleak, split the
stackleak-specific cflags out of GCC_PLUGINS_CFLAGS into
STACKLEAK_CFLAGS.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <x86@kernel.org>
Cc: <linux-arm-kernel@lists.infradead.org>
Cc: <sparclinux@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 arch/arm/vdso/Makefile          |  2 +-
 arch/arm64/kernel/vdso/Makefile |  1 +
 arch/sparc/vdso/Makefile        |  3 ++-
 arch/x86/entry/vdso/Makefile    |  3 ++-
 scripts/Makefile.gcc-plugins    | 11 ++++++-----
 5 files changed, 12 insertions(+), 8 deletions(-)

diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index cb044bfd145d..92748e341b7d 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -26,7 +26,7 @@ CPPFLAGS_vdso.lds += -P -C -U$(ARCH)
 CFLAGS_REMOVE_vdso.o = -pg
 
 # Force -O2 to avoid libgcc dependencies
-CFLAGS_REMOVE_vgettimeofday.o = -pg -Os $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS)
+CFLAGS_REMOVE_vgettimeofday.o = -pg -Os $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(STACKLEAK_CFLAGS)
 ifeq ($(c-gettimeofday-y),)
 CFLAGS_vgettimeofday.o = -O2
 else
diff --git a/arch/arm64/kernel/vdso/Makefile b/arch/arm64/kernel/vdso/Makefile
index 5e27e46aa496..fb17749b93cf 100644
--- a/arch/arm64/kernel/vdso/Makefile
+++ b/arch/arm64/kernel/vdso/Makefile
@@ -37,6 +37,7 @@ ccflags-y += -DDISABLE_BRANCH_PROFILING -DBUILD_VDSO
 # the CFLAGS to make possible to build the kernel with CONFIG_WERROR enabled.
 CC_FLAGS_REMOVE_VDSO := $(CC_FLAGS_FTRACE) -Os $(CC_FLAGS_SCS) \
 			$(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) \
+			$(STACKLEAK_CFLAGS) \
 			$(CC_FLAGS_LTO) $(CC_FLAGS_CFI) \
 			-Wmissing-prototypes -Wmissing-declarations
 
diff --git a/arch/sparc/vdso/Makefile b/arch/sparc/vdso/Makefile
index fdc4a8f5a49c..162a0235f41f 100644
--- a/arch/sparc/vdso/Makefile
+++ b/arch/sparc/vdso/Makefile
@@ -48,7 +48,7 @@ CFL := $(PROFILING) -mcmodel=medlow -fPIC -O2 -fasynchronous-unwind-tables -m64
 
 SPARC_REG_CFLAGS = -ffixed-g4 -ffixed-g5 $(call cc-option,-fcall-used-g5) $(call cc-option,-fcall-used-g7)
 
-$(vobjs): KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
+$(vobjs): KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(STACKLEAK_CFLAGS) $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
 
 #
 # vDSO code runs in userspace and -pg doesn't help with profiling anyway.
@@ -80,6 +80,7 @@ KBUILD_CFLAGS_32 := $(filter-out -mcmodel=medlow,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -fno-pic,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RANDSTRUCT_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(GCC_PLUGINS_CFLAGS),$(KBUILD_CFLAGS_32))
+KBUILD_CFLAGS_32 := $(filter-out $(STACKLEAK_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 += -m32 -msoft-float -fpic
 KBUILD_CFLAGS_32 += -fno-stack-protector
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 54d3e9774d62..cd5249b6ef84 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -62,7 +62,7 @@ ifneq ($(RETPOLINE_VDSO_CFLAGS),)
 endif
 endif
 
-$(vobjs): KBUILD_CFLAGS := $(filter-out $(PADDING_CFLAGS) $(CC_FLAGS_LTO) $(CC_FLAGS_CFI) $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
+$(vobjs): KBUILD_CFLAGS := $(filter-out $(PADDING_CFLAGS) $(CC_FLAGS_LTO) $(CC_FLAGS_CFI) $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(STACKLEAK_CFLAGS) $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
 $(vobjs): KBUILD_AFLAGS += -DBUILD_VDSO
 
 #
@@ -124,6 +124,7 @@ KBUILD_CFLAGS_32 := $(filter-out -fno-pic,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -mfentry,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RANDSTRUCT_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(GCC_PLUGINS_CFLAGS),$(KBUILD_CFLAGS_32))
+KBUILD_CFLAGS_32 := $(filter-out $(STACKLEAK_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(CC_FLAGS_LTO),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(CC_FLAGS_CFI),$(KBUILD_CFLAGS_32))
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index e3ed92e20d16..398b70e2d270 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -23,18 +23,19 @@ gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STRUCTLEAK)		\
 		+= -DSTRUCTLEAK_PLUGIN
 
 gcc-plugin-$(CONFIG_GCC_PLUGIN_STACKLEAK)	+= stackleak_plugin.so
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
+gcc-plugin-stackleak-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
 		+= -DSTACKLEAK_PLUGIN
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
+gcc-plugin-stackleak-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
 		+= -fplugin-arg-stackleak_plugin-track-min-size=$(CONFIG_STACKLEAK_TRACK_MIN_SIZE)
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
+gcc-plugin-stackleak-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
 		+= -fplugin-arg-stackleak_plugin-arch=$(SRCARCH)
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE)	\
+gcc-plugin-stackleak-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE)	\
 		+= -fplugin-arg-stackleak_plugin-verbose
 ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+    STACKLEAK_CFLAGS = $(gcc-plugin-stackleak-cflags-y)
     DISABLE_STACKLEAK += -fplugin-arg-stackleak_plugin-disable
 endif
-export DISABLE_STACKLEAK
+export STACKLEAK_CFLAGS DISABLE_STACKLEAK
 
 gcc-plugin-$(CONFIG_GCC_PLUGIN_ARM_SSP_PER_TASK) += arm_ssp_per_task_plugin.so
 ifdef CONFIG_GCC_PLUGIN_ARM_SSP_PER_TASK
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502190129.246328-3-kees%40kernel.org.
