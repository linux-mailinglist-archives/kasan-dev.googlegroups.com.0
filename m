Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5WG53AAMGQEAKNG6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37FB5AAE892
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:24 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3da6fe3c8e7sf947405ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641783; cv=pass;
        d=google.com; s=arc-20240605;
        b=XNJAUg1VehNnhg4Z4wxB549m52iKnOSoaFxDbvGpAFgGDvryCsuw/k3tVhPRm5HPfY
         3/tSHWyVvF7lb0GQszKjv2L2w40vhjk4g05up3zX48SK6tBTzfMgX+tEMEEXL+zQY89y
         RzQkOUQPpJPrjsK7kvVJvJMnRdoPbo8x1I3RitqTISdOZPPaz9+y0Glkg0FUr43XZIR9
         OPgbURyKdU2T3tQNUKGoZ1lsXZJXdzYfObqcLZLad3q4SVWPJNVge8GnGqHD+rePH9b4
         yS7QEDeoDdoNmF8VyQNP6vWFFRNCpqjCaghfzn3FfTwmYMQDO08/0HiEgNQvODTqyhlI
         t7Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GdQgmMFYaiJj1JbYze84S0tZEHBzKjxHfN6u5aDNVY0=;
        fh=oCO4cg641RKv8Vo6SuG/vK8ECHA3GyoR8w1vqP2vGyI=;
        b=HXpp7RqFwKuZr4Sflv/judr36SMnMW/uiCwCuMdWyVBwX1ieCk2ss3hugT3v2cb+V9
         xaqiUU/j1Yi4ANTteKrz1BcAyXjg8mX67qZ2Dkp2qpPsSmUsBrrCCs4WH5YcRy3Pi0YD
         khej6gnEvuq1u5U2m2HDb+tcJBuPK5e12WQqNZmTjLgxTlDvsd8/KroQu6zkYBBs+wUP
         BEOjNJ2V6rbpTCcHw0/0aQdBmvHTUn5V/WahjAHzc8kU81hE7HSljgd+yHR5rKgZwal7
         CXm/9iyJJYa4bKwr9HteoUlP9xqFFt+RU9jbAGUODyW63zMLovdwHYrEyoV2wDW38PaV
         /Wog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A4eqnIX0;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641783; x=1747246583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GdQgmMFYaiJj1JbYze84S0tZEHBzKjxHfN6u5aDNVY0=;
        b=gbTdKQwoLXa9qEgpJLmWyi9BsVLrHABRihht0R6sTt1sqxMN6ZMLjI0VA7JCk9UKY7
         G6paspLqKxZPKkcqjDfqsiIgBAbWBdgy69qeWpYDOv/q74yDDo9h7pPWTObTlRdxuSPw
         FcZJ1zKvh4slDxkWbvSUPzLTdKz1DPzeX/s3SPF9tRvzNnuJ/61lIBjFrRh69J72Q0QZ
         5FdWc+Ezf6HuQfV+JT6guCSSMocaaQKyXXDRxg17mgLWJbzHO/P9R+aZ7gsB1uAycDgK
         S14NZrq0F4ubqlq20VPxANvOp8qwAJtCHGnHe/OiLwpZd3dFZuUgxNS3E4Jy55KDRy5y
         j/Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641783; x=1747246583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GdQgmMFYaiJj1JbYze84S0tZEHBzKjxHfN6u5aDNVY0=;
        b=O4yyZmQYd6T2eLtM+1UG8jBlnx3NK7aIP6xGHyieOR0CmupLI0QptCf9SxXY4mefFN
         Pe7FPyyc6SVVPSCIG3cPcRd7IbfkG9HBAaSsPQzWZyPR8JPEk3jnosdHXrQDrzyvPjuB
         YH40zcO8MdekDtioAS8KqiHx7EH6QWf00bAMmpfQ/Dvt1E5A7e69OlC44LpbXVFJszCO
         8Thvx74GN2sSwtxTpZsw03tznn+dgDMtQJkUHG1eqoO2K4L8XLzclgg6gsdcaCsDjfyQ
         rPwLKMQqXaG6Ed8CsX7KWd2FxR8ry6KXQnYf44+9i3T37pKl4BdTLgRaWJUFx7upvx8Y
         /V6w==
X-Forwarded-Encrypted: i=2; AJvYcCUEn9NbFGOsKA8Ldh30g4y14Fg0bpjIrECyeQ0tPVziFz3FxfnLjxfnQ+Pp9JWiP7w94Xr26w==@lfdr.de
X-Gm-Message-State: AOJu0YwWnZmK6ZxuxW3M+a/L0bzLsDwdmnpTAiAIDDIXrCxDQLz/+cd0
	ip7PH9TRUwaCMLx1Rd4fXCRkLe5Gzd6mGLbMWLorOTG+Af3BWZzc
X-Google-Smtp-Source: AGHT+IGD6Sf334+wicjdZ0m9Cc46aSmfgksJCSBpkgvGmZfCYq9yvmX1sGAIvgUy9OoDAjG8kNc6xQ==
X-Received: by 2002:a92:cdaf:0:b0:3d8:975:b825 with SMTP id e9e14a558f8ab-3da738d5b28mr50743275ab.5.1746641782808;
        Wed, 07 May 2025 11:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFMf4koufzUVOuPvqoi3HUPEJDTyg5fnXOsSHTAhOatWw==
Received: by 2002:a05:6e02:120f:b0:3d5:e479:cca0 with SMTP id
 e9e14a558f8ab-3da7854fa47ls942605ab.2.-pod-prod-06-us; Wed, 07 May 2025
 11:16:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoRDAZN+r6cfIp8/q8i4GOGCYyvT+pRHdg3smwPn/+ScJmufF5UtZ5/oWKro8lz58pP23T9U2iGRc=@googlegroups.com
X-Received: by 2002:a05:6e02:378f:b0:3d9:644c:e3b7 with SMTP id e9e14a558f8ab-3da7392ad54mr48230385ab.15.1746641782071;
        Wed, 07 May 2025 11:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641782; cv=none;
        d=google.com; s=arc-20240605;
        b=EBE2OsxlrslMk9SNIt3dR5WGb82GK5q+HYWXYFkF+G04bsU8ZyMStmOI7eT8mgRy7w
         tKIya6qyKgrVilVTVkwt/I1fHjNw3PRPIxflR8GSdwjXAHHS5hJ6+rcs/cJr9wxcJ5jD
         G0s90QIiaQ3Ds59WunXB8bL64JvTAbBD8Fx8p5hJXtRM9IRWkSELaxsOlfBmz7wgP6cc
         zkOhgNv/P5rIaycLlaCQMnqy3wWq8QkZONSEQJ7cplVieqbdRdkUjr/yvcaW3DpCC/DU
         0f0U9DQTh7w954kUpTE6QyWPW18xa7BWYJaAxDebBjKppulFLH2j8wMlpOtcLYNEHbyy
         HFYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1v51SgqjEQ/y9ZirW/mBBCxmauRp+qyQkkMTYv5JC64=;
        fh=iqyaNv71WZ05ND5g9H2nycOZ8/KvMBm17gFrrdbmmto=;
        b=FloWqvwD8U/KNbUtPq8Mu068uZOe083iwz/raskYs8gz63llEFR/rXyvwzgiYVjOGb
         yXHPAWzovIWkZBNXQpmuNI6tVj7kNJTwj8A7Nb90JHComBBYavSVFsTYWy80fTAQApes
         aSqM3SDuvCTcEZDsP03O0Wu8tSD0psCDE+i647m2iU3QEzVBm5+W4o5cHVSJ45m/qEGd
         vJHUpprQM1umFoR+wFZ2G/Ph5yW2y1cXCmJCJrf6CRn6mt5ltkpA/IaSMaBIkstumTC8
         9zzj3w5WL4jv0v5F0PlFbCasT5iqV5p9uyF/80B3JAuYtDF3JPTXtr3KEuEk1gn778I3
         D+Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A4eqnIX0;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d975e22be4si7342175ab.1.2025.05.07.11.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 80066A4DC2C;
	Wed,  7 May 2025 18:16:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3ED36C4CEE9;
	Wed,  7 May 2025 18:16:21 +0000 (UTC)
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
Subject: [PATCH 5/8] stackleak: Split STACKLEAK_CFLAGS from GCC_PLUGINS_CFLAGS
Date: Wed,  7 May 2025 11:16:11 -0700
Message-Id: <20250507181615.1947159-5-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=8800; i=kees@kernel.org; h=from:subject; bh=xnX44A875J5pRQUvuRYdVrdaj7yDpDUw7/gsLr5gEV0=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi3P6lfhV/RXS7W7EXssK1NBnXdB5Ysnr/mVB/17fl nyiPW9uRykLgxgXg6yYIkuQnXuci8fb9nD3uYowc1iZQIYwcHEKwEQyLjMydM67eeZ867qfzziX yUjOl4pne5p24PVarrW6CwO/xaRWMDIyvKpsa9K/d9l+e0Fs3d97Xkl7JGyWBRS8mL1yzr8DbL3 FfAA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=A4eqnIX0;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
 Makefile                        |  1 +
 arch/arm/vdso/Makefile          |  2 +-
 arch/arm64/kernel/vdso/Makefile |  3 ++-
 arch/sparc/vdso/Makefile        |  3 ++-
 arch/x86/entry/vdso/Makefile    |  3 ++-
 scripts/Makefile.gcc-plugins    | 16 ++--------------
 scripts/Makefile.stackleak      | 15 +++++++++++++++
 MAINTAINERS                     |  6 ++++--
 8 files changed, 29 insertions(+), 20 deletions(-)
 create mode 100644 scripts/Makefile.stackleak

diff --git a/Makefile b/Makefile
index 5aa9ee52a765..1af8dfbcf0af 100644
--- a/Makefile
+++ b/Makefile
@@ -1089,6 +1089,7 @@ include-$(CONFIG_KMSAN)		+= scripts/Makefile.kmsan
 include-$(CONFIG_UBSAN)		+= scripts/Makefile.ubsan
 include-$(CONFIG_KCOV)		+= scripts/Makefile.kcov
 include-$(CONFIG_RANDSTRUCT)	+= scripts/Makefile.randstruct
+include-$(CONFIG_STACKLEAK)	+= scripts/Makefile.stackleak
 include-$(CONFIG_AUTOFDO_CLANG)	+= scripts/Makefile.autofdo
 include-$(CONFIG_PROPELLER_CLANG)	+= scripts/Makefile.propeller
 include-$(CONFIG_GCC_PLUGINS)	+= scripts/Makefile.gcc-plugins
diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index cb044bfd145d..f05a27909a76 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -26,7 +26,7 @@ CPPFLAGS_vdso.lds += -P -C -U$(ARCH)
 CFLAGS_REMOVE_vdso.o = -pg
 
 # Force -O2 to avoid libgcc dependencies
-CFLAGS_REMOVE_vgettimeofday.o = -pg -Os $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS)
+CFLAGS_REMOVE_vgettimeofday.o = -pg -Os $(RANDSTRUCT_CFLAGS) $(STACKLEAK_CFLAGS) $(GCC_PLUGINS_CFLAGS)
 ifeq ($(c-gettimeofday-y),)
 CFLAGS_vgettimeofday.o = -O2
 else
diff --git a/arch/arm64/kernel/vdso/Makefile b/arch/arm64/kernel/vdso/Makefile
index 5e27e46aa496..d4f60027f910 100644
--- a/arch/arm64/kernel/vdso/Makefile
+++ b/arch/arm64/kernel/vdso/Makefile
@@ -36,7 +36,8 @@ ccflags-y += -DDISABLE_BRANCH_PROFILING -DBUILD_VDSO
 # -Wmissing-prototypes and -Wmissing-declarations are removed from
 # the CFLAGS to make possible to build the kernel with CONFIG_WERROR enabled.
 CC_FLAGS_REMOVE_VDSO := $(CC_FLAGS_FTRACE) -Os $(CC_FLAGS_SCS) \
-			$(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) \
+			$(RANDSTRUCT_CFLAGS) $(STACKLEAK_CFLAGS) \
+			$(GCC_PLUGINS_CFLAGS) \
 			$(CC_FLAGS_LTO) $(CC_FLAGS_CFI) \
 			-Wmissing-prototypes -Wmissing-declarations
 
diff --git a/arch/sparc/vdso/Makefile b/arch/sparc/vdso/Makefile
index fdc4a8f5a49c..d0cfaa2f508a 100644
--- a/arch/sparc/vdso/Makefile
+++ b/arch/sparc/vdso/Makefile
@@ -48,7 +48,7 @@ CFL := $(PROFILING) -mcmodel=medlow -fPIC -O2 -fasynchronous-unwind-tables -m64
 
 SPARC_REG_CFLAGS = -ffixed-g4 -ffixed-g5 $(call cc-option,-fcall-used-g5) $(call cc-option,-fcall-used-g7)
 
-$(vobjs): KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
+$(vobjs): KBUILD_CFLAGS := $(filter-out $(RANDSTRUCT_CFLAGS) $(STACKLEAK_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
 
 #
 # vDSO code runs in userspace and -pg doesn't help with profiling anyway.
@@ -79,6 +79,7 @@ KBUILD_CFLAGS_32 := $(filter-out -m64,$(KBUILD_CFLAGS))
 KBUILD_CFLAGS_32 := $(filter-out -mcmodel=medlow,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -fno-pic,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RANDSTRUCT_CFLAGS),$(KBUILD_CFLAGS_32))
+KBUILD_CFLAGS_32 := $(filter-out $(STACKLEAK_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(GCC_PLUGINS_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(SPARC_REG_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 += -m32 -msoft-float -fpic
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 54d3e9774d62..9e912b6a889c 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -62,7 +62,7 @@ ifneq ($(RETPOLINE_VDSO_CFLAGS),)
 endif
 endif
 
-$(vobjs): KBUILD_CFLAGS := $(filter-out $(PADDING_CFLAGS) $(CC_FLAGS_LTO) $(CC_FLAGS_CFI) $(RANDSTRUCT_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
+$(vobjs): KBUILD_CFLAGS := $(filter-out $(PADDING_CFLAGS) $(CC_FLAGS_LTO) $(CC_FLAGS_CFI) $(RANDSTRUCT_CFLAGS) $(STACKLEAK_CFLAGS) $(GCC_PLUGINS_CFLAGS) $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS)) $(CFL)
 $(vobjs): KBUILD_AFLAGS += -DBUILD_VDSO
 
 #
@@ -123,6 +123,7 @@ KBUILD_CFLAGS_32 := $(filter-out -mcmodel=kernel,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -fno-pic,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out -mfentry,$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RANDSTRUCT_CFLAGS),$(KBUILD_CFLAGS_32))
+KBUILD_CFLAGS_32 := $(filter-out $(STACKLEAK_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(GCC_PLUGINS_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(RETPOLINE_CFLAGS),$(KBUILD_CFLAGS_32))
 KBUILD_CFLAGS_32 := $(filter-out $(CC_FLAGS_LTO),$(KBUILD_CFLAGS_32))
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 33ddf5bfda34..e27ffe8e7c75 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -22,20 +22,6 @@ export DISABLE_STRUCTLEAK_PLUGIN
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STRUCTLEAK)		\
 		+= -DSTRUCTLEAK_PLUGIN
 
-gcc-plugin-$(CONFIG_GCC_PLUGIN_STACKLEAK)	+= stackleak_plugin.so
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+= -DSTACKLEAK_PLUGIN
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+= -fplugin-arg-stackleak_plugin-track-min-size=$(CONFIG_STACKLEAK_TRACK_MIN_SIZE)
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
-		+= -fplugin-arg-stackleak_plugin-arch=$(SRCARCH)
-gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE)	\
-		+= -fplugin-arg-stackleak_plugin-verbose
-ifdef CONFIG_GCC_PLUGIN_STACKLEAK
-    DISABLE_STACKLEAK += -fplugin-arg-stackleak_plugin-disable
-endif
-export DISABLE_STACKLEAK
-
 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
 GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -DGCC_PLUGINS
@@ -50,6 +36,8 @@ gcc-plugin-external-$(CONFIG_GCC_PLUGIN_SANCOV)			\
 	+= sancov_plugin.so
 gcc-plugin-external-$(CONFIG_GCC_PLUGIN_RANDSTRUCT)		\
 	+= randomize_layout_plugin.so
+gcc-plugin-external-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
+	+= stackleak_plugin.so
 
 # All enabled GCC plugins are collected here for building in
 # scripts/gcc-scripts/Makefile.
diff --git a/scripts/Makefile.stackleak b/scripts/Makefile.stackleak
new file mode 100644
index 000000000000..1db0835b29d4
--- /dev/null
+++ b/scripts/Makefile.stackleak
@@ -0,0 +1,15 @@
+# SPDX-License-Identifier: GPL-2.0
+
+ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+stackleak-cflags-y += -fplugin=$(objtree)/scripts/gcc-plugins/stackleak_plugin.so
+stackleak-cflags-y += -fplugin-arg-stackleak_plugin-track-min-size=$(CONFIG_STACKLEAK_TRACK_MIN_SIZE)
+stackleak-cflags-y += -fplugin-arg-stackleak_plugin-arch=$(SRCARCH)
+stackleak-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE) += -fplugin-arg-stackleak_plugin-verbose
+DISABLE_STACKLEAK  := -fplugin-arg-stackleak_plugin-disable
+endif
+
+STACKLEAK_CFLAGS   := $(stackleak-cflags-y)
+
+export STACKLEAK_CFLAGS DISABLE_STACKLEAK
+
+KBUILD_CFLAGS += $(STACKLEAK_CFLAGS)
diff --git a/MAINTAINERS b/MAINTAINERS
index dc535c67a745..9a2be2dd96c9 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9827,8 +9827,6 @@ L:	linux-hardening@vger.kernel.org
 S:	Maintained
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
 F:	Documentation/kbuild/gcc-plugins.rst
-F:	include/linux/stackleak.h
-F:	kernel/stackleak.c
 F:	scripts/Makefile.gcc-plugins
 F:	scripts/gcc-plugins/
 
@@ -12890,11 +12888,15 @@ F:	Documentation/ABI/testing/sysfs-kernel-warn_count
 F:	arch/*/configs/hardening.config
 F:	include/linux/overflow.h
 F:	include/linux/randomize_kstack.h
+F:	include/linux/stackleak.h
 F:	include/linux/ucopysize.h
 F:	kernel/configs/hardening.config
+F:	kernel/stackleak.c
 F:	lib/tests/randstruct_kunit.c
 F:	lib/tests/usercopy_kunit.c
 F:	mm/usercopy.c
+F:	scripts/Makefile.randstruct
+F:	scripts/Makefile.stackleak
 F:	security/Kconfig.hardening
 K:	\b(add|choose)_random_kstack_offset\b
 K:	\b__check_(object_size|heap_object)\b
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-5-kees%40kernel.org.
