Return-Path: <kasan-dev+bncBCF5XGNWYQBRB65T4DZAKGQEDGLEXMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id DE01F1728AA
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:24 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id s18sf371308qkj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832124; cv=pass;
        d=google.com; s=arc-20160816;
        b=WjrmUZzodomHorW4hjej4v7gaokewEpDtfhCRMxU5/Iy3k7FyOg3oiSOMnp2QywkLy
         kWkz6uivqNv6etKv3B8rWlX+eQoUk5tT30A55O7s69/mYCNjZquLJwGCYw5LqetLpboM
         4h0Lzwv/Btiep6zfLqvUP1iUGi8vgyFTf09MWLgKcbA0Jp2DPRXKY8b5vr3a3ujY/LKr
         0KRNV2aTiaya2gPr/f+9fj9nJCCdM1949IzXFcQMxJiH2IlXC5equWlA33jw77hKzayv
         QvN68VhyR33t1zUrnhi6FxZkc7rO2U9HNt8YjTKmQhZcXMjra9ySE9Flv6S98ARiylBN
         XMGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KZudvvWhmqT3DXQdxI/hMHttpJDFvcxQdwognZsOsUo=;
        b=ES+Bkhi/p65MUv54FknBhL16DaZ1VLsUY/GFAvyoeyNZFSaokKPjfTvKNLReKYYXVf
         nsYJSsPh0ykpEgGnk1he5ZUdq7kNQd1JmAVsWTyKNzLumil869fC4DuZNdmqefQ94zKP
         +c/eLJ1Xn6WSdG7zxqiu4/Lm7VV/SzuKEgcFENsaIBk1oDyAfkCEekshNYJCaymZngq+
         k322crUZkr6vIRyaATJZS18Yh7w+niuSo+4qTQ/DIfPFsdFL+HLN8P78CgQyLdG9HpZh
         uPbVHvAUVy4+Da+QU+/wdqsqYDkmriiVeQktlfCiYDzhipwHs2LyBLwwnEBKk0e16pSh
         x4rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fhU4ZWts;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KZudvvWhmqT3DXQdxI/hMHttpJDFvcxQdwognZsOsUo=;
        b=l9d512RXcKIpQdZAJTPiElfjjH4xNGXvJO1Ala5aBXltOMh0UI9DIxyQz+yWXcYpbb
         1rlnX1QgMNAah8UU7p6Lr50mnuGECm1BarSOBhMMGHEQhKSQ2qi3k3gYbzYJUqTtnmkn
         xp0noWGgVgzBYZWC7jeoLdmBAgANQwbTpFko2K6XfwLHqLyfrKADIOdddznscehv81ft
         D6RTwlPMwpP6pAXPTUWDKqFLQs2ntxL/7FlSudgulCAIOuehCeR9suWn+0CZkoaNY20q
         AUhBUlytmysB1WZ3CYSFlOCIbKwtOxhp2ROLeMPmVExf3jshL1sbQWn7PfdxJI+cOdLT
         mGYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KZudvvWhmqT3DXQdxI/hMHttpJDFvcxQdwognZsOsUo=;
        b=Posk8ENBe4A8g8xe8jLNQXJGz+p3R//0V3cht+35fRrEOPzFRjnqFIjicnYZgsn5OW
         M5uqG/qxdrxqrB3JGWUlW5KaFhVAnlUheD2gEVmsK05ez1Evu/zXcdsFY2Yb80J/YHgr
         RCBE1qh/c6vVBNf88nydyQIUadQjUQlDRf1LbSVObOABRMP1Sm9zKPGyDoQhn3ML8nMy
         3BuEjle09Q855cTtS1G9+FU+L6Pb7RGoY+BzK8mTw2YFt8v19mHhikF6ju7BqifuR3PG
         OjMxq+hDIa6bNS3/VvodxK1tWYdcwGvm9CILKBEhKREACfSu6etja380FymymdIT4CmF
         2BQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVKTJ5lx5w2Lvf8/xQNwSU8yRBWVgOnol8hlepe9poYkbl/7bJ1
	gC4pkCpFasxFp+lkI0ubxUo=
X-Google-Smtp-Source: APXvYqylvMHkDQo3MWZ4VCkB9GeZCjK74GEiIz9BLByh7uWNrwaoWMLBCdIEPJ+lDVIiW5ZcMi02hw==
X-Received: by 2002:a37:9104:: with SMTP id t4mr1008608qkd.449.1582832123922;
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9b96:: with SMTP id d144ls167350qke.1.gmail; Thu, 27 Feb
 2020 11:35:23 -0800 (PST)
X-Received: by 2002:a37:ac15:: with SMTP id e21mr960356qkm.349.1582832123574;
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832123; cv=none;
        d=google.com; s=arc-20160816;
        b=kwjBOxGVQ2/I2GQetSS2I1ApaV0MOsdI9+2IAO7dQ7UyVsVQRZXYr5nzHgPWBZSDFM
         QMQDCOVz0B2z2X0KJzjth7xYU2zqoOLOOC+0QQ0SYmayLCLCjRkeX4BiPfXVXmEKfjcd
         mQz51xqfIzd/VilfKtwx+A4hlnlRJTPhFlyvZm3KmOARBwjfvrBEFRiCLC+H/Qs+2ACA
         3NAXY1/hGa2Wprh/CmhARq3p4U3JAQ2qAPV3ea+uySZeNevOkfNWMolarPLog7NSuVvl
         jHuhfhDk4xVFqGwFzdmyqnBf0231m6fHPa6Ra4PIJwhgG1rjtvwQQ96ybaYXk6goVg1x
         D06g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TZN5E5934TvMDmRyA6YbiUZA3oVW+HYGx9jzlGs1fas=;
        b=rp+n1jP2P1SA3dcpLqJRS1gHifsjE2lkirZbegz8h2tN5husJ+tEzsOaTsLlqbPcZ7
         rMz6nStvob/dQL345D6QhtDCVNaIq4M39NuG4250gTvZS5BgL2DLER2bh28bo7dy93m2
         Zr26qegZW/n+WCSBCqwB5OUvr1dQCDY2F0NKz5wm57Z58vc3mu4+D3lU5BjV2fIe9ENI
         +iDyUxxC2jQa7Kzz7Hf9nBwG/zit5C/iw2C+EGZkESUXeAbJ0gMOdCmgrkph/w8fDO68
         LviXE8NmmSXuknxHGBZrhWMocN5hm4B2Ckvl4sbnT881uCwhqe8/zgaDWLBk8nll98j0
         uRtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fhU4ZWts;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id f52si34954qtk.2.2020.02.27.11.35.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id p11so195337plq.10
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:23 -0800 (PST)
X-Received: by 2002:a17:902:7048:: with SMTP id h8mr383251plt.64.1582832122570;
        Thu, 27 Feb 2020 11:35:22 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id x7sm4244205pgp.0.2020.02.27.11.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:20 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v5 2/6] ubsan: Split "bounds" checker from other options
Date: Thu, 27 Feb 2020 11:35:12 -0800
Message-Id: <20200227193516.32566-3-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227193516.32566-1-keescook@chromium.org>
References: <20200227193516.32566-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=fhU4ZWts;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

In order to do kernel builds with the bounds checker individually
available, introduce CONFIG_UBSAN_BOUNDS, with the remaining options
under CONFIG_UBSAN_MISC.

For example, using this, we can start to expand the coverage syzkaller is
providing. Right now, all of UBSan is disabled for syzbot builds because
taken as a whole, it is too noisy. This will let us focus on one feature
at a time.

For the bounds checker specifically, this provides a mechanism to
eliminate an entire class of array overflows with close to zero
performance overhead (I cannot measure a difference). In my (mostly)
defconfig, enabling bounds checking adds ~4200 checks to the kernel.
Performance changes are in the noise, likely due to the branch predictors
optimizing for the non-fail path.

Some notes on the bounds checker:

- it does not instrument {mem,str}*()-family functions, it only
  instruments direct indexed accesses (e.g. "foo[i]"). Dealing with
  the {mem,str}*()-family functions is a work-in-progress around
  CONFIG_FORTIFY_SOURCE[1].

- it ignores flexible array members, including the very old single
  byte (e.g. "int foo[1];") declarations. (Note that GCC's
  implementation appears to ignore _all_ trailing arrays, but Clang only
  ignores empty, 0, and 1 byte arrays[2].)

[1] https://github.com/KSPP/linux/issues/6
[2] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=92589

Suggested-by: Elena Petrova <lenaptr@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/Kconfig.ubsan      | 29 ++++++++++++++++++++++++-----
 scripts/Makefile.ubsan |  7 ++++++-
 2 files changed, 30 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 9deb655838b0..48469c95d78e 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -2,7 +2,7 @@
 config ARCH_HAS_UBSAN_SANITIZE_ALL
 	bool
 
-config UBSAN
+menuconfig UBSAN
 	bool "Undefined behaviour sanity checker"
 	help
 	  This option enables the Undefined Behaviour sanity checker.
@@ -10,9 +10,10 @@ config UBSAN
 	  behaviours at runtime. For more details, see:
 	  Documentation/dev-tools/ubsan.rst
 
+if UBSAN
+
 config UBSAN_TRAP
 	bool "On Sanitizer warnings, abort the running kernel code"
-	depends on UBSAN
 	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
 	help
 	  Building kernels with Sanitizer features enabled tends to grow
@@ -25,9 +26,26 @@ config UBSAN_TRAP
 	  the system. For some system builders this is an acceptable
 	  trade-off.
 
+config UBSAN_BOUNDS
+	bool "Perform array index bounds checking"
+	default UBSAN
+	help
+	  This option enables detection of directly indexed out of bounds
+	  array accesses, where the array size is known at compile time.
+	  Note that this does not protect array overflows via bad calls
+	  to the {str,mem}*cpy() family of functions (that is addressed
+	  by CONFIG_FORTIFY_SOURCE).
+
+config UBSAN_MISC
+	bool "Enable all other Undefined Behavior sanity checks"
+	default UBSAN
+	help
+	  This option enables all sanity checks that don't have their
+	  own Kconfig options. Disable this if you only want to have
+	  individually selected checks.
+
 config UBSAN_SANITIZE_ALL
 	bool "Enable instrumentation for the entire kernel"
-	depends on UBSAN
 	depends on ARCH_HAS_UBSAN_SANITIZE_ALL
 
 	# We build with -Wno-maybe-uninitilzed, but we still want to
@@ -44,7 +62,6 @@ config UBSAN_SANITIZE_ALL
 
 config UBSAN_NO_ALIGNMENT
 	bool "Disable checking of pointers alignment"
-	depends on UBSAN
 	default y if HAVE_EFFICIENT_UNALIGNED_ACCESS
 	help
 	  This option disables the check of unaligned memory accesses.
@@ -57,7 +74,9 @@ config UBSAN_ALIGNMENT
 
 config TEST_UBSAN
 	tristate "Module for testing for undefined behavior detection"
-	depends on m && UBSAN
+	depends on m
 	help
 	  This is a test module for UBSAN.
 	  It triggers various undefined behavior, and detect it.
+
+endif	# if UBSAN
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 668a91510bfe..5b15bc425ec9 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -5,14 +5,19 @@ ifdef CONFIG_UBSAN_ALIGNMENT
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
 endif
 
+ifdef CONFIG_UBSAN_BOUNDS
+      CFLAGS_UBSAN += $(call cc-option, -fsanitize=bounds)
+endif
+
+ifdef CONFIG_UBSAN_MISC
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=shift)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=integer-divide-by-zero)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=unreachable)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=signed-integer-overflow)
-      CFLAGS_UBSAN += $(call cc-option, -fsanitize=bounds)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=object-size)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=bool)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=enum)
+endif
 
 ifdef CONFIG_UBSAN_TRAP
       CFLAGS_UBSAN += $(call cc-option, -fsanitize-undefined-trap-on-error)
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-3-keescook%40chromium.org.
