Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOE64DZAKGQEKGWY35Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id A53F81727FC
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:29 +0100 (CET)
Received: by mail-yw1-xc37.google.com with SMTP id q187sf797089ywg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829368; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ygv6o1z/lTQ4AbAEdNfNhTUL/bMNa61cWg2mikv5T/l5uMJd6/NGxa5+kiTNoPjXTG
         /Ag4D7VOyirzepp7/ekva8ufoQtxi6VkqX/s3j/5QoAzGG615Qs35APfJVYzrsg1uv6Q
         CQ/7Nza/N1tLMcubacStNpu5V/aBmZTebUAvwJC+sElhzP0ml04LorgTAsz6lnY5ddWa
         jt3LXWE05TTjATGi2zuvQT/8JDhDo0ai4yH0kgT5bYjcRZmbYhSpVdiPArau1C8EfCig
         FPy3BERZG3tWM5w3Tjb2JQXJfX9zk1P2hVNjMDbseFk6Xdy82i6Idlwn4DRfHWmJvU5c
         a8TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ILoZffsLIw6nMb5cr/C7n6Y2Fz96KJVkiBAgbqKBtFY=;
        b=FKNRkRHy4j10KrJmQZ2xFTZAjUisYfiBzk8zcjgi0pZnsFOIkfR70nzS8V9wX3+G1j
         5hwTf1Ef66GKJjSVUdTtoNtofv9mkEc6gT9pAoF3Vh3fr4t2oOssoalwVWOJPHxxkzF9
         omMtDDUhtdGkHSAVLGum7sI1oW0ySjAjz4gTGUQSfMEJwXbN/IpeDpjtGfholxDrFw3x
         qQFwlGJhnP3o+SjsyigxCM1scRfh6YPyNEy/8G04f6p/PoukuIDaMavUsHnXQXqjsHDD
         23JJdDAIYsgHr56CeOLF0pM32i5PJTk7/RPp10ZudB9qySrpieBMcGGKhq8cm81KQjqk
         DEIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eXruJRfn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ILoZffsLIw6nMb5cr/C7n6Y2Fz96KJVkiBAgbqKBtFY=;
        b=gRIqY+YRhl4+rLpJ2uHilkcVC7ppv38zHzQ1HpWfoGUJ9oxwlCR6KbYkkNRkLgE75B
         SIZOsPk8pKrseHVz4vzrA+8qxV3eDasB/knVWsaOMW0iE58I7Pl/sz8VCUCkjfgL/vB7
         hvILD6rkW21JJfIrcoNlWtifXL7bXJCamZq8QxTJxYtv367tebhHJNONYOz49tXzFp1s
         QzKQHf8l2+DH1M055KIsvwRcnLQKpfxbR58r1NZ0GbAFfOY8xHDpukJZTapG86kqHTiU
         zSYp15Wi7PFcTROHF64uc/639JcOtk9Md5zGMEWORmsDfkhlUuagYOJ8GJIe1ulXxKGt
         +HjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ILoZffsLIw6nMb5cr/C7n6Y2Fz96KJVkiBAgbqKBtFY=;
        b=HsZWrbBCOr25BOynPzlaRvrBdzRoINWlZPRIA4fbtOe7lnXAJlT815Exgtx9MpItjL
         TXtccUP3YjZ/77EubA4NfAafbRxpuGeL/OJI+pSSPiw2ESmfFTlPop58IWFWFVsqZEQg
         JSX7fPrLgkY8gOzm9nG8KKqfwxwn8NjNFO2mMJtACcyjtr0FWqXCi6U8Enaxdlh66YGq
         9FJVlzqzXI4bwKieECjvsVK0PRTnMlgPMpJ9zQMNLxky4rmXpKWrVDtXugJxXxktfzL4
         XNmOdWkk+YJ/XFVJiDd5q5VdaBNRRK3cB8HyhocsWp0BTiNMeYnRYDbkJL2zBX0Fv9rO
         dbJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfJk6OSW8z/UGI51aEqnZWaNmFJWzVW+yXSd8u2kOKDR1bFy15
	VZTyBHDHdJpsSPEgixRHOww=
X-Google-Smtp-Source: APXvYqwaD/Xc+sAMWL1iINE99rhzUG4N+QH/L86LYYANld9kJ1GHrsLFQ+e4guYAvVGbCiAZ+sKkjg==
X-Received: by 2002:a25:d0e:: with SMTP id 14mr37293ybn.355.1582829368602;
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:fc04:: with SMTP id m4ls391ywf.8.gmail; Thu, 27 Feb 2020
 10:49:28 -0800 (PST)
X-Received: by 2002:a0d:d906:: with SMTP id b6mr813456ywe.151.1582829368229;
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829368; cv=none;
        d=google.com; s=arc-20160816;
        b=e9DELX3Uw/9fYbyRKj5/szeuDZRtEjiOgnhtMqPJTR42hUaoGDcHque/NDok4kT52S
         f4PdJVKLrWkqeyFhvGYEo3p6BapjilJGocQokZUq1c590b6Nyf2JGHjLmCw92vP2WRW5
         3OOjmg+CYMwka2TqtNU26NNZHxppv2C2XeWh1xRdJwOp1k3SfOlD9UrXDe9Gv9/6KxvF
         jss6tNjcI2QiUfeHxidt1mgle1avVbllXkVeW4okAHUWRR+9UT0cO6vPOqTYNRrMJ7Aw
         1N/iBWQqBTP2Z1tqpLzEljzjqxm1j1AR/63H0tP8AlkWRagIUDtEZvgvyKxbm920Unwa
         SBqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TZN5E5934TvMDmRyA6YbiUZA3oVW+HYGx9jzlGs1fas=;
        b=0qYGC3G32P69hTQHRZKfgKSVppPqax9Ue7uCt0iiCyBwDzHhq0UwvqtPbjwgqz3k72
         oJqrcfMEVmuW1OsbR0m9JwjcUzq5zSc+x6L2uQkf/49znRWgTDwUJF7hQveKGartdcuK
         HwDajiLx+yB5hw6AemhYEppA7/7wRjmpD62dQ77N/7AdBlYQ8LDh77Md1/0orazxTgnO
         +BaAeO1745VwHLhTjQfwPTu9JDf4QtrZIjo7PqDIIfNf6Hdovk1kp0rqq6NPTIpa8CvD
         QWDd63wjSdDlbmHKLIcsid4dcZN511YB1tsku9wXCT9Gn1rKq7FsLQCGS8lUkgDKPD/h
         V6EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eXruJRfn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id i200si29280ywa.3.2020.02.27.10.49.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id q4so159822pls.4
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:28 -0800 (PST)
X-Received: by 2002:a17:902:8a89:: with SMTP id p9mr160846plo.286.1582829367317;
        Thu, 27 Feb 2020 10:49:27 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c19sm8674594pfc.144.2020.02.27.10.49.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:26 -0800 (PST)
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
Subject: [PATCH v4 2/6] ubsan: Split "bounds" checker from other options
Date: Thu, 27 Feb 2020 10:49:17 -0800
Message-Id: <20200227184921.30215-3-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227184921.30215-1-keescook@chromium.org>
References: <20200227184921.30215-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eXruJRfn;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-3-keescook%40chromium.org.
