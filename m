Return-Path: <kasan-dev+bncBCF5XGNWYQBRBR7W73YAKGQEKWDJYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 63E8013D173
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:25 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id bg6sf994052pjb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137863; cv=pass;
        d=google.com; s=arc-20160816;
        b=C0oFN0cSCG4vVNID8X0EpMIy7rLAQtfA6mH+XkPNgHUBGsVHLXrAPHeKOFgNUwVVKs
         UUgURpF/8vohXTxjRXSDoiSftCIqpAeiMBhaoYmhD7pad4igjyX0jmAo+PvoX3YNHXkX
         ZvF84wsNBhTfsMhPRCV9JXWYcjZChgM9MpDmfUxx0oMgTE47+4pEXFEvOC+Xs2NKHZYV
         GqgTui89vyp2xBH9lpEwzCvIgfQtgPr06o+aeP9s1liQDPoh27kjp221AibVcBXaZx6L
         ic84oPCmEIsIg7WeotNSe7FzvGN0r5F4ci2yz4kunnUdpKUwoUcTZKagHZU/iVE5q10+
         Lyiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4VXhQT38r2pnOx+6us/YcvZMtOM4FKTtpQVhNNs586M=;
        b=g56x5AKdg8H3PtagdnP9W2rORZoLdJnqsGAPX+BAyKtBVIMDWTEARCLnkNeSIHiG/w
         BYNvmWRUMkmG59K6FaRv8Vux4vX1UzQ9eyDXXB04sk8crDXDJsVqxRMhInrlbXleX3zM
         n1ZhivkWjo+cAAUmh5YoOK6i3+ZO1DVXY/SjlEZLyNkzKFA7lHfg1OoXW1Z10rvPPCmB
         Ma9RVn1u6E8ABlJOsNtXGaqrHS4jvqIFSBEagPyOg9d9wlNxym2JJJWYfs5GPbqhJWs1
         SevObUC6i5booRKd98nHOnLgox7oOSj4SaFOygXWmh/W7SNtnt5y0evMpjrd3IzRHDhv
         fSoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=F0L+2cGd;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4VXhQT38r2pnOx+6us/YcvZMtOM4FKTtpQVhNNs586M=;
        b=BAecLOWd+YMN/1PrzisiE4q2nHEwoUwpYzmmjZZ6mqNWprD3ImPKwSLoeUCfCmAtLi
         lwdj7W8XXcONKKFqXVj4aGsIErjAki+JVOfvSU1/ZZj8wR7uDyuahS9k29jqgXfkzktd
         vo3+s/kOvcWc0Z+KG+l8MI1HXB09/8CRjSKhXfSFf7M2hDhyWvUdOPm8vwDfLdT6Qzqm
         wiFAQPOQhCTzZ8o9SqvfAoQAElfsXgA0LQvn65hxeyBtoyy1XLWChEAcwaTAUJ1q1PKj
         ddod8ny+ScXW6tfbA7Yy37cSj2ndgs8Tvqo625I3R8BNZl0YTSu+XSaVFDexVbYz1JUI
         eW4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4VXhQT38r2pnOx+6us/YcvZMtOM4FKTtpQVhNNs586M=;
        b=pRfxyfgxwFTEEmdoodifLXDZlyo77lu1ELQoSrgGXPQZzwvP34Ss+vmkxk1+E15ugu
         HN2kURG7fJjdkFlc67z2qUfLAHRdTzZZ5M+HspvS1jf0WloyLgdi/D/pj4IKCKhC4KWK
         cP78lhLHX3SFYXpvSQaoMHC9U0U3TFo+5fPdKkF8lt/r0RlvTwkFrOf3ltEYH1W2RyZs
         mCcTM7oEdNsU1Q5dLeaCpWaO1JjvYbjotlbsZrtyeJ8NnL8m/KKwA0zk/EWp/WdNQP6Z
         Xo1P3mI1aurg3kvcedVWRcoZ8WlDpv8/iVE6bp6P5sRWm3i/6mEelppUyTtxXIfKu6uI
         jBSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXGydDenb3aYRUhCbWTFFu/wKrGsR93IZ8URVQEF1h6biXJfGAp
	uCN50e7JLS/kA7rCfR5sD7E=
X-Google-Smtp-Source: APXvYqwDic++Qbg4JBwvZ1ENlNWObNbH70VBzwVn2N0BsSBJzy0JeMYMa0VJB/vagWnD6pJ8Fh5XOg==
X-Received: by 2002:a17:902:ba86:: with SMTP id k6mr33934161pls.96.1579137863699;
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d007:: with SMTP id z7ls5578548pgf.9.gmail; Wed, 15 Jan
 2020 17:24:23 -0800 (PST)
X-Received: by 2002:aa7:9aeb:: with SMTP id y11mr35253142pfp.63.1579137863253;
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137863; cv=none;
        d=google.com; s=arc-20160816;
        b=B9j80yEoM9tI7fJwdfiawxh1zLXkhIyzW9aN8Wtp7hLpMJuoUpbCdRiUd9x7joluiJ
         0pPqehXCkZBOnv2Kc2OBnydjx7YnehHsxlB5hjtGTAMP3daDXYJxZLon/JXhPNcTU3+K
         LwlQy6daZqa1B8EerXQDPpgTFSNW2GpnKzWjUYUhQDKTT1Dq0IE4qW6+VE9vPh9LrNis
         Zg+8tm4lGYnUICTg75cb3CYGkmFTN9fQJ26+KKbeGfL6egjb03wJwvDrT+DSM4FpA1/P
         b/iWtOtioIU54b9P6CN1t7cZc/DPmJKiLtVKewunrYBi+JZrzSScle5iUeo6voUlnUlB
         Vajg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TZN5E5934TvMDmRyA6YbiUZA3oVW+HYGx9jzlGs1fas=;
        b=oI9IzRMVsdAbi7v1CSzV+mv8y4+/aOcNCpElJtxg9INA3YRUCIjtPg4NiEbbkqZnbX
         dxe95EhloY7paZOPhfWvNvdiFSFcBcrX2DJxjeniEJGKAp9p8EDHWlcTsiuT5mgQiIX2
         7gqb58bYZrdD1TFhZZ6iZpKckuzUiuZXQLBaQ8Co4nn1G9+nVH/TSfOw2VtYnPll38EI
         uRhLUZuVddGCzihT5YIAIZkQut6YP2TOjT0mB3s63i5WYMnnM4F0yGAkNn2jaJtxwQ9e
         wxw57upf5kmwCfdUc4gVGTbcjakFYNnXcFGDgAebVV1riYNdIvNbgah7mf1myaoktCTj
         Jenw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=F0L+2cGd;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id h19si1020414pfn.1.2020.01.15.17.24.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id e11so769549pjt.4
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:23 -0800 (PST)
X-Received: by 2002:a17:902:124:: with SMTP id 33mr28734328plb.115.1579137862886;
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id y38sm21836186pgk.33.2020.01.15.17.24.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:18 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
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
Subject: [PATCH v3 2/6] ubsan: Split "bounds" checker from other options
Date: Wed, 15 Jan 2020 17:23:17 -0800
Message-Id: <20200116012321.26254-3-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116012321.26254-1-keescook@chromium.org>
References: <20200116012321.26254-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=F0L+2cGd;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-3-keescook%40chromium.org.
