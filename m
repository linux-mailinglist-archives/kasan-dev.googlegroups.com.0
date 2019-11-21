Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQ5I3PXAKGQEXE7RIGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 20CE3105942
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 19:15:33 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id f21sf2613109pfa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 10:15:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574360131; cv=pass;
        d=google.com; s=arc-20160816;
        b=GB/XYJBbShHUuaSU9MZyUJ6747atPQ6aqv2tvDb2aK4MjPSm4+65YJolJRWEJ+C2VP
         hmLZMfL0T91KiA9AlwvLGwNM+HrSrBVYTC5wXZ1FOXyEW8oMDv4epXdVyCQp+L8nijCW
         zDu2iPmRM+YkgFtGGyRDdOR+Fho0FHGaM5V3PmiIFrxxvVIssrRL0ov2Y0BzHJBcbIxG
         l7tPMaWHEqDd/CULAoWWhOX4TwcAkc3pmUAyBYQruy3UgXJN+tWe5dUX+2I3fc4n/ytZ
         e62jSFz9rX+1lYIZf8V7EULUdkzpX9So7xQKuVRU4qG8EEdlRnXKZ9S2FrSKpAkeX/7c
         7jaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=LCDb9cICfJVGPTmZC4wxaMdm5/i2FFMQSd0CGcuMu0o=;
        b=MRzUcKL0BgxGCiJS2KWYID+38S3399z/YJhltbKxklEHSgtw4B/SnYcyZ7bzTCq5mA
         g/9/Q0fkMCje24v+TpXI6m8e3qtb9kj4XT/9/WP8fWdo+gM4gc1iqwuwFLRPJshb/xp1
         Qd/Fz05DU4AZBtQGtbm0F99M5ufo0pM4NBkfDiEfpjFTUcipRgw7w1rU0MfWI1LQrEER
         xEo9gh+pIryulTgPkcTlXkTSfjrc9AA8KV3DzcLBmJVG/kGFfOcwJ7Ajf4zenFxtBStN
         egLg32EetEKaVrIeD8pBKmUHE8olPgpQYOSrwEDYB8RaUq8Y5/WUa3v3CmdP0jPbN9A4
         yZbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KrN4zpR8;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LCDb9cICfJVGPTmZC4wxaMdm5/i2FFMQSd0CGcuMu0o=;
        b=KWmmjHYQh3PPkdo9UsfVvu2tCoCWpKW+or+BFh7HVtfkltCBgR+A9BBmZEpjUXE9LQ
         riQNnT7lIELTwzP/D69u+o2kM0tw0OH9hP26Tp3dt6EzWIeToyK56ei737yAC0H9AtEj
         T5ci6uUl82G3kvXOHw4dr6vVNdTlRm6lSfdRY2sedPKJ8F3UaVY7ohdd6TEcpAWYHbUL
         yzeOS3D9ywK6V3vzDHgDfUboghBnEOe0EScjLv6oMn2fNyjd1rN8iK9bj96TUBc+raoz
         spAKbVHIRImzvsAELNJGyUEaWw1Fl+4lOZY8JtiMd/DK8WpEhcbqWElH3PCI/+l/TqcJ
         tshQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LCDb9cICfJVGPTmZC4wxaMdm5/i2FFMQSd0CGcuMu0o=;
        b=U80CHlfSGhnsGJWD2y0pTKoCxYJAPxmqE/po5tao+27vFniS82GXyVC56R30m8pe/3
         uvhZ0P572GT8eRUq/jpBUSRTKqAhGcxXN51FYW791qWGDKo8AXrdIhUiA/3CdjoKGqVu
         BrG46MByWecWoI7LYJ/HIZ/BAceBy8KzzJURekS2YPWtxeqaI/9eQ/Uqz1F45RiiuMmC
         lTWYhBjvQvyTgKNB7a2asD1MdNK3U+1mCFOBzMWohbc2h4NSwEw2Yyle2BlX0OLP1R18
         kY24z2nlVr+bWW/RkHfL0wY0D2oI7WGhWvKYW+bCOSb8DI4U0DmT/vQqY+Z9A1+8Ilt4
         /D2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9Wv24JCUy6+BgOo5KbomdeISPkFBWiDdyKe1OftKbVCIClOT5
	QHOn9DtsntzG2GOAnpN0Pgo=
X-Google-Smtp-Source: APXvYqzMtzGzJ5DnDIYgIq2fS11KzO/7a0gQd2KGQkwWu4PeKKRMk7EQRYa8+TOGbX99mm76EEwoFw==
X-Received: by 2002:aa7:920b:: with SMTP id 11mr12598032pfo.61.1574360131537;
        Thu, 21 Nov 2019 10:15:31 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb90:: with SMTP id m16ls1602805pls.13.gmail; Thu,
 21 Nov 2019 10:15:31 -0800 (PST)
X-Received: by 2002:a17:902:b118:: with SMTP id q24mr10279873plr.232.1574360131077;
        Thu, 21 Nov 2019 10:15:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574360131; cv=none;
        d=google.com; s=arc-20160816;
        b=TjktGVgmPqg0t3XZjg6r6dBljnhzUsDjyJcBJH0ouizONb8tBDK+3lJbyWn+rponJk
         VL4HBvg2sdhmmSXbnjABfMiJkpxcbOCEwWDenBKURKIfhjnYw+BHmXIDvctOYQuIiDDm
         TexbZKjaZIMN4gFtJM17heqaXJDVIfvudEI+zJ9+AB/CMsUaGY6L507dY6u0h7Hwb+0R
         sq4yscld2cMXDlvzcrvX8kXRhnmIEiqBADFG3II7HhY5hQjR92ZtFAMejKNUKYGRvKoT
         AGv5T/EyX3WnfPdBFBIWiBR+b1IMO3GZncpaFpz2TC8yziaKNKWlOFWWVw5j0zEBzcSo
         Q32Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=JQs/4UxemMcGCjHZn4niB7nA1rMhXtjAz7kJK3AjL7E=;
        b=i3wo+8Z8lWn08/FjhJjZ3b8lWzNA5h8zEtxWxlGaG2OXtmI9igq4lMFd4Ak/zXw+Jm
         oChzuhhVZE3eDGzC5eZgItXi98ezE3IdKjcFXv1evjr9sLSzJGiirl/Eh7W8qQSOzYS3
         6W7+qBjc7OZSNxk38iLqTTdkGrIuIAib1Ds+klic3LF4jPd6hjItLoes8k9BVuH/1rG6
         pwuZWcGZxgWnJvTn974OQusU8psGbi7CVnTUVVJpDVQBst3Ou0cKc6jcnCEVHk8leZLP
         WreNZmBu2ftFwi3We+afZq2DJT3RL9Q9EtrJ8S6PDxAXTXecEYvwJcTKCtVnDU6Dvbm6
         9aSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KrN4zpR8;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id g10si129117plp.4.2019.11.21.10.15.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 10:15:31 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r18so1980604pgu.13
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 10:15:31 -0800 (PST)
X-Received: by 2002:a65:66c7:: with SMTP id c7mr10861530pgw.407.1574360130724;
        Thu, 21 Nov 2019 10:15:30 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id s66sm4289099pfb.38.2019.11.21.10.15.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2019 10:15:28 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH v2 2/3] ubsan: Split "bounds" checker from other options
Date: Thu, 21 Nov 2019 10:15:18 -0800
Message-Id: <20191121181519.28637-3-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191121181519.28637-1-keescook@chromium.org>
References: <20191121181519.28637-1-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=KrN4zpR8;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543
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
---
 lib/Kconfig.ubsan      | 20 ++++++++++++++++++++
 scripts/Makefile.ubsan |  7 ++++++-
 2 files changed, 26 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 9deb655838b0..9b9f76d1a3f7 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -25,6 +25,26 @@ config UBSAN_TRAP
 	  the system. For some system builders this is an acceptable
 	  trade-off.
 
+config UBSAN_BOUNDS
+	bool "Perform array index bounds checking"
+	depends on UBSAN
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
+	depends on UBSAN
+	default UBSAN
+	help
+	  This option enables all sanity checks that don't have their
+	  own Kconfig options. Disable this if you only want to have
+	  individually selected checks.
+
 config UBSAN_SANITIZE_ALL
 	bool "Enable instrumentation for the entire kernel"
 	depends on UBSAN
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
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191121181519.28637-3-keescook%40chromium.org.
