Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOU64DZAKGQEEKDDIQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 92A5F1727FF
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:31 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id a10sf172085qkg.11
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829370; cv=pass;
        d=google.com; s=arc-20160816;
        b=W9ffP86VApVZdjofmMvRPwtrPk++lE2Hx8YFBelY4I278oV9htCoslvKy5g6r+aW4p
         911yPjOtUmlXlRGk24OGyJydXbqatBs3I9S+hlUru+6pGZU7+VkOYCLaE9rVZNiBwkvp
         R4pVJCumB8BiTaw/YmwpwXwLtyhR9tgzAyWNP5wMHTNtLVGRCE6g8w9x+oaTXSK9IU9i
         NGNcwRCMS2i9FNsGmPvSvIvpnXgnPuPjbOxLpyV3F9e2EvxEr4TKiAiUVAbyzfZvT9yx
         1kSTWmSqLaquXyUe6OKlYQYSoMkYlsgqxZd5tS3XtShBfIalCbXGPw5DPpjGwoC1O/E6
         +n7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GKdqdVYu/rRv8BAGEklZZ4fyQm0YyNkuhxgMLIUDv54=;
        b=mqRoDrRso5p0cGqgHLjNKyNg5D59edYgkdbPzkv+L05Bwf4IODMfHSAjSowZaAC5e3
         PLM6bLnywHAO1EGgDqcFFJU/bLQmAqkHo4wZr4xglGI+zo1xIEYd4LAy2I8Y6/+s7ASe
         P3T012fSJOhuAb45dP6mBmCBVREPlXZjr0Z/bq/SXoYY+toFv4cwIGAa6/QuO7+4X5rp
         rVqcFJcOW365Tq+aRXUZwYDK2UOO/w6ekMJAl6PYZ5e4CwrZkMWFXjP4o04n5xKw9hkf
         XznpIb0xISmU+Usp22yaYUozDeEqV7QfNM2KPD0iuhDroCvRfPlE2qx44cmdfpCZfZGv
         t6sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=OG6B2Rfw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKdqdVYu/rRv8BAGEklZZ4fyQm0YyNkuhxgMLIUDv54=;
        b=NTv+7i5h0s2nkNZnkedD5KGFDkAmnvULbNbuzZNdtbm6DyL+/KvCw5xLIz6SMw8Vs9
         QA5sR4yJ6W9i02YA5D8fg5OvnPY2cb58CSh/StHyyz9Wzqdl3SK9Qa3Ol0qUy71s96aR
         qmJbTU7atCh04Kv2px0l5HpUGZFjwwlZl0qATSSc+hoIPoSibWRkmTu3hP7f9w/TenI/
         +1BTmUNNKEBJV3Pp8igX8bnhjDaurfB2oTljI1DHN3kkwBnfirlhJbAQ/7+n5pqoL2uU
         Stv0JCipMa5/00uFakIArxw6GnLeVfP6m/VnlBVo8D02mxpQ1ZXXMY+lP8BuH+jXL2xh
         +jtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKdqdVYu/rRv8BAGEklZZ4fyQm0YyNkuhxgMLIUDv54=;
        b=J77LrsE4hfa3+QLO5rw5D185vdCcmn2thX69WmU/AlbmXT7agGWFGZ7pyM/eNGjPBM
         8XsFVQ0Kr6T/UqyhymF6niNLapgejKctXejCzbBOROuu7cOhxUA7yNdoTCyREwD27tDu
         wpRm1oYGmrfP+GNXMOwO4zx6bshOtOuEDweE2P/KiIuMLPKh5VVPc8SoK8KBt6hZZS2E
         bO+W1qYQdzmAZp+A4PnUKOYAflq0BitFTPW6HtZ/IsyMcSR7QRC3kRbX9veuzR8yg/qZ
         lSLs7a3tuPgvuymssvLs7GHe6U2EIHvPtjq3ccO7S9C/FrV9SVsMlM1r8hMvYtz/xC2F
         Imiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUxB5xWjb3KMI4sc4vvUgpeIEvWILe66osA1C9PDBFwp7HpuF2W
	7KwItx+25ZHFiV2lfktv99k=
X-Google-Smtp-Source: APXvYqy8zk/GNeC/IXv00rJy97eVRuNxwS+5g6CCA9DYUbfCikb2bItKwx/StXHmqN68Ju7gJugxww==
X-Received: by 2002:ac8:6759:: with SMTP id n25mr699522qtp.226.1582829370655;
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4b68:: with SMTP id m8ls155858qvx.2.gmail; Thu, 27 Feb
 2020 10:49:30 -0800 (PST)
X-Received: by 2002:ad4:554b:: with SMTP id v11mr317405qvy.0.1582829370363;
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829370; cv=none;
        d=google.com; s=arc-20160816;
        b=IofrkvvUE9CKKnhpi4S3LtQNN+QIJ9UQFv3xy03lsn8x6u/PYB/lDUzcNXTbj5yj44
         hvjdXs16tARUBkpNhCDgtBVyZi0KUfqVPKlyzpJ55aFi/ZyoSjIwnFFRmwgft31sV4Mj
         EE4uWIFkn80BZjXid4q6Km3ztqXACsrpkz1XjIiLqu0vz9QI1f88U4q95oq7VeJqgTJO
         xZNZW5CwZ6gAnd0vHbAwTkNsKqbn4+uDUlIaDwxRUUm0vrZkICmbWqj4NF5Xt4PVMgd9
         l6ncC5Hkb0t4zkbTXtlfLfoshOjz1wj4am006PBHoFHG3WU+3FDB1/Gceljc7Mx+nKfY
         qWxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ouVhJC1LzbMtIjBpkBkXzJDLKbzWPj7ADPmF+3aq9S8=;
        b=0FcK6VFLIkp4kOE+oW1L2wY2BEOk0zMsc2l0F8hb9d4S29Xvu11vji6ldP3R9dY6Hq
         U9MCRaKxF6L8uFrLZwAvCE6lX6UK7ws4wH2pxnKeUk9Uj0Tz0BmDQ79aqVh3MWdIYfJ3
         HGh0SDfffCvaxUh/mjAgcMvLsXChFVM2B+M25h/C7N8OcV0gDRWArNJvKzO2CWz9sDUY
         amjv/92Y05hzOMucmvWzdsVaMzHnBCjDcxeW9vukeShuSgFlV/0uHYzft5Aoge3XFoaT
         YDaTj0UmDb5BWFue0m6LtetUnUp2Jm3Cinsp/ZXmbqFO598UkOgoJdIHdxciU8nWcdV6
         HdDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=OG6B2Rfw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id a130si27650qkc.7.2020.02.27.10.49.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id p14so286283pfn.4
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:30 -0800 (PST)
X-Received: by 2002:a63:120f:: with SMTP id h15mr716250pgl.235.1582829369446;
        Thu, 27 Feb 2020 10:49:29 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id q17sm7811248pfg.123.2020.02.27.10.49.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:26 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
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
Subject: [PATCH v4 1/6] ubsan: Add trap instrumentation option
Date: Thu, 27 Feb 2020 10:49:16 -0800
Message-Id: <20200227184921.30215-2-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227184921.30215-1-keescook@chromium.org>
References: <20200227184921.30215-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=OG6B2Rfw;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442
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

The Undefined Behavior Sanitizer can operate in two modes: warning
reporting mode via lib/ubsan.c handler calls, or trap mode, which uses
__builtin_trap() as the handler. Using lib/ubsan.c means the kernel
image is about 5% larger (due to all the debugging text and reporting
structures to capture details about the warning conditions). Using the
trap mode, the image size changes are much smaller, though at the loss
of the "warning only" mode.

In order to give greater flexibility to system builders that want
minimal changes to image size and are prepared to deal with kernel code
being aborted and potentially destabilizing the system, this introduces
CONFIG_UBSAN_TRAP. The resulting image sizes comparison:

   text    data     bss       dec       hex     filename
19533663   6183037  18554956  44271656  2a38828 vmlinux.stock
19991849   7618513  18874448  46484810  2c54d4a vmlinux.ubsan
19712181   6284181  18366540  44362902  2a4ec96 vmlinux.ubsan-trap

CONFIG_UBSAN=y:      image +4.8% (text +2.3%, data +18.9%)
CONFIG_UBSAN_TRAP=y: image +0.2% (text +0.9%, data +1.6%)

Additionally adjusts the CONFIG_UBSAN Kconfig help for clarity and
removes the mention of non-existing boot param "ubsan_handle".

Suggested-by: Elena Petrova <lenaptr@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/Kconfig.ubsan      | 22 ++++++++++++++++++----
 lib/Makefile           |  2 ++
 scripts/Makefile.ubsan |  9 +++++++--
 3 files changed, 27 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 0e04fcb3ab3d..9deb655838b0 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -5,11 +5,25 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
 config UBSAN
 	bool "Undefined behaviour sanity checker"
 	help
-	  This option enables undefined behaviour sanity checker
+	  This option enables the Undefined Behaviour sanity checker.
 	  Compile-time instrumentation is used to detect various undefined
-	  behaviours in runtime. Various types of checks may be enabled
-	  via boot parameter ubsan_handle
-	  (see: Documentation/dev-tools/ubsan.rst).
+	  behaviours at runtime. For more details, see:
+	  Documentation/dev-tools/ubsan.rst
+
+config UBSAN_TRAP
+	bool "On Sanitizer warnings, abort the running kernel code"
+	depends on UBSAN
+	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
+	help
+	  Building kernels with Sanitizer features enabled tends to grow
+	  the kernel size by around 5%, due to adding all the debugging
+	  text on failure paths. To avoid this, Sanitizer instrumentation
+	  can just issue a trap. This reduces the kernel size overhead but
+	  turns all warnings (including potentially harmless conditions)
+	  into full exceptions that abort the running kernel code
+	  (regardless of context, locks held, etc), which may destabilize
+	  the system. For some system builders this is an acceptable
+	  trade-off.
 
 config UBSAN_SANITIZE_ALL
 	bool "Enable instrumentation for the entire kernel"
diff --git a/lib/Makefile b/lib/Makefile
index 611872c06926..55cc8d73cd43 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -279,7 +279,9 @@ quiet_cmd_build_OID_registry = GEN     $@
 clean-files	+= oid_registry_data.c
 
 obj-$(CONFIG_UCS2_STRING) += ucs2_string.o
+ifneq ($(CONFIG_UBSAN_TRAP),y)
 obj-$(CONFIG_UBSAN) += ubsan.o
+endif
 
 UBSAN_SANITIZE_ubsan.o := n
 KASAN_SANITIZE_ubsan.o := n
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 019771b845c5..668a91510bfe 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -1,5 +1,10 @@
 # SPDX-License-Identifier: GPL-2.0
 ifdef CONFIG_UBSAN
+
+ifdef CONFIG_UBSAN_ALIGNMENT
+      CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
+endif
+
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=shift)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=integer-divide-by-zero)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=unreachable)
@@ -9,8 +14,8 @@ ifdef CONFIG_UBSAN
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=bool)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=enum)
 
-ifdef CONFIG_UBSAN_ALIGNMENT
-      CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
+ifdef CONFIG_UBSAN_TRAP
+      CFLAGS_UBSAN += $(call cc-option, -fsanitize-undefined-trap-on-error)
 endif
 
       # -fsanitize=* options makes GCC less smart than usual and
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-2-keescook%40chromium.org.
