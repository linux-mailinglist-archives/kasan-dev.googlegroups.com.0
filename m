Return-Path: <kasan-dev+bncBCF5XGNWYQBRBYGYQKXAMGQE2UZ2JGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 936DC8496AE
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 10:37:37 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-dbf618042dasf5954275276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 01:37:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707125856; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJMTD1evLanwcPpjQnwmFN+KkFYwjyTabmuij4suEV7mZLKzB9lQxAUbGMBJWa/69e
         7+4rtiesd4BXBrbgMeuX8PA4IsMcotOaeOnGaecCz0ODSGQUlhQaCc/tWebE0h2/Vv2D
         yZQEXQdpfn8nrt7MwSjTeb/C9RFHm0Bke2QIAX8H3V5Dc9EL4oA1dLPGt3bB3vEIMQpo
         /ZIPpAhU62iYu0n3cf9eCSxrhh9a667G+Qt7wOOxbG7kMIDRdBlukMsC0kZmGQQMB/i9
         bZVJiHVF7uFgYdq6A4uZt+Gir4q3w1/uo0fRUkd7I+ieIZXR5BplbXTU9AIOWF1NRk/x
         gz6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SMffSOA59eJkI7LSFS+hMHtAeQBb1GvHhhQJETXd4wQ=;
        fh=ifigu7JcFWRII3UbJaZ4Uiwj+/H5jJWratPah0nxxgo=;
        b=sbVAlujXxuXf6lMV6EWoOcRtXeeMN4op72wSs1lPar5o1ZcUE3Qdws/FPBHZqS7uOc
         8Czvpyjg6eE7l0x7OvnDpnv+wWagXW5at7Og8aaH2r3wks4Rav25tuBuY9waQYuafq+e
         UxfmmFHu2je/kMZbq7l0J+JclW07x8XR6nA1NsO6ZESy6ct2AXsv905VFD54a6DaTHHT
         2CA1zYQm2HGjCkvwpcLclnt2oVXctf68cjKP8DYRFfCLbnzIRdEwDF3zhhnOLfrkiTPW
         7ZXRJOU+Cz3towSsLpn3cM+w9aFjjFxjXlaNSe1bPV7CEdviFClBJzziHyCYnWn4ZC5b
         B+uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=cPpUlWso;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707125856; x=1707730656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SMffSOA59eJkI7LSFS+hMHtAeQBb1GvHhhQJETXd4wQ=;
        b=U+/04Zu4NMkX917mxga6spFq+O3DXOhJANw18HdlY03PJDwLAACrLmKaKhPBWWVaT+
         OMg9xUETpZjZTQbjk5nbDWNDnE34PgolXw2OC7HdtosiJpyCU3SsqUNo6RKiUaiT9kve
         HTH9mLw16OcpuzWfkiXBHBQVW7egWgvP9/JwRVr/HNeXCoun8eWUhheylWYP/gpYGVAe
         weFK14gztGFRVUO3+RXPrEVqwjfLEyjPkHsPcbRjVtsVqKu9XOeZNU5GN8gqIvNupt7e
         bgKO5SXlNUYejcn/qOgn+YgSGGoeh5wmcAI8wwckiqyK10kWdb3GJA3mIzG1jMDfmiwL
         YD5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707125856; x=1707730656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SMffSOA59eJkI7LSFS+hMHtAeQBb1GvHhhQJETXd4wQ=;
        b=W/ljeivMKuihEoYxsDnFvlOcNmMOF7G99u87bvgx1gVHHf+uRzYeSeDgqPblN5Uc//
         /cDbhjxhQjACdBzgikiX2nWoHUDEEQbjh18zhJDl8eeLrOXkclhQsoJBnY0IgCeXZzrd
         kueuhVaU5Yz3+ovn36Mqzg47/ereLtHKZRo3Iee7+yX5Gvc9yhqjiFwflgrTToFjbL+y
         AKV/+cqC8aJ2OFmOMfPlD9qlhga4IWs078MV3oo6PSqezIeRr6GX1tRvvdBl2HrJ8sLv
         V8SvAMatLa0gmUf3hPz4mXrTygjooU6Lvwhqr5Aml68mK7eWRknbHeRPDWYPC0lbpWV3
         ZSAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxMKp3cAhInrHoX/2/7yfK9V+t0oev+/MB3r35dJw/WpTeCOdZS
	/s14JbX30gFS4ngjAV53tz7Hs2z0VFw+tVLu6oT+m/b7Op3rcRzHyDo=
X-Google-Smtp-Source: AGHT+IHQvj8JjHJi78fTNK7tqVb4OMdLqBRJi8ej1IBg9hKiYwajBpqkMkdk1pjaDfzycP2Y2K/Qcw==
X-Received: by 2002:a25:690e:0:b0:dc3:6ba4:a2e2 with SMTP id e14-20020a25690e000000b00dc36ba4a2e2mr10588651ybc.49.1707125856229;
        Mon, 05 Feb 2024 01:37:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d844:0:b0:dc2:3107:a9fa with SMTP id p65-20020a25d844000000b00dc23107a9fals686922ybg.0.-pod-prod-02-us;
 Mon, 05 Feb 2024 01:37:35 -0800 (PST)
X-Received: by 2002:a25:b112:0:b0:dc6:978:19a4 with SMTP id g18-20020a25b112000000b00dc6097819a4mr11291566ybj.56.1707125855132;
        Mon, 05 Feb 2024 01:37:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707125855; cv=none;
        d=google.com; s=arc-20160816;
        b=J4UwuUNc9vvZ7FKUCZdAw1WCGE9O6sEJbd1tFr7RGjDNtEppjL7vRCDbEzNIw7ZP5h
         RagVbN879dggC4pqVjYPuTnA23pV9EDTcqY+6LdycN7gk//v30qGKG+nDLpDTm+6KXAd
         xqn0uYkOo1XGNgmsn8BUVD9J+CyUILaUPMzhftHXI833SwYnZRFnDjrLt9Qa7CKfAyGx
         StEE6zFD2ZOTQ1NYGPwYu+i/BlKskyTT5yexOuAS92JJp+Va9orWBa/Z6pful7L7NFj5
         6hVGHVJbhPxI6oGUADm0sQX+4NyIMdLwjr6NGQ9TQzhcoKghChBphiPUd21kcSwv54A9
         3uDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QxCwwNCdFbhbOkkNs+XeuXGgPs25hYCl4cEcrHgPhro=;
        fh=ifigu7JcFWRII3UbJaZ4Uiwj+/H5jJWratPah0nxxgo=;
        b=v+0roC8ONT11LRjp10WT9Wm/gZM/30gMOqBEs40yhfh+v9SJatlJV9jT+0orls8u94
         lIG3HMwTcd+f0ic0/mAXbE3iaGqQ2CJUSCe2/RL4CDMS7AJWO99tWtRCvmV6JPXsvybv
         OPvfctTRG0zOu++TlHW38ClMfScJQW2GhsfzBlJnWoxBWgroI2JAVqxCE8yGXpxFtdFh
         BAU5VZstcTh2xbcdLnbMm2zW4ndkdxa9aTqOU6lm69EGf5loIF8KNTE6GVMXy28fhpyz
         C9wORcCjJzLtVJIyqVE+wyTpaojMSGGb7lv4rlOCrxNTrRfGGtsiU5x4IH09zhI3YpIs
         Lnng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=cPpUlWso;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCW2i10ryf44uRaIVruje8DgqafnPB2/dUWPgc2nvaVg+NAuzxmMc0MFTifs+Bg94TwTPqFaVcSaVDLUyvtcnz+l/pToFjsMph7D7g==
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id d10-20020a25360a000000b00dc657e7de95si746621yba.0.2024.02.05.01.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 01:37:35 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id 46e09a7af769-6e1196dc31bso2219341a34.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 01:37:35 -0800 (PST)
X-Received: by 2002:a05:6808:2f19:b0:3bf:d03b:327e with SMTP id gu25-20020a0568082f1900b003bfd03b327emr7791024oib.37.1707125854639;
        Mon, 05 Feb 2024 01:37:34 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCXVnQMrzKpeRhuVQrxp8VL7XJSRIXie8Q1oeHWosnnXQB8icBA/Txx5Bep55wKUE29kmWnWiwca9tXC0Xq3xutLgoWD3tjkRsQmQijkPblNLO90yMop4RWbwkUAB9OuZ819QaZ0KKo+TDt4JDwv5+Z2oJwCidg/e9HL4sHZb3EfxDiWR00ZyZzZzuZkoeCalaf+HpziR51EcG+ckrDslHH+fXCBtGAojttYIJJoIXtanHAp4pOZdx/OLGZJo2yw/xqKeMndx2ILSLyk51oiplPBLX1q9tsFwAY/3u9Y+bv4PSozQ5i/ucvQKWfqCVU7SAyzgbj5rGeKWmo9mhkxHP3BCmjzTF8PpxJWeCOB5phLZaN2Uu1RS+aNkA9nNvU/cIeHvlWADOYveybspKRNGa3xoP8pTUQ+5rmgjkLiQXFz5jPGp/LzrIyd8hpuzStuSmAsVPxnfjX+U/BSBA3b5JoTzLMb9945xkNihdxMx+WkpkTB1vFnVWrBrncFiLCPhpV6nbMZIX5JjYltarZcycmMCQDSaL2kMz8=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id f11-20020a056a001acb00b006e025ce0beesm4404980pfv.168.2024.02.05.01.37.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Feb 2024 01:37:34 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Justin Stitt <justinstitt@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Hao Luo <haoluo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org
Subject: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
Date: Mon,  5 Feb 2024 01:37:29 -0800
Message-Id: <20240205093725.make.582-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=9230; i=keescook@chromium.org;
 h=from:subject:message-id; bh=B843R/+qtzUW3zjHJinDtuKnCc/TO3v2V71CYIstgfg=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlwKxZBzdKuy8ud3pw8T9E2DmYiTfvHCUk0jD3N
 BpCnUym4ymJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZcCsWQAKCRCJcvTf3G3A
 JskhD/9JYCTa5wf7FnS2pCfrha9Oi4N2gM5sZR7OejTK1cL0yvoY/mqDblqC/xbWC5YGpEDFa9j
 0IuFkJgnmQBhA/0gV4sMZxuBJPbIIn8rrygEh3heAnQ9dX2foVh5aLtjbZjLnZcwT1T4bOjn+HD
 0Adl/jOw+r2VCZwI5mU7tkJWfNBRF5Y4X7JE4cemkFF+4sSepRiGd32bH6p1vWVHwN4ogNFPkL/
 OMMNH3XBgW6Eu7iVZ9SwIyUi319l7PPecOLrfJDhSVkF4q4pCT8+KpzTsaI3RUI1mJQNnNpkARs
 JY1mhhGC+oWxSYgxbWQpZA35MsQrTFuXiW9QK19LuQyemiOxnYOBJDJp1rdu/rOD9dFfEVfFVF1
 Y+dFNNYQUuZnyneTNrWuTnk2Y1yLEz0J4BtyDxVRcO7OjndoLnvp8rYrObO80E582TaYWax9Uih
 C/s1a0/AfT5jzOe24HJsV8AqVFHesweBs0ufcOO+3zdW93XzMoXcnXGmjVlJMqrDXqRfvvRKV7U
 2DRujLplJ+lq/7xoZSliQfe3Oez8vtEfThBJgWm/YjHL1wboWmGWciJiuTHycbkwqtyYZrHz77P
 69fc+OOIqCZrFpWxZMaFBCa/YhSUPJRK8BjH/TtrHiDsAmoxcyGVUyeTUczDH0i9xoHwhYGb/Wx
 THR8NEt ni7QzfXA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=cPpUlWso;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::32b
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

In order to mitigate unexpected signed wrap-around[1], bring back the
signed integer overflow sanitizer. It was removed in commit 6aaa31aeb9cf
("ubsan: remove overflow checks") because it was effectively a no-op
when combined with -fno-strict-overflow (which correctly changes signed
overflow from being "undefined" to being explicitly "wrap around").

Compilers are adjusting their sanitizers to trap wrap-around and to
detecting common code patterns that should not be instrumented
(e.g. "var + offset < var"). Prepare for this and explicitly rename
the option from "OVERFLOW" to "WRAP".

To annotate intentional wrap-around arithmetic, the add/sub/mul_wrap()
helpers can be used for individual statements. At the function level,
the __signed_wrap attribute can be used to mark an entire function as
expecting its signed arithmetic to wrap around. For a single object file
the Makefile can use "UBSAN_WRAP_SIGNED_target.o := n" to mark it as
wrapping, and for an entire directory, "UBSAN_WRAP_SIGNED := n" can be
used.

Additionally keep these disabled under CONFIG_COMPILE_TEST for now.

Link: https://github.com/KSPP/linux/issues/26 [1]
Cc: Justin Stitt <justinstitt@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Miguel Ojeda <ojeda@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Hao Luo <haoluo@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
v3:
 - split out signed overflow sanitizer so we can do each separately
v2: https://lore.kernel.org/all/20240202101311.it.893-kees@kernel.org/
v1: https://lore.kernel.org/all/20240129175033.work.813-kees@kernel.org/
---
 include/linux/compiler_types.h |  9 ++++-
 lib/Kconfig.ubsan              | 14 +++++++
 lib/test_ubsan.c               | 37 ++++++++++++++++++
 lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
 lib/ubsan.h                    |  4 ++
 scripts/Makefile.lib           |  3 ++
 scripts/Makefile.ubsan         |  3 ++
 7 files changed, 137 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 6f1ca49306d2..ee9d272008a5 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -282,11 +282,18 @@ struct ftrace_likely_data {
 #define __no_sanitize_or_inline __always_inline
 #endif
 
+/* Do not trap wrapping arithmetic within an annotated function. */
+#ifdef CONFIG_UBSAN_SIGNED_WRAP
+# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
+#else
+# define __signed_wrap
+#endif
+
 /* Section for code which can't be instrumented at all */
 #define __noinstr_section(section)					\
 	noinline notrace __attribute((__section__(section)))		\
 	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
-	__no_sanitize_memory
+	__no_sanitize_memory __signed_wrap
 
 #define noinstr __noinstr_section(".noinstr.text")
 
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 56d7653f4941..129e9bc21877 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -116,6 +116,20 @@ config UBSAN_UNREACHABLE
 	  This option enables -fsanitize=unreachable which checks for control
 	  flow reaching an expected-to-be-unreachable position.
 
+config UBSAN_SIGNED_WRAP
+	bool "Perform checking for signed arithmetic wrap-around"
+	default UBSAN
+	depends on !COMPILE_TEST
+	depends on $(cc-option,-fsanitize=signed-integer-overflow)
+	help
+	  This option enables -fsanitize=signed-integer-overflow which checks
+	  for wrap-around of any arithmetic operations with signed integers.
+	  This currently performs nearly no instrumentation due to the
+	  kernel's use of -fno-strict-overflow which converts all would-be
+	  arithmetic undefined behavior into wrap-around arithmetic. Future
+	  sanitizer versions will allow for wrap-around checking (rather than
+	  exclusively undefined behavior).
+
 config UBSAN_BOOL
 	bool "Perform checking for non-boolean values used as boolean"
 	default UBSAN
diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index f4ee2484d4b5..276c12140ee2 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -11,6 +11,39 @@ typedef void(*test_ubsan_fp)(void);
 			#config, IS_ENABLED(config) ? "y" : "n");	\
 	} while (0)
 
+static void test_ubsan_add_overflow(void)
+{
+	volatile int val = INT_MAX;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val += 2;
+}
+
+static void test_ubsan_sub_overflow(void)
+{
+	volatile int val = INT_MIN;
+	volatile int val2 = 2;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val -= val2;
+}
+
+static void test_ubsan_mul_overflow(void)
+{
+	volatile int val = INT_MAX / 2;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val *= 3;
+}
+
+static void test_ubsan_negate_overflow(void)
+{
+	volatile int val = INT_MIN;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val = -val;
+}
+
 static void test_ubsan_divrem_overflow(void)
 {
 	volatile int val = 16;
@@ -90,6 +123,10 @@ static void test_ubsan_misaligned_access(void)
 }
 
 static const test_ubsan_fp test_ubsan_array[] = {
+	test_ubsan_add_overflow,
+	test_ubsan_sub_overflow,
+	test_ubsan_mul_overflow,
+	test_ubsan_negate_overflow,
 	test_ubsan_shift_out_of_bounds,
 	test_ubsan_out_of_bounds,
 	test_ubsan_load_invalid_value,
diff --git a/lib/ubsan.c b/lib/ubsan.c
index df4f8d1354bb..5fc107f61934 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -222,6 +222,74 @@ static void ubsan_epilogue(void)
 	check_panic_on_warn("UBSAN");
 }
 
+static void handle_overflow(struct overflow_data *data, void *lhs,
+			void *rhs, char op)
+{
+
+	struct type_descriptor *type = data->type;
+	char lhs_val_str[VALUE_LENGTH];
+	char rhs_val_str[VALUE_LENGTH];
+
+	if (suppress_report(&data->location))
+		return;
+
+	ubsan_prologue(&data->location, type_is_signed(type) ?
+			"signed-integer-overflow" :
+			"unsigned-integer-overflow");
+
+	val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
+	val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
+	pr_err("%s %c %s cannot be represented in type %s\n",
+		lhs_val_str,
+		op,
+		rhs_val_str,
+		type->type_name);
+
+	ubsan_epilogue();
+}
+
+void __ubsan_handle_add_overflow(void *data,
+				void *lhs, void *rhs)
+{
+
+	handle_overflow(data, lhs, rhs, '+');
+}
+EXPORT_SYMBOL(__ubsan_handle_add_overflow);
+
+void __ubsan_handle_sub_overflow(void *data,
+				void *lhs, void *rhs)
+{
+	handle_overflow(data, lhs, rhs, '-');
+}
+EXPORT_SYMBOL(__ubsan_handle_sub_overflow);
+
+void __ubsan_handle_mul_overflow(void *data,
+				void *lhs, void *rhs)
+{
+	handle_overflow(data, lhs, rhs, '*');
+}
+EXPORT_SYMBOL(__ubsan_handle_mul_overflow);
+
+void __ubsan_handle_negate_overflow(void *_data, void *old_val)
+{
+	struct overflow_data *data = _data;
+	char old_val_str[VALUE_LENGTH];
+
+	if (suppress_report(&data->location))
+		return;
+
+	ubsan_prologue(&data->location, "negation-overflow");
+
+	val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
+
+	pr_err("negation of %s cannot be represented in type %s:\n",
+		old_val_str, data->type->type_name);
+
+	ubsan_epilogue();
+}
+EXPORT_SYMBOL(__ubsan_handle_negate_overflow);
+
+
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
 {
 	struct overflow_data *data = _data;
diff --git a/lib/ubsan.h b/lib/ubsan.h
index 5d99ab81913b..0abbbac8700d 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -124,6 +124,10 @@ typedef s64 s_max;
 typedef u64 u_max;
 #endif
 
+void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
+void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
+void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
+void __ubsan_handle_negate_overflow(void *_data, void *old_val);
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
 void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
 void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 52efc520ae4f..7ce8ecccc65a 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -177,6 +177,9 @@ ifeq ($(CONFIG_UBSAN),y)
 _c_flags += $(if $(patsubst n%,, \
 		$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_SANITIZE)y), \
 		$(CFLAGS_UBSAN))
+_c_flags += $(if $(patsubst n%,, \
+		$(UBSAN_WRAP_SIGNED_$(basetarget).o)$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_WRAP_SIGNED)$(UBSAN_SANITIZE)y), \
+		$(CFLAGS_UBSAN_WRAP_SIGNED))
 endif
 
 ifeq ($(CONFIG_KCOV),y)
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 7cf42231042b..bc957add0b4d 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -13,3 +13,6 @@ ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
 ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
 
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
+
+ubsan-wrap-signed-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)     += -fsanitize=signed-integer-overflow
+export CFLAGS_UBSAN_WRAP_SIGNED := $(ubsan-wrap-signed-cflags-y)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240205093725.make.582-kees%40kernel.org.
