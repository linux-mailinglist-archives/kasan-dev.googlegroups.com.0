Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCXOS3YQKGQEJDU3KEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C537B142D0F
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:19:54 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id v11sf21979353edw.11
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:19:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579529994; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnPrD0pcFfSRUxcPawUs+OpZqkS9x60XcOfd1bm4zqEAKijDZEP75KGQcR6VwcPBQa
         61INow2henLuEVt4KyozslJnZel/PZc/yGQ3jw0mYW46Y4jfVdi6T/qbCqnZ8noJ4P1s
         sZsXFH7v6RT1YXQxd09YqwR9S9ZNOymLzC6QmPTcEa1FNXjfXvItbFXMeXdWaV6lSP/L
         vCrWAv0dpsWYM3rEdrIhrvmFzEdEXzKRLLS9db/DX4polijvwUFTeUvykQOhSGSoSeph
         /BqJNPqwtdzIU5IdcDaThxSWsNbGcy+/xTirVw+3bbWK0V5ywvp3es3LBIg6YxMSc3bX
         fNSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZqTB5Pu3SEpWHf62CzzhH0Jh8ZEFbm/VBw0SrQ57OrM=;
        b=FdrIZFkG+vskJiqtneSJggI0Cdjs6sFo+kTpXkKGchxaemfllKGWNMjw3OLq2DGLLn
         law/+BYYrj68oievf+UaEvwxRb2wU38WAMSDuCptlEeqUoFUiGtSkDE0nC2c9UzINLEo
         yrZyggkz0z5JlN3k0af+zubUksDurtd1u93AFm0I19lTXPWtXyAXoPvEZ10G+Tb1ZjR4
         lKNPfJnVekViVtKLBTAfM3CSsk0N9vR8Cbuxzj4vMe3rgwH3b9JBl0KI6SBJVPyFHYhX
         saVkFJdTue6SlYeUG5iHGxtbwE+vV8j5ERhgJ05ewlp6ugRuANK+q0aCT7NtTvFO4Kv5
         Ajhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LSSEn3c2;
       spf=pass (google.com: domain of 3cbclxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CbclXgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZqTB5Pu3SEpWHf62CzzhH0Jh8ZEFbm/VBw0SrQ57OrM=;
        b=Q/z/GZc9mOeveWwKJmiUDk3NvYnEadOjV3HVbZiJOnGI1pFG+2HOmXghck4kjaht/k
         0F0ZqwfS77/e35Tk6Q/14iUd99zHbU8HAyucNBLaNICKnoa0ZjbliESIcahJTocTEfAP
         ABUFrjKYuNzw3/rchLBgmyibMB+IAl9Fkmu2hsDkXy4FUd54saY1ehKoAtvkd3ZVLBE2
         y77aAag0D8Hc/siuh+f4vOyJGT1x0En2N0LxqWnbxgqOL7awZQAGT47juVisPNuXJaiN
         djIdj3dq27jUt0EAQfyhCIkJDkXDGW6NYjEHq/azE4w9bL+XCfuo/6br07sqLE+Ky7Jf
         0xIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZqTB5Pu3SEpWHf62CzzhH0Jh8ZEFbm/VBw0SrQ57OrM=;
        b=p/olJ/+Lo0C3FJIl/X7XILNmw26HeXCezYmAGg+CiIwcyh685Hqzo11AKtEcvSJRev
         RS8Ln2RKLzOIqX8vlEIUV4CcRINnHlVEHJlkUa5grOpfwPkTcxOgetWdA4OWJcyerwjV
         644CU705unAJFoyrP/34LUfqatmqitLnOQ1xw8z3QXS6klK/cX9nS4stnzo205C22ITn
         hBTFzzAxYFCRZDhQDl3LeQmFvUiFUQHdPT+PgiNPX52zmeO85Ba6FHKR8eckRAoymOW0
         u1IWkRTFgWJ9uY/AWwL975nHz/6DRbfMglnAgQapcvwcfUaZ7APLEpOPurp8rTKxN/hx
         GF5g==
X-Gm-Message-State: APjAAAW3bOavOCBjzcV4FubU6yUQlpe1BNjJs5VSMT3LdOJhshl3PM7s
	77iIX3HKPIlAzgUErYWqVCQ=
X-Google-Smtp-Source: APXvYqwpCd1EqnmktHN43rYkg9V1LoE5RD6QdwNZEvMaOJn5fY4MpfPbDnoC8qtJfHBrpFPxtOL4Vg==
X-Received: by 2002:a17:906:a44d:: with SMTP id cb13mr20928646ejb.258.1579529994478;
        Mon, 20 Jan 2020 06:19:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:8597:: with SMTP id v23ls8937122ejx.6.gmail; Mon, 20
 Jan 2020 06:19:53 -0800 (PST)
X-Received: by 2002:a17:907:375:: with SMTP id rs21mr20761832ejb.352.1579529993876;
        Mon, 20 Jan 2020 06:19:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579529993; cv=none;
        d=google.com; s=arc-20160816;
        b=JebqtVveM9WIQIqNVH22d5efEtnvow6RV/Tt9XjEn1h3D50XrTTWupYfcw7vnaceB6
         UpaeUL1zvbMphCYhDkWzKqGUBp3GEaxD9Qiw7+BrpVbuhoWIZo9MZbb/+IERJaIZqsgQ
         tT5WmJtL5qKt/pXyMplbtUkS6sidFhd5DJwbrPGYsCCNSBlqKk8RBTjNpYqMVs2db0Ig
         /0Swa57RJnAu6rs5DPSsrz2tWx6cj/syr+4yGllYl2MHyP/ADEm5s1/+p0BCRXAGzR+c
         UjLZVCmh6Of630ojBj+d0UzSkqwa2Ses3IyOEaR1OmiVZcTxU5PGRbRhJHsLt/MTzmLL
         uplg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sfeBMXRfbNdJgAnQzXh8K2r3zlp1l0BIMpCBNTG8NB8=;
        b=ZCD7q1AXCh7VKgltc4MNsaYVINa0OmNqwPJ1HXBAW0oS51xTMMqWohoTxdwp2WVyWs
         VSeo4L74erQx8ZffsvTN9pgcJg7T0dfb1ny7PoLpyVSLF/KZYKwMVm0OXnE44L7xqFhG
         HSdrZJc4OHkeYv62GgActv50yIYkgDpfIGsbFAPUK10zmBLu69b230qaG4rUNhFDi0df
         jTFDiAMQMaVqjJvWH+MJ9tQvn2I7ont7ePMp+saYD0uIj/eWzt9Y8JlGYVScScIG0gw4
         wsCCVS+xaYGj9roRYSAcDTxakO4cwAcvtSXO6C4Emn9psWuY1K1aHmiKCBCXMxttQOFg
         ZdUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LSSEn3c2;
       spf=pass (google.com: domain of 3cbclxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CbclXgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x18si1439397eds.2.2020.01.20.06.19.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:19:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cbclxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h30so14171262wrh.5
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:19:53 -0800 (PST)
X-Received: by 2002:a5d:5381:: with SMTP id d1mr18199365wrv.259.1579529993355;
 Mon, 20 Jan 2020 06:19:53 -0800 (PST)
Date: Mon, 20 Jan 2020 15:19:27 +0100
In-Reply-To: <20200120141927.114373-1-elver@google.com>
Message-Id: <20200120141927.114373-5-elver@google.com>
Mime-Version: 1.0
References: <20200120141927.114373-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 5/5] copy_to_user, copy_from_user: Use generic instrumented.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, 
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au, 
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org, 
	christian.brauner@ubuntu.com, daniel@iogearbox.net, cyphar@cyphar.com, 
	keescook@chromium.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LSSEn3c2;       spf=pass
 (google.com: domain of 3cbclxgukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CbclXgUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This replaces the KASAN instrumentation with generic instrumentation,
implicitly adding KCSAN instrumentation support.

For KASAN no functional change is intended.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/uaccess.h | 46 +++++++++++++++++++++++++++++------------
 lib/usercopy.c          | 14 ++++++++-----
 2 files changed, 42 insertions(+), 18 deletions(-)

diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index 67f016010aad..d3f2d9a8cae3 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -2,9 +2,9 @@
 #ifndef __LINUX_UACCESS_H__
 #define __LINUX_UACCESS_H__
 
+#include <linux/instrumented.h>
 #include <linux/sched.h>
 #include <linux/thread_info.h>
-#include <linux/kasan-checks.h>
 
 #define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
 
@@ -58,18 +58,26 @@
 static __always_inline __must_check unsigned long
 __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
 {
-	kasan_check_write(to, n);
+	unsigned long res;
+
 	check_object_size(to, n, false);
-	return raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_pre(to, n);
+	res = raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_post(to, n, res);
+	return res;
 }
 
 static __always_inline __must_check unsigned long
 __copy_from_user(void *to, const void __user *from, unsigned long n)
 {
+	unsigned long res;
+
 	might_fault();
-	kasan_check_write(to, n);
 	check_object_size(to, n, false);
-	return raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_pre(to, n);
+	res = raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_post(to, n, res);
+	return res;
 }
 
 /**
@@ -88,18 +96,26 @@ __copy_from_user(void *to, const void __user *from, unsigned long n)
 static __always_inline __must_check unsigned long
 __copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
 {
-	kasan_check_read(from, n);
+	unsigned long res;
+
 	check_object_size(from, n, true);
-	return raw_copy_to_user(to, from, n);
+	instrument_copy_to_user_pre(from, n);
+	res = raw_copy_to_user(to, from, n);
+	instrument_copy_to_user_post(from, n, res);
+	return res;
 }
 
 static __always_inline __must_check unsigned long
 __copy_to_user(void __user *to, const void *from, unsigned long n)
 {
+	unsigned long res;
+
 	might_fault();
-	kasan_check_read(from, n);
 	check_object_size(from, n, true);
-	return raw_copy_to_user(to, from, n);
+	instrument_copy_to_user_pre(from, n);
+	res = raw_copy_to_user(to, from, n);
+	instrument_copy_to_user_post(from, n, res);
+	return res;
 }
 
 #ifdef INLINE_COPY_FROM_USER
@@ -109,8 +125,9 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
 	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(from, n))) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user_pre(to, n);
 		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_post(to, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
@@ -125,12 +142,15 @@ _copy_from_user(void *, const void __user *, unsigned long);
 static inline __must_check unsigned long
 _copy_to_user(void __user *to, const void *from, unsigned long n)
 {
+	unsigned long res = n;
+
 	might_fault();
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
-		n = raw_copy_to_user(to, from, n);
+		instrument_copy_to_user_pre(from, n);
+		res = raw_copy_to_user(to, from, n);
+		instrument_copy_to_user_post(from, n, res);
 	}
-	return n;
+	return res;
 }
 #else
 extern __must_check unsigned long
diff --git a/lib/usercopy.c b/lib/usercopy.c
index cbb4d9ec00f2..1c20d4423b86 100644
--- a/lib/usercopy.c
+++ b/lib/usercopy.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
-#include <linux/uaccess.h>
 #include <linux/bitops.h>
+#include <linux/instrumented.h>
+#include <linux/uaccess.h>
 
 /* out-of-line parts */
 
@@ -10,8 +11,9 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
 	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(from, n))) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user_pre(to, n);
 		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_post(to, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
@@ -23,12 +25,14 @@ EXPORT_SYMBOL(_copy_from_user);
 #ifndef INLINE_COPY_TO_USER
 unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
 {
+	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(to, n))) {
-		kasan_check_read(from, n);
-		n = raw_copy_to_user(to, from, n);
+		instrument_copy_to_user_pre(from, n);
+		res = raw_copy_to_user(to, from, n);
+		instrument_copy_to_user_post(from, n, res);
 	}
-	return n;
+	return res;
 }
 EXPORT_SYMBOL(_copy_to_user);
 #endif
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120141927.114373-5-elver%40google.com.
