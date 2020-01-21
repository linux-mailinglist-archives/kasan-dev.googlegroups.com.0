Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU6CTTYQKGQEXM5F2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D73114418A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:05:40 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id 90sf1511080wrq.6
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:05:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579622740; cv=pass;
        d=google.com; s=arc-20160816;
        b=jV/Q9YlVgmoWAsu3XFdnMDxCr7kYBqEik1a7jm7187AH17yGVdGwUYy+gSJhHWfobn
         BwQeA4HzJFVL+Z+t/VE/3prW3qd0k+izxSKADixsuGAJMlPNM/c4OALaLA2do6GwBl8X
         q8lk1MruKKfRfaw/BkecvhzOMJ9ZeG6w2OuByyU2oFkyBBKhE1Oqh9Tg9LNwcmujhudi
         2odMpLTSDoZzW2NEGWPgABq5oBh5ox13gc7UY+x/5A1J56r46xM+V9C15Ovm7kRazElP
         tGS8hE5dfykhbtVdkQwU1rh+eAd6w0p4H0wMFjS9v8uPVZgPgy97+ZP7YB7PSsEqvJjw
         wy3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mgAQ/qArp/e49x7uJus0ssPlzcjRFlkWBV8Iuwt74ek=;
        b=rTqQZVa+PqsoWqifTRzgh9I9tDNMtlDt/vchq+tv9ad/YH2EFdwN96QqXAXNrQcRSo
         GkSSE83z03lRklM5I2x+aEtdlo5ZdkzxCvt0EQiao81MX2Af98EA5PL6WFHEnSSHB+Mg
         7fv6MBxaZ8myj1IHgE4Jldw61ZRA7eZQ1XiLCvMRPoAwvKJg55ATMTuer6E3YK6Dz7ep
         V3VVHWgv56B33OFGQCR9bwwC0qCMHV8h9DDBCXSv8ZFwefOIFDTPYoNlUYYp/nPu3xWQ
         mgz0vP+/+KkdOd1PRBjjmNr2eYOtLme7mdvoX4HmjvJqLYv8ol+a+jmtLY9uNqA/610L
         le2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vEveYDGl;
       spf=pass (google.com: domain of 3uienxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UiEnXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mgAQ/qArp/e49x7uJus0ssPlzcjRFlkWBV8Iuwt74ek=;
        b=CJQuX1lCSvutC02e71rt3nKOR2Mnx1jgCM5tXXrp0L6mNJoQdXqhMFG48iGb6OSADe
         ZTKOOA2S0iU2FkXlMa5ECizDv1u2IdgnHC5zR+8jLUrxHb+pyka9Gtpm8Il48MqlPHFE
         JtoUZqV8aqMZjc61XxeOxHKoTjgD+ydfh2DjLVqHng8mRaVO2lsFfRrbSt33K7JtuGjX
         k9rNIZcKdC9rjE8anYd91CyddPvupFxko06nrvSt0pHky65OcpVZZVBRlp0Lt+TKCFWe
         rDUtqCs0QtddS24HTpBBDngbzXWUJUDfEG560/amwp9XYdPsvK9O/T0NGtiGfr1zKgeH
         bE1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mgAQ/qArp/e49x7uJus0ssPlzcjRFlkWBV8Iuwt74ek=;
        b=F0B3rLF5vVbVpQ6uwF+eimKy/JdGgyCMmq/AtcZ/V9h5zxXV3wQLaKyWDx4EJRi/bL
         aGzeukRgMsELKmQ/zD8MjjbBoVl94E11eWrtSMrhw+bhlw5vFbjYu67xIpMgdLpYef4a
         ECnBvPXXoQezTwiufhgwgqo8VcLIOJj8X39ZGAtxuapW85m1tgRdGuBHl1u0jf/taPav
         Bmbdo3AvKjQm+H9S7kOEtm5QHAKhMbaryeErunnLawy7GTN0zbzLShFdpKcCAQNLFzvE
         Hh8+cRJV3+p3sHka/dtDgzrXLaVaeEcnz6GC9E1AQQUaVdx4DH9Yh6voG1lgM81vFU5P
         7HWg==
X-Gm-Message-State: APjAAAXAAyrOikiU8QDtusFrrp4zyRG8si+kOnIJoamm8kRzdvz+qn9X
	YghA3m24q0D6H3UN3LByt6c=
X-Google-Smtp-Source: APXvYqzCdrsQ6LWLRsqs0MZCVqydh/podvsFQiCtJeSu34vw5CuXqyXvMebg/wlUaxGmuBTd9J+pmw==
X-Received: by 2002:a05:6000:f:: with SMTP id h15mr6146879wrx.90.1579622739943;
        Tue, 21 Jan 2020 08:05:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c452:: with SMTP id l18ls231942wmi.1.canary-gmail; Tue,
 21 Jan 2020 08:05:39 -0800 (PST)
X-Received: by 2002:a7b:c407:: with SMTP id k7mr5154487wmi.46.1579622739205;
        Tue, 21 Jan 2020 08:05:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579622739; cv=none;
        d=google.com; s=arc-20160816;
        b=N0lk5PrJ/9lToaOzlzcrVaYaYU3cyZLUIMdrNs/96a4Zlp14z9omcoxhMjCEAHm6Ej
         7dZ8fJqhLoRfpJUeexvMzinFxpNwYLTHQicn6YC5GXZttX9PfNPim43m/TbTUzbBnWJl
         Z5jvv/dLCgw+G9ZZIMGspV/TR4YI5NkYrg5KGptqBPkLDvAhgu2B83EzZRf/lvB1jP4h
         Y1yE7A0ljuBU8/CfBnEdxVYkECs4i1/8kM3oGA5SwUcjBXzAoXiT3K+i41WMd3ty+v1u
         cZIjC33hD3+SyuAxhRRFjEE14k3Ne6GXt0s9SBZhOmh//1MhbheTXO0FTGjejDpXkEsB
         T/QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rQnN5kw1tCui7wtVtPb4liBxMrcaouM2L/Dj3ZF7x/U=;
        b=HSs5W4RYNSTaaxp5hsCgMzn/GLZzQz5XTU/5cBnOyzNajNMlIBr1US0jfy5q6UO7xe
         3+kYJRVEE1M5T/J4PgULhiYvDQWD9Yi5B08AWvA61lEJiHCXc/vyS1dhSlf4FjNdM1RX
         GCqUDoh9bZIkSHRG57G7t07OpuTz2rQ9WdG9xzzsZd5HLsD0r2qHCAYI45ftRA+vWTID
         JSNCJ2NwogyIABf6Qy0x/VGVuBF2lj/kHhVhYYirEFbHFAEmxgmzFiRTKQ6mH6K5YJuj
         DzaUUxbg0cTSqdHDAfHMSehJID5dlZuUIy2J5MleXDkyHeiOkyEV45Yb2kX8VNVMhOY6
         V6eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vEveYDGl;
       spf=pass (google.com: domain of 3uienxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UiEnXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b9si1606066wrw.2.2020.01.21.08.05.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:05:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uienxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id c17so1507292wrp.10
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:05:39 -0800 (PST)
X-Received: by 2002:a05:6000:50:: with SMTP id k16mr5659732wrx.145.1579622738696;
 Tue, 21 Jan 2020 08:05:38 -0800 (PST)
Date: Tue, 21 Jan 2020 17:05:12 +0100
In-Reply-To: <20200121160512.70887-1-elver@google.com>
Message-Id: <20200121160512.70887-5-elver@google.com>
Mime-Version: 1.0
References: <20200121160512.70887-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 5/5] copy_to_user, copy_from_user: Use generic instrumented.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, dja@axtens.net, 
	christophe.leroy@c-s.fr, mpe@ellerman.id.au, mhiramat@kernel.org, 
	rostedt@goodmis.org, mingo@kernel.org, christian.brauner@ubuntu.com, 
	daniel@iogearbox.net, keescook@chromium.org, cyphar@cyphar.com, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vEveYDGl;       spf=pass
 (google.com: domain of 3uienxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UiEnXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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
v2:
* Use updated instrumented.h, removing post-hooks for user-copies.
---
 include/linux/uaccess.h | 14 +++++++-------
 lib/usercopy.c          |  7 ++++---
 2 files changed, 11 insertions(+), 10 deletions(-)

diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index 67f016010aad..8a215c5c1aed 100644
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
 
@@ -58,7 +58,7 @@
 static __always_inline __must_check unsigned long
 __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
 {
-	kasan_check_write(to, n);
+	instrument_copy_from_user(to, from, n);
 	check_object_size(to, n, false);
 	return raw_copy_from_user(to, from, n);
 }
@@ -67,7 +67,7 @@ static __always_inline __must_check unsigned long
 __copy_from_user(void *to, const void __user *from, unsigned long n)
 {
 	might_fault();
-	kasan_check_write(to, n);
+	instrument_copy_from_user(to, from, n);
 	check_object_size(to, n, false);
 	return raw_copy_from_user(to, from, n);
 }
@@ -88,7 +88,7 @@ __copy_from_user(void *to, const void __user *from, unsigned long n)
 static __always_inline __must_check unsigned long
 __copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
 {
-	kasan_check_read(from, n);
+	instrument_copy_to_user(to, from, n);
 	check_object_size(from, n, true);
 	return raw_copy_to_user(to, from, n);
 }
@@ -97,7 +97,7 @@ static __always_inline __must_check unsigned long
 __copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	might_fault();
-	kasan_check_read(from, n);
+	instrument_copy_to_user(to, from, n);
 	check_object_size(from, n, true);
 	return raw_copy_to_user(to, from, n);
 }
@@ -109,7 +109,7 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
 	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(from, n))) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user(to, from, n);
 		res = raw_copy_from_user(to, from, n);
 	}
 	if (unlikely(res))
@@ -127,7 +127,7 @@ _copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	might_fault();
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = raw_copy_to_user(to, from, n);
 	}
 	return n;
diff --git a/lib/usercopy.c b/lib/usercopy.c
index cbb4d9ec00f2..4bb1c5e7a3eb 100644
--- a/lib/usercopy.c
+++ b/lib/usercopy.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
-#include <linux/uaccess.h>
 #include <linux/bitops.h>
+#include <linux/instrumented.h>
+#include <linux/uaccess.h>
 
 /* out-of-line parts */
 
@@ -10,7 +11,7 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
 	unsigned long res = n;
 	might_fault();
 	if (likely(access_ok(from, n))) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user(to, from, n);
 		res = raw_copy_from_user(to, from, n);
 	}
 	if (unlikely(res))
@@ -25,7 +26,7 @@ unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	might_fault();
 	if (likely(access_ok(to, n))) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = raw_copy_to_user(to, from, n);
 	}
 	return n;
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-5-elver%40google.com.
