Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5LXLTQKGQEZXFAQOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 821832DF9A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 16:23:36 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id i33sf1647044pld.15
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 07:23:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559139815; cv=pass;
        d=google.com; s=arc-20160816;
        b=kWCG/KA72U56ZQfYezCF0f5rrYydoOpHKmfVRvY9IGiprUg/YFvQhJw0Tl8ExP4X4g
         qN6xnESJUzIxdhxwN7GpQU/f04I/tUyJW0r+wiZFETII6KX14oOOSquZWrn9asxVtNLq
         XbH0GkqmQCHrRqevHq2qupEJs/dWNTvnj/w6iOll9KPqKGGtOLt/o3a/2Mhz9mLV5GUc
         qaY4jcAUZ1/jJY2MxP8JsBT9Eljzzx8X2gmocYQp9v5D1GPvFEmUwvPh1EeHVGijIzz0
         6lVRCsjtqiRD8Fz0/tODvCZoWkgtIoiZBAPUu94a+Uv9vZ5gaXE4e9BmGDJh7639c7w4
         F7sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=REQhNYeoxdBexwypGQRRLGcUQb/j4sZ/6m9cP5Hd4kY=;
        b=om4tG+f/4av9RbRN/LDeXUdUOw+k/eH3ZRPSGiACBN4mIl+wzmP+7fHZ95MKby5KyP
         sUjVPac00gLskMEbO4aQZxY5IRpFUrmWr/FsGKBRAngTznpTTq6IT9Cg3dUM2D1HlO7P
         7A36M08jihV7/IjCO0LAKEDc5CUmnJzrP0+1SvrpIL6zoDm+2f5tr04tiS7u0Yj9DBrO
         dCsAjxePEwNmVd3BJI5Tz0ArkHY/3EGOBlNQitN7lgHCYSOlHsO1LSTIHmXwNoUnzoBR
         RG1LQuxteo7qwOVi/kwEXB+EpspoR8z5o6VJMs8e8G3qA3yKizyv9zvISkfvwCXiOzq5
         ggpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OxGkFght;
       spf=pass (google.com: domain of 35pxuxaukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=35pXuXAUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=REQhNYeoxdBexwypGQRRLGcUQb/j4sZ/6m9cP5Hd4kY=;
        b=jFslwGUiCehBWKuXR1Po7Vbg9YjtYDiZMCZJmdU2x7BHB809BqfT6jng3HvxmWXnrx
         vFJoyRxOdd1G1+GAnytP+wrEagcU2sOTr1SpGBxiHxe/1kYPn6am2sDWfOBJmsWVKrLT
         245SiAk8mtCB0UeTqxp7OYNl4CMNR4wlMg9biiRw4O52sF5cCoRi8L/FijRcGfMTMxSQ
         ljiM2s16tL6qnTDkN63SqBVwC0jupykgwjf1yB+i/B/PRuZDEwU2eRNdAXobTMcuDsco
         0uhpcBKwW6SJ3mUsq7q1hLwL2E9c46Gwg9JlO1vDVC2oZOmZ/KndAmVgTpdI+n2FQzI2
         LNjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=REQhNYeoxdBexwypGQRRLGcUQb/j4sZ/6m9cP5Hd4kY=;
        b=Gkjx+Xn3ReuYiRtZCyEXF9RJYYminxmDh3ZqMTIeJDc7nE0wjYOC2e4r+RSelZNtLd
         FT7241d+WiM76b5dQmKVK1+feHZ/tUrsqiWAWOcgeTNoDzfUeOSEaIxkOTCrRfc1gZ1H
         Tx26Opa47PG2mfaZL283IGqq5FBjzjtCzrmmqMRNNfOSjWqD8y21+mUglgB/9sZ6m4Am
         gtFU3vHJ5u+Tb5j4f7oiybkgX6e7OiwF/wW/fje8puB12gniYf9Jm06fwwzzBIV5fVMG
         I79hRC0Nl9XfOioKbWhd4uCeZluz4pvPyVOt5pEr6uQHLigdQ3JI+vV5TZZVRbPqPtGM
         nrcg==
X-Gm-Message-State: APjAAAXS8tVHmNTRvYefXwoFAqq1ZY68YoX4Z8alMiqXWMmRnHRYOvaP
	VPxKARhNOA2FZtyoVVwugyo=
X-Google-Smtp-Source: APXvYqx8OZczbEuHl+5UP8eqvWxGosKkAahQo80A9NTzHf9on7EjTPcu/ijf2nPLwBrMqp2yWjjZeg==
X-Received: by 2002:a62:164f:: with SMTP id 76mr151827864pfw.172.1559139815262;
        Wed, 29 May 2019 07:23:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:24ec:: with SMTP id i99ls323655pje.5.canary-gmail;
 Wed, 29 May 2019 07:23:34 -0700 (PDT)
X-Received: by 2002:a17:90a:f992:: with SMTP id cq18mr12348830pjb.54.1559139814935;
        Wed, 29 May 2019 07:23:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559139814; cv=none;
        d=google.com; s=arc-20160816;
        b=ARPlF+Dc9QfLUO8/tY3d4vhOgQQBFDjP9mVTp4UkzCTm8i9H/6hA0RSxRlCsMotsbk
         r3qaQuSezzxt7LRVFYu+BhCdknujE7R9Mk6wbAecRAFPhFaL20fjQb09ihoOGHZXjFYu
         OIjhE+1s9wxTPzfOQ5PM/nVwCSGdNodZAIKmoj3DmTjYmg7Tz1ujqoLmeA4GtWqmRzv4
         wZnvTs0oTeHn6Y+cQx0Ju9KBJ/SXp5KF5E8Tszj7AQSMg4Nl90fTti3oYXAx8izsCfCo
         Cxefe6LIq9Wn9PWBFrRKzdZCBFkzSKtlEqcjs7fU7UczSBBFqKjbv8DHP1OyY+lESMHE
         flXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=XGYstJC40WMJZKWA//5lX0DesV6Lf9IkKEWuIExOKfQ=;
        b=lHPbJnC9PQHz1Tg4xnmLc/n45suP0AhOm89mRgXX0ew60i0zKPfD7l9vLuHOEqK0rH
         YYjjGxoUZQyllFAEJUxlN7JipoDzyEBt0nh4W59Iy+BNCH2OqO/B1YKtg0L2o0n1MIMh
         qd8zEZdpvCXyzprjTrX5NXHZQDJHE4E5grkTUOkIhGPw5mo1OnOR5UR1tl7I5qYvACVP
         YKMYj3BOBbiTMMHjmlJsVHnlYqvkiaMf2/8w9/4cJNNqrPRmpRQ6pNOt+Wp06p0wjSmr
         Yn8g7VIQiu7qcpDTEI5WzByvXAGjj3tOJJG9L6QXnpW3W3Nl3pdqVG7QRSyUkGAxu2jh
         J66g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OxGkFght;
       spf=pass (google.com: domain of 35pxuxaukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=35pXuXAUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id z6si515877pgv.0.2019.05.29.07.23.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 07:23:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35pxuxaukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id u128so2021870qka.2
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 07:23:34 -0700 (PDT)
X-Received: by 2002:ac8:270b:: with SMTP id g11mr72071334qtg.363.1559139814057;
 Wed, 29 May 2019 07:23:34 -0700 (PDT)
Date: Wed, 29 May 2019 16:14:59 +0200
In-Reply-To: <20190529141500.193390-1-elver@google.com>
Message-Id: <20190529141500.193390-2-elver@google.com>
Mime-Version: 1.0
References: <20190529141500.193390-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v2 1/3] lib/test_kasan: Add bitops tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OxGkFght;       spf=pass
 (google.com: domain of 35pxuxaukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=35pXuXAUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

This adds bitops tests to the test_kasan module. In a follow-up patch,
support for bitops instrumentation will be added.

Signed-off-by: Marco Elver <elver@google.com>
---
Changes in v2:
* Use BITS_PER_LONG.
* Use heap allocated memory for test, as newer compilers (correctly)
  warn on OOB stack access.
---
 lib/test_kasan.c | 75 ++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 72 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7de2702621dc..6562df0ca30d 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -11,16 +11,17 @@
 
 #define pr_fmt(fmt) "kasan test: %s " fmt, __func__
 
+#include <linux/bitops.h>
 #include <linux/delay.h>
+#include <linux/kasan.h>
 #include <linux/kernel.h>
-#include <linux/mman.h>
 #include <linux/mm.h>
+#include <linux/mman.h>
+#include <linux/module.h>
 #include <linux/printk.h>
 #include <linux/slab.h>
 #include <linux/string.h>
 #include <linux/uaccess.h>
-#include <linux/module.h>
-#include <linux/kasan.h>
 
 /*
  * Note: test functions are marked noinline so that their names appear in
@@ -623,6 +624,73 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kasan_bitops(void)
+{
+	long *bits = kmalloc(sizeof(long), GFP_KERNEL | __GFP_ZERO);
+	if (!bits)
+		return;
+
+	pr_info("within-bounds in set_bit");
+	set_bit(0, bits);
+
+	pr_info("within-bounds in set_bit");
+	set_bit(BITS_PER_LONG - 1, bits);
+
+	pr_info("out-of-bounds in set_bit\n");
+	set_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __set_bit\n");
+	__set_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in clear_bit\n");
+	clear_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __clear_bit\n");
+	__clear_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in clear_bit_unlock\n");
+	clear_bit_unlock(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __clear_bit_unlock\n");
+	__clear_bit_unlock(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in change_bit\n");
+	change_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __change_bit\n");
+	__change_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in test_and_set_bit\n");
+	test_and_set_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __test_and_set_bit\n");
+	__test_and_set_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in test_and_set_bit_lock\n");
+	test_and_set_bit_lock(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in test_and_clear_bit\n");
+	test_and_clear_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __test_and_clear_bit\n");
+	__test_and_clear_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in test_and_change_bit\n");
+	test_and_change_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in __test_and_change_bit\n");
+	__test_and_change_bit(BITS_PER_LONG, bits);
+
+	pr_info("out-of-bounds in test_bit\n");
+	(void)test_bit(BITS_PER_LONG, bits);
+
+#if defined(clear_bit_unlock_is_negative_byte)
+	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
+	clear_bit_unlock_is_negative_byte(BITS_PER_LONG, bits);
+#endif
+	kfree(bits);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -664,6 +732,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kasan_bitops();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529141500.193390-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
