Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT6FWXTQKGQEJMWRNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 90C802CC0F
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 18:33:20 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id e17sf10546269otq.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 09:33:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559061199; cv=pass;
        d=google.com; s=arc-20160816;
        b=HM3mz+qlrrZDNg+LD5Je3ShFDHtFqqnW05/1DzNAC18id+2fsTKWtOPxvpfoTBqbZw
         A1Kfl4zvF7LNgewVws6N8Ms1ToJsh2Fu1zVrBV9S40gubLvE5zH8EFyt3q+kvqsc3L75
         Ms8GqsoIPh9F1TiIWxvm/78Gq/GaU9tP8G2OnEqNvcM9amO7BdA1x/6GbBT7CVSJ+iSO
         cHhRzyaiHUw6QKCAjdpworK7uOMVYpGSzPlDltM4Df7P+NRcR8AYKr3NxvQ95c2sYMtB
         YjvDp1p+bXME1lUH/gyYuOussKIJSDBW9u5zDFIpFDzKdF2F/SabN67Zf/MmrCiuTmvp
         UlnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Rte4/qGwRN3vr8w7cTCFLw/m+RMy/zNIwLCRB57C4BM=;
        b=wTw75dRe5065wEasrXDw7eedCzxHfez/es1QPgI1q9xKL9T4/RYDtR+M8pc9Xe9f/Y
         uR3C7aFhvltAhrMrf9XAAtTwJEEndGGjez20ANbf3i3T3qZ9C9Pk9IUyP8Zcv1P57jMR
         nTGWe6Cfu9bOaznscFHj8yPlzQEF5Lbng+q6NPdz7WIoLw3RRCdG++ecqJ+zYV/gKdMD
         mi/m5SwPEpoGuKRtDUJhULZZFzCUpUQ6t/HBsLI8b4AlOupLE8Q4lAw5mO2/HKpnWOSl
         Y5IzksI+AD2gZLnkaCAZP4SnZSggxTCNteec184H9HhAl27yHzRTUL3TTZbwI5pxwSPt
         Jf1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qze2NuI5;
       spf=pass (google.com: domain of 3zmltxaukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3zmLtXAUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Rte4/qGwRN3vr8w7cTCFLw/m+RMy/zNIwLCRB57C4BM=;
        b=FQGlmTd75wLtAGsA+IG+AtdkW41WcH5wzgL/xrqBh+nRcVTG7ELImHllZoqnGfqGGo
         l6dh7TxrJH47hgJRuP0CjVt2gdAGDPFEXlCIl4mGDvQdy2FgLH9xzj0v9+gUDxmpKcnm
         WaLb2uiCzqfcL0dr+cK4xGsUqe75cWpVC3tcuuSaNAwYsS8rH4VlatbrQ4SVDP9LZ0pj
         wldb+GX28F5UzO8IE9AOZUJ147yeXHSMMy/bzsTTPRC5ffKeYpjVQ/AgGN+Txg8GghQq
         9eXESKtS0ztijHeA9nN2p0iw+p0aymNqrl8ZytoDr6bUK4K/XkkgMDQqYNeFPWzqAqsm
         L4Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Rte4/qGwRN3vr8w7cTCFLw/m+RMy/zNIwLCRB57C4BM=;
        b=KxMMdTx25PXyeo06yUdA3I0cKOzi2P5wDvgxoDkonDg7OPTd4V72RjEJdWevLBCTVP
         I3rOXGFhEtxBd9VEgp3F2Xd1epgQlZCdWYMwfMy3oUXYt3nG4zbmVZ2CSQZWKIg8leb/
         7+ioOlrIm/zRaFu7o/I6LTxiPF7uGiNHL9GTPU8Vi3uyGViKVGQXFmw5ssWt/Yf+FRc/
         QvZkwAVWfXN5m6pGdqvbSkrzkbuDOLLRn9sB/g5CI3AVnGGav71OddyqS8p4o4DJ5P2v
         PLbTb0liGTJg/bK3EY2RfKfG0iyKixL4HyWk09efChQekSU3SLsRZ0RiwNZN2dh7dmM6
         zvuA==
X-Gm-Message-State: APjAAAVTTpYdgeA/oM4ZQKhowXmGvgKUbk7AQpOJgg58dyeFhHAXtdcY
	A0XKHft+zPnj5SH6/Ey6TVY=
X-Google-Smtp-Source: APXvYqzaI3c/4TRDbDmYaVSrGgByaD/agFe2BLsaAMCpQmSFSzCBSpjXeiWZFksGPP4eTxubf9U+1A==
X-Received: by 2002:a05:6830:1344:: with SMTP id r4mr38380706otq.264.1559061199485;
        Tue, 28 May 2019 09:33:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ac89:: with SMTP id v131ls2248516oie.6.gmail; Tue, 28
 May 2019 09:33:19 -0700 (PDT)
X-Received: by 2002:aca:acc7:: with SMTP id v190mr3361025oie.25.1559061199020;
        Tue, 28 May 2019 09:33:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559061199; cv=none;
        d=google.com; s=arc-20160816;
        b=FveUQvfOHW1jxbdRYxTHXegVB9HxRB9TeoCs4NlR49DjjJGJHKcvk2YHDxsFLbjCOh
         O/2vP2e+70+2cRtfGJFon5AzfV9HQoZoSMPHSqSKuNUuEkGmqBNb90lPuqE5lp0lpYIF
         yB/ttIIYao/yB75wrPUprXqtG2wwXdl7SvkjQfmNIMrB9DMMcedW5JAZKWXQqfyZi/H1
         lNQdITBHF+1DczegmhK2FLxBM+zEZfl3dPfO+CeJXuMetrB1Bfe4OvF/RRH7Hqu53sJq
         EkcY1lvNNrC4ZQc9aF/swH/roZVKNFps6IjCI0jm7KVMirjLav5Hh9LBuhLdqGcdhHZo
         UdXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=LR69yw39cmBSKp2W9gsMXj4VuQrD7UTJhZMWtKCJnXo=;
        b=CrT5rJBqkqHsWy6Oa6cNC0lWUGpND8mGqMqOkrzXLwRi567URzXJiitVAwJsWITYbW
         VZlLuJ6woJf8TLt9lA3G+uZfVisD4s1Qj5O/+Ls9nl4Qj2tFr7AdZ7MDVl9ki+9x8nVL
         ycJe87VobIXzRB7xYmjJzVHm0nmNT/4N27IdnE3XcW3gwjkHB6i7CiiZVCqWa6yNJ3N8
         +t4VHAe8hLe73fcSjP/PKzHqanmEeX5TsSQ+1DOACOhj5i8ewy0CaK5jAahPJPW0+ij4
         IB9BLSnSc6zZxXhXLT19uB+kE6F8pTwEf3ssFZJc+ag8+1hEIO/9bTWWyqxv7oHGvhWX
         8pPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qze2NuI5;
       spf=pass (google.com: domain of 3zmltxaukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3zmLtXAUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k22si735237otp.1.2019.05.28.09.33.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 May 2019 09:33:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zmltxaukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id n77so5446419qke.17
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2019 09:33:18 -0700 (PDT)
X-Received: by 2002:ac8:21ba:: with SMTP id 55mr20465060qty.116.1559061198612;
 Tue, 28 May 2019 09:33:18 -0700 (PDT)
Date: Tue, 28 May 2019 18:32:56 +0200
Message-Id: <20190528163258.260144-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH 1/3] lib/test_kasan: Add bitops tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qze2NuI5;       spf=pass
 (google.com: domain of 3zmltxaukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3zmLtXAUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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
 lib/test_kasan.c | 73 ++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 70 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7de2702621dc..f67f3b52251d 100644
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
@@ -623,6 +624,71 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kasan_bitops(void)
+{
+	long bits = 0;
+	const long bit = sizeof(bits) * 8;
+
+	pr_info("within-bounds in set_bit");
+	set_bit(0, &bits);
+
+	pr_info("within-bounds in set_bit");
+	set_bit(bit - 1, &bits);
+
+	pr_info("out-of-bounds in set_bit\n");
+	set_bit(bit, &bits);
+
+	pr_info("out-of-bounds in __set_bit\n");
+	__set_bit(bit, &bits);
+
+	pr_info("out-of-bounds in clear_bit\n");
+	clear_bit(bit, &bits);
+
+	pr_info("out-of-bounds in __clear_bit\n");
+	__clear_bit(bit, &bits);
+
+	pr_info("out-of-bounds in clear_bit_unlock\n");
+	clear_bit_unlock(bit, &bits);
+
+	pr_info("out-of-bounds in __clear_bit_unlock\n");
+	__clear_bit_unlock(bit, &bits);
+
+	pr_info("out-of-bounds in change_bit\n");
+	change_bit(bit, &bits);
+
+	pr_info("out-of-bounds in __change_bit\n");
+	__change_bit(bit, &bits);
+
+	pr_info("out-of-bounds in test_and_set_bit\n");
+	test_and_set_bit(bit, &bits);
+
+	pr_info("out-of-bounds in __test_and_set_bit\n");
+	__test_and_set_bit(bit, &bits);
+
+	pr_info("out-of-bounds in test_and_set_bit_lock\n");
+	test_and_set_bit_lock(bit, &bits);
+
+	pr_info("out-of-bounds in test_and_clear_bit\n");
+	test_and_clear_bit(bit, &bits);
+
+	pr_info("out-of-bounds in __test_and_clear_bit\n");
+	__test_and_clear_bit(bit, &bits);
+
+	pr_info("out-of-bounds in test_and_change_bit\n");
+	test_and_change_bit(bit, &bits);
+
+	pr_info("out-of-bounds in __test_and_change_bit\n");
+	__test_and_change_bit(bit, &bits);
+
+	pr_info("out-of-bounds in test_bit\n");
+	(void)test_bit(bit, &bits);
+
+#if defined(clear_bit_unlock_is_negative_byte)
+	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
+	clear_bit_unlock_is_negative_byte(bit, &bits);
+#endif
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -664,6 +730,7 @@ static int __init kmalloc_tests_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190528163258.260144-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
