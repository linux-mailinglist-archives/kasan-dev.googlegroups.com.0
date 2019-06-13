Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJUFRHUAKGQE4DGZPKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id B95B2435EE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 14:33:43 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id i4sf16432139qkk.22
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 05:33:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560429222; cv=pass;
        d=google.com; s=arc-20160816;
        b=G0r2qS5B/dILnH8kJGIrDOeRAPmWRwcsXCJHjhaQ8AC4gE8ch0s+d5fnBjhj/C+/2l
         rcmqvkJiPLttqkumlcC7HF4acI8r+xva8KvCkPlC2ozPN57bWvM5GMzAipUkCPYAWpzZ
         wT0eU0qCt0HIdRqsy2xULiU+cFTk6idMNxu22bJQtxCpRhyABKRLT7/Vwirj31uwqC64
         18F5pgkuAzc1JqJnaSqPUScm9QbfFh9UvNNRniv04rWNjxsTB0FKyL8CDQ31My733wW4
         rBIxFoOV8LhRi7OKWU1qnhrSiRjANztLGhDPqKtIOWBSn1kpdjLQfXhah8aVfeYnHq2+
         aKAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5NViWaH5kMrZ2Ami2PgFRSFudaar7o6GA4ROx9xr+/8=;
        b=gN/6w5zfkZRUW3RcoFSA9O3I+Lt0xJ640gmLc4nUYS+shbyKq5W5okhwoyjPNeDCLj
         PDkBy0xgHhs3jGDgDl8mt6xeyILcYZ7CEGDSwoecmlRkZmBogNEciAfp0iEqDb8bLKWL
         IsaUmxAHI88ZXMXbUyhIPAsl/9bV6WOWAe5i/v81A6dafoF0j+ijhd+V/EGJ/KADXXwE
         WINrhqDliU+hSfScw8Xji1HByPLMfe7MCeblfZl43tprtGlW7urMGfUk5TzVUpscHOkj
         5E+X4GDijkQzyBgMN419XaAn/54d+YYWQ7DZy1xqczdeQPrZQY0tQ3tGHkoSQWX7copW
         NqzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fR+1en1e;
       spf=pass (google.com: domain of 3puicxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c4a as permitted sender) smtp.mailfrom=3pUICXQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5NViWaH5kMrZ2Ami2PgFRSFudaar7o6GA4ROx9xr+/8=;
        b=ZkiMzxpJmLR9MX5Jsn5XDadpxl6t8Ahsgidv1qP/GNloQBabtMNqDYjizbB/tYTnEK
         aVkywoTMgzUbTjilenAsd8S/05s64S8K6zX9AtkyJRuF+bfRsMsmCysOxRiu9JvUP1jv
         PugC7fcWQB/k6L13vLmGzjVDPPAMA2DN4sqf+XCDme9WA+xvG7d46gO/aoUcCL8c1Znt
         6MHW5B3VYdohSzKmXVE5gOPmou8l34oh4kFI6j17RiEv615e3jRqRuQzCM9dqzYfY8YD
         Fhjd5eiM73sbFoUfmc2KWMRqGqcrNPUT3bfZzxcY58rre5c9J7thyx0hdHu91ew2/XDQ
         OA3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5NViWaH5kMrZ2Ami2PgFRSFudaar7o6GA4ROx9xr+/8=;
        b=H7/tRzaUKU/zvrigVyF1JjqjXgyVG3KBJ1oNLACqFh3mlPzr8iu7v72prucP/bWjBX
         MtCflGXgPq+n++b86W5zixW0k7HW5X8Ui3b1U4noHjHQD598EIv63RhELFUAjg1LYwu5
         3XF1KcvFakIp2Cw2z70ypSp4fxRojjU7R6APDMzc2NNhx8xOdMF3g6fdoiwAwCCTk7aN
         LM4gGSw4bhyZFaIngZ7hBq0us0QoJm9+iI/W7GZ68JxsvOFgN0lxUkG8raURnVRAbzVV
         OG/KiEdRQ7RJ47Vf1FD4Y8XTwfljmLrP9/sHITU8ctl96yx2qBt13xErMfUVcVRAYn7b
         sLHQ==
X-Gm-Message-State: APjAAAVZ6eqUtVdvG/ROuxz0ztvEk+KqPP4u03i0hv9NVTCm68sO2ih7
	kUinnHcYznW8Ip6/D37V4uQ=
X-Google-Smtp-Source: APXvYqzhr6BRV7gF/BNpdH5PBBqs0oTJCIOfnaMQahbG9WfVyamx8xCxSki1oNqg4PrX2wvxGKO1wQ==
X-Received: by 2002:ac8:2734:: with SMTP id g49mr47723021qtg.228.1560429222606;
        Thu, 13 Jun 2019 05:33:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6d45:: with SMTP id i66ls1244028qkc.7.gmail; Thu, 13 Jun
 2019 05:33:42 -0700 (PDT)
X-Received: by 2002:a37:aa8e:: with SMTP id t136mr4168753qke.222.1560429222295;
        Thu, 13 Jun 2019 05:33:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560429222; cv=none;
        d=google.com; s=arc-20160816;
        b=APbZNkL271UsJ1E0v2H8mKbQIDxXXoUnAmTJ1vM/AVbqD6AGJc4xWoTi7oxGqMyDoM
         qIdTwlPbJyOOUBy1kZnbiTVU8RPJbCWI6oLUwa4uvu5vZ6fcHbni6vdEHft5aUS2w5dR
         AEQREO9ftIQVe0+28uHkVKCxmgbc3eBPgu1o5kEwgIsS3gdsnDWBv0nEDqBmsSOIcAML
         5RoqONi/30SytqIZ0+5TgxWPQGJeQAo00DkpZUDf/S1c2On9Tyd6+LqTJl+V1wiHPCcg
         qFi7ZesY4bKWeOygX34M73pRKJisSF1W1WmOR2d5NIga9rJ2GYOt88rf0XH7jNi6J1mh
         PFPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=//K/wTWvNMc+RMO2RQcyAERyaT1WE90cBRxP/iyLlLo=;
        b=tkEqSR2RYSE4qqTCyrVCI8QdJ7Q2eMXM/uJC7s6HnIT4K17vdW4R6XFPVgoc3vuPpm
         trMkUHYiovQ0Ikf52tHX/E3v+WlfqadJeqFzLiWqSuBWsT6BwnzKqww2ZoSdNvO3KFUJ
         QdiZ3REsSkdB4hbvM2eUjesjlV8KZSkeUSXhm4gPlKw/2/8D3u3mvVojywPHfUek0RLF
         tLyczEVZnQd4xIxEDJnLi4RIeKRDPxy/cy5VNvgWRExtnDYJvI8VxcR4vM3b5XoNsS4l
         sabz1L/d6a1giBsXhOh4eqZTE2sjvunCFfvQZAYWpjhTiICsJFlA3srFsBTlKk47kgKw
         Nfow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fR+1en1e;
       spf=pass (google.com: domain of 3puicxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c4a as permitted sender) smtp.mailfrom=3pUICXQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-xc4a.google.com (mail-yw1-xc4a.google.com. [2607:f8b0:4864:20::c4a])
        by gmr-mx.google.com with ESMTPS id t74si125268qka.4.2019.06.13.05.33.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 05:33:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3puicxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c4a as permitted sender) client-ip=2607:f8b0:4864:20::c4a;
Received: by mail-yw1-xc4a.google.com with SMTP id k142so20676510ywa.9
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 05:33:42 -0700 (PDT)
X-Received: by 2002:a25:d708:: with SMTP id o8mr4839586ybg.410.1560429221914;
 Thu, 13 Jun 2019 05:33:41 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:30:26 +0200
In-Reply-To: <20190613123028.179447-1-elver@google.com>
Message-Id: <20190613123028.179447-2-elver@google.com>
Mime-Version: 1.0
References: <20190613123028.179447-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v4 1/3] lib/test_kasan: Add bitops tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fR+1en1e;       spf=pass
 (google.com: domain of 3puicxqukcsicjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::c4a as permitted sender) smtp.mailfrom=3pUICXQUKCSICJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
Acked-by: Mark Rutland <mark.rutland@arm.com>
---
Changes in v4:
* Remove "within-bounds" tests.
* Allocate sizeof(*bite) + 1, to not actually corrupt other memory in
  case instrumentation isn't working.
* Clarify that accesses operate on whole longs, which causes OOB
  regardless of the bit accessed beyond the first long in the test.

Changes in v3:
* Use kzalloc instead of kmalloc.
* Use sizeof(*bits).

Changes in v2:
* Use BITS_PER_LONG.
* Use heap allocated memory for test, as newer compilers (correctly)
  warn on OOB stack access.
---
 lib/test_kasan.c | 82 ++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 79 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7de2702621dc..e76a4711d456 100644
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
@@ -623,6 +624,80 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kasan_bitops(void)
+{
+	/*
+	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
+	 * this way we do not actually corrupt other memory, in case
+	 * instrumentation is not working as intended.
+	 */
+	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
+	if (!bits)
+		return;
+
+	/*
+	 * Below calls try to access bit within allocated memory; however, the
+	 * below accesses are still out-of-bounds, since bitops are defined to
+	 * operate on the whole long the bit is in.
+	 */
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
+	/*
+	 * Below calls try to access bit beyond allocated memory.
+	 */
+	pr_info("out-of-bounds in test_and_set_bit\n");
+	test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in __test_and_set_bit\n");
+	__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in test_and_set_bit_lock\n");
+	test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in test_and_clear_bit\n");
+	test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in __test_and_clear_bit\n");
+	__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in test_and_change_bit\n");
+	test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in __test_and_change_bit\n");
+	__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+	pr_info("out-of-bounds in test_bit\n");
+	(void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+
+#if defined(clear_bit_unlock_is_negative_byte)
+	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
+	clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
+#endif
+	kfree(bits);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -664,6 +739,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kasan_bitops();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.22.0.rc2.383.gf4fbbf30c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613123028.179447-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
