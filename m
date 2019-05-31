Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK4IYXTQKGQEFS34ETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 64262310F0
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 17:11:41 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id x20sf826683pln.6
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 08:11:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559315500; cv=pass;
        d=google.com; s=arc-20160816;
        b=g5LwxRJauFSNaURkckNaNW5KN5xKIIp8fqn+YjkIhk61O+vjknAPSOZnDmoXxihW/V
         hi62ZkwLSY5HftWTcTPHuEPpyeb6/eVxK6lT6NbSApDKojqQs6G2xw/IDw5ObmLte9a2
         ePOt9Hxa2H9+A2OL/Ljxo4QIjwO/mqAE48EpZZPrVWoWSV8IHfsosylnKj2vrmfauxga
         3ffdBo2BfdITtp8DbXHsiX+Rlpfjm57HHvrFBQRK4lC+MDrTPHvh/1PT2uLEwZw75Hvq
         FKv0NsjUASQgINfPHtoRbPucOOtRuRPh/lsCgVtZE1Qqmg37pOULr/hKJhWaTYthCDYw
         7HAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3FNeEbA5/VfnlKtxdy5ukuFqDckfzJyf6bEif1GmNEI=;
        b=UMemWG3TLDe4yio/0Uj4hf/IbYLkMwBHxc5fls3UmpSm50A1DQhWKMyMo0G90BI4ki
         laRPiE7SXaa6/JET8tj60FgAceaM5vlClo57AgXcx44czSIxqd+qX/oaWS89cJndHIC+
         x9Ug55acFo8Pdyc807YWYJsFpkA/gXi1FX7rixagB+4UOLCpzSd6JRfXQNkI7mDN7/3g
         qrLqo+2Wmpg4hg1IB9Rv4omOms6GFJKDp8YVun6Y9noajWcjYrvR1omXLRtN9/y7OrVH
         lotx3Z/aMdAX0x1T5lfsSyIY5Wf7ur8oOgy73Rupx09yRdPMa1aOmHHEBPEYWKnOdo/q
         nUOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rjf39fVr;
       spf=pass (google.com: domain of 3kktxxaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KkTxXAUKCWUHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3FNeEbA5/VfnlKtxdy5ukuFqDckfzJyf6bEif1GmNEI=;
        b=CRps/pWNzYu/0TWPc3vpXZJYHFp92LsvChn7+ohB1na0XK+QrFyH04dcdogeZvWTVd
         1rCNpFFPVgF9nNEYQwnGvU+bmwLkOFb1ez7z5RqIxNpGnaewbPip/jqReVDsqnvBPltT
         TaSDIO9hndPeRhuyk2NsxBGZ9G6uSFkC+pVnRh0b4ZoFQN4WqRFbQbpxeNJsYlxSL5Ze
         HJWHYVdxzElSfylCGZJ2Y5wtcifJarbFbqNZOm7ePruqaSBEDmdw+USdOymxlO+kNVmV
         4fKcZJ9UsDcWgWYA3q1YHHJbNnQu5Lj1ks8lvpZGIFRD2vLZiIBwA6U9t2o2KGFyL86R
         kIAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3FNeEbA5/VfnlKtxdy5ukuFqDckfzJyf6bEif1GmNEI=;
        b=EcYbOvYHelKM7x5m4YT8f1uicaamtuiI1N+/LobLq+NDvacBBw3APh1xBDvG5pEfon
         DfHhom+Bl+2Pmi6u5na9Y/LFDqhkdvw88E6unn0KSXQQHIynVRkcMA1j5nr8lQNzGlJ/
         d43rcECG5PId9Q+cSv+sIfrzCQ3TtdysABTGQ7/Kpe+uuCh4KNDneELM54OTakvCQsf0
         uNd0eGwZL6HutdQcwBhDdX9cpwN/RGS8KmF6xMcJXoKlXT+4zbFfa9nVWtzM96Ejz/AR
         LuDlBgRlZay+hmoTf7ZGMdIE7e1vSHQhLX7X4I8JIsQumvpg0+3X6OfuYJMIv1Yj657a
         t0pA==
X-Gm-Message-State: APjAAAUMcAhc9xOvulLORSowGptegweekvaInn4kn4Y4vLeFM0E0YnuQ
	lejiS/NFZQ604xYc9EnlWic=
X-Google-Smtp-Source: APXvYqxY8FcHN83h6s2bAnvGUodQCDJn1huwt1mP45wC7RAEmit96C87+UIxizFh2LnA/iK3DegSDQ==
X-Received: by 2002:a17:902:7c15:: with SMTP id x21mr9947391pll.311.1559315499712;
        Fri, 31 May 2019 08:11:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b685:: with SMTP id c5ls2131296pls.16.gmail; Fri, 31
 May 2019 08:11:39 -0700 (PDT)
X-Received: by 2002:a17:902:8209:: with SMTP id x9mr10248280pln.327.1559315499340;
        Fri, 31 May 2019 08:11:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559315499; cv=none;
        d=google.com; s=arc-20160816;
        b=fiqR9jwpt5hyn9jQRkpMtPGrH7BGFFt21k95OIi8atLXRRxaNQV5t0CSxf3oB3b+Xi
         10VNOyWTeWhPxzGlIrg8I6FPySHuWDzHb0a3dm1CcFPWiIHMzHyAE4YDdHuUIO798+H9
         6bcfUsGi9MhBFAjFki/yG5/j8hXwoHYspt01gpNVnAOaY1CTUgnQsTwZX5enyejI/8S2
         lQ7pUA1LIry/xH6KBPWO701nAi4sLWwNg9+cHRgOHLxWg71UwFuJX3Bo16f271jOAPJh
         rcV6ee5U/X1mi2RXixGtyz+F9Ld1uTyxKSEo58OmIG1jleH/kCLi39K/mf8ZwXlr/aya
         dixA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gLta7Etz+AT0uZJXEtTw/d9Eqbqeoj2w6clUtWu9Mu8=;
        b=ZiovEDWZjDOqWBME6mQ0Xpz7fBYVZPWUQ01jzvzNGueyOTDfHYZvTOMsQiL6IuN7NA
         5sryjQH86T6zJentPiKmC+3mmKrxuKcIeMTclz+IZ/1JhcUtgiHY8rhHdNbAjIWG66xA
         YfluuooC9/A0xAZLJ22XnSX2TQrBCI7uEINoi+XZpfMy49HJpb88S3/XI0R0JEv8M16S
         kJboQEeiw9lY2pP9b1M/giVD34/HWw6g0hfI1cclJUs7OJlZOBAS5ppDbWENpJF8hU4t
         6jZKxN+RWD6K26ytPhxN75BOtUIcYMdwLTfMvSusVdHl6xFTQW8koTgo6XPOWVxpI3W4
         wYbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rjf39fVr;
       spf=pass (google.com: domain of 3kktxxaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KkTxXAUKCWUHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m100si208880pjb.2.2019.05.31.08.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2019 08:11:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kktxxaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id l184so4037050ybl.3
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2019 08:11:39 -0700 (PDT)
X-Received: by 2002:a81:980b:: with SMTP id p11mr5711332ywg.48.1559315498458;
 Fri, 31 May 2019 08:11:38 -0700 (PDT)
Date: Fri, 31 May 2019 17:08:29 +0200
In-Reply-To: <20190531150828.157832-1-elver@google.com>
Message-Id: <20190531150828.157832-2-elver@google.com>
Mime-Version: 1.0
References: <20190531150828.157832-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v3 1/3] lib/test_kasan: Add bitops tests
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
 header.i=@google.com header.s=20161025 header.b=Rjf39fVr;       spf=pass
 (google.com: domain of 3kktxxaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KkTxXAUKCWUHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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
Changes in v3:
* Use kzalloc instead of kmalloc.
* Use sizeof(*bits).

Changes in v2:
* Use BITS_PER_LONG.
* Use heap allocated memory for test, as newer compilers (correctly)
  warn on OOB stack access.
---
 lib/test_kasan.c | 75 ++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 72 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7de2702621dc..1ef9702327d2 100644
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
+	long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190531150828.157832-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
