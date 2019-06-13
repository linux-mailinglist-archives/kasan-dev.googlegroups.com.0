Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWMRRHUAKGQEA6YOOLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E6F343623
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 15:00:11 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id u10sf11896126plq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 06:00:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560430810; cv=pass;
        d=google.com; s=arc-20160816;
        b=drOM8cnETVar2t/AXStEH9rpRwvVvDmP00VsG3geCv/kQMIKUMTDIcUpxHIVQnWm47
         3F1WC0jWOZuPBIseaQVgAy7+3k6D2uNi8bSS4IOooB+D0ftlocnU+VpI0rKjsJ/Jx0qp
         43fxjAVdw3lBzVmVHjiImYjkxkduyTGW+sYhY8MeBrZOKUSalJoHV72jAWRDHDTMSpU8
         pye1zUZY2vhyRAo/kxsH2Mci4MwVoqdtyiP8T6TgrThoWe9IcXzoectTkxWWkC05Ar9P
         J0wwQK9sMeXMVfTKSnmcjvxhaPKubSaIbURLvAVBDyJPS1B2iuqIO0OVBOej2r80k7s8
         zLpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5wZNZR+rGM6oKRvM1FiDcGZI3dSXxpz1iY95N4fI6So=;
        b=xcnGIi9Ntirlz2v4VYd6TN1eQu89qDQc7rl24VX8A66t8WNfPBQsGGKA/C5Kxf1bBG
         zGxrRM0npR2/yJvncJtHM1brNxUZFRAKc7Goyr8SaraZq8HOfjEZiyZJMUcpDeMhNOi+
         W0KIILMuB+F5VmjKCuoBnhAiPvuiEtgF+tw4KYXAOdlZ4WHl2PlzevvF71Zqp4O7S5ry
         j2BMe1vod1q+pPggrc3ShySyivxLaPWzf9+5N+uyKEBhYPYYyKz4tAzlzlJMm9HvpX26
         QfMwoPNkAfmLWjidLpRVvAC7JfCIe5rpu1qxRrCgk++IMgwb1Rpp68IXHBOU9KAiWfPX
         3VJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ts1iVh+M;
       spf=pass (google.com: domain of 32egcxqukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=32EgCXQUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5wZNZR+rGM6oKRvM1FiDcGZI3dSXxpz1iY95N4fI6So=;
        b=lhx/zbyoNT9IHt8GU1oGrKbMRzSvto0wj5+M0ZsY37hCxLzOV1isTaMgA1lt9gSlVR
         VwuluAYocJSstr5XNS1AjWyV2LvIyd7gKtxAGKeqPt/5poSuLnuFXeBcJ6cOhoYYTObR
         YELPwbv4UwiSs5J5M9r1f1beARy8uoUSGwhZos+ygsxYG4uq5sKuh/T/9Jn1wSGGanSS
         fuAc8hqxm+JWfA1J2ZEeRi3ugj1dpFwKo1AQqAJ2IHYb0vUgiyGN3wFSpMdcEZLFbc7F
         SohJCL9j+qrRHz0ONEmwp84DZSWfqWaglguYEM8xU61Ajzy5XSz7aXehi6TaClzFjr0k
         GgTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5wZNZR+rGM6oKRvM1FiDcGZI3dSXxpz1iY95N4fI6So=;
        b=Mf3x8QtT0hm+QeIKXEIiEqKTV3FKXfw70Mglwu2GV8qLIyMhmbSAPZyFEMU5vr+2IH
         cd4mzHAbxImMpd8taRfBsDYTUDzdzNsSc31nYlByGda/JWQbgXhfFglJY79j/4RlyLs/
         U4BhXAJyDFeE1sF1ApM/fnLIRoVaNYabOjv76cOmQrtjO0vw4Xnzp7xarxNJFigDrcIT
         5wGSjBjOjnqFVrlDaVU5h5McIz6SfJtVkpvR6TiKKCJbMfhDGShxF815xg4WE1WsZorM
         OhFTnd2E72mWRlBR3b+TgZFbFC9/fszr9m2lb3pE3VOpfamcDOJOswUuNvcF95BCvI4n
         wSmw==
X-Gm-Message-State: APjAAAXggYeOfRqbDe9srGlbXkMAyKQhdcfVouLNhHggo0xYJDhMdCXp
	ZOn7QUsCCEBUnTOsJImz/vE=
X-Google-Smtp-Source: APXvYqzPw+eKxaVzzqVWJQc4UbFiO2JpXxDSI3HlUKlupJsKcSKowl4bC5pXU1z+uuUscDsOYl66Jw==
X-Received: by 2002:a63:295:: with SMTP id 143mr29599407pgc.279.1560430810046;
        Thu, 13 Jun 2019 06:00:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:1e8:: with SMTP id b95ls1418961plb.10.gmail; Thu, 13
 Jun 2019 06:00:09 -0700 (PDT)
X-Received: by 2002:a17:90a:a505:: with SMTP id a5mr5580469pjq.27.1560430809682;
        Thu, 13 Jun 2019 06:00:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560430809; cv=none;
        d=google.com; s=arc-20160816;
        b=f8KGmsHd6Py6JpMy3amno0yYlyE4rrM5XR9/pX0pDxP/CwZrMvBvmJy6HhFt5oYtKN
         JM6bN4/F9Xxbi+FitdYIhLEiw0gXWN8NR+gXpRkHHJ4IBs9NlFTLq/40XjZFoq8RzMof
         HWq/TfwwUobX8QIndUZCt0giEX5Wn56rWVmGph1Vu2djj9q5SuUFdx0U06M8Tgw0pHP9
         8ygPBaVoFVLEkZ/ArGbulN7+hllaU8WWTcePgb7qVQk7jk31dPvS/zGCzp7JLQuYJpJt
         R4xyIYZ1fjT31XI8iwZQ2svSn+16oiEMat+WK39n197lrKSkd0AI8hifyUrIpe2wQUgD
         GvOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Ybi8SfjCPz2J5Q8w+1yX5IhzPr2ih+s0DDGtyk1eE0Q=;
        b=aFn8ncO+FtozzY9zkbG/BE1oXP5xylpZdLlRqUvNe7kjk8aSy5/tY4+WCo5s0uroHs
         VyjDyQ/ThJuC68x7TawF+s3ubvM0TjirbEgcxKEPAxvtTb8my9DBMT3xSDvyqJu4pxIx
         USNrHB4hTq4K16cFuTOCfo4fdpntSfmL9f1HV+hCsWQV54GWYIeOTzRglZZcWwSJF8DQ
         hn66qhr6Xrr3ZlgwKychu2VXVy9CKMmoZi8WPlPM+zvD/9AHooX4r1l0UxOUErJwNP0u
         wcjbiFNg87W1gtAtshC2sKjcY7+JvSo9Fjixvw43YHW0YrwaaqaXRs/BVH9gp5ELDuen
         uAOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ts1iVh+M;
       spf=pass (google.com: domain of 32egcxqukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=32EgCXQUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id g18si85434plo.3.2019.06.13.06.00.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 06:00:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32egcxqukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id o4so16475798qko.8
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 06:00:09 -0700 (PDT)
X-Received: by 2002:a37:47d1:: with SMTP id u200mr37053086qka.21.1560430808803;
 Thu, 13 Jun 2019 06:00:08 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:59:48 +0200
In-Reply-To: <20190613125950.197667-1-elver@google.com>
Message-Id: <20190613125950.197667-2-elver@google.com>
Mime-Version: 1.0
References: <20190613125950.197667-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v5 1/3] lib/test_kasan: Add bitops tests
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
 header.i=@google.com header.s=20161025 header.b=ts1iVh+M;       spf=pass
 (google.com: domain of 32egcxqukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=32EgCXQUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---
Changes in v5:
* Remove incorrect comment.

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
 lib/test_kasan.c | 81 ++++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 78 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7de2702621dc..267f31a61870 100644
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
@@ -623,6 +624,79 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kasan_bitops(void)
+{
+	/*
+	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
+	 * this way we do not actually corrupt other memory.
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
@@ -664,6 +738,7 @@ static int __init kmalloc_tests_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613125950.197667-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
