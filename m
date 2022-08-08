Return-Path: <kasan-dev+bncBC5JXFXXVEGRB5WQYGLQMGQERWOS65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E1AE58BF0E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:35:52 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id x7-20020a056e021ca700b002ded2e6331asf5782594ill.20
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:35:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922551; cv=pass;
        d=google.com; s=arc-20160816;
        b=yB1Ygc2InzO84NFAyQQafpbpDzXDzQkhmGTDymEE3xARbHB8E8QLkAkCzN6TEy9E2I
         /ps4onjQ5HEwBt1bPSOXHtCHItDyX7AEui/PlK3oBRzipL+MZ8X+y3lDi4OzlNSDmm6z
         Wmg79UoeE4rOOts29YDYpWGCiG0UGHTYi08yidHS6Z1lvgxbX8dyErDj5tENoSZ3pzLW
         DGMv81JxHZ62zsfI5PnI42aHPscGfFcV6aVe7KmnHjNxNIYPTV70AaERbdY1vZYn9n3F
         2zZfRfOzhOPDoeGUwDrvww56ntxTlGvqDEsHoMEYnZ/4GDAD7MJAx4MZdxmBg1SN9UiX
         iF2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W9ef0J7A+IMs2hiUrEdXYlRDvLMZjXIeLr8KZtEue9Y=;
        b=ebrIhgUJiCFv0DfbNRZZuWNa1Nu9oMJM5UwOBpJj9yW+VKY2Y3/3lKXy8nsY++tKMm
         QNS1X4uQLUaBLT4r6YZ5Hn5ahJalpU9o5tXnJiPdz6znIYRkGmN1+iTUcSnNzcr74vxJ
         nQBvDDEEnrDA+PMpZHNnRxrFGW/SrefCTVs/sH9ArY+h3hdwwYxsG8CwZ6Kec5C92WWS
         yVjXaUCtS4mI+ltETd5Hn6alKkKKp13YLvu0Sx/OGGC6YphRqfhFFWIXW7tHe/fz7zQp
         Q1SZ739o6YGSrckio4MfeHiauwGf1zftKyg4e79qY12O7eQh7joL8/ekb5FtH0cUw51D
         k5aQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tkjc3dpe;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=W9ef0J7A+IMs2hiUrEdXYlRDvLMZjXIeLr8KZtEue9Y=;
        b=KUe39s2UDGBzVKKc9nNIaHmeIVn/xrJSqh3ABeazo8i/sQ34+7ZJY+0S+mRbrVoa6s
         QiZuovluVybyP2hFOnCDkfE4QqbVI1PcmWllHhpH7UxvHxle4aCXQAr+WCBmdWSdn96L
         9yuLr2Lfnbl5fCSSsc0ijSQqgSZ/jq1w9TdGgsB9tc2KVh6O8cg9oIH+kc2K/c8ReBkp
         iZFwTn0wchIjXSuCZrIrf8Jt7rFWYrpT8MD6zIaGmQKHnvWkoTn1RbAbMKORZgKknXtq
         RbQJy6u13u1bnC6jVVABZRTFLEkZhqtLADR3Hq77Q2a/D3tWNpi6Y7btesaq3vpKL2H4
         BVlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=W9ef0J7A+IMs2hiUrEdXYlRDvLMZjXIeLr8KZtEue9Y=;
        b=CXKnNgfkiyFJ/Ox2O+GPzwwOtPQVxhVNHQAjWa/tYHFFHE+zJeAVMdlgE+qiYXwwIt
         wXWv6S/mty+CtdhhKlSrv+sR44LpPKPMGROt709BWQaTRInT989gkz/Ra2IrjIv/nWPp
         7sXdz6pTHpmKVXsE0gxPUZKcqzyqdDyrOcpYKOph02ag5Wim78D7R7TmrmWgIYk9FLiZ
         ZaKIyoV86sZpcpFQjVLZk6eu9AVXiXAQzAt5TAAUEATtGYV6pHZGUWsB9LShK4EAxvtf
         lAI+J9QIQ0065PfMsEsQGX622gZGgj1EGAUzilCfvGyJMRnwaOtOpRF17Sz/SzcET2zt
         dhhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1KAi8NxH/GY8k7C+tp/0sYJNKLoi8c9MOq5YOCT1yO+1pfEF0H
	GgitZp42/5CXlW0m8hWk+f0=
X-Google-Smtp-Source: AA6agR4e+5ePclLS6lfO38E5szKSFFkwBfIra1YfNp2sTPLxSRhdExmocqDVeZhmPfSinK/3l5ANlA==
X-Received: by 2002:a05:6638:dd1:b0:341:55c2:38b6 with SMTP id m17-20020a0566380dd100b0034155c238b6mr7479161jaj.245.1659922550834;
        Sun, 07 Aug 2022 18:35:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b70b:0:b0:66d:2e7:51f with SMTP id h11-20020a6bb70b000000b0066d02e7051fls1049117iof.6.-pod-prod-gmail;
 Sun, 07 Aug 2022 18:35:50 -0700 (PDT)
X-Received: by 2002:a05:6602:1605:b0:67c:18e0:d311 with SMTP id x5-20020a056602160500b0067c18e0d311mr6089327iow.93.1659922550243;
        Sun, 07 Aug 2022 18:35:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922550; cv=none;
        d=google.com; s=arc-20160816;
        b=oWNPdDijo6m/NYgabq3uN9LNgkpifktA3dVFIR1RqQjNj3F19lbX3nR3L4Go9FiG9q
         Y7ar7AEqgJ5AeGhQHMI7WrAreze1yteO3tPa5/vfqiMRCwEuzQTzybVbBZnB8Q6wtZmO
         brWfgU1c2yB1HeN5j0yoarzztDsI4+aNDrRHhtH5wVdaYdyzn+PbSYD2S8o5uGV8mUBi
         8iyactDk/00jovozCu7Wu9UPmTP0VQSaNATQ5A6rVE2VW0eQcNwtj3lMbcJvjzLZZ/e5
         TMKSWYodDcLXpbMzNQ0Tns1tKUejtIUT3tYuEfwG+5v/aRFj8qStF0diy1Q9gCM2ctHd
         y4Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NbVc0Vo1sLqcgfTOm2iqMSV26EFs3rA276g9CXnCZk0=;
        b=A4gX2EiqA/kT99EPRDMB++qmTwFWZoMC6Zhkxh43F8W0MsVRtop35eLvok+OB+i3wP
         G4thVAYr+0DCMonlU8zNY+b4zHFqEo9iFyoJwC5wJLGyLeFG+U+d1t8m/l8vtWtmbcAk
         pGO94CshrljVCcAFUX0LfmgfkLvKQvNmahnNyG0fhYpGexUgF0LkPN0y0tZw5TN36CXR
         jJv87SvEdix82QsQl3wEnoqx0X/j3Mux2c+84kr9Sg1xKoSW2QiVMG06scZREF+mQQH2
         OuRvOvMf13hABDI2a4YSPyaJidu5jG9kMoe+QdZaK1yDTbgRYyLzpzG47IhM4xFTd2yn
         7Cjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Tkjc3dpe;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h4-20020a02c4c4000000b00342bd548fb5si271378jaj.0.2022.08.07.18.35.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:35:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DEA5D60C94;
	Mon,  8 Aug 2022 01:35:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4262CC4347C;
	Mon,  8 Aug 2022 01:35:48 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH AUTOSEL 5.18 53/53] kasan: test: Silence GCC 12 warnings
Date: Sun,  7 Aug 2022 21:33:48 -0400
Message-Id: <20220808013350.314757-53-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013350.314757-1-sashal@kernel.org>
References: <20220808013350.314757-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Tkjc3dpe;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Kees Cook <keescook@chromium.org>

[ Upstream commit aaf50b1969d7933a51ea421b11432a7fb90974e3 ]

GCC 12 continues to get smarter about array accesses. The KASAN tests
are expecting to explicitly test out-of-bounds conditions at run-time,
so hide the variable from GCC, to avoid warnings like:

../lib/test_kasan.c: In function 'ksize_uaf':
../lib/test_kasan.c:790:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
  790 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
      |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
../lib/test_kasan.c:97:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
   97 |         expression; \
      |         ^~~~~~~~~~

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
Link: https://lore.kernel.org/r/20220608214024.1068451-1-keescook@chromium.org
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ad880231dfa8..630e0c31d7c2 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -131,6 +131,7 @@ static void kmalloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	/*
 	 * An unaligned access past the requested kmalloc size.
 	 * Only generic KASAN can precisely detect these.
@@ -159,6 +160,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
@@ -171,6 +173,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
@@ -191,6 +194,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -271,6 +275,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -410,6 +415,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr1);
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
@@ -756,6 +763,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
+
 	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
 
@@ -778,6 +787,7 @@ static void ksize_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013350.314757-53-sashal%40kernel.org.
