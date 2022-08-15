Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBBE55KLQMGQEKXSUJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 29F14593492
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 20:20:54 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d29-20020ac8615d000000b0033d168124e9sf6749820qtm.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 11:20:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660587653; cv=pass;
        d=google.com; s=arc-20160816;
        b=FfGIeVs86+gb4eKoVM3XxgQrBOxj5LhqDMMuJv2Dvbrtcgi+mxXyNMjEX6oM5A9Mmm
         NmXcqrkKrjigOIqM6rADSJdhorFFv6195gm8F4Kc4yzmbbWI5/9DU8/wT7WGcwQHKHli
         kdYi6koSXLQNhzoEh/TrnirYR6j/d2XDeCMz+yt85V+ub0uooJYw37VkamI+grNPKePd
         h/W5/YGSAe4auQIkwv+floWvxfQksELpBt4pCWTuNDu7KC5/bwBta5crfg0DmHN9bSJl
         6HFZuzlCu9DgWzUM5oXHAw08DDy01TrP6s1l+P3/HaS8og7OixN7ODelI3VR4gAE/xkx
         G7QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=nzSpCWPZEyP0aucx9hIIu/5BTzEmxpySsteGRqpJLVs=;
        b=QX0PfX47OxX1WyLnyOaBQE+Hfpq+OAwVKcRT64QkBOwgfSo32bUsMzQPhXucgSaxTY
         WIMxmT5ItGURFuOX1f0Uzq8nzYhxADm1OJ7NCm91HYsnqyGng9S5/AHn71PHHDT1PQZv
         XPOY1VtUTHOomRGZX8v9YyM1jfqxGaymwb0kps3XXCfwnbn5+JcApUuEkBTEOmqtSl6h
         qhOqhHqWJdma9Aj6M5TQtOuylo6JbsO7ZHVxXdJVjSTxZAILrVjLE+Vv23wu/gVhWk5g
         uBn6QUtH4wqwlKT0w7A5vMf2cxlnU+OapOZi/frofe/Tk/z98HX1odknFHp82x5gj6Nv
         nbig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=IlMnuSat;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc;
        bh=nzSpCWPZEyP0aucx9hIIu/5BTzEmxpySsteGRqpJLVs=;
        b=Piz8+yt9/I1zg7gPM6SaI5XV+LYnND0c3YM6Ewrq25UNNhxwVMx+FoFgYoZ4UMbC+t
         eGkJyXxdijuzmKlQ/GdbQiosGKE5eEs7oVA7NAYTs03r2pmPHCKdj7l6QsGCCKw9w7vK
         bURae1E/+iMS42Dtyi70KVCNKoMDdeeR9IaTxwwRoIOjwlotLWw3muHRwG17zmOiUMeK
         g1QG+MnGYi3o6uCWb+XMwr5iOqvx0s7FLS/WsjZzOqnyAndT4RREJeUnecpeoSoYQ5KL
         udNIjIi6j1tCAtT+ok1MRrDIXPn8H8gb4LurIb3lZAYBkliIsw7FLHe1kn4lS4AFp34C
         UyOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc;
        bh=nzSpCWPZEyP0aucx9hIIu/5BTzEmxpySsteGRqpJLVs=;
        b=ZSlnFe3oCjkX8LY1x+GqGySfrsGHDM5Ai2vNDaeMLeG1FtZnsaX9ZUdfCt0i0rLgBs
         htv1mMVg8OE/5GU6LR8d+GDjQxtv9yzDTcJkolxZytbf0WdCebk/qxwKNIX1iGsHLKNS
         XYxXTyDMl9yxrVIFqEhnz4FKBEn5LN2o0ouYAySjEiXz0VH5FNOh/NucOhfZygzHqrSm
         BhvxcSqcnNrH+ti0YUXLHgVU3kAyDGrEKvf/Cr7KMSnn5fXGmVR4NlzSxqYzdD52Jawg
         u3YdUS2bk+lfPe6gHFfZD+F81BiEeIWzy2BaidkM0OpWClljyIWWi1PWQFts2ho9twoc
         obCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo39/kCKxwY8JuebxY3+juIvVrHNhaSz5N/ke0h1OKOe0gDU5dAf
	TE8XY11czYIS3s/zeDOaRug=
X-Google-Smtp-Source: AA6agR6es2q1bH2ZhKGYKTdVJbBJxE4+fdVJ9cD7WKA0LYCz3RJvvi0UVuaI3RUDyTvtIG2X8oFpqg==
X-Received: by 2002:ac8:7f0f:0:b0:344:2fd8:8a66 with SMTP id f15-20020ac87f0f000000b003442fd88a66mr10099343qtk.98.1660587653024;
        Mon, 15 Aug 2022 11:20:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1592:b0:6bb:13a4:5c25 with SMTP id
 d18-20020a05620a159200b006bb13a45c25ls2677802qkk.4.-pod-prod-gmail; Mon, 15
 Aug 2022 11:20:52 -0700 (PDT)
X-Received: by 2002:a05:620a:284c:b0:6b8:6e70:cd95 with SMTP id h12-20020a05620a284c00b006b86e70cd95mr12048172qkp.247.1660587652523;
        Mon, 15 Aug 2022 11:20:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660587652; cv=none;
        d=google.com; s=arc-20160816;
        b=Q0tqcqLOtryHpXIPoDspFksbdPc8eNTTxq0qYhBrL7SQTV5f5S9c3cEzOSofsi03s5
         M7mmEKwa0X3up/FEJIWFsyjB3SmMkg0vm2D+23VyDSDNnXcN3sVs/CLFBIXPGXaS/KEd
         edlPcSoUvikFejpnNDfXOM7uLc6xVeI4UW3P3AE+dFLY5CUxNuu+owBHqXVsuM5Igjua
         mhcO6ZlGUDUNHLqAKgMqRaeWx3uGPYbBfEJJATUJIE6qlwOHtaD52VXpVh3TaWqqLpr7
         6wUjGiMqJe50vF2vzi4HGtuwGfZPKHdhjApibQhzwS4qCDhaiBHO1eEnpbpSR89nymOg
         Uprg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eOFmZIKwdWPayM/IbFRh/n2EQwtjiau2JhlUjiXFPmY=;
        b=XDRie6ToAtuVEQ+17ckDcZmljeAqbdTS1NqFFtkrd5nUv961U6PVJw8M3rYFwSITRH
         6Dx5TGjn9/ZOjk674EF2E8wpnN5z5m2m4iIve3GOf8oPsOZ9c+FDpcEl23xXbckeJgre
         SY+njOFTmolsE+J0ZGfSNNRfZl2jOBKXj3NwW1we8PsLLDO7+KQ1H8E4Jeqeaf97UitT
         AOQdbJrzlrTiV4mF4GAr0OQ3aAH5OBXaheQfcBBDZO+yD0xkjf84eOQh6gDwfnQJvUaE
         sQoY3oNm0g2rHh9fHpngIinecSKrkpSrhc/FVv4IPWXa5n3y6N6k6EPv1JjkHUjynm9x
         ijMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=IlMnuSat;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o4-20020a05620a22c400b006b95949648asi582221qki.1.2022.08.15.11.20.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Aug 2022 11:20:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2D95C6069F;
	Mon, 15 Aug 2022 18:20:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 337A0C433C1;
	Mon, 15 Aug 2022 18:20:51 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	stable@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <keescook@chromium.org>,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 5.15 150/779] kasan: test: Silence GCC 12 warnings
Date: Mon, 15 Aug 2022 19:56:34 +0200
Message-Id: <20220815180343.721810104@linuxfoundation.org>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20220815180337.130757997@linuxfoundation.org>
References: <20220815180337.130757997@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=IlMnuSat;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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
index 8835e0784578..89f444cabd4a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -125,6 +125,7 @@ static void kmalloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	/*
 	 * An unaligned access past the requested kmalloc size.
 	 * Only generic KASAN can precisely detect these.
@@ -153,6 +154,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
@@ -165,6 +167,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
@@ -185,6 +188,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -265,6 +269,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -404,6 +409,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr1);
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
@@ -712,6 +719,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
+
 	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
 
@@ -734,6 +743,7 @@ static void ksize_uaf(struct kunit *test)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220815180343.721810104%40linuxfoundation.org.
