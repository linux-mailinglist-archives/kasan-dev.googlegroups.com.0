Return-Path: <kasan-dev+bncBAABBRWG2CEAMGQETMKZV2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A7B3E3E989C
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:21:42 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id a9-20020a0560000509b029015485b95d0csf1087883wrf.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709702; cv=pass;
        d=google.com; s=arc-20160816;
        b=XyeaAnTDrH3bwew9JP7UGZhjRnJzQMpJt7EaENBhmB8DPvFzv5TwNNTQvAIGisFIka
         6l+DktAgWQlREHBt8xCHfutmwxvhQEVwgsw8wo+FWUx0A6F/f5+ucIX9wrlhSpzLTXZ+
         RnqvYBG8e7Qtm25wEeDs7pye1Qb3rhVsYp7bfrbAad6rXYqeK2jTKLuw9qgJHXndqIjF
         slnQO9ooCOgXNN40WXYq2wprJVrdWCxsURxSajao+7SsFTzjV50K4tGmhACw5pSTPnMc
         uRk/E6E7AliokWdImeLLPkDqqk8x73okEmFocJpwUSXVFR3K49QDjyxmdpUWKE4nIfxH
         3BGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ueGvQQd2l9Mw3lyjxYjRBlB+7UjesnPOmnHGQUya52M=;
        b=xqVw7NPME1U3thwVei7k1zP6bzQd6hQ+BNHsMbvPts23w1Wj7P+umvGF0iAnauOmOi
         qwpGYy/du/vudk6j6gvLwnMYdi6Ybc1FCryZDm9fl4aIRgIJVH9VVB1RjGwIxEBON+Ys
         dTEHZ4npPrsaQXaXAo3s2wvHHwplFWeVy7H4Wxr1SIqXhWoQyVnOP0HKV92x91ediKil
         0qCx+OdSj2bKORQtWD56tnmJ1x03N6vorWxEAbYe95v3cRAG+5/8XbwRqNTmOxvR6pVU
         4oeNAWTUugVG4PDcia9bac9G+5Rudl5W54pNapgzHuMvON+S8G3RgIxo7pEn2Ncf6IyA
         MoHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hOF2jU13;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueGvQQd2l9Mw3lyjxYjRBlB+7UjesnPOmnHGQUya52M=;
        b=JG6S17sYv08bU4inogyrbwH1Nm4OlYiA/2Is+oQy/RCEY4roKIL5epelacuYBDQ5ci
         I3C4OW65LwT8VZI5dqcQ8Dcf5WKFaF+Wes3+7XJe1iSr0b0uMXIG437mw0/h7pL9Xcx2
         3KYO1w+14r3Gwm84vSFIYiNhXlZH43qW3d/k3VpB48eqzT4Eas1NH332TMdrEThSRLjc
         LplRjyiTpZ2mTn7n+sBZML/HBy0H8bNhI0ONgxsWzFB1gb29vN96+vIQbkjKJZVzMGww
         t+L+IFUXnW/nlvkM25616WeVAp68XQBLrE85q0bS5gaw5gWYC531fG80AZf6DU19DI3M
         Wksw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueGvQQd2l9Mw3lyjxYjRBlB+7UjesnPOmnHGQUya52M=;
        b=KDVEhOUyu35lWncVAyR9xSx33ExpI1O2ey53frukNJhobLtsUFnjCCL7EmpQgstCsH
         ATDhAt0AKzrh78/Byupw3S6tN/7gY/57SccqDzOkCtSbbYmBkPXdkOVV11omDjTMjPMl
         rflj9BpxCxLQLT8F6HIv/6d+YEIVmcTTBJ3xNJt8tzkPzhRNHypYvYlRiylMCLofWIs6
         fzcqwpJOjFnXvGswZV17ff0DeaegsE2juBhBzmMrjiQ6YFXdzJ28jbk3UWA6tssM4HLf
         ubgE3a5u/meODAd+npOLVpvEd07JWU4sGwAstUUfCbbfgL5Iyw+oahdsFBsNEFZrEJ8G
         D2KA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RQD3N7UOHo33c4/VVkCwIq33ODJWX8HSNYz/FpgpqQt6W9vlU
	U4MWV6YXelXGDmAs84uga4g=
X-Google-Smtp-Source: ABdhPJx1xHOYkzFe/hhTVuc9fP2vDO2/0PxwyTypsDo5CQYVgz8TvyjNRhXNbSMnWev1j/jW18XsSA==
X-Received: by 2002:a7b:c5d8:: with SMTP id n24mr104748wmk.51.1628709702480;
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:db90:: with SMTP id u16ls2019846wri.2.gmail; Wed, 11 Aug
 2021 12:21:41 -0700 (PDT)
X-Received: by 2002:adf:d1e4:: with SMTP id g4mr3849wrd.371.1628709701694;
        Wed, 11 Aug 2021 12:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709701; cv=none;
        d=google.com; s=arc-20160816;
        b=W9Pv53fVXtexmry6gHDKN/LJN8aleMpzBBy5Hgqh0eS0DrkASJ+BgbgFMXJpVz/Ubp
         5rY+gCUu2/8SG+QaF6oFIqVRNTjXODie/Oiwyd0DNgNPUAxfRboTDlKr2pF/SQT2rwl2
         KfdwGF3tN69ECnuT73W3Ix8kADgYedqa6lk1x8eCJ8f02pHHji0jXCThzlm2Xt/qsEbZ
         4mpkfqnaFnNIt0tQA4w1MkYjpS3bOpt7nLjFRM5y0goC5uDQuMEOe1sma4L/fnIBWezK
         UUX/N8D5Xy68sG2hH2OzS5UVrfxshonr/T7nUzl/tXJmRFCVnPvgkYpcz2dAZYc7PNxk
         DFFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hJvl0j61Zq+oSt6HYk9qiIcFyGt4nhGk7HpIREtRZqk=;
        b=T+ivbP1Nqt+BlDfW04xRQSWyNuOPYuPXhXhGerW8AKpn7RTJjquBC/a/4x+uadX2ha
         p275JP1PoPJJDHjmiaPmJ5G+rwiWDMBxkKSj3kx3M2idCyYvwxuBsLANdydgpogsJmOH
         a8THOESabaaeNGRbMKwt0dzbRbiBmTBjg6zmLfycJF7LSiZyMv0sa49XHn+mI7e2FWIB
         AXG+Pc2F3Yjd2tP7PuPwt7NH2/b+PHZne/fcDoVu2D7MfqMzE4QXrF3oUDqnqdvo28qy
         6jOz+k3li29jG8HuDrgsOKMDliyy8eyNOPOarBk3Eifo2Oa6gpAQgQQsHdZgl4NmR6KQ
         qDuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hOF2jU13;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id w3si478550wmk.1.2021.08.11.12.21.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/8] kasan: test: rework kmalloc_oob_right
Date: Wed, 11 Aug 2021 21:21:17 +0200
Message-Id: <474aa8b7b538c6737a4c6d0090350af2e1776bef.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hOF2jU13;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Rework kmalloc_oob_right() to do these bad access checks:

1. An unaligned access one byte past the requested kmalloc size
   (can only be detected by KASAN_GENERIC).
2. An aligned access into the first out-of-bounds granule that falls
   within the aligned kmalloc object.
3. Out-of-bounds access past the aligned kmalloc object.

Test #3 deliberately uses a read access to avoid corrupting memory.
Otherwise, this test might lead to crashes with the HW_TAGS mode, as it
neither uses quarantine nor redzones.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 20 ++++++++++++++++++--
 1 file changed, 18 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8f7b0b2f6e11..1bc3cdd2957f 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -122,12 +122,28 @@ static void kasan_test_exit(struct kunit *test)
 static void kmalloc_oob_right(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 123;
+	size_t size = 128 - KASAN_GRANULE_SIZE - 5;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 'x');
+	/*
+	 * An unaligned access past the requested kmalloc size.
+	 * Only generic KASAN can precisely detect these.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
+
+	/*
+	 * An aligned access into the first out-of-bounds granule that falls
+	 * within the aligned kmalloc object.
+	 */
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
+
+	/* Out-of-bounds access past the aligned kmalloc object. */
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
+					ptr[size + KASAN_GRANULE_SIZE + 5]);
+
 	kfree(ptr);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/474aa8b7b538c6737a4c6d0090350af2e1776bef.1628709663.git.andreyknvl%40gmail.com.
