Return-Path: <kasan-dev+bncBC5JXFXXVEGRBE6PYGLQMGQEARLO7MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DA7EE58BEBF
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:32:04 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id u14-20020a2e844e000000b0025fbbfc610dsf452644ljh.6
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922324; cv=pass;
        d=google.com; s=arc-20160816;
        b=AOp4jfehD9Y1O9398USX4iPMz5TDWD1Tu+/0DDfhJcEKQjbntlvOY+GzNuXUOmv+4B
         fR96TKVKUzR2OpTiBFw5OM8XaN0dWFIdKN9+CkDRHdi+FLsAahvZx2TWvbKBXk5jEm/O
         rJwaFA5HWcUVJ69PFv4ZbUuC/DMV/Ph5cOHkxkvpVFSTLWm6ANRox1SC/BstBF4V+JTV
         k1fbkfhUed9XaOgZsEUyOOHcg5zZjfH+MR+OhKRNdrlkvmuCSsBBTNnK225nh6Oo7QI5
         PY6DBUhwSgghT7HtabNjvRVjUZ1mATmy6faGIaHctpSVAolA1PX8oga9ORPT3knshJvZ
         fsew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ixCDnGhCRwLvgO4QTpDezfwOMen9ape65UuSFRV57K8=;
        b=JYWGz2En0y9t9L4c5woPMLuSAm3RBvE9oprzd1KPH1sxOzDXgGaxod9dxXo+H5198f
         cD8dVzUq+osHAQvWq2QE6jJg7TzJtzRP9ScmS6LiBET6AfWrApgTG/s9jXaSS8BCrK5x
         ye+kR5OkZA8cNj+gi8DbiGBd/yl67qMf6w80kZPY/FVwN4gySIpNT7pIBIqL4rEsBvyj
         4j8m6CB9BsmjfrxCl3/HaOdKz7ECzS/6lLAJpUGDtjim0Mua3iDo6/SeZmYL9Ik++FQP
         hnbGGBpN69/V0Ipz/7oSxq8xhGyWjL9eXFxdXolkSaOos+RA9LuzoUviDRgp5jYCPr4Q
         fTMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RR9VxMZ1;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=ixCDnGhCRwLvgO4QTpDezfwOMen9ape65UuSFRV57K8=;
        b=q3wjViHRSC2KInVoKCbmFUQ8JGGzgVgl+J14geMErGrD6HRyR8Mq+3Y5Avthpp7vmx
         4pF/662cwpVuhMH3s3xyGXwKrKccASYiqq3dir1EgBKmdz3tnNmlEkj8arTVaEei6aQW
         W0BmU/79ujWYzp+TtN+7QRQusdQNst6dRC0ZStHT3PNi9jIDPdKH64XpHqWi+/mSgT4d
         SKr3TxO2h990Zzk5ImsIWbAA+HxQiZ+o41t3EORucTr2vGOTkKc+TMpfQ+G70UULzV8X
         Mu6i8JEJMVYYRR1KzQzN6q/LXiDpaVhNYsh9lA0x/fPyP6JsHXvhYOP9Zu+cM/vbe9zn
         CceQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=ixCDnGhCRwLvgO4QTpDezfwOMen9ape65UuSFRV57K8=;
        b=QLarCiti4lFBdh9C6JiiIvSodtwGAt+qu8JU0iLx4C8u23YqTjgEP0R7eB1BrWGqa0
         nNOksRNNL0n/UdkAvzCBDXiur4S8Ng4UnCKh8dYyYk/VICrcHKNbmW6H/jCsJ5Zwigky
         YKVrl4OC5fhyIcA8sy4kr9UWsors1Z+6YWABUq0kWl8a4cZ28nojHtNvL/VN1wt+raBl
         1cw8N5jbUjWbsR+DG4a1jxPuSPm1So3EbCWhUEEesDanrIE1kpKiEchNY9s9tcuxtEZp
         bVhD20BBrVAWceCvMz4VZwuR84jOYgNdPh3h5/Jp9aCsUW/LFXeEL+DYLRaAtaWW+gV4
         fn/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2KfbxwAPfsNbTnIdaQGlIqiq0Mni8fW3lNl/1suVbXMI8cVzFy
	Ho9d7xKFbLqlzIydxFQlK/Y=
X-Google-Smtp-Source: AA6agR5QER7On9ZysqY0ZTTjBca0UzCxBcxcA5gLCtomwKEdZx9zf7fXd6mLhwr0VF1clNWVy6X2YQ==
X-Received: by 2002:a05:651c:50f:b0:25d:9c69:a4e6 with SMTP id o15-20020a05651c050f00b0025d9c69a4e6mr5568623ljp.391.1659922324054;
        Sun, 07 Aug 2022 18:32:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f77:0:b0:48b:3a68:3b0 with SMTP id c23-20020ac25f77000000b0048b3a6803b0ls1860618lfc.0.-pod-prod-gmail;
 Sun, 07 Aug 2022 18:32:02 -0700 (PDT)
X-Received: by 2002:a05:6512:e88:b0:48a:f6aa:84a7 with SMTP id bi8-20020a0565120e8800b0048af6aa84a7mr5748772lfb.395.1659922322550;
        Sun, 07 Aug 2022 18:32:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922322; cv=none;
        d=google.com; s=arc-20160816;
        b=dwPQ3jPTHHCNIp87yOyLKeWU3bPW3rlC0yCg83WZJdzKsEoU6RBBceVyDdjkyzqAYG
         xpeDyRvnPuutvs68NNLlxPA1SgSEYqqIl2rbE5EEwuf4JeulLBJmvCcRWYRSChcf7o0P
         zd9mH4yUtvrzVfvrnqg2mh394YUToK7rMCFuz/UOoFBt2bQaFqAYgqdnjAcRmuikPXj5
         5+wxEKV/0zHZ+kgevesigdNol1gCpK/or2IRkPc3QSWfLOS+jZ4DO5c3zgj6p+C6WwmW
         0NKaqjjsY5vfkxtK0UWkmHYHdEXWl2b+lXbiBkzdm0nB7ofj0pCzxfBGbHjHuw9Wyduw
         a5uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rd8ZKdn/WQ0KEm6ZZRaSem3F0aJ3Qe54rAM+TlPiyeE=;
        b=fGq8k3MHZObGkqWzdFpYiaZl52rlHeJOd9/QXQQqpHQiuZscuqDuFc+FoIGZXSGBmr
         hG+BsUMEoGqaJgDnHf2FyNHSuV92cFYVmHw89VNkGmBxJp11rIlQtUEC4URqp8rLY7d/
         uYFhm1TFnqaqD4jA3WWcTNgMQGAKAgPn6CmoM7+1sPxoMkBqKIT6Spi12hDH9gf+2xik
         KBq6VuE2Sg+iL+fN1oxVmbzp/E7NWF2n00W6G5mI2SGKA9PvwIvcafZnl1sUD2rjAXrd
         YKBLTeqTbAzNig5RtOUBN9ELKkxugO/uVG7VNfU/rsLG6ge0GrCJ3UJhyZgBhmpkw0P/
         HpMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RR9VxMZ1;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id e5-20020a05651236c500b0048b9bd44f26si145119lfs.9.2022.08.07.18.32.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:32:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id DFB50B80E05;
	Mon,  8 Aug 2022 01:32:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82E90C43141;
	Mon,  8 Aug 2022 01:31:59 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH AUTOSEL 5.19 10/58] mm: kasan: Ensure the tags are visible before the tag in page->flags
Date: Sun,  7 Aug 2022 21:30:28 -0400
Message-Id: <20220808013118.313965-10-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013118.313965-1-sashal@kernel.org>
References: <20220808013118.313965-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RR9VxMZ1;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Catalin Marinas <catalin.marinas@arm.com>

[ Upstream commit ed0a6d1d973e9763989b44913ae1bd2a5d5d5777 ]

__kasan_unpoison_pages() colours the memory with a random tag and stores
it in page->flags in order to re-create the tagged pointer via
page_to_virt() later. When the tag from the page->flags is read, ensure
that the in-memory tags are already visible by re-ordering the
page_kasan_tag_set() after kasan_unpoison(). The former already has
barriers in place through try_cmpxchg(). On the reader side, the order
is ensured by the address dependency between page->flags and the memory
access.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Link: https://lore.kernel.org/r/20220610152141.2148929-2-catalin.marinas@arm.com
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 mm/kasan/common.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c40c0e7b3b5f..78be2beb7453 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 		return;
 
 	tag = kasan_random_tag();
+	kasan_unpoison(set_tag(page_address(page), tag),
+		       PAGE_SIZE << order, init);
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
 void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013118.313965-10-sashal%40kernel.org.
