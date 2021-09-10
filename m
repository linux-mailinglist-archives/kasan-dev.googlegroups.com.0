Return-Path: <kasan-dev+bncBC5JXFXXVEGRBQWJ5KEQMGQE7V3CSHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BF784060CE
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:19 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id k18-20020a4a94920000b029026767722880sf31994ooi.7
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233218; cv=pass;
        d=google.com; s=arc-20160816;
        b=DnoTVg5XfLVExFoeHPwrlk/pU8PtS6J0QoXZgZQNELmjZ+TjUHCORU9fzwILeUmsHM
         iTkMzpJ/diqyKKWe5UF4HJ3YIf8QWm5/j2BET5nIIVqLawz56c+Tte4ohanBaEunXMyp
         eCEbOszHshv65NmdRzbLlTqv8kk49/JrlXc7pIiiwX/w1Wo/c2mdbZhdEzxphn7r9jZP
         19DmxNlBsx0gZiHcR9c32qPWdcbvDqMqNSg9xr4FwKo7+nvdkhiQEe3vC0d1GrIxjhVH
         DJX5iIVqcwP2DhdMSIvEXFmcB1py1FQsu4kGXBbgDMuI3OnCjxwNhHwumv4shpSL7o8Y
         Cabw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NS/HwVK6Q+nqYGh4U9Dh5eJXq+0Bp1vmDrF5AijShU8=;
        b=t7fPUjRz7MFbneHeu2vNseQeuz5ZVm5bpkZLjp3SbXpYN9Tk+9xEz3baf13czaRsqP
         bFBTip4Bfrg1PMBl11oc/5+FR/XnqMlTbe/JvBUAoQLoOoictaBNa6ldCYnI8gwQ/tHu
         qB4VjM/9mY/7LwvMukMjl7ixxseYnzQpcpjP32KzpKmQF/lDc8MzBkfFCL24YupTSklY
         gS3uLIdwx+H32rXPxSlJpbF9FWcupZq+z6g9V4HrYNqLAdBB6Wn4X29sJapC0go6ozhh
         z2Ps2X8NFAQM0frDoBXpRdn8o7CxReljEBt4Lbt0oHsu3aLvef8OOTbyW2HIU2azsFu0
         a4kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GvgyiBbZ;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NS/HwVK6Q+nqYGh4U9Dh5eJXq+0Bp1vmDrF5AijShU8=;
        b=SmL5fuaUPI4gg7aHeoY2X58VLou2Q608Bz8EVVcxxWwiG6mdHWfFmK23n37oi0sR4G
         BxdvDnpSGEe6+HaqpgbQn3yDxcmGYYoihbtxR04KhaU9LER+uULvFfEyz6yE+5NYey0u
         bhdtK3PrkM+QYb8NFKKoV3+fMv3UfVWsYkamtM0eV48kEBmA7U9lmg0jlgTW47pq+46z
         mKwlhs0gbIp/R74sIYUVaEFs83H9JkbZAWmLR3//048hmSSw03ncGislslsLwRpT15He
         sWuBqerbxlBtrk+mEtTGIFJQ1Af9J0ZEaDHZBLM0E40891jiNulwV843z4NAXT5IibQl
         2uHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NS/HwVK6Q+nqYGh4U9Dh5eJXq+0Bp1vmDrF5AijShU8=;
        b=2Fn6DqPWBxxuGspkrM1dAknHNB2/xaXgPehrj9J/20/ZCRpiUkMECBSyRVPClsWvYn
         xCBvFnSs28QTZom4ju3KyKpFhK0VkQpB+67PVFEV36dc4nEBGp5OgKKWUvvZh1I1Tsx4
         s4b2eGQACmgpjXiqlP5s3XLIT4JxX61fG0ZfYi/c/hCOWgg2MTps6YfWn+mkoZvfvMcT
         t5WKU+G2RDBnelAKLymqP29pRe4mIRW6LEKFZLIv8Cv0qXH1vkIkJH/5hYzEsynjuI8c
         MAmrIfye0aPTI3cXXY04bdBE08wJ80YH2jRXV7ocNDC9xB/lGLTzn9WDLtnqmJNm54wI
         9ZMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532g/LWEZmdOrrIMblCy2x5SjYm9nRuVVNtXX3K2O4ZAqM3txIHx
	vrzl5BbenK0V92v0A1v+GUs=
X-Google-Smtp-Source: ABdhPJwQ5lS93gn+LLrMCfiHqSes7eVJEEHFZjNMPLqZVtcycUmXE0zUPjJ/kA1AkdYsgk01tETv3Q==
X-Received: by 2002:a05:6830:2b2c:: with SMTP id l44mr2345907otv.238.1631233218158;
        Thu, 09 Sep 2021 17:20:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:14d1:: with SMTP id f17ls970802oiw.4.gmail; Thu, 09
 Sep 2021 17:20:17 -0700 (PDT)
X-Received: by 2002:a05:6808:296:: with SMTP id z22mr2098265oic.99.1631233217643;
        Thu, 09 Sep 2021 17:20:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233217; cv=none;
        d=google.com; s=arc-20160816;
        b=J1JWzIjFHutafZLG+s3jV+TFuh0MoiXbkDudGmpBvwClw8fvalhmL2d05+UxHVstQ9
         /AFK6PCrYfktphiaNa/UmLX0I65nwTMAjByk9QIS441PH+XiGbEckkHKKN9CPixU3CSE
         uz05uk+0/J0addsllNSE1f2si87YUH8gDZ6DymHNs45ldpc1SiaU/2gnPZzkp5L7fqxQ
         ncJgyMYf7o2CkBPGqdgsKO4E4HsPxoknuahRE/6Rfx70z17Own4Yq1D3i1+yzf/O1swL
         lJbM2NOWFY5xhxmjynERWr9xdMb+LluhaEnBcsXJrxu6svuk3GDnV8qMIDLrsiQ02S1T
         96wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XeIGdp7dRHWzeLxpVYQlJotanDRBiIrGpb6eQdbk5Fk=;
        b=0vt8t8oyQS22IAgG1uIAUUhPrQweJH02cd+7d/wuPduhwIxuXuac2EsbUBDo07buUn
         deM5G6UWG9gUDN6h4xU+rXrrLogauDmcA77suufIVNziWJFl1l3x8EHH9DjGkh6MVB1S
         tt1aQEqra8sCEeFDbsvYZ6DabMg0/tZcRvOg9jA/Cn3OhDoH6x20kRzmB6y9QjBMqqg9
         DJxF4zjOIS/2+1h9hf7SXFJVxkEuMUicChMrNuLhoRGOIw52lJZkH89Ojliw39q2gEtL
         WBEFtqaDjfzjjmMVBO/QN513A/6CuPVvvoYhnQemiT8oZOSd7vBDt2yX8HmOccHobYSc
         lW4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GvgyiBbZ;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m6si329022otk.4.2021.09.09.17.20.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BC20E610A3;
	Fri, 10 Sep 2021 00:20:15 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.13 82/88] kasan: test: avoid writing invalid memory
Date: Thu,  9 Sep 2021 20:18:14 -0400
Message-Id: <20210910001820.174272-82-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GvgyiBbZ;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit 8fbad19bdcb4b9be8131536e5bb9616ab2e4eeb3 ]

Multiple KASAN tests do writes past the allocated objects or writes to
freed memory.  Turn these writes into reads to avoid corrupting memory.
Otherwise, these tests might lead to crashes with the HW_TAGS mode, as it
neither uses quarantine nor redzones.

Link: https://lkml.kernel.org/r/c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..ba7ba3962949 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -156,7 +156,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
 
@@ -192,7 +192,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_pagealloc_invalid_free(struct kunit *test)
@@ -226,7 +226,7 @@ static void pagealloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -241,7 +241,7 @@ static void pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_oob_right(struct kunit *test)
@@ -503,7 +503,7 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -542,7 +542,7 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -689,7 +689,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	ptr[size] = 'x';
 
 	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
 
 	kfree(ptr);
 }
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-82-sashal%40kernel.org.
