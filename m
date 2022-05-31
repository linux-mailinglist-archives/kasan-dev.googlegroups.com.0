Return-Path: <kasan-dev+bncBAABBO7P3CKAMGQET5GANBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D892F53942E
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 17:43:55 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id c125-20020a1c3583000000b003978decffedsf1684345wma.5
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 08:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654011835; cv=pass;
        d=google.com; s=arc-20160816;
        b=D2TUrxdjVAs1SyRffp2FFf2exiLxnj8M9OHnUMxCMo+zaoVpoBZKLmiV3Jo7JVxw2k
         wy35yjWhPl9vOWHR+F2t1JrJPsUL1+t/BgPej3OyrS3ssFHkro9neL8EOkKuyqJ0faX4
         McuYiQUIWaqCRhU7Bh6vVYDDjIla9MgRFexNYDcrMASekuPXuR44w3E4IBM4+4jpFlTj
         GXia/tA2kTCvD/wU31Ykx98dUywIO8+5yD0Z9LLDoQcdQ9LLuLfpChHHpQeeWHInEu7C
         nXIz86EqWTK2K2m1LrOuYyGfpPhwqRIP13DdbPMKTy8wPvuXUp15FK5+j8as8QwH31Fk
         2KBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jLgo04brfbI5pBhUUhINdqNJGw8t+m1q74bxdxt2i30=;
        b=N3MC7ytVip+Zm/NWeFvqFBmVGlf5HKWSIyc47+v6f1XQg3sPR3tBxGKjBHTtsco3ah
         P6eFRkP3CQOf7HjdCgIke9ajngPf1fEKQKyoM2IekZmVZJH5SXyhDZpg5ZRSYVbEP5DD
         ozkg45kE+dlHyjOTxhhpENMmU/xML9Uzjp3u9IelOlGF2vD9BuntPxCsnPRvJ/rxge0B
         +U/defgYI8qs9TdKJaHkBsgyQcOqEwhknRnvOn+aivBRSvPk9TiXIkGFRbzUDwY8L3MY
         8FNFgsNR3jHWO+NZ7G7O/5jDvwhGWw15Xvk3Z1MF5bmha27kMG/fDrzODs/S+a/+WLyW
         KaqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ce+LyTos;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jLgo04brfbI5pBhUUhINdqNJGw8t+m1q74bxdxt2i30=;
        b=E9SuWyirlXLjx5YAOVkw+QKhn+tE7auFEUVTkqTGD+0rdfWomR2l1v83EoVJrdf7nW
         h6fDmwTCXcNbnqiTRVgOacph+WwFVXXQXxe2WUIfwARkaqEApm+1asmyG/QfTmpfOFvT
         lCfamj0X5rL+BoNyk+fk3wGHgSTTEmiiurug3afdFGQ2Ew9Qk57nDOTzQE/CB3X/qfkQ
         0MKmWriwOucaKvNXKNi4AZyTRKjvcMs5OQ3iDkZ4t+GvdzisYw7Ot2iMvKmxj4XETGdm
         zT4Ynx25S5LXbpWaHNhTePC93+4zGxFapYrvSxCQzk9vdA8lGAR9Twh9I43CcKmFLPfZ
         RXGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jLgo04brfbI5pBhUUhINdqNJGw8t+m1q74bxdxt2i30=;
        b=ihV+wYoN28gqjIYJ4SE3DMCcTfhaOLgoY4s5Y4igDbmk+3ocMSGGmucZzmNs835fMb
         WER8KTZsEDAVKKFfAzMcGjXeBSXqsLw06CbsGLgNc1bE5F/rF+3M7Bd37+Uv0KcJaB8f
         6oo3oTtPgKPVpSLLfLxx++1Q7bpNrsKsKcJDHEty4g40OJbkVGjOcsBJGrRyyC6nz57h
         M0bGEEo3ifdKRzFiltcU+UhbBgpDGaQ/OwK4SjNVQYAR5FynNDgDt7B/a6SQBncKdPGX
         v9Dz/OuWF3893noMmEHoFCBKaFNYYyg17UBJCt1TCsuXspE0VqKhpcLVEf3/faN85Fwd
         x8vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LaChQXhAgtbM5F0ujXWqS0xKswWYhHRoNx8m35AK4jwmyhSQn
	7Wtdp3GsIskv0eQnTAROtb0=
X-Google-Smtp-Source: ABdhPJzjZwEcIHYQnVCnXUc3mEHnC06MCscrPDepT3dm+0x/kfZ/XMTVBngW10wmOlbiDo6/DH/e5w==
X-Received: by 2002:a1c:2504:0:b0:397:288c:c58b with SMTP id l4-20020a1c2504000000b00397288cc58bmr24366271wml.53.1654011835380;
        Tue, 31 May 2022 08:43:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b27:b0:397:4df8:5be with SMTP id
 m39-20020a05600c3b2700b003974df805bels10780170wms.3.canary-gmail; Tue, 31 May
 2022 08:43:54 -0700 (PDT)
X-Received: by 2002:a05:600c:1e1c:b0:397:3c4b:b188 with SMTP id ay28-20020a05600c1e1c00b003973c4bb188mr24551638wmb.64.1654011834662;
        Tue, 31 May 2022 08:43:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654011834; cv=none;
        d=google.com; s=arc-20160816;
        b=YVP1CL4BjP0h4CemY3fTx5Nm+MBO0RkB0sf7ALU8MAbNdn3zFX3+HpHSRe7LJnLso3
         /Id0emAE62zximpax2q/0EZi077R8pHwybOduImSS2GdINS1a58/7XODhf/sul4Rq+mb
         ZCpCp+15i5d4z1XhtS7Ky+6KjH2yRpGVQR5DVU+A5VdNC5d+5ZSTPx2HcU9lsRrif1/R
         n7lFdrkPd8P11vqXJ9BVhEbct5l8a2ydx6V54CfjNrgkOjExDyLsnEsSuhf98dVgumNt
         qLMsfPy0FRjoDxRoW5pX8EHzO75Ze9yYobnB7S0g93xqZGvnkfzdpNrHOXPu3szlJipK
         H08Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tEpZdGz90JlT1Su1SZxeM3e97n4OjIjhauOVgJs/x+Q=;
        b=ReTe8HhjG5b/IBS+Fgt1tzL41ygyRH3osd3sB7d2aU7+bYh4O1uRbO8/pUvcHplwag
         klFhn5ASHTBWDUdPYPTIVXk9ao8YWqHW1tmMWfVf8SI+wagggRcPcPrGigvY2HkaIxXc
         ZMJgsGYb3JR2ypcczTERTo6kX2ANJuoMpN7bUxQoaaXgHGphIfsbSzu/SuYX6nESPl6c
         QrCTqGTTYBbDvqDuVB3AJE8g7X9UZH5woulpWavh82OCT0txsKAep1c1TVgJT1XttCPV
         THetJ4/UG79aZnKvRH1851mSl9w8EOW3WBldANve3YBClgDz8/dHhIcBJy/LJ85XlueN
         N3Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ce+LyTos;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id n32-20020a05600c502000b00396f5233248si161164wmr.0.2022.05.31.08.43.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 31 May 2022 08:43:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 2/3] mm: introduce clear_highpage_tagged
Date: Tue, 31 May 2022 17:43:49 +0200
Message-Id: <d6ba060f18999a00052180c2c10536226b50438a.1654011120.git.andreyknvl@google.com>
In-Reply-To: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
References: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ce+LyTos;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a clear_highpage_tagged() helper that does clear_highpage() on a
page potentially tagged by KASAN.

This helper is used by the following patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/highmem.h | 11 +++++++++++
 mm/page_alloc.c         |  8 ++------
 2 files changed, 13 insertions(+), 6 deletions(-)

diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 3af34de54330..df76a0db7cec 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -243,6 +243,17 @@ static inline void clear_highpage(struct page *page)
 	kunmap_local(kaddr);
 }
 
+static inline void clear_highpage_tagged(struct page *page)
+{
+	u8 tag;
+
+	tag = page_kasan_tag(page);
+	page_kasan_tag_reset(page);
+	clear_highpage(page);
+	page_kasan_tag_set(page, tag);
+
+}
+
 #ifndef __HAVE_ARCH_TAG_CLEAR_HIGHPAGE
 
 static inline void tag_clear_highpage(struct page *page)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 66ef8c310dce..d82ea983a7a3 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1302,12 +1302,8 @@ static void kernel_init_pages(struct page *page, int numpages)
 
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
-	for (i = 0; i < numpages; i++) {
-		u8 tag = page_kasan_tag(page + i);
-		page_kasan_tag_reset(page + i);
-		clear_highpage(page + i);
-		page_kasan_tag_set(page + i, tag);
-	}
+	for (i = 0; i < numpages; i++)
+		clear_highpage_tagged(page + i);
 	kasan_enable_current();
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d6ba060f18999a00052180c2c10536226b50438a.1654011120.git.andreyknvl%40google.com.
