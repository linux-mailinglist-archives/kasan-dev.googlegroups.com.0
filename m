Return-Path: <kasan-dev+bncBAABB5GJ3GMAMGQEJDODT2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC9FA5ADA94
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:07:00 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id r83-20020a1c4456000000b003a7b679981csf7911322wma.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:07:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412020; cv=pass;
        d=google.com; s=arc-20160816;
        b=FuQUBSKZev+xF7Ti5sNm3Jch4XtIAqB6ssOyY+A+04NrnSzVC0ZhWMRu9CPL5XOE/Z
         sDQI2bMIiH2e/owTMeQCb+5iZHzIpj4guoe8eg8YaCXoj70or6wSwArQRVguRYx0Hj8o
         P/FrSaOt/hyVo2haKDynwdj1mtmXWMaQjCZKsHoY8ueTQwuZ1OzxOzShTuIpUPqH99/+
         RofbECbtlB+kPClvGK0eHGxtdoUwvSAzQlY1FcG22/pz0uq1eHtNPE7V0WxbJfnvMT9U
         Vb3zcYApjavJVenyk4g4XxkQ6wKk89PYrAPTt1CcV+947IWXlabKx607ANrh/MNmj3ux
         R6xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tVcp+wlu0+V3ixFgauaojHMPSPvc5AMpiQZu57aR6uI=;
        b=xML3eJOpfKl/QbQGY7fjYhHaQ/0n5rV/1Ofs2Cqz27Thwsm+fpl0oERkXonbtuk+Gz
         H0tEpQn1DqHg+LbTpusmwVAgUWOjPGKdAS2DI1urvSkO1DVRaDtLxg/nOH1d7Kd6m+F0
         PpUpbyUI4BlA5Qk71QpwWvf+kZQ1IWfWTSt3dh/H7bd5r+iOcnKX+cJoh7HzdEA1TPPe
         XszLuqaGYufRmGg9LAQ3Twn00d/rCboTALJlmKBa/kKRe/7vZDFbzwbuGMiGWRUuqOhA
         k23G622USqAK9dIGzSzdAq0q2TIVgLjgGxNoamMTRi0Hyyit3kkzj832WV2crAZ+hCYn
         bL6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="TDgm7/mj";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=tVcp+wlu0+V3ixFgauaojHMPSPvc5AMpiQZu57aR6uI=;
        b=cHL6XyadVtToF5CW6M/aL4Nhh/IK4MhkxG8uARDyi3HVRtmg9pVONpjvCrxXF+LjOc
         NrOaEvbpkKtBUxeI4oDS/R8xfFnTgSbF/RMMWlfk3nH4Msyi3fdrjoNZJ4TN/1O9mFUk
         iYDl2bgMXvVA6J/vJKmUicDLOu+yF90VjQQTzWSGupXVk6zeL6+ifVWqtTvk7tpkDON6
         dgWhTzOfIZWNKAxUBKSyOZJTSp08926hM8nIy0N0uIW5U2ZkUU4oMd1F2zGV1BSM2jQr
         kzBTsS4b9SZQ4Aigzxc/RAo/BIjEsCJPKsJ5/hn9Kzx/R474AVQFLqP95HF62tWGFuVQ
         KT0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=tVcp+wlu0+V3ixFgauaojHMPSPvc5AMpiQZu57aR6uI=;
        b=iLx8EPGUx3vHUrwp+ZlWwK6rflE6Ajh6mSc425XVwO5o5cgUos9xFTrdlaoaHBfQpK
         HuMHMS9o5mS2fdhUnECnFCrG3gbKQyv9bXM0Nh6SzL8nGYN5A85ea6q/Wkgiv2NhycLn
         FrcecQo7goriQnp6GXXra+CQCa58aEAYFEaLnqWwRPFT39jkl5yBhiGYvylPbMF/kXOw
         96rlpRqWyMd5JW3KQyYUhkIrT2ijrb1MQHgQ80b5Rko7bbjVbclTqr6e6UORKg7QOr2A
         R70w8VQnaZxC4iBoTa5FKCblyLUTYoaMd3bE136M3wkrPFrZ1s0EZ2XOAPIV+9MLtvMj
         z64w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3LYK0SgGA+Q3yQ7lb4DISjYKWVhTgs4U8BZb3iVcId22XXOByU
	x0HvlOY++GH7t5mIYj4DjcE=
X-Google-Smtp-Source: AA6agR7GcZVaInfZCAPYNdL7QDBCRwzZQRWmMAfbgCsWGioDcge6Z6QX4Jh0/FIU2bF1ZZ7MVhGsAQ==
X-Received: by 2002:a05:600c:190b:b0:3a5:f8a3:7abe with SMTP id j11-20020a05600c190b00b003a5f8a37abemr11906176wmq.81.1662412020556;
        Mon, 05 Sep 2022 14:07:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c92:b0:3a3:13cc:215 with SMTP id
 k18-20020a05600c1c9200b003a313cc0215ls5117854wms.3.-pod-canary-gmail; Mon, 05
 Sep 2022 14:06:59 -0700 (PDT)
X-Received: by 2002:a05:600c:1d9a:b0:3a6:248:1440 with SMTP id p26-20020a05600c1d9a00b003a602481440mr12375222wms.196.1662412019856;
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412019; cv=none;
        d=google.com; s=arc-20160816;
        b=DaoBrrPN2dxtgfYEgrk3bvf2szd1J6Dczir2JlAA2oCywMIJafGks3v0mQZ70CGMIM
         7t0NEifcdYPhCroYed4xGZQCgnKPK1rnfYd+zTUFt7bURuM6elw4lner5NPNdMUK4qzo
         G/EIsh3XhPZML9PIAl5xO744p3eObXm8HtNiWZlJHBce1awoVvtOT/y7vPrXIpaBSchJ
         gmSZJYDUHDpBiXyslZE86iv5TZ9u6mRIhyi+fWXM5A6Yu8NhYnFXFPE0KFkYVKOv/0Tj
         DLn7Ruaf4yfgANqQFCJ5WYlQebps2YQTmcKozC8lOvZE6Dd7Ha6fdbHeIxZqDjBGxWBX
         gxMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OY6e59NvKBhkMf/4HyAqWSEo1eLRPIhpqy/QZPuprxE=;
        b=MyJnvg16mmyeBjgGzWPhyrVhqcEzUhFZZ5hEJpYccfNx8UL0F02oM9hwhAKhXFqYB5
         57PdenaraSgew6naAR+Pw56Uoly1WcubSwuUZoSSO/wKIEYtE3JX7gKji7wh+AOztvAp
         L4VaAgqvF1yzmBRvHJbBLufGC8yIs3k6PwStza8CBE9rtpOb4Fr8keuYepTh2pZZ1mjt
         NJ/sT/Ic2jlCAw0RCIJiydqu6btkCfnOdfXYaYt6YSiXGfcXpvE4+oHVlZh7t1NDAirF
         wKo/KOn0ckNVzA26WBj0ICokoRzG0377+QCOPeJ1TchU1Rt0rr5FK6+z9pSa49ifKqrC
         yrQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="TDgm7/mj";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id az17-20020adfe191000000b002206b4cd42fsi439297wrb.5.2022.09.05.14.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 09/34] kasan: clear metadata functions for tag-based modes
Date: Mon,  5 Sep 2022 23:05:24 +0200
Message-Id: <470fbe5d15e8015092e76e395de354be18ccceab.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="TDgm7/mj";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Remove implementations of the metadata-related functions for the tag-based
modes.

The following patches in the series will provide alternative
implementations.

As of this patch, the tag-based modes no longer collect alloc and free
stack traces. This functionality will be restored later in the series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/tags.c | 33 ++-------------------------------
 1 file changed, 2 insertions(+), 31 deletions(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 2e200969a4b8..f11c89505c77 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -19,54 +19,25 @@
 
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return;
-
-	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
 						void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->alloc_track;
+	return NULL;
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 						void *object, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
-
-	return &alloc_meta->free_track;
+	return NULL;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/470fbe5d15e8015092e76e395de354be18ccceab.1662411799.git.andreyknvl%40google.com.
