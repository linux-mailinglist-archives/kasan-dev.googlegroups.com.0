Return-Path: <kasan-dev+bncBAABBH5WT2KQMGQEOD6NQPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id EED25549EBE
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:16:31 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id a17-20020a2eb171000000b002556cda407asf869506ljm.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151391; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZ7TE1VWhSKcBteBAY6+5IVSfHepuV5T/SCSNeXkzXlqlXtmn7YfT7P+VU+4EfGlp2
         BPMWOQSHfWLBa3u4OefM2Y6vM1m1K1vjeYE+JOVL8NbX6WB6T3rPQlC1v8S+3wPIx7R1
         ZUSRAg5cDaQQ6Ij+PTgb497LwY3xdZbgbe33WSe8ztty/hvDL+K8Cr6h5oK3ZuRVncTk
         DrfrA6jMGsTR/x6voUHYSYbRJEkHAkXkOfRN7PomlXt0WcrpGp0mEjmsUOW7tt5x7XDa
         LejkLweOPepXSZwky+GkEYzwZnrkVQ7rNTdhMkqZgzytyJKT+EV1O7xm1Kesp/jYH6u8
         lCjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KESfA9QsLTIfAF+3jUC3yQRX+Kqo0xR1Gev62gR7tiI=;
        b=Z5q6VTdLsilp45PwtgQHNA0erA9EQNWquiNQTgJTjDZIKNKcUxuYTuF/wcV+92D4/h
         xaCyak1yf820t3Yo4L/nxhP9l90f6INJykzBaLlJZVIHr9vyIIKhoATC7rvTUM8sftwP
         tycO+cu3HnpWIVvALZO7X28dFoZbMAl1xnT/4QYrzq4GJsQPvgS9uvz/kcC7kYSXjn58
         6VUpikThLsDeJro5AyBk5TwCPNh/OqA2zmoZ5w/aXJYc+K3HuAQIMxAwpTaBEpjsUTzI
         kGVgL0TI5JNCz32Mo+wjwgV8rWGm9oJAZ1dOx+yNgbMrUiTLwlZFarNIEt0r94ysq916
         A+Fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CoZZG3fM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KESfA9QsLTIfAF+3jUC3yQRX+Kqo0xR1Gev62gR7tiI=;
        b=efTbMIjnPGO39oJ13w9nh3yNhh8frVizU+ShBAhfcwU3ePD/NjD4zbrw92VMTr3f+z
         Cal0x9+xZ0jCo+y0raKeSOeDAxZQl7hLoTrDYgJ09J014AVZjbx5HrJfh+ZK6MZpMKXt
         xCIm5q/4A3OX7JYamcHXpFhACGQymvbsbOI83K940OFEryjWvpn7GJi/A329KsQ2NXhZ
         pONUrFXBRahVOV1/IOuYdx1oOuCN9FQsjePKFhjdHnHu19u9uQ6PnKVVyJubWWrqkWel
         uOiKTuIgu1USnSQ1XyFBz7Bn5l0NpKGhm9pfHhJDYA9pBycT8lbcFlc4MSoGTBccURFQ
         e92w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KESfA9QsLTIfAF+3jUC3yQRX+Kqo0xR1Gev62gR7tiI=;
        b=z7WOrIZd2r/MSk1UUJae9KNNQ/ivIBY/EMSVpeMmzcYTqXpbaGOSWzHtK0+EE2D318
         Mj2jAIP0TLdJrydq93zf1nLLwoCPVdTZHv4Z83FlJs3wUkJnm6gKM7EeaMQdEohGdBS5
         Pnq9h/k2w9GyB+fwjytRaQx0wYmq+8A1N1WKldJOnHywmqfInbGM1/AGY4uHW7zO2qR1
         tcB89ius0tVyilovl+lMflfHgJ+WH+iHaPAqVwXcT3sv/RUlmRfYPMJ2BXb4GpxSgrfd
         9DbOlsnFIaARl3yads6e81a6hYkq2pEVfOb3LzX8YWmpTCoPVRTT+RXJ9pvMbxc1pZNB
         OzbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8KHDm6+pj6UnNm+VPPKWIG3RMNYqGCCnTjLOAk5iW6OLM1NGmE
	22eQS2w9k5puZl7Hpp39cWI=
X-Google-Smtp-Source: AGRyM1uILzuFmghjMCsLGiA3EeULtRk94Q0LNwuENi2ttktp4ktSteGj7Az3Ue0Sri32Gj/s/LteBw==
X-Received: by 2002:a19:ca50:0:b0:479:a25:8797 with SMTP id h16-20020a19ca50000000b004790a258797mr898645lfj.363.1655151391313;
        Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls183880lfb.1.gmail; Mon, 13 Jun 2022
 13:16:30 -0700 (PDT)
X-Received: by 2002:a05:6512:3130:b0:479:385f:e2ac with SMTP id p16-20020a056512313000b00479385fe2acmr900751lfd.575.1655151390516;
        Mon, 13 Jun 2022 13:16:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151390; cv=none;
        d=google.com; s=arc-20160816;
        b=dDvujZcxgTq5gRjmSLh9C+UBczW1UOGTXi2sXf0YPp5TuErY8z4RHQpdpNCOT17II5
         LNKkgai8JOZlP5YURNGd3mFSOMBLqGXZ6HF+OArkE2ch9dgtOnRfV/rs76ar1gynkOxl
         baDrtPRx5RRG6lOmzw6ZmdakoeNcb98X8sjFR5GlWrehLZwvQ1l83TRTdv69KNupeVyr
         TGKonrSNfsN5fPOG/L09c7EOKFJ3SLGZikH3QhgMoWn3K34Bl1ZYlEMd6T6CepgRZbqT
         yP+kHTjRw0d2zbB0QA/X9hdiv2brKknTKfMvi+fo0j3qRRwE0b2Ljbfl7OUMzdfiI25o
         EqEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WaDMv1eR0VBdMqxxxIgVz2Jc7x+Lk8L5CflH0yXuFbw=;
        b=k32aHpJM/7661ot3WxCzv6MnB16aGrFETvlt3CXS7LUanoGoVwFS6G8HqRVCcjbM1k
         hd4/R0543I+1tgFtw6oKNvT9MkmSPxtQl22NmpTCxs9ekF8//xgbdqUao9/2NQilMWg8
         ZeICPjnnQd8rdmFB8tDAPvH+XTWLOeao/r9wGZUhNI94BKyGaaR/jbiSTwhAJ9txp96i
         7vLA0Orlb6gAnSYlmInqDy+PIFEcRlPMmXDSnmJn4foeTKVhGdL37DTI5lJGENfaJwjR
         NZ7gdOHuQ74s6qNb9x2mQbh3q8x0ZTig4j01/Dlnx5DBFfPDcU/mhskw6G2JAhFkPOtc
         ExJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CoZZG3fM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id f21-20020a05651232d500b00479321d8077si318196lfg.3.2022.06.13.13.16.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:16:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 09/32] kasan: clear metadata functions for tag-based modes
Date: Mon, 13 Jun 2022 22:14:00 +0200
Message-Id: <db6ce7b46d47aa26056e9eae5c2aa49a3160a566.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CoZZG3fM;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db6ce7b46d47aa26056e9eae5c2aa49a3160a566.1655150842.git.andreyknvl%40google.com.
