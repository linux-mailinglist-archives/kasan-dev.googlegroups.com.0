Return-Path: <kasan-dev+bncBAABBH5XT2KQMGQEJDQWFFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A64D549ED9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:18:40 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id r126-20020a1c4484000000b0039c8f5804c4sf2769455wma.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:18:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151520; cv=pass;
        d=google.com; s=arc-20160816;
        b=JhLxXud5deFVuuH+9wkco0MiQtz/eaRt5l9qf5QHyJY9WXg+j7eCF9eVjizfioekrV
         xQc2Eq1s5PVX4CFVrO9ZaaboiyBLPRcS813J6tHkCU5kiSdauix+4DSaUv/ZbRL63l1K
         mfz05z+7SUd6GqGZpumS07dH/uIaOTzCASMdRR5tnGUf0+wP3WNRSrVhSKyLN5R5mJDE
         gqXRXA24g3wnny2GvW+4G/s+4brBPGm4xUGDogVlgCd1OMv16UYcym/6Q268v73xcgCp
         BYEWB8NtgdQ8eq8tlf3qoXWoDvGQvbeHEvM57gZDcn0qd8wfVJu4kcc9QN/zUknhDvpi
         Y+Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NRM+X0+sGhcIPgJQ4XgiBlUiltPop4RlhcPKEYqABCA=;
        b=BM8qBDEDl6T0N6+wK7rMnp3ga3oLz/tf1ZD1JZ37tnnobn+n0/0oi3psT28jCY4HIK
         9mhIThSpTQLfHV/Ftocvces8XFte6+iUM5/cS4kqWKFtIvodeNXvVe3KoAbElkRgRB1J
         0UdL2yxZB4Gy9XWvshXRD+cwWlvGkuFPryFUY7JApWkEVoPITraS70/5znIS7GHa0vSE
         Z6UYh5eSWdHPg8H15YCj6nhTTlAQ8Cvq0nR/70Rn17WHOk7cioCMCVmGhLj4V3Ot8cSe
         gBxaztJp4uziDkhpJrjf1YkF+wVvPgPjryZZNP2dvJKgtaSY3JD82xKi4gp8cBAcG3u5
         cHsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NmokpH+0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NRM+X0+sGhcIPgJQ4XgiBlUiltPop4RlhcPKEYqABCA=;
        b=LWmEgtA/P06ercCTMJ5dQhyMGHRllE6OwG6V3yZ0e4sBPFCdDPsQGYWyBMqSI0KhO4
         crNHcKRO2d3M71/WRekNSaiCa2iEr+lg7iawyPtZdVhcVanKfincHSQkY43IMXIy0eJq
         8Mkd+b8hdF1yEwrYVl8BeZY7RPY6geEfVPEfTqqU08yxPraZwMr0FyYQ/HwEYhUZSKtU
         mo+L4MhL1FpP58meGPl5xi+96gitxrs2n6DJBdmOq/IlufApukVbG7rE8Mxs2sbxG852
         EfzJuBSfjZAte4Zmhxgc5GMYob/u43cLlSXc6pzAkJzKaZhtmvoqVznSCRdjjAvneKrS
         iMNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NRM+X0+sGhcIPgJQ4XgiBlUiltPop4RlhcPKEYqABCA=;
        b=n4t3zjv5mmT9Xqdr1P0JZCH3a1jGY8CbnYcJb6x20ThNbQzHwSGhJqOFewBpqFlvmL
         SURmsF+lXw1TEgR8MFkK7eTKetdcEDkOZL/wYsh/GqAs9C+GleDJ3pECuYBn1cd3Rz2U
         j7rhRLxTefr3b8xf08AwGnNQY+xr5YhnS7jLNdfPslFqn/y58ZM4UiuZFFPdlPmROcu7
         hQfr/MrHWt+Yk8wu+0VZQ+vCbbizAfmJ5RO90Q/StznU1Wz+6XsKToMfkdz3zusF7BKf
         ZlTKs0mI9RDCFPHbHFEZ7m4XvT5tnPx/bgtyIYxdQVpJGkZCONaHdKUsz+N2/HhZH1pR
         pebA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8VkZe5ElhC1JVhs/zHLUamRHQO32RXCZbvwPt3JsGSwm3G5v8k
	2I1aPXkMX04T/hYz2LK65fk=
X-Google-Smtp-Source: AGRyM1shKifaOtjRXLL+yFEd+YVMxZrqzdCwELvKFdWeI+Yh4Tn7+W2n7Ejjnx3DNBb0WXtGvcJXOg==
X-Received: by 2002:a5d:4206:0:b0:213:bb1f:b81f with SMTP id n6-20020a5d4206000000b00213bb1fb81fmr1356745wrq.363.1655151519955;
        Mon, 13 Jun 2022 13:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6dab:0:b0:212:d9db:a98 with SMTP id u11-20020a5d6dab000000b00212d9db0a98ls7053703wrs.3.gmail;
 Mon, 13 Jun 2022 13:18:39 -0700 (PDT)
X-Received: by 2002:a05:6000:1008:b0:210:3e9a:324c with SMTP id a8-20020a056000100800b002103e9a324cmr1419399wrx.89.1655151519268;
        Mon, 13 Jun 2022 13:18:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151519; cv=none;
        d=google.com; s=arc-20160816;
        b=XPoo0tG/t5mE1INEf1gariRsXJyFWppVDQbIreianoaFHmSMAfeQD2RT910lwTj56T
         ycF1nr1aHJ+73ZAlENGTRm5cSkOVsFsUeG65fd1xCcbhnLzckXn8GndQ1D5T2S993624
         +RSjOhvgGGOSX1E/7hVHkry+JHbJwuQFfGw4pY83N6MqnNL7A/XLCwyW0x6EWsbLogjz
         buOqmmWY7Yed/o1NLS+4RucSOoTDT93vQm5MgCMGAzvLc/iDAbIP2lN5eMD+Yyv3S0ln
         F4k6GMRxcAFiTvJKTU0gjfuCWQFsTFwupQO8MS2a0RceHylHGu+0WdPpyuq+6Fj2DPRM
         DWmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jgPdc9N08SZf7w3C2n6o7Rgh7KKDeUV8LWJsDjGx3bA=;
        b=VbvqZQoVtnEWFCSkgkKWXcEi7mYhbY7eoW0u+Ox2TuPjK/sExRdRqHbOl3MPCHuRyl
         V6cYKs8Q5879WjcSLe7X93qlEv5UlBWWs2QQoWoucFsNKK7wrVV8GZvaVbozA/6hKjb/
         jiNAQUtEiz3TFaOLG1yhze28gUA1Ol6JVzkPQ54LKY3FOU0jvF8sdGDbJh5Bsw6cHTe9
         FuPk7xKAqrRZbuWmFctS9RdOdDmRzZy5JmLP2rze0/yXgcU3Us78z0/2L2/4JU1amrl6
         2+cEARHYb1na96oWG/+pQtUPH77RYpuWRbLIswNwpFq4vAOmYBW81bGJdRN0MR8Hv17U
         ucmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NmokpH+0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o9-20020a05600002c900b002132c766fd7si336145wry.4.2022.06.13.13.18.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:18:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH 19/32] kasan: pass tagged pointers to kasan_save_alloc/free_info
Date: Mon, 13 Jun 2022 22:14:10 +0200
Message-Id: <9363b16202fb04a3223de714e70b7a6b72c4367e.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NmokpH+0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Pass tagged pointers to kasan_save_alloc/free_info().

This is a preparatory patch to simplify other changes in the series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 4 ++--
 mm/kasan/generic.c | 3 +--
 mm/kasan/kasan.h   | 2 +-
 mm/kasan/tags.c    | 3 +--
 4 files changed, 5 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f937b6c9e86a..519fd0b3040b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -227,7 +227,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (kasan_stack_collection_enabled())
-		kasan_save_free_info(cache, object, tag);
+		kasan_save_free_info(cache, tagged_object);
 
 	return kasan_quarantine_put(cache, object);
 }
@@ -316,7 +316,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
-		kasan_save_alloc_info(cache, (void *)object, flags);
+		kasan_save_alloc_info(cache, tagged_object, flags);
 
 	return tagged_object;
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f6bef347de87..aff39af3c532 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -500,8 +500,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
-void kasan_save_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
+void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	struct kasan_free_meta *free_meta;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 30ec9ebf52c3..e8329935fbfb 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -308,7 +308,7 @@ static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
-void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
+void kasan_save_free_info(struct kmem_cache *cache, void *object);
 struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
 						void *object);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 4f24669085e9..fd11d10a4ffc 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -21,8 +21,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 }
 
-void kasan_save_free_info(struct kmem_cache *cache,
-				void *object, u8 tag)
+void kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9363b16202fb04a3223de714e70b7a6b72c4367e.1655150842.git.andreyknvl%40google.com.
