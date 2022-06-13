Return-Path: <kasan-dev+bncBAABBHVWT2KQMGQEMBE6H7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 239B9549EBD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:16:31 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id h35-20020a0565123ca300b00479113319f9sf3524434lfv.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151390; cv=pass;
        d=google.com; s=arc-20160816;
        b=SO+W7CUCiLPSa7twn6SpfVg/GTNvPcVrNIksihOF0X1MKNjwo+zGqYav888TcQ2bTZ
         dTlQw0eY3JfOSfMmEP/mKkTnLmDTE0SZvIU6g+sVgnxAx9tG8qjyefQ0iGULnlIMAZtm
         sFm02Rx4Jz86MBP3r6x3ItIiysG6trzoFCPzh00usCokfKgrGqWCx0Uyzz9aB9joXPr8
         H05hLklnvnbguOSkfVCQIjk2/TkpVDq0ClXxWGcZiWLDNe6sSN2CQvI3YzLCkudw/E4Y
         tCjtRCmKbXH8Y/WHOxi8+wjBa0g8+GnZ8u3jQRgJcaiy86aCLdAVMg8PuXokwpEF+h6A
         +v4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EEts+cNPW4wDEAxHHQX0oK8Avkgk93KMfd1AIxfuyU4=;
        b=da6R4SRDGmfiZDXohbd+TsPygAF/P7bvQ/6KECEZxN5FRXUGe3DyXu+b+VkEu2sr7n
         HfEUORr04MmLjFWie5YligEdPuXiQgRXb24A4nwwlwE1lnkbgcADzXa6AvZ2VXERRsW9
         tzKCLh8ftOPnB2mDY9nrYejBVffJePt2qpHEgLacNCMfL+fy1i/Yx8ZVzmO7r+XCVm6I
         i9GTMhP22+3lPQq9pMtj6CaNa276zG2xkW23L907S7RMViMqaDEdf83Evpg55T+L7h1I
         +R3zEqR4NkCshn7upth9DKiuSi17HcQzJP0hseB/U6WL70exsc6HKnGT3CLTtB/vMbBy
         g3Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="i1iFXVY/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EEts+cNPW4wDEAxHHQX0oK8Avkgk93KMfd1AIxfuyU4=;
        b=TlNfQPmx3qRXzhrdsGoMnPdPB3vHivoHoTN6U92yEM3gUpsenFuwA//08kK2uRHN0n
         +KT5yh/mtqnEP1P5c6eK60w7o36aXGA0Kx4ihBQfR6+tH5mlzF9OmV7/sj3oJUNH0s/m
         VrtSnzv4SRsKfWqxlyXnPrFGMp3MvKyd2Quaf0/sK1a73YuCrC3xwcaKQ/0uXo+ltB8i
         gZyoq1H2z0scUTjLD+DHrdbXDka960L5KhZvaZKpQ9sVikDSou7IGBh28RboikcjRAgh
         qPMuYMZxoFQMqEfSJ5W7mhl6bwSDog126dHbjHOBqz4QVJFwvNJwCucZfpGisaBxt6pp
         j0iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EEts+cNPW4wDEAxHHQX0oK8Avkgk93KMfd1AIxfuyU4=;
        b=naq4+6/XnXn4QFzkkZrCeqm3ScTJlWIpmwiU+cA/N81R0If3VMYXFVrpfXSiSZQDOm
         0uACO+CbdaQb+Kmn3swbajt8BFlWHnHYOXB+bSw8NFbEpJOvzIBVBTh4F1Tr/+t4L8YN
         evb9xn8AcPBO1NQHyy/Td0eQUkuJX5vRA3UEfY8fxY0TPifsanwREIdiF0j9gP48WfoX
         tjawNLfZu4Swsf0wljz1AT5rFjipeD3+E8s733DvLPbj0EyrQPqD6I9bb4iRt6SZ3PE5
         igOqlqxzeK3d7YydlD/IiVMWbsf3iBAln12TuoC79Wiv4TV3az+1KSPB0Fwus1iLarWN
         4YHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9MpBS3itetm7xe5IhQJSkre0ARGXtIBT5H3gELbSJBKI6P929W
	//lUnQvsn9CizXIPHnXcxJk=
X-Google-Smtp-Source: AGRyM1vutPCd7xgesvAe6crG8FeQa7IvafJHgPW5EPS7U84vcFFZ6kIWszHwVYz15jWoUDdRhd6iJA==
X-Received: by 2002:a05:6512:32b2:b0:479:b04:c0af with SMTP id q18-20020a05651232b200b004790b04c0afmr897078lfe.384.1655151390674;
        Mon, 13 Jun 2022 13:16:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc24:0:b0:256:c8db:bc69 with SMTP id b36-20020a2ebc24000000b00256c8dbbc69ls455815ljf.6.gmail;
 Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
X-Received: by 2002:a05:651c:1502:b0:255:b837:a27a with SMTP id e2-20020a05651c150200b00255b837a27amr620662ljf.284.1655151389844;
        Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151389; cv=none;
        d=google.com; s=arc-20160816;
        b=dWxYbMO1D+ibOXRB09so2XM6oRYPEeJhB2tt6y2s16CKHi5fHOIJT+U/LzGctZrblu
         nHbs13RGguacVrdOxyHSxg9Gt65BSGumyFcbTBWhNuxH6JlRnNbAE5oyuBd8AAl2YvR/
         Y80pLFfJ5aMKVBRrJWLQprAs4sCkaaRLveHepruR8F/3xcgsOiJ0FQtK23chZc12Axpm
         +OWXHdt+4kRwdjbP0grTMBHSTlGM+uiNGANKBC8JL9JFsw4CgRVYKIaMr+TVTq8MjYtT
         UvKXqEnmHgSa4PdEdxSEWh18Se1D5mGd+v/yNcO1KKlhaY8jH6j12b5UaxjF6qQlUC0x
         2vWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AFE9jCstOlqWjsTW+x7JNp4EBVRaTizWNRauezofwDY=;
        b=ZGCpDINslfSIeYfRUVKZGP8K3u3RpoQ9z9MyxCzmKi06ku5ZJNsIkJDD9+1BCwThRT
         vS1HnqoEPXF1cNnlNAu2jfctuwvNZCDI8j4c2icfMzQ16Ob6juZNOsuWa02dPJ8XPDQ7
         kSkWFKdufTTkftG9VBQ+GH+VwMqbdWUcOnN+bsdptm3uU2uAsSysUB1gmgtKPETm1y4h
         CG0KDNT8QEgrfkC+CtIOBq93MZQncFEJiwU6BBxP9wyD+zLNjd6xAQHh1ZEvQDP/SlLb
         qpUkd99BsG+N/04x7Xu6D486EvxjDILR9sCRqfwhtVrrJp42HFEuJSIUsxRN8ra88cFv
         9Esg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="i1iFXVY/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id be38-20020a056512252600b00472587043edsi331457lfb.1.2022.06.13.13.16.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
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
Subject: [PATCH 08/32] kasan: introduce kasan_init_object_meta
Date: Mon, 13 Jun 2022 22:13:59 +0200
Message-Id: <8d1cf94238a325e441f684cbdbb2a1da0db78add.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="i1iFXVY/";       spf=pass
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

Add a kasan_init_object_meta() helper that initializes metadata for a slab
object and use it in the common code.

For now, the implementations of this helper are the same for the Generic
and tag-based modes, but they will diverge later in the series.

This change hides references to alloc_meta from the common code. This is
desired as only the Generic mode will be using per-object metadata after
this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 10 +++-------
 mm/kasan/generic.c |  9 +++++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/tags.c    |  9 +++++++++
 4 files changed, 23 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2848c7a2402a..f0ee1c1b4b3c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -312,13 +312,9 @@ static inline u8 assign_tag(struct kmem_cache *cache,
 void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	if (kasan_stack_collection_enabled()) {
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-		if (alloc_meta)
-			__memset(alloc_meta, 0, sizeof(*alloc_meta));
-	}
+	/* Initialize per-object metadata if it is present. */
+	if (kasan_stack_collection_enabled())
+		kasan_init_object_meta(cache, object);
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f212b9ae57b5..5462ddbc21e6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,15 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+}
+
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4005da62a1e1..751c3b17749a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -278,6 +278,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 7b1fc8e7c99c..2e200969a4b8 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,6 +17,15 @@
 
 #include "kasan.h"
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+}
+
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	struct kasan_alloc_meta *alloc_meta;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d1cf94238a325e441f684cbdbb2a1da0db78add.1655150842.git.andreyknvl%40google.com.
