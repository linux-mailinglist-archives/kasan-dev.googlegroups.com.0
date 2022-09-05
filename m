Return-Path: <kasan-dev+bncBAABB5WK3GMAMGQE2YZS6EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BE38E5ADAAB
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:09:10 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id sb14-20020a1709076d8e00b0073d48a10e10sf2647244ejc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412150; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zih3lJ5NOJv4Tw61QtQgAbXQORA44SgW/5WrHH9wTm13j5MIr42AZwBVNAh9nkKpGu
         ByYlD8vLl7PO6JZvxEl80ad+8WINga5Af2ywOokaxOh8nWQSDlpTOCrL8AJKOij632GM
         chPe0OjEBRBq9rRQQfDOZGJ/BvfzVess+Uq2+22LMF30xEcPdD9B4WMpDHCghWjR5RGZ
         l/cHHPeQ/pUHA+KJRYy9pST2bZr4eNNAdbIkOoZ6C+Hym+ap3I6mNYiGwYwW53J8UNWD
         2cHUL4ltWfliwJHsygnM2H5ljSmGftVBRpMulk9Zhx3M7jccodrcDrJih8fHoWRhKGxZ
         zTxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hREwFWzvbRpsEowiZEkJ/h2i4sfGrdreCKRY13evG6Y=;
        b=tIeVuz+1kL34boqlCDrZ24BDj1Sk+dKeNuKCn/nlZ7ilr7RxRnUo8MZ6OUS6FDTqbk
         o99ll4bMeULnkenwjOYQ3L+8dNN6VZyjWbuLXWiMhxDVsW+56kKQjZnh7Pt8rTPZewak
         x265faZWw4E8S2Z+NX8mOBmYPlCwZ4w5p1gACvvHlNdRW0x1mh3QMw/+f/8ndcz53lo8
         LVaIZjdVqwvgniWjgq2W9I62ftLtaUqZwxYED4Er89K8wG15FE/3ENJPSr7ju5Ap4G/3
         C5gSNYkpp3mh0TCHBmW+lCGhFc59YWAsG93Q2wtOS9EVA8hixGinJK2eTh7/GJvs72jq
         sT8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EOUi110q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=hREwFWzvbRpsEowiZEkJ/h2i4sfGrdreCKRY13evG6Y=;
        b=CI+17PxmjeroY+NF3indNOTyRc8tjAALWO6g4d13xDKePYTbBK+L9vElxYkpaqMqfn
         q2FtUgHjXeZbtg343Wl1G/Speh2ihAa2HgcB6NkNAO7e8V3/LKkC8YRuuZ8yqxBmiv6P
         BObWr+kmTX54dhGkcdIAlTtzyiegy1HqNEvWMQ/l7VXWRpg3BXOaZ0wKQulyZt7SKpWf
         1y9cO6laeelmCyrgzBdoU793SjXaN8fiiLJwd0K7Bc2Wk3o5ZntyG8+QZVnja9ijksJm
         1T6ymHoKv7EThOHkmM+62ull49dXoOwZr2amGO7RtPVxcFsjALnq1TJnJLJf6nCAkokI
         tMhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=hREwFWzvbRpsEowiZEkJ/h2i4sfGrdreCKRY13evG6Y=;
        b=AW3w9CZ4r32c2P6DJL2CycvBSsSjLwGtkPIkxzUs7g3Saxof3m/GoIgd48F0tV4RYq
         +8K2VfJiveH729c1b8r+Yzw8SEOic60MXUanJMK9aATRMMbMfqSsamGIk+1YOMXBXOHf
         rQg1L7MCzVRQlA13LrDQKIEPudCNhLLM3M8t+vhttmQMAjnIbyqFrAwqE88bRnJXLkMA
         ioA8Rf3JoxO7/Q5tqdWZIcfU2BxsgKWYstKZ3W3huoRig1BNnaO8zTxOcCZArolqyXrM
         g1tCVkQiwU7RWtak/4inbQcQU846OzWEjyFfoOmI3NFDSOFdXW+Azn0M/gYlKLpIwCVv
         A1QA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2+sIUH2zTYP/L0s9uHrZCmJTbeL4LevZ9p0kXD6rqO0miuGxfG
	NSjMOfYmLu8TPczbTAZM6wM=
X-Google-Smtp-Source: AA6agR4qMBS+JlFiV5Tspbk6efJ3rP+Lh+iLNpdTasOi0rUCh9oa0VcYpbN80l0WaZRkLcb/hKGycA==
X-Received: by 2002:a05:6402:5ca:b0:445:c80a:3c2 with SMTP id n10-20020a05640205ca00b00445c80a03c2mr44994776edx.247.1662412150453;
        Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6553:b0:73d:704f:9649 with SMTP id
 u19-20020a170906655300b0073d704f9649ls3992773ejn.5.-pod-prod-gmail; Mon, 05
 Sep 2022 14:09:09 -0700 (PDT)
X-Received: by 2002:a17:906:58cf:b0:750:524b:e694 with SMTP id e15-20020a17090658cf00b00750524be694mr12165918ejs.472.1662412149660;
        Mon, 05 Sep 2022 14:09:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412149; cv=none;
        d=google.com; s=arc-20160816;
        b=F2Qes8xWplZGEPReY7HVqsAI/HrT7O7ybHyhL3EhJO5GERITz0A6xg8fArK6+7451W
         5NP7c+sfoTrldl09WTYWbntSGsNldbtT1Y5rt2YxsOSgtlq3AqImbE+IOV10zggRqhlG
         2f3qdTGalmcFWf/UOUjsoBE9G8MtBjJQCJ/33G37Bfl42YCp+GFI++g0uJnxtPbebK6d
         vMoRTiz1oOfg1xz3VmagEwk5lh85AYHGG+ULA+FBKd4/FH3Ry01qmL80uDeJOTcbf2zm
         +2FI6eSmTsxAPLTd144eZkyfAuEOsnewew7xL+c1FBmdmj+KFXq/hhclqXZ6SCgMuIkQ
         Cl5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GJNa42EfTEJvCRozp6uSNsCmZYGjNgR5hCDWvh6WqdM=;
        b=VgJbrFDjXT6d9qDNhleHE5WQr8rqt4kUeAHZN5iNdXbIFFRuJfMxBBkTSL5H5ZovEK
         W98TLjpk+41Zd0YK/0M0M/teIP6OUufSyGr/11V4Fp9cXx8MM62kLTDs8l+NPopSouMB
         Db2JSshIjH2HIfpdTs95ypRJcl7NV8oZPfTg2zD/pWvuuHxlvASg6e/H3DKgC9E7HdvH
         JRc+hvxQDK0vamHGKJWz9T1tCA/TTP6c21uE1PPP3HVlFbxjPSTSJDIwW9d044Z5TvRi
         om9dQN6ET5dRQcilWVmMLu7W71w3ufNb2pwc1LuUnfl+oaFGzTr8VtXyjzTH94iizZdN
         V8YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EOUi110q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id y4-20020aa7ccc4000000b00443fc51752dsi526150edt.0.2022.09.05.14.09.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:09:09 -0700 (PDT)
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
Subject: [PATCH mm v3 19/34] kasan: pass tagged pointers to kasan_save_alloc/free_info
Date: Mon,  5 Sep 2022 23:05:34 +0200
Message-Id: <d5bc48cfcf0dca8269dc3ed863047e4d4d2030f1.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EOUi110q;       spf=pass
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

Pass tagged pointers to kasan_save_alloc/free_info().

This is a preparatory patch to simplify other changes in the series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Drop unused variable tag from ____kasan_slab_free().
---
 mm/kasan/common.c  | 6 ++----
 mm/kasan/generic.c | 3 +--
 mm/kasan/kasan.h   | 2 +-
 mm/kasan/tags.c    | 3 +--
 4 files changed, 5 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8efa63190951..f8e16a242197 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -193,13 +193,11 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool quarantine, bool init)
 {
-	u8 tag;
 	void *tagged_object;
 
 	if (!kasan_arch_is_ready())
 		return false;
 
-	tag = get_tag(object);
 	tagged_object = object;
 	object = kasan_reset_tag(object);
 
@@ -228,7 +226,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (kasan_stack_collection_enabled())
-		kasan_save_free_info(cache, object, tag);
+		kasan_save_free_info(cache, tagged_object);
 
 	return kasan_quarantine_put(cache, object);
 }
@@ -317,7 +315,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
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
index cae60e4d8842..cca49ab029f1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -309,7 +309,7 @@ static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d5bc48cfcf0dca8269dc3ed863047e4d4d2030f1.1662411799.git.andreyknvl%40google.com.
