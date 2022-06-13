Return-Path: <kasan-dev+bncBAABBHNWT2KQMGQEYVHRFKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9AA6549EBC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:16:29 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id n15-20020a05600c4f8f00b0039c3e76d646sf3723221wmq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151389; cv=pass;
        d=google.com; s=arc-20160816;
        b=z5qhHMDmxbixiQnHwl+dMJ9uv+NXUj0k6EoXTKUYzBm6P6FP8HNLL1QnvgocHwl0Vk
         JKvkbzMoM1YXlwnYTOqJ2CuPrW3LK8iQ1vsGIsr2I+iHsyq7BFa3dnUj3QXKcx2zo5ax
         YCi746DOaNA8UPGrESXoz7sS5ZFXui8eZ4FZl9qVcokc1H+Y1HRMirfIS69Cq/jqhnEE
         S//up5qJLvZUzEAjtTxBudWw8++a9QtvqfEwkwyqVEsVRPxIou3r3426JtPxERn9unUk
         o8LXAPdFreDl5Y2KzmI+WQCqAbNq7UvJKkFTiMq5/ChI0H4qesnC4uR1fE+q7cRY+u/q
         OVOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Xp7AUCgx2H/9GJaOcsbJSODpKM72vr/RPhKKfeGlJ+g=;
        b=s6xh/ynsK2xZHjfzmJPhBXNVMIyVlJkGjX+jLCl/Evi0YDXrjqxBVYanqMXjLqkud6
         Pj9lnfH0uPbJsFXasz50gtaUsO5T4FqbHm0vdWKHghLdIu2pf12IudTfN4Qp+aQHnvUr
         2oxhbVUI+vzsRbFG9usXHxEydw20BtSOI4rnP84UROPLScZcPn68QXmRYp8tVrTYnqr1
         yP94NbJ+4j9APSNlG6fiCKkh+Mxg1WB/2l++Y8cYZb7NZGsXB6W+tqQjEsQ4IxNd1bIH
         Rld1rQ+LHmZA+m3998OiIoJ85+VxmCtWIbkhWAY4SdW61+zsFq+Qt+HLuhsVLUERQnWw
         lyrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AI29BOaG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xp7AUCgx2H/9GJaOcsbJSODpKM72vr/RPhKKfeGlJ+g=;
        b=mSM5kwyeFxAE/24lcjsnwV0vne7KTg67nRwEzZkp1klEImwzuoEErvE3vFVLX84blx
         7u0lBBmRCwfF0wo50Y/0HkVm065Qf8g1hRM49+4wPA8+H/tYh+92BSgl8SgUv848rJ0x
         5owZMPgOV7nEHJ1mHVLtg73qLxzRIyD09cHrHshYjY7IuT5kxKkbxd9xy7fJjtOKam+c
         bc0xlsazFM4Do5GaV6+Tzxxysi8M/1RochafqIBv2FjxoyNM5EaoxL9iZVlKFsUoFseY
         oRfqEm23kqmKuxUVc2iIy1+xlnQQVinrvP2nThclP7RrOhcK+pNyt38xsttS8G6ytL7J
         m7nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xp7AUCgx2H/9GJaOcsbJSODpKM72vr/RPhKKfeGlJ+g=;
        b=1BCazHlfglPadKwHOyWr1HMoZTy9TyGeJSM76XWSR/brUPeLf7Mm6cgCFLHhLiTu+W
         H+vi6h5jMKBoORfwRIo3aB3Y/MwMj7GvtQxjKNmQGLvaDvofJDrGuSwGy+OCUIEHPFnt
         VAfBJHGROrYHdt2GRuJHJIpLhi2mP25jWMZXozk+4NnNZyt2qgltsHG6Xz4kDnP5akh0
         H+deVcTwm3n0L/ojtPO7Q/Ng+nw9h6PQ4Qge3qIgO0y+5dDKvKB45KwPCgVZsALhj5/o
         riuS6hg35Lio8wcZaJs3W2iWPrSPL4riOGiVuRoDyhpcmceIVbxGXwf3ij54AJ1i5TxM
         Jkxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+gm+RsZHWpZmbMTZgljq3mmJsdqdsxBWdH5f98c0RXTLVQRHEY
	1DVBzfrMMClpt2yoGvcJ/ZY=
X-Google-Smtp-Source: AGRyM1uTEPtKQ1UMaeXOnbS0yT7pKcHOK9ClNl0M8nH8CP6vaKAuc2W6WQQMpSABJjplAiPIQamf/Q==
X-Received: by 2002:a05:6000:1447:b0:218:4501:4b30 with SMTP id v7-20020a056000144700b0021845014b30mr1439648wrx.548.1655151389467;
        Mon, 13 Jun 2022 13:16:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c770:0:b0:39c:7e86:7006 with SMTP id x16-20020a7bc770000000b0039c7e867006ls125003wmk.1.gmail;
 Mon, 13 Jun 2022 13:16:28 -0700 (PDT)
X-Received: by 2002:a05:600c:29d3:b0:397:4730:ee75 with SMTP id s19-20020a05600c29d300b003974730ee75mr411365wmd.149.1655151388862;
        Mon, 13 Jun 2022 13:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151388; cv=none;
        d=google.com; s=arc-20160816;
        b=gE0Rn9HPfVZqtYq0cUfMi/5DQB7gqW5abXUDp+v+bxOMoHok/hWqgJXNYQnld9Nen3
         6LuAqCkyaYAfW/ndPvBXHmedIQvE2LgZ2bwdonqqXS9iT7BZntU+2ond25gBempzeSna
         SrDQRNYzJb3L+nheJ6gU7n/36PKLt63w1EmxLHK+F5s+AnoWUV7+O0AFQ3Zo4adLVitz
         jBUZ5rDW5+LgX1yzVpfm69AHEL5sPdKmuuD5LxuJ/5fUFCSduBT/nVQMRz88C26NArn9
         CppcqrqPb7LTiNOQJIm9RcA6C58ovFAxNXQquB+xJz4HvDxfDsFvJWK9TdWWHoQ7/j0R
         cxAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aoRv/lacQEeXs4iZT+XDlLjdCIzo6qCQWnCOXZwFqpQ=;
        b=P+Fqb0rfcCjYkLN7o/FjI3A9BKQIbcPzyZusAp/KY9NcH4yn+NUTHHAloF1RkNi6oS
         RGkD4u98jmWwtxSCPRRFRldLZyIJZ7GzZ8R3KLy+AEZWb6Itj5g8H9O+7JH0YYqATg3j
         NA9FakprKYM203LUgIj69qpF5bnZBKEZyzIXhd6NnuCCCIKn268e61T7gKgSR2vDDrTz
         sJd8J7WUnH+81oLWbVRoFBQmMJ6I//dC+oOZr2C1zMDgtynEQGkSZN+XIgD2fKhXLFOf
         G99Yinw3R5DOXEl0lpmeQypkiP1qVNDhwa+AbKgkwYK64VrJSn8MTBzs3SAC2SxKk+88
         jj2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AI29BOaG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id p5-20020a05600c1d8500b0039c62488fbbsi5297wms.2.2022.06.13.13.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:16:28 -0700 (PDT)
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
Subject: [PATCH 07/32] kasan: introduce kasan_get_alloc_track
Date: Mon, 13 Jun 2022 22:13:58 +0200
Message-Id: <184ac9df81406e73611e1f639c5d4d09f8d7693a.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AI29BOaG;       spf=pass
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

Add a kasan_get_alloc_track() helper that fetches alloc_track for a slab
object and use this helper in the common reporting code.

For now, the implementations of this helper are the same for the Generic
and tag-based modes, but they will diverge later in the series.

This change hides references to alloc_meta from the common reporting code.
This is desired as only the Generic mode will be using per-object metadata
after this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 14 +++++++++++++-
 mm/kasan/kasan.h   |  4 +++-
 mm/kasan/report.c  |  8 ++++----
 mm/kasan/tags.c    | 14 +++++++++++++-
 4 files changed, 33 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 98c451a3b01f..f212b9ae57b5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -381,8 +381,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
+						void *object, u8 tag)
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
 		return NULL;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index bcea5ed15631..4005da62a1e1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -282,8 +282,10 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag);
+						void *object, u8 tag);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 35dd8aeb115c..f951fd39db74 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -251,12 +251,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 static void describe_object_stacks(struct kmem_cache *cache, void *object,
 					const void *addr, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_track *alloc_track;
 	struct kasan_track *free_track;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta) {
-		print_track(&alloc_meta->alloc_track, "Allocated");
+	alloc_track = kasan_get_alloc_track(cache, object);
+	if (alloc_track) {
+		print_track(alloc_track, "Allocated");
 		pr_err("\n");
 	}
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index e0e5de8ce834..7b1fc8e7c99c 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -38,8 +38,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
 	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
+						void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/184ac9df81406e73611e1f639c5d4d09f8d7693a.1655150842.git.andreyknvl%40google.com.
