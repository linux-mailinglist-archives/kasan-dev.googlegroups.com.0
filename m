Return-Path: <kasan-dev+bncBDTMJ55N44FBBSNQ3GPQMGQE527QFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B1AB969FAA4
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 19:00:42 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id m22-20020a05600c4f5600b003dffc7343c3sf3751468wmq.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 10:00:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677088842; cv=pass;
        d=google.com; s=arc-20160816;
        b=oKAnU2Rmr4PenwaBCGn8wxPfZHILRFSGi4iq764UpdvheM+pSm2AKWfDL71U2dqMBk
         dzGyRALkWb4Gy5c8zZ9VurQbe82RJLG2aY1aBSMAjM2RjePtTcwXLO0gfA8g6wdWD3na
         UDWIqcdaX8BU/zKUHpOYo38GQnuA/vcThFWusbQXqBIRKNN/RChdqYZlRQmG3fD+0LJ4
         cqNK0NZSfIx3mcGdxgbMKLb5bWVKzdUeBg499Lzz2SDBMaJyrzUReH4gmV0wJoP3LT1p
         oyLg7NJTrkT/Xd7g1pavj559KLR2m9PYYkuQ/rHvuSdIkUCVfEgzmXbz7yuHCMrT3nZj
         tXJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SVGzu4kT0lIg5/uqiuUcCE5+3rKCTcnyaCAniWDHtMs=;
        b=aHDZ5ZTEYxmWskKGTxJEKIR0edhdn+VUcb262EgEBa2eg2zQsY2q8rnHfdkgRZWzKu
         +q9Iod2pwQG3Gn8Iuo13COk10GnKaal8BMD3Z/q+14ac1+adwCPzMrvO5tmXYVGmHMC3
         XEMOhoAibccJks0Vsz1hA031I8QPn7fDajYh+ajaVLv8SkXoa88Osx+0WAviN4aMbT/y
         YIgmYjLfZpiqejOjS2mD3rx8xiFmx/y9BlWlU5PyjnaVJUp1uBusQHY98qc9Gjb5rDtb
         6CVYI8+DpvfE1U0B+C7YL2X/rPfc+vF+jI7kSolulp3ANriH4xbagdNqjQBm1FVlu0JL
         pM7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SVGzu4kT0lIg5/uqiuUcCE5+3rKCTcnyaCAniWDHtMs=;
        b=bzBvJgx297iOna81VVwprlApqJjmezWX2NKSaHogWwRvARIy5r0t/PkISFA//4xiI4
         tPIWGeOZeBLx7sWUsyVlOZ+GcqLPptn/VV+GkB8cZhn80m8+yqqOf4liJXhn04xGmb2x
         ZL+Sk0Z6nxouLyon0ht1pUkqHrwjgkIuszv7LEIm02SdseY0hC+p02I75I+iJ4pyAXVb
         3xCootXNBI+htba0SzalsZujsurQ15TBfm5YiBRy+6+kW4AbYf6knUwxfM8BEpkUd0OC
         M6lXGHLiFG0Gl0AT6HAhGPXiNrE0dj5YTPvs+38yxA1yTwBAjN1Uxv3+Qva5EOV036Fi
         oWzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SVGzu4kT0lIg5/uqiuUcCE5+3rKCTcnyaCAniWDHtMs=;
        b=0Hf3yK/y0pbwhyH3fdAPAWt4JuAcjm5jgmHluG1PXuh8UHcREU5+b8L6vnaVPc0Wxf
         des3YVfHIzoxdTrMHPHJzrbVIBOIiv3ZreSGqq16+aqXND9jxalNKX6Ea/Ll1HaitZKb
         wgF/P7ije8SCwDB/uXRbLyrq53NhyMwl7mctT6v317lrvGGw2W81Y+aPOPIhbW0+xQen
         K0CTUnjY45cPi5L6ubCI39wVt28QxH5l2PEo0yd34u305a+IpsZ3JL07+dhdnx/j/zr9
         80ot1zp1ABUo0Pz5tyEtw4pf2JBDJfiwbijNRQb077qhe9iLnD61vFIHAmI+06Pydd21
         kCIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVzgxOTWH+/JZhT3uLukKyrQAeAgKu9I8Yt7pqM5gFX5M+OQVww
	t8vdHyclyNyfn+GOGCUWAKw=
X-Google-Smtp-Source: AK7set9XDXYklRa0G4ksStcCiXj1iteqBfLEGszogSz0aNohaEndpc57W9TndAoYQrMDmpw/Fg96lw==
X-Received: by 2002:a05:600c:3d8e:b0:3e2:6ee:ce9a with SMTP id bi14-20020a05600c3d8e00b003e206eece9amr1804828wmb.51.1677088842009;
        Wed, 22 Feb 2023 10:00:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e1a:b0:2c5:5262:2e24 with SMTP id
 bj26-20020a0560001e1a00b002c552622e24ls2897550wrb.2.-pod-prod-gmail; Wed, 22
 Feb 2023 10:00:40 -0800 (PST)
X-Received: by 2002:a5d:5f03:0:b0:2c3:be89:7c2b with SMTP id cl3-20020a5d5f03000000b002c3be897c2bmr7881366wrb.14.1677088840677;
        Wed, 22 Feb 2023 10:00:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677088840; cv=none;
        d=google.com; s=arc-20160816;
        b=ZWcY1IpawVhBlDqX50yh29EPaWbV40BzcYaXkmmrGZtj5mgXB4M3eaNF3yCoL83z2A
         byhp04PW3gP35vTfUDlyZdmYM97fDI6A7VOcOautT4xWOGoZGZj/F59XMvlm0uuCbPPD
         HuHHL4E5EEPjujbgmidTdqFLH1eprikgY0a7a5G+uzFqhc9PFLqv5/8Wf+q9vQk5bSyG
         Q+5pgl/6X2+3KCptVxLaN6Xc2SC5tfs6s087XP0mgUwM3CZP7zKJbny5lsHI1GzVstAu
         Q63UttM/xuCTF2NITGMgxKvAecucO9Vi6Kngu0qhtQR8lrziDads2JoMCKDpxipDZkcF
         Y/jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xNEnafHq9H7B13AnAe5txqBr7aKjs9xFRkNpLXSLW18=;
        b=UgOdIDK9PmbvH2PmwxL81rlutsO0lGSb/HwT/dkJ/XXD6GJzf+MBvfwVLWr6KquoZ8
         vKv0zDMC04VKdUOU62yIFBQhMZbmUR8G96MrzTWY9dj6dQUmGVwJX9r1oPAvUReT0MZK
         ohyYupO3kheCZ/i1cZl7PAnmm4bnT2wEQDTURcr3RkBuSOPioYLeOwXe3uKS1Xb6ojfb
         +zvZwhzxojGaQUktkC9WGrtAoUXLJqOZL8JhXrGK2BKTwj6/2VUP7UMuM+3nSq+YFtnh
         v9Sk/BzeSfvqqV1VMpsCbmYMMwDnXyjRPn8Gi+bT+IocZ+sdrJzVvmBzf2muikLq16tE
         Of7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wm1-f52.google.com (mail-wm1-f52.google.com. [209.85.128.52])
        by gmr-mx.google.com with ESMTPS id bu26-20020a056000079a00b002c56aba93edsi295099wrb.4.2023.02.22.10.00.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Feb 2023 10:00:40 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) client-ip=209.85.128.52;
Received: by mail-wm1-f52.google.com with SMTP id c18so1708521wmr.3
        for <kasan-dev@googlegroups.com>; Wed, 22 Feb 2023 10:00:40 -0800 (PST)
X-Received: by 2002:a05:600c:4e41:b0:3e1:feb9:5a2f with SMTP id e1-20020a05600c4e4100b003e1feb95a2fmr7846372wmq.2.1677088840397;
        Wed, 22 Feb 2023 10:00:40 -0800 (PST)
Received: from localhost (fwdproxy-cln-023.fbsv.net. [2a03:2880:31ff:17::face:b00c])
        by smtp.gmail.com with ESMTPSA id 1-20020a05600c274100b003dfe549da4fsm9179448wmw.18.2023.02.22.10.00.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Feb 2023 10:00:40 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: axboe@kernel.dk,
	asml.silence@gmail.com,
	io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	gustavold@meta.com,
	leit@meta.com,
	kasan-dev@googlegroups.com,
	Breno Leitao <leit@fb.com>
Subject: [PATCH v2 2/2] io_uring: Add KASAN support for alloc_caches
Date: Wed, 22 Feb 2023 10:00:35 -0800
Message-Id: <20230222180035.3226075-3-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230222180035.3226075-1-leitao@debian.org>
References: <20230222180035.3226075-1-leitao@debian.org>
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

From: Breno Leitao <leit@fb.com>

Add support for KASAN in the alloc_caches (apoll and netmsg_cache).
Thus, if something touches the unused caches, it will raise a KASAN
warning/exception.

It poisons the object when the object is put to the cache, and unpoisons
it when the object is gotten or freed.

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 io_uring/alloc_cache.h | 11 ++++++++---
 io_uring/io_uring.c    | 14 ++++++++++++--
 io_uring/net.c         |  2 +-
 io_uring/net.h         |  4 ----
 io_uring/poll.c        |  2 +-
 5 files changed, 22 insertions(+), 11 deletions(-)

diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index ae61eb383cae..6c6bdde6306b 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -16,16 +16,20 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
 		cache->nr_cached++;
 		wq_stack_add_head(&entry->node, &cache->list);
+		/* KASAN poisons object */
+		kasan_slab_free_mempool(entry);
 		return true;
 	}
 	return false;
 }
 
-static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
+static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache,
+							size_t size)
 {
 	if (cache->list.next) {
 		struct io_cache_entry *entry;
 		entry = container_of(cache->list.next, struct io_cache_entry, node);
+		kasan_unpoison_range(entry, size);
 		cache->list.next = cache->list.next->next;
 		return entry;
 	}
@@ -40,10 +44,11 @@ static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
 }
 
 static inline void io_alloc_cache_free(struct io_alloc_cache *cache,
-					void (*free)(struct io_cache_entry *))
+					void (*free)(struct io_cache_entry *),
+					size_t size)
 {
 	while (1) {
-		struct io_cache_entry *entry = io_alloc_cache_get(cache);
+		struct io_cache_entry *entry = io_alloc_cache_get(cache, size);
 		if (!entry)
 			break;
 		free(entry);
diff --git a/io_uring/io_uring.c b/io_uring/io_uring.c
index 80b6204769e8..01367145689b 100644
--- a/io_uring/io_uring.c
+++ b/io_uring/io_uring.c
@@ -2766,6 +2766,17 @@ static void io_req_caches_free(struct io_ring_ctx *ctx)
 	mutex_unlock(&ctx->uring_lock);
 }
 
+static __cold void io_uring_acache_free(struct io_ring_ctx *ctx)
+{
+
+	io_alloc_cache_free(&ctx->apoll_cache, io_apoll_cache_free,
+			    sizeof(struct async_poll));
+#ifdef CONFIG_NET
+	io_alloc_cache_free(&ctx->netmsg_cache, io_netmsg_cache_free,
+			    sizeof(struct io_async_msghdr));
+#endif
+}
+
 static __cold void io_ring_ctx_free(struct io_ring_ctx *ctx)
 {
 	io_sq_thread_finish(ctx);
@@ -2781,8 +2792,7 @@ static __cold void io_ring_ctx_free(struct io_ring_ctx *ctx)
 		__io_sqe_files_unregister(ctx);
 	io_cqring_overflow_kill(ctx);
 	io_eventfd_unregister(ctx);
-	io_alloc_cache_free(&ctx->apoll_cache, io_apoll_cache_free);
-	io_alloc_cache_free(&ctx->netmsg_cache, io_netmsg_cache_free);
+	io_uring_acache_free(ctx);
 	mutex_unlock(&ctx->uring_lock);
 	io_destroy_buffers(ctx);
 	if (ctx->sq_creds)
diff --git a/io_uring/net.c b/io_uring/net.c
index fbc34a7c2743..8dc67b23b030 100644
--- a/io_uring/net.c
+++ b/io_uring/net.c
@@ -139,7 +139,7 @@ static struct io_async_msghdr *io_msg_alloc_async(struct io_kiocb *req,
 	struct io_async_msghdr *hdr;
 
 	if (!(issue_flags & IO_URING_F_UNLOCKED)) {
-		entry = io_alloc_cache_get(&ctx->netmsg_cache);
+		entry = io_alloc_cache_get(&ctx->netmsg_cache, sizeof(struct io_async_msghdr));
 		if (entry) {
 			hdr = container_of(entry, struct io_async_msghdr, cache);
 			hdr->free_iov = NULL;
diff --git a/io_uring/net.h b/io_uring/net.h
index 5ffa11bf5d2e..d8359de84996 100644
--- a/io_uring/net.h
+++ b/io_uring/net.h
@@ -62,8 +62,4 @@ int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 void io_send_zc_cleanup(struct io_kiocb *req);
 
 void io_netmsg_cache_free(struct io_cache_entry *entry);
-#else
-static inline void io_netmsg_cache_free(struct io_cache_entry *entry)
-{
-}
 #endif
diff --git a/io_uring/poll.c b/io_uring/poll.c
index 8339a92b4510..295d59875f00 100644
--- a/io_uring/poll.c
+++ b/io_uring/poll.c
@@ -661,7 +661,7 @@ static struct async_poll *io_req_alloc_apoll(struct io_kiocb *req,
 		apoll = req->apoll;
 		kfree(apoll->double_poll);
 	} else if (!(issue_flags & IO_URING_F_UNLOCKED)) {
-		entry = io_alloc_cache_get(&ctx->apoll_cache);
+		entry = io_alloc_cache_get(&ctx->apoll_cache, sizeof(struct async_poll));
 		if (entry == NULL)
 			goto alloc_apoll;
 		apoll = container_of(entry, struct async_poll, cache);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230222180035.3226075-3-leitao%40debian.org.
