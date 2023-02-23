Return-Path: <kasan-dev+bncBDTMJ55N44FBBZ5P32PQMGQEXCUX26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FFC26A0E26
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 17:44:24 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id d23-20020a193857000000b004d5a68b0f94sf3092617lfj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 08:44:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677170663; cv=pass;
        d=google.com; s=arc-20160816;
        b=j8mn3NBq59MPCzq3AbOjopba/MGYhwcCAi+5prRviVi0UhuzEsgvQ/eiUX9TAqAWPP
         j1V+ymxTs+gkBt+1ZKpQVgjWVJ/vr5z0RKpIh0cKqZ/UOdTBHcWja3FhDhV/wK8tSvU8
         Sz5JKyqfwb1HmblkCNaPIPmsDj6OKqim69QUHhaO28FpbirawdvQrrAMn4XzXGQQc/cB
         9zUoBZmJXcxfGuFoS/loXWqhpkUno83j9kq0qSqRiqJ6/2f+vZBDbVDwpn2xcZ12DQF4
         mj1FT6vcKZWsrLonrAuRVAeob+Yc7ku8AAKYIv9yzOksZn8n3l0ztmU0JIm7b9ODK2pN
         e91w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=txDS1Tf7Bs7T4/MBhJnTn76mLOdvOy//WSIywsQO9sI=;
        b=EBlsK1d+llbCRxdslApU+TD5vzsUT+ksSJJJDdE4HTOD7PwFIdD4UyhDPMsc9KVgqU
         RTip9W34YZyx/z2OcIxSw1qjHitgk8rfmzuFXip4jH801cwTg/WeG1sjhqk2qzCgqXTB
         Ec9NW86+I4jlQZUbtboniwCCIYPYamQtoip1JYHE73quo2/F8MiHGukqXqCzf1Uo7dLE
         /uBzYzkOWr9iInLOUbiayosuC5groyowKLfIHPhYHYIVrpcvXmqa3sq/7cVjwy+u7zNW
         FLgZ6c5hRNSf+VQUpKcb4SO5/TkBUbJZsns40S6jgJOLpobr2RpDwXpeiHHWuK81VgHF
         mPog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.43 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=txDS1Tf7Bs7T4/MBhJnTn76mLOdvOy//WSIywsQO9sI=;
        b=MDIKNVn9JMAP8W1IdDv1nr1T1UVLXHUgXHNonUgEUQf0sePeOgsqdRu+ZNtkMV8tIA
         D8ItkBw8hcfPXmPxROlyL+3e78+HqmPIuMz6poA4xNC5YRumoUW13TwwNlW8WjCudSe2
         11ahecKJURWlbMaVae+5c1MOLCzW+wKsB7oh1LMWER3mQ3cgmohLNShqfFEt9IVZr+WE
         pft2kOmTYNvplDLLZmSlvtrqtjWOSxo+/qTCkhRKNODizzj4IVRQOnThJUa60P7mGy2R
         qB6ba9kY4G9UoPCr96Z0eZQtFG9UJQc2VbtUxbqJYw1yZ9w7fhizA0Mgsd4NwDq6kV64
         k9JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=txDS1Tf7Bs7T4/MBhJnTn76mLOdvOy//WSIywsQO9sI=;
        b=1tm8aIN0p1TW+GFtBBH/dixu9IDBsE573KGoJoVGUGWLSY6iMoL2VWcQvRJTMT+pYf
         ACSu7Nu1IaA4AP/IZKAdPKMYXRKHccBKi1rHB8Kg9PhjH+YDX+4H142v58aUHMx5GIHo
         soyB7zaEpnxjIUXhu9aNjk4UPF1mL/zrFGpeIDUMMVp634U/k7iWuPOskJok21XD8D9a
         mEiQbs4mExp841k64WDVRNXJZ3OuAnoft80NMSex23NogoKtCJT0eOHNqGDRxw6p7P08
         wkcLHL0UI9kLK3W9WnE9T4m6X4/jwPLoBTcyuIlcjeRNGS6eZo3+q2CJuaA9jkeVfu30
         BBLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUlDbj2vRM8ve4UrvH33zMQ1uZQCuCQC8NDWeDQZd1ds8ELKgNq
	BvkiG1b+ShC3P5s3NoZJXH0=
X-Google-Smtp-Source: AK7set8adwBRJ1zqlbx8LCXxLSfASybcalI/9KZpz0C5hBf1+193K4gbK0q5hzsFIPHIkLOlQn5Gsg==
X-Received: by 2002:a05:651c:3dd:b0:293:47b3:474a with SMTP id f29-20020a05651c03dd00b0029347b3474amr3967348ljp.6.1677170663545;
        Thu, 23 Feb 2023 08:44:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e9f:b0:4db:51a5:d2e8 with SMTP id
 bi31-20020a0565120e9f00b004db51a5d2e8ls47865lfb.2.-pod-prod-gmail; Thu, 23
 Feb 2023 08:44:21 -0800 (PST)
X-Received: by 2002:ac2:4823:0:b0:4cb:10ad:76bd with SMTP id 3-20020ac24823000000b004cb10ad76bdmr4383067lft.64.1677170661905;
        Thu, 23 Feb 2023 08:44:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677170661; cv=none;
        d=google.com; s=arc-20160816;
        b=CIczxoecn7wxdZ09Qp0dzmr13R6B25h8vNYu2hXUg5DULYJT+BWW3e/m8CTyC65Zo1
         ZiJehXN9VjmE0WcbZtNPxlvJilmYmd1nkDw+nXSL3/gpSe1wN5KnYTdLq/ze/YFTdcAn
         JazpPyxqEAsMs3qKUiyntJleHPfH++HTVMyoNkArbpG0sunhu2h0ynYQniHcVRxzdlaK
         kuad7FTcxVIb7VzSfWF6+haADNNpc/Kale5tS34Qes6njSLPqazfVucid/FcMCpSJ3ji
         sX3EBsY49S4p7RARbJSb925sFOpiX/WTbH/i6bqSsPMS1PJyJFyyITVgrsy04FkWSffM
         cmbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=EXP5WLQ9Rub89Gkwnqh+Yqr8BCe99md1ePNpoibd3cQ=;
        b=yUTwkjzc4Q+dcVOdIz0kdfyPZuQl1jwpEkgZiAM34FSow/hRXupy++VHUMyZVKPgPd
         GLldMpHvlz0J3QfOc6rz+DHgdiVgMX1QKiV6jcwi71rJHg0/yNJh2SxS8FP7j75F2zAB
         dIcptqDUJ/bislRaeBe0rMkJLEBpVruQHF2CmAgWok9KTdqBAhcoBJxGTeUCq+VIORNo
         AgohuCxftOjruRTUM+LzBPmFiWynM2jmbRR1OBcNHvtH8O7Kq+knVOefqDYAXSLdN4oz
         IJs7ulZAGHbzTFIe33+cVUO3CjCazNvsbAPJDDrhuUPooMWiNTt4QOJIAb+e83pAeS34
         yVaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.43 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wr1-f43.google.com (mail-wr1-f43.google.com. [209.85.221.43])
        by gmr-mx.google.com with ESMTPS id c31-20020a056512239f00b004dcbff74a12si454143lfv.8.2023.02.23.08.44.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 08:44:21 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.43 as permitted sender) client-ip=209.85.221.43;
Received: by mail-wr1-f43.google.com with SMTP id bt28so4509119wrb.8
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 08:44:21 -0800 (PST)
X-Received: by 2002:a5d:410b:0:b0:2c5:8c56:42d3 with SMTP id l11-20020a5d410b000000b002c58c5642d3mr9678543wrp.23.1677170661338;
        Thu, 23 Feb 2023 08:44:21 -0800 (PST)
Received: from localhost (fwdproxy-cln-026.fbsv.net. [2a03:2880:31ff:1a::face:b00c])
        by smtp.gmail.com with ESMTPSA id x4-20020adfdd84000000b002c556a4f1casm10274330wrl.42.2023.02.23.08.44.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Feb 2023 08:44:21 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: axboe@kernel.dk,
	asml.silence@gmail.com,
	io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	gustavold@meta.com,
	leit@meta.com,
	kasan-dev@googlegroups.com
Subject: [PATCH v3 2/2] io_uring: Add KASAN support for alloc_caches
Date: Thu, 23 Feb 2023 08:43:53 -0800
Message-Id: <20230223164353.2839177-3-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230223164353.2839177-1-leitao@debian.org>
References: <20230223164353.2839177-1-leitao@debian.org>
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.221.43 as
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

Add support for KASAN in the alloc_caches (apoll and netmsg_cache).
Thus, if something touches the unused caches, it will raise a KASAN
warning/exception.

It poisons the object when the object is put to the cache, and unpoisons
it when the object is gotten or freed.

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 include/linux/io_uring_types.h | 1 +
 io_uring/alloc_cache.h         | 6 +++++-
 io_uring/io_uring.c            | 4 ++--
 io_uring/net.h                 | 5 ++++-
 4 files changed, 12 insertions(+), 4 deletions(-)

diff --git a/include/linux/io_uring_types.h b/include/linux/io_uring_types.h
index efa66b6c32c9..35ebcfb46047 100644
--- a/include/linux/io_uring_types.h
+++ b/include/linux/io_uring_types.h
@@ -190,6 +190,7 @@ struct io_ev_fd {
 struct io_alloc_cache {
 	struct io_wq_work_node	list;
 	unsigned int		nr_cached;
+	size_t			elem_size;
 };
 
 struct io_ring_ctx {
diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index 301855e94309..3aba7b356320 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -16,6 +16,8 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
 		cache->nr_cached++;
 		wq_stack_add_head(&entry->node, &cache->list);
+		/* KASAN poisons object */
+		kasan_slab_free_mempool(entry);
 		return true;
 	}
 	return false;
@@ -27,6 +29,7 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
 		struct io_cache_entry *entry;
 
 		entry = container_of(cache->list.next, struct io_cache_entry, node);
+		kasan_unpoison_range(entry, cache->elem_size);
 		cache->list.next = cache->list.next->next;
 		return entry;
 	}
@@ -34,10 +37,11 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
 	return NULL;
 }
 
-static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
+static inline void io_alloc_cache_init(struct io_alloc_cache *cache, size_t size)
 {
 	cache->list.next = NULL;
 	cache->nr_cached = 0;
+	cache->elem_size = size;
 }
 
 static inline void io_alloc_cache_free(struct io_alloc_cache *cache,
diff --git a/io_uring/io_uring.c b/io_uring/io_uring.c
index 80b6204769e8..7a30a3e72fcc 100644
--- a/io_uring/io_uring.c
+++ b/io_uring/io_uring.c
@@ -309,8 +309,8 @@ static __cold struct io_ring_ctx *io_ring_ctx_alloc(struct io_uring_params *p)
 	INIT_LIST_HEAD(&ctx->sqd_list);
 	INIT_LIST_HEAD(&ctx->cq_overflow_list);
 	INIT_LIST_HEAD(&ctx->io_buffers_cache);
-	io_alloc_cache_init(&ctx->apoll_cache);
-	io_alloc_cache_init(&ctx->netmsg_cache);
+	io_alloc_cache_init(&ctx->apoll_cache, sizeof(struct async_poll));
+	io_alloc_cache_init(&ctx->netmsg_cache, sizeof(struct io_async_msghdr));
 	init_completion(&ctx->ref_comp);
 	xa_init_flags(&ctx->personalities, XA_FLAGS_ALLOC1);
 	mutex_init(&ctx->uring_lock);
diff --git a/io_uring/net.h b/io_uring/net.h
index 5ffa11bf5d2e..191009979bcb 100644
--- a/io_uring/net.h
+++ b/io_uring/net.h
@@ -5,8 +5,8 @@
 
 #include "alloc_cache.h"
 
-#if defined(CONFIG_NET)
 struct io_async_msghdr {
+#if defined(CONFIG_NET)
 	union {
 		struct iovec		fast_iov[UIO_FASTIOV];
 		struct {
@@ -22,8 +22,11 @@ struct io_async_msghdr {
 	struct sockaddr __user		*uaddr;
 	struct msghdr			msg;
 	struct sockaddr_storage		addr;
+#endif
 };
 
+#if defined(CONFIG_NET)
+
 struct io_async_connect {
 	struct sockaddr_storage		address;
 };
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230223164353.2839177-3-leitao%40debian.org.
