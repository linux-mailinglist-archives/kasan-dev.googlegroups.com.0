Return-Path: <kasan-dev+bncBDTMJ55N44FBBZNP32PQMGQEKRZ4HZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 887BF6A0E25
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 17:44:22 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id g24-20020a056402321800b004ace77022ebsf15664875eda.8
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 08:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677170662; cv=pass;
        d=google.com; s=arc-20160816;
        b=nP9p8KVDw1QTWE9YJ3yXcBf5AGf2W0HgP+tzuRZ3h/eHsA4RGVRwY+8H82gJN3buIP
         ZZIJ/O3+URNDP0AL66Q11G8biL2tt+4+EjVfNQaY2GBUANTcVHH1H2keW/HHBTkC5mfV
         LDN/WDRH85Zlc7/JFzyzRRensGgnOVOIhOg+w+LP53ibqlwR3Z/3OcnexgJIasq85T2l
         DLgU4mjSagpR1K1O0WPNrH3kH6Y2I+sJ72PBZsiZSVJLl+rGNf62QPckj35Xk3eS9h5N
         pLd5ieCPcHJoBwynpvFb8L7wA0PM2hRx1GH0mdogtHSngqjlk+LpEcIjONpSZKL7btG9
         A1VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q5EBoQOCyut/cukJPittCUG8GKX2YkRT5v8eQLf4RTQ=;
        b=uaYMY0DASwjO7TbltmWVMHYY43mVeeY0jl0EcpfREU4OYXI97L3yBhru4UVMqGezha
         HwP9Mj3M4ibK4fsaOte4KRyyJeaJDVCD4OQoEmGpxRuOaAIg+m8/cdVGY/ldwyIuiJil
         OK4AB/zmwzzLelMdDwUOmK0T6VoYy3KuyCQo7ZK5J1ibrayOZgAJ2wL1+/wF0ILQ00Kp
         ObvmfY4cmuUcXEAMXwDPbCxjC5cTFIZccPjjHrZbuRSGf20iI1JTq7sbLPl2/OWzvHcW
         qXK9YRZpiuImA55QlhxRyAgRFLktG9DKbdGxd3MTEwhTbD9xcZLijQ+SatTtrM/fxi4Z
         e8gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.45 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q5EBoQOCyut/cukJPittCUG8GKX2YkRT5v8eQLf4RTQ=;
        b=DXu6t04M/QtxOMQ6zW1PpoMtP/KowjXbLJKcXrU6MWOVjdrLHCVw37I/knAmXiEioi
         mA6hqtSxz54CrZPJIjF54ENa2g5yPdrQRZLThiIFsVgJG/2bgUBVOILwTUtpImqdseYP
         YgcGZ8rZFOCUg9SAGiZfENWBhRazoWbJNEXLoItPicNRZnev99IisSQCqZjvwABkbaVO
         Ijq43Vnm/rqbdHvRyqkJxtEMpGNmKc0UlmVMQP4ZCqf8DexZt5GbVYmykZiu4qFacrtw
         9R0Z/nFCvmlw0z5puHgeITZ3STHc6a1j6+N7GHn8+KfjryiBqv5cKPSswutUo/efvB/E
         sVUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q5EBoQOCyut/cukJPittCUG8GKX2YkRT5v8eQLf4RTQ=;
        b=X4emK3SYPlgs9oA+Q+8pH3a7jSWz45KD12byuxlaMakajbq8aXr+7DKP6LFz77UQ7V
         3L6XBMjjKO7ciZku3McYXY6FArZdq1qxjLpXgh5Gb5IMgokZOexSFmHhZ4niE0S9LqFI
         y8NfKpcJC6/ujhjOT+cGsRIP4g74HLYa+ACIA1dD2j+75Rg3kbKTfiNrCIuGKdwFnPd9
         beiw+b4euSUWItMNsjDXCdFWtkXNqKRRxguArExkpJDXzLwhGtgzi4RTNYSqtjT3v9H2
         JflnwYiZtu/fiDGxCMMwrkWjAz5RAliVuLd12Z1yAh+3RZf6PjqAPeYn07pHOV3Iyk0k
         GZgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU7ahzAhJo+fJsY/0jcRTCwIovAIT0dGBxYnyCw1G9lgGMdF+iH
	/ld9dm1nSycQ7CjI5+BYkog=
X-Google-Smtp-Source: AK7set/IM8xtD/oAbEjHDPYwgAY8Ye57CH1sv6ljjDqgIv/qqf9ENyE+Tv/t7TwT4vCXZ7Z/4jWD8A==
X-Received: by 2002:a17:906:fc1b:b0:8b1:78b7:6803 with SMTP id ov27-20020a170906fc1b00b008b178b76803mr10864200ejb.4.1677170662176;
        Thu, 23 Feb 2023 08:44:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3583:b0:4ac:b59b:6e28 with SMTP id
 y3-20020a056402358300b004acb59b6e28ls177586edc.2.-pod-prod-gmail; Thu, 23 Feb
 2023 08:44:20 -0800 (PST)
X-Received: by 2002:aa7:c655:0:b0:4ac:c85c:fb8d with SMTP id z21-20020aa7c655000000b004acc85cfb8dmr14718857edr.10.1677170660742;
        Thu, 23 Feb 2023 08:44:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677170660; cv=none;
        d=google.com; s=arc-20160816;
        b=jRqmRxk13GTg+/E6LXC56jNJM1b5CUJ/syKU0e9WmE+zGxWZPWN4QtkmkcVjgcxju9
         1ZRj3oUf2V+5dJeZPg6DTIkbHEModHKjtLwyk/UZGAxYtoa+5bc8C2Lq/KEtjHZ+I0JY
         1P44C7N1y8ZpX7/OpE9PBN3K/P0L37g5woHb1cZNaKEv+6VBhPHzVrPp+7LWrIX40sMW
         76vHPKiuvx6eWXdOi/AzjxOvfc2nAV31GE2QBdEntcDCYcvGnHZL3ENQ3qPIMz37IPRc
         GkdxPkAlkh1ggE5nraQR3fZqx7kHsZXULHOJ8KZ8enztvOEHxIlOnjPVPAOrQvrJdbwC
         Qp1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=+k0d3ITubH2glaeJAp2cfaEZXtQloEAVR31lcQ0bITk=;
        b=PjAH9etPiATR8kShxSeEROsX0tvHi4ODm5nju6z9gwYB4fbnLkiTKuk6YOU8ZTMR5f
         e+n9KbPWdp4SxaDEaCZuXm95KJ0vHtn5FvlIV3ej/S0AUCqgWmjWEVMXEsfcvlm4K4+f
         nfUgrXqwE4wa+Vqjj5vf7La4xvo6vlt3/r9Xepu73Kj2vyUZpSPfrHdVFAbW2MJ3VI64
         Gk7eG4uYV15PknKq04ugkAGGYx+A2l/cOSsKjWHynHrADF3RFdpjwLlhtFGUejV/aT2B
         TDVpwYv8b7BNJN4A4CW633xTZG8o8h7N6ZNStdp4dWzHJEbVOYTuKQzu1ky8QQ1oQXO2
         BnAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.45 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wr1-f45.google.com (mail-wr1-f45.google.com. [209.85.221.45])
        by gmr-mx.google.com with ESMTPS id x1-20020a05640226c100b0046c3ce626bdsi281412edd.2.2023.02.23.08.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 08:44:20 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.221.45 as permitted sender) client-ip=209.85.221.45;
Received: by mail-wr1-f45.google.com with SMTP id q16so822706wrw.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 08:44:20 -0800 (PST)
X-Received: by 2002:a5d:51ca:0:b0:2c7:1159:ea43 with SMTP id n10-20020a5d51ca000000b002c71159ea43mr2492370wrv.51.1677170660333;
        Thu, 23 Feb 2023 08:44:20 -0800 (PST)
Received: from localhost (fwdproxy-cln-008.fbsv.net. [2a03:2880:31ff:8::face:b00c])
        by smtp.gmail.com with ESMTPSA id v26-20020a5d591a000000b002c573cff730sm7700970wrd.68.2023.02.23.08.44.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Feb 2023 08:44:19 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: axboe@kernel.dk,
	asml.silence@gmail.com,
	io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	gustavold@meta.com,
	leit@meta.com,
	kasan-dev@googlegroups.com
Subject: [PATCH v3 1/2] io_uring: Move from hlist to io_wq_work_node
Date: Thu, 23 Feb 2023 08:43:52 -0800
Message-Id: <20230223164353.2839177-2-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20230223164353.2839177-1-leitao@debian.org>
References: <20230223164353.2839177-1-leitao@debian.org>
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.221.45 as
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

Having cache entries linked using the hlist format brings no benefit, and
also requires an unnecessary extra pointer address per cache entry.

Use the internal io_wq_work_node single-linked list for the internal
alloc caches (async_msghdr and async_poll)

This is required to be able to use KASAN on cache entries, since we do
not need to touch unused (and poisoned) cache entries when adding more
entries to the list.

Suggested-by: Pavel Begunkov <asml.silence@gmail.com>
Signed-off-by: Breno Leitao <leitao@debian.org>
---
 include/linux/io_uring_types.h |  2 +-
 io_uring/alloc_cache.h         | 24 +++++++++++++-----------
 2 files changed, 14 insertions(+), 12 deletions(-)

diff --git a/include/linux/io_uring_types.h b/include/linux/io_uring_types.h
index 0efe4d784358..efa66b6c32c9 100644
--- a/include/linux/io_uring_types.h
+++ b/include/linux/io_uring_types.h
@@ -188,7 +188,7 @@ struct io_ev_fd {
 };
 
 struct io_alloc_cache {
-	struct hlist_head	list;
+	struct io_wq_work_node	list;
 	unsigned int		nr_cached;
 };
 
diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index 729793ae9712..301855e94309 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -7,7 +7,7 @@
 #define IO_ALLOC_CACHE_MAX	512
 
 struct io_cache_entry {
-	struct hlist_node	node;
+	struct io_wq_work_node node;
 };
 
 static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
@@ -15,7 +15,7 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 {
 	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
 		cache->nr_cached++;
-		hlist_add_head(&entry->node, &cache->list);
+		wq_stack_add_head(&entry->node, &cache->list);
 		return true;
 	}
 	return false;
@@ -23,11 +23,12 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 
 static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
 {
-	if (!hlist_empty(&cache->list)) {
-		struct hlist_node *node = cache->list.first;
+	if (cache->list.next) {
+		struct io_cache_entry *entry;
 
-		hlist_del(node);
-		return container_of(node, struct io_cache_entry, node);
+		entry = container_of(cache->list.next, struct io_cache_entry, node);
+		cache->list.next = cache->list.next->next;
+		return entry;
 	}
 
 	return NULL;
@@ -35,18 +36,19 @@ static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *c
 
 static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
 {
-	INIT_HLIST_HEAD(&cache->list);
+	cache->list.next = NULL;
 	cache->nr_cached = 0;
 }
 
 static inline void io_alloc_cache_free(struct io_alloc_cache *cache,
 					void (*free)(struct io_cache_entry *))
 {
-	while (!hlist_empty(&cache->list)) {
-		struct hlist_node *node = cache->list.first;
+	while (1) {
+		struct io_cache_entry *entry = io_alloc_cache_get(cache);
 
-		hlist_del(node);
-		free(container_of(node, struct io_cache_entry, node));
+		if (!entry)
+			break;
+		free(entry);
 	}
 	cache->nr_cached = 0;
 }
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230223164353.2839177-2-leitao%40debian.org.
