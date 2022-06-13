Return-Path: <kasan-dev+bncBAABBXVVT2KQMGQEPPGK4DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF92549EB0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:15:26 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id a4-20020a056402168400b0042dc5b94da6sf4632076edv.10
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:15:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151326; cv=pass;
        d=google.com; s=arc-20160816;
        b=xnBS2hB9rzvt02oDoLIQTJFc32mEo4I6FvdrPopeUN6ZVlwGMq4vo7rxgDij7BrEKp
         c4Hctje0V7QOgbzckzB4HDJMHWR+yGQtqXiVjizWpad45SEEHqCJiNW4U4dI+TxGAsLa
         0UteDwYxIl1j0tqpzikoygvb7kcVagPv1elxyqhiR79zl/5mCrO/ONszgLNaA0uuoqQy
         5BBERxuhjLPTLY3BVaWTwcGYjYkDplVRCEWBxmpQACWpDsEo7WJNxuk+pOglgeyI2eSV
         mA5kx05XQObe94UGLiPLwCMZqOS+7yr+dv8x7O8yuCPpKS1NJqnXievZu4D6wtX07XjY
         SL1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=d7uVkvJAFdws61Whq4KgUv0ZMXSs1aYj90mBjUOZS94=;
        b=M9ZRPNgyTZPnqr18OzXD7z1btD1blEY/GNGdJH3sG+eBj6JWzuRFVFw6AsJFPNNI83
         auuYJiorMVG/6eBbNmTeAMu1OmmyW5PBKNvz2NFa9PaSetDMT+rRnyuck2pKTrm86Pez
         QL9JYAXzi3gAbWbMOpa2l4Oqe13cJIal6v14W35DBCppdgkQhbFiB1dnlu+cn2YQcvGV
         3znxFls5EADmY/kA7Jan3CdXQ4oeeSpKtAmkjHpLs2r+oUAED7Y25ZKjEkn81TQuGJkJ
         0oOfN2cW8Ri+/WpSbsJnftcmS1d/ZdfxtTLKsIyQ274YOFU+ypnKivFGl4aQb4E/VEzI
         eVFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vNtdLTu/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d7uVkvJAFdws61Whq4KgUv0ZMXSs1aYj90mBjUOZS94=;
        b=ADkXd2Yg4W6YJUYKQgOSp04LRq1jDvBKiI2Kv6TxusjDqeTq2B6c/wQzDccnZK4AcF
         ZBZZiBUPx9RRDcq2XUOlIpAYdVCKRjabLE6F6J25fmMXW18k5my/y3DXuZLJAIxUSjjV
         SAcenLRQBtYC9QsTvelsyck3Qco3xxOT0poFh4qLQn7jg2RJtywR609Y+NispF5/2R8i
         t9BA+TDKZpajHX1OsUSwU46g65hax95Mmk5K+DIUw+txbWvsvLqOz/WfV1K9/XKcDQ8a
         figVlo87O6I6OMnicss4r7T1sPdy5YaU38zxyvmgcxvh9L2AAxfmu/aO1G7Ie5DWzDDJ
         RN4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d7uVkvJAFdws61Whq4KgUv0ZMXSs1aYj90mBjUOZS94=;
        b=MjUSoZqMgukGk0nqB3YyHmCmhqllpiOt4kVB1/rksfpbsM7Lt+IG7MSyiMHrfc74ZX
         qoO12JFXO245fNmJR793ex7PJJigNzR6lrFjwG3mGZd/+27SDaAZYzCZFLnjp7zF1ChA
         hGnHCj4HZYZGEem6td4HQOepk7wCEJbvKU92V2M7r18O7jLtxrNklIIpYBAgPPT8iXSW
         YpVvLna17nhbYvycTRRtcj9l20rpH6Prq8swg4FXTeyBkFMdMoX6HWJzs8SjGjVYqqc7
         zxguymfp0CRYyIaQain7WxEmirbyQiq+CbFYodZeMxERX0b/m/jgqVOz+x/XIck5j+k+
         F5ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532j5Z3f5ht+hhBfatV2ZAY8e3LkXoteQDrtJGcAXSYQXzNPv7Xt
	AaioIolkIKhwg4YBL7ulvLs=
X-Google-Smtp-Source: ABdhPJwRcXkNBD5M1jmaLH3i2p9sQYlHJZ1Hv1+CpbmJCVCva7cXq7H5gvWEEcvszeErsgtbb4/YDA==
X-Received: by 2002:a05:6402:5388:b0:435:71b:5d44 with SMTP id ew8-20020a056402538800b00435071b5d44mr240659edb.364.1655151326609;
        Mon, 13 Jun 2022 13:15:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2ad6:b0:6fe:976a:7a5 with SMTP id
 m22-20020a1709062ad600b006fe976a07a5ls142629eje.7.gmail; Mon, 13 Jun 2022
 13:15:25 -0700 (PDT)
X-Received: by 2002:a17:907:97d4:b0:711:cf0c:c220 with SMTP id js20-20020a17090797d400b00711cf0cc220mr1269579ejc.269.1655151325886;
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151325; cv=none;
        d=google.com; s=arc-20160816;
        b=L+hGB0ANc2IYnDcuHz/qJ9N4dIRrt2NzmrRc5IpvntxeqH6CLb2X7a6kEw0LmUUwNi
         XBCQQfWcUt4cSrCCNUmuCg/uL+Tr9uHM6VCJAdZQMKSTeGPc+1PQBsYG+qiwEs7Fxx3a
         4DpwrhAfQtpNT02vGX4D1SNNYQ9j4ZDJl5QNLuGHrY/duGeF9SgjsVxwX0h7144Da48h
         nI/+0p9m5HiqEp7EWXxw5ZHaa2G3yVcU5M/U2rmPu82rqjX1XGnsYXi97w6VvngdIe6O
         jW+1q/zDmmm1yGt2lFSgJ94DcRn7TAEW4RvyU5QwqkKUsMmgMlK4iYKAwrxqXYlQr6Af
         KGtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5YxZt8AJdg20zeg5mlaLc0cE80lCSk74fkwRwLQH28g=;
        b=RnnzjIJT1aJw66uPKz7LP7/atHBEQAhukCuvVgMJoQ6zITUV1GnpM0WgI68wnBy4lG
         k3qoPiR7OzKB1nGBVWz2OMp9Yg3XOA8o6CmIPd86TSx1huVrsMNqjIGGwJZ0BYmvyVF8
         n6Tb7FbopmeGPk/C6TjjmtrcgQAuGh/5KAbHhWSqTJAOb0K1+XgUOVggwvK2BPIDm0uL
         nyXek+4ZyidPV6nD0sLbB8PbV1vmzVsoCgoihrHPeRQvfv1OCklhMjuPdUq8YuDXAJI+
         eRJTvCK6jogfls1rRZDBNWsWsoMX6t1GK8660V5Wyx8qGPIlMerKwZz3QIr0kqAQFZFX
         hM/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vNtdLTu/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id j8-20020a170906430800b00711d2027db1si310242ejm.0.2022.06.13.13.15.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
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
Subject: [PATCH 03/32] kasan: move is_kmalloc check out of save_alloc_info
Date: Mon, 13 Jun 2022 22:13:54 +0200
Message-Id: <ad7b6cfa3fbe10d2d9c4d15a9d30c2db9a41362c.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="vNtdLTu/";       spf=pass
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

Move kasan_info.is_kmalloc check out of save_alloc_info().

This is a preparatory change that simplifies the following patches
in this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 15 +++++----------
 1 file changed, 5 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 753775b894b6..a6107e8375e0 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -423,15 +423,10 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void save_alloc_info(struct kmem_cache *cache, void *object,
-				gfp_t flags, bool is_kmalloc)
+static void save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	/* Don't save alloc info for kmalloc caches in kasan_slab_alloc(). */
-	if (cache->kasan_info.is_kmalloc && !is_kmalloc)
-		return;
-
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta)
 		kasan_set_track(&alloc_meta->alloc_track, flags);
@@ -466,8 +461,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	kasan_unpoison(tagged_object, cache->object_size, init);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
-	if (kasan_stack_collection_enabled())
-		save_alloc_info(cache, (void *)object, flags, false);
+	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
+		save_alloc_info(cache, (void *)object, flags);
 
 	return tagged_object;
 }
@@ -512,8 +507,8 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * Save alloc info (if possible) for kmalloc() allocations.
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
-	if (kasan_stack_collection_enabled())
-		save_alloc_info(cache, (void *)object, flags, true);
+	if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
+		save_alloc_info(cache, (void *)object, flags);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
 	return (void *)object;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad7b6cfa3fbe10d2d9c4d15a9d30c2db9a41362c.1655150842.git.andreyknvl%40google.com.
