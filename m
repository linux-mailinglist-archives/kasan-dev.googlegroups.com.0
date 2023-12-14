Return-Path: <kasan-dev+bncBAABBQNB5GVQMGQERBKHRUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 856FF812414
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:48:02 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40b554730c5sf52541315e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:48:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514882; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5rSz2EvLQ2Tl8XMXYfZ0323Vq8X3yJAZxEoIfthqLT0c5aqY+amhufKK46y7Rg7j0
         eQivXSN1l0Ty+pFtQaUgaAFwoJHwt0bkfzzTis/ccXUhgPpBhciJ2bWMN3tUIGpAYClp
         +HsLe+RG5/c3QbnFXa9eThkKDUfY53TdBgst3eEtyed9HXebH9W9Hxjfews7LyvCRrDm
         wiqI2FcCIdSTnzJIGXPm5vxSzlXgXCuMCgu6ZflHSlbDE3Vp7uKHRay+RzFIC6cHuJ5c
         IQ7nj69r+oMuua5Ptv0Wx6pkMq/yjRxrU6HtfDgTTF8Vd0NwicRki2VZKUG2OR4L2IFg
         FMJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mwTJ8RF+miV4F5NPASsIf7Zxx/4w989+EB4LiGBqgUs=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=UBfFZZ5gNr5pEJcZVcvE+X4YKvRIdiAMEmLKwnub59W1ySgkQZs2v8KpfQvJWc/XAe
         regwiVgUD77xg8nWSoAluKIsdp8rxKSoqWz703ZR+ObaWS4/SZIfytKyD/GJ9NjGmHtF
         RsqjLIuKnyEoKbS/WToZYcUN3pMJx9oR01p6oqL5IDoRpsozFpt7IbfS1nXIcZqihaPW
         dOWU44Gf2ub4FcdWy4mg9zwNkXqX+gTuEydrHcV9G0IBaTau6eqp8uTGDhnqe/SkhyH1
         IKPqavEITIbWkhJ4SHsLREgJW94rnRyIFhuOyPAWUfCeTkEsjNhC2pSBlL0jlWBYjFFN
         UPXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NsLzL58t;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514882; x=1703119682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mwTJ8RF+miV4F5NPASsIf7Zxx/4w989+EB4LiGBqgUs=;
        b=sZrejZhLhWu9ouJ0O7MM7bM2ehSM1RMcpXKYKROx0Yd1IxKLIHre9wbDSXnYLLlQz7
         ISwehd8q6C3ugM5gVW3Ha8xhLT/qB8BrTNP7hzrRXy0Qk+A2BU09wetRbGlSb8Qec06U
         pOf8EEHr06onnsaRARkL2FHGdjuU0CQNWY/qKUchUvIyO2Y7rnloBaHibLcITb0TZEzG
         6L9omSbOCNicp/nEMp+qz9of0R6wQRA1js1xwJSigmLPIwW6BCotDPICZNAlFG5arXMx
         Ogrb5Iv/qPRTU6ne3Bb0Fh+QxCR++evqtATtm9/ZNOL6PjmAK0X7B4I84QeHg9aXZNZF
         0Whg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514882; x=1703119682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mwTJ8RF+miV4F5NPASsIf7Zxx/4w989+EB4LiGBqgUs=;
        b=ROMZrmmb9iGY9dTPvAJuthqIZ3oE7RFf3WLK9bCOmtpeSlRLeFh64QaINPgfSl27oF
         kYCijhnezTXANs8n8l7hqsjhv44u88v9zfWA6kb1pYGPwel/0Tt3u4PklTgZOjW8593i
         3rWs0W11lsqMgWdF94Dcvt3ticscHLRUis5BUoZ5D+xFkzldMyBKFTJ1/yqCDycO95/+
         MU5nNyAA4rZ8W3A+7StQ5glQP4jnr5iG95CurVTTVjLKSwgJsjUBlTVLhLAIXRC7fwi7
         q027BmeKDQmtHJ8TNgugSEhmjyMIa8cppMn0+BxSGzFCcgYrFq7eoqw4ZIUy1GIuiHZ4
         XUsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxQDOGntKfWwIomJoBib5r3mB685Srg5gJzTHJlDTJZSoxX+h4d
	cryZZOTQE9Q6zNSdWBqYe2s=
X-Google-Smtp-Source: AGHT+IEcMo3hR6j+x8sJ1L3qjAI1sqSwhVq8Mv+swDLpnFMznN7GCkEze+TUSZFU5JBBwaXUsSGUiQ==
X-Received: by 2002:a05:600c:204b:b0:40b:5e59:e9f3 with SMTP id p11-20020a05600c204b00b0040b5e59e9f3mr4524687wmg.146.1702514881497;
        Wed, 13 Dec 2023 16:48:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca2:b0:406:3989:98ae with SMTP id
 k34-20020a05600c1ca200b00406398998aels550094wms.1.-pod-prod-07-eu; Wed, 13
 Dec 2023 16:48:00 -0800 (PST)
X-Received: by 2002:a7b:c5cc:0:b0:40c:53d1:4c6 with SMTP id n12-20020a7bc5cc000000b0040c53d104c6mr1658814wmk.166.1702514879867;
        Wed, 13 Dec 2023 16:47:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514879; cv=none;
        d=google.com; s=arc-20160816;
        b=kIMTC0j0BS3f/6ADFkLEyZwoXLo8aeoM3oPFATy+vNoERyqFQVnCS4rLfCHahQD6Q/
         EdmWXhjb9sTSaVrRIi8WcfuP6ApVhOmgNB8DVnOcVxLWIW2ZLHoYaAyJEJcA+2UhTur0
         BWSIJF3UiTBrKlvYMhC3IHOMKD9yFdsLlO/mfNOjWzlwaexd7cSJ3xL/y4Y48ACsf8IV
         iCoFQ6XMVO/kwRhIM8TvN9zwG5RXM/L+0dIKuD75J8W3tJ30RD99UcHEaPqq/AzcTWTe
         KUHjZ27fVFtGmlJ6rLyaHOXu1qU70DWzvyzdTMlwe55XQdtp1ON26EvoD3QU7tCB29Al
         /K1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nejB0rN/5EGuA3SQQpabp67CuxIikS5y1NrnTFuMISI=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=kkhy0AfeGwsKS4NxFGTWsISCUSHHju+cP8MK1KQfCVUv5HLevEKsqy/LE05ygfZEe+
         51ioWDntCii1tvtuyRxIECeaNGcVrcdjAcXlEtbZr/oG2zN5LDdHYRKN3GHqJtCFn12g
         HI6duJwHZ9HccjQRS/3Jwzk8J38oirKaJtNdZdXgZMNM8FUsLknPssrreGT5bBDgxIXu
         nCZzRiQYgH1XHJTqUtiBxF29t91Q14k19Kbav9Nos2OMFA71bf+uOAatmU7RjMnX8Ec7
         +ZeObFt+BPIqd1MeYtFco4ixxwbokrnooiO7QkqH6R0QlBvq9Pi5FjNxr4S//4OfWZ6X
         dxpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NsLzL58t;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [95.215.58.170])
        by gmr-mx.google.com with ESMTPS id o29-20020a05600c511d00b0040b4562ee1fsi84366wms.0.2023.12.13.16.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 16:47:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as permitted sender) client-ip=95.215.58.170;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH -v2 mm 1/4] lib/stackdepot: add printk_deferred_enter/exit guards
Date: Thu, 14 Dec 2023 01:47:51 +0100
Message-Id: <b050d29e17195466aa491b37c26916421dfed5a3.1702514411.git.andreyknvl@google.com>
In-Reply-To: <cover.1702514411.git.andreyknvl@google.com>
References: <cover.1702514411.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NsLzL58t;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as
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

Stack depot functions can be called from various contexts that do
allocations, including with console locks taken. At the same time, stack
depot functions might print WARNING's or refcount-related failures.

This can cause a deadlock on console locks.

Add printk_deferred_enter/exit guards to stack depot to avoid this.

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Closes: https://lore.kernel.org/all/000000000000f56750060b9ad216@google.com/
Fixes: 108be8def46e ("lib/stackdepot: allow users to evict stack traces")
Fixes: cd11016e5f52 ("mm, kasan: stackdepot implementation. Enable stackdepot for SLAB")
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 870cce2f4cbd..a0be5d05c7f0 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -506,12 +506,14 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	bucket = &stack_table[hash & stack_hash_mask];
 
 	read_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	/* Fast path: look the stack trace up without full locking. */
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (found) {
 		if (depot_flags & STACK_DEPOT_FLAG_GET)
 			refcount_inc(&found->count);
+		printk_deferred_exit();
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
 	}
@@ -520,6 +522,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	if (new_pool_required)
 		need_alloc = true;
 
+	printk_deferred_exit();
 	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	/*
@@ -541,6 +544,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 	}
 
 	write_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	found = find_stack(bucket, entries, nr_entries, hash);
 	if (!found) {
@@ -562,6 +566,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 			depot_keep_new_pool(&prealloc);
 	}
 
+	printk_deferred_exit();
 	write_unlock_irqrestore(&pool_rwlock, flags);
 exit:
 	if (prealloc) {
@@ -600,9 +605,11 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 		return 0;
 
 	read_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	stack = depot_fetch_stack(handle);
 
+	printk_deferred_exit();
 	read_unlock_irqrestore(&pool_rwlock, flags);
 
 	*entries = stack->entries;
@@ -619,6 +626,7 @@ void stack_depot_put(depot_stack_handle_t handle)
 		return;
 
 	write_lock_irqsave(&pool_rwlock, flags);
+	printk_deferred_enter();
 
 	stack = depot_fetch_stack(handle);
 	if (WARN_ON(!stack))
@@ -633,6 +641,7 @@ void stack_depot_put(depot_stack_handle_t handle)
 	}
 
 out:
+	printk_deferred_exit();
 	write_unlock_irqrestore(&pool_rwlock, flags);
 }
 EXPORT_SYMBOL_GPL(stack_depot_put);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b050d29e17195466aa491b37c26916421dfed5a3.1702514411.git.andreyknvl%40google.com.
