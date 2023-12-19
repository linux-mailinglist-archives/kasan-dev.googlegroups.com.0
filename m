Return-Path: <kasan-dev+bncBAABB7VSRCWAMGQEKI4RL7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B86981938B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:30:23 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-50bf87fcb29sf3844316e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:30:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025022; cv=pass;
        d=google.com; s=arc-20160816;
        b=uPXad6JWpo5C8aAl4ReerZmXX6sdsoY2iELuUtS93ZBFi2ypU9hRuVnE5bq3TBoaKu
         JFevyHmMvYKuSbxSJQ+cktVQKASvgATdlYoKrmSYxkuFWfvvURhKSBXeJrZ4RHUAV0bO
         gMETbXr55tafd5SohiLp8gHoTLhqnfcaEH2mAJYPCYl9wIyCnDizj5LJi7FCT5t8r5/I
         l1A2boWWAjHRMpJBXLFv9OfKN8hprCB0xMdX3uJWC2UDUkl33VhqTD3m5ZWbSgYv6N/n
         gial3V5u4CBpZi6JlwsXqAthHXCgNboaF5Du8hCiNDB/ZIGIodxe3Zln6vBkzJRsVZpZ
         JmDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WzZrk4yrxCNciXRxxq5+Pl6eGJpqnt8ADePxR+ooDKw=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=xQ56iSRaZZ6CvCIIvyWVLP6aFBqyf3MJOb+aR5hV4dU6r8mnfw/YFzW0nSFQbbhu+E
         e/UM/DsNoQt4p3ppJ7w9H5RDQPCG1J9XG7BL5bfn6DwbjaagcIl+36VY9t9cXBA6QWBD
         Yk3SqAwMZAmouqXcco/emeRHXR/I+SjTQq+PqUK0ZnTi31kWrLRlX8Khij/p9RqZSOaE
         jlYf3wfTEeoQgXRwtVc+8n0lgSaY1cmceU4/hJx0vGwJc6SxE2DGVlWxdDYVrAfNX/mh
         aOoBCc3+PSHd/9yrE+4PClUWwAcKC+IxzBSGSkMoaH6+JAo3YQq/EIsc0z9Gfe+dv76o
         yNFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TbFrSJjR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025022; x=1703629822; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WzZrk4yrxCNciXRxxq5+Pl6eGJpqnt8ADePxR+ooDKw=;
        b=d4ljfpOnFNWHSptYTtKZak5K20lgz7wJS+A5g7/bZroiHtLykW6CEfbf5fnOMROaX4
         r92qaT0enREQzndxARcI8ywmnF0V38KPGO3nLrf0UgO9UF2XRrVi1qOGbhJ+N1eDHJEr
         556CGp7RMlwY9uiG9Vq2H2G3iyBalsfodMe85hwBImkZiaKY6X+hypbvLPOYqd+rY6PV
         3Fc07T0ubI246xWUNFdVGLi/FG3oQIxi6huiIp8zTAGhzzGElfu/tljrj+7j3zAEIZD/
         AR9zqr6U2a2BxFxVUSM8CNwZqMrU7+WLpotO8fiScA+8p+igoP98XgfuohcrCUdWFIIY
         cDdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025022; x=1703629822;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WzZrk4yrxCNciXRxxq5+Pl6eGJpqnt8ADePxR+ooDKw=;
        b=l25GyWU+V3uAt8Lsw+R4IBTXwuV2/qPIdWCqqt9WUX+4mOt13RKaDkv4Y2zdyCHO7o
         7egWrWjn6lnZhyv+2XQft669uNJZbGyM/ozE5K1O0fqCzsNlYi4HGTqNkW0kNr6OW3hp
         zHskhp6xNZzidPVL+6bMoE1rnSSjPL9D8aQb7yvE7SbvFV/O2AnxNID5qTbQWqjZcXec
         +w66LM++OgzMotnQXaPZZv7ivlG9IwaArRP1bQGSURPwDIdEYmhCPMvp1lIgW9RRSLfK
         yzDFbH2eJt2HK9RDvmbdwsv5BG+UQQh9jG3LYnEMu3B1Uvpc6kw7ttdNKY5fkQjyoxpI
         1vCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwzslZKQfpZKLO9qI6T+olkUejXw+ADWylb/rpa9pbr/05BXO/p
	4UalBxbBuffL9m4VFO9HGWY=
X-Google-Smtp-Source: AGHT+IFS94c2uzCcqkEDLvfn7JkskMQboYF3lnll4fXe0gK8boBUoWXN4DXCgK4kwmeJLEvrATlzSw==
X-Received: by 2002:a05:6512:128f:b0:50d:1733:cebe with SMTP id u15-20020a056512128f00b0050d1733cebemr10459436lfs.67.1703025022255;
        Tue, 19 Dec 2023 14:30:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4a78:0:b0:50e:3217:bfdb with SMTP id q24-20020ac24a78000000b0050e3217bfdbls519556lfp.1.-pod-prod-06-eu;
 Tue, 19 Dec 2023 14:30:20 -0800 (PST)
X-Received: by 2002:a05:6512:3093:b0:50d:1f0b:d07a with SMTP id z19-20020a056512309300b0050d1f0bd07amr8886663lfd.137.1703025020270;
        Tue, 19 Dec 2023 14:30:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025020; cv=none;
        d=google.com; s=arc-20160816;
        b=DpzQbZd6dE3YC8L5sPhcTl4FjqdNdmOvu7FvNut0RxxdA7E3NDeFUBjSQpbxV76nwi
         FBgTlSWaCcRKcsS2LHTSg3FyDL92Y7bPY/iqlXhf0hMao0yaWSYBlYAGxp8jKCof2Ng5
         gphcMAV2Qh74qdPeGjGAYkH3L03JWUjYx0NMfZurfEsWT/0NGf4+K0cg2nbXYOBl1a0o
         a5q7vGm8NF/qSkGDDiTv0k19srSxNrZ7Sdi/4GLfjSt3f0eF8ii0KLavOO3fc9WmMm+L
         C/kbw7ABURiYYsTVAZuGsOL/2gn/umu88fvap+d+ocKVFdmr/hg/P1tIBYnzDeWqkACB
         JHJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hXURpFT5cXmxHd6E+IlRMk2ARDz23DTQrTWld5qdG1E=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=PGvPBr4urua9nBcyWPLVVHEGHB1TyPgzsvvIv7C3IGL10jECja8o3MAUKprONmuZNR
         +9WyyLZy5YvFcAZ8Z0GVOXyZvg9mUastEjPChU2Q8xdHOYqJkIDc78edElEbqW3C5+Il
         FS9qThmBtQ0cZFZFcTjJSj5ZHts+Tk6QRhWL5yDnAWVFO4CimXjeFPuSR5n/QrdQ73Vu
         SBNulkpvcFfc6D7APy856dCB4OS1q9hUv0YWm5NIWYYOchchKIgu2Yi9z9McGDS+1e65
         2GeUSVia6BgX0BJg3Ng6hFmGNzoMWaOUKSQPBnp5voIBXps8Hp3rS5M6v2x5sdi9l5q0
         wFbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TbFrSJjR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [2001:41d0:1004:224b::ad])
        by gmr-mx.google.com with ESMTPS id o11-20020ac25e2b000000b0050e258cad8dsi426860lfg.8.2023.12.19.14.30.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:30:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) client-ip=2001:41d0:1004:224b::ad;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 09/21] kasan: save free stack traces for slab mempools
Date: Tue, 19 Dec 2023 23:28:53 +0100
Message-Id: <413a7c7c3344fb56809853339ffaabc9e4905e94.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TbFrSJjR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Make kasan_mempool_poison_object save free stack traces for slab and
kmalloc mempools when the object is freed into the mempool.

Also simplify and rename ____kasan_slab_free to poison_slab_object and
do a few other reability changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  5 +++--
 mm/kasan/common.c     | 20 +++++++++-----------
 2 files changed, 12 insertions(+), 13 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f8ebde384bd7..e636a00e26ba 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -268,8 +268,9 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  * to reuse them instead of freeing them back to the slab allocator (e.g.
  * mempool).
  *
- * This function poisons a slab allocation without initializing its memory and
- * without putting it into the quarantine (for the Generic mode).
+ * This function poisons a slab allocation and saves a free stack trace for it
+ * without initializing the allocation's memory and without putting it into the
+ * quarantine (for the Generic mode).
  *
  * This function also performs checks to detect double-free and invalid-free
  * bugs and reports them. The caller can use the return value of this function
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 3f4a1ed69e03..59146886e57d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -207,8 +207,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
-				unsigned long ip, bool quarantine, bool init)
+static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
+				      unsigned long ip, bool init)
 {
 	void *tagged_object;
 
@@ -221,13 +221,12 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (is_kfence_address(object))
 		return false;
 
-	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
-	    object)) {
+	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
 		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
 	}
 
-	/* RCU slabs could be legally used after free within the RCU period */
+	/* RCU slabs could be legally used after free within the RCU period. */
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
@@ -239,19 +238,18 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
 			KASAN_SLAB_FREE, init);
 
-	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
-		return false;
-
 	if (kasan_stack_collection_enabled())
 		kasan_save_free_info(cache, tagged_object);
 
-	return kasan_quarantine_put(cache, object);
+	return false;
 }
 
 bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 				unsigned long ip, bool init)
 {
-	return ____kasan_slab_free(cache, object, ip, true, init);
+	bool buggy_object = poison_slab_object(cache, object, ip, init);
+
+	return buggy_object ? true : kasan_quarantine_put(cache, object);
 }
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
@@ -472,7 +470,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 	}
 
 	slab = folio_slab(folio);
-	return !____kasan_slab_free(slab->slab_cache, ptr, ip, false, false);
+	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
 }
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/413a7c7c3344fb56809853339ffaabc9e4905e94.1703024586.git.andreyknvl%40google.com.
