Return-Path: <kasan-dev+bncBDN7L7O25EIBBQGSQCMQMGQEMKLUCZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id F3B125B6831
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 08:54:56 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id r23-20020adfb1d7000000b002286358a916sf2770044wra.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 23:54:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663052096; cv=pass;
        d=google.com; s=arc-20160816;
        b=XMRbF2FspYV7VNJbm+SWIY860+mHeEENj3NMpO3ciQsMRVF/THy3WSdG3kHJWTLhf3
         +VNyoBiL4JAwz9da4zUllifl038/5B+YconWPpa7t+TI3K1Z+FMXQoaneX7IW8AlaAdx
         sOLTw7qzRi95VLyCkKN2plb7GB3swthzSdze9xPDDf6WyrwuRU1A3kCCAAr9I4HFbwkT
         gaiLEjfluVqbASKYmfpHAtV+Nwqx14vnFBzYMhfvcGqo79e48JstU3+DhOaU7GmhpmXN
         5d5JFbqz3/KLcim7vwWu1Kxro8aEqLUEm1XQyBeDSr9SdnQ3f2rh4XhTBjdkE1Fjt9wg
         txJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1tyzxgNGboWv72HxShv4DGKOjWsaIt3rp6xuXMRE+88=;
        b=jK3yB7+04TXivMLbCdfo5/eaBzKAmEm6q5a+3Z5nsYXBNcR8/yfKdjGb1VTBJYB+KN
         GEIAu2x2zK0m0OZ1NOXvJCLpoxrOn/Grg6tlsj+GQvVpI5DOXGePzK4krAn7rkF0rmZp
         wDW790pCjrO0/DhBYg2NtUwojCyb+GVuGsSkIiuwatrFLqfe5a9v5l0BZdatiEr5ABrd
         Z0sRLVAsi4Y4kjq8M+cSgd4MCvy3lXsmHX5+tePvVAagYXCavrFD9MO7RpSzEQkNy4+k
         QVJDzXHpQUX01sdtUMASYzSPxDAnna7LlcSRRK+g1NMDnu1tTOevXyydZuOJMoe/gg6H
         RmhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Hd0aQ5hB;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=1tyzxgNGboWv72HxShv4DGKOjWsaIt3rp6xuXMRE+88=;
        b=ScPmMzn6uA0rvMykNqakeiCoBf2R9nZKVA+h8y6KqOeFpgWLE3wcy+d69yUdqkfBGG
         VU6c3ibsJsrZA8v4BOLZjSPYxOoQZqGTFEnasHYUAtVpjbd5SIhyWZnF93RS5idKB/0d
         Pvme6fWOJA7gPyaMPuFgZwvTMj5c775eIH4hOPbVfdcf1VpKfTaUZZ2pDRDqx7K9Qtgm
         7SBO3f5AJ5lfvfYugqCpgeFOz/96rQCvHYwD2Cjy7jd4dkyo8J28InkWtwzMoikl1IAa
         QLV0I7KJjfYtK46W5f2MGthem/QzHfexamTzyZI6XyW0L8QxkkuuNp1av7v9alYn0W+G
         k5qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=1tyzxgNGboWv72HxShv4DGKOjWsaIt3rp6xuXMRE+88=;
        b=ZsqiTB1SBclGtkNNZsfbvhxCGy1v66YQgxaENIJiCwgpaKFE7JfNhRts++NRKPxLKi
         THtIYh382LQ15t64AJ33xj0CwGdww3sYIX9Qdoky/lCMkw8YmWCO/IEHcy+826x8Kr4h
         5NUHZFyhIplBLjrJGngfWx3HsskSDJ2stVgLf+Z71M9+z+VdkbkqmTh9XReP+JIoAvG3
         Ky8J2VxRpn4NdHtjbrethKONoSo5mEu37EiFYyoaBFgPAee5V4FapEf4zNgL6YCX5qwI
         p81qWlt5HcGkb5n4T5QMCyUgVqYazYjkuAs9dU+Swr4biDbcZSqZvuR2qOaaeJqP09mJ
         LUUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1WNjewyXe+0+rzVqyKBoSWXM+ZBVr851/ElQIru7lpOq+6O8bl
	Gc5zFdZSWFNQmKbgJMMHYac=
X-Google-Smtp-Source: AA6agR6nYqmKtHaaN7KESlprGkp4ZARc0CmcP/VLM85pRzgx6Pv/AtLrW+nUJd3lY0kJV8aOePKF3A==
X-Received: by 2002:a5d:6504:0:b0:228:c94b:a5bb with SMTP id x4-20020a5d6504000000b00228c94ba5bbmr16565741wru.623.1663052096726;
        Mon, 12 Sep 2022 23:54:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4602:0:b0:3b3:2bde:e52d with SMTP id t2-20020a1c4602000000b003b32bdee52dls60820wma.1.-pod-preprod-gmail;
 Mon, 12 Sep 2022 23:54:55 -0700 (PDT)
X-Received: by 2002:a7b:cb91:0:b0:3b4:75b9:5a4b with SMTP id m17-20020a7bcb91000000b003b475b95a4bmr1177911wmi.33.1663052095747;
        Mon, 12 Sep 2022 23:54:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663052095; cv=none;
        d=google.com; s=arc-20160816;
        b=edkekmcJy/1/lPfR9DDT3TYqC2B3dd0wyErH6v+VJeMT7wsF2JbBVUZlkBovZva9Eu
         fTFgkyOmrQZ9uPpF6dc7YNYfLPAHJluaQTOLeOPNT0Y+gEORWcW4nz/nBfJJOz8EChK3
         jZL7j9OQqOjPoFFMkwQ/SoYDG63M4mGo+AaXp38eijrtEeXluRFrma72uMYDXtfvfRpG
         AThTpP9S9hGz8bP1vfLrGjS1W5L30XE9x4SDVyKZTQswIhQSuAD/Dc/wPd3GCEoZkGWf
         PAbRFB7CSFZu1znd8/fQr8sPMhFilwtGFzTKWIqKQ+MYDxmASzn6fkXg5APczCICJSc+
         mbXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WygvbcU+57VUtDe0idm3K8vvy6IHtOeCKf1SmJPZZYI=;
        b=cuUrwsOO8BVQ3f5N+dgtDx6gdI9hyvSDxxWX80PsvpzJCTmvpT0UxzXvdTD1+xEVGQ
         3BfwWRCEU3hULM28IAHYVjNuDDwV6Xla2nmAbhSbUySwpVscWEH14/j57thJkitskoOB
         F4ZFm1oWXWu+8s9aEWupHHj+7NNMhWLBz/U1NxpY1JrJcFuBxIaueBUKH3FPirMC2yoJ
         YfrYmeWlYmvZ0hPgV/pH1mz3QWgAF6AZpC5MiRnVq5aXOn2rI5w/Co4t492QaLB3250n
         pKgv95kxSx/RRdAGTHWufHjXd/duA/f5tcozJcw0rcaPaINARlT/5gHcTsnftgiWwpys
         6qCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Hd0aQ5hB;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si13124wma.1.2022.09.12.23.54.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Sep 2022 23:54:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10468"; a="285079389"
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="285079389"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Sep 2022 23:54:54 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="861440725"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga006.fm.intel.com with ESMTP; 12 Sep 2022 23:54:51 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v6 2/4] mm/slub: only zero the requested size of buffer for kzalloc
Date: Tue, 13 Sep 2022 14:54:21 +0800
Message-Id: <20220913065423.520159-3-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220913065423.520159-1-feng.tang@intel.com>
References: <20220913065423.520159-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Hd0aQ5hB;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

kzalloc/kmalloc will round up the request size to a fixed size
(mostly power of 2), so the allocated memory could be more than
requested. Currently kzalloc family APIs will zero all the
allocated memory.

To detect out-of-bound usage of the extra allocated memory, only
zero the requested part, so that sanity check could be added to
the extra space later.

Performance wise, smaller zeroing length also brings shorter
execution time, as shown from test data on various server/desktop
platforms.

For kzalloc users who will call ksize() later and utilize this
extra space, please be aware that the space is not zeroed any
more.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slab.c |  7 ++++---
 mm/slab.h |  5 +++--
 mm/slub.c | 10 +++++++---
 3 files changed, 14 insertions(+), 8 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index a5486ff8362a..4594de0e3d6b 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3253,7 +3253,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
 	init = slab_want_init_on_alloc(flags, cachep);
 
 out:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
+				cachep->object_size);
 	return objp;
 }
 
@@ -3506,13 +3507,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled section.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+			slab_want_init_on_alloc(flags, s), s->object_size);
 	/* FIXME: Trace call missing. Christoph would like a bulk variant */
 	return size;
 error:
 	local_irq_enable();
 	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
diff --git a/mm/slab.h b/mm/slab.h
index d0ef9dd44b71..3cf5adf63f48 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -730,7 +730,8 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
 
 static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init)
+					size_t size, void **p, bool init,
+					unsigned int orig_size)
 {
 	size_t i;
 
@@ -746,7 +747,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	for (i = 0; i < size; i++) {
 		p[i] = kasan_slab_alloc(s, p[i], flags, init);
 		if (p[i] && init && !kasan_has_integrated_init())
-			memset(p[i], 0, s->object_size);
+			memset(p[i], 0, orig_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
 	}
diff --git a/mm/slub.c b/mm/slub.c
index c8ba16b3a4db..6f823e99d8b4 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3376,7 +3376,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
 	init = slab_want_init_on_alloc(gfpflags, s);
 
 out:
-	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
+	/*
+	 * When init equals 'true', like for kzalloc() family, only
+	 * @orig_size bytes will be zeroed instead of s->object_size
+	 */
+	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
 
 	return object;
 }
@@ -3833,11 +3837,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled fastpath loop.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+			slab_want_init_on_alloc(flags, s), s->object_size);
 	return i;
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220913065423.520159-3-feng.tang%40intel.com.
