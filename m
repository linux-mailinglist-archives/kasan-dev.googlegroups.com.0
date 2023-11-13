Return-Path: <kasan-dev+bncBDXYDPH3S4OBBB7LZGVAMGQE7SJXD7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 49DB97EA36B
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:16 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2c5194d4e98sf42762881fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902855; cv=pass;
        d=google.com; s=arc-20160816;
        b=U0EX0DME+jxDPmd2MnA4gRR1xNhorHuh6z3PrgUWyl1rcjHikqz3MnFveUd+j6zUNA
         1uzsU+8PClLnZUJyF8lDEd/wYzypwtseJ6+KxyLe19dR+2sTzVpRJUM87kybGetbTNzS
         APedc+rn20KR2u2NrYgqYLze6GywxqcvGoCgwiuWahhKFuC94jgaxzo52TOp2d9S9Yb+
         QP22+GCvjywKaS188VtDD2zWsxY4oVIKsWNp/lj0nodZRpmKb4tjh5XmacFCVmuglzIz
         9erqJLg3HYrP30rQ4ZBe9oP2LjDZR9+vGq0cF6wmacnaVbj6GZZ6pqzeJ7Ki+lGEFfV6
         uFMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xcGARQ3WtekQRrF7DNZJLiUf7gtvfW4cwPeLNlT+AaI=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=JnWI6No5T1xKtJYodGvZZJoTVjMndQXhFQNF256TXZNy3vxxcbYHyLt//NsexlAmbg
         nZgG3anq37HEccH2ZJieLnoPGED011fRVl8tZpyoI3DjWs2SAvyGtSHTsJ9y82zYKXXS
         t70SP+cNOIBjY4coKeLjkOwnA3txk4MBY0yVFqdwFteo2JgbLLcquTQXr6066paduc+L
         XxQW3gXNeNWybmF3yc4v/1ba3qj3JDJ9NwlIzFTOREzmspG6FGe4w2MxJ6U5vKjF6I9u
         OFbn4BRqSYoGOE2YaHvORd8kl/GnFXGGLUWAneORklDjPS5KGYA7UR1EJVz00+xTVjSz
         bgCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=X1zStBcu;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902855; x=1700507655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xcGARQ3WtekQRrF7DNZJLiUf7gtvfW4cwPeLNlT+AaI=;
        b=YYeSMvmNWLsfm7JpaJ++4WJ4eA3RIM57hbvuOBjfCt7/G3R7iH5DuOx/rXmS3QXjFU
         OqVp6NTalTa4rFRQqAjua44OjQpMJZmGGTuC+fysp4pOtIgb2tYaSklsIFnEGWPfrXlQ
         LZXQ4ZRSesA+HDTBQgbOxRswSSfhAM42gwM8WTFHaKNbOn6k7vULb2Q5G+3rvYPftzzG
         LCesswuEfDF07fTaqPMz85NAGm3Npt4ZtFmOTR812D4NwP6OxevwcgyXI1bX7JrbDhhU
         4OP8MC+VsRh8fTtAt/3RjEx1bSIhnNCvcxSDI5uiymbJ2UGDrLVwFcmaO8W/4WsYntd4
         Q//Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902855; x=1700507655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xcGARQ3WtekQRrF7DNZJLiUf7gtvfW4cwPeLNlT+AaI=;
        b=vmqunVgw+n1kl/3WpK6o1bFQ4VKLWXrE0/d/8ZhR++sQaLs+1S1c4TeSIMMWY0uBfS
         x3E4feG416vGRRsCazRj1smFVctNx6y9gvFUL2kHcIMUO64yNrvC7MaoeFpvUR5Dp0Jy
         IzQ9m/+UUSvYnJTPdl8SJoNCEe17zFzlrWSGWn2jVG2yu9FcNmdPWWrvTVWu73WbMAN5
         P8bS4U/bDJQOSZqpnmNd9w3gZKls6V/o0XIFxxc50NAMccT8AqHEZ8JHGIjazqcJTqd8
         fNDHWivIyV7eBuggNYN4FnWWD/4u963Uty0So1pgLGcH/nFUNOdxJtplmsvJmlCT4Ui3
         VWNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YztXgk+yqG+uyMe1uqUNgiiW2LRIW8MLV0v0lLSqZvqqouus+Mz
	usGPciHWTC9IAbg1+6wZEqA=
X-Google-Smtp-Source: AGHT+IFOEgbU7JfXczGdxEnRJ9tBhTVyxSutYmjp0xMUwsiCxtBKZv4pP72C5FueucbWZEfiICp7pw==
X-Received: by 2002:a2e:9bcb:0:b0:2c8:323b:9207 with SMTP id w11-20020a2e9bcb000000b002c8323b9207mr155172ljj.11.1699902855413;
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b0e8:0:b0:2bf:bbc4:45ed with SMTP id h8-20020a2eb0e8000000b002bfbbc445edls853175ljl.2.-pod-prod-06-eu;
 Mon, 13 Nov 2023 11:14:13 -0800 (PST)
X-Received: by 2002:a05:651c:104f:b0:2c6:e46e:9849 with SMTP id x15-20020a05651c104f00b002c6e46e9849mr148944ljm.15.1699902853505;
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902853; cv=none;
        d=google.com; s=arc-20160816;
        b=dlPfQTB4cExbniVT6+Woj9YwRyuEDU8eQZ9N1QwsHDo4WMLw3UPFXG15L3PVX7zY9J
         DGOQcrkh+L3dJ5SDmbajfJJXAWFf+GEGonwj/Y152k8ZkuGOb1yex+Sf8Hzmks84099l
         fCFKcsAe8IltDOHBatJoEmjBZJ7Xn2bT6fnfuHYxwK/vMHe1FNuIAot3GsLepTHIXzsM
         5OOsuvXMFegJNW6YZA86exc/phESGXljsvwyK14NnuW5VWzEXtiqjCXZjbKZC/kb9j/t
         EWNmpKRkQTBnPwdT6Wz5+5drRQibos7iT5sof1LqUjpF48qku1T3DC1c9XVRLszptbTv
         +/MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=0Pl3hBxZTqS7t6wbtH0Om8A7aicbQgQuPXay4H9gSiM=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=oCRoptMZpKPWWAYLa+Ga3AwmRqcutz72KoNci/putl9899p24FPgokb0Lcrvm89fkW
         VlyCSZz1eArU/Z+mp+hEcOGrBo4lxzCo61uRlqM3VzD3VaYNaKvveSu9qpPumrJsNDlX
         ge38pa3JoEHNSTnbdD9nYS2VdtEuq9d5vvrjuH1DKvYEpcjbfKfNOzeY8aH3l8ex4axy
         zT5fXiQKqsaX8aeXsGKEaZq6mt8YX72O80Y37A7QNeEkBL4ywZzXovL7zJt+oLgLGgQj
         2D2NG+1WeNTbiEfD+zdpQP6em8B9HoYye1A1yTJHoEjLH+S4Ycs8iSAXNisokypwH/xz
         mAeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=X1zStBcu;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id ay2-20020a05600c1e0200b003fe2591111dsi708582wmb.1.2023.11.13.11.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 37E401F88D;
	Mon, 13 Nov 2023 19:14:13 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DCED513907;
	Mon, 13 Nov 2023 19:14:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id OPcxNYR1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:12 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 11/20] mm/slab: consolidate includes in the internal mm/slab.h
Date: Mon, 13 Nov 2023 20:13:52 +0100
Message-ID: <20231113191340.17482-33-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=X1zStBcu;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The #include's are scattered at several places of the file, but it does
not seem this is needed to prevent any include loops (anymore?) so
consolidate them at the top. Also move the misplaced kmem_cache_init()
declaration away from the top.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h | 28 ++++++++++++++--------------
 1 file changed, 14 insertions(+), 14 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 6e76216ac74e..c278f8b15251 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -1,10 +1,22 @@
 /* SPDX-License-Identifier: GPL-2.0 */
 #ifndef MM_SLAB_H
 #define MM_SLAB_H
+
+#include <linux/reciprocal_div.h>
+#include <linux/list_lru.h>
+#include <linux/local_lock.h>
+#include <linux/random.h>
+#include <linux/kobject.h>
+#include <linux/sched/mm.h>
+#include <linux/memcontrol.h>
+#include <linux/fault-inject.h>
+#include <linux/kmemleak.h>
+#include <linux/kfence.h>
+#include <linux/kasan.h>
+
 /*
  * Internal slab definitions
  */
-void __init kmem_cache_init(void);
 
 #ifdef CONFIG_64BIT
 # ifdef system_has_cmpxchg128
@@ -209,11 +221,6 @@ static inline size_t slab_size(const struct slab *slab)
 	return PAGE_SIZE << slab_order(slab);
 }
 
-#include <linux/kfence.h>
-#include <linux/kobject.h>
-#include <linux/reciprocal_div.h>
-#include <linux/local_lock.h>
-
 #ifdef CONFIG_SLUB_CPU_PARTIAL
 #define slub_percpu_partial(c)		((c)->partial)
 
@@ -346,14 +353,6 @@ static inline int objs_per_slab(const struct kmem_cache *cache,
 	return slab->objects;
 }
 
-#include <linux/memcontrol.h>
-#include <linux/fault-inject.h>
-#include <linux/kasan.h>
-#include <linux/kmemleak.h>
-#include <linux/random.h>
-#include <linux/sched/mm.h>
-#include <linux/list_lru.h>
-
 /*
  * State of the slab allocator.
  *
@@ -404,6 +403,7 @@ gfp_t kmalloc_fix_flags(gfp_t flags);
 /* Functions provided by the slab allocators */
 int __kmem_cache_create(struct kmem_cache *, slab_flags_t flags);
 
+void __init kmem_cache_init(void);
 void __init new_kmalloc_cache(int idx, enum kmalloc_cache_type type,
 			      slab_flags_t flags);
 extern void create_boot_cache(struct kmem_cache *, const char *name,
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-33-vbabka%40suse.cz.
