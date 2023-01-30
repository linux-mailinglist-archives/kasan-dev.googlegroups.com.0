Return-Path: <kasan-dev+bncBAABBLW34CPAMGQEFTIND4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB011681BC5
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:50:54 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id l8-20020a05600c1d0800b003dc25f6bb5dsf8208062wms.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:50:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111854; cv=pass;
        d=google.com; s=arc-20160816;
        b=bKcAa73jQfx396tUY1NF4K0W2WHzlIzhX+vofGj0NMwgbW1Pt/3srrrscYQWHm2pYl
         grr11qPyt5iKB57ljEz7cWyvT2Y2nfkBZx9uBs73wlC0lG2sIYW/eT9R6uMxrrJFmGnQ
         Q67uLHz6+otAyFHoABoUlbvGj5cMHToqjSPU78zvg7zmltZXWNomWZhxl5+JmtGonlzm
         VJqTSVAz6c5X7xOpQwzlPVEZz8XJwgEsp3x0uxAJ+KFZRXFMPEWcxbqbVMrXBJsxtHZ/
         WPnc8aRNsnkt2GUZtBxtXaxB2J9p3DgBMMUBq4eyRr31ftI9niAlzIuFYRMqHxLdjUbH
         1Nrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9Hxsdviv9W/Nu8t5vngABPe+watcvODmLotwO/8G434=;
        b=glY+L8rZIh7OTUtCfC7y9wJaxE+vAodEVqrMnedcBlHfEgiepO/B/Tm1VP+E1KCB6h
         wliT2s1oFyS70ZvKAFmD23ow2kAIK4bKEQJaNaW/ur8xYFZbwjXqkqWEfGHTPmFWD8LP
         o4YbJS2jfhnSGYPSxP/D6+ZOyjZUOfGfTIaoaFxbcTcCXnmC07zCmMp//IBFQ96KK4sK
         n6j8a2Jj4NLjgtPdLI80tuLOvTtxjVRZ4nhvSIvBPMJkSHBNwGKmu9p9zSJV8B7pYaGn
         IoYWlcFoIzhqpuhchLxLSMknwLn81IjoowT+l+aOOkn3f6FCRqz2RZk8oc5qQRZ+NkAv
         G8IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tFaC4h3n;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.127 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Hxsdviv9W/Nu8t5vngABPe+watcvODmLotwO/8G434=;
        b=Wa6u1fzWMxNFSNnNU2LUBVp1wqDUcmM9X80hjDcPGXvGo2qFx4SKi+s8mIv54G7bsj
         KSh1BfxppMf6WZPb5PhRdJ4nh9Yy9KqzhzMpeRJDah1z13mMddL4uhtcO5dRtIeAwAsP
         gmzfp2y1YFLUInmpwFsqfSyLzpznkpxBzUulcnkMTUNX+igeiLR+zGpk2aSc9aFtyVc7
         8B56OnZrfD2kppQR+t6vJX6w1X4u0JBUAy1d9qJzOfrrYTZ0OP/yrnPJ//bst00cI0vw
         WFozLALFq3iT6zWoEwNC4WQ/QjmUmybv1UfAnndY5oyYUHiUJSvNfFS2P61AEhg2KeSA
         yotg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Hxsdviv9W/Nu8t5vngABPe+watcvODmLotwO/8G434=;
        b=HDFFbIJ98HYglTbTB7T8z9cmXs/3rM170AwT5HLsdDN+83G9RRi11udQssSIbT7BEd
         dCF/gFywddORFkh680oKRKf3NGR2CgTIPcnPuCbQv5L3BPrGCH9v4Z0tboZft//SOx5z
         fN6EaYEXutTplEvkcIwMJi/IF9YS9vxA+Esgjv9IowPUUVzfaQgKIKdJwbCKec6dIahR
         rdX/k2Hf+lHp6+TaSw49UEi3P3oi+oIpSbWKotqk21qNezAcbvoov9Thq/ad7ByIjJ2i
         AvARYSIINQgkqRvPdnUnftt4Y9HNeAzS+BSBuQebvz5Mi21OOo81pDzMRiVG16Cy3qgc
         5MoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUZw6bg3rDyy1ec7oKr3NQIaTmAEWlmIDW5b3Bo3GDu9PScbVz9
	sEfgJg3aEGvWDR2smJSnP30=
X-Google-Smtp-Source: AK7set9zyLqTcK5LWRlN8YU8HSYjL/CWvlHp+GmUDR35xMX8RGQTlBqcVSTVKTTj/cr8fDKjg5vZKA==
X-Received: by 2002:a05:6000:1a52:b0:2bf:b92d:8108 with SMTP id t18-20020a0560001a5200b002bfb92d8108mr657526wry.245.1675111854377;
        Mon, 30 Jan 2023 12:50:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3509:b0:3cf:72dc:df8 with SMTP id
 h9-20020a05600c350900b003cf72dc0df8ls3367412wmq.0.-pod-canary-gmail; Mon, 30
 Jan 2023 12:50:53 -0800 (PST)
X-Received: by 2002:a05:600c:4f06:b0:3dc:5321:8457 with SMTP id l6-20020a05600c4f0600b003dc53218457mr872138wmq.5.1675111853579;
        Mon, 30 Jan 2023 12:50:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111853; cv=none;
        d=google.com; s=arc-20160816;
        b=VQRoANt9WqE2G0hfmh/k4eIDtjJ+6HK52fc0uFhhWfj0oR1Ifl7A8E0AX86BfawJVn
         G/J9c7p2ykmDxN593AM3Mh3TNeaOr1ma1wY5KCThUDaFCpZaF+PRz5UJgk2GHJHPuDYt
         JBZxtvhwDoJFpIhOxReFnXKW9oNAIOG7On2swsCzLuwcU6lq3iWCLl4k2319fmIROQAn
         M6DteY2oz7A9iYxDNj1Cwl9PdML+FIhE1UdQ7Y9/3J8iZ/Mfjiq33v8vSrEu27PaF+wV
         Eb2rg2QpTJZFJDJgqkgrmsIRadaLOHWYhQQhHYSBis8up6kbdYIvoudtL67ReTRtOgTu
         aljQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=57d540mJERXvBQP3H394VQ1KkYAn0jgbzOXp+cklDfk=;
        b=nEnOcDAGCxRBFVBZGHW3TVmYvx6d09a5afc1UPsmeQq94+K4DtRHaK7oryxq1IyMNP
         zY/qajCMRwZpiidsGrnCE4szju6cKdqH8MUvObswLH/C0RKUNq90BSk4RSRszkRxhOL5
         e13Qc0UGib4QXEqWcJBvFClMoB/kPEG2oXDIYTqbpDUobsmADsxoDX1+Qcnkrmie5WC+
         JFEQ/vhE/mwtiq8R+D8n1pJVwaw3QPymHNxlTXlWO/n6/UiQCTUPViKORhcoRMOW5jYW
         5CrPRG0fURLwFnZCXItMEBf8DXJ3KXx+pp8XObH9+Puahd2HHIsA2Cc4DEDrBw9fQJEX
         wcUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tFaC4h3n;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.127 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-127.mta0.migadu.com (out-127.mta0.migadu.com. [91.218.175.127])
        by gmr-mx.google.com with ESMTPS id ch17-20020a5d5d11000000b002bddc018216si619280wrb.1.2023.01.30.12.50.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:50:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.127 as permitted sender) client-ip=91.218.175.127;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 10/18] lib/stackdepot: rename init_stack_slab
Date: Mon, 30 Jan 2023 21:49:34 +0100
Message-Id: <b756e381a3526c6e59cb68c53ac0f172ddd22776.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tFaC4h3n;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.127
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Rename init_stack_slab to depot_init_slab to align the name with
depot_alloc_stack.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index cddcf029e307..69b9316b0d4b 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -220,7 +220,7 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-static bool init_stack_slab(void **prealloc)
+static bool depot_init_slab(void **prealloc)
 {
 	if (!*prealloc)
 		return false;
@@ -268,12 +268,12 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		/*
 		 * smp_store_release() here pairs with smp_load_acquire() from
 		 * |next_slab_inited| in stack_depot_save() and
-		 * init_stack_slab().
+		 * depot_init_slab().
 		 */
 		if (depot_index + 1 < STACK_ALLOC_MAX_SLABS)
 			smp_store_release(&next_slab_inited, 0);
 	}
-	init_stack_slab(prealloc);
+	depot_init_slab(prealloc);
 	if (stack_slabs[depot_index] == NULL)
 		return NULL;
 
@@ -402,7 +402,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * lock.
 	 *
 	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_slab_inited| in depot_alloc_stack() and init_stack_slab().
+	 * |next_slab_inited| in depot_alloc_stack() and depot_init_slab().
 	 */
 	if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
 		/*
@@ -438,7 +438,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * We didn't need to store this stack trace, but let's keep
 		 * the preallocated memory for the future.
 		 */
-		WARN_ON(!init_stack_slab(&prealloc));
+		WARN_ON(!depot_init_slab(&prealloc));
 	}
 
 	raw_spin_unlock_irqrestore(&depot_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b756e381a3526c6e59cb68c53ac0f172ddd22776.1675111415.git.andreyknvl%40google.com.
