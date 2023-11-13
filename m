Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCPLZGVAMGQEOXXMUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A5257EA373
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:19 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5091368e043sf5040039e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902859; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQqJkeWgnIEgA3At+3+xpHWl220Y+49iRCq6xoPIE4sY2fP4usLbrukUsg1gQQiGUX
         d6ZfCZ5Uttt1JnWFJBqiAL424kdglO/0KL89ZDd0nY7/SKABUW+8SE1ZqY2n7AvjDuyR
         zxijcSnBW9ANexHNtGE4R1kZM/ywCbmT66BNwf3ScY3BESnf3il/Cg6yKFWCmkStGEcd
         DnXLQsdFASWM/RidxuHz4dZ9QbIeerfOvmta3CQ1900kYMqr3TLsc/PsYDuvdJAoqQsT
         9QwmdvbZi1uB2eaMe49b4hFLDUzsa54r0W8BQBRqzR2hgMLL6gX39wA8P1LwvwRGMm46
         ioxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=guLoqFrvRONxdUbqjnfkcsZAxKEDpAkwhhPBTn3pnz4=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=jrH/5XItJq0F7RrI4z6kQF6fOFjjZIU5J9u3gaaa675Y7yCg2ie9/ja7GiPeFkofNo
         zj0tHQkvbfalRZZt2bVBDlIZEeX7Y4KfKGB/gazmWIZvqqOJjb+6kb/9GLjFjlkrbLEY
         356J7+aJN1soW5YQfdzc5YXK8hRTuNlEdxHP8xh5g/1Z+sHMDtQQGr1A7uJNHyB+DQAp
         c7dbemPR9a4M6du576297FZcJ+cPERrmraLTD88wIMGuwnhEDxNqUuVCb2DBXx28mYVU
         I2dG638LJqpmd/9+HnUrUVU9o4+AwdtGdYIfOt/fleIngHc61xyfghL7Z23YbEwsiSQ1
         Ifkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Cb9azOi+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YZzAxb8Q;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902859; x=1700507659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=guLoqFrvRONxdUbqjnfkcsZAxKEDpAkwhhPBTn3pnz4=;
        b=YpR6+v4Mw5I88SHLF1TCMVGVYM/Nn5Fwle3TyjBnD6xHoT3ETOEljF029eP1MvDL8E
         8yrTe3OIsSGlYdB/qSG/aXYZUxGAsw+2JWaSNdO/x4yYoYfg0Tz+fFMvsjAb3Z3p1ixQ
         A3Q/kFjAeZ47R5zTOUPmecrwCW88RRzr0qRmsALY3ygFnhSwKyYk3Y7PP+j+kCso/oGS
         +wgVnebhy9WcYROwuelin0xwvcM3g5qi/qYt+QiVtvsz8xMxPKt54DA5MV0WNgD96BkA
         eGfi71b5eHol7RdFlF9X0RVlQap49q+IeD1b3sNjibEoGXLzneBpEreno+fPZTOXGcrl
         BM8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902859; x=1700507659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=guLoqFrvRONxdUbqjnfkcsZAxKEDpAkwhhPBTn3pnz4=;
        b=h8VruzXu04iEkxbTrASb8v01TU8iq9YqXmaMqrieJBogJwZH2liIbw151Uqg1tTlj9
         vMzUGDvulNEmFoE1vFtDRPgVzsk26X+mHLwdLqGEqQWMKQJRQCwwE64prlDJZ66r3FWb
         pZ1bSSyT1GEeIv4PqR2bxoeN5K1GZp2LWcoofvUxa8l7AszyDQ0XzxTrk/3D21WQx30x
         lrb92bOyxDzDU6C34OIpoU/Ejbcmjgn8wSQ0Ov+ko9I2ezlkZAzcMd9gCe5pKsO+5XeI
         A9gI63N+Om8jg1+yVYj95dvEB8B12kXZQ9snrPMzU5xYKmBxwj/z0kB1+gvODHNCQalF
         elfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzFOXRfYdOZ/Yncmdz6JDrZeVgMyGCFXWgW6bZjsU0ruN62zMQP
	zKMTs/cu+Gtm63pLK2M8vjU=
X-Google-Smtp-Source: AGHT+IFoNbO3BenR/u3ng86vI9kekRXTrbWax+thHsZKmIOzYM2pBaSKvWt/CMbl587equQy1ppMzQ==
X-Received: by 2002:a19:6510:0:b0:50a:73f0:8535 with SMTP id z16-20020a196510000000b0050a73f08535mr5265289lfb.1.1699902858072;
        Mon, 13 Nov 2023 11:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e01:b0:507:b8d5:d6d3 with SMTP id
 i1-20020a0565123e0100b00507b8d5d6d3ls183764lfv.0.-pod-prod-09-eu; Mon, 13 Nov
 2023 11:14:16 -0800 (PST)
X-Received: by 2002:a2e:6e12:0:b0:2c8:35fb:af08 with SMTP id j18-20020a2e6e12000000b002c835fbaf08mr155874ljc.30.1699902856109;
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902856; cv=none;
        d=google.com; s=arc-20160816;
        b=YU4Cf4Z/vAt9oxkQNdHUhdmntV9OVE7zDIIzWy5CxamnslSyFuuWY6fJtynKaZ1k2L
         Ccsw/sotVbxtiMt8+rBlSu3jl79/t1CzV3i8RaNs5ecwSildVHyIOmg6gzTENYoFbbWV
         GejCHo8DTxJyNbKA5Or0V3PKR37M48TdvhH5yv/DrZ5qQhlqtLh364eLC6nJTQTp8KHu
         frfS4SDRhw9hgPak2P7mF3dOFW4iRfBtSDYCiRzVrpKY3SemN8FSxJkGm+2FUfqt3rHG
         nr8eAjLY33hBSBCVpIA3QKHRO4c21YC9yvPNU1CWB7zVRxMWaoowzRfW1rJJvG8w9WAJ
         krSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=Yc0ydpEKadjGMZmR6AOilRcjjCaikOgVLMhJfLa5KNY=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=JucFvzj0zhukYLqxU1IvPrOK/cvOVaZjpsjcCpPz15GeyZ0t0zcCBvwOe6OsqB2LNZ
         FuTKIs91OZW1aYcGwHhP6THz2IvZJy8Ud5NTvGFH1G7NXav/26sxXkUWhW+1geD+Lxjo
         8Cvd7Pk1k+1xbc7Hn68l+qfbq/dHRu45hhWRilDQZyeFSdPKiakeFopLJunWH3S1WU4F
         u85t2DFR2doBUUr0vY5t7cdUyqSLFknlrxRSkkcsTKXvzHNNrAhT0rExgAS3m7p3CrLh
         AiOQg6yHPsTPtkYjVCen2Au6UftEaUdtN9xcjpRe+9NCqW96KylQwryywIyIA4VdsLek
         4egA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Cb9azOi+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YZzAxb8Q;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id c7-20020a2e9d87000000b002c29b97d5f2si250460ljj.1.2023.11.13.11.14.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:16 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 893D52193C;
	Mon, 13 Nov 2023 19:14:15 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3EDFC13398;
	Mon, 13 Nov 2023 19:14:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id eOW7Dod1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:15 +0000
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
Subject: [PATCH 18/20] mm/slub: remove slab_alloc() and __kmem_cache_alloc_lru() wrappers
Date: Mon, 13 Nov 2023 20:13:59 +0100
Message-ID: <20231113191340.17482-40-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Cb9azOi+;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=YZzAxb8Q;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

slab_alloc() is a thin wrapper around slab_alloc_node() with only one
caller.  Replace with direct call of slab_alloc_node().
__kmem_cache_alloc_lru() itself is a thin wrapper with two callers,
so replace it with direct calls of slab_alloc_node() and
trace_kmem_cache_alloc().

This also makes sure _RET_IP_ has always the expected value and not
depending on inlining decisions.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 28 +++++++++++-----------------
 1 file changed, 11 insertions(+), 17 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b44243e7cc5e..d2363b91d55c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3821,39 +3821,33 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	return object;
 }
 
-static __fastpath_inline void *slab_alloc(struct kmem_cache *s, struct list_lru *lru,
-		gfp_t gfpflags, unsigned long addr, size_t orig_size)
-{
-	return slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, addr, orig_size);
-}
-
-static __fastpath_inline
-void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
-			     gfp_t gfpflags)
+void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 {
-	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
+	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE, _RET_IP_,
+				    s->object_size);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
 
 	return ret;
 }
-
-void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
-{
-	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
-}
 EXPORT_SYMBOL(kmem_cache_alloc);
 
 void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 			   gfp_t gfpflags)
 {
-	return __kmem_cache_alloc_lru(s, lru, gfpflags);
+	void *ret = slab_alloc_node(s, lru, gfpflags, NUMA_NO_NODE, _RET_IP_,
+				    s->object_size);
+
+	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
+
+	return ret;
 }
 EXPORT_SYMBOL(kmem_cache_alloc_lru);
 
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
-	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
+	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_,
+				    s->object_size);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, node);
 
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-40-vbabka%40suse.cz.
