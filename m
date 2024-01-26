Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWMKZ6WQMGQE2ECELUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EEC283DCA5
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 15:44:43 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40e435a606asf2750485e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 06:44:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706280282; cv=pass;
        d=google.com; s=arc-20160816;
        b=kxf3vxQ/F3fY/DH5JfrWBu/3rZeut9DQVk4t/uTfJNYeK98D3Z6kjSsSYApq0+7+F5
         WxezqgCeS4PCDvGdwoDlC+GPB/1hbsye6vWdKaWWYfAeWWhXYT1GVdaDSfYXsLFDaIDX
         jLsguVkLcpYX9+aQSt45IQjHLmOR0qiMBjsPAvwvs4aE1fwoXcaNbQ1W3x75dORgKCaY
         1wAW5dudG5HR4iSSS0O6kF8QQf2VsCILTMHfScDK3TuHTpTnDgmIZWAAfT1t49VUYm9n
         5Of+FczwSN4qpyBL2CI3znjqZ1EQXcSAidAmY9HyDVM0rWPudhT9WWdzPCpLok+Y4xtG
         hyCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=l6Wyp2oniqHlVGbDV5eEI8KgzqL4AeAiLWUN4mhhSig=;
        fh=BI3rcWnDvL/7fXSIgr+SN/3NGEHrtjNtnNQ2IyTlgaQ=;
        b=c730J9ceit2lW42oYfsca3SU07wvisjWvgKAa5aovLhUMAuI7mX+IdlBlU2rW9I02o
         LBUNUWMRH/kMznwhiJmjp0eJpyNNr60v8T4W4meB2YMLDwTCpdBIQs+Fav8LQ1o7ELFw
         L0bLbrqBAXZLxfvDCnWQ5MUPG2rDDNfHayIOpZS0cpcdZ8frY3gOoS87PG2IMd0f/nIJ
         Vg7Zw0d/Uo3lA5ijybjO5U1ly1S8viNE0/9LT3JOaQ6H5iDDFPEO2eQ8tDKhfTL4HFKZ
         jhFlQ2p78LWMNU+8RwwBQjkCJlXctDs/ryrulH9y9H1wUptpba3+8aqaW8zIFbavP8Fd
         FqmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gJm37CT1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706280282; x=1706885082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=l6Wyp2oniqHlVGbDV5eEI8KgzqL4AeAiLWUN4mhhSig=;
        b=nYLPYtHCeBQ9v93YVgMgyftVIwbKvF5B+JUmFnVD6ET7jMSpadYSz9AGdNA83/tXRF
         7GJtnhBh0Uk8ghKlnfXl9SENUsWJJwHzP64DGnXBeuS81RvwtDm5ebooPQmiO/xHj4RD
         5BGgPs16jKVWYjtU8UY1jQQ1eySyQVjGOQzZ77L5eyJcy/EcYO0GIWgNq0upRB2nAOuB
         C+o4E6+B75Wq9mvxWTwQBmuqAe2MBuF0FbP0xi4ARBZaaZ0UWTu3H3JYv8QszGUeE+Pw
         7IG0eBHV7SUnEViWdjeeFOz1HasSUTRpuZTXokrSuFeBchgkBfXx6jxCC9jplByiu+PR
         Hd2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706280282; x=1706885082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=l6Wyp2oniqHlVGbDV5eEI8KgzqL4AeAiLWUN4mhhSig=;
        b=ipH1i28GubJuRI507K3k4V+iKHtXP9OXWQ54xlMqKXl9UINBt+ObavhvoV975aAFBd
         5EKlfTAFPBgW8PKtvsaBd/xcJXheOVdb92F9fOhAKgdxn9aFjKoER6CCCcGL+eU3td3o
         Nt7mY2PkGxoRsh6pLPG0/ejE1nUiy4pcfLqUdCzvIPIvyz1LwY6EJs2zzzeSwcLVoccH
         SeT5I8kXuCiAtWkitug4A7CCs4YfVTQSrnWV/+iA82Z1Wlejwa2kbKf1GIEv+ppWdjd8
         IB0kC1e1l1mCjj8wPgPQ357zKCgGe4wy6s9FD/w4f63sL+U9Z37Ov4o2XFXptpEOMLg9
         xEzg==
X-Gm-Message-State: AOJu0YxXyRjvE+GfH+nLK3MhjYkteHmVgzhHS9eSKZYtaxCEfJb4CvJB
	FouC90nzOH3KpNdICNUxBpCIaYxUBiTCJlcG+xkd1zwkXyKXZABm
X-Google-Smtp-Source: AGHT+IEhYd/OwDSZimVRTsiGnSLizw7g9YkzxlCLmV7rMmzGiey3sfWq0r5kpk3X014WgCS2dhQYkw==
X-Received: by 2002:a05:600c:3b96:b0:40e:c7dd:e4c0 with SMTP id n22-20020a05600c3b9600b0040ec7dde4c0mr1967001wms.9.1706280282091;
        Fri, 26 Jan 2024 06:44:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c83:b0:40e:87b7:8332 with SMTP id
 bg3-20020a05600c3c8300b0040e87b78332ls370505wmb.1.-pod-prod-09-eu; Fri, 26
 Jan 2024 06:44:40 -0800 (PST)
X-Received: by 2002:a05:600c:511c:b0:40e:6eef:9d46 with SMTP id o28-20020a05600c511c00b0040e6eef9d46mr2050212wms.20.1706280280189;
        Fri, 26 Jan 2024 06:44:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706280280; cv=none;
        d=google.com; s=arc-20160816;
        b=wJplhha1j7qBWgzlHIi0Cv456b8qNexuIzj9Qys/2zlawAVfNaAoUx837ilR4iuwPz
         Y09SBpnr43O1xSlWsUYb4/58h43/7rZeZ8rh3casLVjZBrR+pM31CbuciKsBPaDOdsNS
         NohRfVumKVdcDclu/unWEs3m1xtE71TJ4I697Zwh22IErUN/XddjtQ3punMfCvZ8TiSa
         sP9MJ45Hqa0SAlZ7/diEGz03NiBwYhZgi9Z5ownIOWKAg/WS8k/v/U7fpjKug0qhTzdO
         yvXFBdd/EfdL38rWFVvh99N7vsU4M7NHuIqKvId1yh1S0oj1nE00yoE76gY8my19TV3I
         jwdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=i5B+fHMvjnJUN3quASTzUIwtKvGYeHenqNIe0ucdsRE=;
        fh=BI3rcWnDvL/7fXSIgr+SN/3NGEHrtjNtnNQ2IyTlgaQ=;
        b=eg1qXiD8dArbHvV47hZrBm/1Ujbahs9bHwvIG+qFnzuytBcbXpBqHFiZh5Z67rRPUJ
         LBcUErDgT1mp+qRmzgepJKuV2Sn8ZBDMGkgBH+y4Zm/67zYWgDmIUNhbEjdTNOLc0qf+
         HAxxmU1/fo5lVVqqDcr0tAA0WryuV3jQs0Xk/IMc8i1OoLW/f/3ZLFkA+7e7+1uNrrgs
         hiwE021zlMG6bM5PbjQCnPcywPtc8jVM/Xf6mw9JVkR/lbWYAZPmw6G7Dvytw+XB2fdm
         vIhJk7koYTXNj9HT7ELRn4BCwZe3UGXRwzXIQW9BYMfqQuDy/4S4/O7uG0zsbe5sDe7V
         hEpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gJm37CT1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id f9-20020a05600c154900b0040ece057ff3si155378wmg.0.2024.01.26.06.44.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jan 2024 06:44:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-33937dd1b43so265719f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 26 Jan 2024 06:44:40 -0800 (PST)
X-Received: by 2002:adf:f10e:0:b0:337:9d3b:c180 with SMTP id r14-20020adff10e000000b003379d3bc180mr1855231wro.4.1706280279513;
        Fri, 26 Jan 2024 06:44:39 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:3837:e733:e624:7fe2])
        by smtp.gmail.com with ESMTPSA id f15-20020a056000036f00b00337d84efaf7sm1415718wrf.74.2024.01.26.06.44.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 26 Jan 2024 06:44:38 -0800 (PST)
Date: Fri, 26 Jan 2024 15:44:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH 2/2] kasan: revert eviction of stack traces in generic
 mode
Message-ID: <ZbPFUXNeENyuwync@elver.google.com>
References: <20240125094815.2041933-1-elver@google.com>
 <20240125094815.2041933-2-elver@google.com>
 <CA+fCnZc6L3t3AdQS1rjFCT0s6RpT+q4Z4GmctOveeaDJW0tBow@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZc6L3t3AdQS1rjFCT0s6RpT+q4Z4GmctOveeaDJW0tBow@mail.gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gJm37CT1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Jan 25, 2024 at 11:36PM +0100, Andrey Konovalov wrote:
[...]
> 
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> 
> But I'm wondering if we should also stop resetting metadata when the
> object is fully freed (from quarantine or bypassing quarantine).
> 
> With stack_depot_put, I had to put the stack handles on free, as
> otherwise we would leak the stack depot references. And I also chose
> to memset meta at that point, as its gets invalid anyway. But without
> stack_depot_put, this is not required.
> 
> Before the stack depot-related changes, the code was inconsistent in
> this regard AFAICS: for quarantine, free meta was marked as invalid
> via KASAN_SLAB_FREE but alloc meta was kept; for no quarantine, both
> alloc and free meta were kept.
> 
> So perhaps we can just keep both metas on full free. I.e. drop both
> kasan_release_object_meta calls. This will go back to the old behavior
> + keeping free meta for the quarantine case (I think there's no harm
> in that). This will give better reporting for uaf-before-realloc bugs.
> 
> WDYT?

Yes, that makes sense.

You mean this on top?

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ad32803e34e9..0577db1d2c62 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -264,12 +264,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (kasan_quarantine_put(cache, object))
 		return true;
 
-	/*
-	 * If the object is not put into quarantine, it will likely be quickly
-	 * reallocated. Thus, release its metadata now.
-	 */
-	kasan_release_object_meta(cache, object);
-
 	/* Let slab put the object onto the freelist. */
 	return false;
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 8bfb52b28c22..fc9cf1860efb 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -510,20 +510,6 @@ static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
 }
 
-void kasan_release_object_meta(struct kmem_cache *cache, const void *object)
-{
-	struct kasan_alloc_meta *alloc_meta;
-	struct kasan_free_meta *free_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		release_alloc_meta(alloc_meta);
-
-	free_meta = kasan_get_free_meta(cache, object);
-	if (free_meta)
-		release_free_meta(object, free_meta);
-}
-
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
 	struct kasan_cache *info = &cache->kasan_info;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 216ae0ef1e4b..fb2b9ac0659a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -390,10 +390,8 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
-void kasan_release_object_meta(struct kmem_cache *cache, const void *object);
 #else
 static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
-static inline void kasan_release_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 3ba02efb952a..a758c2e10703 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -145,8 +145,6 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	void *object = qlink_to_object(qlink, cache);
 	struct kasan_free_meta *free_meta = kasan_get_free_meta(cache, object);
 
-	kasan_release_object_meta(cache, object);
-
 	/*
 	 * If init_on_free is enabled and KASAN's free metadata is stored in
 	 * the object, zero the metadata. Otherwise, the object's memory will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbPFUXNeENyuwync%40elver.google.com.
