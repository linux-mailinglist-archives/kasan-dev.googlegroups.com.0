Return-Path: <kasan-dev+bncBCT4XGV33UIBBP6OU2JQMGQE6ASWTEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BEB115123DF
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 22:27:44 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id f19-20020a0565123b1300b004720c485b64sf1101283lfv.5
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 13:27:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651091264; cv=pass;
        d=google.com; s=arc-20160816;
        b=YccMgMe/zdAgkzQANTglvNIshIcdqVQ7OjqWS4M58cXLXNmZIwJQbGMF+Dd5QOxUVb
         RFShjczU5aY5orQ5t8y3i3UBdY9j1iwOgQl/byUTovbVKiJUCwmckJJvl2ohbSmXBHAj
         5Km8WfUvEIxES4dzJaL463mf2++zjofgjqzPIage5sGMD0cnOzCO75kmDJux85YmqZSA
         appU+q2zBz+Oke5kUJbTBqB9izbu/Ru1zl9mikJ5uLwU3NUAJUwUzCWs0CocIZ9Ev7/X
         cyFOYLddtRDequea45+UQ6ZzFLJYO8TBRp1385KsjsTYwBCBEpZxc4klZY9iM6mr6i+H
         vcHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=NGwmGI1YYJ3Drs6gjEPEg6qTKeaa6zBHgEMXAmuzVb0=;
        b=t0fmomP0omThnunxcGWRnG6TzPC23aIU3DnvKWWJYaF6m88D/eOgO5UlhalPy4BgXq
         jEHc/iEYFFa917ea8JZ1kwRYQXj2UCIw25ytRrYg9lZo4SJIfwNge/dxGrZWTIFY45TM
         KzhG20GPSW1tfp5AiONisemSjDp+i7d83BOL8JlaJq2ySXKFDrhyWlYgDXilmieCAd3p
         KnpFqIdOXdlFNBjepaQwxGC0mk+lVZc0uyXqdWOyF6A2lBA3FNu78o6ppDz00teVmrWm
         toDPqyVGCrhWX1fRpMuanddMqOgePOOG0wUNcfrz3Eedzo89D/jxuBNSEQjAg9rtk64R
         wzfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=A+M6kHjN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NGwmGI1YYJ3Drs6gjEPEg6qTKeaa6zBHgEMXAmuzVb0=;
        b=GXc8ldH6xP5rK9UtzryhB+3KiwyIjLXS0nIT8+u6Ut6RyY//BmLEW1JaVZRjx5vmCZ
         7oWqfKlwR9EPQMxCv8E4EMYwXIQMmJUsT9y735rJhZp1Q56BNJO0R3sPaAccArQt0vyI
         krekxWwPAo7GsqYxTzms7N0Gbjkqe5p6YVN3PfNp6OCsEZWqAYuwtQ9ruUn4Einadgqq
         C1AXtgs/3FS+mLsc6yKIk/o5fhQr3EhF2NpH9vUVET12i6WASqAO7OL2+NHMPk97/MAR
         GqGn4nuY3p1zxZjT7kl62RbxeURktrctKIdxvUJpJ41OKP0WnH5ufmW8JoBqyxFoSBBA
         /5ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NGwmGI1YYJ3Drs6gjEPEg6qTKeaa6zBHgEMXAmuzVb0=;
        b=DMjv7TbYkfLgfD7FlAZ8NIsDbqAfFBbEaqGwRdPy4GA0GSZ4ZH9C5bWZ3AwnUfknLl
         VIXYlTk3cj4LH4Nh7wd67Pkn1Mq77mBcP/eADATF68k7b8gnTlLDzqXYJMSRQT8LHPzt
         JY/2GOfR0ChpC6knNwZxeMhc6/OHFrG8ppySEN7LLU27wZuCSsscdyvg748XGHHgPWJu
         xSlfovjJSvTr/3nMG45gAEstLo6OMBKi0Hb4Bq6iY5u1H4UeU7E1k2OGZuv0WY2MamdZ
         3C9U1PBNap/Yk8U9bxUlZN3vCQa/vIGs2di4MKrET3APYK8A6uYrUhNAPdYkiBj8ZKLo
         iD8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532L/BPLg7pT0g4pBZHmvnX25VRzTbqA7DsB5DjX+2nqSNlMN5IX
	xhZYm0oOrpHHHf46qxdCHMI=
X-Google-Smtp-Source: ABdhPJxldxRj8r9187OZUDIsb8ph0ZlxeqjYSZxud0TNvyghW5PobVXLR5Q/X/EhMEDU619t9cPXtQ==
X-Received: by 2002:a05:651c:248:b0:24f:d8b:113a with SMTP id x8-20020a05651c024800b0024f0d8b113amr13114968ljn.447.1651091263944;
        Wed, 27 Apr 2022 13:27:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2818446lfb.1.gmail; Wed, 27 Apr 2022
 13:27:42 -0700 (PDT)
X-Received: by 2002:a05:6512:5c6:b0:472:9a4:9382 with SMTP id o6-20020a05651205c600b0047209a49382mr10905543lfo.333.1651091262492;
        Wed, 27 Apr 2022 13:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651091262; cv=none;
        d=google.com; s=arc-20160816;
        b=YVi5qb0hGoxVgPkxVjHrHt0WEAUEASlaDqucMqEZFWl/mSyvousSVP4qfQ0e11fg3Y
         ky1lMRJcvjr4KpyW3BjjS6DnBLOaGpyJfQJD1kwrClSd/SbECkxUlva5XGtCdjYHR4rM
         /qy8MhpfSGsywVD0ZNtbPlNfwQUyLnSI8hmi9gvSjsoMFL3H0gw5hT2kaV+y+FqaAKvQ
         Cmzt6MiDQaRNW5xx+IFynQEXh/QNGMWDxnBEr86XDLgvicHaQ+vacpzLyMnmf1fd1VJZ
         JTdTKusTnpC/DrDU8pmyXFOjhVhjCBOo6LD2sxoeYIJ/+8u7NHOTSiH3c36e/Zd6SY5t
         sGYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qHeBKXMy7PyGOmgOW8+SV/ud/uP2aFzkTi95OSB4wGc=;
        b=xOorGSx0r+Zzqbw22ueYPNgG+pJ+XXb7iJmUdMgenWfkhEI99cy0kWwWJ5/qU7+UW7
         0ZXzjTUp7SuYYs/Wm9iVGo8bCt3dxowpKcm8yzMEFFeQ8SqZHqAE7IvTO+JJWNZuGR4H
         3WnK/lOpzGGDLuNBAYMF5OAJtXZEYzVCnbBDsZDcRVcVwBrCeTJGQUtFaK1iY/6HUHs7
         sVYpQMJNpVjYkwTnc9f6Ufthbgsm9PRIt9QgawJZtZ1ycc778ap25JRCTDIccxwFR9vi
         XCPlqbN3e0LiNMb8MAiS4RRxTmgvWfSTeZznmpIGqSGqS2IpQOYT7zhnP8ZAGuv1gvCY
         0SkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=A+M6kHjN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v4-20020a2e7a04000000b0024eee872899si109939ljc.0.2022.04.27.13.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 13:27:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id DDA39B82AB7;
	Wed, 27 Apr 2022 20:27:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82E48C385A7;
	Wed, 27 Apr 2022 20:27:39 +0000 (UTC)
Date: Wed, 27 Apr 2022 13:27:38 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo
 <42.hyeyoo@gmail.com>, Catalin Marinas <catalin.marinas@arm.com>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, Linux Memory Management List
 <linux-mm@kvack.org>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, vbabka@suse.cz, penberg@kernel.org,
 roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, rientjes@google.com,
 Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Eric
 Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v5 2/2] mm: make minimum slab alignment a runtime
 property
Message-Id: <20220427132738.fdca02736b5d067c92185c5b@linux-foundation.org>
In-Reply-To: <20220427195820.1716975-2-pcc@google.com>
References: <20220427195820.1716975-1-pcc@google.com>
	<20220427195820.1716975-2-pcc@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=A+M6kHjN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 27 Apr 2022 12:58:20 -0700 Peter Collingbourne <pcc@google.com> wrote:

> When CONFIG_KASAN_HW_TAGS is enabled we currently increase the minimum
> slab alignment to 16. This happens even if MTE is not supported in
> hardware or disabled via kasan=off, which creates an unnecessary
> memory overhead in those cases. Eliminate this overhead by making
> the minimum slab alignment a runtime property and only aligning to
> 16 if KASAN is enabled at runtime.
> 
> On a DragonBoard 845c (non-MTE hardware) with a kernel built with
> CONFIG_KASAN_HW_TAGS, waiting for quiescence after a full Android
> boot I see the following Slab measurements in /proc/meminfo (median
> of 3 reboots):
> 
> ...
>
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3009,10 +3009,9 @@ static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
>  	objp += obj_offset(cachep);
>  	if (cachep->ctor && cachep->flags & SLAB_POISON)
>  		cachep->ctor(objp);
> -	if (ARCH_SLAB_MINALIGN &&
> -	    ((unsigned long)objp & (ARCH_SLAB_MINALIGN-1))) {
> -		pr_err("0x%px: not aligned to ARCH_SLAB_MINALIGN=%d\n",
> -		       objp, (int)ARCH_SLAB_MINALIGN);
> +	if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
> +		pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
> +		       (int)arch_slab_minalign());

printf/printk know about size_t.  Use %zu, no cast needed.  But...

>  	}
>  	return objp;
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 2b3206a2c3b5..33cc49810a54 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -154,8 +154,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
>  		align = max(align, ralign);
>  	}
>  
> -	if (align < ARCH_SLAB_MINALIGN)
> -		align = ARCH_SLAB_MINALIGN;
> +	align = max_t(size_t, align, arch_slab_minalign());

max_t/min_t are nature's way of telling us "you screwed up the types".

So what type _is_ slab alignment?  size_t seems sensible, but the code
prefers unsigned int.  So how about we stick with that?


This compiles.  Still some max_t's in slob.c because I was too lazy to
go fix the type of ARCH_KMALLOC_MINALIGN.

Shrug, I don't know if we can be bothered.   You decide :)


 arch/arm64/include/asm/cache.h |    2 +-
 include/linux/slab.h           |    2 +-
 mm/slab.c                      |    4 ++--
 mm/slab_common.c               |    2 +-
 mm/slob.c                      |   16 +++++++++++-----
 5 files changed, 16 insertions(+), 10 deletions(-)

--- a/arch/arm64/include/asm/cache.h~mm-make-minimum-slab-alignment-a-runtime-property-fix
+++ a/arch/arm64/include/asm/cache.h
@@ -58,7 +58,7 @@
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
 #elif defined(CONFIG_KASAN_HW_TAGS)
-static inline size_t arch_slab_minalign(void)
+static inline unsigned int arch_slab_minalign(void)
 {
 	return kasan_hw_tags_enabled() ? MTE_GRANULE_SIZE :
 					 __alignof__(unsigned long long);
--- a/include/linux/slab.h~mm-make-minimum-slab-alignment-a-runtime-property-fix
+++ a/include/linux/slab.h
@@ -215,7 +215,7 @@ void kmem_dump_obj(void *object);
  * of two and >= ARCH_SLAB_MINALIGN.
  */
 #ifndef arch_slab_minalign
-static inline size_t arch_slab_minalign(void)
+static inline unsigned int arch_slab_minalign(void)
 {
 	return ARCH_SLAB_MINALIGN;
 }
--- a/mm/slab.c~mm-make-minimum-slab-alignment-a-runtime-property-fix
+++ a/mm/slab.c
@@ -3010,8 +3010,8 @@ static void *cache_alloc_debugcheck_afte
 	if (cachep->ctor && cachep->flags & SLAB_POISON)
 		cachep->ctor(objp);
 	if ((unsigned long)objp & (arch_slab_minalign() - 1)) {
-		pr_err("0x%px: not aligned to arch_slab_minalign()=%d\n", objp,
-		       (int)arch_slab_minalign());
+		pr_err("0x%px: not aligned to arch_slab_minalign()=%u\n", objp,
+		       arch_slab_minalign());
 	}
 	return objp;
 }
--- a/mm/slab_common.c~mm-make-minimum-slab-alignment-a-runtime-property-fix
+++ a/mm/slab_common.c
@@ -154,7 +154,7 @@ static unsigned int calculate_alignment(
 		align = max(align, ralign);
 	}
 
-	align = max_t(size_t, align, arch_slab_minalign());
+	align = max(align, arch_slab_minalign());
 
 	return ALIGN(align, sizeof(void *));
 }
--- a/mm/slob.c~mm-make-minimum-slab-alignment-a-runtime-property-fix
+++ a/mm/slob.c
@@ -478,9 +478,11 @@ static __always_inline void *
 __do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
 {
 	unsigned int *m;
-	int minalign = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
+	unsigned int minalign;
 	void *ret;
 
+	minalign = max_t(unsigned int, ARCH_KMALLOC_MINALIGN,
+			 arch_slab_minalign());
 	gfp &= gfp_allowed_mask;
 
 	might_alloc(gfp);
@@ -493,7 +495,7 @@ __do_kmalloc_node(size_t size, gfp_t gfp
 		 * kmalloc()'d objects.
 		 */
 		if (is_power_of_2(size))
-			align = max(minalign, (int) size);
+			align = max_t(unsigned int, minalign, size);
 
 		if (!size)
 			return ZERO_SIZE_PTR;
@@ -555,8 +557,11 @@ void kfree(const void *block)
 
 	sp = virt_to_folio(block);
 	if (folio_test_slab(sp)) {
-		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
+		unsigned int align = max_t(unsigned int,
+					   ARCH_KMALLOC_MINALIGN,
+					   arch_slab_minalign());
 		unsigned int *m = (unsigned int *)(block - align);
+
 		slob_free(m, *m + align);
 	} else {
 		unsigned int order = folio_order(sp);
@@ -573,7 +578,7 @@ EXPORT_SYMBOL(kfree);
 size_t __ksize(const void *block)
 {
 	struct folio *folio;
-	int align;
+	unsigned int align;
 	unsigned int *m;
 
 	BUG_ON(!block);
@@ -584,7 +589,8 @@ size_t __ksize(const void *block)
 	if (unlikely(!folio_test_slab(folio)))
 		return folio_size(folio);
 
-	align = max_t(size_t, ARCH_KMALLOC_MINALIGN, arch_slab_minalign());
+	align = max_t(unsigned int, ARCH_KMALLOC_MINALIGN,
+		      arch_slab_minalign());
 	m = (unsigned int *)(block - align);
 	return SLOB_UNITS(*m) * SLOB_UNIT;
 }
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427132738.fdca02736b5d067c92185c5b%40linux-foundation.org.
