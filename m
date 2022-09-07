Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB7GP4KMAMGQEFO4MBCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id CBAB65B0642
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 16:17:38 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id m12-20020a056e021c2c00b002ed9189c241sf12189084ilh.15
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 07:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662560252; cv=pass;
        d=google.com; s=arc-20160816;
        b=p7vv5UxTARWvT/0UIQoGzJH6pWAWEHs5irKGEuRlzDVeFNYTe8e7XZIdp6cpPXBtqx
         VPZRU2PNnKW66Q7SNRAtYwSmxEY5KF94gZm6LIBJ0IEJ1CUbbwuVHnNkNEME/mA5RAfZ
         qXUZmrrf8q8tk1rLvxKuFG4Xa+TuTiJ7qk0J9i5RSVSX/hgGrAXp2iuFkq0qQHiA2i/M
         6FNUsM1PnQ25lslfYjIbjBS+PS8OBvCctmlez7amuEsd0bZ6kFDkvWCtN7YVCg3AZI7m
         MbDf8Vo5NokqMxONBqKGVFbmsZ8P8/Jh1fLTLziTI9kQrqdkveXzYKHfWJ6VFKAwv40+
         DQ1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=pPV/ULK99skyNmXJ7Id2TtZ5OXqRt4061Fop9MZjODs=;
        b=Wg0RtAyyYTqGTHZhqooGiOVMHFRE/xTu45B8Hi/Zth46ICnFNoOpVIQMyXmWYJ97Ie
         P+qCCZSL4skroXF2v9pQHBI9HIkcWxPst7dydWD4AHK3lEp4f7vxC7dMbaERHENaOIHz
         bEWmdOyhbswbFXvtKNcAy7WQ1+zlLDjIw/Yyrb6gq4S2gX3WgPoPDSx9F+X0aik+9+uS
         2NPWrueHTlMUNhnxNr38keaIga8GLXYMDJ2DE48Qc4kRIJ/u+VxCA13n3wr498XM8Myy
         EAflgvVuBvLQOX0j7QCQLyT0r8ddIFHqy889BkhPbIqyauagpdCy+Fl8kXMsptldLQlk
         Blsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Gpa7p7Jh;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=pPV/ULK99skyNmXJ7Id2TtZ5OXqRt4061Fop9MZjODs=;
        b=kwLH7vmUmXvJgirdSZ/c24HEp6xUKykp1PWPHLacW67/5/12C5ywI6AbaSQyVO7lRV
         sEQGJgdxMzDyglZFFXOwpkSd1Mh8UxzYoL2AcVCL6Y91wHTR9qRdtb+YGJ4O+KRK/BGh
         5G6lg6On9usgZ0acpJR4eTkgZ5FgOlEkfnXkk6gdbKHXkPLfbfXureKboqJV8fls6NRm
         LOw++2H5Oyu6pjUf3G/ShvnfJqlfkWZIP7HfeldZejTXrxH0O2c72gKDq9lTDPq2DGLO
         1FK8YEj2PPAicPTsdUA16ghGP0Em+ij4wOb6oV2sbYpa6qR0iWSUFld1jNYzLVIRgDL6
         HXTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=pPV/ULK99skyNmXJ7Id2TtZ5OXqRt4061Fop9MZjODs=;
        b=kMOLr7dypWOncdBDwgPVIxtGehyH67CzF8SxUOUj6Jki2F8f2qBPy6lF5M/KV14nNe
         PUA+1f99/VRpREAuVeK0Iaw2+reSUG8v2tEUf89NTv/hpK6G9aIFGclB4xYo7F96B4oM
         /RnHi4Pgp3Npe3v88sCRJQ0Ak8BvwU9KVUmbtgq24APALldXSQBswtMuSesOMJosJzEI
         qOe11pwa4pbDTrkp0pFNQ6YQz4lCUpJLW2e+VJ7Fwbsql/jsTWOl+idJoz9TZlqA3qWp
         o2eIepXIHUSlMLZBAW/ABw/05e2XyCIwizufH0gipGwJkq0PCiyMOU38DGj4mw6Ae+iU
         yQxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=pPV/ULK99skyNmXJ7Id2TtZ5OXqRt4061Fop9MZjODs=;
        b=KFixk3R3Fgh+biXuBFhiOoZFIAP72TTtqVz90AHuaZVzp2YZ5NBYv0rW7UUW3Jbh1R
         QtvTwaWaZuJkftkHvoQoVO12m406SdzH0oc52Pquo7hFYC1Ouxt9mtEyqWlZ++yjNKH3
         9RGCH393Ib9EoyUVOqBPdbTqn9Th5fO3duNhH6zgHfZin6Ss66hn0nR7PylmrrCs4gd6
         ++namfj7DyEQEAoIipksdZLyekKH/CJ0fxICsfSjZdGWQRr0nOPS99m9Fg7vAAeJZhfM
         QUaOUi29wAHMsEqFYKLE+dq4BbfUjaHA8yZUm8e/e7syvdc0LO8rZxt9ZLo/nJo5F8fo
         aZ4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2ZH3fgT3ARClli/6CfCEls9BXOB74Ynfz7xfKrrPoyuUord7pO
	1KoGCr9rIfzpEcVIuvNlpUM=
X-Google-Smtp-Source: AA6agR6FWHvyAVp5WyKMeQY7mKMCf04RGB8rm2SqwEKmxlBYuCJUrrlpob2OBEfQl5r77knJBim+bQ==
X-Received: by 2002:a02:93e1:0:b0:33f:1c51:3fee with SMTP id z88-20020a0293e1000000b0033f1c513feemr2103765jah.171.1662560252305;
        Wed, 07 Sep 2022 07:17:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:95cb:0:b0:34c:dcb:a180 with SMTP id b69-20020a0295cb000000b0034c0dcba180ls3853187jai.4.-pod-prod-gmail;
 Wed, 07 Sep 2022 07:17:31 -0700 (PDT)
X-Received: by 2002:a05:6638:1396:b0:357:148d:8705 with SMTP id w22-20020a056638139600b00357148d8705mr1547194jad.61.1662560251734;
        Wed, 07 Sep 2022 07:17:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662560251; cv=none;
        d=google.com; s=arc-20160816;
        b=IVaUHFIdB0e/Fe+/+beBpQegiXZ8DnIiOCBt4Asf5byPapr7TalGCFrF+MHzSq4IiL
         ozzIxK2RiA/g2r1dHkEjlbjDA6bIDDPZrE9UcFSxgLDqghQSEK2lWpkAjDnYuKzjSuVh
         JMCXe8YN+ok4zzGJBNo8vssRXbfOlbIi38TWwSbE/ruU5DAfSYlJ7WFvvP156Px6qkTc
         1pdz12cqLC54s6bxMY99yawwc7kBat/bZWqhUVJmIuvQwT7O6DmSk255AzxRfF0zB/A9
         /dJgsAZykSnhIUdk6/5+Y5oZDLgVuUEmEUw4RESu1cUKnyywWeSzYwPEnxqKSHsmkZ1A
         VxMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SWMuG44udYJwJObiClAKE7nLIWqZqCJNqUvyZYZ3slI=;
        b=LniuptueF/Lvdzk9IZ1u/0kWqpMf8p9J36IY3eCRoBMS6AfVIPAGeGCUSiViOUqZGR
         raRBGIlDGjH3L58wHrKGTOi9+3hVxk/eldDd8QuoCMLlohodkz4EPR8304NLba1VZrJY
         uMKH4ndINB2yA22TumvyB4PwR6e8I1hrlOzKpBWVhHgqMxE5ntOGgkqCKmXAKUPgEVUc
         Rleer2EqawXOiZ5+rUwcPJTz1g68SQ4jIF2WvoWmHraGAwHa3ahQP8yUSiY+k7DIs/Co
         zeJTR5XRDCEvco5aFklsgXEHtTGEWyTYJt++QMBXuVws1AExTW1sSTy4ZTuCFKU1fRzT
         IdzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Gpa7p7Jh;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id y10-20020a056602178a00b0068aba53032bsi1545059iox.0.2022.09.07.07.17.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 07:17:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id jm11so14643979plb.13
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 07:17:31 -0700 (PDT)
X-Received: by 2002:a17:90a:4d8d:b0:1fa:9cc6:3408 with SMTP id m13-20020a17090a4d8d00b001fa9cc63408mr4106124pjh.245.1662560250867;
        Wed, 07 Sep 2022 07:17:30 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id o15-20020a170902d4cf00b00173411a4385sm2001483plg.43.2022.09.07.07.17.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Sep 2022 07:17:29 -0700 (PDT)
Date: Wed, 7 Sep 2022 23:17:22 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Robin Murphy <robin.murphy@arm.com>,
	John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH v5 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Yxin8k0BFijbkGK0@hyeyoo>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-2-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220907071023.3838692-2-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Gpa7p7Jh;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Sep 07, 2022 at 03:10:20PM +0800, Feng Tang wrote:
> kmalloc's API family is critical for mm, with one nature that it will
> round up the request size to a fixed one (mostly power of 2). Say
> when user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
> could be allocated, so in worst case, there is around 50% memory
> space waste.
> 
> The wastage is not a big issue for requests that get allocated/freed
> quickly, but may cause problems with objects that have longer life
> time.
> 
> We've met a kernel boot OOM panic (v5.10), and from the dumped slab
> info:
> 
>     [   26.062145] kmalloc-2k            814056KB     814056KB
> 
> >From debug we found there are huge number of 'struct iova_magazine',
> whose size is 1032 bytes (1024 + 8), so each allocation will waste
> 1016 bytes. Though the issue was solved by giving the right (bigger)
> size of RAM, it is still nice to optimize the size (either use a
> kmalloc friendly size or create a dedicated slab for it).
> 
> And from lkml archive, there was another crash kernel OOM case [1]
> back in 2019, which seems to be related with the similar slab waste
> situation, as the log is similar:
> 
>     [    4.332648] iommu: Adding device 0000:20:02.0 to group 16
>     [    4.338946] swapper/0 invoked oom-killer: gfp_mask=0x6040c0(GFP_KERNEL|__GFP_COMP), nodemask=(null), order=0, oom_score_adj=0
>     ...
>     [    4.857565] kmalloc-2048           59164KB      59164KB
> 
> The crash kernel only has 256M memory, and 59M is pretty big here.
> (Note: the related code has been changed and optimised in recent
> kernel [2], these logs are just picked to demo the problem, also
> a patch changing its size to 1024 bytes has been merged)
> 
> So add an way to track each kmalloc's memory waste info, and
> leverage the existing SLUB debug framework (specifically
> SLUB_STORE_USER) to show its call stack of original allocation,
> so that user can evaluate the waste situation, identify some hot
> spots and optimize accordingly, for a better utilization of memory.
> 
> The waste info is integrated into existing interface:
> '/sys/kernel/debug/slab/kmalloc-xx/alloc_traces', one example of
> 'kmalloc-4k' after boot is:
> 
>  126 ixgbe_alloc_q_vector+0xbe/0x830 [ixgbe] waste=233856/1856 age=280763/281414/282065 pid=1330 cpus=32 nodes=1
>      __kmem_cache_alloc_node+0x11f/0x4e0
>      __kmalloc_node+0x4e/0x140
>      ixgbe_alloc_q_vector+0xbe/0x830 [ixgbe]
>      ixgbe_init_interrupt_scheme+0x2ae/0xc90 [ixgbe]
>      ixgbe_probe+0x165f/0x1d20 [ixgbe]
>      local_pci_probe+0x78/0xc0
>      work_for_cpu_fn+0x26/0x40
>      ...
> 
> which means in 'kmalloc-4k' slab, there are 126 requests of
> 2240 bytes which got a 4KB space (wasting 1856 bytes each
> and 233856 bytes in total), from ixgbe_alloc_q_vector().
> 
> And when system starts some real workload like multiple docker
> instances, there could are more severe waste.
> 
> [1]. https://lkml.org/lkml/2019/8/12/266
> [2]. https://lore.kernel.org/lkml/2920df89-9975-5785-f79b-257d3052dfaf@huawei.com/
> 
> [Thanks Hyeonggon for pointing out several bugs about sorting/format]
> [Thanks Vlastimil for suggesting way to reduce memory usage of
>  orig_size and keep it only for kmalloc objects]
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Cc: Robin Murphy <robin.murphy@arm.com>
> Cc: John Garry <john.garry@huawei.com>
> Cc: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  Documentation/mm/slub.rst |  33 +++++---
>  include/linux/slab.h      |   2 +
>  mm/slub.c                 | 156 ++++++++++++++++++++++++++++----------
>  3 files changed, 141 insertions(+), 50 deletions(-)
> 

Looks good to me.
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> diff --git a/Documentation/mm/slub.rst b/Documentation/mm/slub.rst

[...]

> +/* Structure holding parameters for get_partial() call chain */
> +struct partial_context {
> +	struct slab **slab;
> +	gfp_t flags;
> +	int orig_size;

Nit: unsigned int orig_size

Thanks!

> +};
> +



>  static inline bool kmem_cache_debug(struct kmem_cache *s)
>  {
>  	return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
>  }
>  
> +static inline bool slub_debug_orig_size(struct kmem_cache *s)
> +{
> +	return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> +			(s->flags & SLAB_KMALLOC));
> +}
> +
>  void *fixup_red_left(struct kmem_cache *s, void *p)
>  {
>  	if (kmem_cache_debug_flags(s, SLAB_RED_ZONE))
> @@ -785,6 +798,39 @@ static void print_slab_info(const struct slab *slab)
>  	       folio_flags(folio, 0));
>  }
>  
> +/*
> + * kmalloc caches has fixed sizes (mostly power of 2), and kmalloc() API
> + * family will round up the real request size to these fixed ones, so
> + * there could be an extra area than what is requested. Save the original
> + * request size in the meta data area, for better debug and sanity check.
> + */
> +static inline void set_orig_size(struct kmem_cache *s,
> +				void *object, unsigned int orig_size)
> +{
> +	void *p = kasan_reset_tag(object);
> +
> +	if (!slub_debug_orig_size(s))
> +		return;
> +
> +	p += get_info_end(s);
> +	p += sizeof(struct track) * 2;
> +
> +	*(unsigned int *)p = orig_size;
> +}
> +
> +static unsigned int get_orig_size(struct kmem_cache *s, void *object)
> +{
> +	void *p = kasan_reset_tag(object);
> +
> +	if (!slub_debug_orig_size(s))
> +		return s->object_size;
> +
> +	p += get_info_end(s);
> +	p += sizeof(struct track) * 2;
> +
> +	return *(unsigned int *)p;
> +}
> +
>  static void slab_bug(struct kmem_cache *s, char *fmt, ...)
>  {
>  	struct va_format vaf;
> @@ -844,6 +890,9 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
>  	if (s->flags & SLAB_STORE_USER)
>  		off += 2 * sizeof(struct track);
>  
> +	if (slub_debug_orig_size(s))
> +		off += sizeof(unsigned int);
> +
>  	off += kasan_metadata_size(s);
>  
>  	if (off != size_from_object(s))
> @@ -977,7 +1026,8 @@ static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
>   *
>   * 	A. Free pointer (if we cannot overwrite object on free)
>   * 	B. Tracking data for SLAB_STORE_USER
> - *	C. Padding to reach required alignment boundary or at minimum
> + *	C. Original request size for kmalloc object (SLAB_STORE_USER enabled)
> + *	D. Padding to reach required alignment boundary or at minimum
>   * 		one word if debugging is on to be able to detect writes
>   * 		before the word boundary.
>   *
> @@ -995,10 +1045,14 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
>  {
>  	unsigned long off = get_info_end(s);	/* The end of info */
>  
> -	if (s->flags & SLAB_STORE_USER)
> +	if (s->flags & SLAB_STORE_USER) {
>  		/* We also have user information there */
>  		off += 2 * sizeof(struct track);
>  
> +		if (s->flags & SLAB_KMALLOC)
> +			off += sizeof(unsigned int);
> +	}
> +
>  	off += kasan_metadata_size(s);
>  
>  	if (size_from_object(s) == off)
> @@ -1293,7 +1347,7 @@ static inline int alloc_consistency_checks(struct kmem_cache *s,
>  }
>  
>  static noinline int alloc_debug_processing(struct kmem_cache *s,
> -					struct slab *slab, void *object)
> +			struct slab *slab, void *object, int orig_size)
>  {
>  	if (s->flags & SLAB_CONSISTENCY_CHECKS) {
>  		if (!alloc_consistency_checks(s, slab, object))
> @@ -1302,6 +1356,7 @@ static noinline int alloc_debug_processing(struct kmem_cache *s,
>  
>  	/* Success. Perform special debug activities for allocs */
>  	trace(s, slab, object, 1);
> +	set_orig_size(s, object, orig_size);
>  	init_object(s, object, SLUB_RED_ACTIVE);
>  	return 1;
>  
> @@ -1570,7 +1625,10 @@ static inline
>  void setup_slab_debug(struct kmem_cache *s, struct slab *slab, void *addr) {}
>  
>  static inline int alloc_debug_processing(struct kmem_cache *s,
> -	struct slab *slab, void *object) { return 0; }
> +	struct slab *slab, void *object, int orig_size) { return 0; }
> +
> +static inline void set_orig_size(struct kmem_cache *s,
> +	void *object, unsigned int orig_size) {}
>  
>  static inline void free_debug_processing(
>  	struct kmem_cache *s, struct slab *slab,
> @@ -1999,7 +2057,7 @@ static inline void remove_partial(struct kmem_cache_node *n,
>   * it to full list if it was the last free object.
>   */
>  static void *alloc_single_from_partial(struct kmem_cache *s,
> -		struct kmem_cache_node *n, struct slab *slab)
> +		struct kmem_cache_node *n, struct slab *slab, int orig_size)
>  {
>  	void *object;
>  
> @@ -2009,7 +2067,7 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
>  	slab->freelist = get_freepointer(s, object);
>  	slab->inuse++;
>  
> -	if (!alloc_debug_processing(s, slab, object)) {
> +	if (!alloc_debug_processing(s, slab, object, orig_size)) {
>  		remove_partial(n, slab);
>  		return NULL;
>  	}
> @@ -2028,7 +2086,7 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
>   * and put the slab to the partial (or full) list.
>   */
>  static void *alloc_single_from_new_slab(struct kmem_cache *s,
> -					struct slab *slab)
> +					struct slab *slab, int orig_size)
>  {
>  	int nid = slab_nid(slab);
>  	struct kmem_cache_node *n = get_node(s, nid);
> @@ -2040,7 +2098,7 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s,
>  	slab->freelist = get_freepointer(s, object);
>  	slab->inuse = 1;
>  
> -	if (!alloc_debug_processing(s, slab, object))
> +	if (!alloc_debug_processing(s, slab, object, orig_size))
>  		/*
>  		 * It's not really expected that this would fail on a
>  		 * freshly allocated slab, but a concurrent memory
> @@ -2118,7 +2176,7 @@ static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>   * Try to allocate a partial slab from a specific node.
>   */
>  static void *get_partial_node(struct kmem_cache *s, struct kmem_cache_node *n,
> -			      struct slab **ret_slab, gfp_t gfpflags)
> +			      struct partial_context *pc)
>  {
>  	struct slab *slab, *slab2;
>  	void *object = NULL;
> @@ -2138,11 +2196,12 @@ static void *get_partial_node(struct kmem_cache *s, struct kmem_cache_node *n,
>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
>  		void *t;
>  
> -		if (!pfmemalloc_match(slab, gfpflags))
> +		if (!pfmemalloc_match(slab, pc->flags))
>  			continue;
>  
>  		if (kmem_cache_debug(s)) {
> -			object = alloc_single_from_partial(s, n, slab);
> +			object = alloc_single_from_partial(s, n, slab,
> +							pc->orig_size);
>  			if (object)
>  				break;
>  			continue;
> @@ -2153,7 +2212,7 @@ static void *get_partial_node(struct kmem_cache *s, struct kmem_cache_node *n,
>  			break;
>  
>  		if (!object) {
> -			*ret_slab = slab;
> +			*pc->slab = slab;
>  			stat(s, ALLOC_FROM_PARTIAL);
>  			object = t;
>  		} else {
> @@ -2177,14 +2236,13 @@ static void *get_partial_node(struct kmem_cache *s, struct kmem_cache_node *n,
>  /*
>   * Get a slab from somewhere. Search in increasing NUMA distances.
>   */
> -static void *get_any_partial(struct kmem_cache *s, gfp_t flags,
> -			     struct slab **ret_slab)
> +static void *get_any_partial(struct kmem_cache *s, struct partial_context *pc)
>  {
>  #ifdef CONFIG_NUMA
>  	struct zonelist *zonelist;
>  	struct zoneref *z;
>  	struct zone *zone;
> -	enum zone_type highest_zoneidx = gfp_zone(flags);
> +	enum zone_type highest_zoneidx = gfp_zone(pc->flags);
>  	void *object;
>  	unsigned int cpuset_mems_cookie;
>  
> @@ -2212,15 +2270,15 @@ static void *get_any_partial(struct kmem_cache *s, gfp_t flags,
>  
>  	do {
>  		cpuset_mems_cookie = read_mems_allowed_begin();
> -		zonelist = node_zonelist(mempolicy_slab_node(), flags);
> +		zonelist = node_zonelist(mempolicy_slab_node(), pc->flags);
>  		for_each_zone_zonelist(zone, z, zonelist, highest_zoneidx) {
>  			struct kmem_cache_node *n;
>  
>  			n = get_node(s, zone_to_nid(zone));
>  
> -			if (n && cpuset_zone_allowed(zone, flags) &&
> +			if (n && cpuset_zone_allowed(zone, pc->flags) &&
>  					n->nr_partial > s->min_partial) {
> -				object = get_partial_node(s, n, ret_slab, flags);
> +				object = get_partial_node(s, n, pc);
>  				if (object) {
>  					/*
>  					 * Don't check read_mems_allowed_retry()
> @@ -2241,8 +2299,7 @@ static void *get_any_partial(struct kmem_cache *s, gfp_t flags,
>  /*
>   * Get a partial slab, lock it and return it.
>   */
> -static void *get_partial(struct kmem_cache *s, gfp_t flags, int node,
> -			 struct slab **ret_slab)
> +static void *get_partial(struct kmem_cache *s, int node, struct partial_context *pc)
>  {
>  	void *object;
>  	int searchnode = node;
> @@ -2250,11 +2307,11 @@ static void *get_partial(struct kmem_cache *s, gfp_t flags, int node,
>  	if (node == NUMA_NO_NODE)
>  		searchnode = numa_mem_id();
>  
> -	object = get_partial_node(s, get_node(s, searchnode), ret_slab, flags);
> +	object = get_partial_node(s, get_node(s, searchnode), pc);
>  	if (object || node != NUMA_NO_NODE)
>  		return object;
>  
> -	return get_any_partial(s, flags, ret_slab);
> +	return get_any_partial(s, pc);
>  }
>  
>  #ifdef CONFIG_PREEMPTION
> @@ -2974,11 +3031,12 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
>   * already disabled (which is the case for bulk allocation).
>   */
>  static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
> -			  unsigned long addr, struct kmem_cache_cpu *c)
> +			  unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
>  {
>  	void *freelist;
>  	struct slab *slab;
>  	unsigned long flags;
> +	struct partial_context pc;
>  
>  	stat(s, ALLOC_SLOWPATH);
>  
> @@ -3092,7 +3150,10 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  
>  new_objects:
>  
> -	freelist = get_partial(s, gfpflags, node, &slab);
> +	pc.flags = gfpflags;
> +	pc.slab = &slab;
> +	pc.orig_size = orig_size;
> +	freelist = get_partial(s, node, &pc);
>  	if (freelist)
>  		goto check_new_slab;
>  
> @@ -3108,7 +3169,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  	stat(s, ALLOC_SLAB);
>  
>  	if (kmem_cache_debug(s)) {
> -		freelist = alloc_single_from_new_slab(s, slab);
> +		freelist = alloc_single_from_new_slab(s, slab, orig_size);
>  
>  		if (unlikely(!freelist))
>  			goto new_objects;
> @@ -3140,6 +3201,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  		 */
>  		if (s->flags & SLAB_STORE_USER)
>  			set_track(s, freelist, TRACK_ALLOC, addr);
> +
>  		return freelist;
>  	}
>  
> @@ -3182,7 +3244,7 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>   * pointer.
>   */
>  static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
> -			  unsigned long addr, struct kmem_cache_cpu *c)
> +			  unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
>  {
>  	void *p;
>  
> @@ -3195,7 +3257,7 @@ static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  	c = slub_get_cpu_ptr(s->cpu_slab);
>  #endif
>  
> -	p = ___slab_alloc(s, gfpflags, node, addr, c);
> +	p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
>  #ifdef CONFIG_PREEMPT_COUNT
>  	slub_put_cpu_ptr(s->cpu_slab);
>  #endif
> @@ -3280,7 +3342,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>  
>  	if (!USE_LOCKLESS_FAST_PATH() ||
>  	    unlikely(!object || !slab || !node_match(slab, node))) {
> -		object = __slab_alloc(s, gfpflags, node, addr, c);
> +		object = __slab_alloc(s, gfpflags, node, addr, c, orig_size);
>  	} else {
>  		void *next_object = get_freepointer_safe(s, object);
>  
> @@ -3747,7 +3809,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  			 * of re-populating per CPU c->freelist
>  			 */
>  			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE,
> -					    _RET_IP_, c);
> +					    _RET_IP_, c, s->object_size);
>  			if (unlikely(!p[i]))
>  				goto error;
>  
> @@ -4150,12 +4212,17 @@ static int calculate_sizes(struct kmem_cache *s)
>  	}
>  
>  #ifdef CONFIG_SLUB_DEBUG
> -	if (flags & SLAB_STORE_USER)
> +	if (flags & SLAB_STORE_USER) {
>  		/*
>  		 * Need to store information about allocs and frees after
>  		 * the object.
>  		 */
>  		size += 2 * sizeof(struct track);
> +
> +		/* Save the original kmalloc request size */
> +		if (flags & SLAB_KMALLOC)
> +			size += sizeof(unsigned int);
> +	}
>  #endif
>  
>  	kasan_cache_create(s, &size, &s->flags);
> @@ -4770,7 +4837,7 @@ void __init kmem_cache_init(void)
>  
>  	/* Now we can use the kmem_cache to allocate kmalloc slabs */
>  	setup_kmalloc_cache_index_table();
> -	create_kmalloc_caches(0);
> +	create_kmalloc_caches(SLAB_KMALLOC);
>  
>  	/* Setup random freelists for each cache */
>  	init_freelist_randomization();
> @@ -4937,6 +5004,7 @@ struct location {
>  	depot_stack_handle_t handle;
>  	unsigned long count;
>  	unsigned long addr;
> +	unsigned long waste;
>  	long long sum_time;
>  	long min_time;
>  	long max_time;
> @@ -4983,13 +5051,15 @@ static int alloc_loc_track(struct loc_track *t, unsigned long max, gfp_t flags)
>  }
>  
>  static int add_location(struct loc_track *t, struct kmem_cache *s,
> -				const struct track *track)
> +				const struct track *track,
> +				unsigned int orig_size)
>  {
>  	long start, end, pos;
>  	struct location *l;
> -	unsigned long caddr, chandle;
> +	unsigned long caddr, chandle, cwaste;
>  	unsigned long age = jiffies - track->when;
>  	depot_stack_handle_t handle = 0;
> +	unsigned int waste = s->object_size - orig_size;
>  
>  #ifdef CONFIG_STACKDEPOT
>  	handle = READ_ONCE(track->handle);
> @@ -5007,11 +5077,13 @@ static int add_location(struct loc_track *t, struct kmem_cache *s,
>  		if (pos == end)
>  			break;
>  
> -		caddr = t->loc[pos].addr;
> -		chandle = t->loc[pos].handle;
> -		if ((track->addr == caddr) && (handle == chandle)) {
> +		l = &t->loc[pos];
> +		caddr = l->addr;
> +		chandle = l->handle;
> +		cwaste = l->waste;
> +		if ((track->addr == caddr) && (handle == chandle) &&
> +			(waste == cwaste)) {
>  
> -			l = &t->loc[pos];
>  			l->count++;
>  			if (track->when) {
>  				l->sum_time += age;
> @@ -5036,6 +5108,9 @@ static int add_location(struct loc_track *t, struct kmem_cache *s,
>  			end = pos;
>  		else if (track->addr == caddr && handle < chandle)
>  			end = pos;
> +		else if (track->addr == caddr && handle == chandle &&
> +				waste < cwaste)
> +			end = pos;
>  		else
>  			start = pos;
>  	}
> @@ -5059,6 +5134,7 @@ static int add_location(struct loc_track *t, struct kmem_cache *s,
>  	l->min_pid = track->pid;
>  	l->max_pid = track->pid;
>  	l->handle = handle;
> +	l->waste = waste;
>  	cpumask_clear(to_cpumask(l->cpus));
>  	cpumask_set_cpu(track->cpu, to_cpumask(l->cpus));
>  	nodes_clear(l->nodes);
> @@ -5077,7 +5153,7 @@ static void process_slab(struct loc_track *t, struct kmem_cache *s,
>  
>  	for_each_object(p, s, addr, slab->objects)
>  		if (!test_bit(__obj_to_index(s, addr, p), obj_map))
> -			add_location(t, s, get_track(s, p, alloc));
> +			add_location(t, s, get_track(s, p, alloc), get_orig_size(s, p));
>  }
>  #endif  /* CONFIG_DEBUG_FS   */
>  #endif	/* CONFIG_SLUB_DEBUG */
> @@ -5942,6 +6018,10 @@ static int slab_debugfs_show(struct seq_file *seq, void *v)
>  		else
>  			seq_puts(seq, "<not-available>");
>  
> +		if (l->waste)
> +			seq_printf(seq, " waste=%lu/%lu",
> +				l->count * l->waste, l->waste);
> +
>  		if (l->sum_time != l->min_time) {
>  			seq_printf(seq, " age=%ld/%llu/%ld",
>  				l->min_time, div_u64(l->sum_time, l->count),
> -- 
> 2.34.1
>

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxin8k0BFijbkGK0%40hyeyoo.
