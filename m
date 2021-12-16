Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBJFJ5WGQMGQEFT5KFGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 48AA0477538
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 16:00:54 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id bo6-20020a17090b090600b001b103b70a1esf3519751pjb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 07:00:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639666853; cv=pass;
        d=google.com; s=arc-20160816;
        b=OrArNRBVo+4FTBgFLXMj+ZY5PXPeHGtyrNI/6juW3pk48VpdmKnB6vVrNAvrwouOfK
         0884tYoI3iuOLCo3EJ2PNjUYOh/023OEXxi/YZW+BQxKQX53A/LgpG1OYoYUjKrWvy32
         6GfX5P53WWX9XVnpZDabNXzU1f68cMU+e5eN166uB9iID4Rd1GIj3Su9YNuCeRHvcyvt
         XWc5A3Go2OQVpGDv4XQT1/R15cJutExNofi/iFUa+Vl6gW84fv0UyN3VGStRErFQYZ9P
         Cxn+OXeM3gbF0uxlfNPjA9/851Fur95Ovq6jXMlp0BfT1O7TPNVWf+9jYmqTnb3Z2ZWL
         EJAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=iBDbNwth7tZnyCTbeW1JvL77/ZTnC1NIjqhvw0pOmPI=;
        b=VFi4chbtzbdgJqqbMVJi8Y3poBGOB6UYATZI2V52Ii8obKnUqvZS0oUD2OjZWknw/R
         TfeyK+G6PkqGzRVUKCmhvhug8g2IxkGQDW7dRdHC/zZGWBI5pfbdLec5ErnfsprH9+Ez
         8cxcNUeH9SjSYG41T4ZkrFJj/+aS5CoyfgH1KZ/SGcqmn1ph4Nza1GmFCq8P6xSNIx9f
         mi6KJOmT83r5BUhYuSG+bpA8sRJAiadZqwN/XeA6wcLsx3aJzVMcTm7wEJ8xye+3vFTO
         S6G440p3ZDuycDEn5Y+9rtNGjmUubrXur8jP4qvawEHlGrpomNQi4nBbStD6ELpaPD2b
         tu7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=T999Vkev;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iBDbNwth7tZnyCTbeW1JvL77/ZTnC1NIjqhvw0pOmPI=;
        b=ZSHijdROpuS9ysBa0eLqXjPhxOlWrhkrjf0Gwoy9xbcdRYwtBYwu3cT2Rkh0NjCM1i
         lSdCOYc4OpRq++M/IYVQSv8XEhU1bqw11BlzpQNwC3ldjlDBmFtA1mYPhKdlX9cy63Ei
         em0XqoUvjgw5OOYd5LroCIFLGxx/jOwXpuPYL+fwV37XgD4aQLUdH66uQu4YwpfUQ9q1
         awmoIkSHEy8wyXWCrqc840XuO4dYeoD0crRawpN9t9Zm7n103d/PvXm19J7nyyQfkuKl
         A09tLyRMIto3jETCVqRUyw04hqzPd4cwhUIQmG0mCMp2WWKHnwktEN2ELRVdwyKn6mUt
         PRTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iBDbNwth7tZnyCTbeW1JvL77/ZTnC1NIjqhvw0pOmPI=;
        b=od3CZtZOsaYRBPnvq4P/Hsvnd8wumJK1eEQAfOu0GIOBshBF3NpV3ZYQpm6laLTdlL
         XP/kxejHza9d0IdI1jYVa44KOFxaI4xNwU6TKMN01sYGbf9/KR7llqDwiE6sqktC6xRQ
         KMpQZG+jggNq68qHzCBCf+t+/eyKfYA/R0/HUivJzqLPAhUCGO5/gHgUTuOQKq3IOoGN
         XnQpAV0ZVbbm/pCVKFuQawwAT1LRhtJznsYeMH6qssAdRS93Ia5h7DmYCw+DFwELauGy
         i1DIqf05sPyKmG8BJCRQAiq3yhdBNcQ9f4SDVnt1ZoKrZzKttNu7DpIrT92H9rdXYgjz
         MTvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iBDbNwth7tZnyCTbeW1JvL77/ZTnC1NIjqhvw0pOmPI=;
        b=haNL4ZSYqNt1nOHsnDcXbM8YCTHcRV2OACns5Vm0ZVvlrFbw72rFyhuGkpF3TRSSWg
         dybd+0s4scl0jnu4UnqprHZK79IivhisjR18NZXeN0ny3ib0RldjvjhgC0NyXbu183Qj
         H1ehXmDg0zxL7etrZjMEEaZFFF8cRbxPPdRYVOURkqBifBp2JcNXOMReT76TwKBj520q
         8f4fIGMKoVAILVE3vZDnzu9Z2x17U9UwfzbmYHEC+Z/w5w5idyArWxY8jClmrOPy8cN1
         9KkwkeKO2OYHDTskELeJrEGOMUikh4mcT2re46Daxb/4u9PxznWIcD3lmgyqQT12c2qJ
         xUIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oob3VFbDFLljZX9lm6e/8ekAyrY28y5yuETiSMVuPJkPxYfys
	lhS0GX5rvWNLi4xmCSx7k4Q=
X-Google-Smtp-Source: ABdhPJwjpJIlygjUTEaLajeEWcjFevwXAoFoFNg3d8kKkd7bneETDbicHenqmt5M8yZFYyrxGwFrPg==
X-Received: by 2002:a17:90a:af97:: with SMTP id w23mr6470199pjq.128.1639666852934;
        Thu, 16 Dec 2021 07:00:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7f52:: with SMTP id p18ls2016877pgn.7.gmail; Thu, 16 Dec
 2021 07:00:52 -0800 (PST)
X-Received: by 2002:aa7:9904:0:b0:4ba:5abb:aaf9 with SMTP id z4-20020aa79904000000b004ba5abbaaf9mr1997548pff.16.1639666852266;
        Thu, 16 Dec 2021 07:00:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639666852; cv=none;
        d=google.com; s=arc-20160816;
        b=DE5Y1ZBr4N5FK2Mo4nPD1fkRD0Pau6I6fdlPSgJMFoazAzsZv1uZIKg01OQT9qvQKV
         QfpdWHEj8K9KqSzPQgIFxAKd5aJHPLmV02a/l+MMD3EGcecqNHwe3hhhj4hSvj5OJOhA
         EvMQrNf0gVcPDnwzrkncU6qz5iuA4fLnX8zI+4S9obbdQsoujV1QMz/itNaXAYI5gYnQ
         spcZIkDbd9btMz9bABiW/RIoJMsqZVvjiXUm2fHxzb7IhbzJ28noi+OLmvRSQIb37yhB
         vd1vcjHPnsHRFk1tZecTGHA9SMn23T0aYbkTSe46HMKcpLov+tiBbqnmtNMEZxGQ8nlZ
         /9AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0aFEGyGgxYBEzyXnobj/2Sxx3wLs42RPScuyGczznaE=;
        b=v6/uStr0SDCWT/N/HhJ/dAuW/P/SlfoZZVuNML0X2NGKl1EAxH3XwWh+yVOQlj6DF3
         r2YaT1VMm1dWpomcHBJmFHgJ44LcSTUl/RLww0Yisg5Ywx2yx8PRR5uW1yXfoRANMNXI
         LoXJcF4qnlKoLh65FYq8Uhmh5M3Kx8VNvym9Mi7/kyjocG1NRCoOt1VSA7WKMEsxY2y0
         oqEbdhmbmkCo5c7yJbIfH4LqSEKQHEc8fzQ1v8B1jKufX4WuqBCHz9UiH5QXs/2D9jl7
         sAZtACcl44XjeljH+TzKXwUmNLbe77f1oafLUsCebKPVqMqg+WFLov9g1+vWQTcpdWL9
         FImQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=T999Vkev;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id q19si356377pfj.0.2021.12.16.07.00.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 07:00:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id q16so23248540pgq.10
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 07:00:52 -0800 (PST)
X-Received: by 2002:a05:6a00:2408:b0:4a8:45ef:c960 with SMTP id z8-20020a056a00240800b004a845efc960mr14027027pfh.53.1639666851848;
        Thu, 16 Dec 2021 07:00:51 -0800 (PST)
Received: from ip-172-31-30-232.ap-northeast-1.compute.internal (ec2-18-181-137-102.ap-northeast-1.compute.amazonaws.com. [18.181.137.102])
        by smtp.gmail.com with ESMTPSA id x37sm6586180pfh.116.2021.12.16.07.00.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Dec 2021 07:00:51 -0800 (PST)
Date: Thu, 16 Dec 2021 15:00:42 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <YbtUmi5kkhmlXEB1@ip-172-31-30-232.ap-northeast-1.compute.internal>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=T999Vkev;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536
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

On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
> On 12/1/21 19:14, Vlastimil Babka wrote:
> > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> > this cover letter.
> > 
> > Series also available in git, based on 5.16-rc3:
> > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> 
> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:

Reviewing the whole patch series takes longer than I thought.
I'll try to review and test rest of patches when I have time.

I added Tested-by if kernel builds okay and kselftests
does not break the kernel on my machine.
(with CONFIG_SLAB/SLUB/SLOB depending on the patch),
Let me know me if you know better way to test a patch.

# mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only when enabled

Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Comment:
Works on both SLUB_CPU_PARTIAL and !SLUB_CPU_PARTIAL.
btw, do we need slabs_cpu_partial attribute when we don't use
cpu partials? (!SLUB_CPU_PARTIAL)

# mm/slub: Simplify struct slab slabs field definition
Comment:

This is how struct page looks on the top of v3r3 branch:
struct page {
[...]
                struct {        /* slab, slob and slub */
                        union {
                                struct list_head slab_list;
                                struct {        /* Partial pages */
                                        struct page *next;
#ifdef CONFIG_64BIT
                                        int pages;      /* Nr of pages left */
#else
                                        short int pages;
#endif
                                };
                        };
[...]

It's not consistent with struct slab.
I think this is because "mm: Remove slab from struct page" was dropped.
Would you update some of patches?

# mm/sl*b: Differentiate struct slab fields by sl*b implementations
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Works SL[AUO]B on my machine and makes code much better.

# mm/slob: Convert SLOB to use struct slab and struct folio
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
It still works fine on SLOB.

# mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

# mm/slub: Convert __free_slab() to use struct slab
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks,
Hyeonggon.

> 
>  1:  10b656f9eb1e =  1:  10b656f9eb1e mm: add virt_to_folio() and folio_address()
>  2:  5e6ad846acf1 =  2:  5e6ad846acf1 mm/slab: Dissolve slab_map_pages() in its caller
>  3:  48d4e9407aa0 =  3:  48d4e9407aa0 mm/slub: Make object_err() static
>  4:  fe1e19081321 =  4:  fe1e19081321 mm: Split slab into its own type
>  5:  af7fd46fbb9b =  5:  af7fd46fbb9b mm: Add account_slab() and unaccount_slab()
>  6:  7ed088d601d9 =  6:  7ed088d601d9 mm: Convert virt_to_cache() to use struct slab
>  7:  1d41188b9401 =  7:  1d41188b9401 mm: Convert __ksize() to struct slab
>  8:  5d9d1231461f !  8:  8fd22e0b086e mm: Use struct slab in kmem_obj_info()
>     @@ Commit message
>          slab type instead of the page type, we make it obvious that this can
>          only be called for slabs.
>      
>     +    [ vbabka@suse.cz: also convert the related kmem_valid_obj() to folios ]
>     +
>          Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
>          Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>      
>     @@ mm/slab.h: struct kmem_obj_info {
>       #endif /* MM_SLAB_H */
>      
>       ## mm/slab_common.c ##
>     +@@ mm/slab_common.c: bool slab_is_available(void)
>     +  */
>     + bool kmem_valid_obj(void *object)
>     + {
>     +-	struct page *page;
>     ++	struct folio *folio;
>     + 
>     + 	/* Some arches consider ZERO_SIZE_PTR to be a valid address. */
>     + 	if (object < (void *)PAGE_SIZE || !virt_addr_valid(object))
>     + 		return false;
>     +-	page = virt_to_head_page(object);
>     +-	return PageSlab(page);
>     ++	folio = virt_to_folio(object);
>     ++	return folio_test_slab(folio);
>     + }
>     + EXPORT_SYMBOL_GPL(kmem_valid_obj);
>     + 
>      @@ mm/slab_common.c: void kmem_dump_obj(void *object)
>       {
>       	char *cp = IS_ENABLED(CONFIG_MMU) ? "" : "/vmalloc";
>     @@ mm/slub.c: int __kmem_cache_shutdown(struct kmem_cache *s)
>       	objp = base + s->size * objnr;
>       	kpp->kp_objp = objp;
>      -	if (WARN_ON_ONCE(objp < base || objp >= base + page->objects * s->size || (objp - base) % s->size) ||
>     -+	if (WARN_ON_ONCE(objp < base || objp >= base + slab->objects * s->size || (objp - base) % s->size) ||
>     ++	if (WARN_ON_ONCE(objp < base || objp >= base + slab->objects * s->size
>     ++			 || (objp - base) % s->size) ||
>       	    !(s->flags & SLAB_STORE_USER))
>       		return;
>       #ifdef CONFIG_SLUB_DEBUG
>  9:  3aef771be335 !  9:  c97e73c3b6c2 mm: Convert check_heap_object() to use struct slab
>     @@ mm/slab.h: struct kmem_obj_info {
>      +#else
>      +static inline
>      +void __check_heap_object(const void *ptr, unsigned long n,
>     -+			 const struct slab *slab, bool to_user) { }
>     ++			 const struct slab *slab, bool to_user)
>     ++{
>     ++}
>      +#endif
>      +
>       #endif /* MM_SLAB_H */
> 10:  2253e45e6bef = 10:  da05e0f7179c mm/slub: Convert detached_freelist to use a struct slab
> 11:  f28202bc27ba = 11:  383887e77104 mm/slub: Convert kfree() to use a struct slab
> 12:  31b58b1e914f = 12:  c46be093c637 mm/slub: Convert __slab_lock() and __slab_unlock() to struct slab
> 13:  636406a3ad59 = 13:  49dbbf917052 mm/slub: Convert print_page_info() to print_slab_info()
> 14:  3b49efda3b6f = 14:  4bb0c932156a mm/slub: Convert alloc_slab_page() to return a struct slab
> 15:  61a195526d3b ! 15:  4b9761b5cfab mm/slub: Convert __free_slab() to use struct slab
>     @@ mm/slub.c: static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int n
>       
>      -	__ClearPageSlabPfmemalloc(page);
>      -	__ClearPageSlab(page);
>     +-	/* In union with page->mapping where page allocator expects NULL */
>     +-	page->slab_cache = NULL;
>      +	__slab_clear_pfmemalloc(slab);
>      +	__folio_clear_slab(folio);
>     - 	/* In union with page->mapping where page allocator expects NULL */
>     --	page->slab_cache = NULL;
>     -+	slab->slab_cache = NULL;
>     ++	folio->mapping = NULL;
>       	if (current->reclaim_state)
>       		current->reclaim_state->reclaimed_slab += pages;
>      -	unaccount_slab(page_slab(page), order, s);
> 16:  987c7ed31580 = 16:  f384ec918065 mm/slub: Convert pfmemalloc_match() to take a struct slab
> 17:  cc742564237e ! 17:  06738ade4e17 mm/slub: Convert most struct page to struct slab by spatch
>     @@ Commit message
>      
>          // Options: --include-headers --no-includes --smpl-spacing include/linux/slub_def.h mm/slub.c
>          // Note: needs coccinelle 1.1.1 to avoid breaking whitespace, and ocaml for the
>     -    // embedded script script
>     +    // embedded script
>      
>          // build list of functions to exclude from applying the next rule
>          @initialize:ocaml@
> 18:  b45acac9aace = 18:  1a4f69a4cced mm/slub: Finish struct page to struct slab conversion
> 19:  76c3eeb39684 ! 19:  1d62d706e884 mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
>     @@ mm/slab.c: slab_out_of_memory(struct kmem_cache *cachep, gfp_t gfpflags, int nod
>      -	__ClearPageSlabPfmemalloc(page);
>      -	__ClearPageSlab(page);
>      -	page_mapcount_reset(page);
>     +-	/* In union with page->mapping where page allocator expects NULL */
>     +-	page->slab_cache = NULL;
>      +	BUG_ON(!folio_test_slab(folio));
>      +	__slab_clear_pfmemalloc(slab);
>      +	__folio_clear_slab(folio);
>      +	page_mapcount_reset(folio_page(folio, 0));
>     - 	/* In union with page->mapping where page allocator expects NULL */
>     --	page->slab_cache = NULL;
>     -+	slab->slab_cache = NULL;
>     ++	folio->mapping = NULL;
>       
>       	if (current->reclaim_state)
>       		current->reclaim_state->reclaimed_slab += 1 << order;
> 20:  ed6144dbebce ! 20:  fd4c3aabacd3 mm/slab: Convert most struct page to struct slab by spatch
>     @@ Commit message
>      
>          // Options: --include-headers --no-includes --smpl-spacing mm/slab.c
>          // Note: needs coccinelle 1.1.1 to avoid breaking whitespace, and ocaml for the
>     -    // embedded script script
>     +    // embedded script
>      
>          // build list of functions for applying the next rule
>          @initialize:ocaml@
> 21:  17fb81e601e6 = 21:  b59720b2edba mm/slab: Finish struct page to struct slab conversion
> 22:  4e8d1faebc24 ! 22:  65ced071c3e7 mm: Convert struct page to struct slab in functions used by other subsystems
>     @@ Commit message
>            ,...)
>      
>          Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>     +    Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>          Cc: Julia Lawall <julia.lawall@inria.fr>
>          Cc: Luis Chamberlain <mcgrof@kernel.org>
>          Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> 23:  eefa12e18a92 = 23:  c9c8dee01e5d mm/memcg: Convert slab objcgs from struct page to struct slab
> 24:  fa5ba4107ce2 ! 24:  def731137335 mm/slob: Convert SLOB to use struct slab
>     @@ Metadata
>      Author: Matthew Wilcox (Oracle) <willy@infradead.org>
>      
>       ## Commit message ##
>     -    mm/slob: Convert SLOB to use struct slab
>     +    mm/slob: Convert SLOB to use struct slab and struct folio
>      
>     -    Use struct slab throughout the slob allocator.
>     +    Use struct slab throughout the slob allocator. Where non-slab page can appear
>     +    use struct folio instead of struct page.
>      
>          [ vbabka@suse.cz: don't introduce wrappers for PageSlobFree in mm/slab.h just
>            for the single callers being wrappers in mm/slob.c ]
>      
>     +    [ Hyeonggon Yoo <42.hyeyoo@gmail.com>: fix NULL pointer deference ]
>     +
>          Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
>          Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>      
>       ## mm/slob.c ##
>     +@@
>     +  * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
>     +  * alloc_pages() directly, allocating compound pages so the page order
>     +  * does not have to be separately tracked.
>     +- * These objects are detected in kfree() because PageSlab()
>     ++ * These objects are detected in kfree() because folio_test_slab()
>     +  * is false for them.
>     +  *
>     +  * SLAB is emulated on top of SLOB by simply calling constructors and
>      @@ mm/slob.c: static LIST_HEAD(free_slob_large);
>       /*
>        * slob_page_free: true for pages on free_slob_pages list.
>     @@ mm/slob.c: static void *slob_page_alloc(struct page *sp, size_t size, int align,
>       							int align_offset)
>       {
>      -	struct page *sp;
>     ++	struct folio *folio;
>      +	struct slab *sp;
>       	struct list_head *slob_list;
>       	slob_t *b = NULL;
>     @@ mm/slob.c: static void *slob_alloc(size_t size, gfp_t gfp, int align, int node,
>       			return NULL;
>      -		sp = virt_to_page(b);
>      -		__SetPageSlab(sp);
>     -+		sp = virt_to_slab(b);
>     -+		__SetPageSlab(slab_page(sp));
>     ++		folio = virt_to_folio(b);
>     ++		__folio_set_slab(folio);
>     ++		sp = folio_slab(folio);
>       
>       		spin_lock_irqsave(&slob_lock, flags);
>       		sp->units = SLOB_UNITS(PAGE_SIZE);
>     @@ mm/slob.c: static void slob_free(void *block, int size)
>       		spin_unlock_irqrestore(&slob_lock, flags);
>      -		__ClearPageSlab(sp);
>      -		page_mapcount_reset(sp);
>     -+		__ClearPageSlab(slab_page(sp));
>     ++		__folio_clear_slab(slab_folio(sp));
>      +		page_mapcount_reset(slab_page(sp));
>       		slob_free_pages(b, 0);
>       		return;
>       	}
>     +@@ mm/slob.c: EXPORT_SYMBOL(__kmalloc_node_track_caller);
>     + 
>     + void kfree(const void *block)
>     + {
>     +-	struct page *sp;
>     ++	struct folio *sp;
>     + 
>     + 	trace_kfree(_RET_IP_, block);
>     + 
>     +@@ mm/slob.c: void kfree(const void *block)
>     + 		return;
>     + 	kmemleak_free(block);
>     + 
>     +-	sp = virt_to_page(block);
>     +-	if (PageSlab(sp)) {
>     ++	sp = virt_to_folio(block);
>     ++	if (folio_test_slab(sp)) {
>     + 		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
>     + 		unsigned int *m = (unsigned int *)(block - align);
>     + 		slob_free(m, *m + align);
>     + 	} else {
>     +-		unsigned int order = compound_order(sp);
>     +-		mod_node_page_state(page_pgdat(sp), NR_SLAB_UNRECLAIMABLE_B,
>     ++		unsigned int order = folio_order(sp);
>     ++
>     ++		mod_node_page_state(folio_pgdat(sp), NR_SLAB_UNRECLAIMABLE_B,
>     + 				    -(PAGE_SIZE << order));
>     +-		__free_pages(sp, order);
>     ++		__free_pages(folio_page(sp, 0), order);
>     + 
>     + 	}
>     + }
> 25:  aa4f573a4c96 ! 25:  466b9fb1f6e5 mm/kasan: Convert to struct folio and struct slab
>     @@ Commit message
>      
>          Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
>          Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>     +    Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>          Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>          Cc: Alexander Potapenko <glider@google.com>
>          Cc: Andrey Konovalov <andreyknvl@gmail.com>
> 26:  67b7966d2fb6 = 26:  b8159ae8e5cd mm/kfence: Convert kfence_guarded_alloc() to struct slab
> 31:  d64dfe49c1e7 ! 27:  4525180926f9 mm/sl*b: Differentiate struct slab fields by sl*b implementations
>     @@ Commit message
>          possible.
>      
>          This should also prevent accidental use of fields that don't exist in given
>     -    implementation. Before this patch virt_to_cache() and and cache_from_obj() was
>     -    visible for SLOB (albeit not used), although it relies on the slab_cache field
>     +    implementation. Before this patch virt_to_cache() and cache_from_obj() were
>     +    visible for SLOB (albeit not used), although they rely on the slab_cache field
>          that isn't set by SLOB. With this patch it's now a compile error, so these
>          functions are now hidden behind #ifndef CONFIG_SLOB.
>      
>     @@ mm/kfence/core.c: static void *kfence_guarded_alloc(struct kmem_cache *cache, si
>      -		slab->s_mem = addr;
>      +#if defined(CONFIG_SLUB)
>      +	slab->objects = 1;
>     -+#elif defined (CONFIG_SLAB)
>     ++#elif defined(CONFIG_SLAB)
>      +	slab->s_mem = addr;
>      +#endif
>       
>     @@ mm/slab.h
>      +
>      +#if defined(CONFIG_SLAB)
>      +
>     -+	union {
>     -+		struct list_head slab_list;
>     + 	union {
>     + 		struct list_head slab_list;
>     +-		struct {	/* Partial pages */
>      +		struct rcu_head rcu_head;
>      +	};
>      +	struct kmem_cache *slab_cache;
>      +	void *freelist;	/* array of free object indexes */
>     -+	void * s_mem;	/* first object */
>     ++	void *s_mem;	/* first object */
>      +	unsigned int active;
>      +
>      +#elif defined(CONFIG_SLUB)
>      +
>     - 	union {
>     - 		struct list_head slab_list;
>     --		struct {	/* Partial pages */
>     ++	union {
>     ++		struct list_head slab_list;
>      +		struct rcu_head rcu_head;
>      +		struct {
>       			struct slab *next;
>     @@ mm/slab.h: struct slab {
>      +#elif defined(CONFIG_SLOB)
>      +
>      +	struct list_head slab_list;
>     -+	void * __unused_1;
>     ++	void *__unused_1;
>      +	void *freelist;		/* first free block */
>     -+	void * __unused_2;
>     ++	void *__unused_2;
>      +	int units;
>      +
>      +#else
>     @@ mm/slab.h: struct slab {
>       #ifdef CONFIG_MEMCG
>       	unsigned long memcg_data;
>      @@ mm/slab.h: struct slab {
>     - 	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
>       SLAB_MATCH(flags, __page_flags);
>       SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
>     + SLAB_MATCH(slab_list, slab_list);
>      +#ifndef CONFIG_SLOB
>       SLAB_MATCH(rcu_head, rcu_head);
>     + SLAB_MATCH(slab_cache, slab_cache);
>     ++#endif
>     ++#ifdef CONFIG_SLAB
>     + SLAB_MATCH(s_mem, s_mem);
>     + SLAB_MATCH(active, active);
>      +#endif
>       SLAB_MATCH(_refcount, __page_refcount);
>       #ifdef CONFIG_MEMCG
> 32:  0abf87bae67e = 28:  94b78948d53f mm/slub: Simplify struct slab slabs field definition
> 33:  813c304f18e4 = 29:  f5261e6375f0 mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only when enabled
> 27:  ebce4b5b5ced ! 30:  1414e8c87de6 zsmalloc: Stop using slab fields in struct page
>     @@ Commit message
>      
>          Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
>          Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>     -    Cc: Minchan Kim <minchan@kernel.org>
>     +    Acked-by: Minchan Kim <minchan@kernel.org>
>          Cc: Nitin Gupta <ngupta@vflare.org>
>          Cc: Sergey Senozhatsky <senozhatsky@chromium.org>
>      
> 28:  f124425ae7de = 31:  8a3cda6b38eb bootmem: Use page->index instead of page->freelist
> 29:  82da48c73b2e <  -:  ------------ iommu: Use put_pages_list
> 30:  181e16dfefbb <  -:  ------------ mm: Remove slab from struct page
>  -:  ------------ > 32:  91e069ba116b mm/slob: Remove unnecessary page_mapcount_reset() function call

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbtUmi5kkhmlXEB1%40ip-172-31-30-232.ap-northeast-1.compute.internal.
