Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBNNJ4KGQMGQEHAICNOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E2C80474305
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 13:57:25 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id h17-20020a05651c125100b0021ba28cf54dsf5400691ljh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 04:57:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639486645; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2vDoO+QSrcZmalzdkJSo63fLbwI4Eb3c5hQ/u2HP5/MMdNnNAT5LWibyepSdkbx1y
         0aXV24d53DACP2mwhiuTeQDv0ailA5bMn9vpori1f0eXDF8AjK9inwf+piuX2tMHYav9
         GKGqd7tE7kC0PDI60fQ3vrOgOB1yVST/pLm/CoJs8sqqoG2Q/4Jur5Sqpu+G6JimBVNE
         4QqDkR8Z1jH3uF/TP1ghMd3/IshJs9XB26/zRYM1K9OYuFHhGwnuvcFQ6kDMOEUmFrNh
         P4rvcdzoBNnWBG1B+o8NZCAXpVzpwA8/GQrrR+EEK5o4JQtJ3P4hXJGGRgMcSL6QGM9z
         qjaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=hlGQ0vyQcUv9+e4ZbZQArygJmzk2wDp8Mz82sJF6/1M=;
        b=Hjdybyt6kQe736d4i4ms7xS1WrS2GGm/GsCs1lS4CAgEmfaBuIuzakd2VPpACQZ+tw
         qPRC7L0eNac6Fd2TXm7JjyevXqgJ3dn3oj57INHcaZ9BZc8t9PiXukVo0pXCIg7uvTmv
         EgqKkK3UUNede0P5dmShcVZaWfahXacr0oq2noNq5JbHD7QzixDXOv4qDFgFobXmsSA7
         JMMtzthHxQNuggzJezizsvBuwQa4UxnftFGsHgd9GCrs+gnu2R9JmAxV4CX0ekIsu918
         f34uPECmOi71OJ+EJrmQLYYuYXkgOw+HMTNIvn74qj8mHvG+5JhUUF/5FpIFBmUkKHAZ
         mMlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="YtlW/pXH";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hlGQ0vyQcUv9+e4ZbZQArygJmzk2wDp8Mz82sJF6/1M=;
        b=OXhiPQFgDCpbZ8zaUXXgjDuypPCT/dB0qyTF7JLSlMMBVYPYBkWjeO/xn0T3W/igb8
         8boaf4xMSEz01BlBRILI2MlG+bZMIjIKmyx0V1M9toIFuKHqve7UhdHWTo8VXqYPj56e
         AiCIcn7F2Z39PG5fRh21c26xOXuXi1euese2dTp6x3qzcJdyrkaku0kcxQWlsBPKVG/P
         y5bAoLKkCdWB3Uc7kCnyXEBiexuKIMRYh0QOqxKg9Ts01kJBa7tJOtCimej2OB2sZ+wU
         DMIn/y/lAXto1xpU/56XrYoU+2YB510AAlW+iC3/fNkWuUtFu2TVKn18xlCkJJvFpaa+
         6qRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hlGQ0vyQcUv9+e4ZbZQArygJmzk2wDp8Mz82sJF6/1M=;
        b=vTeb1JAF5Y0O6S54khX/kqNJLjK9cCwXnlQ9xl7eWUdpcp2s7pzLK44guzdPnj633Z
         Arws+t+Ig8Hs2huutiubYT9fj4zzc1DuWXIv5TwWpWig8lBQ+W07/rongCJQGVql9nUN
         47GoN/nGjTxjx2sTpsnPS+MR18+9f4OC7KZkU8BSg/t+7WHjq8awmWarp3HusElhwbtf
         hhIo6+FT4Pf4Ny/rE6ctj2D09BOKbjm0O40XFnEg+X3Jzv2yPNu8gaStFuhFHys5c61k
         Dc1wqn1kb/5itGVojS26N4HG5b3AamafgECNL27aEwx+dwylkPVj+RBdW/kp3EVcCXrd
         HOUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325Wxz9q1xKlw68cVa5a1R3EYH0m03EzIoHpjAPDdKd3CgjNem3
	CT49kkYDTG+u5y1BGogPbLw=
X-Google-Smtp-Source: ABdhPJz712OAC+xzgxkijYOIbVNQh1XsFTqrhZ/Ic/HN5iGjgjfi+FjQKnO0lKdR6Ymg7ipC90BxPw==
X-Received: by 2002:a2e:97cb:: with SMTP id m11mr4787093ljj.324.1639486645268;
        Tue, 14 Dec 2021 04:57:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls1108278ljn.3.gmail; Tue, 14 Dec
 2021 04:57:24 -0800 (PST)
X-Received: by 2002:a05:651c:160d:: with SMTP id f13mr4768142ljq.147.1639486644119;
        Tue, 14 Dec 2021 04:57:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639486644; cv=none;
        d=google.com; s=arc-20160816;
        b=IEdy0sVeEtAOg1ljpZH72wKiKoTJTzNWGMMffLvkt4q+WYKfKp3PLDuIPeCZ0ZUAzP
         /d2pg1zXgl6jPou23Rf47xOc2Eyh60ANqrp5fBUsJCIHObMX3b0kau+5US35uQT7rI0G
         rQJG6n6R/B1SvpGw1q8hus2EOzYyyoHkGW4s0Mu8H5hfNdoMgyMkr6KTCPVlyLt29+4a
         hjf3EpACTVvJ5Y+rnvV6Ia0YEmTfT3JGBzqoCWPOAYuaw77f/f/EdUmZEvWbQXGQksaN
         dBPnXtuBmacCDX79n6xoOoHpK13GrhVofcxJkd4iE8W2AjdUd/R/qz1ChA5raVw4lVLA
         q/vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=SkeW1MNcRF04Ru6QPjaKAo21US3gEoUATt9Eryrrd00=;
        b=WZaZkmeiXgwIVNFH641r1tOxJpyA1walMsONdLeNBvJO2bcdU6m92o9YIxtq2l2Bhy
         yfXC4vje9e+wiTHXEppCLMjEZsHbzZwThBtAfkP7hg/+ISFBdTGzJs3Z14jqu16Sk0Cm
         tCpDCk8XEiO499JXN5TaMapHQ3zFh96lsTdFXWCv+CCQ1Qei1W7dJA/QZGfgG+43R+Ge
         TmD/2vqg0d9aH3iGR3+3jXQtq7VsFdbiWnIioRIquQm597eiHzR4jjPviqBC+Ps9Bmji
         gGS4yDzzLiEu0zEDoB0TJzqaW1aBt5hyBxWOEG/yZxLvQspXwNxg88CoN4TZhffghgAO
         IjIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="YtlW/pXH";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id g21si924548lfv.11.2021.12.14.04.57.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 04:57:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 51ABE1F380;
	Tue, 14 Dec 2021 12:57:23 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BA9E613DD9;
	Tue, 14 Dec 2021 12:57:22 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UD/FLLKUuGEsGwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Dec 2021 12:57:22 +0000
Message-ID: <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
Date: Tue, 14 Dec 2021 13:57:22 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Content-Language: en-US
To: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org, Andrew Morton <akpm@linux-foundation.org>,
 patches@lists.linux.dev, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andy Lutomirski <luto@kernel.org>,
 Borislav Petkov <bp@alien8.de>, cgroups@vger.kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>,
 David Woodhouse <dwmw2@infradead.org>, Dmitry Vyukov <dvyukov@google.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
 Johannes Weiner <hannes@cmpxchg.org>, Julia Lawall <julia.lawall@inria.fr>,
 kasan-dev@googlegroups.com, Lu Baolu <baolu.lu@linux.intel.com>,
 Luis Chamberlain <mcgrof@kernel.org>, Marco Elver <elver@google.com>,
 Michal Hocko <mhocko@kernel.org>, Minchan Kim <minchan@kernel.org>,
 Nitin Gupta <ngupta@vflare.org>, Peter Zijlstra <peterz@infradead.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
 Thomas Gleixner <tglx@linutronix.de>,
 Vladimir Davydov <vdavydov.dev@gmail.com>, Will Deacon <will@kernel.org>,
 x86@kernel.org, Hyeonggon Yoo <42.hyeyoo@gmail.com>
References: <20211201181510.18784-1-vbabka@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211201181510.18784-1-vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="YtlW/pXH";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/1/21 19:14, Vlastimil Babka wrote:
> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> this cover letter.
> 
> Series also available in git, based on 5.16-rc3:
> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2

Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:

 1:  10b656f9eb1e =  1:  10b656f9eb1e mm: add virt_to_folio() and folio_address()
 2:  5e6ad846acf1 =  2:  5e6ad846acf1 mm/slab: Dissolve slab_map_pages() in its caller
 3:  48d4e9407aa0 =  3:  48d4e9407aa0 mm/slub: Make object_err() static
 4:  fe1e19081321 =  4:  fe1e19081321 mm: Split slab into its own type
 5:  af7fd46fbb9b =  5:  af7fd46fbb9b mm: Add account_slab() and unaccount_slab()
 6:  7ed088d601d9 =  6:  7ed088d601d9 mm: Convert virt_to_cache() to use struct slab
 7:  1d41188b9401 =  7:  1d41188b9401 mm: Convert __ksize() to struct slab
 8:  5d9d1231461f !  8:  8fd22e0b086e mm: Use struct slab in kmem_obj_info()
    @@ Commit message
         slab type instead of the page type, we make it obvious that this can
         only be called for slabs.
     
    +    [ vbabka@suse.cz: also convert the related kmem_valid_obj() to folios ]
    +
         Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
         Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
     
    @@ mm/slab.h: struct kmem_obj_info {
      #endif /* MM_SLAB_H */
     
      ## mm/slab_common.c ##
    +@@ mm/slab_common.c: bool slab_is_available(void)
    +  */
    + bool kmem_valid_obj(void *object)
    + {
    +-	struct page *page;
    ++	struct folio *folio;
    + 
    + 	/* Some arches consider ZERO_SIZE_PTR to be a valid address. */
    + 	if (object < (void *)PAGE_SIZE || !virt_addr_valid(object))
    + 		return false;
    +-	page = virt_to_head_page(object);
    +-	return PageSlab(page);
    ++	folio = virt_to_folio(object);
    ++	return folio_test_slab(folio);
    + }
    + EXPORT_SYMBOL_GPL(kmem_valid_obj);
    + 
     @@ mm/slab_common.c: void kmem_dump_obj(void *object)
      {
      	char *cp = IS_ENABLED(CONFIG_MMU) ? "" : "/vmalloc";
    @@ mm/slub.c: int __kmem_cache_shutdown(struct kmem_cache *s)
      	objp = base + s->size * objnr;
      	kpp->kp_objp = objp;
     -	if (WARN_ON_ONCE(objp < base || objp >= base + page->objects * s->size || (objp - base) % s->size) ||
    -+	if (WARN_ON_ONCE(objp < base || objp >= base + slab->objects * s->size || (objp - base) % s->size) ||
    ++	if (WARN_ON_ONCE(objp < base || objp >= base + slab->objects * s->size
    ++			 || (objp - base) % s->size) ||
      	    !(s->flags & SLAB_STORE_USER))
      		return;
      #ifdef CONFIG_SLUB_DEBUG
 9:  3aef771be335 !  9:  c97e73c3b6c2 mm: Convert check_heap_object() to use struct slab
    @@ mm/slab.h: struct kmem_obj_info {
     +#else
     +static inline
     +void __check_heap_object(const void *ptr, unsigned long n,
    -+			 const struct slab *slab, bool to_user) { }
    ++			 const struct slab *slab, bool to_user)
    ++{
    ++}
     +#endif
     +
      #endif /* MM_SLAB_H */
10:  2253e45e6bef = 10:  da05e0f7179c mm/slub: Convert detached_freelist to use a struct slab
11:  f28202bc27ba = 11:  383887e77104 mm/slub: Convert kfree() to use a struct slab
12:  31b58b1e914f = 12:  c46be093c637 mm/slub: Convert __slab_lock() and __slab_unlock() to struct slab
13:  636406a3ad59 = 13:  49dbbf917052 mm/slub: Convert print_page_info() to print_slab_info()
14:  3b49efda3b6f = 14:  4bb0c932156a mm/slub: Convert alloc_slab_page() to return a struct slab
15:  61a195526d3b ! 15:  4b9761b5cfab mm/slub: Convert __free_slab() to use struct slab
    @@ mm/slub.c: static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int n
      
     -	__ClearPageSlabPfmemalloc(page);
     -	__ClearPageSlab(page);
    +-	/* In union with page->mapping where page allocator expects NULL */
    +-	page->slab_cache = NULL;
     +	__slab_clear_pfmemalloc(slab);
     +	__folio_clear_slab(folio);
    - 	/* In union with page->mapping where page allocator expects NULL */
    --	page->slab_cache = NULL;
    -+	slab->slab_cache = NULL;
    ++	folio->mapping = NULL;
      	if (current->reclaim_state)
      		current->reclaim_state->reclaimed_slab += pages;
     -	unaccount_slab(page_slab(page), order, s);
16:  987c7ed31580 = 16:  f384ec918065 mm/slub: Convert pfmemalloc_match() to take a struct slab
17:  cc742564237e ! 17:  06738ade4e17 mm/slub: Convert most struct page to struct slab by spatch
    @@ Commit message
     
         // Options: --include-headers --no-includes --smpl-spacing include/linux/slub_def.h mm/slub.c
         // Note: needs coccinelle 1.1.1 to avoid breaking whitespace, and ocaml for the
    -    // embedded script script
    +    // embedded script
     
         // build list of functions to exclude from applying the next rule
         @initialize:ocaml@
18:  b45acac9aace = 18:  1a4f69a4cced mm/slub: Finish struct page to struct slab conversion
19:  76c3eeb39684 ! 19:  1d62d706e884 mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
    @@ mm/slab.c: slab_out_of_memory(struct kmem_cache *cachep, gfp_t gfpflags, int nod
     -	__ClearPageSlabPfmemalloc(page);
     -	__ClearPageSlab(page);
     -	page_mapcount_reset(page);
    +-	/* In union with page->mapping where page allocator expects NULL */
    +-	page->slab_cache = NULL;
     +	BUG_ON(!folio_test_slab(folio));
     +	__slab_clear_pfmemalloc(slab);
     +	__folio_clear_slab(folio);
     +	page_mapcount_reset(folio_page(folio, 0));
    - 	/* In union with page->mapping where page allocator expects NULL */
    --	page->slab_cache = NULL;
    -+	slab->slab_cache = NULL;
    ++	folio->mapping = NULL;
      
      	if (current->reclaim_state)
      		current->reclaim_state->reclaimed_slab += 1 << order;
20:  ed6144dbebce ! 20:  fd4c3aabacd3 mm/slab: Convert most struct page to struct slab by spatch
    @@ Commit message
     
         // Options: --include-headers --no-includes --smpl-spacing mm/slab.c
         // Note: needs coccinelle 1.1.1 to avoid breaking whitespace, and ocaml for the
    -    // embedded script script
    +    // embedded script
     
         // build list of functions for applying the next rule
         @initialize:ocaml@
21:  17fb81e601e6 = 21:  b59720b2edba mm/slab: Finish struct page to struct slab conversion
22:  4e8d1faebc24 ! 22:  65ced071c3e7 mm: Convert struct page to struct slab in functions used by other subsystems
    @@ Commit message
           ,...)
     
         Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
    +    Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
         Cc: Julia Lawall <julia.lawall@inria.fr>
         Cc: Luis Chamberlain <mcgrof@kernel.org>
         Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
23:  eefa12e18a92 = 23:  c9c8dee01e5d mm/memcg: Convert slab objcgs from struct page to struct slab
24:  fa5ba4107ce2 ! 24:  def731137335 mm/slob: Convert SLOB to use struct slab
    @@ Metadata
     Author: Matthew Wilcox (Oracle) <willy@infradead.org>
     
      ## Commit message ##
    -    mm/slob: Convert SLOB to use struct slab
    +    mm/slob: Convert SLOB to use struct slab and struct folio
     
    -    Use struct slab throughout the slob allocator.
    +    Use struct slab throughout the slob allocator. Where non-slab page can appear
    +    use struct folio instead of struct page.
     
         [ vbabka@suse.cz: don't introduce wrappers for PageSlobFree in mm/slab.h just
           for the single callers being wrappers in mm/slob.c ]
     
    +    [ Hyeonggon Yoo <42.hyeyoo@gmail.com>: fix NULL pointer deference ]
    +
         Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
         Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
     
      ## mm/slob.c ##
    +@@
    +  * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
    +  * alloc_pages() directly, allocating compound pages so the page order
    +  * does not have to be separately tracked.
    +- * These objects are detected in kfree() because PageSlab()
    ++ * These objects are detected in kfree() because folio_test_slab()
    +  * is false for them.
    +  *
    +  * SLAB is emulated on top of SLOB by simply calling constructors and
     @@ mm/slob.c: static LIST_HEAD(free_slob_large);
      /*
       * slob_page_free: true for pages on free_slob_pages list.
    @@ mm/slob.c: static void *slob_page_alloc(struct page *sp, size_t size, int align,
      							int align_offset)
      {
     -	struct page *sp;
    ++	struct folio *folio;
     +	struct slab *sp;
      	struct list_head *slob_list;
      	slob_t *b = NULL;
    @@ mm/slob.c: static void *slob_alloc(size_t size, gfp_t gfp, int align, int node,
      			return NULL;
     -		sp = virt_to_page(b);
     -		__SetPageSlab(sp);
    -+		sp = virt_to_slab(b);
    -+		__SetPageSlab(slab_page(sp));
    ++		folio = virt_to_folio(b);
    ++		__folio_set_slab(folio);
    ++		sp = folio_slab(folio);
      
      		spin_lock_irqsave(&slob_lock, flags);
      		sp->units = SLOB_UNITS(PAGE_SIZE);
    @@ mm/slob.c: static void slob_free(void *block, int size)
      		spin_unlock_irqrestore(&slob_lock, flags);
     -		__ClearPageSlab(sp);
     -		page_mapcount_reset(sp);
    -+		__ClearPageSlab(slab_page(sp));
    ++		__folio_clear_slab(slab_folio(sp));
     +		page_mapcount_reset(slab_page(sp));
      		slob_free_pages(b, 0);
      		return;
      	}
    +@@ mm/slob.c: EXPORT_SYMBOL(__kmalloc_node_track_caller);
    + 
    + void kfree(const void *block)
    + {
    +-	struct page *sp;
    ++	struct folio *sp;
    + 
    + 	trace_kfree(_RET_IP_, block);
    + 
    +@@ mm/slob.c: void kfree(const void *block)
    + 		return;
    + 	kmemleak_free(block);
    + 
    +-	sp = virt_to_page(block);
    +-	if (PageSlab(sp)) {
    ++	sp = virt_to_folio(block);
    ++	if (folio_test_slab(sp)) {
    + 		int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
    + 		unsigned int *m = (unsigned int *)(block - align);
    + 		slob_free(m, *m + align);
    + 	} else {
    +-		unsigned int order = compound_order(sp);
    +-		mod_node_page_state(page_pgdat(sp), NR_SLAB_UNRECLAIMABLE_B,
    ++		unsigned int order = folio_order(sp);
    ++
    ++		mod_node_page_state(folio_pgdat(sp), NR_SLAB_UNRECLAIMABLE_B,
    + 				    -(PAGE_SIZE << order));
    +-		__free_pages(sp, order);
    ++		__free_pages(folio_page(sp, 0), order);
    + 
    + 	}
    + }
25:  aa4f573a4c96 ! 25:  466b9fb1f6e5 mm/kasan: Convert to struct folio and struct slab
    @@ Commit message
     
         Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
         Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
    +    Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
         Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
         Cc: Alexander Potapenko <glider@google.com>
         Cc: Andrey Konovalov <andreyknvl@gmail.com>
26:  67b7966d2fb6 = 26:  b8159ae8e5cd mm/kfence: Convert kfence_guarded_alloc() to struct slab
31:  d64dfe49c1e7 ! 27:  4525180926f9 mm/sl*b: Differentiate struct slab fields by sl*b implementations
    @@ Commit message
         possible.
     
         This should also prevent accidental use of fields that don't exist in given
    -    implementation. Before this patch virt_to_cache() and and cache_from_obj() was
    -    visible for SLOB (albeit not used), although it relies on the slab_cache field
    +    implementation. Before this patch virt_to_cache() and cache_from_obj() were
    +    visible for SLOB (albeit not used), although they rely on the slab_cache field
         that isn't set by SLOB. With this patch it's now a compile error, so these
         functions are now hidden behind #ifndef CONFIG_SLOB.
     
    @@ mm/kfence/core.c: static void *kfence_guarded_alloc(struct kmem_cache *cache, si
     -		slab->s_mem = addr;
     +#if defined(CONFIG_SLUB)
     +	slab->objects = 1;
    -+#elif defined (CONFIG_SLAB)
    ++#elif defined(CONFIG_SLAB)
     +	slab->s_mem = addr;
     +#endif
      
    @@ mm/slab.h
     +
     +#if defined(CONFIG_SLAB)
     +
    -+	union {
    -+		struct list_head slab_list;
    + 	union {
    + 		struct list_head slab_list;
    +-		struct {	/* Partial pages */
     +		struct rcu_head rcu_head;
     +	};
     +	struct kmem_cache *slab_cache;
     +	void *freelist;	/* array of free object indexes */
    -+	void * s_mem;	/* first object */
    ++	void *s_mem;	/* first object */
     +	unsigned int active;
     +
     +#elif defined(CONFIG_SLUB)
     +
    - 	union {
    - 		struct list_head slab_list;
    --		struct {	/* Partial pages */
    ++	union {
    ++		struct list_head slab_list;
     +		struct rcu_head rcu_head;
     +		struct {
      			struct slab *next;
    @@ mm/slab.h: struct slab {
     +#elif defined(CONFIG_SLOB)
     +
     +	struct list_head slab_list;
    -+	void * __unused_1;
    ++	void *__unused_1;
     +	void *freelist;		/* first free block */
    -+	void * __unused_2;
    ++	void *__unused_2;
     +	int units;
     +
     +#else
    @@ mm/slab.h: struct slab {
      #ifdef CONFIG_MEMCG
      	unsigned long memcg_data;
     @@ mm/slab.h: struct slab {
    - 	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
      SLAB_MATCH(flags, __page_flags);
      SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
    + SLAB_MATCH(slab_list, slab_list);
     +#ifndef CONFIG_SLOB
      SLAB_MATCH(rcu_head, rcu_head);
    + SLAB_MATCH(slab_cache, slab_cache);
    ++#endif
    ++#ifdef CONFIG_SLAB
    + SLAB_MATCH(s_mem, s_mem);
    + SLAB_MATCH(active, active);
     +#endif
      SLAB_MATCH(_refcount, __page_refcount);
      #ifdef CONFIG_MEMCG
32:  0abf87bae67e = 28:  94b78948d53f mm/slub: Simplify struct slab slabs field definition
33:  813c304f18e4 = 29:  f5261e6375f0 mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only when enabled
27:  ebce4b5b5ced ! 30:  1414e8c87de6 zsmalloc: Stop using slab fields in struct page
    @@ Commit message
     
         Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
         Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
    -    Cc: Minchan Kim <minchan@kernel.org>
    +    Acked-by: Minchan Kim <minchan@kernel.org>
         Cc: Nitin Gupta <ngupta@vflare.org>
         Cc: Sergey Senozhatsky <senozhatsky@chromium.org>
     
28:  f124425ae7de = 31:  8a3cda6b38eb bootmem: Use page->index instead of page->freelist
29:  82da48c73b2e <  -:  ------------ iommu: Use put_pages_list
30:  181e16dfefbb <  -:  ------------ mm: Remove slab from struct page
 -:  ------------ > 32:  91e069ba116b mm/slob: Remove unnecessary page_mapcount_reset() function call

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05%40suse.cz.
