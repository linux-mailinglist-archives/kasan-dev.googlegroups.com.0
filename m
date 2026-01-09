Return-Path: <kasan-dev+bncBAABBHGWQPFQMGQE6WL2DGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F28FD09005
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 12:48:46 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-64b735f514dsf5194875a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 03:48:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767959325; cv=pass;
        d=google.com; s=arc-20240605;
        b=EpT02V7/aa97ve/thrr/YAvWy40sHMfMu8IP4Ym4MUt7uz4OHCKcEAdqlcHSGdNFiw
         ucq3va7DXmNu78uCnVwipwbncFNoWmOaWNcGlz0uI8w0C4PiLiv8tSBDblEqz7+brrY/
         ZRgy+EUqTJNgg8APMGc4Bvc3FDHIKczXZh1hVxzobQN5cnjQ7ZiZ9QDR+E/OwmQUdTix
         nvUdUXNvjJ0png3DgkugxYcQvNMYaHAGjmjHfuKW5C9E8H/694D9gfNKl1gJWK7aMTw0
         o6KQm9OkFGtBTnjXmETfkZEv30smlh08QHolSlf9J+UEiQvYxh4oKC5/4IaE/1DpQl8a
         Ly2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Kc4peGSgSnW7zIbvxhlgHFCDHu4DnYIANHklh9FJ6gw=;
        fh=J/FWBEignJZ7xg9aoQIzoGXFEfXXp9/IED1UG6aRt9I=;
        b=kMrzNEuav5N6vvo+cYd7z43YxGRvThEQpsbpHcjXAPUSroh4UQJZQrUD7mpS7Ao0Ix
         R+zgJDQg3WOarUPcRPkf127D2P24RefYmcoMAeg1Q+R7ytTZlXSf8WzJL1Cam1W83JV5
         IrAqSdc/YdIA275PT5oS65A7N2yh+uW/6VEZ+iqHVPvqK4GhDm+lMUfemLl0/JEwMf4q
         FKgCfg2nWHYO5vZ5T++ZnFd0WHg4QHmyPvx01y2TOedL92C0Y4VJzFO9jr9/bCDkgCQt
         T7mHTM0xSIwF/ANS+6oc3RfhlAI41HUBPpMNmZ5DRnr0/RLBRcgyvxRB4VpHmNDFTUXT
         zMyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DGG+debD;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767959325; x=1768564125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Kc4peGSgSnW7zIbvxhlgHFCDHu4DnYIANHklh9FJ6gw=;
        b=oNdVOWdI0MIjyK0KjkjoqTV3u996I/K8lYRBLhysyAuMyyMHno6EMP9Zd2SSf3wQ/9
         U8SOTbgTc4Oe0UXhqSpTo0HeFbtgGYqHjwGvBFGulku6jAFmppnVKGGF4b+GGNk3JBbb
         DtX7jSPwROKsEW5+PRcmhtNd639FzQPwTa5CKN/nbOoD2UO9O3/yiswvCcIjvIY93Hxh
         HgWi1fcpoW3EgL1lWT7q8EULnlTMMpy7h+8jgnsqvwVWzaKleQcNTEdzrCGP3wigOcIy
         V6PZJ142tGGEbNzYLvt6wRtfs61QvOGHmNben0bTVLoKY+Uj3YbdHzL8vieLSR7VO/Eg
         my5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767959325; x=1768564125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Kc4peGSgSnW7zIbvxhlgHFCDHu4DnYIANHklh9FJ6gw=;
        b=Qvtjb+TAmStEeNCG/azvwDHzOCptPsOWMGuyVc66e7lcOijPEvAiJuByokDDXRQlS6
         eAwe5S3FSfLKJG2nIsdrP5MJ5KN8cvs49eUAh6vLsEwyUlImB+zd9BpUT67zJftM10TU
         3V8hqpfXrhyaRw3/uWg0MJFw1Liw7AP/x0Cki01pX9DziMoVlklz6KBy8Sk4VwqlpDr1
         UzwaJOS50TTxJiHGhm4eqP66P8xOz5FM+ZFYHlrwLBXLAVzllhN170/e9LpRAFpQLXhi
         ok0+k5qOKJFfm5rncy/qQ3jVOFXrFLIt/nUJtiKHKwIkKnHQ2CoDuVEScnbYhk3WW1XC
         +YUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsFicZhh9pcwpwQkuBqUoxrIIWZV6xsYEqdZgjsEgd6uLjA+3JA40Wn+GwFiyQT3K7SrFYkQ==@lfdr.de
X-Gm-Message-State: AOJu0YwdD75wNJ0RIUl7cKNg2FaGynIE3g8otqwC/SxPuzNaCIhb391w
	VIwEE0fNXm37g6PTx8VOiaI/xUovMDRp7xnLVapzm9hGLUOSuo6CrKeJ
X-Google-Smtp-Source: AGHT+IGTGyb9rcCEfFaAXy1d0QPXPBwEjFRGvB/CVWoA9YwT1N4jUU2oAG7hzhvQut8LVB19bf5QNg==
X-Received: by 2002:a05:6402:2554:b0:64c:90e9:aeac with SMTP id 4fb4d7f45d1cf-65097df5640mr9099886a12.13.1767959325413;
        Fri, 09 Jan 2026 03:48:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HyvAJkI+rDUrNa+FtK6Ja2WiSmoeGn54cs3kL0FEExbQ=="
Received: by 2002:a05:6402:304e:10b0:650:855d:592a with SMTP id
 4fb4d7f45d1cf-650855d5aadls1093569a12.2.-pod-prod-07-eu; Fri, 09 Jan 2026
 03:48:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV/TkLttpLbOx8DA1YVxFaz/zIHO4sYEL8yweYKVcUj8Gz96abs63d2VS6hcIShNSLWcajK/2nX4EA=@googlegroups.com
X-Received: by 2002:a05:6402:274c:b0:650:8563:fdee with SMTP id 4fb4d7f45d1cf-65097e5d7c8mr8058595a12.25.1767959323583;
        Fri, 09 Jan 2026 03:48:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767959323; cv=none;
        d=google.com; s=arc-20240605;
        b=ObB5JUYhfFUYzqEovrbsY1FhEP0LE3vKITY/tFFINvB9SHOp7vhF6NPMeQdh115hLZ
         +LzKeEl/gv78BCl1Oj+OQbs3nyQe7vhyT9bIyoOW4TkeFGFYrbmzdLuhI/5ndI/O/+82
         Xv+LYf3s3FYX9oWsPUeOXIgIHBSCTF1arnSCMn83CEcGasJwIsVkwhPzcgFPkX8jFeVH
         a9S5EKXrs8ZT/Hd5eAPX57UMiaWUtYkHkQRSsA9aX/uC6N5PdJxeGnES0V8yy5uDpN51
         3iBO3w+pGFAR3n5StFVvp8a43EK2hszJImQKUxiNQWExaXbf6PxN6KI95aQyaRgMZyy9
         azZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=oYF757VFZbjPp9+rgGQc+tuvo82+suocCGJ/1TmFUs0=;
        fh=UxK0f7Sg+Kvncwz8/Gj/XfKMLaSYI6WylwLy90nXgxM=;
        b=RubgX675skNI8k841UVAqB9Vhr+Meme0VIwJskAQ2ZNapRTG2wcIPNENTfgUPPuof2
         K7h7R7DheOkNVaKuNrrAWZTPfuNka88EMSNRXPwv/vdC5sAR7G4HQtF+H2JxDWUzcW/e
         mYAlEeW0TVmwo85mVV5Cl6RDMHkVrD8wbqpORLhVrOtipYePBS5ktifmR8dOkzJNUrte
         axk/YD2sowo/83vWzSAXmntHWiE/MijVdtEBS+sm31mV3H/5S4H2GlzvYxDDdewB0Yj+
         Qmo7XZDpBG1YbKBvQ+4OhHaOO/UtFXP/y3CkhDkNBg/2v832oPxqiTrSSppbK0St8OSA
         7nLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DGG+debD;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta0.migadu.com (out-180.mta0.migadu.com. [91.218.175.180])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d5b8e44si213993a12.2.2026.01.09.03.48.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 03:48:43 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.180 as permitted sender) client-ip=91.218.175.180;
Date: Fri, 9 Jan 2026 19:48:20 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC 14/19] slab: simplify kmalloc_nolock()
Message-ID: <6lagtqkkxsnuphgmluwodah7nlhiuovw74fzdzr7xgq4nwdwup@eyfgwukzbynd>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-14-6ffa2c9941c0@suse.cz>
 <4ukrk3ziayvxrcfxm2izwrwt3qrmr4fcsefl4n7oodc4t2hxgt@ijk63r4f3rkr>
 <4fca7893-60bd-41da-844f-971934de19b6@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4fca7893-60bd-41da-844f-971934de19b6@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DGG+debD;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.180 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Jan 09, 2026 at 11:11:26AM +0100, Vlastimil Babka wrote:
> On 12/16/25 03:35, Hao Li wrote:
> > On Thu, Oct 23, 2025 at 03:52:36PM +0200, Vlastimil Babka wrote:
> >> @@ -5214,27 +5144,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
> >>  	if (ret)
> >>  		goto success;
> >>  
> >> -	ret = ERR_PTR(-EBUSY);
> >> -
> >>  	/*
> >>  	 * Do not call slab_alloc_node(), since trylock mode isn't
> >>  	 * compatible with slab_pre_alloc_hook/should_failslab and
> >>  	 * kfence_alloc. Hence call __slab_alloc_node() (at most twice)
> >>  	 * and slab_post_alloc_hook() directly.
> >> -	 *
> >> -	 * In !PREEMPT_RT ___slab_alloc() manipulates (freelist,tid) pair
> >> -	 * in irq saved region. It assumes that the same cpu will not
> >> -	 * __update_cpu_freelist_fast() into the same (freelist,tid) pair.
> >> -	 * Therefore use in_nmi() to check whether particular bucket is in
> >> -	 * irq protected section.
> >> -	 *
> >> -	 * If in_nmi() && local_lock_is_locked(s->cpu_slab) then it means that
> >> -	 * this cpu was interrupted somewhere inside ___slab_alloc() after
> >> -	 * it did local_lock_irqsave(&s->cpu_slab->lock, flags).
> >> -	 * In this case fast path with __update_cpu_freelist_fast() is not safe.
> >>  	 */
> >> -	if (!in_nmi() || !local_lock_is_locked(&s->cpu_slab->lock))
> >> -		ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
> >> +	ret = __slab_alloc_node(s, alloc_gfp, node, _RET_IP_, size);
> >>  
> >>  	if (PTR_ERR(ret) == -EBUSY) {
> > 
> > After Patch 10 is applied, the logic that returns `EBUSY` has been
> > removed along with the `s->cpu_slab` logic. As a result, it appears that
> > `__slab_alloc_node` will no longer return `EBUSY`.
> 
> True, I missed that, thanks.
> Since we can still get failures due to the cpu_sheaves local lock held, I
> think we could just do the single retry with a larger bucket if ret is NULL.

Sounds good - this is a clean approach.

> Whlle it may be NULL for other reasons (being genuinely out of memory and
> the limited context not allowing reclaim etc), it wouldn't hurt, and it's
> better than to introduce returning EBUSY into various paths.

I agree - it seems cleaner for __slab_alloc_node() to return only NULL
or a valid pointer. If it could also return -EBUSY, the return semantics
would be a bit less clear.

-- 
Thanks,
Hao

> 
> >>  		if (can_retry) {
> >> @@ -7250,10 +7166,6 @@ void __kmem_cache_release(struct kmem_cache *s)
> >>  {
> >>  	cache_random_seq_destroy(s);
> >>  	pcs_destroy(s);
> >> -#ifdef CONFIG_PREEMPT_RT
> >> -	if (s->cpu_slab)
> >> -		lockdep_unregister_key(&s->lock_key);
> >> -#endif
> >>  	free_percpu(s->cpu_slab);
> >>  	free_kmem_cache_nodes(s);
> >>  }
> >> 
> >> -- 
> >> 2.51.1
> >> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6lagtqkkxsnuphgmluwodah7nlhiuovw74fzdzr7xgq4nwdwup%40eyfgwukzbynd.
