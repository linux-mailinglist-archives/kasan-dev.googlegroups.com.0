Return-Path: <kasan-dev+bncBAABBPG5XPFQMGQE3O47VDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D3804D3BDB8
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 03:55:57 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-382fbcb5076sf22391181fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 18:55:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768877757; cv=pass;
        d=google.com; s=arc-20240605;
        b=TR/34oJBD0BZAQwxsCegeVuGnHyEl91V+298qvCKClfQxFihBuJ/kliF/bW0ZXTasL
         vfW3yudCr4xCdIzGzALv/kLG79pNAt0i4uadYrRu+r56FKRaT71gwRgtQlPzMMObZQUF
         7GMvEHKyc4cLRiSk0D/hd2cvUUG3uD9vUK3bRIMrGY8nFPj0GQ+cqxmxVNSHrSjqxYyg
         8Jz82wUMWxLs1nFs3tN5XeTMQLxGPfmL2o5f/oPnZpG+1171+1IMpOGiVnio8UQ9SiR2
         58/co9XofYCWRi+LEBoIOLmDJ8593yiDpQUS3ZI8Xo9WwWpXXqRPdxDvlOJ7UyoLlAwN
         R+qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rIlcH1/0w8xo5Pr6QLuOvdrcWB3ZLjoBoCvGDTetoEQ=;
        fh=jXCGGgZuY+5mKF3cmHnZCDFrgXIm1bL8OWS6bJr+yI8=;
        b=gDfeKEdsbYLvFuIR0pbYtPN9AZ628HYRFJ0uUvSYMEt4lLOYibg35RkvET0+Btxtmh
         FGTXiyRZ5SvhdPR8MdJtBheQ9RPzX8voM8RU2868l0KdKKaKDWJBETSIC9IvrhyR27da
         j5vw027mqePcl9Cj6ZXcK4hrhIIeDQBEDxR14VFbbcJkitmc6zANLJ1oIFOwXMkHT4FI
         tqNx6c5VWcFquVaPnzxFUviiguSrZYiCIYG1sWBAaodHMCO6KJqJbU4vmsAC/xRpXH/q
         HV0VmMrZKXGchMAHr/NNm+xNUe94rbz6WvT1pHountPkrgE7rBPg1xcgvrwoRp+8aarC
         mcIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ul671Yoi;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768877757; x=1769482557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rIlcH1/0w8xo5Pr6QLuOvdrcWB3ZLjoBoCvGDTetoEQ=;
        b=Ctyiy99xZ+95zEB8DjaDfVUk3PW0VHnV8NnkIB0jj0orHPSqJxl80rPXF8KZwMO9IW
         AggdNSnJ3GY1ZzKciCO5Rg4Ln0C197q47rEo42BlRt/L8fJ0Z9NESQ5qss6vN/0DxMwG
         c2tpnGX1kX1sNVFVyjvBDSQxsduteE+VeVXfwVMTLi0zz7N9Vhm5kOJmAes42HZcDNAq
         eWNJh0H8K7m3lPVt7rxqZKcV1KJR0XHRxkBL4Q4GA1aLNFZVK8OjHvJaqvzp9yNMqWIt
         GzfVLR+PeH7dgWuU07cib8w5Ufq926NwGnNLEPzXkJVfjGgDg4Gf+gW5ClOimC8M7qur
         3/oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768877757; x=1769482557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rIlcH1/0w8xo5Pr6QLuOvdrcWB3ZLjoBoCvGDTetoEQ=;
        b=SsASIdU9yZOs9LG1q/eLJcfoKNNKPI9eUE5lF/dEpXvu4YTPc+b4qzgmpyOWRWnTHU
         anopznWUtZPSMc//sRyXrKfvj9cRjSeXydnjHKBg1Cf1WZRxIU7e8Z0tzEdeyFdAFkF3
         xz6s+Xnepk19twE/Jy+kFjk2V9i+oUnN/NW+rlYNjo9rhwtg+/Qwzn6S+sx/hA4unDT1
         +/yQFSMAk7iQLAY3C/gEN83OHc3m+wSjb5c34Jio/+OmyMRnNwrFPb09TxB3HjhB8Mfe
         smxFjMKxcgUVsi6C6IWFP8+TbWzEfbabwTGWzy3yEGn45rTkkFbx5d0ZFunV620s9XjC
         xIzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUSdnAf0IB+8mRBWnO1ebDVU8ifMb3BKnrwugQSnRrxitNUJ6JFBaz9pMYahejcCVDW7Zd+PA==@lfdr.de
X-Gm-Message-State: AOJu0YxXnMR1wSDz8qjaQiqYZIl8y/CqR5Il4qnYUxDv8j7QJxyHLySz
	Q2a/ukzbf9q3fRYUV1vLYOKT07x3lcplgTuZV/Q47kgSOqiy4UUmfzN4
X-Received: by 2002:a05:6512:61a6:b0:59b:8483:8d8b with SMTP id 2adb3069b0e04-59dc901d3afmr151020e87.18.1768877756796;
        Mon, 19 Jan 2026 18:55:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FUuKqzfVSIVZd4tVK+Fnsz+Gx87kil+ghau180CwayKQ=="
Received: by 2002:a05:6512:3c8c:b0:59b:7324:a12c with SMTP id
 2adb3069b0e04-59ba6c612acls1444926e87.2.-pod-prod-07-eu; Mon, 19 Jan 2026
 18:55:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVyqq90Vim5PZ0tUCU4XDlHEhhLp6NpVKAXvsi1Aci+R34m4BB2lEiqP9iLr/c6hh78Y87F3ROvDI=@googlegroups.com
X-Received: by 2002:a2e:9a10:0:b0:383:f43:ed30 with SMTP id 38308e7fff4ca-385a53f4a56mr1735931fa.12.1768877754543;
        Mon, 19 Jan 2026 18:55:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768877754; cv=none;
        d=google.com; s=arc-20240605;
        b=je8s4Z4gfllGd8j3S5AxOFbtaT/ngRVbC9v32fj0s+AVFQyBgQyYDc5kn5Cpc5BD+I
         WIkl39kmik4ouZbpjc/SQXb/Lf7w4pR3NUkeysGo5BjpE//xaced7evmzyEhnewcppg3
         Vv/E642p9zt1hVTLmMTmceUcBv47u/hHOnFC7yAFhZyD3S0ypUROvkIl112pbAqYgz3R
         gpig0JUyDq3+nmLMERHFguw7Zf+0vGnwXa2jO6mVbq0Wzd1mQ/7OfF62Yqsa4nR9F53B
         O174/WSz5zPHM8Xsiehe81mntQtN+p8UJP3JgoAkpLu6o5IpB//ff8AdghAKXezOTDum
         zcpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=inDvl4GaipWhYSp0U8tScgUdBjqvSGDRhS8Caxa209Y=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=XYTFMW5MpndbMbKY7URPqMh710RtQEhEAa2SdU6z4BvQwsjvLMdT+StaN6w5KABPVb
         o+Kerny9kA5X/57SEdIevfRb5hB7DHh1WaWcuNRsLy0DUqwnvceBpfTKWPp2osRYLgjE
         EIJLWUd3GPSORioaN/ccbc55jKyhHFSUz28Vcdrs2iYyKhPmyTibxQBDeKnM5Aq4VKrq
         b5phhwB3MM0FPA8R/0Az3bk1fnbCWnzGpOWoPm5ba8ogh0mP6tRvdB4bAwQL0XQPzTMN
         SzzXB65axHk6+1z3DbJ6dIMLXhcvJ5c56PV/+/KrGo6NWJyk6dXTFoDg2JMqrcq+cnwk
         4wJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ul671Yoi;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [2001:41d0:203:375::aa])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e78091si2310161fa.8.2026.01.19.18.55.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 18:55:54 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::aa as permitted sender) client-ip=2001:41d0:203:375::aa;
Date: Tue, 20 Jan 2026 10:55:25 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Message-ID: <mxrcthlqj6rbecg5z33lc7oqnbicr5fn5lmvni2tjo2dc3oe76@u5vettfyypl4>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ul671Yoi;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::aa as
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

On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
> 
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> 
> Extend struct partial_context so it can return a list of slabs from the
> partial list with the sum of free objects in them within the requested
> min and max.
> 
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list.
> 
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
> 
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions.
> 
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> 
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 264 insertions(+), 20 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 9bea8a65e510..dce80463f92c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -246,6 +246,9 @@ struct partial_context {
>  	gfp_t flags;
>  	unsigned int orig_size;
>  	void *object;
> +	unsigned int min_objects;
> +	unsigned int max_objects;
> +	struct list_head slabs;
>  };
>  
...
> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> +		void **p, unsigned int count, bool allow_spin)
> +{
> +	unsigned int allocated = 0;
> +	struct kmem_cache_node *n;
> +	unsigned long flags;
> +	void *object;
> +
> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {

I was wondering - given that slab->inuse is 0 for a newly allocated slab, is
there a reason to use "slab->objects - slab->inuse" instead of simply
slab->objects.

> +
> +		n = get_node(s, slab_nid(slab));
> +
> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> +			/* Unlucky, discard newly allocated slab */
> +			defer_deactivate_slab(slab, NULL);
> +			return 0;
> +		}
> +	}
> +
> +	object = slab->freelist;
> +	while (object && allocated < count) {
> +		p[allocated] = object;
> +		object = get_freepointer(s, object);
> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> +
> +		slab->inuse++;
> +		allocated++;
> +	}
> +	slab->freelist = object;
> +
> +	if (slab->freelist) {
> +
> +		if (allow_spin) {
> +			n = get_node(s, slab_nid(slab));
> +			spin_lock_irqsave(&n->list_lock, flags);
> +		}
> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +	}
> +
> +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> +	return allocated;
> +}
> +
...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/mxrcthlqj6rbecg5z33lc7oqnbicr5fn5lmvni2tjo2dc3oe76%40u5vettfyypl4.
