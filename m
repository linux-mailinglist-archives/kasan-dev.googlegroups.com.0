Return-Path: <kasan-dev+bncBAABBXNUU7FQMGQEZ5RRJKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 22FF6D2C879
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 07:27:43 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-64ba9c07ea2sf2203105a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 22:27:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768544862; cv=pass;
        d=google.com; s=arc-20240605;
        b=lQ2rmQJAwDZpu6vDchcXa3E7FA0UOSYB1TRlit40Q+kamAqFsxVGFDmnMCosEC3Mnz
         AFlwSVoYDdJsgH6vdVWRxLLJJqT3l0LLSoYLHkYhj5PCbUWK2/2ovYuUo95ceOsbFD4Q
         2eKuPTXbMbS4/CNCaTT8W1aitdgSXmGMRzCf7SHm8nHXJStY+NDtLMhNef8UGLo2fPrV
         L+Pm65J3OUKRVmdiIBiHovFF6FqoyJtnuXSUPjp0wSSLtIQBMMlGu1YDWcfwzN8LEii2
         XJwCxmxRcmMv1E4LK3qJ82MkxhDmErAtHiSSfVx6PlVbd0zlVRG6xU9Zhp0YyRRuU4v3
         KXLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iWGH0KyK8yEt/FAJLArKqxPlUlFzmU/PJ/njWx1xPjg=;
        fh=QHWPTkopGtFU8lbTpw1ke8MgEUXxddBsFZaAl7CW/SM=;
        b=MCy3XKcKMt5NT9XuWHUapqreECKr1yod9A7wYgKD7q1rPZkCkScY6Eamh+NZHH1oxt
         odzQo6IPc5IZVuQpl0gihg++/DD912m8qF54GeIoI4j24r4McWhJhcAjQtILguyUCJYt
         6/dy6cBckWhuUCdmAJ8aL6J8EIwFX9t8Fjzs4Kq1lQo+CERbePd6Alv4PXoFCbIFRkVa
         m/GjJ5Hhtiv3SiKyQHGw3m9P/WeKHYo6ioMlRzRygnhRxv5ZtLc53jSVJZoB5SG7UnFJ
         y2/oE8d2x9j0PfxotvXXjMTDTJ7fKMQN5kNy0vci/qj7pWeN1O7mt9YkMphbBznNO7He
         PuvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YTxvBXK0;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768544862; x=1769149662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iWGH0KyK8yEt/FAJLArKqxPlUlFzmU/PJ/njWx1xPjg=;
        b=bdvFiDWPjr1mDG92ea6KEdeXfNL9ccyzIpVslssTksstRFUIjGm6ZPeReiupHaniwo
         N9VkkFIH186keu1RURZCUFia/mejCQgRZXydBgZXjQVgc3SywIhKH3cKKlJKUXydFcLb
         ML702e0jfoiMm9vSnAhtPOGu34oWR+yhB+XubnCfDum0pRUtRqglw4GzS9MR/+wF4xlf
         gMbVvtfvbhzzFRvR6UahQG9329bDtuzluZ3EiMoat0RlPnJQ+X7wgcAz+jWQ87zX1Jox
         +laPmhGauMM/1lhSmPa6v9xJpzQEx9FWbJzHUaxG7jY6IReZcta3TA42HnNyxK6H4TNc
         4KZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768544862; x=1769149662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iWGH0KyK8yEt/FAJLArKqxPlUlFzmU/PJ/njWx1xPjg=;
        b=Wz803NrnooWzkMQMbZVmvGZGrSOHZrR55453AqTwdxrWZNJtDuiNow3WYD5t3kDO42
         ptJboTNJ1x8dRFtWsn56AMQHvzOmayE7IQdfGnMfGZawZkEsC7+Lq7qNu+jLRLjuFlCm
         HPWj+8hBy7fqrvoL/QDG6JtstrEdsylpIwey2u/ARf0CoHRDePvl+BwwYADoS6udyHNv
         hC7nFkIB5UIsOK4ryAWxPsyViQoD5DhcvGHPeTCRcG/hdbTt0E/pjPlXp7NXzd9A07Gu
         dDR4NAIsaIs56sTrCpTDCiIGAcsqpDs2j/4rGuQBHWa+mU9QG3+BrYT5JnHMmk2DIbiJ
         PKdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWkbbicIRldu10VarbKdXs9J4qpstr6iuCpDhvI+dbUiVO4tHD7N1v/jwaKlXJmM9v0Plt92w==@lfdr.de
X-Gm-Message-State: AOJu0Yxjfb2HiIP/bCAyhX7+jHUd6nRIDLhk12IPnVxQ8isKYGoxLsOP
	/3XN556+LvtL7+C3+x0kj0d5QHC+NkUN/rEITxX1xY9+E2kQ8y+CCvW1
X-Received: by 2002:a05:6402:51c9:b0:645:1078:22aa with SMTP id 4fb4d7f45d1cf-65452acb341mr1401644a12.19.1768544862369;
        Thu, 15 Jan 2026 22:27:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HgpuRKg6cocOoSXsTfnL7ctXesMQmLEnFRZPslLUttmw=="
Received: by 2002:a05:6402:4044:20b0:64b:403b:d9ba with SMTP id
 4fb4d7f45d1cf-6541c6d9c5als1309658a12.1.-pod-prod-01-eu; Thu, 15 Jan 2026
 22:27:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzOvnzyitxG3PRJCZ0pmTlZAGKQ2hPKKJEF4aaGJ+Y54T2YD+WcDC5u4/OO/o27z8gqkaqXG30GWs=@googlegroups.com
X-Received: by 2002:a50:cc05:0:b0:653:b83b:a66d with SMTP id 4fb4d7f45d1cf-65452bcc0a1mr1122914a12.28.1768544860464;
        Thu, 15 Jan 2026 22:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768544860; cv=none;
        d=google.com; s=arc-20240605;
        b=UPAySpxxGoy9qc3Bf8iAcyKNND649h1E9R029Uj1wDsjMZGH1KhN00uADpVKsokf/x
         XKAZV+aGwXS957PujPYQiAWs8QwaRayBWMJl4uorJt0Z09mO1Bc9MQPZnKUZ6kVKJMaE
         k5G4rUXdHICqCXRlLR2S9i6YiLlsH30XdXORXp8UI0p5OGbXqq2/yiMmoxbFHBfHEqyk
         fwwttqeB7QG0h90MTgJOoIWIOkg+XBrCsm+S2bjI9TTpRA8TJ84c6g+y/Ge9zwBPtR8/
         OWIznhfoMk2FYRWyU4LgRe5aN9wdfOIGE0UoylUbpqX4F1xszM7UpFX556ro/E3oQ4xp
         6oXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ZtRqq1YheiNBBvVmImDMizfzqDOKIgcriEPR9727W+A=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=XinO5mBjkFXAVAbghq8NTqR/BV84/uN6C4x2v4G0vZ+7jX7mIyCQw3GM3SC+LaFTUQ
         Q7T+Ci1OuhSAKTjqOiRnoXdi/vRSPcUKBK6d59VK5cUQwHH3rqbTsIpmlgba2l7d09eB
         DW3ZUR9LUmPOe+S+ltYSLaaCWGvTzxzBj3WhX1uK0ZXcAqllJMQjo29b4umeXZBjDDek
         9QpBQPKLlVVCTznFBpnUeulj1qf7/Ykg3GPgrxa7kMipU7psE5D8+00JB5nTT2Ky2ebB
         jJ4/Nc7mJsvsc2TlPep7dj8w8o9+y5gpKegmErOUQ7n6M9HE3gBbSIlffBZbT81SVChE
         gXtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YTxvBXK0;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [91.218.175.179])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532cef9dsi32142a12.6.2026.01.15.22.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 22:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.179 as permitted sender) client-ip=91.218.175.179;
Date: Fri, 16 Jan 2026 14:27:28 +0800
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
Subject: Re: [PATCH RFC v2 08/20] slab: add optimized sheaf refill from
 partial list
Message-ID: <kp7fvhxxjyyzk47n67m4xwzgm7gxoqmgglqdvzpkcxqb26sjc4@bu4lil75nc3c>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-8-98225cfb50cf@suse.cz>
 <38de0039-e0ea-41c4-a293-400798390ea1@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <38de0039-e0ea-41c4-a293-400798390ea1@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=YTxvBXK0;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.179 as
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

On Thu, Jan 15, 2026 at 03:25:59PM +0100, Vlastimil Babka wrote:
> On 1/12/26 16:17, Vlastimil Babka wrote:
> > At this point we have sheaves enabled for all caches, but their refill
> > is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> > slabs - now a redundant caching layer that we are about to remove.
> > 
> > The refill will thus be done from slabs on the node partial list.
> > Introduce new functions that can do that in an optimized way as it's
> > easier than modifying the __kmem_cache_alloc_bulk() call chain.
> > 
> > Extend struct partial_context so it can return a list of slabs from the
> > partial list with the sum of free objects in them within the requested
> > min and max.
> > 
> > Introduce get_partial_node_bulk() that removes the slabs from freelist
> > and returns them in the list.
> > 
> > Introduce get_freelist_nofreeze() which grabs the freelist without
> > freezing the slab.
> > 
> > Introduce alloc_from_new_slab() which can allocate multiple objects from
> > a newly allocated slab where we don't need to synchronize with freeing.
> > In some aspects it's similar to alloc_single_from_new_slab() but assumes
> > the cache is a non-debug one so it can avoid some actions.
> > 
> > Introduce __refill_objects() that uses the functions above to fill an
> > array of objects. It has to handle the possibility that the slabs will
> > contain more objects that were requested, due to concurrent freeing of
> > objects to those slabs. When no more slabs on partial lists are
> > available, it will allocate new slabs. It is intended to be only used
> > in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> > 
> > Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> > only refilled from contexts that allow spinning, or even blocking.
> > 
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> 
> ...
> 
> > +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> > +		void **p, unsigned int count, bool allow_spin)
> > +{
> > +	unsigned int allocated = 0;
> > +	struct kmem_cache_node *n;
> > +	unsigned long flags;
> > +	void *object;
> > +
> > +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> > +
> > +		n = get_node(s, slab_nid(slab));
> > +
> > +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> > +			/* Unlucky, discard newly allocated slab */
> > +			defer_deactivate_slab(slab, NULL);
> 
> This actually does dec_slabs_node() only with slab->frozen which we don't set.

Hi, I think I follow the intent, but I got a little tripped up here: patch 08
(current patch) seems to assume "slab->frozen = 1" is already gone. That's true
after the whole series, but the removal only happens in patch 09.

Would it make sense to avoid relying on that assumption when looking at patch 08
in isolation?

> 
> > +			return 0;
> > +		}
> > +	}
> > +
> > +	object = slab->freelist;
> > +	while (object && allocated < count) {
> > +		p[allocated] = object;
> > +		object = get_freepointer(s, object);
> > +		maybe_wipe_obj_freeptr(s, p[allocated]);
> > +
> > +		slab->inuse++;
> > +		allocated++;
> > +	}
> > +	slab->freelist = object;
> > +
> > +	if (slab->freelist) {
> > +
> > +		if (allow_spin) {
> > +			n = get_node(s, slab_nid(slab));
> > +			spin_lock_irqsave(&n->list_lock, flags);
> > +		}
> > +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> > +		spin_unlock_irqrestore(&n->list_lock, flags);
> > +	}
> 
> So we should only do inc_slabs_node() here.
> This also addresses the problem in 9/20 that Hao Li pointed out...

Yes, thanks,
Looking at the patchset as a whole, I think this part - together with the later
removal of inc_slabs_node() - does address the issue.

> 
> > +	return allocated;
> > +}
> > +
> 
> ...
> 
> > +static unsigned int
> > +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> > +		 unsigned int max)
> > +{
> > +	struct slab *slab, *slab2;
> > +	struct partial_context pc;
> > +	unsigned int refilled = 0;
> > +	unsigned long flags;
> > +	void *object;
> > +	int node;
> > +
> > +	pc.flags = gfp;
> > +	pc.min_objects = min;
> > +	pc.max_objects = max;
> > +
> > +	node = numa_mem_id();
> > +
> > +	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> > +		return 0;
> > +
> > +	/* TODO: consider also other nodes? */
> > +	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> > +		goto new_slab;
> > +
> > +	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> > +
> > +		list_del(&slab->slab_list);
> > +
> > +		object = get_freelist_nofreeze(s, slab);
> > +
> > +		while (object && refilled < max) {
> > +			p[refilled] = object;
> > +			object = get_freepointer(s, object);
> > +			maybe_wipe_obj_freeptr(s, p[refilled]);
> > +
> > +			refilled++;
> > +		}
> > +
> > +		/*
> > +		 * Freelist had more objects than we can accomodate, we need to
> > +		 * free them back. We can treat it like a detached freelist, just
> > +		 * need to find the tail object.
> > +		 */
> > +		if (unlikely(object)) {
> > +			void *head = object;
> > +			void *tail;
> > +			int cnt = 0;
> > +
> > +			do {
> > +				tail = object;
> > +				cnt++;
> > +				object = get_freepointer(s, object);
> > +			} while (object);
> > +			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
> > +		}
> > +
> > +		if (refilled >= max)
> > +			break;
> > +	}
> > +
> > +	if (unlikely(!list_empty(&pc.slabs))) {
> > +		struct kmem_cache_node *n = get_node(s, node);
> > +
> > +		spin_lock_irqsave(&n->list_lock, flags);
> > +
> > +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> > +
> > +			if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
> > +				continue;
> > +
> > +			list_del(&slab->slab_list);
> > +			add_partial(n, slab, DEACTIVATE_TO_HEAD);
> > +		}
> > +
> > +		spin_unlock_irqrestore(&n->list_lock, flags);
> > +
> > +		/* any slabs left are completely free and for discard */
> > +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> > +
> > +			list_del(&slab->slab_list);
> > +			discard_slab(s, slab);
> > +		}
> > +	}
> > +
> > +
> > +	if (likely(refilled >= min))
> > +		goto out;
> > +
> > +new_slab:
> > +
> > +	slab = new_slab(s, pc.flags, node);
> > +	if (!slab)
> > +		goto out;
> > +
> > +	stat(s, ALLOC_SLAB);
> > +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> 
> And remove it from here.
> 
> > +
> > +	/*
> > +	 * TODO: possible optimization - if we know we will consume the whole
> > +	 * slab we might skip creating the freelist?
> > +	 */
> > +	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
> > +					/* allow_spin = */ true);
> > +
> > +	if (refilled < min)
> > +		goto new_slab;
> > +out:
> > +
> > +	return refilled;
> > +}
> > +
> >  static inline
> >  int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
> >  			    void **p)
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/kp7fvhxxjyyzk47n67m4xwzgm7gxoqmgglqdvzpkcxqb26sjc4%40bu4lil75nc3c.
