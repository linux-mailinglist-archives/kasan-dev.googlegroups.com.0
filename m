Return-Path: <kasan-dev+bncBAABBQMXXXFQMGQEWK6IDFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 268D1D3C392
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 10:32:51 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-430f4609e80sf3035047f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 01:32:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768901570; cv=pass;
        d=google.com; s=arc-20240605;
        b=JMw/Na5FR2vaD7+QtrNZbGL1o7xG8otM6TfGuhE0/fpVh50QxC51ncBA8Tz4msmbc9
         lGahIMc1DQJhgCtZx14awVLB8zuy2culgI03W+oHzfe+u8/MkJMKCXb8BeYzQNkAUqnI
         sKU0fpHK6B1pZfc1oqkBnbbnB+MbW4EBCCQS1eym1Pv0Qi8rkwXJ/rgtqJRm0PZJlR6h
         YQmRQelaJkcKki1U1YABvjAMV+/1Y4z94ZAqtsCJ7y9N9/VQOcDJnoNl7AQIdlpd0ipU
         zsPCva339QlH+Y+nTydhE0in2q5wwuGz2Y+ggtm9KqqQgRO2aGc/Mpni+NWN1JUe3VJt
         axAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yzrF05VC+aXg4kjTS5siulm+xo/Bru1v49Y+FaK6nVk=;
        fh=U3CfbT8EaveT4Rw1OwxXiEjoEcaqg28FwdmxSQdbJoM=;
        b=YFnSY9d/bTch7x5xZYlB1qikiNly7kntSrmdawTJg+zjWZeYtMuvH5h+Whae3Bedw7
         k/iofpnpx325r4N2HBitDXA92mFAdJPPrfKDjONtPiN4/f/d3pSKFfk+/JKxDk+3qeMl
         GSCq7LhBBMQ5xX0uvNGyiRqFYHE3BKIOOMFjJ4+42Kk7pfrWbem9v1oS0E+fsQaOhjRC
         9Mi9rCkZWqgwwHmSeLy60mSaUszM0QAX7Wvddyd3XRG2CDugkXFWb8ILcd4LFSPqxWFs
         gl3NPYtQqyn6q7iVVYTdpsd5pZ24F1J915uPt9mk4vmFCedLLksorFys28KJUAya3XYM
         LQQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZYE6svoZ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768901570; x=1769506370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yzrF05VC+aXg4kjTS5siulm+xo/Bru1v49Y+FaK6nVk=;
        b=NkuidNeGcD1t5uA/ZXVNvlJQ9ZjYqox5RukcJ71mw2+F1yPaoCnJXguDsulvci48gu
         TxVe0cKLGT2qLGaZV0WnH0f31LbmT8OAuq86ARBIOsBGTjtPb/Pa9u+pL8AY4gxCe/el
         cQyI+CFCH/udepEpVoETcoR24Aebn/iipclp+rdDSpqQYnE/3WPT1usMhURpPgiXjuav
         1A1lZoUnjsN+tcNzlHnSeAih732xXijKpSl21zgX3J/S/rjBM+uB+3uGT93xleYIKykp
         UUvPfdXJmYzAK9gjBbSd/2uQwG1jC/IpRf6IrHSexKRoGSWt5KTA3XZ5B64ovsuKmxya
         ZJ4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768901570; x=1769506370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yzrF05VC+aXg4kjTS5siulm+xo/Bru1v49Y+FaK6nVk=;
        b=clnWNJZMGxJ41Konrgaimx53GdmwTghAbD1GapMDGtlGUt6w+NU2CFeETXQDQgBS7S
         sWG/H7mqKJjMoJws7uiQzdF3SDgXGsfO7+NndmweJUM9a2MdR8yTnTITBIWz0wncOoda
         EieXxowT5J051eMW7Z1v2cXY+WRcI5KTJ6qt9z9VdagbbkRibBvERH5NmXz8aniWcs0q
         apsRhDiYFoXLF3nQhpQ/yIbgMNeUiZCR9w/eA25o7kYzp0D950PQHRpi8w77wHDi2GRN
         h9LyPsx8Ov7kA4ly4YQrC83uxB6CAuhqO4VX/xUbnjaIoGPABrevgSpdBrNNBNoZZZal
         OWIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWO8XdG7jep7STZVsTNOZe02N8e3lWZwZ14SQx7UEjYd+GrGUcEnaxTra9//7+ZNaJqG5v/Dw==@lfdr.de
X-Gm-Message-State: AOJu0YwMVU2+qNB8lD1YdAZW34qnDmWJHRmzBfUvU+LS/O0I21qypTyS
	FAv83lq/inm6IRZinbwVGMsnCJQdqH1vi/0OTDB/WR5ZckRJl6ZTHMHX
X-Received: by 2002:a05:6000:2c05:b0:42b:3ee9:4776 with SMTP id ffacd0b85a97d-4356a02649cmr20414911f8f.5.1768901570335;
        Tue, 20 Jan 2026 01:32:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GS3CqFnv+QawhV+OVWih7qvX3b7APakHiFQlKy8stZQw=="
Received: by 2002:a05:6000:430d:b0:435:95d2:8af4 with SMTP id
 ffacd0b85a97d-43595d28d32ls28555f8f.0.-pod-prod-04-eu; Tue, 20 Jan 2026
 01:32:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXt1Ee5xOw8Ttw8YEim1sFZg3128GogeVBL4/dI9n2YUHi66bZ92+nKJg0zo3AEEjLH6hgsFKlME3I=@googlegroups.com
X-Received: by 2002:a05:6000:230f:b0:432:c37c:d83a with SMTP id ffacd0b85a97d-4356a02c238mr18710922f8f.15.1768901568278;
        Tue, 20 Jan 2026 01:32:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768901568; cv=none;
        d=google.com; s=arc-20240605;
        b=izhDC7B6GD5n90RbBaE3CgOW0Q7PhyyLHvDKiIiq0lGWePG+onE1SQCottH8naIXh9
         6HPcTknvkhT8hyj2DhHwwScYfWlnbCr7WnCB5UUJcClga0sBDtdLQDYHI/4mZmSlqWsx
         QTDhhy25oE8bcusOikK/KIaMYcJ4eULlerRPz5xn2Fbw7+SXQOlREAxwOhs0WjgueTbJ
         13XFxX6f/MAKAD9nPHEdfCVodo8xXBy52I87/ZpxdE+Ak9YEt8Ltmi4/o267+lUKf+9D
         S7MAhNKD8xupiw0Butyy6DDq2S87uO6CSz7+NV8RhsvO/4W8aweUjH9vx25aBwjlOHIX
         ZcNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=kHHh12InGybJlgb+yVFYP3fxoRRSSX2x0XpjMmVp7aY=;
        fh=S92BviIZbfEQZeR9HMQx/kOqL+g0FVMqXRnC/moZTp8=;
        b=IMpWIqavXvPPSdOy2krmu8typwBr2MT+iR22pHJduVw+dcnvmKuV5jRO1KD+4zE0SN
         nrG8xW2Ncq8j5HReGz8Ccd5s+IO23qkayipRZ//CmFkf/AATxVlOJsekzehpIiTSbxAb
         AzUs2suvkRqa6MGtRV1bvr3DVmfBaG+DxaKWIl1TDbtcfN1zPy6BU/gHu08W+TSSkxyK
         PSnBlEuSvMZKtl/yEk4J3D0uSBz9G9oVUvvjKlIw0zunPD6BRzr4qXsuhwLW04uvJ6NX
         LC6uK4nkjuj288jUHYMk68s4AOISEafTg9hHjmX6O7EJqb0tDpIdq/n9+E+OluBsTIOR
         js2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZYE6svoZ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta0.migadu.com (out-181.mta0.migadu.com. [2001:41d0:1004:224b::b5])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356994f0dcsi320334f8f.5.2026.01.20.01.32.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 01:32:48 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) client-ip=2001:41d0:1004:224b::b5;
Date: Tue, 20 Jan 2026 17:32:37 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Message-ID: <zo75mmcyxdzrefl7fo4vy2zqfpzcox4vrmjsk63qtzzmwigbzk@2hb52by2j7yy>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <aW3SJBR1BcDor-ya@hyeyoo>
 <e106a4d5-32f7-4314-b8c1-19ebc6da6d7a@suse.cz>
 <aW7dUeoDALhJI0Ic@hyeyoo>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aW7dUeoDALhJI0Ic@hyeyoo>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZYE6svoZ;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as
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

On Tue, Jan 20, 2026 at 10:41:37AM +0900, Harry Yoo wrote:
> On Mon, Jan 19, 2026 at 11:54:18AM +0100, Vlastimil Babka wrote:
> > On 1/19/26 07:41, Harry Yoo wrote:
> > > On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
> > >>  /*
> > >>   * Try to allocate a partial slab from a specific node.
> > >>   */
> > >> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> > >> +		void **p, unsigned int count, bool allow_spin)
> > >> +{
> > >> +	unsigned int allocated = 0;
> > >> +	struct kmem_cache_node *n;
> > >> +	unsigned long flags;
> > >> +	void *object;
> > >> +
> > >> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> > >> +
> > >> +		n = get_node(s, slab_nid(slab));
> > >> +
> > >> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> > >> +			/* Unlucky, discard newly allocated slab */
> > >> +			defer_deactivate_slab(slab, NULL);
> > >> +			return 0;
> > >> +		}
> > >> +	}
> > >> +
> > >> +	object = slab->freelist;
> > >> +	while (object && allocated < count) {
> > >> +		p[allocated] = object;
> > >> +		object = get_freepointer(s, object);
> > >> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> > >> +
> > >> +		slab->inuse++;
> > >> +		allocated++;
> > >> +	}
> > >> +	slab->freelist = object;
> > >> +
> > >> +	if (slab->freelist) {
> > >> +
> > >> +		if (allow_spin) {
> > >> +			n = get_node(s, slab_nid(slab));
> > >> +			spin_lock_irqsave(&n->list_lock, flags);
> > >> +		}
> > >> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> > >> +		spin_unlock_irqrestore(&n->list_lock, flags);
> > >> +	}
> > >> +
> > >> +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> > > 
> > > Maybe add a comment explaining why inc_slabs_node() doesn't need to be
> > > called under n->list_lock?

I think this is a great observation.

> > 
> > Hm, we might not even be holding it. The old code also did the inc with no
> > comment. If anything could use one, it would be in
> > alloc_single_from_new_slab()? But that's outside the scope here.
> 
> Ok. Perhaps worth adding something like this later, but yeah it's outside
> the scope here.
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 698c0d940f06..c5a1e47dfe16 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1633,6 +1633,9 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node, int objects)
>  {
>  	struct kmem_cache_node *n = get_node(s, node);
>  
> +	if (kmem_cache_debug(s))
> +		/* slab validation may generate false errors without the lock */
> +		lockdep_assert_held(&n->list_lock);
>  	atomic_long_inc(&n->nr_slabs);
>  	atomic_long_add(objects, &n->total_objects);
>  }

Yes. This makes sense to me.

Just to double-check - I noticed that inc_slabs_node() is also called by
early_kmem_cache_node_alloc(). Could this potentially lead to false positive
warnings for boot-time caches when debug flags are enabled?

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/zo75mmcyxdzrefl7fo4vy2zqfpzcox4vrmjsk63qtzzmwigbzk%402hb52by2j7yy.
