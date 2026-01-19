Return-Path: <kasan-dev+bncBAABBWN4XDFQMGQEEQL7QWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BC7FD3A7E7
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 13:06:50 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4801d21c280sf24366545e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 04:06:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768824410; cv=pass;
        d=google.com; s=arc-20240605;
        b=VQUE55EoSHaFVh48u0LJykYVIywFTJpdiFuztSD7auvhW2/5wJvU2JeTqBLbuHEfue
         kqzH91xnEuuDlqkzDSV+u5UeL+auEpL9+fS5oeGxPB6JTw2jCz5zjxUdwk4GyB9BI9fI
         awe1c9UBQo1nUPAHoPiYVg6jwTDO4KY+hrcAKDl237VMQaqjloCuMTCXMGigyZYawFe/
         277Nj6pOw3zLFo3k5a7i85ZvcWbwgJV7OsaupvZWLbkDSccHA1TdSe6BBgxFD15392ks
         6THVokv/HBTHgneio1OfztNXfnpchwrn8GujeV9oL6TUYclxGLFljeTQ0H1HZO+CBmHX
         VH2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bhQcUpd5xS0eXYyHxURQgoCrLtdFnYuSTs5zxTBuelI=;
        fh=iGz3PwltfVGNmNuVKg0t8oNuZhq/9QQzZuZlaUF5zgU=;
        b=bRz3Eq0gdpnz8cXMfjjZEENP7utnrRYrBHMbQfKbhd+B28aHsWKDdHQfXroKoCKCJp
         HFJtrB1FfuNrEN92gGTLRkjzbcY/q9h4uAC7B1Gx6E0S7F9AngU1300EeTDEsizOIRIn
         uYuBfT+rJe/zui4iMcvowjGsNKf8gu34WpYBcs+m/BaqQpNqp1WEMs74I9QFCxq4xIDP
         mwQozWvo7G5MO726yLfdBPdziqwHYwRRoWEILrhisQdi6CXMQqAgrmaE1BXqMUPmk945
         ROOMJxPQiG80+SS+O0nLzLcRpiCTNJRAyWn8HzTsftLRHXTxkRBR8lfywQ1gnuEqyvI2
         3hfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ujesgdvy;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768824410; x=1769429210; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bhQcUpd5xS0eXYyHxURQgoCrLtdFnYuSTs5zxTBuelI=;
        b=OXBKeh8o7lDtJ23qgeQUOreg2wWzxYRvI7NWVMfTDbe6keHobZJVl6fSzgV2dP5x5X
         UP/Ee6QIvevaCa/j7mgVRrUZS8aNxf7p2U/c6U5cCjA2+7xZDKWhPVvjp5bZhf8UIwa2
         WJh34PMOKKhMDXwYnfpRjDjnfzm7foEH25sHCZPQlnc8pOBr+NOip3+yKfizCanIpmgx
         mgUN+KDqmU7BrNZ3CQ0nNCUHt+VL91pGPJPykEDHWbc7hQjDC48+BuoI1dL8fxw/+4bR
         XEzR4VHvhgPJFsbFSg9ce/htFsBpVWCIC+mbGT9gOIVuaaKTHMawX2xTKDOVCWKaTJgj
         3nWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768824410; x=1769429210;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bhQcUpd5xS0eXYyHxURQgoCrLtdFnYuSTs5zxTBuelI=;
        b=wNxIhTa5J8ZdLciFVr38xx1U+25j2kb7EDkl2h+ns8hFwCgZwAHO6akVJF/9EY7Yv8
         Y1vPmssSTR0vzGJUwdFQ4Nlvng1ncn2aiSJ7n1kvjuPgyfNx0p7uP/qEyOhNMmSwoAiw
         DzzwHnkSCQqgOBIwEL4j+ju8QdvdqGzEFMtrYU1z0CkKxNO5kCK7NmiIpTZ4nG6Bkjs+
         3Yi0IizQnkWHS6fQC/ki/4ZlX1vZGoNodiNqiM3P1jaWdOapQmBg6qYdV8E7bhAs6qRg
         YF4dBfBWMMg+CjFZcQj0/nNVqLDQi5VQb/pujM3XfemhOCqN5wxf8WWu1WTn0a7y/89R
         IK+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvEk9V18DcxCM/BXgYwXAHKLepbNiuEMta5j4QKKu2w3TUrOU7K2Wtl+jOnesSEcoy9Jybnw==@lfdr.de
X-Gm-Message-State: AOJu0YyAcp58T1etDJVBPMvR8zkDnWL/WvCFR+h9l9Hml1FEy0nRKSBV
	tiYD8of6Rmz6RlKqOvk0Rg5VhPLw0ePCrtHxbATLah3gA+3B3APIAPqH
X-Received: by 2002:a05:600c:4449:b0:477:7b9a:bb0a with SMTP id 5b1f17b1804b1-4801e34318cmr141224305e9.21.1768824409862;
        Mon, 19 Jan 2026 04:06:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eekak4em9ouhpYT/5xqnx2+f8D3QQRUHKouMiWkMpoNQ=="
Received: by 2002:a05:6000:2481:b0:432:84f4:e9d3 with SMTP id
 ffacd0b85a97d-43564178837ls2317801f8f.1.-pod-prod-01-eu; Mon, 19 Jan 2026
 04:06:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU4EjZZqKIcCdn02t1VGcJcP1zR/vFOYX4h0o9TkoxA8MqIATJ4g4GgvAtmzQw0KLr5Q/n9VeTTrAs=@googlegroups.com
X-Received: by 2002:a05:6000:26c7:b0:432:86dd:ef31 with SMTP id ffacd0b85a97d-43569bd46demr15641769f8f.56.1768824408141;
        Mon, 19 Jan 2026 04:06:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768824408; cv=none;
        d=google.com; s=arc-20240605;
        b=JfH/J8pipQGUDw/0ShxUobCR7kVSRVvveyIDdgkYa5IPTyIwSwQSylLOkvGt50TqRr
         vg0nzqibdCefjJQpEFOjYDNGmgogSrK1ADZfiHBaDjCmm/05aQOs/hKqrN5La9H8IAaE
         1m8mime8mIOsgtkBBuzw1LfvlnsXBvtLVi0hN6jXeDoKYIjJuPQMhdrbj/BQI6z6Fnz2
         U6jrR66HInDXVQ9QCNXNezetvGjGVPuuzi8uQHWMo2sam3vAkPnK98idb6dHBiQtaRr4
         +iUGGw8HXZ/609ZbAsUv8lFX1w+mtP6Aap+jxl6ICe+Yo3F/kSBgRfNRIWtYItyzebYh
         hPzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=lpMiDKyrIJgj/yq5I6LOa2WeBqzXUsHVn4Q35ITZoyg=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=T7e+ksgUAzQdGQ1PbO0Tsw6c+UHU5oJlWv1hMKfQQ3EvvuJHY21cA+zWgrFtG41+SK
         HWob3CTxE6ag27W79K6CS6/dnFU7b9Lo4h5PKm5rNn/ntIJHCgUptvmeVId85Tlsqc8Y
         AvBoB1YZBgq2FBwsj0fMYQg5CcFS+Xav96qH8KASHkCM+pKerzNjA51JjZB6m9gGTL5o
         thftc2EhwxgDo+IXQ0/u0Jl3akgRRuAiO7N6wBDTy5FcXYLVAznDM5ha8z3ZNafZd3NZ
         Qnpr37aRDut2bZfiM7667N5uv6RlrC/xW6raCNV+fIUvUWQxqkwgQTQ257Cwy80DqrU2
         GSLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ujesgdvy;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta0.migadu.com (out-181.mta0.migadu.com. [2001:41d0:1004:224b::b5])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356994f0dcsi248704f8f.5.2026.01.19.04.06.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 04:06:48 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) client-ip=2001:41d0:1004:224b::b5;
Date: Mon, 19 Jan 2026 20:06:35 +0800
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
Subject: Re: [PATCH v3 07/21] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Message-ID: <gv3ixsxai47hjv2pzpnptcjeqw7ikt5nnds22hkxlbtk7wgnfd@rzzcijtth6f6>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
 <aW2zmf4dXL5C_Iu2@hyeyoo>
 <e4831aab-40e6-48ec-a4b9-1967bd0d6a4c@suse.cz>
 <008029ff-3fd8-49cf-8aa7-71b98dc15be9@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <008029ff-3fd8-49cf-8aa7-71b98dc15be9@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ujesgdvy;       spf=pass
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

On Mon, Jan 19, 2026 at 11:23:04AM +0100, Vlastimil Babka wrote:
> On 1/19/26 11:09, Vlastimil Babka wrote:
> > On 1/19/26 05:31, Harry Yoo wrote:
> >> On Fri, Jan 16, 2026 at 03:40:27PM +0100, Vlastimil Babka wrote:
> >>> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> >>> kmalloc_nolock() and kfree_nolock() will continue working properly and
> >>> not spin when not allowed to.
> >>> 
> >>> Percpu sheaves themselves use local_trylock() so they are already
> >>> compatible. We just need to be careful with the barn->lock spin_lock.
> >>> Pass a new allow_spin parameter where necessary to use
> >>> spin_trylock_irqsave().
> >>> 
> >>> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> >>> for now it will always fail until we enable sheaves for kmalloc caches
> >>> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
> >>> 
> >>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >>> ---
> >> 
> >> Looks good to me,
> >> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> > 
> > Thanks.
> > 
> >> 
> >> with a nit below.
> >> 
> >>>  mm/slub.c | 79 ++++++++++++++++++++++++++++++++++++++++++++-------------------
> >>>  1 file changed, 56 insertions(+), 23 deletions(-)
> >>> 
> >>> diff --git a/mm/slub.c b/mm/slub.c
> >>> index 706cb6398f05..b385247c219f 100644
> >>> --- a/mm/slub.c
> >>> +++ b/mm/slub.c
> >>> @@ -6703,7 +6735,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
> >>>  
> >>>  	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
> >>>  	    && likely(!slab_test_pfmemalloc(slab))) {
> >>> -		if (likely(free_to_pcs(s, object)))
> >>> +		if (likely(free_to_pcs(s, object, true)))
> >>>  			return;
> >>>  	}
> >>>  
> >>> @@ -6964,7 +6996,8 @@ void kfree_nolock(const void *object)
> >>>  	 * since kasan quarantine takes locks and not supported from NMI.
> >>>  	 */
> >>>  	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
> >>> -	do_slab_free(s, slab, x, x, 0, _RET_IP_);
> >>> +	if (!free_to_pcs(s, x, false))
> >>> +		do_slab_free(s, slab, x, x, 0, _RET_IP_);
> >>>  }
> >> 
> >> nit: Maybe it's not that common but should we bypass sheaves if
> >> it's from remote NUMA node just like slab_free()?
> > 
> > Right, will do.
> 
> However that means sheaves will help less with the defer_free() avoidance
> here. It becomes more obvious after "slab: remove the do_slab_free()
> fastpath". All remote object frees will be deferred. Guess we can revisit
> later if we see there are too many and have no better solution...

This makes sense to me, and the commit looks good as well. Thanks!

Reviewed-by: Hao Li <hao.li@linux.dev>

> 
> >>>  EXPORT_SYMBOL_GPL(kfree_nolock);
> >>>  
> >>> @@ -7516,7 +7549,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
> >>>  		size--;
> >>>  	}
> >>>  
> >>> -	i = alloc_from_pcs_bulk(s, size, p);
> >>> +	i = alloc_from_pcs_bulk(s, flags, size, p);
> >>>  
> >>>  	if (i < size) { >  		/*
> >>> 
> >> 
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gv3ixsxai47hjv2pzpnptcjeqw7ikt5nnds22hkxlbtk7wgnfd%40rzzcijtth6f6.
