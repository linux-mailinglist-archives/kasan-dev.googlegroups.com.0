Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBCUZ2OLQMGQE6STFTMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 8624258FA17
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 11:31:55 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id l19-20020a056402255300b0043df64f9a0fsf10616416edb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 02:31:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660210315; cv=pass;
        d=google.com; s=arc-20160816;
        b=cEwfn3ybbgiAB17+bm//TDvYK5lp0c53t9TYk/djsKo1jBMEhe70RZtK4hHZqIqmIL
         ATxnl3O4/pqJzimgxDyO3uAAVRx5uYmg5lA1gOhXz6Ph4KjZkQRWxbcfNRCQhwnoacjF
         vp3MDzdxBKTe2AfkYND2yPgecQIW9ccXmUYSA0Bo7BGm6cXx2VgCwuXS3qTuR04zQQrS
         B8K1rohtPxSelPb+XnwuUnS8m301O58rhhDsk2RshcMutzQFghyBacoQxdn0RwlCsoQx
         pVrTdTQE8HgKSjwquV7W92Keg7HUTnGkrcztFKkrec/IFYnsYJ0mHdNqD7iqL8qKc0lb
         6p2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to
         :content-language:subject:from:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=ysUbXmyWtdtl1Vpgj+4RF9IkdM0fYN1kM/y1W1+o5LY=;
        b=Hhr4LQWacQ1qHJTnGlAHepbqzX8mtCKd5JO54J7UEh56YypYLu+5s6tKeUrlihD2C9
         3I7OYB7Fq2iTb9hGCfGjjRIWcisOgd/LE5q5BrxXq3sSKQwaXJjddJJd34qtMu2AakXx
         +7W1qfDHvIXP6+vRMsFPfA1/IZedGRBfFhej/HTJpInAxxGH+fMeuUAZC7hi82ax4Jgo
         /xCQvCA28rwyPjsFnpSp3Il0DlpoSILIWjdPIKp/EU/4jcRx7iFCyo3m8j5Awxn14H0J
         jBfhqKqWJ3qMoD9kddQgrL0YoGTmmA9moTjBCUIhM+pUEMlSdVjnkQe4tPEmAzaj64ZY
         gytA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pq4UUdvC;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:content-language
         :subject:from:user-agent:mime-version:date:message-id:sender:from:to
         :cc;
        bh=ysUbXmyWtdtl1Vpgj+4RF9IkdM0fYN1kM/y1W1+o5LY=;
        b=h1zs4an9A6kzyJS98RF9boXALvGIbk3yxgs0+J1GfVv/m7vBzHowfK+GqOdIGL7c/H
         T2wVatJwiyWnRX3fOzUhcjdie8EUoxo2nmyMLd7sebtex5e+adzUfcTGN9zehLfSv3Eu
         1+vFzNEaCCWUUqvgnWZgW87Y1YP4wTgxcGdGV2KmDif/7pSaWGz5UdRUgHU4JVS9HBFB
         v8330sgv1Sl0IXNOJZY/ZuEwN+oTB52KZCLi2cvr+KmHnY85yhhqnjK0/AX9I2JiTs2N
         yA4Iwzen2YWdNj9kYvDzd8upvfWIeuEIeDQyn4CGsO8yRShAOzIJA0UTv6Hv3pGe8KU/
         d6og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:content-language:subject:from:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=ysUbXmyWtdtl1Vpgj+4RF9IkdM0fYN1kM/y1W1+o5LY=;
        b=vi6oUrWnEqR6hdWe+0j04PNQnqsCKm16VTUrV9Q2SZ6v6BYf5e4XcRfZEcK/ATFock
         TL3Gvjv2oWpy8mzEVfOReDoF5ZYGmXfk8b827BFJXptksCytc97SO+YUsJegdy5Gxm/m
         eHcqx6yD/jKg2i9ZMErVN7h6ovKk5FTmMFB4+VrePc/oeuqjKHiOshR5UCa/NWmJZHIG
         KwQCXPGyzyhbI27ORYpPUUHVRF9JubKzevZIA5BE4x7GKossnG8Ik+UcPNAC/b4O38+u
         FHJjLuX5uWnECL6q3Le5cImB3QG/GurI9kcXXqN2vqNeoWbVc5FpQTq597+x8P0TB9sD
         hi6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3l8LxLrRuJLm1wdT/3qfLxg845nm+S/rTKzOnt6rRuoVjTkmp0
	ljGEooSMtQ7F64vY2M8SwBI=
X-Google-Smtp-Source: AA6agR5kBzTYGdNZRVavSaujJlqF2naPXXPUks87rWs4XgymD7C0ZmQpQSB5TvXxpFa6OeoSUY/g2g==
X-Received: by 2002:a17:907:2e01:b0:731:1eb0:b9ff with SMTP id ig1-20020a1709072e0100b007311eb0b9ffmr18248337ejc.728.1660210314987;
        Thu, 11 Aug 2022 02:31:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b248:b0:730:6969:95e6 with SMTP id
 ce8-20020a170906b24800b00730696995e6ls724852ejb.7.-pod-prod-gmail; Thu, 11
 Aug 2022 02:31:53 -0700 (PDT)
X-Received: by 2002:a17:907:87b0:b0:731:36ab:3223 with SMTP id qv48-20020a17090787b000b0073136ab3223mr16053462ejc.715.1660210313624;
        Thu, 11 Aug 2022 02:31:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660210313; cv=none;
        d=google.com; s=arc-20160816;
        b=Ceu20gkbmpQQA1Fi6o4hYRjhHd/xNbL9sM991zf3mm6v6afYc4QOBHneMoP/b7Yht4
         g9bAp/+y1CmuftKVvw+hFUOdhIagvUwvpUT1znc8aLS0cDzuu0+ZwNHfiT3v3TzPi61n
         owPdxIIyqw5HGZKv5ff0GhQjt865fZT+FC13T58IPB9F8L4f2+h9LMqYZtaLTJ8OWNup
         z8qGnxpqZ1Sdva08XhgqRn5DiPupxfb2UBI12lw+34RezjDwS85AfKtjwxgwx7ss66ZX
         RWoxQgdUTrrq4f3kzdrSHOYvnxSCUqzFMDi7SxkYxyJDiK5FPWvLaDa/yZKwBMDiWkBS
         pAYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to
         :content-language:subject:from:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature;
        bh=rF+k9eDGRl2XR235Pzqvbau2Y08myECs6AhHVzgotHk=;
        b=voB5mGmATqmtDuml2el4l1xuyOTy/1cOF2hfBNrdPRkchBcARWtdB6Fhc8syQ2T+eU
         zCUTumH2b7Hntsk/gCj6sQmKwNCl4cr0R9TBNKgMdFVKljbWXdoSEvSnnodfUNCLC5P5
         BJfu4i+31us0oUM8UiHySda0oHMLsuA6mil1h+iyDPGqWfXPoNFKia2uH/TpDME5gDoG
         NJpOqUxmwUYBh0/mGKs4U7p81ZbDymrjYYdqd627ne4grH2lvXGZuYIGyzjfKmmZGKay
         pMOHPk1uqDrj6/vJmft3LfvZMcQYlyWG5WC6R1Jthim1epEbA7unaLDAl5yRPK1VBANf
         GRKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pq4UUdvC;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id gz7-20020a170907a04700b00730b5fd89d2si306377ejc.1.2022.08.11.02.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Aug 2022 02:31:53 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 35F335C70F;
	Thu, 11 Aug 2022 09:31:53 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id F01821342A;
	Thu, 11 Aug 2022 09:31:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id /f3ZOYjM9GJacAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 11 Aug 2022 09:31:52 +0000
Message-ID: <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz>
Date: Thu, 11 Aug 2022 11:31:52 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.0
From: vbabka@suse.cz
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
Content-Language: en-US
To: Imran Khan <imran.f.khan@oracle.com>, glider@google.com,
 elver@google.com, dvyukov@google.com, cl@linux.com, penberg@kernel.org,
 rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
 roman.gushchin@linux.dev, 42.hyeyoo@gmail.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
In-Reply-To: <20220811085938.2506536-1-imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=pq4UUdvC;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/11/22 10:59, Imran Khan wrote:
> By default kfence allocation can happen for any slab object, whose size
> is up to PAGE_SIZE, as long as that allocation is the first allocation
> after expiration of kfence sample interval. But in certain debugging
> scenarios we may be interested in debugging corruptions involving
> some specific slub objects like dentry or ext4_* etc. In such cases
> limiting kfence for allocations involving only specific slub objects
> will increase the probablity of catching the issue since kfence pool
> will not be consumed by other slab objects.

So you want to enable specific caches for kfence.

> This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
> to disable kfence for specific slabs. Having the interface work in this
> way does not impact current/default behavior of kfence and allows us to
> use kfence for specific slabs (when needed) as well. The decision to
> skip/use kfence is taken depending on whether kmem_cache.flags has
> (newly introduced) SLAB_SKIP_KFENCE flag set or not.

But this seems everything is still enabled and you can selectively disable.
Isn't that rather impractical?

How about making this cache flag rather denote that KFENCE is enabled (not
skipped), set it by default only for for caches with size <= 1024, then you
can drop the size check in __kfence_alloc and rely only on the flag? And if
you need, you can also enable a cache with size > 1024 with the sysfs
interface, to override the limit, which isn't possible now.
(I don't think changing the limit to always act on s->object_size instead of
e.g. size passed to kmalloc() that it can pick up now, will change anything
in practice)
Then you can also have a kernel boot param that tells kfence to set the flag
on no cache at all, and you can easily enable just the specific caches you
want. Or make a parameter that lets you override the 1024 size limit
globally, and if you set it to 0, it means no cache is enabled for kfence?

> Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
> ---
> 
> Changes since v1:
>  - Remove RFC tag
> 
>  include/linux/slab.h |  6 ++++++
>  mm/kfence/core.c     |  7 +++++++
>  mm/slub.c            | 27 +++++++++++++++++++++++++++
>  3 files changed, 40 insertions(+)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 0fefdf528e0d..947d912fd08c 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -119,6 +119,12 @@
>   */
>  #define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
>  
> +#ifdef CONFIG_KFENCE
> +#define SLAB_SKIP_KFENCE            ((slab_flags_t __force)0x20000000U)
> +#else
> +#define SLAB_SKIP_KFENCE            0
> +#endif
> +
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c252081b11df..8c08ae2101d7 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -1003,6 +1003,13 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  		return NULL;
>  	}
>  
> +	/*
> +	 * Skip allocations for this slab, if KFENCE has been disabled for
> +	 * this slab.
> +	 */
> +	if (s->flags & SLAB_SKIP_KFENCE)
> +		return NULL;
> +
>  	if (atomic_inc_return(&kfence_allocation_gate) > 1)
>  		return NULL;
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> diff --git a/mm/slub.c b/mm/slub.c
> index 862dbd9af4f5..ee8b48327536 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5745,6 +5745,30 @@ STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
>  STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
>  #endif	/* CONFIG_SLUB_STATS */
>  
> +#ifdef CONFIG_KFENCE
> +static ssize_t skip_kfence_show(struct kmem_cache *s, char *buf)
> +{
> +	return sysfs_emit(buf, "%d\n", !!(s->flags & SLAB_SKIP_KFENCE));
> +}
> +
> +static ssize_t skip_kfence_store(struct kmem_cache *s,
> +			const char *buf, size_t length)
> +{
> +	int ret = length;
> +
> +	if (buf[0] == '0')
> +		s->flags &= ~SLAB_SKIP_KFENCE;
> +	else if (buf[0] == '1')
> +		s->flags |= SLAB_SKIP_KFENCE;
> +	else
> +		ret = -EINVAL;
> +
> +	return ret;
> +}
> +SLAB_ATTR(skip_kfence);
> +
> +#endif
> +
>  static struct attribute *slab_attrs[] = {
>  	&slab_size_attr.attr,
>  	&object_size_attr.attr,
> @@ -5812,6 +5836,9 @@ static struct attribute *slab_attrs[] = {
>  	&failslab_attr.attr,
>  #endif
>  	&usersize_attr.attr,
> +#ifdef CONFIG_KFENCE
> +	&skip_kfence_attr.attr,
> +#endif
>  
>  	NULL
>  };
> 
> base-commit: 40d43a7507e1547dd45cb02af2e40d897c591870

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d3cd0f34-b30b-9a1d-8715-439ffb818539%40suse.cz.
