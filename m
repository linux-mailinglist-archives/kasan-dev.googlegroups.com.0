Return-Path: <kasan-dev+bncBCJNVUGE34MBB2VW53DQMGQEU6Y3U6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id B7789C06F99
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 17:29:47 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-88ec911196asf555529085a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 08:29:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761319786; cv=pass;
        d=google.com; s=arc-20240605;
        b=B2SyBWq+nXXrY87frcbUCZXdX3CtwnmfYoGRWyV0C1P6qMfZ/p1VwwqAUraghU3XNZ
         0hJzPr+qurlugode6zRn8/dxPPIi0YqcGr0uEvncIEyRpb3HEpMA6r0qFAlkEkbvgKeH
         xbyJSyDiIOP+ZnaqvETbbemBkkk41YIAxWNZyQDp5OdyPt8YAApWFPWQbsWqwTn4N4d1
         PrYN4CpgisWdNuooiSxSiCkiKRgihyn4gYyDgxboNp3f81d1t/r1pAhRICXhQFAROSU0
         5jeTGLFTUGcs8ddBxpYHaofREf9xiuDTH7otOqNAA14QGwcI06CNywW1HczRkTCRHhHp
         8kMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=I1aZtp1CQor6J2i4x0LeXxosy8+Vl89DRaIjm3gTSoI=;
        fh=D6N9yCCHo3A5l0D8bnisTnY1uzYmg6gYZI0hAqBca2o=;
        b=UNpMdJy4s4RnVr2EbMyAFHFfM3SOPZjvuH+AxQ5nRktXK7Ni/E/3Y5L0kxXiBnzmsB
         gytCQCenW6YaSpj96EDAHvl0ZdXWxu02IV1Z8r0DAf3S+s7H9cbsTmzceaS6qeOSMF+4
         PHwh2mg6yTq43Rc1d91LQzMmFunna8Wk1LaznpwKZDwMVMANM5nE6QH8+/5ivZ2EGcNh
         4G9PLBM/DZ1TBM9xOOJXDsqi6BUC6FXXiZixH76BYhrYEDQ0+Aa11lxA0KxZZE34B5CC
         0hZQYEI4uWHI+ndMvgb8IganQBcG6shqiYFxGR02/rNhZRVLIiaxKVzyBQI9ytAdN/7n
         SJQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=u1H8joWQ;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761319786; x=1761924586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=I1aZtp1CQor6J2i4x0LeXxosy8+Vl89DRaIjm3gTSoI=;
        b=TTnt2ujF3CU4XTqtXt/4qFaDzemnsWZFM0Wgri7B9RQPe/hN1meOz6mEAs9PLwsufH
         Y5b1a1w644XNNF7tW4SIPi1hKtdtI4YsapMYBmpoefRyf3FKyxsedGS5U3Pr+H3lTdEl
         BJi57YUaTfmaPPfOezmm11HakhItKT8udqvkLEUWcV3PrOLbtp2SKF+lwdL3+8eAhmeW
         d6sLpUjncf300kKloSra8BhHCquqiny8oAt2wiZCFFGpp1hvyh97TZqcWWzWjM+J+P/X
         SZdq5cbTT+ZvHXEJlDuvVjxmrX348QOEQHjp3Vlr0pnV2q9TrYU6ZH1nEAUvY7sr7K6S
         JbWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761319786; x=1761924586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I1aZtp1CQor6J2i4x0LeXxosy8+Vl89DRaIjm3gTSoI=;
        b=JtCA3hb2NPdDS6/OeghLuEYkqvVsjjjhxfKmM1xZ+dnhv+Bf8GvDFcRGhIcUCWns6v
         MBRfSItP8l/H6TtHV4I8CPfXnPQhBa77HhSb06MIykmhvrMWQXk7KrO4q1N4KTCrZNMM
         OZM15Hr2t1N80TvLDqLM1uhDyqIwnk7ukvwWcM5pNtg1oLHNUhEJtP2jC/hMkkXahVvD
         Jv4Je/9dkIB4TijZNGBiuIKkW/bztEJKnBFHaHoSUa6odXcEw7MDJakXDcIW3aUKgzfk
         hC9UXTpjvfZ7+4zOPEe+HH8SunzAp7UDF8N0KwP2GEkspjqubSs/YaYNfAK62YpFYbsT
         jbtw==
X-Forwarded-Encrypted: i=2; AJvYcCUUiMbWuA4j/vufflJkiv9iM7BmsTGL93zs+T3IZu9NE0IaT8Dh0EuPHl4fLyii+0ExGhoaQQ==@lfdr.de
X-Gm-Message-State: AOJu0YzpgiYDC772CPRD6rrLCoLQyNEV8xXH1eczT2lVh5uvms8conVo
	m4eME4SxhrUjaThzhROhiDsRKd+WUQg5rVSg56LiU7Qe5QftskVbwYrP
X-Google-Smtp-Source: AGHT+IEj/W2GYCV3g2jcAyiQRHcgIZm//CHaHU6+HHNvtl9iIRcbRecJmj6EOh8UVY5ILOhUTvgahQ==
X-Received: by 2002:a05:6214:2aa6:b0:70f:a4b0:1eb8 with SMTP id 6a1803df08f44-87c2054addbmr322365216d6.13.1761319786388;
        Fri, 24 Oct 2025 08:29:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YhVchyNJywxwno8NrtK1RpcbwSLjWgyvBxLvUnhKyr9A=="
Received: by 2002:a05:6214:f2b:b0:819:df42:aa30 with SMTP id
 6a1803df08f44-87f9f9b67bcls35741776d6.2.-pod-prod-07-us; Fri, 24 Oct 2025
 08:29:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmQsBpq1/GGgRikCUC9dJ0Vnj46+6g1V7jI5+CRmJJ4JSWH734yt7xykVzyMj8B9x+d6nmuzPJMx0=@googlegroups.com
X-Received: by 2002:a05:6214:d44:b0:87d:ca27:ac14 with SMTP id 6a1803df08f44-87dca27c324mr327962886d6.39.1761319785527;
        Fri, 24 Oct 2025 08:29:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761319785; cv=none;
        d=google.com; s=arc-20240605;
        b=lC1fbvIrENgV2XMSfjiCoDd1yV8Ez2tNZVnaQBf/j4PjezpMWWXhdfOxkox3/LFo5r
         OVPX0UGV43oZxc4jEm0pSPh6x4muqy6QKp3tdB9n+TIARJIQydMTUREfODNzXUrd4FdT
         Z+h2qgkviOOUdM4/w3Ztf7gOKPv7rWiwmgm+rnRBdW2YfvNHgWIqwSfBp8IJfkSDzsCH
         xy+GdZ2OUAS4xpuHEEwletmzkQK9IQQrBmfdobKGk/A6JThV3wLaIB8X/R/YfpJ+rx4Z
         wwv3a2CoYBTV03kKQD5Z4g0o9mnEjQLs0CsrAV5cMPlnpobGY4cvNnXvICl9hy7WrPAW
         E9ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JYg1vP9W9v0SXXkTSNQM/3alSk45Op1+j7AlOwvEtcM=;
        fh=bHAfn63gfa/6zgOaS4Q5hb17jvUVzDiE3LdJ4wZASA0=;
        b=S5ewNGajnZ48aejJfTHT0KwAYjaYTSbNh5BWhlbWnwl0qMLULFHA9BrhNbomyoYsUb
         +VpusOnjY8/bRykiYVH0Fvxib23GDBj+Y0ALzr8NSwLSnGc3dnENLEE5r+D/PcFloQ5K
         /D2/XHKuVleCMbFK65p8SMTb7rXVRkAOpkqNWl1Uu1YkFn+g/oqR322WEyzrsW/UZkX6
         KrbnI9uoquT3bPAPDOhOcKAPiPIr43R0fbV/byM2sIkY90jBz9K/VwVXJ5EqgMyKZEsK
         FRqw99VRjrEBfa/DpEHR2KGmEcKtm0N79ciIunjdbJ5yMzmgDoFZdIm1qGF4X/ZN84Sr
         96FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=u1H8joWQ;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87f9e25e687si3555736d6.3.2025.10.24.08.29.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Oct 2025 08:29:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0001303.ppops.net [127.0.0.1])
	by m0001303.ppops.net (8.18.1.11/8.18.1.11) with ESMTP id 59OE2RhP2211218;
	Fri, 24 Oct 2025 08:29:42 -0700
Received: from mail.thefacebook.com ([163.114.134.16])
	by m0001303.ppops.net (PPS) with ESMTPS id 49yxkh4c3r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Fri, 24 Oct 2025 08:29:42 -0700 (PDT)
Received: from devbig091.ldc1.facebook.com (2620:10d:c085:208::7cb7) by
 mail.thefacebook.com (2620:10d:c08b:78::2ac9) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.20; Fri, 24 Oct 2025 15:29:40 +0000
From: "'Chris Mason' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Chris Mason <clm@meta.com>, Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett"
	<Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        "Sebastian
 Andrzej Siewior" <bigeasy@linutronix.de>,
        Alexei Starovoitov
	<ast@kernel.org>, <linux-mm@kvack.org>,
        <linux-kernel@vger.kernel.org>, <linux-rt-devel@lists.linux.dev>,
        <bpf@vger.kernel.org>, <kasan-dev@googlegroups.com>
Subject: Re: [PATCH RFC 06/19] slab: introduce percpu sheaves bootstrap
Date: Fri, 24 Oct 2025 08:29:09 -0700
Message-ID: <20251024152913.1115220-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <20251023-sheaves-for-all-v1-6-6ffa2c9941c0@suse.cz>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c085:208::7cb7]
X-Proofpoint-GUID: kkk2s3qprms9Z7I2EC8CkdtQeZfZNQk7
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI0MDEzOSBTYWx0ZWRfX7OIXVkMX9geX
 7pzjGpPRSpFcTx7fX8n9LXsYKQ3g0QZRGy/YPxIO393qaVutmBVwI5lA7gFo2Q5Hwa8+P741e63
 xa6tJDDXt4JLNHQXxoIcH9J3r2OhtgnPlM4/Dr6jsPRXB1oEw/kPigXQ63CZR62E3oWIRwP92bI
 Uyw/Rir17bhjlbv9m3LRbTZKG10KB7hH/N6P1EqnkT0Cqw/05VrvLihNzZyUp7LDWbJDlLeGXcc
 H/V7buo1lPWg9avwKIjQpsh4ufOJ0RbDY3XF7efzaPcvEl+kxGuwx0N75gZk9lfpaNVUS9+08yq
 tCSqvOvqHCgRAFoEYuICfiy9uaKRTDvTQ2t2EAEZ5GLOUuAXhopMjOObCyRbGyHI7KdUgqT79Bs
 +PdwDPQk/r7OGlJSV6buVYTVGDTVHg==
X-Authority-Analysis: v=2.4 cv=RqHI7SmK c=1 sm=1 tr=0 ts=68fb9b66 cx=c_pps
 a=CB4LiSf2rd0gKozIdrpkBw==:117 a=CB4LiSf2rd0gKozIdrpkBw==:17
 a=x6icFKpwvdMA:10 a=VkNPw1HP01LnGYTKEx00:22 a=7e5GxzTNbid4F3B1EgkA:9
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-ORIG-GUID: kkk2s3qprms9Z7I2EC8CkdtQeZfZNQk7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-24_02,2025-10-22_01,2025-03-28_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=u1H8joWQ;       spf=pass
 (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30
 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
X-Original-From: Chris Mason <clm@meta.com>
Reply-To: Chris Mason <clm@meta.com>
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

On Thu, 23 Oct 2025 15:52:28 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> sheaves enabled. Since we want to enable them for almost all caches,
> it's suboptimal to test the pointer in the fast paths, so instead
> allocate it for all caches in do_kmem_cache_create(). Instead of testing
> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> kmem_cache->sheaf_capacity for being 0, where needed.
> 
> However, for the fast paths sake we also assume that the main sheaf
> always exists (pcs->main is !NULL), and during bootstrap we cannot
> allocate sheaves yet.
> 
> Solve this by introducing a single static bootstrap_sheaf that's
> assigned as pcs->main during bootstrap. It has a size of 0, so during
> allocations, the fast path will find it's empty. Since the size of 0
> matches sheaf_capacity of 0, the freeing fast paths will find it's
> "full". In the slow path handlers, we check sheaf_capacity to recognize
> that the cache doesn't (yet) have real sheaves, and fall back. Thus
> sharing the single bootstrap sheaf like this for multiple caches and
> cpus is safe.
>

Hi Vlastimil,

We're trying out the AI patch review automation on the BPF commits and it had
some questions about a few of these.  Since the goal is to actually test the
automation, I'm putting them in unedited, but I did try and make sure they
were valid before sending.

> diff --git a/mm/slub.c b/mm/slub.c
> index a6e58d3708f4..ecb10ed5acfe 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c

[ ... ]

> @@ -7733,8 +7782,7 @@ static void free_kmem_cache_nodes(struct kmem_cache *s)
>  void __kmem_cache_release(struct kmem_cache *s)
>  {
>  	cache_random_seq_destroy(s);
> -	if (s->cpu_sheaves)
> -		pcs_destroy(s);
> +	pcs_destroy(s);

Can pcs_destroy() handle a NULL cpu_sheaves pointer? Looking at the
error path in do_kmem_cache_create():

    s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
    if (!s->cpu_sheaves) {
        err = -ENOMEM;
        goto out;
    }
    ...
    out:
        if (err)
            __kmem_cache_release(s);

If alloc_percpu() fails, __kmem_cache_release() now calls pcs_destroy()
unconditionally. In pcs_destroy(), the first operation is:

    for_each_possible_cpu(cpu) {
        pcs = per_cpu_ptr(s->cpu_sheaves, cpu);

Does per_cpu_ptr() dereference s->cpu_sheaves when it's NULL?

>  #ifdef CONFIG_PREEMPT_RT
>  	if (s->cpu_slab)
>  		lockdep_unregister_key(&s->lock_key);

[ ... ]

> @@ -8608,12 +8656,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>
>  	set_cpu_partial(s);
>
> -	if (s->sheaf_capacity) {
> -		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> -		if (!s->cpu_sheaves) {
> -			err = -ENOMEM;
> -			goto out;
> -		}
> +	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> +	if (!s->cpu_sheaves) {
> +		err = -ENOMEM;
> +		goto out;
>  	}

This error path triggers the call chain: do_kmem_cache_create() error
path -> __kmem_cache_release() -> pcs_destroy() with NULL cpu_sheaves.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251024152913.1115220-1-clm%40meta.com.
