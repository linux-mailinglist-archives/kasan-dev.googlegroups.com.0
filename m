Return-Path: <kasan-dev+bncBCJNVUGE34MBBB4X53DQMGQEJUHWUBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id CEFDCC06ACA
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 16:22:02 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-88375756116sf741676885a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 07:22:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761315721; cv=pass;
        d=google.com; s=arc-20240605;
        b=AoB2d78UJM3TWGr+DWNFxYisQxEgYq4BUMsX5VBUNBeNqh7MnOW+2bTC7rsRB3EF2i
         KdsuuzyQBOerT7c27s8lWJEtkLAnVI85ZlDLqgzIVTRAYNb5tUSD6QDXn18zmPsmjvu9
         9BNEQFxxILMYbxTsAg65KPxFP0M4oRC1mKFagBZ069gWnLCSZzi+/rwUIWJBRsU8ti4/
         uDa72LI2+j99OPg2pMnAFjaeXGsoOYr/dtFAhyNEyC+oMkBjxnWOW37li8hWsSIhebvU
         YaYuGXucSSnF+VfADuvXuJpyXLsSU4losh1ozFPA8/+KLTOOBaBfddkscg5En+HBQxin
         O44Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NE24ZrDFD3PsfMG6tnRr2ZiVspfgBUyk1Cb5J3pXP9g=;
        fh=2Nv+ektf8E2tcBQgQAClz9nsvknyGE/4KPrKbN5pWMQ=;
        b=H1z51abki+1ayaL4MEn6u6hntQkMM2XM5/wrY1uDkpjDzH6yMctjcqKz5WsNAmW1xO
         esqeuzenDFtI/cXSiscenk4XFG1hbTA2x/2ij05iLLSDBeEKgSODfxjRvilbcX9BwOXW
         yiOzhmUmnDiRNDiyW+3C4+ao/Y8l7uihmOhVrv9QlS6O6QLSmE4LIcO+LGlYSs8uoAOs
         LCsH1CVYl0UBsVA5YxWWFJTVhMEJtKZktZp5YMxk+kXz5UkE+qAmVRI5mWwNaaQpauRv
         tHhVFeW5IHSiy/rOwB3zBumhgF2Bh+Dke/oNx9mXbna43w3pJ3ht/VTuRpp9BQAQiIbV
         xbqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=ezQP+7u3;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761315721; x=1761920521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NE24ZrDFD3PsfMG6tnRr2ZiVspfgBUyk1Cb5J3pXP9g=;
        b=Oe+yewaZG+G2zc0mu92XuFt4cTsl91d0GSAXnYcbPy8zYi1oLWS8ALvIcIHxYP4IS6
         1X0siWLgy8yn0r4YdnHmt7uxRCVase7n00DtQeLxT7fyURCYvNMMMs8Ke/XL2tpUOSuP
         x/UhfrwSngPF9YbLd1DZ0u1QVjidII4ZOKnsBVJ6ngpilF7f2lYZsvmQbVTITk3rHu53
         u8P/utAcM3iGxIruWuNxObg7u+isthar61z+LGcBvp9m4CD0Zxw5DtEEaOcu8+e4rymz
         SzTowdrsUzmaxXmvqp1ZkGLWv663ZFvZhttWQYkaDWIKRZzDoG4xEUeZvKwRXarvEUED
         zP1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761315721; x=1761920521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NE24ZrDFD3PsfMG6tnRr2ZiVspfgBUyk1Cb5J3pXP9g=;
        b=nannGMrXtYCX5vXpzowFYq55EbvDf70wmfInCRgEJ8X7sZF1Xl/iXD/DRyi/w2P6d+
         fKjMRue3y9MLbVnFKUmhsETpM2jk2YmXmymWx6j5IBr0gBeyKgZHENKS+8/CgPFAc/cZ
         xiXo8slRqBK8J/xgfiOXiPEVxeeeZCrumaywldy0R1r9rSd70c0sqbgd8gdyIwzpqGEk
         IrSLtUpFU+2k92+KU3W+6cnQxrkJlmLO9zrZyONjP5Q/xhK+FD5EYuzmZszj//5/bpbv
         mR6VQdWDU4inxl3EPoXK9+mW62YBMYXNhrVfYpRnuS0frCIAk8vdaicJ4k+XpIdEnTXq
         MGug==
X-Forwarded-Encrypted: i=2; AJvYcCWeGM/t1ebKsV/2QAiqRUe2T2SqSI0CO5aR0iIMzcko2kq7s7aBMLvZkHtmo9QoRFZh2LaUlg==@lfdr.de
X-Gm-Message-State: AOJu0YzeOuQQ7aA1cW9yhPXgPY7H8BePhhjE6DasHtVMi2Z+FSXfIUyb
	bs6GG6ReUw1Re9lHy8MvzelqTLV3O6N14DdVKtxHnPqxd/ec4j4nKN0O
X-Google-Smtp-Source: AGHT+IGtfPkWZEHfp6+q4t7ZAjbUSaHUqQ9jb3lklz5gV/XrtL605fHhZPXhvJfOLYfyCTZc4nQ4MQ==
X-Received: by 2002:a05:620a:a1d3:10b0:891:5527:8f28 with SMTP id af79cd13be357-89155279055mr1047712385a.42.1761315719312;
        Fri, 24 Oct 2025 07:21:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd50ZaoTTn5l4T2RLUGChcSD4OsI7h8Ta0Fi2wzQ8yVchQ=="
Received: by 2002:a05:622a:1827:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4eb815a0d04ls14224971cf.2.-pod-prod-04-us; Fri, 24 Oct 2025
 07:21:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2r2td1YL74RxfIdqMy/WDmjLzo/EzCLPPuIO3oCoZQK6qNzHg54K34a33S/jx7/tW69jByMblxxM=@googlegroups.com
X-Received: by 2002:a05:622a:4d07:b0:4eb:a07a:5fce with SMTP id d75a77b69052e-4eba07a61ccmr114361cf.17.1761315718426;
        Fri, 24 Oct 2025 07:21:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761315718; cv=none;
        d=google.com; s=arc-20240605;
        b=KhhE1GxtaJv0b0uT/DZ4ZzVXCMOejDqWeXr1yIGemabqyLc/PDZXxh4Lazs6UEyMAd
         qlGUo93mXVShU9S/nqE4LuTr6PfYv41VY09qyiWMpUWz81WB480oh/J8DLP/V2EQb0w/
         lC83XTMl7Hgv9KnYwDqC5ztA+oCjfVnVzq1hONbp/xjTi9bXMQ+rVAFR+PkXIxJZU1Lh
         xXI7g0uLljLiHm/S7glwjcP6QaC8kRUCEf1Vx6AffoTJZMLD9GSiqBWQnIqhhAJlhrEg
         5XciV3ClE1k5W3cGb9a5wrd8JjQZcZO2gaCJdwm9MUejtRz0247q6KjbxIH9inSAr1Wi
         Wo8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=b/ol2wZmOZszG9k8vxf893BYtcntNjtXKAqt3ZVyZ6M=;
        fh=bHAfn63gfa/6zgOaS4Q5hb17jvUVzDiE3LdJ4wZASA0=;
        b=DIdy1zhYioPiof2EaYHzoET5HU+Cj9bbKGV8Y3eRkX8mxsKtFlEJoZfUcLBqrIgUQZ
         jjRQozWQZQcwWdNH7eOpYUlnkI0BIt3urVP/ErFzrW2oJYBuHFvqHQcpJ5m+pTA9yK6P
         UJAK9MFUSZWew+Zdqlj69ro7k0yOhncsnFpJRP3t8sKMdjjFwhN8ALB6+ZL2r2nbL0cn
         u97iwypNZYCvpomS4KfexmLTNXjN0oSOTKk13pWwlcHHb07/yTjNN0uCIkbI7L5t+5Ra
         oeQiyHwPcZbIBR64SFuSkyqbB0uUFm3kCezo6yysyhcG+0+YN4Pv8cGaNuMA1NJC/dTi
         OpcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=ezQP+7u3;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0b-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4eb808765desi551801cf.5.2025.10.24.07.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Oct 2025 07:21:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0148460.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 59OBwgYl419537;
	Fri, 24 Oct 2025 07:21:55 -0700
Received: from mail.thefacebook.com ([163.114.134.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 4a09288x7k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Fri, 24 Oct 2025 07:21:55 -0700 (PDT)
Received: from devbig091.ldc1.facebook.com (2620:10d:c085:108::4) by
 mail.thefacebook.com (2620:10d:c08b:78::c78f) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.20; Fri, 24 Oct 2025 14:21:52 +0000
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
Subject: Re: [PATCH RFC 02/19] slab: handle pfmemalloc slabs properly with sheaves
Date: Fri, 24 Oct 2025 07:21:35 -0700
Message-ID: <20251024142137.739555-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <20251023-sheaves-for-all-v1-2-6ffa2c9941c0@suse.cz>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c085:108::4]
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI0MDEyOCBTYWx0ZWRfXwTD/VmjTrZA6
 JRMZKrwqksV2xp1yhJWxwn6gzdqQ6FLs2fQ0eb7xBONuzcwgzrrSURnRmWBCizGKI+13LbnEIl4
 ylNtvCoS+qc8ZaNrun/2WUn50FZBKyvgRCtxu011MC4I60o1A0gUQr7LQe1DnOC1f19Mw9W27VB
 MlWsAS28QxLMenEBX7/purq6SIW3f2Ls4I6uC6IrLhRbaN7uAosLW6+sFcqB5q5bySPDl5GzzE5
 R9gNXo0vhN4ZummzWu1+T3C/Fckz++HJCysc3xdveEplf4WxEoLA0JxvzvfFP6keHpZ+LjYmoHz
 lUK8NtClWc9hhIyXgA6umSdgtc7sWHlWqXnnspAxBWh4MhmjJc8arJC6lHS0Uji0i8FsmPJ+NE1
 uMZWCoJMv2b3asDyr7V0u3Kf1VWvBQ==
X-Proofpoint-GUID: 1v7_B19uZD_UKIAK3zHZIbCsxtzfqkFk
X-Authority-Analysis: v=2.4 cv=aK79aL9m c=1 sm=1 tr=0 ts=68fb8b83 cx=c_pps
 a=CB4LiSf2rd0gKozIdrpkBw==:117 a=CB4LiSf2rd0gKozIdrpkBw==:17
 a=x6icFKpwvdMA:10 a=VkNPw1HP01LnGYTKEx00:22 a=PCJbmnWxFXnHO1kFQDsA:9
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-ORIG-GUID: 1v7_B19uZD_UKIAK3zHZIbCsxtzfqkFk
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-24_02,2025-10-22_01,2025-03-28_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=ezQP+7u3;       spf=pass
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

On Thu, 23 Oct 2025 15:52:24 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

> When a pfmemalloc allocation actually dips into reserves, the slab is
> marked accordingly and non-pfmemalloc allocations should not be allowed
> to allocate from it. The sheaves percpu caching currently doesn't follow
> this rule, so implement it before we expand sheaves usage to all caches.
> 
> Make sure objects from pfmemalloc slabs don't end up in percpu sheaves.
> When freeing, skip sheaves when freeing an object from pfmemalloc slab.
> When refilling sheaves, use __GFP_NOMEMALLOC to override any pfmemalloc
> context - the allocation will fallback to regular slab allocations when
> sheaves are depleted and can't be refilled because of the override.
> 
> For kfree_rcu(), detect pfmemalloc slabs after processing the rcu_sheaf
> after the grace period in __rcu_free_sheaf_prepare() and simply flush
> it if any object is from pfmemalloc slabs.
> 
> For prefilled sheaves, try to refill them first with __GFP_NOMEMALLOC
> and if it fails, retry without __GFP_NOMEMALLOC but then mark the sheaf
> pfmemalloc, which makes it flushed back to slabs when returned.
>

Hi Vlastimil,

We're trying out the AI patch review automation on the BPF commits and it had
some questions about a few of these.  Since the goal is to actually test the
automation, I'm putting them in unedited, but I did try and make sure they
were valid before sending.

For this one, I'm not sure if the behavior AI is flagging is intentional or
not, so it feels like a reasonable question to me at least:

> diff --git a/mm/slub.c b/mm/slub.c
> index 4731b9e461c2..ab03f29dc3bf 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c

[ ... ]

> @@ -5331,6 +5340,26 @@ void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t gfpflags, int nod
>  }
>  EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
>
> +static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
> +				      struct slab_sheaf *sheaf, gfp_t gfp)
> +{
> +	int ret = 0;
> +
> +	ret = refill_sheaf(s, sheaf, gfp | __GFP_NOMEMALLOC);
> +
> +	if (likely(!ret || !gfp_pfmemalloc_allowed(gfp)))
> +		return ret;
> +
> +	/*
> +	 * if we are allowed to, refill sheaf with pfmemalloc but then remember
> +	 * it for when it's returned
> +	 */
> +	ret = refill_sheaf(s, sheaf, gfp);
> +	sheaf->pfmemalloc = true;
> +
> +	return ret;
> +}

[ ... ]

> @@ -5497,7 +5528,7 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
>
>  	if (likely(sheaf->capacity >= size)) {
>  		if (likely(sheaf->capacity == s->sheaf_capacity))
> -			return refill_sheaf(s, sheaf, gfp);
> +			return __prefill_sheaf_pfmemalloc(s, sheaf, gfp);
>
>  		if (!__kmem_cache_alloc_bulk(s, gfp, sheaf->capacity - sheaf->size,
>  					     &sheaf->objects[sheaf->size])) {
                                             ^^^

In kmem_cache_refill_sheaf(), does the oversize sheaf path (when
sheaf->capacity != s->sheaf_capacity) need __GFP_NOMEMALLOC too?

The commit message says "When refilling sheaves, use __GFP_NOMEMALLOC
to override any pfmemalloc context", and the normal capacity path now
calls __prefill_sheaf_pfmemalloc() which adds __GFP_NOMEMALLOC.

But this oversize path still calls __kmem_cache_alloc_bulk() with the
raw gfp flags. If the calling context is pfmemalloc-enabled (e.g.,
during swap or network operations), could pfmemalloc objects be
allocated into the sheaf? Those objects would then be returned via
kmem_cache_alloc_from_sheaf() to potentially non-pfmemalloc callers.

Similar issue exists in kmem_cache_prefill_sheaf() for the oversize
path at the function's start, though that code wasn't modified by this
patch.

>  			return -ENOMEM;
>  		}
>  		sheaf->size = sheaf->capacity;

[ ... ]


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251024142137.739555-1-clm%40meta.com.
