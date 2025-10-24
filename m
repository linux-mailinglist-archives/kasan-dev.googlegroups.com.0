Return-Path: <kasan-dev+bncBCJNVUGE34MBBOMP53DQMGQEGK44NLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A7EDC069BF
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 16:05:48 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-290d860acbcsf41385355ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 07:05:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761314746; cv=pass;
        d=google.com; s=arc-20240605;
        b=VPLy8xdctckF3zhloF3UzzJY4nDIkJ+LdGWHwsBR9cByTJe0h4NHMpmr29vOEgcQj6
         ueBB0ZoA0i3oihFG0FjGLJcnefMb8eHcJIITNfPyvxy00BgqGDIMgrpA6jn74kIL8ngn
         BJTUshLEloiTbN1ooJ3U7xrOcGeq6oQfBWbanwMnVbArQDhfRncA3zuIP40AW9GJM244
         FqjM753/4IrCPa8fMV8gHEQxtEwI7/Q6f6+iUiOFitErsZaneGC6Jlj0sfypGvKRMRbb
         r1cqqwar6M6hfcqyKngQvsAldg0a2ryErTHu0mUlXeJVOYQkgM6hz1md+5pUMFRmyRRe
         mqLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4Dalloo47mTSzAwJH2WYg/1cKXdNewY1a0N2KX6O2fA=;
        fh=gEE40ElMOivaJmd9z3kYU+EiB5AghXMWklT0moHF9F4=;
        b=b2h9F4PZor7QIKn74InHTCGIUt1i18+v27KqsAp+DfNCmkIvgK86ZoIFdOBxMfdf76
         pH5AyKR7oeesiiL3sUh++bAfYJrkebVsnM+dqxaWkKobNZTZGUuiSJDMlYcbkmsOnGIs
         1qYUsXA1gqak9lWuBONX3lMpr6gMHWbm7WQnoJ7lQUiGTN3YrULd9Yo+xxBdHpL+jooF
         Eg3HaZNPeYmHGh5wA+YE3/LqW1tmsFNA4leHU39EMx+mHfxdciaKoRB/HUvG+FYYovcI
         wGrpK1/toZHxbJACXPWUEEWWAbf4g3shHPE+GU1Y1h0y/fwc9gCPHqK3K4cMXuIDVbF+
         hRUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=fnXo7b6r;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761314746; x=1761919546; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4Dalloo47mTSzAwJH2WYg/1cKXdNewY1a0N2KX6O2fA=;
        b=Xf8pO6qeqj3a2C7c2pLQYMxQIcPxBaRjJzbbaubebxFOmU0v7GVUrJbt/I5HMoXD0G
         MqjW4SFQ8ulyIrGCZRoVekDacRHotCdhtH8NrcnCKS1A80kJkoJ3ZrwnJpkoP+pud+GS
         ko2E48LBIBYdE5fH4FPsSoGB7Aq9Dglq34uVDQjO9XunJYnMeAOEdWJGF3MD9+0IjRaP
         2RxXk5BdhRJ1xbLVQHNTpHOI+b8o/QdVjS0nSUimZw2S9CunvNEScNtKeBJSxEV4N+R9
         ihQ1IQqFWyQUoGXMzyGkd8JHdowL5pq8IB2lOfen3tsTa5SLIwqsGcliSG/RI8VkTUxo
         baTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761314746; x=1761919546;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Dalloo47mTSzAwJH2WYg/1cKXdNewY1a0N2KX6O2fA=;
        b=p9WO9Us6rashfmvAAvov6TuIo1OwlEVGDJufMfXFuhR9L1LOr9/AYTQj616ZbFyh7W
         iwhoV4j9J7qpU2D4wSqzOWPCOUd+a4Etaf9Yql485bjfH13PefXTFTH2OOr5tHMXQHuT
         W24qn/MWlqIWD46MyngQoAkpPApO9p5OFYo6MDO5JyBMvUNr6d8FRYFTsQJ1nwsRfc54
         Zgq0YwfLbH18+Y1mw2X1f2FghtxXok4RJQTcaWR1gG8NVFeuP9MuEuuCIJI647MR9q7y
         +aollj1KTJ/4cMbdT0WLrr9b5iO1jtMlT3zrrXgxz9AlUbmcQNPQtcOJSuZizPnO6g+Y
         qJcw==
X-Forwarded-Encrypted: i=2; AJvYcCVHiRbdA1s09z/u/YMhT+K8TjFg9Z5wVv78+SS4SbX3MlQfVP/5rtjE2cYeHd2AjL7AHEjTUw==@lfdr.de
X-Gm-Message-State: AOJu0YyO4Sbl0zTbvpUEYyrP7/JR3BwMunweuGIwMiD+bH/54JETFVdO
	mWGSwMvQ/Pw2A1gK70cU5Tm0K12kjC9L6yb9tu0oWB8662FaziXPCzOD
X-Google-Smtp-Source: AGHT+IGxzJo45ernrUIkegtX8cal5MoSwEhjl77KJrTAWZzrs2C/DUiFZeg0GWLCXOxKEOdO2ApLlQ==
X-Received: by 2002:a17:902:ec87:b0:24b:24dc:91a7 with SMTP id d9443c01a7336-290cb65c5a6mr333858005ad.45.1761314746092;
        Fri, 24 Oct 2025 07:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bMkGR7zFPJGQ3StUC7UDf/rs4Kl7MyIDp1gdIDvO5Lrg=="
Received: by 2002:a17:902:7898:b0:268:589:fe0b with SMTP id
 d9443c01a7336-2946c7694a3ls17913525ad.0.-pod-prod-06-us; Fri, 24 Oct 2025
 07:05:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3LgzpZETSoY3wcdJ7szyzGbIfM9ZKLbaWBveBHHwki2+198/RtQrLQ9OuogFa2tisUmPyMEZECyA=@googlegroups.com
X-Received: by 2002:a17:902:ce12:b0:279:daa1:6780 with SMTP id d9443c01a7336-290cba41dd2mr314750605ad.52.1761314744253;
        Fri, 24 Oct 2025 07:05:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761314744; cv=none;
        d=google.com; s=arc-20240605;
        b=HuRns26g0/g4QmQ+wmV9gP3WIuDsOdESwf57lMYxY17ceTQoA4/KcgcvY0LG62Zh1u
         DGNr9PifRQwLrX4aGIV5v/LmAYJ4opN/wdGK1d5adRAxnsiEKx1gNXh27naceKM4QIt1
         7OfjHCC+5l6UhVjWtR2McU87losB8lo5OrrEFd7PZhj6TEGDzcgdDWExBaljHqSndx0G
         JJyTeM1qPNVlXAXCWmuo4na3aZJ2sbkx+cToFDdHCd8TScbChBf12JvlgKAQmxpIHpKD
         YGAsydD80gceNHSjOIbElxGmlOx3srq63L0T8pKeCXm1syKZ6jUM5+PYhjlj8vcfoEXD
         42cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=d+lSgdkA9+bEZAYGayqSUgiThyPvWrBH7x+H6ZQsxL8=;
        fh=bHAfn63gfa/6zgOaS4Q5hb17jvUVzDiE3LdJ4wZASA0=;
        b=hVwzZq4xJkTgoRETvVQ8FBy/pc6w2gCdmX8SJhUn/0pSO65pZwlstbpIt19Sdxz7oW
         0yV6rBR9jR8QhzyEAnmYyjH/Gdocv/zWxPZdoblJwYUnRK/4XU6z8g7dTYmeI1Mn4dIR
         mM9xMCop2EwS4w3fhNN+q+GQbHlXP0SmLKMM8kIm6eyisBZKN+kly0o3xFEGxB2IWYIh
         bMBB4ubom2gE38HO0XJ1xjzEfaaMDw8NSaAQVFtYI87dHbvzx9hcJ4JWHsHMfBjxU6Tf
         hJB6Sijxvyoj22Eom3ycUd9IR5lGEocv5b1rfLjkzfbT9bDaJYh7mI1fsPac8rrnLi+F
         VSkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=fnXo7b6r;
       spf=pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=63920b99c4=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2946deb9112si3318465ad.1.2025.10.24.07.05.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Oct 2025 07:05:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0044010.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 59O2USQQ1836938;
	Fri, 24 Oct 2025 07:05:39 -0700
Received: from mail.thefacebook.com ([163.114.134.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 4a00qr3619-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Fri, 24 Oct 2025 07:05:39 -0700 (PDT)
Received: from devbig091.ldc1.facebook.com (2620:10d:c085:208::7cb7) by
 mail.thefacebook.com (2620:10d:c08b:78::2ac9) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.2562.20; Fri, 24 Oct 2025 14:05:37 +0000
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
Subject: Re: [PATCH RFC 07/19] slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
Date: Fri, 24 Oct 2025 07:04:12 -0700
Message-ID: <20251024140416.642903-1-clm@meta.com>
X-Mailer: git-send-email 2.47.3
In-Reply-To: <20251023-sheaves-for-all-v1-7-6ffa2c9941c0@suse.cz>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [2620:10d:c085:208::7cb7]
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI0MDEyNSBTYWx0ZWRfX/YulqWc9km6x
 rZ9QcTf19ercfPCVy42mSwO7q320WyUffMX/ZOVV7/0+LFbBFHmAfk2Z1nHq59y7qfsbHdViGRD
 io4nb8k8yiW8czQRYEwRQEohNhFCUEl4NRmZCYsgFJZlRxj1PtPgWgZzuVIHIIhPct9t2Wfu13D
 SLHDI/8l3xJYV14IBIkFzMZH2jMjSo9AdnQtxANe+GN3UolHaVOk7d0MrciDj2ba98RBSEmnLzO
 kdTPYGW/hzVqoNvRfKQibEWBbPQz4XKL0KqpaA61zheqxCgwbjLC/NI+Q6G3Ayt2KkYvzXNpdE0
 FNU6tWhrKW6R4RJlXT9SFRQZnB8ZN5hzY5AQz5eKeJWqoWxcu69Fpr1LA7wONxXD7eMaFZm2vNM
 KjiYAhsQxFDrI5BZx4kLTH5W8/mBsA==
X-Authority-Analysis: v=2.4 cv=YfWwJgRf c=1 sm=1 tr=0 ts=68fb87b3 cx=c_pps
 a=CB4LiSf2rd0gKozIdrpkBw==:117 a=CB4LiSf2rd0gKozIdrpkBw==:17
 a=x6icFKpwvdMA:10 a=VkNPw1HP01LnGYTKEx00:22 a=y43Pqs-daWJVC1BrHOAA:9
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-GUID: ypt68hrsJxSCnWKUb2JArGmMBobBfU89
X-Proofpoint-ORIG-GUID: ypt68hrsJxSCnWKUb2JArGmMBobBfU89
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-24_02,2025-10-22_01,2025-03-28_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=fnXo7b6r;       spf=pass
 (google.com: domain of prvs=63920b99c4=clm@meta.com designates 67.231.145.42
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

On Thu, 23 Oct 2025 15:52:29 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> kmalloc_nolock() and kfree_nolock() will continue working properly and
> not spin when not allowed to.
> 
> Percpu sheaves themselves use local_trylock() so they are already
> compatible. We just need to be careful with the barn->lock spin_lock.
> Pass a new allow_spin parameter where necessary to use
> spin_trylock_irqsave().
> 
> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> for now it will always fail until we enable sheaves for kmalloc caches
> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>

Hi Vlastimil,

We're trying out the AI patch review automation on the BPF commits and it had
some questions about a few of these.  Since the goal is to actually test the
automation, I'm putting them in unedited, but I did try and make sure they
were valid before sending.

This one is a little verbose for s/NULL/ERR_PTR/ suggestions, but:

> diff --git a/mm/slub.c b/mm/slub.c
> index ecb10ed5acfe..5d0b2cf66520 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c

[ ... ]

> @@ -2990,7 +2998,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>   * barn. But if there are too many full sheaves, reject this with -E2BIG.
>   */
>  static struct slab_sheaf *
> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
> +			bool allow_spin)
>  {
>  	struct slab_sheaf *empty;
>  	unsigned long flags;
> @@ -3001,7 +3010,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>  	if (!data_race(barn->nr_empty))
>  		return ERR_PTR(-ENOMEM);
>
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return NULL;

barn_replace_full_sheaf() now returns NULL when the trylock fails, in
addition to its existing ERR_PTR(-ENOMEM) and ERR_PTR(-E2BIG) returns.

[ ... ]

> @@ -6047,7 +6070,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
>   * unlocked.
>   */
>  static struct slub_percpu_sheaves *
> -__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
> +__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
> +			bool allow_spin)
>  {
>  	struct slab_sheaf *empty;
>  	struct node_barn *barn;
> @@ -6071,7 +6095,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  	put_fail = false;
>
>  	if (!pcs->spare) {
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, allow_spin);
>  		if (empty) {
>  			pcs->spare = pcs->main;
>  			pcs->main = empty;
> @@ -6085,7 +6109,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  		return pcs;
>  	}
>
> -	empty = barn_replace_full_sheaf(barn, pcs->main);
> +	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
>
>  	if (!IS_ERR(empty)) {
>  		stat(s, BARN_PUT);
>  		pcs->main = empty;
>  		return pcs;
>  	}

Can this set pcs->main to NULL? When allow_spin=false and the trylock
fails, barn_replace_full_sheaf() returns NULL. Since !IS_ERR(NULL) is
true, the code executes pcs->main = NULL and returns pcs. This violates
the documented invariant that main is "never NULL when unlocked" (from
struct slub_percpu_sheaves comment at mm/slub.c:481).

The caller free_to_pcs() then dereferences pcs->main->objects at
mm/slub.c:6208, which would be a NULL pointer dereference:

    pcs->main->objects[pcs->main->size++] = object;

The execution path is:
1. kfree_nolock() calls free_to_pcs() with allow_spin=false
2. free_to_pcs() calls __pcs_replace_full_main() with allow_spin=false
3. pcs->spare exists and is full (size == s->sheaf_capacity)
4. barn_replace_full_sheaf() trylock fails, returns NULL
5. !IS_ERR(NULL) = true, so pcs->main = NULL is executed
6. __pcs_replace_full_main() returns pcs with NULL main
7. free_to_pcs() dereferences pcs->main->objects causing NULL deref

Should the check be if (empty && !IS_ERR(empty)) to properly handle the
new NULL return case?

> @@ -6093,6 +6117,11 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  		return pcs;
>  	}
>
> +	if (!allow_spin) {
> +		local_unlock(&s->cpu_sheaves->lock);
> +		return NULL;
> +	}

This check is never reached when barn_replace_full_sheaf() returns NULL,
because the early return at the !IS_ERR(empty) check above executes first.

[ ... ]


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251024140416.642903-1-clm%40meta.com.
