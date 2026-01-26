Return-Path: <kasan-dev+bncBAABBLEM3TFQMGQEH4DWUIA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id HMRyGi4Gd2lGawEAu9opvQ
	(envelope-from <kasan-dev+bncBAABBLEM3TFQMGQEH4DWUIA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 07:14:06 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id EC64F84625
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 07:14:05 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-b88489c64dcsf340336966b.1
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jan 2026 22:14:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769408045; cv=pass;
        d=google.com; s=arc-20240605;
        b=WMO8q3+RhcTbiTFLGlUgJJyPGlEBQdoV5QYuQO1RiBSaWq78TmCSJJBuRxBEifP0rN
         oxQQlSbcVmN6lGKAeI6hC3mGHC2b9jVKsAEZEBt90XlaxFEXbxGByNUfyxiy6oU3nmZW
         w04hzmCFkibPCBOr+9kEE/9uL17a0dLyzkiur+boDeRlO7lA707S2Hv7z5vO3/l2EMaV
         YNhH0fCpk6DoyWwnIIqclTwW8SqVoGB3lTfrYmuj1rjkYPvno2V537qZSf7Vf5rWkq0a
         +qbandVLFaH8/fem/svFy/GO/peQ4xYOjbpisR3WiHe2pgXoI5EcqA9us/1oNBtJz688
         GTCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZhqS4Eil1zF9xbr5PfUgriULDEtefmi7fNz5TAQKjv8=;
        fh=6l1PUZTkDi9pBg88bsDjxQ3kb8M45UzL38lPo17kzdg=;
        b=GMg13I2XQgh0MJHL+GMkY96nsTE0w2IWo7f3rXrFyZe4lvqvL7TyKTht1UUeA6gDpx
         2PXXoWod7pH0kVdzorYSIjbNBpNy8LW9qAsqMljoeu7XyG9g0XLbogR4vsTHMHKgILmb
         VA4Xohmox/LBD2D6uNYy/S0OuIqwrX79pl/lq6ljUkArW9yjg/Q5y+iqO4kliOjbmoG7
         Mo/OE45vVnlchNhNB1n4rZ0TaWXDGyuDztHDg4NzkNF0+ifX72gQDg0qc1cUqT5Y+ufk
         fC1Ftg+iCViNzzFZ/3LCScxh7Wfdbvf1tN6izOYc3rBfobc61lsNHZEhrgPBa6+mW/Ug
         oUXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pmKuYWar;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.188 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769408045; x=1770012845; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZhqS4Eil1zF9xbr5PfUgriULDEtefmi7fNz5TAQKjv8=;
        b=a9J2OOhiIA6aWnEd6VlPKE6d0WwlHnPPYEKwhHsLRU3Yw61Ya2Rng9oj7+5kqtAu1l
         9ISq0q6Yt/XDgb324tbYrPN2+FgUcMt9G2zfB3NBR4Kp8yzEc3slRp2edb5IufYuyz/R
         IgT4MwsllezS/orAuD2XjscRtlB3ebIhgwzbrF6PGMLdlcl4iwR3yyIiJSh7KtdAgYIj
         WN5Wmic+MyTzYc3zYnBkDG4Z8fVKIR0g/DfvlNR27WYwPqScI9AILxP94WriLmrnb6MY
         /yqY6TDxk91oWhhcDOMBFEAk0HvfYnUKWt7aUVXKB/uybMHADbtJYxERst/SgE3oIGjz
         yLpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769408045; x=1770012845;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZhqS4Eil1zF9xbr5PfUgriULDEtefmi7fNz5TAQKjv8=;
        b=IbFTw0Zos4gzRYr2YNkoOAgvkGKy+1768tj2dTESdTVHNQ3hn6sL2xqgJYWCqSaQFA
         Lfd+QV/mlkMw4VAUpguh7LriuVemAsddfOCT8NKBwjE+joXm4/Q1y3vGOqIPSGfyhK96
         MLZJnWt3QErVSAmXdJTWTL0Cle24jHklCkDQU6IRguhthQStOqHkg2OP8A9PamCxN0y2
         sFie3I6yz3TnOXm0NyUCbNFiWa88k9jFCSmklAvf2edSTN2X/ikiuuDzcsChUbiMd874
         2PUsVHe1lJl6AG9/8xE5+zRH+Ti+YVfZfxYwkAQ5LoR6uwAZIAPslH8Y/wvYNsEXU0nu
         iFhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVllNMaz2Bkpyo6+rnm5dyVwqdtr4g48U9vd2bb8xest1YjAqlBLw/sKT/OLj27k5Ykx1hTbQ==@lfdr.de
X-Gm-Message-State: AOJu0YwrMQaeOGh6Dst4oOSKs7dFFqub3aiV+cbE6ftpJSMdJUhZIkJI
	mIhSTYtCfEGk67w1KEbDJBWi+PbL03kZav5fOBYimv50sNm/bwDjqSFJ
X-Received: by 2002:a17:907:a088:b0:b87:15a7:8603 with SMTP id a640c23a62f3a-b8d2e70959amr267187766b.43.1769408044799;
        Sun, 25 Jan 2026 22:14:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EC34iOy22HSTBxdVuS9zfL86btjiAMWyeeCodKoF1Uww=="
Received: by 2002:a05:6402:1658:b0:658:3078:75b5 with SMTP id
 4fb4d7f45d1cf-65832d546f9ls3253905a12.1.-pod-prod-03-eu; Sun, 25 Jan 2026
 22:14:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfpZTjJu7IW/bhGAnLqVGIiz6DjVp6OOqEI0eLs69xyt6r0UULQuBxJkYR9m4xPlsq69M+NK2ZTZ0=@googlegroups.com
X-Received: by 2002:a17:907:968f:b0:b87:322d:a8d0 with SMTP id a640c23a62f3a-b8d2e6f8c48mr233946066b.41.1769408042904;
        Sun, 25 Jan 2026 22:14:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769408042; cv=none;
        d=google.com; s=arc-20240605;
        b=Q05xFV9FX5cfOCpAc4IU3WoXqswc9wOY5ScfawB1DIxpkzkNJatcg3yGyVQ4Qh2ozU
         Aug2lfO5xUT2ev8L/69JA2J1fespl1YrjTIVRldNAt4ANhGyKgBs6i0mjBWR8Pp+Xrja
         BgYRrEiQsAcU56x9dOx/rSv4hkudHMdVKj9iwQnmqOvFayfwk6R7zSRIYT2D0GijoUcS
         kndS3PpXxA6lYAk3OnXTQEokkEJR9Keb24kxWYBBSFjVxwJEyZLxUE8TjGI/d/ptJm3o
         t517r1Ii551pcLJ1X9vahSUlGH/PdNBrdQ/qnFN2lIHOFov3fUlQJWyTnsZYypla5Js1
         VedA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=fRkLP4BJZeXuj/pQ6WlXqQb5hFaywSSeMSj8bpxWqBU=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=AXDi5IqOwSGYtA27aMKt4qL6hspjNnHCV6uh82J9fLGJQl4L70OJjBjOFfvp9VcKy0
         srfGvRJ2HHWOD4Pa+e9tHhrSHzBuriWKQCgC+E7RcV1coHa5RVTZ3cIgV5bcMJOoHONt
         fzizJiHBVfKBmIT0Gk3R8BfDb0HqT06ls+WchyiLPWsXoRrIHDuAKfTo+XZpxi2SaqiT
         ik5W+GDmi7zntVoY2Api7yWX7MxxeSIiTohtcMv7uJHy5ILPV5PstNOIeXVP3DJDE6NG
         z0Yo5w2bAen74ssGvaNjm+KxOCDRD/6UvmjuJ2JOzZBEiolpumk6pBSxiFd+IKixHpR0
         CuiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pmKuYWar;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.188 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta1.migadu.com (out-188.mta1.migadu.com. [95.215.58.188])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6585f1fdf42si124011a12.5.2026.01.25.22.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 25 Jan 2026 22:14:02 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 95.215.58.188 as permitted sender) client-ip=95.215.58.188;
Date: Mon, 26 Jan 2026 14:13:51 +0800
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
Subject: Re: [PATCH v4 07/22] slab: introduce percpu sheaves bootstrap
Message-ID: <qrekwm7js5t4kmahu3toqnrepnvk7ve5h624f6hm262mmybvtx@rewwd4rbvf3b>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-7-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-7-041323d506f7@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pmKuYWar;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 95.215.58.188 as permitted
 sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABBLEM3TFQMGQEH4DWUIA];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,oracle.com:email,linux.dev:email]
X-Rspamd-Queue-Id: EC64F84625
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:45AM +0100, Vlastimil Babka wrote:
> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> sheaves enabled. Since we want to enable them for almost all caches,
> it's suboptimal to test the pointer in the fast paths, so instead
> allocate it for all caches in do_kmem_cache_create(). Instead of testing
> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> kmem_cache->sheaf_capacity for being 0, where needed, using a new
> cache_has_sheaves() helper.
> 
> However, for the fast paths sake we also assume that the main sheaf
> always exists (pcs->main is !NULL), and during bootstrap we cannot
> allocate sheaves yet.
> 
> Solve this by introducing a single static bootstrap_sheaf that's
> assigned as pcs->main during bootstrap. It has a size of 0, so during
> allocations, the fast path will find it's empty. Since the size of 0
> matches sheaf_capacity of 0, the freeing fast paths will find it's
> "full". In the slow path handlers, we use cache_has_sheaves() to
> recognize that the cache doesn't (yet) have real sheaves, and fall back.
> Thus sharing the single bootstrap sheaf like this for multiple caches
> and cpus is safe.
> 
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h        |  12 ++++++
>  mm/slab_common.c |   2 +-
>  mm/slub.c        | 123 ++++++++++++++++++++++++++++++++++++-------------------
>  3 files changed, 95 insertions(+), 42 deletions(-)

Tiny consistency nit: in kfree_rcu_sheaf(), there's a remaining "if
(s->cpu_sheaves)" that could be replaced with "if (cache_has_sheaves(s))" for
consistency. It's trivial, so no need to respin - happy to have it addressed
opportunistically.

The rest looks great to me!

Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/qrekwm7js5t4kmahu3toqnrepnvk7ve5h624f6hm262mmybvtx%40rewwd4rbvf3b.
