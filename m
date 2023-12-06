Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBNHBYCVQMGQEO3D5WXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E0E280699D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 09:28:38 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-db401df7735sf5979791276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 00:28:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701851317; cv=pass;
        d=google.com; s=arc-20160816;
        b=bkQcZY+i6T8OquN8S51K3Alf6171XRyWb+tP7E/FSjQ2sP2szJz8L/8X5RQiyYJlir
         kF29NiLPNYalqqucTOzh8E+ujS8nJiRcR7ejlKsMf5GdKAaNGOWidO4hExLRuTohSFfM
         n9OF2Uwt4x00aQiDfRkLOFKwWkOjiUBUf0QUHi/06uPTzy61stJCDQri8ZTv6AltM3Rg
         B7keEABzDPoaEtRJ5AHb3jXjjql56FUIrRh4WZC7IVOXdrOdL6Dadd9TkHrGNEzpYT3G
         X8J+i0milgrypE+NdTuiRqqfZLNvMcN1JEwuVAJiHHIh+VjP3ahQ1EcPBP0kyeEZESY+
         Ffkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=+wCtXiU2OsjtfTCZIomm1uG/a2skOz/W903rsq1SwgA=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=BtnGK4oc1FZYjjUxlDuIpnzbgyy7cTU9qhjsPhlCyZV02BfZixvdBvITEDmNiDu6L/
         MmFStHr29cLNsrJqQfcuzh2UUkRVKrZqUQXfYkwlkrQ+IrYcvB45l3H22BwIbYFqIIUp
         83/wmILJUi514nkCARU7RClsNQWSZdkocecgI6PzWuhMixLrBte7R5jo/fn7lcsjcKby
         RxE7OryIDs5wqTn34CNxsYpAtFmbMmzwZwl71lrNUPtTL9vibHPvFfiBeWOdGUh96vwL
         8e21UWommccuwFYzDo6MEhv6xqelpsoVS15Sqr7DQT17BAgfiBKJBTVZJGMvO8ih3SLF
         yL5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XvRY4a4I;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701851317; x=1702456117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+wCtXiU2OsjtfTCZIomm1uG/a2skOz/W903rsq1SwgA=;
        b=XNoORddzm5I0dEaV22tbFdQQwwU6TZxu4NhtZCUeOVTLyPOpgbbo0oZjo2VpPjX84q
         nDt/eONh2WiHIuzlhmbdTw380jmJ63tbdRii4E7eFyq+bZFVm3Fw23SG8p6mYj+fDs4R
         uOHsVSiTJ2dFQyfnD0x3tbLrGnpxJ8JwOmWxylPddBxWMkV8oYVFNVpx23aJpJqFRtG4
         FrOSsIZwPDlufGf/jYkmp2wa78ZT6mr5lP6bXDHj4zI5G7ycBn90O2DDFCARE3ldbI7R
         I6Z9aePpP4DIvkp7U8f+Cw7wAg9LTzoSUUIR8o3+OWRVORkOoJjg7rlMl/2ivCBylGDY
         BYTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701851317; x=1702456117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+wCtXiU2OsjtfTCZIomm1uG/a2skOz/W903rsq1SwgA=;
        b=UBd6374F8BO8V4dUA4axgWM5A2ZbUYoRwVEK4hZczmiB+r1xrN7aNCKFTTsnsTBfpG
         zAH9cAObzsbI5N1fU/H5JX6AbtbwCqHkXjKh3iAtkgyKJidX2Mi1uIJX2upxWKzBezMe
         joqrKxZm7lDcVL4CWYk56FLrF/bOGUo95OB65kFS1B/KE2X7BX0dWT6fXbT4eQV9j8LJ
         8SkCSPO8WeLmv5GRmU/XzV4jjw/UqpyjxIGNChIkFArXGKoTr9hPYWuE1l2Rsxeyd0iL
         q6emqM6T2M5XCeyEo/r85sK94Jt8RWm06gOJgdI/rKE4TCShopdNsYYHBXbbi87FGlsN
         fl4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701851317; x=1702456117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+wCtXiU2OsjtfTCZIomm1uG/a2skOz/W903rsq1SwgA=;
        b=cVXleZZ6RCOMTOOLF0KEic8E7LBOBr5kPxrzV/hnIwyH5jICQpkywlqJksf5lAWKXd
         MrM0iIyQeviyA45W6bpv29FXUo1UJEoEXUniKeiKKEgZ2ZqI7tNPsWlB33X3H1MixoD4
         BeRe3q+Ss8fg/qGn/3HQaVT0n/kOpksgsYsPWMxyfkD14gUYu/lVutbJJOGU40wj3qip
         EyMPejl6DOR1T1oUWaZqEzbS9N0SDqjc6IPEjLnR4CMZ/8GfeSH98wg4YLQ9Zxl2hmfu
         QJuTLIOpdLY0Ql0iTTpXI4cSgKY0Z0D1lVnrvPtHQb9mY8nbkl6De/1mppvsjPNVzLol
         zqEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzU2zKrghZDTkQpo7+KRyGBrcrW4NU68L4oLTJrKy9DNcfRRa4Y
	m8MRxk1FExp9rjvhPjWIU1w=
X-Google-Smtp-Source: AGHT+IFZms8w4k87oLIXtX2D30Qr/P8Ulsjr+ovaOd6GterXRqh9aJ1khWFKb7FLwgrahup3SJEcuA==
X-Received: by 2002:a05:6902:343:b0:db7:dacf:3fa7 with SMTP id e3-20020a056902034300b00db7dacf3fa7mr317304ybs.84.1701851316980;
        Wed, 06 Dec 2023 00:28:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9343:0:b0:db5:e688:5ce6 with SMTP id g3-20020a259343000000b00db5e6885ce6ls480616ybo.1.-pod-prod-02-us;
 Wed, 06 Dec 2023 00:28:36 -0800 (PST)
X-Received: by 2002:a25:488:0:b0:db7:dacf:3fbc with SMTP id 130-20020a250488000000b00db7dacf3fbcmr334884ybe.105.1701851316138;
        Wed, 06 Dec 2023 00:28:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701851316; cv=none;
        d=google.com; s=arc-20160816;
        b=YBGdHadBEa4PgmW+zCCfR+p46LJkalyobo4hcDGKy3BiH8gB6Ci9h7tM75smmY70xB
         EtKIWT/YNAXK7ACO8EBFutQhjkyhmO+2kf8G9rFqr5xeqAbvpaXUePVR9lZfhvNkf1eI
         AlpEefTQd8QB99mZe6RknsKiOpfDS2yUpk6JHzStgPLfqlzTp6zpKPiQ0q/I6QNoAq3h
         sP1QcGB/Fnm2I/Ytgf0iQ1pOkNN3rZXCRB+uJPg0i+r6y7KcnzB94wTrnypMZ3EUM960
         5jjgl2zlLJLVi74+KqQFk+l8Tp6MGLGzcJIAS5P6RQPdL4NnspwkE4PnY9weXZvN4Sqt
         DN7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0OhTf7i4X5voZ/FZ2Ct3sZZmvFDR7n3hZqKxzvAgYhg=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=tyezmoevZ0SwsJZ31dA9pLi2s14W8d2COZ3wMsQNInOf1yODEnsjrWPzbzJAdYvPB4
         ECWAyjryTxIqWxBXMk7sfl6F0l5houBSKrux4cbYnipO59jQPEpHJnukymCOqa5MPx93
         ZtC9zolJZzNBQdn4f4hl94Z2FRtnAuRw2mkgQEEsR4WXtL7r3wEXAU/ebic9NC89FQf3
         GvPolTSZjSFqSccTJ2be0Un3BYPeKyrulW2LyTPjdqH2P1g1bAh7pqENnSoyFQxgVF4Y
         K+x7g+ycqF9sDNhMXIIAo7Oy2B9AmSsuDOUN5b9+E9oANsEFoD9U6fqqNMIQ65gf+xHW
         v9iA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XvRY4a4I;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id x137-20020a25e08f000000b00db53bfbfd19si1039543ybg.3.2023.12.06.00.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 00:28:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1d05212a7c5so28511015ad.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 00:28:36 -0800 (PST)
X-Received: by 2002:a17:902:7b84:b0:1d0:6ffd:836b with SMTP id w4-20020a1709027b8400b001d06ffd836bmr260600pll.118.1701851315542;
        Wed, 06 Dec 2023 00:28:35 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id w17-20020a170902e89100b001cfc2e0a82fsm11474978plg.26.2023.12.06.00.28.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 00:28:34 -0800 (PST)
Date: Wed, 6 Dec 2023 17:28:18 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 06/21] cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
Message-ID: <ZXAwomfWa6fdcPQ+@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-6-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-6-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XvRY4a4I;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::634
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:17PM +0100, Vlastimil Babka wrote:
> The CPUHP_SLAB_PREPARE hooks are only used by SLAB which is removed.
> SLUB defines them as NULL, so we can remove those altogether.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/cpuhotplug.h | 1 -
>  include/linux/slab.h       | 8 --------
>  kernel/cpu.c               | 5 -----
>  3 files changed, 14 deletions(-)
> 
> diff --git a/include/linux/cpuhotplug.h b/include/linux/cpuhotplug.h
> index d305db70674b..07cb8f7030b6 100644
> --- a/include/linux/cpuhotplug.h
> +++ b/include/linux/cpuhotplug.h
> @@ -108,7 +108,6 @@ enum cpuhp_state {
>  	CPUHP_X2APIC_PREPARE,
>  	CPUHP_SMPCFD_PREPARE,
>  	CPUHP_RELAY_PREPARE,
> -	CPUHP_SLAB_PREPARE,
>  	CPUHP_MD_RAID5_PREPARE,
>  	CPUHP_RCUTREE_PREP,
>  	CPUHP_CPUIDLE_COUPLED_PREPARE,
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index d6d6ffeeb9a2..34e43cddc520 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -788,12 +788,4 @@ size_t kmalloc_size_roundup(size_t size);
>  
>  void __init kmem_cache_init_late(void);
>  
> -#if defined(CONFIG_SMP) && defined(CONFIG_SLAB)
> -int slab_prepare_cpu(unsigned int cpu);
> -int slab_dead_cpu(unsigned int cpu);
> -#else
> -#define slab_prepare_cpu	NULL
> -#define slab_dead_cpu		NULL
> -#endif
> -
>  #endif	/* _LINUX_SLAB_H */
> diff --git a/kernel/cpu.c b/kernel/cpu.c
> index 9e4c6780adde..530b026d95a1 100644
> --- a/kernel/cpu.c
> +++ b/kernel/cpu.c
> @@ -2125,11 +2125,6 @@ static struct cpuhp_step cpuhp_hp_states[] = {
>  		.startup.single		= relay_prepare_cpu,
>  		.teardown.single	= NULL,
>  	},
> -	[CPUHP_SLAB_PREPARE] = {
> -		.name			= "slab:prepare",
> -		.startup.single		= slab_prepare_cpu,
> -		.teardown.single	= slab_dead_cpu,
> -	},
>  	[CPUHP_RCUTREE_PREP] = {
>  		.name			= "RCU/tree:prepare",
>  		.startup.single		= rcutree_prepare_cpu,

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXAwomfWa6fdcPQ%2B%40localhost.localdomain.
