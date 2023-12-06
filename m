Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBG62YCVQMGQE2R53SXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id E0233806934
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 09:13:22 +0100 (CET)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-5d3a1f612b3sf93507587b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 00:13:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701850396; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBn0kYkHz2csnGLNQYeX0WucRW7M0AjuYIuT8SkCpnBWyrl5mASaMnD5e2Lvi5C6p5
         kwRII9jJGIKMyhMkYzgjnGttDZDc5Yk7nQms4F9cKry5RX89wL6lYvNcPeUoxsmCOg65
         KNdyWQi5q2ITVbmPIz/AUs2ySwYZjO9uzMZvkCe5rp40FXwtGsE91py1msLUS5vfdTcm
         VadzmDqrrjirNfDNpMVfPoMbVA3hEeBQfFmC6gCZnylITRNtewWNHJNzVDM/9sjr/AAu
         XKTfP2lGkgia74gv6n2A7CbBD4XyY71sCGEE6Sd3t3soYD0f64yrOhvrUcDtYDBHLyzu
         9jPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=LIxadb/1sZGXXx+WBSVb0h2FjgVxEiNHswR3PSKT7p4=;
        fh=2r5aaXXmN8Cw+jz/mFF4Be4bCeBgMfrMSyfH8yhLbGA=;
        b=b1li9ERVsssF8V75UfJiB3kQIZvjy/Y1LQhquSUNggCZYLz4vvDhNXwsHzmwukLCce
         R98vo/BBLABLdlvW7ZI7M1GJxBVOcoKr77W3hbrAziH8AA2H8ImT05qhlJanD/ak8vot
         20e02vD1L/oWLCMTqpg6hqJdfuXSUkdJTKswX/HWKsopE4cRcb8ca0LWbM/hzeG6d3Z/
         T4llSoND4WuClPHdFcxdpAqcL4X27nxIiEx+rBmJcXpZq9CKM8lQR4Fq2QNqXCsLBv2q
         fXhHL/D8CVTWxY0dj8U5A89JGgkxAHrjgz3WDuE44VvIfXkRuLzulzg36FepBiaWu0td
         LXDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=X1S1VQIr;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701850396; x=1702455196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LIxadb/1sZGXXx+WBSVb0h2FjgVxEiNHswR3PSKT7p4=;
        b=Mq0ir5z7Y61tj/4cxExNtmUMamEtL+VyqY7i+HexoSXvVCaV28fHPFSA93zRbd15Ir
         mgA0f6U24h6mcbx5QJhuHUxvO0UQjVFG4+4au35+VB9Mjdu8omSQpUdtxRFhjfEAk9dz
         FmYxNHyZf5H57TCuuRPC2YN3h/imGLocHgTV7XU8zf5LxQmkZbbN08R3HAfQPvC9BrDe
         RKXPq2Q6+irhEbU+pHuwmHFQDl3Jlr/3vBbvGhEgn0+yKWhB1kSVf38+keOTewhFzenC
         OJvGamvMAVBYWEk0AzthosYEGKYGvb4C2il9yriXwWb2tMs+s5pxrDqUaXkzuCISre21
         UiPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701850396; x=1702455196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=LIxadb/1sZGXXx+WBSVb0h2FjgVxEiNHswR3PSKT7p4=;
        b=PZUFDN5dji/JI7fq5fRxT1CFtPz63mgF7yqc8andXwWY0q7rxt0heYZMsupliBzPe+
         D2E+7FiQf2cTifI4cZSc4PQ94YVEWwDJq7GM8fdUp6mp0MCw4FVvdUjOsGn28J6hV9Fa
         w1rF2Hm4fL19ahspADTVcF2Zj4+tMKvBrCMzXLlRER7QZigps0FHoZLIowfv8uZSsea+
         mtETxovBIvQ0ge/Iobjyktv5GqbpfQ7mYr8c3nx+tX1HWigPYZrvBdWkHeDZMwcwf2Nb
         eYo/Dcodr39ztzhX7Qj/Gjn8yEc5Ig47fMv6MdLw/R81FJeFC3OBJBiFRz9WShaUSr9I
         kecg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701850396; x=1702455196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LIxadb/1sZGXXx+WBSVb0h2FjgVxEiNHswR3PSKT7p4=;
        b=h+bEnupk+QxWiZ2m4c5z19CQtFrQLkHc7v3+/e9+FkI6kNgsP8LUgkVPHrX3pAUzrF
         4NsG4ZWvyyr0EOmizKS1P0F+hf0/cH16IA2YK7uwQWs4XRqcix6cAS/JfRmOGXGuCmxq
         D+4WiQLd0gqaMojwFu2a9zEI1KBe1ilpG62aN6bB2Cpci2h6ttzyZSU+YLF6y6xnSgla
         4lao+LNr24pPQT2fHLHvqWmp1+zaIewI/2HKpWT1eF6h+BdUsNhH98SktLDzaQPKqMvN
         pB+t6dIv/QsXZSifWCYd65zAloRRLYTym93S18LymM4RBqbzDjjeh2a7fLFXeHGgcgFv
         U5Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxL72XEBHIH7bV3EXgPmHhR4jVEUIKV22/Yucife2New6TIe6kV
	u8ih3pkilcPBdiRlGtXxkZo=
X-Google-Smtp-Source: AGHT+IHwfVQFGi1xFVvgznjBmJeTqJp8udO+kg83cW5yvFAL5v7b6MfM+wVHUr1WC8M60Zr6GP561A==
X-Received: by 2002:a05:690c:a81:b0:5c9:8532:e868 with SMTP id ci1-20020a05690c0a8100b005c98532e868mr377503ywb.52.1701850396111;
        Wed, 06 Dec 2023 00:13:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5de3:0:b0:67a:9611:38ee with SMTP id jn3-20020ad45de3000000b0067a961138eels6473730qvb.2.-pod-prod-07-us;
 Wed, 06 Dec 2023 00:13:15 -0800 (PST)
X-Received: by 2002:a1f:e243:0:b0:4b2:c555:37e with SMTP id z64-20020a1fe243000000b004b2c555037emr425389vkg.20.1701850395163;
        Wed, 06 Dec 2023 00:13:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701850395; cv=none;
        d=google.com; s=arc-20160816;
        b=itC3a0dcUOVva4CFUeC2H78LxnDJNMY7NlGD9oWSyrpwsra5j1p6TMe4b/UaZ1Dj4z
         VMTs6/ENmdzmtcGRF2nqQmDIWWwChj6T4OnQoCcZqXbZDyZtejtxbCtH1+FVMB9D1IFc
         zqvI7OPvf5kLimOXOFO3FxmqpH9cjcT2Yu2GbeLUeIAXWN8bs7BOp51oKg8RydnjDVfK
         pWL3okY6GAiZObEgHm0fE3X0tcIs6hDeK2vHgDlDkYKK5ZneOL52DWMechu1oUIPoROg
         CCPJVEfxziDQQUxks+PjIPvNf5XU10ivOVS++rrW3XqvtT/mt36TRTffMNqutcodG/n2
         el0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZKizt4iTnV9cayPmYedMVcEI9nEBmDM8KpDsNPl1XzI=;
        fh=2r5aaXXmN8Cw+jz/mFF4Be4bCeBgMfrMSyfH8yhLbGA=;
        b=KxMlEw8LzmQSOWX5BENTe2Nt6/hEErftbaxbrRmpBtQyM3U14HwbBqW+WPrA+zkf6r
         0EPAN8KfvzcCddNbjux1dbiyVyRYwL8Q1iBrcfDhphAb21Byj9DQJbuMmjwxX92dNiCW
         IhseZyqxB/OeL3mD0gMhjt7MbUJLYO3YxC1pLtKIVela1frJLtV3rlrAGqJUGHD5q7I/
         KgyS2FKwM6GkyPBDF4NqbLV3L5ZtdEvG10QbdPp2EnHz8rosRsUaJIPoynVGqYyEJ5kF
         th+Kc3baWBy292Wk4D7bQb/a7GbT/KDC79jmoo/RrpSOxdP1tdlyUDE42TrKkLRd1efL
         ZkOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=X1S1VQIr;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id bj28-20020a05620a191c00b0077f09d5186bsi350528qkb.4.2023.12.06.00.13.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 00:13:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id 5614622812f47-3b844e3e817so3843638b6e.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 00:13:15 -0800 (PST)
X-Received: by 2002:a05:6808:2e4a:b0:3b8:b063:9b7b with SMTP id gp10-20020a0568082e4a00b003b8b0639b7bmr906780oib.109.1701850394310;
        Wed, 06 Dec 2023 00:13:14 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id p12-20020a62ab0c000000b006ce7c28be72sm1455066pff.118.2023.12.06.00.13.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 00:13:13 -0800 (PST)
Date: Wed, 6 Dec 2023 17:12:58 +0900
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
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org,
	Michal Hocko <mhocko@suse.com>
Subject: Re: [PATCH v2 05/21] mm/memcontrol: remove CONFIG_SLAB #ifdef guards
Message-ID: <ZXAtCuk7cFQqpJE6@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-5-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-5-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=X1S1VQIr;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::22f
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

On Mon, Nov 20, 2023 at 07:34:16PM +0100, Vlastimil Babka wrote:
> With SLAB removed, these are never true anymore so we can clean up.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Acked-by: Michal Hocko <mhocko@suse.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/memcontrol.c | 5 ++---
>  1 file changed, 2 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/memcontrol.c b/mm/memcontrol.c
> index 774bd6e21e27..947fb50eba31 100644
> --- a/mm/memcontrol.c
> +++ b/mm/memcontrol.c
> @@ -5149,7 +5149,7 @@ static ssize_t memcg_write_event_control(struct kernfs_open_file *of,
>  	return ret;
>  }
>  
> -#if defined(CONFIG_MEMCG_KMEM) && (defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
> +#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
>  static int mem_cgroup_slab_show(struct seq_file *m, void *p)
>  {
>  	/*
> @@ -5258,8 +5258,7 @@ static struct cftype mem_cgroup_legacy_files[] = {
>  		.write = mem_cgroup_reset,
>  		.read_u64 = mem_cgroup_read_u64,
>  	},
> -#if defined(CONFIG_MEMCG_KMEM) && \
> -	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB_DEBUG))
> +#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_SLUB_DEBUG)
>  	{
>  		.name = "kmem.slabinfo",
>  		.seq_show = mem_cgroup_slab_show,

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXAtCuk7cFQqpJE6%40localhost.localdomain.
