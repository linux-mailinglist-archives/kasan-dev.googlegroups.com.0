Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5UO2LCAMGQEL7VA77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 693F0B1D643
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 13:01:12 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3322dedb9d8sf3940831fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 04:01:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754564471; cv=pass;
        d=google.com; s=arc-20240605;
        b=OJlV8kYhq0/PBzbFSP0rhdBJjTkkm/R8hcxUqeuWOITZZaQmDo8DAwEqWEFKlpb+Le
         xmsfFE8QHfOX7gKumeGgGQomngaWVdMsTX3FoGWMoRB/S9cft96l86CIdtvtCCoH3VJH
         xbuwdTSX6l2CEfhvMqeYHEX/r8YRd9v09QjH/vHEIcFlaXrki1/dbwl4SCyJVILNdne/
         pVQo29+jN7HcI2TlkpEX6vgI3KICHYCiE4S8MzSgG7fi7msyfrgrwZJpVPV7ideQXFP1
         Wp0IqX6MmfrPj9hUQ7QiR4znlvPMVV6+SXXwfmAolQ29AW50bUSotRN1fX2UfvpKzJNS
         Agrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DgIjIgvfrinkPBMbsFXO5QkIuzsz8K/GPyN2q7E/I7E=;
        fh=HwS+63CRBa/sMjnEZoCW9rE1ktPPM60FAoKqU0jpYQc=;
        b=U/oy0i+iriU9+w7XM1X62mOX0v3kqc+PrU8go9Q30ts1kVymCtUqbpNCvm8CUs30IL
         kBG06xKbRVqxrVVP2X33/ViUGXLrPvPFVyGw1AwUZ2k3A+8K+glQuogGaTSCBxfLg5Ci
         yv3lMfFWk3kdyufPZavnHvZPchFEXwRlK9aFY8aHlFS9BrVxSbxTSl6LBIQk823hMk9R
         ufCreBw5zSVJr17q1Nn7n20G6DGd+VzkK8hY3hQdYIS00i+SKA3UopxjeIsPf72ZHLhq
         40NRQROLo846BOr8Xp6qdbOfRBzhOlMjtT7mCm2VqFWmInQudEIyMtD6P0Lqf+jK+6MR
         OI8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AtjTOSyT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754564471; x=1755169271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=DgIjIgvfrinkPBMbsFXO5QkIuzsz8K/GPyN2q7E/I7E=;
        b=tClnluECjJvHueDw888D07XN0BaTdXGQ84sl/HgFiY/iuxCbbU1A7tSg6UkZTO/8OB
         R1n3t+Aj4w9ueq/VTbLRktEgZEMifqHKugwxN4MO0udyjTWXzlaqP8Abg2IbfFCrJuMA
         +f4DY9CPpgOxWxYgEdyryvqlbkqMTmI5V5abpFqwPB88TWuD1xKn/G2GPyxJ9FFzqKrI
         /a1XdeRZtPoiPs3iLaoedq5m/6poXbFb3K70mcZzug7I1Ku2y/A5eRIRBV/rWUFu2kU8
         V5CmzvRnv7MTc8nAZATWcVOFnU7BGoUfZCwOIvPX1ueQ6hdyZe6i4rY4i4P7GBz/tfUq
         X/5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754564471; x=1755169271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DgIjIgvfrinkPBMbsFXO5QkIuzsz8K/GPyN2q7E/I7E=;
        b=fnlj81VlsD0MebbmWhR9TnpK1IHI3wUS2NuQAEY0bp87c990SNh8+iRCaXvSiwE5qX
         LtSU+hjVnel/mQscn6nRAT9ryC2B+ijKFAMql6Oy7FM9puRRgZA8WJS33qwjHeCHwtpA
         A+Qd5Z/6TDtOewrEs1Vhe7z0rEfh6E7WafVFFKE+XETwXTzv+AuJysIAD0QcWamHETF4
         8g1Bu988zgQiwHEAdBDGfS1bLgEx6NRherCEYdFl/84z+qCzG7VgXOxlBVOtBmz/G8J0
         cteJiCrbt0JHTWBQpc51q7GbnmxPSvL4PPHLVI2O2Y9hjqvNtiTSM/xxwX1oeWTsB+Hq
         VImQ==
X-Forwarded-Encrypted: i=2; AJvYcCX4g2B0G9dRGt72WrFvLURmDT/Eye0cn1PQj+dqNVsFKEEFs2eava64RvnAxOxTTeAyHDMpSA==@lfdr.de
X-Gm-Message-State: AOJu0YyO6gz3EmcGrheKQnTvHh0N8vAijAAOPz8401gVsiipyKANo7dO
	6xTU88JLd8Xd+H01O867j/E5j7K6lgZaws5f/ERAbWC5xcR6DG51nFRY
X-Google-Smtp-Source: AGHT+IHLDZnGB7A0FfXtQLG3pUsYVqJJzA6t/8g2XOrnjqqMhEaKFv+mW2AhtUBUfEA4t1mMhdGiRw==
X-Received: by 2002:a2e:bea7:0:b0:332:3b34:1f09 with SMTP id 38308e7fff4ca-3338137d225mr17872121fa.19.1754564471212;
        Thu, 07 Aug 2025 04:01:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcAYMab8pS2aTMODdIlrqKRUAzNBrO6dcxw3Lsu71ENHA==
Received: by 2002:a05:651c:418c:b0:32a:6e73:cf7e with SMTP id
 38308e7fff4ca-3338cb39aaals857711fa.2.-pod-prod-03-eu; Thu, 07 Aug 2025
 04:01:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+TkZKbzzgQtWfW6g1Do71yB1rmOwZmSrpcITnZzziqRhrz4ANxg8VQAJd2L7CI/jjgpADlHjqykQ=@googlegroups.com
X-Received: by 2002:a05:651c:3248:10b0:32b:7ddd:278d with SMTP id 38308e7fff4ca-3338120ce12mr12068661fa.3.1754564467750;
        Thu, 07 Aug 2025 04:01:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754564467; cv=none;
        d=google.com; s=arc-20240605;
        b=FlSMNRYQUfFRThoiJKstyYYIbYjv0rAqvr8GaqQNzL+AEAf6qhXBUd7dOlPLBKF4hk
         z8AsPaDwUoX5tyys4PT6rmMbdChJED34oztrc3fhXhdL9LhOC4RnYlMsQwrU+2906HhW
         91iad6eUyjeDXfZYTDAVPxH6JxqoaYWw4t8KFRef1vBEQuqo8edK++PAZCSEVPDeGV6I
         tCRofLNrua+QlvKJmDxzHdREHXoCRPP2ZJ+b/7RXJbDAyyfY62P2oBU3sOjHH9SrBsa9
         RWxiX+UhMgaj3AoWJP0wuLqpWKrpu2k5VSr+OWbTXB1z3wRHQkQTdxJYSxiOseEKPu8d
         NFZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=z1LA4zLatdYQ3Y3OjAbWN8XrQew8n5n36uGhalyKn/8=;
        fh=a/MHj0OSzI3Fk5pGsss/mnhxPVZk/jUl1XuN2lobhn4=;
        b=XP6L3mQ3H+Smdn94Tzi2GKULSNNLsLHrU7Y4o0hgfMYTKZsePYWihfbcD7QAwo+1mz
         76zO3zP4Ttvw5yRX6txOpK6fcx7pft9AtIG2wV10NFT4uyJEB8ZSZyqwc24oxs6t6/WS
         xWTf+5Y4niLfHUBupFDwWuQu3VKw78Bu+ey/V5LKAvephDxR7aOA+YoAnykyg/erRt7z
         535zKxMTU5wTT27s+Re30JItuSBul/RtJr4zpj1PbRhrUyyLJFZTYWv3VfkFgbTivN9V
         skfwTW9cnX0y91poCUlFb3u8hy6Zj5m9/1ww4PG8Qb7Ot3TyH4P0KP27pjQLWWyLmbn+
         lG6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AtjTOSyT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33237fffb5fsi4280831fa.4.2025.08.07.04.01.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 04:01:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3b78b2c6ecfso414054f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 04:01:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU084kVVgJKFoXHouLdzb3ld/Sh+e7hqqFMDse+xiHUQFO4jr17uT0+WqRl28a4gYAJpEFdXthJeNY=@googlegroups.com
X-Gm-Gg: ASbGncsNuoQXQVz8bYSdqILAxXCLXb9YyPdKGO5XJi0PVATz5lAWb/xxITS6aMk8/eV
	8x878HsQ4W5VWHlFsHFOMLFtj9dmqU6BKy17M17W53WuUMlTgkWK8ySR/McYxvf/B3ER4NLVX1F
	JWQPmL0oBcUelqz4OXKkJEIUeP3HcdLcmFVM+B8lZ2vng/GFfekp2X+2tHS3OJf60vO9mhSZbbW
	L3Ov/koLaro1xFbiXwhLdc5R10EXJIdFwFk1UAVANsnRb/UxTEZfHGMQki9IEsGJiZBTRiKSZvi
	R+tYvGqJgekwKRJieFgBIvn85x/q7oRSIUh+TDZvcn5IPelilpUZDl6NBPp19HBoopGZxuGoVEF
	LRN5vEpLPFO+qaZtQkMvNv4KY3nxPWx/X/+PFyQwmMgRDeHdB0ZrHNMU5wi0=
X-Received: by 2002:a05:6000:2489:b0:3a4:d6ed:8df8 with SMTP id ffacd0b85a97d-3b8f41b4ed8mr5599905f8f.39.1754564466804;
        Thu, 07 Aug 2025 04:01:06 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:ad48:3e8a:43af:495d])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b79c453aeasm27312698f8f.40.2025.08.07.04.01.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 04:01:05 -0700 (PDT)
Date: Thu, 7 Aug 2025 13:01:00 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Uladzislau Rezki (Sony)" <urezki@gmail.com>
Cc: linux-mm@kvack.org, Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Michal Hocko <mhocko@kernel.org>,
	Baoquan He <bhe@redhat.com>, LKML <linux-kernel@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/8] __vmalloc() and no-block support
Message-ID: <aJSHbFviIiB2oN5G@elver.google.com>
References: <20250807075810.358714-1-urezki@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250807075810.358714-1-urezki@gmail.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AtjTOSyT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Aug 07, 2025 at 09:58AM +0200, Uladzislau Rezki (Sony) wrote:
> Hello.
> 
> This is a second series of making __vmalloc() to support GFP_ATOMIC and
> GFP_NOWAIT flags. It tends to improve the non-blocking behaviour.
> 
> The first one can be found here:
> 
> https://lore.kernel.org/all/20250704152537.55724-1-urezki@gmail.com/
> 
> that was an RFC. Using this series for testing i have not found more
> places which can trigger: scheduling during atomic. Though there is
> one which requires attention. I will explain in [1].
> 
> Please note, non-blocking gets improved in the __vmalloc() call only,
> i.e. vmalloc_huge() still contains in its paths many cond_resched()
> points and can not be used as non-blocking as of now.
> 
> [1] The vmap_pages_range_noflush() contains the kmsan_vmap_pages_range_noflush()
> external implementation for KCSAN specifically which is hard coded to GFP_KERNEL.
> The kernel should be built with CONFIG_KCSAN option. To me it looks like not
> straight forward to run such kernel on my box, therefore i need more time to
> investigate what is wrong with CONFIG_KCSAN and my env.

KMSAN or KCSAN?

[+Cc KMSAN maintainers]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJSHbFviIiB2oN5G%40elver.google.com.
