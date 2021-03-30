Return-Path: <kasan-dev+bncBCRKNY4WZECBB2UFROBQMGQEBPNZ3UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F75034E116
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 08:19:24 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id u30sf8985009ooj.22
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 23:19:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617085163; cv=pass;
        d=google.com; s=arc-20160816;
        b=OgCHT7XLlCWuh/xYeWwXcHySwm8E6dSsetZd7v5X3RShzF2lUGEKW8hsNgIFJWuFX7
         VlhA223MLiq8qadIsWfUi0awB1rP+hXfQTxXerSJU3TaBYANeZQmjeml7hCmS4CxSkbB
         2D+GaXOznZXSxAiqYICP0UT7jvYaf+3ZFYrMwsxjIwY0QKzoUWek0G4BIfTzfyE9J9gX
         Y5ztWbIiyEcUjimLAeNFvSQ4hdnJd53tNoMwabLRH/66YIx8ZcLGlq9td8Oe5Z6upffy
         tbK5GczpEOcyWlLJBM1pJ9B2anBisScTwxWOqfBM+69sD4IybfkaWSpXpf4FkeFUtcDv
         xN7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=O0CQgy/mb480gOaeVBLG4gcf32/WOOSxp+43CqzypAc=;
        b=frMe2sSXpyLSTH+n5Oi+yZnzFvDwMlz6MbdwUWzFkhBs4ywBcmGOK5EB6j+sMjb2yN
         ckDdfnQIBeQI/+OgjEX3NBfLwKDZjzqVYGlhtNQO99sMuxNIaDcw/oE3RDJ16vqc68wv
         bmuQ32BmviuVfiNViPQNKccfcZkvlNpi5ZlBqd4+nUo/+nuQJlG0iWvPUSWvo0gXddgS
         MYFs5Z0rP2nawghIYsQW+clgCSprFAjeajz9w1xPdLSWISVGvlbM6zBotzON3N2InV1o
         dLjEuN5VSe7tVg1GSIYM4uc2tevPtiEi1HH/xExUcxNlPz8RJRTodQdHi/d3ALEv00JX
         dUaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=efEB3t5k;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O0CQgy/mb480gOaeVBLG4gcf32/WOOSxp+43CqzypAc=;
        b=Gr4k7cr5hhSJfGkNcRvwCRMpw+rDL+9lQQL1E+cRasTxL2y2OpIypj/MugMwdOtrmb
         Pzcixyy4zYSPZE1Yitb5501Fyy7w1pySe2xEOZaRZE8OkLV9qu5TVADWlzpGJawN6C1Q
         UihBNiBjda5cVEKikptfXzRsWaG89kohkqY+n4VZzSxeDLpnkS5/peok0lWq078y0Ydf
         ePU1fK8brhFq4J7utAuHrizItYvsw7dSMS5uqLKoSTz5diCPM48lp3AmXqEfPtWeM3YQ
         pUGdvD4FyycmSfonYXCw7UNjXNdlXTyjQzr7vUg+mW8ceX9HIkwv6MUOmcstee/Lswzd
         xd/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O0CQgy/mb480gOaeVBLG4gcf32/WOOSxp+43CqzypAc=;
        b=un+yudORwfbXj9nuSqskKihCMG65uQwB3ln5kd6fVln261oWBY0VWdhTtW5iNfDb05
         zed5o5yPZyex3LAncaGqd5QrTo+nPJbwyuH8/l0cPT9NiLRa0+w9+bxIhOnC7888jr5i
         tV2OpHABlNWLNj+u0Mz6yfpEiLUnmVbCfG+R2Aai/JARLwvRtAp1kV33++NmrwsBXUeC
         sAzURQNsNYvSwZnyb9uixIdaFIji6RNNBA6+Us3Ox9u+BNMcYHxPNeG4m5LUzODQyzR0
         SXZ2U+zWKKhxhNfwNaytBgndH/KGGn+veLv+iPbWVRoO3/gok0GCwQv7ZSOxeB2kDoTI
         bWWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334elJFTQWKyIkmG47n4W2Sux4/jJxYADk9iLxpEZdfMJyJpMZh
	Xcxch11fFB+ph6Qjo8agrDU=
X-Google-Smtp-Source: ABdhPJwKzssI0APbZGTzFkOujHZ2tuV7KCZu4gQfMXJG+ZjVhvCt+jhdJxnvruBEMz85xv7N23rsbg==
X-Received: by 2002:a05:6830:130b:: with SMTP id p11mr25748322otq.320.1617085163059;
        Mon, 29 Mar 2021 23:19:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c650:: with SMTP id w77ls4318447oif.1.gmail; Mon, 29 Mar
 2021 23:19:22 -0700 (PDT)
X-Received: by 2002:aca:1b01:: with SMTP id b1mr1981057oib.177.1617085162737;
        Mon, 29 Mar 2021 23:19:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617085162; cv=none;
        d=google.com; s=arc-20160816;
        b=VgRODRJ9iLtac8WvBo4HyW9NCZldWmy3/Y8JHs9BqQdIo9K3O4ZB25f2OWO5acmDLI
         krHI9NdJtm1c65Fij2pkoXXOp/KVRR3qIRBNBZWa4VoWnK1o4i2Sl2vdnBYaMvtoiVoh
         jy4lOAYjiuc61iybuz/Q5iRDB/f+Kswb2F3d+6TUJjNt0Mru+1FMn39Kjo7uP8UmQ9Ke
         ml3DH7LfuygvYafJSBJcKGeBUoIvHv6nAjGJLBU4SDW62J4zRYHs4q9a7Af49ngoS6z3
         91EHE1ZR92CZ6c0QmIrUAcMdRjALcYSMkz0pPhe0VxKqZO22G0k8J4rcsnQpaKvjD8bS
         YkGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=Wntns3ARiXICiDfUR6aRU71JIRxADrA3zKs3aGI5BBM=;
        b=p8ZdXc3rvoU/dPUtbtXR8uDH5lfY9s5CI2e4rI54huI72vyv9ckcKR1W2FxyFuAYX8
         VviKn9LbSOE1vG6AK8jTo0kahfSWFtyUFPfeTrCZpCy+m2jRCnDfF2VAmCOyANy8zeRI
         QtpTOR+xJvhkf9mMcjTTTuD9CWP0edU2fBHX7OjAe8YYn9oz2a2sGwNWGPFGrR4Qc3Rl
         iaWCZzjGKelW13OkUXEDyRY3Vx1g/zkx1HreZXzvHYCoL0ZNldMEnBFyenetsymBaBQA
         HVAkB1Vi8NmK51QTs54JHHcxKpJqZjOYhFt19EWPZskooVKyZrOOV+TsmIYx4vKNxEkb
         lYsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=efEB3t5k;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id v31si680631ott.5.2021.03.29.23.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 23:19:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id y2so5603840plg.5
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 23:19:22 -0700 (PDT)
X-Received: by 2002:a17:902:9b8b:b029:e6:b027:2f96 with SMTP id y11-20020a1709029b8bb02900e6b0272f96mr33264341plp.28.1617085162278;
        Mon, 29 Mar 2021 23:19:22 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id q25sm18713746pfh.34.2021.03.29.23.19.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Mar 2021 23:19:21 -0700 (PDT)
Date: Mon, 29 Mar 2021 23:19:21 -0700 (PDT)
Subject: Re: [PATCH] riscv: remove unneeded semicolon
In-Reply-To: <1616402316-19705-1-git-send-email-yang.lee@linux.alibaba.com>
CC: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  yang.lee@linux.alibaba.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: yang.lee@linux.alibaba.com
Message-ID: <mhng-f2509677-edc1-4e9b-b718-74ba0b9484fe@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=efEB3t5k;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 22 Mar 2021 01:38:36 PDT (-0700), yang.lee@linux.alibaba.com wrote:
> Eliminate the following coccicheck warning:
> ./arch/riscv/mm/kasan_init.c:219:2-3: Unneeded semicolon
>
> Reported-by: Abaci Robot <abaci@linux.alibaba.com>
> Signed-off-by: Yang Li <yang.lee@linux.alibaba.com>
> ---
>  arch/riscv/mm/kasan_init.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 4f85c6d..937d13c 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -216,7 +216,7 @@ void __init kasan_init(void)
>  			break;
>
>  		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
> -	};
> +	}
>
>  	for (i = 0; i < PTRS_PER_PTE; i++)
>  		set_pte(&kasan_early_shadow_pte[i],

Thanks, this is on fixes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-f2509677-edc1-4e9b-b718-74ba0b9484fe%40palmerdabbelt-glaptop.
