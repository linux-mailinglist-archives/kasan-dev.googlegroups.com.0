Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5HJ3T5QKGQEQHJCIEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 419C62814B3
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 16:11:02 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id q5sf1234385pfl.16
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 07:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601647861; cv=pass;
        d=google.com; s=arc-20160816;
        b=BcTsG2EMwj5IK9nsNxyV2/w7IpUSRiLIgqNy7hYd5bwDC5QcBYCOhVdcUKFZulaRPb
         xdizfoLGm3Ckuwbk5KF5+Uw0nSrlVxH+gM0JvXfyNz7i6kcOUHQZQ8UUYn1MnaAaJ8dw
         VOcWvJyaxII3q3SJnm2H8PKqQE8vv0hNMk2sMdtEAguuFy6TGbMaFv+KI8rywCAnRp2s
         WFsWBLoyFtz/e6vEkixctysN9mzSzFHDPul3ux82SMHa/1sqx0yH0lNCfWCZIX5rp1wK
         4zqyHBTn058q8SvOVdBsfeeI3poWF8LWCbQsk0qYNlsJOg0Bo/tLmQq7+p90MvRUqoCo
         WGTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=WFS7jz1xsdlEuxa4yJXOKzq0S/vM4SeKkc3HFKZ6Dqc=;
        b=swU1H9OszYY1+ZyiVJOqWTmWfOTYrPOnRsNfzzbYLCdzSsqk/HKZQiAqwmFrxuwPHp
         V+5mEDYW0KwJvSuVdIfE9SkC9auSV1sDaV2hFDtlMWoYJxn7KearPWzm6yn6zwDMpDOC
         ECLNvpWlBi6apPJ2eitZi371NWM/0IGkrkeLga/o/+mO+2AN2WExiG7O5N2pyaSbHWG0
         TbPARM3GnLjUyyvdFgwVfPcGhMGmu4vw3m/jtqX+7Xnc76Zr9J/HF3iRhv390FfiB9lX
         zjj58n4PwjDvgUs6OtdKceM1mBW7UTpaMx0ttn7OjatA2tEuhLz5TaE4cckM0F9tZA+t
         R2AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WFS7jz1xsdlEuxa4yJXOKzq0S/vM4SeKkc3HFKZ6Dqc=;
        b=IP3aj0swh+GZRnv+w7lN9WLjJsJ2vF6+VVSdnfrgkkHkfdeenKrNhufho3SyrGB0dC
         8fMDZN0n3TJ9iZjx2mEEk2WB5J0CVzUSlN9WUAU4jfm+RobgSDcVpGdaA8puiYkzo4WU
         flp2wfjUxYVu5FGaRcAMZVHd+EOq4KIrbw8ngHs6jq54x8wO4N8bcDqUIEq+EGYlXO3N
         ACsud2uFwztPPs99jvIt0qyMhE6jPljRbBKULOZjh2ND2tPL4HeWgrz4BAhfEX3MpKVg
         sP4QttKUz6JSxq+vGc5ufZEjbeDM5ELM/D2wC1lv9TEpSDrl7rhnQL9+hyBNy4iBVlR2
         lezw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WFS7jz1xsdlEuxa4yJXOKzq0S/vM4SeKkc3HFKZ6Dqc=;
        b=YL9MLTnoapi0NnEkme/GuBYT7TwIpjvRraKlM1YAgF2+iBXkZGJeQcSs5IB9aU3I68
         SW5aovvaLbiRiO5iLHm2yP4EfhGWc6Ap8C8ClwyFsBmai774JtW4VuRDuRkhCN/yhNex
         zApwSvlb1DnfWeW/DQY/48wh7YL8ogbHs66L979tTZ5BXgXNPkr2CGY6FI8RBp3K+T0O
         kk/vvHjeMFHV0kr9LzUzjBGnP/mXl2T7/tnqPa9Hv4k2pnEDUSq17E3RoKz1C8jkgUZv
         w5mBBOurTry+bddQ0tJiq+Wd1Eif6HSZVggRdRqUKSE/6n0e3Kb0fzc4D2EHY3AHb+P/
         QhxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZV3BpU/H0UVk0Sesgf0xyBxwVut8N/L79kbewQ1yfBYXwq+jV
	q3cy+x/bt6g0UHi/UtUXngk=
X-Google-Smtp-Source: ABdhPJz/cDFxpYN7oehPjq4ZsCg7kxSudPlNlsO4KukzICkOvUlESUb4KbVh46YQ7c2s9di+gfhWdw==
X-Received: by 2002:a65:6883:: with SMTP id e3mr2316626pgt.250.1601647860963;
        Fri, 02 Oct 2020 07:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:3855:: with SMTP id f82ls937999pfa.10.gmail; Fri, 02 Oct
 2020 07:11:00 -0700 (PDT)
X-Received: by 2002:a62:8806:0:b029:13c:d37c:5e47 with SMTP id l6-20020a6288060000b029013cd37c5e47mr3015689pfd.13.1601647860144;
        Fri, 02 Oct 2020 07:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601647860; cv=none;
        d=google.com; s=arc-20160816;
        b=FG6TB7GT1qBrVrLcbP8Ksa7bYhAS/chJ5JB/pO7k6qT5k27lT/zJRcMr6olwiIXgmE
         eg1LqwNuAw3I8H4pu2yhlx1MkeGLtkLRaXRSoMmoUO6inmNNcRAiuvMzfy124vOtkovq
         jOyynp4LCsJ2UZyHp/ytjxm+ZGuYeg8usqfDTcQk+RfrFJoYSSRRiPpRLUYKK8+1RHJf
         8XP3gk64Zcv3Hm2w2ThVVQYQ2u+rzqSh9edhAzGvOts/0U05lNqKWrBEmjJirXRa9/HQ
         SmIYneOapepLtsllLkLqZR4O9QQfUibBpKkLejHQhqcXL+c28cJgJctQkuy+9c3oRtrm
         +NGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=7DCCdHJ4aS7wyGNpnqISdswTAklZ+I5mglaTpJ6kt3s=;
        b=jMV1Po9E4ApH11rNrhyvwPy/Dry2MDeyLYyqLO8cLnqawQ3R+CODXEOIMrDV0pwm78
         WaLGy/FBQP0AL+DxYpAhEJjT2+H/aJiKouVEW6frDj4kQbJQcgo6nTDLiRDN3wg05wJ2
         8zqRH46YuIY0mM2ee53y3ECybvK+TrMHU6jJJ9HwvLtUCIE/Sa9K/ca+2FafsDh9f6uC
         sGwS9QQWD0PylrLf3JJqqJ9pQS2a215USg40tVMetapRyRdADSWK2ssiy5b6/5RB+Ejo
         yV2yxNM4V3tgwzNYZ9QRugGiZNla2O0gRNzQoRknSLKOAS/22gytAda+NG3zIBLUb2vp
         2ATA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w15si84565pfu.6.2020.10.02.07.11.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Oct 2020 07:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.149.105.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7543C206DB;
	Fri,  2 Oct 2020 14:10:57 +0000 (UTC)
Date: Fri, 2 Oct 2020 15:10:55 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 30/39] arm64: kasan: Enable TBI EL1
Message-ID: <20201002141054.GH7034@gaia>
References: <cover.1601593784.git.andreyknvl@google.com>
 <bcd566b9e00a28698d12a403f02dc89fcfd03558.1601593784.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bcd566b9e00a28698d12a403f02dc89fcfd03558.1601593784.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Oct 02, 2020 at 01:10:31AM +0200, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) that is
> built on top of the Top Byte Ignore (TBI) feature.
> 
> Enable in-kernel TBI when CONFIG_KASAN_HW_TAGS is turned on by enabling
> the TCR_TBI1 bit in proc.S.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
> Change-Id: I91944903bc9c9c9044f0d50e74bcd6b9971d21ff
> ---
>  arch/arm64/mm/proc.S | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 6c1a6621d769..7c3304fb15d9 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -46,7 +46,7 @@
>  #endif
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1
> +#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
>  #else
>  #define TCR_KASAN_HW_FLAGS 0
>  #endif

Please merge this patch with the one one introducing TCR_KASAN_HW_FLAGS,
no need to have both around. You can add my Reviewed-by on that one.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002141054.GH7034%40gaia.
