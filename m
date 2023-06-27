Return-Path: <kasan-dev+bncBDH43ZGQR4ARB6NB5SSAMGQEM2Z7DZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CFBA74016D
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jun 2023 18:40:27 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1b02751458asf19300fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jun 2023 09:40:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687884025; cv=pass;
        d=google.com; s=arc-20160816;
        b=wguHfSjfSLuL3Onxb65qb/mOEuEMmSBWwoDZMTS6q4d4rlb4n0fxobW4CAivpCKjy4
         b+LGpaShLNX+Wg4WlEugKcuzXUNwNXxnNXsVDdg9dwB227p4QTWvihtcRxq4pMjCVGMd
         UcXBZrSPni3wyj6qyZj0PtPz+7uu0Eayhbn6vBbpm27PYq50Okke7qt8T+u0e7g6OK/s
         mmpAWietW9oYLhuF0oILnloHhs+PMz5/9olFVzaijZoilCdCo4e997qSKvXFqW6+ybvB
         ghMH45PGzSNdLeKhUttVwU/ftw/ehCfQJAtwFl05dzznF1GovegSxoRhuIrqD79Dpos2
         Lcog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=oReQ0XU9hJu4/mXIJftoCAypbrN2aviS7dMlZpaypy0=;
        b=M70m5xNrk7of/p3hICKufBTI2zlVe42pS2f0gZik0cwL245wE7s0vk3OtCFpUlke+X
         /imjaladksgbiDAmxX9kMPpIUaV0pzxJE7+z6ZZeUFyMW7tp7K/Ep9N2rpvTDiLWrvcK
         Am4ygolQELE0ksKbVXaeu60XGZn79AESN+TB1H+SkRjhlEoZHaRdP/iFlPruJILeBw/3
         YlXjv+LJtoC5zTB9xd4clxjW1Wsa9d6vAZZ0Hz9A7X9IjUXIWo8p+Wqc0tFwdlRlIMdh
         zhxr6wb9F/4eoOxj9KaAbIEBAS9XoPtvGaiopS9rkQoeEUKildP/+tW6SrY9caRhktnd
         pw7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XGRGiORn;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687884025; x=1690476025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oReQ0XU9hJu4/mXIJftoCAypbrN2aviS7dMlZpaypy0=;
        b=jzqCrJv+We7nxaz5t9g11nFyPK2NwRYyFkvOlga/NIZyAx4Fxmz9+cdWJohAbyvCKB
         krf2Q8iRay9I+4yS24iMZhL/fQgrn6FybJOPkotYoyP9OdE1Zf/5uGE4tGGwVYXUiRT6
         vU8kzAb5x+CzGh0af8s3Fzi460RaUvoAI+oDydRBqabVFOt1P5T1QVAgTcPWavKryAvy
         wnZo3R6UJIw2KdC0B4yUvp8i0hACslXpNDFTUV6yZhScbYfjASTkExpG24E/61r1HmWo
         i0ZLH5iNuRNzAewSNGRfKubY9zga4ktVnnX+XEZOCS5Z3x9ysDrOI42xjBy6RhUDGAeU
         fZxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687884025; x=1690476025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oReQ0XU9hJu4/mXIJftoCAypbrN2aviS7dMlZpaypy0=;
        b=JUACfczxJXYgagLLYS9uZl0qPpLkRCM/AUZ7sTwrNHWd6B3nRMFGioBVZBBDayHsaw
         74K82fwxlaEpwAyyoa5U+SA+zlCyu0KAPFS4PvcYe81wiLsjdF05X5txZiPrzrApf8aT
         AfkUteLTohi+c31gQ/oZsP3EW+iHdwDnbsNvxYEoXZ8GDsgzGh8h0+7iXPqXZvewcRZV
         lker4zLd00FGyyafSY3op1XDAtb7cHtpVBiwp6HcfpcAAJvF5CCqX2MYqupsEU5A8nAU
         4rYGwPUQr7AJ6QFj3fG4JXK3g4FNMUEtxksgjcKiqoN7+CJrnVm9et4f9m4G9ooYZRhu
         HtTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyYq2GGmK6X8Yp1kES4wv6VjpydDAzKF8ROn7fzkGbP52j2aWvP
	aojApIQ33L5ahtYVuLnQZSU=
X-Google-Smtp-Source: ACHHUZ4MibYksOM7pGPrLeitJX+RzipgRo1TCg/A70cCaQQDDaEK1IT0T5Aw96G+LRD+wF5DCUdVoA==
X-Received: by 2002:a05:6870:9565:b0:1b0:166f:dc66 with SMTP id v37-20020a056870956500b001b0166fdc66mr5631814oal.22.1687884025595;
        Tue, 27 Jun 2023 09:40:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f70e:b0:1aa:1314:488f with SMTP id
 ej14-20020a056870f70e00b001aa1314488fls836388oab.0.-pod-prod-00-us; Tue, 27
 Jun 2023 09:40:25 -0700 (PDT)
X-Received: by 2002:a05:6870:9106:b0:1b0:1dcb:e706 with SMTP id o6-20020a056870910600b001b01dcbe706mr4642326oae.26.1687884025172;
        Tue, 27 Jun 2023 09:40:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687884025; cv=none;
        d=google.com; s=arc-20160816;
        b=TKOSURNgdW20ML86iaFxvHKrBHLF2aoMgU0LRqm16+/uH+210GFk+nlQ/fmARvtJ0k
         4l5ZeyoFh+jmHMCOy5WizVnroJJLHnFBfFY/jlkbMGt7BjgC0xVLyGe7dOlHs2jPqHZi
         wnWrKCAo77/gBsvUTPCIUwrTvCOpjeUoFLB0RDL4hphKvzIQosi1ZxYqOGk+OSxOAoUr
         pKRvS+F+Ya36ES1/YBwskCkZoabJgRwbSzgUjRDk0OMnr70Pbwh9b9qDD7QXR2Lyh4f7
         IIw8ESwGhhM3Sq4H4JffOpKEYOfULuB8dI2igbTDJBEM8me8QOVLFQavT6jM4NdwSF7k
         8w5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=ZmpvG54YyN2RV5qgts0ahvI0sx/D9QE15f2q2zTG7d4=;
        fh=bXTV400VIlhis8ER1uHZgXneWL8fPwBhBFvqvoIZR98=;
        b=1JHyHFhC7BQSxZAjF+ErVaPGV2XJEDgF8dBDXAgz2GDW7ArQXmZoY+D9CIq68topOp
         g9sPs8LtaZGWbs7iW2pcZGBxF0uGpx7DX8tveQFI9QW3Z6bJJG9Xluz98q7rZ2EJD3rM
         yyliLvFG3yb3edTK6eG+Bj00gzN9ytKA8ucxcWWA8rQr1imeGbrWIBH/eS+JIWpaLjlV
         zD7PlOJe8t/VhrdYNpUsosaMscQRHvK/IArJspSPGBpxPRaW/b7HDI+Jg3b4NwuceDXj
         YFV6+6rneBKzLuRoyCtgbVRNm8avOqgTk2XkiMD5WBlZ14ebEtuPIyqSqWIIONXrYIC+
         GqNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XGRGiORn;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bx12-20020a056830600c00b006b45ec3498esi719814otb.4.2023.06.27.09.40.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jun 2023 09:40:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BC0CE611F2;
	Tue, 27 Jun 2023 16:40:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 9D8F0C433C9;
	Tue, 27 Jun 2023 16:40:23 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 7B046C64458;
	Tue, 27 Jun 2023 16:40:23 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v2 00/24] use vmalloc_array and vcalloc
From: patchwork-bot+netdevbpf@kernel.org
Message-Id: <168788402349.21860.17350888958370358926.git-patchwork-notify@kernel.org>
Date: Tue, 27 Jun 2023 16:40:23 +0000
References: <20230627144339.144478-1-Julia.Lawall@inria.fr>
In-Reply-To: <20230627144339.144478-1-Julia.Lawall@inria.fr>
To: Julia Lawall <julia.lawall@inria.fr>
Cc: linux-hyperv@vger.kernel.org, kernel-janitors@vger.kernel.org,
 keescook@chromium.org, christophe.jaillet@wanadoo.fr, kuba@kernel.org,
 kasan-dev@googlegroups.com, andreyknvl@gmail.com, dvyukov@google.com,
 iommu@lists.linux.dev, linux-tegra@vger.kernel.org, robin.murphy@arm.com,
 vdumpa@nvidia.com, virtualization@lists.linux-foundation.org,
 xuanzhuo@linux.alibaba.com, linux-scsi@vger.kernel.org,
 linaro-mm-sig@lists.linaro.org, linux-media@vger.kernel.org,
 jstultz@google.com, Brian.Starkey@arm.com, labbott@redhat.com,
 lmark@codeaurora.org, benjamin.gaignard@collabora.com,
 dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org,
 netdev@vger.kernel.org, shailend@google.com, linux-rdma@vger.kernel.org,
 mhi@lists.linux.dev, linux-arm-msm@vger.kernel.org,
 linux-btrfs@vger.kernel.org, intel-gvt-dev@lists.freedesktop.org,
 intel-gfx@lists.freedesktop.org, dave.hansen@linux.intel.com, hpa@zytor.com,
 linux-sgx@vger.kernel.org
X-Original-Sender: patchwork-bot+netdevbpf@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XGRGiORn;       spf=pass
 (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello:

This series was applied to netdev/net-next.git (main)
by Jakub Kicinski <kuba@kernel.org>:

On Tue, 27 Jun 2023 16:43:15 +0200 you wrote:
> The functions vmalloc_array and vcalloc were introduced in
> 
> commit a8749a35c399 ("mm: vmalloc: introduce array allocation functions")
> 
> but are not used much yet.  This series introduces uses of
> these functions, to protect against multiplication overflows.
> 
> [...]

Here is the summary with links:
  - [v2,02/24] octeon_ep: use vmalloc_array and vcalloc
    https://git.kernel.org/netdev/net-next/c/32d462a5c3e5
  - [v2,04/24] gve: use vmalloc_array and vcalloc
    https://git.kernel.org/netdev/net-next/c/a13de901e8d5
  - [v2,09/24] pds_core: use vmalloc_array and vcalloc
    https://git.kernel.org/netdev/net-next/c/906a76cc7645
  - [v2,11/24] ionic: use vmalloc_array and vcalloc
    https://git.kernel.org/netdev/net-next/c/f712c8297e0a
  - [v2,18/24] net: enetc: use vmalloc_array and vcalloc
    https://git.kernel.org/netdev/net-next/c/fa87c54693ae
  - [v2,22/24] net: mana: use vmalloc_array and vcalloc
    https://git.kernel.org/netdev/net-next/c/e9c74f8b8a31

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168788402349.21860.17350888958370358926.git-patchwork-notify%40kernel.org.
