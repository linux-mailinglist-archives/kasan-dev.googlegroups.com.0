Return-Path: <kasan-dev+bncBDDL3KWR4EBRB56UX2BAMGQEWHZALSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC9E633C5E9
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 19:42:00 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id u188sf18774488pfu.23
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 11:42:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615833719; cv=pass;
        d=google.com; s=arc-20160816;
        b=uNa5mxRE+sJW1wy2lem7DN2tO99Tr9zlB7SZPPdSuxDYP3zaj5g6UJJIrAZW9H22vf
         QqSpc2KgTE5pFKWdQZBY3qZpi3NiZCCAWFS5CvBYR+Apk0/8BYkfQ7l5HiCa5imUifLX
         yjl1xkk7TDQNx69leGvxceePod99/JkQckCh9wjceVQ1WoKvq0pIXpXonslYC9of0IZY
         SqC44cLNZ39Licb6dA3z3M+nPfadLzFx0MShkm57o4Rphy7F83vuv6sYv+scL9GEiTxD
         sPl4YlKm2dY/IvUAhl/AcotxnEK8iLGEgK7+m+cWSDjYATuHm4Xo1wWHnxbj21KKQZZ7
         S3dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nY5WW151mkY1qHvGS3DATUBS6MN+JoaJ0/sWOByC7yg=;
        b=AhaptDxk1hk/pNUBcRXhqpdsUtV6Mp+K9Pzn1u/yMnpRcQiOoC5xWWj01Czso0lLW7
         CQqjaD85YOaLI5qvSHp5SA4EoO3sz9PDcdccyPqsx6ZDkuaLTxQw2iWN/TOHudn77Qpb
         hUlxTRKAfDpx8ucY/nSWGAEXhSvhPEWglnULkfvN/m698XRQQQQf2b8qPSnAuu/mlDsQ
         fQPfHmcxg7WZtRewmJ1J8KLUh5hIBDDy4A3PAhAYXWZ5qDHBb6XuQwRJzSWMKjPEGkCj
         EnLMh6H1dNFprGqX3eMQteT50S5NlP67yBeLlshBzGCdQDiMeK1vK72og4QBn4km9LZQ
         AcXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nY5WW151mkY1qHvGS3DATUBS6MN+JoaJ0/sWOByC7yg=;
        b=tnuZ1Y4BX+KudUOlvOO67rfiNR6mElT3tM3/EVRyDLJ660PVepQIqwDViOWINLCyj5
         yzlhB4n7gMzwUJ5J60Q0ZfYjyOcpJHDc7iaEkYTonNqABM1LkS6IfOHOVSOy1/kt7UPr
         LBOOaPbD0BH18VYQny6Q4SxoJ5ZlD0t5TwQSjhbh+rx0IZiU50EcKiSI04ENA7/MkHjp
         DrwExkbx++x8NtJJBv1YqaD5Wei+5iqU0fOgPURHDgy3c5L71wKCdaiQ1ZgCF9F45Be1
         eYIkZyDK9xAaVcfbMCl1/yLOi/oh5QDBOl0fXYtmz8zvJgst+l01gBbghVyCCkeD68cS
         gWeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nY5WW151mkY1qHvGS3DATUBS6MN+JoaJ0/sWOByC7yg=;
        b=er3D9bHbfIPwOsfwdvAFvGHAEuiwpKfScbDMURD8Sl/LosGsivllOYbXhhNFTAFbvb
         VIebwYo6mHC0vGHVuCtKmFlrm0PsR6zyQ9/3wQSEM6H16s1JBthKCxvNG+r0Tqu5oEds
         Jg+D6OAo/sLuBqqMILVS3/JEbVkSn7M24spZkG4Ek8mszNiHNPjqnE0eNrGN8+3nvKDA
         vsy11T9i4lNdFS73dxGNHFPUPs4QJqMAoUHjtysYPekMtmJzCVAERcWW2zIs9S9LYpSB
         4cRRh+7ckXnbHqcONC/Vei4kZ8QF+/2+lhrhOuSm4sPAv1C+DP4zYH5qMzb3DwwOipkm
         5/1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PZV0PA+ed1kGzWBoTj9qCu1cLNP8pBHO0UX2on+wszE+t81e/
	yti94fpHwsMV4oGsAjl+E9w=
X-Google-Smtp-Source: ABdhPJwNlap82bkfy4PMxICaY85YRIZU85D5FqaNxCDW/CbOgnpMb2oYr3pVtHa06F3rBYUKWCsoBA==
X-Received: by 2002:a17:902:d341:b029:e6:9a9f:5614 with SMTP id l1-20020a170902d341b02900e69a9f5614mr12419085plk.48.1615833719495;
        Mon, 15 Mar 2021 11:41:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls6522219pgu.6.gmail; Mon, 15 Mar
 2021 11:41:59 -0700 (PDT)
X-Received: by 2002:a63:515a:: with SMTP id r26mr419910pgl.257.1615833718923;
        Mon, 15 Mar 2021 11:41:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615833718; cv=none;
        d=google.com; s=arc-20160816;
        b=0QsAGhwWP/UN8NQzujinXKgW+AXtOAzzD4pcnqiPdNxp09UbHn5UMWImbfkXtUxqwS
         vOv+Cb3apF0RoVP5A9uYkBPlge5g7a0oh4QEac3ctwn36w6/qEGhOsIENuUuN3uSe+aL
         iw9KPL1EdLtRQ5Af2bzsQe9L/AQ3M16Khcq8XQJ32c1x/uCkv0xySIhMQFCuZygt840E
         gZGrSkAZlEQf8EvDdYhPV/uY2wj44pnUGGFZye3a5/4OCRvKBcmM3K133y2/u4PJI1DB
         WFa4O88qWGzTftnsQxGQZGiG9yGSPf+5u0Ny5Dj6mi0RwKMZFarg4SJatMgvJW5pFlkl
         MPcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=UKdVLMHsyYPp1zy05XlPglC4+G+wuoRYIcRwhtHGogA=;
        b=N3w5pH7avH56/11KrHyA/H8Q/aXM/GctR3JSW1iZp0gTqmLWyGX7l10IYOCwGDhlvw
         0TDPbm6imQ3zlCSwK4dABM4xsU3UNQR74H2tQnMu/ETwKly5jvx1R8mi1EnULpI+HvPh
         mig2i6MDdj5TR2BzSvvOObezgTnflFdszVfnJLoG3i8RiX5lp3L/D40hAEr51jrhYdxp
         aEpGalxZqGkW8UtjEmwkFra/X1csH8xFO2YzTfLkn9yXieg0vcaQigUt630JyKmixmCV
         P+yejUuv0t0qxieRex8i9P+bEudeQQ8AT31soez20T7IupGU60nG36evEacqtSlhvvqP
         yapg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y11si975808pju.3.2021.03.15.11.41.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Mar 2021 11:41:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6E9DA601FE;
	Mon, 15 Mar 2021 18:41:56 +0000 (UTC)
Date: Mon, 15 Mar 2021 18:41:53 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v16 6/9] arm64: mte: Conditionally compile
 mte_enable_kernel_*()
Message-ID: <20210315184152.GC22897@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
 <20210315132019.33202-7-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210315132019.33202-7-vincenzo.frascino@arm.com>
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

On Mon, Mar 15, 2021 at 01:20:16PM +0000, Vincenzo Frascino wrote:
> mte_enable_kernel_*() are not needed if KASAN_HW is disabled.
> 
> Add ash defines around the functions to conditionally compile the
> functions.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

(BTW, Andrey now has a different email address; use the one in the
MAINTAINERS file)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315184152.GC22897%40arm.com.
