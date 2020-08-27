Return-Path: <kasan-dev+bncBDDL3KWR4EBRBGMJT35AKGQEATE6SWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F233254307
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:02:03 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id y7sf3779524ilm.11
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:02:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598522522; cv=pass;
        d=google.com; s=arc-20160816;
        b=QF0ZaDzNv0zEw1KkTudYG5aIzQnjFsnSl6E4iPAMOhcyJdq9tLWXSDzz8M48aCLRE+
         3mtcFc+QEy3cVOViMlEOCRVsyZ5dfedM+X5q7UHzwvp/ucnhhFARrCSXX4AXMD1oHkoX
         GORaC2rzEWMHo2/UPma9kpR+1tnYQ6Z92jIP3AQhwG2KO68YPdj9K0b3c1M9G+xRQvEI
         Ucmz0QH2HpQa1zeWMEPj/jVV99bZMyNHWLEtuJIY77W3zYRhvJkRIF7+lK6Q2GKOPO+G
         GvMIICYuChUq6dw9ujSbHaF4LBy4T+jIqoPzL+cFkP4mNBEwBUXkcn3jU6lCTZ1dQNqW
         imrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6+eAQ7W6yJoyjpl2l3mwuQ371lemqwspAEmhNDlP33g=;
        b=Ay6qIkAJqvOW5B/Xuw3AtOlj7qOuH3QqxzCip0i0G2hb3z4cemztohrmW25E7tvzaM
         YdJa2R0yITG6wTSyltEjhUeGPSGgqQo4lVsj2kq4rPE38xazx2J3Vh+nbPUZZnA01lEN
         0VxqZJQ1SeS2BFByigd2FEkYMFVnppfqjOeGs/uSDrzmfSE3aA89QlAnnW06MdDsph9p
         6bRB85LN6tOTp/jCNnmARzdw1FubnPaa2QwgNsf+enaRvKbDyJPJ5/vy+1SXCTebwnEB
         ZCNuLvLOLvbySGM3j/NXeNprLw/VIMEV+ccXBi7TKMyH2mB+71RGhBoiNOJETdjP/rJO
         +hLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6+eAQ7W6yJoyjpl2l3mwuQ371lemqwspAEmhNDlP33g=;
        b=sGW1VXA15WT//AcOhL8ioflFBB9sbpY9HZzxDeI+0QfvhCcI4lSgEoTWtnA7BJe+OT
         MyRbTQv74Rqf908NXat8mWSmNsjy6fBMx5HIX+mCQ56uE5IEpxLb4u7PDeCrvjv9zkTW
         fDlJW57JHAbH3YEjBZzqLSwqj7tQuX99IY/ZUoOTr7dBMpvI1QbG01ZEFfXOoSofUe4z
         x4Id6QZlybnuZZnwKloK6N5xHw/nHemU350WPdCIVxN2dNQmFskkgN6eEbJG35WwtJrt
         kNyKkO+e28vDGgWWlIoigP/bPibcxmgmJSu4DJd/yW4vkpfwgrKhCdjM+atUbjmOW7z8
         5o3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6+eAQ7W6yJoyjpl2l3mwuQ371lemqwspAEmhNDlP33g=;
        b=ev+ybrzkZnwuIfRC4KSUR+34iI/axGhjjl3Txkl6cSK1ai0Vu/yoH40JN7GMRQoeNS
         Vbp2E0obzepdnOahlig2hCRqFNV9mlBpnecaQeDyU9uy4U9EtLDp4RkG7A2AKSbCxy8D
         mCdmaitaH+1zA+mOPLBnXaoWJ4fa3/TTDu/GV1OBTw3BWdrKZfGbqH04cd/+XN9l28rC
         aijq4ydRXPS+B+QCXWJ//gNIIRQaZIXSBwD+puhiQB/nmCWCDdQSuJK5UULbHWbq9Zy2
         af7/dZb1adpPjcDGGUS3idb+qWRbhkI1K76HvYTXcTGg5r4RD33tQew5I1dOgbmv6hzW
         BYCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jxQ8DE7CgcYCc2UONuCYYlfzoq9+q1wxx4wbu7hzANBHONFY+
	i8umy9vt1MHIKzfIxyH7g8s=
X-Google-Smtp-Source: ABdhPJx9od6/Une6pNE2K2y3tHBG+taF2NhNdBQrB2g84zCZ2mraZwQ4yk13VKaVYwbV+zpDqngimw==
X-Received: by 2002:a05:6e02:1387:: with SMTP id d7mr15693867ilo.182.1598522522115;
        Thu, 27 Aug 2020 03:02:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:22cb:: with SMTP id j11ls255366jat.8.gmail; Thu, 27
 Aug 2020 03:02:01 -0700 (PDT)
X-Received: by 2002:a02:454:: with SMTP id 81mr19398678jab.142.1598522521650;
        Thu, 27 Aug 2020 03:02:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598522521; cv=none;
        d=google.com; s=arc-20160816;
        b=h3wJUm9OwYd/eZ8VPLwN5+JBpFF5dQm1XMqsrMMa3IGw8sJBuPa05ONmeTSnxZUJ4p
         p92elwrmzyJdHM09sbhyfZAM0wDJtHYJsU6qrfhOQh8VRDpTsiFw43g2noVqfiv0NcBb
         LaOHBDv8ko6y0R4cfbhlFJyajYNqibINzdDQANeOl6Kdq1ZKWGqd0YmXkbVV3NH8UJpD
         o8/RFxR1oE3UoUSYBjtROquuBIbVYUB2xQ1K+p9HAHkHRsKr2KFM8b3lZrkKdZvH/H5d
         FVQBBbIZVlM63BRYCPnoN82nlGRRwfD3oTSwJ/euaT2/BLsyzxyePpgg/YCq2ptFXYwQ
         RzRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=HGoopylQ//x3ghdSb8zGEUU2QuyAa6AsFLxOkvFGOVQ=;
        b=beAqoTKNo5RIL5deZBkRd+o3M6/ndZMIgvn6Cv9tCIcFX5eBR+PJOuiCMSVruw/GkK
         ly/MVntBw7aT3XO1c53IVVISsybJgabL5wA7B2ATaZ/YRjggSHdqoOu95FF+JqpHMd6T
         aKbv7UV0Mcpud67l2PXuaOARmG2Or5gI0K3npmVmtKlITDxnPqNuWvelUiP2Zoyy7Ch5
         IGniq/Tr8+cZahtu6fN8rGVhrhzbL6Xsgii5brjo3v/BZX3BaKlJOtGQkk152OnnaFJa
         BplyQaXQvgQqpuo3rz5thTzZZeK+LaeS0BfrvZIMDB/5KRT3aXBym7SH6Q8MflD3QWPH
         ggDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j9si96220iow.3.2020.08.27.03.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 03:02:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 71C892075B;
	Thu, 27 Aug 2020 10:01:58 +0000 (UTC)
Date: Thu, 27 Aug 2020 11:01:56 +0100
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
Subject: Re: [PATCH 22/35] arm64: mte: Enable in-kernel MTE
Message-ID: <20200827100155.GD29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Aug 14, 2020 at 07:27:04PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index 4d3abb51f7d4..4d94af19d8f6 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -1670,6 +1670,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>  	write_sysreg_s(0, SYS_TFSR_EL1);
>  	write_sysreg_s(0, SYS_TFSRE0_EL1);
>  
> +	/* Enable Match-All at EL1 */
> +	sysreg_clear_set(tcr_el1, 0, SYS_TCR_EL1_TCMA1);
> +
>  	/*
>  	 * CnP must be enabled only after the MAIR_EL1 register has been set
>  	 * up. Inconsistent MAIR_EL1 between CPUs sharing the same TLB may
> @@ -1687,6 +1690,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>  	mair &= ~MAIR_ATTRIDX(MAIR_ATTR_MASK, MT_NORMAL_TAGGED);
>  	mair |= MAIR_ATTRIDX(MAIR_ATTR_NORMAL_TAGGED, MT_NORMAL_TAGGED);
>  	write_sysreg_s(mair, SYS_MAIR_EL1);
> +
> +	/* Enable MTE Sync Mode for EL1 */
> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);

In the 8th incarnation of the user MTE patches, this initialisation
moved to proc.S before the MMU is initialised. When rebasing, please
take this into account.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827100155.GD29264%40gaia.
