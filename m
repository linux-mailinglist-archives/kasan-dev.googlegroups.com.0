Return-Path: <kasan-dev+bncBCT4XGV33UIBBFMGTSVQMGQEEJRDDZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 625BF7FD25F
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:23:34 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-421a7c49567sf171991cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:23:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701249813; cv=pass;
        d=google.com; s=arc-20160816;
        b=R9SqXb7qbKZSVXwSNBMY5WWQ79iakOKluMswKJM/VGYnR2MCFDjsnSE5YUVT/wfS1S
         cD4DP7Ddjiqht30yqjSOHKokKJZ/250NA/SGXUSzqbGkMIlp20TRotzmRzEDIN9NTUZv
         VwFsKG3rdggag9NQ6zG4axH/vKqYOO5Lp9FiQo8Tb2Gw5/25tXRmtqYc6t+sGHUJKbNQ
         PQ9tCiCZq1uZDu1CLwyU1Gg4tk0lfsqoSI2dKNJoEYxPS1P4LZUR0r4vB1LhTmqDW8J6
         HSSx/C1Fu/HhPXh/o+mlGPiaX6/+mS0CUuXeuFOLOVDOd8BEWJ40/QjWrcjkPlAgX6OZ
         DC5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=tHIAp36X/WYtl16RKqPTQTSYJw84xMfnSUMhS3TUmS8=;
        fh=sTYBHJN5GmqANGuMsiwPiRM0p4FWsDmmxhFaF8zsscc=;
        b=RWZCzzhcpVwAXk4qtRtS3vcOJoIeY2L31X5Njz33rsUki2UrpqnW8s1HIGGrwLyZkM
         Ib3RtWlMjgH1v0BNVUDUrnCbnNeheXrul3wXAoaEzhfxqheA1KS2UWhkccCzyEJ92+A6
         eMaJSUXeqtnWH+n2ZQYc2c3PV2ltm3TzHmSn0K4KL58L7KKH/OtafWAPSK2LpXin/keb
         ByR4D2bfcZStUJDcC9zZqFNKFAISyISIHn2YgR9t75zQzoSejjMTUN2kbKHRyD/RH8NW
         zp3/Jim0vH0fup1L52ZXo9BJpMAWO3aa5rcXSi+z8xkJIpyAk0Tl3KKEBPCTOr+8O/Kg
         rTRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=HTEloEWx;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701249813; x=1701854613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tHIAp36X/WYtl16RKqPTQTSYJw84xMfnSUMhS3TUmS8=;
        b=nOKd6W31oqqOL3wb4SFvCf0eWMQvb14my9zSUjQMyCwlCSflQUxt2wNlFKg4tnG45R
         CflBouSTGLSblCiUlNtXRO+vrycasGAjTZhQOBmxP1SshM+AUrgBDq1vRL7owimEDG+y
         l+i0vOIMvtUD47jsB40Bgi+8eo3FaI9P38x6+OeqIrqwFJpEoL54LspTrn3OfdK7ZQTu
         nRim9tmNsw8wtq8eKGXbPxusaIk4kYKsxZe6TEsGNwupRCjsc5ollLtV5D9QdActlWcx
         GejkUl3c/xJLsgDNyPCMWoGWaN2tx+nla0mtRamUbfkiS0PXxLetW86atfOLYrCgN+RT
         OeEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701249813; x=1701854613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=tHIAp36X/WYtl16RKqPTQTSYJw84xMfnSUMhS3TUmS8=;
        b=QNRf60MSLndmmfFWFTWtJ8tWZxUJLCjsGtTIxDPGViCNLoximLL/aagcJVme/tdhDR
         zVXCSsTjcFcREFoRzl1oGvvcyKaBo62kmWN+AzAwQItk8KFPWVqfzAKrZJmc/jADb/9I
         M/9QQD1vNpdpzE+sHLtwF5ZoVCThRZKUtQYS7/7H7Titqqz6/BpzP5+FX+WK6hslt5WU
         85xowh1GNRs2M03HZ1CjUwr4kyRcReWuwVKzYWAoeX7UDRfcLpOXqa59EQbPwURR9upA
         HOTChkVpnpu9yUdYjuKqLPw7Ak7upzJw5bMYKH8D/LXEgTMgq19a2AMZ4RvEZxVyhWUx
         uFMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz3yJok0Q4OCfcT1vQoAwsPiBo9crAHZo7NfbEY/nuJaRhAldFr
	yoeHiLtWyJ4s2n21KF/2VYM=
X-Google-Smtp-Source: AGHT+IE60XC+tKF06JgPS50tPxj2y8US73ertnQlOGL0X7wJth2So54t0e0vy7DGMB3kImmupTueRg==
X-Received: by 2002:ac8:5992:0:b0:41c:da14:f9bd with SMTP id e18-20020ac85992000000b0041cda14f9bdmr1467512qte.15.1701249813193;
        Wed, 29 Nov 2023 01:23:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5dce:0:b0:423:8c6b:503a with SMTP id e14-20020ac85dce000000b004238c6b503als1843905qtx.1.-pod-prod-07-us;
 Wed, 29 Nov 2023 01:23:32 -0800 (PST)
X-Received: by 2002:a05:620a:a94:b0:76c:8fe1:604 with SMTP id v20-20020a05620a0a9400b0076c8fe10604mr479065qkg.13.1701249812716;
        Wed, 29 Nov 2023 01:23:32 -0800 (PST)
Received: by 2002:a05:620a:460f:b0:77d:9a82:fb38 with SMTP id af79cd13be357-77d9a8303b7ms85a;
        Tue, 28 Nov 2023 17:22:43 -0800 (PST)
X-Received: by 2002:a05:6000:1805:b0:332:f910:50db with SMTP id m5-20020a056000180500b00332f91050dbmr8847690wrh.14.1701220960894;
        Tue, 28 Nov 2023 17:22:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701220960; cv=none;
        d=google.com; s=arc-20160816;
        b=h9gMXwmqVoHXVlGLZnNJE0eRDWzc7Y1dMg4vPrEW/TOu6lMm3BjMZOlFCR6/EWheNy
         bPUcZYSPIftBXc1sG7U3yMsfREQvynxJ/ovpT1/UBlGbAiybpW5fanCjzgB+G2nJWZn8
         H/wi/k3DKQG64Kq4Az8HleDZo+fSV5XSjEbqJF/O174tUpjwbtRBIaXz/ZAS+xnr5KXp
         HdHiuxQg+7hy/Wy0uDnYj32zIoqSbyF4ijjwLzp3btVAQIjGO7tITCdnVC/lbFn4L+1r
         kehGFy/c3bhM7AhLgM8N7m+a26lp9tpKZ0ScQfkjnXyZBc8FHMVRGafRodwGiyhgLcM3
         Pe/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tpFoDWxzhly8vBWsBuFUUlmjaSBQExvhtIJrmrRoKEE=;
        fh=sTYBHJN5GmqANGuMsiwPiRM0p4FWsDmmxhFaF8zsscc=;
        b=cOFDxKgfqzVdNylsYZanwsmSwUvNxe8e5IB4Uov09O583aWaVH+zqDoaj61ms/Lgkg
         sKS/YCLoJ43ATijS416Tg/WkldXfT57Y5Ue2FhX24gqbyePmnsyb+g1O6g+bNS4q7P/i
         GYWf/EkqHSm1ECvVF7BgY0l+e4twmlV4gbEkkOF3RGYc1Jdxc1+QR6FkHWGAexGijiwX
         v+WjkEmaufP6zO8V9pVP+2L5SQH/MK9BLRiCuVpLVAXroLXwKJjFGnqHqgpscMSOW3kV
         bdNApbkXsijJRN+p846TULcgtLs22pOd0ho1qnqCe7OG4jx7ifY1Spg/iE0be5mevvH6
         izng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=HTEloEWx;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id d24-20020adf9b98000000b00332c094fc56si1078370wrc.5.2023.11.28.17.22.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Nov 2023 17:22:40 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 7B95FB835E0;
	Wed, 29 Nov 2023 01:22:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 67609C433C8;
	Wed, 29 Nov 2023 01:22:39 +0000 (UTC)
Date: Tue, 28 Nov 2023 17:22:38 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Haibo Li <haibo.li@mediatek.com>
Cc: <linux-kernel@vger.kernel.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, AngeloGioacchino Del Regno
 <angelogioacchino.delregno@collabora.com>, <kasan-dev@googlegroups.com>,
 <linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
 <linux-mediatek@lists.infradead.org>, <xiaoming.yu@mediatek.com>, kernel
 test robot <lkp@intel.com>
Subject: Re: [PATCH] fix comparison of unsigned expression < 0
Message-Id: <20231128172238.f80ed8dd74ab2a13eba33091@linux-foundation.org>
In-Reply-To: <20231128075532.110251-1-haibo.li@mediatek.com>
References: <20231128075532.110251-1-haibo.li@mediatek.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=HTEloEWx;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, 28 Nov 2023 15:55:32 +0800 Haibo Li <haibo.li@mediatek.com> wrote:

> Kernel test robot reported:
> 
> '''
> mm/kasan/report.c:637 kasan_non_canonical_hook() warn:
> unsigned 'addr' is never less than zero.
> '''
> The KASAN_SHADOW_OFFSET is 0 on loongarch64.
> 
> To fix it,check the KASAN_SHADOW_OFFSET before do comparison.
> 
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -634,10 +634,10 @@ void kasan_non_canonical_hook(unsigned long addr)
>  {
>  	unsigned long orig_addr;
>  	const char *bug_type;
> -
> +#if KASAN_SHADOW_OFFSET > 0
>  	if (addr < KASAN_SHADOW_OFFSET)
>  		return;
> -
> +#endif

We'd rather not add ugly ifdefs for a simple test like this.  If we
replace "<" with "<=", does it fix?  I suspect that's wrong.

But really, some hardwired comparison with an absolute address seems
lazy.  If KASAN_SHADOW_OFFSET is variable on a per-architecture basis
then the expression which checks the validity of an arbitrary address
should also be per-architecture.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231128172238.f80ed8dd74ab2a13eba33091%40linux-foundation.org.
