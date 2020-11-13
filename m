Return-Path: <kasan-dev+bncBCT4XGV33UIBBWFQXT6QKGQERNQRJUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A3BA02B293B
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Nov 2020 00:35:53 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id w79sf7733446pfc.14
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 15:35:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605310552; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThrzV9HTFTfvKt6JyWtd2+t1jzcMlf+XdPMd1gn2f8fSl0SE3y2qhbYjDpm5DmnhDS
         atbqPxAg4M4zQK/p9XrQx6F7N7otUad/HFvquhbhRWfZ2bKXzgntMbrL52PLLIMjLHey
         cfo8s17LfxcnvKe3T9X5vPmtwi+sQGSn/IdklsmigqgHZ+ENGBBMAFB/R0MjTGG1SPdL
         Uyzrj1RSuCuKY7ls21m5ksLmkUSnKrYTOqLC/r7Bp6soP8zqTTt6TaA68h9yIKE9FdDT
         hrAjXEA59jWxoeFyvRgNGtkNNs+YO1xjxcQkOKfTxj221QrCtPWuhzyBHivuhCEGIPqi
         DzBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=aknvNg/W+2WIBeIRCkXJPC8s9itOZRHiD8aZTR0WnhM=;
        b=DSs3NRujwzPHFXphcGWsH1rW7Ja/+Y9txj8Eq9T2Q8HuNOa2Z3LhuGUdzLFEh/cjMX
         cXxN3ppih5GfKurcQD9yKZ+nWFI8eoM3UOJe9HQxOlAJ2MEkX3I4xasvV31o6TpV0SZJ
         9rpfKMaF9XmM7QFwnhOY068doM30ZI7km0u28ipKRIoAUYID53UlFuwU4w99r8/GuHff
         8HbgwBw5yhj9AaL8HfBJWIpE1KaP+uICHPu1sYn3F4La6c+Zo20hbGcMz5KF+SvvTd2p
         ZQurfS+RgIBlAqsFqSZrzFV9NSYvJYmA7N025oq0tk0CLl6RbELhXpAEQDnqsVONIpVG
         6EbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=NReDqobe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aknvNg/W+2WIBeIRCkXJPC8s9itOZRHiD8aZTR0WnhM=;
        b=SaCx2/PQ+HsRG0sbI4fYGZ9H2/JrgPGIRlNIm8aldnpnkKq+QtyC553xI+uZmEgr7c
         lmAdNq0zcfgLIZzo4X3PUcf536alaDBDhM5WnFRO2hMXiU0BwEOciBiqsF06xwjP2YOY
         hnuLYPp1AeVePver0QRdPKPeYiBm019V7nu0RVdnniK+IGxj+b0mO3jugF9zGu5Cri8p
         imJJJBq5Icx06+ZP5Jm+0Fpdxkr/03Y4INPIeTxxCHr6TEk9CiHOxK8h7D40UK692WCt
         4K9eonOll5A4OBihdpWLEEV2gbOgOb19yXjA9JfFCJrb6XWJtu8KZm2iSIWZivAfw/cd
         B6dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aknvNg/W+2WIBeIRCkXJPC8s9itOZRHiD8aZTR0WnhM=;
        b=QAisKG+0yk5umu3imWIRabVD9Z6m7ka4ECvWGt4wapcQ8A0lZI17hHpiQrZcdKL87m
         450pixzrGynKe6F89k2PqbGwhMz8ccbC9wCG1oKduXONdyg44PHgswfZtg4J+80Miiqo
         a7t4GT5jytkzLI96Omzq7Tiouy/fFjtXQW4amJ39KQoESUg1Vf6Hm8xhurddms16cSjc
         cH1xw0y7z/ZgZRaunNbu0lKiuhdaQTJ01SodQ/Wwwd2FUJKEAhE/xC4ZRw1PLpFcFXKR
         b398w/Y91uC8dGPiVdBoz6ae2ECQkjYPBnqQfd1L07zY+iv/CkYFgtn6YHFFLT9muggH
         QRgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DIjr2Gfsn1OnSJS8Xe01C7J1hrHjNuZ116FHbdOLwVmt5BSZt
	mIiKoOnAXLEboMlTf5OwiDQ=
X-Google-Smtp-Source: ABdhPJyqZJwdDYe/8RkPsi6CqOSSRBa45xZt4ckqntKPgJh0FT6kxH/UESI8oBqL/EY2YT5UT5ly1Q==
X-Received: by 2002:a05:6a00:91:b029:18c:abea:233e with SMTP id c17-20020a056a000091b029018cabea233emr3984859pfj.36.1605310552361;
        Fri, 13 Nov 2020 15:35:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8cc4:: with SMTP id m187ls2754177pfd.4.gmail; Fri, 13
 Nov 2020 15:35:51 -0800 (PST)
X-Received: by 2002:a63:4648:: with SMTP id v8mr3871486pgk.248.1605310551666;
        Fri, 13 Nov 2020 15:35:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605310551; cv=none;
        d=google.com; s=arc-20160816;
        b=C88IT0SglUF6Bj7zEuhaGyRR2XMHJVcpynCSbxWegdze8K4/he1VkUlLEuiSo/fS7E
         E77kj2uwUx/s+i8OQq0mmL198FJ7AgE/2OJ2vIx2/VMzDIoVMX958WLQcyHk4Ncgtv2l
         MN5pY7C9qxCXGjXoaYj8mX1jduIEgDPBZNfWfIRPIDV4k/l3vPZ2eWaHYr2mXmPJCW14
         m0X48TT4Osj3H0wJMijy/7LBVgQO60nZhxbub8tJ5mwWjie/tmU4JjvsrPNY1S0nmpTr
         1PpDTj/mn81Sze40jxyOeqrGN5qfATUJteGtFw3pfWnTheNa/XCzAvNs0JEX+W3x7l+6
         QNfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=76jQq4FI3qVf7YEugCZt2cZOHCCY1cZhTijQdf0pY3w=;
        b=qBz6Euq5ybMpYfdUGAyJ9lOj46DpDZzJM6hXTBcqBuWqLnvfVLQiR1lzfvntT3e2uB
         tezAn9ANdhrDAqSQBhRslAXiYtInUGAuH0IV54i2UmE5byEscB2Uj2w3t/7Dkyt/yyCb
         XN2lqwEpRpcRj00zasTEcbUGgtblGnWOTdyYI7DpX8It5hS7kU6Ixc/onJXQ3JCRl+BP
         OvVUb4V97gvnkPfCQcyAIhHQhPiowXNaIOLAKqeKNSZ+XBlF5NjjUQzGd6WBz2mSuHIE
         ZXWb+1dsBcE0ElR84R4MN+PSOtPieDQT7RnCXVKeHRIZG7L0kj7aaUkp5ihMn41VBXtW
         K+jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=NReDqobe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i5si1396263pjz.1.2020.11.13.15.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Nov 2020 15:35:51 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id AE40D22256;
	Fri, 13 Nov 2020 23:35:50 +0000 (UTC)
Date: Fri, 13 Nov 2020 15:35:50 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, Branislav
 Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v10 00/42] kasan: add hardware tag-based mode for
 arm64
Message-Id: <20201113153550.5ab0f21942ef7331935fecc4@linux-foundation.org>
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=NReDqobe;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 13 Nov 2020 23:15:28 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> This patchset adds a new hardware tag-based mode to KASAN [1]. The new mode
> is similar to the existing software tag-based KASAN, but relies on arm64
> Memory Tagging Extension (MTE) [2] to perform memory and pointer tagging
> (instead of shadow memory and compiler instrumentation).
> 
> ...
>
> ====== History
> 
> Change v9->v10:

I'll drop v9 from -mm and shall go into hiding for a few days, see how
the ongoing review is proceeding.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113153550.5ab0f21942ef7331935fecc4%40linux-foundation.org.
