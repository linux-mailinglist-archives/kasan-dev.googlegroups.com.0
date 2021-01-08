Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWNJ4L7QKGQEVXG3THQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C6F932EF664
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 18:22:34 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id x7sf8394790ion.12
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 09:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610126553; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lr5cEABxoULrl2YUWtv+y94+3OoB7CEGZgvfMTBxasDWIKKIBb2Xb81aOJVi7LR8/I
         5MENUHzaeuA+UTiqlt3l1/8pW9sX7fcZhTI3Fm97yPR27NEt9CdxQljIBTUgd8FSY4SP
         nSq4EXIT/tgbATZH+lWNsN9BH5a5k0+JHzaeUCp9ys73BIA77mNwx1lGr8mibbnkeIgw
         axeaPn3pv3MDRNBFXWdcJ5GSSnyqneM/i/NgYQ9i5it+gRCPcLFjw2FPCsl9QxfoQp7y
         O5At2mUsgYwxm+hWVbn80b2D/Es/NCHNNdJTw29AHNDO7iebFl0Sz077rA5b2XnWH5+y
         Gh3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=bZPcLFLIuj/ilHjNgGG0z5YYFupHZK0QtZV/e4W+pwc=;
        b=ucWpWUGBJ66ha30cueBS4JmcrfOhNsnk1s5kcXYllvWGjtuPMv03YZ1hN2J8OIFOJs
         HhQZxREiSg/B38ebNpHC75dS5beEO7dhMpuEPBAHuPJkYMhYyDibekz6bc/cRXmG3JMt
         6JRf9Y26gNiDgfLPmBIBDy5OAmX3qus925SjQ2T0fooAHaWUDS3AXh3tdeE2czss5L7n
         fOc9Q90k8BVfGLISZbMv5YLosYaOfmj8rbDINtrgSekAUqTmJEIfovCXJjxvV8OZHwGq
         SrDNHiXz9FzAeaAcEHVijvRdAfrvHyhBshk6//NHxB8TLbYx+oOjfQLMOzyih0mUDHB7
         gofw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bZPcLFLIuj/ilHjNgGG0z5YYFupHZK0QtZV/e4W+pwc=;
        b=hOj6WFebbLgNCtvp9VwakbxVP4EABJyVFuSrCW026ryDvayd6Soc8Tghp/JmwdEYjW
         WVzevcg54Fgadd0jCQ8LIyKdmfQKaQ+FwGGGj+Ushl7OgswiV21WVHVetv3I4WLag99l
         bnbm7eXOSbarbqXtGMI0PNSelWehIqskWTTGxCIrkyDF8K14E2tNh5CcRGcVo7rnDBKh
         xfBqB8FRPlgECXdG5boWxXXpUIVmENyvVViMQoTw4Xwnns2j6hgM7pGuAZdiLuGx2ArA
         y0yXA+7Os7W97iy2REZiuWbSGvHRoRvtfj7Hox02zK+Uq11eGPzDsglKKYZEk/NJUtFS
         K2lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bZPcLFLIuj/ilHjNgGG0z5YYFupHZK0QtZV/e4W+pwc=;
        b=Hi4LZhXeG1jhw/E+tYZWo4ciAHxI5/z+0TlXCdcvclDHzgGqC0/D2mzQcXpxOcUOLj
         PAcUTgt03yBKmB1u+d0PcZlFGElqQm2UFub+KJbuz2I2qG7v4atn5afieMmkVkCU4yMB
         5p8GoMvaxrEj0003uyrl8bx0rf8CbcZ7aQztZ4hlwMwM9hgWT91Vj+YtPIMY7Zuh9wZL
         pUWJFTYDPwISa1vBwKoLc9VPiT+Q3CKlb5b8MmxdxuVHJuoYx4dZXuQ/bwjqtRx0+nqN
         d5bDvQVXcJ78stezBN/lONGpIMTPj6nNOMYhz7k0WYvMgEbUc5id1hn0cPk/KUN5V6oM
         XlXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533UNXPS4HGGVPu+GobOQWE8vRGare2hFPfEm3uLclFPO0nGf/Kc
	YZI6q9gyXVI/2ite9o24H4I=
X-Google-Smtp-Source: ABdhPJzZi81Mb5JvWLn1lxpEfERAChqaw7ZY1oaPEm0wa+BZf2pQ12Dp/P6iBfc5uLJjyugWgZ0ViQ==
X-Received: by 2002:a5e:990c:: with SMTP id t12mr6373997ioj.177.1610126553577;
        Fri, 08 Jan 2021 09:22:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3609:: with SMTP id d9ls3363019ila.4.gmail; Fri, 08 Jan
 2021 09:22:33 -0800 (PST)
X-Received: by 2002:a05:6e02:ca5:: with SMTP id 5mr4769067ilg.183.1610126553141;
        Fri, 08 Jan 2021 09:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610126553; cv=none;
        d=google.com; s=arc-20160816;
        b=PsM71n0oCFiLJih9HQiqj36RGtBJpd6TanqNe2ml8Er10Yhmvg/nGDhMlJZXoPIs3r
         ylGVMkfn4ak7l83kfcNX66j2UfGyLiP/vCXWuJd4+6KSRKVTsGElaRESqp5iwaUIzx9N
         898vHCZUhUliNNnnSbaVWI1l/D61NcOwOR4X9yc1ggiRg6GDQ5PkKP5JXSRMtCoilLDl
         f4cQMyyTONsJRSGH2ayhpCeYFd/XkjednUYcmgm73AryMe/uNwBJe5CfXy5PEY0Z3Pa/
         KgOHlgnj+fsocWuvhYlAuSsW95pFZP2ILHZUOzARAZiP+2zgkMoHOhAislab0iDe1py0
         nArg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=gItCsg3RIM2Z39chtN/iBrunm6Nekq2j9nsHEFGLuc0=;
        b=Qu2AM40d5fRfQr56wXhjwueLEviUmGNJZ3RJu29d96gBXukqhO/Pm3oN4SLNo53gIK
         JQ7bJ7mdgks9/jfBt//TwkcmCZBePbQ8TC1pjwA3iUl7aTIeaBjrJT/b/4mcnGUCZHSF
         V/WJu5uwULXSSAlbM2u+xgXtY1DpqfYtE2NWqw+Nkzhnxqg0m5+mkKH+JiTR8NYwA1Zz
         l2ap7mKM8RLncsoykzenVMretjFvZ9urYMaW2pLIhbJlLc6kK5DRymJ88vggX2kB1Z/4
         gtlELIryp4SLhEAH+6C/Kl/SA0knH1IinoIqssgl8bN+HuSc4C3JmVWmGt7Iq8qHBhjy
         TCyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e26si851008ios.2.2021.01.08.09.22.32
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Jan 2021 09:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 662B111FB;
	Fri,  8 Jan 2021 09:22:32 -0800 (PST)
Received: from [10.37.8.22] (unknown [10.37.8.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 16B6F3F70D;
	Fri,  8 Jan 2021 09:22:29 -0800 (PST)
Subject: Re: [PATCH 2/4] arm64: mte: Add asynchronous mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
 <20210106115519.32222-3-vincenzo.frascino@arm.com>
 <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
 <c4f04127-a682-d809-1dad-5ee1f51d3e0a@arm.com>
 <CAAeHK+xBrCX1Ly0RU-=ySEU8SsyyRkMdOYrN52ONc4DeRJA5eg@mail.gmail.com>
 <c3efaa8d-cb3a-0c2a-457e-bfba60551d80@arm.com>
 <CAAeHK+zjwr0M92zqUjseJmRmhHb=4GjevEft-mahfx5DOkq==w@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1e1e9d66-32da-6bb8-b4cf-91c03ea90180@arm.com>
Date: Fri, 8 Jan 2021 17:26:10 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zjwr0M92zqUjseJmRmhHb=4GjevEft-mahfx5DOkq==w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 1/8/21 1:36 PM, Andrey Konovalov wrote:
> Perhaps we could add a generic arch-agnostic enum to
> include/linux/kasan.h and use it in both arm64 and KASAN code?
> 
> enum kasan_hw_tags_mode {
>   KASAN_HW_TAGS_SYNC,
>   KASAN_HW_TAGS_ASYNC
> }
> 
> Assuming other architectures that support memory tagging will end up
> with sync/async mode separation as well, this should work. But even if
> that doesn't happen, this interface can be adjusted later.

I am fine with this solution, I will add it in my v3.
As part of the enumeration I will add READ_SYNC mode as well, so we have all the
possible combinations.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1e1e9d66-32da-6bb8-b4cf-91c03ea90180%40arm.com.
