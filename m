Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVYQWJQMGQE2E3FUIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 14EEB50A0D6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 15:29:24 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id i10-20020a1709026aca00b00158f14b4f2fsf2543039plt.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 06:29:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650547762; cv=pass;
        d=google.com; s=arc-20160816;
        b=D/qymtdKoeONB4Sf3yAkprq0Hng2Gu5exQafbs7Fh0UdkmeQn6FDnMMqBQ/wXroSEJ
         qdMzvtMLfBlXGFE1dIALlTygy+MtEiLOasji2AotuNuX+nXCskhiqZpvasNgkkCowj1K
         20BCObuWYc3dYG8//oT8BSBSwF/zVAaW+dwv2PHeLJJbl6s6hwAKk61atPbH7IDyO+5X
         WbFDh9XoZyO2em5N+TlSnqJfaVzVAvpSb0+LdpPmASJg6ZSf6/CYhQ7FCU8y5bucpNhM
         LPaH4ztVzCyEira+FchfSywy+GGWQc1UA3GGIuvhNnONpK+GwW4ID6xeq8XKFti+DNIf
         ju2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BxwlRn71M3hwyTFpGuwRmh0CiVAifVuKxDTiDUVKs28=;
        b=hBaJvBXHzCA5t94M2HMaSyPvfE16dmKYfqF+JGfv52KBNMSWforamxsCZasxgtgK8W
         jJH8C3kSoekOKgp221feL0Y0mYzkK3ByXeXVTLzlh6chl03dq6ovna9H4kKKGXpxLK0+
         UvoYDsQakrm12EJHEK5uPDngoOEunX9/KmgeBfLU/ti1wu89LAj5EgXnurk3FtvDl+ns
         pIVkhDLnaIDQXASPD/RJgYPJJy6/6ziHft6HKs9iZc6rpamUtaHFcIbi9jKZAV2DDMxJ
         AgxLzUl7tBv15TWfIGdM62M6J2TeTMGYGtV6S5GJmGgTG17kjK/gN5hv+yP9mYfG2CaA
         qQlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U513sTPi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BxwlRn71M3hwyTFpGuwRmh0CiVAifVuKxDTiDUVKs28=;
        b=gSafmtuq1JNLWaWkWrnyoZAIsja37d0pL1MCtVo3kynF3VHJkoPD3I35PVGBixdXr+
         71AufI4QBj6fYSqmyzjdTmkIhjUIPjmCVz4pbI44cRq/gX1HVX4hBwmsEktEUEVLDxK0
         J2/OFy3TJArvYiGKcwHtAFr+qLknNJ4P5x1o+1M7ST+R8wTbJONPFCYoEoyQ5qwD0C5w
         zaNWmg3LDfscyZEPANNdJkrBui1b5Ri1uOzPPyo3jumoZA2SkxPmokB23HrJPEzcEVnN
         YU1PQE8+46gcl1pOv/6ikBkETQTjavhJqQPkwAynUjFqGXFCnOV8y6/DSnPu8KLk4pD3
         QIOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BxwlRn71M3hwyTFpGuwRmh0CiVAifVuKxDTiDUVKs28=;
        b=3Hf5RkEdLiCWEWuWrfqoXWakVUkkHDJQ5F6l/YdwKEIHTN5mmmqhufGjQDaemf6Jqu
         oWhlA6JbaKEG9ThrCF8VdDrSv0RYI6xUh1q9Yv0ame+9MGiFcOcBexCZOv4O28YofFtq
         muZJtTljXa55ukF1lcFKnf9YTpmF9C8bQRfaGO1Yy04+ydUIfSo4fPfAsxlC5gxvcOUG
         nDGPfXSLB0WLIngvkm7G9OYJXM90U0hGwAVT2QGbXcxNI11aUrj9tlVt5hqLa7n5D/CR
         TPzIRS92YFcxxQp2weelPmG1x0Dwz6+OCZw64+znMkrZa4Vvo7w71kbuaVfLj6A75QAt
         S2ng==
X-Gm-Message-State: AOAM530HUdajo5sAqpEAby88TwyUh9Y8ZNcWV+ljsgHyoeEcgE1jlphw
	VIM3vDorRCISkyZA/D7a+zU=
X-Google-Smtp-Source: ABdhPJwwRwVQrFoIXEnlOg2w9/a3oA8f2004pjyywImFEFE3movjsrWQr2sd0WrOjBSmct8B4zUa0A==
X-Received: by 2002:a63:7247:0:b0:39d:8460:7431 with SMTP id c7-20020a637247000000b0039d84607431mr23942085pgn.227.1650547762842;
        Thu, 21 Apr 2022 06:29:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e513:0:b0:380:b1af:86bb with SMTP id r19-20020a63e513000000b00380b1af86bbls2735126pgh.4.gmail;
 Thu, 21 Apr 2022 06:29:22 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a4a:b0:4f7:be32:3184 with SMTP id h10-20020a056a001a4a00b004f7be323184mr29205851pfv.65.1650547762112;
        Thu, 21 Apr 2022 06:29:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650547762; cv=none;
        d=google.com; s=arc-20160816;
        b=PB0QKjI1K8a/2Vo1IRkYJN6XUQ6FfV5CV9Lc5AAQE1hIpdLEncLYYls8MAJKHroa4j
         ZzN/qdAIp8qUXOsBdDMNFhOVT8Yd3PErrbv+i2ZFNQAqgRweN19ZeAwrTYbuTdfBanAY
         jWPEtExTztaka3St8nX8o3vVWvE8H6uhFXCGYK6OmlSwJ+NQW5ktdomkBZSWS9N4I+6e
         NRPpfTNGZ5broLFyOGxCTdS/BYwDMJLet+eF0fwSIkU5jtp9oLqPUUviwdd3hdcwXuFF
         bHnuqVXdjcqFTlZwtRW3+bDhhLE98/PIiplN7IQY3uVdfG44gjUgUslveztkwB70ck0x
         x85w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MqWLSGF5u7HAvIurWy83H/sqpyLwV1ABomzO+8j+TCM=;
        b=Xc6sfJGiZRc90sZ/FM04+hfozYbG+4f8c+Gd7axtYhlCw5j8NEwQUF7KdliqlNSkd7
         onsgj/d8/91qacQSpIWdgx1gXkBvAOlODDkixpQwnMAmKskXf3QUOs6t3d5e6Y8w9dot
         dHljKzy9hIdktsNRfcopB09LIDWaOqAIaXYNQ3c4Gzwb6KAQdTDDWSn9wD3JqkBM4338
         CnhxXQDY0ARftL/+1BT1b4wZoiGtoUrd58ddgZncsSv9wKnKTx9/LcJ4//bPoLCp6NNo
         a2oelBHQpvUGgi++/gqzhpvFjAUx2Lnohe+8El4Q6lobO/vktY4i7aVCBwTKGeCQzAS1
         4udQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U513sTPi;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id t1-20020a62d141000000b004f6fe5417cesi493564pfl.2.2022.04.21.06.29.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 06:29:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-2ec0bb4b715so51946217b3.5
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 06:29:22 -0700 (PDT)
X-Received: by 2002:a81:f211:0:b0:2eb:9ac6:4dda with SMTP id
 i17-20020a81f211000000b002eb9ac64ddamr26303415ywm.362.1650547761401; Thu, 21
 Apr 2022 06:29:21 -0700 (PDT)
MIME-Version: 1.0
References: <CAG_fn=Xs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug@mail.gmail.com>
 <20220421121018.60860-1-huangshaobo6@huawei.com> <CAG_fn=UxSwgO8D2dCkM3vWPwcz0-rjvFdwr37cxYUt4awT3crA@mail.gmail.com>
In-Reply-To: <CAG_fn=UxSwgO8D2dCkM3vWPwcz0-rjvFdwr37cxYUt4awT3crA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 15:28:45 +0200
Message-ID: <CANpmjNM0qeKraYviOXFO4znVE3hUdG8-0VbFbzXzWH8twtQM9w@mail.gmail.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
To: Alexander Potapenko <glider@google.com>
Cc: Shaobo Huang <huangshaobo6@huawei.com>, Andrew Morton <akpm@linux-foundation.org>, 
	chenzefeng2@huawei.com, Dmitriy Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, nixiaoming@huawei.com, wangbing6@huawei.com, 
	wangfangpeng1@huawei.com, young.liuyang@huawei.com, zengweilin@huawei.com, 
	zhongjubin@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U513sTPi;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 21 Apr 2022 at 15:06, Alexander Potapenko <glider@google.com> wrote:
[...]
> This report will denote that in a system that could have been running for days a particular skbuff was corrupted by some unknown task at some unknown point in time.
> How do we figure out what exactly caused this corruption?
>
> When we deploy KFENCE at scale, it is rarely possible for the kernel developer to get access to the host that reported the bug and try to reproduce it.
> With that in mind, the report (plus the kernel source) must contain all the necessary information to address the bug, otherwise reporting it will result in wasting the developer's time.
> Moreover, if we report such bugs too often, our tool loses the credit, which is hard to regain.

I second this - in particular we'll want this off in fuzzers etc.,
because it'll just generate reports that nobody can use to debug an
issue. I do see the value in this in potentially narrowing the cause
of a panic, but that information is likely not enough to fully
diagnose the root cause of the panic - it might however prompt to
re-run with KASAN, or check if memory DIMMs are faulty etc.

We can still have this feature, but I suggest to make it
off-by-default, and only enable via a boot param. I'd call it
'kfence.check_on_panic'. For your setup, you can then use it to enable
where you see fit.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM0qeKraYviOXFO4znVE3hUdG8-0VbFbzXzWH8twtQM9w%40mail.gmail.com.
