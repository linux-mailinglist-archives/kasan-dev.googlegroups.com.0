Return-Path: <kasan-dev+bncBCRKNY4WZECBBHXR6CFQMGQE6JULUOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 966C84401B4
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Oct 2021 20:08:31 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id s143-20020acaa995000000b0029997b94a79sf5455819oie.13
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Oct 2021 11:08:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635530910; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpXPnTzElrwJ4Kn/Si8Cr0/cQ/q8C7DFDcwk+oItPnA2u16TWdQwiMPvdvqVDr31je
         C5KZz7rvoDRO2ETGWhLiURmj/hNsI+4dTpHaVLFhsDOuFGOA+WMOKPXdUgUmnN+GlCKK
         6e2Ij4BY2tnKsdc8b97b5o6KDf4SEZ8GXwWct3vGd19nHc7w4Z0/LXOCGbS+5yg32/Hq
         qMfde+GU51W8in2FC8rZYV45lJU2+JLJlxpk3F7WhO+Dp20BTUyyxR2NjpG4y/6BYqd+
         zEjYRcE2ChHn2hhjNzMcP3ZV29StamKkDggCxXAk7JmNtF1hQ3XAr4JFPDpuvqkEzsYO
         jQww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=is0+mYVfqqpa3iYBxxAMRELu8HJk2d021Iqa9mMwk9I=;
        b=JdBq9Lhzn9EO4vn5rfH6TdAsxYV8LwEXzE7PTtJeQryunIw86zJQbMwyfdtl4uaq2c
         psIsSl3mq8HbdAdizhHmJamWcL/1OeBWfHXnHkDCSKNtfY/o3qTd01KZZ659kzdpY2sO
         T47ff7ASbnQ17DX0XK+oKNltbz+DXtpz4mtcvKl8GLJFcCfINFxu/FmBeznanqjsJY8L
         9Y/Noyrm+A8IFGzSm5Vp3quOX9ZQq6Vu0KrKADZys6eNXardvFlchaBnZUOeb9HyLbvc
         1CSPS08kfgp1VZOKdq5P660cBIpK5Khb3vuDu2N1o3mJ2Sw8aIVjNJ8chUBUcQHToaOy
         qKhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=bvJHJP9y;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=is0+mYVfqqpa3iYBxxAMRELu8HJk2d021Iqa9mMwk9I=;
        b=NJ0/LbOqNo7xY4QoD1wCAfS6/SixWyX6NJjPk8QNLZcLke33cbUcAhObbzG2WIGaLL
         wjT6oohRABObeBKkQViGGGrwWur9rcsFf7XjdopYNxqtJHh8e4012EHryOTGAk3jeD/O
         MCL6Si9paj/zhofXn27KGKX3KgRAxzhzV/okNfJOEbLP5fN+YWhl9TIEIFodWwYexvZz
         15PTsnnCr6bn3AWqdQqzChTT8rioJTN9YbJtll/kAb+kbT0yBPEno7n7c5NNcacQvrVh
         P22QLfB0sFDhBCLeyboQXieN3oX/1ZL4r9HHjyY1tYL6OH/167EZ9g9HSCuJy8aI5IG1
         5/tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=is0+mYVfqqpa3iYBxxAMRELu8HJk2d021Iqa9mMwk9I=;
        b=6ft934xEot9emorl6jSjwjWgor+gr3p/CZrdVM8KdMiqmEIEKNBV3sf58mu8UXHbai
         OTP3Uc42qRv2q2E9fA2bl8OTbs+npjsOldlNUUj2U1+9NgHTUoZQNQx+SySZ4aDapgM1
         PD4e/RJBHSbZ7kTP4P9MUFZiQUR8gSjoVaAlznJhxU2tq7oCkyMHfYjRfYX535s5Ui9o
         9U5ZSV7W9S2fCRIW/ir66LrjQlty0X3iXMVHni3+DkMh5Gh+lToQZX51SugrsOviuQhk
         xnUa18+Io/Tw5zyeR6QAlOwtW6F0qimFMAyHr5tScT7TjnzfTmU/uBEGIyh+5EQn3Qz4
         eUSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XClqBFMFEEQEMdLGL+rIObo4xOHyqm8e0DBuuUtiXp1ZAhYxw
	slj6kMH7Fta1mAamjiHLd9I=
X-Google-Smtp-Source: ABdhPJxPPANrEsEOYbt6ho3CVBRLABPtPvMUw4rfZQGhZtFxPGpE4TJh40vFYASHv+fhqJ89xS1Q3A==
X-Received: by 2002:aca:3446:: with SMTP id b67mr14887981oia.84.1635530910416;
        Fri, 29 Oct 2021 11:08:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:946:: with SMTP id 67ls497616ooa.9.gmail; Fri, 29 Oct
 2021 11:08:30 -0700 (PDT)
X-Received: by 2002:a4a:d2cf:: with SMTP id j15mr4695151oos.53.1635530909997;
        Fri, 29 Oct 2021 11:08:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635530909; cv=none;
        d=google.com; s=arc-20160816;
        b=OArRtf2MYctvZpCOR1XZj+mYIaG1LfMBdQ1PZcSI19aGtJz40nIMAG76EZF6Wg6WTB
         ZeEwHZfHmbVpNhr7FP9njBRa2aYedLGdoPu+qUTk5gj2dRrQh5IpW7UJZEeYlFYqTuX2
         u78FS19hjH68avtT2XmnnQzO7VowsTzprdMNNkuavI//PIOZz1WBFDt32aRbhEyREwY+
         fs+nZQEIu1+ADCdyqxWipp8CzqFN+jfS7BpcjZrJMk1rE2k3o+pBDEcljYbCUJCmvfq0
         8XdUJxQAX2u8v1BS9mL215Djzb5d/ynrMsQT57RG0jJysoRVzWR3rBCGTxtLsVMWFG/G
         7DWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=xFYea77yp7hHF39j7jIyl1YqhsIj0k6eOQNJFYQ5RKU=;
        b=QlNgoC2+DLxyKHj92XDQMM4nxdlApLwCPBg61sutAwLdksAfsvaGxQsvFD685vQJXi
         d/V8pHYmKBz1391ttdVpWHvfnq2k1cVtQEUURUBG006Y9an+F4AXv/uv3uZT3JFra7Oq
         86dKh6iiEO+w4uygElAMPeXF4v2ZKF1Ko6CGYCeTOSsuHlXIwIaijG2oDJ/pD9NvMQSE
         xLyBgK+Atwdo9CAdlU85hx2E3hJoVuXmmp1uTaSW8Tq4L1RDteGvBQdlogD9YxC7Piws
         bNIPNWQ1Q/Tbqw2XTJoTJMTYyJ2A+8ePyyoFBgZstj+8bjebMDoiwlTOXbSHBZDLpU9k
         gDaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=bvJHJP9y;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id p128si375572oih.0.2021.10.29.11.08.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Oct 2021 11:08:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id 187so9923562pfc.10
        for <kasan-dev@googlegroups.com>; Fri, 29 Oct 2021 11:08:29 -0700 (PDT)
X-Received: by 2002:a63:3546:: with SMTP id c67mr9131634pga.201.1635530909069;
        Fri, 29 Oct 2021 11:08:29 -0700 (PDT)
Received: from localhost ([2620:0:1000:5e10:b1bb:1ca3:676a:3e09])
        by smtp.gmail.com with ESMTPSA id k8sm8099425pfu.179.2021.10.29.11.08.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Oct 2021 11:08:28 -0700 (PDT)
Date: Fri, 29 Oct 2021 11:08:28 -0700 (PDT)
Subject: Re: [PATCH v2 0/2] riscv asan-stack fixes
In-Reply-To: <20211029045927.72933-1-alexandre.ghiti@canonical.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
  alexandre.ghiti@canonical.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-b840919e-0658-4567-8639-f15c6076a860@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=bvJHJP9y;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Thu, 28 Oct 2021 21:59:25 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> This small patchset fixes asan-stack for riscv.
>
> Changes in v2:
>  * fix KASAN_VMALLOC=n
>  * swap both patches in order not to have a non-bootable kernel commit
>
> Alexandre Ghiti (2):
>   riscv: Do not re-populate shadow memory with
>     kasan_populate_early_shadow
>   riscv: Fix asan-stack clang build
>
>  arch/riscv/Kconfig             |  6 ++++++
>  arch/riscv/include/asm/kasan.h |  3 +--
>  arch/riscv/mm/kasan_init.c     | 14 +++-----------
>  3 files changed, 10 insertions(+), 13 deletions(-)

Thanks, these are on fixes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-b840919e-0658-4567-8639-f15c6076a860%40palmerdabbelt-glaptop.
