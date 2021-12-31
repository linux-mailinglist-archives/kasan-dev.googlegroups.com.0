Return-Path: <kasan-dev+bncBCT4XGV33UIBBYWWXGHAMGQETU2G3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9231F48218A
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Dec 2021 03:30:58 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id o20-20020adfa114000000b001a2abc089d8sf6902814wro.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 18:30:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640917858; cv=pass;
        d=google.com; s=arc-20160816;
        b=KfewV82eSrVFST43qWDqWxBUPQx1xXnvNgPZuTPW5Nd79GxGhQp13wzrxx3hvw7wDv
         ojG0e/wIXxF2T5M/a15uOUIiE9URm+JONqoubChUNpWFFr8GqpW2ssm8fwFUCWvDwFj1
         lBkN3g619nKyivgsCyQ2yC5+7NvVxZ8d3iex0wlBfL0+x+O2bgoG0rsNpE4TLF7HiRt+
         MAaV0ieRrdFsyubRDDKaV59O7G1RBc5I0O93tb4eToNjnEXWd3hOYuqN/RxGTxSN+tIj
         ezuUQ80hvOSD0g7Zzbos5pTo6GuFHpPSyLIo3cBqOkg1XSVV25db/kCXvLzZWbyQ/jRw
         Lo0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qqzLZvVgOIsXiO8qX2d8ABdR14uzf7XyoTjw/pJbrJk=;
        b=JH6SwkI6+M58LnWEkIREcP0pDQ987ywGco4i5whK4K8auXVKsggUIZvWVVufc8oZiN
         56Q46efX3fPN/p99Y0cML9M/AfUxvIVURFE8lk/v0ABN5O/D0YZCOseX6L6uivAsHAS4
         mTSlXVC1GnQRPVPJTBD86V2juhktGumNvyoSguWzEjnhjaEO/WzZ7d5NWaysT23gm1Vw
         XE/WFTX1X1K6tzdLEinKWh8vKO3EXaoM04blLAgibAxzyDazly3m2nlswYXIlk28I/HT
         EXHN0F57coEE61hhdIjhKqekH7aKCOl8O4J/hC0ZQHE2+Zn8So2SF4iWTxAHmixljuz8
         z8VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="XK8n+Jc/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qqzLZvVgOIsXiO8qX2d8ABdR14uzf7XyoTjw/pJbrJk=;
        b=O62qA5KGSSNUUzz21KoODIUWXq8Ryjw2foBODZDYvKVQKoFg9jfji78uRBR8VbXFOl
         bLSF88HljaHDiFOYXS53A/PL+XrW8FsE74gUl/aHySwU2qb/l4r5056NOt7SjmEfiwAe
         uwaa+VwFFv7yGparr1xzY+q7zWnBghVAM1tx8TbJdhcjCeKL+awXrr6F3PA0tSoI6REE
         H+BB11iHtpmlOiw2X1N4CrhPgFV4015ULSCgJJ/y1WwnPOHbzzBMP+PTMUOXFuq/qIwZ
         QbkdunxGxDx04kjQUVlfPuIr5nc3H7Gu0zt+MBfRkMawsHSNgt5IMrxOtN+LHPPmPCtp
         63YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qqzLZvVgOIsXiO8qX2d8ABdR14uzf7XyoTjw/pJbrJk=;
        b=ksxvQsv6s8UqPYyDojS5xxRPiRUIfQZwoZbs0u7tF9YsZigO/elGFm4BFSxhKMdHBa
         DG9PFehlA6Err8Nm+lw0lxiJ9m/YPWF53jORVHnG4Hk4UYMDuRIqvTkXCC1+NxlAdkmF
         duPKsRGNJOu86vVq7Bka3YtziTXVNheqoMTQvjEVem1SAf6sN63Qh/R5Chd7Oad6Zj08
         F/KR9dWwS0pyG+W8TLsk+HmiEO1as3y/r1eajKDKNswvn6+1S9WgY6aLQAmRISTxU3WA
         A8KV3fpAFn/chXlzUmn3um3SEMPnAHV51KZwGKVQefqv+CIg4SZhqRSZIlsqh/aOAadf
         8iVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZGsR9G8JbMZ7132b/V8FBZ2PrI9q0uk21Oh8hAAC2jxyQXwRr
	38zf6jnYRfukfmSpYiWY8No=
X-Google-Smtp-Source: ABdhPJyKriFbH3Ugu4TJR0cNioauHGqtTCt1r9fAP49NymiwcVXhXt3Y+DrDid+T42EKw54lzHwTqA==
X-Received: by 2002:a5d:588f:: with SMTP id n15mr27956819wrf.159.1640917858211;
        Thu, 30 Dec 2021 18:30:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1067710wrb.2.gmail; Thu, 30 Dec
 2021 18:30:57 -0800 (PST)
X-Received: by 2002:a05:6000:178c:: with SMTP id e12mr27498756wrg.563.1640917857277;
        Thu, 30 Dec 2021 18:30:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640917857; cv=none;
        d=google.com; s=arc-20160816;
        b=xdRA+mCMM6epMN1vF+M8hgMt1RsJp4KlI3zxukQdLlk2WPA6C6YI5dWHQUSwe0zZx4
         ZieEyGn7+345OFwvI99fgT+XxqLOo6m2iBw397aLVaj+hl/pWqBZAd/a//oldOsUZRVA
         VZhLZPGep3M/i0sXKK6q7Gv+BEtJwbOgtLN1nobeKpfU6UURqmNb0rzZXfsruqwFXQgd
         CAt5rcKUmmxv2Vb3all4IcyDyynZHwRwvmKZFS/hg5ChiHfXE4q8KGs6jWPf9km2P8+8
         ftZybRK7mNV8ml1BEX/dtiIwIzaGu61DRUB0bQ30fVT7IG3TTugWdYoIr2rhOPH+THxJ
         EunQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7sj6CF347P5a5/CxHJ7uph1lB75B+xCi7nel49MY9zY=;
        b=jSSvNO3vdYB8Fu7dmjVCs+QsCdS2hO0vhJRHM1dnZrxn27xM/xk3E+ULZ1/qamcXkq
         d+JK15TL21nSJV9J12QHH31paL0bpb110Hv38bh1J5d/Gcc+A2nfDpo3UKXPvW9SEZQA
         swGZqbrcZf7yzYwt+PmRTYiw1+1uGDvMb7bh+Zri8cB2xar/OBY2yFLHLrj4euqosaAe
         gWIxw/Go9rbfpmuFrfNnAv2+96Vc/H3C2mLOXcxQHo0kBi2BsaxnPCuWV4NGFhqxPF8j
         6Z5VCudta36/PvBYzqIr/w7qvd1MIYn0N2xjRYBHElReJAyi3EaFYjLoG3jv/wzODwzY
         udjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="XK8n+Jc/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id q193si792427wme.0.2021.12.30.18.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Dec 2021 18:30:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E5C7BB81CAD;
	Fri, 31 Dec 2021 02:30:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0A2B9C36AEB;
	Fri, 31 Dec 2021 02:30:55 +0000 (UTC)
Date: Thu, 30 Dec 2021 18:30:54 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, Linux
 ARM <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne
 <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML
 <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>,
 andrey.konovalov@linux.dev
Subject: Re: [PATCH mm v5 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
Message-Id: <20211230183054.a06a88b459b393957cb2d823@linux-foundation.org>
In-Reply-To: <CA+fCnZd+sBzecOGBD8zR3CxXS1yjV-X3-epAb6N=ZT8rJdCU6A@mail.gmail.com>
References: <cover.1640891329.git.andreyknvl@google.com>
	<CA+fCnZd+sBzecOGBD8zR3CxXS1yjV-X3-epAb6N=ZT8rJdCU6A@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="XK8n+Jc/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 30 Dec 2021 20:19:01 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:

> Could you PTAL and consider taking this into mm?

What's PTAL?

We're at -rc7 so I'll process this after -rc1.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211230183054.a06a88b459b393957cb2d823%40linux-foundation.org.
