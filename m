Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTNP7TCAMGQESRTL4YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 91ACCB27F16
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 13:19:42 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e56ffea78fsf23858125ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 04:19:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755256781; cv=pass;
        d=google.com; s=arc-20240605;
        b=XUTGocxkaAAqDZRTG0DipeFcwI5pnS/xfRIV5jGZ1xu/G+JmgWDyweUuz7u2CQ0rlG
         IaATmGziJ6wP+ZGYHj3hnR5aWUBm71cSqGT3Mwc5Q6oivUof8Jf1bg9S0a7SGsj3ekQ8
         UuBud+NRY6eAO4Lk1lelNToQ7SsGSpSWl4cEQRJdmiwdtc3fGSlJU2oca0YCTIj2Pkk8
         Mf++Q+bc6PsNa7UUCvO6E8ocwWQvmKqpK/Kaumjr5GnXy8uU8aTP8ZsbHItSOC4x1N0v
         9kNK0BVkbWNHIGlQQmoMGkBKRA78k4Xhc1nBFaXHFSciQtb+ZEWFxIqdARxkF1pM74nh
         T0YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1eqJjVXl8xflHBlOouASND2etaGoBREle2LtRiUIT4I=;
        fh=UisUFfrm8Tpz3jG9xDvyqsVjuS9S8puP1o3lndUAVno=;
        b=AUtTB7coh5N+Qc364mvBvbIkMAsRf/PdUMHaRaTkS/YXRAOF4g7fbvh4VIPdPagjZD
         ZQuY1k6D2+3PfEHfURQ/zWQQJ3y6sLsH4T7Ta4TVODc7sH/2pvYFT2qbbHk9eJyI1olS
         T5SQxi4Fc8jxOv9mdPi8tPNgQuYXSxuqa8k6fcHW3yCVj/iS/D/U0i8r3dF6QpPQkhj4
         ls/yMxSDIyCsiQAfftgmvKYwN0DhbGIaiBq9CajmBeqD5WC7I0yPCgGMHb11BaJqPhL5
         E+jP2lNNO/LBGyTjM9tOc1q8/cb7sjq+dNhL4g7TcCMhBE6X3UopldWXbOFHRrnd00LS
         KkFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755256781; x=1755861581; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1eqJjVXl8xflHBlOouASND2etaGoBREle2LtRiUIT4I=;
        b=jZPbHP2N3GdnhirrPWj95e6KP4G/K/vrGG5sFGOLTh/EgJRWshrSXPGwuSLMwS7Rie
         4+OSDjmowRjmNIbNvwrZhuHcLxqUKXe6bB7fii2rSL+fVt8xmLOsmx+AxeMrkNayxOIC
         xHevkAm7sMTB/mQ/79BCh+w4PUh7nzmSGiummkJ+TL2lBwiU56E//BwEOjlQ11iN36VK
         72qVYfyTo4K+R+4VdBijNcdKDBNkNnl5mIJ/R2Gi8Lfmagoa5rbDiovnlLGPZcPpkYUT
         4hZbhLLRKumtcG4TGMP/BVBCstmDFWgMHRCs3uUKDjIN7g8QytXmTaQ46RuaY2+Ikd3p
         RZxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755256781; x=1755861581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1eqJjVXl8xflHBlOouASND2etaGoBREle2LtRiUIT4I=;
        b=NvH2+C0MKfaOuCPVSSQGdDhNjSHagPSPqhA8MsHI5MkbzvCUOv19OnF3+zoFYAPaPO
         h/jbH+6IUOzEameOvTtbB2AjAkKW2BbceXtMt0N2z8mWbW5Zr7R35ngsSwaN8AqDot8p
         bTSoqwDl3F9wYb1nl8/1CapQkaq35kKEB6XZKEFXYtAy+seqGUx+8mxk/5vUNPs2O30F
         YCZvWde56vcam2+zH7GLZabUAnVBFFICnRznMyB6ipaHMDeYLBTTmJm3R5gQt1UI+8t6
         a1GEfRbMsRoB40pHlFjXovOybgBDr4lta04glYyM8Du3jmHEUUL0e06Jgg4vba4x9wKB
         i4Cw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvODXPPUeQ3A5GSLMd4tmno1KSmSwvZhm3xOZIPOWj/ED5Tx+qDHDWFVKUr3nRuBDI3hRhcw==@lfdr.de
X-Gm-Message-State: AOJu0Yw+9vUihpSFp8wi2Y660r5OtyY6KmfL+/srCPzjP+CvdiVGn/Ac
	N/zWHJscaD6YCDpXJcSi43ED9L6rFOHjj9WDLu3wWBo5634SCvo1JUeL
X-Google-Smtp-Source: AGHT+IHdHoK4IeanllOZ1Q5llTqPPTih6izaOnBb8t4/oenlFfUdFUczcX07r/ctnh28lrxObDiP6Q==
X-Received: by 2002:a05:6e02:461a:b0:3e5:7f31:5b43 with SMTP id e9e14a558f8ab-3e57f315b44mr27026985ab.1.1755256781299;
        Fri, 15 Aug 2025 04:19:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdFx68yd9QtLUE/RCkugnxZTGswnDRQJQDqP8FBkmp8Bg==
Received: by 2002:a05:6e02:3e04:b0:3e5:77c5:9198 with SMTP id
 e9e14a558f8ab-3e577c59391ls10641725ab.1.-pod-prod-06-us; Fri, 15 Aug 2025
 04:19:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKuJ3rdmtEtFz2ZQX0eFqWGwf7ty6snq+f0kS3a0omga9MIlgiJJprUDMOok9158eZn5+vLl+tPtQ=@googlegroups.com
X-Received: by 2002:a05:6e02:1a85:b0:3e5:7437:696f with SMTP id e9e14a558f8ab-3e57e9c8b6bmr30019155ab.24.1755256780307;
        Fri, 15 Aug 2025 04:19:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755256780; cv=none;
        d=google.com; s=arc-20240605;
        b=UWu4DhSuK+ORMvK7uAiVPO9fiMcwF36XtVoTtWSwVMJPZejcFyDQc7XUU7dbuN623n
         8LBLiATCG6IhCZ/kjDCMcNqy72DdWBTQBEu/4n+SlS/rDVHFkwBAa/xtzfTA+2er/49s
         NvT2333i226Io159Viv1zexE/u5TEu3CYRmNweQwLtjuB60UcOTT0xpKN5wk0R6OrRJT
         weq/9IOKf69Lw7KcP+vBfESNuQPhwLi5CKFdn9ZJoioGbSxinZPZT2rrromT+9k1CGO/
         0PTqkVDe0BSIFvCUOwctElzxbFJ4bapWMhW8AoETqG8hMDIuQYYpgdLMrgt5IW2xfxQc
         Grzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=aqyNw+Jm7HoH5Z0KlAgJAQwfjE1pdVnkoWxhIxI0/t0=;
        fh=DGto/6WmjTsiSqI0AZvvQSzM02IQHCjZKB3sooklP7U=;
        b=Vw+WK881VieZLoNrl3oYz/MFJJQSUSwWmoRHBQX2cMaP5ML04T3GIbIPHloPF+SLqU
         XPWv9gz7lBjaMa1eBkjGC4ZZlcU/irtMcoB+7tmjXf/JtjfhrHY81BqJaWBwVzs/B5Dt
         sQ4Z2RqShR0OnArNb93DLlJrrbRTyANl80xZuFcTGWYbpD8mIR/3EEx2GRoyk/bL3UhY
         6Uia8usHLcBOEpQFz2FVukHJkyYDR3mFiV4mzeBsThKFrirtB7lChIU4O6Zz85xjVud0
         XFsYWZLI5N5AJ41EYEnZ1KNHakp7bI303VX5Yi+mlNQPiNQ1bVLTv9r/H34btUvno2uB
         NNYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e6655b4si540495ab.1.2025.08.15.04.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 04:19:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9C5FB6116F;
	Fri, 15 Aug 2025 11:19:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B5CE9C4CEF0;
	Fri, 15 Aug 2025 11:19:34 +0000 (UTC)
Date: Fri, 15 Aug 2025 12:19:32 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Yeoreum Yun <yeoreum.yun@arm.com>, glider@google.com,
	Marco Elver <elver@google.com>, ryabinin.a.a@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Message-ID: <aJ8XxLGiaVmWUCk6@arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
 <CA+fCnZd=EQ+5b=rBQ66LkJ3Bz2GrKHvnYk0DQLbs=o9=k0C69g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZd=EQ+5b=rBQ66LkJ3Bz2GrKHvnYk0DQLbs=o9=k0C69g@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Aug 14, 2025 at 07:03:35AM +0200, Andrey Konovalov wrote:
> On Wed, Aug 13, 2025 at 7:53=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com>=
 wrote:
> > Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> > raise of tag check fault on store operation only.
> > Introcude KASAN store only mode based on this feature.
> >
> > KASAN store only mode restricts KASAN checks operation for store only a=
nd
> > omits the checks for fetch/read operation when accessing memory.
> > So it might be used not only debugging enviroment but also normal
> > enviroment to check memory safty.
> >
> > This features can be controlled with "kasan.store_only" arguments.
> > When "kasan.store_only=3Don", KASAN checks store only mode otherwise
> > KASAN checks all operations.
>=20
> I'm thinking if we should name this "kasan.write_only" instead of
> "kasan.store_only". This would align the terms with the
> "kasan.fault=3Dpanic_on_write" parameter we already have. But then it
> would be different from "FEATURE_MTE_STORE_ONLY", which is what Arm
> documentation uses (right?).

"write_only" works for me, kasan is meant to be generic even though it
currently closely follows the arm nomenclature.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
J8XxLGiaVmWUCk6%40arm.com.
