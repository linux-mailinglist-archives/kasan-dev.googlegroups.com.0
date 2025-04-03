Return-Path: <kasan-dev+bncBDKMZTOATIBRBDPVXK7QMGQEBF5D6SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 9320CA7A816
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Apr 2025 18:42:54 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43d22c304adsf10808125e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Apr 2025 09:42:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743698574; cv=pass;
        d=google.com; s=arc-20240605;
        b=kcCXSvNgUkfmvmuKiJyYkZ4EXWO56QAcGL4AJPAVDZoXe2UtmdeMSGl5dBclwQ8UVk
         xt3i3mYav9ZZY1BecV9ZTVQVlYw+7FeAubjkVjjhvBs7XzKlyY4AadVEl0dbHo6vJT6v
         4pf7wVFVJNFdtOnPazaB1mtJxO8CDpXh5UkA+b7kG3u9yxLDfr6HXw2Wg5bGSQjoQa8s
         4Au/tedh+CI85Xhj57voUxAQqKOFRU69Ior7+m99Uv18HBsg9qr4DVH7VGHAagC0rQAT
         Yv3kv+eDOZdrazsyL+SqBqRTmttSEbiFfEwRJSzGF32NKF/H8HYYafOZKyvV6im4EY9G
         E0dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ufAx6j2HLsZX+V38VFtzzBnCAS6zcPBFSfHd+Ndkz8g=;
        fh=YiUOM575pxnO27RqkG0E0H/Y3p4c+pa2nUHa15ojpew=;
        b=SxDow4bEnO7obUQYOCoBpMjQ4/qxdl5GlNny0s7JK2548p/EtKNnR12G+kS/jp5vYe
         V68fFeRhv2GzuLKJwjDKenmihAOYsfdeBJ6vmqJh/KhW4kcZO3g9p6CdZJVxE/xs5s+t
         WdbKyS+sGBT0YaTsRICWF0Za1IySjcl5xM3qcE3mxq2pZM1b0aKa70o3DgVCi4dau7E1
         QNPNRHNZUcWomJiKiU8hjx0E+o/cwKOtmaTQi6nxqDdv/3uvJUUI17KwcwWcBRx4IoI0
         lfmYmWr6cNO9PKwnBWo64xzfhKRiQgCNdoaweFRsHPaa70c9/dCr1xV/rT1L9e6S4tLL
         z3fQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Bvd4N/bt";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743698574; x=1744303374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ufAx6j2HLsZX+V38VFtzzBnCAS6zcPBFSfHd+Ndkz8g=;
        b=IHgv0gt+aqoMu0TNbLJ0zFgEBtZgrxZ+R2YWfgLlktfE8IP6osLK+WcEBdZ4RLrtQe
         sUZQNGrPFGb2AakLG9WOkgfw5p0A3HDJa7Y0IahdXs55dsbldUMWENOhAWJUnNhJ/9Jp
         FyUNfWh2Zj8VwmwvM2/S41FQagR4YJjxZn2tfFo7fGW2CSC8CJRsSZwVanOjJWUvbFzo
         h9f9QPVm3ijqwtuavu/VXw4uEe0Why6fFIOg81xZmH0xMopgubR+wtD0zL8GK2tA+NwS
         hxM9YIvPYIF7a9MppQnRLaIgmCdto8rlD6OAVjAm4/v6Q3/NX7xSjDr67/yleFYJHXY6
         JOiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743698574; x=1744303374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ufAx6j2HLsZX+V38VFtzzBnCAS6zcPBFSfHd+Ndkz8g=;
        b=VW0anmefR+DHjrQ3fb3y/Rm0Xc5Qk4lUJo6/Mgb8TGMxoM/47J6KEmFsYj2m2RLS3T
         bdYUUxO3r92r0O1LvjYCBMxyrhcFXXgEHjbrlb3sZA87nKdey8MAKuLqEQSBW3ldKcnM
         Wo3GBciNNsnbj4T19Laz8f8gxPkS6SmRWv76plP/r+/DlntFN4A+F8w5CnwH6SwWe9WA
         4/9/jY4E9cwevMB8Eyp1cShono1uomtHBMKc2vuJIix2gqJUBK95+ndsWGc/mJ89WRLP
         Zel+8y4dGHmd5C0GQDPX7MtZhgAvg70TI4E6deb9jrpxvEw+ooCgGpxyIWzZdchmqWCe
         ZJUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEBAMnHUw9hnP59Z3AMB/bOryNTTmKy92gt7x38MCsf6/aeQ3DFSstJx2rQy8Me5gaxcKL0w==@lfdr.de
X-Gm-Message-State: AOJu0YxbfiUJXRRYdTncgaWi18uPvZsqDiNjK7CdP2QEg/JI/T0XtHIb
	Z2yoKV2VIcjgET48r9v7L5jF1CDIx1Kx0iCJjMhwHSJQJQMoiXs8
X-Google-Smtp-Source: AGHT+IHoPetpCWQevtLSTgftw4TSU5vWMsMxKdCt2s3uDjP2+3xCSMKvPNGw0h73Wt7HA+awwGgZrA==
X-Received: by 2002:a05:600c:83c3:b0:43c:ed33:a500 with SMTP id 5b1f17b1804b1-43ec630446dmr30224535e9.10.1743698573606;
        Thu, 03 Apr 2025 09:42:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJc5d47WpYFAjIMxD7v3wGHS6Ned0V4+BGbwSOIcA20Jw==
Received: by 2002:a05:600c:5129:b0:43c:e5d6:41de with SMTP id
 5b1f17b1804b1-43eb3384267ls8136845e9.0.-pod-prod-00-eu-canary; Thu, 03 Apr
 2025 09:42:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1RGKptS4BxLQqZyl8xKgmfyV44yE2Kq9d0nNW97zYo0vwQwzrg8A8mbOtiPvOHvXqgyjv1ZyHqss=@googlegroups.com
X-Received: by 2002:a05:600c:4e10:b0:43c:ec72:3daf with SMTP id 5b1f17b1804b1-43ebf6645demr46048615e9.14.1743698570510;
        Thu, 03 Apr 2025 09:42:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743698570; cv=none;
        d=google.com; s=arc-20240605;
        b=Iwa7D3HWjhKTU0jVqvBVU1qa6UGzbEIdD/wqTNgcKRSyHxnEYRnLsP+cHH+niZZ3MS
         qxg/ECWho7kXBEmimAHxMJBMSJrUWrYAGVYvkRw2HTLIaOgUVM3QPtkIgAVv/sw8uHIk
         WVKqPxrD58c+Y5FrIyL3Ub1TEynj7jkUi22N8udU1km9cvNPFTDLeBD3ptJDfupqrEJR
         M6B70MDNQtvM1jjCbWyZjkncNXaI7D+Mycda42FyehoedzI2mfBjFHzhp1/nuTeyZgzc
         28WqpvHvBzK9zbP2Q9LNFWHv9X8cURCjdlZYsu/OBaeFSuY2gT/LxfxxWROqGB6rK2gc
         sLow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=e1Hu1zsZjaevlSh/stot8ZuqTptYeGlG6FSdt/83NoM=;
        fh=KkfmahYuUfDzssE6vqJO7GOX7cNAd3pi2ivkNfvBrDs=;
        b=FMNK4lGJ+SZZNHq5/z6XJLDF+Z7i9DBhQ9to9xP637FgDkJ3/9PsFjPaHr5kP0U2/u
         uxJVQUi/gF+nDK3zP0l+wogtcEEXvwI9kYt3C+6LAJYXWEpZdU9SsgYAcSBS/JHDgH1U
         IWyYCtpjTuHtxidCAnbBg0622ZKyLHBK6aA/XNO/PEksBxBOrx/8c5L2SRCP3URel3ZZ
         y2G8Os4rJ2i4L+Yr3I5UmjsvgUgJ1doCANrFQFHLBYyaHboTiuX67X96mkzrK+qD/foH
         RvVPw7lQCnTMZ302wvCdgKeF4iMA+wGkbi/pFxFciedn7ynsA/BjeJGye3MD+Ag99MC8
         QrVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Bvd4N/bt";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [2001:41d0:203:375::bd])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ea8d166f4si1134745e9.0.2025.04.03.09.42.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Apr 2025 09:42:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bd as permitted sender) client-ip=2001:41d0:203:375::bd;
Date: Thu, 3 Apr 2025 12:42:46 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] kmsan: disable recursion in kmsan_handle_dma()
Message-ID: <btccfddwal3w5sca33u4tgoppdncmdyc6h6h2xrrris5wvbnbe@nhbtxg4mxuiv>
References: <20250321145332.3481843-1-kent.overstreet@linux.dev>
 <CAG_fn=WmyMug7mkD57OubPz31mH_W7C1u-VStCQ7UeYh_CCtPg@mail.gmail.com>
 <vd736huqp7kfy3gbzeowm2kzk72nst2s37knhuwlqvncwpsl22@oxilwothvgta>
 <CAG_fn=UM27-8G8XsWEHSGACEwOyeuKzdTf1benQEtZ1WwAWg+Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=UM27-8G8XsWEHSGACEwOyeuKzdTf1benQEtZ1WwAWg+Q@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Bvd4N/bt";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Apr 03, 2025 at 04:50:59PM +0200, Alexander Potapenko wrote:
> > If you want to reproduce it, use ktest:
> > https://evilpiepirate.org/git/ktest.git/
> 
> I encountered a minor issue setting ktest up, see
> https://github.com/koverstreet/ktest/issues/38

Thanks, typod that line - fixed now.

btw, how'd you like ktest?

> > btk run -IP ~/ktest/tests/fs/bcachefs/kmsan-single-device.ktest crc32c
> >
> > (or any kmsan test)
> >
> > And you'll have to create a kmsan error since I just fixed them - in the
> > example below I deleted the #if defined(KMSAN) checks in util.h.
> >
> > The thing that's required is virtio-console, since that uses DMA unlike
> > a normal (emulated or no) serial console.
> >
> > > I started looking, and in general I don't like how inconsistently
> > > kmsan_in_runtime() is checked in hooks.c
> > > I am currently trying to apply Marco's capability analysis
> > > (https://web.git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=cap-analysis/dev)
> > > to validate these checks.
> >
> > Yeah, I was noticing that.
> >
> > Would lockdep or sparse checks be useful here? You could model this as a
> > lock you want held or not held, no?
> 
> This is basically what CONFIG_CAPABILITY_ANALYSIS is doing:
> https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com/T/#u

interesting

> > WARNING: CPU: 1 PID: 451 at mm/kmsan/kmsan.h:114 kmsan_internal_check_memory+0x317/0x550
> 
> I managed to trigger these warnings on kernel 6.14.
> 
> After enabling the capability analysis for KMSAN and fixing its
> reports (https://github.com/google/kmsan/commits/kmsan-capabilities/)
> the warnings were gone, but there was a KMSAN report, after which the
> tests started OOMing:
> 
> =====================================================
> BUG: KMSAN: uninit-value in __alloc_pages_slowpath+0xe6e/0x10a0
> mm/page_alloc.c:4416
>  __alloc_pages_slowpath+0xe6e/0x10a0 mm/page_alloc.c:4416
>  __alloc_frozen_pages_noprof+0x4f2/0x930 mm/page_alloc.c:4752
>  __alloc_pages_noprof mm/page_alloc.c:4773
>  __folio_alloc_noprof+0x51/0x170 mm/page_alloc.c:4783
>  __folio_alloc_node_noprof include/linux/gfp.h:276
>  folio_alloc_noprof include/linux/gfp.h:311
>  filemap_alloc_folio_noprof include/linux/pagemap.h:668
>  __filemap_get_folio+0x7f0/0x14b0 mm/filemap.c:1970
>  grow_dev_folio fs/buffer.c:1039
>  grow_buffers fs/buffer.c:1105
>  __getblk_slow fs/buffer.c:1131
>  bdev_getblk+0x1e4/0x920 fs/buffer.c:1431
> ...
> Uninit was stored to memory at:
>  __alloc_pages_slowpath+0xe67/0x10a0 mm/page_alloc.c:4417
>  __alloc_frozen_pages_noprof+0x4f2/0x930 mm/page_alloc.c:4752
>  __alloc_pages_noprof mm/page_alloc.c:4773
>  __folio_alloc_noprof+0x51/0x170 mm/page_alloc.c:4783
>  __folio_alloc_node_noprof include/linux/gfp.h:276
>  folio_alloc_noprof include/linux/gfp.h:311
>  filemap_alloc_folio_noprof include/linux/pagemap.h:668
>  __filemap_get_folio+0x7f0/0x14b0 mm/filemap.c:1970
>  grow_dev_folio fs/buffer.c:1039
>  grow_buffers fs/buffer.c:1105
>  __getblk_slow fs/buffer.c:1131
> =====================================================
> 
> Have you seen something like that? Perhaps this is related to me not
> using the top of the tree kernel?
> Anyways, could you give a shot to the patches above (except for
> "DO-NOT-SUBMIT: kmsan: enable capability analysis", which you won't
> need)?

It's not popping for me in my tree, my tree is based on 6.14-rc6 and
yours is rc5. But that code did change, and it's something percpu
related - must've gotten fixed in rc6.

Injected kmsan errors with your patches and the reports look good :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/btccfddwal3w5sca33u4tgoppdncmdyc6h6h2xrrris5wvbnbe%40nhbtxg4mxuiv.
