Return-Path: <kasan-dev+bncBDYZRFP3QIJBBHX75KVQMGQEFDRLA3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E03A812A8E
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 09:41:03 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-35f68dc93d5sf24420895ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:41:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702543262; cv=pass;
        d=google.com; s=arc-20160816;
        b=D5b/ujVI9jOh/ZOfZHPrn4rA1Kgh9ujEdlfSslOw5yv8QP6ZGlcGSEXcwYk7osPQnl
         /zOyxp5CmBejv+zywdDLVTQZ4GdxmYPmj39A5k5xjHIdPEm+1yvw9pv/YAgbq8DFmiKo
         S7r++CZSpjaWvWjJZzJzAatJJHNgpaihwyaMoJ4vGfIxLBqIJUv5NCosltvkp3KpkcAB
         pK1fkU+HF0KzCTv/XV7fOqzWwnnxVU+rnVxy4CIs13KTYDha+s8kHZKijjoXSj1+NXbX
         g4T4BfAJVmd31CfBfBn3hASx0Oe11Y2H24kDRqMr7+TZqSFqoXpzgJpn4D9cIIS18LP4
         SrtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9Rrj0mKwr81hauwamWvYLYDEC67wbe8zJyU4Iw1XGOo=;
        fh=f1eG24fLE50oJLlpN6q45mWEES4s7GsWvScw+XEiX5Y=;
        b=VQ93o5y1mt19roYqQdtf2jLyyTgwhCd67WrXf8xmg8qrfO4jTWA0gEw4WfBZFUKynT
         ihU13RtrmJUPPHhQw9avnr5J6d8HYkgK9qZT5jd9ohdzXH5LlFHOtMPRHUM8w2RRW2fV
         FiRXvt9Oq61rKzORpe94xgaY/WJvxWscpDSsNf/KfY/i8ZE/OsBE3ztvmLkvproEgDmo
         hxLdW3nE218wIg9iAVU1HzuoSWoyqw1gGyMbGN65ibv6qjjq81Lor6SoIrYNkg2EWZIh
         YBVheJQz91DLH1kip8MpMXsArO3bhzGGKkk3//0p9FB3IL7TRrJ5XDAiPg6sfmlq7K0i
         uzkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.166.171 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702543262; x=1703148062; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9Rrj0mKwr81hauwamWvYLYDEC67wbe8zJyU4Iw1XGOo=;
        b=qVPpacHvfa9hACs/rB+pWxqG4Dtw3l6pjLIc3bEn8XBed6XO+/DXwP+fzj0D2vBCBP
         0r4GAgag2s44knux3qA80Fa016pcQdP0XH+yvQzvj9YL6ZyEklhPxRDFmD5t5x2z9lKz
         gGy1bSdJmOtNH5CaA/um4BXkUUxZFyFiuSOE9/0c8FwbJBvc1HrlQjekIVUEMaz+Y2Hu
         2pFD7JFx9I5nZL8ODEY8ePnTPVXLtGt4+uXs89KQOeCb0m699JbVCKmu29V8vn3h9iaW
         J3NksLJfkb8YK71yplAZUofZfBR0pC45VtGLE5gQXoGl6rKt1H6WDlo6SpV66m1XjZw7
         Tkkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702543262; x=1703148062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9Rrj0mKwr81hauwamWvYLYDEC67wbe8zJyU4Iw1XGOo=;
        b=Umx3SoDndeRRwdPiR128O0iAhOUZPsRb/wJMrJcG9ePXfp3sxUhWaIGuXYvh26ecSO
         mBYg3E4u94W+U/DCJB0L33rMmi5JVs2wiwIqBoSU9lVpgC/vPvOiLcPUBeAR29BhGBGE
         4AS6CdxSDNZYCgsSp6AdU07QJo7HCQyEfUU02qkr22fKrOTnIw4tTryM2tTfd1y4GDCX
         BNQJakjxEhGMEbnTTU6K0feomWPuuGGdeq/RI1PvcDe+IWsRlBg80rL9W6cwpMiV9ydA
         LYJghiINi7UeJTygOCF1JbdqdBvBtfkL3D+mxmG3Ua7ZQxIa/OW3HDjBR+xSNpQoaIwz
         S2Qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywk1Y990kBkHeP4oaxYuB2jiFG9Huq/ekToNqfHDjhJ5QHgXzso
	vN6ebskPnmo3iewN5O5CekI=
X-Google-Smtp-Source: AGHT+IHHyizn2QlxQyfkmz/aeMy5H6kpV50ucGk/5m0mOVBXCQF/XWi0kwU2d9nQXUyTIWG/b2nB5g==
X-Received: by 2002:a05:6e02:b2a:b0:357:f487:32b6 with SMTP id e10-20020a056e020b2a00b00357f48732b6mr11297183ilu.22.1702543262288;
        Thu, 14 Dec 2023 00:41:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cd8d:0:b0:35d:a38e:6b85 with SMTP id r13-20020a92cd8d000000b0035da38e6b85ls2185252ilb.0.-pod-prod-05-us;
 Thu, 14 Dec 2023 00:41:01 -0800 (PST)
X-Received: by 2002:a05:6e02:154c:b0:35f:8014:4b7b with SMTP id j12-20020a056e02154c00b0035f80144b7bmr732935ilu.21.1702543261545;
        Thu, 14 Dec 2023 00:41:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702543261; cv=none;
        d=google.com; s=arc-20160816;
        b=hMYPQ8kdpIlICpnSS8ON7xbkl46GNSNb7pODWITbsSiGMA7W761waGTeawdKCMsZVg
         vaVo/guiKR+UHJCHH3ca5RGBnb/yDZxghnMqu4SdCb+IknXN565zjbcRveN7aULm6hfO
         YAqF05qYxP6FWanshnpGrCOO8r3kjP7KV5kZH7/FD73Bv391gNi4DePs1G0QPjcJTIVU
         MCOZ0OYmZs5Jg12i0a7Jo9l3Gzkd3b5MwrKvS0z09JueCpUWgahsGTe0s6coHJmbnMfI
         KGtRjGmJhoc+N5coeIuZvwvF1WTcPLCK2V80cg/FbL65WSSYnhiHwk6dggIZdEtwQUgV
         xA6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=aQbR2JO/KFK5RF93JUmmx4V523VsDvrN1w2XiDVyh7c=;
        fh=f1eG24fLE50oJLlpN6q45mWEES4s7GsWvScw+XEiX5Y=;
        b=qihG9ST9y9SfbNH4IGh8DfFAWbYoW5DLuy1MvAPHgjdg9Tty+rCaq4jA4vbgyFAvrY
         fcYjR7tSI/gSZ1SETwVW/XuGzGE6JxNFBhxo8KbZV4gS1E9RN0nPT6ArxyCb94TpeEm2
         d9PuvcrZnXraQEFFJj7MYOw+uhyGovBC3nAv610NbA0HVhjZFxQSkPEK3DectKWsKj+W
         Vn8bDwc8NLKcQ3t+3XcisspwZxnpjbl97OvkXPHOn6gpF+OAh6MJkVRtzFW5aASQBELW
         T5w5GPOPHUl284BaiSquvYt+DSpZ4R9/q/otQxXzsiNVhOr2rq3S3MkpeeRKp+OCK2aw
         O1EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.166.171 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-il1-f171.google.com (mail-il1-f171.google.com. [209.85.166.171])
        by gmr-mx.google.com with ESMTPS id 9-20020a056e0220c900b0035c8cf634b9si1168276ilq.0.2023.12.14.00.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Dec 2023 00:41:01 -0800 (PST)
Received-SPF: pass (google.com: domain of dennisszhou@gmail.com designates 209.85.166.171 as permitted sender) client-ip=209.85.166.171;
Received: by mail-il1-f171.google.com with SMTP id e9e14a558f8ab-35f418f394dso21642245ab.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Dec 2023 00:41:01 -0800 (PST)
X-Received: by 2002:a05:6e02:1c4d:b0:35f:7629:87d3 with SMTP id d13-20020a056e021c4d00b0035f762987d3mr2870814ilg.43.1702543261164;
        Thu, 14 Dec 2023 00:41:01 -0800 (PST)
Received: from snowbird ([136.25.84.107])
        by smtp.gmail.com with ESMTPSA id o2-20020a1709026b0200b001cfad034756sm11747930plk.138.2023.12.14.00.40.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Dec 2023 00:41:00 -0800 (PST)
Date: Thu, 14 Dec 2023 00:40:58 -0800
From: Dennis Zhou <dennis@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 0/2] riscv: Enable percpu page first chunk allocator
Message-ID: <ZXq/msjihOEZAo3w@snowbird>
References: <20231212213457.132605-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231212213457.132605-1-alexghiti@rivosinc.com>
X-Original-Sender: dennis@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dennisszhou@gmail.com designates 209.85.166.171 as
 permitted sender) smtp.mailfrom=dennisszhou@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello,

On Tue, Dec 12, 2023 at 10:34:55PM +0100, Alexandre Ghiti wrote:
> While working with pcpu variables, I noticed that riscv did not support
> first chunk allocation in the vmalloc area which may be needed as a fallback
> in case of a sparse NUMA configuration.
> 
> patch 1 starts by introducing a new function flush_cache_vmap_early() which
> is needed since a new vmalloc mapping is established and directly accessed:
> on riscv, this would likely fail in case of a reordered access or if the
> uarch caches invalid entries in TLB.
> Note that most architectures do not include asm-generic/cacheflush.h so to
> avoid build failures, this patch implements the new function on each of
> those architectures. For all architectures except riscv, this new function
> is implemented as a no-op to keep the existing behaviour but it likely
> needs another implementation.
> 
> patch 2 simply enables the page percpu first chunk allocator in riscv.
> 
> Changes in v2:
> - Rebase on top of 6.7
> - Define flush_cache_vmap_early() for all architectures that do
>   not include <asm-generic/cacheflush.h> to avoid build failures
> 
> Alexandre Ghiti (2):
>   mm: Introduce flush_cache_vmap_early()
>   riscv: Enable pcpu page first chunk allocator
> 
>  arch/arc/include/asm/cacheflush.h      | 1 +
>  arch/arm/include/asm/cacheflush.h      | 2 ++
>  arch/csky/abiv1/inc/abi/cacheflush.h   | 1 +
>  arch/csky/abiv2/inc/abi/cacheflush.h   | 1 +
>  arch/m68k/include/asm/cacheflush_mm.h  | 1 +
>  arch/mips/include/asm/cacheflush.h     | 2 ++
>  arch/nios2/include/asm/cacheflush.h    | 1 +
>  arch/parisc/include/asm/cacheflush.h   | 1 +
>  arch/riscv/Kconfig                     | 2 ++
>  arch/riscv/include/asm/cacheflush.h    | 3 ++-
>  arch/riscv/include/asm/tlbflush.h      | 1 +
>  arch/riscv/mm/kasan_init.c             | 8 ++++++++
>  arch/riscv/mm/tlbflush.c               | 5 +++++
>  arch/sh/include/asm/cacheflush.h       | 1 +
>  arch/sparc/include/asm/cacheflush_32.h | 1 +
>  arch/sparc/include/asm/cacheflush_64.h | 1 +
>  arch/xtensa/include/asm/cacheflush.h   | 6 ++++--
>  include/asm-generic/cacheflush.h       | 6 ++++++
>  mm/percpu.c                            | 8 +-------
>  19 files changed, 42 insertions(+), 10 deletions(-)
> 
> -- 
> 2.39.2
> 

Thanks for the quick v2. Applied to percpu#for-6.8.

Thanks,
Dennis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXq/msjihOEZAo3w%40snowbird.
