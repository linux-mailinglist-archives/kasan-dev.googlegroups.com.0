Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYGM4L7QKGQENVUBWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D4602EF781
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:37:21 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id g26sf9973586qkk.13
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:37:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610131040; cv=pass;
        d=google.com; s=arc-20160816;
        b=hgTBD/sO0yn0lmgFKUjO5a2l6T3lENDXIyMcshaY4tvvYNnMXPCqMlRyaSKT68IrGm
         NLzXyAkHd3X4JosYxZ57osSWuIcQ/dhEKTQgnonOzoGVe4HH1s3IzdVSL1C0y8KIge/Z
         mUFyg2UL3Pi4gyFQV9WP0eSfI/h2X+kwC+03yYgTMlQTYzOpMDXS6JtAE1mEBwW0pPWk
         QidQr2SM2U5zcAV20QMs0o9QJB83Y+wKg4tHfjXbPvMEJTUdg0tMXdDWOBaKz8IQmpu9
         2ta1QYrvy3AQEz3TNfHE5eiLtibL9lMOiivDW/dnuEfWv8hU5FEwWIfFuYV4bJ6iAaia
         UoIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BsB0gYC4Y5fCjIUhLfrsa1wA8cidjcIXmmhr79e0+rI=;
        b=fzTN3f09uIimdljiECuMxcKS+kxCtzLbvkpYyZqYDLr8y30AZh6/3RS7O1/qKV8gXj
         KHMomv0y3ADi4n+SuryxP5+fiUPGZJlnQZDfSbu1M9rWeKa423NutIXZcF8tR8PxQatu
         pA+hw7q4nvowxvcDFXCYmnt4pCUyQNXpOlreihqPgCphWqILGv34II0JQhtVY8ZAhjkz
         vA5RsA8bWqmXHhBVNbuq0V5c5qIAysIt1fykrFGZltjfmRobayMVUF5bQEKabGju3Vbl
         SswzVP+7ainPgzCcfC7I6dABVz1UOvs1s1lbfzjaK7nMmSqZUlG/hFJPQuF7OFfvdLmS
         Z+gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eW2T0ERT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BsB0gYC4Y5fCjIUhLfrsa1wA8cidjcIXmmhr79e0+rI=;
        b=aRvXfpAcVu8pI/UCZnZhyk1pHyD98h1WO6a0UQBPn4kiYjJYd5rGZpSaRg6w8RZpQB
         7hchRqrRV5TeebDhKUOPAC9cLB2fjl9Xb2z8CDs/kUoYzknh6UklYP579HfUHFu85FHq
         ngy+jB0bEj+nIUjLcYFze4YN+nzfSKkHIMhCpBwspVij4zQ8vxEFZdbDZs7QzDQkIHV8
         cixY+LpAzYZaNe0WRPnJAMAJOT0F8R0Y5EtGTmhiVv1FgTOeOFi2EvySx7di9ZN19nbo
         Y+g54p3U6wcn+oGePTVbvK47p56TLJOW5iWzdd9NqYh+QJwpokvQ+wK1QiflCM7ezNuH
         Uh9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BsB0gYC4Y5fCjIUhLfrsa1wA8cidjcIXmmhr79e0+rI=;
        b=f5b+sKbLkqWtTPQdnkzkMLisRIOjiLhTS/rYW2ra/e3jtTRzT69jkCUo/eMfGcSAcp
         5RCs/xBh7Q4N7v4KTQ5gLU7MW6pUFLYveQoVpUKt7Ua0WIKHxJzNiU3uNFWC59kH4gwZ
         DfmqhNOWENHFLa05l4CEOGg/YcEp1SbELtejbfkdm4zpcd9QGkHbsT4ZfEQcsvUcm39c
         38sphfZ/SQIKJUbIXVVcPq1mV9TYQOyYJ7vpysc62yeNKuPDOJlHZjEQZnsDX0ioPcAN
         08KGmwuvgZB/cw9LvpZsfxoTBtTJVsNRgBwc+3e86+noScGyDSRSZnm3ygWe9RGfoki9
         m3Jw==
X-Gm-Message-State: AOAM532VLd85YcNnnc3p1GS492xOknhYvYy8SzUHOwgV2EYpsVrC30aR
	6VAVfq59VyBkDwRFsxmyFIE=
X-Google-Smtp-Source: ABdhPJxunL/4rG/2umObl9EI+pZiSle6qJxX4tXJDR7QUMvnTO7obzS0sCrUetMxef9f1bDsotCvYg==
X-Received: by 2002:ac8:3417:: with SMTP id u23mr4827587qtb.80.1610131040333;
        Fri, 08 Jan 2021 10:37:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5603:: with SMTP id k3ls6094849qkb.2.gmail; Fri, 08 Jan
 2021 10:37:19 -0800 (PST)
X-Received: by 2002:a05:620a:2047:: with SMTP id d7mr5088195qka.255.1610131039909;
        Fri, 08 Jan 2021 10:37:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610131039; cv=none;
        d=google.com; s=arc-20160816;
        b=iQhcbgMRfaZstk84QvEQQGHqbgIivGU6b01/3BdOSiETlbElCRrC7xVZP1aqdXzaBn
         DaBtoaQJumbAzPYvd6FziRwj6GVZOVTj/YqqFl2nphrAkAYFM8rkDZA7ewR4nIVKpnIN
         VUHQe3OzfLQaHognR8yk+ExoaUYJwyKjDYGvsuz0c8ScPu32Ceea30TszddlFE37gSjZ
         ImL8pmHT+Mc50O8ykGD44UNreRIRE+AGsRVWtnNWCAzzBW4DcVShLUAnzIjacm7QRluE
         qSkD/KhwGJE7t1gE/npa0/0XZVYzrnG3zghiCoUgEJnffCOBGu6ntJ9qfYL/Hs5A5boO
         6ufQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NdEgLCv0WcsMLswh+8Qu2jUrNvErOztEJExOtEtsP1U=;
        b=iuA+x3EPOLE8Fj1tB1+sf3AqdC/0+G6f0hUl/GZJWf/jjZqYEoYDHHJdkPHx3Eys/9
         zuDfTCHnQFeVK2WLvuVH0bfIoJ68fbl5r2UToVAh4PtWh+XDJTGOVbQgMSj6S4RnCfVN
         LqdJn0Bjf76jVaL2JpslgBvg+33PvKhKN69cbLi5/8qIdOEMSVEraNJI7DSsmqjPi4Uz
         QLt3UUYriyOxTkB9apWduZt3OSbqLN2Wi6Wtm/pyzYsfI6WCQMhdSIPMG09K3dJSNUer
         MZ+G1PtdPvQWwopLKENEvdZ2vPPqiHEgm8pMaaR34Ja9+CNry0WVGUfOr8fMrXEdJ0O3
         1d7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eW2T0ERT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id z25si459790qth.3.2021.01.08.10.37.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:37:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 30so8159162pgr.6
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:37:19 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr8354904pgk.440.1610131038922;
 Fri, 08 Jan 2021 10:37:18 -0800 (PST)
MIME-Version: 1.0
References: <20210103171137.153834-1-lecopzer@gmail.com>
In-Reply-To: <20210103171137.153834-1-lecopzer@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 19:37:08 +0100
Message-ID: <CAAeHK+xaVvvMfd8LhPssYi+mjS-3OVsDaiNq2Li+J7JLF6k3Gg@mail.gmail.com>
Subject: Re: [PATCH 0/3] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eW2T0ERT;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::532
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sun, Jan 3, 2021 at 6:12 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
>
> Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> by not to populate the vmalloc area except for kimg address.
>
> Test environment:
>     4G and 8G Qemu virt,
>     39-bit VA + 4k PAGE_SIZE with 3-level page table,
>     test by lib/test_kasan.ko and lib/test_kasan_module.ko
>
> It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL,
> but not test for HW_TAG(I have no proper device), thus keep
> HW_TAG and KASAN_VMALLOC mutual exclusion until confirming
> the functionality.

Re this: it makes sense to introduce vmalloc support one step a time
and add SW_TAGS support before taking on HW_TAGS. SW_TAGS doesn't
require any special hardware. Working on SW_TAGS first will also allow
dealing with potential conflicts between vmalloc and tags without
having MTE in the picture as well. Just FYI, no need to include that
in this change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxaVvvMfd8LhPssYi%2BmjS-3OVsDaiNq2Li%2BJ7JLF6k3Gg%40mail.gmail.com.
