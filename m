Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVOJ4L7QKGQEIANXNZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A28A2EF757
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:30:46 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id j67sf5760060vkh.15
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:30:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610130645; cv=pass;
        d=google.com; s=arc-20160816;
        b=nkpmjrDuS+UuodvT9w57HyNVKkIchSLe1CuS3Wy8G7TZ1RkZ9EUhs0IOkZ4ctHz23i
         iwMCL9UPf8vuOanrX1Au5vSuugq6MB8kXaSKzYPPf0Se/o0HigqI/mOAI/QIo1uLZBXV
         ihPN6QA3CgKNCfrHcbjZzgrA64eQ5FQ97Q5x8FDIbhHi9euhfFtl443JVAZwODQL+17q
         uJueQLOi7qWidAyAEMw0gnHPiAgYY4wodKxIcpCY9YM3pM1FH6Vvu8dkHPU+i1DJMeFb
         g5eWBJcI1G/pgPvPip/tQ53xhbR9O5NDqlxxnUkzxITqvKUVzx1dBsSeycNN4HL3oIn8
         S7wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WeJZXyXma4BIKLnmu4DxUJve2BV7pKkZPLj5EP7C4Hw=;
        b=kHH4dulROXgWcVplleyUyoX6XWDJhbOZwHe7cwpI4qqQRsltujTLzyznPn6GpIWzam
         A2zyZIkCEMtZgSrLtM7kBlq9lDPnmDPU+Qi0ncJF64oPP7GWdx26h4i//5QW1aufF+7f
         RJdmaVN2fLYAkvClBgkTU1mufhgiNfJCQzLOMdTOHgW1TXKwZqugWvH+kaWMMqCfpw4S
         wqOceEwq6oQaJAl4XOB3zyyL7LBj3TzmD2Q8WGByRxegsDqcsgxiEXRFflrps4Z+tcfI
         LIIH7jIGe///tN2V+X7YENsqnFjPKqhYH+s8F5hoKXjunanbZ/hX1W1hn8cN8HAeRbkT
         OYcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NtitF2di;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WeJZXyXma4BIKLnmu4DxUJve2BV7pKkZPLj5EP7C4Hw=;
        b=neySoRDKaahcQfjQY19hIj256/mWm78AztG6mIPNOpMNrpJEQKb2jAy1oNNRyCky44
         +JYDum2j5erXbmhlnKdJOC0m3yHQdN5U9Ld+Quhm0Rs4MBoTHTgLceLdwvpJmenHeIji
         m+Pd7MpBGRSbiCT0ogtbQYmgoBlqOpTbicD3ljePYc9NA7wQLnqS1x7C9JVA5nrGKQrN
         HfVr1+GIZ3yjPQ7omzSUKA/NHN35P1xzk2FyHfn9h/zmvLlO/kLx/m9oyPMEPRKlOCrF
         aPwEJILBecNmHboIeR3HgA6qvUs+yC57/okProDLiX9PSvTaDxQWQj/uTXjqFgjOJoZg
         dYdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WeJZXyXma4BIKLnmu4DxUJve2BV7pKkZPLj5EP7C4Hw=;
        b=oCgTcgII/A/1BErplGUVvaswXXpSU9HQ7CvQRvB/qZ4CaoTttOiH/QxhBMgRNTd7Km
         Y3QmS/1Sxus0b72VeYRx5sizyu1AP0UgslmzqQRTltF10cP4S49mGdR/FXSd+HXQlM1C
         PDWDLen8YWvQyDzSgWRbydEX0IQk/GeQLxPOjoadNltjm9f39qlAz6alhglfWqSY7AEa
         AncP2cHn0hKtpGAfq9NS2lcbZfSNTQ7s1B1NfAMdIuxJXYb2wFhnKeKeBu4Py+itNCV5
         LmwcyQIKm2n6pGsaC1yUC7XaJkREqSQqKQXU2mx7Ej8/WbVaYvJRP1bT4bNrLMyDwRMf
         a4LA==
X-Gm-Message-State: AOAM530mjo/liyQSAV43HJEQWvF3MXrbTNYQLwqYxv+P+dxRK5PFuHpI
	7hcFwwyzNuSBMFx0/ZY8vIM=
X-Google-Smtp-Source: ABdhPJwlbG6D6dFxvd3ekwAN6Vr6QLDGdPmedXnqrZCgPFl4kYXN7QFzDgvxceIk0j0z7SPrueqhVQ==
X-Received: by 2002:ab0:480f:: with SMTP id b15mr4211324uad.103.1610130645512;
        Fri, 08 Jan 2021 10:30:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7843:: with SMTP id y3ls1006032uaq.5.gmail; Fri, 08 Jan
 2021 10:30:44 -0800 (PST)
X-Received: by 2002:ab0:14e4:: with SMTP id f33mr4092578uae.142.1610130644934;
        Fri, 08 Jan 2021 10:30:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610130644; cv=none;
        d=google.com; s=arc-20160816;
        b=OhBOP60GIB7KKOcYlgcfO1TLgTarP4gGoMPP7sCAQDTHl6mxcUvAKoQYScaJf6FUE5
         M+a1e5xs9Ik7Gat2WsIswsA0ZrMHg8d4SCtb8nMs4Se3GbTKNybzD/JfElU8rZmwjKju
         yh6e95gi8q5bX3ogzV7RD2FrUJ5j+MI8+98A+i7pS+VgJMgniNml2XOLiGoBgIxpsAwb
         Cwn1QxhiinoJTiK/H7zQgjf3zgsQSv0huWHaRpl0PvxtoFLDaBcjNx7YAybZ3W5bCy8R
         o3I/jopkWl8gK+9QCSMPrAWPM67l7r8iO1rn92d0u4W03f8GlDuAU8UxxMe9Sz8xTfLe
         2nmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QMtgJrbmi2Dq7xj4bsuhnhgijvRCuVpV/hWagawzWvg=;
        b=THeXTO+oeUm7Ds5R47whwPFQllPl+UWOOPevZlg7dMjS/Ca7b7FkVZS1IWovbM2E1n
         xezBCR0lrzZnw6uT3Zx4BXlFOIDm0uTY7J1muvAziuL90huvpUNGWat1UxZQA40Zs8j3
         6prbywVM8T2jqE8gSab3fLjijtNgeDNJ0Aw24qZSWo80jSSeVJbtZqZIBo/i0epM7VNh
         HsLkCjq8clJho/KrRCkhcsBwdcEYxj/FQZBVNxUaGe+Aa5NrFqWR4itRCkBA6Ur95Pgf
         AEYGXnnkOzsRB3wcAsQi2XZ2xH6yOoiVst3TkeWw9ewetb47sgY/PQEroFiZR+BuwzbH
         NNHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NtitF2di;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id y8si371951vko.4.2021.01.08.10.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:30:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id c22so8107401pgg.13
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:30:44 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr4942892pfh.24.1610130643942; Fri, 08 Jan
 2021 10:30:43 -0800 (PST)
MIME-Version: 1.0
References: <20210103171137.153834-1-lecopzer@gmail.com>
In-Reply-To: <20210103171137.153834-1-lecopzer@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 19:30:33 +0100
Message-ID: <CAAeHK+y=vEuSe-LFOhxkEu4x0Dy2jYts18R0V6Pbv1-5Cwg9_g@mail.gmail.com>
Subject: Re: [PATCH 0/3] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer@gmail.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Dan Williams <dan.j.williams@intel.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mediatek@lists.infradead.org, 
	yj.chiang@mediatek.com, Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NtitF2di;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b
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
>
>
> [1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>

Hi Lecopzer,

Thanks for working on this!

Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>

for the series along with the other two patches minding the nit in patch #3.

Will, Catalin, could you please take a look at the arm changes?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By%3DvEuSe-LFOhxkEu4x0Dy2jYts18R0V6Pbv1-5Cwg9_g%40mail.gmail.com.
