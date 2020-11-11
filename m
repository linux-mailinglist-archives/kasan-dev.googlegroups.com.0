Return-Path: <kasan-dev+bncBCCMH5WKTMGRB35PWD6QKGQE566AFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 24E6A2AF708
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:57:20 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id f9sf2118119qkg.13
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:57:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605113839; cv=pass;
        d=google.com; s=arc-20160816;
        b=NiRMuyXZrM9VLVBZSCwHc2cMPL8Yi+eB4Yn0Q3t9c+hotsH0prGKvJRN6L3eA6Hgb9
         Jhixz9VisrhbBLCi3i7V9XnoGmTtaJgZchf4icUI4g6xixfRfUjPdtSzfLxTzBfnuQYV
         +ast/1rMF7ExoxMsZW+uN7Oj8ZVv6+dGWZ4z84IWmZJTWpdSsLrtFmhNszfiAcmyoBOq
         YtcLAyVqYBywkZeNhyssHT2BQQg/cYieaPlgHKt+YAV5zUNVwTXfhjXiuzi+h8lmOM6A
         QTojVyMEyqnIzHXpVvwiqJQ5VeTTrMOCm8Qa5tbPY3jrO+gLdG4d4JgIAAzPnAvECuXk
         VrLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E+9mreLVBdZqaR4Kg3EyOFYH7FtvWwQV6bfVFed4g3A=;
        b=ZRnm2oQ3pJYKyve1eRDWMus+6aeXjm6rp1IbrkrYc4nNMnTeeuxIjssDKF0KIDjYXI
         Xq3pw9lJ3HDkjv7ZZHeDnxCJADC6ydlFz8/B6+Byv9TRQ0YMlFhHC2XxkIOO5Km66cBL
         ag4VkWJf2OYuwh7j7jVmfthN7Q+4NPxBc/xmp8S5lNzsnD2pR+7c8dLKEXjN81BnRc0P
         5sy8uY6ec3BMmS5pITG0Dh49ACdX+nwsJtjXC9pGmzq5b7nrwdJHtQZoQj24SiZRAI/r
         egQFlg/dzLGYL5PfKBrPLNMubQLxplNGcimRwvhLEsVWcmitPHNBRd6p8RfJ0FCTx3eu
         4+QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HRDAD/hw";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E+9mreLVBdZqaR4Kg3EyOFYH7FtvWwQV6bfVFed4g3A=;
        b=EufU7xZTVTuCw07IdiV0Ra08Gw02OIWwCQhOOzPbjOzioUMnBoOP8MoLb3DwXmxZRl
         KXotYYEML5gfXefK3GA+06mtRo/PxwL9MmDlr4Qh0vLINibSXvPl2P5PvjCsQWw91ctz
         oGdzUtsZPOSHefHH16p4bk3twFoD2KNazJzKV4mLlafaucGwWZmK+AaKewuN1ynd9w0c
         AoVVI+kGTrkqvK3IOAETycWU0GgELD+lukPLvV/w+6c6j6EcmIh6nfc5p8uxcIY4zVL4
         jasUdAr1tHb+8wFUnygCUe9UCyB5M0kXRZNBRA2oaj5R0T6iy+2ICcFGjSte7FYjbRFE
         T3ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E+9mreLVBdZqaR4Kg3EyOFYH7FtvWwQV6bfVFed4g3A=;
        b=NaBpwQPJZ6KKFmatWlEh9U+C53b4Xr7FVvB9zvkaKIf4MqAP0X6ExGZFDijp4la2r4
         ODrJFbTm7B+fnDD3oSP55LZDo2vKxhmOyB1QDM4kMzzPf1ECwqPn8+vBEqHS8l7rDSk+
         dTPv1Tw6wkqklKE6BwelX7p1WV0vc+Sz4LAMx5GQk9y+uvhbByIojAO1JbzNeKxoiVsD
         QYgAGNGWIYEod4pFbOdm15GRIpmLbyueITtD+nSqICoS6RpNPCvow1ajy+KOXG4jq1Ro
         h/E/azAlaTSl4dUgVwWjOwXvikywgaYcK4HZ/QZVtRGTD8hgwHPzQomOEJFnr+LcKzsa
         z+Mw==
X-Gm-Message-State: AOAM530B9sh7lE/QojGCX6z5ILaMFwups6j6GiqJ7hIAnS7mhJF6wjqX
	jTT4e6d6DFHKyBXSYDliSzs=
X-Google-Smtp-Source: ABdhPJyVNWNmBg/EOOyMNcbouq1e6ZBHo20N6t4wURVAx4smgn/eZPyM9y7BldL93AAafSDWWZYjeg==
X-Received: by 2002:a37:9441:: with SMTP id w62mr26095023qkd.474.1605113839183;
        Wed, 11 Nov 2020 08:57:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:abc3:: with SMTP id k3ls18194qvb.1.gmail; Wed, 11 Nov
 2020 08:57:18 -0800 (PST)
X-Received: by 2002:a0c:eb91:: with SMTP id x17mr10180722qvo.36.1605113838728;
        Wed, 11 Nov 2020 08:57:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605113838; cv=none;
        d=google.com; s=arc-20160816;
        b=G0N4B6UJTqkPXBx/qQ6ovTWh7wIAux6kzeU2J1w4PJ5ZDKj/aLbyybQGz0i3Tk1aCf
         DFdSMayxhrlbBvG4Iw+1umeZZd77Z7XySJAbc/UCXNBNUIPsTroodIspj0oFbzjJZq1j
         ItxCP8t3HAjQWEhXgEzGdgKdSKWMNKaJB6Y9L/ZsprMr8mm8b78lIG/QfQp+NqLzdOxr
         08kyl7Vvrr9u2yiPOpn9xJAnlwOaRe9DWUpjr/AnOPjoN/3S4mvw5NCFJo0LD0QexxIF
         N59eCT/SNZsosozy55nxQ5YgLmW5LeLqbGgjmwMSfWJKcm6cUL8FDtcn/E5uc2wqozAe
         Wuaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yelVk1suTz9Rsjb1IsDRFFlgbkKWxRF4BCpHMaeax1Q=;
        b=j14bn4ExaUhBIfAAej9ZXnaxSskVvRDUzstxqSWk9Tu6dumZeNckOvFXi02x9d2dTq
         uooBatknWS0qt7i6t+TCjkJdFiZu6im1Leb6HDIO49pxk4Lz8pzJPRmgy+Q6KUheflQO
         WbuBQWwLkKZQ/UnIgm7jtpGCq4+Nu098Cp1TUiv112JrBDz/sHFZ9fvUhMX69o5IxstR
         HL+crFWOJxzss7381LjK2Amntx1DvMPdjFe/0KyhclwRU/lyoKG25LxBtF+dOOzywlUn
         5tFQwAzpsKKoTLBK/PsURaA3naBVb4GTBrIbcIKZK4nrepsHW4SbYHYI55M/eBBmkc1C
         kulQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HRDAD/hw";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id m21si163364qkn.6.2020.11.11.08.57.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:57:18 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id 11so2306744qkd.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:57:18 -0800 (PST)
X-Received: by 2002:a37:4552:: with SMTP id s79mr19890977qka.6.1605113838237;
 Wed, 11 Nov 2020 08:57:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <e9077072bcdd4ccaecb1c84105f54bac5dc6f182.1605046192.git.andreyknvl@google.com>
In-Reply-To: <e9077072bcdd4ccaecb1c84105f54bac5dc6f182.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:57:07 +0100
Message-ID: <CAG_fn=XvXDe=+wuBNBq=fmidZkghNx_g6RbHRjgMMa658_1LXA@mail.gmail.com>
Subject: Re: [PATCH v9 43/44] kasan: add documentation for hardware tag-based mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="HRDAD/hw";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add documentation for hardware tag-based KASAN mode and also add some
> clarifications for software tag-based mode.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258

> +
> +Software tag-based KASAN currently only supports tagging of slab memory.

I think the reader may confuse "slab memory" here with "memory
returned by SLAB" (as opposed to SLUB).
Maybe "heap memory" is less ambiguous?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXvXDe%3D%2BwuBNBq%3DfmidZkghNx_g6RbHRjgMMa658_1LXA%40mail.gmail.com.
