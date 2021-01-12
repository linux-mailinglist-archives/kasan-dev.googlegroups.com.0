Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHN26X7QKGQE4SW2TXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D68102F29F4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:26:06 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id g9sf710437ybe.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 00:26:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610439966; cv=pass;
        d=google.com; s=arc-20160816;
        b=d7U1xHDaDeLXGOyfblN9q8M+4Fs+X34OGqaa/nZAQxfow+4k6u1C3IdQzVoE8a6Ywj
         XAm2rVkHXuCvdThNC2DYilBQZFf/LhyHp4jgiIWZ6JBO6y8ibDBksNGrOCB85aJ/KfDy
         /P/vvheBiy4+TPJ4Hua/wF3WQ+m4jdrC9Kt/2S/FduSch8Y5ToHVSuflET3RrbINEi2H
         wx/guAc+ygphU8N8IewWuWV0Txwy8wMZKHoBtMPIZF2oEGZPTpoL8igxm1sYHoVG4l9Q
         1z+Q9seNjFRRuIcheDB8OdjYs8zQ5YmD4ChAHp+ixmUwaY6uyAKf+gxfFyDsEi0mi5D9
         fh2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4ZDolTamwHtRPQgQYPoN/3B91Taj09klBTyH0ZWXjmI=;
        b=MTT1yZz4PszdVEhtYpd74LFLpYUrwmSBBRHNNKSbGUI6QF5YYbgZlypR0Ex9DiT02J
         yvJhhJJkpI4WNfoWqdfYfWJy38GGYwQUFaD6K1RFTN/MHz7Cybww5a5SLDUoB06acgAy
         8D9yWM5SoS6mCDvJxzOHgYCLnZvqs6OTuJrosycEJX/rhtiStqj17Q+CZ4TkWAqoIREA
         OEZznAU6RaqbVSP2zq0RO4RQEe3WjYCLpudX/u4MZwS7WVowL+od9egn+N91aTZeJkGu
         Odnd6dveOXfRxvamO8tCTrqZzcoXDq4jUR1qmZm8tdxCArb6iBZwAgH6k2FTRr6MSrlY
         2rfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYTicqMf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ZDolTamwHtRPQgQYPoN/3B91Taj09klBTyH0ZWXjmI=;
        b=JjEkvakW0j7p5TfN8Yo44YkMhrMCoPlPkALGLA2DX7OKfWFlriR1ngwH50alhec+3z
         semFb294n617JGr/a/545uIB8PgyQz/QTteKf2cRVomfy4Diux5piYHlmg4U4dbWEA8N
         Jzi9hjbT6q9tvN8bPraBYdixiUSAyl8yBhvlPJWBuLwuq5TTeGynTLMtgxcOTiB4+6AD
         zd+47sixwkbbCvkz1szyWr/c2EZutVM16O3UzdB7LcMYM6Eg8Awq7e1RMcEMtj03NWKp
         dMFBBRS6a8tdviif6VlI3nO4D/rWWBm2ggxr5FCRBJgJfZ9iVy0T2W3ZVvFJa0SK9LcZ
         L/OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ZDolTamwHtRPQgQYPoN/3B91Taj09klBTyH0ZWXjmI=;
        b=lb4OwxMOrG/jbEHEWIyTrkh2VR8dfwBtaJ6/uf0oN+NU92BAO9dBTsF1+IVyVyL2tE
         QTy/3mdrPnqcb7W1fJypNOmKyRyj8bO6En5+Jf83pCNziPfDwYbRDxtzhOcXbqdiBNJv
         aflXwhbXO8/Jj67kJyrsRZ7MQNcgFsIvGFPrFI5I94DBSw8nyDFz0kQ8RfJlLA99WvLU
         x8qAM0cFkZINa0CbkAl1xI4fffIDLuyaEce9mdhmePJtIVscnoSAfXfDHOCZXCobCNRX
         kREPbF/mJ7WOAKlybJQECKVPJmThQSBPCZlaDepNmZrQGo5iP0GyW9fPL7+0utEJf3Iy
         KCAg==
X-Gm-Message-State: AOAM530L4P87AnEKIKaAeuJxMIpOF2bUj4FKTd1975GIh6C1V8Yl1ZoD
	ZmSnVTKqYjI8JmC8eWqQCw4=
X-Google-Smtp-Source: ABdhPJw39N1hBQCPvosu3jVRHGPNPCWvY4ralqR8Qjnf6aiTG4gOlz3OXpWMpSo6QuWIS7cHwdohNg==
X-Received: by 2002:a25:7e05:: with SMTP id z5mr5247787ybc.497.1610439965910;
        Tue, 12 Jan 2021 00:26:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e407:: with SMTP id b7ls1210843ybh.6.gmail; Tue, 12 Jan
 2021 00:26:05 -0800 (PST)
X-Received: by 2002:a25:e708:: with SMTP id e8mr5291987ybh.174.1610439965477;
        Tue, 12 Jan 2021 00:26:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610439965; cv=none;
        d=google.com; s=arc-20160816;
        b=UZ4Yf2mr+w8b0Jch7IcCKbZNVkxGMgy5UVFAJpoL0kUMfMdV3u2Nz4uw2vj673r8fO
         WFhxe+7G0+/OmRYCaIAXPj5sq8nsx8yZV4FAPqkiEMJRDBg8Tr7/By+HIk1nO77qHmu5
         FHEWEIhl+hsb6hAmm9STPC5CttqY1vYALC3wVcTp2H5bJYsO0u4bpxg3+jQzClGQ8eib
         0RxYkBLL4C6si8R0jvP3nJzT2hoL1+mpTuQWrdUCMjsQkGHVqErANrlZPxayhCJo9HR9
         IIEcSRhn2kXZCgK83zstF/PfvwfBG6vT0HtN7sQLD2pdOptgdP7cEPUY7hehYBjg4ASH
         W9NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u66Zz7BdRS7VV/vrWqqvG+i4Lg5S/n1M+J8zEYi5Ao4=;
        b=zvFTTH5Cep7rFYtlu8etoZ8pZ/YqhzH9xgorTwd3s/9/9p64hevM5x8Lejlp6m5ffr
         6ubFBn/dKGGcDH8qQmhhXHSmUncDxcZY27P7+aalLmCGVzVlw+G9xBMXCWbSGH387LIC
         Hw6OKR+YeWgIBov8D44jweFLVo1xVEvzyfT8L6rxsU31deBuXQzenyby+YUojthYMQcK
         5UkkByToIHmyqqL80gpJxpPFrDnHJm2l0sKJRol/tiiKckzalvuSE32VjHJsllIBzfRl
         LN6KsbiHJOVFy1Y0DnYcOGGszOQ4+QiSmSlnkYGjMQvgVTQpt1dKLkRCDuZ5ceR6vqFi
         M05g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYTicqMf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id e10si286570ybp.4.2021.01.12.00.26.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 00:26:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id z9so1075215qtn.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 00:26:05 -0800 (PST)
X-Received: by 2002:ac8:6f32:: with SMTP id i18mr3418479qtv.175.1610439964938;
 Tue, 12 Jan 2021 00:26:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
In-Reply-To: <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 09:25:53 +0100
Message-ID: <CAG_fn=X0YY8+FUWWyLqGUu5Z6-eEaSAOVGYj9PKzhzqyA1BvsA@mail.gmail.com>
Subject: Re: [PATCH 08/11] kasan: adopt kmalloc_uaf2 test to HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eYTicqMf;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82c as
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

Nit: s/adopt/adapt in the title.


> +again:
>         ptr1 = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>
> @@ -384,6 +386,13 @@ static void kmalloc_uaf2(struct kunit *test)
>         ptr2 = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>
> +       /*
> +        * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
> +        * Allow up to 4 attempts at generating different tags.
> +        */
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 4)
> +               goto again;
> +

Looks like we are leaking memory allocated for ptr2 here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX0YY8%2BFUWWyLqGUu5Z6-eEaSAOVGYj9PKzhzqyA1BvsA%40mail.gmail.com.
