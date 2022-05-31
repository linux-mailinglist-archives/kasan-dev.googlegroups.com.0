Return-Path: <kasan-dev+bncBDW2JDUY5AORBX423GKAMGQED4EZLKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id B7C9A539554
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 19:16:17 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id n8-20020a170902d2c800b00161ffe6804esf9168812plc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 10:16:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654017376; cv=pass;
        d=google.com; s=arc-20160816;
        b=qZrjdThCE9ds0vI4P6SZ5T5bagGhQD+LdfACOSy7pRXxhjs064hlinq2O7gg0QQTxS
         NlJydtD5jcrGDdnXd+eVgj9Z1oz0xyZ9rArJ3Dni8s9z4lO5HSk18toyJG89Xcq47PkX
         ld1N1lM/mfYc49dXMPNqvNiUEl+8equOkl1tPQZWeqr0L55epEUhNS0y/SugRb/yVDK3
         Pfg50BPKVavM8MEGusGokghGaw4zt0YlPglDoxFsAp4+uHkhwS7XTlQlIzp86ZllBR18
         KvwRA0vrVJPJTZYM9wH1rAjYAAhR+/MLMqpy1Ftl2XvlVWTxZVh2mpjWI6ulCZquaoJF
         C46g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0F9cZc5z5VRFaVwHVWNCyutWSBdDd4HcJaMcDSaSz2o=;
        b=Z8Mew99aCSTWO5fpLduq0I2dY3t6ltcrRvCMaAeB5PXgADFMQmMX5FiHoY5Q1Cg8kq
         NUUYQtuz74vG7FXRpLATKd1+yoY9+HxmRycN/UtrFRYs015VbbX+g62PfaS7JyLprmA6
         rAtgkUhSWFxCRYlbiNCeEKMWkHDdX8B+fSqWg8aYhE7CdUhMMNnvR/CXL04jvUbPTKQn
         Vw7b8AdlLF8LEQJbt582bmbb0w8IIuc0ocLRsQVx2ibWOhsjXflFdbygBoTl/S+i4qGt
         cFmE65zEfYv/gTWAcFDqAaTsFwV2Nf0b9m6Jwz3vgz0rQZ11E7qkwu3EG1etES+qTlVN
         cBDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="EWBdzD/W";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0F9cZc5z5VRFaVwHVWNCyutWSBdDd4HcJaMcDSaSz2o=;
        b=fbandn2VvjPrp9ukXvkVP1FVBDU1w9DxEBKhB8M7Wg7W+rVF9KdTPGF6lZ/NQWyV7p
         yjn4HPLkJoeWxgiekViECzdXSIA17uDHuTAawPxjUsEY+8vvPxvY+lBUGgxrHNRq9xEm
         T3MO4Be9CSQQGjt16f85qfeTkwZoagosNTh6f41Duh4+ukMHb8tNXrLQ3LRQET9KGRCh
         Eld4+S9OeyVdp7KZbTKKcbHib0Ah0PSKWKqidY+ybwUOfwbqxkJN8j4lHT0bfiUw9u7G
         nQsFLkIPmGqcihZ6IEttd3OxrUU4yH4PdezcpyEg6J7yt2PvVoXM71D6XcUfowGyrcdm
         jEVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0F9cZc5z5VRFaVwHVWNCyutWSBdDd4HcJaMcDSaSz2o=;
        b=qSbLBT7/pZkLqgGeNRZnU3c/YriZ9le7tl42NhV1u/q1KU9HVgWizzyIq6SZBlunDR
         I7HE8TtixHvJiW/RUwrM8jp50AAcKb6Z02Rc//l2zk/MWe8qItBu7PY3tice9t+f0zNX
         oKkhrbs8R2eWJQ/SNXuon1lasGEjMGQr04tTWVnGOliBB1RUjbbCL4E+QTC8BYpX6NlT
         7Mdrq7hmXpFV8YqDobGKx7jmabIR3LWs9erZDSGN2bWH8ayZMw/fd02JyPxUjf5gX38b
         J7mro7bXNLa3319wg7KwxJg+cPrqaSX2VaXSG4arGblfczKzXnr6NV4efKrwFDxsGj93
         D3IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0F9cZc5z5VRFaVwHVWNCyutWSBdDd4HcJaMcDSaSz2o=;
        b=v57teoU6VIE6PObfPK4P1RfrkU4QqWz25gukVt5BH5xXjCbDlP55T9yWS6OR7CoHnZ
         OdkPkc9wcJsbUf+vsFmp4oLzfUp/8qK5eWamGhKHg170hovDj4MO9yNsGpNRpNfP1MsU
         2y5kR/kP/7asp6DkaHzudbyJdfXTVQJxKErCnLUfk3pacePMUgJZJZJn73WEVmnkvFmo
         qWGI1m/RGFGBFS0EMBdVxOyaPDsKxaSY7wlb1oo7qNH1Uq2I6WjZ7pfA6oMYZ5XF3qCB
         L867mXBzjHLOwYz63nlsZnMp77NH/Lo1GN/QWnaFTfKWhpLjQIyyQw4i/OZMwkVgAJTS
         z1cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UWjeWQU+bIM726HKPM/pQWBFm2JhZ7pVDljqQ4A3RaSwGKiqE
	5FWeHT51/yZDMDSeF8Md+tg=
X-Google-Smtp-Source: ABdhPJyONDa8GyG+POTPwZLeE+apVw//nJf3R3S1eQOPQ37ievwYjueMaPFQ1VqbYiYkUz9CxB/rEA==
X-Received: by 2002:a17:90b:4b4f:b0:1e0:33c1:59c7 with SMTP id mi15-20020a17090b4b4f00b001e033c159c7mr30188698pjb.131.1654017375844;
        Tue, 31 May 2022 10:16:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d506:b0:161:d3bd:ebea with SMTP id
 b6-20020a170902d50600b00161d3bdebeals326009plg.0.gmail; Tue, 31 May 2022
 10:16:15 -0700 (PDT)
X-Received: by 2002:a17:90a:2f84:b0:1dd:940:50e7 with SMTP id t4-20020a17090a2f8400b001dd094050e7mr29496216pjd.210.1654017375111;
        Tue, 31 May 2022 10:16:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654017375; cv=none;
        d=google.com; s=arc-20160816;
        b=VHmzFE84FnZ7rpFQka+K9GHTAgVtc3rS6EeM9KRkIWyK6W1GlgDa1K8ehbU0Mb8Ibu
         QWTOkDImIdkgm+/ErRFnC22a8yGE9ebuA8JhwqXlDse7LLRMqRZl1bnGA0XIx2ovoAfm
         yAqU1EUTid8rIFvWdK7U/IVB5SA4e/Fdy1Oqgq5UvtUisNMH0UyOm8KlPk+w76Bt8tmS
         Whxl68f7xj9YId4vzl9kg6vBOZrw61zb6ow/SOefMQ8vS9nJ1du4Bh9aDiGiNI3ea01s
         heUvsefHq+BaMjDby7GPt4lhmpodSQY4lzqZtnPcEb0A7t03XDYQ4Qfz6nhHMgDNWw8p
         vVRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VRR/7w506vBh7WOgx3P+Z/7F/uNHjpGKlcsdV9A5CEQ=;
        b=Kl1ayGELWMR7HQyQy105kOy1+/0jFqqG3yLELwA0FWI1wLMbIRvSIDe48rwQSCi8cb
         R/UuPSJwaIMB1wZU7Y3cDQTWueHUeWIFHd2HYhDMvSaP7O5DwdOcOVR2yyH+2ZUG9QMb
         mTyTOKVDyyxVs1sbkF7ejUIKgKosawr5krwEUggFj43q8F4X27r23/Nw87W9LsIetEXL
         ws5veQt0rti4jslTBg9PNF6m45NEUCp3FexmnZMgsXUlO22uvVZ+Q2ePPNm7ZCcQWMz1
         ZBTeJ8BSQL3MV2VNKmXtgAlf8Fuu1X5xCObIgoZ6kE1k4r0DPfNtIQKNVkeX3ueFq2zH
         l2aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="EWBdzD/W";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id iy11-20020a170903130b00b00163ebd072bcsi214865plb.6.2022.05.31.10.16.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 May 2022 10:16:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id f7so3576011ilr.5
        for <kasan-dev@googlegroups.com>; Tue, 31 May 2022 10:16:15 -0700 (PDT)
X-Received: by 2002:a05:6e02:1c2a:b0:2d1:9e4c:203d with SMTP id
 m10-20020a056e021c2a00b002d19e4c203dmr23852118ilh.235.1654017374514; Tue, 31
 May 2022 10:16:14 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
 <YoeROxju/rzTyyod@arm.com> <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
 <Yo5PAJTI7CwxVZ/q@arm.com> <CA+fCnZc1CUatXbp=KVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ@mail.gmail.com>
 <Yo9xbkyfj0zkc1qa@arm.com>
In-Reply-To: <Yo9xbkyfj0zkc1qa@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 May 2022 19:16:03 +0200
Message-ID: <CA+fCnZfZv3Q-2Xj1X6wEN13R6kJQbE_3EgzYMyZ8ZmWogf28Ww@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="EWBdzD/W";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, May 26, 2022 at 2:24 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Wed, May 25, 2022 at 07:41:08PM +0200, Andrey Konovalov wrote:
> > On Wed, May 25, 2022 at 5:45 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > Adding __GFP_SKIP_KASAN_UNPOISON makes sense, but we still need to
> > > > reset the tag in page->flags.
> > >
> > > My thought was to reset the tag in page->flags based on 'unpoison'
> > > alone without any extra flags. We use this flag for vmalloc() pages but
> > > it seems we don't reset the page tags (as we do via
> > > kasan_poison_slab()).
> >
> > I just realized that we already have __GFP_ZEROTAGS that initializes
> > both in-memory and page->flags tags.
>
> IIUC it only zeroes the tags and skips the unpoisoning but
> page_kasan_tag() remains unchanged.

No, it does page_kasan_tag_reset() via tag_clear_highpage(). At least,
currently.

> > Currently only used for user
> > pages allocated via alloc_zeroed_user_highpage_movable(). Perhaps we
> > can add this flag to GFP_HIGHUSER_MOVABLE?
>
> I wouldn't add __GFP_ZEROTAGS to GFP_HIGHUSER_MOVABLE as we only need it
> if the page is mapped with PROT_MTE. Clearing a page without tags may be
> marginally faster.

Ah, right. We need a dedicated flag for PROT_MTE allocations.

> > We'll also need to change the behavior of __GFP_ZEROTAGS to work even
> > when GFP_ZERO is not set, but this doesn't seem to be a problem.
>
> Why? We'd get unnecessary tag zeroing. We have these cases for
> anonymous, private pages:
>
> 1. Zeroed page allocation without PROT_MTE: we need GFP_ZERO and
>    page_kasan_tag_reset() in case of later mprotect(PROT_MTE).
>
> 2. Zeroed page allocation with PROT_MTE: we need GFP_ZERO,
>    __GFP_ZEROTAGS and page_kasan_tag_reset().
>
> 3. CoW page allocation without PROT_MTE: copy data and we only need
>    page_kasan_tag_reset() in case of later mprotect(PROT_MTE).
>
> 4. CoW page allocation with PROT_MTE: copy data and tags together with
>    page_kasan_tag_reset().
>
> So basically we always need page_kasan_tag_reset() for pages mapped in
> user space even if they are not PROT_MTE, in case of a later
> mprotect(PROT_MTE). For (1), (3) and (4) we don't need to zero the tags.
> For (1) maybe we could do it as part of data zeroing (subject to some
> benchmarks) but for (3) and (4) they'd be overridden by the copy anyway.

Ack.

> > And, at this point, we can probably combine __GFP_ZEROTAGS with
> > __GFP_SKIP_KASAN_POISON, as they both would target user pages.
>
> For user pages, I think we should skip unpoisoning as well. We can keep
> unpoisoning around but if we end up calling page_kasan_tag_reset(),
> there's not much value, at least in page_address() accesses since the
> pointer would match all tags. That's unless you want to detect other
> stray pointers to such pages but we already skip the poisoning on free,
> so it doesn't seem to be a use-case.

Skipping unpoisoning makes sense.

> If we skip unpoisoning (not just poisoning as we already do) for user
> pages, we should reset the tags in page->flags. Whether __GFP_ZEROTAGS
> is passed is complementary, depending on the reason for allocation.

[...]

> Currently if __GFP_ZEROTAGS is passed, the unpoisoning is skipped but I
> think we should have just added __GFP_SKIP_KASAN_UNPOISON instead and
> not add a new argument to should_skip_kasan_unpoison(). If we decide to
> always skip unpoisoning, something like below on top of the vanilla
> kernel:

[...]

> With the above, we can wire up page_kasan_tag_reset() to the
> __GFP_SKIP_KASAN_UNPOISON check without any additional flags.

This would make __GFP_SKIP_KASAN_UNPOISON do two logically unrelated
things: skip setting memory tags and reset page tags. This seems
weird.

I think it makes more sense to split __GFP_ZEROTAGS into
__GFP_ZERO_MEMORY_TAGS and __GFP_ZERO_PAGE_TAGS: the first one does
tag_clear_highpage() without page_kasan_tag_reset() and the second one
does page_kasan_tag_reset() in post_alloc_hook(). Then, add
__GFP_ZERO_PAGE_TAGS to GFP_HIGHUSER_MOVABLE along with
__GFP_SKIP_KASAN_UNPOISON and __GFP_SKIP_KASAN_POISON. And replace
__GFP_ZEROTAGS with __GFP_ZERO_MEMORY_TAGS in
alloc_zeroed_user_highpage_movable().

An a alternative approach that would reduce the number of GFP flags,
we could extend your suggestion and pre-combining all standalone
MTE-related GFP flags based on their use cases:

__GFP_KASAN_VMALLOC == essentially __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO
__GFP_MTE_USER == essentially __GFP_ZERO_PAGE_TAGS |
__GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_KASAN_POISON
__GFP_MTE_USER_ZERO == essentially __GFP_ZERO_MEMORY_TAGS

Then we would only need 3 flags instead of 5.

However, this seems to be unaligned with the idea that __GFP flags
should enable/disable a single piece of functionality. So I like the
first approach better.

What do you think?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfZv3Q-2Xj1X6wEN13R6kJQbE_3EgzYMyZ8ZmWogf28Ww%40mail.gmail.com.
