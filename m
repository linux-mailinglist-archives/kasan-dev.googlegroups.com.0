Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNOF677QKGQECOITO4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DD672F37BA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 18:56:06 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id l17sf1807481pff.17
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:56:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610474165; cv=pass;
        d=google.com; s=arc-20160816;
        b=0bD3ZeOc3CbLiS1sW4UTQdZXBap5M4q9fime5hccl9Ak0IM9DIjGhw5LnHY+CM96pY
         fmkP5dsXQRvc9TtWQ5EgtnI3C7ZI74nrUEa7fDC61XL+UkpkeUBJeiYZs76K0i4Ww2g8
         iEH+GwEv1hUWPrWLOkG92qlxgXweDiPfcWdbpjyJzYHyc0RAP/5S04ijmX6qpnrNcYlx
         RdS+T1u4KSjcwiFjZ5LWIUMIv1VA9+tBlznWHwygqLRT+7g1pzeQMZ9JCNzvxQpE3T/5
         WoCMDku/aP+JUalf32FArpvV/pMIkbjjKb/Eo2evVF0NRkC0ImSlzKS0GUjitoQd/28l
         2TWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ACWMr3+jWTgPyephRKgkTjJt1nejMDfKdj91YjqR5WY=;
        b=i6UJLl+p8RXXOu9exGdrmC8mazRUPkV9IBY3xWlB8eNljznqea7qlZdlYEzYtzBYDV
         iFbMv4jMm0UQqz+0ATr/VCuknoPmxBDcSH9OszZZiKo2/z/h03loAWvE/JO4qyQzfVUu
         X+gCuIgxK8rMOrJHbOzptVOzckEAPBD1qZqcJZrkEen07rF12JyOV5zoRMhwHshYq6G8
         iIhesvvEpR7pQrlLhyoPjMYZwjdj3PgZdRYCOggqG2H1BDNReALoAXsstHiuH76Dwjlg
         LlrX3au0KXLqpWgbvGTAdOVeWpJPntjL7JiKqSsw3H0tAryjiE4weKXpH0B+UtiQmeWK
         O4HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cFM44SJt;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ACWMr3+jWTgPyephRKgkTjJt1nejMDfKdj91YjqR5WY=;
        b=btE6GKmKDu/qO5QqqQuJfFTy5OGrXbj+6ftXPJV4vj8eKJ3tQtpL3zSdOLke2WNqD6
         DUwoNZNW6/RfTWwHFa8Jim0/0pMnVc2yoB/ySt/AoBNTfnaKYaL7kJrlLUaSCGhH8uzr
         VkC4yBnMLC683Hg5vJaMYrqWLJXuSrrVTABK6Tji8q9PBO6gKAz2CDZJQU7Gx6CpKNuC
         x+yrC3DuhijEROaCWi9Ft3mspfEmwaP/S6+Por6EkO+dKLCQAaaoA934MJ1VN0O43kXV
         9LQ6fQTtR3mBe8i8qKI+CNhU/G1UmgPLuGzTSbGzKH+Y9BGB5wccGHEC+KcSGZHoxqqD
         YYpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ACWMr3+jWTgPyephRKgkTjJt1nejMDfKdj91YjqR5WY=;
        b=nK+3wC+UqsqZHiGVo4IT86g4kncCwzgEjuJ3rQtaIdU5M0+AIHXJJqcz4bEl30IrY9
         iFGjZl/zltRkQb1mumQJsrAIjirN77eoIEFlqBmmV0Hb91KfbbCzke2gFlQ0ycu6FxrB
         630gHj0gew4U58VUTP9SGhoaWY7o40rslLvsDNOW33XwKWgeNkYY5b4ibDeT8+DBI46P
         MMKv5CCqASGTZmXvY0cfHNhkQf5m2ELewgwmbvqZ5i+9oIA+t9IfL2TIrcOTP05wcaxG
         Y+zxloqgQ40fWyNnDWpKKr7LFL9k8GeXDPPZF+NLNcJ3crqyg0ZMHwEhsiPLk3NL2qA7
         9ORQ==
X-Gm-Message-State: AOAM5326ytsZS8NhYWzF5577hZ3NCvYdLMnZuzftB52ERE+fHpuZ+zPG
	43BGFA3KWN1Gsmdy0DHtAVs=
X-Google-Smtp-Source: ABdhPJwgjbeFKrcRhEXD3zGwpnJ6ee6gcAkCJxy0gjNDmZ/yDdfJeusmSFiB3TZxawBynDIeAPTg5A==
X-Received: by 2002:a62:e213:0:b029:19e:59d3:a76a with SMTP id a19-20020a62e2130000b029019e59d3a76amr392517pfi.53.1610474165261;
        Tue, 12 Jan 2021 09:56:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ee90:: with SMTP id i16ls1959080pjz.1.canary-gmail;
 Tue, 12 Jan 2021 09:56:04 -0800 (PST)
X-Received: by 2002:a17:902:ab97:b029:de:30a:5234 with SMTP id f23-20020a170902ab97b02900de030a5234mr237910plr.55.1610474164725;
        Tue, 12 Jan 2021 09:56:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610474164; cv=none;
        d=google.com; s=arc-20160816;
        b=PYb3+bi4MEsVmM/g86I3EEOUV9kmuUz2thUKjrOw4FLoaOAd4jmy7p3cFFoNEIHAqV
         wxNIfqaSn98UZDpO7SuuCWhh8LQVMTHCXoM4dLvJPG6cEWI5WZO6CyKmlhMB+RfGB9XD
         hC5F2PYLBdpads+v3CM8dk4xg7PCrbm8DYDg/IZyCnrXpCD47F808DFtXU+aoDsz7ZH4
         zuZ9b2oHXpe5yjtFfKO15dBoopAgTgE5UiwtYs5A8Q2MBrS8cABR1h+xEjpD1So+Twdz
         QVXGx95D6p3dbABdL382nS2AWM78iwBYWIxqt9aHjYUNH9N2yUd7b/cFZsIQvSesbULt
         VlNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Upx2oTWYrPXCgwMubh2XCOEphSc2BQiSntB9Zcy4eo4=;
        b=EIg9IhCRFmq6KZpwYf5Cmq6GF+PRi3GCXN1jvcLfSz14jQCZ73WTiecGOShyuHiI3Q
         p+EDs3dBMwLwmgru6BrTA8ntdQvsc9/EkD8IFUFjgYYq839TahZINQcaFLHZlvVeWrrp
         tENL5qo4ll0GkTlhRUe74qfX5IEEA6G+8gjKGC/gydr2q/WpWFTV3ogsbxMs4urxphKB
         SkxvOfqd/sTFOT7xb1qZj9xqEfb8scIHwbANTYM8IhX8vdN+Ve7sDdiPag0xfdseRIOc
         rwB+3sGydFI/5coKinpIAlModSMarU6Ync2DkfPWtOPzkJiocc3HJNTQnU4/iTe329iz
         3l+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cFM44SJt;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id z18si256682plo.5.2021.01.12.09.56.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 09:56:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id m6so1835661pfm.6
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 09:56:04 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr435587pfh.24.1610474164246; Tue, 12 Jan
 2021 09:56:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl@google.com>
 <CAG_fn=VDPR2bkHA_CeDP-m8vwr3rTH+3-qwMNHNUQA2g6VghKA@mail.gmail.com>
In-Reply-To: <CAG_fn=VDPR2bkHA_CeDP-m8vwr3rTH+3-qwMNHNUQA2g6VghKA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 18:55:53 +0100
Message-ID: <CAAeHK+yJ=fLMXtH0o0YEri+pn0k+zN_YSY9a93DeYZL0wrLzow@mail.gmail.com>
Subject: Re: [PATCH 03/11] kasan: clean up comments in tests
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cFM44SJt;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429
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

On Tue, Jan 12, 2021 at 8:53 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Clarify and update comments and info messages in KASAN tests.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8
>
> >  void *kasan_ptr_result;
> >  int kasan_int_result;
> Shouldn't these two variables be static, by the way?

No, then the compiler starts eliminating accesses.

> > @@ -39,14 +38,13 @@ static struct kunit_resource resource;
> >  static struct kunit_kasan_expectation fail_data;
> >  static bool multishot;
> >
> > +/*
> > + * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
> > + * first detected bug and panic the kernel if panic_on_warn is enabled.
> > + */
>
> YMMV, but I think this comment was at its place already.

It gets updated by one of the subsequent patches.

> >  static int kasan_test_init(struct kunit *test)
> >  {
> > -       /*
> > -        * Temporarily enable multi-shot mode and set panic_on_warn=0.
> > -        * Otherwise, we'd only get a report for the first case.
> > -        */
> >         multishot = kasan_save_enable_multi_shot();
>
> Unrelated to this change, but have you considered storing
> test-specific data in test->priv instead of globals?

I'd say that test->priv is for some per-test data that's used in the
tests, and multishot is not a part of that.

> >         if (!IS_ENABLED(CONFIG_SLUB)) {
> > -               kunit_info(test, "CONFIG_SLUB is not enabled.");
> > +               kunit_info(test, "skipping, CONFIG_SLUB required");
> >                 return;
> >         }
>
> You may want to introduce a macro that takes a config name and prints
> the warning/returns if it's not enabled.

Good idea, will do in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByJ%3DfLMXtH0o0YEri%2Bpn0k%2BzN_YSY9a93DeYZL0wrLzow%40mail.gmail.com.
