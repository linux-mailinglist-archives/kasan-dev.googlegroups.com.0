Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLUBWL6QKGQEVUYU6FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C6C42AFBC4
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:24:15 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 36sf1674868otu.11
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:24:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605140654; cv=pass;
        d=google.com; s=arc-20160816;
        b=edZ+oHf36hUJOWP1DKdaf7hFH6dqu6sjWF7MbPNnWnMW0mYq9EQfNuvjpQo0U0H+Ug
         AktGeqesfIeQ6OLXvs/1ynxQO+xFj0dqGBM6haN1jrTQGUSPzC2/7VdVx4P9WudY+pNb
         IjrHNufdyPkNK70jdnrALKMiIZhabRJmNlApLXvMLafKiSwXtmeZCoOT5x13z7QQ4wEA
         d/kESDx/KbgTplMkcQsvj0GazLhDk+4tlgqMi5i5MdJeM2FmGa023uKkOoUKMchCQ4l6
         xqkXKgvQJu1y2NfOm4rA8hDpNoRxz1Bfsb7AYpdCq5pmIhT+kw08+HBisUfSPHltb7Ii
         KsSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k53HgXSun4PxUXUTU5Q2vJxYXhwJ5ez+SsSw6ahPIrw=;
        b=WyP+9YpFxvs446SZ0z+ASQ9498UR9h6A7FplarMHW9BAPL1GOb++kfxGZnSstGZeBJ
         b3tsOE5XkVDLw3yTEZhK7sfd5Ft6S/yhkEDNYw02hKMTm0Axf48t+mK/CBrcTgjrTRFF
         6dlRblvjpDnaK0QayDpCXEZdYsJNJRZtv/XTTObyXj9EPM6aUBrR6EuFqYTPAglMplQD
         E+lHED7I4gUnO2MrRkONSu2YYCRVTrTeZVE4U59RX/bLtrmQ2EABPXUF+70Pj1ss9EUv
         HesH1bURTF0UXhw7bPP0fI6+FitAKv3xgJ6HwWJHharAwJ4GviJp34PaV5pZNNqiRrx3
         2eTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d5XFm+nA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k53HgXSun4PxUXUTU5Q2vJxYXhwJ5ez+SsSw6ahPIrw=;
        b=EjXH1nz8zNabGAvq4FWOE0g7TyhWMcC6tTIWzYvQHiYPPLZXmojzpBofvbbKW2F1rn
         rGowdaoJny+B/WToAS8uMEMFUxwMY+X4DWbwjd8sR4dOG9Jb2Uu9NMtdlggw0FXdrLxh
         7AF0d9AHTRKZuAvMCJ2hdATrsM9dOdN2terLQyQ7Nuw/vtAIUdziBk7rVcazSfiQCqwW
         AHZf9EcIXSDlDeHgciuNYPTU/gdhwCc2zQbxMFnguH2YCgNlfG9mJxP7ACkh3ceaN1FG
         5k2P5CeImvCTeRGnZ3tr17BoR3UqzO7NlL5v3MRS4hIo1XrPeVhE19dQlhFLpOg+3hUo
         rlcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k53HgXSun4PxUXUTU5Q2vJxYXhwJ5ez+SsSw6ahPIrw=;
        b=g/l7fXMK0xcrpfBMb7uFjx5wuCSduovozEQzAlnlOjeWpMV76F6JUhroKA1vmIW1/H
         HfRzzHUFdvWIJ0DmApcgLoLq4KZJE3W4D7zovIj2LQPGv5zEpSbR8NhPt97nG/qsMeZ7
         KEDu07jC974bg4Xb7ad1NrcgCp5ilza8mssWNHc3ghW/BnIOi/nhy1pU329AjuV8Ma0u
         62Vm1w1SJ917IDRB/awhIMPwIf4P45Vjlfayt24Ziv3f8LfRcRZTkQu43NQq6DAn91Tv
         GUjQAm4h+pVcxWjIXms9xUL9vK0pYouDI/UKOZluOCP0VPvGj6hpcwvcmj7sKGZaExlR
         E0IQ==
X-Gm-Message-State: AOAM532pWeI55T0KpvArlbxAqNhcDhdYYlEanmMVZVUASMf8j4bmk/6S
	6NWODpokORVtclU2Eljp+B8=
X-Google-Smtp-Source: ABdhPJyVKj/s9y10JT7a1L8QCgIVbXFlLcyYdTbKHCpGCfESa5BCm12ZTl9AV1lkfoDFPdQ0x9NT1Q==
X-Received: by 2002:a05:6830:400a:: with SMTP id h10mr18675955ots.299.1605140654398;
        Wed, 11 Nov 2020 16:24:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5214:: with SMTP id g20ls284011oib.9.gmail; Wed, 11 Nov
 2020 16:24:14 -0800 (PST)
X-Received: by 2002:aca:3c41:: with SMTP id j62mr2973866oia.98.1605140654043;
        Wed, 11 Nov 2020 16:24:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605140654; cv=none;
        d=google.com; s=arc-20160816;
        b=xidKCNDKdmJhcAd2MpW3/a6MHOIbAwN6uZv2Pdds0rosDx248V27zCZmxaNbx35Xoc
         zu7EVxqAgR07JvoXqr5Eg3Pp55BYLLWK3pj+Prot8JUZ2T/GdOyI+tHGGjb/Ggdyebhu
         B90U6sbJid36BrHozEIPjZ6HtxfLMq6YaIlN5nGmI3XoHY2+pG2HiruKGimsnh3XVPvF
         fVTslS6d4+gUH8OoK7oJUWxzCQU4kOdgyrgWBWNUGfy2qk2MQVX6Zvulj2LxN+jv51l1
         V8zjJVenk15nUwqzy+IWS/uS2eIdj3xqiRaYIh25wPMlB3Vv2EtfPUV1Bh2Q0tO/2aXL
         WwzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c/7uKp3kPU+6BPx3Z+SeH1/mQzwr6aT8nYVy2fS4R+I=;
        b=pf3Cthl0Ru0kDbqnZbH5mJcAFiHmNTpuC25n/UYTdi+tbdDrjUkjKUCLObkZCSzkX9
         Hm/IgpoAAM23bsEoXk6kFvzT4qZfZiH2IySjSe4JiYt3WP/AfL2uGxnoWcCO75p2YHTs
         eXMFu+pIjeAMNKvDsFqoE9LwDsAgqhq9ZDOPcQbVtNYLC0gjpoPNhFHelE+D+bt9mEUD
         rGKSUuq9Cy+4CrgU+Ia2qeXEy/gvzYVK8L5Z5PYI9vpZaw8Tqw2rj7qNWf8ZThF/v3XI
         Rdy3cOhF9yuaWRFo+qlBVRuEPeElVT1pQCBeY5smvjQcFzPRT1lVO5Awiqqa4c77XaDj
         2yIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d5XFm+nA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id d22si375363ooj.1.2020.11.11.16.24.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 16:24:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id w11so1853634pll.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 16:24:14 -0800 (PST)
X-Received: by 2002:a17:902:d90d:b029:d6:ecf9:c1dd with SMTP id
 c13-20020a170902d90db02900d6ecf9c1ddmr23089538plz.13.1605140653446; Wed, 11
 Nov 2020 16:24:13 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl@google.com>
 <20201111162051.GG517454@elver.google.com>
In-Reply-To: <20201111162051.GG517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 01:24:02 +0100
Message-ID: <CAAeHK+x=8TF1Rda9mVCRe+-_A72BDSFg-e8w9mG-JKgCkfb8=g@mail.gmail.com>
Subject: Re: [PATCH v2 05/20] kasan: allow VMAP_STACK for HW_TAGS mode
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d5XFm+nA;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Wed, Nov 11, 2020 at 5:20 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > Even though hardware tag-based mode currently doesn't support checking
> > vmalloc allocations, it doesn't use shadow memory and works with
> > VMAP_STACK as is. Change VMAP_STACK definition accordingly.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
> > ---
>
> Shouldn't this be in the other series?

I don't think it makes much difference considering the series will go
in together.

>
> FWIW,
>
> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

>
> >  arch/Kconfig | 8 ++++----
> >  1 file changed, 4 insertions(+), 4 deletions(-)
> >
> > diff --git a/arch/Kconfig b/arch/Kconfig
> > index 56b6ccc0e32d..7e7d14fae568 100644
> > --- a/arch/Kconfig
> > +++ b/arch/Kconfig
> > @@ -914,16 +914,16 @@ config VMAP_STACK
> >       default y
> >       bool "Use a virtually-mapped stack"
> >       depends on HAVE_ARCH_VMAP_STACK
> > -     depends on !KASAN || KASAN_VMALLOC
> > +     depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
> >       help
> >         Enable this if you want the use virtually-mapped kernel stacks
> >         with guard pages.  This causes kernel stack overflows to be
> >         caught immediately rather than causing difficult-to-diagnose
> >         corruption.
> >
> > -       To use this with KASAN, the architecture must support backing
> > -       virtual mappings with real shadow memory, and KASAN_VMALLOC must
> > -       be enabled.
> > +       To use this with software KASAN modes, the architecture must support
> > +       backing virtual mappings with real shadow memory, and KASAN_VMALLOC
> > +       must be enabled.
> >
> >  config ARCH_OPTIONAL_KERNEL_RWX
> >       def_bool n
> > --
> > 2.29.2.222.g5d2a92d10f8-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx%3D8TF1Rda9mVCRe%2B-_A72BDSFg-e8w9mG-JKgCkfb8%3Dg%40mail.gmail.com.
