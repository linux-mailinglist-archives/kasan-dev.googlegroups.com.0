Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5FUU36AKGQE7I6677Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 590392905AA
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 15:04:54 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id q15sf1421368qkq.23
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 06:04:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602853493; cv=pass;
        d=google.com; s=arc-20160816;
        b=lhWAsg2LccSktHKOg5PhAGkSzXw4mRigaw3s9OCBfRx1NUpJnn0QthUl3NcFwwv8lR
         5Mb9YDwhag2qvqREZ1qj/VOum2qocHaiJ3qGIHnA1dYQSqwB7Jo900ECZNXsBeKPEL3C
         +7ycDZZDtWoPGY7DiRWk7l/1xrqOj5drdZlHybsOEKBOpKGi6iU9Maqz3QKEMMA1IQqC
         KYghPc3Lwklrv6TB6ZStfUriSQSzoA2cHOVkd8x7h7EdxogzGbPDlA4nk5hdicGmvrSL
         kEJ/WwlQPvGvj/ehTA+wZEvRXnHSGCHdFTyLgkL3rqwGpojPfedEtALnZJkD9oHGT0Qh
         m59Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xKergNG799dUcohdanTWVeknwUHN/bMtPqYn4gzSMSs=;
        b=AK/lFTTkWWbx3uar79LqNDSyXZNb7bHZdNW+t77yZtZ4UYOu2HWLoRqN7WW4BHgQrE
         W7mWjg0hjaSjeBsmA9GOkSotfzTPmqGLsmHi7shA3BcpfV+x5l9gGuWR61oFukc9lAjF
         /sTGmXWLCpGP1FDGKnHb1X47Z8xoyUUeSOPFD24aiQsyuvNS1bCcXyKhcwLviYjbFE1p
         grtycrM5K1qGZ/lnJ3yo2IJaXsDzJ9be8arDPv7XxjGntgmBAtBxq2THmCe9XtXGQruJ
         deB1FH/r+I301mFh5DVkwUl+E+4kgUpT0qzeRV8SbdRocBwFDxqX/Uo3yuwnCtxeiPDR
         MGnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tNSpsnAo;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xKergNG799dUcohdanTWVeknwUHN/bMtPqYn4gzSMSs=;
        b=fdp4kODa4pwH5YwwtUq0uKN7QzyP/kBf1WzYmuIMt/VxVdzefnvV7KZVv33IrDQXQw
         BuZXuutZT0cWtdRvrtmerW7bc3Kn4Fuws1tBC5X3RWQ58rPt5jyk4Ee7fwbY133ODPTT
         hg0vNFzH2T60LDZEBI2xKF94foE8NW//h7+RwNqQYwHoVNs+8Y9CmCbbtuWWKyjlZEVT
         NOXVgJ3VPpVKEen2MkMzTOg3Hlmw7CpozhIWcRo3HVGMU819vleNB8NHuBn2hkyBogJh
         HMpjFYb0QsdxOvWhH0b9diDMHhyNvektHnScX1DLgYirjCyBt56SFkNYXutjK5EiAoMV
         n6aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xKergNG799dUcohdanTWVeknwUHN/bMtPqYn4gzSMSs=;
        b=not66FqdP2A3R5IDGZypm+asfQ0Xo435VBpyAPJT9L1dept8Xm0i3EqB/SXl3/m+4S
         YIfhOqO5d42b5ih15tlBFyQrYMpAWqHis1kgQWoZ7XsbaXEQsEDi4Qqac68uscciQscI
         FGupWN6okQCkelbMks8Fa7L5s0fS/12ZLUGEMKocGLWZu4PZc/HwhTxh0shwcH2TjUjl
         VWwGtiFarpmd3x6ELdfxIzMGAQ/xKeG29bhwlFWIvFVFpOkvEWGHGymUOC25YpPqY+wo
         GRueiFk5N2/x+5nkZQfRPc9xZAuuFHxT1/M0SW9nCJkmZBpb7iHRVWlenaWm7zu0Twh7
         jZeQ==
X-Gm-Message-State: AOAM533DD1CrfQb4yOIXYjXWOtJvSc/Jh64xCmEXAWB9NiZu0sdngpu5
	656iOlbfQO87BtkBSWOhlMA=
X-Google-Smtp-Source: ABdhPJwi9qAUcZwZF5Tk3+5kHumXXM0q6aSwX6xYG0k2ffdZJGjdekyqgxJmRiA7xu2+KPBLRmguQg==
X-Received: by 2002:a37:480f:: with SMTP id v15mr3645357qka.279.1602853492495;
        Fri, 16 Oct 2020 06:04:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1132:: with SMTP id p18ls1154425qkk.9.gmail; Fri,
 16 Oct 2020 06:04:51 -0700 (PDT)
X-Received: by 2002:ae9:ed02:: with SMTP id c2mr3810982qkg.410.1602853491624;
        Fri, 16 Oct 2020 06:04:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602853491; cv=none;
        d=google.com; s=arc-20160816;
        b=mBhSU52FB+GL/a7uIONSVLVA6WI0hY8u/T6ovBH02kO8WMI+PVvZZDJwp/BsB3mvmw
         hL/Xwi/bxXpoJPdKGiUH5m/7la4svTvWrfOHSg+k1qWZZTdO1mnciTolegzliuCiEu5X
         JoOV6eAv06nccUubvGeiJhA8XNYooEpCbNq8bCxHJZI9UqnZJ9etjsQjZZC3C3veoTIz
         o0AkJUVqLEfOljJvDCvPQZcJa5bdw3CjKe/NlvLMf90SM8LcfXIF/ijjBEzsVqjsfYyi
         IHz1nP9io36JShyNX4Tva9OEATm2x/HxaHmBD+kBuFF5s8yUmZJOf5Urqp4EUMCY7UHX
         vmlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Kg/AR7kJChmFU99Vav3gO3g+4etmp4JgAFXVamIUngo=;
        b=Zb5UBw/+5QHf9AFueoDS1vhHB3cVYOsovulOn6DxBTgc5w5cKfirwv+u2SEdB3Nud4
         6pPMVGOGO6dAa3k8+qSCmE5rvmHc0i8O/T3XBOzESwGnOztW5AqEJVvcRmD/XuL4OwNe
         akcRZsaDOajAi5fpWC7PWG02z7+fy5RWf6z2dvrzLWZEjfb23NJz4/qTW4EyV1DsfKap
         /w9BsS6Nb2jYlcqCVAlUR3KQ12m5Cbik/DZ3ZxZ3PxSKjwnK9Zzfe69aSbEA+eJBzl2I
         tx7I6nHlTZ8b1BYg202/g56WVITsoBCjI7Y9AlqjnSO5GWy03F9pm4MXgdhhn7C8pByx
         jhxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tNSpsnAo;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id v35si166860qtv.1.2020.10.16.06.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 06:04:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id w11so1245214pll.8
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 06:04:51 -0700 (PDT)
X-Received: by 2002:a17:902:9681:b029:d5:cdbd:c38c with SMTP id
 n1-20020a1709029681b02900d5cdbdc38cmr201999plp.85.1602853490651; Fri, 16 Oct
 2020 06:04:50 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <8fe7b641027ea3151bc84e0d7c81d2d8104d50d7.1602708025.git.andreyknvl@google.com>
 <CANpmjNOKM8=MWPR2MPPrdu0fhvzwD4dDO-xnfeqcxOY1DQe09g@mail.gmail.com>
In-Reply-To: <CANpmjNOKM8=MWPR2MPPrdu0fhvzwD4dDO-xnfeqcxOY1DQe09g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 15:04:39 +0200
Message-ID: <CAAeHK+xSa6jMH6x5BgAuArD8kVURm8DCu-xhiN6mWMkR5n1auA@mail.gmail.com>
Subject: Re: [PATCH RFC 5/8] kasan: mark kasan_init_tags as __init
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tNSpsnAo;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643
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

On Thu, Oct 15, 2020 at 12:23 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Similarly to kasan_init() mark kasan_init_tags() as __init.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I8792e22f1ca5a703c5e979969147968a99312558
> > ---
> >  include/linux/kasan.h | 4 ++--
> >  mm/kasan/hw_tags.c    | 2 +-
> >  mm/kasan/sw_tags.c    | 2 +-
> >  3 files changed, 4 insertions(+), 4 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 7be9fb9146ac..af8317b416a8 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -185,7 +185,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
> >
> >  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >
> > -void kasan_init_tags(void);
> > +void __init kasan_init_tags(void);
> >
> >  void *kasan_reset_tag(const void *addr);
> >
> > @@ -194,7 +194,7 @@ bool kasan_report(unsigned long addr, size_t size,
> >
> >  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> >
> > -static inline void kasan_init_tags(void) { }
> > +static inline void __init kasan_init_tags(void) { }
>
> Should we mark empty static inline functions __init? __init comes with
> a bunch of other attributes, but hopefully they don't interfere with
> inlining?

I think it's a good idea to drop __init, as the function call should
be optimized away anyway.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxSa6jMH6x5BgAuArD8kVURm8DCu-xhiN6mWMkR5n1auA%40mail.gmail.com.
