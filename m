Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFH26D6AKGQESNFU5VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C9132A0AF8
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 17:19:34 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 19sf4959663pgq.18
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 09:19:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604074773; cv=pass;
        d=google.com; s=arc-20160816;
        b=O+aC7dPZl28g0RoU1ww0yO0QRq0GFx2fy1ByQWv+oCupynqX4my8QFLCtgB7SOzw5N
         1rjBD4F+GJKBcCQj8WYmYN9q6HWetD1uPX7cgKB2sF2pGB3OUTMWksmaMcAJz8iI/CDq
         gdZJbhc4/WZzi1CGeBSopEu8aeb/2cu6zlybbxBO8igD21oZ/yQWX8gD/e2JN2fzW989
         eohkoVdxl8OoZhTaJX+MC3p5XnjQNxNxlqqYhOBgy4l6kgBJw1C/Il1c6IzRP+1Sj76n
         B4Q6Icuf/IprnEAnRZqJwFPMYEP3TgFl5FjlRHCUoAFwbOLlMK6zxP3lymUOhtkzlswP
         UBYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=S/JUfQ12PAroUMz4skgsMx4R9uSH+3WqM1MHfql1w30=;
        b=u7YmJJ8DbwgpQNcskZIBTRH1cM5v6si3zpwMjFFbroDw6iS8+8a1WXyuzFHZ/e0mcM
         9ZsKRPSIYY/8zJGA8Fu/ijkUVPMdMozWMg8rFUZjiO9/AF1nDnQbozhca2HKdrkIm7M+
         OF9ChjWeqzCldIZxBog/d/f3CkvR8h2Ltcwk6JOCV/1zg+PHt0j1VvRsLGxf5N37RJmf
         VMuOZk43yMfA+Mb0lAR3+lVVQarXAGWkQq1AkPWkB30YFk8mLDm4J+7UZu1XshU3nyEn
         wTeY89kMKoOW/Ysg86AOxlKWHdmoAOEeK0Tt446ITp/ITvIeQXZ3SYY0YhPTGLhEV+SN
         h64A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FSWYLdrs;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S/JUfQ12PAroUMz4skgsMx4R9uSH+3WqM1MHfql1w30=;
        b=hwRiGsRVHjdmoPFf+gFTcOa2W9z1UAGFN1to2ll3p3Ygwab5AyQtGxxypTLzKlMWa4
         g281wZ6Y6gT8NdBraXXeC+HdmnJDqJAA0VPWkvbJ0WFv7i2zAkHE91SvOkbKwxgiHgzE
         1y8JtWkF7jiz979M5YrJGML5KbEIiLr/VcQbpS0imghwCU1YBJ3Q+UGhj1SjwMVygqeF
         pOgdE5XQ7ZPlnEeVZFqNdh83alrNxmUifib2/KiKo0qELsvz+4NcM9T+PCmOloBY4gq2
         hfvoBFxkLMEf/kstHYtF4rO1q8sM94sP3kKKrmHUlM+Ajy4kHmMUa+Tp2cNi1mKHQm5H
         u2Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S/JUfQ12PAroUMz4skgsMx4R9uSH+3WqM1MHfql1w30=;
        b=U9OOCs5kqunPXkl2DEC/5Hl9n8kbzZT3+VCETfSsk9IvJ9gWDJKFRf0hrtRO0aIJwW
         ScjjX9uYCGSJMSPpAe6vTjwoKRsWGGitfnS8IJeZlLHOqELAPdDeoqMUlGKIM74ytVvi
         YApbhPpAA66+V0Jsc5+9oP7f5RWGWDZr0uoSsMWg8WuRFD4U1yA/XZupiyvAuRwyfnxf
         uvBriCeUJmFFRNxTeIlPbYziOGayDR/c8hm/W1ZI7IKIQTe0KQXLCfgpTmw3qhfmJ3oJ
         XhDODRCPbul/Vxt8QPklE/g7CAl/0MYONc9MxqSEcWTKSpHiqZAD+gYzWOaMrIRxY4A2
         qTNw==
X-Gm-Message-State: AOAM532sUdMsrapkGbMZuSpd0PDrJmB1HFk90GHRp9GfbFzjVHSkgXHU
	gtPBn1q43mTftEaNJxn7D3w=
X-Google-Smtp-Source: ABdhPJxch+cTxqeD7JR6QaLC5DwGtD3PjWHvJjCUm0nzsdJJX7OVzghNTKL65pm/Cx7IlgBZMW8Vuw==
X-Received: by 2002:a17:90b:305:: with SMTP id ay5mr3897517pjb.129.1604074772881;
        Fri, 30 Oct 2020 09:19:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls2266829pjq.0.gmail; Fri, 30
 Oct 2020 09:19:32 -0700 (PDT)
X-Received: by 2002:a17:90a:bb17:: with SMTP id u23mr2446892pjr.25.1604074772364;
        Fri, 30 Oct 2020 09:19:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604074772; cv=none;
        d=google.com; s=arc-20160816;
        b=wCcrBiSzBPHChxmJZv8NUeCtxfMcN9g8USHiYYUSUTpoXhTO6m8qMJMQHKVUKcSFUR
         U0KPn+kLgPoBo6wOIqHe3Vd46V9IHOTnGrBp4KjiGecmADViMVpqxi6IX5es+1I6bPiD
         RfzrVAfl4W/zqsAN3HIieOCwcpkjnR4rF2oL5wnBFm2tv/8aPbjZ+KyN4oiNwz9nG78m
         P9lCvl4adxzu1tRiC+LV2cOb9HsuCEq1NZ3p2EQOD0UXFYcG5pI07UloAPAAVoK1lmBP
         KvRhR2fG1ibWA74FmWmkMjwezRwVh9/HuiRJ+g3V9gLbjjLXcV3wmHR2jUhBoYkzmXBe
         +fSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dpV5+JCLvAj2Fu+RD4QwotunWLsVQxGyCVUUhxPbUwA=;
        b=kBTZb1lzqorXmcETTDnDTS07tK5tnFatDMA2pJaXBAcQta8Kn7e18ZD+qKuLkarvoh
         RmuHgMZzXwTUZbTme4ke1Jw5n8sFQfepa2SFbkEWMsm+1QtB1vKHM6UkVJD4LGMMhRX+
         oSaNsTe1RPvvJcQ4YcVaN5o4KDyEG+2OMu6Zee6RuORQwUAk9yYhAHrnrsyRsv9/jIU9
         vlzI1HdJF8haKC+udWcQBk+5C9ydfwT+PV3hTy+jOZ5Ax45WF7oGkv0oE/hXOi1RGy2L
         sB9W265Ibnq7Yd6CmAgdShkbfO8EPJ7kPbD7pPLX1rP80Y6OD2DYDYJYEAs05/ykrYz4
         FHvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FSWYLdrs;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id l7si380509plt.3.2020.10.30.09.19.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 09:19:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id r186so5649124pgr.0
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 09:19:32 -0700 (PDT)
X-Received: by 2002:a17:90b:807:: with SMTP id bk7mr3737334pjb.166.1604074771799;
 Fri, 30 Oct 2020 09:19:31 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <b75b7fe2842e916f5e39ac5355c29ae38a2c5e0a.1603372719.git.andreyknvl@google.com>
 <CACT4Y+YcQH2mKv3y15XkWa-tKvyhRQHAw5dLVoAkFRWgFMLq1w@mail.gmail.com>
In-Reply-To: <CACT4Y+YcQH2mKv3y15XkWa-tKvyhRQHAw5dLVoAkFRWgFMLq1w@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 17:19:20 +0100
Message-ID: <CAAeHK+xN4x4ggcBxTZj53OWCzKMe5LVLK1JMhKd3u87=E_Aw1A@mail.gmail.com>
Subject: Re: [PATCH RFC v2 09/21] kasan: inline kasan_reset_tag for tag-based modes
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FSWYLdrs;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Wed, Oct 28, 2020 at 12:05 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Using kasan_reset_tag() currently results in a function call. As it's
> > called quite often from the allocator code this leads to a noticeable
> > slowdown. Move it to include/linux/kasan.h and turn it into a static
> > inline function.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I4d2061acfe91d480a75df00b07c22d8494ef14b5
> > ---
> >  include/linux/kasan.h | 5 ++++-
> >  mm/kasan/hw_tags.c    | 5 -----
> >  mm/kasan/kasan.h      | 6 ++----
> >  mm/kasan/sw_tags.c    | 5 -----
> >  4 files changed, 6 insertions(+), 15 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 93d9834b7122..6377d7d3a951 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -187,7 +187,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
> >
> >  void __init kasan_init_tags(void);
> >
> > -void *kasan_reset_tag(const void *addr);
> > +static inline void *kasan_reset_tag(const void *addr)
> > +{
> > +       return (void *)arch_kasan_reset_tag(addr);
>
> It seems that all implementations already return (void *), so the cast
> is not needed.

arch_kasan_reset_tag() (->__tag_reset() -> __untagged_addr())
preserves the type of the argument, so the cast is needed.

>
> > +}
> >
> >  bool kasan_report(unsigned long addr, size_t size,
> >                 bool is_write, unsigned long ip);
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index b372421258c8..c3a0e83b5e7a 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -24,11 +24,6 @@ void __init kasan_init_tags(void)
> >         pr_info("KernelAddressSanitizer initialized\n");
> >  }
> >
> > -void *kasan_reset_tag(const void *addr)
> > -{
> > -       return reset_tag(addr);
> > -}
> > -
> >  void kasan_poison_memory(const void *address, size_t size, u8 value)
> >  {
> >         set_mem_tag_range(reset_tag(address),
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 456b264e5124..0ccbb3c4c519 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -246,15 +246,13 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> >         return addr;
> >  }
> >  #endif
> > -#ifndef arch_kasan_reset_tag
> > -#define arch_kasan_reset_tag(addr)     ((void *)(addr))
> > -#endif
> >  #ifndef arch_kasan_get_tag
> >  #define arch_kasan_get_tag(addr)       0
> >  #endif
> >
> > +/* kasan_reset_tag() defined in include/linux/kasan.h. */
> > +#define reset_tag(addr)                ((void *)kasan_reset_tag(addr))
>
> The cast is not needed.
>
> I would also now remove reset_tag entirely by replacing it with
> kasan_reset_tag. Having 2 names for the same thing does not add
> clarity.

Will remove it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxN4x4ggcBxTZj53OWCzKMe5LVLK1JMhKd3u87%3DE_Aw1A%40mail.gmail.com.
