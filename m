Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIGF5T6AKGQENULVUFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1726829F5EE
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 21:14:26 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id k26sf857417otb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 13:14:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604002465; cv=pass;
        d=google.com; s=arc-20160816;
        b=JcOOqE9wuJnw9oMdjgiYKjg4xSLaU9bMYCVKNbkdmv6joxbnol8KN4CdT+D7hzISSL
         AttRDsNCMgvw+IBD3TEu9V46uf7PSGO4pJs3bwSSvNJndfXYnfiCsOAfg04NAQIL3mcC
         tIi7tTl4trnSyKWW76vvthEY2Wgq1IurBdkYwfmostUHvx5BLIJT13/fUQK/C1/ZjHY5
         5PZyIS6kgDmZ/J9K3HQwHdgUWqZyEEe0vpUqiznoIAW9/lxZX4EeCLvSCw1tTkczuFNe
         5nVwl+Cj6b9LP/NsUyYWL4OGtLM4kUn8FPNsGsbhaaM3sPKC7hmrQ4gq4aNCKtE5JK9U
         h3Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9PZXT768J/R91VIrCkt6kIM1G4g/uPNa9optxZYnT74=;
        b=zEkaX/xeAiMGCeYWXnQFhe7sAuKAZ9oA9KXN73o/HE9UCuVGp4mTCLYjKMt0ZPPjR+
         078mg/Zs9h8hUSlF/6DB24xtXW7Ju648MzJMq2NOhR84eXgQ9c03IPXLO+Gz9GMrF/ly
         1jb/+9PdDhmUZvVscE2gz0QXlSoJVbvXehumcQ1NodSOxJOr2ozj0unGDee6SyXiDQcU
         tXGi6gRgYmABHoDVFk4cHK5HNPHckciBb5RDzduUxfr6JlWnU4wa4C9TJ5HQHMt7H5wn
         3RXpV8QgbY+FX/tMsVjJWDBR+eAhBN/R+MVoEBU+B2oVk5sFCeXFr7whj6WnxbfJaE7c
         nuMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ds1NXPTL;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9PZXT768J/R91VIrCkt6kIM1G4g/uPNa9optxZYnT74=;
        b=cPi2NFv9nmPdCjQ87Fq9BxTRi7hDD+9nRAWYMwa47NcyklOyZ3Hqsmg9cgF0V7hFgd
         Q+3hqtlI9P6/ZYOuDz1w2GnY2SluWNQBt7kxwR+sOhgPaOzphe16beFsdHUMMaTwWXyK
         CPy6x9cly3mJXPrGBlb+YW3XuiSerL2eHZrGU4fVrcnNvA9WioQ/pXfHo2Ke1oIFSXQf
         JTQwYR48/BjKxNQIpUkH1fG7ViRPqT+C768QIgZpN2Zs9ICpbRYf9ZDH3hfrsp3Uu+Pb
         g2m63o3WJRRH+H7NjTun9UXXEF73mNBOfI1EgYkIxYgKlT0dBo3TF5rUJ7urz3/LpR35
         Nx8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9PZXT768J/R91VIrCkt6kIM1G4g/uPNa9optxZYnT74=;
        b=ItMHYuzZB+aDqvWsZnyhYy/RGkxhbEoYscur6DBxL03J0RH3fnxP9IC1q1AdISBqk2
         otkeCl68r159gNx6Ews5cN9jeBHFIoMH0Xo2sH3+nSBAK0ftPloKnyJfcncGgWouhzHJ
         p+tv4XunTt2Jszgr/sW0IulpJJTrfmTK1/e25z0RCVSgj8Nh34q0jzeoHvjoF8RhhOgd
         WiuR9imMWuKJdPchS8oViSqPl9TSI4DyGJnrYPiAv33vU/pgkOURymCRcOsOV5TUIsON
         Z9WyA7VSgRSJJn5lxE3MAX6N+DqXVsIwHeFVpNeJH1t3Cl0iVr6JZjgJPmA/LRaPMGQ9
         N0fA==
X-Gm-Message-State: AOAM533qGBnQfnvS6Yb4ftLQWByyluyhymj/YQQBOxXKWbUgSJqefkC9
	xfwwrlS0F8nhk7ZnLF8hfgY=
X-Google-Smtp-Source: ABdhPJy/+jVcD5a12dxiZR8HoJBtcq4UhSwltCGQHAsdtTAQAYjqB9EVNOJGOshqseJm2w7VFCrpew==
X-Received: by 2002:a4a:e1d7:: with SMTP id n23mr4597244oot.85.1604002464986;
        Thu, 29 Oct 2020 13:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6949:: with SMTP id p9ls1025469oto.6.gmail; Thu, 29 Oct
 2020 13:14:24 -0700 (PDT)
X-Received: by 2002:a9d:ee6:: with SMTP id 93mr4708854otj.195.1604002464625;
        Thu, 29 Oct 2020 13:14:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604002464; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5qgL478/8Kwc4lN3TCBn9X7V2fka4TwhCzP3lnimZ/dS5kiKV1BWG/HtRRKar0SL9
         WKh/i/3Ufo1FlJ8f+u5KdcCsrl/YGwBju7cDrjJSCQlVMR7q+wwhJXvMtzKO4wieJofl
         QMnlvJ2sY8OfUL6k7dhN/Bpe7KN71uGOWgb3lsO3vGviEetS+OzyNJx20oULTtrG0LCm
         1L0iZPfCbKamLbBj9/ZPvI7hTp49Pr9FxaqQrXNcnzipCRyw/R/0gvO3ywf2cL0GogWv
         O8e9bXfFwKIa7rmksjMrCsxzxkHZfLashCFEQTCMvwQ+2zjHP3atsk+O90Gl7xsoJXoX
         rxvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l77n7oC/IyxQLfCBGbQpiCRFFdLcSomb1vOdKMROYRs=;
        b=pRxdPbJvQ9Kg7ylOYe++J72wh7BWRtKkILM+zejhRbBCaKvcjpK3WqCuUp1sMZxWze
         G40fmNNGlPXGSES/qmNFgAJlMz0FM7BSofR6NIrifsrnShU5QSNT/spf9FFGmD5pN07U
         ZXunirBIo4Qi7g9N7ktgdCRbrSqtgCBf06p6x/BrkkvjvhpfbBGmjxOxaa706oCIJRyP
         /zb4BZANQu2DahRtMv6loMrQ5oLLm5VJwUJ3wuOzUqctdSf0N+gSkE8tIaS6lMclIiuP
         Hg8QYRDcThg/rm/hX45UqSGuQHUeMY9QRbgfd1PUEVyckH7iPUc9LG2U0od700HRqXmV
         ZX1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ds1NXPTL;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id q10si334781oov.2.2020.10.29.13.14.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 13:14:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id 10so3299950pfp.5
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 13:14:24 -0700 (PDT)
X-Received: by 2002:a17:90a:cb92:: with SMTP id a18mr1508972pju.136.1604002463411;
 Thu, 29 Oct 2020 13:14:23 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <1d87f0d5a282d9e8d14d408ac6d63462129f524c.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Y6jbXh28U=9oK_1ihMhePRhZ6WP9vBwr8nVm_aU3BmNQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Y6jbXh28U=9oK_1ihMhePRhZ6WP9vBwr8nVm_aU3BmNQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Oct 2020 21:14:12 +0100
Message-ID: <CAAeHK+wqdtPkrhbxPanu79iCJxdYczKQ6k7+8u-hnC5JONEgNQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2 07/21] kasan, arm64: move initialization message
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
 header.i=@google.com header.s=20161025 header.b=ds1NXPTL;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Wed, Oct 28, 2020 at 11:56 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Tag-based KASAN modes are fully initialized with kasan_init_tags(),
> > while the generic mode only requireds kasan_init(). Move the
> > initialization message for tag-based modes into kasan_init_tags().
> >
> > Also fix pr_fmt() usage for KASAN code: generic mode doesn't need it,
>
> Why doesn't it need it? What's the difference with tag modes?

I need to reword the patch descriptions: it's not the mode that
doesn't need it, it's the generic.c file, as it doesn't use any pr_*()
functions.

>
> > tag-based modes should use "kasan:" instead of KBUILD_MODNAME.
>
> With generic KASAN I currently see:
>
> [    0.571473][    T0] kasan: KernelAddressSanitizer initialized
>
> So KBUILD_MODNAME somehow works. Is there some difference between files?

That code is printed from arch/xxx/mm/kasan_init*.c, which has its own
pr_fmt defined.

>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Idfd1e50625ffdf42dfc3dbf7455b11bd200a0a49
> > ---
> >  arch/arm64/mm/kasan_init.c | 3 +++
> >  mm/kasan/generic.c         | 2 --
> >  mm/kasan/hw_tags.c         | 4 ++++
> >  mm/kasan/sw_tags.c         | 4 +++-
> >  4 files changed, 10 insertions(+), 3 deletions(-)
> >
> > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > index b6b9d55bb72e..8f17fa834b62 100644
> > --- a/arch/arm64/mm/kasan_init.c
> > +++ b/arch/arm64/mm/kasan_init.c
> > @@ -290,5 +290,8 @@ void __init kasan_init(void)
> >  {
> >         kasan_init_shadow();
> >         kasan_init_depth();
> > +#if defined(CONFIG_KASAN_GENERIC)
> > +       /* CONFIG_KASAN_SW/HW_TAGS also requires kasan_init_tags(). */
>
> A bit cleaner way may be to introduce kasan_init_early() and
> kasan_init_late(). Late() will do tag init and always print the
> message.

It appears we'll also need kasan_init_even_later() for some
MTE-related stuff. I'll try to figure out some sane naming scheme here
and include it into the next version.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwqdtPkrhbxPanu79iCJxdYczKQ6k7%2B8u-hnC5JONEgNQ%40mail.gmail.com.
