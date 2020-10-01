Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQNB3H5QKGQEAK2OB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE04E2809C9
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 23:57:22 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id q12sf82651pjg.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 14:57:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601589441; cv=pass;
        d=google.com; s=arc-20160816;
        b=jheZ7x9twoqKYaVnO3b+GTMUJYpk8mqOqw6GNEtCWtHYvzEU8hHjfYHykR9nAyPpIi
         kSBRh3y9KyYTyMRMSE1mEfL6fb7g5uk3auvHNMC67lTml5mG7GleO+837Pca7PLlrgzV
         Dug3BouTlKJaeAkpangco+VBGhYcd5j3agjsCRcgGYvJ/j2+rMHKwq7RximjchzauETT
         /QxMkXd/6YQRSIVM5e9YVt35Qpqhceug8VwVIfZ9pp/nKoYBP18quc/XG8Hm2gfmVr2y
         CaFewhJhLdyHLia9AZDVKN+7phxkItkYQpw8fAoGvBWkTChtMca5dTT0Y42/bAlD49dX
         MrdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NRSSdzA5FA6ilYIxTuqbWvJdtvW/8dH9uiWG8qsKvt8=;
        b=djLrb/9pc1qcUUdBVurDTJ2O18sb9KG8wApcqfLORKfwPue6lk0cfUTUX7569RNLAV
         zVnip8Wj5qwFienYiKjfw3xQ0xLBHAz/FcRDahItLjpW87HvvVcIRxPdT2E3k4rco6Hq
         PJIc8mLEdYfTnl72hy+jtxphiJdjVLI2KiaruVAWIDVFISVPl3XfnYLGdEHLbCRwdeUI
         kcMHA5OVrj/8XNvbAkAqO+th5/2YVJOtGyvBAzDQ65okWgKJQ6yTixSluFY24DIZlXCD
         oB5iKZU3uMZWWBNYb/dnmNDawEyQCm3PHZ78ANrV8vJkqFRTJ0RBRPLnWwLTJMl8sH9J
         ChlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qy1x+J2U;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NRSSdzA5FA6ilYIxTuqbWvJdtvW/8dH9uiWG8qsKvt8=;
        b=tbwFKCyLXkS6rYIuew95dC5f2aAeIZFrBje2incGAIMrKWhN3G3k+MWDNaa9FjKKqU
         keTtKruk9gbHehEUQ6CM01ZB3pYNKGu7Q8QUIgeWzGPsG2l3VLAr5aE4E7ePTM5klx0H
         hhCkWlMi6DyFdE63OBmkC+i0zdVo7ORPPllw7KXTAVpsaeb0/ADStHM6FgRmQ8QWAi8v
         /sddJGH9XPnJ+CUt+4f+DGgBl0HK8C0uL2JDcE+chVDkQbSr9FK7sBEsY1OCyI4f0qmO
         uz6k6GYve2glAxOpKXdW6JWw79yDEwAnFO6JCV95gvza+mmQp75fVCC92yR+xztBNaof
         y3hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NRSSdzA5FA6ilYIxTuqbWvJdtvW/8dH9uiWG8qsKvt8=;
        b=GZJjNclH846cehJcz5LBGIQ+xnv6SNzJgbOQivw8JhyKeCQzZ8g55GdoAvCNX4CCDw
         BOgzq4itU0I8sfU+xvWWkQIep6vzHvAXTn1Rxg3jurA01uUkCE1M6LB8J0fR0alpQN/H
         2BEpOOsdWlLksnjyqYD6HQSIlYvwF581ybk5NykFGNeceCQ2b9la+hshhoV8+Jl9vIZO
         dpmCZ+cvzfuo8lAT/0FhWvEIdseoe10/2P9i5gcG3Z5NMu3bGZKIwFW/yIk3UzPJ8BHS
         Ock6rqfM/JOFt4WCXAPNw8+kLB81BcysaogkCdpo9KqP50FvuqbCvh7fVxe/wlaKXdxC
         +qoA==
X-Gm-Message-State: AOAM531D8q9EJdIHFtjPKeueuSsbp1j8MAQsw/xL7MfDwgJOG0R1MDzA
	bGUswIk3jidol+nIg+GV6Is=
X-Google-Smtp-Source: ABdhPJys9fjsGWzse763lY+KhQpFFxN/MewSHKJjhkiuI2Ms3d0l3FMQ+WdQu5i/SfSZX8OYD6wFIw==
X-Received: by 2002:a17:90b:3004:: with SMTP id hg4mr1877562pjb.7.1601589441516;
        Thu, 01 Oct 2020 14:57:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2292:: with SMTP id f18ls2737544pfe.6.gmail; Thu,
 01 Oct 2020 14:57:21 -0700 (PDT)
X-Received: by 2002:a62:3585:0:b029:142:2501:3985 with SMTP id c127-20020a6235850000b029014225013985mr9586201pfa.74.1601589440905;
        Thu, 01 Oct 2020 14:57:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601589440; cv=none;
        d=google.com; s=arc-20160816;
        b=wGYC01iA/LwVDIu8NfKyh1XcwgZWNaOuh95VDf2nsad5t4z9Ba3Hmtuj+go+LatTY2
         ZZX8nzXKGk85k+NVhy+67Ar4QQJzh0FcU/looYgKqFkZXJmbw5Zvt7WLJaZocGiSF1Rp
         yzHpGpnirV+15S/seMgFHDv2FeGoCt/nXL/yL0hNLvLGuyur6UtqKyiYsSCyK24tYqgh
         wxaGgUqrhyIqF2uxuvyyCd+iod4fwevjAUxg8VEksIEAqTBodC6LuNJckcoEBs4sTwRE
         j4XvkmVksKKwR2i40HbykZgujGS7wB4ESiRGr8BDLwvrsspsvFIJMAMfaDJ4pyyyYrk7
         nMIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7vBVgkba9wR9rMzobTFcbe2FRbrTf2j7jPc/dQj28oc=;
        b=BdpjqKtU8FZkkXoli7FayItVt6seidyv3cXwq4bRVZFedJvG+nBx3UfyE4IMT4f13Y
         nLH+v5Gc2aH20fOLJwH12yNB3g+in29sQl9nK7xe3X2OpY+JsH4VrFcF2GXRnSgL0hao
         WBjWrGhCOUr7K6UcE1BciA8frW5EwpYCF9eMBssfPOsfVbQU+Eo/SxxBdKEgoD3+9rh+
         kicT13OD0Q9Acm20iUPYQzw8VhW0FgxheG2koXK9DsHO3GLcqNzqMzSz05NAbXNiKu+c
         JOO38AfNRfvJyC+/O/JW4XbHzWMLck+HcDA5gn4n0xLVk7W3hzexZvAk3ZpAzrre4irX
         CzXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qy1x+J2U;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id e18si466092pld.5.2020.10.01.14.57.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 14:57:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id d9so5964339pfd.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 14:57:20 -0700 (PDT)
X-Received: by 2002:a17:902:d716:b029:d3:8e2a:1b5d with SMTP id
 w22-20020a170902d716b02900d38e2a1b5dmr4556745ply.85.1601589440484; Thu, 01
 Oct 2020 14:57:20 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <d00f21f69ba7cb4809e850cf322247d48dae75ce.1600987622.git.andreyknvl@google.com>
 <20201001175539.GQ4162920@elver.google.com>
In-Reply-To: <20201001175539.GQ4162920@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Oct 2020 23:57:09 +0200
Message-ID: <CAAeHK+ygFuqZyJKpKT6dqi8Suu3bnr_wP60ZwAQeLu6vSim+rA@mail.gmail.com>
Subject: Re: [PATCH v3 21/39] kasan: don't allow SW_TAGS with ARM64_MTE
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Qy1x+J2U;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Thu, Oct 1, 2020 at 7:55 PM <elver@google.com> wrote:
>
> Does that patch title need an ", arm64" in it, like the others?

Yes, will fix in v4, thanks!

>
> On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> > Software tag-based KASAN provides its own tag checking machinery that
> > can conflict with MTE. Don't allow enabling software tag-based KASAN
> > when MTE is enabled.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> > ---
> > Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
> > ---
> >  arch/arm64/Kconfig | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index e7450fbd0aa7..e875db8e1c86 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -131,7 +131,7 @@ config ARM64
> >       select HAVE_ARCH_JUMP_LABEL
> >       select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >       select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> > -     select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> > +     select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
> >       select HAVE_ARCH_KGDB
> >       select HAVE_ARCH_MMAP_RND_BITS
> >       select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> > --
> > 2.28.0.681.g6f77f65b4e-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BygFuqZyJKpKT6dqi8Suu3bnr_wP60ZwAQeLu6vSim%2BrA%40mail.gmail.com.
