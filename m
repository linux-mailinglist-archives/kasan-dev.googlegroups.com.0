Return-Path: <kasan-dev+bncBD52JJ7JXILRBL6A62PQMGQEGIBMIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 461586A530C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 07:33:21 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id e9-20020a196909000000b004cca10c5ae6sf2583204lfc.9
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 22:33:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677566000; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Eqg/NdOAH2507GwBAHZ16a1A26C4c26QhKpNftHfMyxCf2zaM0kZgiIhJANjD3KVj
         lfoeKo5cyek2SWcVh0w0RMn72z8YFnP7U/UckPBDemwlew4tcsobuQQIwgq7699aeMLv
         oZafNWRxXIFg4HCLZC0KiOtG9rVxLZVbAG7+KhiyOh5VpMJW+kVONTjifB0W5sktxtxX
         yehhSkaXLi9lOTuYola9I9NU3oHPFQZAn14iDSXRT4tJZwxu0XC7ncRkhj2YM3s+jIyx
         XblvOQCF7cT/2kQOplJ6MOKfxkcMwLZy5EF+fQhod+ovevU+N82tD2Y+zpv7OlovEUJM
         Om6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OHwFc5eEWUicVByEURp5/EcnOC7IODD4jsXpZtMgp34=;
        b=uK3+x5TnLW4KutPg+QFgF1vNIz6Iu7zEbYvpaDOm3FbtoNvt5ToAJAAq3/mRiNvmOs
         XOXBRy+mOOQPEIDRoZmXsGDF5ssMjd6XeGLJ7qxy0agIIlYA9/s5BsW4qnxw7j5cGqI2
         EOupn5WDLo3OzbhNyOYt7n3MJXp/yyTPqJkLW8/349CTZ2xMt9ilN8jszfMJUQha352a
         NGrcV8B77QSETzqSyFH41u04R1PEwSdMFm1/RBm+sT6BNXlwD1l12aVrgN/HzrnNc5ih
         z/gASNivkemjjEB/cIAnA4wSuYY6zjnUO2tb4uV0uQ2ty5751FOdsx3Fqi0+pFWE+Q5n
         uBHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hpEGmJ1V;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OHwFc5eEWUicVByEURp5/EcnOC7IODD4jsXpZtMgp34=;
        b=ituQoUGALIzh3VWWJtwjzYSQYw34sSV2wvmflmeHp70cKfT5YiA75QintaBwqDxolp
         +hTvDHzlS3WkciG/sgX22CYKNnmewSXDHv/UpHC/2oumli+cvHvVAkG/EFWWLrBQD3kY
         FZnDo9yVPgukFxSqXBmxoPc+bojco7v2Im8fkGjN3te3DExjghhf88v+LU/epZugW4wj
         KW/V/mAUvMeGZYfUiJ4zcN7TlPacYXRSBC1NEkkXzPVQa3uyyg4ADhlU3xjlpgNFbiD1
         +pDIRzV0TyAP9QRz9eWaknsgZtgGvj3+MXhtsy00SDgMN2OGRYwYpbHJ/o5uds7WW5Wn
         XDEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OHwFc5eEWUicVByEURp5/EcnOC7IODD4jsXpZtMgp34=;
        b=3yljV9CQZCqH80wGisbIdd+c9M15zIYesUyya+Xo9R5zmXTL5a1GVct7vm6pfAMDoV
         etjYxByNJUL/2UMPvM3Mp0RcV0iLLV7Kaj7RkA8NHPZAES3Mln0Ad8fGdxzapCqUt/Ff
         3M/IdJ70xLZOMVoW8QjavUSkGthF3yydXRocLkABXfl409oifSnBy9YMP35AlAxgOzCf
         040GCMu2+/orq+b2pQAa9z5jPx1IAv3WpCktzAhWnylJ4/MrJLu8TFmF+6Z/cPKnfWxp
         NTGQDt+UGRLHOawk/nDkGez4jLX7JnkSNs00Vtw6wHrrfsZjGgdze+hRSlVFNNs2hNSY
         8f2A==
X-Gm-Message-State: AO0yUKX9rOxmgckMiFEWPifnMWODlPhDGjn3wgel4yervIATxQit3WQj
	tq5pcjJ4loIP87Xp+0vt2Y4=
X-Google-Smtp-Source: AK7set8Dj6Xcn8V231sXh71MTUSLWfuCvVdrPXGioXyp6b5GQY8sJq9VnLvu8IS9XcP1jSAmvRlT5Q==
X-Received: by 2002:a05:6512:402a:b0:4d5:ca32:6ed8 with SMTP id br42-20020a056512402a00b004d5ca326ed8mr1012266lfb.6.1677566000206;
        Mon, 27 Feb 2023 22:33:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4024:b0:4dd:8403:13fe with SMTP id
 br36-20020a056512402400b004dd840313fels1692900lfb.3.-pod-prod-gmail; Mon, 27
 Feb 2023 22:33:18 -0800 (PST)
X-Received: by 2002:ac2:5e8e:0:b0:4cb:430b:c6b with SMTP id b14-20020ac25e8e000000b004cb430b0c6bmr328915lfq.29.1677565998737;
        Mon, 27 Feb 2023 22:33:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677565998; cv=none;
        d=google.com; s=arc-20160816;
        b=tKrbLI+pTZGuzgUaKYByWurRs0BQS108TNfxPx4jw1JbzuxRA8r+hs9YH9l0zlsj9t
         9Up+rVnSqvaiwevRN3FZRwppJXVZjN+eg9mIcLrCxKpgBnoQCcge79KG0e9/qBGGo1Yy
         Ous0kZCCEH66opKhLg83NMbqAN4hlP+y1lib374BT+qmAWBB2M+ai1shJT/0pxx+3K19
         FX8LRK8ly79m65wskEbFtoX+bOXvoVHi3JymACMKA2mCUpx4Bry1KnMSs+UYyrLvwknI
         7rUlDDbUq9nvBIsPbq5XYPsSscfHs989AzqdDuilVA3auo6mqHUG2Dd82tzEE2oCC9Cu
         uJaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bUIZxkEW9znfcwTzBX3QFKfrO4/r5gi0IWGewBBrVw0=;
        b=dyazQr/jlZ49ncrL2Jezcbrx4XSL2qwFWJf8+nDK1MgC3kiL434WQehgIRAffSe7uN
         MLRPl6MoThOn4abkhs2no6gZoVwBuar3rdufP9lc2d2q99AK0jGO65j+M3ypOoGSrPNK
         009McM/PMewcfHme/A8QfNlLoUIGj5nm+3wHeeaVEjJsLDzAJ9WUFK3vp5SIcsv0BHvE
         R0ckkTVP017CgSjnkmbwyLHaFM9GXZCqLtqMjWtWiTV7Nfmq9W8fBV7xODmA0HpS6p1C
         aX8svxbVE27Ng3ZeOMc1QOs2WMSPatimQBU/UHXxoS5UuYc+Mqqju8qCvVT6DhLyZtZ3
         nQSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hpEGmJ1V;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id y25-20020a056512045900b004d5786b729esi362903lfk.9.2023.02.27.22.33.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Feb 2023 22:33:18 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id bv17so8557131wrb.5
        for <kasan-dev@googlegroups.com>; Mon, 27 Feb 2023 22:33:18 -0800 (PST)
X-Received: by 2002:a5d:4d03:0:b0:2c5:3fcb:682b with SMTP id
 z3-20020a5d4d03000000b002c53fcb682bmr285444wrt.2.1677565997813; Mon, 27 Feb
 2023 22:33:17 -0800 (PST)
MIME-Version: 1.0
References: <20230224065128.505605-1-pcc@google.com> <CA+fCnZc-iLXbEUzYhEZtY5wHc=G3p=m-fuNdVsmovg-MT8c-6g@mail.gmail.com>
In-Reply-To: <CA+fCnZc-iLXbEUzYhEZtY5wHc=G3p=m-fuNdVsmovg-MT8c-6g@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Feb 2023 22:33:05 -0800
Message-ID: <CAMn1gO6cBC6G0EC+JUM+hXmt-dsCt_BAQHn6oyT9TU6NOhYc0w@mail.gmail.com>
Subject: Re: [PATCH] kasan: remove PG_skip_kasan_poison flag
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hpEGmJ1V;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::435 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Sun, Feb 26, 2023 at 4:20=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Fri, Feb 24, 2023 at 7:51 AM Peter Collingbourne <pcc@google.com> wrot=
e:
> >
> > Code inspection reveals that PG_skip_kasan_poison is redundant with
> > kasantag, because the former is intended to be set iff the latter is
> > the match-all tag. It can also be observed that it's basically pointles=
s
> > to poison pages which have kasantag=3D0, because any pages with this ta=
g
> > would have been pointed to by pointers with match-all tags, so poisonin=
g
> > the pages would have little to no effect in terms of bug detection.
> > Therefore, change the condition in should_skip_kasan_poison() to check
> > kasantag instead, and remove PG_skip_kasan_poison.
>
> This seems reasonable.
>
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf=
4597c8a5821359838
> > ---
> > I sent this independently of
> > https://lore.kernel.org/all/20230224061550.177541-1-pcc@google.com/
> > because I initially thought that the patches were independent.
> > But moments after sending it, I realized that this patch depends on
> > that one, because without that patch, this patch will end up disabling
> > page poisoning altogether! But it's too late to turn them into a series
> > now; I'll do that for v2.
> >
> >  include/linux/page-flags.h     |  9 ---------
> >  include/trace/events/mmflags.h |  9 +--------
> >  mm/page_alloc.c                | 28 ++++++++--------------------
> >  3 files changed, 9 insertions(+), 37 deletions(-)
> >
> > diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> > index a7e3a3405520..74f81a52e7e1 100644
> > --- a/include/linux/page-flags.h
> > +++ b/include/linux/page-flags.h
> > @@ -135,9 +135,6 @@ enum pageflags {
> >  #ifdef CONFIG_ARCH_USES_PG_ARCH_X
> >         PG_arch_2,
> >         PG_arch_3,
> > -#endif
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -       PG_skip_kasan_poison,
> >  #endif
> >         __NR_PAGEFLAGS,
> >
> > @@ -594,12 +591,6 @@ TESTCLEARFLAG(Young, young, PF_ANY)
> >  PAGEFLAG(Idle, idle, PF_ANY)
> >  #endif
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -PAGEFLAG(SkipKASanPoison, skip_kasan_poison, PF_HEAD)
> > -#else
> > -PAGEFLAG_FALSE(SkipKASanPoison, skip_kasan_poison)
> > -#endif
> > -
> >  /*
> >   * PageReported() is used to track reported free pages within the Budd=
y
> >   * allocator. We can use the non-atomic version of the test and set
> > diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmfl=
ags.h
> > index 9db52bc4ce19..c448694fc7e9 100644
> > --- a/include/trace/events/mmflags.h
> > +++ b/include/trace/events/mmflags.h
> > @@ -96,12 +96,6 @@
> >  #define IF_HAVE_PG_ARCH_X(flag,string)
> >  #endif
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string) ,{1UL << flag, strin=
g}
> > -#else
> > -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string)
> > -#endif
> > -
> >  #define __def_pageflag_names                                          =
 \
> >         {1UL << PG_locked,              "locked"        },             =
 \
> >         {1UL << PG_waiters,             "waiters"       },             =
 \
> > @@ -130,8 +124,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,    "hwpoison"     =
 )               \
> >  IF_HAVE_PG_IDLE(PG_young,              "young"         )              =
 \
> >  IF_HAVE_PG_IDLE(PG_idle,               "idle"          )              =
 \
> >  IF_HAVE_PG_ARCH_X(PG_arch_2,           "arch_2"        )              =
 \
> > -IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )              =
 \
> > -IF_HAVE_PG_SKIP_KASAN_POISON(PG_skip_kasan_poison, "skip_kasan_poison"=
)
> > +IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )
> >
> >  #define show_page_flags(flags)                                        =
 \
> >         (flags) ? __print_flags(flags, "|",                            =
 \
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 7136c36c5d01..2509b8bde8d5 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -1380,7 +1380,7 @@ static inline bool should_skip_kasan_poison(struc=
t page *page, fpi_t fpi_flags)
> >         return deferred_pages_enabled() ||
> >                (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> >                 (fpi_flags & FPI_SKIP_KASAN_POISON)) ||
> > -              PageSkipKASanPoison(page);
> > +              page_kasan_tag(page) =3D=3D 0xff;
>
> Please also update the comment above should_skip_kasan_poison.

Done in v2.

> I think we can drop #3 and #4 from that comment and instead add a more
> generic #3: "Page tags have not been assigned, as unpoisoning has been
> skipped".

I realized that the page tag will also be unassigned when the page is
first being initialized, so I decided to be more explicit in the
comment here about the circumstances where this will happen. I also
took the opportunity to remove the FPI_SKIP_KASAN_POISON flag, since I
realized that it is now also redundant with the page tag.

> >  }
> >
> >  static void kernel_init_pages(struct page *page, int numpages)
> > @@ -2511,22 +2511,13 @@ inline void post_alloc_hook(struct page *page, =
unsigned int order,
> >                 /* Take note that memory was initialized by the loop ab=
ove. */
> >                 init =3D false;
> >         }
> > -       if (!should_skip_kasan_unpoison(gfp_flags)) {
> > -               /* Try unpoisoning (or setting tags) and initializing m=
emory. */
> > -               if (kasan_unpoison_pages(page, order, init)) {
> > -                       /* Take note that memory was initialized by KAS=
AN. */
> > -                       if (kasan_has_integrated_init())
> > -                               init =3D false;
> > -                       /* Take note that memory tags were set by KASAN=
. */
> > -                       reset_tags =3D false;
> > -               } else {
> > -                       /*
> > -                        * KASAN decided to exclude this allocation fro=
m being
> > -                        * (un)poisoned due to sampling. Make KASAN ski=
p
> > -                        * poisoning when the allocation is freed.
> > -                        */
> > -                       SetPageSkipKASanPoison(page);
> > -               }
> > +       if (!should_skip_kasan_unpoison(gfp_flags) &&
> > +           kasan_unpoison_pages(page, order, init)) {
> > +               /* Take note that memory was initialized by KASAN. */
> > +               if (kasan_has_integrated_init())
> > +                       init =3D false;
> > +               /* Take note that memory tags were set by KASAN. */
> > +               reset_tags =3D false;
> >         }
> >         /*
> >          * If memory tags have not been set by KASAN, reset the page ta=
gs to
> > @@ -2539,9 +2530,6 @@ inline void post_alloc_hook(struct page *page, un=
signed int order,
> >         /* If memory is still not initialized, initialize it now. */
> >         if (init)
> >                 kernel_init_pages(page, 1 << order);
> > -       /* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
> > -       if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_PO=
ISON))
> > -               SetPageSkipKASanPoison(page);
>
> With this removed, __GFP_SKIP_KASAN_POISON is no longer used and can
> be removed too.

Done in v2. Since the remaining flag will skip both poisoning and
unpoisoning, I decided to rename it to GFP_SKIP_KASAN.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO6cBC6G0EC%2BJUM%2BhXmt-dsCt_BAQHn6oyT9TU6NOhYc0w%40mail.gm=
ail.com.
