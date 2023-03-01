Return-Path: <kasan-dev+bncBD52JJ7JXILRBAF47KPQMGQEH6ODK4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 407606A6450
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 01:36:17 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id c15-20020a05651200cf00b004b6fe4513b7sf3396577lfp.23
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 16:36:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677630976; cv=pass;
        d=google.com; s=arc-20160816;
        b=LtlUiQYth1UxRx4ozXBJ/Pe5NeGb1vY6XOC0VIHYlSMI38gpU7oZ4qKC0VvR1zRWNB
         pq1weVeZIaI0eiQKHqXq0D2Nr3xrF8kwFKF/ooseRJnGPtKNn/P7vr5i99go0BZmLdHD
         ONKgcVXLv4BbvezVqeTgfEPbocprfLNUySLsunJyliqkCZSM3RW4xyIbJIi9vUZ+aMRH
         kSqWrPvCKrWKGjoeczyFCGQhcPCKoWaZ0Je2FZ4DjZBigioHvitCSU98t+/49iddn8Kj
         mATede97vFSaV3P7PmJ0XvT/UfwBevx8LkoX3Z5PJoRlVgNde3MhsOKDCIECq5px+xbH
         1fIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P57L+RhZq2UPfBsrnPLjm41SWEiL2dPVjfXZkBa/L+Y=;
        b=ZlQ5XvQmg9LL6KMzQoMxv61ksetVsTTxdeXZBOXp5GtguAOoIBMRTo1Adet9bWjYrH
         WBVnOleES4w0LjdDAeCDCCjYnhEbRWxoQHr8EEDKBfMt6WIp4mgz3qNL1xFfm5JB/moR
         eiaIM1UH/jl570GQr75zepPY3F5xmJC0VBpEMW/W1LphGv1hNZH0gSJsWS3Pe8FCeL5T
         eaW/rx9Ep7MuwKLBcSFyh0N16krR5nXaE0+JthQEODDi8fMPV7B0AImn74y37d/F53qs
         sPUyc/u77NP+AM178eimsR8XTCECzF9ooBDC+ONLWNKhEVkekm3qRzygw0zHnnWePCkz
         yaDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kYq0xtp1;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P57L+RhZq2UPfBsrnPLjm41SWEiL2dPVjfXZkBa/L+Y=;
        b=W2jP6fGbJC4xITsfGPeqkQjA+3dwEqal8LSqhM/e7yomX8P0YwiqSZX8bILF7NBMIL
         MI5n2sKV/Lbw7UfXafERNpFR0AbrYBYA5JmlEDgbrtcvVn83b/9sepG+bjbM9KPyQPop
         4W7tx8LdcjbPJjE+dr3T+nZJA8mjWpt64DZc2HaRXcPWSyGSsfttv4cZkMSBodr6TIo9
         bYlpmlcYPByTJpvznG661A7n0pBkYoMezRu1G3o/OVQXT17gU6gJ6i+eCju7sGhpe5nJ
         1MPa6GA1hb+aAcm0+R/UETd91marvVoWM46jvqrbCbLRoaWJKlNYzFAo1YH3gHxG7Fdw
         B3aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P57L+RhZq2UPfBsrnPLjm41SWEiL2dPVjfXZkBa/L+Y=;
        b=HUJma4DDW+7W+yR80oo1CbI37sAODLOJ0dOdK0XLpBJ/NxZqhhLvhGbMHgJiuqF8YB
         d/8URDgoGth9x2yUKIaHrt/A4V2Jereie3dlm0DQJrn/Eff76GcogPZzYKjjt2v3u9Ll
         3rsibyRSbTOyH82ZYVoOXO31wADXiaG3CJi9Owe8JcsA6zXKoiMBRy2J1hDiZ4t6MWnz
         VF6j+A7T8sLG5KdaSl5Eb9y4XrvColvAohvIwoq6+ZvmcU/V/Tk8gqo06szMT6vkZnm4
         kyti3Wt2dsk1PmDDxNWw/ZCTwkBEfNjnDApw/+eJjEU0EAiJWLoF+WXOKJRcNdv8ov9m
         T9/A==
X-Gm-Message-State: AO0yUKXBSDDcWN0TpnyqDdOdcnDouFYl6fnhxFRIr+QDqACZdmH6torb
	AKkXGCAR2fEVKmNMlBFa8vc=
X-Google-Smtp-Source: AK7set91KXli41D1FoDaynCQb6Xm9vHFqh7gNlZ/e0zki4CgvKmBp3kxySE73b4h2wm4AKJSkg5Xbg==
X-Received: by 2002:a05:6512:402a:b0:4d5:ca32:6ed8 with SMTP id br42-20020a056512402a00b004d5ca326ed8mr2488985lfb.6.1677630976355;
        Tue, 28 Feb 2023 16:36:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bd0d:0:b0:293:4d60:102b with SMTP id n13-20020a2ebd0d000000b002934d60102bls2359189ljq.1.-pod-prod-gmail;
 Tue, 28 Feb 2023 16:36:14 -0800 (PST)
X-Received: by 2002:a2e:86cd:0:b0:283:4310:da75 with SMTP id n13-20020a2e86cd000000b002834310da75mr1396345ljj.39.1677630974880;
        Tue, 28 Feb 2023 16:36:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677630974; cv=none;
        d=google.com; s=arc-20160816;
        b=aqzUXZtlWyz2SpPd4lNZawjiuUFWxnldJI6Ke56CGFm4D8kD0AHVgQwZ2UABRCIlns
         0NxW5bI60f6ffy/cXhvI67chbaSiV9fk1nhtBU3X+C+eIdIcpE1ODYaZpi4BEBCrdXx3
         M3nr7QfmAGHxmGHai3EXzOrhyBTltlI25MgjS2CmoPCY8pySnuzPINMmv6i3sirUjcuA
         IoGx1vwOcucbBuAKJROqBk/AO4NmukVLfDP/EjQlb7QqAq5Ifdj5KabwmA2u/a9EP8sO
         OjPfqqQ0naQGP2D37mKY/8Q83/uc761UX4tt8JUyF1HxG448Od4PGptQtmuRH34/e0FZ
         xUBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=a+LHz6oHstuW8LVb7HnzFGpbNVne+AJV/ef0qI77F2g=;
        b=GUFO44O2jZ9bgrrm2vuDo3u1blYBdUMmxgR4MkVtHo/Rm6hLHMkfJY445g+u2kSnvE
         aOYwLd3LfA/PD4WY6igJs6B3xplSfQ2FLdgB9Q7yczmDlNrdmZwhT+pOatw3sYsgGykt
         SJz5vblhidNVF0+t/sxWEU/dIUElbC6qQ4jQhkh75M+/8KOKpw3AB0BXzS1Feg2OrAPa
         ULe36oORxe+TTSFatJjfBVAipkxRzn1l1+XIY3JKtnsYZzB2RLBeQ55Ic34IHCZ2wfM3
         oJUUEUYyThA8rhyK4QLlOHfrpHjzoyH+IlbjimcsyyWMb1ZMybgqLfm8MjjgjhjVq3fI
         w2Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kYq0xtp1;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id u3-20020a2eb803000000b00295a08c1798si466670ljo.1.2023.02.28.16.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 16:36:14 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id l25so11590367wrb.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 16:36:14 -0800 (PST)
X-Received: by 2002:a5d:42d2:0:b0:2cd:bc79:542c with SMTP id
 t18-20020a5d42d2000000b002cdbc79542cmr9043wrr.2.1677630973834; Tue, 28 Feb
 2023 16:36:13 -0800 (PST)
MIME-Version: 1.0
References: <20230228063240.3613139-1-pcc@google.com> <20230228063240.3613139-3-pcc@google.com>
 <CA+fCnZcDK_zwGDkLC9GmgkQhzXu8yZ8GUghyCR2M7TUdgcGonw@mail.gmail.com>
In-Reply-To: <CA+fCnZcDK_zwGDkLC9GmgkQhzXu8yZ8GUghyCR2M7TUdgcGonw@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Feb 2023 16:36:01 -0800
Message-ID: <CAMn1gO7waRRwn8VOYyz3Mwp4SjK=Z1o42ZBes5pfomNDUa9ATA@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan: remove PG_skip_kasan_poison flag
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kYq0xtp1;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42b as
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

On Tue, Feb 28, 2023 at 12:48=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
>
> On Tue, Feb 28, 2023 at 7:32=E2=80=AFAM Peter Collingbourne <pcc@google.c=
om> wrote:
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
> > kasantag instead, and remove PG_skip_kasan_poison and associated flags.
> >
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf=
4597c8a5821359838
> > ---
> > v2:
> > - also remove GFP_SKIP_KASAN_POISON and FPI_SKIP_KASAN_POISON
> > - rename GFP_SKIP_KASAN_UNPOISON to GFP_SKIP_KASAN
> > - update comments
> > - simplify control flow by removing reset_tags
> >
> >  include/linux/gfp_types.h      | 28 +++++-------
> >  include/linux/page-flags.h     |  9 ----
> >  include/trace/events/mmflags.h | 12 +-----
> >  mm/kasan/hw_tags.c             |  2 +-
> >  mm/page_alloc.c                | 79 +++++++++++++---------------------
> >  mm/vmalloc.c                   |  2 +-
> >  6 files changed, 44 insertions(+), 88 deletions(-)
> >
> > diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> > index 5088637fe5c2..9bd45cdd19ac 100644
> > --- a/include/linux/gfp_types.h
> > +++ b/include/linux/gfp_types.h
> > @@ -47,16 +47,14 @@ typedef unsigned int __bitwise gfp_t;
> >  #define ___GFP_ACCOUNT         0x400000u
> >  #define ___GFP_ZEROTAGS                0x800000u
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > -#define ___GFP_SKIP_ZERO               0x1000000u
> > -#define ___GFP_SKIP_KASAN_UNPOISON     0x2000000u
> > -#define ___GFP_SKIP_KASAN_POISON       0x4000000u
> > +#define ___GFP_SKIP_ZERO       0x1000000u
> > +#define ___GFP_SKIP_KASAN      0x2000000u
> >  #else
> > -#define ___GFP_SKIP_ZERO               0
> > -#define ___GFP_SKIP_KASAN_UNPOISON     0
> > -#define ___GFP_SKIP_KASAN_POISON       0
> > +#define ___GFP_SKIP_ZERO       0
> > +#define ___GFP_SKIP_KASAN      0
> >  #endif
> >  #ifdef CONFIG_LOCKDEP
> > -#define ___GFP_NOLOCKDEP       0x8000000u
> > +#define ___GFP_NOLOCKDEP       0x4000000u
> >  #else
> >  #define ___GFP_NOLOCKDEP       0
> >  #endif
> > @@ -234,25 +232,22 @@ typedef unsigned int __bitwise gfp_t;
> >   * memory tags at the same time as zeroing memory has minimal addition=
al
> >   * performace impact.
> >   *
> > - * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page all=
ocation.
> > - * Only effective in HW_TAGS mode.
> > - *
> > - * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page dealloc=
ation.
> > - * Typically, used for userspace pages. Only effective in HW_TAGS mode=
.
> > + * %__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation a=
nd
> > + * poisoning on page deallocation. Typically used for userspace and vm=
alloc
> > + * pages. Only effective in HW_TAGS mode.
>
> This is not entirely correct: for vmalloc pages, this flag doesn't
> result in poisoning being skipped, as the memory is unpoisoned and
> page tags are assigned by kasan_unpoison_vmalloc.

I see. I somehow missed that vmalloc was setting the tag itself.

> How about something like this:
>
> %__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation.
> Used for userspace and vmalloc pages; the latter are unpoisoned by
> kasan_unpoison_vmalloc instead. For userspace pages, results in
> poisoning being skipped as well, see should_skip_kasan_poison for
> details. Only effective in HW_TAGS mode.

Yes, that sounds reasonable. Done in v3.

> >   */
> >  #define __GFP_NOWARN   ((__force gfp_t)___GFP_NOWARN)
> >  #define __GFP_COMP     ((__force gfp_t)___GFP_COMP)
> >  #define __GFP_ZERO     ((__force gfp_t)___GFP_ZERO)
> >  #define __GFP_ZEROTAGS ((__force gfp_t)___GFP_ZEROTAGS)
> >  #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
> > -#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UN=
POISON)
> > -#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_PO=
ISON)
> > +#define __GFP_SKIP_KASAN ((__force gfp_t)___GFP_SKIP_KASAN)
> >
> >  /* Disable lockdep for GFP context tracking */
> >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> >
> >  /* Room for N __GFP_FOO bits */
> > -#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
> > +#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> >  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
> >
> >  /**
> > @@ -335,8 +330,7 @@ typedef unsigned int __bitwise gfp_t;
> >  #define GFP_DMA                __GFP_DMA
> >  #define GFP_DMA32      __GFP_DMA32
> >  #define GFP_HIGHUSER   (GFP_USER | __GFP_HIGHMEM)
> > -#define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | \
> > -                        __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNP=
OISON)
> > +#define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | __GFP_S=
KIP_KASAN)
> >  #define GFP_TRANSHUGE_LIGHT    ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
> >                          __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECL=
AIM)
> >  #define GFP_TRANSHUGE  (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
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
> > index 9db52bc4ce19..232bc8efc98e 100644
> > --- a/include/trace/events/mmflags.h
> > +++ b/include/trace/events/mmflags.h
> > @@ -55,8 +55,7 @@
> >  #ifdef CONFIG_KASAN_HW_TAGS
> >  #define __def_gfpflag_names_kasan ,                    \
> >         gfpflag_string(__GFP_SKIP_ZERO),                \
> > -       gfpflag_string(__GFP_SKIP_KASAN_POISON),        \
> > -       gfpflag_string(__GFP_SKIP_KASAN_UNPOISON)
> > +       gfpflag_string(__GFP_SKIP_KASAN)
> >  #else
> >  #define __def_gfpflag_names_kasan
> >  #endif
> > @@ -96,12 +95,6 @@
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
> > @@ -130,8 +123,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,    "hwpoison"     =
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
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index d1bcb0205327..bb4f56e5bdec 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -318,7 +318,7 @@ void *__kasan_unpoison_vmalloc(const void *start, u=
nsigned long size,
> >          * Thus, for VM_ALLOC mappings, hardware tag-based KASAN only t=
ags
> >          * the first virtual mapping, which is created by vmalloc().
> >          * Tagging the page_alloc memory backing that vmalloc() allocat=
ion is
> > -        * skipped, see ___GFP_SKIP_KASAN_UNPOISON.
> > +        * skipped, see ___GFP_SKIP_KASAN.
> >          *
> >          * For non-VM_ALLOC allocations, page_alloc memory is tagged as=
 usual.
> >          */
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 7136c36c5d01..960e0edd413d 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -112,17 +112,6 @@ typedef int __bitwise fpi_t;
> >   */
> >  #define FPI_TO_TAIL            ((__force fpi_t)BIT(1))
> >
> > -/*
> > - * Don't poison memory with KASAN (only for the tag-based modes).
> > - * During boot, all non-reserved memblock memory is exposed to page_al=
loc.
> > - * Poisoning all that memory lengthens boot time, especially on system=
s with
> > - * large amount of RAM. This flag is used to skip that poisoning.
> > - * This is only done for the tag-based KASAN modes, as those are able =
to
> > - * detect memory corruptions with the memory tags assigned by default.
> > - * All memory allocated normally after boot gets poisoned as usual.
> > - */
> > -#define FPI_SKIP_KASAN_POISON  ((__force fpi_t)BIT(2))
> > -
> >  /* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fiel=
ds */
> >  static DEFINE_MUTEX(pcp_batch_high_lock);
> >  #define MIN_PERCPU_PAGELIST_HIGH_FRACTION (8)
> > @@ -1355,13 +1344,19 @@ static int free_tail_pages_check(struct page *h=
ead_page, struct page *page)
> >  /*
> >   * Skip KASAN memory poisoning when either:
> >   *
> > - * 1. Deferred memory initialization has not yet completed,
> > - *    see the explanation below.
> > - * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
> > - *    see the comment next to it.
> > - * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
> > + * 1. For generic KASAN: deferred memory initialization has not yet co=
mpleted.
> > + *    Tag-based KASAN modes skip pages freed via deferred memory initi=
alization
> > + *    using page tags instead (see below).
> > + * 2. For tag-based KASAN: the page has a match-all KASAN tag, indicat=
ing
>
> For tag-based KASAN modes: ...

Done in v3.

> > + *    that error detection is disabled for accesses via the page addre=
ss.
> > + *
> > + * Pages will have match-all tags in the following circumstances:
> > + *
> > + * 1. Skipping poisoning is requested via __GFP_SKIP_KASAN,
> >   *    see the comment next to it.
>
> According to the vmalloc thing I mentioned above, let's reword this to:
>
> The allocation was not unpoisoned due to __GFP_SKIP_KASAN, with the
> exception of pages unpoisoned by kasan_unpoison_vmalloc.

Done in v3.

> > - * 4. The allocation is excluded from being checked due to sampling,
> > + * 2. Pages are being initialized for the first time, including during=
 deferred
> > + *    memory init; see the call to page_kasan_tag_reset in __init_sing=
le_page.
>
> Let's put this item first in the list.
>
> > + * 3. The allocation is excluded from being checked due to sampling,

Done in v3.

> "is" -> "was" possibly sounds better with "was" in #1.

Done in v3.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO7waRRwn8VOYyz3Mwp4SjK%3DZ1o42ZBes5pfomNDUa9ATA%40mail.gmai=
l.com.
