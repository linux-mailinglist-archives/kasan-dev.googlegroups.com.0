Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCW2XH3AKGQETXPVNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 707501E43DE
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 15:37:16 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id d190sf12984324qkc.20
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 06:37:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590586635; cv=pass;
        d=google.com; s=arc-20160816;
        b=u7SUx1OYKQmvFvs5SRvdyJPu9qj6+uKZyUaLiKaM2g+wc1N3KyKuWBwspQgj7bOEwY
         8lgR2Z1w7g5PxlhJMJAV23p3tLXjux3e0NL6D4EkegsgkLPDr3LAWU5eXQ+b2TjwZGJI
         zrpfa2WhEbfLuvlyiMuLPAcepLQCA1/PWXYe9XqG0FI1r3VxBYsmCwPmE+lqAlAgJ+gO
         QhYakr0q3d2FmC3Wv7l1Zpe/HH3kmWNvpWm1AE/xWwgiH/3CX5Qpfbt/qo4nR65LbF8D
         bKWkMvvhceOFs5AkrltBxCQUWDnNwrIz3oiaBfItqLRpHpiSd6BnveNVFX4/W8T79ET6
         xAiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gCGCvIgbvZHI3Rnpifc+UO52i7gqN2D+RQn2vFGnCQY=;
        b=ORiavFzG9eb1pILX4iXrOnsavwtlvAaLyeXivPO8Z1pi4j2+Q2/tuNCvRVreOQ83Fg
         wG2gXxzN35Wf1U6cEz77rJE227AxVSrW1dorbzYPAF79a4udbgQba7gVfR41ew5uygjI
         th0OFLio5j1T6MgMnPK7zDuGnOfI/+RCyQAqqGtQmBfwRbMr8NM9Ksv+vJbSd0Glh6sW
         +dPWr7AFNFczdh6o43zrzHc4FEWq6Rz/aWU8ujBrM/ooha8CHHJmjbsxNI55dmg38rM9
         6Obt+WZQpSVO8S20c7eV5O83OokRiGQjgr/BrPwzzQUEAwVd/UOZAYoF15fzb8Z63mJl
         ODAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QbtHWfZ+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCGCvIgbvZHI3Rnpifc+UO52i7gqN2D+RQn2vFGnCQY=;
        b=h1JZxLWZApobU9rID+TeSQaWy6nDZD9kFEG0e+qE7CoXTK0Tw403tF18kp7+GEUglz
         AcEkloZxBH5RPKjgYHFGtKpchpIWtrKPL9paBcl0ARYDw/Nu7lIxlv3E04Y+bOqR19WH
         r2MmMCMsWdYsVCMBj1dFTnj/+mvm7sBCoxiEk4VnNVDYiUXrryaT9Wig9CEn1fhCWt0b
         63YBMpR65P3ulklvolDKMAPSoqjohYm5SZIfFUbZ+9TLXr4x2dD6Eaj1DHqOAFc7IvTy
         AEurba2lyqhDH1k+gh/L1y8Dzg7cH37lOjY/CTIEJUxndks5s2oFkgtmWNhGEvUQFAYG
         YD2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCGCvIgbvZHI3Rnpifc+UO52i7gqN2D+RQn2vFGnCQY=;
        b=Nje3kqeThPoboeFCF8lJRZPjzYaylLO+EbXPhg46ghztRM2OgTBAfV+4eKJTLAfsLY
         qE5bYa6YJPWfzYKDJevHud8sU5B/40KuiYIK0oaXJQi7DG4sRbSM+VLh3xgEgavfaS4d
         Ff5AyLZAo+lI7KQkhy+BY+A+QW8TgbJkV5JBuKISoRiNtRbEwVBqCDAQsh+yLjPwwYv1
         XqGBXxCqxomc8xtD5ym16RFxwCXUvA7Z6H2BFdzMzrieg51sSFYwrYz1bOnAENSXmk6Y
         lWeJeA27OpDw5V5vCzX1eZiEFcyanoy3o9nbNnaY6g1wOc7KghJpd6GF/16wssoYPrxM
         pQKQ==
X-Gm-Message-State: AOAM5303ILyfWXGmvgCi6b+yxED4RtoI9giN5XNuBDxxrvZJp9EfDkM7
	cuIsHo9HLRVNeaCI05SpAEc=
X-Google-Smtp-Source: ABdhPJwTdRhbotDheiMGdI5tVOg2ftp9tVFCGQ3WD5goXCAEUNo9oZWfvdG5OM0lkOWTVWWy7ArvJA==
X-Received: by 2002:ac8:9d:: with SMTP id c29mr4379792qtg.288.1590586634530;
        Wed, 27 May 2020 06:37:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7406:: with SMTP id p6ls2026256qkc.8.gmail; Wed, 27 May
 2020 06:37:13 -0700 (PDT)
X-Received: by 2002:a05:620a:6bc:: with SMTP id i28mr4179043qkh.330.1590586633854;
        Wed, 27 May 2020 06:37:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590586633; cv=none;
        d=google.com; s=arc-20160816;
        b=VrKG0jVGGRAX2+nQThLH8sfK6KTsb75FQYiDoS1HmcPeZMpEK1Jt74zbipO8Zo2//e
         xk9JjZsKgVPG3ydatt8XEQU4t4/9oDQNmFUjomACsQnTWhvvbtG3Wqlxw9yyj4ytUvWg
         2NXss6BjI5BBv3i0/fANduwQ8IeBhR/pAjn4yDJyJsEjfijnOQ58gjuPBdGJLJ4AkUmh
         +4f+GbAfslmnehyqx8DN+UOygOtixCGNcV+pYKkW2iHGi2y6F+mICxhrJH8YyJct57Qx
         LW+GGZoYUPxdruUjQginfUi3xazh6RTBsLzg0OPo2pip0yp2wj2PZbZyR4MyV11omxqO
         BXkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AwQUYVAQCrlzegHmktwvd3qax/+buVYaETqLr5p2maM=;
        b=V7kIDaXrbbYC9d4w+8ZVVVhHFyECtYc1/kHo5zcDcgOGFubvXaOHhkxHqWXXns7lZV
         h83LnCwvRMCd087JtUQQwZJYPN/o3zDB2Xaoa0oe1bWyTFWA/jhDuEOJ2aA1nxnB9fXz
         vFZH9ND0/yokpVDiI2P0WIUqFxya3ustJ71EJJEPR2SENGbxEggSKQD25Q1akCP5RJXG
         /0po/Xz62mFR4WU753Bap4AU+b2xqWI5FQYHHFop+G3IyQP2mXyVNtKgvBEJ904uDcMl
         rp0QmtIYOmy+WRCnlNaoLOazeRyRWzQ/fx4V+dEBV1O8dSVzgSQiFbRLsGh1/ay/RvAA
         TLzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QbtHWfZ+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id s11si199635qtq.1.2020.05.27.06.37.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 06:37:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b3so21675039oib.13
        for <kasan-dev@googlegroups.com>; Wed, 27 May 2020 06:37:13 -0700 (PDT)
X-Received: by 2002:aca:d0d:: with SMTP id 13mr2676966oin.172.1590586219764;
 Wed, 27 May 2020 06:30:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com> <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
In-Reply-To: <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 May 2020 15:30:08 +0200
Message-ID: <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: sedat.dilek@gmail.com
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QbtHWfZ+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 27 May 2020 at 15:11, Sedat Dilek <sedat.dilek@gmail.com> wrote:
>
> On Wed, May 27, 2020 at 2:50 PM Arnd Bergmann <arnd@arndb.de> wrote:
> >
> > On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > > > >
> > > > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > > > of the drop I saw with gcc, compared to current mainline.
> > > > > >
> > > > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > >
> > > > >
> > > > > Hi Arnd,
> > > > >
> > > > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> > > >
> > > > I meant v5.7.
> > > >
> > > > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > > > >
> > > > > Is there a speedup benefit also for Linux v5.7?
> > > > > Which patches do I need?
> > > >
> > > > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > > > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > > > linux-next
> > > > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > > > almost back to the speed of linux-5.7.
> > > >
> > >
> > > Which clang version did you use - and have you set KCSAN kconfigs -
> > > AFAICS this needs clang-11?
> >
> > I'm currently using clang-11, but I see the same problem with older
> > versions, and both with and without KCSAN enabled. I think the issue
> > is mostly the deep nesting of macros that leads to code bloat.
> >
>
> Thanks.
>
> With clang-10:
>
> $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
>  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> +HAVE_ARCH_KCSAN y

Clang 10 doesn't support KCSAN (HAVE_KCSAN_COMPILER unset).

> With clang-11:
>
> $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
>  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
>  CLANG_VERSION 100001 -> 110000
> +CC_HAS_ASM_INLINE y
> +HAVE_ARCH_KCSAN y
> +HAVE_KCSAN_COMPILER y
> +KCSAN n
>
> Which KCSAN kconfigs did you enable?

To clarify: as said in [1], KCSAN (or any other instrumentation) is no
longer relevant to the issue here, and the compile-time regression is
observable with most configs. The problem is due to pre-processing and
parsing, which came about due to new READ_ONCE() and the
__unqual_scalar_typeof() macro (which this patch optimizes).

KCSAN and new ONCEs got tangled up because we first attempted to
annotate {READ,WRITE}_ONCE() with data_race(), but that turned out to
have all kinds of other issues (explanation in [2]). So we decided to
drop all the KCSAN-specific bits from ONCE, and require KCSAN to be
Clang 11. Those fixes were applied to the first version of new
{READ,WRITE}_ONCE() in -tip, which actually restored the new ONCEs to
the pre-KCSAN version (now that KCSAN can deal with them without
annotations).

Hope this makes more sense now.

[1] https://lore.kernel.org/lkml/CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com/
[2] https://lore.kernel.org/lkml/20200521142047.169334-1-elver@google.com/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP%2BxNozRbmHJXZqXGFw%40mail.gmail.com.
