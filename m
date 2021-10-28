Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBHXL5CFQMGQEWO6CMNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B34E43DABE
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 07:31:11 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id q6-20020a056402518600b003dd81fc405esf4498509edd.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 22:31:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635399071; cv=pass;
        d=google.com; s=arc-20160816;
        b=ptwa9Hw10WKXjjsvKi8og+D5CBA1uzALfcxMA8THHSIsFiY6ckIxECp+xwWOW9JShN
         p7esOG9srInigxhrQts14nptYj7H0G0Ky7jc3vZgJ90nx64Rl76C5F3wSQJ1HFElP3Cp
         smwu8f0oxQQbssuM5k7y4se0Pa1cqYfjemUkH7tuPypQ/wDQySSkwIKjArG2IOslf8A2
         XV+lSFiQ764WJEVzgw+GDLRmxO5jCI6y5ZMwP5Ylg3r9tJosrv+3Z3ykJ3esPdjPdTqZ
         tBpiuTqtapHg7RylHmUte8LtQzLFndl56XjU5VZfqaP3hjoESTBjCdVkVZhjsHYhJ7Ha
         D62A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=bl5rcFrFjMwmfltDjnBUUw97zJU/kXVDPd/MIOW8y94=;
        b=VD2+Ea+q+QEcRymN9z+R7PaGa11apkC/clOlgI88OQv7MIVtnc54tYcsFbexljayRj
         8oGADW3+xpdXHkEpBkCBDko4LxFA93Dg1vMqFKcPlcFg5jIipi6tcGCm6lzlPeJ9dNir
         LSXem9Ge3PWreKrGIg2g5db1EojsabK0WpXh6CGGxu/MtJC49vLM9aQ438IZqCht3SuX
         zbjpLlMdO1K1XBh1Jlts1e5niIkCXRJT0dCDPOoFhcR7nktuOs+WcOGvdib7HfSKF5SE
         GMWcFFudA3TmfwMn2fupCUJIYkNMUxhSpLKkFuhEVGDiFiJva5J/qAPAT6UgQHc62bW9
         dEgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=XmNKvwNb;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bl5rcFrFjMwmfltDjnBUUw97zJU/kXVDPd/MIOW8y94=;
        b=Ss9v2fz12zamLIire2mQJKHFkj4QXX7UzP46bkDBERJcfBayeYCCnh4pKOPX7BQALT
         qnkZ0/nNinQQwnQS1LJmkcSiCGao1PBErk0c3i2c67/z/HdHWw123hLqHVS0ibpVCtXx
         BGE3voM3dglvvFnQHrgDW6CCnT5NGioE39e4X+30I4awz5nkNbIgLrKjh6SW0frHGEp9
         qrB1B4lKdOqv2VXKqsJOCnoBqAiU8gk6IF+nwPkLVfOoxubnbf/9GD8/IAOlmucVAFU8
         QZGdwhLeIa2UA8MhplUawSJDOYM8wAYAgm5fhnj8DGI3/QuRaiT6HSwMnL1KbwdzjxNE
         WRlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bl5rcFrFjMwmfltDjnBUUw97zJU/kXVDPd/MIOW8y94=;
        b=CFkUKLWrjlLMw+OH0NTS7n8rLO3SX6NzwljqqwhuJ5y8Z9okviqYBko1sMSjTddosH
         zg9WdVEaXm6CILtji94NjDo2RAGmJDCYmUiDcJsjqFiCUxl6FaUvEMw9sDABR0oWOuev
         HEgTgeAjZQwfgUBTCcNDuEuJKAANJsSfCvz/svDOHi2+YdZnyno1vJwY1dCzoCTGLgm9
         saqULOsjRFwBkpGmtIx2QgSjmyuI/qPO76z+fSOEuANiYsUes77HmZsWULifz1vbZPlx
         +uDLxpwUNQ6iRBKQ2ROhN9m/JOPTsmCRqKRi0LDcA4IjeDFlxUjoyWdOL7LN2FwImtrk
         B2ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53115nIkejaGpyqEN768cdjqd0BJ7vwERbT1/ehzSH/lNqhNTgUM
	dmJMCup2LWU58WT/alZTnMM=
X-Google-Smtp-Source: ABdhPJwCdIt/v5+RaltXpifkoqeulsQ00jheUHOgbrqrvRDLPduSEptfOkdduZG+cLIYVtEAMoKC3A==
X-Received: by 2002:a05:6402:2789:: with SMTP id b9mr3201353ede.142.1635399070946;
        Wed, 27 Oct 2021 22:31:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd17:: with SMTP id i23ls749215eds.3.gmail; Wed, 27 Oct
 2021 22:31:10 -0700 (PDT)
X-Received: by 2002:a05:6402:11d4:: with SMTP id j20mr3171070edw.267.1635399070091;
        Wed, 27 Oct 2021 22:31:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635399070; cv=none;
        d=google.com; s=arc-20160816;
        b=WFXhmYY9ayJbqmGhqWM2czpi6hr0ZXzenbT1jdeVU7c1HCt5iqeNwsCKsWwEOv0bFg
         tlFHP9jBdSV41OCFAuNQngWPC6Uu4e3UUFu+SUN6fi77c1IYCeTiiLnkmXCdaq8O+Pcu
         86sYI5zYybPqsJjWphV3j7BYIf78AyeQDYrsQNGbPE1TQKmn6quSbMbQLZhDbDj65z2D
         PsJeg8PqLsSB2RRVdWZQB3go7ctcE+nCz+rwJE6/xy8x7LPB6SS99lpxToaDvSh++c2I
         xP4keQzJ6ctlNt04EmQdH8QYvL8FWDX6CNZQB4i3UigYCkNyQ6DrLhy+7pWeqLWmWTDz
         U2vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=noNS8SKbWs06fUT37mVtwhaSupIHvr5prwGIHsMJYxw=;
        b=f+49B0uiCmWPa48OJcQXzullTLYyxHLh8mcYZGs4MvjWMjz6XB8Pn99uYYN+/s0eXR
         3N62Pd9LUFb7Q+QpFRNoo4jhsahb7OWqyDkbvKge7boHYjaFZ0xKUM9+xk7qnX5Q+YeY
         Q6HqUesCryYDjklMqkIwrJ2QQG3fBChxf7osI3luCEWS9J2A1adNGtM+iq0Oy6Ao71S6
         gdNOpTto99CcpdR6u2NBIRtKMUpMayXc3Wr6vRCpjXzFpyimGAUaMVVomzWEEkLsyCTk
         6Xuq1plo6wA30vdlS60aDOovMOssXSU0EZ2Yh0rtHNO7Y2B9rPeAS2PFtCMPhdtgzPD6
         WC1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=XmNKvwNb;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id bi21si142605edb.0.2021.10.27.22.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Oct 2021 22:31:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id B9C973F165
	for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 05:31:09 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id u10-20020a50d94a000000b003dc51565894so4426181edj.21
        for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 22:31:09 -0700 (PDT)
X-Received: by 2002:a05:6402:190e:: with SMTP id e14mr3208498edz.20.1635399069429;
        Wed, 27 Oct 2021 22:31:09 -0700 (PDT)
X-Received: by 2002:a05:6402:190e:: with SMTP id e14mr3208483edz.20.1635399069250;
 Wed, 27 Oct 2021 22:31:09 -0700 (PDT)
MIME-Version: 1.0
References: <CA+zEjCuUCxqTtbox2K8c=ymHC8X97LV6CSO3ydJKgRR9cBXUEw@mail.gmail.com>
 <mhng-897d082f-5ca4-4d77-a69d-4efaa456bf3b@palmerdabbelt-glaptop>
In-Reply-To: <mhng-897d082f-5ca4-4d77-a69d-4efaa456bf3b@palmerdabbelt-glaptop>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 28 Oct 2021 07:30:58 +0200
Message-ID: <CA+zEjCvF7yCbA9KvsD+OaGXhEAF4x_jBB+OZ3C-Q6RctYSjd7w@mail.gmail.com>
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, 
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=XmNKvwNb;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Thu, Oct 28, 2021 at 7:02 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>
> On Wed, 27 Oct 2021 21:15:28 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> > On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> >>
> >> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> >> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
> >> > Kconfig, it prevents asan-stack from getting disabled with clang even
> >> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
> >> > corresponding config.
> >> >
> >> > Reported-by: Nathan Chancellor <nathan@kernel.org>
> >> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> >> > ---
> >> >  arch/riscv/Kconfig             | 6 ++++++
> >> >  arch/riscv/include/asm/kasan.h | 3 +--
> >> >  arch/riscv/mm/kasan_init.c     | 3 +++
> >> >  3 files changed, 10 insertions(+), 2 deletions(-)
> >> >
> >> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> >> > index c1abbc876e5b..79250b1ed54e 100644
> >> > --- a/arch/riscv/Kconfig
> >> > +++ b/arch/riscv/Kconfig
> >> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
> >> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
> >> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
> >> >
> >> > +config KASAN_SHADOW_OFFSET
> >> > +     hex
> >> > +     depends on KASAN_GENERIC
> >> > +     default 0xdfffffc800000000 if 64BIT
> >> > +     default 0xffffffff if 32BIT
> >>
> >> I thought I posted this somewhere, but this is exactly what my first
> >> guess was.  The problem is that it's hanging on boot for me.  I don't
> >> really have anything exotic going on, it's just a defconfig with
> >> CONFIG_KASAN=y running in QEMU.
> >>
> >> Does this boot for you?
> >
> > Yes with the 2nd patch of this series which fixes the issue
> > encountered here. And that's true I copied/pasted this part of your
> > patch which was better than what I had initially done, sorry I should
> > have mentioned you did that, please add a Codeveloped-by or something
> > like that.
>
> Not sure if I'm missing something, but it's still not booting for me.
> I've put what I'm testing on palmer/to-test, it's these two on top of
> fixes and merged into Linus' tree
>
>     *   6d7d351902ff - (HEAD -> to-test, palmer/to-test) Merge remote-tracking branch 'palmer/fixes' into to-test (7 minutes ago) <Palmer Dabbelt>
>     |\
>     | * 782551edf8f8 - (palmer/fixes) riscv: Fix CONFIG_KASAN_STACK build (6 hours ago) <Alexandre Ghiti>
>     | * 47383e5b3c4f - riscv: Fix asan-stack clang build (6 hours ago) <Alexandre Ghiti>
>     | * 64a19591a293 - (riscv/fixes) riscv: fix misalgned trap vector base address (9 hours ago) <Chen Lu>
>     * |   1fc596a56b33 - (palmer/master, linus/master, linus/HEAD, master) Merge tag 'trace-v5.15-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace (11 hours ago) <Linus Torvalds>
>
> Am I missing something else?

Hmm, that's weird, I have just done the same: cherry-picked both my
commits on top of fixes (64a19591a293) and it boots fine with KASAN
enabled. Maybe a config thing? I pushed my branch here:
https://github.com/AlexGhiti/riscv-linux/tree/int/alex/kasan_stack_fixes_rebase

>
> >
> > Thanks,
> >
> > Alex
> >
> >>
> >> > +
> >> >  config ARCH_FLATMEM_ENABLE
> >> >       def_bool !NUMA
> >> >
> >> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> >> > index a2b3d9cdbc86..b00f503ec124 100644
> >> > --- a/arch/riscv/include/asm/kasan.h
> >> > +++ b/arch/riscv/include/asm/kasan.h
> >> > @@ -30,8 +30,7 @@
> >> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> >> >  #define KASAN_SHADOW_START   KERN_VIRT_START
> >> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> >> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
> >> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
> >> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> >> >
> >> >  void kasan_init(void);
> >> >  asmlinkage void kasan_early_init(void);
> >> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> >> > index d7189c8714a9..8175e98b9073 100644
> >> > --- a/arch/riscv/mm/kasan_init.c
> >> > +++ b/arch/riscv/mm/kasan_init.c
> >> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
> >> >       uintptr_t i;
> >> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
> >> >
> >> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> >> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> >> > +
> >> >       for (i = 0; i < PTRS_PER_PTE; ++i)
> >> >               set_pte(kasan_early_shadow_pte + i,
> >> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCvF7yCbA9KvsD%2BOaGXhEAF4x_jBB%2BOZ3C-Q6RctYSjd7w%40mail.gmail.com.
