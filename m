Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBEGP36FQMGQEYAQG4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0527943B146
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 13:33:37 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id z137-20020a1c7e8f000000b0030cd1800d86sf5011798wmc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 04:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635248016; cv=pass;
        d=google.com; s=arc-20160816;
        b=EQIc1bPH/shM3QRlisL4tAja4I4M7lGUECtIbNOHcV6qwNH4U5FP2jOoIkLtehOtzz
         OCSpwlgjyf8NNF7N9Ioqi6PcMDQizfyVapy41oZWDXuAcEPQntEkpJ3V09DGDP6XYqkP
         zOZstxCHXq6zt6DeIlBFm7cnP9lAEB/5ZepHJ5d/OI6C7RmtMgPe/41WbysQeX5B/6oU
         mWqBroGMZtyeiUSRi52LUIDIudGAkj0qgsv7L7uGCd7ydyni9YEJ46NQ6VbDWcVH4CT8
         2ZJRPvdmfaNT9MGidSDKDvil4vX+m2o7T0HRPmAvPNTgy6VYN6TZmJQFApNsZUvaHnqz
         kubg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=VvCQ1akbfhJMzBX7epqso1rd/SUPNtxHXlR/H2F3s4M=;
        b=b+eBZOQbiXJN18s8NzrF0wpIjBgdFEludxJ6EncAfdcZuMmYvhop/iSIm3rj94FtDz
         0cyG+rOLyADLm7dmb1+xtttaAIfjC1SrIUOibv8nBZbs+XPylFjmPuLV5SvxuasSDSsJ
         m8mAgqRjoinSGuilSqX/3kjMrBYQTN9/8UmEKFqMhrW3bySiMecG4Se7YHicHyac78Gp
         LXsfVX/xeTlYe6jWSxJh8e3QjFDSvLzNnUraPMpYJ3PsahfIKxTC2G0bRW0IGnqz/YRF
         G8dxnaes4JcMABvzwX808ft+YTye6VACP0LUNtOWlmzHO6+nQm1HMrmf6fin5l2xE2HA
         /5xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=YOg1qO1H;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VvCQ1akbfhJMzBX7epqso1rd/SUPNtxHXlR/H2F3s4M=;
        b=o3iZ5oJZlWTIH4+ZU8OPi4xLHSi9enyQRqL0Lk5R0X33Io4CkAE2mPANpHOwu+/UvE
         XcL4eo0223GZ/qvZu0LcPSwP1E0MxYu2pV5Isi/K8mBA/cEUqtYxABGt7IT3lhIu0F82
         jDpjDs40ajwk4WSA8G5Giubf7zZ3Y8Qy50NG/LK5waL0uqOaGY61b+83sPOzeu6En8R3
         +MKPPJyQoYOyC6R7obATdXa/QhvG5nr4qKmTLU6P+5812wj6Rx8hEHNXMbWns8QJyNcA
         /SWjLQbmWBJnxUK0ZZ4uj0vsPDZ8MC0YFo1W/yOzAAxTtjtcYiuMy5dkKXbwE8eSS/c4
         4iMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VvCQ1akbfhJMzBX7epqso1rd/SUPNtxHXlR/H2F3s4M=;
        b=pA1rQXfPYx+1eNADLbTDUIzHtRPjg/AcRjstrA7ymv1V21dpFFdNwHMMDpBnSsxtuP
         UwmKTlO1LJPLg+3KYKl9N/H5lTr6ik4SF/HLkGRUgCNd0nOczJqhpTj7MF5op6NZqm4b
         L4IhvAMKGBl8QekCXHZKQIqexZj+PuluOBxs1p5n4T+hDRyXY81U96rRs1pY2S6bT0Yc
         BNyHWITNaE903gg65YbMsRoWJwb8NoL7DYBLMCdmDTcK0jdSjPdxHs27maL5Pt/RTNUX
         t+gdVbwzQs/va6TFY7Mx3NFx90qy/MNBDLDaYh12jPuOFBTDKdbFKY7haYD7hG0FlC6m
         m2oQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53134IONwGZMbYcvPligMmBq3i9di2tUm85MX213I8ZOi130vVCB
	B6FLPufvG+47c4AcMcskScA=
X-Google-Smtp-Source: ABdhPJxeZ2oPZ9KasS+dL+i5ehHtRgG7HZ94BcAO6F7FM2bKGh0HCET4dQB3KnApZeQySU7QFmoyTA==
X-Received: by 2002:adf:d4cc:: with SMTP id w12mr1003983wrk.275.1635248016627;
        Tue, 26 Oct 2021 04:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6b08:: with SMTP id v8ls5313010wrw.3.gmail; Tue, 26 Oct
 2021 04:33:35 -0700 (PDT)
X-Received: by 2002:a05:6000:110b:: with SMTP id z11mr4366573wrw.172.1635248015708;
        Tue, 26 Oct 2021 04:33:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635248015; cv=none;
        d=google.com; s=arc-20160816;
        b=mphzkWGTKqVjCS5Gg5r5XGHzPZ2oJvX3IYbdYL0RUD/B2LRN0b3Cq++evsNX2S90Zx
         mhISQmG1nz0MIMuy2Lx+tcWaB125b4pc5MkC59btozzE0Qr5h9aVv3aS1RMjDGhG7U6H
         1A2LZ7bzGyeRXFgt+HlR6MvOEhpb+5jQKc6sgl3TAEERSyEVZyFV7zsJXSaufM5mrbrG
         vRFXuIMa0lH6ntRfNBm8YAx6NYldmSZlCwvTMi56q2VJRd/VwWq4EiMw2ota/Kcvg6Pv
         mazB507fRsyQBlvyY9zQsON1P1SqQ2VvzC/veb8/RyUiKzFkHeEZmoanKh/YkzTx2UUf
         r3Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=p/YSQVHQ2qVFgAnoHpMJgz8Z7UR53z+rl6CiCMg8icA=;
        b=tN0j/AKtPLdJEqnkO0vfrbYTN7VHdTvusPi27a8Mow8XekCHIG244xA36I7A7mVBVf
         tsgaDY6Jx1f/skC7Xr2W5otuqDixZpRB2Ruk7r5fJiVYmTSwngHqtrQlRmSSsaIxF3Hi
         tGr70WeXEuiYGFqV13R4zaT4FOABxk35qfp3go0lTEAoqG6hPonxcsTaVXU49li80KOt
         pZXQdb6XXL40UVRkIqTW+rVnrJT0xrg6cijDOPhypioiYKEhisJm6gufZuveFinqlhK3
         ICdBX55cBa97ReA7kqkBT2Z6c4WTR5vjnZwD4v1GSa4YnSZBccVRK0tu0I7iHdLlcv8d
         ZRhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=YOg1qO1H;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id f9si23718wmg.2.2021.10.26.04.33.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Oct 2021 04:33:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f71.google.com (mail-ed1-f71.google.com [209.85.208.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 163533F19B
	for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 11:33:35 +0000 (UTC)
Received: by mail-ed1-f71.google.com with SMTP id i9-20020a508709000000b003dd4b55a3caso3111257edb.19
        for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 04:33:35 -0700 (PDT)
X-Received: by 2002:a17:907:3e0a:: with SMTP id hp10mr5178678ejc.156.1635248012164;
        Tue, 26 Oct 2021 04:33:32 -0700 (PDT)
X-Received: by 2002:a17:907:3e0a:: with SMTP id hp10mr5178648ejc.156.1635248011842;
 Tue, 26 Oct 2021 04:33:31 -0700 (PDT)
MIME-Version: 1.0
References: <YUyWYpDl2Dmegz0a@archlinux-ax161> <mhng-b5f8a6a0-c3e8-4d25-9daa-346fdc8a2e5e@palmerdabbelt-glaptop>
 <YWhg8/UzjJsB51Gd@archlinux-ax161> <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
 <990a894c-1806-5ab2-775e-a6f2355c2299@ghiti.fr> <CA+zEjCt28iYQARQa=8Nsw8+_j0PuEee==gUqjKjasMo+w2Ohwg@mail.gmail.com>
 <CACT4Y+YB8bjqxFfSrXKbfETXJAUxH=HR+kizC0T-AZLArY3A5A@mail.gmail.com>
In-Reply-To: <CACT4Y+YB8bjqxFfSrXKbfETXJAUxH=HR+kizC0T-AZLArY3A5A@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Tue, 26 Oct 2021 13:33:20 +0200
Message-ID: <CA+zEjCtVYLdg3FQnnZjv+Bb-bn2mvj9BCZF787dbNNRHPvyZug@mail.gmail.com>
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexandre ghiti <alex@ghiti.fr>, Nathan Chancellor <nathan@kernel.org>, 
	Palmer Dabbelt <palmer@dabbelt.com>, elver@google.com, akpm@linux-foundation.org, 
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	ndesaulniers@google.com, Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, Paul Walmsley <paul.walmsley@sifive.com>, 
	aou@eecs.berkeley.edu, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=YOg1qO1H;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

On Tue, Oct 26, 2021 at 6:48 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, 26 Oct 2021 at 06:39, Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > Hi,
> >
> > On Fri, Oct 15, 2021 at 3:08 PM Alexandre ghiti <alex@ghiti.fr> wrote:
> > >
> > > On 10/14/21 8:31 PM, Alex Ghiti wrote:
> > > > Hi Nathan,
> > > >
> > > > Le 14/10/2021 =C3=A0 18:55, Nathan Chancellor a =C3=A9crit :
> > > >> On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
> > > >>> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote=
:
> > > >>>> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
> > > >>>>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor
> > > >>>>> <nathan@kernel.org> wrote:
> > > >>>>>> Currently, the asan-stack parameter is only passed along if
> > > >>>>>> CFLAGS_KASAN_SHADOW is not empty, which requires
> > > >>>>>> KASAN_SHADOW_OFFSET to
> > > >>>>>> be defined in Kconfig so that the value can be checked. In RIS=
C-V's
> > > >>>>>> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which mea=
ns
> > > >>>>>> that
> > > >>>>>> asan-stack does not get disabled with clang even when
> > > >>>>>> CONFIG_KASAN_STACK
> > > >>>>>> is disabled, resulting in large stack warnings with allmodconf=
ig:
> > > >>>>>>
> > > >>>>>> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb03=
5q02.c:117:12:
> > > >>>>>>
> > > >>>>>> error: stack frame size (14400) exceeds limit (2048) in functi=
on
> > > >>>>>> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
> > > >>>>>> static int lb035q02_connect(struct omap_dss_device *dssdev)
> > > >>>>>>             ^
> > > >>>>>> 1 error generated.
> > > >>>>>>
> > > >>>>>> Ensure that the value of CONFIG_KASAN_STACK is always passed
> > > >>>>>> along to
> > > >>>>>> the compiler so that these warnings do not happen when
> > > >>>>>> CONFIG_KASAN_STACK is disabled.
> > > >>>>>>
> > > >>>>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
> > > >>>>>> References: 6baec880d7a5 ("kasan: turn off asan-stack for clan=
g-8
> > > >>>>>> and earlier")
> > > >>>>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> > > >>>>>
> > > >>>>> Reviewed-by: Marco Elver <elver@google.com>
> > > >>>>
> > > >>>> Thanks!
> > > >>>>
> > > >>>>> [ Which tree are you planning to take it through? ]
> > > >>>>
> > > >>>> Gah, I was intending for it to go through -mm, then I cc'd neith=
er
> > > >>>> Andrew nor linux-mm... :/ Andrew, do you want me to resend or ca=
n you
> > > >>>> grab it from LKML?
> > > >>>
> > > >>> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
> > > >>>
> > > >>> (assuming you still want it through somewhere else)
> > > >>
> > > >> Thanks, it is now in mainline as commit 19532869feb9 ("kasan: alwa=
ys
> > > >> respect CONFIG_KASAN_STACK").
> > > >>
> > > >>>>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFS=
ET in
> > > >>>>> comment (copied from arm64). Did RISC-V just forget to copy ove=
r the
> > > >>>>> Kconfig option?
> > > >>>>
> > > >>>> I do see it defined in that file as well but you are right that
> > > >>>> they did
> > > >>>> not copy the Kconfig logic, even though it was present in the tr=
ee
> > > >>>> when
> > > >>>> RISC-V KASAN was implemented. Perhaps they should so that they g=
et
> > > >>>> access to the other flags in the "else" branch?
> > > >>>
> > > >>> Ya, looks like we just screwed this up.  I'm seeing some warnings=
 like
> > > >>>
> > > >>>     cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 w=
ith stack protection
> > > >>> is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=80=
=99 for this target
> > > >>
> > > >> Hmmm, I thought I did a GCC build with this change but I must not =
have
> > > >> :/
> > > >>
> > > >>> which is how I ended up here, I'm assuming that's what you're
> > > >>> talking about
> > > >>> here?  LMK if you were planning on sending along a fix or if you
> > > >>> want me to
> > > >>> go figure it out.
> > > >>
> > > >> I took a look at moving the logic into Kconfig like arm64 before s=
ending
> > > >> this change and I did not really understand it well enough to do s=
o. I
> > > >> think it would be best if you were able to do that so that nothing=
 gets
> > > >> messed up.
> > > >>
> > > >
> > > > I'll do it tomorrow, I'm the last one who touched kasan on riscv :)
> > > >
> > >
> > > Adding KASAN_SHADOW_OFFSET config makes kasan kernel fails to boot.
> > > It receives a *write* fault at the beginning of a memblock_alloc
> > > function while populating the kernel shadow memory: the trap address =
is
> > > in the kasan shadow virtual address range and this corresponds to a
> > > kernel address in init_stack. The question is: how do I populate the
> > > stack shadow mapping without using memblock API? It's weird, I don't
> > > find anything on other architectures.
> >
> > @kasan: Any idea what we are doing wrong in riscv to encounter the
> > above situation?
>
> Hi Alex, Palmer,
>
> The patch changes the definition of the KASAN_SHADOW_OFFSET const.
> Does it's value change as a result or not? Have you tried to print it
> before/after?
> If value does not change, then this is more mysterious. If it changes,
> then there lots of possible explanations (points to unmapped region,
> overlaps with something), but we need to know values before/after to

So I debugged a bit more what happened here, and actually the culprit
is the call to kasan_populate_early_shadow at the beginning of
kasan_init which write-protects the access to kasan_early_shadow_page
and hence the write fault later when using memblock. I don't see the
point of this call anyway since we populate swapper_pg_dir in
kasan_early_init and then we write-protect the access to
kasan_early_shadow_page at the end of kasan_init.

But that may not be ideal, so I'm open to a better suggestion than
just removing the call to kasan_populate_early_shadow.

Sorry I did not dig further before asking and thanks for your time,

Alex

> answer this.
>
>
> > Thanks,
> >
> > Alex
> >
> > >
> > > And just a short note: I have realized this will break with the sv48
> > > patchset as we decide at runtime the address space width and the kasa=
n
> > > shadow start address is different between sv39 and sv48. I will have =
to
> > > do like x86 and move the kasan shadow start at the end of the address
> > > space so that it is the same for both sv39 and sv48.
> > >
> > > Thanks,
> > >
> > > Alex
> > >
> > >
> > > > Thanks,
> > > >
> > > > Alex
> > > >
> > > >> Cheers,
> > > >> Nathan
> > > >>
> > > >> _______________________________________________
> > > >> linux-riscv mailing list
> > > >> linux-riscv@lists.infradead.org
> > > >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> > > >>
> > > >
> > > > _______________________________________________
> > > > linux-riscv mailing list
> > > > linux-riscv@lists.infradead.org
> > > > http://lists.infradead.org/mailman/listinfo/linux-riscv
> > >
> > > _______________________________________________
> > > linux-riscv mailing list
> > > linux-riscv@lists.infradead.org
> > > http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BzEjCtVYLdg3FQnnZjv%2BBb-bn2mvj9BCZF787dbNNRHPvyZug%40mail.gm=
ail.com.
