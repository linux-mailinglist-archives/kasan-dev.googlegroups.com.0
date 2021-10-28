Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBD435GFQMGQELEMX7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F8EB43DBB6
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 09:13:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id h5-20020a2e9005000000b00210d01099b3sf1276564ljg.17
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 00:13:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635405199; cv=pass;
        d=google.com; s=arc-20160816;
        b=A8SwcAt2t91wuVsioOhl0DzWlinNrYaphk0XGE2ik67BLCXVptQhz0pKJL5RfKDztm
         +YPv6rzeUZSYeuRKjJV/abWzg9figRzZvPuhWpI5TM2q+XnBve654H+nroNt6GNXWVv5
         0Gbfi3NE5AmDhoeyZfkGBwUSbWRZHN+rZVDuvNx9ZlmTQtmY9cj66V7JQ3oUCvoFsZA8
         fneWNEbOPdwkkPzsI9u4SeGrZRLsYd5WJosqFykQM7hQnbL78xjAToO54aamnBUJiPF9
         uVuYh8yXcVjmswnjV1fyhsBugRx2vNhDkcOwXrXCCcLiS/GW0X9+HrE90/B7omsKRbHx
         8cPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=YxseKFGAe2fZSN4/ISGNdaXimw2uPX2Ja+FqMdlPdEc=;
        b=e+UOBnrjYHbNWu1Ca0NyjoL+3Un8d9HTr1gElCCoBh5F3xM68tQs1L+I9DnGb5H/g9
         ATIAAXW2R/FHPEgZZiZawSRjls7vxphe5UJ/JFR3ec/H9Duj03/vJWjD4YxsXEp9vgO6
         +4HHTXPRW67PLs7xuLhmloG762bVqekyENdiXWYcGcrx0lnY89BW3WIZSzzk+qaSWTKi
         V+Um0zh9Kd+fPi5/u1hSFalmNKPOXj3Vxl413YxLQmY0UuvhQGQlwpXQIlncRkLErCF1
         R3QVQvp9FQiEsgSQAJDnNjRn60uGoPdEolSkiJV1mYMviQoXYaVjV3ZafKGojTGCpR82
         WhSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=SG2iTgh7;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YxseKFGAe2fZSN4/ISGNdaXimw2uPX2Ja+FqMdlPdEc=;
        b=LxsNFdOK+K8PPXrQb9LWpn92WbrAK9Exj5MjLM9qpkF3cmzUndHZVS1VI9AVd6e62t
         mZ+pZvyuzKhPklFHiVprSAzVpKFGqr2kvnbfunLWSgK6flUj8U7SWiDdg8YKN060M1iJ
         e/bXIgePNlV6B+ESE82oaIXuZJVUw3l8l+XS1tJxVaBau15QZpSmGB02HkQdmpdPBDuq
         GQCNXobSWByi4LsopaFBWG4WweMhg03plZkjc+XfLFium/DRhZkF/G8oJiAgK8+TgWB8
         RXg/b6HUt8HXRR6mXMSdy43LMPP3mMY4c4NX5JY9wVtiGB8h30aPQtuiyPBkyndXOhfn
         RYSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YxseKFGAe2fZSN4/ISGNdaXimw2uPX2Ja+FqMdlPdEc=;
        b=173kMkTtuEJBxTe75yolBVM3opKRahZAeILc2HuAWfNecC4Aq2DovoCEZxVrO+/iMb
         VEA7VQXgInInkqD9Za2ivPkynEP/28vBCrNvZU5ttv2YnYjVu9LC4O4hZmxl54r8wLtw
         V0IDeuTTGS/0hJtflT0snIld3W83x8yS40VStF3ykvQK2bXQLFfaCEsYAr2DabS80MOj
         qmX6Vz4ZgEUqMMK6BUlmydm/VAEl66sVntE92pemAPdac+VA/d7pM6UZmXy8Vs6z4XVv
         aGXyqls6Wy0vJX/kcyTRTwg9ugECkcD7SpDiSxqiW8g4ZDALbZDchnLDa8J1TrKBT5Il
         7GZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GiF9dGm+QEWi23XxajaKb9AQoUwWdPFK5mCXLjFxEX2UjUqv8
	MFH0ywitXEbXT8P2nh4yVz4=
X-Google-Smtp-Source: ABdhPJyMdhsvHOOyhhJlU5gQhpt7FEtV/gqGn3JsgruicPlVWA+c7RAFSt2XPi9fJQhFS3hHIg3YFQ==
X-Received: by 2002:a05:6512:1690:: with SMTP id bu16mr2420575lfb.401.1635405199691;
        Thu, 28 Oct 2021 00:13:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0f:: with SMTP id k15ls428843ljq.5.gmail; Thu, 28
 Oct 2021 00:13:18 -0700 (PDT)
X-Received: by 2002:a2e:9dc7:: with SMTP id x7mr2966122ljj.144.1635405198623;
        Thu, 28 Oct 2021 00:13:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635405198; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+5mHhsuSxK7oqistoeaXzTNkbAt2C7nc9g6tMfryUBg3UdRHo2Hm4Kvd2nj3qmIIV
         EojeddvGEzcBnICgUNfuLH1vDs2QTFMe2IIitYBt3npNchHsZoLtCILZjVrOQ6rN9gV4
         RgGdPKOwPhSIcD1W4WkNXw3F4ouSdx4S7S1OYDSjL5B8dYgZPMkigAsDngieBbiwFgee
         V9TnQ9D0jGA+GBWbjTDFn4w6wVCzkd3/G4WRevC70BdjARN6lcatVNmGGu6zMTLJ19ja
         T1a9qVULnJO9Dof2ZeFUvW1mGaDUKPXIdZ6nFGqtgSwj741yhhZ55ufQGcZTvJwtk+Em
         1mjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=odvfeEDaRD9GtVNTdM8NO1Yqau879jijgr+/mlFCwcA=;
        b=SIj4sb48FSQgGNMJvGDhcgDcBWAFPby/M7GKBfojwqgFnH7A+RUCcYzj8KJtTyJfxM
         7iSppsJhB2QFIvZ64QXAd23SndFihePtyvQnNNbueRsHFr9IcBmGkdjtew2ucozLyZKR
         jKLPX/EKcCpyCGvEYK1A9VZy+GBnq3Lf8qPlrjRM7muMCt8wYf03gwGAL5QT7BHGpdpI
         fsvEyz9B1MFiAA4oYW8lHi2Ur4m0jl6SqHMEDj5ExyyuKPbVtQajCjnwCrKphxZz0bnw
         TDQTtxLE+GzCcJXoeow/qTYg6qpIahuOwJSlVB7BTzy9Uuo0wovRsSwbJTPcEKXW5SeE
         NTsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=SG2iTgh7;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id v25si137025lfr.1.2021.10.28.00.13.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 00:13:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id C12363F178
	for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 07:13:17 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id q6-20020a056402518600b003dd81fc405eso4711770edd.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 00:13:17 -0700 (PDT)
X-Received: by 2002:a17:907:d22:: with SMTP id gn34mr3130399ejc.463.1635405197372;
        Thu, 28 Oct 2021 00:13:17 -0700 (PDT)
X-Received: by 2002:a17:907:d22:: with SMTP id gn34mr3130368ejc.463.1635405197149;
 Thu, 28 Oct 2021 00:13:17 -0700 (PDT)
MIME-Version: 1.0
References: <CA+zEjCus8+jzn074GwqhJ54Y180RASr_YaC=6zdBZSzonEtjDA@mail.gmail.com>
 <mhng-3ac5b2b9-c9da-42e5-bc56-d779fb4dd1dd@palmerdabbelt-glaptop>
In-Reply-To: <mhng-3ac5b2b9-c9da-42e5-bc56-d779fb4dd1dd@palmerdabbelt-glaptop>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 28 Oct 2021 09:13:06 +0200
Message-ID: <CA+zEjCv+whmnL_SFf20j06NpikaMtA7MNQ9+o8Zz7=1_nAtTqw@mail.gmail.com>
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, 
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=SG2iTgh7;       spf=pass
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

On Thu, Oct 28, 2021 at 8:45 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>
> On Wed, 27 Oct 2021 22:34:32 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> > On Thu, Oct 28, 2021 at 7:30 AM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> >>
> >> On Thu, Oct 28, 2021 at 7:02 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> >> >
> >> > On Wed, 27 Oct 2021 21:15:28 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> >> > > On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> >> > >>
> >> > >> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> >> > >> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
> >> > >> > Kconfig, it prevents asan-stack from getting disabled with clang even
> >> > >> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
> >> > >> > corresponding config.
> >> > >> >
> >> > >> > Reported-by: Nathan Chancellor <nathan@kernel.org>
> >> > >> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> >> > >> > ---
> >> > >> >  arch/riscv/Kconfig             | 6 ++++++
> >> > >> >  arch/riscv/include/asm/kasan.h | 3 +--
> >> > >> >  arch/riscv/mm/kasan_init.c     | 3 +++
> >> > >> >  3 files changed, 10 insertions(+), 2 deletions(-)
> >> > >> >
> >> > >> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> >> > >> > index c1abbc876e5b..79250b1ed54e 100644
> >> > >> > --- a/arch/riscv/Kconfig
> >> > >> > +++ b/arch/riscv/Kconfig
> >> > >> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
> >> > >> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
> >> > >> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
> >> > >> >
> >> > >> > +config KASAN_SHADOW_OFFSET
> >> > >> > +     hex
> >> > >> > +     depends on KASAN_GENERIC
> >> > >> > +     default 0xdfffffc800000000 if 64BIT
> >> > >> > +     default 0xffffffff if 32BIT
> >> > >>
> >> > >> I thought I posted this somewhere, but this is exactly what my first
> >> > >> guess was.  The problem is that it's hanging on boot for me.  I don't
> >> > >> really have anything exotic going on, it's just a defconfig with
> >> > >> CONFIG_KASAN=y running in QEMU.
> >> > >>
> >> > >> Does this boot for you?
> >> > >
> >> > > Yes with the 2nd patch of this series which fixes the issue
> >> > > encountered here. And that's true I copied/pasted this part of your
> >> > > patch which was better than what I had initially done, sorry I should
> >> > > have mentioned you did that, please add a Codeveloped-by or something
> >> > > like that.
>
> OK, those should probably be in the opposite order (though it looks like
> they're inter-dependent, which makes things a bit trickier).
>
> >> >
> >> > Not sure if I'm missing something, but it's still not booting for me.
> >> > I've put what I'm testing on palmer/to-test, it's these two on top of
> >> > fixes and merged into Linus' tree
> >> >
> >> >     *   6d7d351902ff - (HEAD -> to-test, palmer/to-test) Merge remote-tracking branch 'palmer/fixes' into to-test (7 minutes ago) <Palmer Dabbelt>
> >> >     |\
> >> >     | * 782551edf8f8 - (palmer/fixes) riscv: Fix CONFIG_KASAN_STACK build (6 hours ago) <Alexandre Ghiti>
> >> >     | * 47383e5b3c4f - riscv: Fix asan-stack clang build (6 hours ago) <Alexandre Ghiti>
> >> >     | * 64a19591a293 - (riscv/fixes) riscv: fix misalgned trap vector base address (9 hours ago) <Chen Lu>
> >> >     * |   1fc596a56b33 - (palmer/master, linus/master, linus/HEAD, master) Merge tag 'trace-v5.15-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace (11 hours ago) <Linus Torvalds>
> >> >
> >> > Am I missing something else?
> >>
> >> Hmm, that's weird, I have just done the same: cherry-picked both my
> >> commits on top of fixes (64a19591a293) and it boots fine with KASAN
> >> enabled. Maybe a config thing? I pushed my branch here:
> >> https://github.com/AlexGhiti/riscv-linux/tree/int/alex/kasan_stack_fixes_rebase
> >
> > I pushed the config I use and that boots in that branch, maybe there's
> > another issue somewhere.
>
> CONFIG_KASAN_VMALLOC=n is what's causing the failure.  I'm testing both
> polarities of that, looks like your config has =y.  I haven't looked any
> further as I'm pretty much cooked for tonight, but if you don't have
> time then I'll try to find some time tomorrow.
>

Arf, that was obvious and just under my nose: without KASAN_VMALLOC,
kasan_populate_early_shadow is called and creates the same issue that
the second patch fixes.

I'll send a v2 today and try to swap both patches to avoid having a
non-bootable kernel commit.

Alex

> >
> >>
> >> >
> >> > >
> >> > > Thanks,
> >> > >
> >> > > Alex
> >> > >
> >> > >>
> >> > >> > +
> >> > >> >  config ARCH_FLATMEM_ENABLE
> >> > >> >       def_bool !NUMA
> >> > >> >
> >> > >> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> >> > >> > index a2b3d9cdbc86..b00f503ec124 100644
> >> > >> > --- a/arch/riscv/include/asm/kasan.h
> >> > >> > +++ b/arch/riscv/include/asm/kasan.h
> >> > >> > @@ -30,8 +30,7 @@
> >> > >> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> >> > >> >  #define KASAN_SHADOW_START   KERN_VIRT_START
> >> > >> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> >> > >> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
> >> > >> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
> >> > >> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> >> > >> >
> >> > >> >  void kasan_init(void);
> >> > >> >  asmlinkage void kasan_early_init(void);
> >> > >> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> >> > >> > index d7189c8714a9..8175e98b9073 100644
> >> > >> > --- a/arch/riscv/mm/kasan_init.c
> >> > >> > +++ b/arch/riscv/mm/kasan_init.c
> >> > >> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
> >> > >> >       uintptr_t i;
> >> > >> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
> >> > >> >
> >> > >> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> >> > >> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> >> > >> > +
> >> > >> >       for (i = 0; i < PTRS_PER_PTE; ++i)
> >> > >> >               set_pte(kasan_early_shadow_pte + i,
> >> > >> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCv%2BwhmnL_SFf20j06NpikaMtA7MNQ9%2Bo8Zz7%3D1_nAtTqw%40mail.gmail.com.
