Return-Path: <kasan-dev+bncBCRKNY4WZECBBEH35KFQMGQECP32A6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id ADBFB43E4AA
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 17:11:14 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id r79-20020acaa852000000b002991da0573asf3207548oie.23
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 08:11:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635433872; cv=pass;
        d=google.com; s=arc-20160816;
        b=DckMlsfRqOuR5CpIBSoHt+TqJ3mukaxucDRmyBtAQ/nBgDxwPyVO77sTWXj1xWnAxL
         pQWL28mLQGwDp8aYkJ+C9+XXYG4HPKmDiVNQOCIc62Fpn0Lr1xs+2prNZ++xzi4UfQl0
         vUG9kNn7T6YB1f6lNp5ujzRFM0U65oIaA33GY/8+vbYY68Nv2qP2oBSigK+/ZXuou/5p
         nGVFo8y2vpqLe7Ycac/IXeVuyFzTOEeogyWTiWSkHAlX7VAXr8FMOcB7NzFAhyg+dq6T
         ImtNXpXDfGdpv0sJjUSnKCp554uH95KhVr8QLo8RqPqIPPn9pTQoibVaUQQnKCThju3v
         3m3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=OAALNjtcfGxC1W57STNaOYfkRstOha7sVBBrUC8vuuE=;
        b=cAGHE+mlk17rtS3r/5duod4gWNeR8uwlfWjK6kB/MRvT5amqoGnIHkVtdc1LN0hscs
         tL7piU/USGPsi8swufc/K5NlL816rAr+s6M20ZIIb/sYxMPvpACy5DdlUXHVuYfPmMQQ
         ZJ2ldo9MqNMMGsIDR5qQKNwqllcyy/w9wZ/p7cC+17B8q3o+Cq+bA1jib+oStjwNfZ+i
         E8zMmuWCbd4x//t0Uy0ncZSTxvZDVRUzrg7ReIn4K86AbCwCRmmXKSEGSSEn8+Zen1tG
         etsaLP1FbbBzRfZs2BCJ8UIEd+2uBn7xa+unCzem6Fxs6fLolwPmE7sTA8GWtG6PQ/T1
         +CmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=FSE7WAV8;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OAALNjtcfGxC1W57STNaOYfkRstOha7sVBBrUC8vuuE=;
        b=fkrdZ6uhIBtDvhOzTt9/CP6uxHz+VxDxLM9FrFgfgaXmZxhiGgmW/v8TRLsTDf5Xpe
         5VCz4w5O/2oljaJJKwranXeRnW4wQhAZlaLny2XrLrO2xCntHlXI6LNGZY33EJiOG6cx
         O4ujha1PRTJk1TU4/QKMMtPz2YVlFg8WjLuRvHNrTDy1MuPF+iQGj2nHdfqtkYCms7R9
         46VBf5+lMPxmTM0matTy369ruIYQ+qkRoHpOJ7xgQ6PmgnOV0mEaH0Azyu1WJVbuX8s7
         UnlQqdqWxN4FPiV6v0UyXu7/6d4mI7vi6tPLCaIObdQIq2UkxheAgTjpxeOINDpgGtIa
         ZFzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OAALNjtcfGxC1W57STNaOYfkRstOha7sVBBrUC8vuuE=;
        b=4NxBf2GHQY2E2sIgUPwwgDHGEM4LBEnjvBpDfcaqfZ0aVMatjTfRLaw7XKnfdipdjD
         hn/kN05wYBU2stgoQjJP1TWcBJnw6/jiP9aMYqZthtEENUWhVCL05n8CTP0ZOFplFSnf
         rVq5lPgSqqoWMiiT0m6IAakRk186L/G10x4zJlSJQX4tUINerlnssmTRlQF0oiXCI6X+
         mSc+Xp7dzXMY8dTZnhvx6A7nz043l0xXz4nIyYezWlUT4XBRm7fNUvNu2sUQJh9JgpE8
         KgBhg6AFXqPIvw/YErFMQzbA6b76D1UBFADk8q74FipJUD8A+vKeH5PIoLZXKLPJfqLs
         ScXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zYt6KtPRFGPycgDLMAUQ7J7BBYsEoETCiVzZzdLlZYUbKzUb2
	EbWH3HcoUkg9dZDB2HpCLDA=
X-Google-Smtp-Source: ABdhPJwip1xtOlDa60DifvNAno7U38UoxQuHxISPDNJoO0YUNfcASQuUPrZC9LEKHZdUzBaHXTqqtA==
X-Received: by 2002:aca:dbc2:: with SMTP id s185mr3329120oig.141.1635433872438;
        Thu, 28 Oct 2021 08:11:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5989:: with SMTP id n131ls964270oib.3.gmail; Thu, 28 Oct
 2021 08:11:12 -0700 (PDT)
X-Received: by 2002:a05:6808:989:: with SMTP id a9mr3478874oic.41.1635433872076;
        Thu, 28 Oct 2021 08:11:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635433872; cv=none;
        d=google.com; s=arc-20160816;
        b=gqyrwu8wyVUDg+FQDgqiGxh6C0Wd/w7TqfnKDbP8xIdQphVwYbm+kOVRH0+00729/u
         izGIQ1/IVFUsgTBdY4YEfvfuikvUoQN2A48aueFLVUppEvKTRpz0sh3je/DoDymQmACt
         O4PFh8XZKv+QiGBizV72CLo+8ppsvKg7MIFq3ymQe570j7Wj8MTT/rZRWTR0kGCP7QIA
         BDAksK0qwOvmavYE/ZqWfy+VGxp8z6j1DylTbIKHPaCprXxv3OY2qGqi7CM9+YuzcoPm
         IggrS4AZ7iKBbrwVKQOklVfqORYnIzpv9beJbAsKiTsCjicC4YeLViLgmR20eXsyTYdv
         mx+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=259aXqiOnA5iWuUV4ETs5uC0oUlsrJdMmweeqlD6Flw=;
        b=He352s+5Bzab5RCvdihWGWMLooodJTLjI656uHOGpqE5+cbcZ0bJeTRTXzTHVjAcSg
         juaIWd5WNjhuSH+VvB0wE2RLMSGb4nBd9RubBaYnsV0d3q/Db/WbvXEVzdstw1X0dC1U
         7M0up+ERYcUI5LYlxN8kUH4z0DTvY6Qwy74h9n4/VVkcIp7NA9Y1O4zbBmO7NlOfbBlt
         nNQ0lCzrOgDEV3lFjvySEvPzxn/olUvG/mhPB/6v/BIYNCStNKVzqfGcXcOSYetA9rv7
         HNWgD1Uy90IHbB1ocJAwVb+7rW244tmzV4WDwRsj98aI4Cm1wfSQ72STin4/w0iCUxgi
         MHhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=FSE7WAV8;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id r130si163706oig.2.2021.10.28.08.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Oct 2021 08:11:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id m26so6285612pff.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 08:11:11 -0700 (PDT)
X-Received: by 2002:a63:3446:: with SMTP id b67mr3614765pga.258.1635433871085;
        Thu, 28 Oct 2021 08:11:11 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id f14sm2956300pfv.5.2021.10.28.08.11.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 08:11:10 -0700 (PDT)
Date: Thu, 28 Oct 2021 08:11:10 -0700 (PDT)
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
In-Reply-To: <CA+zEjCv+whmnL_SFf20j06NpikaMtA7MNQ9+o8Zz7=1_nAtTqw@mail.gmail.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, nathan@kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-4c43fe14-f36b-4232-a316-530a4d041d49@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=FSE7WAV8;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Thu, 28 Oct 2021 00:13:06 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> On Thu, Oct 28, 2021 at 8:45 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>>
>> On Wed, 27 Oct 2021 22:34:32 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> > On Thu, Oct 28, 2021 at 7:30 AM Alexandre Ghiti
>> > <alexandre.ghiti@canonical.com> wrote:
>> >>
>> >> On Thu, Oct 28, 2021 at 7:02 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>> >> >
>> >> > On Wed, 27 Oct 2021 21:15:28 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> >> > > On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>> >> > >>
>> >> > >> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> >> > >> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
>> >> > >> > Kconfig, it prevents asan-stack from getting disabled with clang even
>> >> > >> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
>> >> > >> > corresponding config.
>> >> > >> >
>> >> > >> > Reported-by: Nathan Chancellor <nathan@kernel.org>
>> >> > >> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>> >> > >> > ---
>> >> > >> >  arch/riscv/Kconfig             | 6 ++++++
>> >> > >> >  arch/riscv/include/asm/kasan.h | 3 +--
>> >> > >> >  arch/riscv/mm/kasan_init.c     | 3 +++
>> >> > >> >  3 files changed, 10 insertions(+), 2 deletions(-)
>> >> > >> >
>> >> > >> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> >> > >> > index c1abbc876e5b..79250b1ed54e 100644
>> >> > >> > --- a/arch/riscv/Kconfig
>> >> > >> > +++ b/arch/riscv/Kconfig
>> >> > >> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
>> >> > >> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
>> >> > >> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
>> >> > >> >
>> >> > >> > +config KASAN_SHADOW_OFFSET
>> >> > >> > +     hex
>> >> > >> > +     depends on KASAN_GENERIC
>> >> > >> > +     default 0xdfffffc800000000 if 64BIT
>> >> > >> > +     default 0xffffffff if 32BIT
>> >> > >>
>> >> > >> I thought I posted this somewhere, but this is exactly what my first
>> >> > >> guess was.  The problem is that it's hanging on boot for me.  I don't
>> >> > >> really have anything exotic going on, it's just a defconfig with
>> >> > >> CONFIG_KASAN=y running in QEMU.
>> >> > >>
>> >> > >> Does this boot for you?
>> >> > >
>> >> > > Yes with the 2nd patch of this series which fixes the issue
>> >> > > encountered here. And that's true I copied/pasted this part of your
>> >> > > patch which was better than what I had initially done, sorry I should
>> >> > > have mentioned you did that, please add a Codeveloped-by or something
>> >> > > like that.
>>
>> OK, those should probably be in the opposite order (though it looks like
>> they're inter-dependent, which makes things a bit trickier).
>>
>> >> >
>> >> > Not sure if I'm missing something, but it's still not booting for me.
>> >> > I've put what I'm testing on palmer/to-test, it's these two on top of
>> >> > fixes and merged into Linus' tree
>> >> >
>> >> >     *   6d7d351902ff - (HEAD -> to-test, palmer/to-test) Merge remote-tracking branch 'palmer/fixes' into to-test (7 minutes ago) <Palmer Dabbelt>
>> >> >     |\
>> >> >     | * 782551edf8f8 - (palmer/fixes) riscv: Fix CONFIG_KASAN_STACK build (6 hours ago) <Alexandre Ghiti>
>> >> >     | * 47383e5b3c4f - riscv: Fix asan-stack clang build (6 hours ago) <Alexandre Ghiti>
>> >> >     | * 64a19591a293 - (riscv/fixes) riscv: fix misalgned trap vector base address (9 hours ago) <Chen Lu>
>> >> >     * |   1fc596a56b33 - (palmer/master, linus/master, linus/HEAD, master) Merge tag 'trace-v5.15-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace (11 hours ago) <Linus Torvalds>
>> >> >
>> >> > Am I missing something else?
>> >>
>> >> Hmm, that's weird, I have just done the same: cherry-picked both my
>> >> commits on top of fixes (64a19591a293) and it boots fine with KASAN
>> >> enabled. Maybe a config thing? I pushed my branch here:
>> >> https://github.com/AlexGhiti/riscv-linux/tree/int/alex/kasan_stack_fixes_rebase
>> >
>> > I pushed the config I use and that boots in that branch, maybe there's
>> > another issue somewhere.
>>
>> CONFIG_KASAN_VMALLOC=n is what's causing the failure.  I'm testing both
>> polarities of that, looks like your config has =y.  I haven't looked any
>> further as I'm pretty much cooked for tonight, but if you don't have
>> time then I'll try to find some time tomorrow.
>>
>
> Arf, that was obvious and just under my nose: without KASAN_VMALLOC,
> kasan_populate_early_shadow is called and creates the same issue that
> the second patch fixes.
>
> I'll send a v2 today and try to swap both patches to avoid having a
> non-bootable kernel commit.

Thanks.

>
> Alex
>
>> >
>> >>
>> >> >
>> >> > >
>> >> > > Thanks,
>> >> > >
>> >> > > Alex
>> >> > >
>> >> > >>
>> >> > >> > +
>> >> > >> >  config ARCH_FLATMEM_ENABLE
>> >> > >> >       def_bool !NUMA
>> >> > >> >
>> >> > >> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
>> >> > >> > index a2b3d9cdbc86..b00f503ec124 100644
>> >> > >> > --- a/arch/riscv/include/asm/kasan.h
>> >> > >> > +++ b/arch/riscv/include/asm/kasan.h
>> >> > >> > @@ -30,8 +30,7 @@
>> >> > >> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
>> >> > >> >  #define KASAN_SHADOW_START   KERN_VIRT_START
>> >> > >> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
>> >> > >> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
>> >> > >> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
>> >> > >> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> >> > >> >
>> >> > >> >  void kasan_init(void);
>> >> > >> >  asmlinkage void kasan_early_init(void);
>> >> > >> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> >> > >> > index d7189c8714a9..8175e98b9073 100644
>> >> > >> > --- a/arch/riscv/mm/kasan_init.c
>> >> > >> > +++ b/arch/riscv/mm/kasan_init.c
>> >> > >> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
>> >> > >> >       uintptr_t i;
>> >> > >> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
>> >> > >> >
>> >> > >> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
>> >> > >> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
>> >> > >> > +
>> >> > >> >       for (i = 0; i < PTRS_PER_PTE; ++i)
>> >> > >> >               set_pte(kasan_early_shadow_pte + i,
>> >> > >> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-4c43fe14-f36b-4232-a316-530a4d041d49%40palmerdabbelt-glaptop.
