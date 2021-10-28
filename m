Return-Path: <kasan-dev+bncBCRKNY4WZECBBH4O5GFQMGQEY7OZJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id EB98943DB79
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 08:45:52 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id e5-20020ab04985000000b002cad81164cbsf2862760uad.10
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 23:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635403551; cv=pass;
        d=google.com; s=arc-20160816;
        b=aE1f5C2xDRQbo/F3MpcNONoRzsQdj9s935ifAmdwgee13BrSytXnwDfH4pfWKPK50i
         j4BGVBli2l0QT25ihrO741uO6ijEpKszWP/02D82bm4GumXNHTHUWQaSVkazjlxNHPd9
         YAFnzmC6RoI7aAbAdVKnOAWFATA9STV+Ukw/Ei5mxH9gmFst5B3BuzpyXrcGjfCuaCUP
         RDXc53VGBsjzMLfT5n+QGV1MI7+QFOBrNZlGU8TCEeeOk9MTNFC5xgs8P/8iRa/uj2Ky
         LwkqvBTkKEmsdRiQWP+Lm+3f5eTzzcyz8MXAYS/0dNVMluo9G58+8gT5oV69468wtJiK
         xIOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=9t8xE9mGxFKyHlVbZV9q+XInzkIc/mwSx34Inzu50Ak=;
        b=BP7eaQgRsYREGhRRpMi9rD0mcNvSbfJcup13V62oJmCDQxuFr7smZSacgiuW9HE6gA
         lNsyHWB3btGw63c718pWtnEmutPQIag9rihTwUwyy4nJsMRB+lxM58QhjaPBeV/rqLvP
         0SZAtovWwz976qlWZKMW5rh5mNiqPCfC4braasEPHRGl3Td2FXXdLHywKxzLZzmXueyU
         R3Tu/k9KP00B0+TPYfcu9szwDMTvmC7XjYvRu7GI6Ee1soFL/d/2IVB9trWpg0YmqAto
         5KI8ek1J89YeNGg4XWkAYcVcuC6h38Atc2Mu+mAWFYuiLq6g2mseqzYp4kF0sqdtSt3/
         NUIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=moYXi3sC;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9t8xE9mGxFKyHlVbZV9q+XInzkIc/mwSx34Inzu50Ak=;
        b=Ntzyk/aN2Qq9YpSh/W4IVtTYR42qyF5BOhi1lRIn07xE9dkbeVl8nJWijopXUYhqWk
         GnZi1RNQxSnh1hBxNpelrzbY4KAbB3DIe2/vP13GTS5KYP0ycqx9ZNFmgOcCtsJ8qHXE
         jEc85mQSH2QP6/QWLXYPQUdo7aBf29xAJSZt/5lLfwxBfQq4cBqbKwTGd1FJgZuRDebY
         bv8XXBYf+Jo8fcNL+8plCW5KtPoviO9nbiaQTRH3qnMdTMMo9DNofwdj/juOtxD18b6K
         +HWSTarvvd1aEhFiCZ2yCYnYBsX/woEx8U1Z87FVhu7FevCKN+e8d+aZM0Ox37Cm41GX
         95Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9t8xE9mGxFKyHlVbZV9q+XInzkIc/mwSx34Inzu50Ak=;
        b=bYtjicGhB5op9/OFRY33Id9OkwZw5RboiuPZHWY4jooiXsClGCGHqo274TYawk+DLm
         FjuQ3KP3Leb+ziLUxUOBD2Yp00R2C64b8yxvSThax5ac90XPXVrTxDwcTxUj39dd3IxA
         wX0XMVjZ2xRQlHN2lI5A6cf+gvU+4yLqQWkwavz5JQZG890GNHeL4Eo5vTJWUgXKWjpq
         EDrUUBfpGOoLuw9GVct6wSZYvK6U0cO9DMadk9zE3VSmtqvvX5aUQVUBHEOFDbh90wpw
         Ry2gfUqL7S+Lu/YQepuCGPi3/W3IdCb/7QOsPK5ckBhPZgCv3F98o50NCBEnbgj2HYJz
         3MgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fU7W6rQEoHTr3zxWY/v7SsWgPB06DhUB+OjyYLFcEazziE3OD
	9GjDnnYHr6mHg8UVRHM5rIk=
X-Google-Smtp-Source: ABdhPJzDnUlJn9x7+RofoGu08UoHoh299YuF1bMr2S6m2abiUszRWjY5iYFqcsuRxlVmOf6o5gTocQ==
X-Received: by 2002:ab0:3c54:: with SMTP id u20mr2575521uaw.107.1635403551700;
        Wed, 27 Oct 2021 23:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:22db:: with SMTP id a27ls680997vsh.2.gmail; Wed, 27
 Oct 2021 23:45:51 -0700 (PDT)
X-Received: by 2002:a67:ec8f:: with SMTP id h15mr2483488vsp.53.1635403551058;
        Wed, 27 Oct 2021 23:45:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635403551; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0lhzdmfKR11Wv4szLqpOnazLmCUVOzFD6QwT28ZYr5qUdTyooebMCLcF0EM/8Arou
         U1hP4IEjItObbvx2vYgNycNxjMg50q2O+bm6+ei4damSHeiWXfTzXxwRUYZNnlSUX5G6
         GeNL4QSy2jJ23KRvbgMejfm90lBxbXKMX8VXa7YMf1+sqeTkSYnhaNL8ZlZ/avLbOVpt
         Fa+aYwfZwQk5ot8SKmRoOuU68/NeLorW6p78LjDkvV+hwlJUYgNwAmZ6RUEO44m39jWF
         rThscOiUdtPMPvE02YHSfI86MB3uilMuiDQDIJnhZuDQ134uZOMBEvkUtXJwfZZJTCKk
         ZbOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=rs7fMWgOkQnNoOUFxUJo1UP4rGXZdVB5PK/ehuT/wOs=;
        b=w273tK7Ph/a7TzrmyOZpeH4FvbC6WpuEFcPK2Hik65AIb8H8aDIG3liSdYMO4C4awp
         C+/GL6Aadp+hbCTXJl+ZwfcpywIrFlZDcxomCLUfsmjFFdQ1RKR+adz5MR7jMwn59KdS
         OUwGAbNKy1NSrDFMDJLW2+Krl0ib57o88to0EaCYZ/OXSV2eJ34keOs+7oX9+AOqQbS5
         1rm4aWlidYinsaXtTGivMe5nCitrusQVjvIMFdZeNp/iwBI/t7sG8YKxQqkPd+AFro+N
         zRh3MnB7f/kQ/Ph21pyjYISftFbjgkyYqPyCZa1RK7iNTN4GxFG0gsuFCoCD5EYXVjEj
         a1zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=moYXi3sC;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id o3si169805vkg.4.2021.10.27.23.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Oct 2021 23:45:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 83so5442001pgc.8
        for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 23:45:50 -0700 (PDT)
X-Received: by 2002:a63:8f4c:: with SMTP id r12mr1863151pgn.0.1635403550335;
        Wed, 27 Oct 2021 23:45:50 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id j16sm2310979pfj.16.2021.10.27.23.45.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Oct 2021 23:45:49 -0700 (PDT)
Date: Wed, 27 Oct 2021 23:45:49 -0700 (PDT)
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
In-Reply-To: <CA+zEjCus8+jzn074GwqhJ54Y180RASr_YaC=6zdBZSzonEtjDA@mail.gmail.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, nathan@kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-3ac5b2b9-c9da-42e5-bc56-d779fb4dd1dd@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=moYXi3sC;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Wed, 27 Oct 2021 22:34:32 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> On Thu, Oct 28, 2021 at 7:30 AM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
>>
>> On Thu, Oct 28, 2021 at 7:02 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>> >
>> > On Wed, 27 Oct 2021 21:15:28 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> > > On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>> > >>
>> > >> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> > >> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
>> > >> > Kconfig, it prevents asan-stack from getting disabled with clang even
>> > >> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
>> > >> > corresponding config.
>> > >> >
>> > >> > Reported-by: Nathan Chancellor <nathan@kernel.org>
>> > >> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>> > >> > ---
>> > >> >  arch/riscv/Kconfig             | 6 ++++++
>> > >> >  arch/riscv/include/asm/kasan.h | 3 +--
>> > >> >  arch/riscv/mm/kasan_init.c     | 3 +++
>> > >> >  3 files changed, 10 insertions(+), 2 deletions(-)
>> > >> >
>> > >> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> > >> > index c1abbc876e5b..79250b1ed54e 100644
>> > >> > --- a/arch/riscv/Kconfig
>> > >> > +++ b/arch/riscv/Kconfig
>> > >> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
>> > >> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
>> > >> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
>> > >> >
>> > >> > +config KASAN_SHADOW_OFFSET
>> > >> > +     hex
>> > >> > +     depends on KASAN_GENERIC
>> > >> > +     default 0xdfffffc800000000 if 64BIT
>> > >> > +     default 0xffffffff if 32BIT
>> > >>
>> > >> I thought I posted this somewhere, but this is exactly what my first
>> > >> guess was.  The problem is that it's hanging on boot for me.  I don't
>> > >> really have anything exotic going on, it's just a defconfig with
>> > >> CONFIG_KASAN=y running in QEMU.
>> > >>
>> > >> Does this boot for you?
>> > >
>> > > Yes with the 2nd patch of this series which fixes the issue
>> > > encountered here. And that's true I copied/pasted this part of your
>> > > patch which was better than what I had initially done, sorry I should
>> > > have mentioned you did that, please add a Codeveloped-by or something
>> > > like that.

OK, those should probably be in the opposite order (though it looks like 
they're inter-dependent, which makes things a bit trickier).

>> >
>> > Not sure if I'm missing something, but it's still not booting for me.
>> > I've put what I'm testing on palmer/to-test, it's these two on top of
>> > fixes and merged into Linus' tree
>> >
>> >     *   6d7d351902ff - (HEAD -> to-test, palmer/to-test) Merge remote-tracking branch 'palmer/fixes' into to-test (7 minutes ago) <Palmer Dabbelt>
>> >     |\
>> >     | * 782551edf8f8 - (palmer/fixes) riscv: Fix CONFIG_KASAN_STACK build (6 hours ago) <Alexandre Ghiti>
>> >     | * 47383e5b3c4f - riscv: Fix asan-stack clang build (6 hours ago) <Alexandre Ghiti>
>> >     | * 64a19591a293 - (riscv/fixes) riscv: fix misalgned trap vector base address (9 hours ago) <Chen Lu>
>> >     * |   1fc596a56b33 - (palmer/master, linus/master, linus/HEAD, master) Merge tag 'trace-v5.15-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace (11 hours ago) <Linus Torvalds>
>> >
>> > Am I missing something else?
>>
>> Hmm, that's weird, I have just done the same: cherry-picked both my
>> commits on top of fixes (64a19591a293) and it boots fine with KASAN
>> enabled. Maybe a config thing? I pushed my branch here:
>> https://github.com/AlexGhiti/riscv-linux/tree/int/alex/kasan_stack_fixes_rebase
>
> I pushed the config I use and that boots in that branch, maybe there's
> another issue somewhere.

CONFIG_KASAN_VMALLOC=n is what's causing the failure.  I'm testing both 
polarities of that, looks like your config has =y.  I haven't looked any 
further as I'm pretty much cooked for tonight, but if you don't have 
time then I'll try to find some time tomorrow.

>
>>
>> >
>> > >
>> > > Thanks,
>> > >
>> > > Alex
>> > >
>> > >>
>> > >> > +
>> > >> >  config ARCH_FLATMEM_ENABLE
>> > >> >       def_bool !NUMA
>> > >> >
>> > >> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
>> > >> > index a2b3d9cdbc86..b00f503ec124 100644
>> > >> > --- a/arch/riscv/include/asm/kasan.h
>> > >> > +++ b/arch/riscv/include/asm/kasan.h
>> > >> > @@ -30,8 +30,7 @@
>> > >> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
>> > >> >  #define KASAN_SHADOW_START   KERN_VIRT_START
>> > >> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
>> > >> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
>> > >> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
>> > >> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> > >> >
>> > >> >  void kasan_init(void);
>> > >> >  asmlinkage void kasan_early_init(void);
>> > >> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> > >> > index d7189c8714a9..8175e98b9073 100644
>> > >> > --- a/arch/riscv/mm/kasan_init.c
>> > >> > +++ b/arch/riscv/mm/kasan_init.c
>> > >> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
>> > >> >       uintptr_t i;
>> > >> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
>> > >> >
>> > >> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
>> > >> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
>> > >> > +
>> > >> >       for (i = 0; i < PTRS_PER_PTE; ++i)
>> > >> >               set_pte(kasan_early_shadow_pte + i,
>> > >> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-3ac5b2b9-c9da-42e5-bc56-d779fb4dd1dd%40palmerdabbelt-glaptop.
