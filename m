Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB5PM5CFQMGQEW5KYMCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0385243DAC9
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 07:34:46 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id r25-20020a05640216d900b003dca3501ab4sf4433441edx.15
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 22:34:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635399285; cv=pass;
        d=google.com; s=arc-20160816;
        b=TKDX/48KBevaxvxn7wJLx5wYUY0IejfPp60MPaboF3onhYi8QBEpvFUua4EeJKU5zg
         pWzYDY5JsZp2LacKlZj2/wTomqDnDnVtpMqACfrrMSqxaTuSf9rh+3lYfyvfHfwDktJ/
         wWhQaZBREQS/USu7x+8ETUiAS7l2X6lUttj2Pl92jXq+Ko6bmoda1bUxoqyp9llow6FT
         FcbcyF8dP8hzKsPl1Wtu9vAW8/fzwUflbfJfcjMNNtkuS3bXBawwE2fs67E59yqoP8rA
         +o2ygQCr8b1ju8z40n+9Tq3nVBSWRkj/Js6JvHeCvCwzchciGoyIfTDBcMi/dDx5T3vm
         jjSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=rAcultRjB9EyPhiGDQByP85szjAeyJ/2QUQkaUXystw=;
        b=ZktWiNqcQRln4yIy9ffOyS4h35TIokmXoi4bWifiixgwpYLgKqbJ0sJL58sS/RyUAw
         KtPhaC4nc65idFwyynHDqgRwqyFPRBVR+DLOE2EFCy1artH/yyyCu5EnrsQRgT67i9IM
         B3gHGOKdU0ShL/OQREIw9qnK0/7/yApZZmipqwsIP+7srrejs/Pb/NXU3oMVfhQIpcDq
         el+INZm88CpC0QhDLoRw/JJSt90deSbnqUcrisrxirGctgnthnpXBS+6o6Zoy7CEYsOT
         XqksHa2OKtiEx4tHhzNDvY70kEsMC5JgSXUvfL3hxLTo98rF5Wlq2pPzeeEhH3PS9RoI
         iKkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=VR6NgBZS;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rAcultRjB9EyPhiGDQByP85szjAeyJ/2QUQkaUXystw=;
        b=cSKmifRCjllv/a2im2ju3HPxcXRwWgNFqRDtCrqz3a9/FlsGWU+0WbJqMLRWjl4ndj
         GElUpu2Usq4Et/bC4sk7fTx9tkMvkhgmdJiIrZNOkPBxjlN53mzfHpM9wcTSBKVw/Qq+
         vxNkP+zowWyFaUZn8t+tRfb1Sx1JRYOB2SUZkGmE9KD5NCLoddpWKNOwhub3YZcXWXYq
         PeIAo+2hjJS0Nvrl/2cNmAwlzvse6LP9rk4a/neWwvC+c2sBp1ntBgqmrT/MzwGk1f6+
         L2ziBbmxXYJKl8D8SXG5Dtyw11PnKn+dNsVaX1OZ4aUZzqmeEuet+SoQxd0VU21KhnNe
         leDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rAcultRjB9EyPhiGDQByP85szjAeyJ/2QUQkaUXystw=;
        b=HDArU4fpfzXTN0bgdXxln9fcmFPid+IJCZNNpn81eQLY4Y+RFC1yu3I7IFYNHe8e/1
         NgLgT8RvDzybMhyRkoli2+hYpyNZPsjna+ST84BuielnijQuPhz+gTj5V60t/kboeUWL
         q3e0dFBDJoRwAckD3EcK5PW/oEkYWmnxAxliHKBOJXg1Pz2+/GfusORNnUi8bJaCOBaC
         DEJ0MmbYEE9NJwf8XOivdrbisJLR8qnVae6Uh+Q/6xcv5YeXwkHSHnJRw4OKzvgqgEGL
         /V42EyZ3E6B8fLRv9CWa7iOiVx9gKgGR5WCWKvJ9DZC+4fDVKqh0WvEQT9D37UYNzj2w
         Fu0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532R9qQwItDZWyAyzzxAulK/6Xni34Exlmnhe4ffJ6MX1RU2RzSc
	m71YN75DncJhG9L4b8IvOx8=
X-Google-Smtp-Source: ABdhPJx2YWE8klU8an1xYEYyh6Io7XrjvAJowz1oOe0TorK3JPWAjDMBBqa4RlXAnVZ88ShUB5RITw==
X-Received: by 2002:a05:6402:7:: with SMTP id d7mr3269978edu.265.1635399285788;
        Wed, 27 Oct 2021 22:34:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3f1c:: with SMTP id hq28ls977555ejc.8.gmail; Wed, 27
 Oct 2021 22:34:44 -0700 (PDT)
X-Received: by 2002:a17:906:2ed5:: with SMTP id s21mr2696990eji.30.1635399284888;
        Wed, 27 Oct 2021 22:34:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635399284; cv=none;
        d=google.com; s=arc-20160816;
        b=w50Qxnb40mTf/75J4bgopfDRVKfF46hEo1D9M/qxFjrlLMuxEJALyjtG7UBXNJCPeW
         KnLgUZP4wCtXFA44EEoX+ZeyWG+1fM75t62qABxy8xIdofh10jjkn+1OGPSUFdUdVRK/
         dR78SMhKK1miT+HxEZkwWhUdGxhlbx3Gis4p4pGnFRLQ3/pBddea77UDI0tGHsbqEUXo
         YbJj16wFv6ZIPA9rnaT+QFE4LbOVaMUn0WvBbaZy17er5ak1O3FgCBgrotnXGxGeXILD
         hsLikIorxsvZcKebW4eearIuiKrBmD9fKEBHtlEO563ykD9mbAzViMJR9Qt7poqP6Blo
         2tYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lNwK2X60c7f9X7KPf6h2ScbG4X9q5dg3Bv4L43p8gyc=;
        b=ppu77D4WL+bh6Zc6j3yUq3PA/lbqVkKXgRgt8Tqi887YQus7+pCOL5kZNmDuHlwAJh
         K5u9hcxuhA1anirIWIJWKiaJ7T9SCe7GCKPp5PAEiOoHPyt17cauClJ8BXpvoIr87n19
         H5Dl+Gql0K2yzHKznz07eS0wl0LHW86Yu1qBDgvEz2U2vEPX7TYv+tKA36WSv+RBn85T
         HhBNWqYS0ZaIcvA7ghb6t+xNQKoTCx6S+4Syh5LLOSsddzlNQ8YTqTYY38rbZyCARQL/
         PukTW+Cn0NWUySVWYSc12bjH8T2rzwg5VKcR5YQY0nXVFd+Y4uOEu0A/tjZn1614t8nl
         RyDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=VR6NgBZS;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id o25si94974eju.1.2021.10.27.22.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Oct 2021 22:34:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 9B3C63F17A
	for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 05:34:44 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id q6-20020a056402518600b003dd81fc405eso4505417edd.1
        for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 22:34:44 -0700 (PDT)
X-Received: by 2002:a17:907:d22:: with SMTP id gn34mr2588257ejc.463.1635399284143;
        Wed, 27 Oct 2021 22:34:44 -0700 (PDT)
X-Received: by 2002:a17:907:d22:: with SMTP id gn34mr2588238ejc.463.1635399283919;
 Wed, 27 Oct 2021 22:34:43 -0700 (PDT)
MIME-Version: 1.0
References: <CA+zEjCuUCxqTtbox2K8c=ymHC8X97LV6CSO3ydJKgRR9cBXUEw@mail.gmail.com>
 <mhng-897d082f-5ca4-4d77-a69d-4efaa456bf3b@palmerdabbelt-glaptop> <CA+zEjCvF7yCbA9KvsD+OaGXhEAF4x_jBB+OZ3C-Q6RctYSjd7w@mail.gmail.com>
In-Reply-To: <CA+zEjCvF7yCbA9KvsD+OaGXhEAF4x_jBB+OZ3C-Q6RctYSjd7w@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 28 Oct 2021 07:34:32 +0200
Message-ID: <CA+zEjCus8+jzn074GwqhJ54Y180RASr_YaC=6zdBZSzonEtjDA@mail.gmail.com>
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, 
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=VR6NgBZS;       spf=pass
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

On Thu, Oct 28, 2021 at 7:30 AM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> On Thu, Oct 28, 2021 at 7:02 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> >
> > On Wed, 27 Oct 2021 21:15:28 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> > > On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> > >>
> > >> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> > >> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
> > >> > Kconfig, it prevents asan-stack from getting disabled with clang even
> > >> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
> > >> > corresponding config.
> > >> >
> > >> > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > >> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > >> > ---
> > >> >  arch/riscv/Kconfig             | 6 ++++++
> > >> >  arch/riscv/include/asm/kasan.h | 3 +--
> > >> >  arch/riscv/mm/kasan_init.c     | 3 +++
> > >> >  3 files changed, 10 insertions(+), 2 deletions(-)
> > >> >
> > >> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> > >> > index c1abbc876e5b..79250b1ed54e 100644
> > >> > --- a/arch/riscv/Kconfig
> > >> > +++ b/arch/riscv/Kconfig
> > >> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
> > >> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
> > >> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
> > >> >
> > >> > +config KASAN_SHADOW_OFFSET
> > >> > +     hex
> > >> > +     depends on KASAN_GENERIC
> > >> > +     default 0xdfffffc800000000 if 64BIT
> > >> > +     default 0xffffffff if 32BIT
> > >>
> > >> I thought I posted this somewhere, but this is exactly what my first
> > >> guess was.  The problem is that it's hanging on boot for me.  I don't
> > >> really have anything exotic going on, it's just a defconfig with
> > >> CONFIG_KASAN=y running in QEMU.
> > >>
> > >> Does this boot for you?
> > >
> > > Yes with the 2nd patch of this series which fixes the issue
> > > encountered here. And that's true I copied/pasted this part of your
> > > patch which was better than what I had initially done, sorry I should
> > > have mentioned you did that, please add a Codeveloped-by or something
> > > like that.
> >
> > Not sure if I'm missing something, but it's still not booting for me.
> > I've put what I'm testing on palmer/to-test, it's these two on top of
> > fixes and merged into Linus' tree
> >
> >     *   6d7d351902ff - (HEAD -> to-test, palmer/to-test) Merge remote-tracking branch 'palmer/fixes' into to-test (7 minutes ago) <Palmer Dabbelt>
> >     |\
> >     | * 782551edf8f8 - (palmer/fixes) riscv: Fix CONFIG_KASAN_STACK build (6 hours ago) <Alexandre Ghiti>
> >     | * 47383e5b3c4f - riscv: Fix asan-stack clang build (6 hours ago) <Alexandre Ghiti>
> >     | * 64a19591a293 - (riscv/fixes) riscv: fix misalgned trap vector base address (9 hours ago) <Chen Lu>
> >     * |   1fc596a56b33 - (palmer/master, linus/master, linus/HEAD, master) Merge tag 'trace-v5.15-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace (11 hours ago) <Linus Torvalds>
> >
> > Am I missing something else?
>
> Hmm, that's weird, I have just done the same: cherry-picked both my
> commits on top of fixes (64a19591a293) and it boots fine with KASAN
> enabled. Maybe a config thing? I pushed my branch here:
> https://github.com/AlexGhiti/riscv-linux/tree/int/alex/kasan_stack_fixes_rebase

I pushed the config I use and that boots in that branch, maybe there's
another issue somewhere.

>
> >
> > >
> > > Thanks,
> > >
> > > Alex
> > >
> > >>
> > >> > +
> > >> >  config ARCH_FLATMEM_ENABLE
> > >> >       def_bool !NUMA
> > >> >
> > >> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> > >> > index a2b3d9cdbc86..b00f503ec124 100644
> > >> > --- a/arch/riscv/include/asm/kasan.h
> > >> > +++ b/arch/riscv/include/asm/kasan.h
> > >> > @@ -30,8 +30,7 @@
> > >> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> > >> >  #define KASAN_SHADOW_START   KERN_VIRT_START
> > >> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> > >> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
> > >> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
> > >> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> > >> >
> > >> >  void kasan_init(void);
> > >> >  asmlinkage void kasan_early_init(void);
> > >> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > >> > index d7189c8714a9..8175e98b9073 100644
> > >> > --- a/arch/riscv/mm/kasan_init.c
> > >> > +++ b/arch/riscv/mm/kasan_init.c
> > >> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
> > >> >       uintptr_t i;
> > >> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
> > >> >
> > >> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> > >> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> > >> > +
> > >> >       for (i = 0; i < PTRS_PER_PTE; ++i)
> > >> >               set_pte(kasan_early_shadow_pte + i,
> > >> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCus8%2Bjzn074GwqhJ54Y180RASr_YaC%3D6zdBZSzonEtjDA%40mail.gmail.com.
