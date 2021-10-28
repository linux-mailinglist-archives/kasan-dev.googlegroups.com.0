Return-Path: <kasan-dev+bncBCRKNY4WZECBB5G55CFQMGQELKJO7JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AEB343DA9F
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 07:02:46 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id 63-20020a9f2345000000b002cbbc79fb71sf2770344uae.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 22:02:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635397365; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHXRzJHbLi4MaXs13VJ1hqYFpYf1LiVvq+08zOMEMwzF+pXtogAvi9KVfEBgsBVs3X
         wfliJB7VEfpUydoUDhkp0NLDHbggatrsPaugzJYc26pe0MUClfx2zQLEKF4vfwHtoFr3
         dCmViVZEIjGIRhog0z9llUyjSQY1mODQEcnqupRU248YNInzsGOQhoDlXIsKxrGeL4W8
         r6JUbq90u56hh04aPvPIDNkIuxrYl2yPM18c2qaknSQHm//QGzdOegrCwmFHBo8rl4rv
         1b5fc8yokPx8GVzmNOKuqIbeEJhehtglemi1M+c3/Ox2KrbPg3CozyjELoOFOgIJK5Wo
         IQaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=fLTeGVMusCZlEY3g2SAjOZqsun3Pb8GsclAQNG6yqAw=;
        b=fZPS3wNFvjK7/bershrFsRApUdE7V9ebDWme9CfpnK2MR5sAHWqDy2hB72OjBVJo7t
         +/Hokqm/FieEivsu9ZKN6B+AbpOcgKjrfiU2gZ+hkii7h8yIopO9OcDx8CV0HTLD2wQJ
         WWiiIA2tS1yM02Sf08DGOJmbcv5ksEeQi5h/PqkHJs6reM69OZAO8Arc8Y3S3W+/nei1
         QnTNU+g1yBWk5xl9nhUzW0KhQ2oRtTKLX7VYWUmvotaEv1HowQ8H8WxUUNvkMoFJTbcc
         QX7ZxaBTji4B7kDiWdzFGa/ixRhglI3GyWmM9pxCNx7Ey63byneGecFzNjMoXbFq69RR
         C17w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=WxFhA8TZ;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fLTeGVMusCZlEY3g2SAjOZqsun3Pb8GsclAQNG6yqAw=;
        b=opWb2vphN33dDiSoMSox73tQyg14eqgWIu8LgpKD+mwNY9AvoPkmL2O+tZykEcloTy
         izeBKWnLgU13V6nY2r2XQPQbIN645lSBj927etQGEBSflsRBC3zjqpAuOw46fiafIcWk
         QJOhWxgG9UaQ7bgzEcsqPKATT2prTL7s9k4HKjLu5NzMg1O7pRvT9ffLjVrE7OZUAeM7
         E6MAO4RITBuGe2ds5VE1J5TWMIuIWV21zPJ/WZvoHuv1YtzbFabz9oVRPHkyXIul/NVF
         hJxl6rGVDKZLPQOVRVRm2lKyCcGKrnlhiYOCebGnYPgA+erJw7MZ19NUvnyF7jz9YVYf
         /dDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fLTeGVMusCZlEY3g2SAjOZqsun3Pb8GsclAQNG6yqAw=;
        b=vX7YXAWYUaUF3LStk4mh6yfPc8oUeP/kPEZan83KGTYxJ7GR7PFRlfPY6YGTrPuB/M
         P3j5QdVhc2MRhndIaPMI8ptBQTCNpc3nrEftaWnBD8UhcPu0Se3O2d1HU8hSSTBy7n72
         W0M/4dSLZCv1YB/yoTA5aevQgjqnJhbFcBUfFGTx7YE+Hkj54s6oAb/c38G6k12auPMp
         d5MmYam5JAOE+Rx4KH+uqKhFX1UyfOD1SAbe2OkSzngbRMBLEpQhIal40p1Syly6OeZy
         BV+lZdi4YDCEfvpwBPgBm9eAc2N/x1gDIPqb1cC/bdeYBs0qh0EzSu8yyu1DiPeLCenb
         KJ0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NOmgZYNYA3azVBOEzBS/ZUtJyw7Wtb4VcY/CRH6kI7gz559k7
	iaTwOogiCQPzFZwbbLbTYEI=
X-Google-Smtp-Source: ABdhPJwdh8BjpyQitZeQD0dZsa9sIVwTVi7Scd77r0OQZuPYIcPv+lF3uCaZzFDIVomVkt3i5hMuIg==
X-Received: by 2002:a05:6102:528:: with SMTP id m8mr404540vsa.40.1635397365196;
        Wed, 27 Oct 2021 22:02:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2b96:: with SMTP id q22ls379590uar.1.gmail; Wed, 27 Oct
 2021 22:02:44 -0700 (PDT)
X-Received: by 2002:ab0:6154:: with SMTP id w20mr2258791uan.25.1635397364578;
        Wed, 27 Oct 2021 22:02:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635397364; cv=none;
        d=google.com; s=arc-20160816;
        b=fLyQxoTXwGBFKopQ2SKa6rRZaOih3Qwg3zt7O62E6Jbn/yPHl+4SZdRdeQMorKxTiW
         s7Lad2+NunABENThzmDxOLTa+njlxkbzTUzoarOmv/71Fn2ngU2F5Uc4AX6GOahJuP/F
         +Ymjozx6WNxcV6/w9GKCeNLhRPEC9ql4ti2fvfS0+All6lxP3OcJgkxnld7MAXAllT1U
         tzOf33kT59/JO17L7Um6mL8h2M0Cgn/MjiQESdLcvQh/MI48BM5SThs6mrwy/Hr9i9yW
         YHOXqHhgUinxeEreKJ9Cc6/aBZL/tQOhxg8xFIis/aPAyUerUe1Fb+/cPzjL02kebEzv
         dydQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=ET9rgc2cPQO0D9fY/bz0XEDC7bhtrK0ZvnRrK6wQ7eU=;
        b=yRbVnRAnizI+Q9beQtV+qAP3Bg69DV7pplALuPGNuNnaKxgkpwBsr1kkdh9c8fhuhq
         EcA6H/XkIrXtujOaIKKn2WCb4AsgGVLAVHMoMY2pDoN3Afl9b0G+yGEF+aLaPjQ7ofy5
         9rvJgyJamu4oPnJpjjGLRb9Mv6PJMIRMrMqthw/xKy4kKo7ti+JEqH9h4TnAsjgPChEC
         eSLncBAF4yb5JzZ7zMpXIqt9yS5bp8/TjML/ELUEusa4iSppjomOkrri0X9sruiI5ZYp
         zE1abuJr4c+BLlKg7GH3qB0HOkeOMqLaMTcejMZzfe5hbV1Y6MboAVhWbMDtcYEVyslU
         e8Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=WxFhA8TZ;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id az35si532156uab.1.2021.10.27.22.02.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Oct 2021 22:02:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id oa12-20020a17090b1bcc00b0019f715462a8so3730945pjb.3
        for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 22:02:44 -0700 (PDT)
X-Received: by 2002:a17:90b:f82:: with SMTP id ft2mr911134pjb.107.1635397363825;
        Wed, 27 Oct 2021 22:02:43 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id y6sm1667005pfi.154.2021.10.27.22.02.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Oct 2021 22:02:43 -0700 (PDT)
Date: Wed, 27 Oct 2021 22:02:43 -0700 (PDT)
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
In-Reply-To: <CA+zEjCuUCxqTtbox2K8c=ymHC8X97LV6CSO3ydJKgRR9cBXUEw@mail.gmail.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, nathan@kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-897d082f-5ca4-4d77-a69d-4efaa456bf3b@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=WxFhA8TZ;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Wed, 27 Oct 2021 21:15:28 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>>
>> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
>> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
>> > Kconfig, it prevents asan-stack from getting disabled with clang even
>> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
>> > corresponding config.
>> >
>> > Reported-by: Nathan Chancellor <nathan@kernel.org>
>> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>> > ---
>> >  arch/riscv/Kconfig             | 6 ++++++
>> >  arch/riscv/include/asm/kasan.h | 3 +--
>> >  arch/riscv/mm/kasan_init.c     | 3 +++
>> >  3 files changed, 10 insertions(+), 2 deletions(-)
>> >
>> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> > index c1abbc876e5b..79250b1ed54e 100644
>> > --- a/arch/riscv/Kconfig
>> > +++ b/arch/riscv/Kconfig
>> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
>> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
>> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
>> >
>> > +config KASAN_SHADOW_OFFSET
>> > +     hex
>> > +     depends on KASAN_GENERIC
>> > +     default 0xdfffffc800000000 if 64BIT
>> > +     default 0xffffffff if 32BIT
>>
>> I thought I posted this somewhere, but this is exactly what my first
>> guess was.  The problem is that it's hanging on boot for me.  I don't
>> really have anything exotic going on, it's just a defconfig with
>> CONFIG_KASAN=y running in QEMU.
>>
>> Does this boot for you?
>
> Yes with the 2nd patch of this series which fixes the issue
> encountered here. And that's true I copied/pasted this part of your
> patch which was better than what I had initially done, sorry I should
> have mentioned you did that, please add a Codeveloped-by or something
> like that.

Not sure if I'm missing something, but it's still not booting for me.  
I've put what I'm testing on palmer/to-test, it's these two on top of 
fixes and merged into Linus' tree

    *   6d7d351902ff - (HEAD -> to-test, palmer/to-test) Merge remote-tracking branch 'palmer/fixes' into to-test (7 minutes ago) <Palmer Dabbelt>
    |\
    | * 782551edf8f8 - (palmer/fixes) riscv: Fix CONFIG_KASAN_STACK build (6 hours ago) <Alexandre Ghiti>
    | * 47383e5b3c4f - riscv: Fix asan-stack clang build (6 hours ago) <Alexandre Ghiti>
    | * 64a19591a293 - (riscv/fixes) riscv: fix misalgned trap vector base address (9 hours ago) <Chen Lu>
    * |   1fc596a56b33 - (palmer/master, linus/master, linus/HEAD, master) Merge tag 'trace-v5.15-rc6' of git://git.kernel.org/pub/scm/linux/kernel/git/rostedt/linux-trace (11 hours ago) <Linus Torvalds>

Am I missing something else?

>
> Thanks,
>
> Alex
>
>>
>> > +
>> >  config ARCH_FLATMEM_ENABLE
>> >       def_bool !NUMA
>> >
>> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
>> > index a2b3d9cdbc86..b00f503ec124 100644
>> > --- a/arch/riscv/include/asm/kasan.h
>> > +++ b/arch/riscv/include/asm/kasan.h
>> > @@ -30,8 +30,7 @@
>> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
>> >  #define KASAN_SHADOW_START   KERN_VIRT_START
>> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
>> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
>> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
>> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> >
>> >  void kasan_init(void);
>> >  asmlinkage void kasan_early_init(void);
>> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> > index d7189c8714a9..8175e98b9073 100644
>> > --- a/arch/riscv/mm/kasan_init.c
>> > +++ b/arch/riscv/mm/kasan_init.c
>> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
>> >       uintptr_t i;
>> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
>> >
>> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
>> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
>> > +
>> >       for (i = 0; i < PTRS_PER_PTE; ++i)
>> >               set_pte(kasan_early_shadow_pte + i,
>> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-897d082f-5ca4-4d77-a69d-4efaa456bf3b%40palmerdabbelt-glaptop.
