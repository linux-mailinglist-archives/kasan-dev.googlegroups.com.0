Return-Path: <kasan-dev+bncBCMIZB7QWENRBUV52PZQKGQE2SRAEYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C61818D2AA
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 16:18:44 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id q7sf5979486qtp.16
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 08:18:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584717523; cv=pass;
        d=google.com; s=arc-20160816;
        b=goPdP3SW92CpoV4BxmmGU7ew8JfLwSI0T+0lc2rbRvlhS/vKIrsO9jpvm89Z6CzdZq
         GogQo+kwBvsKbLG1a2TrGhz9A6LA8F/+jpxu6GLODHkXHwabNRO0Fou5uAf8O+8g4a+m
         xrIQsmuxegEyXwXP0MPI3ZTEx6G/r5AXURPlrOTRM/7S0ERWMObBMc4EFanxNuJqWjtH
         QD9YBUOWxOuxjLueLrSCHexzVpobJyCeIbvO/zrPV4W4Nhmlx3W2Gx4YM4GW38CF75ea
         qCZFafmlmYv7nGy0NH0/FsD0U0czR+qy5K7JfJZ/GSRj+mTjA3FU3EUdDhNGzIlnSH6M
         TECg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B3PCGxJ/lkaJDNQUCOUhMMpyD2bop8qKHeMMKmztP2M=;
        b=qffOQRqZC6Ny+twWPysAhWr3rPUEIw6jBLE4kwtmy09u+aS5H1nl7vYIF4uQbsqJwf
         iK9V+Cq6cNsnx4xnBme8icr8/12qDUt71ZRuatFW9ALXLixktBLz9qzhvt9QUhpJu0M4
         ThhSqKTNs6Vvfe9NYc4vsheA4GgK4YV2cUtue1l1WVassQD+lYa7Xa1bUReV+2n9jagg
         AVmhJ/0qKoRviqycA0i2I35omsMCcR9C7CKnNKWuUR1Da3rqMU44J4b8dJJpzvtDXTiR
         GcYCaV6ksl8BPf8sBnM9cOOdD6Z/85FnvBmwVEZIT3vxB/pgKLp31FToHLp6APf/kenb
         znrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dyq1Yvhz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3PCGxJ/lkaJDNQUCOUhMMpyD2bop8qKHeMMKmztP2M=;
        b=RfdcL83CSGnjABcgIad5+l4+BnyS01D9pvVdip3WsvUlX+Qzf9Au77CR+iZcmYN7cq
         tB4c8ItrOLnlRSfgJOLESpSif+x873VNPe/Ykag7JfHemc3aX6imFn+7FpOQONEuIHis
         uJkMkrRn0ZFai2ZD8MIb6jpRJC6gB7oJPr7RRy+3kpDKUEdUHhtz/onZCVcLLDaEV6Bf
         AL6Wjzg+foAQQ3Tr306MpKnTeRh7JJedFguOK+pKWF+FH1fesgEDMn5oeKX9C3rupX/a
         l7nTU0JfnDENdKMCUqChe8aI9xS+wn98fqr1V8qO9Qz/BLJu2idJoZ8foGuZki96j0DF
         Hwuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3PCGxJ/lkaJDNQUCOUhMMpyD2bop8qKHeMMKmztP2M=;
        b=LilKAyrgd+7EObUtKlOmJXh0u3u+Z9qItVrEkMfulsrKsY+9kyac0b9lbflPsRHF+t
         3g/VVj0Ti7WyWKlOEMcoMh1sYdh+EeIUdajKt2rHqarBImOh2Mqn51Mt4QQsBUChT97q
         PqQFRN5pdLVVEkVE/e5ttVVOSMI3MpRHVKFBP5ro0uU3+oYSpHLZOY6TaeTlmfMh8fhb
         0by+wsrLAd8CJaydmJ452NyutP65EQWMukfubv6NGbSqon3pxIJBqapEHv/uQ5Ug1Wzy
         ho0tarn0dGbHhKrL5BuE2xdwfhNVD+SUEBKy5MPnRGm+Gmg09lYF6g3LXciZnUMWB32M
         Qyvg==
X-Gm-Message-State: ANhLgQ1UPonzRlIaKmjRqluR7/lZyqgSMztLK6NdXVWubLYTT4qnTXqs
	vf0a1LQxBziKyI7DCNeEWPI=
X-Google-Smtp-Source: ADFU+vswhIPoVgR2Wj8uFwGGfTNnWYKU8paL2LfS3lf79vuMIg/7kfwgIlnbS9gGAOleang6iV4ybg==
X-Received: by 2002:a05:6214:188e:: with SMTP id cx14mr8828129qvb.187.1584717522909;
        Fri, 20 Mar 2020 08:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2ca1:: with SMTP id g30ls2847408qtd.1.gmail; Fri, 20 Mar
 2020 08:18:42 -0700 (PDT)
X-Received: by 2002:aed:2591:: with SMTP id x17mr8786929qtc.380.1584717522466;
        Fri, 20 Mar 2020 08:18:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584717522; cv=none;
        d=google.com; s=arc-20160816;
        b=zLZFmt0ounkDOT60FDuw9r0MlxA3XUpZGyCavMRqY6Mxx1RLFulmHPNSDSsqEQe8iX
         4kQAJ0Up1nw9vwozcoi26mqnNantvZNUAF4Vjkh4+fMNxQiH0R33ccn4U32GK6hlXvTx
         NimuhsS1G/IOR0B/iWvFDvBqZwapHLjM7iDKfY3QMB2ypwxbg0G/I0OtD2W6YRqytmsG
         aZDho0Hpsx4lKjbSaknWzmUdnTB5o63zVAkxLGiAbW+gPOBI0QEG3beF29nluQCkemoR
         fhxuNLX8uyOWRbXapHS4z3jZdQtSWZjYW2dBzGSIwdMOfxzhqx3122qxJFLM/UhZApDR
         OAHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CMdn/vEztvR1JjJusqBbOT1Y2kMsnjTOnNP0m/IulTk=;
        b=XMGEtDNkuyXbz2U4+mvJoJetyMDhGiFzf9cRoKmgHk14YapA2O4onrlRB4fF/Gvex7
         xSRItd5dfMYKDQyLxawJJm8bTru/i1q103lzNXG7YgUpiumfXK9dmhsODtKKQ7CkAcQi
         hb7jjf3yNNavjLF7v25lu/7J0/iHU3iKJylRcL2dDBZzyRD7yp58eIUNSUXWJz1uKbqe
         +ALKGZOQaYEFmDxOKAXM3KsGgdEdeviKM5kiUBouEeadOU/1Ij2S13cfg74KaFQwrpuk
         QyjqybG5AY6x6h7AUi1ScEoexMW4o+mXgC6xXpKMmKuTUKwvoL1X4P25qzppDbBmSYni
         x5Vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dyq1Yvhz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id d34si409571qte.4.2020.03.20.08.18.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Mar 2020 08:18:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id f28so7111544qkk.13
        for <kasan-dev@googlegroups.com>; Fri, 20 Mar 2020 08:18:42 -0700 (PDT)
X-Received: by 2002:a37:8b01:: with SMTP id n1mr7514871qkd.407.1584717521649;
 Fri, 20 Mar 2020 08:18:41 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com> <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
In-Reply-To: <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Mar 2020 16:18:30 +0100
Message-ID: <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Dyq1Yvhz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Mar 20, 2020 at 2:39 PM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Wed, 2020-03-11 at 18:34 +0100, Dmitry Vyukov wrote:
>
> > > $ gdb -p ...
> > > (gdb) p/x task_size
> > > $1 = 0x7fc0000000
> > > (gdb) p/x __end_of_fixed_addresses
> > > $2 = 0x0
> > > (gdb) p/x end_iomem
> > > $3 = 0x70000000
> > > (gdb) p/x __va_space
> > >
> > > #define TASK_SIZE (task_size)
> > > #define FIXADDR_TOP        (TASK_SIZE - 2 * PAGE_SIZE)
> > >
> > > #define FIXADDR_START      (FIXADDR_TOP - FIXADDR_SIZE)
> > > #define FIXADDR_SIZE       (__end_of_fixed_addresses << PAGE_SHIFT)
> > >
> > > #define VMALLOC_END       (FIXADDR_START-2*PAGE_SIZE)
> > >
> > > #define MODULES_VADDR   VMALLOC_START
> > > #define MODULES_END       VMALLOC_END
> > > #define VMALLOC_START ((end_iomem + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1))
> > > #define VMALLOC_OFFSET  (__va_space)
> > > #define __va_space (8*1024*1024)
> > >
> > >
> > > So from that, it would look like the UML vmalloc area is from
> > > 0x  70800000 all the way to
> > > 0x7fbfffc000, which obviously clashes with the KASAN_SHADOW_OFFSET being
> > > just 0x7fff8000.
> > >
> > >
> > > I'm guessing that basically the module loading overwrote the kasan
> > > shadow then?
> >
> > Well, ok, this is definitely not going to fly :)
>
> Yeah, not with vmalloc/modules at least, but you can't really prevent
> vmalloc :)
>
> > I don't know if it's easy to move modules to a different location.
>
> We'd have to not just move modules, but also vmalloc space. They're one
> and the same in UML.
>
> > It
> > would be nice because 0x7fbfffc000 is the shadow start that's used in
> > userspace asan and it allows to faster instrumentation (if offset is
> > within first 2 gigs, the instruction encoding is much more compact,
> > for >2gigs it will require several instructions).
>
> Wait ... Now you say 0x7fbfffc000, but that is almost fine? I think you
> confused the values - because I see, on userspace, the following:

Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000. Here is the
user-space mapping that uses it:
https://github.com/llvm/llvm-project/blob/master/compiler-rt/lib/asan/asan_mapping.h#L25


> || `[0x10007fff8000, 0x7fffffffffff]` || HighMem    ||
> || `[0x02008fff7000, 0x10007fff7fff]` || HighShadow ||
> || `[0x00008fff7000, 0x02008fff6fff]` || ShadowGap  ||
> || `[0x00007fff8000, 0x00008fff6fff]` || LowShadow  ||
> || `[0x000000000000, 0x00007fff7fff]` || LowMem     ||
>
>
> Now, I also don't really understand what UML is doing here -
> os_get_top_address() determines some sort of "top address"? But all that
> is only on 32-bit, on 64-bit, that's always 0x7fc0000000.

Then I would expect 0x1000 0000 0000 to work, but you say it doesn't...

> So basically that means it's just _slightly_ higher than what you
> suggested as the KASAN_SHADOW_OFFSET now (even if erroneously?), and
> shouldn't actually clash (and we can just change the top address value
> to be slightly lower anyway to prevent clashing).
>
> > But if it's not really easy, I guess we go with a large shadow start
> > (at least initially). A slower but working KASAN is better than fast
> > non-working KASAN :)
>
> Indeed, but I can't even get it to work regardless of the offset.
>
> Note that I have lockdep enabled, and at least some crashes appear to be
> because of the stack unwinding code that is called by lockdep in various
> situations...

This is something new, right? The previous stacks you posted did not
mention lockdep.

> > > I tried changing it
> > >
> > >  config KASAN_SHADOW_OFFSET
> > >         hex
> > >         depends on KASAN
> > > -       default 0x7fff8000
> > > +       default 0x8000000000
> > >
> > >
> > > and also put a check in like this:
> > >
> > > +++ b/arch/um/kernel/um_arch.c
> > > @@ -13,6 +13,7 @@
> > >  #include <linux/sched.h>
> > >  #include <linux/sched/task.h>
> > >  #include <linux/kmsg_dump.h>
> > > +#include <linux/kasan.h>
> > >
> > >  #include <asm/pgtable.h>
> > >  #include <asm/processor.h>
> > > @@ -267,9 +268,11 @@ int __init linux_main(int argc, char **argv)
> > >         /*
> > >          * TASK_SIZE needs to be PGDIR_SIZE aligned or else exit_mmap craps
> > >          * out
> > >          */
> > >         task_size = host_task_size & PGDIR_MASK;
> > >
> > > +       if (task_size > KASAN_SHADOW_OFFSET)
> > > +               panic("KASAN shadow offset must be bigger than task size");
> > >
> > >
> > > but now I just crash accessing the shadow even though it was mapped fine?
> >
> > Yes, this is puzzling.
> > I noticed that RIP is the same in both cases and it relates to vmap code.
> > A support for shadow for vmalloced-memory was added to KASAN recently
> > and I suspect it may conflict with UML.
>
> This can't be it - HAVE_ARCH_KASAN_VMALLOC isn't selected, so
> KASAN_VMALLOC isn't set.
>
> > What does pte-manipulation code even do under UML?
>
> No idea.
>
> > Looking at the code around, kasan_mem_notifier may be a problem too,
> > or at least excessive and confusing. We already have shadow for
> > everything, we don't need _any_ of dynamic/lazy shadow mapping.
>
> CONFIG_MEMORY_HOTPLUG is also not supported in ARCH=um, or at least not
> used in my config.

Ack.

Maybe if you dump /proc/self/maps for the process, it will shed some light.
Or is it possible to run it under strace? If we get all
mmap/munmap/mprotect, we will maybe see the offender that messes the
shadow...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYzM5bwvJ%3Dyryrz1_y%3Duh%3DNX%2B2PNu4pLFaqQ2BMS39Fdg%40mail.gmail.com.
