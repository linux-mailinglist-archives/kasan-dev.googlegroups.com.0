Return-Path: <kasan-dev+bncBCMIZB7QWENRBSWCUTZQKGQEQIPBNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B8B7181F95
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 18:35:08 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id m29sf1719345pgd.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 10:35:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583948106; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCcDqk5ZYhJ2JWRPLpaCDM9hX6kAGIbkk5Mnpq74XiW6q0C1o2XB9dM7/rkkiO12eg
         Gfi62cmNX3qUVKwnTQ20bXG767NuNmgKNO/DHnY5H/VqgV01no8bLBSduRwjN49mP8sf
         l0Vtq0TMbZ8Wv+HeNYnVQcAPRo8SgpPJB2SHcE1JYhDb9Hjhua6DDEcizidtfM52Z8ab
         YSGBdqT7gl3kNGbC7tCHiwAGa3drambgg+7cFgB34jt1il8D42tJXVrCc+RNM949kPxm
         4yVnkXrXTDrc41NnaaWehpXrx3vsU0iV+mJxy+DNn2VWxWytpDadFLZUkzAQWIvEuz6w
         sj+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pRsxBeN6JoG0iErsEUzuvuJlr6tzdf0sQF2Dwwv2Yto=;
        b=dWjBIJBIcI8DpxqS6sSK0yX7DQygEIcX7zTXXpRgP3ZvMv/0zkvTYGrE4BH2oUjzaJ
         hlhQGjfk+bjHbiKEGdix9JoolTh8Ag6fLBpce2P8TrwrEGOE+TbJ8GM1YVCKSGMph+6Q
         6i19kzrxb2yKsk/N3S7ksXaRySOu6ByB8gN2IdFkADwnT6Hfh0Zxc36hg413mnVB3YIl
         fi84QO3Xql1jWWVEUSe/G1vACVav2xphnQpgiNtSHaoBnMmeG/gDY8DsuUFE+Y7iU4IB
         mxoRI8+PsHZDDrfj3Iu1mFInuAb0dOVMypuXJQum37CvdysbNlgFDKgpLxqKfhqWKIW7
         0OTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NvKtUY0D;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pRsxBeN6JoG0iErsEUzuvuJlr6tzdf0sQF2Dwwv2Yto=;
        b=kt0IamcOwvEYBfS5VEHrKnE1eoLj4m6+NSZwVVrmDVu5vPiQymjP668qZGlBdzGOzF
         jE7I4idHISEv8fJKdZizP0ixz51MCiG3lcRaN3XgYrUcH3PR/h2hwKbafdY3oN33vLo8
         ZXaTlUSCMxZGmyguJXXnyLYzT2kHZzfC3N+0te2QQOzsy1be2TFPt2vZpK75oUir18dG
         XgucCPosBDHwOCJpK3reZS3I1hInCfS867T0rCmvP9Abja9wr12+QBa5mGuzB+Qpxe97
         3SH9wQGfQnKmHvSaFOMyV4+kZ+AtF880M5PMH2M9dyZ1aRcVyDlFZXcsVZF4aVdRxHCm
         frFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pRsxBeN6JoG0iErsEUzuvuJlr6tzdf0sQF2Dwwv2Yto=;
        b=Dj255hmn4EPdj0qTVn2Nuz1hhHPG3Bl212vsJHhKUjhTNZk4isc6SspTNiSPQIxoRL
         8Ju5sDP14jDBPdlh51tmOTWjy0TrbMV5Y/J2lBndatFlWR/bqX06E1NFbRbH9kPAV76w
         g8Ls+WZxNf0HBYFJFgqtFMK0V0w45ZgDIjUYW1RPWVfDRDMSy8Oc6b4Z7S/nCJPqcr9V
         BttYi/YdLpPr2vvF/Cw+M3j1LA6nKu2QDoKZ0gDkTxseZL3tAeVwBAp5hK0A0Yguh/h9
         Qq7sRAvzYoY7ybs73Mm8H4ytl51Zg3QudbkdpRCK3GFjV30TU02S7cAqDVP7IRhle86M
         X8og==
X-Gm-Message-State: ANhLgQ2ubd/D/RWy7dO9MU0TvQfKnrK2TSQsQlRnbqaFwASSB+XPZUn1
	iPeH+WRp0/UKXUUyq8Ji9BQ=
X-Google-Smtp-Source: ADFU+vvgp+aI33/FGAdK1EMGlyR1ryE/l6PoQIn072+XNFxNQf5zkqLFRvdSoxSV/5nnKqomcyNOXQ==
X-Received: by 2002:a65:5a8a:: with SMTP id c10mr4006646pgt.315.1583948106489;
        Wed, 11 Mar 2020 10:35:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5f8b:: with SMTP id t133ls1277334pgb.1.gmail; Wed, 11
 Mar 2020 10:35:06 -0700 (PDT)
X-Received: by 2002:a63:1744:: with SMTP id 4mr4087137pgx.238.1583948105935;
        Wed, 11 Mar 2020 10:35:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583948105; cv=none;
        d=google.com; s=arc-20160816;
        b=A8skcXF3AAezIs1uPPnVPxL2VtJKgUE1pKSe82gcHv1y0u6cSqNK1FE9OevFg5kqAn
         cVv5hav+6DmFGE4uxmCKSS7RXEGIbiPg0/63QFrSKpKifnieLiaVKFz3ud/CYCCdIeAL
         lHZjDbOuxsFaeif7xvUFwIBIsVUMzZStTWJ4utXkJsdNC8wKMzUU3c9ry+ukSs3orX3q
         dZLa3XfIHeYeMysDgAHlTkRXEGePro6dMNrbS1o2C/goA9YpmFIzp1RmSaj/TipIca5e
         DCViLzqjrPT2mCLU/322lrLgUBkjPnS/YTdUIFpLatFbPzPG2qpp4LuCFiTAYMCgC8Yp
         4iYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fa8m8jYa1TakhUMQnyj4bRdIQUor/ug/z2CxDzEB9h0=;
        b=rH8zJbI2GjM0rDGTbqI9KzcDuGXmPUrEXgUaetBAyNUQnh5FXqtXq5l1TnI3zQUvjf
         ur8mDj4lDigdBXvaQANnIOAhkTD5AYlVaDhITYNzQy5BhlkHA4f5bE2LRgJlq+AZqypd
         K2MFcqaQm2Q0yhJMise/dQHy0bJdfkqGd/hAoGUqWfOAKyxW2Vd8caGOe5CCSG2dJMeX
         RcEtGHqD/gW+wgr2ED6s+H47m1zKHRJQomJXeR8eO3jN+ZzYOCY2McqMMBxtSWqCaxUN
         AJXhZQIUtgRsU1HgtoUPfFf7KhpXtGZNgUJx7MbHF942J0rUld8ca3UfRulEudk+MD6X
         fKMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NvKtUY0D;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id my13si25521pjb.1.2020.03.11.10.35.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Mar 2020 10:35:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id y126so2905133qke.4
        for <kasan-dev@googlegroups.com>; Wed, 11 Mar 2020 10:35:05 -0700 (PDT)
X-Received: by 2002:a37:8b01:: with SMTP id n1mr3423155qkd.407.1583948104591;
 Wed, 11 Mar 2020 10:35:04 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net> <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
In-Reply-To: <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Mar 2020 18:34:53 +0100
Message-ID: <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NvKtUY0D;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Wed, Mar 11, 2020 at 12:19 PM Johannes Berg
<johannes@sipsolutions.net> wrote:
>
> On Wed, 2020-03-11 at 11:32 +0100, Johannes Berg wrote:
> >
> > I do see issues with modules though, e.g.
> > https://p.sipsolutions.net/1a2df5f65d885937.txt
> >
> > where we seem to get some real confusion when lockdep is storing the
> > stack trace??
> >
> > And https://p.sipsolutions.net/9a97e8f68d8d24b7.txt, where something
> > convinces ASAN that an address is a user address (it might even be
> > right?) and it disallows kernel access to it?
>
> I can work around both of these by not freeing the original module copy
> in kernel/module.c:
>
>         /* Get rid of temporary copy. */
> //      free_copy(info);
>
> but I really have no idea why we get this in the first place?
>
> Another interesting data point is that it never happens on the first
> module.
>
> Also, I've managed to get a report like this:
>
> Memory state around the buggy address:
>  000000007106cf00: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
>  000000007106cf80: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
> >000000007106d000: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
>                    ^
>  000000007106d080: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
>  000000007106d100: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
>
>
> which indicates that something's _really_ off with the KASAN shadow?
>
>
> Ohhh ...
>
> $ gdb -p ...
> (gdb) p/x task_size
> $1 =3D 0x7fc0000000
> (gdb) p/x __end_of_fixed_addresses
> $2 =3D 0x0
> (gdb) p/x end_iomem
> $3 =3D 0x70000000
> (gdb) p/x __va_space
>
> #define TASK_SIZE (task_size)
> #define FIXADDR_TOP        (TASK_SIZE - 2 * PAGE_SIZE)
>
> #define FIXADDR_START      (FIXADDR_TOP - FIXADDR_SIZE)
> #define FIXADDR_SIZE       (__end_of_fixed_addresses << PAGE_SHIFT)
>
> #define VMALLOC_END       (FIXADDR_START-2*PAGE_SIZE)
>
> #define MODULES_VADDR   VMALLOC_START
> #define MODULES_END       VMALLOC_END
> #define VMALLOC_START ((end_iomem + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1)=
)
> #define VMALLOC_OFFSET  (__va_space)
> #define __va_space (8*1024*1024)
>
>
> So from that, it would look like the UML vmalloc area is from
> 0x  70800000 all the way to
> 0x7fbfffc000, which obviously clashes with the KASAN_SHADOW_OFFSET being
> just 0x7fff8000.
>
>
> I'm guessing that basically the module loading overwrote the kasan
> shadow then?

Well, ok, this is definitely not going to fly :)

I don't know if it's easy to move modules to a different location. It
would be nice because 0x7fbfffc000 is the shadow start that's used in
userspace asan and it allows to faster instrumentation (if offset is
within first 2 gigs, the instruction encoding is much more compact,
for >2gigs it will require several instructions).
But if it's not really easy, I guess we go with a large shadow start
(at least initially). A slower but working KASAN is better than fast
non-working KASAN :)

> I tried changing it
>
>  config KASAN_SHADOW_OFFSET
>         hex
>         depends on KASAN
> -       default 0x7fff8000
> +       default 0x8000000000
>
>
> and also put a check in like this:
>
> +++ b/arch/um/kernel/um_arch.c
> @@ -13,6 +13,7 @@
>  #include <linux/sched.h>
>  #include <linux/sched/task.h>
>  #include <linux/kmsg_dump.h>
> +#include <linux/kasan.h>
>
>  #include <asm/pgtable.h>
>  #include <asm/processor.h>
> @@ -267,9 +268,11 @@ int __init linux_main(int argc, char **argv)
>         /*
>          * TASK_SIZE needs to be PGDIR_SIZE aligned or else exit_mmap cra=
ps
>          * out
>          */
>         task_size =3D host_task_size & PGDIR_MASK;
>
> +       if (task_size > KASAN_SHADOW_OFFSET)
> +               panic("KASAN shadow offset must be bigger than task size"=
);
>
>
> but now I just crash accessing the shadow even though it was mapped fine?

Yes, this is puzzling.
I noticed that RIP is the same in both cases and it relates to vmap code.
A support for shadow for vmalloced-memory was added to KASAN recently
and I suspect it may conflict with UML.
See:
https://elixir.bootlin.com/linux/v5.6-rc5/ident/kasan_populate_vmalloc

I think we simply don't need any of that because we already mapped
shadow for all potentially used memory.
A simple thing to try is to disable CONFIG_KASAN_VMALLOC. If it fixes
the problem, we need to either force-disable CONFIG_KASAN_VMALLOC
under UML or return early from these functions.

What does pte-manipulation code even do under UML?

Looking at the code around, kasan_mem_notifier may be a problem too,
or at least excessive and confusing. We already have shadow for
everything, we don't need _any_ of dynamic/lazy shadow mapping.


> Pid: 504, comm: modprobe Tainted: G           O      5.5.0-rc6-00009-g094=
62ab4014b-dirty
> RIP:
> RSP: 000000006d68fa90  EFLAGS: 00010202
> RAX: 000000800e0210cd RBX: 000000007010866f RCX: 00000000601a9777
> RDX: 000000800e0210ce RSI: 0000000000000004 RDI: 000000007010866c
> RBP: 000000006d68faa0 R08: 000000800e0210cd R09: 0000000060041432
> R10: 000000800e0210ce R11: 0000000000000001 R12: 000000800e0210cd
> R13: 0000000000000000 R14: 0000000000000001 R15: 00000000601c2e82
> Kernel panic - not syncing: Kernel mode fault at addr 0x800e0210cd, ip 0x=
601c332b
> CPU: 0 PID: 504 Comm: modprobe Tainted: G           O      5.5.0-rc6-0000=
9-g09462ab4014b-dirty #24
> Stack:
> 601c2f89 70108638 6d68fab0 601c1209
> 6d68fad0 601a9777 6cf2b240 7317f000
> 6d68fb40 601a2ae9 6f15b118 00000001
> Call Trace:
> ? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> __kasan_check_write (/home/tester/vlab/linux/mm/kasan/common.c:102)
> __free_pages (/home/tester/vlab/linux/./arch/x86/include/asm/atomic.h:125=
 /home/tester/vlab/linux/./include/asm-generic/atomic-instrumented.h:748 /h=
ome/tester/vlab/linux/./include/linux/page_ref.h:139 /home/tester/vlab/linu=
x/./include/linux/mm.h:593 /home/tester/vlab/linux/mm/page_alloc.c:4823)
> __vunmap (/home/tester/vlab/linux/mm/vmalloc.c:2303 (discriminator 2))
> ? __asan_load4 (/home/tester/vlab/linux/mm/kasan/generic.c:251)
> ? sysfs_create_bin_file (/home/tester/vlab/linux/fs/sysfs/file.c:537)
> __vfree (/home/tester/vlab/linux/mm/vmalloc.c:2356)
> ? delete_object_full (/home/tester/vlab/linux/mm/kmemleak.c:693)
> vfree (/home/tester/vlab/linux/mm/vmalloc.c:2386)
> ? sysfs_create_bin_file (/home/tester/vlab/linux/fs/sysfs/file.c:537)
> ? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> load_module (/home/tester/vlab/linux/./include/linux/jump_label.h:254 /ho=
me/tester/vlab/linux/./include/linux/jump_label.h:264 /home/tester/vlab/lin=
ux/./include/trace/events/module.h:31 /home/tester/vlab/linux/kernel/module=
.c:3927)
> ? kernel_read_file_from_fd (/home/tester/vlab/linux/fs/exec.c:993)
> ? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> __do_sys_finit_module (/home/tester/vlab/linux/kernel/module.c:4019)
> ? sys_finit_module (/home/tester/vlab/linux/kernel/module.c:3995)
> ? __asan_store8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> sys_finit_module (/home/tester/vlab/linux/kernel/module.c:3995)
> handle_syscall (/home/tester/vlab/linux/arch/um/kernel/skas/syscall.c:44)
> userspace (/home/tester/vlab/linux/arch/um/os-Linux/skas/process.c:173 /h=
ome/tester/vlab/linux/arch/um/os-Linux/skas/process.c:416)
> ? save_registers (/home/tester/vlab/linux/arch/um/os-Linux/registers.c:18=
)
> ? arch_prctl (/home/tester/vlab/linux/arch/x86/um/syscalls_64.c:65)
> ? calculate_sigpending (/home/tester/vlab/linux/kernel/signal.c:200)
> ? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> ? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> ? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)
> fork_handler (/home/tester/vlab/linux/arch/um/kernel/process.c:154)
>
> johannes
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbdxmRmr57JO_k0whhnT2BqcSA%3DJwa5M6%3D9wdyOryv6Ug%40mail.=
gmail.com.
