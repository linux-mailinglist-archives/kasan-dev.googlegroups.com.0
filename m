Return-Path: <kasan-dev+bncBCMIZB7QWENRBF7XYXTAKGQES2XKOZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id E424D163CA
	for <lists+kasan-dev@lfdr.de>; Tue,  7 May 2019 14:35:36 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id l192sf31323428ywc.10
        for <lists+kasan-dev@lfdr.de>; Tue, 07 May 2019 05:35:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1557232535; cv=pass;
        d=google.com; s=arc-20160816;
        b=T0QPOVdjC7Lskiogk6gCfN3vgbtbJiRJqfQbmhVpznQQX1xJG7XKD/I1saZ8M+cQ0r
         XC2X8c90ajCh8yeD6HRfYKy3OtUHshkkFjqOLrxm91pDdmoA0W3p4lhQ8iTLjc21tWgL
         +VkuvVVJReIyQLDrBCvMpGjJhFYihuQBbJphzs98jyn2LfHZTEjdujY2eYnCiadxV5Ub
         BjfsIlW+1OiURL9iSfH4lpXHoe0iFYrizLoD/pNavuNEuTKjcwJ+CdKflgRNd/Pwy46p
         gy7ZwN4E3kCWrUCxQcHT6nHJuJVymX6BiGkIJcyB7dbbZ0gPbHkG5CwIq4BGAkyFKj5o
         kwCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s9cUxcTpvSF3VyBcTgep/LWDW3NsSqStBcbrmzrMJ5A=;
        b=TD6z9eHOJoORQvrXwXJyHSKoSe9B8AdvDoblF680r9L8vhH0S9P2H5PS4L9avlTrza
         6YxD+BZyc0HqURcZLmouYy2go1+XpO1KLp5WaM5kwl7/pH8q+cUveIXO5AXzBcPTjqo6
         zsFd3Dnizx+kkTp8ossz21/vCl47wiQhiSNUjaejSTbg5c+H2DIjnBHG/ypQ27/Sa+Ft
         pryXkTzuItnsO5m7lfugwiMIeGiPTHjGvRHoG+rZhP1qPOdKwUggxb6UTE1pQ6VDX20Z
         yZm/5414K78mVPS1DBWb1rEjpIf1fByVPf0QtGAmBkVVZVOXfOOqPuVt39w9IFCbC/on
         YeQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cxND2L+x;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s9cUxcTpvSF3VyBcTgep/LWDW3NsSqStBcbrmzrMJ5A=;
        b=KgCdVAZTeKk/epPyzaIMGszKTuR+KmbM7xx+Nywklerx+a5Lm/nV3s17l/Jxm94Y4l
         Stp3aaMVbtGgMKas+PHfLzFAOjrGeDwe4nBOzYgeC4fkvfC8un9X/Nfu6OynCfFEpRry
         DQHW3lgAWh0RCy+F4Li3u4Uitk9h8HnZSW9Ex5OYAbZn1+9mQrbgocFdOQ+PNgRDkWcO
         zUZAfHYuNK0nkbcFnHhGSGA/KW6VnG8/f0hyHPzUI+iPNOSkUx4v/kkiOUzb3F/tOz3B
         o5kPKNCeano6/IckGtbcMG8a/3sdw5p78rI4VfCkicnl8S/dLcF8Fo3iFVa+dS95HML3
         Sizw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s9cUxcTpvSF3VyBcTgep/LWDW3NsSqStBcbrmzrMJ5A=;
        b=JbriT6WYt4YUv7Tq7fKqSowKxY7zxNHsor5DmcvjCTj7hRvAVIEb9OpEeIrPRQMJIV
         Eyjg/5j7nj5OEovgQHuFhqQPGbfoPK6ql8YNazOm0LyiRJrWVgyzPjJ92TX+HvlYPzNl
         w/RIuxiqSZnzQWYyZfwwhZs9LHDRHck/g8l25s/e1rfJ9u5NWRDtyV4rNT53vxEonKyz
         r8X/d3XUcOiO3INOvyuvM1xukiaXbVH+WJhlbGo7Oh59x0bZMyd9Pwj0rSDscNSp5YVl
         RWDQzuhFS+57szXFF4CKx4+v+xZXJI0dAGJUWxCYHGRGAN+jD/LhuKM/vRzQOM9UzCAQ
         HvBw==
X-Gm-Message-State: APjAAAXZ3N8JyvSRi0gUISvMF6VGfS6Vrlq/rr58ZUT2wFueax15MIyL
	LNDug0eb47eTSp6tgWDUhN8=
X-Google-Smtp-Source: APXvYqzHwnpv8tUybKLlCYq+9gHmShCiEp7xlKm4h9juajWfQZ7SUs0RzO7qq12fn1NWhbKcgUKrLA==
X-Received: by 2002:a81:3b16:: with SMTP id i22mr21041238ywa.107.1557232535685;
        Tue, 07 May 2019 05:35:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:670b:: with SMTP id b11ls2680289ybc.16.gmail; Tue, 07
 May 2019 05:35:35 -0700 (PDT)
X-Received: by 2002:a25:1a02:: with SMTP id a2mr20626123yba.306.1557232535350;
        Tue, 07 May 2019 05:35:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1557232535; cv=none;
        d=google.com; s=arc-20160816;
        b=n4rP/0ttLSqaNxKvQYhfn7VSbQQ0qNhpIT6MxT1fP67rm0Zho+EBitpKiNg9oqOTi7
         J1z9/kEKAx5Num/ohBN9DNz+EElTvlirrnjs2LZF+r41WPjl0iPfY7yt8jhC4HWOJfsK
         CtJbr5uvWLAtcOWIrwR6OyvDldr3gcnBFGNqmLsgJ6kL5peqH+31S8xYEROVeGz9vwPG
         e1wwOISaZw6AU+ohjcgULwDi6FDOch57OMYI0Y3uCT6D9Lsl3wEU8JiiLSuPzlEztqah
         H/uNEXIsz5MW30j9EY32lRoFm0tZVGKy7ZQWi+ZkNM4hU2SwDm9AG1nw7uJ6zjgFzcWn
         d4Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uqbDEJvUV2meANT+WZ2EOZlAGhQpXj7MHX9UDI2n0gQ=;
        b=f1wCmU42JjZN17Xj4Z+WSmyuvcDgaApfQBCdLG9+Mokgy1/CP4CuNsSg05tBQQTE/9
         hVFiCe8z+6IQDNidVlFNPp4uw7g0lOlXUMHczX4aWSJiT3Q2KuGeAAynM54f6bHhs2FJ
         jc/yYB2T65cqKbG7HtPO+ms4kr0US3gwXwNRLPAYylYR2A/BLEZb4xa86o29jq1kLQDf
         UKQJp5tJXPbf7DVDpZ+FDgYSvwp6FumbBjoRnb0MNrj+EOS5VFvRPLIpIsWyapySRjxu
         Cgd2EHukbmdtTjIUjM7RX9XDsOZf+KoOAMcPWBzKMcbr0AKQWQ7+4JWSn6+0iBj7rqlR
         d1zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cxND2L+x;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x12c.google.com (mail-it1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id l65si731490ywl.1.2019.05.07.05.35.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 May 2019 05:35:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-it1-x12c.google.com with SMTP id q132so10847421itc.5
        for <kasan-dev@googlegroups.com>; Tue, 07 May 2019 05:35:35 -0700 (PDT)
X-Received: by 2002:a05:660c:38a:: with SMTP id x10mr22609291itj.12.1557232534695;
 Tue, 07 May 2019 05:35:34 -0700 (PDT)
MIME-Version: 1.0
References: <0f7b6576-b8be-4143-91ce-1984945d93ca@googlegroups.com>
 <CACT4Y+bNjbhW2vEGA_M_FwDEhXe5ntR7b1rHMe3xf5pz0Oth+A@mail.gmail.com>
 <4873cc8b-f651-4fab-b8c3-02a0c020e1c5@googlegroups.com> <f6134a64-f48c-483a-9d27-e5bc1a1e9baa@googlegroups.com>
In-Reply-To: <f6134a64-f48c-483a-9d27-e5bc1a1e9baa@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 May 2019 14:35:23 +0200
Message-ID: <CACT4Y+abVUNrK61yFiLwOzti4bXv6d6PGJiMTm2ZdRKYXcXXDg@mail.gmail.com>
Subject: Re: How to debug these general protection fault: 0000 [#1] SMP KASAN
 PTI issues ?
To: JohnD Oracle <johndonoracle@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cxND2L+x;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12c
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

From: <johndonoracle@gmail.com>
Date: Mon, Apr 29, 2019 at 11:50 PM
To: syzkaller

>
>
> On Monday, April 29, 2019 at 10:26:23 AM UTC-5, johndo...@gmail.com wrote:
>>
>>
>>
>> On Monday, April 29, 2019 at 9:24:28 AM UTC-5, Dmitry Vyukov wrote:
>>>
>>> On Fri, Apr 26, 2019 at 8:40 PM JohnD Oracle <johndo...@gmail.com> wrote:
>>> >
>>> > Hi
>>> >
>>> >
>>> >  I am seeing a number of miss leading information in these reports , and I don't have an adequate understanding how KASAN
>>> > works in order to know to debug it.
>>> >
>>> > For instance;
>>> >
>>> > Lets look at this event :
>>> >
>>> > kasan: CONFIG_KASAN_INLINE enabled
>>> > kasan: GPF could be caused by NULL-ptr deref or user memory access
>>> >  general protection fault: 0000 [#1] SMP KASAN PTI
>>> >
>>> > CPU: 0 PID: 2823 Comm: test2 Not tainted 4.14.35.jpd-ksan.01.-syzkaller #22
>>> >  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
>>> >  task: ffff88805ac89780 task.stack: ffff888054920000
>>> > RIP: 0010:vhost_vsock_dev_release+0x10f/0x450 [vhost_vsock]
>>> > RSP: 0018:ffff888054927be8 EFLAGS: 00010206
>>> > RAX: dffffc0000000000 RBX: 727574616e676973 RCX: 1ffff1100a924f76
>>> > RDX: 0e4eae8c2dcced2e RSI: ffff88805a4a0500 RDI: ffff88807e5e8bb8
>>> > RBP: ffff888054927c38 R08: 0000000000000000 R09: 0000000000000000
>>> > R10: ffffed100a924f3d R11: ffff8880549279ef R12: ffff88807e5e0000
>>> > R13: 00686769685f7265 R14: ffff88807e5e8bc0 R15: ffffffffc04e2a30
>>> > FS:  0000000000000000(0000) GS:ffff88805e400000(0000) knlGS:0000000000000000
>>> > CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>>> > CR2: 00007fe5af16c6c8 CR3: 0000000003a0e000 CR4: 00000000000006f0
>>> > Call Trace:
>>> >  ? ima_file_free+0xb6/0x316
>>> >  ? vhost_vsock_dev_open+0x2d0/0x2d0 [vhost_vsock]
>>> > __fput+0x25d/0x775
>>> >   ____fput+0x1a/0x1d
>>> >  task_work_run+0x12e/0x18f
>>> >  do_exit+0x6ee/0x2a5e
>>> >
>>> > Issue number 1 :
>>> >
>>> > The static trace shows vhost_vsock_dev_open() ;   but in reality , we are in a system EXIT call closing open file descriptors because the RIP is:
>>> >
>>> > RIP: 0010:vhost_vsock_dev_release+0x10f
>>> >
>>> > Ok ;  So the stack is dirty with old information, but using GDB, I set a breakpoint at ksan die exception handler that generates the kernel trace message
>>> > that include vhost_vsock_dev_open() :
>>> >
>>> >
>>> > #0  kasan_die_handler (self=0xffffffff83aa8420 <kasan_die_notifier>, val=0x9, data=0xffff888054927a60) at arch/x86/mm/kasan_init_64.c:245
>>> > #1  0xffffffff8120363e in notifier_call_chain (nl=<optimized out>, val=<optimized out>, v=<optimized out>, nr_to_call=0xfffffffb,
>>> >     nr_calls=0x0 <irq_stack_union>) at kernel/notifier.c:93
>>> > #2  0xffffffff81203d2b in __atomic_notifier_call_chain (nr_calls=<optimized out>, nr_to_call=<optimized out>, v=<optimized out>,
>>> >     val=<optimized out>, nh=<optimized out>) at kernel/notifier.c:183
>>> > #3  atomic_notifier_call_chain (v=<optimized out>, val=<optimized out>, nh=<optimized out>) at kernel/notifier.c:193
>>> > #4  notify_die (val=<optimized out>, str=<optimized out>, regs=<optimized out>, err=0x0, trap=0xd, sig=0xb) at kernel/notifier.c:549
>>> > #5  0xffffffff8108997f in do_general_protection (regs=0xffff888054927b38, error_code=0x0) at arch/x86/kernel/traps.c:558
>>> > #6  0xffffffff82e037bc in general_protection () at arch/x86/entry/entry_64.S:1275
>>> > #7  0xffffffffc04e2a30 in vhost_vsock_dev_open (inode=<optimized out>, file=0x0 <irq_stack_union>) at drivers/vhost/vsock.c:526
>>> >
>>> > What am I suppose to believe ?  Are we calling vsock_open()  from the exit  or  vsock_dev_release()   ?
>>> >
>>> >
>>> > What really gets confusing is what the dis-assembling shows around the gdb exception "
>>> >
>>> >   #7  0xffffffffc04e2a30 in vhost_vsock_dev_open (inode=<optimized out>, file=0x0 <irq_stack_union>) at drivers/vhost/vsock.c:526
>>> >
>>> >
>>> > Lets look at   failing instructions around  at vsock_open()  0xffffffffc04e2a30 :
>>> >
>>> >    0xffffffffc04e2a19 <vhost_vsock_dev_open+697>:    callq  0xffffffff816a94c0 <__asan_report_store8_noabort>
>>> >    0xffffffffc04e2a1e <vhost_vsock_dev_open+702>:    jmpq   0xffffffffc04e2848 <vhost_vsock_dev_open+232>
>>> >    0xffffffffc04e2a23 <vhost_vsock_dev_open+707>:    mov    %r12,%rdi
>>> >    0xffffffffc04e2a26 <vhost_vsock_dev_open+710>:    callq  0xffffffff816a94c0 <__asan_report_store8_noabort>
>>> >    0xffffffffc04e2a2b <vhost_vsock_dev_open+715>:    jmpq   0xffffffffc04e286f <vhost_vsock_dev_open+271>
>>> >   0xffffffffc04e2a30 <vhost_vsock_dev_release>:    nopl   0x0(%rax,%rax,1)           <<<<<<<<<<  FAILING  ADDRESS
>>> >
>>> >   How can I be getting a fault on a 5 byte NOP instruction : nopl   0x0(%rax,%rax,1)
>>> >
>>> >   ax is 0xdffffc0000000000;  so it should be a   move register ax to ax.
>>> >
>>> >  I have no idea what the inserted functions :  asan_report_store8_noabort()  are;  They don't appear in the kernel source that I can find.
>>> >
>>> > Lets look at  the RIP from ksan die() :
>>> >
>>> >
>>> > 353    void die(const char *str, struct pt_regs *regs, long err)
>>> > 354    {
>>> > 355        unsigned long flags = oops_begin();
>>> > 356        int sig = SIGSEGV;
>>> > 357
>>> > 358        if (__die(str, regs, err))
>>> > (gdb) p *regs
>>> > $1 = {
>>> >   r15 = 0xffffffffc04e2a30,
>>> >   r14 = 0xffff888053a38bc0,
>>> >   r13 = 0x483a750000002825,
>>> >   r12 = 0xffff888053a30000,
>>> >   bp = 0xffff888056347c38,
>>> >   bx = 0x415c415d5b48c483,
>>> >   r11 = 0xffff8880563479ef,
>>> >   r10 = 0xffffed100ac68f3d,
>>> >   r9 = 0x0,
>>> >   r8 = 0x0,
>>> >   ax = 0xdffffc0000000000,
>>> >   cx = 0x1ffff1100ac68f76,
>>> >   dx = 0x82b882bab691890,
>>> >   si = 0xffff88807eef5b40,
>>> >   di = 0xffff888053a38bb8,
>>> >   orig_ax = 0xffffffffffffffff,
>>> >   ip = 0xffffffffc04e2b3f,
>>> >   cs = 0x10,
>>> >   flags = 0x10206,
>>> >   sp = 0xffff888056347be8,
>>> >   ss = 0x18
>>> > }
>>> >
>>> > the regs.ip  ==   0xffffffffc04e2b3f
>>> >    0xffffffffc04e2b3f <vhost_vsock_dev_release+271>:    cmpb   $0x0,(%rdx,%rax,1)
>>> >    0xffffffffc04e2b43 <vhost_vsock_dev_release+275>:    jne    0xffffffffc04e2e50 <vhost_vsock_dev_release+1056>
>>> > (gdb)
>>> >
>>> >
>>> >
>>> > (gdb) x/2i 0xffffffffc04e2b3f
>>> >    0xffffffffc04e2b3f <vhost_vsock_dev_release+271>:    cmpb   $0x0,(%rdx,%rax,1)
>>> >    0xffffffffc04e2b43 <vhost_vsock_dev_release+275>:    jne    0xffffffffc04e2e50 <vhost_vsock_dev_release+1056>
>>> >
>>> >
>>> > I can believe getting a fault doing a cmpb   (dx,ax )
>>> >
>>> > Is this a complex instruction comparing *dx to *ax ?  the the register contents ?
>>> >
>>> >
>>> > ax =
>>> >
>>> > (gdb) x/2b 0xdffffc0000000000
>>> > 0xdffffc0000000000:    Cannot access memory at address 0xdffffc0000000000
>>> >
>>> > dx =
>>> >
>>> > (gdb) x/2b 0x82b882bab691890
>>> > 0x82b882bab691890:    Cannot access memory at address 0x82b882bab691890
>>> >
>>> >
>>> > Debugging suggestions welcome !
>>> >
>>> > JD
>>> >
>>> > ===
>>> >
>>> >
>>> > Attached is the test case.
>>> your info,
>>>
>>> Hi JohnD,
>>>
>>> Are you debugging some syzbot-reported bug? Which one? It's useful to
>>> keep this in the same email thread as the report in somebody else will
>>> look at it later (or maybe debugging the same at the same time).
>>> syzkaller-bugs@ is generally not read by anyone and is only CCed in
>>> syzbot reports. We should direct people to syzkaller@ mailing list
>>> everywhere.
>>>
>>> Looking at the info, it seems that the crash happens in
>>> vhost_vsock_dev_release and gdb improperly unwinds kernel (maybe you
>>> need a latest gdb or something).
>>> __fput generally calls callbacks that close/release/destroy something.
>>> And it seems that vhost_vsock_dev_release perfectly matches this
>>> definition.
>>> Also "cmpb   $0x0,(%rdx,%rax,1)" looks like KASAN shadow check and is
>>> the instruction where NULL derefs usually caught.
>>> This instruction does "if (*(byte*)(rax + rdx) == 0)". Perhaps you
>>> better turn off CONFIG_KASAN to make debugging simpler. Since it's not
>>> KASAN-detected crash, there is no point enabling KASAN.
>>
>>
>>
>>  Thank you for the feed back !
>>
>> I am new to this team and project so I am not quite sure on the protocol !  Yes - I can see the error is in the exit path via _fput ; I just wanted to post my confusion on the misleading  stack traces between dump_stack() , panic () ;  and gdb ;
>>
>>
>> I will try turning KASAN off ;
>>
>> These are in-house reported defects ; I haven't found a corresponding syzkaller defect .
>
>
>
> When I turn CONFIG_KASAN off  - the tests runs


Humm... perhaps KASAN shuffles things a bit and masks the bug somehow...

KASAN insert validity check before each memory access.
This check is done with:

   0xffffffffc04e2b3f <vhost_vsock_dev_release+271>:    cmpb
$0x0,(%rdx,%rax,1)

When kernel accesses address ADDR, KASAN checks (0xdffffc0000000000 +
ADDR / 8) address.
This transformation is reversible. If you had:

  ax = 0xdffffc0000000000,
  dx = 0x82b882bab691890,

this means that kernel code tried to access 0x82b882bab691890 * 8 =
0x415c415d5b48c480 address, which does not look like a valid address
at all. It seems that the kernel code somehow dereferences random
numbers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BabVUNrK61yFiLwOzti4bXv6d6PGJiMTm2ZdRKYXcXXDg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
