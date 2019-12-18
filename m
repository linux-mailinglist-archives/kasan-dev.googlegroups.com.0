Return-Path: <kasan-dev+bncBCMIZB7QWENRBIHJ5DXQKGQEV3VPEOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E64B124939
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 15:16:01 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id 143sf1390646qkg.12
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 06:16:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576678560; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cc5mFoQacOa0lyKRqCN3vanUHja8HYd/7kgJIlUxbpyx45np9fq0Md+bQBlLR41nxo
         YJEbsgJNIkqyiEpw1PbZ+B/3kJNzaWgPmCE09nAEutC1mZ2sCvaLjAKUTo00Baxfjtrr
         FyP8dijufQl2UoOtS9xD6TcUCp0UM55fKthlRafP0IgiDDmwsFxX5anUEkQPG1YGLWfx
         WbaQfVsZ6Lp3s5XOFTmceEoqSBoOq9QBIZ1nueWt7PhFMQ2JT76R0vQxIaDcjveDx0zz
         IwRrRl0KVpyuDMr/JF6rlda9fJ21CAUV5hY6XDfJl26I+GUm+VAw20Enj5cG1cQuPaj3
         UYxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jcPG/5lsf0K73gCYcReljd2w63ihrTf3rkWjACq8A0E=;
        b=PX3+wJui4U+zPE/7EmNH237Ckenw0rBs6WQeUG+1Kprh/ygMSFGfH+xmgQuxa5A+cC
         bviAENFrGD4l/h1sEJuv3g0Lv4qNqP9A5ydxjeCiO5OFR1TIPmWXxXwzoeVCouNWjPAH
         Bf02KLlMorqg4pETwdSk4siz73CGjDw3Q2KJjsij1R3d3doTblBfVBwzCSFJOhlf4fDV
         Jwe59b1lqgUHpeYGAw8BxehA1MqvBHeBClGakkErXWJ1UJyXzCsbUIiRfhm84sq82x3q
         K9jY5cnoAYVpFHAI1/F4OS9VKgGAgFUE/Xj6qV95c19qjbh1hGKSrhWeRhBGjii5ht8V
         68NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bPZjeT/S";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jcPG/5lsf0K73gCYcReljd2w63ihrTf3rkWjACq8A0E=;
        b=NcNeXBIGBdT3e/uQBqpB9ameIGqcSOXomVcyDk2W2TyBKz7P5bSMcHvLJqxhahzy43
         hCJZk0XYfs1TRW39HEMW2EH6dVCy/pitiTuvZhMCnKEOLH08DxGedVr+q32anZEHVbYu
         XVAMZhl9TKKAwBZjryKcbeWjWgXFQrDKeC36uu0xGo6252fx6QjZEuSh4cIRNkrYKJzI
         IQPv8ZtPhvvGP7/YvGvPvHkSeLD8191GLOWtGES2xU1ox/gi66eOoin+eVyYOpAIe3Ub
         0UoVtgDw7qmqpBT4GKrkYO4NRWPndUSLwg10nBjn1BVoKp05RgyZiP0ZMb9JMS59vA+Q
         hwsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jcPG/5lsf0K73gCYcReljd2w63ihrTf3rkWjACq8A0E=;
        b=bZaObqEyr9hUd7IKFdCsmy9Ux+hp/Gl0cuFkazV39Mv85DDSjeWcz+gz9EzEim+zdp
         CcNEFa9v2JPUSa/0I4Sop5evr8KGe7eFTnVB6IQM7M1kgA+wlVAETTVm6WjPtlpTNB8f
         sY0wUvCR9q5Mfu2SwETP9o2yB6HdnJ/aE8yoYLQ05VDXz+IlxjeEzrAmLWtyxoL1T05g
         1JCnaItGwJd34NlWoOzH8+ehYKfOGq+ayQ4f2F0SrOsKl7j/K2GprHVySiZPKBH5VxKa
         McLqfHkX35l1DRi2KA+y293CtxBArbDWw8tcCxEhAnWcj6sT32StSet/xLhwwsoNCKkE
         Y1FQ==
X-Gm-Message-State: APjAAAUfHLioMqvEjOUMksOrRuF1sNq9VwtOdvnqCbIQg0QT8JUvpwMt
	M6y2PBYME+x26Xs8WxzviUo=
X-Google-Smtp-Source: APXvYqyKXqbAc1GY4W2W/FsWcx0teqAGSSJPSP9081zEeqZijcTw2TQGdbB+TEP9RL20tTcjw05X3Q==
X-Received: by 2002:ac8:5457:: with SMTP id d23mr2230873qtq.93.1576678560160;
        Wed, 18 Dec 2019 06:16:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c17:: with SMTP id 23ls847336qkm.14.gmail; Wed, 18 Dec
 2019 06:15:59 -0800 (PST)
X-Received: by 2002:a37:bc04:: with SMTP id m4mr2777837qkf.224.1576678559815;
        Wed, 18 Dec 2019 06:15:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576678559; cv=none;
        d=google.com; s=arc-20160816;
        b=P9NFlYg1kkiK6XcuHXnnchzSF/rRoJiEw2QxLm0hisI/+DvwczS6C/R7ahZbv7ZYkR
         CZW2n28k+PH9M9cq0jyP0tvCFwKdqWW2sjlY9DNjJrTtegylLvC7pxMhw+HOe/KX2kdO
         dnZrCpS9RKB8ytZNcb14YfvVZol7J2nlfgRDAGEBM6cORXUBADG1F32/a/Ofl3P96hBX
         A5+HI1rLp73zOgTtmlXQUOq7d/UypLOkOpV91eC2LTeJ096fLvzI570ZMy3wHbqqdErE
         p2pcEOkCwNVnWJ/tQ/0O2qxEpRM3P+3TF5Y5mb++19Qybk3uIV0XUyz9jiZYAl1fjwXo
         CzeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8t0dYHbivI7jIsrUuwVR27YLo8SMDodvslI109VrSWw=;
        b=OAFuztL2a7XQeOTLBttitgC9CuEMkMFLWAE01+uA5OipmiLsVANfKH6cPvK01uK5g2
         KE06sxD/8l3RxoVsDiQuzmJ9PrsbVlysGdfiH5PoRDzT8hnSHA4zgG3UvgplreOWUBk5
         Fm+pnWkOm0l1MGrZ2aGPPvJKM34uSgVgLADUX2ujnbCCoMWjMPLiNRLJQeYovrMXvBdr
         Y/AlxJBFoj5ZXKHj4jVleKIbznuBoCVBd6QlrFdVGsEDWg7mY+XcDTnsWHeecdQzHaim
         R3r1KopjzZqYXgQ3hJ0fkEYw72uyNy9LqPVVoZoCAfdLf9NBPtah3NMsh1f4AVHdxh6X
         zfVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="bPZjeT/S";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id 134si83439qkd.2.2019.12.18.06.15.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 06:15:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id t9so772692qvh.13
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 06:15:59 -0800 (PST)
X-Received: by 2002:ad4:4810:: with SMTP id g16mr2402347qvy.22.1576678558999;
 Wed, 18 Dec 2019 06:15:58 -0800 (PST)
MIME-Version: 1.0
References: <00000000000021cc1a0599f66f55@google.com> <CACT4Y+Y0FXiGgsMt=k9d73bkQvW-NqyUoS=w6KXQ=28_ROz1YA@mail.gmail.com>
 <87o8w5u47c.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87o8w5u47c.fsf@dja-thinkpad.axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Dec 2019 15:15:47 +0100
Message-ID: <CACT4Y+ZaT37yoxU7iXUF73iszxNSW_8QVys7NxRnXZZ-pa9Lgg@mail.gmail.com>
Subject: Re: BUG: soft lockup in sock_setsockopt
To: Daniel Axtens <dja@axtens.net>, "Paul E. McKenney" <paulmck@linux.ibm.com>
Cc: syzbot <syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	LKML <linux-kernel@vger.kernel.org>, namit@vmware.com, 
	Peter Zijlstra <peterz@infradead.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="bPZjeT/S";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Wed, Dec 18, 2019 at 2:57 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Dmitry Vyukov <dvyukov@google.com> writes:
>
> > On Wed, Dec 18, 2019 at 9:43 AM syzbot
> > <syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com> wrote:
> >>
> >> Hello,
> >>
> >> syzbot found the following crash on:
> >>
> >> HEAD commit:    9065e063 Merge branch 'x86-urgent-for-linus' of git://git...
> >> git tree:       upstream
> >> console output: https://syzkaller.appspot.com/x/log.txt?x=17185e99e00000
> >> kernel config:  https://syzkaller.appspot.com/x/.config?x=dcf10bf83926432a
> >> dashboard link: https://syzkaller.appspot.com/bug?extid=e7e13ce5d4ca294ca90a
> >> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> >>
> >> Unfortunately, I don't have any reproducer for this crash yet.
> >>
> >> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> >> Reported-by: syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com
> >
> > +Daniel, kasan-dev,
> >
> > This looks like another stall caused by KASAN+vmalloc. Now it has
> > reached upstream and this instance uses Apparmor rather than Smack.
>
> weird. It looks like the hang happens while waiting for a tlb range
> flush - in particular CPU#0 hangs while waiting for CPU#1 to finish. I
> don't know what was running on CPU#1 122s ago, but it's currently
> SRCU. I see the SRCU code does smp_lock_irq_... but I don't know how
> interrupts would be disabled for that long. (Unless the IPI just gets
> dropped on the floor if it the CPU currently has IRQs off, but surely
> we'd have picked that up somewhere else first?)
>
> The whole code is deep magic to me. Am I accidentally violating any
> restrictions on what can be called when?

Maybe bpf_int_jit_compile stack is in srcu reader critical section and
try_check_zero waits forever for it to leave, while
bpf_int_jit_compile tries to send IPI which does not reach
try_check_zero CPU?

Should this:
    if (--trycount + !srcu_get_delay(ssp) <= 0)
      return false;
in try_check_zero break eventually? What is even the type of that
expression? That's playing with fire in C :)

Can if jump across 0 because  both trycount and srcu_get_delay change
at the same iteration? And then if it's unsigned type in the end, it
does not become -1, but instead 0xffffffff which is not <=0?....


> >> watchdog: BUG: soft lockup - CPU#0 stuck for 122s! [syz-executor.3:9634]
> >> Modules linked in:
> >> irq event stamp: 35786
> >> hardirqs last  enabled at (35785): [<ffffffff81006983>]
> >> trace_hardirqs_on_thunk+0x1a/0x1c arch/x86/entry/thunk_64.S:41
> >> hardirqs last disabled at (35786): [<ffffffff8100699f>]
> >> trace_hardirqs_off_thunk+0x1a/0x1c arch/x86/entry/thunk_64.S:42
> >> softirqs last  enabled at (5788): [<ffffffff880006cd>]
> >> __do_softirq+0x6cd/0x98c kernel/softirq.c:319
> >> softirqs last disabled at (5707): [<ffffffff81478ceb>] invoke_softirq
> >> kernel/softirq.c:373 [inline]
> >> softirqs last disabled at (5707): [<ffffffff81478ceb>] irq_exit+0x19b/0x1e0
> >> kernel/softirq.c:413
> >> CPU: 0 PID: 9634 Comm: syz-executor.3 Not tainted 5.5.0-rc2-syzkaller #0
> >> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> >> Google 01/01/2011
> >> RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
> >> RIP: 0010:csd_lock_wait kernel/smp.c:109 [inline]
> >> RIP: 0010:smp_call_function_single+0x188/0x480 kernel/smp.c:311
> >> Code: 00 e8 6c 23 0b 00 48 8b 4c 24 08 48 8b 54 24 10 48 8d 74 24 40 8b 7c
> >> 24 1c e8 c4 f9 ff ff 41 89 c5 eb 07 e8 4a 23 0b 00 f3 90 <44> 8b 64 24 58
> >> 31 ff 41 83 e4 01 44 89 e6 e8 b5 24 0b 00 45 85 e4
> >> RSP: 0018:ffffc90004d3f480 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
> >> RAX: 0000000000040000 RBX: 1ffff920009a7e94 RCX: ffffc90010442000
> >> RDX: 0000000000040000 RSI: ffffffff816a0856 RDI: 0000000000000005
> >> RBP: ffffc90004d3f550 R08: ffff88809e5161c0 R09: ffffed1015d27059
> >> R10: ffffed1015d27058 R11: ffff8880ae9382c7 R12: 0000000000000001
> >> R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000000
> >> FS:  00007f19610d6700(0000) GS:ffff8880ae800000(0000) knlGS:0000000000000000
> >> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> >> CR2: 00007fe53bcc09c0 CR3: 000000008ffc6000 CR4: 00000000001426f0
> >> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> >> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> >> Call Trace:
> >>   smp_call_function_many+0x7ba/0x940 kernel/smp.c:451
> >>   smp_call_function+0x42/0x90 kernel/smp.c:509
> >>   on_each_cpu+0x2f/0x1f0 kernel/smp.c:616
> >>   flush_tlb_kernel_range+0x19b/0x250 arch/x86/mm/tlb.c:839
> >>   kasan_release_vmalloc+0xb4/0xc0 mm/kasan/common.c:976
> >>   __purge_vmap_area_lazy+0xca5/0x1ef0 mm/vmalloc.c:1313
> >>   _vm_unmap_aliases mm/vmalloc.c:1730 [inline]
> >>   _vm_unmap_aliases+0x396/0x480 mm/vmalloc.c:1695
> >>   vm_unmap_aliases+0x19/0x20 mm/vmalloc.c:1753
> >>   change_page_attr_set_clr+0x22e/0x840 arch/x86/mm/pageattr.c:1709
> >>   change_page_attr_clear arch/x86/mm/pageattr.c:1766 [inline]
> >>   set_memory_ro+0x7b/0xa0 arch/x86/mm/pageattr.c:1899
> >>   bpf_jit_binary_lock_ro include/linux/filter.h:790 [inline]
> >>   bpf_int_jit_compile+0xebd/0x12ce arch/x86/net/bpf_jit_comp.c:1659
> >>   bpf_prog_select_runtime+0x4b9/0x850 kernel/bpf/core.c:1801
> >>   bpf_migrate_filter net/core/filter.c:1275 [inline]
> >>   bpf_prepare_filter net/core/filter.c:1323 [inline]
> >>   bpf_prepare_filter+0x977/0xd60 net/core/filter.c:1289
> >>   __get_filter+0x212/0x2c0 net/core/filter.c:1492
> >>   sk_attach_filter+0x1e/0xa0 net/core/filter.c:1507
> >>   sock_setsockopt+0x1f44/0x22b0 net/core/sock.c:999
> >>   __sys_setsockopt+0x440/0x4c0 net/socket.c:2113
> >>   __do_sys_setsockopt net/socket.c:2133 [inline]
> >>   __se_sys_setsockopt net/socket.c:2130 [inline]
> >>   __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
> >>   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
> >>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >> RIP: 0033:0x45a919
> >> Code: ad b6 fb ff c3 66 2e 0f 1f 84 00 00 00 00 00 66 90 48 89 f8 48 89 f7
> >> 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff
> >> ff 0f 83 7b b6 fb ff c3 66 2e 0f 1f 84 00 00 00 00
> >> RSP: 002b:00007f19610d5c78 EFLAGS: 00000246 ORIG_RAX: 0000000000000036
> >> RAX: ffffffffffffffda RBX: 0000000000000005 RCX: 000000000045a919
> >> RDX: 000000000000001a RSI: 0000000000000001 RDI: 000000000000000c
> >> RBP: 000000000075c070 R08: 0000000000000010 R09: 0000000000000000
> >> R10: 0000000020000480 R11: 0000000000000246 R12: 00007f19610d66d4
> >> R13: 00000000004c9e34 R14: 00000000004e1f78 R15: 00000000ffffffff
> >> Sending NMI from CPU 0 to CPUs 1:
> >> NMI backtrace for cpu 1
> >> CPU: 1 PID: 3231 Comm: kworker/1:3 Not tainted 5.5.0-rc2-syzkaller #0
> >> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> >> Google 01/01/2011
> >> Workqueue: rcu_gp process_srcu
> >> RIP: 0010:delay_tsc+0x33/0xc0 arch/x86/lib/delay.c:68
> >> Code: bf 01 00 00 00 41 55 41 54 53 e8 58 95 8b f9 e8 63 b4 cd fb 41 89 c5
> >> 0f 01 f9 66 90 48 c1 e2 20 48 09 c2 49 89 d4 eb 16 f3 90 <bf> 01 00 00 00
> >> e8 33 95 8b f9 e8 3e b4 cd fb 44 39 e8 75 36 0f 01
> >> RSP: 0018:ffffc9000898fbb0 EFLAGS: 00000286
> >> RAX: 0000000080000000 RBX: 000000c937e7f04b RCX: 0000000000000000
> >> RDX: 0000000000000001 RSI: ffffffff8392f013 RDI: 0000000000000001
> >> RBP: ffffc9000898fbd0 R08: ffff88809e1e2200 R09: 0000000000000040
> >> R10: 0000000000000040 R11: ffffffff89a4f487 R12: 000000c937e7c4ab
> >> R13: 0000000000000001 R14: 0000000000002ced R15: 0000000000000047
> >> FS:  0000000000000000(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
> >> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> >> CR2: 00007fbb9d9c6000 CR3: 0000000094911000 CR4: 00000000001426e0
> >> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> >> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> >> Call Trace:
> >>   __delay arch/x86/lib/delay.c:161 [inline]
> >>   __const_udelay+0x59/0x80 arch/x86/lib/delay.c:175
> >>   try_check_zero+0x201/0x330 kernel/rcu/srcutree.c:705
> >>   srcu_advance_state kernel/rcu/srcutree.c:1142 [inline]
> >>   process_srcu+0x329/0xe10 kernel/rcu/srcutree.c:1237
> >>   process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
> >>   worker_thread+0x98/0xe40 kernel/workqueue.c:2410
> >>   kthread+0x361/0x430 kernel/kthread.c:255
> >>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> >>
> >>
> >> ---
> >> This bug is generated by a bot. It may contain errors.
> >> See https://goo.gl/tpsmEJ for more information about syzbot.
> >> syzbot engineers can be reached at syzkaller@googlegroups.com.
> >>
> >> syzbot will keep track of this bug report. See:
> >> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> >>
> >> --
> >> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> >> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> >> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000021cc1a0599f66f55%40google.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o8w5u47c.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZaT37yoxU7iXUF73iszxNSW_8QVys7NxRnXZZ-pa9Lgg%40mail.gmail.com.
