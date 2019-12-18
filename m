Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPPA5DXQKGQEOOE6WJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11BEF1248CD
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 14:57:19 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id u9sf1424478qte.5
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 05:57:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576677437; cv=pass;
        d=google.com; s=arc-20160816;
        b=XufhjEELgTZkFAjqlGSJ81rHYFtvG430RcLIJPAWp7N8IhMD/Ew41ARhzgTC+uAd4L
         9Ebi2/L9T+sXh/5zKmUVLvKj6k/MAZsdho3ssmLsGrSIxnZMCaAfYmgkyCJkrWnyxQvp
         QFQF8oXxufHS/y1LPgwPTZK9aCySumePU3IVSrq93c8y8qXIsvcipeX9RvKsOiiE/NRJ
         Cqn0G3JYWJWrXU+uiCbFy1JcA/c3+xDQknsnkCBo6IKZ7MIxyfec4xftByW5QKufbRXy
         3oBDa/baW5M8PKcEvE6mC4/O8N+kO/8DyUTEeetxuRM9wt3kGS7al9XnslTEfRmSxrPM
         TTjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Rwgp+XoMpO4Xk+K5uO+3lgkI2O4e6Fe/F3oHxLrnVTE=;
        b=x4UvYILjxKA85dEW1Qo/eJm3Wvwd0OQDBba99bC6ylP8BQ3G0IpwCvt1YpzDRNNPPe
         DRNh+Qo6Y7qcBpM/gsG1x4OZ10xObuW1A2d2MlQ4dQmn7vOP3+7645/0/cFZZORjRXIJ
         mo/8JX8nI0Darb/sBRqgeYk9FbtVmqn3bAkMex4cbX0n8CUUDcEXCgEsGxPnxeHfoBx3
         BsBM6og41PMKSKtA0q0hGQAZKmQmzFU1wErEP72WasKzv2hftLHVrlzKqDSvlJH4A0XI
         tkEkUZn0cZUItH2KNVi02rC9Sa1FPEsBgadv+aAsrOjgaq0ftqHpr79LLMOHEwhaHG69
         dv1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fpAA6eat;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rwgp+XoMpO4Xk+K5uO+3lgkI2O4e6Fe/F3oHxLrnVTE=;
        b=g3KZqrnXUKJb14hgs6wspHLCbkIF9BOT2mnFuRue4AaMR98IuE/YxIjU+L2yFzVkNQ
         iIewo9ZzR98aIzh64sAm82DK0vWKZBGO2izsb+ptgOJGdxkY21lLaIq5ckrwTyATH0fE
         PB38wZEzW9/NVskxylgXsoZteo+42THU/C76p/McHjjIdSz8AvqC8c8RjJsZE2Z37dJQ
         Wvcap+OW6KkrvFKxJSIwzU35FxXP7pcno713QWk8sEIk+AqR43wF4utF7Ina2gL6gsDv
         iiZ94mrcqU32B+ofuoGc/BbIq7y6tVuTJwLExJlC50Z3ZhExLaJbKNYGlCXS+IEfBDu0
         cwWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rwgp+XoMpO4Xk+K5uO+3lgkI2O4e6Fe/F3oHxLrnVTE=;
        b=e8fiIRpKoHBil/ajRqzr296jynUls8TeL1I/HMrJiW+t/3aBqIX1qFbr0RKSykCSGN
         XUENYv+ilFh4K/dIfKb8k+wDuzdKC01UoZ+MzOO778vQg8E7efl7eVm2w83MNTP3F2z/
         sHgh5p/OkutcsAaYfmZlIlTBITEnQR0ySAys3WPRa6uG34eSLsvyIUYB1rCgJdpgIDjG
         HjonjXgmtIqSTq/HcFkAvMNYhEBtZ3/wvZTQ126SEqxtkHxv8oBfk22b6RtNk+N0tnoe
         ijuKulWpsiH1bMiSVVy2AokZnABEI/L9M7dvvaZseqkU8q74BMMKa3Ui87Mdjks8Ud/g
         JDlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxIMsRNm7hE/yfAp4MxxjHPd4UhdC5DbIHwEq8ilvXaiI+36nT
	a/C+yHK3U1sbZbnNmaBKH3k=
X-Google-Smtp-Source: APXvYqyrMRMJdu1G/8hO5WuqbDLedWbswmsDkNZPqhGN/0pS+Hi2e93uQBWukxcYwYUJrkmhwQVW1Q==
X-Received: by 2002:ad4:5487:: with SMTP id q7mr2420893qvy.19.1576677437591;
        Wed, 18 Dec 2019 05:57:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d49d:: with SMTP id u29ls359577qvh.5.gmail; Wed, 18 Dec
 2019 05:57:17 -0800 (PST)
X-Received: by 2002:a0c:964f:: with SMTP id 15mr2426940qvy.64.1576677437120;
        Wed, 18 Dec 2019 05:57:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576677437; cv=none;
        d=google.com; s=arc-20160816;
        b=SG9BDFKWgRIRO9eJBUtoiuONZhyXx9D866qXlGYBmmeVeKsj9AOyqmBvXCpYk7o49A
         Sk1ZFhMWb5t6evZntUNdoGdQpxMIPiknZGkgJmq6zoJ6HMG+kDdglyG2mTfIYVJliJ0R
         zFazy1gHt94M3vLPF1SwTLNnSpgv7XsevhCjF8crceoKZisngH/yPome7lvLn2I9dMKt
         0Wbc47xh5wopWqJEANx35QtSEiZKAs7KVdyNpz6E0AUkp7K5LTdFKYtBzy5NcwbQDmeb
         S/t5ko46JSoMUyZBRGwmMiLa25Um3w8u/ejdVj8eDORTI64iksMAzij/9TyO++4dqE2g
         D9XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=VxC231H+PdMtVaz0/s83RFTA+hXKLHmd3SS9wuvq3KA=;
        b=PE0DI6YQE0rEhQutEs8OxPHBWOnPjvqXnSS6ZXkCFWOP8aRuCLg2fjJEU8H7nLtjyn
         BoaYyfIfoaTmVvnhVBq36fPUTbXVxByofwCmnY7JNOqrQqd2UySPYZf+Q/zgs1CkdxI7
         Y3x3bo0ZhNvuJQDAowGXXoDxs1M45ayjcZ3IIZ4+yzHADYRArcRyyJo85m7knv/AkDKt
         ZgGFpsExeU5SgF3+P3RkSqv7s8eSB8fvxrmSG8uTJJcG7KVcWk28voMfP1Iv56zRT6YQ
         ZBO9ps05sI8E9mGluDOWU8CXXM1UdHcEATOPWUJ888/7HuSY/hxb3qC8V8jSbDHgbMjC
         aevg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fpAA6eat;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id d135si91399qke.7.2019.12.18.05.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 05:57:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id p9so1008277plk.9
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 05:57:17 -0800 (PST)
X-Received: by 2002:a17:902:aa8f:: with SMTP id d15mr2721475plr.276.1576677435966;
        Wed, 18 Dec 2019 05:57:15 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-a084-b324-40b3-453d.static.ipv6.internode.on.net. [2001:44b8:1113:6700:a084:b324:40b3:453d])
        by smtp.gmail.com with ESMTPSA id 16sm3563085pfh.182.2019.12.18.05.57.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Dec 2019 05:57:15 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>, syzbot <syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Josh Poimboeuf <jpoimboe@redhat.com>, LKML <linux-kernel@vger.kernel.org>, namit@vmware.com, Peter Zijlstra <peterz@infradead.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Thomas Gleixner <tglx@linutronix.de>
Subject: Re: BUG: soft lockup in sock_setsockopt
In-Reply-To: <CACT4Y+Y0FXiGgsMt=k9d73bkQvW-NqyUoS=w6KXQ=28_ROz1YA@mail.gmail.com>
References: <00000000000021cc1a0599f66f55@google.com> <CACT4Y+Y0FXiGgsMt=k9d73bkQvW-NqyUoS=w6KXQ=28_ROz1YA@mail.gmail.com>
Date: Thu, 19 Dec 2019 00:57:11 +1100
Message-ID: <87o8w5u47c.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fpAA6eat;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Dmitry Vyukov <dvyukov@google.com> writes:

> On Wed, Dec 18, 2019 at 9:43 AM syzbot
> <syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com> wrote:
>>
>> Hello,
>>
>> syzbot found the following crash on:
>>
>> HEAD commit:    9065e063 Merge branch 'x86-urgent-for-linus' of git://git...
>> git tree:       upstream
>> console output: https://syzkaller.appspot.com/x/log.txt?x=17185e99e00000
>> kernel config:  https://syzkaller.appspot.com/x/.config?x=dcf10bf83926432a
>> dashboard link: https://syzkaller.appspot.com/bug?extid=e7e13ce5d4ca294ca90a
>> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>>
>> Unfortunately, I don't have any reproducer for this crash yet.
>>
>> IMPORTANT: if you fix the bug, please add the following tag to the commit:
>> Reported-by: syzbot+e7e13ce5d4ca294ca90a@syzkaller.appspotmail.com
>
> +Daniel, kasan-dev,
>
> This looks like another stall caused by KASAN+vmalloc. Now it has
> reached upstream and this instance uses Apparmor rather than Smack.

weird. It looks like the hang happens while waiting for a tlb range
flush - in particular CPU#0 hangs while waiting for CPU#1 to finish. I
don't know what was running on CPU#1 122s ago, but it's currently
SRCU. I see the SRCU code does smp_lock_irq_... but I don't know how
interrupts would be disabled for that long. (Unless the IPI just gets
dropped on the floor if it the CPU currently has IRQs off, but surely
we'd have picked that up somewhere else first?)

The whole code is deep magic to me. Am I accidentally violating any
restrictions on what can be called when?

Regards,
Daniel

>
>> watchdog: BUG: soft lockup - CPU#0 stuck for 122s! [syz-executor.3:9634]
>> Modules linked in:
>> irq event stamp: 35786
>> hardirqs last  enabled at (35785): [<ffffffff81006983>]
>> trace_hardirqs_on_thunk+0x1a/0x1c arch/x86/entry/thunk_64.S:41
>> hardirqs last disabled at (35786): [<ffffffff8100699f>]
>> trace_hardirqs_off_thunk+0x1a/0x1c arch/x86/entry/thunk_64.S:42
>> softirqs last  enabled at (5788): [<ffffffff880006cd>]
>> __do_softirq+0x6cd/0x98c kernel/softirq.c:319
>> softirqs last disabled at (5707): [<ffffffff81478ceb>] invoke_softirq
>> kernel/softirq.c:373 [inline]
>> softirqs last disabled at (5707): [<ffffffff81478ceb>] irq_exit+0x19b/0x1e0
>> kernel/softirq.c:413
>> CPU: 0 PID: 9634 Comm: syz-executor.3 Not tainted 5.5.0-rc2-syzkaller #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
>> Google 01/01/2011
>> RIP: 0010:__read_once_size include/linux/compiler.h:199 [inline]
>> RIP: 0010:csd_lock_wait kernel/smp.c:109 [inline]
>> RIP: 0010:smp_call_function_single+0x188/0x480 kernel/smp.c:311
>> Code: 00 e8 6c 23 0b 00 48 8b 4c 24 08 48 8b 54 24 10 48 8d 74 24 40 8b 7c
>> 24 1c e8 c4 f9 ff ff 41 89 c5 eb 07 e8 4a 23 0b 00 f3 90 <44> 8b 64 24 58
>> 31 ff 41 83 e4 01 44 89 e6 e8 b5 24 0b 00 45 85 e4
>> RSP: 0018:ffffc90004d3f480 EFLAGS: 00000246 ORIG_RAX: ffffffffffffff13
>> RAX: 0000000000040000 RBX: 1ffff920009a7e94 RCX: ffffc90010442000
>> RDX: 0000000000040000 RSI: ffffffff816a0856 RDI: 0000000000000005
>> RBP: ffffc90004d3f550 R08: ffff88809e5161c0 R09: ffffed1015d27059
>> R10: ffffed1015d27058 R11: ffff8880ae9382c7 R12: 0000000000000001
>> R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000000
>> FS:  00007f19610d6700(0000) GS:ffff8880ae800000(0000) knlGS:0000000000000000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: 00007fe53bcc09c0 CR3: 000000008ffc6000 CR4: 00000000001426f0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> Call Trace:
>>   smp_call_function_many+0x7ba/0x940 kernel/smp.c:451
>>   smp_call_function+0x42/0x90 kernel/smp.c:509
>>   on_each_cpu+0x2f/0x1f0 kernel/smp.c:616
>>   flush_tlb_kernel_range+0x19b/0x250 arch/x86/mm/tlb.c:839
>>   kasan_release_vmalloc+0xb4/0xc0 mm/kasan/common.c:976
>>   __purge_vmap_area_lazy+0xca5/0x1ef0 mm/vmalloc.c:1313
>>   _vm_unmap_aliases mm/vmalloc.c:1730 [inline]
>>   _vm_unmap_aliases+0x396/0x480 mm/vmalloc.c:1695
>>   vm_unmap_aliases+0x19/0x20 mm/vmalloc.c:1753
>>   change_page_attr_set_clr+0x22e/0x840 arch/x86/mm/pageattr.c:1709
>>   change_page_attr_clear arch/x86/mm/pageattr.c:1766 [inline]
>>   set_memory_ro+0x7b/0xa0 arch/x86/mm/pageattr.c:1899
>>   bpf_jit_binary_lock_ro include/linux/filter.h:790 [inline]
>>   bpf_int_jit_compile+0xebd/0x12ce arch/x86/net/bpf_jit_comp.c:1659
>>   bpf_prog_select_runtime+0x4b9/0x850 kernel/bpf/core.c:1801
>>   bpf_migrate_filter net/core/filter.c:1275 [inline]
>>   bpf_prepare_filter net/core/filter.c:1323 [inline]
>>   bpf_prepare_filter+0x977/0xd60 net/core/filter.c:1289
>>   __get_filter+0x212/0x2c0 net/core/filter.c:1492
>>   sk_attach_filter+0x1e/0xa0 net/core/filter.c:1507
>>   sock_setsockopt+0x1f44/0x22b0 net/core/sock.c:999
>>   __sys_setsockopt+0x440/0x4c0 net/socket.c:2113
>>   __do_sys_setsockopt net/socket.c:2133 [inline]
>>   __se_sys_setsockopt net/socket.c:2130 [inline]
>>   __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
>>   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
>>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
>> RIP: 0033:0x45a919
>> Code: ad b6 fb ff c3 66 2e 0f 1f 84 00 00 00 00 00 66 90 48 89 f8 48 89 f7
>> 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff
>> ff 0f 83 7b b6 fb ff c3 66 2e 0f 1f 84 00 00 00 00
>> RSP: 002b:00007f19610d5c78 EFLAGS: 00000246 ORIG_RAX: 0000000000000036
>> RAX: ffffffffffffffda RBX: 0000000000000005 RCX: 000000000045a919
>> RDX: 000000000000001a RSI: 0000000000000001 RDI: 000000000000000c
>> RBP: 000000000075c070 R08: 0000000000000010 R09: 0000000000000000
>> R10: 0000000020000480 R11: 0000000000000246 R12: 00007f19610d66d4
>> R13: 00000000004c9e34 R14: 00000000004e1f78 R15: 00000000ffffffff
>> Sending NMI from CPU 0 to CPUs 1:
>> NMI backtrace for cpu 1
>> CPU: 1 PID: 3231 Comm: kworker/1:3 Not tainted 5.5.0-rc2-syzkaller #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
>> Google 01/01/2011
>> Workqueue: rcu_gp process_srcu
>> RIP: 0010:delay_tsc+0x33/0xc0 arch/x86/lib/delay.c:68
>> Code: bf 01 00 00 00 41 55 41 54 53 e8 58 95 8b f9 e8 63 b4 cd fb 41 89 c5
>> 0f 01 f9 66 90 48 c1 e2 20 48 09 c2 49 89 d4 eb 16 f3 90 <bf> 01 00 00 00
>> e8 33 95 8b f9 e8 3e b4 cd fb 44 39 e8 75 36 0f 01
>> RSP: 0018:ffffc9000898fbb0 EFLAGS: 00000286
>> RAX: 0000000080000000 RBX: 000000c937e7f04b RCX: 0000000000000000
>> RDX: 0000000000000001 RSI: ffffffff8392f013 RDI: 0000000000000001
>> RBP: ffffc9000898fbd0 R08: ffff88809e1e2200 R09: 0000000000000040
>> R10: 0000000000000040 R11: ffffffff89a4f487 R12: 000000c937e7c4ab
>> R13: 0000000000000001 R14: 0000000000002ced R15: 0000000000000047
>> FS:  0000000000000000(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: 00007fbb9d9c6000 CR3: 0000000094911000 CR4: 00000000001426e0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> Call Trace:
>>   __delay arch/x86/lib/delay.c:161 [inline]
>>   __const_udelay+0x59/0x80 arch/x86/lib/delay.c:175
>>   try_check_zero+0x201/0x330 kernel/rcu/srcutree.c:705
>>   srcu_advance_state kernel/rcu/srcutree.c:1142 [inline]
>>   process_srcu+0x329/0xe10 kernel/rcu/srcutree.c:1237
>>   process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
>>   worker_thread+0x98/0xe40 kernel/workqueue.c:2410
>>   kthread+0x361/0x430 kernel/kthread.c:255
>>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>>
>>
>> ---
>> This bug is generated by a bot. It may contain errors.
>> See https://goo.gl/tpsmEJ for more information about syzbot.
>> syzbot engineers can be reached at syzkaller@googlegroups.com.
>>
>> syzbot will keep track of this bug report. See:
>> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>>
>> --
>> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000021cc1a0599f66f55%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o8w5u47c.fsf%40dja-thinkpad.axtens.net.
