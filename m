Return-Path: <kasan-dev+bncBDZKHAFW3AGBBBHF3KHAMGQEKV4EUWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD0B4861DC
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jan 2022 10:12:38 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id n4-20020aa79044000000b004bcd447b6easf1343752pfo.22
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Jan 2022 01:12:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641460357; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmeU5uvrnAuYVrqyL0FDXOuItIGDZp/CZj4JmdvTaZLogrGU6q8V3LlK4Oh/M8P7/2
         idXOId4S0eWklaDR0hH99aqBaFsdvh3t5ftQn/6lk7T/G+XKcSBTmQ8d/dcLDYhNNSij
         P/b9jKdBB8qJxsrvf4a2KHmUjffCgiju8w0G2rA09gzQUOe5H3VdEvmyHRMENA+WcaKw
         B1w6MP2LgGwydOYm9+7yPBUQdM2g97XIUw3G1V2RItd3NzLYBFCsk7vRJRlYrxHHKMsN
         i2SWoEPEZabYi+KzJHJg4w8SV6MLwrFYR0XENbv5k8gNmNPlM0bwZebk6L2UgmhEd93M
         /NcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/sjBmY4m7N5xZ53HwRKTwIxG6NXQyNrbxHmzgiriQQg=;
        b=pJ/85WofgH8PwT+wcsQ3fBDjkkZHZljdjQHJdtdKm5ltB3eWnlM8SUoOrkOJNHa+2G
         BZB0vEok0hN4gPSK4BksiSRx8tPJk9ICL/PR0LYjxPf8dIxt4Zgbg2TA89tDWgfGP2MM
         J7bTWIojb5Tbj01zx9WVrEVZDCJiQfsxbecGYwzND/87GlmLrS/OkDL235Z/lEUbuMKg
         P5MwWd4A43s1uCzTWur4nYk9Kq/GncnuDVmel0man8fy1bdXcfkWtmcSBySwJfQ16Y0g
         k6q9JhOjgMSzmm8ALsf3+0T8DKtMZtiALf3Tbnptq1W8g3NBa6Dw9uchkz8ES7iUn0O7
         BOCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=i6GwA8wb;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/sjBmY4m7N5xZ53HwRKTwIxG6NXQyNrbxHmzgiriQQg=;
        b=VKBO2EgaDku/iOPtrftE9Il9FB0hDWg1W2LwCMa2pHTZwo2t/Dnj9s9IiT+jHRTG9n
         Degh9soJqEFC7n3Q4Ej6/AkDLE1c24a3gcjiZb1E2fF55IQhNEaym/oTX2SOL15/hWAB
         Lv7pL4fsRXHWuq63ovAmXA6xo8Liq7XLDo2l1DSQhznkeG8icK9yQ6j9MpBnyjHfu7Jk
         cjFj3wQ6g8K7/O6KgrXOdrVRtk21pwcJPNMvtH2s1h6BxeqhZ0qD9EmnI5gMRYm9C7uS
         GMFSQ7mhFGwCVcJYWpbGEtzQeoolvGOpA3jlBeyLanNXQDpLfjc0uXfFe3RJXlpAhWcl
         tV1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sjBmY4m7N5xZ53HwRKTwIxG6NXQyNrbxHmzgiriQQg=;
        b=WoZs7dtRp9OrzZfkLnUJnhpDkI81sSkTyN78JFW2v5wc0qI4GX/zH3XdpJ26urJnVw
         BtTtI4XT7z1CLQVMkBUTDyTH/pToNDby3c0b183TKK7PGpuDNpnHuIAgZ4LH9OcN2C4v
         DQU8xk7iF6sbfbqpvfUGa/vQ0zOMsJp4HKYJ4CXxDX4OW051D7fv+rowM4UWI+u7iDF+
         UL4mKmMX1nq74NcztLw9wObgW91gCX+zBUFN4+2GjNOi7/pWsKmGpaIdhWD/L9SwwV6c
         cddI8aXvWyIfG6IUG7tvRfbgc2gt1QYrPUreme8Hw4OWphqwNfBwnBw+oINejHA/TC3M
         gShg==
X-Gm-Message-State: AOAM532EmvqF80PcPKhpfUd1xj7y1g/MyltfZG/mGqj2YmRa6p033a5o
	JLOjgVDumMZ9UES5HFByTjs=
X-Google-Smtp-Source: ABdhPJyV3U2+rwLOIPQaQl8EAnxf9E/MSehYUwCMixwVxPWq7WpM3gcOgC+890NtJxReyqnYNJ2Anw==
X-Received: by 2002:a17:90a:414b:: with SMTP id m11mr9016205pjg.158.1641460356550;
        Thu, 06 Jan 2022 01:12:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:78ce:: with SMTP id t197ls613650pgc.1.gmail; Thu, 06 Jan
 2022 01:12:36 -0800 (PST)
X-Received: by 2002:a63:8f05:: with SMTP id n5mr51302724pgd.606.1641460355923;
        Thu, 06 Jan 2022 01:12:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641460355; cv=none;
        d=google.com; s=arc-20160816;
        b=OLj7Xq636onJ59nH/WSZtCIN8DjiobmlQtSHxkFR0uORjXhmD+Q1SnTZ3c2/zQk51P
         rurMWJGlzYQiqmAUBi5gyClkhM2peQjTfoQLhhlYzMjt2LY87uSuXha3d7ZGx1MAn0A2
         hPp3HexkdxQPmMtO3duUUiEiNQGXmfJOPwu/8UuYEFzHp7dWZQfxIngrMUrzY9mzNYNp
         t//81phRQkXSrnhYDTuJ1Kt/u10Mc6XaVNhOSpsBcbIC2MOkcWeJK+iVzJF//46YBrXT
         WBv+KwcDnu6oVshhLLcZd33b8fDUkvFP76MgkKe+QzqLY8lQtPu23zLOEnXzGOme5OCf
         S/CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2brGx705QYkY0AujJCUiwrOpHDiV9D8MTqlymar57Js=;
        b=KO11MDgrsYRW0R1nQMnlGggfv5T1Hn6IKraQNfkkpJT+2+DkbpYdRf+Q4a+7tuMich
         JmH+U/x4ureoFzehe1lR5HBGJeotcr/5dVmBwlEqiBWBuGzwbmC8hIjcWK+VmHRTmoWd
         jwuBfEySpZNLXeMM9tfL/QpEjkJqq3Eg8/1v57ucJoA8bVof62BlQMg97sjaq0ZBzkUC
         0Hrd5MUFhopiDfFfcu/Lhq19XLi9/qZLZz+ETvl8sNPIm7uuXrlaFDhzTZfpr9szZOqu
         7dQoQORBAYHSlHQuZzXpf/KOk+2F1S8lwv9kuN+d8/NJrR7r70bcdDHaEzLjt1/CRLOq
         +wCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=i6GwA8wb;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id j11si46950plx.9.2022.01.06.01.12.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Jan 2022 01:12:35 -0800 (PST)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 52FBB1F37C;
	Thu,  6 Jan 2022 09:12:34 +0000 (UTC)
Received: from suse.cz (unknown [10.100.224.162])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id D052AA3B84;
	Thu,  6 Jan 2022 09:12:33 +0000 (UTC)
Date: Thu, 6 Jan 2022 10:12:30 +0100
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Sabri N. Ferreiro" <snferreiro1@gmail.com>
Cc: Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	John Ogness <john.ogness@linutronix.de>,
	Kees Cook <keescook@chromium.org>,
	Anton Vorontsov <anton@enomsg.org>,
	Colin Cross <ccross@android.com>, Tony Luck <tony.luck@intel.com>,
	linux-kernel@vger.kernel.org, mosesfonscqf75@gmail.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: INFO: rcu detected stall in devkmsg_read
Message-ID: <YdayfngxLCBB/Ful@alley>
References: <CAKG+3NT_v6fVOOn-qftVTLTHg5kSgsfnwb_-+zAQ-3drJm5+=A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKG+3NT_v6fVOOn-qftVTLTHg5kSgsfnwb_-+zAQ-3drJm5+=A@mail.gmail.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=i6GwA8wb;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Wed 2022-01-05 23:54:16, Sabri N. Ferreiro wrote:
> Hi,
> 
> When using Syzkaller to fuzz the Linux kernel, it triggers the following crash.
> 
> HEAD commit: a7904a538933 Linux 5.16-rc6
> git tree: upstream
> console output: https://paste.ubuntu.com/p/mdfS9m5C74/
> kernel config: https://docs.google.com/document/d/1w94kqQ4ZSIE6BW-5WIhqp4_Zh7XTPH57L5OF2Xb6O6o/view
> 
> If you fix this issue, please add the following tag to the commit:
> Reported-by:  Yuheng Shen <mosesfonscqf75@gmail.com>
> 
> Sorry for my lack of this crash reproducer, I hope the symbolic report
> will help you.
> 
> R13: 00007ffd0a4a0e08 R14: 000055d71ee2c958 R15: 0005d4cd3d2ed07c
>  </TASK>
> Call Trace:
>  <IRQ>
>  x86_pmu_stop+0x11b/0x320 root/fuzz/kernel/5.16/arch/x86/events/core.c:1597
> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
>  x86_pmu_del+0x1a5/0x5b0 root/fuzz/kernel/5.16/arch/x86/events/core.c:1636
> rcu: 1-....: (108 ticks this GP) idle=459/1/0x4000000000000000
> softirq=39414/39414 fqs=4592
> (detected by 3, t=21002 jiffies, g=40973, q=19739)
>  event_sched_out.part.0+0x1ea/0x820
> root/fuzz/kernel/5.16/kernel/events/core.c:2285
> Sending NMI from CPU 3 to CPUs 1:
> NMI backtrace for cpu 1
> CPU: 1 PID: 121 Comm: systemd-journal Not tainted 5.16.0-rc6 #3
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
> 1.13.0-1ubuntu1.1 04/01/2014
> RIP: 0010:preempt_count_add+0x7/0x140
> root/fuzz/kernel/5.16/kernel/sched/core.c:5422
> Code: df 03 00 48 89 ef e8 68 81 04 00 48 8b 3d b1 ca b8 03 48 89 ee
> 5d e9 a8 2b 44 00 0f 1f 84 00 00 00 00 00 48 c7 c0 c0 ef 6d 92 <55> 48
> ba 00 00 00 00 00 fc ff df 48 89 c1 53 83 e0 07 89 fb 48 c1
> RSP: 0018:ffff8881f7289868 EFLAGS: 00000046
> RAX: ffffffff926defc0 RBX: 1ffff1103ee5130e RCX: ffffffff8e253c25
> RDX: ffff8881082bd3c0 RSI: 0000000000000000 RDI: 0000000000000001
> RBP: ffffffff9269e980 R08: 0000000000000001 R09: ffffffff9269e30e
> R10: fffffbfff24d3c61 R11: 0000000000000001 R12: ffff8881f7289940
> R13: 0000000000014f2e R14: 0000000000014f2e R15: ffff8881f7289ad0
> FS:  00007f3f4e83c8c0(0000) GS:ffff8881f7280000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: 00007f3f4a04b000 CR3: 0000000108138000 CR4: 0000000000350ee0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000ffff4ff0 DR7: 0000000000000400
> Call Trace:
>  <IRQ>

The backtrace is from IRQ context.

>  __raw_spin_lock
> root/fuzz/kernel/5.16/./include/linux/spinlock_api_smp.h:132 [inline]
>  _raw_spin_lock+0x5e/0xd0 root/fuzz/kernel/5.16/kernel/locking/spinlock.c:154
>  console_lock_spinning_enable
> root/fuzz/kernel/5.16/kernel/printk/printk.c:1776 [inline]
>  console_unlock+0x28e/0x8e0 root/fuzz/kernel/5.16/kernel/printk/printk.c:2708

console_unlock() was called from IRQ context.

It is a known printk() design problem that console_unlock() called
from IRQ context can cause softlockups, rcu stalls, ... when it has
to flush too many messages to the consoles. Especially when there
are messages added from other CPUs.

And the console output at https://paste.ubuntu.com/p/mdfS9m5C74/ suggests
that there were many printk messages flushed.

John Ogness is working on solving this design problem by offloading
the console handling to kthreads. So, we hopefully get rid of it
one day.


At the moment, the only solution is to reduce the number of messages
printed to the console.

And I am a bit confused here. I do not understand who is producing all
the other messages. They look like "regular" snapshots but I do not
understand who triggered them.

We should make sure that there is no infinite loop caused by kasan
reports and printk code. But I do not fully understand if this is
the case here. Adding Kasan people into CC.

Best Regards,
Petr


>  vprintk_emit+0xf8/0x230 root/fuzz/kernel/5.16/kernel/printk/printk.c:2245
>  vprintk+0x69/0x80 root/fuzz/kernel/5.16/kernel/printk/printk_safe.c:50
>  _printk+0xba/0xed root/fuzz/kernel/5.16/kernel/printk/printk.c:2266
>  printk_stack_address
> root/fuzz/kernel/5.16/arch/x86/kernel/dumpstack.c:72 [inline]
>  show_trace_log_lvl+0x263/0x2ca
> root/fuzz/kernel/5.16/arch/x86/kernel/dumpstack.c:282
>  ex_handler_wrmsr_unsafe root/fuzz/kernel/5.16/arch/x86/mm/extable.c:87 [inline]
>  fixup_exception+0x3bb/0x690 root/fuzz/kernel/5.16/arch/x86/mm/extable.c:150
>  __exc_general_protection
> root/fuzz/kernel/5.16/arch/x86/kernel/traps.c:601 [inline]
>  exc_general_protection+0xed/0x2e0
> root/fuzz/kernel/5.16/arch/x86/kernel/traps.c:562
>  asm_exc_general_protection+0x1e/0x30
> root/fuzz/kernel/5.16/./arch/x86/include/asm/idtentry.h:562
> RIP: 0010:__wrmsr
> root/fuzz/kernel/5.16/./arch/x86/include/asm/msr.h:103 [inline]
> RIP: 0010:native_write_msr
> root/fuzz/kernel/5.16/./arch/x86/include/asm/msr.h:160 [inline]
> RIP: 0010:wrmsrl root/fuzz/kernel/5.16/./arch/x86/include/asm/msr.h:281 [inline]
> RIP: 0010:x86_pmu_disable_event
> root/fuzz/kernel/5.16/arch/x86/events/amd/../perf_event.h:1138
> [inline]
> RIP: 0010:amd_pmu_disable_event+0x83/0x280
> root/fuzz/kernel/5.16/arch/x86/events/amd/core.c:639
> Code: 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 80 3c 02 00 0f 85 e0 01
> 00 00 48 8b ab 78 01 00 00 4c 89 e2 44 89 e0 48 c1 ea 20 89 e9 <0f> 30
> 66 90 e8 34 4a 38 00 e8 2f 4a 38 00 48 8d bb 94 01 00 00 48
> RSP: 0018:ffff8881f7289df8 EFLAGS: 00010016
> RAX: 0000000000110076 RBX: ffff88810e915c88 RCX: 00000000c0010200
> RDX: 0000000000000100 RSI: ffffffff90e07480 RDI: ffff88810e915e00
> RBP: 00000000c0010200 R08: 0000000000000000 R09: ffff8881f72a19e7
> R10: ffffed103ee5433c R11: 0000000000000001 R12: 0000010000110076
> R13: 0000000000000000 R14: ffff8881f72a17e0 R15: ffff88810e915e14
>  x86_pmu_stop+0x11b/0x320 root/fuzz/kernel/5.16/arch/x86/events/core.c:1597
>  x86_pmu_del+0x1a5/0x5b0 root/fuzz/kernel/5.16/arch/x86/events/core.c:1636
>  event_sched_out.part.0+0x1ea/0x820
> root/fuzz/kernel/5.16/kernel/events/core.c:2285
>  event_sched_out root/fuzz/kernel/5.16/kernel/events/core.c:2354 [inline]
>  __perf_remove_from_context+0x5c6/0x750
> root/fuzz/kernel/5.16/kernel/events/core.c:2352
>  event_function+0x216/0x310 root/fuzz/kernel/5.16/kernel/events/core.c:253
>  remote_function root/fuzz/kernel/5.16/kernel/events/core.c:91 [inline]
>  remote_function+0x110/0x190 root/fuzz/kernel/5.16/kernel/events/core.c:71
>  flush_smp_call_function_queue+0x162/0x4f0
> root/fuzz/kernel/5.16/kernel/smp.c:628
>  __sysvec_call_function_single+0x62/0x200
> root/fuzz/kernel/5.16/arch/x86/kernel/smp.c:248
>  sysvec_call_function_single+0x89/0xc0
> root/fuzz/kernel/5.16/arch/x86/kernel/smp.c:243
>  </IRQ>
>  <TASK>
>  asm_sysvec_call_function_single+0x12/0x20
> root/fuzz/kernel/5.16/./arch/x86/include/asm/idtentry.h:646
> RIP: 0010:bytes_is_nonzero root/fuzz/kernel/5.16/mm/kasan/generic.c:85 [inline]
> RIP: 0010:memory_is_nonzero
> root/fuzz/kernel/5.16/mm/kasan/generic.c:102 [inline]
> RIP: 0010:memory_is_poisoned_n
> root/fuzz/kernel/5.16/mm/kasan/generic.c:128 [inline]
> RIP: 0010:memory_is_poisoned
> root/fuzz/kernel/5.16/mm/kasan/generic.c:159 [inline]
> RIP: 0010:check_region_inline
> root/fuzz/kernel/5.16/mm/kasan/generic.c:180 [inline]
> RIP: 0010:kasan_check_range+0x18e/0x1e0
> root/fuzz/kernel/5.16/mm/kasan/generic.c:189
> Code: 07 48 39 d0 7d 87 41 bb 01 00 00 00 5b 5d 44 89 d8 41 5c c3 48
> 85 d2 74 ed 48 01 ea eb 09 48 83 c0 01 48 39 d0 74 df 80 38 00 <74> f2
> e9 32 ff ff ff 41 bb 01 00 00 00 44 89 d8 c3 48 29 c3 48 89
> RSP: 0018:ffff888108c07b68 EFLAGS: 00000246
> RAX: fffffbfff22dc768 RBX: fffffbfff22dc769 RCX: ffffffff8e254b5c
> RDX: fffffbfff22dc769 RSI: 0000000000000008 RDI: ffffffff916e3b40
> RBP: fffffbfff22dc768 R08: 0000000000000000 R09: ffffffff916e3b47
> R10: fffffbfff22dc768 R11: 0000000000000001 R12: ffffffff916e3b40
> R13: ffff888108c07c30 R14: ffff888108c07c50 R15: ffffffff916e3b20
>  instrument_atomic_read
> root/fuzz/kernel/5.16/./include/linux/instrumented.h:71 [inline]
>  atomic_long_read
> root/fuzz/kernel/5.16/./include/linux/atomic/atomic-instrumented.h:1183
> [inline]
>  prb_first_seq root/fuzz/kernel/5.16/kernel/printk/printk_ringbuffer.c:1833
> [inline]
>  _prb_read_valid+0x48c/0x660
> root/fuzz/kernel/5.16/kernel/printk/printk_ringbuffer.c:1881
>  prb_read_valid+0x75/0xa0
> root/fuzz/kernel/5.16/kernel/printk/printk_ringbuffer.c:1929
>  devkmsg_read+0x158/0x680 root/fuzz/kernel/5.16/kernel/printk/printk.c:730
>  vfs_read+0x13c/0x4c0 root/fuzz/kernel/5.16/fs/read_write.c:479
>  ksys_read+0x100/0x210 root/fuzz/kernel/5.16/fs/read_write.c:619
>  do_syscall_x64 root/fuzz/kernel/5.16/arch/x86/entry/common.c:50 [inline]
>  do_syscall_64+0x3b/0x90 root/fuzz/kernel/5.16/arch/x86/entry/common.c:80
>  entry_SYSCALL_64_after_hwframe+0x44/0xae
> RIP: 0033:0x7f3f4ddcd210
> Code: 73 01 c3 48 8b 0d 98 7d 20 00 f7 d8 64 89 01 48 83 c8 ff c3 66
> 0f 1f 44 00 00 83 3d b9 c1 20 00 00 75 10 b8 00 00 00 00 0f 05 <48> 3d
> 01 f0 ff ff 73 31 c3 48 83 ec 08 e8 4e fc ff ff 48 89 04 24
> RSP: 002b:00007ffd0a49e438 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
> RAX: ffffffffffffffda RBX: 00007ffd0a4a0eb0 RCX: 00007f3f4ddcd210
> RDX: 0000000000002000 RSI: 00007ffd0a49ecb0 RDI: 0000000000000009
> RBP: 0000000000000000 R08: 000000000000e000 R09: 0000000000000007
> R10: 0000000000000002 R11: 0000000000000246 R12: 00007ffd0a49ecb0
> R13: 00007ffd0a4a0e08 R14: 000055d71ee2c958 R15: 0005d4cd3d2ed07c
>  </TASK>
>  event_sched_out root/fuzz/kernel/5.16/kernel/events/core.c:2354 [inline]
>  __perf_remove_from_context+0x5c6/0x750
> root/fuzz/kernel/5.16/kernel/events/core.c:2352
>  event_function+0x216/0x310 root/fuzz/kernel/5.16/kernel/events/core.c:253
>  remote_function root/fuzz/kernel/5.16/kernel/events/core.c:91 [inline]
>  remote_function+0x110/0x190 root/fuzz/kernel/5.16/kernel/events/core.c:71
>  flush_smp_call_function_queue+0x162/0x4f0
> root/fuzz/kernel/5.16/kernel/smp.c:628
>  __sysvec_call_function_single+0x62/0x200
> root/fuzz/kernel/5.16/arch/x86/kernel/smp.c:248
>  sysvec_call_function_single+0x89/0xc0
> root/fuzz/kernel/5.16/arch/x86/kernel/smp.c:243
>  </IRQ>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YdayfngxLCBB/Ful%40alley.
