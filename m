Return-Path: <kasan-dev+bncBCMIZB7QWENRBM6B7X5AKGQEA2S4JJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id CEB70268AC9
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 14:23:16 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id o5sf9423563pgm.19
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 05:23:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600086195; cv=pass;
        d=google.com; s=arc-20160816;
        b=TCt5KCp7kRG8/EH91zRbNfrwatZAQPt/bnQyMM/tpEhNYzG/0jEXgtMMDEAa2qp3Co
         yzY3mLhROIA+aLn6l4k2Vd6uQbn7wqAftjnZVxP7/LzESebMp3hvHXUYEmaHQDifD3Gl
         UX2YBzaXHdRw4RLc3cvAympYDH9UNuUuiwnOAdYuPj2oXeFuE8nwkZqy+FUzbV8V6rkp
         ZSA/V1likOMR/p4Ha66vBIFrx9WF0S5yf4aeZnaCSsFIxxgbH8kQvhu3XCgqplE+kYJS
         CTuPRycRWWQ/jLdMURM6ybpQbfLUNXeZE6o/T3D8MN2zw/6neidmb/2wmxj9Kvkxd30H
         9KjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1oIWP7cabcrti+MH1Aef67ptrKib02Jq/OiwTw9OZNQ=;
        b=G31/KA4gZ57fYXVh03Of3+D2EBwlgZL+H58IePmfiA90zh8mSVRNsNh19Gh+le0qMp
         l9Q0a3bCnHohgunI/GoKh2miKUQZrBRHvbeKjXVByyWeO7p1vsWNrSScRvFozVeqf+RI
         9kLKEWkTwoq3lXrEOLo+nkCftvstj8kA/8gA72qFdN44AqPB0L++2SyUUvTDS2WXJK49
         RA6t4wcchKA36aVHovIMi0MCtjo7LnoZ/if0c02UdOOltZ/WCEw/8lANLPTW8sNwTW1y
         i5dxOvOfonj6M3B+xIWzS3ukvLK1+MFz8j3tsBuxqnLoNGRJu1oTdDFJfHD8zarcmvmY
         Q07g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uBVbEj6C;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1oIWP7cabcrti+MH1Aef67ptrKib02Jq/OiwTw9OZNQ=;
        b=V2BGNFtdS1d6y8vVA6C3B/BlmdGeX9z7n331PHVifKSalQL6SrFtKFupdcZj2e28ag
         bgd33LJln3aSLqJQb5vVzck0DrnRzKIiOsmRttZTHIzfPt2gmoSqMU0ywi1Q8SI52/9d
         dV9L99rUHn3E49dO4jFC8FahVkgycODc8megTMevAWhVTOjEznpiFfY49EnaKTxfyKuL
         iM5nTE8qMl6tgBHPLpW5ynKAo8hDOZ79slp+2aTIMmu6hT6HIV4bipCUVo24hNI3KDyL
         +IuGB7YndyUH+37HzZgpNr5ukI4F6YsshC0TnKemI2+Uv0/jQXj3/jMsJc6oMgsPoURh
         FHtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1oIWP7cabcrti+MH1Aef67ptrKib02Jq/OiwTw9OZNQ=;
        b=r6AH6dzHhUGhxupLbbj3iZWLohRXOkJiFo4ZgUOJ3o1p3DM/Dz0fXWIQnxCqnGxVLm
         xPhKcmjcNnqdOEhedZV3pVoyqPZznrBhe/3c+BGtDbQpPFkXTFe1ILD2djOnUEh9uu6C
         zA2O61dpig9IrD08zXQn+0Q/1dwHBPXUac1PG7fzsXH8AaZpe1ZVbB2LRZ57KQ4HP+I3
         BdbGx2uq5LG8KomqLg3h2qkobITHBCYb3mkn94cITq22tmvOcC315SPD5us+u5ZOGyXN
         NiALTNvKEPdh/PKm68ETvZOJPNConV3cPjd6YzDTo4Hwf/re8tUcavafn9e6PiCR+6KA
         3bzQ==
X-Gm-Message-State: AOAM530Ka7UOvnrp/abgOBbYAJQnMPySJmQQP1SENziFfQ6xKtt4xKUx
	PUwbzkC7nhOQbjxQWS2V6GQ=
X-Google-Smtp-Source: ABdhPJwLm9FGeaXOngG5b4sCy2+Y1eWyUFRSS4vXPE9ngqgHpacHVy29sXgYhVQ4xQWKWxjz7BY7kg==
X-Received: by 2002:a63:b44f:: with SMTP id n15mr10842694pgu.282.1600086195212;
        Mon, 14 Sep 2020 05:23:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:620d:: with SMTP id d13ls2795322pgv.0.gmail; Mon, 14 Sep
 2020 05:23:14 -0700 (PDT)
X-Received: by 2002:a63:28c:: with SMTP id 134mr10614245pgc.385.1600086194578;
        Mon, 14 Sep 2020 05:23:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600086194; cv=none;
        d=google.com; s=arc-20160816;
        b=UhAeVnh0KsolJQHdYXuSr3d8hw4cN76LbL/muohLSCh8CukU5SCYwuJM4whxkx3W3a
         fumCmNh1jkbdNdkb22L0/KB84VcPBvzLuTFsbCVYE6uChb+3GrFqOTND06WrzrdKusQa
         RwVunJPlu9tEm2AASgfzOQRI6+F1iR1dp11rr6a5bl6Bduqw6wNjNmzyyM2vzA4Cp4ua
         ksw5cx+LcvQfMzlVjLEJsrZio1sx/s8MsxKOrFV9FHAnZNBG/Wrp85IJ/w6PabIlI0jo
         V7I5QygSBYAxI/y01/U2UQGBmZo1nrF+fkXdwYgjItqJsl67eUS4hzCUgWH69cOTTsUB
         EOgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ss/SJTzMTJ6NYsdm+9+ea3ztoCizcQb7pDEcNQl4ncE=;
        b=fZw8iQaGv6ezlsdofJcMm+UgwZ469vibrJlxhQ5HqiWJF07ytsd3vIaHkxWd+rZ98I
         oB75X4rjANYi/VeF3/BNWP/wlSbPCmMxenh+ZydTBTdPguMx9eg5nfdCJJreZnAAR1l1
         PtZmYZnZen998somFDy+dd8gZnV6nx3XXWhe66p7OmbWrnu/AQvZkrOblwe1VDMwy52a
         aUxP86KxFcPorhnqTeK9T8+w3fcwxjk9FmmTDxvc5Z0hBgMsc20CvMMMBZwPPln/ze20
         m2aeACDAhMjocwxJjn82YDC1/tTgB9pV6J6Cc87YHn4kINkd7wNpe8KUEL73M3oAwrsN
         fhNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uBVbEj6C;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id w15si573952pfu.6.2020.09.14.05.23.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 05:23:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id v54so13205944qtj.7
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 05:23:14 -0700 (PDT)
X-Received: by 2002:ac8:bc9:: with SMTP id p9mr474696qti.50.1600086193654;
 Mon, 14 Sep 2020 05:23:13 -0700 (PDT)
MIME-Version: 1.0
References: <00000000000005f0b605af42ab4e@google.com> <87zh5stv04.fsf@x220.int.ebiederm.org>
In-Reply-To: <87zh5stv04.fsf@x220.int.ebiederm.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Sep 2020 14:23:01 +0200
Message-ID: <CACT4Y+ZcrHFS45-NFxZKWdoesCdLwk-_1YvMJr01FRL1sG-ZeQ@mail.gmail.com>
Subject: Re: KASAN: unknown-crash Read in do_exit
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christian Brauner <christian@brauner.io>, 
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Eric Sandeen <sandeen@sandeen.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uBVbEj6C;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Mon, Sep 14, 2020 at 2:15 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com> writes:
>
> > Hello,
> >
> > syzbot found the following issue on:
>
> Skimming the code it appears this is a feature not a bug.
>
> The stack_not_used code deliberately reads the unused/unitiailized
> portion of the stack, to see if that part of the stack was used.
>
> Perhaps someone wants to make this play nice with KASAN?
>
> KASAN should be able to provide better information than reading the
> stack to see if it is still zeroed out.
>
> Eric

Hi Eric,

Thanks for looking into this.

There may be something else in play here. Unused parts of the stack
are supposed to have zero shadow. The stack instrumentation code
assumes that. If there is some garbage left in the shadow (like these
"70 07 00 00 77" in this case), then it will lead to very obscure
false positives later (e.g. some out-of-bounds on stack which can't be
explained easily).
If some code does something like "jongjmp", then we should clear the
stack at the point of longjmp. I think we did something similar for
something called jprobles, but jprobes were removed at some point.

Oh, wait, the reproducer uses /dev/fb. And as far as I understand
/dev/fd smashes kernel memory left and right. So most likely it's some
wild out of bounds write in /dev/fb.

> > HEAD commit:    729e3d09 Merge tag 'ceph-for-5.9-rc5' of git://github.com/..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=170a7cf1900000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=c61610091f4ca8c4
> > dashboard link: https://syzkaller.appspot.com/bug?extid=d9ae84069cff753e94bf
> > compiler:       gcc (GCC) 10.1.0-syz 20200507
> > syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=10642545900000
> > C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=141f2bed900000
> >
> > Bisection is inconclusive: the issue happens on the oldest tested release.
> >
> > bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=17b9ffcd900000
> > final oops:     https://syzkaller.appspot.com/x/report.txt?x=1479ffcd900000
> > console output: https://syzkaller.appspot.com/x/log.txt?x=1079ffcd900000
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com
> >
> > ==================================================================
> > BUG: KASAN: unknown-crash in stack_not_used include/linux/sched/task_stack.h:101 [inline]
> > BUG: KASAN: unknown-crash in check_stack_usage kernel/exit.c:692 [inline]
> > BUG: KASAN: unknown-crash in do_exit+0x24a6/0x29f0 kernel/exit.c:849
> > Read of size 8 at addr ffffc9000cf30130 by task syz-executor624/10359
> >
> > CPU: 1 PID: 10359 Comm: syz-executor624 Not tainted 5.9.0-rc4-syzkaller #0
> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> > Call Trace:
> >  __dump_stack lib/dump_stack.c:77 [inline]
> >  dump_stack+0x198/0x1fd lib/dump_stack.c:118
> >  print_address_description.constprop.0.cold+0x5/0x497 mm/kasan/report.c:383
> >  __kasan_report mm/kasan/report.c:513 [inline]
> >  kasan_report.cold+0x1f/0x37 mm/kasan/report.c:530
> >  stack_not_used include/linux/sched/task_stack.h:101 [inline]
> >  check_stack_usage kernel/exit.c:692 [inline]
> >  do_exit+0x24a6/0x29f0 kernel/exit.c:849
> >  do_group_exit+0x125/0x310 kernel/exit.c:903
> >  get_signal+0x428/0x1f00 kernel/signal.c:2757
> >  arch_do_signal+0x82/0x2520 arch/x86/kernel/signal.c:811
> >  exit_to_user_mode_loop kernel/entry/common.c:159 [inline]
> >  exit_to_user_mode_prepare+0x1ae/0x200 kernel/entry/common.c:190
> >  syscall_exit_to_user_mode+0x7e/0x2e0 kernel/entry/common.c:265
> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > RIP: 0033:0x446b99
> > Code: Bad RIP value.
> > RSP: 002b:00007f70f5ed9d18 EFLAGS: 00000246 ORIG_RAX: 0000000000000038
> > RAX: 0000000000002878 RBX: 00000000006dbc58 RCX: 0000000000446b99
> > RDX: 9999999999999999 RSI: 0000000000000000 RDI: 0000020002004ffc
> > RBP: 00000000006dbc50 R08: ffffffffffffffff R09: 0000000000000000
> > R10: 0000000000000000 R11: 0000000000000246 R12: 00000000006dbc5c
> > R13: 00007f70f5ed9d20 R14: 00007f70f5ed9d20 R15: 000000000000002d
> >
> >
> > Memory state around the buggy address:
> >  ffffc9000cf30000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >  ffffc9000cf30080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >>ffffc9000cf30100: 00 00 00 00 00 00 70 07 00 00 77 00 00 00 00 00
> >                                      ^
> >  ffffc9000cf30180: 00 00 70 07 00 00 70 07 00 00 00 00 77 00 70 07
> >  ffffc9000cf30200: 00 70 07 00 77 00 00 00 00 00 70 07 00 00 00 00
> > ==================================================================
> >
> >
> > ---
> > This report is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this issue. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> > For information about bisection process see: https://goo.gl/tpsmEJ#bisection
> > syzbot can test patches for this issue, for details see:
> > https://goo.gl/tpsmEJ#testing-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZcrHFS45-NFxZKWdoesCdLwk-_1YvMJr01FRL1sG-ZeQ%40mail.gmail.com.
