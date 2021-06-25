Return-Path: <kasan-dev+bncBCMIZB7QWENRBQOV26DAMGQEDQZCCKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 99CC33B45EB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 16:40:02 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id q7-20020a5d87c70000b02904eff8ce1ea0sf2661408ios.5
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 07:40:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624632001; cv=pass;
        d=google.com; s=arc-20160816;
        b=BQayawmovs2x9X2ZqFG+z2L29884TcAx69POEqCqYcq+DMSthla2ukYWA+og5+7QC9
         10AKBXSsmjR1D39eO/vkggVD4Iv8TD+97H87UQGt5YIQl4fhsFFNh+rZeIyTJkkhZ18y
         Mx4oisNiY3W2mUefocgt8lkyzHu0ENQeuXBOYHzniZTgri037YY+mvDFlomd2hSFAAOZ
         15PuDdg4Bed/MrxnUaJ6YAQbm5p/3OJFFFtcjBG9q98F59AloxbuHjzoFiJxAfGAed6g
         eqAaEwEHs4Ld8qYN2INPYnXjq11XOjE6smTapFBRa1TnegS9JJsxb1t6fSXIYrmNtPWB
         Tyyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GTyWdbRrxH9eZdJirpdDU3yXKasfPMTIlBSzMop+rEg=;
        b=Q2ua2LE7reIK3MUZ840thNRQivjvbNdg1iXzlb375KtqQ1qnO5scG2aDfmir9iYJJe
         4O2CyYv3UaxKHMRnzTy5ooBOIq3PPElQiTfSwKjjovBuNSfudNGj62H8VGMsqMn+fHqe
         FK51Unasaf1Wgj5wNzD+2sVkzqi2cBHIU7kQZ2uq/ur8gb9Fre4QkfxXspkQXX6CH9R8
         Npf3D56cUj7V+VOp2jULgwJvot41tEZ8o/OQJXxaN6eDuHm/gruNexOVo8UMP+pbdxyN
         225FozHHPvqRKKpgBG5IfkQDQM3pGwvvAjOd2B6JKNncSuNyFj5ccrTfXVXA/VXI2E9Q
         x7bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nv/+OmOb";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GTyWdbRrxH9eZdJirpdDU3yXKasfPMTIlBSzMop+rEg=;
        b=gIWvqnKzIcC/4bvOAlFBlyb3h7pQUeg92CBcrKqhPrnMFSIRNtJmho4pG+Hgd5zSnz
         dthavQ3UeZMgyJGXAFteZABYb+Pi37t0JbvoiOAUzwFvFH/5aiIPX7xM7wSxjeLxf6x+
         kvMl/aJsN2xPb8rgaLVcyOKwKkywhPEl0YRVN2QnGHkXTMchsVqJbQLGEE9KRh1+KezM
         qaklQqx2eGWjnI7LicCXl6xuhQPanCV5hT2MnlxfD6Kx9Lk8db3j5ASwQEwz9DfHA6WZ
         rmI4SXI7ltG9z6eZTj1d306rVEIO8JiUdJUMAb5A+2mD7FVVsKRsI4PY03ng36KzJNzw
         Veqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GTyWdbRrxH9eZdJirpdDU3yXKasfPMTIlBSzMop+rEg=;
        b=o/FSZ8SxgTP05jSgsim8GbW7gpQYmE57vXUYqBNNo+9jY18JBcHg0r4BACD9ACM7/L
         mGrXN6rWrIQ0Aa1UcjE4Laa2dd/IqDSrx+5jMYPSVcNZobyx2MP+JL2YdtlEOose8lff
         GTVY+64epHEnOOQ60lnrFTL9iX0Ndm7jz3ZisYu6GSks+kLIustFA8lZJ+vpR1k8w8RF
         2io78w2Sedq/tnaqMVykWawOLQWho/BRz7WwiVF6iU6IcSfUp7C4m0M24mZNizgL8/3w
         WI0QGXveanfEN7f/Zti3fAOS51aBs7L0iwNZuQUtyVcxAQtwPdMUV29zGVIy5CGPvBRb
         fRvQ==
X-Gm-Message-State: AOAM530KEm4/vAkpwUj/NOUBFHaaD5XC2+RJFQ3jb1ajff4lEE51gdbf
	zehoyqZT/vM9k94VDuvcZuo=
X-Google-Smtp-Source: ABdhPJzfLFjQU0CN8eVnpbsl40tyyBeVnpfwQvdZYxE2+0rwy9n/Wb2lcn/HdF9yMXCvDEsKmEAG2g==
X-Received: by 2002:a92:d849:: with SMTP id h9mr7792994ilq.262.1624632001153;
        Fri, 25 Jun 2021 07:40:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c60c:: with SMTP id i12ls700017jan.8.gmail; Fri, 25 Jun
 2021 07:40:00 -0700 (PDT)
X-Received: by 2002:a02:c6ae:: with SMTP id o14mr10001748jan.73.1624632000765;
        Fri, 25 Jun 2021 07:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624632000; cv=none;
        d=google.com; s=arc-20160816;
        b=vXRff9NzcvFhXD9kzib+RcNvUo+1HPxTOSBSLF2VD8mSs4H72P9ItAQp7BtqbS6QLb
         dW/q4Rfk9wU6gCvhBlNnwHP2JOQPjJsnn4Eaq2r/cw3iEGnZLO8gz1i9FYyw1tz9ZI95
         xvXKLCG2sOCm3Fob6V7/wk4IhA96R1SUiPc5U02MuARPzbpzi5Qv5VlCkZNfxDs5mYin
         UZ7eesKbKNTR1BomXxghGUU7hs9Yolpqzdb0Eg7S2Xnd8vhYqevu/S3qCBpm3rEbEZD/
         D6dzvs2Qo5ryktkN/4M+nwdq96JE67SpMRf4RRHpEn5Nq2i/I9KZxZBULjfFQesb+yR9
         8Emw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nD0kmHbZLR2o/dbFfrzrGrzfR5OtIwAqoz1ygGc2h+s=;
        b=kxuK1edtHKhXYvln+qmgbOLw1LyI+vO6kOSyYOUbiJdmZ+uNrh+9Z5vBy6JGHc5lCU
         y0A+BmCDARo1PHijSoPXW/4MVazqWoBJTr+QcN6YhYP2u3wBRrGV1LyDcFsYFgS/rYtA
         FNJ4YE2SBpn7kFrbuhOQ0Yec8c66B90C1RizhypTDAqiTfF4ZI752faVHvPEjEaEJHiZ
         1EOyMuc3QyVxXIbj6XiT4C9NLwwJvj61pY+PBuxbrxOpv7pkuSB8ezGz2sbxIQhcqLSb
         pxePOqT0CARRAfkzLKoPmQQ+pvH59wAIY8ip0pf/iF3go3NTbws+Kzfjtf85i1bo+v4m
         HFdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nv/+OmOb";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id e9si422690ilc.3.2021.06.25.07.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jun 2021 07:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id c23so19271236qkc.10
        for <kasan-dev@googlegroups.com>; Fri, 25 Jun 2021 07:40:00 -0700 (PDT)
X-Received: by 2002:a37:9d93:: with SMTP id g141mr11934052qke.350.1624632000188;
 Fri, 25 Jun 2021 07:40:00 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000ef5d1b05c57c2262@google.com> <87fsx7akyf.fsf@disp2133>
In-Reply-To: <87fsx7akyf.fsf@disp2133>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Jun 2021 16:39:46 +0200
Message-ID: <CACT4Y+YM8wONCrOq75-TFwA86Sg5gRHDK81LQH_O_+yWsdTr=g@mail.gmail.com>
Subject: Re: [syzbot] KASAN: out-of-bounds Read in do_exit
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: syzbot <syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com>, 
	akpm@linux-foundation.org, ast@kernel.org, christian@brauner.io, 
	jnewsome@torproject.org, linux-kernel@vger.kernel.org, minchan@kernel.org, 
	oleg@redhat.com, syzkaller-bugs@googlegroups.com, 
	Ingo Molnar <mingo@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="nv/+OmOb";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736
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

On Thu, Jun 24, 2021 at 7:31 AM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> syzbot <syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com> writes:
>
> > Hello,
> >
> > syzbot found the following issue on:
>
> This looks like dueling debug mechanism.  At a quick glance
> stack_no_used is deliberately looking for an uninitialized part of the
> stack.
>
> Perhaps the fix is to make KASAN and DEBUG_STACK_USAGE impossible to
> select at the same time in Kconfig?

+kasan-dev

Hi Eric,

Thanks for looking into this.

I see several strange things about this KASAN report:
1. KASAN is not supposed to leave unused stack memory as "poisoned".
Function entry poisons its own frame and function exit unpoisions it.
Longjmp-like things can leave unused stack poisoned. We have
kasan_unpoison_task_stack_below() for these, so maybe we are missing
this annotation somewhere.

2. This stand-alone shadow pattern "07 07 07 07 07 07 07 07" looks fishy.
It means there are 7 good bytes, then 1 poisoned byte, then 7 good
bytes and so on. I am not sure what can leave such a pattern. Both
heap and stack objects have larger redzones in between. I am not sure
about globals, but stack should not overlap with globals (and there
are no modules on syzbot).

So far this happened only once and no reproducer. If nobody sees
anything obvious, I would say we just wait for more info.



> > HEAD commit:    9ed13a17 Merge tag 'net-5.13-rc7' of git://git.kernel.org/..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=116c517bd00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=bf635d6d1c7ebabc
> > dashboard link: https://syzkaller.appspot.com/bug?extid=b80bbdcca4c4dfaa189e
> > compiler:       Debian clang version 11.0.1-2
> >
> > Unfortunately, I don't have any reproducer for this issue yet.
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com
> >
> > ==================================================================
> > BUG: KASAN: out-of-bounds in stack_not_used include/linux/sched/task_stack.h:101 [inline]
> > BUG: KASAN: out-of-bounds in check_stack_usage kernel/exit.c:711 [inline]
> > BUG: KASAN: out-of-bounds in do_exit+0x1c6b/0x23d0 kernel/exit.c:869
> > Read of size 8 at addr ffffc90017d60400 by task loop0/31717
> >
> > CPU: 0 PID: 31717 Comm: loop0 Not tainted 5.13.0-rc6-syzkaller #0
> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> > Call Trace:
> >  __dump_stack lib/dump_stack.c:79 [inline]
> >  dump_stack+0x202/0x31e lib/dump_stack.c:120
> >  print_address_description+0x5f/0x3b0 mm/kasan/report.c:233
> >  __kasan_report mm/kasan/report.c:419 [inline]
> >  kasan_report+0x15c/0x200 mm/kasan/report.c:436
> >  stack_not_used include/linux/sched/task_stack.h:101 [inline]
> >  check_stack_usage kernel/exit.c:711 [inline]
> >  do_exit+0x1c6b/0x23d0 kernel/exit.c:869
> >  kthread+0x3b8/0x3c0 kernel/kthread.c:315
> >  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:294
> >
> >
> > Memory state around the buggy address:
> >  ffffc90017d60300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >  ffffc90017d60380: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >>ffffc90017d60400: 07 07 07 07 07 07 07 07 00 00 00 00 00 00 00 00
> >                    ^
> >  ffffc90017d60480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >  ffffc90017d60500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
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
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/87fsx7akyf.fsf%40disp2133.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYM8wONCrOq75-TFwA86Sg5gRHDK81LQH_O_%2ByWsdTr%3Dg%40mail.gmail.com.
