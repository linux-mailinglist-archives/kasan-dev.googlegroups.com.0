Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQHMSGFAMGQE2UCTPHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id B602440F670
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 13:04:33 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id d202-20020a3768d3000000b003d30722c98fsf65230225qkc.10
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 04:04:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631876672; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5wIBYjau+piz2qCYW204PFgd3S7cc/9/CYbynkM0zFbtkCpqoPx2pMMPdKAU9JC7B
         w05EdkS0kGyxka5X9Qc7T70xxLj7GBR/Xs5/30gZhtC4GACqdgS+LNEFrnYqIecxheZy
         bKSCNTNkUzD6qjEgtTM0apJpLIrmg+p35XwpNvBRj70aNq2ym1iXQk0yCJJ6fMOWYb0S
         YGL6kH/4wMct+V3t4Zr5A6VFZ2w/5g2MIo2W97zfeBvrmZ0dxYtYWaBJPpX3uGxc6q48
         +7tSlAJ00TBezTt2dBTH2mcFuVUp/tb/bRtqpQoE8zxcaFZREtcqEAoD4M0IZrTc8o6+
         rLcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LMyCp/lhDqwaYUk6yZdUFq6HsgbIhcJtVLRnW/Yoopw=;
        b=SmR0UQ3M/NDJFedoT3Z6JXMPEW4LzyNjOpt3yQt5LcozQha9idHx7IeBI9DBtXmD/+
         u68gLGnGnllIJ5yaZHUAQtR/jNg8BbUyGZRMdrVHsudWK2pnW6PZqKcjfxt5TWBuCctS
         0KavzNlTolSb3bEDkuzkQk9F7z2P2r94D2BQHsGmwSb2n4YlZJbtehPaWGpVGNeRIO4x
         0bkd0ZmT8M3puk/wfi2KWnhDObwkF8BQ3b9ig87UJUQswrXpP6zT0Uv1G2iTZyXSojaw
         DPY0W2yHnzKKOLregEuPZWk+s9efyMrEXvA2M8QHU46xZDUBzdLemWsY5IfEZwyuEnE2
         llIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kKWaEJBP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LMyCp/lhDqwaYUk6yZdUFq6HsgbIhcJtVLRnW/Yoopw=;
        b=iyT3ukqYMiFNHUUr4pS6KI2BXwErOEbpXW44tP4XEbGo5xFR/+59xUr+jNHnX3mJio
         59u2v65Wmv/S6yqT9higtqgxu8SVkjfSzRythw9HGj6VqKQOf3770Rb1auiqmF4FtzsK
         Kl2t2pMNGGYaY1WhgyPhrV5tBXg6Iy5TWOkKU231pu3j4Xkn4MZbpk9LCcrmvyJ+ysH8
         pA4FFrOc+tZC/k2jyLUPttO9zP5+cFXA00tpqukXH9OeaLBH2yD155t0Nby9VXSOSyhJ
         3umSAWJx7bMtStSiiL0M+4aoHCVW+GUeHvxWikjpVsfDQPlH6nW8T/IeZcKCWPcjXkcu
         sSbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LMyCp/lhDqwaYUk6yZdUFq6HsgbIhcJtVLRnW/Yoopw=;
        b=0rTmSYGEO4AdQGIrxFFzZ1fPxz1+AuW5yCfdB1A2cpnRHE6gTbfOeLMBvJ21rrfk7N
         APJOWUQsBXDdoPkCSqVqFrEKD3Ew7P3mmtw/pJhTai0agvycEzzn8plo7c+SAlibXD0X
         KPJVuOSjXJkZO1WxQDsDr3bwRg88PBjJyAsSJLBg46O4wKKT6Ke0svd0vRE/QFpUZ5bm
         KvQnXRa5hhRlBrswLv8GrhppS6Z4AaKTsBlHw50RnJmCeebf4fH6uQGc/LF2JPQIi+pm
         R6D5/bu8qQ72Nb0Kc40hepjA5gFwGzKEaahKNrhGv9JOs4ifotFhw6RPe1ncqQ+74byx
         P45A==
X-Gm-Message-State: AOAM532gWy9V0UuhQGFFJVBulXGb+uae8MZpDqDo5CuJFE/8zauqc5dT
	bxdsyspSJLfm0Np0swpOC+Q=
X-Google-Smtp-Source: ABdhPJxP2J4m4viJm4yvkZ9qe6fIRUzeNEmfdELxUHqjlpphHjOYr3K3Uw7Ec+9nHJu+qwWQYLy1uQ==
X-Received: by 2002:a37:a04e:: with SMTP id j75mr9634827qke.98.1631876672732;
        Fri, 17 Sep 2021 04:04:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1e06:: with SMTP id n6ls6735037qtl.9.gmail; Fri, 17 Sep
 2021 04:04:32 -0700 (PDT)
X-Received: by 2002:a05:622a:1a24:: with SMTP id f36mr9793407qtb.294.1631876672187;
        Fri, 17 Sep 2021 04:04:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631876672; cv=none;
        d=google.com; s=arc-20160816;
        b=J4V4Pn/kvdizoXXiSGkRSEkT0UJhyHJLQJw/SAwLadSZGe3e80p1Q6gJqnKXmqJnmV
         CIwXNOerDpnz2YbUZP3wi6u2IlcLXiE6e6muDEM27r5p5u61cj6jJkv9AWt57U6ElYmT
         p3PD1n+tcRPMS06/A+XGoFOZg1w65yNgZSz8BiRLjoNu9iaOCScwL5j6tItGSVnWZKJS
         WXH6TU/AqFCD2a7nyogzqhPYcAtNN7TSJ2V6aB5s4lN4lpRJhFFDH53jgVVfmDFJpzW9
         k5YMiaYScDnnBMTJb0nid60vD8Rd5heoDvN43+wbPUxVhru9wRIfUKF4Tgz5YC+yPSiy
         YhNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZsW5kPocZcxB329voa1FeRViMqD2LaT+HDfOLYt3vUc=;
        b=DYp6Othl0e3wXlEoPwattM7Eey5AGYDV8dqOMKl4Bu0o+guwPA4sJLRqdlvNm4Krts
         tp36oynYB9AOEmi2Y16jzIAKAvrC2qMRdBhwGHy/3oDYkSdsJYJJtfaJlU2MiVlMtIWV
         igav8kWin4z7y7BgHpRED68EOaFRgqZ/gn4xpSiFAopQUc5IkFlW7IonWU4bHPhBd7FK
         wd6b0/CKv7Ncdmju1xsGfKfPs07NJXm92X1T7vHx3MUPbvfSEpvhxn5Jc4U/RSI/v97y
         1cx6BHCjrBCetJOl69I5djFuam2lbJrHHbuQ+DzVISTy5dytWnqbmktmI0vL+TPoEOPN
         xqLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kKWaEJBP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id b125si688140qkf.0.2021.09.17.04.04.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 04:04:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id j66so13398762oih.12
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 04:04:32 -0700 (PDT)
X-Received: by 2002:a05:6808:21a5:: with SMTP id be37mr3470073oib.172.1631876671347;
 Fri, 17 Sep 2021 04:04:31 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d6b66705cb2fffd4@google.com> <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
In-Reply-To: <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 13:04:19 +0200
Message-ID: <CANpmjNMq=2zjDYJgGvHcsjnPNOpR=nj-gQ43hk2mJga0ES+wzQ@mail.gmail.com>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in kvm_fastop_exception
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk, 
	"the arch/x86 maintainers" <x86@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kKWaEJBP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 17 Sept 2021 at 12:01, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, 4 Sept 2021 at 20:58, syzbot
> <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com> wrote:
> >
> > Hello,
> >
> > syzbot found the following issue on:
> >
> > HEAD commit:    835d31d319d9 Merge tag 'media/v5.15-1' of git://git.kernel..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=1189fe49300000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=d1a7a34dc082816f
> > dashboard link: https://syzkaller.appspot.com/bug?extid=d08efd12a2905a344291
> > compiler:       gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.1
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com
> >
> > ==================================================================
> > BUG: KFENCE: use-after-free read in kvm_fastop_exception+0xf6d/0x105b
> >
> > Use-after-free read at 0xffff88823bc0c020 (in kfence-#5):
> >  kvm_fastop_exception+0xf6d/0x105b
>
> There is probably some bug in d_lookup, but there is also something
> wrong with the unwinder. It prints an unrelated kvm_fastop_exception
> frame instead of __d_lookup and interestingly a very similar thing
> happens on arm64 with HWASAN and a similar bug in d_lookup. The
> corresponding report is:
> https://syzkaller.appspot.com/bug?extid=488ddf8087564d6de6e2
>
> BUG: KASAN: invalid-access in __entry_tramp_text_end+0xddc/0xd000
> CPU: 0 PID: 22 Comm: kdevtmpfs Not tainted
> 5.14.0-syzkaller-11152-g78e709522d2c #0
> Hardware name: linux,dummy-virt (DT)
> Call trace:
>  dump_backtrace+0x0/0x1ac arch/arm64/kernel/stacktrace.c:76
>  show_stack+0x18/0x24 arch/arm64/kernel/stacktrace.c:215
>  __dump_stack lib/dump_stack.c:88 [inline]
>  dump_stack_lvl+0x68/0x84 lib/dump_stack.c:106
>  print_address_description+0x7c/0x2b4 mm/kasan/report.c:256
>  __kasan_report mm/kasan/report.c:442 [inline]
>  kasan_report+0x134/0x380 mm/kasan/report.c:459
>  __do_kernel_fault+0x128/0x1bc arch/arm64/mm/fault.c:317
>  do_bad_area arch/arm64/mm/fault.c:466 [inline]
>  do_tag_check_fault+0x74/0x90 arch/arm64/mm/fault.c:737
>  do_mem_abort+0x44/0xb4 arch/arm64/mm/fault.c:813
>  el1_abort+0x40/0x60 arch/arm64/kernel/entry-common.c:357
>  el1h_64_sync_handler+0xb0/0xd0 arch/arm64/kernel/entry-common.c:408
>  el1h_64_sync+0x78/0x7c arch/arm64/kernel/entry.S:567
>  __entry_tramp_text_end+0xddc/0xd000
>  d_lookup+0x44/0x70 fs/dcache.c:2370
>  lookup_dcache+0x24/0x84 fs/namei.c:1520
>  __lookup_hash+0x24/0xd0 fs/namei.c:1543
>  kern_path_locked+0x90/0x10c fs/namei.c:2567
>  handle_remove+0x38/0x284 drivers/base/devtmpfs.c:312
>  handle drivers/base/devtmpfs.c:382 [inline]
>  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
>  devtmpfsd+0x8c/0xd0 drivers/base/devtmpfs.c:437
>  kthread+0x150/0x15c kernel/kthread.c:319
>  ret_from_fork+0x10/0x20 arch/arm64/kernel/entry.S:756
>
> Here kernel unwinder prints __entry_tramp_text_end instead of __d_lookup.
>
> I've looked in more detail into the arm64 case:
> d_lookup contains a static call to __d_lookup as expected:
>
> ffff8000102e0780 <d_lookup>:
> ...
> ffff8000102e07c0: 97ffffa4 bl ffff8000102e0650 <__d_lookup>
> ...
> ffff8000102e07e8: d65f03c0 ret
>
> and these symbols don't overlap or something:
>
> $ aarch64-linux-gnu-nm -nS vmlinux | egrep -C 1 " (t|T)
> (__entry_tramp_text|__d_lookup)"
> ffff8000102e01f0 0000000000000458 T d_alloc_parallel
> ffff8000102e0650 0000000000000128 T __d_lookup
> ffff8000102e0780 000000000000006c T d_lookup
> --
> ffff8000117a1f88 T __hibernate_exit_text_end
> ffff8000117a2000 T __entry_tramp_text_start
> ffff8000117a2000 00000000000007c8 T tramp_vectors
> --
> ffff8000117a27f0 0000000000000024 T tramp_exit_compat
> ffff8000117a3000 T __entry_tramp_text_end
> ffff8000117b0000 D _etext
>
> So it looks like in both cases the top fault frame is just wrong. But
> I would assume it's extracted by arch-dependent code, so it's
> suspicious that it affects both x86 and arm64...
>
> Any ideas what's happening?

My suspicion for the x86 case is that kvm_fastop_exception is related
to instruction emulation and the fault occurs in an emulated
instruction?

But I can't explain the arm64 case.

> >  d_lookup+0xd8/0x170 fs/dcache.c:2370
> >  lookup_dcache+0x1e/0x130 fs/namei.c:1520
> >  __lookup_hash+0x29/0x180 fs/namei.c:1543
> >  kern_path_locked+0x17e/0x320 fs/namei.c:2567
> >  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
> >  handle drivers/base/devtmpfs.c:382 [inline]
> >  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
> >  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
> >  kthread+0x3e5/0x4d0 kernel/kthread.c:319
> >  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
> >
> > kfence-#5 [0xffff88823bc0c000-0xffff88823bc0cfff, size=4096, cache=names_cache] allocated by task 22:
> >  getname_kernel+0x4e/0x370 fs/namei.c:226
> >  kern_path_locked+0x71/0x320 fs/namei.c:2558
> >  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
> >  handle drivers/base/devtmpfs.c:382 [inline]
> >  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
> >  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
> >  kthread+0x3e5/0x4d0 kernel/kthread.c:319
> >  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
> >
> > freed by task 22:
> >  putname.part.0+0xe1/0x120 fs/namei.c:270
> >  putname include/linux/err.h:41 [inline]
> >  filename_parentat fs/namei.c:2547 [inline]
> >  kern_path_locked+0xc2/0x320 fs/namei.c:2558
> >  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
> >  handle drivers/base/devtmpfs.c:382 [inline]
> >  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
> >  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
> >  kthread+0x3e5/0x4d0 kernel/kthread.c:319
> >  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
> >
> > CPU: 1 PID: 22 Comm: kdevtmpfs Not tainted 5.14.0-syzkaller #0
> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> > RIP: 0010:kvm_fastop_exception+0xf6d/0x105b
> > Code: d3 ed e9 14 1b 6d f8 49 8d 0e 48 83 e1 f8 4c 8b 21 41 8d 0e 83 e1 07 c1 e1 03 49 d3 ec e9 6a 28 6d f8 49 8d 4d 00 48 83 e1 f8 <4c> 8b 21 41 8d 4d 00 83 e1 07 c1 e1 03 49 d3 ec e9 5a 32 6d f8 bd
> > RSP: 0018:ffffc90000fe7ae8 EFLAGS: 00010282
> > RAX: 0000000035736376 RBX: ffff88803b141cc0 RCX: ffff88823bc0c020
> > RDX: ffffed100762839f RSI: 0000000000000004 RDI: 0000000000000007
> > RBP: 0000000000000004 R08: 0000000000000000 R09: ffff88803b141cf0
> > R10: ffffed100762839e R11: 0000000000000000 R12: ffff88823bc0c020
> > R13: ffff88823bc0c020 R14: ffff88803b141cf0 R15: dffffc0000000000
> > FS:  0000000000000000(0000) GS:ffff8880b9d00000(0000) knlGS:0000000000000000
> > CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > CR2: ffff88823bc0c020 CR3: 0000000029892000 CR4: 00000000001506e0
> > DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> > DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> > Call Trace:
> >  d_lookup+0xd8/0x170 fs/dcache.c:2370
> >  lookup_dcache+0x1e/0x130 fs/namei.c:1520
> >  __lookup_hash+0x29/0x180 fs/namei.c:1543
> >  kern_path_locked+0x17e/0x320 fs/namei.c:2567
> >  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
> >  handle drivers/base/devtmpfs.c:382 [inline]
> >  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
> >  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
> >  kthread+0x3e5/0x4d0 kernel/kthread.c:319
> >  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
> > ==================================================================
> > ----------------
> > Code disassembly (best guess):
> >    0:   d3 ed                   shr    %cl,%ebp
> >    2:   e9 14 1b 6d f8          jmpq   0xf86d1b1b
> >    7:   49 8d 0e                lea    (%r14),%rcx
> >    a:   48 83 e1 f8             and    $0xfffffffffffffff8,%rcx
> >    e:   4c 8b 21                mov    (%rcx),%r12
> >   11:   41 8d 0e                lea    (%r14),%ecx
> >   14:   83 e1 07                and    $0x7,%ecx
> >   17:   c1 e1 03                shl    $0x3,%ecx
> >   1a:   49 d3 ec                shr    %cl,%r12
> >   1d:   e9 6a 28 6d f8          jmpq   0xf86d288c
> >   22:   49 8d 4d 00             lea    0x0(%r13),%rcx
> >   26:   48 83 e1 f8             and    $0xfffffffffffffff8,%rcx
> > * 2a:   4c 8b 21                mov    (%rcx),%r12 <-- trapping instruction
> >   2d:   41 8d 4d 00             lea    0x0(%r13),%ecx
> >   31:   83 e1 07                and    $0x7,%ecx
> >   34:   c1 e1 03                shl    $0x3,%ecx
> >   37:   49 d3 ec                shr    %cl,%r12
> >   3a:   e9 5a 32 6d f8          jmpq   0xf86d3299
> >   3f:   bd                      .byte 0xbd
> >
> >
> > ---
> > This report is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this issue. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMq%3D2zjDYJgGvHcsjnPNOpR%3Dnj-gQ43hk2mJga0ES%2BwzQ%40mail.gmail.com.
