Return-Path: <kasan-dev+bncBCMIZB7QWENRBXGOSGFAMGQEY7CUSPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BAC240F573
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 12:01:02 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id z18-20020a9d71d2000000b0053b1b34084bsf39019763otj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 03:01:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631872861; cv=pass;
        d=google.com; s=arc-20160816;
        b=PQNzbf3EG3DHTcp7G5C0DYNhFWTyIJYWYe5THXKF7iR3lw83OBowcni3hUkOoX2meF
         XW2BnGDBh2klVVZ+EFUYYVQTP1O58geuP4kZOcHFO3B/RacIOqQxks3WEzITsnLBbz4K
         zPhKyJkm5KqiEwxmUc5DFTDjqqFzppItBfY4A0ZwXa48PZNdB+Vll+dHUW36PGcdr7S7
         liu7yOwkB16fCd8W9x3O1h6LgrFqrmWdvdKd5yZ7galcEqtAlAIpTHAef0Vqp9Axdogx
         /dH3PNHnRQanaAzYNhvYS25sdqhqx7qtWgt3CX2x4jzNPOYaRhxDDb2A8+k1kbKnl0cF
         As/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aDCShA8Yh8scYZmNzvY5W2/h9XADaOPpkF+7akUhH/I=;
        b=MxxyP/DVPuGos9oZDBWQbv5sSEEjh7dtrvTh7KYgaKM5CgPjpl/TbzN9wSh4gIHwxN
         Y5da7UjeWL7JwuXUNaq2mcWEvX+bcSrZ6KIgs58IYRvdJqCaY4GggY3WUJqLSmxxK6tX
         D9w88JoHd6FSfpQV0RSeIRoj3PQOkDMvJjZoB2uYHWDdQRSCmbBdhvUEjh6Q7J+tC/dn
         awo+uatOUBN9+/U2LL3pAGyi693/BVnTvD6XVf9gl/PeM4VTCNR2yKc+t0wZejKTWKIo
         drzS9RwCYugh5PxpdsoJYIcI/l4SWfi1N8sumzJ27ggqKErXvOacFZi8Ys4BvhJ/C8Jp
         ZqPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HJoQ9Ktz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aDCShA8Yh8scYZmNzvY5W2/h9XADaOPpkF+7akUhH/I=;
        b=Kl+h5wAwMQ71UYXkkMjpovXUKXj5r5wJKR54uvadCifYPZFO/vQhwHtNDzK1cyqber
         0+lbPzzSZFdrIx1CaINQvivhtO+VhycttRjpOMwFJ3YuUZgvWQ56tROCkvxFYHXKw8hx
         nCj4oxDuCeuJlBcTX7HZkfDkyL0ZFnp2ktQ4J2gmygnyR3OA3kEx5s0Kr+NDsxIOujV7
         Y/cHuMq+4ZmFrH1IWbnw40bbb4kx+Ney2RfbcYSSmEpY8+2Jzp2+IvO8TV7nSzxQwqAd
         MNhef7HdKGZPpHKgmo8ZB0nXKjWUsQFN1F1afXWxA/Tx2l0As1yME7NW1FiT4IF/PEne
         i75g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aDCShA8Yh8scYZmNzvY5W2/h9XADaOPpkF+7akUhH/I=;
        b=hyB1j72NkgytN223ialTS9rVlKvMDRZ7ZT1Rs/zRC7zxVaxq9ciT5PBOxVZf2/jm11
         FngkZGRTymPNkRKGMByw7sPVPr3GBMHGgsxCbfzzReNtRABWL+mXoL7uqKmczwxABLON
         JnDRcalbbUrnDQ8Nt/HrvHe8x5Kz4nn4zwDzboPrE0oDE/Vjemfh8xrEj1VI7qp8IXyW
         m81yDwjwzOmtzdAIOfNDibvVq2t67WkS+w/hbM1CpgEXNkZqXuz2nK6f41mnSY6x7PG3
         eIsdraKzi6ZIfjrhESOXyQvM+he5ircOtAa4B4SGQaPHvguMkr7KJ7BTOfXkTUsYqVc0
         itig==
X-Gm-Message-State: AOAM531J0uEYPoKII3Ccs8W/CYJEQrSzPogwB7wvC9BpSprRw4f4aGEc
	ZDzEMZ852rCuULmpb8jMncU=
X-Google-Smtp-Source: ABdhPJz95k66qYDw8raEhn+/fhql7wnF0/IDMz1MQmy5iP/O9kvJjpp7vCVkqyCJzdv6JcJvRNyeOw==
X-Received: by 2002:a54:4e94:: with SMTP id c20mr3293601oiy.57.1631872860502;
        Fri, 17 Sep 2021 03:01:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2442:: with SMTP id x2ls2894788otr.3.gmail; Fri, 17
 Sep 2021 03:01:00 -0700 (PDT)
X-Received: by 2002:a9d:4e0f:: with SMTP id p15mr8853463otf.328.1631872860124;
        Fri, 17 Sep 2021 03:01:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631872860; cv=none;
        d=google.com; s=arc-20160816;
        b=F5RTMGSx62Eac9SM9BlT2XYOMi3p+M1J9UXvr9fIOyHZImRhWttLkX5Nmd1v4HAAGu
         L3esqQP8tW1lSH0Q2qwG2EyCGA6dNZTzknJTUodePzwBjVtcxc1sJoAKwS6vr0/sRvmC
         /p0+jexwjAM2EyNBTZ8f1EbuFKuD3chPkYhXiVBY3CE1gwSYj175MoGjgt4QWvtWLb+/
         chit6nXLyobg4dbl1hRvQ+bGfIGfLnLxah7X9w1hL/GKi7d7/2eM/6KG6EVZCBjuFcP+
         eV/iUkNWpzFOd5ZhQqSvil1NEt8GMIF3KayqOnsjHyEsIVmjm/J/85udoVdaQzQiiOi2
         17MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QQGUIYGa72lvZ1fJnt/dZhyGt1NzDN7NWR4yTDfiT5Y=;
        b=glCKQuJRKJHuM771NCdXqugWgdQoK2Qy0yx4MMreIYTji9eO5d1NHFJlZk4osO85OU
         CUoIvZ7CfglJ2oEsYhWiBTt0Xi3yB5uzmnbysrMWQh9B+E7TmsKdspjqPIXLUc3oUQd9
         Ymuw3BfI5DKvAgCarDyHxYd7g/a/R/R9y6wSksQkJ5Xu/QBxvQv5xG40vZ+xa95M6V4N
         1xffxo3PxVGDNEaYznz+/JKbTep2hQrnBIC01QZ6Tdvex88tWpdZoRASk9mI++h8U/lQ
         FbqpLvaK/3H9+S/qxB3508XgSqR56zP6sFmU2+omZM9RqIbG761MR6JNqcneXCRvshhZ
         EuSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HJoQ9Ktz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id h24si714187otk.1.2021.09.17.03.01.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 03:01:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id n2-20020a9d6f02000000b0054455dae485so6898997otq.3
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 03:01:00 -0700 (PDT)
X-Received: by 2002:a05:6830:78c:: with SMTP id w12mr8607355ots.196.1631872859431;
 Fri, 17 Sep 2021 03:00:59 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d6b66705cb2fffd4@google.com>
In-Reply-To: <000000000000d6b66705cb2fffd4@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 12:00:48 +0200
Message-ID: <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in kvm_fastop_exception
To: syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>
Cc: linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk, 
	"the arch/x86 maintainers" <x86@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HJoQ9Ktz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::336
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

On Sat, 4 Sept 2021 at 20:58, syzbot
<syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following issue on:
>
> HEAD commit:    835d31d319d9 Merge tag 'media/v5.15-1' of git://git.kernel..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=1189fe49300000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=d1a7a34dc082816f
> dashboard link: https://syzkaller.appspot.com/bug?extid=d08efd12a2905a344291
> compiler:       gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.1
>
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com
>
> ==================================================================
> BUG: KFENCE: use-after-free read in kvm_fastop_exception+0xf6d/0x105b
>
> Use-after-free read at 0xffff88823bc0c020 (in kfence-#5):
>  kvm_fastop_exception+0xf6d/0x105b

There is probably some bug in d_lookup, but there is also something
wrong with the unwinder. It prints an unrelated kvm_fastop_exception
frame instead of __d_lookup and interestingly a very similar thing
happens on arm64 with HWASAN and a similar bug in d_lookup. The
corresponding report is:
https://syzkaller.appspot.com/bug?extid=488ddf8087564d6de6e2

BUG: KASAN: invalid-access in __entry_tramp_text_end+0xddc/0xd000
CPU: 0 PID: 22 Comm: kdevtmpfs Not tainted
5.14.0-syzkaller-11152-g78e709522d2c #0
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x1ac arch/arm64/kernel/stacktrace.c:76
 show_stack+0x18/0x24 arch/arm64/kernel/stacktrace.c:215
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x68/0x84 lib/dump_stack.c:106
 print_address_description+0x7c/0x2b4 mm/kasan/report.c:256
 __kasan_report mm/kasan/report.c:442 [inline]
 kasan_report+0x134/0x380 mm/kasan/report.c:459
 __do_kernel_fault+0x128/0x1bc arch/arm64/mm/fault.c:317
 do_bad_area arch/arm64/mm/fault.c:466 [inline]
 do_tag_check_fault+0x74/0x90 arch/arm64/mm/fault.c:737
 do_mem_abort+0x44/0xb4 arch/arm64/mm/fault.c:813
 el1_abort+0x40/0x60 arch/arm64/kernel/entry-common.c:357
 el1h_64_sync_handler+0xb0/0xd0 arch/arm64/kernel/entry-common.c:408
 el1h_64_sync+0x78/0x7c arch/arm64/kernel/entry.S:567
 __entry_tramp_text_end+0xddc/0xd000
 d_lookup+0x44/0x70 fs/dcache.c:2370
 lookup_dcache+0x24/0x84 fs/namei.c:1520
 __lookup_hash+0x24/0xd0 fs/namei.c:1543
 kern_path_locked+0x90/0x10c fs/namei.c:2567
 handle_remove+0x38/0x284 drivers/base/devtmpfs.c:312
 handle drivers/base/devtmpfs.c:382 [inline]
 devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
 devtmpfsd+0x8c/0xd0 drivers/base/devtmpfs.c:437
 kthread+0x150/0x15c kernel/kthread.c:319
 ret_from_fork+0x10/0x20 arch/arm64/kernel/entry.S:756

Here kernel unwinder prints __entry_tramp_text_end instead of __d_lookup.

I've looked in more detail into the arm64 case:
d_lookup contains a static call to __d_lookup as expected:

ffff8000102e0780 <d_lookup>:
...
ffff8000102e07c0: 97ffffa4 bl ffff8000102e0650 <__d_lookup>
...
ffff8000102e07e8: d65f03c0 ret

and these symbols don't overlap or something:

$ aarch64-linux-gnu-nm -nS vmlinux | egrep -C 1 " (t|T)
(__entry_tramp_text|__d_lookup)"
ffff8000102e01f0 0000000000000458 T d_alloc_parallel
ffff8000102e0650 0000000000000128 T __d_lookup
ffff8000102e0780 000000000000006c T d_lookup
--
ffff8000117a1f88 T __hibernate_exit_text_end
ffff8000117a2000 T __entry_tramp_text_start
ffff8000117a2000 00000000000007c8 T tramp_vectors
--
ffff8000117a27f0 0000000000000024 T tramp_exit_compat
ffff8000117a3000 T __entry_tramp_text_end
ffff8000117b0000 D _etext

So it looks like in both cases the top fault frame is just wrong. But
I would assume it's extracted by arch-dependent code, so it's
suspicious that it affects both x86 and arm64...

Any ideas what's happening?



>  d_lookup+0xd8/0x170 fs/dcache.c:2370
>  lookup_dcache+0x1e/0x130 fs/namei.c:1520
>  __lookup_hash+0x29/0x180 fs/namei.c:1543
>  kern_path_locked+0x17e/0x320 fs/namei.c:2567
>  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
>  handle drivers/base/devtmpfs.c:382 [inline]
>  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
>  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
>  kthread+0x3e5/0x4d0 kernel/kthread.c:319
>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
>
> kfence-#5 [0xffff88823bc0c000-0xffff88823bc0cfff, size=4096, cache=names_cache] allocated by task 22:
>  getname_kernel+0x4e/0x370 fs/namei.c:226
>  kern_path_locked+0x71/0x320 fs/namei.c:2558
>  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
>  handle drivers/base/devtmpfs.c:382 [inline]
>  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
>  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
>  kthread+0x3e5/0x4d0 kernel/kthread.c:319
>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
>
> freed by task 22:
>  putname.part.0+0xe1/0x120 fs/namei.c:270
>  putname include/linux/err.h:41 [inline]
>  filename_parentat fs/namei.c:2547 [inline]
>  kern_path_locked+0xc2/0x320 fs/namei.c:2558
>  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
>  handle drivers/base/devtmpfs.c:382 [inline]
>  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
>  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
>  kthread+0x3e5/0x4d0 kernel/kthread.c:319
>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
>
> CPU: 1 PID: 22 Comm: kdevtmpfs Not tainted 5.14.0-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> RIP: 0010:kvm_fastop_exception+0xf6d/0x105b
> Code: d3 ed e9 14 1b 6d f8 49 8d 0e 48 83 e1 f8 4c 8b 21 41 8d 0e 83 e1 07 c1 e1 03 49 d3 ec e9 6a 28 6d f8 49 8d 4d 00 48 83 e1 f8 <4c> 8b 21 41 8d 4d 00 83 e1 07 c1 e1 03 49 d3 ec e9 5a 32 6d f8 bd
> RSP: 0018:ffffc90000fe7ae8 EFLAGS: 00010282
> RAX: 0000000035736376 RBX: ffff88803b141cc0 RCX: ffff88823bc0c020
> RDX: ffffed100762839f RSI: 0000000000000004 RDI: 0000000000000007
> RBP: 0000000000000004 R08: 0000000000000000 R09: ffff88803b141cf0
> R10: ffffed100762839e R11: 0000000000000000 R12: ffff88823bc0c020
> R13: ffff88823bc0c020 R14: ffff88803b141cf0 R15: dffffc0000000000
> FS:  0000000000000000(0000) GS:ffff8880b9d00000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: ffff88823bc0c020 CR3: 0000000029892000 CR4: 00000000001506e0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>  d_lookup+0xd8/0x170 fs/dcache.c:2370
>  lookup_dcache+0x1e/0x130 fs/namei.c:1520
>  __lookup_hash+0x29/0x180 fs/namei.c:1543
>  kern_path_locked+0x17e/0x320 fs/namei.c:2567
>  handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
>  handle drivers/base/devtmpfs.c:382 [inline]
>  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
>  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
>  kthread+0x3e5/0x4d0 kernel/kthread.c:319
>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
> ==================================================================
> ----------------
> Code disassembly (best guess):
>    0:   d3 ed                   shr    %cl,%ebp
>    2:   e9 14 1b 6d f8          jmpq   0xf86d1b1b
>    7:   49 8d 0e                lea    (%r14),%rcx
>    a:   48 83 e1 f8             and    $0xfffffffffffffff8,%rcx
>    e:   4c 8b 21                mov    (%rcx),%r12
>   11:   41 8d 0e                lea    (%r14),%ecx
>   14:   83 e1 07                and    $0x7,%ecx
>   17:   c1 e1 03                shl    $0x3,%ecx
>   1a:   49 d3 ec                shr    %cl,%r12
>   1d:   e9 6a 28 6d f8          jmpq   0xf86d288c
>   22:   49 8d 4d 00             lea    0x0(%r13),%rcx
>   26:   48 83 e1 f8             and    $0xfffffffffffffff8,%rcx
> * 2a:   4c 8b 21                mov    (%rcx),%r12 <-- trapping instruction
>   2d:   41 8d 4d 00             lea    0x0(%r13),%ecx
>   31:   83 e1 07                and    $0x7,%ecx
>   34:   c1 e1 03                shl    $0x3,%ecx
>   37:   49 d3 ec                shr    %cl,%r12
>   3a:   e9 5a 32 6d f8          jmpq   0xf86d3299
>   3f:   bd                      .byte 0xbd
>
>
> ---
> This report is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this issue. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw%40mail.gmail.com.
