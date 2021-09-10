Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDMV5SEQMGQEDPGUIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E7AAA4067BC
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 09:34:38 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id q12-20020a05683033cc00b00521230773b1sf511229ott.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 00:34:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631259277; cv=pass;
        d=google.com; s=arc-20160816;
        b=o1VOsDACnSL/O1WBY0FjlWy5gHG2ljMcXu00Brtjkf32bTjbyWmNJtjKVyI9GBCO0K
         ssF5hlwPTYgSH6gEiMjV+OBb0KN7ngW4/Y0kUiehNEey0wcfm/jR1OKU6FQJQjvQKYl2
         66uAH4O7NOraO26kJjKczpl0U/GM2HIIlbVajV3IC5KT05hR5MWsdrNQsZjd5+kHFw0s
         qUlvqhgjGNP+S32gIRjaMOFtuVXRuhfQtEtepmBDrVn8Rw8DEnCpDMcXY+tPAkSWjJPH
         tE6Fd1oolx3BV1ehqIJfp0wWzRfoTuCxRtxRvdp6lxQaLyjD8yhMQ0Qd3fKevgZeM0gW
         J0iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aFgFIZFvhUia1LzMXgBQd28vBEA0u0pj4QQLcQT+IwA=;
        b=IHUBvMflGBsWXVWaExehNJPBsYu6cJCn/FPlWxP6i0PUN27XUPxaxxkIuEAMpVKUni
         jWCTzKFI2e+X3zAf4Kjwzp+MEUY0p7mhY6fo2OTzvGLf5sIJ5x/Igf5kCj/99HFE47Vk
         9hwPSGZkfnzKhJdolQgyvwv+V9sD/Dx/JIgK8WDIXGaq+Vw38ePJlxpCs9vryw63hBB3
         GEebA4TY0xV4LJy5zn7njXd+l3USTnvC2O/+MSQxXsCawpIc+6+2DOrxLA5j7lwG7FBL
         +kA5iq4VbdR1q5ZI2T5SkrN7LdRPYWcaI1FlJ//XZxBOJwZje3vzHNsusfq34M6/7tnJ
         RCgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oXHQEES4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aFgFIZFvhUia1LzMXgBQd28vBEA0u0pj4QQLcQT+IwA=;
        b=kBwXaZnkpRwmOJ8IS3tJdcvH3pToixM9z1sB7MlekNDPGUUsz2HWVRGqT0zgPfz9+l
         C+hbr/Ns12AGv5WwN0fGlEvjJUlhuH3oRzSOkucrpLD2UxV4Nhfs6CjrGn786+PtrxCZ
         ddRvaaeAwfKO7axoZcoQ4YVVmnmeXJQc9+AF/91RbmZQgAJBNLuFk7FUYX/odm4Mp9jd
         StUhpXuwoVw8bk/SX0zaApmSX1q2J5abxiUy4X+tNAbH4CeWfH/on0dPv4eeywY5Qion
         Mz4+lpDCQhTScUpgUv8Vv0yKUv3Iuee28bnxtG47ufz5zl+E/F1ucTGaipzPFD9L4G2q
         n3XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aFgFIZFvhUia1LzMXgBQd28vBEA0u0pj4QQLcQT+IwA=;
        b=w/Vr5Q4/nf4NAx0IkpujvOR54dTmYeKiLSFaKnYautuy1/JFyOq0OD8ILwD4Szypwu
         as801ZpOQOPgExQ484dYaJrtEscy93mo3f9SCkj/jiGjdb8lQGO5Ducer/XuOwr3WwGm
         xtbMrg/hwWXu2kmubX32oNKB4DrdCKPKws/og0grqTGLnODmfRdL9SIIAUHUBFAIhfAD
         59e50PvyZu6DjeLyhf1Hb7Sjp5vBMvA/ix5GWpDZ4/+/8NUp8hVWQIkwksDvfD4VivJr
         NzNX3UEZN0i2jutVH/nn83YA9V0nCqGT0ciD9oA5QpPC1cOcPR8R7xws1udusnXaM0tu
         4/5A==
X-Gm-Message-State: AOAM533al4P/44/IR2Ge9/VKWkH5cLCgWxhTzUAvvrS5uMCmR8JfEq38
	11FiOfgaOiXNNE8hbm/2QI8=
X-Google-Smtp-Source: ABdhPJzxe0L89Q5kOg3r/tBBZisFzlV76BjClyP+Xa8vT1sxvcSQXKNVs+QUFDPNK4VV19Sg1PN+dQ==
X-Received: by 2002:a9d:7111:: with SMTP id n17mr3400183otj.279.1631259277825;
        Fri, 10 Sep 2021 00:34:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1e87:: with SMTP id n7ls1315005otr.4.gmail; Fri, 10
 Sep 2021 00:34:37 -0700 (PDT)
X-Received: by 2002:a05:6830:44aa:: with SMTP id r42mr3445440otv.113.1631259277413;
        Fri, 10 Sep 2021 00:34:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631259277; cv=none;
        d=google.com; s=arc-20160816;
        b=R9vN77ge8ZJdZBqBPgvoGpfRFyBrxAfz8WjOABR9P0dOLU5prKhrlviOv6Hj3NfwZX
         n8yNjWwyizHJ5AWxvQCkF88oi6meGsouji8TYv9siy/5w6lGzRXE5RHVu3wA6zCwyfz2
         fafeJvJ7Vk6AUliEqEtTv6y16jvtG3jx3Do14zSB+MXV9xV4ylsP4iQC9jT45giHzJlP
         4envEsaxKn2Wr8zWgefW7Xf+dI8bowzw2lwHPmdVGZUHgswt132ByIa6KIlN+0g2FD8I
         W2qVq0FXzDMfmBX+sY8MKO4ROOOETkFohdsVv2VrEfTjOoAigq1DWawFYpCCI75Z5Ipr
         oGPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7VzJcLlZdw5d6SucUkv011Tx3+9MpvlSVesKT1t7kQ4=;
        b=adWvCi10CNIr0c7zdY368uawsfpK7C1O9VTl6ZDsUhwhzgBqUkafq5xvLCl4el6VmZ
         CadktzdSpDXP7/+9+zlYayF/XH9nWuMrvOTX7vk8TVRKhZBpGy8uKXa2pIUz0BFodbS6
         5xL08i3kC53gBz0H3bV2A+MoEyX2XU9AqA7SNokfFZ03uBvpDonpp1FtMNftVys5+Nox
         7tnTsO8EdAe+Ir2ZRP/m4R0whqsKceIRhZP7JsGExnpaUlNkHo0dZpRN+NQunnPPxCGr
         yHVEH9v2tPsD+h7xwtHD/on2Pqq732DCWTB5Fs/LUW2HJ/5fBWST/fZGFbiFA137c/D5
         kX3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oXHQEES4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id bf14si609231oib.0.2021.09.10.00.34.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Sep 2021 00:34:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id n27so1850643oij.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Sep 2021 00:34:37 -0700 (PDT)
X-Received: by 2002:aca:4344:: with SMTP id q65mr3175015oia.70.1631259276843;
 Fri, 10 Sep 2021 00:34:36 -0700 (PDT)
MIME-Version: 1.0
References: <00000000000071b5b105cb994728@google.com>
In-Reply-To: <00000000000071b5b105cb994728@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Sep 2021 09:34:25 +0200
Message-ID: <CANpmjNOuPyF4z28V=J=JjxV25QhY-vMtE+7OCZbweWFx01my3Q@mail.gmail.com>
Subject: Re: [syzbot] kernel panic: panic_on_warn set (3)
To: syzbot <syzbot+8d41ad9c88279d71f7c9@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, dvyukov@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzkaller-bugs@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oXHQEES4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as
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

#syz invalid

Corrupt report. (syzbot somehow failed to parse the report?)

Same use-after-free bug as this:
https://lore.kernel.org/all/000000000000d6b66705cb2fffd4@google.com/T/#u
which still seems unfixed...

On Fri, 10 Sept 2021 at 02:34, syzbot
<syzbot+8d41ad9c88279d71f7c9@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following issue on:
>
> HEAD commit:    ac08b1c68d1b Merge tag 'pci-v5.15-changes' of git://git.ke..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=16144a63300000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=16e23f04679ec35e
> dashboard link: https://syzkaller.appspot.com/bug?extid=8d41ad9c88279d71f7c9
> compiler:       gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.1
> userspace arch: i386
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=136aedb5300000
>
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+8d41ad9c88279d71f7c9@syzkaller.appspotmail.com
>
>  handle drivers/base/devtmpfs.c:382 [inline]
>  devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
>  devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
>  kthread+0x3e5/0x4d0 kernel/kthread.c:319
>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
> ==================================================================
> Kernel panic - not syncing: panic_on_warn set ...
> CPU: 0 PID: 22 Comm: kdevtmpfs Not tainted 5.14.0-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> Call Trace:
>  __dump_stack lib/dump_stack.c:88 [inline]
>  dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:105
>  panic+0x2b0/0x6dd kernel/panic.c:232
>  kfence_report_error.cold+0x304/0xa56 mm/kfence/report.c:264
>  kfence_handle_page_fault+0x203/0x630 mm/kfence/core.c:880
>  page_fault_oops+0x1c5/0x6b0 arch/x86/mm/fault.c:686
>  kernelmode_fixup_or_oops+0x219/0x280 arch/x86/mm/fault.c:755
>  __bad_area_nosemaphore+0x36d/0x400 arch/x86/mm/fault.c:801
>  do_kern_addr_fault+0x5b/0x70 arch/x86/mm/fault.c:1200
>  handle_page_fault arch/x86/mm/fault.c:1473 [inline]
>  exc_page_fault+0x155/0x180 arch/x86/mm/fault.c:1531
>  asm_exc_page_fault+0x1e/0x30 arch/x86/include/asm/idtentry.h:568
> RIP: 0010:kvm_fastop_exception+0xf6a/0x1058
> Code: d3 ed e9 ef d4 6e f8 49 8d 0e 48 83 e1 f8 4c 8b 21 41 8d 0e 83 e1 07 c1 e1 03 49 d3 ec e9 45 e2 6e f8 49 8d 4d 00 48 83 e1 f8 <4c> 8b 21 41 8d 4d 00 83 e1 07 c1 e1 03 49 d3 ec e9 35 ec 6e f8 bd
> RSP: 0018:ffffc90000dcfae8 EFLAGS: 00010282
> RAX: 0000003361736376 RBX: ffff88806f1e3068 RCX: ffff88823bd14020
> RDX: ffffed100de3c614 RSI: 0000000000000005 RDI: 0000000000000007
> RBP: 0000000000000005 R08: 0000000000000000 R09: ffff88806f1e3098
> R10: ffffed100de3c613 R11: 0000000000000000 R12: ffff88823bd14020
> R13: ffff88823bd14020 R14: ffff88806f1e3098 R15: dffffc0000000000
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
> Kernel Offset: disabled
> ----------------
> Code disassembly (best guess):
>    0:   d3 ed                   shr    %cl,%ebp
>    2:   e9 ef d4 6e f8          jmpq   0xf86ed4f6
>    7:   49 8d 0e                lea    (%r14),%rcx
>    a:   48 83 e1 f8             and    $0xfffffffffffffff8,%rcx
>    e:   4c 8b 21                mov    (%rcx),%r12
>   11:   41 8d 0e                lea    (%r14),%ecx
>   14:   83 e1 07                and    $0x7,%ecx
>   17:   c1 e1 03                shl    $0x3,%ecx
>   1a:   49 d3 ec                shr    %cl,%r12
>   1d:   e9 45 e2 6e f8          jmpq   0xf86ee267
>   22:   49 8d 4d 00             lea    0x0(%r13),%rcx
>   26:   48 83 e1 f8             and    $0xfffffffffffffff8,%rcx
> * 2a:   4c 8b 21                mov    (%rcx),%r12 <-- trapping instruction
>   2d:   41 8d 4d 00             lea    0x0(%r13),%ecx
>   31:   83 e1 07                and    $0x7,%ecx
>   34:   c1 e1 03                shl    $0x3,%ecx
>   37:   49 d3 ec                shr    %cl,%r12
>   3a:   e9 35 ec 6e f8          jmpq   0xf86eec74
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
> syzbot can test patches for this issue, for details see:
> https://goo.gl/tpsmEJ#testing-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOuPyF4z28V%3DJ%3DJjxV25QhY-vMtE%2B7OCZbweWFx01my3Q%40mail.gmail.com.
