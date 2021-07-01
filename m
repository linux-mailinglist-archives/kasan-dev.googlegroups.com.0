Return-Path: <kasan-dev+bncBCMIZB7QWENRBOWF62DAMGQECXIXBMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DBDE3B90FF
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 13:10:51 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id t18-20020a056a001392b02903039eb2e663sf3842073pfg.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jul 2021 04:10:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625137850; cv=pass;
        d=google.com; s=arc-20160816;
        b=uSAqSfes+R8aMzpeXXhISPs/vcH5zQ097qmmzRKykI+Sa6/MIfzYG4BSEyLQDn6NCG
         VFoylUGBXPSUsN8Ycn9Xay6LuZCqMFe3TWH/fmeOTtkT1TN3Az5NzcYaFW7ybHEP/zz8
         XIJNt0GtcedV0wJIcyhQhVT6VyxEY2uxlMMEY1zPvPJxxTonivhhSR9wbakEEDM38bwZ
         Xi2eFQsAV7dbA3ptbQcZZFQ2hpvPlwMp9CpIH00MQR/l011t8Knn42ZFbrGBNnmVgwyy
         uvPkvtdhx2kFap2o69F93qcr0KZbEjU7DcSccyStuXwc4cRRQT4ETRQLpekmxwb3wUDn
         hy/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E54RU0AG0PTN2CeNtj/RIedqixfFGhZxDQha12kQxIs=;
        b=aykEYK2U3KxWYoEIJJHS3Ua/aEk9VP4xS9STy0Huiy11j6FP2XdZYQPGbsk+d65ECF
         gMLNf8drsRkziJH7XtQuNM5rGyrB9IFyYXtCdmt9m43cHehGtZ/UZqZ6ljE43AV+mPhl
         tm8deGDZwseluiBEi/Ke/g235Gs1XzdiQ+Tynx9ASEQRrTvZ2lTy9fOkRmg9QPL/yK4Z
         J5aiv1c0g5cHWX5iW4glBFgtdPESJjp0W76KKEIcwqpAVmSHtzyjyZeAComH57ScGNqj
         z6Ix08sIZ3Sk7tdQyil1n6Gvv6yU62CSedcMIx0CvResrCxHYVGAPdQ9YBaoTONECKAd
         XJUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ek+morMn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E54RU0AG0PTN2CeNtj/RIedqixfFGhZxDQha12kQxIs=;
        b=E+l5Jg7hQlnpCHR3vqR6pa4mYE4K96KvwiRIwYvQvextCGQHYVRS7NcoI2mMIfI74E
         zeZa/0CejEm92adG1Eo3hOTpnp+7rS/pJ1Fs+5quq1DYhZIb/bzYaOTPrXZcAOY0bhOn
         oL0I/UnvPkBn3phA8Bux4nA6LCeB7posxBwWkF6zOk2OvPacEMd8/rAk2UqPn1xBksnu
         SB+CGi8r4VboKhpIQH30+jxJV4TPvmfrjEpLwvyroSkdH48RaVxSCRDhDnEiqKwVnX/p
         nxDpUh2UMW7JRazi+3P/ORkbY90C1tXxufxGOx7aMHgUNTsjnc4tM6wU8RgazQwfuqOH
         m0QA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E54RU0AG0PTN2CeNtj/RIedqixfFGhZxDQha12kQxIs=;
        b=AR3TXnpkbjU5Qf0wq5xLCCYMiqVbDlvkFPKzbVBU5M7oq2tOeNswtg5VsY50UCOa1i
         a5o/WwhhkRPxToRZWYtnbVTu4mvv5uv1XRlTvshGOrCjQXuUXDcHtg70RSbPHFAV3OAJ
         3yEyklIqXqaBplFomSPV+IcVM3vY6BbZieZA3Gcput1WMISaSG6EWXadlpr3RWuT+v00
         wGU8QNry1PxiDG4gPKgj3eSAI9rwjRYtbZffIOpvSbqX+KZ6ctMKVSfGUd/3E4g+Sxy4
         Bbgk2/4mqwVfVaFc5rd4CJseJaJ49NKc7Ek2fFqf6UKFBxuXH9Z+3sIvLTdIq5kDJ6yE
         VqEw==
X-Gm-Message-State: AOAM531mSPKuiz/R+NmZM9Ce9K3mUM0j/nZ0iNfE/QeOlU3chsapbYWd
	Ia776LeP4Pt4C2dzx1E7AVM=
X-Google-Smtp-Source: ABdhPJx9flNKciDGzbB5dqxtnT+i5aC5bkzk+Kgybsi0tkf2lodLOk0aJLtDjaulWFF3qt7FP++erQ==
X-Received: by 2002:a63:1e1f:: with SMTP id e31mr9051746pge.44.1625137850109;
        Thu, 01 Jul 2021 04:10:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1946:: with SMTP id s6ls2865309pfk.8.gmail; Thu, 01
 Jul 2021 04:10:49 -0700 (PDT)
X-Received: by 2002:a63:f348:: with SMTP id t8mr2090166pgj.23.1625137849498;
        Thu, 01 Jul 2021 04:10:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625137849; cv=none;
        d=google.com; s=arc-20160816;
        b=daoKqqUkqPkHDV4uxA9kPfEuyOwGfMtyFI4cCBauV0HyiAGkBmqj9su3t3HrOU4YQ1
         mv8P5G7UhMLInqvTjphcN7iRACzpgLj/IybQKcfMgT90a69DniPghTsT9ZWWlUK8Q3d5
         G4hxN1omwZ592L3tE410a0FDD3RxnXX7RpznN9QiPCUQXKpJgRPh4oDTYU6qxXxog1Fd
         s7SeY44ef2wG/WpjFiFaS31rRBWiPxzvCi/+L93LeSeAR018Z5Bd5Nf9NfrWYPhSy7+t
         YLuF7/UkqM9mVTrl4mGvv1dnzyDY6wMi7ckIUiO2atL1erRHpA03xm12RQxwvha2cue4
         GtIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=loo3kxtDTTKC5s2MMEWFo7j8wTG4bg5yCpaYGdH8riY=;
        b=bi7KYPlCQEFHGXxk1GpzlDNUwgV+63wteaybHpRGaspAkaIWKoTgT0kbD7OcseXgT+
         yQvXONxLVMe+eUEgf8bcVLuCu7tbo4zkqbgw74dH+ndqj2agHGJy2lyS+r5yDT1jbyoj
         oSkruqxhCuEiA/5SLGEe3i9EBHd6795RHxaWJkCbXhgrwXvGnU7yw/bg0nvFEsOO6bg3
         u7Iy9eqLPWJ00v+j8OD4eIB2kfyE0i91WWn0PvZF9+Mj4NiWXNm3Obmn+npzpqTMRlsx
         4vFUdmxswyLcIuZx6NlAWEpNt653Z+3cBT50UAieKROZUaLagPo2qFp2psL2bPKwrQtm
         nYZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ek+morMn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id z18si1904205pfc.5.2021.07.01.04.10.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Jul 2021 04:10:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id f20so3789543qtk.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Jul 2021 04:10:49 -0700 (PDT)
X-Received: by 2002:a05:622a:15cc:: with SMTP id d12mr35964132qty.67.1625137848606;
 Thu, 01 Jul 2021 04:10:48 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000009e7f6405c60dbe3b@google.com>
In-Reply-To: <0000000000009e7f6405c60dbe3b@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Jul 2021 13:10:37 +0200
Message-ID: <CACT4Y+ZY4sOXQ0F5cumzpwo2V8TLN+kDAj=eAYWX4f5sqg993w@mail.gmail.com>
Subject: Re: [syzbot] upstream test error: BUG: sleeping function called from
 invalid context in stack_depot_save
To: syzbot <syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ek+morMn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835
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

On Thu, Jul 1, 2021 at 1:00 PM syzbot
<syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following issue on:
>
> HEAD commit:    dbe69e43 Merge tag 'net-next-5.14' of git://git.kernel.org..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=1216d478300000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=47e4697be2f5b985
> dashboard link: https://syzkaller.appspot.com/bug?extid=e45919db2eab5e837646
>
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com

+kasan-dev@ for for stack_depot_save warning

> BUG: sleeping function called from invalid context at mm/page_alloc.c:5179
> in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 8436, name: syz-fuzzer
> INFO: lockdep is turned off.
> irq event stamp: 0
> hardirqs last  enabled at (0): [<0000000000000000>] 0x0
> hardirqs last disabled at (0): [<ffffffff814406db>] copy_process+0x1e1b/0x74c0 kernel/fork.c:2061
> softirqs last  enabled at (0): [<ffffffff8144071c>] copy_process+0x1e5c/0x74c0 kernel/fork.c:2065
> softirqs last disabled at (0): [<0000000000000000>] 0x0
> CPU: 1 PID: 8436 Comm: syz-fuzzer Tainted: G        W         5.13.0-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> Call Trace:
>  __dump_stack lib/dump_stack.c:79 [inline]
>  dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:96
>  ___might_sleep.cold+0x1f1/0x237 kernel/sched/core.c:9153
>  prepare_alloc_pages+0x3da/0x580 mm/page_alloc.c:5179
>  __alloc_pages+0x12f/0x500 mm/page_alloc.c:5375
>  alloc_pages+0x18c/0x2a0 mm/mempolicy.c:2272
>  stack_depot_save+0x39d/0x4e0 lib/stackdepot.c:303
>  save_stack+0x15e/0x1e0 mm/page_owner.c:120
>  __set_page_owner+0x50/0x290 mm/page_owner.c:181
>  prep_new_page mm/page_alloc.c:2445 [inline]
>  __alloc_pages_bulk+0x8b9/0x1870 mm/page_alloc.c:5313
>  alloc_pages_bulk_array_node include/linux/gfp.h:557 [inline]
>  vm_area_alloc_pages mm/vmalloc.c:2775 [inline]
>  __vmalloc_area_node mm/vmalloc.c:2845 [inline]
>  __vmalloc_node_range+0x39d/0x960 mm/vmalloc.c:2947
>  __vmalloc_node mm/vmalloc.c:2996 [inline]
>  vzalloc+0x67/0x80 mm/vmalloc.c:3066
>  n_tty_open+0x16/0x170 drivers/tty/n_tty.c:1914
>  tty_ldisc_open+0x9b/0x110 drivers/tty/tty_ldisc.c:464
>  tty_ldisc_setup+0x43/0x100 drivers/tty/tty_ldisc.c:781
>  tty_init_dev.part.0+0x1f4/0x610 drivers/tty/tty_io.c:1461
>  tty_init_dev include/linux/err.h:36 [inline]
>  tty_open_by_driver drivers/tty/tty_io.c:2102 [inline]
>  tty_open+0xb16/0x1000 drivers/tty/tty_io.c:2150
>  chrdev_open+0x266/0x770 fs/char_dev.c:414
>  do_dentry_open+0x4c8/0x11c0 fs/open.c:826
>  do_open fs/namei.c:3361 [inline]
>  path_openat+0x1c0e/0x27e0 fs/namei.c:3494
>  do_filp_open+0x190/0x3d0 fs/namei.c:3521
>  do_sys_openat2+0x16d/0x420 fs/open.c:1195
>  do_sys_open fs/open.c:1211 [inline]
>  __do_sys_openat fs/open.c:1227 [inline]
>  __se_sys_openat fs/open.c:1222 [inline]
>  __x64_sys_openat+0x13f/0x1f0 fs/open.c:1222
>  do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>  do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
>  entry_SYSCALL_64_after_hwframe+0x44/0xae
> RIP: 0033:0x4af20a
> Code: e8 3b 82 fb ff 48 8b 7c 24 10 48 8b 74 24 18 48 8b 54 24 20 4c 8b 54 24 28 4c 8b 44 24 30 4c 8b 4c 24 38 48 8b 44 24 08 0f 05 <48> 3d 01 f0 ff ff 76 20 48 c7 44 24 40 ff ff ff ff 48 c7 44 24 48
> RSP: 002b:000000c0003293f8 EFLAGS: 00000216 ORIG_RAX: 0000000000000101
> RAX: ffffffffffffffda RBX: 000000c00001e800 RCX: 00000000004af20a
> RDX: 0000000000000000 RSI: 000000c0001a5a50 RDI: ffffffffffffff9c
> RBP: 000000c000329470 R08: 0000000000000000 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000216 R12: 00000000000001a6
> R13: 00000000000001a5 R14: 0000000000000200 R15: 000000c00029c280
> can: request_module (can-proto-0) failed.
> can: request_module (can-proto-0) failed.
> can: request_module (can-proto-0) failed.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZY4sOXQ0F5cumzpwo2V8TLN%2BkDAj%3DeAYWX4f5sqg993w%40mail.gmail.com.
