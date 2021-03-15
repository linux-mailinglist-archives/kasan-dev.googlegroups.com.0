Return-Path: <kasan-dev+bncBCMIZB7QWENRBYUPXSBAMGQEHLN7UBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F33233ABFF
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 08:08:19 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id m14sf16599661pgr.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 00:08:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615792098; cv=pass;
        d=google.com; s=arc-20160816;
        b=vO3KJUzi6LVzjWepGfxc2wLcj2x9//S3onukq9FQVvPlp0WRk1169hh2CJ141gFxxK
         02WbIRjB+LK4hvgSE14lxFQZ0ClZjmJXnLAXqHx9Y9RYb+s0m/V/aEwb/YK/zxbdJ+II
         8ZaY+3eRzrkvj5rhsNn1QDSY7CgqvQ9gxWPOzjSQHUsLXAJVypV138aqqe8i4hJus/Wv
         9OSr0E5+y2HZs9vn0adVFg31ckc4SuQ51v5LecBsGEPhRbkX8ziai7pbuNUTXBVCKJmn
         /A4CVleDAnpii/muqILK8eThWvZ6pqXXAD7pXFX40jKbZUveTdRrXquqo3EmRJS/ry82
         KD7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tIxhyvHLFQUHTNr03w5XuAcP2lkt8scl7ZGxHOqA6i4=;
        b=ujzRxeeTFxlXKYVjyD+8sPvOmsytb37+QgEPLi8Q5MJSr3LcUR5hd3w8MYpL1DQ77u
         SVokDtMWOH0DgzQ+OAdxyPz72YEbczgYe8USITm6yQLeuuAH2G8krcoSTCcmw+xSIzNn
         gfban/nkZApGon6C8zvEZMm2gwINCzDRds5zTWDu01ObZdTSSZNOl2pgpF5fNjYINw5v
         aPsox/7nByMSPy4kjOAo2bf71GPjXZ+1LCjeJVTbDb8lPRJmCeg9UCbrUp5KSXVGgt3U
         ojJDmgvgRaAcjRxd5j0n9EDCKCggOkdC2dq+8nITZF8YaZRy7Ol2t/8BVVrcPxoHK3qI
         f5IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KEfEimh9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIxhyvHLFQUHTNr03w5XuAcP2lkt8scl7ZGxHOqA6i4=;
        b=qHd7LyMxYBuxL3TZCevforcisL3nQuV/hSJbnrpyawhiw2KTx56qVHs2OYFRxgkEJs
         iXOsboPuJ1HAiCaujhy1gEEhrQ9oYGf5yuTVGrxY1XsF2MFfldPwpUH4TzmIveXX3e5m
         uRRfjbU6WuD9NR+vuulYZkid7tU8IAwrXAQA0lrOMsK59yGtJLGDhp1/+jAXwBkZ5V+i
         KkxSHxw+NB+FPR0MFtQAU91pOApYmKATyFE5qtKSJKdP5NJ26Mms3WK9gkaEAp05znd3
         IxiuhWB5iTAeQYm5oz2xMIB1cugR+eqttwQidCfAreN6eICIyw7b2VE/lCePqNq69o5E
         yljQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIxhyvHLFQUHTNr03w5XuAcP2lkt8scl7ZGxHOqA6i4=;
        b=q9mgrxmJ0/1XkZ2QLZs3jX0kuoPMwO2dOS1OkEzmLaWHlpnuP+Xz69ULNsb5Sq/red
         bG5ZnUEkrhpxcsqfi5+LJCeGfoU5GGF0fI3zzGVPLIo4VscAbLtJYt9KTAFKdanEoBkY
         JvloADl0n2LepoWd+OuzRDAmEbFGH76VBLr5+ffmq5EyqAJfH8ZxY7hYb45WlC7XbgPP
         kXGxVZpGxXiVy6/5spv1T9Q7csf6LJZLJFRX8SUB+NSKNKtkZeP6fy5wAEObSDSGTvX8
         wakxK5ukenFiC2VALataS70hmrv9qEDJt2tIsNfxyPjMNWicXFPdFiTR/yR2II54vK6y
         o2Yg==
X-Gm-Message-State: AOAM5329ljwEEVnyi3I4D5I+dgoiHQUZrrosXfg7Jp7IOUMQCDRzSxjX
	MEsDfOyiRD59m3E1jSxd2d0=
X-Google-Smtp-Source: ABdhPJz/N7w5ZZIoA6gxctafWo13bsbeIVaKmPzZ9OkwT78wr7+/COSyCzl4YFwcW0jReh2A99Uk8A==
X-Received: by 2002:aa7:9521:0:b029:1f1:b27f:1a43 with SMTP id c1-20020aa795210000b02901f1b27f1a43mr9223758pfp.4.1615792098220;
        Mon, 15 Mar 2021 00:08:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c40a:: with SMTP id k10ls8287224plk.2.gmail; Mon, 15
 Mar 2021 00:08:17 -0700 (PDT)
X-Received: by 2002:a17:902:ee95:b029:e5:e2c7:5f76 with SMTP id a21-20020a170902ee95b02900e5e2c75f76mr10313745pld.25.1615792097755;
        Mon, 15 Mar 2021 00:08:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615792097; cv=none;
        d=google.com; s=arc-20160816;
        b=a0x2HphRQNjM8hJIZ+wBNNEbsoj8udi4h9c+cH3EJmqjawQl2vBg5+GNJD2E/CESL6
         3hQxOsjZz3MpoWi64WPo5kZv0mh2Yty/G/urTSczVBnEkchV/Zng0fc3q/a+edblZI0L
         2fhqVcpzgHtnvniPTjJarAJPjX7vlrFUiHEdnKn6byP8nYhwnlXob8jdyUssR+1inouO
         Rs7FpF670Koiy7rV0zuRpya3jjj1jJH0HzYVA2i/Fh89+1Z9lCB2iPveugp9V5dw7KmU
         AYO0o2GkLy5mEex+vlv9V/ui0cQ9FLm0Hqo/WbRqnvGGiiiX7re7hwiKq4f1Svh1xADL
         8Vew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f1GxjtXWQ8Nd14Ufajvp9SrNLduuTL53iMB054m6SMU=;
        b=mdK9qCA0N77uO+RJ5ayWpGBI7bDqVawYl7jEKAhTU3tlzBuP4N0kF3KTIkT3EQj2B/
         eiH6jxjoPmdKrIdeeDR6nFhsq7wr8htK3ezZke8gQgD4OTy2xtExzVwPJk6JtcOgLTlt
         fBFGNQ5tZ9piCRmQC/leHVujwGiDtOPkOeifGwSWuumHi7OiCABgTb2GMSnFeOSKO3cm
         Cjp4BWpilo5XUHuQI2yg0omvauRcKoCB4oYstfsdcpAJMGkZZYvwFYWpiq55in+Sb3Xo
         PG2X/VPgp+S/TRPfPf1+S7/XbrEgLphoVJof7sLR3x8m4DLEKlv7XIg8rNo5eFZ4e9dt
         4WGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KEfEimh9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id md20si1283774pjb.1.2021.03.15.00.08.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 00:08:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id x10so30700223qkm.8
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 00:08:17 -0700 (PDT)
X-Received: by 2002:a05:620a:410f:: with SMTP id j15mr24039751qko.424.1615792097213;
 Mon, 15 Mar 2021 00:08:17 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000009c21de05ba6849e7@google.com>
In-Reply-To: <0000000000009c21de05ba6849e7@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Mar 2021 08:08:06 +0100
Message-ID: <CACT4Y+ZjVc+_fg+Ggx8zRWSGqzf4gmZcngBXLf_R4F-GKU4a9A@mail.gmail.com>
Subject: Re: kernel BUG in memory_bm_free
To: syzbot <syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com>
Cc: Len Brown <len.brown@intel.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-pm@vger.kernel.org, "Rafael J. Wysocki" <rjw@rjwysocki.net>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Pavel Machek <pavel@ucw.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KEfEimh9;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735
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

On Wed, Feb 3, 2021 at 6:59 AM syzbot
<syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following issue on:
>
> HEAD commit:    3aaf0a27 Merge tag 'clang-format-for-linux-v5.11-rc7' of g..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=17ef6108d00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=10152c2ea16351e7
> dashboard link: https://syzkaller.appspot.com/bug?extid=5ecbe63baca437585bd4
> userspace arch: arm64
>
> Unfortunately, I don't have any reproducer for this issue yet.
>
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com

The BUG is:
BUG_ON(!virt_addr_valid(addr));

#syz fix: arm64: Do not pass tagged addresses to __is_lm_address()

> ------------[ cut here ]------------
> kernel BUG at kernel/power/snapshot.c:257!
> Internal error: Oops - BUG: 0 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 1 PID: 2394 Comm: syz-executor.0 Not tainted 5.11.0-rc6-syzkaller-00055-g3aaf0a27ffc2 #0
> Hardware name: linux,dummy-virt (DT)
> pstate: 20400009 (nzCv daif +PAN -UAO -TCO BTYPE=--)
> pc : free_image_page kernel/power/snapshot.c:257 [inline]
> pc : free_image_page kernel/power/snapshot.c:253 [inline]
> pc : free_list_of_pages kernel/power/snapshot.c:274 [inline]
> pc : memory_bm_free+0x260/0x320 kernel/power/snapshot.c:726
> lr : free_basic_memory_bitmaps+0x3c/0x90 kernel/power/snapshot.c:1173
> sp : ffff8000163dbc50
> x29: ffff8000163dbc50 x28: f4ff000025204070
> x27: ffff800012d4c000 x26: f4ff000025204008
> x25: f5ff00002827c700 x24: ffff800012d4c000
> x23: 00007fffffffffff x22: f4ff000025204018
> x21: 0000000000000001 x20: ffff800013b576d0
> x19: f5ff00002827c700 x18: 0000000000000000
> x17: 0000000000000000 x16: 0000000000000000
> x15: 0000000000000000 x14: 0000000000000000
> x13: 0000000000000000 x12: 0000000000000000
> x11: 0000000000000000 x10: 0000000000000000
> x9 : fcff000025205400 x8 : 0000000000000002
> x7 : f6ff000025205000 x6 : 00000000000001ff
> x5 : 0000000000000000 x4 : 0000000000000000
> x3 : ffff800013b576d0 x2 : f4ff00002517e000
> x1 : 0000000000000001 x0 : 0b0000002517e000
> Call trace:
>  free_image_page kernel/power/snapshot.c:257 [inline]
>  free_list_of_pages kernel/power/snapshot.c:274 [inline]
>  memory_bm_free+0x260/0x320 kernel/power/snapshot.c:726
>  free_basic_memory_bitmaps+0x3c/0x90 kernel/power/snapshot.c:1173
>  snapshot_release+0x74/0x90 kernel/power/user.c:120
>  __fput+0x78/0x230 fs/file_table.c:280
>  ____fput+0x10/0x20 fs/file_table.c:313
>  task_work_run+0x80/0x160 kernel/task_work.c:140
>  tracehook_notify_resume include/linux/tracehook.h:189 [inline]
>  do_notify_resume+0x20c/0x13e0 arch/arm64/kernel/signal.c:939
>  work_pending+0xc/0x3d4
> Code: cb000260 d34cfc00 97fcf6fe 35fffc20 (d4210000)
> ---[ end trace 174c294156b0dfb3 ]---
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZjVc%2B_fg%2BGgx8zRWSGqzf4gmZcngBXLf_R4F-GKU4a9A%40mail.gmail.com.
