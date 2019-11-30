Return-Path: <kasan-dev+bncBCMIZB7QWENRBMWDRDXQKGQECMHNWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2277010DD0E
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 09:00:52 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id t126sf824134vkg.6
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 00:00:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575100851; cv=pass;
        d=google.com; s=arc-20160816;
        b=TE471GFEt3UssOWN/rlFAwYQcmp9FPb95J7WiZyfEdRGoPe/boo70TG1AoDWNciLTe
         dlMgCMSR7/DyQ2Hm5HYzc9XzxRUYnTaA1GGEj1Fejdlfqi49NhhwGjI1RTFuqTJfaMvX
         5mepTLabNi1ZrXQGoJlsQueOpXQSyN7ohBR4wxbp1bhgx1JAp6R/1JDxmTk7w44D/ZS3
         SeGsEUHpWVrGhFq6Prcrwt2DRxxaPq0pi+yiyyLDKugG+GS7n29yB50j/tX6quL6rYo7
         w4qoL6Ngilgla6k1PEbtmxM2JCe69AoGZFOzBUT4fupz7hr1JNJuWPihyoNRmRMSVrfs
         Poog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PVgxp/uSf5lFJoy2JDVoH41iTt0guvzZLzS6OYSIQlw=;
        b=qqq1DTZAvKOaQEjSV6dlvtT8dMNO86KTM482oU7UapygKjhHZRsSfjCRiLTDNpEnv+
         eszmpf5rYzZ7nqczTeGev1uUeUAJqXAaRYLTl93u6hHWFJqfUnDDG94eyXBa108Ob3wt
         5PCKMB4DVa8jXmY7ODuM3VXSgapyiiL44mM/krXGKucl/3bwVCf68xYWbyH695d2+PLe
         amvshRsJTJMMOAcShgKcCfKoJulSp4z1iziU4jBO+8ppIUAzP3ZlCwmrleN1AaTtlA7a
         uQHGmpBkuE282UIC2bri4P5asUJdPDte12MN4XFp7Y5ezrLT1+cX3ENQLfFcq2+HdyEJ
         iv0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fmxbj52I;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PVgxp/uSf5lFJoy2JDVoH41iTt0guvzZLzS6OYSIQlw=;
        b=qbdTzIt/q0mJo2pNFSz33JrD4/Zy2vltpFha79WQHuP7m412MYF6yCf37mxkrBZm4s
         AP5gK51PlqnkhEZY8bGw1I8he+1jxxTCu+py9fI/st4joj/y87O+QAAt8OX7a5t/rZab
         OyjQR8F5+xe3YUDLuLb3RI4fyHUyU1ZOUzumjRKQKr1C1LVpRmofv8LVe4QhT2Q4xhLT
         XolYB5ZH3pGIp4jyYEn1Fn0DVsz/0Y5JfDIS83Gp4E2Qezu4kFji4jmohDyYlTR8p2LN
         WXus/wChzj1FX3lvm9DVY85VJVL5ZECw4e7D7NHia/v+TEdBPv9nqzUOFz/aw7sx0+UE
         a2Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PVgxp/uSf5lFJoy2JDVoH41iTt0guvzZLzS6OYSIQlw=;
        b=BwM1x5vJoJiTiLlYaGfUF2g2Dd6n4t2k9rUk58vLbn3wa3ejWfjHbLboWEQp6u+S6t
         Eab2rSz1B+uZye0ogHhUI9IeOpxKVam2YfQTHLy+I6lRSnB4dWF6AziZMtOCYpqI1Zm/
         TzIhRmb/hyUeZXaUfIxQGJs74vHxGO0Oqjt0ndXpL+JReq/NXh9O58fx3Mz8XtL0wCwr
         7u290f0P6MC2YmZgtUL6nUfwB/0Ld7zZjbWwja6ZyCx1ikfVR793LYNmMOB5G+8uoAZO
         AHPLKQSCptLC63cCuK/SO5N5T3mlAj/qtgxZlwyout851EHas+55bL9bQbg6QluCVa36
         wCUQ==
X-Gm-Message-State: APjAAAWqOANHijywl1Lj5AdhsMzeKacZQPtk+82C6LsJelnf1Yq02udt
	hdeTi6r7CZJ/j2gjP0j9BiI=
X-Google-Smtp-Source: APXvYqyPCAYi0LzBPYOAktgra0+jFgSUpwuOMFBRt4tEVdB0NzUbJd40zOAx2+26oI8DTsv29XF6pA==
X-Received: by 2002:a67:c99a:: with SMTP id y26mr34379721vsk.213.1575100850898;
        Sat, 30 Nov 2019 00:00:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3239:: with SMTP id x25ls3301945vsf.4.gmail; Sat,
 30 Nov 2019 00:00:50 -0800 (PST)
X-Received: by 2002:a67:f1cc:: with SMTP id v12mr34463109vsm.78.1575100850435;
        Sat, 30 Nov 2019 00:00:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575100850; cv=none;
        d=google.com; s=arc-20160816;
        b=c969EY0q0t0AoE88WhnQ+4b32DXyEo3bErY+neeuTBPt8D2ecyPs/OeAhzfRd7uQkV
         b2s1CTON6T6mn+e+AcMdMfUSr+p900mdzZ3tTV0AAbUhMZgh0OhOBeuWc4UPRO4xgdK+
         /kssJqnana7eGfY1sX3D83GNUfRjKPvuhC6xYrpDNGX1thYbdZ/kRgCsP4z59jDgNo7D
         kKXkc3msBvLqPbj4Hz8YcX4/LiQDwji4yRNsBspQWUYakBBTDmsHH64M8ROk6gCXD+pJ
         ba477G6nj41UoZyjuGSmkT6wNdP0eKGDpSXRH1QrAOD6pi2t5fMxDlu4TQvRtFZlkwfg
         YF7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o46WZxPqRgJv0aRTEdOKQ8kVdntcooFcgI2XD+4wx4c=;
        b=ubLZ6WIlKlGydKZLNfEL9gAHdgn5m9ICQAwWOAgS2+AC+Lf7BlIt+TS4WN6p+MiGDC
         j6X5rTUeGMLAsO23i/IiQSpI05ND68d/vUSIce1PM1JSU4Yw5oTR9DwA7sy6/DVsZepq
         14bpw/rStEkbq3ojNeNL4fdCVldH3yNdWSPQjjNWfbGwzvLgDaEKOlk//PuwesLhiT+s
         /Sjct/wdqD3ZvNMWUAMydkgL2q96q5coWtlX/ZVWc9d9WrqX8LGsC0zRxQ7koIFN1QX0
         29sNCL8XhJZXbEdUesjIHCVGxJGcuLo8Bo3V8tqwKUOK8UU4Ax37wYzjVFPPUS7Cm1y1
         Q/vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fmxbj52I;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id f186si1147749vkc.5.2019.11.30.00.00.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Nov 2019 00:00:50 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id t9so2423264qvh.13
        for <kasan-dev@googlegroups.com>; Sat, 30 Nov 2019 00:00:50 -0800 (PST)
X-Received: by 2002:a0c:c125:: with SMTP id f34mr21651241qvh.22.1575100849562;
 Sat, 30 Nov 2019 00:00:49 -0800 (PST)
MIME-Version: 1.0
References: <0000000000005f386305988bb15f@google.com> <CACT4Y+aQic2aM1gPOp_1Nh0ydAeeJk=KVbRZJpo9S1Zdt7SuzQ@mail.gmail.com>
In-Reply-To: <CACT4Y+aQic2aM1gPOp_1Nh0ydAeeJk=KVbRZJpo9S1Zdt7SuzQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 30 Nov 2019 09:00:38 +0100
Message-ID: <CACT4Y+aM7Jy=+Fq-yzUo-3WMchhtua9wWvqyL21VPh2b0cZtRg@mail.gmail.com>
Subject: Re: BUG: unable to handle kernel paging request in xfs_sb_read_verify
To: syzbot <syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com>, 
	Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>
Cc: allison.henderson@oracle.com, Brian Foster <bfoster@redhat.com>, 
	"Darrick J. Wong" <darrick.wong@oracle.com>, dchinner@redhat.com, 
	LKML <linux-kernel@vger.kernel.org>, linux-xfs <linux-xfs@vger.kernel.org>, 
	sandeen@redhat.com, syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fmxbj52I;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Sat, Nov 30, 2019 at 8:58 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, Nov 30, 2019 at 8:57 AM syzbot
> <syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com> wrote:
> >
> > Hello,
> >
> > syzbot found the following crash on:
> >
> > HEAD commit:    419593da Add linux-next specific files for 20191129
> > git tree:       linux-next
> > console output: https://syzkaller.appspot.com/x/log.txt?x=10cecb36e00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
> > dashboard link: https://syzkaller.appspot.com/bug?extid=6be2cbddaad2e32b47a0
> > compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> >
> > Unfortunately, I don't have any reproducer for this crash yet.
> >
> > IMPORTANT: if you fix the bug, please add the following tag to the commit:
> > Reported-by: syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com
>
> +Daniel, kasan-dev
> This is presumably from the new CONFIG_KASAN_VMALLOC

This should be:
#syz fix: kasan: support vmalloc backing of vm_map_ram()

> > BUG: unable to handle page fault for address: fffff52002e00000
> > #PF: supervisor read access in kernel mode
> > #PF: error_code(0x0000) - not-present page
> > PGD 21ffee067 P4D 21ffee067 PUD aa11c067 PMD 0
> > Oops: 0000 [#1] PREEMPT SMP KASAN
> > CPU: 0 PID: 2938 Comm: kworker/0:2 Not tainted
> > 5.4.0-next-20191129-syzkaller #0
> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> > Google 01/01/2011
> > Workqueue: xfs-buf/loop3 xfs_buf_ioend_work
> > RIP: 0010:xfs_sb_read_verify+0xf0/0x540 fs/xfs/libxfs/xfs_sb.c:691
> > Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 18 04 00 00 4d 8b ac 24 30 01
> > 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6 04 02 84
> > c0 74 08 3c 03 0f 8e a7 03 00 00 41 8b 75 00 bf 58
> > RSP: 0018:ffffc90007e5faf0 EFLAGS: 00010a06
> > RAX: dffffc0000000000 RBX: 1ffff92000fcbf61 RCX: ffffffff82acb516
> > RDX: 1ffff92002e00000 RSI: ffffffff82a97e3b RDI: ffff888091bada60
> > RBP: ffffc90007e5fcd0 R08: ffff88809f3c2040 R09: ffffed1015cc7045
> > R10: ffffed1015cc7044 R11: ffff8880ae638223 R12: ffff888091bad940
> > R13: ffffc90017000000 R14: ffffc90007e5fca8 R15: ffff88809feb8000
> > FS:  0000000000000000(0000) GS:ffff8880ae600000(0000) knlGS:0000000000000000
> > CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > CR2: fffff52002e00000 CR3: 0000000069ceb000 CR4: 00000000001406f0
> > DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> > DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> > Call Trace:
> >   xfs_buf_ioend+0x3f9/0xde0 fs/xfs/xfs_buf.c:1162
> >   xfs_buf_ioend_work+0x19/0x20 fs/xfs/xfs_buf.c:1183
> >   process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
> >   worker_thread+0x98/0xe40 kernel/workqueue.c:2410
> >   kthread+0x361/0x430 kernel/kthread.c:255
> >   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> > Modules linked in:
> > CR2: fffff52002e00000
> > ---[ end trace aef83d995322cc4a ]---
> > RIP: 0010:xfs_sb_read_verify+0xf0/0x540 fs/xfs/libxfs/xfs_sb.c:691
> > Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 18 04 00 00 4d 8b ac 24 30 01
> > 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6 04 02 84
> > c0 74 08 3c 03 0f 8e a7 03 00 00 41 8b 75 00 bf 58
> > RSP: 0018:ffffc90007e5faf0 EFLAGS: 00010a06
> > RAX: dffffc0000000000 RBX: 1ffff92000fcbf61 RCX: ffffffff82acb516
> > RDX: 1ffff92002e00000 RSI: ffffffff82a97e3b RDI: ffff888091bada60
> > RBP: ffffc90007e5fcd0 R08: ffff88809f3c2040 R09: ffffed1015cc7045
> > R10: ffffed1015cc7044 R11: ffff8880ae638223 R12: ffff888091bad940
> > R13: ffffc90017000000 R14: ffffc90007e5fca8 R15: ffff88809feb8000
> > FS:  0000000000000000(0000) GS:ffff8880ae600000(0000) knlGS:0000000000000000
> > CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > CR2: fffff52002e00000 CR3: 0000000069ceb000 CR4: 00000000001406f0
> > DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> > DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> >
> >
> > ---
> > This bug is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this bug report. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/0000000000005f386305988bb15f%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaM7Jy%3D%2BFq-yzUo-3WMchhtua9wWvqyL21VPh2b0cZtRg%40mail.gmail.com.
