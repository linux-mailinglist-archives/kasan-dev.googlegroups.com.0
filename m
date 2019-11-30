Return-Path: <kasan-dev+bncBCMIZB7QWENRBM6CRDXQKGQES2SCF2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C1CA10DD08
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 08:58:44 +0100 (CET)
Received: by mail-yw1-xc37.google.com with SMTP id s128sf22000355ywf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 23:58:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575100723; cv=pass;
        d=google.com; s=arc-20160816;
        b=PKVXt3FpLlQPCzWUc7ZBgAn22/q7klviPcE3noRE3/94VW/vcyw8Ixd2pu39JPsQ+b
         eSYvliyah9yPjQ806gO+FFtX10m5PY2DMPM0FB37V62AnLINwr0ErG9rZ9Y9MFwdK+yt
         BG2QOIh9r4G39rHR4b5+GUBwpGQYdk6zvoVhHFK4cwWifzPSAXdySK4BNgiVkejdyTnT
         Tlk0Zdp42TPl3F1vKI50eOpgl0kyfJsrrBrkSkn2DE5adPj8sVh2jbPNwOX8sVxjYn8J
         OAOR/049y+1RRfu17dD1pM2CT9k28hnW/4Tpunte/4H0Bxdj8Pwl1I6ULZEeNvPGqFHn
         uYMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BUTPBEKLLfE+5LiDbOlTye9IoOSuUhBLKf/rrSKjYOk=;
        b=PS7CwbN1D/Qa1tToWfZ6zoDhGG4/CQk5D2Kle7UzsNaQG63uq8v4bRslp8f0JuFrBr
         GBjS0kCA4oUCvBhhvYMX8fnqs2o5g0jx60bz0VRZGO6cVTJO02kgxp2O8bxmScoMP5zl
         w1Ae5bN8QYh/n7DsI543GR2JEbIgTrQ72iD7EiCn4jPD9IkY70VGkIGmOiGF5yUXTzEA
         Tuw6ebXM5os8EvQt3072AyrXzxnhQnLiqAkH3o61uc/8Yz3FkwjXXCXqRKzlFFgwmMAd
         vpBqzDwysJqlL7yD5J44F2dSi91bkrRbfo03JPJmo1FSCpstLzrRtFJ0aNIok1B80yS8
         8jYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X21jOhTV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BUTPBEKLLfE+5LiDbOlTye9IoOSuUhBLKf/rrSKjYOk=;
        b=aUdQvIoKdwgMtb36IkkXb21dgv8ob6N2djjAHph9R6KTZ4B24G/NqovC5bU+hE8lJD
         mTvUvxFdmUUu1MP3nHSG5BTjUGUKuGlEb2FiWFPKr8A5wAv0CSkTpC2OZ7QPAnG/IuOp
         I8mSgxWrUo7Uq28KONmrAjQFHwEKfXPWcFGXtiWqOE91c5KdYh/J9C60xgVh9iqezffW
         u938+HnluoSflLk6Hq3A+/uzzb1ASu7j9qYd+SaQnMoH6Jqr20O9Fu5BscXlhtT5+7WH
         y0xDJLuvSmZglepsmnNOn6+eKm5tRsvotCLulzXcz8Hy0X0B4/Zioh67tJwNHYFQPYCG
         HHAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BUTPBEKLLfE+5LiDbOlTye9IoOSuUhBLKf/rrSKjYOk=;
        b=b/1XWQi7uSMEomuSBs9gKhPvgFTdWXqy2MoJm1GYXBr1hpgo6F74aVpFpTAl8w0x/Y
         O4tKhAvFJV8Lf9PJjLiWesRizWWIXPi+ZkH2n/yXYWxKcd+d1X2Ti1/3Z3cG3u8zsUW9
         yj72nS9LAy2fPGX0euSy/TV9iG1saqcvLYnGExm+SYYjv1nIfsKnhwsjgw6UB8HEppWz
         qLZlj6zw1eZVtHxybYpLqi+AMxM+QcijaSD92wUKcLBkjB7E6Q1wqt1i1cRDQ+enbjI4
         VvbrGaLFRyLJNYZism+nSYdk13JgDFqY6l4PBCuElic0M7rTEtJaueEK4Ab5fNrkdxzv
         pU8g==
X-Gm-Message-State: APjAAAXulFvidntY6Td6pcV7yi/vCbpEUJVF59CHpbeBgUagORvA+35N
	HHb7kqw5VnoFqNojoQLDiYo=
X-Google-Smtp-Source: APXvYqxQ9fK1qomT8EQRaUwy9RrmADz7VwmAN0nIH/Beo/vWrKaGipYRwvTDoytsKe7HygH4dBjV0Q==
X-Received: by 2002:a25:4292:: with SMTP id p140mr43271321yba.455.1575100723207;
        Fri, 29 Nov 2019 23:58:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1445:: with SMTP id 66ls5338003ybu.5.gmail; Fri, 29 Nov
 2019 23:58:42 -0800 (PST)
X-Received: by 2002:a25:208b:: with SMTP id g133mr31534596ybg.71.1575100722810;
        Fri, 29 Nov 2019 23:58:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575100722; cv=none;
        d=google.com; s=arc-20160816;
        b=ubbfDbVkPOqCm4InvwDEyctMUYpXeIydwJ6vUia5FectlP1Mkt+iCI7G5B/q2VvFjt
         LDGUlRhb8yeRhE2cElCYXVP0VgSawgKx2rqxR0sDYgRUUGU79Y6GrF1gpoq6crJdjQza
         nc2/T2Qn7OIv6mfUa4G9OjG7/C4ulRRtl2FX0Z6DIF6TJvnZY7WRyGpIanXYpFUt9jUL
         aviLWJsGJUYf6UQRVoOdhzloJwJxPlEbq5aPIiRj2r1/42ZRynbWUt9OsMbjKLFfWqhO
         pmU3HGAtNVedcWRG8sWOYhYCW4HkndHb5Rxo0aDW0AeQw24Y9qLSfWGMwLvdAGH+ypDj
         jkZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4TuWJxEYOJBolLGVAjehyG+fbpPZ9w2ICQlbTaVLWXk=;
        b=ivLl+uw1JLqLoOMNbdVVXlO9dEAWjl9UAg/+rY0rty8/Umyl9Sp9iFbsnPohxckZTk
         DvRUZATpPDSl33NTtF2ABbfu1BFKlawMRVKRtQZDrWOtGPjrF3YdKvmiloxjO4jt6WpQ
         aX7R8WgSkvuwx98h/zxnFIs8aMBWFQzeQfd3poh4RDnDuC8KVw2N4JJR4BXAkotftS5m
         FQA5XLwsD+UZmm6krNrVS/b0Nj8xXDqsLeeulqZgybD9bAEJQkxP0e/UWINjYNOZs/eB
         4yaLYAlZ4mlnM3L1bI/nol73XjeQwuycNxohBPsUCXmgcC7d2XIZ2RoJC2BOH9lTJm0H
         2JWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X21jOhTV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id v64si4933ywa.4.2019.11.29.23.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 23:58:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id q8so32424703qtr.10
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 23:58:42 -0800 (PST)
X-Received: by 2002:ac8:ccf:: with SMTP id o15mr56539039qti.380.1575100721993;
 Fri, 29 Nov 2019 23:58:41 -0800 (PST)
MIME-Version: 1.0
References: <0000000000005f386305988bb15f@google.com>
In-Reply-To: <0000000000005f386305988bb15f@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 30 Nov 2019 08:58:30 +0100
Message-ID: <CACT4Y+aQic2aM1gPOp_1Nh0ydAeeJk=KVbRZJpo9S1Zdt7SuzQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=X21jOhTV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Sat, Nov 30, 2019 at 8:57 AM syzbot
<syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    419593da Add linux-next specific files for 20191129
> git tree:       linux-next
> console output: https://syzkaller.appspot.com/x/log.txt?x=10cecb36e00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
> dashboard link: https://syzkaller.appspot.com/bug?extid=6be2cbddaad2e32b47a0
> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>
> Unfortunately, I don't have any reproducer for this crash yet.
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com

+Daniel, kasan-dev
This is presumably from the new CONFIG_KASAN_VMALLOC


> BUG: unable to handle page fault for address: fffff52002e00000
> #PF: supervisor read access in kernel mode
> #PF: error_code(0x0000) - not-present page
> PGD 21ffee067 P4D 21ffee067 PUD aa11c067 PMD 0
> Oops: 0000 [#1] PREEMPT SMP KASAN
> CPU: 0 PID: 2938 Comm: kworker/0:2 Not tainted
> 5.4.0-next-20191129-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> Workqueue: xfs-buf/loop3 xfs_buf_ioend_work
> RIP: 0010:xfs_sb_read_verify+0xf0/0x540 fs/xfs/libxfs/xfs_sb.c:691
> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 18 04 00 00 4d 8b ac 24 30 01
> 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6 04 02 84
> c0 74 08 3c 03 0f 8e a7 03 00 00 41 8b 75 00 bf 58
> RSP: 0018:ffffc90007e5faf0 EFLAGS: 00010a06
> RAX: dffffc0000000000 RBX: 1ffff92000fcbf61 RCX: ffffffff82acb516
> RDX: 1ffff92002e00000 RSI: ffffffff82a97e3b RDI: ffff888091bada60
> RBP: ffffc90007e5fcd0 R08: ffff88809f3c2040 R09: ffffed1015cc7045
> R10: ffffed1015cc7044 R11: ffff8880ae638223 R12: ffff888091bad940
> R13: ffffc90017000000 R14: ffffc90007e5fca8 R15: ffff88809feb8000
> FS:  0000000000000000(0000) GS:ffff8880ae600000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff52002e00000 CR3: 0000000069ceb000 CR4: 00000000001406f0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>   xfs_buf_ioend+0x3f9/0xde0 fs/xfs/xfs_buf.c:1162
>   xfs_buf_ioend_work+0x19/0x20 fs/xfs/xfs_buf.c:1183
>   process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
>   worker_thread+0x98/0xe40 kernel/workqueue.c:2410
>   kthread+0x361/0x430 kernel/kthread.c:255
>   ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> Modules linked in:
> CR2: fffff52002e00000
> ---[ end trace aef83d995322cc4a ]---
> RIP: 0010:xfs_sb_read_verify+0xf0/0x540 fs/xfs/libxfs/xfs_sb.c:691
> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 18 04 00 00 4d 8b ac 24 30 01
> 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6 04 02 84
> c0 74 08 3c 03 0f 8e a7 03 00 00 41 8b 75 00 bf 58
> RSP: 0018:ffffc90007e5faf0 EFLAGS: 00010a06
> RAX: dffffc0000000000 RBX: 1ffff92000fcbf61 RCX: ffffffff82acb516
> RDX: 1ffff92002e00000 RSI: ffffffff82a97e3b RDI: ffff888091bada60
> RBP: ffffc90007e5fcd0 R08: ffff88809f3c2040 R09: ffffed1015cc7045
> R10: ffffed1015cc7044 R11: ffff8880ae638223 R12: ffff888091bad940
> R13: ffffc90017000000 R14: ffffc90007e5fca8 R15: ffff88809feb8000
> FS:  0000000000000000(0000) GS:ffff8880ae600000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff52002e00000 CR3: 0000000069ceb000 CR4: 00000000001406f0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>
>
> ---
> This bug is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this bug report. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/0000000000005f386305988bb15f%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaQic2aM1gPOp_1Nh0ydAeeJk%3DKVbRZJpo9S1Zdt7SuzQ%40mail.gmail.com.
