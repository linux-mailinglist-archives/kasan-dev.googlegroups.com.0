Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJEG23ZAKGQEA3TMDGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E3A3D16F005
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2020 21:27:17 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id 203sf249428pfx.5
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2020 12:27:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582662436; cv=pass;
        d=google.com; s=arc-20160816;
        b=hmTi20MyCSD2HjdrODt543CCZVNoSkSRzmQl0bwD4dmbQxeofXuRVO9L4ic1UEEzrp
         JniDPDqUkAGdzqptlUNw25ggOsLWtczsM+aiBQF42dPCHKYcjFsx7tE9/YOQzPLnFDeE
         fQlOPg16bTRSIUQnSMTLk7yRfZ/NhzhQft5QSstUWdvSOka0MeMTUPWxKmCpsmHBGI3D
         dl7Wkft4QfBnD/2/QyGpJx21Cnhm8NwSaLsmgFeacd9oteg/sFXGjc9M62cTHhx4yGLB
         ci3sogOcdy8UgafjtOZ/tbUi3/dqHAqyds8tenridRIfapQvO4qYB6lErT+9oMFJYuEO
         KWMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3c9MUmJMCt3X52OiDmXhgF3l47+16NNvYqyF5IWpINA=;
        b=RH0EusHxi6q/y69vRngLLp4+x+wJl+ghBxaCIEE/CzBP7dfjzLsSGgTaYRNs7T9dPg
         XZ9Bxei+TIeh++wpHeLmprBiS/o4rqPv5MawM1qYzTXRGlUNQVZLEsvyrUmg5njW5QBr
         Na+3j4vGwrg11arOmLFrK85LIwFnzUDFVWchzlDe59e6PZybeaAa/cY39pBH3VVBKjzs
         C6+qKn6bf0JzDp0NZAyClrF9ZSREoAKKfoSJVBBd+s541vLC5J0Zug2/aJz9Ez/FcvdP
         fOabb6OkImiefrNaHnF7necMJ3V5HKtZWQsn9co5Q3/u1VHM+dbvVCKFRPWnHDcedPAI
         tuyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WmQJlJHU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3c9MUmJMCt3X52OiDmXhgF3l47+16NNvYqyF5IWpINA=;
        b=mdKgXx8eoBxZXLi45w+diWtdznSJrwxRy51oM9gkZ7Nqj0nQFQuFrLLmucnBRgabD1
         zCQy/jEHfDJgrJhu8rvlpVY+Oyp7YDGD+hCuiJ/vgVJ/Yc51pKh7g8Nj3lfBWo4gOr7t
         xG9eWThtOWqg+8Fy37A6mybptlxUgZaInnIacr623fzEbyd7nCUsbL3Qkt+iDH+JvPcz
         eiUxdhq06UzR7L+rZIM6xz5oW1MMm0ZkWKt20GapvtHPKJj8CqMDdtnjCvNr1WZyC2jF
         irPXbXyTSe9VJCsfEe2YYlobeCY9B79Rk278KnGjs85kyQD0oiROtkbXW6HXTKZGgX6c
         WQ4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3c9MUmJMCt3X52OiDmXhgF3l47+16NNvYqyF5IWpINA=;
        b=pw6ajtbdGED7ZrgxZQ95xP+H/uWDimCEKHh6o8DJIGl0NJw3bdaRDdPOl1sj2AReGq
         8dPYjPhy0NZTRKEQ6bHvyvUl0NFc2cT1YjAWEER6nmdScX9YJu97WnUkDSHXcHpcfw0N
         G7cw9c8TOf0WdT7s0gh1cXyPNK2yNq8j2H9n9pYGepT7wmIycAvHRzQT+cdCpg5Oik/B
         adcnKwKvXOHNoJfQxME7FWRYb/jLoaSXWqnSo1gaBLii4t4Au1vjliFjfFHHourjat2O
         QaZJQvPh+TVV12pvNdFrPuZgWffjgosBKICWfbHASTvnFvbgxcW0nq9R6yrcH18SuWa9
         OoPg==
X-Gm-Message-State: APjAAAUNqCwgFZfA4N09ep+SoqBbJRf0pYTkRwciIDxol9iKrpqOlLf2
	7WaFSviNEk/zb7sGba7dxo0=
X-Google-Smtp-Source: APXvYqzvrq7GJEiYznfsF7pNYGrsOt5sB98ONPFIdbK4yQ1nTbt+3pU0niphHqR4a/Tx6RsE6F2Msg==
X-Received: by 2002:a17:902:b206:: with SMTP id t6mr276371plr.211.1582662436626;
        Tue, 25 Feb 2020 12:27:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a81:: with SMTP id w1ls174083plp.2.gmail; Tue, 25
 Feb 2020 12:27:16 -0800 (PST)
X-Received: by 2002:a17:902:8f8e:: with SMTP id z14mr273048plo.195.1582662436106;
        Tue, 25 Feb 2020 12:27:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582662436; cv=none;
        d=google.com; s=arc-20160816;
        b=ePuSlXvWoZfaabfkU6WKV37c3+AKtwsvf6+KAEoUn3aF6D8n5LwC0cBPXaYxrgi/A/
         8bVaE3yJ2XXzJ9tGDREYwhodDoO42Ft4B1YgguwPxb7kxiAaJCgpZ3jHbqyJULOlsUXy
         nsCCI54TMb6NZHtazx3zsFdCxD2QsVXqt5H91EvW3cFHbUSFsw7Lr3AETX2RDFfeebVr
         AfO/CSnbS24uFd2rDCFWuCU6StVWztq1KLnHLhbUYnBgqYxHHubTWnJykStYkHTmad9b
         af8k3zUrAmSAGsd1sC1tjjjF7oYU3wQE0HXOEZRI4snhaP8klWgWu8ozNoJWrVoC5D+a
         CmCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h8zKM3vL3MUBQAymrTc6L3H6hz70LO6qXSQaWI0IU04=;
        b=hxdB0WdPVuXl84sC2Q/sFNkD4WYkoaBBaBVgGNSD4HXdN3tKhAsmZoJhetCwN7L+/1
         gdjEvaYrwQs0sGv7nw8/Y0U/BOXBIhnRXx9fJ/e/DlQXjDj9zUKeXL4LUR6lYDcriyM4
         mCiVAZ/O9lIuAKprjoL96NiUBuWpCL4zw9ZCYTaIcP/MimuYFClNsX5Ta+iDv4OykqZ4
         hDkTNA0KsBj40t/lk0DVeKWkQ45BKsIZWtBHoeZVnB5Sadl3cUu7scv6tCU2uq7dfH7M
         +mPaLLE8OLdVAW/9Eiv+jhsnE76+IqPzn4iJRPNdHjy4xec0mJbX8GvhRtr2LLAJi/yb
         rEfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WmQJlJHU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id j123si36927pfd.5.2020.02.25.12.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2020 12:27:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id r16so805403otd.2
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2020 12:27:16 -0800 (PST)
X-Received: by 2002:a9d:66d1:: with SMTP id t17mr292149otm.233.1582662435427;
 Tue, 25 Feb 2020 12:27:15 -0800 (PST)
MIME-Version: 1.0
References: <1582661385-30210-1-git-send-email-cai@lca.pw>
In-Reply-To: <1582661385-30210-1-git-send-email-cai@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 Feb 2020 21:27:03 +0100
Message-ID: <CANpmjNMepxzC1Sy7S9SjLSMOMCVR-5ycEecYcmxUitiiXmPF1Q@mail.gmail.com>
Subject: Re: [PATCH] xfs: fix data races in inode->i_*time
To: Qian Cai <cai@lca.pw>
Cc: "Darrick J. Wong" <darrick.wong@oracle.com>, linux-xfs@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WmQJlJHU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Tue, 25 Feb 2020 at 21:09, Qian Cai <cai@lca.pw> wrote:
>
> inode->i_*time could be accessed concurrently. The plain reads in
> xfs_vn_getattr() is lockless which result in data races. To avoid bad
> compiler optimizations like load tearing, adding pairs of
> READ|WRITE_ONCE(). While at it, also take care of xfs_setattr_time()
> which presumably could run concurrently with xfs_vn_getattr() as well.
> The data races were reported by KCSAN,
>
>  write to 0xffff9275a1920ad8 of 16 bytes by task 47311 on cpu 46:
>   xfs_vn_update_time+0x1b0/0x400 [xfs]
>   xfs_vn_update_time at fs/xfs/xfs_iops.c:1122

So this one is doing concurrent writes and reads of the whole struct,
which is 16 bytes. This will always be split into multiple
loads/stores. Is it intentional?

Sadly, this is pretty much guaranteed to tear, even with the
READ/WRITE_ONCE.  The *ONCE will just make KCSAN not tell us about
this one, which is probably not what we want right now, unless we know
for sure the race is intentional.

Thanks,
-- Marco

>   update_time+0x57/0x80
>   file_update_time+0x143/0x1f0
>   __xfs_filemap_fault+0x1be/0x3d0 [xfs]
>   xfs_filemap_page_mkwrite+0x25/0x40 [xfs]
>   do_page_mkwrite+0xf7/0x250
>   do_fault+0x679/0x920
>   __handle_mm_fault+0xc9f/0xd40
>   handle_mm_fault+0xfc/0x2f0
>   do_page_fault+0x263/0x6f9
>   page_fault+0x34/0x40
>
>  4 locks held by doio/47311:
>   #0: ffff9275e7d70808 (&mm->mmap_sem#2){++++}, at: do_page_fault+0x143/0x6f9
>   #1: ffff9274864394d8 (sb_pagefaults){.+.+}, at: __xfs_filemap_fault+0x19b/0x3d0 [xfs]
>   #2: ffff9274864395b8 (sb_internal){.+.+}, at: xfs_trans_alloc+0x2af/0x3c0 [xfs]
>   #3: ffff9275a1920920 (&xfs_nondir_ilock_class){++++}, at: xfs_ilock+0x116/0x2c0 [xfs]
>  irq event stamp: 42649
>  hardirqs last  enabled at (42649): [<ffffffffb22dcdb3>] _raw_spin_unlock_irqrestore+0x53/0x60
>  hardirqs last disabled at (42648): [<ffffffffb22dcad1>] _raw_spin_lock_irqsave+0x21/0x60
>  softirqs last  enabled at (42306): [<ffffffffb260034c>] __do_softirq+0x34c/0x57c
>  softirqs last disabled at (42299): [<ffffffffb18c6762>] irq_exit+0xa2/0xc0
>
>  read to 0xffff9275a1920ad8 of 16 bytes by task 47312 on cpu 40:
>   xfs_vn_getattr+0x20c/0x6a0 [xfs]
>   xfs_vn_getattr at fs/xfs/xfs_iops.c:551
>   vfs_getattr_nosec+0x11a/0x170
>   vfs_statx_fd+0x54/0x90
>   __do_sys_newfstat+0x40/0x90
>   __x64_sys_newfstat+0x3a/0x50
>   do_syscall_64+0x91/0xb05
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
>
>  no locks held by doio/47312.
>  irq event stamp: 43883
>  hardirqs last  enabled at (43883): [<ffffffffb1805119>] do_syscall_64+0x39/0xb05
>  hardirqs last disabled at (43882): [<ffffffffb1803ede>] trace_hardirqs_off_thunk+0x1a/0x1c
>  softirqs last  enabled at (43844): [<ffffffffb260034c>] __do_softirq+0x34c/0x57c
>  softirqs last disabled at (43141): [<ffffffffb18c6762>] irq_exit+0xa2/0xc0
>
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>  fs/xfs/xfs_iops.c | 18 +++++++++---------
>  1 file changed, 9 insertions(+), 9 deletions(-)
>
> diff --git a/fs/xfs/xfs_iops.c b/fs/xfs/xfs_iops.c
> index 81f2f93caec0..2d5ca13ee9da 100644
> --- a/fs/xfs/xfs_iops.c
> +++ b/fs/xfs/xfs_iops.c
> @@ -547,9 +547,9 @@
>         stat->uid = inode->i_uid;
>         stat->gid = inode->i_gid;
>         stat->ino = ip->i_ino;
> -       stat->atime = inode->i_atime;
> -       stat->mtime = inode->i_mtime;
> -       stat->ctime = inode->i_ctime;
> +       stat->atime = READ_ONCE(inode->i_atime);
> +       stat->mtime = READ_ONCE(inode->i_mtime);
> +       stat->ctime = READ_ONCE(inode->i_ctime);
>         stat->blocks =
>                 XFS_FSB_TO_BB(mp, ip->i_d.di_nblocks + ip->i_delayed_blks);
>
> @@ -614,11 +614,11 @@
>         ASSERT(xfs_isilocked(ip, XFS_ILOCK_EXCL));
>
>         if (iattr->ia_valid & ATTR_ATIME)
> -               inode->i_atime = iattr->ia_atime;
> +               WRITE_ONCE(inode->i_atime, iattr->ia_atime);
>         if (iattr->ia_valid & ATTR_CTIME)
> -               inode->i_ctime = iattr->ia_ctime;
> +               WRITE_ONCE(inode->i_ctime, iattr->ia_ctime);
>         if (iattr->ia_valid & ATTR_MTIME)
> -               inode->i_mtime = iattr->ia_mtime;
> +               WRITE_ONCE(inode->i_mtime, iattr->ia_mtime);
>  }
>
>  static int
> @@ -1117,11 +1117,11 @@
>
>         xfs_ilock(ip, XFS_ILOCK_EXCL);
>         if (flags & S_CTIME)
> -               inode->i_ctime = *now;
> +               WRITE_ONCE(inode->i_ctime, *now);
>         if (flags & S_MTIME)
> -               inode->i_mtime = *now;
> +               WRITE_ONCE(inode->i_mtime, *now);
>         if (flags & S_ATIME)
> -               inode->i_atime = *now;
> +               WRITE_ONCE(inode->i_atime, *now);
>
>         xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);
>         xfs_trans_log_inode(tp, ip, log_flags);
> --
> 1.8.3.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMepxzC1Sy7S9SjLSMOMCVR-5ycEecYcmxUitiiXmPF1Q%40mail.gmail.com.
