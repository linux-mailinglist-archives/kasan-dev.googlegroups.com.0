Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBBNQ4SAAMGQEBNHK65I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id F029C30BAAA
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 10:14:45 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id le12sf9682338ejb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 01:14:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612257285; cv=pass;
        d=google.com; s=arc-20160816;
        b=C3VN2srqPrP6adnSaDH6SUKQuWQrm7YAURFwJcLU6iYxAkJ/bwdLhROHLYSQCxkLSZ
         OI8j4cbCBtqh66YXhvwf3KJPuyJeU1KNYFsqGT/+zDyYS4T1qFaPj/uwjziXlZVqiiju
         Ebvh0pk5YXOsQFcmpCnOYZRsm03uke+w3wXU2GnkWTeUcTn74uK8HSgGMUTSXiu1p1Yb
         b8fo7PYLr6rGLqGi4az0HzrPypNZbiI74c7mpVoODXhdmENtZ+Y2PzL3OsDJad8sR052
         UvmjSU8pA9AqyVOso0MwaQ9U2nnrVOzFAYca76CsBJAD85bGDHlApeLVE4qDfsTI1GWy
         y+JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=RgMAeW0LcM3zMbo0hA3EoXj0IMaeBzpNJeUWL44vSM0=;
        b=jf6TIYkZXrLn1kR8B3hDJ3CzOrLAiWxR98RVRRBVuu9ZPJc3e2Yms55pWNdmVgQ2km
         k0IAOxYDwd1UCXnltpoFCIYMiXIg7I7sks1qZhDWdiSyUluhQOycvi6G0fhUzloy+13Y
         AK3H/JEj0xlTYr2P2oW4S5ygc3Kvbr4/brkXXA2GZEc4Nbm/HoeZT0IAim9w0dzII9KW
         oWewcB7QTaF8C+rMTU3lr6YOHcl4tShKj+CXXLBnmbx7TEjCcJmC3eHMk48QvF9YFUC1
         AeNmuP/MTolqYPPCm1aSzdupY3sr+Bid2nIusa5bJOnQ+VjPsF1i388wCLsnRmqz1rPq
         b6Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LHNtm0Qf;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RgMAeW0LcM3zMbo0hA3EoXj0IMaeBzpNJeUWL44vSM0=;
        b=YXsBuO33nTSKNIJRx3sd/70AXmXx2tmhtUdt72qAZVn2ceIuiObXxuLG5cGijhzaql
         XJNBWJPFQmO5RngGaa+yefuY73FAO/6jvWlYUnlYBnVn46ROIAPL7CQJogTews8oOHRs
         NM+lcJTt3sxE1014YbwQMorMqguVWQOColUvuAiBfVNdI75mKcq13RLduCB2zfODrs0H
         yBy0eRoEiToCA16F3d7EkIvSsGzQYe9dLU6V0RslyrXCBR+RwFxeqrXnDNHx2qDvMnA0
         dp0BGKpltfLagRgeS/jfpiVQFu1+wP1ZZ8K8PO0KVsMyqGkplsnyNBeWUqPE9+3FxHr3
         yMlQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RgMAeW0LcM3zMbo0hA3EoXj0IMaeBzpNJeUWL44vSM0=;
        b=H8BOW2n8dFCNIunASknfRKU0TO0eXXLoM8kWvuHmVgGgFfO446PReMtUGJ8DEpjzVy
         7yAcVRrBxxyIwjFH+r/I0zeksMbAaxDY4MXjYpcKepU3Ge1JW9vXvPmnVPALvz+6v6nd
         etnJNi09sx/4wxnG6Tt79cIwLz9ooQAuoGQ/0TAUrR1Ru3OAU4OCNnKOZ5jYYgpNjUTs
         KPp08bD+ZKK5qcy1gNbxzr7Xz7f9aEiKBZcGhFrjSepmVpiEp3ldnMuMTxtp8OmJ2M8C
         sdaOvayQdIOV47atE0dmSWhV7VttO3pA0FStRLBBOvh6SaHhdIsFHD9ho7mp62L7grqQ
         Pb9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RgMAeW0LcM3zMbo0hA3EoXj0IMaeBzpNJeUWL44vSM0=;
        b=XnHcpnbRap/uSk/uyYiI7vhJFd0mt6Cky+P4e+TShMpTD1XJC7RSu7s0/G85pSTATc
         7b1Rcvajqwu51AQaQ5wsEsUQ1Ql1fe3A/WwemGIVGnjU0xVr8+5ZjUxjaehYjh7/j5K4
         f7DNjHGedGfALR8G8B4GP30Hk1mq2da9kCVnaiWSBmpFETvZOzmL0ZYtVcsDdsXUhd3v
         2ZNhb3N1DY8Z2EFiYmYScbdp9aw9OFZRB3yHKe+9T6X53Q47aoMxXS33cPoI990X9H/2
         m6z16CAxNx++PQ6+0DOtt/McY600fR22blX4yfMn7TKOkbzb8YfqUVcd+0k5Np9M+X+P
         mUgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Yg0TmYflFYNFh2z/yjN3MhdKbG+Wi0NUXFtxFP6k4EbTPyUGp
	5BLe2C07uCrzXkMBTdOdk4I=
X-Google-Smtp-Source: ABdhPJxyVxorBzmKipqbPI8hJ+maWVGJRfQ9yHlLTNNN7+egViRXoUtJsUahn8Z81Ugjoz/FpjQPMA==
X-Received: by 2002:a05:6402:208:: with SMTP id t8mr22571836edv.189.1612257285756;
        Tue, 02 Feb 2021 01:14:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls1708068edd.3.gmail; Tue,
 02 Feb 2021 01:14:44 -0800 (PST)
X-Received: by 2002:a50:ec06:: with SMTP id g6mr13870813edr.12.1612257284741;
        Tue, 02 Feb 2021 01:14:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612257284; cv=none;
        d=google.com; s=arc-20160816;
        b=EMhG4rBayiTDJeKBplUHokiW12BrPN3itMcReMqT+M/2zWdXNgpU4fvR/iXj00iNeU
         ZpqUYJChrYIcBjqOVKdM1vaY4sQvCT5l0e/WnW+as+AnNiQonfhTZL9VIugtPz87v/aQ
         Nx8U6dBp0XnIIt0hX5DOdZYa9yFx4OF3giNdFeEblP/did+kH9SjSo98yH4pWjkC2Dt6
         AFH0h2lIxAs28X3+gJiHP7peP1FxX9svC0cg1H58MXyH3UpZQ46X4cM4DbXAOFdSI0wZ
         1EFhRwEbYGsyt4HejU/nImhQNS95hbzR3NBE3XhbPb2NdlP0RubonNmz/VqLsbO1ZiJg
         I7+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vdvEOnj19JQ+8ZVGUsw5w+AWiybF4jukVufLlReJmJQ=;
        b=nCuc1c0L1gxslcKhsWrTzVuEh7kDf55pTsNQPjKDaNiQSQfnTHGLde003z/bOgcTnM
         Zqvnfh2svs3EjKrK0cGFEIcoik8hNGKXYChWNTRIwP9G1RJ6e8vrCQO4Kft/4b6w+wSc
         5p1y9aIykXzirtSGhZXxhMPn73oTVIx7W7/w1FULDVCnteIEfKHNV4yleAhobATQ56nQ
         Aml3dLFOhcvSAir69q9SkpYgk7YnbK8b11n0gm2eQEuYpUKVX++igsGCaHBg445uMvxu
         mhQy3PlKmek9RFQvIOR+M/CyF4LNELw9hl3TNKB4kfT8iSOqcS5GcIM4H1K0sjJYDQHY
         hnuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LHNtm0Qf;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id jz19si52715ejb.0.2021.02.02.01.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 01:14:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id s3so8330288edi.7
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 01:14:44 -0800 (PST)
X-Received: by 2002:a05:6402:318e:: with SMTP id di14mr22700664edb.223.1612257284474;
 Tue, 02 Feb 2021 01:14:44 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
 <20210128232821.GW2743@paulmck-ThinkPad-P72> <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
 <CACT4Y+YFfej26JkuH1szEUKKvEP-TaD+rugdTNfsw-bALzSMZA@mail.gmail.com>
 <CACV+naogeDve+4jGsoMUTa-T_UDojyV5GKsX0+VBR7uGg_9-gA@mail.gmail.com> <CACT4Y+YxQjm3y6fDhcG5D=9pfTCWAMNTiuwjZfNMfScSzMwJ5Q@mail.gmail.com>
In-Reply-To: <CACT4Y+YxQjm3y6fDhcG5D=9pfTCWAMNTiuwjZfNMfScSzMwJ5Q@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Tue, 2 Feb 2021 04:14:33 -0500
Message-ID: <CACV+naoJX7Dw_zoLyQdfgSv38MDo2zF8MGs9=CpiUa7LEju7sg@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000ba49be05ba56e6f3"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=LHNtm0Qf;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52a
 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000ba49be05ba56e6f3
Content-Type: text/plain; charset="UTF-8"

Seems sometimes need to subtract 1 and sometimes not? How could we know?
And seems parsing DWARF will be a better option? At least I see the
addr2line result misses some inline call info in the stack.

syzkaller log
  backtrace:
    [<00000000e98ac262>] v2_read_file_info+0x2c6/0xa10
    [<0000000005a7ae24>] dquot_load_quota_sb+0x692/0xe30
    [<0000000003d57be5>] dquot_load_quota_inode+0x1d1/0x330
    [<00000000776b8d1b>] ext4_enable_quotas+0x53e/0x8c0
    [<000000007f6e8b33>] ext4_fill_super+0xbdd1/0xced0
    [<00000000eed8917b>] mount_bdev+0x331/0x3f0
    [<00000000d809ca96>] legacy_get_tree+0x105/0x220
    [<000000002503c8bb>] vfs_get_tree+0x8e/0x2f0
    [<00000000b9b2b4e2>] path_mount+0x139a/0x2080
    [<00000000ccc3b35f>] __x64_sys_mount+0x27e/0x300
    [<00000000f471fbd6>] do_syscall_64+0x33/0x40
    [<000000005a34ab49>] entry_SYSCALL_64_after_hwframe+0x44/0xa9

syzkaller report
  backtrace:
    [<00000000e98ac262>] kmalloc include/linux/slab.h:552 [inline]
    [<00000000e98ac262>] v2_read_file_info+0x2c6/0xa10
fs/quota/quota_v2.c:122
    [<0000000005a7ae24>] dquot_load_quota_sb+0x692/0xe30
fs/quota/dquot.c:2387
    [<0000000003d57be5>] dquot_load_quota_inode fs/quota/dquot.c:2423
[inline]
    [<0000000003d57be5>] dquot_load_quota_inode+0x1d1/0x330
fs/quota/dquot.c:2415
    [<00000000776b8d1b>] ext4_quota_enable fs/ext4/super.c:6400 [inline]
    [<00000000776b8d1b>] ext4_enable_quotas+0x53e/0x8c0 fs/ext4/super.c:6426
    [<000000007f6e8b33>] ext4_fill_super+0xbdd1/0xced0 fs/ext4/super.c:5034
    [<00000000eed8917b>] mount_bdev+0x331/0x3f0 fs/super.c:1366
    [<00000000d809ca96>] legacy_get_tree+0x105/0x220 fs/fs_context.c:592
    [<000000002503c8bb>] vfs_get_tree+0x8e/0x2f0 fs/super.c:1496
    [<00000000b9b2b4e2>] do_new_mount fs/namespace.c:2881 [inline]
    [<00000000b9b2b4e2>] path_mount+0x139a/0x2080 fs/namespace.c:3211
    [<00000000ccc3b35f>] do_mount fs/namespace.c:3224 [inline]
    [<00000000ccc3b35f>] __do_sys_mount fs/namespace.c:3432 [inline]
    [<00000000ccc3b35f>] __se_sys_mount fs/namespace.c:3409 [inline]
    [<00000000ccc3b35f>] __x64_sys_mount+0x27e/0x300 fs/namespace.c:3409
    [<00000000f471fbd6>] do_syscall_64+0x33/0x40 arch/x86/entry/common.c:46
    [<000000005a34ab49>] entry_SYSCALL_64_after_hwframe+0x44/0xa9

Below is mine, misses 2 top inline function call info, and the line number
sometimes will be 1 or 2 more, sometimes correct, so weird.
First I generate the objdump file of the vmlinux: objdump -d vmlinux >
vmlinux.S
Then, get the address of the function call in vmlinux.S and add the offset,
and use adr2line to get the file:line info, like: addr2line -f -i -e
vmlinux 0xffffffff8177927e/0x300

I have marked the mistakes red.

  My Backtrace:

    miss 1 call

    [<00000000e98ac262>] v2_read_file_info+0x2c6/0xa10
fs/quota/quota_v2.c:122

    [<0000000005a7ae24>] dquot_load_quota_sb+0x692/0xe30 fs/quota/dquot.c:
2388

    [<0000000003d57be5>] dquot_load_quota_inode fs/quota/dquot.c:2424
[inline]

    [<0000000003d57be5>] dquot_load_quota_inode+0x1d1/0x330
fs/quota/dquot.c:2415

    [<00000000776b8d1b>] ext4_quota_enable fs/ext4/super.c:6401 [inline]

    [<00000000776b8d1b>] ext4_enable_quotas+0x53e/0x8c0 fs/ext4/super.c:6426

    [<000000007f6e8b33>] ext4_fill_super+0xbdd1/0xced0 fs/ext4/super.c:5035

    [<00000000eed8917b>] mount_bdev+0x331/0x3f0 fs/super.c:1367

    [<00000000d809ca96>] legacy_get_tree+0x105/0x220 fs/fs_context.c:594

    [<000000002503c8bb>] vfs_get_tree+0x8e/0x2f0 fs/super.c:1497

    [<00000000b9b2b4e2>] do_new_mount fs/namespace.c:2882 [inline]

    [<00000000b9b2b4e2>] path_mount+0x139a/0x2080 fs/namespace.c:3211

    miss 1 call

    [<00000000ccc3b35f>] __do_sys_mount fs/namespace.c:3432 [inline]

    [<00000000ccc3b35f>] __se_sys_mount fs/namespace.c:3409 [inline]

    [<00000000ccc3b35f>] __x64_sys_mount+0x27e/0x300 fs/namespace.c:3409

    [<00000000f471fbd6>] do_syscall_64+0x33/0x40 arch/x86/entry/common.c:46


Thank You
Best
Jin Huang


On Tue, Feb 2, 2021 at 4:08 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Tue, Feb 2, 2021 at 10:04 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
> >
> > Hi, Dimitry
> > Really thank you for your help.
> > I still want to ask some questions, did syzkaller directly use addr2line
> on the vmlinux dump file?
>
> I don't remember. In some places we used addr2line, but in some we
> switched to parsing DWARF manually.
>
> > I run syzkaller on linux-5.11-rc5 myself, and with the log and report,
> when I tried to use addr2line to reproduce the call stack as the one
> provided by syzkaller report, I found the result I got from addr2line are
> not so precise and completed as the syzkaller report. As shown in the
> screenshot below, the log and report of syzkaller and my callstack from
> addr2line. Do you have some idea what is wrong with my solution?
>
> I can't see any pictures (please post text in future),  but I suspect
> you did not subtract 1 from return PCs.
> Most PCs in stack traces are call _return_ PCs and point to the _next_
> instruction. So you need to subtract 1 from most PCs in the trace.
>
>
> > Below is mine, misses 2 top inline function call info, and the line
> number sometimes will be 1 or 2 more, sometimes correct, so weird.
> > First I generate the objdump file of the vmlinux: objdump -d vmlinux >
> vmlinux.S
> > Then, get the address of the function call in vmlinux.S and add the
> offset, and use adr2line to get the file:line info, like: addr2line -f -i
> -e vmlinux 0xffffffff8177927e/0x300
> >
> > I have marked the mistakes red.
> >
> >
> >
> > Thank You
> > Best
> > Jin Huang
> >
> >
> > On Fri, Jan 29, 2021 at 3:03 AM Dmitry Vyukov <dvyukov@google.com>
> wrote:
> >>
> >> On Fri, Jan 29, 2021 at 1:07 AM Jin Huang <andy.jinhuang@gmail.com>
> wrote:
> >> >
> >> > Thank you for your reply, Paul.
> >> >
> >> > Sorry I did not state my question clearly, my question is now I want
> to get the call stack myself, not from syzkaller report. For example I
> write the code in linux kernel some point, dump_stack(), then I can get the
> call stack when execution, and later I can translate the symbol to get the
> file:line.
> >> >
> >> > But the point is dump_stack() function in Linux Kernel does not
> contain the inline function calls as shown below, if I want to implement
> display call stack myself, do you have any idea? I think I can modify
> dump_stack(), but seems I cannot figure out where the address of inline
> function is, according to the source code of dump_stack() in Linux Kernel,
> it only displays the address of the function call within
> 'kernel_text_address', or maybe the inline function calls have  not even
> been recorded. Or maybe I am not on the right track.
> >> > I also try to compile with -fno-inline, but the kernel cannot be
> compiled successfully in this way.
> >> >
> >> > Syzkaller report:
> >> >
> >> > dont_mount include/linux/dcache.h:355 [inline]
> >> >
> >> >  vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> >> >
> >> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> >> >
> >> >  __do_sys_unlink fs/namei.c:3945 [inline]
> >> >
> >> >  __se_sys_unlink fs/namei.c:3943 [inline]
> >> >
> >> >  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> >> >
> >> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> >> >
> >> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> >> >
> >> >
> >> > dump_stack result, the inline function calls are missing.
> >> >
> >> > vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> >> >
> >> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> >> >
> >> >   __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> >> >
> >> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> >> >
> >> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> >>
> >> Inlining info is provided by addr2line with -i flag.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnaoJX7Dw_zoLyQdfgSv38MDo2zF8MGs9%3DCpiUa7LEju7sg%40mail.gmail.com.

--000000000000ba49be05ba56e6f3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br><div>Seems sometimes need to subtract 1 and sometimes =
not? How could we know?=C2=A0</div><div>And seems parsing DWARF will be a b=
etter option? At least I see the addr2line result misses some inline call i=
nfo in the stack.</div><div><font size=3D"4"><br></font></div><div>syzkalle=
r log <br>=C2=A0 backtrace:<br>=C2=A0 =C2=A0 [&lt;00000000e98ac262&gt;] v2_=
read_file_info+0x2c6/0xa10<br>=C2=A0 =C2=A0 [&lt;0000000005a7ae24&gt;] dquo=
t_load_quota_sb+0x692/0xe30<br>=C2=A0 =C2=A0 [&lt;0000000003d57be5&gt;] dqu=
ot_load_quota_inode+0x1d1/0x330<br>=C2=A0 =C2=A0 [&lt;00000000776b8d1b&gt;]=
 ext4_enable_quotas+0x53e/0x8c0<br>=C2=A0 =C2=A0 [&lt;000000007f6e8b33&gt;]=
 ext4_fill_super+0xbdd1/0xced0<br>=C2=A0 =C2=A0 [&lt;00000000eed8917b&gt;] =
mount_bdev+0x331/0x3f0<br>=C2=A0 =C2=A0 [&lt;00000000d809ca96&gt;] legacy_g=
et_tree+0x105/0x220<br>=C2=A0 =C2=A0 [&lt;000000002503c8bb&gt;] vfs_get_tre=
e+0x8e/0x2f0<br>=C2=A0 =C2=A0 [&lt;00000000b9b2b4e2&gt;] path_mount+0x139a/=
0x2080<br>=C2=A0 =C2=A0 [&lt;00000000ccc3b35f&gt;] __x64_sys_mount+0x27e/0x=
300<br>=C2=A0 =C2=A0 [&lt;00000000f471fbd6&gt;] do_syscall_64+0x33/0x40<br>=
=C2=A0 =C2=A0 [&lt;000000005a34ab49&gt;] entry_SYSCALL_64_after_hwframe+0x4=
4/0xa9<font size=3D"4"><br></font></div><div><br></div><div>syzkaller repor=
t<br>=C2=A0 backtrace:<br>=C2=A0 =C2=A0 [&lt;00000000e98ac262&gt;] kmalloc =
include/linux/slab.h:552 [inline]<br>=C2=A0 =C2=A0 [&lt;00000000e98ac262&gt=
;] v2_read_file_info+0x2c6/0xa10 fs/quota/quota_v2.c:122<br>=C2=A0 =C2=A0 [=
&lt;0000000005a7ae24&gt;] dquot_load_quota_sb+0x692/0xe30 fs/quota/dquot.c:=
2387<br>=C2=A0 =C2=A0 [&lt;0000000003d57be5&gt;] dquot_load_quota_inode fs/=
quota/dquot.c:2423 [inline]<br>=C2=A0 =C2=A0 [&lt;0000000003d57be5&gt;] dqu=
ot_load_quota_inode+0x1d1/0x330 fs/quota/dquot.c:2415<br>=C2=A0 =C2=A0 [&lt=
;00000000776b8d1b&gt;] ext4_quota_enable fs/ext4/super.c:6400 [inline]<br>=
=C2=A0 =C2=A0 [&lt;00000000776b8d1b&gt;] ext4_enable_quotas+0x53e/0x8c0 fs/=
ext4/super.c:6426<br>=C2=A0 =C2=A0 [&lt;000000007f6e8b33&gt;] ext4_fill_sup=
er+0xbdd1/0xced0 fs/ext4/super.c:5034<br>=C2=A0 =C2=A0 [&lt;00000000eed8917=
b&gt;] mount_bdev+0x331/0x3f0 fs/super.c:1366<br>=C2=A0 =C2=A0 [&lt;0000000=
0d809ca96&gt;] legacy_get_tree+0x105/0x220 fs/fs_context.c:592<br>=C2=A0 =
=C2=A0 [&lt;000000002503c8bb&gt;] vfs_get_tree+0x8e/0x2f0 fs/super.c:1496<b=
r>=C2=A0 =C2=A0 [&lt;00000000b9b2b4e2&gt;] do_new_mount fs/namespace.c:2881=
 [inline]<br>=C2=A0 =C2=A0 [&lt;00000000b9b2b4e2&gt;] path_mount+0x139a/0x2=
080 fs/namespace.c:3211<br>=C2=A0 =C2=A0 [&lt;00000000ccc3b35f&gt;] do_moun=
t fs/namespace.c:3224 [inline]<br>=C2=A0 =C2=A0 [&lt;00000000ccc3b35f&gt;] =
__do_sys_mount fs/namespace.c:3432 [inline]<br>=C2=A0 =C2=A0 [&lt;00000000c=
cc3b35f&gt;] __se_sys_mount fs/namespace.c:3409 [inline]<br>=C2=A0 =C2=A0 [=
&lt;00000000ccc3b35f&gt;] __x64_sys_mount+0x27e/0x300 fs/namespace.c:3409<b=
r>=C2=A0 =C2=A0 [&lt;00000000f471fbd6&gt;] do_syscall_64+0x33/0x40 arch/x86=
/entry/common.c:46<br>=C2=A0 =C2=A0 [&lt;000000005a34ab49&gt;] entry_SYSCAL=
L_64_after_hwframe+0x44/0xa9<br></div><div><br></div><div><div>Below is min=
e, misses 2 top inline function call info, and the line number sometimes wi=
ll be 1 or 2 more, sometimes correct, so weird.</div><div>First I generate=
=C2=A0the objdump file of the vmlinux:=C2=A0<span style=3D"background-color=
:transparent;color:rgb(0,0,0);font-family:Arial;white-space:pre-wrap">objdu=
mp -d vmlinux &gt; vmlinux.S</span></div><div><span style=3D"background-col=
or:transparent;color:rgb(0,0,0);font-family:Arial;white-space:pre-wrap">The=
n, get the address of the function call in vmlinux.S and add the offset, an=
d use adr2line to get the file:line info, like: </span><span style=3D"backg=
round-color:transparent;color:rgb(0,0,0);font-family:Arial;white-space:pre-=
wrap">addr2line -f -i -e vmlinux 0xffffffff8177927e/0x300</span></div><div>=
<span style=3D"background-color:transparent;color:rgb(0,0,0);font-family:Ar=
ial;white-space:pre-wrap"><br></span></div><div><span style=3D"background-c=
olor:transparent;color:rgb(0,0,0);font-family:Arial;white-space:pre-wrap">I=
 have marked the mistakes red.</span></div></div><div><span id=3D"gmail-m_-=
7162427106550590751gmail-docs-internal-guid-a4ba6c97-7fff-46a0-53ea-8018f74=
2c19d"><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-botto=
m:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0My Back=
trace:</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;ma=
rgin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(=
0,0,0);background-color:transparent;font-variant-numeric:normal;font-varian=
t-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=
=A0=C2=A0=C2=A0</span><span style=3D"font-size:11pt;font-family:Arial;color=
:rgb(255,0,0);background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">mi=
ss 1 call</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt=
;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:r=
gb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-var=
iant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=
=C2=A0=C2=A0=C2=A0[&lt;00000000e98ac262&gt;] v2_read_file_info+0x2c6/0xa10 =
fs/quota/quota_v2.c:122</span></p><p dir=3D"ltr" style=3D"line-height:1.38;=
margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family=
:Arial;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;vertical-align:baseline;white-space:pr=
e-wrap">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;0000000005a7ae24&gt;] dquot_load_quota=
_sb+0x692/0xe30 fs/quota/dquot.c:</span><span style=3D"font-size:11pt;font-=
family:Arial;color:rgb(255,0,0);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;vertical-align:baseline;white-=
space:pre-wrap">2388</span></p><p dir=3D"ltr" style=3D"line-height:1.38;mar=
gin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Ar=
ial;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;vertical-align:baseline;white-space:pre-w=
rap">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;0000000003d57be5&gt;] dquot_load_quota_in=
ode fs/quota/dquot.c:</span><span style=3D"font-size:11pt;font-family:Arial=
;color:rgb(255,0,0);background-color:transparent;font-variant-numeric:norma=
l;font-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wr=
ap">2424</span><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;vertical-align:baseline;white-space:pre-wrap"> [inline]</=
span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bot=
tom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=
=A0=C2=A0[&lt;0000000003d57be5&gt;] dquot_load_quota_inode+0x1d1/0x330 fs/q=
uota/dquot.c:2415</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin=
-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial=
;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;=
font-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap=
">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;00000000776b8d1b&gt;] ext4_quota_enable fs/e=
xt4/super.c:</span><span style=3D"font-size:11pt;font-family:Arial;color:rg=
b(255,0,0);background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">6401<=
/span><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;vertical-align:baseline;white-space:pre-wrap"> [inline]</span></p>=
<p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt">=
<span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=A0=C2=A0[&=
lt;00000000776b8d1b&gt;] ext4_enable_quotas+0x53e/0x8c0 fs/ext4/super.c:642=
6</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-=
bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0=
);background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=
=C2=A0=C2=A0[&lt;000000007f6e8b33&gt;] ext4_fill_super+0xbdd1/0xced0 fs/ext=
4/super.c:</span><span style=3D"font-size:11pt;font-family:Arial;color:rgb(=
255,0,0);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">5035</s=
pan></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bott=
om:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=A0=
=C2=A0[&lt;00000000eed8917b&gt;] mount_bdev+0x331/0x3f0 fs/super.c:</span><=
span style=3D"font-size:11pt;font-family:Arial;color:rgb(255,0,0);backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;vertical-align:baseline;white-space:pre-wrap">1367</span></p><p dir=3D"=
ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span styl=
e=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;vertica=
l-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;0000000=
0d809ca96&gt;] legacy_get_tree+0x105/0x220 fs/fs_context.c:</span><span sty=
le=3D"font-size:11pt;font-family:Arial;color:rgb(255,0,0);background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;vert=
ical-align:baseline;white-space:pre-wrap">594</span></p><p dir=3D"ltr" styl=
e=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:b=
aseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;000000002503c8bb=
&gt;] vfs_get_tree+0x8e/0x2f0 fs/super.c:</span><span style=3D"font-size:11=
pt;font-family:Arial;color:rgb(255,0,0);background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;vertical-align:baselin=
e;white-space:pre-wrap">1497</span></p><p dir=3D"ltr" style=3D"line-height:=
1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-f=
amily:Arial;color:rgb(0,0,0);background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;vertical-align:baseline;white-spa=
ce:pre-wrap">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;00000000b9b2b4e2&gt;] do_new_moun=
t fs/namespace.c:</span><span style=3D"font-size:11pt;font-family:Arial;col=
or:rgb(255,0,0);background-color:transparent;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=
2882</span><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0)=
;background-color:transparent;font-variant-numeric:normal;font-variant-east=
-asian:normal;vertical-align:baseline;white-space:pre-wrap"> [inline]</span=
></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:=
0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);backg=
round-color:transparent;font-variant-numeric:normal;font-variant-east-asian=
:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=A0=C2=
=A0[&lt;00000000b9b2b4e2&gt;] path_mount+0x139a/0x2080 fs/namespace.c:3211<=
/span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bo=
ttom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);=
background-color:transparent;font-variant-numeric:normal;font-variant-east-=
asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=C2=
=A0=C2=A0</span><span style=3D"font-size:11pt;font-family:Arial;color:rgb(2=
55,0,0);background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">miss 1 c=
all</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margi=
n-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0=
,0);background-color:transparent;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=C2=A0=
=C2=A0=C2=A0[&lt;00000000ccc3b35f&gt;] __do_sys_mount fs/namespace.c:3432 [=
inline]</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;m=
argin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb=
(0,0,0);background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=
=C2=A0=C2=A0=C2=A0[&lt;00000000ccc3b35f&gt;] __se_sys_mount fs/namespace.c:=
3409 [inline]</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top=
:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;col=
or:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=
=C2=A0=C2=A0=C2=A0=C2=A0[&lt;00000000ccc3b35f&gt;] __x64_sys_mount+0x27e/0x=
300 fs/namespace.c:3409</span></p><p dir=3D"ltr" style=3D"line-height:1.38;=
margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family=
:Arial;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;vertical-align:baseline;white-space:pr=
e-wrap">=C2=A0=C2=A0=C2=A0=C2=A0[&lt;00000000f471fbd6&gt;] do_syscall_64+0x=
33/0x40 arch/x86/entry/common.c:46</span></p></span><br></div><div></div><d=
iv><div dir=3D"ltr" class=3D"gmail_signature" data-smartmail=3D"gmail_signa=
ture"><div dir=3D"ltr"><div><br></div><div>Thank You</div>Best<div>Jin Huan=
g</div></div></div></div><br></div><br><div class=3D"gmail_quote"><div dir=
=3D"ltr" class=3D"gmail_attr">On Tue, Feb 2, 2021 at 4:08 AM Dmitry Vyukov =
&lt;<a href=3D"mailto:dvyukov@google.com">dvyukov@google.com</a>&gt; wrote:=
<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8=
ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">On Tue, Feb 2, =
2021 at 10:04 AM Jin Huang &lt;<a href=3D"mailto:andy.jinhuang@gmail.com" t=
arget=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hi, Dimitry<br>
&gt; Really thank you for your help.<br>
&gt; I still want to ask some questions, did syzkaller directly use addr2li=
ne on the vmlinux dump file?<br>
<br>
I don&#39;t remember. In some places we used addr2line, but in some we<br>
switched to parsing DWARF manually.<br>
<br>
&gt; I run syzkaller on linux-5.11-rc5 myself, and with the log and report,=
 when I tried to use addr2line to reproduce the call stack as the one provi=
ded by syzkaller report, I found the result I got from addr2line are not so=
 precise and completed as the syzkaller report. As shown in the screenshot =
below, the log and report of syzkaller and my callstack from addr2line. Do =
you have some idea what is wrong with my solution?<br>
<br>
I can&#39;t see any pictures (please post text in future),=C2=A0 but I susp=
ect<br>
you did not subtract 1 from return PCs.<br>
Most PCs in stack traces are call _return_ PCs and point to the _next_<br>
instruction. So you need to subtract 1 from most PCs in the trace.<br>
<br>
<br>
&gt; Below is mine, misses 2 top inline function call info, and the line nu=
mber sometimes will be 1 or 2 more, sometimes correct, so weird.<br>
&gt; First I generate the objdump file of the vmlinux: objdump -d vmlinux &=
gt; vmlinux.S<br>
&gt; Then, get the address of the function call in vmlinux.S and add the of=
fset, and use adr2line to get the file:line info, like: addr2line -f -i -e =
vmlinux 0xffffffff8177927e/0x300<br>
&gt;<br>
&gt; I have marked the mistakes red.<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; Thank You<br>
&gt; Best<br>
&gt; Jin Huang<br>
&gt;<br>
&gt;<br>
&gt; On Fri, Jan 29, 2021 at 3:03 AM Dmitry Vyukov &lt;<a href=3D"mailto:dv=
yukov@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Fri, Jan 29, 2021 at 1:07 AM Jin Huang &lt;<a href=3D"mailto:an=
dy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wr=
ote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Thank you for your reply, Paul.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Sorry I did not state my question clearly, my question is now=
 I want to get the call stack myself, not from syzkaller report. For exampl=
e I write the code in linux kernel some point, dump_stack(), then I can get=
 the call stack when execution, and later I can translate the symbol to get=
 the file:line.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; But the point is dump_stack() function in Linux Kernel does n=
ot contain the inline function calls as shown below, if I want to implement=
 display call stack myself, do you have any idea? I think I can modify dump=
_stack(), but seems I cannot figure out where the address of inline functio=
n is, according to the source code of dump_stack() in Linux Kernel, it only=
 displays the address of the function call within &#39;kernel_text_address&=
#39;, or maybe the inline function calls have=C2=A0 not even been recorded.=
 Or maybe I am not on the right track.<br>
&gt;&gt; &gt; I also try to compile with -fno-inline, but the kernel cannot=
 be compiled successfully in this way.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Syzkaller report:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; dont_mount include/linux/dcache.h:355 [inline]<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 vfs_unlink+0x269/0x3b0 fs/namei.c:3837<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 __do_sys_unlink fs/namei.c:3945 [inline]<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 __se_sys_unlink fs/namei.c:3943 [inline]<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; dump_stack result, the inline function calls are missing.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; vfs_unlink+0x269/0x3b0 fs/namei.c:3837<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 =C2=A0__x64_sys_unlink+0x2c/0x30 fs/namei.c:3943<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9<br>
&gt;&gt;<br>
&gt;&gt; Inlining info is provided by addr2line with -i flag.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnaoJX7Dw_zoLyQdfgSv38MDo2zF8MGs9%3DCpiUa7LEju7s=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CACV%2BnaoJX7Dw_zoLyQdfgSv38MDo2zF8MGs9%3DCpiUa=
7LEju7sg%40mail.gmail.com</a>.<br />

--000000000000ba49be05ba56e6f3--
