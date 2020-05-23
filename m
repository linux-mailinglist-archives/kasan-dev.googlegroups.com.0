Return-Path: <kasan-dev+bncBCMIZB7QWENRBB5XUT3AKGQETNR3E4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DC251DF747
	for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 14:48:08 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id r3sf10371259pfg.12
        for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 05:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590238087; cv=pass;
        d=google.com; s=arc-20160816;
        b=sHwM9R9xaetQCjNjgl8LTOnMNt3wq+UuBVqyk5XEue2Z1/fbNStJ94/c61+VCrjtvD
         mh1eDuzbbvQcLT3pNpziUQuig19Zduse+JTS9VLvI6tJtajlLKLnM2wF0HUoCYdgxh/N
         23iw25K1+eP1MC2KKOvOEBLDSgcvn3aTJyH0aQSqHFXWDPWNp5ACVbxxXz5HUK7cgkaT
         zq55rHPCHBMdPukDmwxDO97G8lvNma48Sks6/R/6M0/x8aE75V6nIyEKAakv66y6U2+2
         et7wKf5GxjckZlX6jR6Lvoeot0Vpx/iJjiY+IPtHHweLEk/nU6sdqRglUs4fbaxZNHlD
         zf8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=up0V4HBjI2DHvHLmHwFauE1y1zwinfcgptiVfh+L32s=;
        b=f2gjI1bCez6pxhhnllzmUY6v4IF+AlkWrA4s3dbqKEyalGW0KmIL2Ti3Jm6KqFqQ5+
         0QVi0qxxBYwpPOM0ErDjNby4slJ+rx2hT3wkOD2o/kf2yIuS3k5cHNKat+jWoNqeHbjE
         ovKLUW6LpdCKELTrgfhmH9a2toL9nVPdmz/1CMs2hlwJn/6y/9uGbc3bRt32TCFHF/X2
         26HcD20kn8V2Ajh7X9nHPwGQ1DTXWFKaumIvTnZ9cPQlulrbCrmu6IQzl1L6k5p9XEaY
         NwGY+NVeeUXxbEAnHu1x+e8p1O6IumdcmaqShrn/I4FC73DuvxtF7vaTpgsHp5IUK/M+
         wRFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EvIQkIPd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=up0V4HBjI2DHvHLmHwFauE1y1zwinfcgptiVfh+L32s=;
        b=q8K2gCbjrQov81wAJCHxTrsbAAUnC4A8TA0VaX7/WTJRgJfppL6+tsneiOqvgXA9Jt
         gloifZy2W8PSHz2J/0BLCmfPSgDKfj2bmUzGzc/hxkhE2977154gTl0vwPaVYBuESjdT
         3SHv19baM3mtMjkVUyqVIeW8GX+YCREEiaNfh26ZrNSuszNenFgcOm8wiopT7AZ+SBcf
         4W3zx7jjt5RHWTKdiwyBq089YX8Lkw7/Mp5x8nkIaSJyKjhCbVXieH3OPs5MzXI4UWUZ
         MB0e5FUifpMraFQYwroMYU3yhBBlibHk0GlVlCAzEkakE+IH8WfYbaROz3pUhndnO6iG
         cD7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=up0V4HBjI2DHvHLmHwFauE1y1zwinfcgptiVfh+L32s=;
        b=nM/GZPGgVUJrcKxxt78GLHF8fgoDb7TVFcuTqIUwgAVVdZi+fmgKoL4h3Q5JRAZrqd
         7H2e0xF+Ffl3A/9MgzTONMYZw40RDP3RVE76dwm+fadOqPSfi0n3gO5B2AKJCXCo3qNQ
         q16UscgODLAxichqiEa+usfNiBoCjLWnf7A6h3AYFEAQrkHq3I7yDJqHh1tUYayJ3/1I
         UKBzrnJ7TlgplBLw4774t3/HdNLlj5gORMsFMKk2D4JjID48o5CLp2dX7yrr+pE/GgMm
         JL7SW/LHwB5IrVcyDJmvH4Z/g7wtutHp+YO4jChegMxtLOFV7rLY9CEliXkb6sJLlOcq
         7m9A==
X-Gm-Message-State: AOAM5300r5pdl2jwuqJMJ77Nqsj63TNmDUaq4Hf+PA0hmcq10jBEQINz
	FlQGhu1xWyVWgEFO9ZwHq3w=
X-Google-Smtp-Source: ABdhPJxmn969AC+dO0Q2h8ASn9OwDGpbCTb/kADzB02XzcfBWYk1EaD1MX7yNhaEkgi4kqWvP4FEEQ==
X-Received: by 2002:a62:e117:: with SMTP id q23mr9048421pfh.188.1590238087140;
        Sat, 23 May 2020 05:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d684:: with SMTP id v4ls1556962ply.11.gmail; Sat, 23
 May 2020 05:48:06 -0700 (PDT)
X-Received: by 2002:a17:902:c489:: with SMTP id n9mr19202041plx.186.1590238086716;
        Sat, 23 May 2020 05:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590238086; cv=none;
        d=google.com; s=arc-20160816;
        b=b6OgrOP6iILt6B9sYRjzDnPshD/Qp+pLRFXjcMCWWiV8/wCEaGxvXT3UEQkbY252yP
         4yjVhaRfRFYL0JekC1gopnPVNBmGNZJwH+jMW4lQ5SgXYrX1QFePA94NekGKLWe87SaV
         P1MKDuaI0LwrbFNn1vM6KjFguFjsjcfmHgD8wI8wo1tANE4aL5Dq+qETDNhsxDOF9GwZ
         BHVvoeJ46PIORjL6DDOthvYhKVpAkacPyLCLSR64d//UVqEHkMhuIPnMPhDrdb7MhbSU
         FznLH1rr47E6pO4L0hmDem036MV/oV03BOqpJfYsQBPpijLj/2cN8YZUt8YCv6LZy1VB
         uBXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+dzkYsLXQ/6pCwh8XLHuqb5R6wUCjmMnznnLfjKGHMs=;
        b=NEudIx9EmDQQPRXCz4/VOpW9RpFLGaoiLiRqfMM1Rne01kUY8KTtpFrTsLUIo7mMgV
         n3y9MCrNbICEbMsTQwSl6J6/9gLqehhbgzhNbErr71ryHiRcn4VpmEYbn9lwx6BPqaab
         oeL1wiowyYZrWY9i9UQT+3Mu/dKoXcB0GWOCc8gDcC3h2K7jOGzpZh4xV8cbpEpnkH8/
         eWTADhwrtI9TPYd+SunDaUFpTnXqxJ581FSqAzZtZGu2L5ca9zMEcrrG4P/QZBexUm6m
         G3GKPi5HEnNt0VBfb7zJHayyvnYoCdm2jt064Cyejbs4wPdQHvY4DBnEQq6tUkLF0O8y
         NAAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EvIQkIPd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id c15si1233440pjv.1.2020.05.23.05.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 May 2020 05:48:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id v79so3338612qkb.10
        for <kasan-dev@googlegroups.com>; Sat, 23 May 2020 05:48:06 -0700 (PDT)
X-Received: by 2002:a05:620a:990:: with SMTP id x16mr18823834qkx.256.1590238085646;
 Sat, 23 May 2020 05:48:05 -0700 (PDT)
MIME-Version: 1.0
References: <18768d5f-b3ee-4c46-a87f-2d3642fd923b@googlegroups.com>
In-Reply-To: <18768d5f-b3ee-4c46-a87f-2d3642fd923b@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 23 May 2020 14:47:53 +0200
Message-ID: <CACT4Y+biun_HgJT+RRPq--aRJ9nL+qoeqmVB4HwekxW04Y4yUg@mail.gmail.com>
Subject: Re: Is this a bug in KASAN?
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EvIQkIPd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Fri, May 22, 2020 at 10:35 PM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangab=
cd@gmail.com> wrote:
>
> Hi all, I found an issue in analyzing the bug(https://syzkaller.appspot.c=
om/bug?id=3Dd75bc1468fb7ff9c2fa47437f4f1dc87ec7d8094).
>
> From the allocation and free trace, we could find that the related object=
 is "struct inode"(inode =3D kmem_cache_alloc(inode_cachep, GFP_KERNEL);  a=
nd kmem_cache_free(inode_cachep, inode);)
>
> Allocated by task 2222:
>  save_stack+0x43/0xd0 mm/kasan/kasan.c:448
>  set_track mm/kasan/kasan.c:460 [inline]
>  kasan_kmalloc+0xc4/0xe0 mm/kasan/kasan.c:553
>  kasan_slab_alloc+0x12/0x20 mm/kasan/kasan.c:490
>  kmem_cache_alloc+0x12e/0x760 mm/slab.c:3554
>  alloc_inode+0xb2/0x190 fs/inode.c:212
>  new_inode_pseudo+0x69/0x1a0 fs/inode.c:895
>  get_pipe_inode fs/pipe.c:707 [inline]
>  create_pipe_files+0x90/0x940 fs/pipe.c:748
>  umh_pipe_setup+0xac/0x430 kernel/umh.c:431
>  call_usermodehelper_exec_async+0x3c0/0x9e0 kernel/umh.c:93
>  ret_from_fork+0x3a/0x50 arch/x86/entry/entry_64.S:412
>
> Freed by task 2222:
>  save_stack+0x43/0xd0 mm/kasan/kasan.c:448
>  set_track mm/kasan/kasan.c:460 [inline]
>  __kasan_slab_free+0x11a/0x170 mm/kasan/kasan.c:521
>  kasan_slab_free+0xe/0x10 mm/kasan/kasan.c:528
>  __cache_free mm/slab.c:3498 [inline]
>  kmem_cache_free+0x86/0x2d0 mm/slab.c:3756
>  free_inode_nonrcu+0x1c/0x20 fs/inode.c:230
>  destroy_inode+0x151/0x1f0 fs/inode.c:267
>  evict+0x5cd/0x960 fs/inode.c:575
>  iput_final fs/inode.c:1520 [inline]
>  iput+0x62d/0xa80 fs/inode.c:1546
>  dentry_unlink_inode+0x49a/0x620 fs/dcache.c:376
>  __dentry_kill+0x444/0x790 fs/dcache.c:568
>  dentry_kill+0xc9/0x5a0 fs/dcache.c:687
>  dput.part.26+0x65a/0x780 fs/dcache.c:848
>  dput+0x15/0x20 fs/dcache.c:830
>  __fput+0x558/0x890 fs/file_table.c:227
>  ____fput+0x15/0x20 fs/file_table.c:243
>  task_work_run+0x1e4/0x290 kernel/task_work.c:113
>  exit_task_work include/linux/task_work.h:22 [inline]
>  do_exit+0x1aee/0x2730 kernel/exit.c:865
>  do_group_exit+0x16f/0x430 kernel/exit.c:968
>  __do_sys_exit_group kernel/exit.c:979 [inline]
>  __se_sys_exit_group kernel/exit.c:977 [inline]
>  __x64_sys_exit_group+0x3e/0x50 kernel/exit.c:977
>  do_syscall_64+0x1b1/0x800 arch/x86/entry/common.c:287
>  entry_SYSCALL_64_after_hwframe+0x49/0xbe
>
> But the use site of this bug is in the "io_is_direct". And the correspond=
ing memory reference is "return (filp->f_flags & O_DIRECT) || IS_DAX(filp->=
f_mapping->host);". I do not find any operation related with the inode obje=
ct.
>
> So is this a bug in the KASAN?

Hi,

KASAN makes several practical tradeoffs regarding bug detection
probability and precision.
Out-of-bound detection is based on finite size redzones and
use-after-free detection is based on finite size quarantine for freed
objects. Both these aspects may lead to both missed bugs and
misreported bugs. This is an intentional tradeoff and it is not
fixable with the current implementation approach.

For that particular KASAN report, most likely there is a real bug at
the reported call stack, but allocation/free stacks belong to a
different heap object.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Bbiun_HgJT%2BRRPq--aRJ9nL%2BqoeqmVB4HwekxW04Y4yUg%40mail.=
gmail.com.
