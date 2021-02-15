Return-Path: <kasan-dev+bncBCMIZB7QWENRBCFZVGAQMGQER2S26DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id E909231B812
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 12:35:37 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id l16sf6647937ion.8
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 03:35:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613388936; cv=pass;
        d=google.com; s=arc-20160816;
        b=n8KiSojWup5BzFNOI+LYqk71RoOYJW8vz0SPNHcK1S9iX0P7i27/PqEiN8Z/1S44f2
         VX7Lx0iUtOW09RSQZ6sRPz31LxxkKpFg9LPVtOHWxsLN/NKgQhw8v4RE0dm9YpyTOsXK
         BCM6hOFqUhWPMVAUKOfmwDkNgdUzw4hFOqa6T1qQSQoOV4dS8SstUGMLlPEiOy7tZWeg
         xlyBwZnhdtF10a35f9pRhDNkNhHuhRY8Yl+rU/rbx+mYasB2+ySeI6OkKo7DuyXNppXh
         wJuZQOeiKBaPHAPmcUD9v0IfjeWSjHU2nAbRjUjJILGGJ1fi6SM4zrVMcrMEUoMLuu5I
         muPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=z84oCofPrTWjv+fNbBbbQCuhYW8SiLkyEb9u0axGlso=;
        b=c9YmCQ6eK/40wWp55FCxJ8vALOTk53hvGX6e26w42nEDSDd46j13U3LweDfT37JAJ2
         EiFJb6c8nBigkPpilClIh5Q1RS/DbhtKgy3o5ehfS+l/LDpuY9eQQ91R/dp72gTvCBCt
         8eHlzLU6CKSHI2/xhSmdDi8yyDZolVq42lkhtyWnZt+NUwLfd58ZAAfgcL/kObaRORJF
         4cGdlg3eeSYWBJYZZV1Vi9yBc/wYl5OwhJqavp6WU6sn9irKu0N2bZNmT/OwKBmENqox
         dNxBEPIkfxoPCjwUPLWOcYAAtk7APsdiV6WFgFgv0WY5QdekKRw/a1AZGQp5XQmLyRzi
         Na8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MrJePHdF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z84oCofPrTWjv+fNbBbbQCuhYW8SiLkyEb9u0axGlso=;
        b=pAEbZ3f1vE+5iRdmxkA8+YAuQkqiIPv9+6PupNDnlyjlen+y6rQ3u4/HxJOyrCJiXY
         I4AYd+yyGwiYBJSI9lM+0EoFfp8j7SYWFGQhnPdsyRw+WVGTS4TXvA9g3cN1aGcr1o+x
         5sjSAGchbB91OBKRN+Vt5jRJRwhySyNbx7YWpu85eVDEHhyMT03oCysblhanL35Tyv+a
         reKptU/Qzu3OhS7EbQz7MOKEHmkZEIM+wcSEchE+eHAT+4QrU7TAzAyiZi3s/nJBEaut
         8F1PZgqnfTFmhtr28yFwbtD/yVrd5k9OA8azQLKNVrmfQme3WCTqLtaJJEgHeVOE54OX
         garg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z84oCofPrTWjv+fNbBbbQCuhYW8SiLkyEb9u0axGlso=;
        b=EPO3Tj0SnAuvoseM5QyagZRdTJOYgOwBin9smCn4oytSgJO24RMOLB1WbW+D3T1fN6
         MVXDUxO0jlkiOCVBPZJyO9974VPKYO7C+91JcNFi7qNZp22COU/416AwwKJyWYFs7RPp
         /UkZlAAHfhhjIV3OCb6XLDNzPAfEZtbWccDrwk50OMWcEDJh3gcFWW/K1kzTlRypAhQr
         1eB59vdfsWIKP0pSTx0aDDNGqK7Na7Cw3U8ohMVbdSQVTIYJ6bZ/Oni89CBmby7Uh4XJ
         xJ0Ik2oltmKRc01Vr2vnTQNLG8NRGBUFfPPQeVASsmXm6nqxUXgMu8epT6NNZ9FdcUIL
         XzSQ==
X-Gm-Message-State: AOAM533kMWzolY3qfyK3bZ1jPoB8nSg+xKltrwGEVy4ar3kocFWjdXaN
	QWglwed8gRgdkb6+qY2+3J0=
X-Google-Smtp-Source: ABdhPJzh2DrpeBLXyDLDdfpmGCyPOtUFHWg5hb+h0NgXIWm0P5m/dqaD0/sNkxyKZEDClZty/d633A==
X-Received: by 2002:a05:6e02:1c0f:: with SMTP id l15mr12522001ilh.21.1613388936566;
        Mon, 15 Feb 2021 03:35:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f713:: with SMTP id k19ls2576234iog.3.gmail; Mon, 15 Feb
 2021 03:35:36 -0800 (PST)
X-Received: by 2002:a6b:d207:: with SMTP id q7mr12551054iob.42.1613388936171;
        Mon, 15 Feb 2021 03:35:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613388936; cv=none;
        d=google.com; s=arc-20160816;
        b=iFOhlE3RmlKVQMkmp75GbSJomfSN7vfbN50NsGSR6Bx4UaFY0a++vAwpPpa0sFXwer
         /qkSRUqMYjr+z14IkMqQbnckz8nPedA6jk/bIcraYwOV0iOOPm/nFCNmwfamq2yMkpjP
         fbpvBlhDOI2J5emLtszOYi5KF45sUhCRDwHA2KwArUSpb/1wl0OWT/E47XMIO/j97x8N
         wt6VSPrc1yI8KZ5vDCIr2hVgReieh5bj9zQYe6itvZWON74Imc3eQsulvF3nHHRDQrF7
         GaJV9osGz/kC0FO6Cgrgz85FMT3+LEcNhZI0cfbJmXNLTcq9syIVn/N1et4SL1coQFhA
         1sqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DuJTdKrLYIzVj2tXafxqvf4ZFvum5KsOZmSm/E+DInk=;
        b=yaVDcHRmguXGX2xEVcwA6mT38vc3cuxC7aN6BWSBYJxkmF+3tTSl/RZOZBWc6+I355
         xAfJfIyvaPFIMJEDLFeys6BGITyLnRjjtss7Os6JR3OrL2Yj35Df7y8OW011BLcKJxxt
         83xbHyYAIqLeVGCNXMR4oBKyuvCH9jmt5LcTHPr9/Vqt9FQrWmyR01vnAv5jpbpGhzBi
         HrBTtRcHw/68GxLJ4271g7InLm1nMSaN5nVj+fVrjDb7KPE7oT5REjAFMLS+7wqx17Yb
         7wKVJdoxqd2boiFwnqU2zdfKgOy5/xT/8xly2eKj562huPm+We21Jc5btS/OTT2l7i6y
         CJhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MrJePHdF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id r2si190398ilb.3.2021.02.15.03.35.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Feb 2021 03:35:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id c1so4616124qtc.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 03:35:36 -0800 (PST)
X-Received: by 2002:ac8:7512:: with SMTP id u18mr13545213qtq.290.1613388935393;
 Mon, 15 Feb 2021 03:35:35 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
 <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
 <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
 <CACV+naoDZiei0UR5psO05UhJXiYtgLzfBamoYNfKmOPNaBFr_g@mail.gmail.com>
 <CACT4Y+aCJOL3bQEcBNVqXWTWD5xZyB_E53_OGYB33gG+G8PLFQ@mail.gmail.com>
 <CACV+napVK9r2a61a8=bPcgAzeK+xdbg6fskBX+Aan2_b4+G5EQ@mail.gmail.com>
 <CACV+naq++A0btYaV8POmP8+_3BytCaGnOGDG6KmXYCfv463q1g@mail.gmail.com>
 <CACT4Y+bLfsCp_2s3Yb=B9p8DMGzDZsOvc=F0j5+mBpKLKnD8Vw@mail.gmail.com> <CACV+naoAE9B9+kk_C3HrXGdSHCpJC-vDBnhomYGLqK5msMfROA@mail.gmail.com>
In-Reply-To: <CACV+naoAE9B9+kk_C3HrXGdSHCpJC-vDBnhomYGLqK5msMfROA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Feb 2021 12:35:24 +0100
Message-ID: <CACT4Y+ah2=sWOHeeQs3fWf8Q+8=teKkBMKpQm+vMO7fO0hsp1g@mail.gmail.com>
Subject: Re: reproduce data race
To: Hunter J <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MrJePHdF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829
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

On Mon, Feb 15, 2021 at 11:06 AM Hunter J <andy.jinhuang@gmail.com> wrote:
>
> Hi, Dmitry
> I found it is hard for me to first select the potential program exceptions that could trigger data race.
> For example, the KCSAN data race report in the crash log is:
> BUG: KCSAN: data-race in step_into / vfs_unlink
> write to 0xffff9af42962b270 of 4 bytes by task 15262 on cpu 0:
> vfs_unlink+0x27a/0x3c0
> do_unlinkat+0x211/0x4c0
> __x64_sys_unlink+0x2c/0x30
> do_syscall_64+0x37/0x50
> entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
> read to 0xffff9af42962b270 of 4 bytes by task 110 on cpu 1:
> step_into+0x159/0xfb0
> walk_component+0x1a5/0x380
> path_lookupat+0x11d/0x560
> filename_lookup+0xf2/0x380
> user_path_at_empty+0x3b/0x50
> do_readlinkat+0x87/0x200
> __x64_sys_readlink+0x43/0x50
> do_syscall_64+0x37/0x50
> entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
> I even did not find any readlink syscall in the crash log file. Did I miss something?

Hi Jin,

Some syscalls may be executed by the syz-executor binary itself. It
needs to allocate some memory, etc, that's also syscalls.
Some syscalls may be executed by the syz-fuzzer binary.
Some syscalls may be executed by other processes in your user-space
system that are not related to syzkaller.



> On Thu, Feb 11, 2021 at 6:31 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Thu, Feb 11, 2021 at 10:49 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>> >
>> > Hi, Dmitry
>> > Still a question , for example the log I select is:
>> > 08:55:49 executing program 1:
>> > r0 = epoll_create(0x800)
>> > syz_io_uring_setup(0x472e, &(0x7f0000000100), &(0x7f0000ffe000/0x1000)=nil, &(0x7f0000ffc000/0x1000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
>> > epoll_wait(r0, &(0x7f0000000000)=[{}], 0x1, 0x0)
>> >
>> > 08:55:49 executing program 2:
>> > r0 = syz_io_uring_setup(0x61a1, &(0x7f0000000000)={0x0, 0x4ff, 0x1, 0x0, 0x32a}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000000080), &(0x7f00000000c0))
>> > syz_io_uring_setup(0x3243, &(0x7f0000000100)={0x0, 0xd02d, 0x20, 0x3, 0x16e, 0x0, r0}, &(0x7f0000ffc000/0x3000)=nil, &(0x7f0000ffc000/0x4000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
>> > clone(0x22102000, 0x0, 0x0, 0x0, 0x0)
>> > syz_io_uring_setup(0x2fa8, &(0x7f0000000200)={0x0, 0xd1a6, 0x0, 0x1, 0xf6, 0x0, r0}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x1000)=nil, &(0x7f0000000280), &(0x7f00000002c0))
>> >
>> > Could I generate the C program to run program1 and program2 on different threads? Or I need to generate for program1 and program2 separately and merge the program source code myself?
>> > Since I see the -threaded option for syz-prog2c, but not sure the effect.
>>
>> Such functionality does not exist now. If you need exactly that, you
>> need to merge yourself.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bah2%3DsWOHeeQs3fWf8Q%2B8%3DteKkBMKpQm%2BvMO7fO0hsp1g%40mail.gmail.com.
