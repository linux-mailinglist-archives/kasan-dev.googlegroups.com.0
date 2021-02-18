Return-Path: <kasan-dev+bncBCMIZB7QWENRB34AXGAQMGQEVBDJHEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6578231E872
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 11:24:48 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id a4sf893114ooj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 02:24:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613643887; cv=pass;
        d=google.com; s=arc-20160816;
        b=gB1Kkt9Zw/fYgI+zUXdO93dLWWvRQTp+5q/TIdEt1vY0VRwlV6QO1h5lfqbVmbDV4/
         lklGbLGnXaWUIFMBR2cH8M+X86Es1FqLiQ5h3iViMKLrwGYdlLBywIXoT1xWSFAIi1Lx
         axDOugKCoCkzVfBrzoZbIyTJN3HONvPucWlSmGIaBkWIclCUcmRTEIZ6MASBDcqMXlBE
         jj/3lBR2u79GRqQWgwadSe31v8rmmOkzsiAP/SMRR3zE1BtIW9Ktibv25TnlHl9h2emb
         DHoNJffR5H4rDy+0KweUBQcNnAy//ngwcUdQ6JGA4MX0+xfudy/nt9EYARXoCT65OfaE
         XrCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LacZUo8Ll8gHKNR56lu50dMqR1MFUY5P9Oa3lBpJvmQ=;
        b=fj60Q5376FiV4XTp3a+kGsfAIY3g1yaYsR3z2UFJOc/1g3WvgPjhjy1e+cYqcs4F4R
         pbGdZW3R+uzfHmQeqHU9KAFRptmCvQ69PgWsPUE0+gC56DfYGyqHILLvurkMRc1TuyqP
         tcKevjSe1kGXigcPuBumDvNY6mlzF7Z+IHGHcK8CrKRfiI3Zfm3E1UQcrGTgit1n+Sm+
         4218pm2oZaeYntQJPFbDcMETS5GKahKNiOL0eLgQ0M6I8u8/olSg4BUuW/BI+DfmDK0b
         nEKrPhQPW2v0gnunmpCnk6zdkX/BexOnkrKbzt/q4zSu2UM23QaqyrM/HoM3fQweIhud
         3KlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gmCbBsLo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LacZUo8Ll8gHKNR56lu50dMqR1MFUY5P9Oa3lBpJvmQ=;
        b=k63WIDxtWofnCqwaozPBeBH1QqZzlOHvrI2llq1DRuTr5Xt0uKr43KpeMfpCEHG4aT
         zk9DaT0CWYniVAh+NNzi8bjRa/+YottwCFy5TfXwLm1CjeiOQHtmuPfUbh/cRQofWT08
         xcHDcQPqKFLtkBGjwA4hH+rImBfSSEPuxvgz1nRPSsEfPxJikArnG6UwEf+G2SvjF7Jt
         nkaDrsh6I0AJfu6KQqsWJA3lfHRuoAOTw1Bma4P0Jb2RPSXpwSnGveiUAD555MMuJSgl
         wEeU/QY8pXi2xX30jRsHu8tCTzcXPR4wiOGHqPNK9ucQOnU3Cy6lKrDh2LzuLGe34x0a
         9pvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LacZUo8Ll8gHKNR56lu50dMqR1MFUY5P9Oa3lBpJvmQ=;
        b=ev/m3PTC5aX3vWWbHoZFyFthOm77l7OsA0rjBkV/yT6n5xJDz7TU01AzkCJoGVHeP2
         kAsOdLXkchrDyBCqbKcIi0XSszmMJMEUiRNhB+0XkZ+JBC98+K/Adq/JiW1MWO1MWK8H
         IwHlP4G7RCtR+cJEBYPump8sUa/pzyaLKYu1Lw7Vs0TNScwjqJcapQvHkOQE+eePLlPG
         GWL9JEy5vyC019dz3IGFAQBnfiyBkQAeIJAnCxBDsJ8Qmo/5HTGKhW8XwP88wCyx5BjN
         aVcw9jzbR+wT6sf5JGtJJqmzPrljKvTp7HYl4bNNdCHgZYS+/SEZHabI2gHDTZOKE/Ew
         JaWA==
X-Gm-Message-State: AOAM531iaXG7mjdM2v84id03e4IMYHuNXwdQR7YNQL/Mr7SG6OrP7wZD
	xwrdFZ/SOzJBeBioKiGkjMI=
X-Google-Smtp-Source: ABdhPJy2vZrT+M1CUoqHR/VNh8mSyufmlYjDwz/CKcaqOdUH51n5DA7OWPRBGwWTMUXHq03iUKlcPA==
X-Received: by 2002:a4a:db78:: with SMTP id o24mr2473468ood.69.1613643887171;
        Thu, 18 Feb 2021 02:24:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:4d:: with SMTP id v13ls1301589oic.3.gmail; Thu, 18
 Feb 2021 02:24:46 -0800 (PST)
X-Received: by 2002:a05:6808:1383:: with SMTP id c3mr2202060oiw.153.1613643886855;
        Thu, 18 Feb 2021 02:24:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613643886; cv=none;
        d=google.com; s=arc-20160816;
        b=wq65aKVe8ksLy2BeQzYi1OX8TnJzkil+wQ8rAjNkHX49nP7V+EuHL9a4KAMCfZyJQe
         KxO7dwG0xSkxg28CrLtLDXKKArVZaUFAj1D/ANbXSHhm3dA7o1qtLAwyl4VjIjaXqwWo
         x0EFQBe7Zj1GoQBV+KOxvG71JH3U5mJqoxm1gdBinnWJ+jpXVYt+aK5ZHyEIr94+V5V1
         3UGJTDVJ0OJObjcsMOB1rhidQL6f44Mi/+C+Jyo8SEh6nMghXQUExjsCuXf+pcyWHi2m
         kPz46CMvzvfdr1DUAACyQP25hKJZPAqJ6vDhG3lxQy77G/yK3H12v5CqgZlwm1xhn06F
         wtRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qe6LuOdye3LN3KxfBffrxpsnfajOIcjf7WHxonMjtkI=;
        b=GYpsVERzJBda/lBnfE7G1swjBoYmW7inHsoQojcRU09TmjnySILKcWnCj905fLwkE8
         aWT851iE5NEMuN5nDg1ZNMcdxi0gi7O7M8DZPgAaaqyiFraE2adzA7wG+rmvw8cwLsnM
         2pi/U0Y6lQ4xycEDtm+l0X//rGXsb5TOb3+pjyn+I6JLK1uFN/alK3iOPHmWCdRY4JXk
         X03YMHrqFuyPHVaD25rGIepd5QmBDobBxmFBxq2+LrIMethLHCWmSZ9LxdKhEHjN38uu
         4iJ2aTeFv64ITM5twrLLxUbVUbgRyPwxZ8BO0hvpf/kooev4N6BfV+dzflr2IjbeZVOL
         ailA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gmCbBsLo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id n19si497977oic.5.2021.02.18.02.24.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 02:24:46 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id z190so1519805qka.9
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 02:24:46 -0800 (PST)
X-Received: by 2002:a37:7306:: with SMTP id o6mr3624309qkc.231.1613643886000;
 Thu, 18 Feb 2021 02:24:46 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
 <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
 <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
 <CACV+naoDZiei0UR5psO05UhJXiYtgLzfBamoYNfKmOPNaBFr_g@mail.gmail.com>
 <CACT4Y+aCJOL3bQEcBNVqXWTWD5xZyB_E53_OGYB33gG+G8PLFQ@mail.gmail.com>
 <CACV+napVK9r2a61a8=bPcgAzeK+xdbg6fskBX+Aan2_b4+G5EQ@mail.gmail.com>
 <CACV+naq++A0btYaV8POmP8+_3BytCaGnOGDG6KmXYCfv463q1g@mail.gmail.com>
 <CACT4Y+bLfsCp_2s3Yb=B9p8DMGzDZsOvc=F0j5+mBpKLKnD8Vw@mail.gmail.com>
 <CACV+naoAE9B9+kk_C3HrXGdSHCpJC-vDBnhomYGLqK5msMfROA@mail.gmail.com>
 <CACT4Y+ah2=sWOHeeQs3fWf8Q+8=teKkBMKpQm+vMO7fO0hsp1g@mail.gmail.com> <CACV+naqWUYUgcadD6ADCKqLLgLUPBm6AgrHaQ3MHAJmYJvYbtg@mail.gmail.com>
In-Reply-To: <CACV+naqWUYUgcadD6ADCKqLLgLUPBm6AgrHaQ3MHAJmYJvYbtg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Feb 2021 11:24:34 +0100
Message-ID: <CACT4Y+ZnrkYSWDNMWaSwD6UKoryytOp63cfpy4-jddzaZ+LWAg@mail.gmail.com>
Subject: Re: reproduce data race
To: Hunter J <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gmCbBsLo;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::729
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

On Thu, Feb 18, 2021 at 10:25 AM Hunter J <andy.jinhuang@gmail.com> wrote:
>
> Hi, Dmitry
> When I try to run syz-kaller to reproduce this data race, syscalls of sendfile64 and write, https://lore.kernel.org/lkml/0000000000000cfff005a26226ce@google.com/.
> But when I set them in my .cfg file like this:
>
> {
> "target": "linux/amd64",
> "http": "127.0.0.1:56741",
> "workdir": "workdir",
> "kernel_obj": "linux-5.11",
> "image": "stretch.img",
> "sshkey": "stretch.id_rsa",
> "syzkaller": "gopath/src/github.com/google/syzkaller",
> "procs": 4,
> "type": "qemu",
> "vm": {
> "count": 8,
> "kernel": "/home/jin/syzkaller_space/linux-5.11/arch/x86/boot/bzImage",
> "cpu": 2,
> "mem": 4096
> },
> "enable_syscalls" : ["open", "sendfile64", "write"]
> }
>
> Then syz-manager complains 'unknown enabled syscall: sendfile64', but I actually find sendfile64 in syzkaller/sys/linux/sys.txt:
> sendfile64(fdout fd, fdin fd, off ptr[inout, fileoff[int64], opt], count intptr)
>
> Did I miss something?

Hi Jin,

THis syscall only seems to be present on arm32 architecture:

sys/linux/sys.txt.const:__NR_sendfile64 = 239,
amd64:arm64:mips64le:ppc64le:riscv64:s390x:???



> On Mon, Feb 15, 2021 at 6:35 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Mon, Feb 15, 2021 at 11:06 AM Hunter J <andy.jinhuang@gmail.com> wrote:
>> >
>> > Hi, Dmitry
>> > I found it is hard for me to first select the potential program exceptions that could trigger data race.
>> > For example, the KCSAN data race report in the crash log is:
>> > BUG: KCSAN: data-race in step_into / vfs_unlink
>> > write to 0xffff9af42962b270 of 4 bytes by task 15262 on cpu 0:
>> > vfs_unlink+0x27a/0x3c0
>> > do_unlinkat+0x211/0x4c0
>> > __x64_sys_unlink+0x2c/0x30
>> > do_syscall_64+0x37/0x50
>> > entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> >
>> > read to 0xffff9af42962b270 of 4 bytes by task 110 on cpu 1:
>> > step_into+0x159/0xfb0
>> > walk_component+0x1a5/0x380
>> > path_lookupat+0x11d/0x560
>> > filename_lookup+0xf2/0x380
>> > user_path_at_empty+0x3b/0x50
>> > do_readlinkat+0x87/0x200
>> > __x64_sys_readlink+0x43/0x50
>> > do_syscall_64+0x37/0x50
>> > entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> >
>> > I even did not find any readlink syscall in the crash log file. Did I miss something?
>>
>> Hi Jin,
>>
>> Some syscalls may be executed by the syz-executor binary itself. It
>> needs to allocate some memory, etc, that's also syscalls.
>> Some syscalls may be executed by the syz-fuzzer binary.
>> Some syscalls may be executed by other processes in your user-space
>> system that are not related to syzkaller.
>>
>>
>>
>> > On Thu, Feb 11, 2021 at 6:31 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>> >>
>> >> On Thu, Feb 11, 2021 at 10:49 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>> >> >
>> >> > Hi, Dmitry
>> >> > Still a question , for example the log I select is:
>> >> > 08:55:49 executing program 1:
>> >> > r0 = epoll_create(0x800)
>> >> > syz_io_uring_setup(0x472e, &(0x7f0000000100), &(0x7f0000ffe000/0x1000)=nil, &(0x7f0000ffc000/0x1000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
>> >> > epoll_wait(r0, &(0x7f0000000000)=[{}], 0x1, 0x0)
>> >> >
>> >> > 08:55:49 executing program 2:
>> >> > r0 = syz_io_uring_setup(0x61a1, &(0x7f0000000000)={0x0, 0x4ff, 0x1, 0x0, 0x32a}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000000080), &(0x7f00000000c0))
>> >> > syz_io_uring_setup(0x3243, &(0x7f0000000100)={0x0, 0xd02d, 0x20, 0x3, 0x16e, 0x0, r0}, &(0x7f0000ffc000/0x3000)=nil, &(0x7f0000ffc000/0x4000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
>> >> > clone(0x22102000, 0x0, 0x0, 0x0, 0x0)
>> >> > syz_io_uring_setup(0x2fa8, &(0x7f0000000200)={0x0, 0xd1a6, 0x0, 0x1, 0xf6, 0x0, r0}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x1000)=nil, &(0x7f0000000280), &(0x7f00000002c0))
>> >> >
>> >> > Could I generate the C program to run program1 and program2 on different threads? Or I need to generate for program1 and program2 separately and merge the program source code myself?
>> >> > Since I see the -threaded option for syz-prog2c, but not sure the effect.
>> >>
>> >> Such functionality does not exist now. If you need exactly that, you
>> >> need to merge yourself.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZnrkYSWDNMWaSwD6UKoryytOp63cfpy4-jddzaZ%2BLWAg%40mail.gmail.com.
