Return-Path: <kasan-dev+bncBCMIZB7QWENRBF5N4SAAMGQE5SWLN5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id E31D230BA90
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 10:08:40 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id l22sf13384986pgc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 01:08:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612256919; cv=pass;
        d=google.com; s=arc-20160816;
        b=G9hpJRqGgY2Bo8zqa8NHyM/pi31Ik5GHVVanW1lxyL/O/vNeNAD+Y0a+wQmmWxsm/x
         /u+TuMQ4UT0yAB3NRRnS6r774mICs7RlJRN/Vvhx0DiUvzcv3/o6vZfVG/FyRBmrErVc
         Q+o6uyWB72Gql6ylqVNXUPk7iFd5y+fcnblRCtVilj8gbn+roxvLRp7Bx4k9QbkvCH/D
         c+rcV118S/XfawVxqN+VPt44BMW9CAN1ZXimBf0q0+r+hteE9ZCpD2cxxewFhc3PqB2p
         uz7XExrDhQsVJQ2WW8wVN76JQU65ND1DNM2WS7nD1X0O83WZcFbbi4qOcskG244f/tgN
         XlBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iuCHpmMVMBo4wJ4KfBStBlb9YUSNzCG9fgV86LItH2w=;
        b=AkkzAXi9nD0rj/pXIE8+uaJ83YTovUmQYdA2MgsYrB5mWnZRwKunyZ2leVJc5Hn3Vj
         J0ZQI4WWFTIK26vawKu8JYmlaFtRmHRV7pNJkoZDOXay46YOKUDgkiT6zLc6SdqePa7M
         6HoRf6NKbW49WLRMuFAqmAfvWtsw7PzRMkzSMT4ikEBzU9kjIVbnqEY/MBpC3v8VtW44
         AZzk+oIjB69ASR0QtyrRVI1YD5S4MGhTNman262ndl0oL9L+p40nUnvvNr1/mGzCeVN2
         LzmuuvfUZWxsRpuIaWauNLzjXOjNw2fi7UDBjXD4kd8EKkF4reGYjtuxvLy+BBHPykow
         pdKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XUh/t0Ki";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=iuCHpmMVMBo4wJ4KfBStBlb9YUSNzCG9fgV86LItH2w=;
        b=J1BPu6UIeeYpbAvHE3jcYdWkqgd3g3naueL5mTx/WlVFdZR7q7TVCzgwTvcHYZ4jPj
         fjygEGa8rsLl2mMTDg5Nf5EC9fAwz2BpjwC9sE9Cbwskfp4pxH0SUNbrCFzPZO7UUv9N
         /bYX3SZagf4e6yxbGj0nOXkCmuYmAOx3f3fIf5b0etOGXZ9LmCAqWMV1rkG5Z/38JdVy
         nKse7JdXQNKKO147x94UFEAI8gx0ZzblIE8aywdsyT7xHE8eszBmordvTaAULgM2LfRE
         WRxNMhcSUEJkKiz4uGT8qanj0MMxH14XefCOrnnMrnsl4clO2tg/bfIvyY8yckT29QdB
         UwGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iuCHpmMVMBo4wJ4KfBStBlb9YUSNzCG9fgV86LItH2w=;
        b=sVaUAeO8FhJ/6R2i2oyokoWapphch0c1yBKrmrPupVyaXJCHL6nZSQnkuIZflEbD/Y
         ByyWb9oSwvoSdAurhUiienKSYoqrhKsKWJKQplw/DE3s3FUlqOxawl5Imo4RzPXLmP4+
         e8cOYx9oxeZ8p3usY4vaalOHg/KSpieLjmUQu1yuHYKT5lAcD41OqYbh49dRlHU3Ioir
         SuP6R8mWYomO3YwqjO391mhfIIkxnR3+eirzjzxT8FOqcScbJGyyt0RvRvZXmcbHu0Kk
         au6hsSVfhneCJKcgjGb6CTAQaOwHxF8QJuDmtGcMn0HZOck7KCKUmxu+JtKzfjlYsuYC
         S+fQ==
X-Gm-Message-State: AOAM530QdFxN+EBh29+xuEYu6YWCO6oFlxmW60DECjNFWL+6AfL9bPBn
	3Nz5y0OYqODT/+OO9M9zKAM=
X-Google-Smtp-Source: ABdhPJxyCuN4Wi2hAFKwG15R+FqZ2cZRTl4mVQ8c6VvTLcsxbQCyofytf7OsG6vcICslCpBuu9A/rg==
X-Received: by 2002:a62:ddcf:0:b029:1b7:baca:6c71 with SMTP id w198-20020a62ddcf0000b02901b7baca6c71mr20553516pff.43.1612256919518;
        Tue, 02 Feb 2021 01:08:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d0e:: with SMTP id i14ls7678639pgc.8.gmail; Tue, 02 Feb
 2021 01:08:39 -0800 (PST)
X-Received: by 2002:a63:63c3:: with SMTP id x186mr20682685pgb.54.1612256918951;
        Tue, 02 Feb 2021 01:08:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612256918; cv=none;
        d=google.com; s=arc-20160816;
        b=PxRZB7NN30kbK7BbDl7MEvf3XCE3vpVhP0bAocuMsud1jkqPI4MOMh9JaELsM3HQju
         zHAkDcYbuL9P3+PXOuASOqqzkaVuwS5QxeMyrDYraoXvOF0EUbPywyTzgI8/IZm38Anh
         rT0CwG2GFGeLpW4buBTS0ck9F5bw24XhBz+NAaJDWobSqaeHyiAVhT0FjtwEwcOCMR3B
         mG9Z6I+9J1XA30mylshEDCmWBzEBiRa7tynipICciXobMSdAdkP+s8KRhjs7/LbD6pUp
         rnurpLOMJFCo9RJYldIjPvBMzN8FL732rzGEUlE/2A5fC3xIjreRAbGiV57ifmh/QNI6
         Zvdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=15na+UMKk+PRl1nBpbKnY1B8op4zOBafL+guqRlZspI=;
        b=qPrbt8kPFPbvjF7a+m7Ae18y0BuOpElpLH0QPVQkINMjSlUcuaOuOyxcZYq5iK7rOl
         0IWXbqKUvWAIRi/HOEEDJpUkT/q7x6P2h6RbwijMP9l8Kq8BwVDJnbSDt8vHLdKkMQsg
         x46ZZct+HbOdACdFAHqwIhhqxRCiMBQuUCwC8xszz+n7d5oRb+z76ZokZ62ou/ee1ITM
         k+p9885JcgMrlYR+MprsBc1AkjZQXwHCmT7PpXPIAcRmreOEIcPs5LEuWPXO0VWOjLau
         tUn18H4IGBPzIMwtJiavRMkNDoVLUcZlXfI0m0XN3TaMBgZnAPm90t+R3Yjrn/jeaKIo
         owxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XUh/t0Ki";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id l8si215970plg.2.2021.02.02.01.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 01:08:38 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id z9so14422376qtv.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 01:08:38 -0800 (PST)
X-Received: by 2002:ac8:66c9:: with SMTP id m9mr18483490qtp.43.1612256917856;
 Tue, 02 Feb 2021 01:08:37 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
 <20210128232821.GW2743@paulmck-ThinkPad-P72> <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
 <CACT4Y+YFfej26JkuH1szEUKKvEP-TaD+rugdTNfsw-bALzSMZA@mail.gmail.com> <CACV+naogeDve+4jGsoMUTa-T_UDojyV5GKsX0+VBR7uGg_9-gA@mail.gmail.com>
In-Reply-To: <CACV+naogeDve+4jGsoMUTa-T_UDojyV5GKsX0+VBR7uGg_9-gA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 10:08:26 +0100
Message-ID: <CACT4Y+YxQjm3y6fDhcG5D=9pfTCWAMNTiuwjZfNMfScSzMwJ5Q@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="XUh/t0Ki";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::832
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

On Tue, Feb 2, 2021 at 10:04 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Hi, Dimitry
> Really thank you for your help.
> I still want to ask some questions, did syzkaller directly use addr2line =
on the vmlinux dump file?

I don't remember. In some places we used addr2line, but in some we
switched to parsing DWARF manually.

> I run syzkaller on linux-5.11-rc5 myself, and with the log and report, wh=
en I tried to use addr2line to reproduce the call stack as the one provided=
 by syzkaller report, I found the result I got from addr2line are not so pr=
ecise and completed as the syzkaller report. As shown in the screenshot bel=
ow, the log and report of syzkaller and my callstack from addr2line. Do you=
 have some idea what is wrong with my solution?

I can't see any pictures (please post text in future),  but I suspect
you did not subtract 1 from return PCs.
Most PCs in stack traces are call _return_ PCs and point to the _next_
instruction. So you need to subtract 1 from most PCs in the trace.


> Below is mine, misses 2 top inline function call info, and the line numbe=
r sometimes will be 1 or 2 more, sometimes correct, so weird.
> First I generate the objdump file of the vmlinux: objdump -d vmlinux > vm=
linux.S
> Then, get the address of the function call in vmlinux.S and add the offse=
t, and use adr2line to get the file:line info, like: addr2line -f -i -e vml=
inux 0xffffffff8177927e/0x300
>
> I have marked the mistakes red.
>
>
>
> Thank You
> Best
> Jin Huang
>
>
> On Fri, Jan 29, 2021 at 3:03 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Fri, Jan 29, 2021 at 1:07 AM Jin Huang <andy.jinhuang@gmail.com> wrot=
e:
>> >
>> > Thank you for your reply, Paul.
>> >
>> > Sorry I did not state my question clearly, my question is now I want t=
o get the call stack myself, not from syzkaller report. For example I write=
 the code in linux kernel some point, dump_stack(), then I can get the call=
 stack when execution, and later I can translate the symbol to get the file=
:line.
>> >
>> > But the point is dump_stack() function in Linux Kernel does not contai=
n the inline function calls as shown below, if I want to implement display =
call stack myself, do you have any idea? I think I can modify dump_stack(),=
 but seems I cannot figure out where the address of inline function is, acc=
ording to the source code of dump_stack() in Linux Kernel, it only displays=
 the address of the function call within 'kernel_text_address', or maybe th=
e inline function calls have  not even been recorded. Or maybe I am not on =
the right track.
>> > I also try to compile with -fno-inline, but the kernel cannot be compi=
led successfully in this way.
>> >
>> > Syzkaller report:
>> >
>> > dont_mount include/linux/dcache.h:355 [inline]
>> >
>> >  vfs_unlink+0x269/0x3b0 fs/namei.c:3837
>> >
>> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
>> >
>> >  __do_sys_unlink fs/namei.c:3945 [inline]
>> >
>> >  __se_sys_unlink fs/namei.c:3943 [inline]
>> >
>> >  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
>> >
>> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
>> >
>> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> >
>> >
>> > dump_stack result, the inline function calls are missing.
>> >
>> > vfs_unlink+0x269/0x3b0 fs/namei.c:3837
>> >
>> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
>> >
>> >   __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
>> >
>> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
>> >
>> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>>
>> Inlining info is provided by addr2line with -i flag.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYxQjm3y6fDhcG5D%3D9pfTCWAMNTiuwjZfNMfScSzMwJ5Q%40mail.gm=
ail.com.
