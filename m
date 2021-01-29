Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQHIZ2AAMGQEOY6RSWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D8A308639
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 08:07:46 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id e5sf6311198qkn.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 23:07:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611904065; cv=pass;
        d=google.com; s=arc-20160816;
        b=cMHNcdWCWlC/6v2p4i6n25Dvb6rdhD97LIGPDTZFKijNdMvsyUutlm1uuBm5XpSxOK
         Gt4qJl2JWzc3VkIDI+cOOFdZG9xKXQR6sb69/+GfKMN2i9XwW9HjBxQLISDikKaCBX1l
         MN94/NTZD+zXKTm+x7/5sfq9XMhU8t2gvWFWmycC/cYTGeyM9ZmH6oUfi/GaDWPLjyve
         vuRL36pqHbsMsQTHiSThCb+/7ALfaSmb6uEm9VtTCIvPJoBznP7ix3DNsnNCjwRDFxMm
         lba5aP7NPb06dwE4TGuqZ+2PyhXMRAJFywdMRu0/n42dvmEX11tFrYg+mQs6CQ0aN048
         gRFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7MeyXokucTZnWbAt1v/DTDCWQUAOiNUDIRV2TS1DlGI=;
        b=H8wx2EC5MOAZBnFfL7V50wEEsLAUkpfcDa8tpgH8WdYLmvtqa5PZ12BCVZNu/Q6DEF
         OhSGAj8bt5L/tf7nSpm8L5HV468qVXHFY89aAhiItz5g5qSLsuDu+iLvTLqeIRwKp2VS
         17Vpt1MzLnk4mj9OTzfFnOz6EKZDLzuLa8jcnMqC8Ai76ZBr4aUgGxIJaymwCNGHgRqk
         s7comlX5vz0qHYa+NKx+GsQI7ZnfUu/mo4scctkbg1Qfai3LSKgiMYg4VFAWE8aQ0s91
         LDLSuNXdrNMbkKUK3VkFH9McVI/s4rSwtN7l59sXDnPvcDJYA6m6PqT3aLojxm0A9iWk
         FUpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c+JAERKc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7MeyXokucTZnWbAt1v/DTDCWQUAOiNUDIRV2TS1DlGI=;
        b=LJY9PvwnKa6A4t8gH+cxIpA9iNFaji/eXolMQtPPQwfBieMO0uNfiHyuDBd+xzeRUH
         w0HizxhAIC+21ZKKAj4VaN7qazGMlWrHCyya9CGypZGMhqokwcdaPd/SoeGG8UsY8Sow
         GX17o8LoIBGvUxS8aO9LWZUSZ/VKpDjVrqWlyfMqn/LXbaiecrY92Cmt0OgefTMNMGYL
         ZGiuK/EzLechkuwPenj8JiRA4k8xe/EA0cOTCx2VFPhmcCaDaPxxrtZ6w4semQM2NM2h
         mtotDPOadIKm2KJdcFMPIDui8zBH+2CyljypR9cSdahizuwQFXVcZ++ZemOuqI+APoNk
         4VkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7MeyXokucTZnWbAt1v/DTDCWQUAOiNUDIRV2TS1DlGI=;
        b=MdfuuZizLYsPsbfOJlQWBEj8vt91RpYBRigbYnnHZwT8+rtm3yIxtofcbwLt8QGLM7
         Ay/E7Gzd9h62NYK7gooGdEGIRuZZw2EKEGScZ9uQtF+KrDKetXznFjwG5O5xr8muMJsT
         8BKNgcoSnKvSs9bITJEVKD3GyRloS920XkEbMbkeP8B4kLtwFF0tjPmQQOFlF45yOA1i
         9N0ZPFpO4lSkQBi+awdIZ/OEXyIxuOI4IEaPd7bsprAoIzI4erBEk/sL2cGz/hNIwTUc
         L+jq2oRcQsvnzBkEzBmQHBkfGXhHzJ/Upg3ThBLHoB+1VMNNl7BCOhdMcahN9/bbgn1Q
         UYxQ==
X-Gm-Message-State: AOAM533QYZziybQeDZMQpn6z2/AUisBG1pZm9eFphVH75k244oE9gVXo
	n75QoWkbou03Uqi6WKvGpAY=
X-Google-Smtp-Source: ABdhPJwwI/dy+4q6yz/cNsoULPiztup+pYT1S4G6Y2IkOX6cM116e7gbjcVDjSCPws2cAx5tSYe8ag==
X-Received: by 2002:a05:6214:613:: with SMTP id z19mr2908211qvw.2.1611904064759;
        Thu, 28 Jan 2021 23:07:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:2f42:: with SMTP id v63ls284717qkh.5.gmail; Thu, 28 Jan
 2021 23:07:44 -0800 (PST)
X-Received: by 2002:a37:9bd3:: with SMTP id d202mr2871717qke.163.1611904064383;
        Thu, 28 Jan 2021 23:07:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611904064; cv=none;
        d=google.com; s=arc-20160816;
        b=cqijXDrLrZcwagU0sUXF3qco5MzI7a6y7kYnecxg/SBS1PIRB6jRxjA6TC3vm4bxHm
         LJVvAIo7InOpM9bdoFpcUWwN4njkAOGHvqAULWlLsvV1MFYLv+OJG7tFiPF7O3qU3Bpv
         KiGHra5LWY9YwC5BOyU6usfqE34KMYwvidpsDTcnxt1Zmby4zkSnfpGqxZSkQ5oAd/UH
         GVfwK2QZRzuY5ODktMIWKyiMcTvmCHmFcAjSLjYnKye0i7gaCPBXO4Mr9gcSOQJf2ZIN
         2cUUmHjX+qYX5dDcCL8JXbxA7fQPKASTS92XvBJTKdT9LVf2UwtteBgaBqaVjzu0IMOV
         AaMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KCeyoLCma3PHjkYTlcopmOu5s9uA7eGzuWEMP+hw1NQ=;
        b=tIIfMCNBOUd3pVa1nG/ErnZLaejL4KLEFebHtFCorN02cgy1KnLutnUsc9+tgaIbSK
         YmWjm4r4i2gpU4foJOn1R81gfnVwIqhnBJIN7kOegPO6ZoOIQzoUk2t+HFPIWqvomR2v
         9oIO5ESHjg75Q8BN9LX8qXjUHezad/rigGMCJCpOEcgnlqiAKeTO9RNX32FstwWxPeCB
         M4KVOUkGVVl0FIyQbCt3Kr3VRAhlkCocXHjgMXMbwVdiKvjtqQverTkQTIsdNkGoPdpc
         pnBiu9wfQH3Nh2Q2xD7tN68mMGB1HQzduNBMKL/GwoqsJq2wzRXA33NJgF02VvvJnY6R
         gzdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c+JAERKc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc32.google.com (mail-oo1-xc32.google.com. [2607:f8b0:4864:20::c32])
        by gmr-mx.google.com with ESMTPS id a26si449968qkl.1.2021.01.28.23.07.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Jan 2021 23:07:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) client-ip=2607:f8b0:4864:20::c32;
Received: by mail-oo1-xc32.google.com with SMTP id q3so2073619oog.4
        for <kasan-dev@googlegroups.com>; Thu, 28 Jan 2021 23:07:44 -0800 (PST)
X-Received: by 2002:a4a:d384:: with SMTP id i4mr2292746oos.14.1611904063727;
 Thu, 28 Jan 2021 23:07:43 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
 <20210128232821.GW2743@paulmck-ThinkPad-P72> <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
In-Reply-To: <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 08:07:31 +0100
Message-ID: <CANpmjNNi=mH4JTZNeR7sKBmRj6EMywh6FYf+R1O6LJQApeq4Gw@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c+JAERKc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as
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

On Fri, 29 Jan 2021 at 01:07, Jin Huang <andy.jinhuang@gmail.com> wrote:
> Thank you for your reply, Paul.
>
> Sorry I did not state my question clearly, my question is now I want to g=
et the call stack myself, not from syzkaller report. For example I write th=
e code in linux kernel some point, dump_stack(), then I can get the call st=
ack when execution, and later I can translate the symbol to get the file:li=
ne.
>
> But the point is dump_stack() function in Linux Kernel does not contain t=
he inline function calls as shown below, if I want to implement display cal=
l stack myself, do you have any idea? I think I can modify dump_stack(), bu=
t seems I cannot figure out where the address of inline function is, accord=
ing to the source code of dump_stack() in Linux Kernel, it only displays th=
e address of the function call within 'kernel_text_address', or maybe the i=
nline function calls have  not even been recorded. Or maybe I am not on the=
 right track.
> I also try to compile with -fno-inline, but the kernel cannot be compiled=
 successfully in this way.
[...]
> On Thu, Jan 28, 2021 at 6:28 PM Paul E. McKenney <paulmck@kernel.org> wro=
te:
>>
>> On Thu, Jan 28, 2021 at 05:43:00PM -0500, Jin Huang wrote:
>> > Hi, Dmitry
>> > Thank you for your help.
>> >
>> > I also want to ask an interesting question about the call stack
>> > information, how did you get the inline function call information in t=
he
>> > call stack like this:
[...]
>> > Obviously, inline function info misses. When I look at the Linux Kerne=
l
>> > source code, the implementation of dump_stack(), seems because the inl=
ine
>> > function is not within the range of kernel_text_address().
>> > Do you have any idea?
>>
>> If you build your kernel with CONFIG_DEBUG_INFO=3Dy, any number of tools
>> will be able to translate those addresses to filenames and line numbers.
>> For but one example, given the vmlinux, you could give the following
>> command to "gdb vmlinux":
>>
>>         l *vfs_unlink+0x269
>>
>>                                                         Thanx, Paul
>>
>> > Thank You
>> > Best
>> > Jin Huang
>> >
>> >
>> > On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov <dvyukov@google.com> wro=
te:
>> >
>> > > On Wed, Jan 27, 2021 at 5:57 AM Jin Huang <andy.jinhuang@gmail.com> =
wrote:
>> > > >
>> > > > Hi, Macro
>> > > > Could you provide some instructions about how to use syz-symbolize=
 to
>> > > locate the kernel source code?
>> > > > I did not find any document about it.
>> > >
>> > > Hi Jin,
>> > >
>> > > If you build kernel in-tree, then you can just run:
>> > > $ syz-symbolize file-with-kernel-crash
>> > > from the kernel dir.
>> > >
>> > > Otherwise add -kernel_src flag and/or -kernel_obj flag:
>> > >
>> > > https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/=
symbolize.go#L24

syz-symbolize adds the inline information. Have a go at running
syz-symbolize on a stacktrace and you should see the output you want.

There are other tools that should also be able to add the inline
information (e.g. gdb should point at the right line if it was an
inline function), but the format you're asking for is the output from
syz-symbolize.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNi%3DmH4JTZNeR7sKBmRj6EMywh6FYf%2BR1O6LJQApeq4Gw%40mail.gm=
ail.com.
