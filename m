Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBNNL4SAAMGQEKWOW7OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id F27BF30BA8D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 10:04:53 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id z5sf10956299ljo.6
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 01:04:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612256693; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ga9xbs2QGdO8jPuXATh5n0aFr23NuyJN+ijqRnUJAxFr3QYgXTsqXvTnhVEgCMBc2W
         rjm2vR+vDDBgu+ABBULsrTFZq3mC8+Y20rPboxKS2IT9BgUnd27aw5F3Frjms8nCH2d1
         5ZFBbaadM94W396+nsBWUM4d5sVmm0cAoR5RqXyzaa8fwZALedYrPTaEujmXF70IYAO7
         RO+MIAZq3WFOKJOxPxSs2yim4VJzFoKuVd/kPogDM/s6ZutC6AXhzQ5j0x3fT3P+t4zt
         laHvS1l3QvbVPppzqC/YkZCEvrphdUhjnQQvFRqoAsqScSSIHn/+BGPw3j0oKPrDQZMu
         VAJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MaVyzjJf7bihhnZxaBolw/dSQ3K4mA18/eIS4fst1wM=;
        b=eLt/naMketHvFxVAXRH3YDgTFL4LK1Uxk+gfkn69GIUU2FGT4UZmR690vJQivYOVEQ
         5pRswniXwqhDw0+ctmb4xzdo6/Y5dRXrYuy4uoGjHJ0UGTvpUF4+qn8ag8QEqKBf1u1e
         JeCVah7iuthsAuZNBvP87fCA4V+Bfg5Jrj7mwMTNiCVElJ1DOpJuorb3NuGidyFnTBo/
         3eSEfStSa7DVfkXlOHwywM7S1qXOq0W+oa7EmNTEdrRLcXeEYDSNHpgLtYD4RGGJLeoE
         +67IugLFffXAmpBDFHfJy/ALAy11VEamsUoXIS84OXoniAeA6wxrIwrhZaD7dGbT2NQA
         3SlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ft0C2R3D;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MaVyzjJf7bihhnZxaBolw/dSQ3K4mA18/eIS4fst1wM=;
        b=aoo+giEd5TuGV1s+7N4K2xDxSCOsB32+DiEyk25qmAaY2SdHNHGlnWqxxWpukkl3Iy
         +6Futd48M5zjNjBXoz6XCQbYBQb5/60f2RKqUahINEcRlUaJhNeEI/VQhLHXU1MfaE6h
         RKsAGd1Q9FveZDR6x7AHORYi6gLfCg0/oBCb0Pk5tpycVts2dMEpGUmMEYbGf0rIFuI9
         ywcX4Po6QQTtwgbFo/+Iz4kAgByQjBjPwxI3wekROeH5pN3zILep8docqyrmz/n8qCzK
         qbcPWxE1zSIiazWXTHWCjtlUznweLPkPDSsEg6pk9He+bfMT18oAWz4uEwLb+eSkMkUd
         /Hbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MaVyzjJf7bihhnZxaBolw/dSQ3K4mA18/eIS4fst1wM=;
        b=hp9Fow3FHpIs8CMBg0AI+vqv3ddJnaS9eBDBv/tZkTd5YsV5Izq53qEsHdIZUg2NEm
         cqSS6WJwdO/AMllmEBhcsts3+MULKSRexGxk+8RDsT0+9sCvme6YWINskhxEW7PMW+mT
         QD52JmSxKuMVNccmHdgYsrUD1YTtyn6x4sHwDbYi2qb/sRh4v8YXjIYnJn94UPXVb4QG
         Ca8v718nvOIn6tKFMyDhgDfYprRgRkauLuxUWo00nhzEpDQtrLWTNH+51wmlPtWxAv88
         efk4LaXp8bbyu+ELD2nwuvawi+W9YN+Ipcl2c4mjQa6fgLdKR7+QTuRRZpCZMf4pcaUs
         6vcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MaVyzjJf7bihhnZxaBolw/dSQ3K4mA18/eIS4fst1wM=;
        b=SrgSIBY4WD0UpxdhLqQHwe7+gaVVy20d1H+czKWTt6/vjSxxbLwwA+m3uzIjci1WUD
         3qyE/lrzhao9o5Ccea9TY4OZHWnLmP9NDxcWa3MJQB+SGnFQSZ3s7SN7N8b7yPBXBYI/
         0gSkVUy9Ukl2NRQSI/XHStraIfMf1O1xe7PezzbO5cgYEN6WYNEsY3z79ODKkRPurhjR
         ckeuZmoh6khJI190knY0nSaoQxVNwe89GhZp/UnEINQQgFGiUfC3rJKalJYP8HPCFwZs
         YmLX/iUgq9uqZt7azDPiRy80JgDaNfqU2+oXc3FUr9biOwE68N2pbq/Uza1RHkj56ixH
         hwEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325NPGPpRocbSntZbUs/xpEv4/8xATw67OoJyJFONJDAo/AaiFz
	45xbaEYw1NHZjibgZAexpe8=
X-Google-Smtp-Source: ABdhPJyLun/SSjGdWTVqoHJaeKg6fQA/EYTAcisglT/GQz9UVzkoPii2lEfxspsP4iZT2K1BMKn3eg==
X-Received: by 2002:a19:5e52:: with SMTP id z18mr10134154lfi.234.1612256693469;
        Tue, 02 Feb 2021 01:04:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e77:: with SMTP id t23ls3667660ljk.0.gmail; Tue, 02 Feb
 2021 01:04:52 -0800 (PST)
X-Received: by 2002:a2e:9b16:: with SMTP id u22mr5990011lji.416.1612256692352;
        Tue, 02 Feb 2021 01:04:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612256692; cv=none;
        d=google.com; s=arc-20160816;
        b=yVljzCv4k/F2n3ZT8ZoXGRgSAXTlh15YZNTPWmkyd5LbgqpVrlx0wW4FZMIO5ZgZ76
         JfCJDJPgTK15Ic8Qfjar9CDwiaLG1YdZFRH2ZaHTCC1HCVEZ937zlmOi46SNVfHt/OQs
         L6mYmyyqgo7y2IBmxaJX1g0t24O7BaspKsWwJYOaG2TtDjkBlyLLOwTK8V/FbEr2m7Lu
         n+Ry4ol9jT0FIoDkpcfa27zUHoiIbyMqNS9HVzVzGt4GTOhfiY63vyJaguYoVesozevt
         JjH0r5J39V82p/ZNKO/5aM2iNwyKStZDwJ3nkD7ufPnLwaX+RNFI5X+6GgpS4hnm111w
         CidQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dYDK7SftuOKkXxdcEKqjs38JeXniLa/P1FBzpz02xJw=;
        b=s0MiK3RmBU7zxa0bCRjwMNY0NP+PeyhN5KcpP8VVpebmYl8WPTK6cyu7WpXuSKorUP
         Hkrg06uhx2DTK3YrmNyeOTSnbPPF+1PHExfqTm2cPflozPgwn90LfBYfN1msKq6cz+LI
         Auf+R1yAafRlee2RTT0J3Nt1D936iE3ZzCJov9PC3ZNUt8zwALSU5/F4eOtfrRUT06FQ
         hH89jRZ1fER7oxHpDwcpAySCQCSKsD7QAsFNhLvNM6G4wtZ3Zn0d3Ek0DBQ6TWndHIEq
         4qaGXYp78Lga5q2qvCnyYspvMxEgAB0OZccFugk2ENtkTmw3K5otyviwB4fKSTazK7cn
         /Y+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ft0C2R3D;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id g28si55171lfh.12.2021.02.02.01.04.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 01:04:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id p20so9398737ejb.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 01:04:52 -0800 (PST)
X-Received: by 2002:a17:906:5917:: with SMTP id h23mr10732238ejq.407.1612256692002;
 Tue, 02 Feb 2021 01:04:52 -0800 (PST)
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
In-Reply-To: <CACT4Y+YFfej26JkuH1szEUKKvEP-TaD+rugdTNfsw-bALzSMZA@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Tue, 2 Feb 2021 04:04:41 -0500
Message-ID: <CACV+naogeDve+4jGsoMUTa-T_UDojyV5GKsX0+VBR7uGg_9-gA@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="00000000000069eac705ba56c304"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ft0C2R3D;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62f
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

--00000000000069eac705ba56c304
Content-Type: text/plain; charset="UTF-8"

Hi, Dimitry
Really thank you for your help.
I still want to ask some questions, did syzkaller directly use addr2line on
the vmlinux dump file?

I run syzkaller on linux-5.11-rc5 myself, and with the log and report, when
I tried to use addr2line to reproduce the call stack as the one provided by
syzkaller report, I found the result I got from addr2line are not so
precise and completed as the syzkaller report. As shown in the
screenshot below, the log and report of syzkaller and my callstack from
addr2line. Do you have some idea what is wrong with my solution?

[image: image.png]
[image: image.png]

Below is mine, misses 2 top inline function call info, and the line number
sometimes will be 1 or 2 more, sometimes correct, so weird.
First I generate the objdump file of the vmlinux: objdump -d vmlinux >
vmlinux.S
Then, get the address of the function call in vmlinux.S and add the offset,
and use adr2line to get the file:line info, like: addr2line -f -i -e
vmlinux 0xffffffff8177927e/0x300

I have marked the mistakes red.
[image: image.png]


Thank You
Best
Jin Huang


On Fri, Jan 29, 2021 at 3:03 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Fri, Jan 29, 2021 at 1:07 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
> >
> > Thank you for your reply, Paul.
> >
> > Sorry I did not state my question clearly, my question is now I want to
> get the call stack myself, not from syzkaller report. For example I write
> the code in linux kernel some point, dump_stack(), then I can get the call
> stack when execution, and later I can translate the symbol to get the
> file:line.
> >
> > But the point is dump_stack() function in Linux Kernel does not contain
> the inline function calls as shown below, if I want to implement display
> call stack myself, do you have any idea? I think I can modify dump_stack(),
> but seems I cannot figure out where the address of inline function is,
> according to the source code of dump_stack() in Linux Kernel, it only
> displays the address of the function call within 'kernel_text_address', or
> maybe the inline function calls have  not even been recorded. Or maybe I am
> not on the right track.
> > I also try to compile with -fno-inline, but the kernel cannot be
> compiled successfully in this way.
> >
> > Syzkaller report:
> >
> > dont_mount include/linux/dcache.h:355 [inline]
> >
> >  vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> >
> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> >
> >  __do_sys_unlink fs/namei.c:3945 [inline]
> >
> >  __se_sys_unlink fs/namei.c:3943 [inline]
> >
> >  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> >
> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> >
> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> >
> >
> > dump_stack result, the inline function calls are missing.
> >
> > vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> >
> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> >
> >   __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> >
> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> >
> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
> Inlining info is provided by addr2line with -i flag.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnaogeDve%2B4jGsoMUTa-T_UDojyV5GKsX0%2BVBR7uGg_9-gA%40mail.gmail.com.

--00000000000069eac705ba56c304
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><font size=3D"4">Hi, Dimitry</font><div><font size=3D"4">R=
eally thank you for your help.</font></div><div><font size=3D"4">I still wa=
nt to ask some questions, did syzkaller directly use addr2line on the vmlin=
ux dump file?</font></div><div><font size=3D"4"><br></font></div><div><font=
 size=3D"4">I run syzkaller on linux-5.11-rc5 myself, and with the log and =
report, when I tried to use addr2line to reproduce the call stack=C2=A0as t=
he one provided by syzkaller report, I found the result I got from addr2lin=
e are not so precise and completed as the syzkaller report. As shown in the=
 screenshot=C2=A0below, the log and report of syzkaller and my callstack fr=
om addr2line. Do you have some idea what is wrong with my solution?</font><=
/div><div><br></div><div><img src=3D"cid:ii_kknrewv10" alt=3D"image.png" wi=
dth=3D"562" height=3D"240"><br></div><div><img src=3D"cid:ii_kknrfkv81" alt=
=3D"image.png" width=3D"562" height=3D"280"><br></div><div><br></div><div><=
font size=3D"4">Below is mine, misses 2 top inline function call info, and =
the line number sometimes will be 1 or 2 more, sometimes correct, so weird.=
</font></div><div>First I generate=C2=A0the objdump file of the vmlinux:=C2=
=A0<span style=3D"background-color:transparent;color:rgb(0,0,0);font-family=
:Arial;white-space:pre-wrap">objdump -d vmlinux &gt; vmlinux.S</span></div>=
<div><span style=3D"background-color:transparent;color:rgb(0,0,0);font-fami=
ly:Arial;white-space:pre-wrap">Then, get the address of the function call i=
n vmlinux.S and add the offset, and use adr2line to get the file:line info,=
 like: </span><span style=3D"background-color:transparent;color:rgb(0,0,0);=
font-family:Arial;white-space:pre-wrap">addr2line -f -i -e vmlinux 0xffffff=
ff8177927e/0x300</span></div><div><span style=3D"background-color:transpare=
nt;color:rgb(0,0,0);font-family:Arial;white-space:pre-wrap"><br></span></di=
v><div><span style=3D"background-color:transparent;color:rgb(0,0,0);font-fa=
mily:Arial;white-space:pre-wrap"><font size=3D"4">I have marked the mistake=
s red.</font></span></div><div><img src=3D"cid:ii_kknromc63" alt=3D"image.p=
ng" width=3D"562" height=3D"368"><br></div><div></div><div><div dir=3D"ltr"=
 class=3D"gmail_signature" data-smartmail=3D"gmail_signature"><div dir=3D"l=
tr"><div><br></div><div><br></div><div>Thank You</div>Best<div>Jin Huang</d=
iv></div></div></div><br></div><br><div class=3D"gmail_quote"><div dir=3D"l=
tr" class=3D"gmail_attr">On Fri, Jan 29, 2021 at 3:03 AM Dmitry Vyukov &lt;=
<a href=3D"mailto:dvyukov@google.com">dvyukov@google.com</a>&gt; wrote:<br>=
</div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;b=
order-left:1px solid rgb(204,204,204);padding-left:1ex">On Fri, Jan 29, 202=
1 at 1:07 AM Jin Huang &lt;<a href=3D"mailto:andy.jinhuang@gmail.com" targe=
t=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Thank you for your reply, Paul.<br>
&gt;<br>
&gt; Sorry I did not state my question clearly, my question is now I want t=
o get the call stack myself, not from syzkaller report. For example I write=
 the code in linux kernel some point, dump_stack(), then I can get the call=
 stack when execution, and later I can translate the symbol to get the file=
:line.<br>
&gt;<br>
&gt; But the point is dump_stack() function in Linux Kernel does not contai=
n the inline function calls as shown below, if I want to implement display =
call stack myself, do you have any idea? I think I can modify dump_stack(),=
 but seems I cannot figure out where the address of inline function is, acc=
ording to the source code of dump_stack() in Linux Kernel, it only displays=
 the address of the function call within &#39;kernel_text_address&#39;, or =
maybe the inline function calls have=C2=A0 not even been recorded. Or maybe=
 I am not on the right track.<br>
&gt; I also try to compile with -fno-inline, but the kernel cannot be compi=
led successfully in this way.<br>
&gt;<br>
&gt; Syzkaller report:<br>
&gt;<br>
&gt; dont_mount include/linux/dcache.h:355 [inline]<br>
&gt;<br>
&gt;=C2=A0 vfs_unlink+0x269/0x3b0 fs/namei.c:3837<br>
&gt;<br>
&gt;=C2=A0 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899<br>
&gt;<br>
&gt;=C2=A0 __do_sys_unlink fs/namei.c:3945 [inline]<br>
&gt;<br>
&gt;=C2=A0 __se_sys_unlink fs/namei.c:3943 [inline]<br>
&gt;<br>
&gt;=C2=A0 __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943<br>
&gt;<br>
&gt;=C2=A0 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46<br>
&gt;<br>
&gt;=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9<br>
&gt;<br>
&gt;<br>
&gt; dump_stack result, the inline function calls are missing.<br>
&gt;<br>
&gt; vfs_unlink+0x269/0x3b0 fs/namei.c:3837<br>
&gt;<br>
&gt;=C2=A0 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899<br>
&gt;<br>
&gt;=C2=A0 =C2=A0__x64_sys_unlink+0x2c/0x30 fs/namei.c:3943<br>
&gt;<br>
&gt;=C2=A0 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46<br>
&gt;<br>
&gt;=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9<br>
<br>
Inlining info is provided by addr2line with -i flag.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnaogeDve%2B4jGsoMUTa-T_UDojyV5GKsX0%2BVBR7uGg_9=
-gA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CACV%2BnaogeDve%2B4jGsoMUTa-T_UDojyV5GKsX0%2B=
VBR7uGg_9-gA%40mail.gmail.com</a>.<br />

--00000000000069eac705ba56c304--
