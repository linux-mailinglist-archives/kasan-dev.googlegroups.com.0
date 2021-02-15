Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBLUPVGAQMGQEM6WDO2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E8ECC31B6DD
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 11:06:38 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 186sf1778791lfl.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 02:06:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613383598; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6YXPeWX/9J/fdW9guNRLlfHAGIpAoDOxYCMIyP8JSUG7uqqz69HzdldFBbyXqC+59
         PFiYm0b7ldkGxUezqtU7SCbuUpIKMKe4zfhyHlkDJuXH5DO7OKoiYpUreGUzg/I5Qh0L
         ea2k2ElCpJkToidP+HoP9qCC8FdOuvhoddKcxcsgepdQBm3BHw+1u4EDFLa4+FsN8t46
         fDFdTdHmyDw9OS2jB83HwItaHyGPifxdaFPbMXPNfl6GeS0gX6j22GNEzWcu0f4ppNVu
         gXNgLScRgwenbb+tnsTNBSnynPZ7QItkKf2/sd1rkNsh363jDFtD+QpSSuOXe/a38LKB
         U+sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=HmreeFPCc5rzPgbaVF3wDkN4id9QqVfelZkRT0k+WpQ=;
        b=TqjPSXhjl+WH1wEcKiKA0R66MkSKeC70Y6Sr3hpXX7pJDs6msB/m+qr2tyYMR8qVYa
         GsQY+nr9S3UxJHyR76+2vk40OUZrTwOZie4iBsNKrAGHWvOBbR8A3z8R2qcJsNrXUrWz
         NjW3eV56yaWPWJ3/8P5S4HmpwwSwzkLHSP+UWCprcpKSXt96ZTzWtcc5R8ai1AJjJ7Cq
         tysIZHtfHVIG9DUTjG3O87C5HLwJKbQOEvnzgIWLVUXWvN2owZHSUmUuUcKBw/pZKejJ
         8jcLHW4RX+qqiXOQlucjKuoEpu7/ev0CIbyZFrQsPwt9F5cXY8/420KO35sqB+eAyKe+
         Ti6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kOjFTs2M;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HmreeFPCc5rzPgbaVF3wDkN4id9QqVfelZkRT0k+WpQ=;
        b=T16U5d6d7xiHmfWHzESemkUSw6jSr8uDc0p1UMPxFGVIgNKzGiX4ZYUChBpJxJSLbM
         yRinukAx20C99Qj5NCaxnBUuZXClPugQY7dTtVbbfUbmwvnoGXLjpTTUYQM2xTJMxVML
         DrewqmMoW+ItlWtiBWs1oBaTh2/pzhJvj3hOcDzg0zbdUSh7GkH8yl1ug/YbMNQunVeP
         b3uz2aoKgKdF0HiF/YsxQeWyv0eWj5vWkbrSA4W1mbSdhy+JHjTIP06Tcgyc8oXcPGlE
         7LORrLThwmlxb1N48uUKbr3/Tfaobo+Zh3utiC464RMHNQTQlmCF/lTquzjnT8tTJyyF
         VstA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HmreeFPCc5rzPgbaVF3wDkN4id9QqVfelZkRT0k+WpQ=;
        b=H3OiiaKQUfklvXRoFrOyvoY+rGrvhbUyWvnI3V+qAp6sRiw8y765KmUCD2enhdbYwN
         CnDsWjGH5zQqPQj1S/zFwQGDPTIjnnB+MvNWLPJ166Nk//uPvNkEKMak2GACRXj7f3t6
         pFwlLr7nOVIBq1/UFttR+nrasZtw1cfFF2bTTZYeNOXmEJHYfg8upEtoBVO/8CGhbM/M
         AY+JpFrQwyXjgpMD8G2yzTAb1UEPZ+qod3zwKzC9G4VfD9wyAHO6HK5UjS46t2JcP+sZ
         rh+gyoosdua9gCDnMCvu8SK2OprB4f7TXUltfNm9menp/Gz4Ps7SK1+GvWpGHmbyjwav
         sE7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HmreeFPCc5rzPgbaVF3wDkN4id9QqVfelZkRT0k+WpQ=;
        b=cnjfwpZU2vBuk4EPZ3s3/BVgn4CwoHDymoelgds0Q1apywxuiqP9u6BVHRbAxyLtAf
         gLl9FdB1wLygvPSoG0JP+d9OZCFNV19q9pdaUQxzptrlgIFoJAwn5IFbhw0YJRHbMko9
         HN/kbyQmmGqYmLZZzpeu6KCXm8cD/4WaRtS7A4L/ilzkZm5lAdo7QlKKFl9pJckuKUhn
         08iBsxW+C3z8Ksd7A+TdSDwU6UnELcYoY+oe5HM74JSM8nrrBrAjWrA5uHtkWOqMj/mK
         ycfe00GeBP53uvwaX5mIdU5AHA6jtvxvcEKXLKVXXHr5KHdKaAyBfRNshQDZxfAVZs0F
         r/Kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533u6+sqBd/S7GhPWmfY8vALJqD4qvGWtMNi/FNQpORtml2+scfk
	FkY0kPWLi/PBk4umKKJSXB8=
X-Google-Smtp-Source: ABdhPJxO572dadHBCy0Cds0jV0s52aWD9/KuqH7e27JyiIEnTrT/pHUhUs366Z0X0WC53qhPSQGliw==
X-Received: by 2002:a2e:7205:: with SMTP id n5mr6440292ljc.239.1613383598472;
        Mon, 15 Feb 2021 02:06:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls72460lff.1.gmail; Mon, 15
 Feb 2021 02:06:37 -0800 (PST)
X-Received: by 2002:a05:6512:2251:: with SMTP id i17mr7860525lfu.566.1613383597385;
        Mon, 15 Feb 2021 02:06:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613383597; cv=none;
        d=google.com; s=arc-20160816;
        b=yLMDZa0s1jeAZiRsf2yF8XW9t0tc4uWs0p9uXUT5ib3x1vc0vRKuFd8QyVWmV4KU6s
         mI2kN3ipcKqvKLt71ZCOiT8H5OYDVgUjPQbqlyObS7OtX8izIOfGKWfoLlHU+homxBeQ
         y3um6i5kXZ2w4YvL6xsIi73YH/UTBE6KrUtfOWly5jZNdrNEbuWhrH0mkMLlSDhSOGyf
         NShKcAyhDnvd8mDZknQgBCgxQ/QI4MeOiiGRO+fnVcEA9UiPxvDzYXpPcoEm4xyiyJkc
         7ezNYkK4Eet8Pdr1rK4LsabJQRxRaIdZrL/ywKx7/nPhehKQXF4SsGd4tWbZYK6dHy1U
         sG8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lCp6HjMux2FbSyaDABM2cLXUgmRsHU2/TL/hpxVQhBo=;
        b=keHOspby98v9SjYjYAHB/9qACZwC3afWm1uNbjP1GIomSvgoVXoPN6dz1fMMlub1Lw
         GlDqlPwULqXAaB2aIE6VsmJk7Xz6aDL6NjQ5RTFNYvd+Rkg7+JcUO7vUcPN+YlEVRkgc
         GD2VVTDFqy8TEYazbHH9D+1hVdGqThQuU8u99kZCIEeZ6FG6IJT/uenHS7d2qNBkS1GV
         tVFdSO7fhmwB9Q6Q4+z/xSHcj7d75vB/AsXR1ktqnrh9s/TS2Y+AKA3oejQoxPqNVTP0
         6QJK2N2qK3uHH3AiIdVjdLmelDfkFtBZENeeMZJiuh4ncfDdUYGmJM/UsToqzvDcbqIt
         91Lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kOjFTs2M;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id z4si738128lfh.1.2021.02.15.02.06.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Feb 2021 02:06:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id ot7so7504936ejb.9;
        Mon, 15 Feb 2021 02:06:37 -0800 (PST)
X-Received: by 2002:a17:906:184e:: with SMTP id w14mr15101352eje.56.1613383596907;
 Mon, 15 Feb 2021 02:06:36 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
 <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
 <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
 <CACV+naoDZiei0UR5psO05UhJXiYtgLzfBamoYNfKmOPNaBFr_g@mail.gmail.com>
 <CACT4Y+aCJOL3bQEcBNVqXWTWD5xZyB_E53_OGYB33gG+G8PLFQ@mail.gmail.com>
 <CACV+napVK9r2a61a8=bPcgAzeK+xdbg6fskBX+Aan2_b4+G5EQ@mail.gmail.com>
 <CACV+naq++A0btYaV8POmP8+_3BytCaGnOGDG6KmXYCfv463q1g@mail.gmail.com> <CACT4Y+bLfsCp_2s3Yb=B9p8DMGzDZsOvc=F0j5+mBpKLKnD8Vw@mail.gmail.com>
In-Reply-To: <CACT4Y+bLfsCp_2s3Yb=B9p8DMGzDZsOvc=F0j5+mBpKLKnD8Vw@mail.gmail.com>
From: Hunter J <andy.jinhuang@gmail.com>
Date: Mon, 15 Feb 2021 05:06:25 -0500
Message-ID: <CACV+naoAE9B9+kk_C3HrXGdSHCpJC-vDBnhomYGLqK5msMfROA@mail.gmail.com>
Subject: Re: reproduce data race
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: multipart/alternative; boundary="0000000000002e20ee05bb5d240f"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kOjFTs2M;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62c
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

--0000000000002e20ee05bb5d240f
Content-Type: text/plain; charset="UTF-8"

Hi, Dmitry
I found it is hard for me to first select the potential program
exceptions that could trigger data race.
For example, the KCSAN data race report in the crash log is:
BUG: KCSAN: data-race in step_into / vfs_unlink
write to 0xffff9af42962b270 of 4 bytes by task 15262 on cpu 0:
vfs_unlink+0x27a/0x3c0
do_unlinkat+0x211/0x4c0
__x64_sys_unlink+0x2c/0x30
do_syscall_64+0x37/0x50
entry_SYSCALL_64_after_hwframe+0x44/0xa9

read to 0xffff9af42962b270 of 4 bytes by task 110 on cpu 1:
step_into+0x159/0xfb0
walk_component+0x1a5/0x380
path_lookupat+0x11d/0x560
filename_lookup+0xf2/0x380
user_path_at_empty+0x3b/0x50
do_readlinkat+0x87/0x200
__x64_sys_readlink+0x43/0x50
do_syscall_64+0x37/0x50
entry_SYSCALL_64_after_hwframe+0x44/0xa9

I even did not find any readlink syscall in the crash log file. Did I
miss something?



Thank You
Best
Jin Huang


On Thu, Feb 11, 2021 at 6:31 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Thu, Feb 11, 2021 at 10:49 AM Jin Huang <andy.jinhuang@gmail.com>
> wrote:
> >
> > Hi, Dmitry
> > Still a question , for example the log I select is:
> > 08:55:49 executing program 1:
> > r0 = epoll_create(0x800)
> > syz_io_uring_setup(0x472e, &(0x7f0000000100),
> &(0x7f0000ffe000/0x1000)=nil, &(0x7f0000ffc000/0x1000)=nil,
> &(0x7f0000000180), &(0x7f00000001c0))
> > epoll_wait(r0, &(0x7f0000000000)=[{}], 0x1, 0x0)
> >
> > 08:55:49 executing program 2:
> > r0 = syz_io_uring_setup(0x61a1, &(0x7f0000000000)={0x0, 0x4ff, 0x1, 0x0,
> 0x32a}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x2000)=nil,
> &(0x7f0000000080), &(0x7f00000000c0))
> > syz_io_uring_setup(0x3243, &(0x7f0000000100)={0x0, 0xd02d, 0x20, 0x3,
> 0x16e, 0x0, r0}, &(0x7f0000ffc000/0x3000)=nil,
> &(0x7f0000ffc000/0x4000)=nil, &(0x7f0000000180), &(0x7f00000001c0))
> > clone(0x22102000, 0x0, 0x0, 0x0, 0x0)
> > syz_io_uring_setup(0x2fa8, &(0x7f0000000200)={0x0, 0xd1a6, 0x0, 0x1,
> 0xf6, 0x0, r0}, &(0x7f0000ffc000/0x2000)=nil, &(0x7f0000ffc000/0x1000)=nil,
> &(0x7f0000000280), &(0x7f00000002c0))
> >
> > Could I generate the C program to run program1 and program2 on different
> threads? Or I need to generate for program1 and program2 separately and
> merge the program source code myself?
> > Since I see the -threaded option for syz-prog2c, but not sure the effect.
>
> Such functionality does not exist now. If you need exactly that, you
> need to merge yourself.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnaoAE9B9%2Bkk_C3HrXGdSHCpJC-vDBnhomYGLqK5msMfROA%40mail.gmail.com.

--0000000000002e20ee05bb5d240f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi, Dmitry<div>I found it is hard for me to first select t=
he potential program exceptions=C2=A0that could trigger data race.</div><di=
v>For example, the KCSAN data race report in the crash log is:</div><div>BU=
G: KCSAN: data-race in step_into / vfs_unlink<br>write to 0xffff9af42962b27=
0 of 4 bytes by task 15262 on cpu 0:<br>vfs_unlink+0x27a/0x3c0<br>do_unlink=
at+0x211/0x4c0<br>__x64_sys_unlink+0x2c/0x30<br>do_syscall_64+0x37/0x50<br>=
entry_SYSCALL_64_after_hwframe+0x44/0xa9<br><br>read to 0xffff9af42962b270 =
of 4 bytes by task 110 on cpu 1:<br>step_into+0x159/0xfb0<br>walk_component=
+0x1a5/0x380<br>path_lookupat+0x11d/0x560<br>filename_lookup+0xf2/0x380<br>=
user_path_at_empty+0x3b/0x50<br>do_readlinkat+0x87/0x200<br>__x64_sys_readl=
ink+0x43/0x50<br>do_syscall_64+0x37/0x50<br>entry_SYSCALL_64_after_hwframe+=
0x44/0xa9<br></div><div><br></div><div>I even did not find any readlink sys=
call in the crash log file. Did I miss=C2=A0something?</div><div><br></div>=
<div><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_signature" data=
-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div><br></div><div>Thank Y=
ou</div>Best<div>Jin Huang</div></div></div></div><br></div></div><br><div =
class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Thu, Feb 11,=
 2021 at 6:31 AM Dmitry Vyukov &lt;<a href=3D"mailto:dvyukov@google.com">dv=
yukov@google.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" =
style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);pa=
dding-left:1ex">On Thu, Feb 11, 2021 at 10:49 AM Jin Huang &lt;<a href=3D"m=
ailto:andy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a=
>&gt; wrote:<br>
&gt;<br>
&gt; Hi, Dmitry<br>
&gt; Still a question , for example the log I select is:<br>
&gt; 08:55:49 executing program 1:<br>
&gt; r0 =3D epoll_create(0x800)<br>
&gt; syz_io_uring_setup(0x472e, &amp;(0x7f0000000100), &amp;(0x7f0000ffe000=
/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil, &amp;(0x7f0000000180), =
&amp;(0x7f00000001c0))<br>
&gt; epoll_wait(r0, &amp;(0x7f0000000000)=3D[{}], 0x1, 0x0)<br>
&gt;<br>
&gt; 08:55:49 executing program 2:<br>
&gt; r0 =3D syz_io_uring_setup(0x61a1, &amp;(0x7f0000000000)=3D{0x0, 0x4ff,=
 0x1, 0x0, 0x32a}, &amp;(0x7f0000ffc000/0x2000)=3Dnil, &amp;(0x7f0000ffc000=
/0x2000)=3Dnil, &amp;(0x7f0000000080), &amp;(0x7f00000000c0))<br>
&gt; syz_io_uring_setup(0x3243, &amp;(0x7f0000000100)=3D{0x0, 0xd02d, 0x20,=
 0x3, 0x16e, 0x0, r0}, &amp;(0x7f0000ffc000/0x3000)=3Dnil, &amp;(0x7f0000ff=
c000/0x4000)=3Dnil, &amp;(0x7f0000000180), &amp;(0x7f00000001c0))<br>
&gt; clone(0x22102000, 0x0, 0x0, 0x0, 0x0)<br>
&gt; syz_io_uring_setup(0x2fa8, &amp;(0x7f0000000200)=3D{0x0, 0xd1a6, 0x0, =
0x1, 0xf6, 0x0, r0}, &amp;(0x7f0000ffc000/0x2000)=3Dnil, &amp;(0x7f0000ffc0=
00/0x1000)=3Dnil, &amp;(0x7f0000000280), &amp;(0x7f00000002c0))<br>
&gt;<br>
&gt; Could I generate the C program to run program1 and program2 on differe=
nt threads? Or I need to generate for program1 and program2 separately and =
merge the program source code myself?<br>
&gt; Since I see the -threaded option for syz-prog2c, but not sure the effe=
ct.<br>
<br>
Such functionality does not exist now. If you need exactly that, you<br>
need to merge yourself.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnaoAE9B9%2Bkk_C3HrXGdSHCpJC-vDBnhomYGLqK5msMfRO=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CACV%2BnaoAE9B9%2Bkk_C3HrXGdSHCpJC-vDBnhomYGLqK=
5msMfROA%40mail.gmail.com</a>.<br />

--0000000000002e20ee05bb5d240f--
