Return-Path: <kasan-dev+bncBCRY3K6ZWAFRB2UGZ3XQKGQE3LMTWRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA3AB11E38A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 13:26:19 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id y7sf1197651oie.13
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 04:26:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576239978; cv=pass;
        d=google.com; s=arc-20160816;
        b=AMorWiKn88YwedYHcEb/pDUpm5ILRiBSFsZcswSM0/BNTv50lw/8hfuzupRm2HUNSv
         tLaSnte14R6mm7vLhhRZh3I1jJmpZTYuwFS0WcHUA1UnsIjXn4uCLRRmVMPZPSX9wXxV
         LNToEKeozrJPoEO3LoS+tapkXmd2DVofzmCDHXE0FtcJqVAu3oGQ0/E073b55GpY7tBt
         s75F+tGcGYS6fNkPgvz7KMY7EiHwINSIiMZRZXZfrjU6bg+YwuOqzWlCVzn5KqnWHIFE
         PHvAcX+9pFciDXfeAkHMTJ9hBmieZRLFgu1zEP6U8sFUwBGBUgN09o46L4juqwUjkHhR
         VIiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ApF/OA1nqJNK/RfKcMOpG3i2OZxisyB2kbMn2DkNEs4=;
        b=EPGjstW5IZgN76GuGs8YYx8UwrorJuLKuLXI6BAdcLiyqUig/tY8mE3RRgJUjzAhjW
         QYJo/IQvUyK9M8YY66s4s/2bjfLbbbSuFpLCvI1XTI61GrT25/sKh8NbunRnXRIPeQjk
         7Gf+NSEMOaa8h33VQuRiLbbRZvAGYaSzlk5ci8Usvh7i35qDL0iEVFOYoBCUxv7w2fqE
         wJ54QCq7HY+1GFzPh75BCLk0gyaxWRWmD/bF3nH0aKtgvYnf0aEFSZUaP9N0mU70Oi9O
         1p8WANThGOMR8UbcS/eRph7rpNzry7pIzmSzSUH+5ZmpjrzGbG8bppMnWHgs+Fsujhx2
         dj9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=DfxorJaQ;
       spf=pass (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=truhuan@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ApF/OA1nqJNK/RfKcMOpG3i2OZxisyB2kbMn2DkNEs4=;
        b=o9G7fXD19XGsNIsh36XePULOBtEcke6bWMJ8STWB40PPuVzmHJ/99xG+12YSd7fLE0
         GN3ZQUZD5LEdPpect2eXVN4VwcvX+28gsDyw28WwJ9aBY1fFYilrtNJEvNZbXA5oBLtj
         Vb8d9JIRzfxAdGiKws5/uT5iHZAaD2dYXPaJWND2+LpS9icjy7Mz2HWseReqXG71893e
         xsUiIfecPTpsG2m3+EYk0oc4t96BCOseW7eXKXzdfiHRMmxzCNL4T3a4eI2IQEhfp577
         3yqfmsLEEO0DkpsDCrLVG6JT0S9FaxlITpdHRECSSjyv3elIVmB9MbIn3XD9YIP6thZx
         p3CQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ApF/OA1nqJNK/RfKcMOpG3i2OZxisyB2kbMn2DkNEs4=;
        b=uSXSTeKRMhYpHJnElSY9R2FHwCNPysi6escr3Hc/zzVdEupX/ZpV5PuJlLhTzqH9/S
         DAHRLc3HXW/CU1ZokOiHMxq1FtsBgGAsrtFcbg7/Wfd7dTgo6NSDFO6fz/ZMmEft0NyC
         vWF7K3YXv6HZbk0o+yoaswg4IDAipYEt7TUv3Z0V1XbGD2O8ar9nEoC0lINJG+T0aR52
         6ATmdG9Omw5S7NfuPvJGzMFZJQHYa4mxHAXAD5yU4Cwrk7hoR+GVsxAbkxYZGoa5l6Z7
         H+K7KDFrMDX8nN/YA1YeYb+HxL2/GbyKRRK6YHYWVmErOBfs3KCyMuLcWA1uLk59rQf4
         QkZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ApF/OA1nqJNK/RfKcMOpG3i2OZxisyB2kbMn2DkNEs4=;
        b=sNy7zoxbCF1ah0RcFOl37y1TB6jYDQDK1ZzB2QBaOUVy4E74w6cNvUdF1RYPRdVRdO
         1u+kzatIA6tAMdtw+Rq3iXxSYIhJbvfYgJ1c/dBuuxOflo/zucTvtQDBmzOCMScYH13G
         PnpYTZSWYufjRlUpwIJOHRfUfx3whK3BpUV/fJQit6TG/cONZwDoqXJWrUKNUA/U7WdB
         SjcQp05XN0aQ0KV8nHunYKD36+uN0MkIYFDPWofDuXBF57sUBemGNMGVxJpaUUFt2DpS
         m8f45p+ZVBlyU6sTcA/3hSZxe6rApDBXYPTPKhtGeS0zmC3VSPttGU3quvR6YqVlXs4j
         nR5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV11vagvuQYXfMhVrBzI4BDhLWHpEal/XWJyVkjMQfxiNX2Ha4j
	uwXtRh1PwRauLvlkjRnJkcU=
X-Google-Smtp-Source: APXvYqy6WFs8br1f9S5hrA67BqeWdb1r2d6PMWxkOlthphBRhGDXBwUiEzAqz6nsUDWnMbwUDgWThQ==
X-Received: by 2002:aca:52c4:: with SMTP id g187mr6931086oib.76.1576239978470;
        Fri, 13 Dec 2019 04:26:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:aaca:: with SMTP id t193ls981201oie.15.gmail; Fri, 13
 Dec 2019 04:26:18 -0800 (PST)
X-Received: by 2002:aca:4911:: with SMTP id w17mr6968223oia.170.1576239978106;
        Fri, 13 Dec 2019 04:26:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576239978; cv=none;
        d=google.com; s=arc-20160816;
        b=glGZPoaYFimRbXABt/C+AeUKBycjm+ErraAs+3IQI2Atrb9CUWyGmLasCrQ9q9se1Z
         TSjZi3Ve6RcPBYQr4KePFNa3ZA2tkIKBOPt9tON5Y0wszCc5vp4ZGGlz0peg6EFwN+Hi
         e7HyvrkJkKIyPZ7/PecW/vvYrCce6C4gqnRUscaQTb52mDbtxjdqAqUxzvL/w8Blwy5j
         FlH+8GypQ8LUZFpf/QMhgTNNge2bBJiIRK81/wddsS6GxM7ChF4wbajX9E12oPiQTXDF
         YErlcg2Nnu0vWgcbCq6AYwsZTF0itbHJUJCQh6MFVb1OZMjQd8MAAFJfoo4HP0T58U83
         xSBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nI5OYCtIJUIg9H79Hy8gpb6QpaCJy/O6Tgeg7hFQUJQ=;
        b=BTbutgFnmzglJZ9NBm/kgWOcsktVz++43G5s3lMQG5nL5NmIf/IsDmtO0JZlnN2VBM
         gG+mpGgO7uBUKp0hwpemAK2K1Ohrb0HziB1oAb3dQRDszW4g/mD2MDu6l/6w549fQMsG
         LQj2hmogTVgqs+3AGAooRfG5uFipkGnFPmZXGx9abJrcTTcRL8r9rr1H31AUtd6hcRgu
         xunmAnW/LlG6IAvWcOuIrsYQuc2H2u47/wLyl60Afk3h737eBYzZ0kaBAxQLoSG4Iuc/
         0IEi7ig7qhx/m3XpRrGajAf7pysIzGtd0L6FrJsZYS2aSgWV+bdjS+zULfuq76NSdO+w
         6hIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=DfxorJaQ;
       spf=pass (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=truhuan@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id 13si432738oin.1.2019.12.13.04.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Dec 2019 04:26:18 -0800 (PST)
Received-SPF: pass (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id k40so2089792qtk.8
        for <kasan-dev@googlegroups.com>; Fri, 13 Dec 2019 04:26:18 -0800 (PST)
X-Received: by 2002:ac8:6686:: with SMTP id d6mr12007362qtp.147.1576239977490;
 Fri, 13 Dec 2019 04:26:17 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <CADyx2V6j+do+CmmSYEUr0iP7TUWD7xHLP2ZJPrqB1Y+QEAwzhw@mail.gmail.com> <CANpmjNOCUF8xW69oG9om91HRKxsj0L5DXSgf5j+D1EK_j29sqQ@mail.gmail.com>
In-Reply-To: <CANpmjNOCUF8xW69oG9om91HRKxsj0L5DXSgf5j+D1EK_j29sqQ@mail.gmail.com>
From: Walter Wu <truhuan@gmail.com>
Date: Fri, 13 Dec 2019 20:26:06 +0800
Message-ID: <CADyx2V7xeX_5sAe2UmcfC7uzwdfmiRJ=0LZnVfojrYXoiqZBbQ@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: multipart/alternative; boundary="000000000000f06fbd059994f773"
X-Original-Sender: truhuan@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=DfxorJaQ;       spf=pass
 (google.com: domain of truhuan@gmail.com designates 2607:f8b0:4864:20::834 as
 permitted sender) smtp.mailfrom=truhuan@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000f06fbd059994f773
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Marco Elver <elver@google.com> =E6=96=BC 2019=E5=B9=B412=E6=9C=8813=E6=97=
=A5 =E9=80=B1=E4=BA=94 =E4=B8=8A=E5=8D=884:53=E5=AF=AB=E9=81=93=EF=BC=9A

> On Thu, 12 Dec 2019 at 10:57, Walter <truhuan@gmail.com> wrote:
> >
> > Hi Marco,
> >
> > Data racing issues always bothers us, we are happy to use this debug
> tool to
> > detect the root cause. So, we need to understand this tool
> implementation,
> > we try to trace your code and have some questions, would you take the
> free time
> > to answer the question.
> > Thanks.
> >
> > Question:
> > We assume they access the same variable when use read() and write()
> > Below two Scenario are false negative?
> >
> > =3D=3D=3D
> > Scenario 1:
> >
> > CPU 0:
>                    CPU 1:
> > tsan_read()
>                  tsan_write()
> >   check_access()
>                  check_access()
> >      watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
>  watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
> >      kcsan_setup_watchpoint()
>               kcsan_setup_watchpoint()
> >         watchpoint =3D insert_watchpoint
>                   watchpoint =3D insert_watchpoint
>
> Assumption: have more than 1 free slot for the address, otherwise
> impossible that both set up a watchpoint.
>
> >         if (!remove_watchpoint(watchpoint)) // no enter, no report
>      if (!remove_watchpoint(watchpoint)) // no enter, no report
>
> Correct.
>
> > =3D=3D=3D
> > Scenario 2:
> >
> > CPU 0:
>                   CPU 1:
> > tsan_read()
> >   check_access()
> >     watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
> >     kcsan_setup_watchpoint()
> >       watchpoint =3D insert_watchpoint()
> >
> > tsan_read()
>                 tsan_write()
> >   check_access()
>                 check_access()
> >     find_watchpoint()
> >       if(expect_write && !is_write)
> >         continue
> >       return NULL
> >     kcsan_setup_watchpoint()
> >       watchpoint =3D insert_watchpoint()
> >       remove_watchpoint(watchpoint)
> >         watchpoint =3D INVALID_WATCHPOINT
> >
>                              watchpoint =3D find_watchpoint()
> >
>                              kcsan_found_watchpoint()
>
> This is a bit incorrect, because if atomically setting watchpoint to
> INVALID_WATCHPOINT happened before concurrent find_watchpoint(),
> find_watchpoint will not return anything, thus not entering
> kcsan_found_watchpoint. If find_watchpoint happened before setting
> watchpoint to INVALID_WATCHPOINT, the rest of the trace matches.
> Either way,  no reporting will happen.
>
> >
>                                  consumed =3D try_consume_watchpoint() //
> consumed=3Dfalse, no report
>
> Correct again, no reporting would happen.  While running, have a look
> at /sys/kernel/debug/kcsan and look at the 'report_races' counter;
> that counter tells you how often this case actually occurred. In all
> our testing with the default config, this case is extremely rare.
>
> As it says on the tin, KCSAN is a *sampling watchpoint* based data
> race detector so all the above are expected. If you want to tweak
> KCSAN's config to be more aggressive, there are various options
> available. The most important ones:
>
> * KCSAN_UDELAY_{TASK,INTERRUPT} -- Watchpoint delay in microseconds
> for tasks and interrupts respectively. [Increasing this will make
> KCSAN more aggressive.]
>

Timing should be an important factor for data racing, if we change this
config,
May the data racing issue be disappeared? or?

* KCSAN_SKIP_WATCH -- Skip instructions before setting up watchpoint.
> [Decreasing this will make KCSAN more aggressive.]
>

I see.

>
> Note, however, that making KCSAN more aggressive also implies a
> noticeable performance hit.
>
> Thanks for your suggestion.
In fact, we are more concerned about false positive, we haven't seen it. if
we see it is
exist, we will report upwards to you.

Also, please find the latest version here:
>
> https://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git/log=
/?h=3Dkcsan
> -- there have been a number of changes since the initial version from
> September/October.
>
> Yes, we will continue to see newer KCSAN, when it is upstream success, we
will import it
to our company, and I have another question, do you know whether it will
merge into
Android common kernel?

Walter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CADyx2V7xeX_5sAe2UmcfC7uzwdfmiRJ%3D0LZnVfojrYXoiqZBbQ%40mail.gmai=
l.com.

--000000000000f06fbd059994f773
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr">Marco Elver &lt;<a href=3D"mailto:elver@g=
oogle.com" target=3D"_blank">elver@google.com</a>&gt; =E6=96=BC 2019=E5=B9=
=B412=E6=9C=8813=E6=97=A5 =E9=80=B1=E4=BA=94 =E4=B8=8A=E5=8D=884:53=E5=AF=
=AB=E9=81=93=EF=BC=9A<br></div><div class=3D"gmail_quote"><blockquote class=
=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rg=
b(204,204,204);padding-left:1ex">On Thu, 12 Dec 2019 at 10:57, Walter &lt;<=
a href=3D"mailto:truhuan@gmail.com" target=3D"_blank">truhuan@gmail.com</a>=
&gt; wrote:<br>
&gt;<br>
&gt; Hi Marco,<br>
&gt;<br>
&gt; Data racing issues always bothers us, we are happy to use this debug t=
ool to<br>
&gt; detect the root cause. So, we need to understand this tool implementat=
ion,<br>
&gt; we try to trace your code and have some questions, would you take the =
free time<br>
&gt; to answer the question.<br>
&gt; Thanks.<br>
&gt;<br>
&gt; Question:<br>
&gt; We assume they access the same variable when use read() and write()<br=
>
&gt; Below two Scenario are false negative?<br>
&gt;<br>
&gt; =3D=3D=3D<br>
&gt; Scenario 1:<br>
&gt;<br>
&gt; CPU 0:=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0CPU 1:<br>
&gt; tsan_read()=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0ts=
an_write()<br>
&gt;=C2=A0 =C2=A0check_access()=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0check_=
access()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 watchpoint=3Dfind_watchpoint() // watchpoint=3DNUL=
L=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL<br>
&gt;=C2=A0 =C2=A0 =C2=A0 kcsan_setup_watchpoint()=C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 kcsan_setup_watchpoint()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0watchpoint =3D insert_watchpoint=C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 watchpoint =3D insert_watchpoint<br>
<br>
Assumption: have more than 1 free slot for the address, otherwise<br>
impossible that both set up a watchpoint.<br>
<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (!remove_watchpoint(watchpoint)) /=
/ no enter, no report=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (!remove_w=
atchpoint(watchpoint)) // no enter, no report<br>
<br>
Correct.<br>
<br>
&gt; =3D=3D=3D<br>
&gt; Scenario 2:<br>
&gt;<br>
&gt; CPU 0:=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 CPU 1:<br>
&gt; tsan_read()<br>
&gt;=C2=A0 =C2=A0check_access()<br>
&gt;=C2=A0 =C2=A0 =C2=A0watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL=
<br>
&gt;=C2=A0 =C2=A0 =C2=A0kcsan_setup_watchpoint()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0watchpoint =3D insert_watchpoint()<br>
&gt;<br>
&gt; tsan_read()=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 tsan_wri=
te()<br>
&gt;=C2=A0 =C2=A0check_access()=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 check_access=
()<br>
&gt;=C2=A0 =C2=A0 =C2=A0find_watchpoint()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0if(expect_write &amp;&amp; !is_write)<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0continue<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0return NULL<br>
&gt;=C2=A0 =C2=A0 =C2=A0kcsan_setup_watchpoint()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0watchpoint =3D insert_watchpoint()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0remove_watchpoint(watchpoint)<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0watchpoint =3D INVALID_WATCHPOINT<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0wa=
tchpoint =3D find_watchpoint()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kc=
san_found_watchpoint()<br>
<br>
This is a bit incorrect, because if atomically setting watchpoint to<br>
INVALID_WATCHPOINT happened before concurrent find_watchpoint(),<br>
find_watchpoint will not return anything, thus not entering<br>
kcsan_found_watchpoint. If find_watchpoint happened before setting<br>
watchpoint to INVALID_WATCHPOINT, the rest of the trace matches.<br>
Either way,=C2=A0 no reporting will happen.<br>
<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0consumed =3D try_consume_watchpoint() // consumed=3Dfalse, no =
report<br>
<br>
Correct again, no reporting would happen.=C2=A0 While running, have a look<=
br>
at /sys/kernel/debug/kcsan and look at the &#39;report_races&#39; counter;<=
br>
that counter tells you how often this case actually occurred. In all<br>
our testing with the default config, this case is extremely rare.<br>
<br>
As it says on the tin, KCSAN is a *sampling watchpoint* based data<br>
race detector so all the above are expected. If you want to tweak<br>
KCSAN&#39;s config to be more aggressive, there are various options<br>
available. The most important ones:<br>
<br>
* KCSAN_UDELAY_{TASK,INTERRUPT} -- Watchpoint delay in microseconds<br>
for tasks and interrupts respectively. [Increasing this will make<br>
KCSAN more aggressive.]<br></blockquote><div><br></div><div>Timing should b=
e an important factor for data racing, if we change this config,</div><div>=
May the data racing issue be disappeared? or?</div><div><br></div><blockquo=
te class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px =
solid rgb(204,204,204);padding-left:1ex">
* KCSAN_SKIP_WATCH -- Skip instructions before setting up watchpoint.<br>
[Decreasing this will make KCSAN more aggressive.]<br></blockquote><div>=C2=
=A0</div><div>I see.=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"=
margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-lef=
t:1ex">
<br>
Note, however, that making KCSAN more aggressive also implies a<br>
noticeable performance hit.<br>
<br></blockquote><div>Thanks for your suggestion.</div><div>In fact, we are=
 more concerned about false positive, we haven&#39;t seen it. if we see it =
is</div><div>exist, we will report upwards to you.=C2=A0</div><div><br></di=
v><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;borde=
r-left:1px solid rgb(204,204,204);padding-left:1ex">
Also, please find the latest version here:<br>
<a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rc=
u.git/log/?h=3Dkcsan" rel=3D"noreferrer" target=3D"_blank">https://git.kern=
el.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git/log/?h=3Dkcsan</a><br=
>
-- there have been a number of changes since the initial version from<br>
September/October.<br>
<br></blockquote><div>Yes, we will continue to see newer KCSAN, when it is =
upstream success, we will import it</div><div>to our company, and I have an=
other question, do you know whether it will merge into</div><div>Android co=
mmon kernel?=C2=A0</div><div><br></div><div>Walter</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CADyx2V7xeX_5sAe2UmcfC7uzwdfmiRJ%3D0LZnVfojrYXoiqZBbQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CADyx2V7xeX_5sAe2UmcfC7uzwdfmiRJ%3D0LZnVfojrYXoiq=
ZBbQ%40mail.gmail.com</a>.<br />

--000000000000f06fbd059994f773--
