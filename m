Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBJ7FYOAAMGQEJSOI6BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 03D66305183
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 05:57:12 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id h25sf316481wmb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 20:57:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611723431; cv=pass;
        d=google.com; s=arc-20160816;
        b=WacnJl2mLa2ovA8RMk5+DvBJZ28+9pQd++9qsJ1oPBn0zHZgHDt6NwAogHxIBMda2o
         y4w5wNeWkuj3Mcf6g3RvoksJoZVgsN0G8O1s26P+zZUhd5o7gtkHaVm42IIszNvYjx3K
         rxPmB9WSQqOeWxEYWD/9K+zaAwAhyQARAxT/WhDG1zvDdlLUR5l9xJvEqouDyYs1JQT2
         jCA9Uf/6O9Gp9OtT9x/N+EQ7CAhtvrADrTSc4UazH/dU0z9R7uj4EyUQal18L6JdzoBB
         iaL/iprEWQaUdUt5KaY0f5Ju+fpjGNxlC6hmvRarweLeKbTKKoyuwv9kB7yQkcbHPKmS
         6FYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Q+drRrU/98LYIZurAj5bQUStAz1FlapwKvhEarQ5bxg=;
        b=i4wH5NVKIWYj41ODgOSP8Qi8nKvJiTO7fsTJukrZkmB3O+zA3QRVgG5HaFsEhhxM4n
         4Kfk4VR3kDdGtPeluXeSQvLEGFgD7w3VyTLDuzOlzBPBjVFeNLekDQuNhOCVIQCbptUd
         xkjZlM2O5IlFQKjhIiEdCBcADUoaQeXtgpzd0COIHA+OhNRWxNUdC2VL5LXhyVbblc+H
         p3y1daEdYByaZiMAiyi3EiLZNRpJkV77Wd5FkfQ5oyHaXXIPwU4cSPfJDzSWvljxdNQN
         aF7bUZwOPOMbpBiyKWHWtnQ4lH0DM6VIQSSynNQNUGZU0gF3mgiDk48J5wM01RskQSR0
         hM/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KO214SrT;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+drRrU/98LYIZurAj5bQUStAz1FlapwKvhEarQ5bxg=;
        b=AFdA0JTOv0TJ5fTvFKqDd5KO6M4ZmI138+OYXXUIGi6G+YFxia052320ECNZmxqEK+
         vmOaUKtidfB19LGylC1LUWJCcuYUXn6LM6IPKVcp8qSelhfWWdVC6NHGK+dmRYqEIMnj
         XqwjE0q784LjS/gqiu9hmQME8PgWzqrBoQ+OylYlF3h7JSTlqdCS1FD04Ticv4i/f8l2
         MO8s0nLz7eqS1roLoB+Tv7m4+I3YeYAqsYnekWpnFrGMHT3JSIrMMDRJoPfsjwQz1RG+
         30cTGW/rf0NRv5u8OHJKnSFRi75Mssz0911BKeWZRcCuBdG6nQo+F/mxpF81Br9phpKg
         8xTQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+drRrU/98LYIZurAj5bQUStAz1FlapwKvhEarQ5bxg=;
        b=hHBO7EwjnrSPsWRHJaP1ts2GgVs17re2DUvkW6WgN6pNdprdIPoSP3MWWzXKJMrz19
         8Ih+2RVDVhECXRAjtc1XGYDZDBxxT+zLIQ6gIc4uuo3u5t0woVxk0aqpJJU5zuM3iGSL
         XSfvHaIDGutYyqqsfPLVrEz4jwvsVaI+KYJCXTgS+cv5T9/0/9zEq4/tZRWi0oCZi3jH
         /2qR4qJvUKE+Wth0FT7JcT3KaHt40lq9CvLK0x2QUCMu+rsz2jcU8R/HXXhbXeyHZ9Tc
         xGjs6KkQkS5bjla2OpE1k1KeC1oMYr/0RsuSP/ZerI5Na86QH5ewROGNTSUU3jxDdadJ
         4NcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+drRrU/98LYIZurAj5bQUStAz1FlapwKvhEarQ5bxg=;
        b=HXYtSdpmURinfdZyVdZL/BbThLMlzRLc6azTgwJ8BdnQpk/gSgtxixS/enMtak7yRO
         Eccu5NQJmCWq6bQzr8IkylIy1rrkj0hLkx70MPHiclzNoQyB8KbmK5zkkKlUjp6CvdZR
         bdxNCJGcTdbTA88KripauaDwQXcSqbGMof8bJuLunUGsur0Tbbg0rL9918vgeDXlscD/
         BrWU0x4x70twZnzhqs+8hp++L0Jsujge4DvTbFFrbcFdCM+D2jDLrwQSe06KQpObCFO6
         6/yzMghKv1nxa5UkT+eFZhbYPiIONrdiq0qfw93Fl9JmHnPep4Za38yXEsY0b8JegLA8
         sm/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530s93On/37zKA7CXcNRBhtCtJvlstBBMRekH5hTcianZ5vPQ7v0
	dSVaewX45/4yTIiaSJospU0=
X-Google-Smtp-Source: ABdhPJwvNfmW30nEDFoTK1USV5JUM/MNNOrGNF8LnntDiZ5PflFUQDucoSMhKXH9j2SHNi5x7/lKdg==
X-Received: by 2002:adf:f9cb:: with SMTP id w11mr9255068wrr.199.1611723431740;
        Tue, 26 Jan 2021 20:57:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls279065wmb.2.gmail; Tue, 26 Jan
 2021 20:57:10 -0800 (PST)
X-Received: by 2002:a1c:c903:: with SMTP id f3mr2416357wmb.69.1611723430860;
        Tue, 26 Jan 2021 20:57:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611723430; cv=none;
        d=google.com; s=arc-20160816;
        b=HeyPrMZwWz1ruR1Aryl4zUa2K8FgsQAkqmnCJVeB1CqKvGYyYTZLhTx6H5JX5cbuL/
         787LKNh8b1EqtNWqcuJcg2n5Jdes4wdJUYmi1or9y2XXaCoIoxZklUofTUrvDIPsSas6
         ErCfpH9OGPQLR8rP0sBrqz9MTkV8ap/FKQij5xL/wUKdnUuwrf3nqUsWRFOgovO5A7n5
         7r0fpc3wkPMq3+2+D69744WHDD/cgrDTzZRtXGc0qlw294G7W6JA6GY1SvJloopsvAj7
         fHN1yWWyCBQ0Eh0R9391iGPCNMzNULYaRFseX5PmB2/aYpGc9RL/z9G5NkpkKA5T87d6
         6C8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vwwDZBdWlgLBuzIeJHR39YkeYL+oLkUUrXs0UCFlkK0=;
        b=WlcdOxUeHAGRmDhqifFunFFkBdnsIctrYNSMGqOvToFp7Xn7sZ3VkL6Sju2mCgD4FO
         fvdzuFQb/md91zLZd0Pu6reAKhkijhvqO1Zhmp0s15SMEKlV5d5O1uQUOQKJYwg9YEmR
         J4rUwaV/cf5gEYoDITUbcmAQPCDdeHWI3H1Bxd84zRwNNj0BuWuo96Qrq6YY1HVKKwVn
         GHpxxfmSHBvN0YJHy1iUXAZOB5Bsv0sSTJVjC4WqXOyTZm6zMVoJJ7rEuVD1+NhJr3SZ
         uo4o2rlX/FD/F72q8OoDsNwYoB76bHPzqFoygPxt2kTv7aGO+CXTC01gHTk96qwPi5lv
         Brkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KO214SrT;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id s74si49174wme.0.2021.01.26.20.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Jan 2021 20:57:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id bx12so823394edb.8
        for <kasan-dev@googlegroups.com>; Tue, 26 Jan 2021 20:57:10 -0800 (PST)
X-Received: by 2002:aa7:c813:: with SMTP id a19mr7500079edt.136.1611723430545;
 Tue, 26 Jan 2021 20:57:10 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com> <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
In-Reply-To: <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Tue, 26 Jan 2021 23:56:59 -0500
Message-ID: <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: multipart/alternative; boundary="0000000000008dcc7305b9da9a21"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=KO214SrT;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52c
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

--0000000000008dcc7305b9da9a21
Content-Type: text/plain; charset="UTF-8"

Hi, Macro
Could you provide some instructions about how to use syz-symbolize to
locate the kernel source code?
I did not find any document about it.

Thank You
Best
Jin Huang


On Mon, Jan 11, 2021 at 2:09 AM Marco Elver <elver@google.com> wrote:

> On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com> wrote:
>
>> Really thank you for your help, Dmitry.
>> I tried and saw the KCSAN info.
>>
>> But now it seems weird, the KCSAN reports differently every time I run
>> the kernel, and the /sys/kernel/debug/kcsan seems does not match with the
>> KCSAN report. What is wrong?
>>
>
> /sys/kernel/debug/kcsan shows the total data races found, but that may
> differ from those reported to console, because there is an extra filtering
> step (e.g. KCSAN won't report the same data race more than once 3 sec).
>
>
>> And I also want to ask, besides gdb, how to use other ways to locate the
>> kernel source code, like decode_stacktrace.sh and syz-symbolize, talked
>> about here https://lwn.net/Articles/816850/. Is gdb the best way?
>>
>
> I use syz-symbolize 99% of the time.
>
>
>> Also, does KCSAN recognizes all the synchronizations in the Linux Kernel?
>> Is there false positives or false negatives?
>>
>
> Data races in the Linux kernel is an ongoing story, however, there are no
> false positives (but KCSAN can miss data races).
>
> Regarding the data races you're observing: there are numerous known data
> races in the kernel that are expected when you currently run KCSAN. To
> understand the severity of different reports, let's define the following 3
> concurrency bug classes:
>
> A. Data race, where failure due to current compilers is unlikely
> (supposedly "benign"); merely marking the accesses appropriately is
> sufficient. Finding a crash for these will require a miscompilation, but
> otherwise look "benign" at the C-language level.
>
> B. Race-condition bugs where the bug manifests as a data race, too --
> simply marking things doesn't fix the problem. These are the types of bugs
> where a data race would point out a more severe issue.
>
> C. Race-condition bugs where the bug never manifests as a data race. An
> example of these might be 2 threads that acquire the necessary locks, yet
> some interleaving of them still results in a bug (e.g. because the logic
> inside the critical sections is buggy). These are harder to detect with
> KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or
> ASSERT_EXCLUSIVE_WRITER() in the right place. See
> https://lwn.net/Articles/816854/.
>
> One problem currently is that the kernel has quite a lot type-(A) reports
> if we run KCSAN, which makes it harder to identify bugs of type (B) and
> (C). My wish for the future is that we can get to a place, where the kernel
> has almost no unintentional (A) issues, so that we primarily find (B) and
> (C) bugs.
>
> Hope this helps.
>
> Thanks,
> -- Marco
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnarfJs5WSpdbG8%3DUi0mCda4%2BibToEMPxu4GHhGu0RbhD_w%40mail.gmail.com.

--0000000000008dcc7305b9da9a21
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi, Macro<div>Could you provide some instructions about ho=
w to use syz-symbolize to locate the kernel source code?</div><div>I did no=
t find any document about it.<br clear=3D"all"><div><div dir=3D"ltr" class=
=3D"gmail_signature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><d=
iv><br></div><div>Thank You</div>Best<div>Jin Huang</div></div></div></div>=
<br></div></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gm=
ail_attr">On Mon, Jan 11, 2021 at 2:09 AM Marco Elver &lt;<a href=3D"mailto=
:elver@google.com">elver@google.com</a>&gt; wrote:<br></div><blockquote cla=
ss=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid =
rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr"><div dir=3D"ltr">On Mon=
, 11 Jan 2021 at 07:54, Jin Huang &lt;<a href=3D"mailto:andy.jinhuang@gmail=
.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wrote:<br></div><di=
v class=3D"gmail_quote"><blockquote class=3D"gmail_quote" style=3D"margin:0=
px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"><=
div dir=3D"ltr">Really thank you for your help, Dmitry.=C2=A0<div>I tried a=
nd saw the KCSAN info.<div><br></div><div>But now it seems weird, the KCSAN=
 reports differently every=C2=A0time I run the kernel,=C2=A0and the /sys/ke=
rnel/debug/kcsan seems does not match with the KCSAN report. What is wrong?=
</div></div></div></blockquote><div><br></div><div>/sys/kernel/debug/kcsan =
shows the total data races found, but that may differ from those reported t=
o console, because there is an extra filtering step (e.g. KCSAN won&#39;t r=
eport the same data race more than once 3 sec).<br></div><div>=C2=A0</div><=
blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-l=
eft:1px solid rgb(204,204,204);padding-left:1ex"><div dir=3D"ltr"><div><div=
>And I also want to ask, besides gdb, how to use other ways to locate the k=
ernel source code, like decode_stacktrace.sh and syz-symbolize, talked abou=
t here=C2=A0<a href=3D"https://lwn.net/Articles/816850/" target=3D"_blank">=
https://lwn.net/Articles/816850/</a>. Is gdb the best way?</div></div></div=
></blockquote><div><br></div><div>I use=C2=A0syz-symbolize 99% of the time.=
</div><div>=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"margin:0p=
x 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"><d=
iv dir=3D"ltr"><div><div>Also, does KCSAN=C2=A0recognizes all the synchroni=
zations in the Linux Kernel? Is there false positives or false negatives?</=
div></div></div></blockquote><div><br></div><div>Data races in the Linux ke=
rnel is an ongoing story, however, there are no false positives (but KCSAN =
can miss data races).</div><div><br></div><div>Regarding the data races you=
&#39;re observing: there are numerous known data races in the kernel that a=
re expected when you currently run KCSAN. To understand the severity of dif=
ferent reports, let&#39;s define the following 3 concurrency bug classes:</=
div><br>A. Data race, where failure due to current compilers is unlikely (s=
upposedly &quot;benign&quot;); merely marking the accesses appropriately is=
 sufficient. Finding a crash for these will require a miscompilation, but o=
therwise look &quot;benign&quot; at the C-language level.<br><br>B. Race-co=
ndition bugs where the bug manifests as a data race, too -- simply marking =
things doesn&#39;t fix the problem. These are the types of bugs where a dat=
a race would point out a more severe issue.<br><br>C. Race-condition bugs w=
here the bug never manifests as a data race. An example of these might be 2=
 threads that acquire the necessary locks, yet some interleaving of them st=
ill results in a bug (e.g. because the logic inside the critical sections i=
s buggy). These are harder to detect with KCSAN as-is, and require using AS=
SERT_EXCLUSIVE_ACCESS() or ASSERT_EXCLUSIVE_WRITER() in the right place. Se=
e <a href=3D"https://lwn.net/Articles/816854/" target=3D"_blank">https://lw=
n.net/Articles/816854/</a>.<br><br>One problem currently is that the kernel=
 has quite a lot type-(A) reports if we run KCSAN, which makes it harder to=
 identify bugs of type (B) and (C). My wish for the future is that we can g=
et to a place, where the kernel has almost no unintentional (A) issues, so =
that we primarily find (B) and (C) bugs.</div><div class=3D"gmail_quote"><b=
r></div><div class=3D"gmail_quote">Hope this helps.</div><div class=3D"gmai=
l_quote"><br></div><div class=3D"gmail_quote">Thanks,</div><div class=3D"gm=
ail_quote">-- Marco</div></div>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnarfJs5WSpdbG8%3DUi0mCda4%2BibToEMPxu4GHhGu0Rbh=
D_w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CACV%2BnarfJs5WSpdbG8%3DUi0mCda4%2BibToEMPxu4=
GHhGu0RbhD_w%40mail.gmail.com</a>.<br />

--0000000000008dcc7305b9da9a21--
