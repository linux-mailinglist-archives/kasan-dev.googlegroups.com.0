Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHXT577QKGQECOXMPTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 267312F0D1A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 08:09:19 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id y12sf4202752vsq.21
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Jan 2021 23:09:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610348958; cv=pass;
        d=google.com; s=arc-20160816;
        b=kp5yQEz5kxEjmMBp5xMlOcF7nsrDKJa85n+4e9HY9fcNaoed/om4Vh3B+rtAGyFjSv
         jLrCW89FQKBfjTamp9Lr2wR7QvC66JfOS+bXNHDCO7aYLPBvBQkOTMkbl317YArB/Ws+
         eOvg0Gj1LdKYeicg2v2mqXTKc7nHTKx7yRLquEAAyzx1f/xunrWzE6KOBm9oluNdnD6q
         yMD4CwR26FnROvoucMKd6LnuIVxNotJ0GGCbLgrBe17JskAwELWgHysmYNbeX3whVRL9
         46YVH3FKpmsnmj1xHc5vg6G0MBo53ICtz0P0fHGw7KKuD+XFaO7XKSYEQl2hukDCQSaw
         OkHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gESxCKXEcqMnIl3Oc12/MFkzr0uKLvDuuQDVk7LUmck=;
        b=sAGj3I8pXVKy/RpSZy+TaQl/f59YmWbEIP0S5gbYC0yY76jEY+zN4h1T/C92m1fP4n
         nF8dfrhgXWI6vVEDvn/7TBjpgrsXUdhSuWmaRpL9/BeeUueqdBXHv0n1BAa+NEPUqChS
         fo8XBuBjW7USynjxoOchoMPnquSTIB23gaKAsQGHJBHDhW8XQd0gh2BVZUPEMAghTUFa
         zUITLu5PoWKrOrqaWYjS4nniH6x9/chdfWQU8YqAExZWP9LYZ9RFD1BV6sEFRJ0t+tkR
         ZKkzv6E9SYcxKLjEzB1gd3946nxlcBRV88nwBUWVVePSIWehCVeh8K7NiY5a2JUvXm8s
         D5CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GAx09Xvq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gESxCKXEcqMnIl3Oc12/MFkzr0uKLvDuuQDVk7LUmck=;
        b=S3y8b9jT402SgzPfc9M2+6anWXk7Z+WLwugfeot9KrjWVfMMgnAruPXz/zZzMXvA07
         stWqir3kNTLT5lmPRgGQivqvQ9mz9gHglAfsPmh6XpqcnuP2AjpRoNT+ovw2RWp2ASNS
         zjWytwHiboZSojlKsUAzlHuEFRpvdBn9GyNdcGNFVoNDBXzG6hfviIfSldEA0XAIzuRs
         8uEQjrvys09PNxciwi6O2kfo3XTSb1aq+c0ULkJ2W3yeSVliPw56dqbRVSn6no8agD8y
         CH7oG2BzpWM99HgeqDQmQ9jybok8n/BEAB6Ug4tmKPG43zL+uLCFYqisyMNFPAFZdeSB
         EoQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gESxCKXEcqMnIl3Oc12/MFkzr0uKLvDuuQDVk7LUmck=;
        b=Lw6T0C1hjZjyLDJT0k1q5soD31OGMiGoh4SDpNE9Dg8qGlfPjF3CpZzHa4kMLJY6fw
         2jH81QO+ccDBKFur8SSpmlWEqJrOL1iKlBKS3RLXZni/CM7gn/TeHiS69n4CiHIz0QhI
         O0ZXcV1vpskHaZg2Eh2m1BhdN5jVXZtaVNgQcSbqctDgmxuf2eZ9fnH2tUSPUpRBMRGb
         NsYQIcKvnecfnpa9cM4UQcbgoLwj5E0OKT0C9WKF8tddN8ppO1ka9PE/u7eCC54TbkVM
         VfvBU0mOfn5EOBWAlnEC3prCG3LsMm0MaD47ZZ4jAZmbDtM8QLn7UL5T1oDKZ3tYZTrJ
         ac4A==
X-Gm-Message-State: AOAM530es7M3TeGI42idGhPR/oA5wiuC0N0IQRd3IFOToBMln0R6FpMz
	jsxp8g3vRWsuIjJz+DUhuGg=
X-Google-Smtp-Source: ABdhPJzYzhmvTX58Ot+IIRUdgetXIHswJLlyReqvhz7CLKHz3kryJVGKItuD3TDgtxI6NePlwTiQ1A==
X-Received: by 2002:ac5:c284:: with SMTP id h4mr11736422vkk.14.1610348958223;
        Sun, 10 Jan 2021 23:09:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:11aa:: with SMTP id y10ls957152vkn.1.gmail; Sun, 10
 Jan 2021 23:09:17 -0800 (PST)
X-Received: by 2002:a1f:9156:: with SMTP id t83mr12094360vkd.3.1610348957709;
        Sun, 10 Jan 2021 23:09:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610348957; cv=none;
        d=google.com; s=arc-20160816;
        b=VupDmq59ygMMq1HkNF7VLX+/bWt2Z0V+V9b2zm15V3fmyvQ58MwQJwzHa8I9Bjtmwx
         KhQgwRp8DmMQ3CLtvRI1YR8UHxX0o3i9r35aW/eYspe6D7Lh/ts7KPRDBx+w91a0w/JC
         imikBcx9V1wXxAED9WCmxO+AOnaxH9yEhSEaI5FdW2slRFWM0kdZGGGDNG1Oa2McY/me
         wiuZrwBwtPvNJZY6rvqI2tCBSa3L/gqshYldwXIYt4M0D7up7JA63cKhpSydUlalbNOC
         DeZnQTls6yUVSJanmNgTHxmSSSBAWO0YSEmFoIO6c0P0t0JE+5XqLZiCeClT5zKQcO7C
         kukg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aAbOQG+yLQeuSu80aVAbjnCeQllp4m9/39WwQVAMIes=;
        b=oOTSXb/WjLKI3QgoPhRkY//ng5YKxUuPmo71U4wgYxAx8Zj9TZyGjQBIQrsPbuMsZM
         6jyXGqn7uWSGkoAC2CIxq3TJLKPUWNF7BrYovkia6IRy8GlPZM0857T5NjuNNFUP8Sr+
         GbR2reFT2WAYW7d2D9Ooq0ey+C3tEBMWFO1gm/m3Hlb529lBHhk5AMPKD7syO/agUPU9
         2xLmvnBCnUmXZKcCjCturYzHbS+/tY98jDpf1HqHDGuv4f/kKNmJsBe8y2sIvFa03e78
         09g2U5D2nToQ6sZIl/YdU3FTt5dqaXHgR7/D7wkiJMlpXcEFWlSZSlXzWUpiKwd2emgV
         OZ5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GAx09Xvq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc29.google.com (mail-oo1-xc29.google.com. [2607:f8b0:4864:20::c29])
        by gmr-mx.google.com with ESMTPS id v23si1546630uap.1.2021.01.10.23.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Jan 2021 23:09:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) client-ip=2607:f8b0:4864:20::c29;
Received: by mail-oo1-xc29.google.com with SMTP id j21so3868837oou.11
        for <kasan-dev@googlegroups.com>; Sun, 10 Jan 2021 23:09:17 -0800 (PST)
X-Received: by 2002:a4a:4ccb:: with SMTP id a194mr11135371oob.14.1610348956882;
 Sun, 10 Jan 2021 23:09:16 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com> <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
In-Reply-To: <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jan 2021 08:09:05 +0100
Message-ID: <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: multipart/alternative; boundary="0000000000008a6e8e05b89a95dd"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GAx09Xvq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c29 as
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

--0000000000008a6e8e05b89a95dd
Content-Type: text/plain; charset="UTF-8"

On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com> wrote:

> Really thank you for your help, Dmitry.
> I tried and saw the KCSAN info.
>
> But now it seems weird, the KCSAN reports differently every time I run the
> kernel, and the /sys/kernel/debug/kcsan seems does not match with the KCSAN
> report. What is wrong?
>

/sys/kernel/debug/kcsan shows the total data races found, but that may
differ from those reported to console, because there is an extra filtering
step (e.g. KCSAN won't report the same data race more than once 3 sec).


> And I also want to ask, besides gdb, how to use other ways to locate the
> kernel source code, like decode_stacktrace.sh and syz-symbolize, talked
> about here https://lwn.net/Articles/816850/. Is gdb the best way?
>

I use syz-symbolize 99% of the time.


> Also, does KCSAN recognizes all the synchronizations in the Linux Kernel?
> Is there false positives or false negatives?
>

Data races in the Linux kernel is an ongoing story, however, there are no
false positives (but KCSAN can miss data races).

Regarding the data races you're observing: there are numerous known data
races in the kernel that are expected when you currently run KCSAN. To
understand the severity of different reports, let's define the following 3
concurrency bug classes:

A. Data race, where failure due to current compilers is unlikely
(supposedly "benign"); merely marking the accesses appropriately is
sufficient. Finding a crash for these will require a miscompilation, but
otherwise look "benign" at the C-language level.

B. Race-condition bugs where the bug manifests as a data race, too --
simply marking things doesn't fix the problem. These are the types of bugs
where a data race would point out a more severe issue.

C. Race-condition bugs where the bug never manifests as a data race. An
example of these might be 2 threads that acquire the necessary locks, yet
some interleaving of them still results in a bug (e.g. because the logic
inside the critical sections is buggy). These are harder to detect with
KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or
ASSERT_EXCLUSIVE_WRITER() in the right place. See
https://lwn.net/Articles/816854/.

One problem currently is that the kernel has quite a lot type-(A) reports
if we run KCSAN, which makes it harder to identify bugs of type (B) and
(C). My wish for the future is that we can get to a place, where the kernel
has almost no unintentional (A) issues, so that we primarily find (B) and
(C) bugs.

Hope this helps.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM_zO_u%3Dr732JLzE5%3D%2BTimjgky%2B7P8So_k9_cukO876CQ%40mail.gmail.com.

--0000000000008a6e8e05b89a95dd
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr">On Mon, 11 Jan 2021 at 07:54, Jin Huang &=
lt;<a href=3D"mailto:andy.jinhuang@gmail.com">andy.jinhuang@gmail.com</a>&g=
t; wrote:<br></div><div class=3D"gmail_quote"><blockquote class=3D"gmail_qu=
ote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,20=
4);padding-left:1ex"><div dir=3D"ltr">Really thank you for your help, Dmitr=
y.=C2=A0<div>I tried and saw the KCSAN info.<div><br></div><div>But now it =
seems weird, the KCSAN reports differently every=C2=A0time I run the kernel=
,=C2=A0and the /sys/kernel/debug/kcsan seems does not match with the KCSAN =
report. What is wrong?</div></div></div></blockquote><div><br></div><div>/s=
ys/kernel/debug/kcsan shows the total data races found, but that may differ=
 from those reported to console, because there is an extra filtering step (=
e.g. KCSAN won&#39;t report the same data race more than once 3 sec).<br></=
div><div>=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"margin:0px =
0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"><div=
 dir=3D"ltr"><div><div>And I also want to ask, besides gdb, how to use othe=
r ways to locate the kernel source code, like decode_stacktrace.sh and syz-=
symbolize, talked about here=C2=A0<a href=3D"https://lwn.net/Articles/81685=
0/" target=3D"_blank">https://lwn.net/Articles/816850/</a>. Is gdb the best=
 way?</div></div></div></blockquote><div><br></div><div>I use=C2=A0syz-symb=
olize 99% of the time.</div><div>=C2=A0</div><blockquote class=3D"gmail_quo=
te" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204=
);padding-left:1ex"><div dir=3D"ltr"><div><div>Also, does KCSAN=C2=A0recogn=
izes all the synchronizations in the Linux Kernel? Is there false positives=
 or false negatives?</div></div></div></blockquote><div><br></div><div>Data=
 races in the Linux kernel is an ongoing story, however, there are no false=
 positives (but KCSAN can miss data races).</div><div><br></div><div>Regard=
ing the data races you&#39;re observing: there are numerous known data race=
s in the kernel that are expected when you currently run KCSAN. To understa=
nd the severity of different reports, let&#39;s define the following 3 conc=
urrency bug classes:</div><br>A. Data race, where failure due to current co=
mpilers is unlikely (supposedly &quot;benign&quot;); merely marking the acc=
esses appropriately is sufficient. Finding a crash for these will require a=
 miscompilation, but otherwise look &quot;benign&quot; at the C-language le=
vel.<br><br>B. Race-condition bugs where the bug manifests as a data race, =
too -- simply marking things doesn&#39;t fix the problem. These are the typ=
es of bugs where a data race would point out a more severe issue.<br><br>C.=
 Race-condition bugs where the bug never manifests as a data race. An examp=
le of these might be 2 threads that acquire the necessary locks, yet some i=
nterleaving of them still results in a bug (e.g. because the logic inside t=
he critical sections is buggy). These are harder to detect with KCSAN as-is=
, and require using ASSERT_EXCLUSIVE_ACCESS() or ASSERT_EXCLUSIVE_WRITER() =
in the right place. See <a href=3D"https://lwn.net/Articles/816854/">https:=
//lwn.net/Articles/816854/</a>.<br><br>One problem currently is that the ke=
rnel has quite a lot type-(A) reports if we run KCSAN, which makes it harde=
r to identify bugs of type (B) and (C). My wish for the future is that we c=
an get to a place, where the kernel has almost no unintentional (A) issues,=
 so that we primarily find (B) and (C) bugs.</div><div class=3D"gmail_quote=
"><br></div><div class=3D"gmail_quote">Hope this helps.</div><div class=3D"=
gmail_quote"><br></div><div class=3D"gmail_quote">Thanks,</div><div class=
=3D"gmail_quote">-- Marco</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CANpmjNM_zO_u%3Dr732JLzE5%3D%2BTimjgky%2B7P8So_k9_cukO=
876CQ%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CANpmjNM_zO_u%3Dr732JLzE5%3D%2BTimjgky%2B7P=
8So_k9_cukO876CQ%40mail.gmail.com</a>.<br />

--0000000000008a6e8e05b89a95dd--
