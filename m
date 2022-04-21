Return-Path: <kasan-dev+bncBCCMH5WKTMGRB35NQWJQMGQEINT67FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F56E50A059
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 15:06:57 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id a15-20020a63cd4f000000b003a9f17da993sf2771884pgj.13
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 06:06:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650546416; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOrgpCbFujQnIMVpruZ8x0fLFMamuInye6u59qyXDzPHaAWjUezoX5faPffiVvWvXa
         9sHJ40S7sYKSnygnHfdZAFrk2UaBsY+7n5tEbxm9u4uAVQPoAQYA/edAj6y0MBRZ30Dc
         la/YIx9NKhi9EWMO3s+umAnnLS4rgdpxu5Gjlm/kHfJ9VU9zeTHicACC0TkMG/iPGv4i
         YsJpYlkSTxUFbAXR+Gw7lxwvYrg/k1IG6AXYiS6o2JbVq/p3VWvNYHQhFlYn1BoQm7N9
         rzEQfEfyQbdgVJiZOjZ0fqMxNQtnfLBIp3Qwe0ZkQKzM2hkE19D4v/pwiYlhz9iF+g36
         aO7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BpreNlbrY9ZlxK0E/8Nz8WWtmseHK49DkF/kiOmuDLs=;
        b=zetd1Mc50X0gVyt30n5QLaCwd9Glntc41NatTNsXIw9ZXzjlQeyqMiHgS1QplOpMOV
         zZOHnLCfIei2iviPYN+nShJq30M3f83ztAeJsIf+86wPyocB9gKROoLv/0ojNmnnYBqL
         0ZMH5u/0zjRjHtao7BwDA4rCxYdmmkXzT9HAjkaTI7EeGi2RsgD04nkFDNEoxT5BkOvz
         /2IIO6ufQrW5k0jA9LuHubVVjIdfCI5YC0U3yr5jJqBf1nfaGLZFhy2MzmHnNNSOT6D4
         xwbFT0E7JSOnrsSuE4uA54LUq8W40ywNtFQKDcm6F/Qb0ir8Mzrh/HPzP4JQVOKjuvjR
         hsbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=N+bbZtE9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BpreNlbrY9ZlxK0E/8Nz8WWtmseHK49DkF/kiOmuDLs=;
        b=OqknsLS306+LtJa3XEdHOYwTtNGMPfLIFBvYh4e8IoGQcx3VFPrySguIGfHa6u/BCc
         5iqRJMAYJJ4O3W9ynVdY8XDW54p1c54dG33+lqTcH7oRqu5gmdNor2DPFh8Afe38WkB6
         1BGTSO/9qayPff2Zdlybnl4Dkp2lH08qjVS0EQwOw1/RXMrFg/SvHz1DsrFUwuYKm6RD
         dr4Sy+BDs3GbKcsDRsrxVDySEx5oGEgNoYKx85k7UT2R0gCf7z1w/hA6R5D0gNxAgG3U
         +3MZr5xA0z5dZWqmC8MzhLI3Gxp/xDxhIsFtEjH4dMu4qjeaF6TzuYeMPLxYTqrnVuuN
         qBiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BpreNlbrY9ZlxK0E/8Nz8WWtmseHK49DkF/kiOmuDLs=;
        b=UphKuKAIrH6+eR7/HZIvjVP01B/omYLlelE+AlZo6bgXOaxVi3oHnGrOAPQQlONBGk
         s6H87iFfvpwpJvNo07C4L4R8o9YSLN9FvuurF3+Wr42fLjI30yOZPDetQCtf1n7Kqz7K
         HEmAX0yjeY4kFctx2qpaiE2VBxJL9//1/epfKfH9fNii9uoGiT4qt41V6l+NphIur2Wo
         OvWjjfzF2UuNLVxL+gqG/fOzoB/F8Oi+YgKrEdbRDu/QmfWJ5lLbSW0/5ZLNtUhICbp3
         wdQRvAE+Bj5DhdNyTFkzEOs97LJO4idrOiJPJ5bcXlltvhvLZW4FyDybaIJVBgJj5/0P
         XtXw==
X-Gm-Message-State: AOAM531c8ekdOu+GIydEZ2TDxoNSaOJqoDr1M2WRIUiTLpa48nKlgYPd
	RlUk2PS8/7pJBvv/nnvksjE=
X-Google-Smtp-Source: ABdhPJxvWJ8DuEM09XGl763las/g2LnOCcNnccx+d7PChtoy2/C9FTjoxC71xZhGAuShLFM3bTFjQg==
X-Received: by 2002:a63:9203:0:b0:386:3b37:76b5 with SMTP id o3-20020a639203000000b003863b3776b5mr24266308pgd.234.1650546415890;
        Thu, 21 Apr 2022 06:06:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fc44:0:b0:3a9:f988:c0cb with SMTP id r4-20020a63fc44000000b003a9f988c0cbls2720718pgk.0.gmail;
 Thu, 21 Apr 2022 06:06:55 -0700 (PDT)
X-Received: by 2002:a62:7b53:0:b0:50a:d3a5:f747 with SMTP id w80-20020a627b53000000b0050ad3a5f747mr4775631pfc.12.1650546415135;
        Thu, 21 Apr 2022 06:06:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650546415; cv=none;
        d=google.com; s=arc-20160816;
        b=dOlXM+glKF3VnV2cr8N666LxhnIZlIgZ+hBGJ8rhbA4Mk1i1Sz6iocr15CN9COubOY
         yWtHBHdkPjrintAobwfthFBl4WlE5aVr8B+0lassULcsR4f5UhJZJ+RFSuKyRJghABSu
         5uQ6Zj8zS/TPbaZEcf0m7uQ7gnZGI89q6EQyMulWe45dsKN8e3wU6OMXZK6tp0IGat8w
         0nOOKHbkPg+uju6Q2E1nSnHuxYLyAncIjk/6PtPTWMbgB/zkYp43BsmrhrDweC6+FetA
         tIWyNIMWLrXBFhF0KBTEoDHTbv3NukNhRm/Sy+m4MsSpz2R+ZKvbHJ0wKxzxFxWGfbNP
         vCKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CPNtVPMGS6n30NXy9Kmuz6m/u8UhzbZkV2pRi1jdkeY=;
        b=jaQS6BT0XIutSxLeCKRzcvbFajzoDakQjVWoRcKsyicmSc4zE+5TuQXfAZZ3C6jktl
         vCOruX9Wxu71Lf6JtHGWZQc8F/WlEmmoUBSiMNVF2ZCJpWZgoTXEhCkyLHQDDjP9u9gO
         Tp5BsI0mMn68g/GwvqgR9ZTKbtr35dV4xOWB8yE8mo3FUY4iiOkMq/KSPWy1HO+tVPZf
         Kb5E3Jrr71wIUO5bXD0gpfQoC7wmdntlt0UQuqekrmtGySCOcfiLnCHv+fl8aqNmCr9B
         cFPLDgYUCvtKkHoS2mthYqQPbnsmyaZr3NIfiGNkxaD9k+au8illx4NbBHriEIph/N/w
         X4Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=N+bbZtE9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id p4-20020a170903248400b00157192fc8c6si393032plw.0.2022.04.21.06.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 06:06:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id f17so8603528ybj.10
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 06:06:55 -0700 (PDT)
X-Received: by 2002:a25:b19b:0:b0:641:af55:af7 with SMTP id
 h27-20020a25b19b000000b00641af550af7mr25456838ybj.5.1650546408935; Thu, 21
 Apr 2022 06:06:48 -0700 (PDT)
MIME-Version: 1.0
References: <CAG_fn=Xs-OqpVCW5KyQLYKXNmQ4aH-KDjY0BrWpqMfPKcu-dug@mail.gmail.com>
 <20220421121018.60860-1-huangshaobo6@huawei.com>
In-Reply-To: <20220421121018.60860-1-huangshaobo6@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 15:06:10 +0200
Message-ID: <CAG_fn=UxSwgO8D2dCkM3vWPwcz0-rjvFdwr37cxYUt4awT3crA@mail.gmail.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, chenzefeng2@huawei.com, 
	Dmitriy Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, nixiaoming@huawei.com, wangbing6@huawei.com, 
	wangfangpeng1@huawei.com, young.liuyang@huawei.com, zengweilin@huawei.com, 
	zhongjubin@huawei.com
Content-Type: multipart/alternative; boundary="00000000000069dfc805dd29c821"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=N+bbZtE9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--00000000000069dfc805dd29c821
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Thu, Apr 21, 2022 at 2:10 PM Shaobo Huang <huangshaobo6@huawei.com>
wrote:

> > > From: huangshaobo <huangshaobo6@huawei.com>
> > >
> > > when writing out of bounds to the red zone, it can only be detected a=
t
> > > kfree. However, there were many scenarios before kfree that caused th=
is
> > > out-of-bounds write to not be detected. Therefore, it is necessary to
> > > provide a method for actively detecting out-of-bounds writing to the
> red
> > > zone, so that users can actively detect, and can be detected in the
> > > system reboot or panic.
> > >
> > >
> > After having analyzed a couple of KFENCE memory corruption reports in t=
he
> > wild, I have doubts that this approach will be helpful.
> >
> > Note that KFENCE knows nothing about the memory access that performs th=
e
> > actual corruption.
> >
> > It's rather easy to investigate corruptions of short-living objects, e.=
g.
> > those that are allocated and freed within the same function. In that
> case,
> > one can examine the region of the code between these two events and try
> to
> > understand what exactly caused the corruption.
> >
> > But for long-living objects checked at panic/reboot we'll effectively
> have
> > only the allocation stack and will have to check all the places where t=
he
> > corrupted object was potentially used.
> > Most of the time, such reports won't be actionable.
>
> The detection mechanism of kfence is probabilistic. It is not easy to fin=
d
> a bug.
> It is a pity to catch a bug without reporting it. and the cost of panic
> detection
> is not large, so panic detection is still valuable.
>
>
I am also a big fan of showing as much information as possible to help the
developers debug a memory corruption.
But I am still struggling to understand how the proposed patch helps.
Assume we have some generic allocation of an skbuff, so the reports looks
like this:

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
BUG: KFENCE: memory corruption in <frame that triggered reboot>
Corrupted memory at <end+1>
<stack trace of reboot event>

kfence-#59: <start>-<end>,size=3D100,cache=3Dkmalloc-128  allocated by task=
 77
on cpu 0 at 28.018073s:
kmem_cache_alloc
__alloc_skb
alloc_skb_with_frags
sock_alloc_send_pskb
unix_stream_sendmsg
sock_sendmsg
__sys_sendto
__x64_sys_sendto
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

This report will denote that in a system that could have been running for
days a particular skbuff was corrupted by some unknown task at some unknown
point in time.
How do we figure out what exactly caused this corruption?

When we deploy KFENCE at scale, it is rarely possible for the kernel
developer to get access to the host that reported the bug and try to
reproduce it.
With that in mind, the report (plus the kernel source) must contain all the
necessary information to address the bug, otherwise reporting it will
result in wasting the developer's time.
Moreover, if we report such bugs too often, our tool loses the credit,
which is hard to regain.

> > for example, if the application memory is out of bounds and written to
> > > the red zone in the kfence object, the system suddenly panics, and th=
e
> > > following log can be seen during system reset:
> > > BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x7=
0
> [...]
>
> thanks,
> ShaoBo Huang
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erhalt=
en
haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen,
dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by mistake,
please don't forward it to anyone else, please erase all copies and
attachments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUxSwgO8D2dCkM3vWPwcz0-rjvFdwr37cxYUt4awT3crA%40mail.gmai=
l.com.

--00000000000069dfc805dd29c821
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Thu, Apr 21, 2022 at 2:10 PM Shaob=
o Huang &lt;<a href=3D"mailto:huangshaobo6@huawei.com">huangshaobo6@huawei.=
com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"marg=
in:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1e=
x">&gt; &gt; From: huangshaobo &lt;<a href=3D"mailto:huangshaobo6@huawei.co=
m" target=3D"_blank">huangshaobo6@huawei.com</a>&gt;<br>
&gt; &gt;<br>
&gt; &gt; when writing out of bounds to the red zone, it can only be detect=
ed at<br>
&gt; &gt; kfree. However, there were many scenarios before kfree that cause=
d this<br>
&gt; &gt; out-of-bounds write to not be detected. Therefore, it is necessar=
y to<br>
&gt; &gt; provide a method for actively detecting out-of-bounds writing to =
the red<br>
&gt; &gt; zone, so that users can actively detect, and can be detected in t=
he<br>
&gt; &gt; system reboot or panic.<br>
&gt; &gt;<br>
&gt; &gt;<br>
&gt; After having analyzed a couple of KFENCE memory corruption reports in =
the<br>
&gt; wild, I have doubts that this approach will be helpful.<br>
&gt; <br>
&gt; Note that KFENCE knows nothing about the memory access that performs t=
he<br>
&gt; actual corruption.<br>
&gt; <br>
&gt; It&#39;s rather easy to investigate corruptions of short-living object=
s, e.g.<br>
&gt; those that are allocated and freed within the same function. In that c=
ase,<br>
&gt; one can examine the region of the code between these two events and tr=
y to<br>
&gt; understand what exactly caused the corruption.<br>
&gt; <br>
&gt; But for long-living objects checked at panic/reboot we&#39;ll effectiv=
ely have<br>
&gt; only the allocation stack and will have to check all the places where =
the<br>
&gt; corrupted object was potentially used.<br>
&gt; Most of the time, such reports won&#39;t be actionable.<br>
<br>
The detection mechanism of kfence is probabilistic. It is not easy to find =
a bug.<br>
It is a pity to catch a bug without reporting it. and the cost of panic det=
ection<br>
is not large, so panic detection is still valuable.<br>
<br></blockquote><div><br></div><div>I am also a big fan of showing as much=
 information as possible to help the developers debug a memory corruption.<=
/div><div>But I am still struggling to understand how the proposed patch he=
lps.</div><div>Assume we have some generic allocation of an skbuff, so the =
reports looks like this:</div><div><br></div><div>=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D</div><div>BUG: KFENCE: memory corrupti=
on in &lt;frame that triggered reboot&gt;</div><div>Corrupted memory at &lt=
;end+1&gt;</div><div>&lt;stack trace of reboot event&gt;</div><div><br></di=
v>kfence-#59: &lt;start&gt;-&lt;end&gt;,size=3D100,cache=3Dkmalloc-128=C2=
=A0=C2=A0allocated by task 77 on cpu 0 at 28.018073s:<br>kmem_cache_alloc<b=
r>__alloc_skb<br>alloc_skb_with_frags<br>sock_alloc_send_pskb<br>unix_strea=
m_sendmsg<br>sock_sendmsg<br>__sys_sendto<br>__x64_sys_sendto<br><div>=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D</div><div>=C2=A0<=
/div><div>This report will denote that in a system that could have been run=
ning for days a particular skbuff was corrupted by some unknown task at som=
e unknown point in time.</div><div>How do we figure out what exactly caused=
 this corruption?</div><div><br></div><div>When we deploy KFENCE at scale, =
it is rarely possible for the kernel developer to get access to the host th=
at reported the bug and try to reproduce it.</div><div>With that in mind, t=
he report (plus the kernel source) must contain all the necessary informati=
on to address the bug, otherwise reporting it will result in wasting the de=
veloper&#39;s time.</div><div>Moreover, if we report such bugs too often, o=
ur tool loses the credit, which is hard to regain.</div><div><br></div><blo=
ckquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left=
:1px solid rgb(204,204,204);padding-left:1ex">&gt; &gt; for example, if the=
 application memory is out of bounds and written to<br>
&gt; &gt; the red zone in the kfence object, the system suddenly panics, an=
d the<br>
&gt; &gt; following log can be seen during system reset:<br>
&gt; &gt; BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49=
/0x70<br>
[...]<br>
<br>
thanks,<br>
ShaoBo Huang<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4ls=
chlicherweise erhalten haben sollten, leiten Sie diese bitte nicht an jeman=
d anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet=
 wurde.<br><br><br>This e-mail is confidential. If you received this commun=
ication by mistake, please don&#39;t forward it to anyone else, please eras=
e all copies and attachments, and please let me know that it has gone to th=
e wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DUxSwgO8D2dCkM3vWPwcz0-rjvFdwr37cxYUt4awT3crA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DUxSwgO8D2dCkM3vWPwcz0-rjvFdwr37cxYUt4awT=
3crA%40mail.gmail.com</a>.<br />

--00000000000069dfc805dd29c821--
