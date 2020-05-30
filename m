Return-Path: <kasan-dev+bncBCFLDU5RYAIRB7FRY73AKGQE2R6QUKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A9C91E8D8E
	for <lists+kasan-dev@lfdr.de>; Sat, 30 May 2020 05:54:37 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id w16sf1725656wru.18
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 20:54:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590810877; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cht3gDx5e+8brbCdeR5YqntpaTX19ruPTeB6phfWC58Ra/BWvgUazxf/A+K2TNeEm9
         A2b2G9kAgOJIq2zLysPsh3fCfag12x0QLh/6POTZQa6XTvPwCEMzKIUIsDfNvU9JLe89
         QVceMWDg/0sKbX7pCZ6tRtqtLfUK7fOCw/koW+tpdyLfWzg+0JU/IA1YFnSdE7v2neUV
         NeCVbRYYyrh1/mUggNMiumqowrrPlmE8UTn6WApVbvuD+8O+VhzKX5rTnerVrr56or/C
         62UBxULi7ehB0GM4/G6fux38QwKLHC4GftknBzkDeF6jI62YWgjpt9HoZzqgf+fw57kH
         YHWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=n6NzU4xWBKum7sBN+kJ21TXgDu0BKUK4Z1H1XrCuHMM=;
        b=TglQ9tGFEfFY5ztEeBHTxe7A5HKdQQBlbr6L+hqFTNnIKA78mwr89Sn4IS1Sen/4Ie
         /2TalGsS1+fRRerGnSmdmTP9QnMzQs3DpdcEIHjVvtwwD9ZSun5KHVDi0KhTfiPOs7+E
         mqfALe04af88royaz1EEUHMNSEc8+4EHf3pitGh6qorRUsLQY7dlXersyxyvFXrsKswx
         R/bCmIYlI09KLGd7xS8I/rxEVydWCU24tL7B37qsCJWaeUSpneY79nLs6t8xRKD0HUX5
         JJtHo2MbZE6oglVjFSU3nHMVgZogWdVNbUmPr9Qij2naipF8jMaUUx7/B5T3C91dkxlZ
         YNRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vHVRqaWt;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n6NzU4xWBKum7sBN+kJ21TXgDu0BKUK4Z1H1XrCuHMM=;
        b=oZXrtId/df/S4RWwNm+7ImzPJdvf1Md9w7q7sxIbg5dkDQK6MdLO5R16vl6beT8gLz
         vJ7AF2JCBQ+5clJalPrRO5tAgdtDyY4PQljhDtkU1qNZLBystZ1FGkmJbvi7jnBGTq8W
         Sktm7XhHxZnjk+IhH145gZxv+iyFpftu8JqFzWTsz6Y8A5wLxbaYUKsq8V8/wuzc0qi2
         37D1h1fX1fa+se4gEE7bKMehL6dum/XduQfhe3O9NN7iFnmXonRl3ZrTLww3+Cl21hTe
         phUTpOzCaGsFv/DcV0+Ws7EdflNWBWF7jWJKbmJS/HncSMCiy9aTzciWjfOGDFwDSrso
         vgsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n6NzU4xWBKum7sBN+kJ21TXgDu0BKUK4Z1H1XrCuHMM=;
        b=RQWPvi0BFCc8j6SVBrImbqFgtrSZM/M1Jfy4NpYXoDImxynVgIMnz2mJMnW+ppTd/1
         HIgq+g8pQt3Xs1m8JMvIYYEud8aiXbrnwECd7OuolRSfqsSzDuxfH9LTIQqeTCCKmKbw
         8Odvv7V7z9JykXJk7Xqjj/PPaRjqQsIdGvjimaSdOG794wWm78dGptRfmYrHehFjgRud
         lrbxEdmktom8GdpZRdWioJLLbHXzdxHXkI8YsevZ6lk5YeN+oKc+igbC6kAN9zNpUbSm
         +SBeEAnvhOishDP3n7PfYahghk4/tnCpUe/hBAHvFN5/RGFL7GAV6R3O+b9I4qWSvoFQ
         1SOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n6NzU4xWBKum7sBN+kJ21TXgDu0BKUK4Z1H1XrCuHMM=;
        b=mfh1/5sScW+Reo4dzzkIq+Sq9zCJyuFpXODEPwqP9K6172aXSvHYvgcMYDtmXBZtGN
         xFXjyLr/drjStxD6EYRPrrbUWclZxQQZ7/SEx1i08dyXd+6kf1x380uFt3hZNfAS7XvW
         IgCt5iFr4IzFKiJTnRL2J18jyl/OkvHtiJtPEFLSeyPuN1lWb4V4/8NFm9c9AAPnX6sG
         Igu3wqeLzkwr9UxOjyNsZrCdhlKG9xwlKEjO6YqKztFOlAf1lCxwRyDR4/Rfriad/ua8
         vlQ05LJhc7vfOadzQLnkwC3H3XbOKTemyuwgX6ypN85gyqbdp48Owakh94LoX8LDbkGl
         126Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328MaoyKiWlf7JeM4ju7VEcaYqBPgTBRDkrisy1udoKBi1ieOeu
	NG5rZq9yEsc/9ui1ICE/E5g=
X-Google-Smtp-Source: ABdhPJy5HHigHUCHNceXukf8a1rAVTc5Q9vfgfHOTgV9AiWMAbYobQbaua6KDBcJvHxxepQfEINuLQ==
X-Received: by 2002:a5d:6acf:: with SMTP id u15mr7371682wrw.277.1590810876892;
        Fri, 29 May 2020 20:54:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d53:: with SMTP id d80ls4186342wmd.3.canary-gmail; Fri,
 29 May 2020 20:54:36 -0700 (PDT)
X-Received: by 2002:a1c:e389:: with SMTP id a131mr11916659wmh.46.1590810876299;
        Fri, 29 May 2020 20:54:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590810876; cv=none;
        d=google.com; s=arc-20160816;
        b=A/EI4JlrOALMuQxy3PMDpGo9xdYCxLNVi0aUvzzeJszYRuS5gbztY5JS2dLVt2vAjp
         LXT0K1XEuXeMitUsQLerNIgbA3DTSto49wyczsvVx5aPaF+UG/3DQeKOYiQi+gxRFhG3
         bgmYztMQX2z/dsWNcFt2Ax4QlVl2APTAHgiTZdNogROtXBm3U/VoAJQ8JOdmodYBog7F
         8Au5RpEUXFA9ZBpzufURnG5DfEbCeskaBoXf7rNLOJ/UoLGhlTr24nAtIoTLvRkZbq4r
         03ef9R2GS1DZdLavKvI7RYvIqwtYwGJ4DG9oOf4c3yChowUoen3V8k88WmOOGDjxskvd
         lmpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6ygYeqhYirybgboA1SGqTWMUJ7m8kbe4gsH9+VaA9go=;
        b=xhU/RDpmd+JyysLS8T6gyJardb6wEA6D613+MfAHE69p7YOwQqKQieGFxuZdhuYwv/
         zfSmyT7POYPy0ISMmG/Qx4KYxHwBvo/Kg0fobVhrsIK2+Y3hlKZzqC3YD1Rb8TkvkyJU
         HXDvKhXK3XCc3Jb/0sm/NswJj2xqm4Ntu/vWOWfmp6slRseomkbIv2NKYKmppD1IPDmO
         AUKx32StQbCdsGCpYq3PfLTTWWwKoHt411ZIvfKOn+xT4GGUi8YiPbwKLMNfMH9WaoV/
         /Wwkeuy/SNtDk1C6QJWSIOil9tWG65tqHsKYAiJ01WIEL+H2xUG2kkkZhKm7LwvWcuUY
         swvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vHVRqaWt;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id z18si63868wml.2.2020.05.29.20.54.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 20:54:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id m18so1698102ljo.5
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 20:54:36 -0700 (PDT)
X-Received: by 2002:a2e:97c3:: with SMTP id m3mr5245490ljj.23.1590810875670;
 Fri, 29 May 2020 20:54:35 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com> <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
In-Reply-To: <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Fri, 29 May 2020 20:54:24 -0700
Message-ID: <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="00000000000026353905a6d5859a"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=vHVRqaWt;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000026353905a6d5859a
Content-Type: text/plain; charset="UTF-8"

Thank you very much for updated patches Walleij.

I took all the patches-V9   plus one @
https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/


and I  hit below  BUG ,

void notrace cpu_init(void)
{
#ifndef CONFIG_CPU_V7M
        unsigned int cpu = smp_processor_id();
        struct stack *stk = &stacks[cpu];

        if (cpu >= NR_CPUS) {
                pr_crit("CPU%u: bad primary CPU number\n", cpu);
                BUG();
        }



Thanks,
Venkat Sana.


On Fri, May 29, 2020 at 3:41 PM Linus Walleij <linus.walleij@linaro.org>
wrote:

> Hi Raju, Dmitry,
>
> On Fri, May 29, 2020 at 9:59 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Fri, May 29, 2020 at 5:39 PM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> > >
> > > Hello All,
> > >
> > > I started   porting
> https://github.com/torvalds/linux/compare/master...ffainelli:kasan-v7?expand=1
> > >
> > > to one out target , compilation seems fine but  target is not booting ,
> > >
> > > Any help can be greatly appreciated
> > >
> > > Thanks,
> > > Venkat Sana
> >
> > Hi Venkat,
> >
> > +Linus, Abbott who implemented KASAN for ARM (if I am not mistaken).
> >
> > However, you need to provide more details. There is not much
> > information to act on.
>
> Different parts were written by different people over time,
> Andrey, Abbot and Florian, and some by myself as well.
>
> I am trying to finish the job and it is starting to look good :)
>
> I need to rebase it for v5.7 but then it should be in mergeable
> state.
>
> Please try the latest v9 patch set:
>
> https://lore.kernel.org/linux-arm-kernel/20200515114028.135674-1-linus.walleij@linaro.org/
>
> You also need this patch:
>
> https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/
>
> You have it all in a branch in my git here:
>
> https://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git/log/?h=kasan
>
> Yours,
> Linus Walleij
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkanvC%2BRU0DjiCz%3D4e%2BZhy%2BmEux-NHX5VO5YUCkhowN4Z_g%40mail.gmail.com.

--00000000000026353905a6d5859a
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank you very=C2=A0much for updated patches Walleij.<div>=
<br></div><div>I took all the patches-V9=C2=A0 =C2=A0plus one=C2=A0@=C2=A0<=
a href=3D"https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-=
linus.walleij@linaro.org/" rel=3D"noreferrer" target=3D"_blank">https://lor=
e.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.=
org/</a></div><div><br></div><div><br></div><div>and I=C2=A0 hit below=C2=
=A0 BUG ,</div><div><br></div><div>void notrace cpu_init(void)<br>{<br>#ifn=
def CONFIG_CPU_V7M<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 unsigned int cpu =3D smp_=
processor_id();<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 struct stack *stk =3D &amp;s=
tacks[cpu];<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (cpu &gt;=3D NR_CPUS) {<b=
r>=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_crit(&quot;CPU=
%u: bad primary CPU number\n&quot;, cpu);<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 BUG();<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br></di=
v><div><br></div><div><br></div><div><br></div><div>Thanks,</div><div>Venka=
t Sana.</div><div><br></div></div><br><div class=3D"gmail_quote"><div dir=
=3D"ltr" class=3D"gmail_attr">On Fri, May 29, 2020 at 3:41 PM Linus Walleij=
 &lt;<a href=3D"mailto:linus.walleij@linaro.org">linus.walleij@linaro.org</=
a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0p=
x 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">Hi=
 Raju, Dmitry,<br>
<br>
On Fri, May 29, 2020 at 9:59 PM Dmitry Vyukov &lt;<a href=3D"mailto:dvyukov=
@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wrote:<br>
&gt; On Fri, May 29, 2020 at 5:39 PM Raju Sana &lt;<a href=3D"mailto:venkat=
.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; wrot=
e:<br>
&gt; &gt;<br>
&gt; &gt; Hello All,<br>
&gt; &gt;<br>
&gt; &gt; I started=C2=A0 =C2=A0porting <a href=3D"https://github.com/torva=
lds/linux/compare/master...ffainelli:kasan-v7?expand=3D1" rel=3D"noreferrer=
" target=3D"_blank">https://github.com/torvalds/linux/compare/master...ffai=
nelli:kasan-v7?expand=3D1</a><br>
&gt; &gt;<br>
&gt; &gt; to one out target , compilation seems fine but=C2=A0 target is no=
t booting ,<br>
&gt; &gt;<br>
&gt; &gt; Any help can be greatly appreciated<br>
&gt; &gt;<br>
&gt; &gt; Thanks,<br>
&gt; &gt; Venkat Sana<br>
&gt;<br>
&gt; Hi Venkat,<br>
&gt;<br>
&gt; +Linus, Abbott who implemented KASAN for ARM (if I am not mistaken).<b=
r>
&gt;<br>
&gt; However, you need to provide more details. There is not much<br>
&gt; information to act on.<br>
<br>
Different parts were written by different people over time,<br>
Andrey, Abbot and Florian, and some by myself as well.<br>
<br>
I am trying to finish the job and it is starting to look good :)<br>
<br>
I need to rebase it for v5.7 but then it should be in mergeable<br>
state.<br>
<br>
Please try the latest v9 patch set:<br>
<a href=3D"https://lore.kernel.org/linux-arm-kernel/20200515114028.135674-1=
-linus.walleij@linaro.org/" rel=3D"noreferrer" target=3D"_blank">https://lo=
re.kernel.org/linux-arm-kernel/20200515114028.135674-1-linus.walleij@linaro=
.org/</a><br>
<br>
You also need this patch:<br>
<a href=3D"https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1=
-linus.walleij@linaro.org/" rel=3D"noreferrer" target=3D"_blank">https://lo=
re.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro=
.org/</a><br>
<br>
You have it all in a branch in my git here:<br>
<a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/linusw/linux-int=
egrator.git/log/?h=3Dkasan" rel=3D"noreferrer" target=3D"_blank">https://gi=
t.kernel.org/pub/scm/linux/kernel/git/linusw/linux-integrator.git/log/?h=3D=
kasan</a><br>
<br>
Yours,<br>
Linus Walleij<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkanvC%2BRU0DjiCz%3D4e%2BZhy%2BmEux-NHX5VO5YUCkh=
owN4Z_g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://gr=
oups.google.com/d/msgid/kasan-dev/CA%2BdZkanvC%2BRU0DjiCz%3D4e%2BZhy%2BmEux=
-NHX5VO5YUCkhowN4Z_g%40mail.gmail.com</a>.<br />

--00000000000026353905a6d5859a--
