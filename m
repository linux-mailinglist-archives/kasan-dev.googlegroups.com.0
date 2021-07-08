Return-Path: <kasan-dev+bncBCS4LXWYTMCBBJOJTODQMGQEX2YQ5QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 26C563BF93F
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Jul 2021 13:42:30 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 39-20020a9d092a0000b02904b4e396a9a3sf233534otp.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jul 2021 04:42:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625744549; cv=pass;
        d=google.com; s=arc-20160816;
        b=VdGy5SHlJoCCw0i3Zk5XKzd3lAhdBz4ae0ygmJuNa8g02Q+8yr3VxAQhvChnyvTq8B
         /z9Gbeu3/GdlQYHmgbj361kDiV1R5JpKK0HbWclp6qUsrxUCo08jgviaZBrLC3qiJYGV
         5QSPtOoueC4bLiMwu61oXkOca8ZsEeSMqlAHTLekfhj+hnJK0aGUdLe9TDxNcMQXCDfz
         ZMpj+Z/mVxTHpZhLzFqUs4eJqojJNelxBN37Ent6WqvdJ5LI3/ipmitknz20XpIs0gub
         ceLbgyrLxtKHme/zuUHSYY7KD54uBHr0MqRrVQ/5VQPtYqTrHqU6zmZx7V5NuK1+R7fm
         HyFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=K1Uq60DFP5dQ68wWGmDnVXNuhC/utgAmVeG71+2gUws=;
        b=LfAHpzfwhSGb2jz4kLC1FOpQza7GEqkFXvrqpGlnd+UpW5JjV7JuLefaWjCZsYAhJ1
         FWV6JaFH57sGsD4gndw62sNA3mRIxZY5mxbCVtytvtLx8vmHYoJfn82TN1h+eLVKfOBf
         78haMQr6RPlhEy4KQqPHJPWCErFbC6H1rX1zGUUr13w4xoWY8Z5TXm5U9f5yj+NcwnCp
         8SACP0deyQUc2pA4J01hkkDaQVSRi0KcrUlC4oK1Qw83U816ifPg8DgTFJzFZaQge0wN
         iAEkXlDuyf1oxgy3x/5qhIwvFfnzYHjd7kZlMYAWhO/zzDCfxeQ+sfzB25HsFkqhxTUp
         Y9Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Ki1WXt5h;
       spf=pass (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=o451686892@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1Uq60DFP5dQ68wWGmDnVXNuhC/utgAmVeG71+2gUws=;
        b=QjrtknYjSCH7TDJPP2lf65H+DmliSyNRjpP7zYHWsjuharRksN/N31p7O/Okw/S1GS
         H38FyveZXG3M8LI5sGNpC0iTuNPLWIW9s0JFqDP/Aa85v7Vb2ZQYRJ6LhxNszHARENtD
         Y0drvFPM4eE04X8IrR3/litilbWt813lAoBKT9qUh52sxXT9vymGZ/4XDLsnv6Zs1hoK
         3Eeq2uXJqX1b7vQD2m0yNwc0UhJyw9+r6GqueJubB96M18FIzu0KEl6pyqBb4gZMZM9M
         lmSrQgefA/WEDciv+auMBhIgl4mChbe9FQNgzBtFayiyYR6VhFBu/AbaNI6hlzTGtk7F
         BNKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1Uq60DFP5dQ68wWGmDnVXNuhC/utgAmVeG71+2gUws=;
        b=fH9PpVfZk/HzBY8mSCQ+ptlPnBO2U474ZiEdkRJ0z1qb3EzdMLMxi+kwSnwB/zJ/sQ
         h8xQl7EuS9wbjVW4ZTXwYWQtDkYjouD4BnAQarCc4y2/1chfUvpN6hKdUK5evbCQDktJ
         FbNlBSleTDif8rnOsgshq9RxiJ7/RWu6IXPH9iwU9rgbiIQY0p7/lZJbPas+Gcd+n/GL
         iTrHtdLTdSINKcIA7OD/+BwVyCqSufQKggOTy45RYToezXIUUXM89PwiBUopmgTQo0hs
         gNfLBTxW76iQlxp7B8ICtyMoejn+Pz11e2O5AyxbqZ9AyP+SkKGZ43d4IQZPVxFZNzdK
         HN3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1Uq60DFP5dQ68wWGmDnVXNuhC/utgAmVeG71+2gUws=;
        b=W17QgT22bnCvl4xZGio4mNh2OIWUH4EdLoK1BAnhMLVV6MBIsdXRJP+yAWYlVrcxyT
         /G/yLUCCyyyokVUAJZ24oSuzgYSvnsQAS97u0qW8lA3cIxzDRZljn+Tjol4EQIoHulFi
         SBZxt04dU6lzCR0a81yIez2OQ9AlfduLAZMaVFhfjF4dix3i0V1ehSN0ON4V9wC4nfNM
         6V2027+nMSN7aWq2W6qSnGF1YH6cGDQNGeC8AJxvFmRx9tenbbzgOKsOkbCSomv2JphL
         smIDmF3KvedKt/4jv5NGtUCZvfmRSB9KjDIOu8j6ICLogbuX3W+vr9BElIKk+qsDmfJO
         eHzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FzpkzfOoucxGn5NTl+2asNn7qOsc2OuncWQDIRuRe1XcvBN8G
	816F9s3EHafKS4p3IeAB1Bg=
X-Google-Smtp-Source: ABdhPJx7MZU5IjOlwD6A13lrD5zRhiYO2YhlgmZYl1eO6dT5AYWGZN5R5025JVLaoZpjEtlaRlfBFg==
X-Received: by 2002:a4a:6941:: with SMTP id v1mr21889353oof.38.1625744549131;
        Thu, 08 Jul 2021 04:42:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c7d2:: with SMTP id x201ls833612oif.2.gmail; Thu, 08 Jul
 2021 04:42:28 -0700 (PDT)
X-Received: by 2002:aca:f491:: with SMTP id s139mr17069315oih.128.1625744548832;
        Thu, 08 Jul 2021 04:42:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625744548; cv=none;
        d=google.com; s=arc-20160816;
        b=PCiIhckmXPmia3dZkAfF/zduSmFY+bI4p8uqO77RK9AsSUlPfjTvdSqGnVSTo4RilO
         GHsfrBCufbsV+XJSTvihoAutIwK/uV4qK9g3b7jlClPT0m/h+rWwQeSf3iYj3wzoCxpp
         g/KgMMLEca1jM/Hl5GognBHdl9NkVRD1xEsP/9/g3ira/8GA9GdgRpi61VFcZtP8agu/
         trShcCOpBVxAd3Q+bBx/Z1ysNWVIHoGDSA20QBSZUeqOFXidxHWK80wu6zXI+9AfceoD
         8Evp+tCTZU2+0I3CwMbjsHGzh48J7KRgWt1GNG7WgUIR+V12X2ToUkfwuJ0b9NNikH6s
         oKAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wK9F6VwrIvSmhXH28Ks01EAfvoNEtdHptVsB1Jf6Ggg=;
        b=ZHZ9UnwUEsuGrsW5YeFHjW36tcHZM9xbUQDRwDiaAEO4D3lSQKbnAHCgUvqH6Ajjbs
         gUGWjTnDINvHXMZckYLeLupMNk/IupBUF61jSEn1QeaxarHfOylDrCgrVGbMRCGwLbuV
         7pVjH/SZiwF7EuNfyCDB/r2EcSJyWgP0OlQknALIpyEL7yIm/UherKGUi2T0k9buLc7H
         t6sJKeJ77GYaNw7+gsHy+l6rugUnOQgrB01GpWbfiFxnV/tFdiNRCYajL07O+8WESKli
         EDebeGr8ZhthB6fmd1EFwAmqknNPtG6wU4YKxa8zaVj/Hq3/PUEF441KZbkXt0DzGYLC
         4TWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Ki1WXt5h;
       spf=pass (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=o451686892@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id k24si151801otn.3.2021.07.08.04.42.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Jul 2021 04:42:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id c5so2607440qvu.11
        for <kasan-dev@googlegroups.com>; Thu, 08 Jul 2021 04:42:28 -0700 (PDT)
X-Received: by 2002:a0c:c249:: with SMTP id w9mr29554073qvh.32.1625744548163;
 Thu, 08 Jul 2021 04:42:28 -0700 (PDT)
MIME-Version: 1.0
References: <CAHk0HosPFmeuWoEfAgvTNhzNqqjQ7Hm5=QvmcX67mY5MV-ysNw@mail.gmail.com>
 <CANpmjNO4ib8v1w7xfVO8a_zTQn1qztiz9E15XLDhZ+aqCZd40w@mail.gmail.com>
In-Reply-To: <CANpmjNO4ib8v1w7xfVO8a_zTQn1qztiz9E15XLDhZ+aqCZd40w@mail.gmail.com>
From: Weizhao Ouyang <o451686892@gmail.com>
Date: Thu, 8 Jul 2021 19:42:16 +0800
Message-ID: <CAHk0HouF7gs4qkrkHsJ_juV9k-TN-1uDZr4fc2S8k5q6TBymxg@mail.gmail.com>
Subject: Re: is KFENCE enabled on ARM now
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="00000000000049f32f05c69b26c0"
X-Original-Sender: o451686892@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Ki1WXt5h;       spf=pass
 (google.com: domain of o451686892@gmail.com designates 2607:f8b0:4864:20::f2e
 as permitted sender) smtp.mailfrom=o451686892@gmail.com;       dmarc=pass
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

--00000000000049f32f05c69b26c0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

OK, thanks for the reply.

Marco Elver <elver@google.com> =E4=BA=8E2021=E5=B9=B47=E6=9C=888=E6=97=A5=
=E5=91=A8=E5=9B=9B =E4=B8=8B=E5=8D=886:48=E5=86=99=E9=81=93=EF=BC=9A

> Unfortunately, KFENCE is not on arm32 yet, and we're not aware of any
> ports.
>
> On Thu, 8 Jul 2021 at 11:57, Weizhao Ouyang <o451686892@gmail.com> wrote:
> >
> > Hi elver,
> >
> > Since arm64 introduced  KFENCE has been a time, and I has ported it to
> our ARM64 product for memory error detecting.
> > I wonder is there a ARM architecture implementation now or a RFC patch?
> I'm thirst for deploying it on an arm32 product.
> > Look forward to your reply.
> >
> > Thanks,
> > Weizhao Ouyang
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHk0HouF7gs4qkrkHsJ_juV9k-TN-1uDZr4fc2S8k5q6TBymxg%40mail.gmail.=
com.

--00000000000049f32f05c69b26c0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">OK, thanks for the reply.=C2=A0<br></div><br><div class=3D=
"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">Marco Elver &lt;<a href=
=3D"mailto:elver@google.com">elver@google.com</a>&gt; =E4=BA=8E2021=E5=B9=
=B47=E6=9C=888=E6=97=A5=E5=91=A8=E5=9B=9B =E4=B8=8B=E5=8D=886:48=E5=86=99=
=E9=81=93=EF=BC=9A<br></div><blockquote class=3D"gmail_quote" style=3D"marg=
in:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1e=
x">Unfortunately, KFENCE is not on arm32 yet, and we&#39;re not aware of an=
y ports.<br>
<br>
On Thu, 8 Jul 2021 at 11:57, Weizhao Ouyang &lt;<a href=3D"mailto:o45168689=
2@gmail.com" target=3D"_blank">o451686892@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hi elver,<br>
&gt;<br>
&gt; Since arm64 introduced=C2=A0 KFENCE has been a time, and I has ported =
it to our ARM64 product for memory error detecting.<br>
&gt; I wonder is there a ARM architecture implementation now or a RFC patch=
? I&#39;m thirst for deploying it on an arm32 product.<br>
&gt; Look forward to your reply.<br>
&gt;<br>
&gt; Thanks,<br>
&gt; Weizhao Ouyang<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHk0HouF7gs4qkrkHsJ_juV9k-TN-1uDZr4fc2S8k5q6TBymxg%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAHk0HouF7gs4qkrkHsJ_juV9k-TN-1uDZr4fc2S8k5q6TBymxg=
%40mail.gmail.com</a>.<br />

--00000000000049f32f05c69b26c0--
