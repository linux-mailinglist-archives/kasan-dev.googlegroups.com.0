Return-Path: <kasan-dev+bncBCFLDU5RYAIRBT5D433AKGQEHCJQMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EA471EEEC1
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 02:29:03 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id e14sf2806538ejt.16
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 17:29:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591316943; cv=pass;
        d=google.com; s=arc-20160816;
        b=MMqFcKQXOfVDZABm1PQsCtbgHYK6qAwLeX0GLjw2ekGw4B35xxoeRXgN6UrdxzG4Zb
         /3/vUERwIg4WQdcieC8jpKZxfIGPjjCGA9Km91PYq8SSl38W2xHcbC5V3qTPjZJ2aHmV
         3lnvFsPoYDYP6YZyCi4dho/S5cAbIkiButIYKYKKnux3y8PXko2Hn97Il34dUm667mAW
         lceFwuNkaJB4YR91D0wMXeZ7FjJfCToXHGvgCjknYVC0aqTBq437NX1mL+6ENhdKTrHi
         EyaNTxnNOqGdeAbmBr8QCM2EtLb8KEpPuUALomkGOT50AUJ0PFio9hikIfnTcMpj3Etf
         CYlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Nu1hR63MaV9CvoMcJ/gXSkN+1fhxzUwABee+Brfvb6I=;
        b=bvAbzYuJ1f9b1rnYLjClueqYN9D6Rqqvf8y19d/TDxsGnkl1U6yiZ3F6bhZ2fZfuBZ
         q6x77GRR935qzEXKHs6v4jqRoJxmiaqSq+aWT914bbpLONNjiZsenb8jCVIzI5ixylNO
         V9IO2NuAyWX5WzOTT8E6sGOSyz/rG65ZAIxqDjjthTSsvRUv9QnXdJNAjlE1IUJ63F9/
         BOKsIWQj2WgE16LPAw9OKB/8mJKq4QbU7Ca/ryZtH5hl86xSzXBjKxMEEravnzFc0kjD
         t1xRcL0w9/F/HE8M/DWzCHjdWj4tCQNsEr9ANWCu6IhGkQAEjpXc8CR4F0mx+XwC9OlS
         Aiaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pyaquprT;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nu1hR63MaV9CvoMcJ/gXSkN+1fhxzUwABee+Brfvb6I=;
        b=HexR4gQVnQmxpBmfmcRYT1IRFhropt2y8Emx7Az2q0V0cvWVD2Gx5rBEy7H8IipRDs
         VGujT8zFXXeg1+WuNK4kqq4wDQ7VWlwv4EIi+paPGK+hcIPbi74zdFTyAO9XbiMFYDnB
         znQsQH8oH183YwT+lVbihiwpS+d9PP4TMHe886Bj+SsxvpDUxp37jhGyOJ5wIMgW7Uio
         w8VUDALyAC2q9Y7iQaigoguGsumULVyxg1iBgpFhu3NKyuhdv8pZE+rL/PcwiSYdccP+
         BamJzhcsqs4Pj+sR4DEZFJU1qxJhC5sTIjjZG9tZzLwu5UBxE5MUkqpHWsmQ0An7jsP8
         SYOg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nu1hR63MaV9CvoMcJ/gXSkN+1fhxzUwABee+Brfvb6I=;
        b=dZ/xx+yDC+FcAXvJkS+VHJBV2/pOR2bsGKeZJx5kgQGzXrH13sYSD2/pxG1RuOaW+V
         hvilzp4ah1cGN5hrO3dpzAw35NbrfTWFzJJr5ohYqKyX1IS8QeIzV0kufspHE9gelH/2
         3XQo5wUiKA2JsCmvCQTdbm+D2vvF6z+dgRA8NmmWtD0BiBGAxlLbOGDtNxg5vYJy5bwA
         2hWKE2e7305/dxAwoprDkCSoxLFI3p05jpR3cLJNVJy6C2kMGpk5dSeUDrIHp6y9iKrW
         C0n1E42Cxp6m7DNy2IxupCcECQdqxZfDOEjvQijkuR7f37jKmh3qseFxG7tIm+6A4lVS
         QNog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nu1hR63MaV9CvoMcJ/gXSkN+1fhxzUwABee+Brfvb6I=;
        b=BS5wDsvHbdV+NSmZ8dP9WSK38RVwDaI7FRsJ7NP1hu4Z2X831gjD7fdUuuUxB1ahPm
         3IJobYTkIB2j7wR9mDhIcpB5432PzoVFTHkSw13OMhJHTlnraLuVeTECPZz9HurS0ZyE
         qQel6tvbmw0+Eri+PgEjgS/5n6MMzq1KW3aUttTn6dPwwmFqr8CqzOZoGINsJu1FUV5S
         ZoQ3SMeQoP+M+BlLuYvAy6myyh76LKI3+PiX8r7cHRrymrvvSgrR+YZCu7bPc8DyA18u
         LhauzSFKigI3Dj+N1f2SJK/72Lk4mbQ92ThBSnp+StqOld3pjBSJ3JC6I/ENKZWvGbi7
         hHFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327NZx0T5G3Fsl75RO/poJwRI8Uq3o5JTFO76vVcH3NavL7Yet6
	PA5GJj2Lgtpway4DySXq960=
X-Google-Smtp-Source: ABdhPJwI01uIEzxHigpstnp4n9dRjof5JbN09fOg7KUwQURkS+sSWFMfLYtCOH3QfrAWSP9RphLD7Q==
X-Received: by 2002:a17:906:7c58:: with SMTP id g24mr6524083ejp.205.1591316943373;
        Thu, 04 Jun 2020 17:29:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7fc1:: with SMTP id r1ls3229764ejs.1.gmail; Thu, 04
 Jun 2020 17:29:02 -0700 (PDT)
X-Received: by 2002:a17:906:fa03:: with SMTP id lo3mr6394996ejb.196.1591316942784;
        Thu, 04 Jun 2020 17:29:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591316942; cv=none;
        d=google.com; s=arc-20160816;
        b=kfcevzxZCtmNjcBxio0os4HRwVqk2kb+JzVSSjksw/wUeQXQra4HwHn/aNAICvW7Gk
         jz3TqpTYGLCD1+qjgrcGjkt/cBCbIQukWg9+zEIjbrLlxn5giHLLBMtZnVxtAI/PSa8h
         RD9f73M8QPGbFssKDehmjV/5w57YxRk0HDvZS99PHJGemq2WLb1gpijkdg7S66ykRt45
         iVh2m8S/Q48oUqTNC9RF1NJ0BjphkZwMjwXomYQhZW1Rx6fe5PvHou276ltvUK3Ljezr
         V9fKPMB9iOGMw0D0xCCCs9cHZDflaz8006iCG1GFZ6oLGpxBH463Ae0wiNlOak5GogvW
         269w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ptc9ysnkoSwrJ705oNAxJM6LKqgC/ZvEwaN3D8G8uTk=;
        b=CP4+tMNCHYImKz46VEqiIbUrb4J0GUACP0DWnh2i5iSeG+pWmZwyVvorIxQA1VNIwM
         F74y7rl4s6S6ZPthQsaz+LPkXx0tD/AAnOP4t762MvvCukmiHxyBvr6rv9ze0PpLfqhy
         FH4WLswYKREwrtj/BBCXD4qT01e5HaRIwNovy0r+7sfkA7VPxxt5PcJreW49wulypg8j
         YSpXMcArykykRd71bjovHjI/A9YViWPbhndADrsFEEQeR3Z5L6ZRicSw+zZAj2nTZI2X
         QHscPQwwYuHXHU/9ApJJoCwMH3Mkz592LQRnxYP0pvzcAeSwGmErsfQx+29Q2B/XVJaP
         Qp6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pyaquprT;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id bt20si276489edb.2.2020.06.04.17.29.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 17:29:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id a9so6020233ljn.6
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 17:29:02 -0700 (PDT)
X-Received: by 2002:a05:651c:391:: with SMTP id e17mr3146351ljp.373.1591316942105;
 Thu, 04 Jun 2020 17:29:02 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
 <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
 <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
 <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com>
 <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com>
 <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com>
 <CA+dZkakFEJZLtfe7L2oN4w4O=T+x1L2WxZyKtSyofs8m3wLEzw@mail.gmail.com> <CAAeHK+xA6NaC0d36OtAhMgbA=sCvKHa1bN-a4zQZkzLh+EMGDQ@mail.gmail.com>
In-Reply-To: <CAAeHK+xA6NaC0d36OtAhMgbA=sCvKHa1bN-a4zQZkzLh+EMGDQ@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Thu, 4 Jun 2020 17:28:50 -0700
Message-ID: <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Daniel Axtens <dja@axtens.net>
Content-Type: multipart/alternative; boundary="0000000000000f344f05a74b59a5"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=pyaquprT;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
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

--0000000000000f344f05a74b59a5
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Thank you Andrey.

How do I access those patches ?

Thanks,
Venkat Sana.

On Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov <andreyknvl@google.com>
wrote:

> On Fri, Jun 5, 2020 at 2:14 AM Raju Sana <venkat.rajuece@gmail.com> wrote=
:
> >
> > Hello ALL,
> >
> > Thanks Alexander, I did attach to lauterbach  and debugging this now..
> to see where exactly failures..
> >
> > Initial Issue  behind memcpy failure is due to  FORTIFY  is enabled in
> my build, after turning off the FORTIFY  like below  , I was bale to gte
> pass memcpy issue.
> >
> > index 947f93037d87..64f0c81ac9a0 100644
> > --- a/arch/arm/include/asm/string.h
> > +++ b/arch/arm/include/asm/string.h
> > @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t v,
> __kernel_size_t n)
> >  #define memcpy(dst, src, len) __memcpy(dst, src, len)
> >  #define memmove(dst, src, len) __memmove(dst, src, len)
> >  #define memset(s, c, n) __memset(s, c, n)
> > +#ifndef __NO_FORTIFY
> > +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> > +#endif
> >  #endif
> >
> >
> > Is  KASAN expected to  work when  FORTIFY enabled  ?
>
> There's a series from Daniel related to KASAN + FORTIFY_SOURCE [1]
> btw, which might help you here.
>
> [1] https://lkml.org/lkml/2020/4/24/729
>
> >
> > After above change , I was  table to succeed with all  early init calls
> and also was able to dump the cmd_line args using lauterbach it was showi=
ng
> as accurate.
> >
> > Now I ran into  READ_ONCE and JUMP_LABEL issues  while running arch
> specific CPU hooks   ?  aAe these two related ? Appreciate any pointers
> here.
> >
> > Thanks
> > Venkat Sana.
> >
> >
> >
> >
> >
> >
> > BTW,  is this tested with FORTIFY
> >
> >
> > On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko <glider@google.com>
> wrote:
> >>
> >> On Mon, Jun 1, 2020 at 10:18 PM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> >> >
> >> > Thank you Walleij.
> >> >
> >> > I tried booting form 0x50000000,  but  hit the same issue.
> >> > I tried disabling instrumentation by passing KASAN_SANITIZE :=3Dn  @
> arch/arm/Makefile , but still no luck.
> >>
> >> This only disables instrumentation for files in arch/arm, which might
> >> be not enough.
> >> Try removing the -fsanitize=3Dkernel-address flag from
> scripts/Makefile.kasan
> >>
> >> > Thanks,
> >> > Venkat Sana.
> >> >
> >> > On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij <
> linus.walleij@linaro.org> wrote:
> >> >>
> >> >> On Mon, Jun 1, 2020 at 1:07 AM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> >> >>
> >> >>> And I am  loading image @ 0x44000000 in DDR and boot  using
> "bootm   0x44000000"
> >> >>
> >> >>
> >> >> Hm... can you try loading it at 0x50000000 and see what happens?
> >> >>
> >> >> We had issues with non-aligned physical base.
> >> >>
> >> >> Yours,
> >> >> Linus Walleij
> >> >
> >> > --
> >> > You received this message because you are subscribed to the Google
> Groups "kasan-dev" group.
> >> > To unsubscribe from this group and stop receiving emails from it,
> send an email to kasan-dev+unsubscribe@googlegroups.com.
> >> > To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrA=
iAaohZfke8aoyhcqvs_CYSuirA%40mail.gmail.com
> .
> >>
> >>
> >>
> >> --
> >> Alexander Potapenko
> >> Software Engineer
> >>
> >> Google Germany GmbH
> >> Erika-Mann-Stra=C3=9Fe, 33
> >> 80636 M=C3=BCnchen
> >>
> >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> >> Registergericht und -nummer: Hamburg, HRB 86891
> >> Sitz der Gesellschaft: Hamburg
> >
> > --
> > You received this message because you are subscribed to the Google
> Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send
> an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3=
DT%2Bx1L2WxZyKtSyofs8m3wLEzw%40mail.gmail.com
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BdZkakGP0O_H2x0z%2Bz_xojtDHR59jKqb1M97KvO7yjzxsC5%2Bg%40mail.=
gmail.com.

--0000000000000f344f05a74b59a5
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank you Andrey.<div><br></div><div>How do I access those=
 patches ?</div><div><br></div><div>Thanks,</div><div>Venkat Sana.</div></d=
iv><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On =
Thu, Jun 4, 2020 at 5:20 PM Andrey Konovalov &lt;<a href=3D"mailto:andreykn=
vl@google.com">andreyknvl@google.com</a>&gt; wrote:<br></div><blockquote cl=
ass=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid=
 rgb(204,204,204);padding-left:1ex">On Fri, Jun 5, 2020 at 2:14 AM Raju San=
a &lt;<a href=3D"mailto:venkat.rajuece@gmail.com" target=3D"_blank">venkat.=
rajuece@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hello ALL,<br>
&gt;<br>
&gt; Thanks Alexander, I did attach to lauterbach=C2=A0 and debugging this =
now.. to see where exactly failures..<br>
&gt;<br>
&gt; Initial Issue=C2=A0 behind memcpy failure is due to=C2=A0 FORTIFY=C2=
=A0 is enabled in my build, after turning off the FORTIFY=C2=A0 like below=
=C2=A0 , I was bale to gte pass memcpy issue.<br>
&gt;<br>
&gt; index 947f93037d87..64f0c81ac9a0 100644<br>
&gt; --- a/arch/arm/include/asm/string.h<br>
&gt; +++ b/arch/arm/include/asm/string.h<br>
&gt; @@ -58,6 +58,9 @@ static inline void *memset64(uint64_t *p, uint64_t v=
, __kernel_size_t n)<br>
&gt;=C2=A0 #define memcpy(dst, src, len) __memcpy(dst, src, len)<br>
&gt;=C2=A0 #define memmove(dst, src, len) __memmove(dst, src, len)<br>
&gt;=C2=A0 #define memset(s, c, n) __memset(s, c, n)<br>
&gt; +#ifndef __NO_FORTIFY<br>
&gt; +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */=
<br>
&gt; +#endif<br>
&gt;=C2=A0 #endif<br>
&gt;<br>
&gt;<br>
&gt; Is=C2=A0 KASAN expected to=C2=A0 work when=C2=A0 FORTIFY enabled=C2=A0=
 ?<br>
<br>
There&#39;s a series from Daniel related to KASAN + FORTIFY_SOURCE [1]<br>
btw, which might help you here.<br>
<br>
[1] <a href=3D"https://lkml.org/lkml/2020/4/24/729" rel=3D"noreferrer" targ=
et=3D"_blank">https://lkml.org/lkml/2020/4/24/729</a><br>
<br>
&gt;<br>
&gt; After above change , I was=C2=A0 table to succeed with all=C2=A0 early=
 init calls=C2=A0 and also was able to dump the cmd_line args using lauterb=
ach it was showing as accurate.<br>
&gt;<br>
&gt; Now I ran into=C2=A0 READ_ONCE and JUMP_LABEL issues=C2=A0 while runni=
ng arch specific CPU hooks=C2=A0 =C2=A0?=C2=A0 aAe these two related ? Appr=
eciate any pointers here.<br>
&gt;<br>
&gt; Thanks<br>
&gt; Venkat Sana.<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; BTW,=C2=A0 is this tested with FORTIFY<br>
&gt;<br>
&gt;<br>
&gt; On Tue, Jun 2, 2020 at 5:55 AM Alexander Potapenko &lt;<a href=3D"mail=
to:glider@google.com" target=3D"_blank">glider@google.com</a>&gt; wrote:<br=
>
&gt;&gt;<br>
&gt;&gt; On Mon, Jun 1, 2020 at 10:18 PM Raju Sana &lt;<a href=3D"mailto:ve=
nkat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; =
wrote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Thank you Walleij.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; I tried booting form 0x50000000,=C2=A0 but=C2=A0 hit the same=
 issue.<br>
&gt;&gt; &gt; I tried disabling instrumentation by passing KASAN_SANITIZE :=
=3Dn=C2=A0 @ arch/arm/Makefile , but still no luck.<br>
&gt;&gt;<br>
&gt;&gt; This only disables instrumentation for files in arch/arm, which mi=
ght<br>
&gt;&gt; be not enough.<br>
&gt;&gt; Try removing the -fsanitize=3Dkernel-address flag from scripts/Mak=
efile.kasan<br>
&gt;&gt;<br>
&gt;&gt; &gt; Thanks,<br>
&gt;&gt; &gt; Venkat Sana.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; On Mon, Jun 1, 2020 at 1:57 AM Linus Walleij &lt;<a href=3D"m=
ailto:linus.walleij@linaro.org" target=3D"_blank">linus.walleij@linaro.org<=
/a>&gt; wrote:<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; On Mon, Jun 1, 2020 at 1:07 AM Raju Sana &lt;<a href=3D"m=
ailto:venkat.rajuece@gmail.com" target=3D"_blank">venkat.rajuece@gmail.com<=
/a>&gt; wrote:<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt;&gt; And I am=C2=A0 loading image @ 0x44000000 in DDR and =
boot=C2=A0 using=C2=A0 &quot;bootm=C2=A0 =C2=A00x44000000&quot;<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Hm... can you try loading it at 0x50000000 and see what h=
appens?<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; We had issues with non-aligned physical base.<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Yours,<br>
&gt;&gt; &gt;&gt; Linus Walleij<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; --<br>
&gt;&gt; &gt; You received this message because you are subscribed to the G=
oogle Groups &quot;kasan-dev&quot; group.<br>
&gt;&gt; &gt; To unsubscribe from this group and stop receiving emails from=
 it, send an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroup=
s.com" target=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
&gt;&gt; &gt; To view this discussion on the web visit <a href=3D"https://g=
roups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZfke8a=
oyhcqvs_CYSuirA%40mail.gmail.com" rel=3D"noreferrer" target=3D"_blank">http=
s://groups.google.com/d/msgid/kasan-dev/CA%2BdZkann4Z1TavtJ%2Biq9oBrAiAaohZ=
fke8aoyhcqvs_CYSuirA%40mail.gmail.com</a>.<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; --<br>
&gt;&gt; Alexander Potapenko<br>
&gt;&gt; Software Engineer<br>
&gt;&gt;<br>
&gt;&gt; Google Germany GmbH<br>
&gt;&gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; 80636 M=C3=BCnchen<br>
&gt;&gt;<br>
&gt;&gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado<br>
&gt;&gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt;&gt; Sitz der Gesellschaft: Hamburg<br>
&gt;<br>
&gt; --<br>
&gt; You received this message because you are subscribed to the Google Gro=
ups &quot;kasan-dev&quot; group.<br>
&gt; To unsubscribe from this group and stop receiving emails from it, send=
 an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com" ta=
rget=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
&gt; To view this discussion on the web visit <a href=3D"https://groups.goo=
gle.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZyKtSyofs=
8m3wLEzw%40mail.gmail.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/CA%2BdZkakFEJZLtfe7L2oN4w4O%3DT%2Bx1L2WxZy=
KtSyofs8m3wLEzw%40mail.gmail.com</a>.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkakGP0O_H2x0z%2Bz_xojtDHR59jKqb1M97KvO7yjzxsC5%=
2Bg%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CA%2BdZkakGP0O_H2x0z%2Bz_xojtDHR59jKqb1M97KvO=
7yjzxsC5%2Bg%40mail.gmail.com</a>.<br />

--0000000000000f344f05a74b59a5--
