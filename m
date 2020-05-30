Return-Path: <kasan-dev+bncBCFLDU5RYAIRBHG6ZL3AKGQEKCSOEXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86E1D1E9342
	for <lists+kasan-dev@lfdr.de>; Sat, 30 May 2020 21:08:13 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id d16sf425196ljg.10
        for <lists+kasan-dev@lfdr.de>; Sat, 30 May 2020 12:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590865693; cv=pass;
        d=google.com; s=arc-20160816;
        b=e0shn36f2Su4SnoEWEmfMHO2x/G9aALeM4pnUf7GICHquLrZOA5CT2brYLpgXndWQ1
         AWveZ9y7gTHJD58qgTafi1G+7kLQDqNoh3/7sesIEZy5HAFkn141HeE9DwvjYUlIA2+I
         slSn2VYFVp/jmcK+o0j10cj2oyVohxSK6FJNzfoav4opauQGDtt2FGD+JAruIPDuNjce
         TgeSj0OXJLspHAGrn+FXm29O0TrsFiPttOrYFNygcuKFrnSWbVzDMn1XqkN6KLxJ5QBw
         zdw1+jjXIEfG/N8giXucaXEVYLELKBrV6AUggmgQ4vRM671PCRU6Hu3HOOMomyJyQV4l
         PSJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bPPzxCuiVKPyEKnsFagMQt+6+whYPCOitX0GjP41m4M=;
        b=AjDB/xrSKY+YEOp9MFUo1TNCT8VasV4n+uMoAyEzU0fT5MSHS2ydShLZy85iU3+IQ8
         SISuYIf//2WKNjYJ2hOgV87HIQle2sORv64041WhyYC9A9tZmafJy4uxYVjnOzY6wFjP
         JdEbqARt9JWtU4Gm27fO6lCGR5hCN/eOvN7c/8h6vPmRVEK0sbJOagCKi3oz4wsJNNLH
         D4Bowqoz93z6NuBOeESkTWtsBuR3pgsaSDU2c2BCucaInx0RBg9t2XZ8aXnhNzvYmSMQ
         28Cow980AeJqvnxv/K1xPgcXaOOGK16OMG3SG8IQAnXO5vW2sS44b8YvKFoOUYuP30LI
         AQjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MApZl3c6;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bPPzxCuiVKPyEKnsFagMQt+6+whYPCOitX0GjP41m4M=;
        b=UsC5+WQrdUqaxRp7sXSmdKpqnaRGpAiTKYspTuILH4ZNdMlhBFaxlZewegKrzi39Fv
         v0xXOMgqKEGTZZ9qNuL8Ton7MEMQWBFnXa0c22Ccfs4R+B9jKqzhHetu6B5l8XEK+L/F
         uPpaUGMwRT2M9Oc3WlliEAdV/3KBtdoO32x8gv7jWOlTT8eBsKnYsBDpyOab9Ufpi0pd
         hbvQ0JOHZlo0ZmYl06Xd6lj78npk0z5BeK1WW38mKRAGBE/7016qGwZ2G6nS2wv0l6s/
         yxq1fMy5ETC16Uf5D2/NF7rXcHzyN9HlPIbNyePh5MeR3UbfO4nZG8tb59GmtupgFhp4
         +bfg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bPPzxCuiVKPyEKnsFagMQt+6+whYPCOitX0GjP41m4M=;
        b=UnHRPIn4M4YsX6uxipYuHbvkCsjIcJxw4NAmKXQ7U1mR5TPnInZjD3fV/jfqy/Q4HS
         QfD+NqGETa4KDCMTiVC1vm1V6IxiFLyTgzJITXssF8QPckCZiiOnRKaEx7KP+yiHUJyo
         72aJxVyYymq2StfMQq1AT/6222LNlKltEKvpQKrdsB5dO6Utdv+cNCy51w/F0khTl8lH
         GfLN1G+/0L0R13Za8qMEeSzeIwreSk3prVrkIsAyXg4RGPb/G46UW9yfzX6Qmklx28wh
         AmIkHoqjPMebvw/NDACit5mbMxFD2fqdcA8G1ow6DvJj6MhzU88Z0cCU1QhHP42807S1
         UQZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bPPzxCuiVKPyEKnsFagMQt+6+whYPCOitX0GjP41m4M=;
        b=jVYam0XKSC7fjdJtjoKsH7vuR2UoO2P6t9ewGwqa84811wrZAn8moD4PKYnja2UjMe
         GztP8FEjpoRcpGNwCijbueBCKNeDMyBTt/H0butPDsqd1Y8UFl9KSuVvbRoIrT91hMwK
         M6iUKkp6aWAzZ7EVMbEBl6LKg7cvahij3dzJ1AisovRDS30VmMGZMxLzXpa6HV+F5UOf
         3rcF1lJu6eEkS0D95DEX9I2erKvuLS0AVqmdXjiPK+vC31vvUg1DMtNYMCKkqL3xZ/BY
         +yDMDNo2hnqfYJsYWGtZTBKQHWV5KoszUcNM7/ah1qSbytlvk75y/lV+ntX2y7Dz73Ai
         38LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310E+jrfHu82rE4yPsCO4fV+nL++biM8jVvjiSxgjSWCgSJm7Mc
	terDQR1oVt8S1795gdszAT0=
X-Google-Smtp-Source: ABdhPJzFWHxm0E2KNvp3HH8M3KMh/wDZ0VfPtcZMjdu/4i0x6LuIiyz3F9yVlUy7w26cIQAbcA9AiA==
X-Received: by 2002:a05:651c:547:: with SMTP id q7mr6429160ljp.437.1590865692846;
        Sat, 30 May 2020 12:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:860d:: with SMTP id a13ls992011lji.11.gmail; Sat, 30 May
 2020 12:08:12 -0700 (PDT)
X-Received: by 2002:a2e:9ed5:: with SMTP id h21mr7302119ljk.324.1590865692144;
        Sat, 30 May 2020 12:08:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590865692; cv=none;
        d=google.com; s=arc-20160816;
        b=NseaynwEK4XLTfbeiwUN5E9Po4Y1xJv5uZGSF1LzcwtC1XFJPTeA4xkDwz9jc1+DEg
         v9+RmQhV15wQWD2oG76u103rGudA3zzipt5kkhnezrhPbpL4ioDK277B1AAq0hiFzbQ0
         heNwHIQ7N8UoSs9//bUX+3hv9MFFluc0zZUXAGQs83fQoKzR682selKCg4mGwgF5F9BI
         4hWzQmPnt260aQljFZT/kP644Ygn39VRTaYBtJXisWD3WGTJ76QL2QT/451+gJJ1I0XG
         xLyUlsd4R8puFVLb5+GG0A2yp6YV9KkxsD+WoU4TXV4vXnVBTF0ZjnMbeEJfjYuVxFAB
         vgTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HpE7RoiJzC3XTgsa0LMnVr87+YVjdQlL3Wr+dB2kzQo=;
        b=SZ2YSDtCu7CgEpTmctBc60zeWXhaNMe8Pe/hOdR8Y4mezrYbS/Vv1vf99XTbRoJ1uk
         t3BDN20tdoJ7GbinLnrRM7oe3FfXbkBi69Jr5bdEpAs9PotgkVr/d5Mq2+yILBZito5z
         AjR6lPeFcCsiqV+Kh/Yi+KopTWBjyF43p8x8oh7sLFWcOboqeRiUqa485PJCp6NcwLkX
         N+TMCdKW4d2NpMan7J5o+0uItzvHu0E6ZP1PiRB+ygMNg2yYszbNDuu9CW56TYjOGa/H
         bo0IKyeth9dKoUeKajchZAyddKmXznmYlKwKoYcPgYo28SuKMHtP0FyCk/TOZrc4FU65
         +7ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MApZl3c6;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id e7si696255ljo.2.2020.05.30.12.08.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 May 2020 12:08:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id z6so3242094ljm.13
        for <kasan-dev@googlegroups.com>; Sat, 30 May 2020 12:08:12 -0700 (PDT)
X-Received: by 2002:a2e:a284:: with SMTP id k4mr2490366lja.234.1590865691873;
 Sat, 30 May 2020 12:08:11 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com> <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
In-Reply-To: <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Sat, 30 May 2020 12:08:00 -0700
Message-ID: <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="0000000000007317c405a6e2484d"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=MApZl3c6;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
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

--0000000000007317c405a6e2484d
Content-Type: text/plain; charset="UTF-8"

Thank you Walleij.

Interestingly , if I turn off   KASAN configs,  the target is booting ..
 Will check more and post details here if i find any clue.

Thanks,
Venkat Sana.

On Sat, May 30, 2020 at 3:55 AM Linus Walleij <linus.walleij@linaro.org>
wrote:

> On Sat, May 30, 2020 at 5:54 AM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
>
> > I took all the patches-V9   plus one @
> https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/
> >
> >
> > and I  hit below  BUG ,
> >
> > void notrace cpu_init(void)
> > {
> > #ifndef CONFIG_CPU_V7M
> >         unsigned int cpu = smp_processor_id();
> >         struct stack *stk = &stacks[cpu];
> >
> >         if (cpu >= NR_CPUS) {
> >                 pr_crit("CPU%u: bad primary CPU number\n", cpu);
> >                 BUG();
>
> That's weird, I can't see why that would have anything to do with KASan.
> Please see if you can figure it out!
>
> Yours,
> Linus Walleij
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com.

--0000000000007317c405a6e2484d
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div class=3D"gmail-gE gmail-iv gmail-gt" style=3D"padding=
:20px 0px 0px;font-size:0.875rem;font-family:Roboto,RobotoDraft,Helvetica,A=
rial,sans-serif">Thank you Walleij.<br class=3D"gmail-Apple-interchange-new=
line"><table cellpadding=3D"0" class=3D"gmail-cf gmail-gJ" style=3D"border-=
collapse:collapse;margin-top:0px;width:auto;font-size:0.875rem;letter-spaci=
ng:0.2px;display:block"><tbody style=3D"display:block"><tr class=3D"gmail-a=
cZ" style=3D"height:auto;display:flex"><td class=3D"gmail-gF gmail-gK" styl=
e=3D"white-space:nowrap;padding:0px;vertical-align:top;width:1237.75px;line=
-height:20px;display:block;max-height:20px"><br></td></tr></tbody></table><=
/div><div class=3D"gmail-" style=3D"font-family:Roboto,RobotoDraft,Helvetic=
a,Arial,sans-serif;font-size:medium"><div id=3D"gmail-:1ih" class=3D"gmail-=
ii gmail-gt gmail-adO" style=3D"font-size:0.875rem;direction:ltr;margin:8px=
 0px 0px;padding:0px"><div id=3D"gmail-:1ce" class=3D"gmail-a3s gmail-aXjCH=
" style=3D"overflow:hidden;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-stretch:normal;font-size:small;line-height:1.5;font-family:=
Arial,Helvetica,sans-serif"><div dir=3D"ltr"><div>Interestingly , if I turn=
 off=C2=A0 =C2=A0KASAN configs,=C2=A0 the target is booting ..<br></div><di=
v>=C2=A0Will check more and post details here if i find any clue.</div><div=
><br></div><div>Thanks,</div><div>Venkat Sana.</div></div></div></div></div=
></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr"=
>On Sat, May 30, 2020 at 3:55 AM Linus Walleij &lt;<a href=3D"mailto:linus.=
walleij@linaro.org">linus.walleij@linaro.org</a>&gt; wrote:<br></div><block=
quote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1=
px solid rgb(204,204,204);padding-left:1ex">On Sat, May 30, 2020 at 5:54 AM=
 Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@gmail.com" target=3D"_blank=
">venkat.rajuece@gmail.com</a>&gt; wrote:<br>
<br>
&gt; I took all the patches-V9=C2=A0 =C2=A0plus one @ <a href=3D"https://lo=
re.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro=
.org/" rel=3D"noreferrer" target=3D"_blank">https://lore.kernel.org/linux-a=
rm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/</a><br>
&gt;<br>
&gt;<br>
&gt; and I=C2=A0 hit below=C2=A0 BUG ,<br>
&gt;<br>
&gt; void notrace cpu_init(void)<br>
&gt; {<br>
&gt; #ifndef CONFIG_CPU_V7M<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0unsigned int cpu =3D smp_processor_id=
();<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0struct stack *stk =3D &amp;stacks[cpu=
];<br>
&gt;<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0if (cpu &gt;=3D NR_CPUS) {<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_crit(&=
quot;CPU%u: bad primary CPU number\n&quot;, cpu);<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0BUG();<br=
>
<br>
That&#39;s weird, I can&#39;t see why that would have anything to do with K=
ASan.<br>
Please see if you can figure it out!<br>
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
om/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJ=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwy=
xqnNOSJg%40mail.gmail.com</a>.<br />

--0000000000007317c405a6e2484d--
