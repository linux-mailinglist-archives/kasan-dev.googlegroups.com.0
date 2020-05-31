Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAGXZX3AKGQEU2KAJTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E74CD1E9658
	for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 10:32:00 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id o1sf3188520wrm.17
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 01:32:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590913920; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5KctDxUqCUv9sVW7l+iaNXZj5dxrhOdcgDjIA8gswc98W2sEx8/r5QyZVppEohC2u
         3q0WJkiN0tZM8E6IUovOIEYSzKK9votR8UvDatdMssx2yYCmsM3wJL3Utn6lPRwNJDWy
         aef9e6Vxsbh8MN6VWTSb1HhqL3JZm7mJ/I7SEkYvDlWsniESlrvD3mIZikMnnZEOZhKw
         fOoqZuaBjT/E0ORzjHu2sULjzOSFU7dOUVw39QgSgedW7CcHED4bNfSHbflMDDg1Tew/
         +iAPdPavL511CVvBz5TQZdRhKoHNOui3FqyLD9I4ryypTXlUfUwwOyy3fEs2npujcuE+
         +OnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dGj8VKM+bxUID6rnVp+iydfxNtmkN/4aeXUHAScs4SE=;
        b=omM+HZ5eqjDNtqDIiTfi8+f3T8+gba3+Q4KeJpiXCQwMGkIdiepAaHciv5YCYFCcln
         TWx45l0FhLIpSF4vf1lWXB3SXevxy64I3wZo11doqBs3ObltX3793n+JanN2f/L5y8V6
         WXdBCJ4HSvxJssEs4esrpH2HN2hNQrUB2wTo8gMjiIx5YcmhgLgMhNcot4s26e16qTqF
         TyJWd4kAA4RPCoGfoqscPrygB2+NcTmP1Hhmk1rcoKyrOZQkYdU3ujn1eVqE1j4RYKI5
         FuEqjPSzmRRuEkhANrbQYAPGYqtHe6XTo++FXDwYwb6ZkUMXRHLs36Voc+CNlnsSeNIS
         R+Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V1Jok8Zb;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGj8VKM+bxUID6rnVp+iydfxNtmkN/4aeXUHAScs4SE=;
        b=YAr5JWqH56zh78hnTkN7jwl8P/jRJosGlK5ULlHB+Q01fKA6JL7xTeSk8Xz+Y2ZNSg
         q7qI9D66jIsIU/2GVyXXrUWGFsgF/QOfM7/PYmBeAFnYLxkbCTnz5YLIuCUZJ73ODJpS
         fDa83ro2Vq1TNm+mFyXQ8LTUGWUi41Q1SYvYuhYVGO5WSrwRNYZmBP6T8hsWtVvHVeiK
         tqbMzTRcNZihBKUczn7MbIGBShd9667ajFHV7nC4n6J+bq6XMA4uAArqk3GjCbu9ilIj
         agZXHutGzotJob4M4Hc5/iQYZnPi/xVSvK2L6OfPTJ4SuyX4YlnoxEAS+/Y04c6jI8Gh
         17NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dGj8VKM+bxUID6rnVp+iydfxNtmkN/4aeXUHAScs4SE=;
        b=Q8bPb6CUeVb/TScZRHv+ht6vFBTVi8/9wug5QddBGNXgXvDMJFfH1aTGQcZNuYzCfx
         rQDbkL5IrgArEmvjAGXhCcaEhWRHeC8Tr5bxCQzoRHEebIUHhkE/JKGsYtotHZeufEYZ
         UmCqNSyIIVCETfcvcU4cXgXMVW28322Yipv3zBF/wk9Dv37TKAhgqcAo6S9DXtYATZ8c
         +iXXj+drn6uXJ3ZalC+WkLG70/7r8tNRF1xs/sPcBq3KLTmN6iJA9rKDzlC+n2Cl+huv
         e2fL9wvUS5CZ6M2/+IpVB4zN2YhGAWJbRSjz0/MyvEBmp3RG/13V8wSHHS9xm3mRvuuk
         eijA==
X-Gm-Message-State: AOAM531qpgpXmjYUwmSlBzqMi5FQEht+NNs11K0m5quYWA8yB2QDzZdd
	NZgenA8FNm0tiDZB+Tq3/x4=
X-Google-Smtp-Source: ABdhPJyBll7gBJ85/Vimhoyzh8JjinQCcbeiHvjbIlPukRNXOWX1bKhCDSfLzHDEAxW5ZYGpZwr/Aw==
X-Received: by 2002:adf:f707:: with SMTP id r7mr17808389wrp.390.1590913920644;
        Sun, 31 May 2020 01:32:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5224:: with SMTP id i4ls13588833wra.0.gmail; Sun, 31 May
 2020 01:32:00 -0700 (PDT)
X-Received: by 2002:adf:b348:: with SMTP id k8mr18293228wrd.157.1590913920093;
        Sun, 31 May 2020 01:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590913920; cv=none;
        d=google.com; s=arc-20160816;
        b=dG8jgMFjHPvIVB19e6GKEXQ13Rwm5xfealsOSeC5LdRxJ865hgAEx7h4dbYL8wWk39
         MAbTgHB3nQiT4RDTqzb+33+DqBRxK39IvdxMdxqU1Zwg1Z7YxPHgh+npnLU4el4WI5qf
         RPU2kHaVFKvRHhAtS/6lZyWxWG0uPmxC0oMmGF+A2KV33ibq/G0wBirKtLRSefwC/i75
         DWjMxTYbnjyaNJpb87Xxl44441fSGnzZcBHUoG9lU67dR9kDYwqbLe/W3E+yj2fbOXMW
         /Q53tZhKCCdS5bZFw94zZD76YpEWd4cYWs4FIxiJVYMRTihyaN8tkwwQ2EJnvB4f7Qd8
         WaUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hCvLCPk56Vm5IImWYFFedyXWI8zos1z+BfOGpQvb/Js=;
        b=JaKI9C1Ze0E50qn8mZntnXpl9JPFFD3IRhsJ9MhxL/fKOShE/kgrxgZ1Ilp8PMU6mn
         ZFqTbMqXUdWIdkcen/GaPjXlNW5b232ooZzO7WhVb9y7nUAjWvb0perNv9EIuw26QKkf
         LJBE/NS6igTcJk5Hi0GQZztrGYGP1ggR0jDxq1SDTlczrUpMHRi0TR5R0i0hn+qH27Ck
         A4G/y04Xf+18yiJXY+gbhavZr+uVic4Ymr+KK578ePrXc6ctkpBi7GthSblJGpACbms5
         ui2XVLOwHPGF2ZI86HfGDcKEfALwAcGg4XWPTBH3TRGTiLH1ogCB6Nsye2RSayYq5R0r
         qDgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V1Jok8Zb;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id l4si81152wrc.0.2020.05.31.01.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 31 May 2020 01:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id n5so8358627wmd.0
        for <kasan-dev@googlegroups.com>; Sun, 31 May 2020 01:32:00 -0700 (PDT)
X-Received: by 2002:a1c:2082:: with SMTP id g124mr17191207wmg.21.1590913919220;
 Sun, 31 May 2020 01:31:59 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com> <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
In-Reply-To: <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 31 May 2020 10:31:46 +0200
Message-ID: <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>
Content-Type: multipart/alternative; boundary="00000000000006929605a6ed8355"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V1Jok8Zb;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
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

--00000000000006929605a6ed8355
Content-Type: text/plain; charset="UTF-8"

On Sat, May 30, 2020, 21:08 Raju Sana <venkat.rajuece@gmail.com> wrote:

> Thank you Walleij.
>
> Interestingly , if I turn off   KASAN configs,  the target is booting ..
>  Will check more and post details here if i find any clue.
>

This could be related to e.g. KASAN shadow overlapping with .text - check
if your section layout leaves place for the KASAN shadow memory.
You can also try disabling the instrumentation, leaving only KASAN runtime
part and see if that boots. If it doesn't, look closer at the
initialization routines.
If the kernel boots without instrumentation, wrap the compiler into a
script that strips away KASAN flags if the file name starts with [a-z].
This build should also boot, as it effectively disables instrumentation. If
it does, try narrowing down the set of files for which you disable the
instrumentation.

HTH,
Alex


> Thanks,
> Venkat Sana.
>
> On Sat, May 30, 2020 at 3:55 AM Linus Walleij <linus.walleij@linaro.org>
> wrote:
>
>> On Sat, May 30, 2020 at 5:54 AM Raju Sana <venkat.rajuece@gmail.com>
>> wrote:
>>
>> > I took all the patches-V9   plus one @
>> https://lore.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/
>> >
>> >
>> > and I  hit below  BUG ,
>> >
>> > void notrace cpu_init(void)
>> > {
>> > #ifndef CONFIG_CPU_V7M
>> >         unsigned int cpu = smp_processor_id();
>> >         struct stack *stk = &stacks[cpu];
>> >
>> >         if (cpu >= NR_CPUS) {
>> >                 pr_crit("CPU%u: bad primary CPU number\n", cpu);
>> >                 BUG();
>>
>> That's weird, I can't see why that would have anything to do with KASan.
>> Please see if you can figure it out!
>>
>> Yours,
>> Linus Walleij
>>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com
> <https://groups.google.com/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com?utm_medium=email&utm_source=footer>
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q%40mail.gmail.com.

--00000000000006929605a6ed8355
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr">On Sat, May 30, 2020, 21:08 Raju Sana &lt;<a href=3D"m=
ailto:venkat.rajuece@gmail.com">venkat.rajuece@gmail.com</a>&gt; wrote:<br>=
</div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-l=
eft:1px #ccc solid;padding-left:1ex"><div dir=3D"ltr"><div style=3D"padding=
:20px 0px 0px;font-size:0.875rem;font-family:Roboto,RobotoDraft,Helvetica,A=
rial,sans-serif">Thank you Walleij.<br><table cellpadding=3D"0" style=3D"bo=
rder-collapse:collapse;margin-top:0px;width:auto;font-size:0.875rem;letter-=
spacing:0.2px;display:block"><tbody style=3D"display:block"><tr style=3D"he=
ight:auto;display:flex"><td style=3D"white-space:nowrap;padding:0px;vertica=
l-align:top;width:1237.75px;line-height:20px;display:block;max-height:20px"=
><br></td></tr></tbody></table></div><div style=3D"font-family:Roboto,Robot=
oDraft,Helvetica,Arial,sans-serif;font-size:medium"><div id=3D"m_-149581390=
995811377gmail-:1ih" style=3D"font-size:0.875rem;direction:ltr;margin:8px 0=
px 0px;padding:0px"><div id=3D"m_-149581390995811377gmail-:1ce" style=3D"ov=
erflow:hidden;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-stretch:normal;font-size:small;line-height:1.5;font-family:Arial,Helveti=
ca,sans-serif"><div dir=3D"ltr"><div>Interestingly , if I turn off=C2=A0 =
=C2=A0KASAN configs,=C2=A0 the target is booting ..<br></div><div>=C2=A0Wil=
l check more and post details here if i find any clue.</div><div></div></di=
v></div></div></div></div></blockquote></div></div><div dir=3D"auto"><br></=
div><div dir=3D"auto">This could be related to e.g. KASAN shadow overlappin=
g with .text - check if your section layout leaves place for the KASAN shad=
ow memory.</div><div dir=3D"auto">You can also try disabling the instrument=
ation, leaving only KASAN runtime part and see if that boots. If it doesn&#=
39;t, look closer at the initialization routines.</div><div dir=3D"auto">If=
 the kernel boots without instrumentation, wrap the compiler into a script =
that strips away KASAN flags if the file name starts with [a-z]. This build=
 should also boot, as it effectively disables instrumentation. If it does, =
try narrowing down the set of files for which you disable the instrumentati=
on.</div><div dir=3D"auto"><br></div><div dir=3D"auto">HTH,</div><div dir=
=3D"auto">Alex</div><div dir=3D"auto"><br></div><div dir=3D"auto"><div clas=
s=3D"gmail_quote"><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .=
8ex;border-left:1px #ccc solid;padding-left:1ex"><div dir=3D"ltr"><div styl=
e=3D"font-family:Roboto,RobotoDraft,Helvetica,Arial,sans-serif;font-size:me=
dium"><div id=3D"m_-149581390995811377gmail-:1ih" style=3D"font-size:0.875r=
em;direction:ltr;margin:8px 0px 0px;padding:0px"><div id=3D"m_-149581390995=
811377gmail-:1ce" style=3D"overflow:hidden;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-stretch:normal;font-size:small;line-height:=
1.5;font-family:Arial,Helvetica,sans-serif"><div dir=3D"ltr"><div><br></div=
><div>Thanks,</div><div>Venkat Sana.</div></div></div></div></div></div><br=
><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Sat, M=
ay 30, 2020 at 3:55 AM Linus Walleij &lt;<a href=3D"mailto:linus.walleij@li=
naro.org" target=3D"_blank" rel=3D"noreferrer">linus.walleij@linaro.org</a>=
&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px =
0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">On S=
at, May 30, 2020 at 5:54 AM Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@=
gmail.com" target=3D"_blank" rel=3D"noreferrer">venkat.rajuece@gmail.com</a=
>&gt; wrote:<br>
<br>
&gt; I took all the patches-V9=C2=A0 =C2=A0plus one @ <a href=3D"https://lo=
re.kernel.org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro=
.org/" rel=3D"noreferrer noreferrer" target=3D"_blank">https://lore.kernel.=
org/linux-arm-kernel/20200515124808.213538-1-linus.walleij@linaro.org/</a><=
br>
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

-- <br>
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br>
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com" target=3D=
"_blank" rel=3D"noreferrer">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJ=
g%40mail.gmail.com?utm_medium=3Demail&amp;utm_source=3Dfooter" target=3D"_b=
lank" rel=3D"noreferrer">https://groups.google.com/d/msgid/kasan-dev/CA%2Bd=
Zka%3D1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg%40mail.gmail.com</a>.<br>
</blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DWM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DWM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0t=
Yg4Q%40mail.gmail.com</a>.<br />

--00000000000006929605a6ed8355--
