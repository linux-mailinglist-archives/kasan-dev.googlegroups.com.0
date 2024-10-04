Return-Path: <kasan-dev+bncBDAOJ6534YNBB74U763QMGQERW5FTEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C540F9901B9
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 12:59:13 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5399065f64bsf1531308e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 03:59:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728039553; cv=pass;
        d=google.com; s=arc-20240605;
        b=KUfDUZHl/i1PwxRzhgOwZVuaoW6JTeNV4R0VKjuzyHA/ol4ekM7cRY0KiHHpCOBErk
         xv0mM9FqryAzo4ih88/FglZMwBXo+pL+jLgfz6y/KUUsnvyVs99UQetmmFersm534gwm
         ehbFGWI+03GKxvoCl1yk0WwRzAjnw2dks7S6C+5EN/Vb/W1OljmR04CNtyioLbpEgZ6i
         UPsg+dD3MLW0hpdliUBf1ECvAuo3RDnB2Zf6GKkaztJZUW8S3x3s6LwKdwJXADgDrPKR
         UEdb9aZJiT4XCbnIUQFjCulzDhRgMu9dLtWEyOkFYrNZtyMc3yqaeHcQ+Lbv1tNTM4aW
         Fc5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=8JhZvL/0qrKvjBUTqdg2OU5xNmKucC0lC6rhUuHa+YY=;
        fh=5fUw7fPpdsTa30bipyW1jVEDvbwV7Rlcy0gUnvoSs3k=;
        b=WzXBQD3ROnsipIUPf/kkCUaIuh8kS7ZHrEx88zlXOakHi8aY5F5mcLySO1lT5e96/O
         BFhT8t6+mVzlpekKQqQOZQrNpLCltK0ll5A1xcXkgqqz6pfK7WAilgA2q2mSMJZZCKsK
         xcnATU4EAWD2tx7C5aYZLb+e9SxFC4Q0Hy5T0GB7bVcvSNz+vxr/G8C2JkfvaUe8nT4u
         SqiQR+Hi53PnrQgk5bP7rRYNYnu62NlKibqUha07N4wFXdsKmrooNmjrh4UUkSumsgys
         FlDvtSdHU+V0xefcTEl/KP+MmJqSdVy1T3l+iWcwj3/+k5X6yOipzBcgpio7jPBzX7cO
         mbhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MCCNgbX0;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728039553; x=1728644353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8JhZvL/0qrKvjBUTqdg2OU5xNmKucC0lC6rhUuHa+YY=;
        b=wqKkVzy9kj8P9wlKG8CExICh5cptQfF46ovgM9MjzPcQgBEJv30TDGVyZ0JKMlH3QH
         EL0NEr+Ql+pFaZFTJaSWWBQo7Nuri0Uznl4p23xO+L03g/nZPaZt1VXRiTwypA//GryK
         9yoJIZ3rjsIR+jYtcXotr3j42L3PKExA8VyA2wtNdwQ4wQGgxDwj79e9jCX9NmjwC/Da
         y6Cbx67IxKe6AiuYLg4N9j5IOr/9wrc84cJ3tx9k3lVW97dhKZ2mZiMbyuDuCgAueaB2
         MG3f4Yj9lCEzzA1PpLwn+w4hY6D18kxVfHVQfvfF0bb1VhSbfCpvwvuOJJjIGI37FGGU
         Bd0g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728039553; x=1728644353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=8JhZvL/0qrKvjBUTqdg2OU5xNmKucC0lC6rhUuHa+YY=;
        b=NXIERnt6q6LXk1HmbI875maWC5AABO9XaurOQiB3FUaWhYTzpsEgbITDIajzP16vo+
         LJyRCLvwo9Way5bBfpj/xugqIgiXSqbh7f6vDEGfg8ddVXJWhR6XFaI5w7gDCMhVNLKY
         5uuqwy6wRc10OoFD7tksI7Fqjcewe65l55QwLFaW9YNZ/dm0NLGdaSPEu/7IaeTKT2YX
         8Ma4WQdx6hIW1tEBmOdQt3UvtOrLqys5e4CX93Aglb3LCZ1vV0WO7NDeXmQZduOaBaxd
         Zf4w+xqxV8+ShCpbxGaUGHWTfInzY1121Y/BJC4pvO/e1K7UckucsDC5HPspISxDkQqn
         b3Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728039553; x=1728644353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8JhZvL/0qrKvjBUTqdg2OU5xNmKucC0lC6rhUuHa+YY=;
        b=DbmCNGmRWxwOPngws697Y82317MLLUftG86R6QeBchoefsepYDXe4a4f4JxbdLQw+P
         5wyZ4kSOTlaiNOqNQaHP3KJ8ticMrB29BlgjXxQdOu/V61VQ3uBKdgLniKCs0Bq6CMjs
         VweRXLKQACLp/QIXV7IzWvnWWaTUgPaU0zoGNHjx/8NgYG92LAwWpVUvbPkgS8K4/GBU
         /4dA6jZAjGx6q2DTWFKB5ZS+9aRGRnY8uXSEh8mD0EXGvtvT8DFYQb7ycjv83M66dkvw
         NtTl86GyizyRqALJy50eHiGLMkayiqDQ4p3Wys4Uv4sYE8IK+4Ez4d3pTwIDuJJjDvRv
         qJkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOJ6NJ8cOGySVoXO0XRIVS1ZTKbuJYN7dWHcqjm3MrDrk6IxBrOKPdJlkIXRwliKRU3q3DAQ==@lfdr.de
X-Gm-Message-State: AOJu0YxC9nm0H+mXXenZ9xzwTxO5O1IupJtyKK4Vxdrdj/YurciJ1Epg
	JRvMMSouXaKcJMoro3bY4ZSxfPWfPgmrEuuooU/iTfhkWzTJLsvd
X-Google-Smtp-Source: AGHT+IFrphhBOW61FFEQ5gczOmCOyT2au7myhSXu8xygkuW6CGx0DKPauA/FBcU/UU7XEy7D3aURdA==
X-Received: by 2002:a05:6512:234d:b0:535:6cf6:92fc with SMTP id 2adb3069b0e04-539ab84a7damr1086523e87.8.1728039551947;
        Fri, 04 Oct 2024 03:59:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234b:b0:539:907d:1edb with SMTP id
 2adb3069b0e04-539a638c4d4ls178130e87.2.-pod-prod-01-eu; Fri, 04 Oct 2024
 03:59:10 -0700 (PDT)
X-Received: by 2002:a05:6512:398d:b0:539:8847:d7e9 with SMTP id 2adb3069b0e04-539ab8843c9mr1484961e87.35.1728039549878;
        Fri, 04 Oct 2024 03:59:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728039549; cv=none;
        d=google.com; s=arc-20240605;
        b=U3Lo1iW2YqbxIV4J6C/PtcdwrrKUonQUKGiAURS36A/vvNV204owJq4vOg6ZNHrLpG
         p/+PA/PXSFtGcVAPsgIgqN2FtUn3aqIwix3OoYtNtsfid+NLABysENnDh2LXmoZl70YA
         VKO5o1WLQA62eXTQJjTHryqM1PNDB5rSnrUWbq15yiQ0mEtJ9L7E6S2sgNPszZsaH4No
         Il29aWaudu50+ZxhB16gHJpl46Dq8z6mKV/tN+1NysGI0xLE1tObCn3vyeamskecia9c
         kxnO90YKhqiNnS5zIv+2Y3qpj1asX6cTzYhACPLEWFJlk2Dp/Qwzyjf75kV0/V7K+eV/
         uHuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/GtNbdnqto5NBRjVx9Glg1iL+9UCVZdLhxnnUDUgPk0=;
        fh=KkU+4XG+ZDNHyRtV457mPjd2XYtkFuAXsLVZ/xfI5Ps=;
        b=UbblbH5aJyX960AQoJjUOQSl9wnSxiVDaTZQMMqBTlfVC+E94M1UNs7tUrxH5seK9b
         o0YzLZloC8wwWP6FJ1D1NIRCXaYBu7HTr79ZUrRb5QMOEWzoeTrpeHFGz7B2agNhCQDS
         WVqX5UF+t4Wnaqvz/muwLwiq3AYi3cMKvsE2ud2ebZlyWStUXk7O5eUcFj3194vSYOJf
         ZS8YAMppcaSLH4xclJX2v1mCzT+7vS+5t3uyyI0Fhy2FInTicZI1kbenFgrtSUs9sHyO
         e5SRquNGN8ROtsiOjJ6WoGbj1AiLToSOlAbOMzRV85DFjBcerMMpMpuzCOPQfWtb9z+z
         haAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MCCNgbX0;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539a8297908si69290e87.11.2024.10.04.03.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2024 03:59:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-2fac49b17ebso16067771fa.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2024 03:59:09 -0700 (PDT)
X-Received: by 2002:a2e:4601:0:b0:2fa:d386:c8a4 with SMTP id
 38308e7fff4ca-2faf3c146demr10433981fa.12.1728039548935; Fri, 04 Oct 2024
 03:59:08 -0700 (PDT)
MIME-Version: 1.0
References: <b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn@googlegroups.com> <CAG_fn=UM_J6n2Rem5-kYY-Pd1FzMykVsod_heXMaw=S1o2TUSg@mail.gmail.com>
In-Reply-To: <CAG_fn=UM_J6n2Rem5-kYY-Pd1FzMykVsod_heXMaw=S1o2TUSg@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 4 Oct 2024 14:58:56 +0400
Message-ID: <CACzwLxiD-_DqfK0ykNpGp+cRPNXS1--p1uk-TBp7kZR7574NHw@mail.gmail.com>
Subject: Re: booting qemu with KMSAN is stuck
To: Alexander Potapenko <glider@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="00000000000078f1eb0623a48fd4"
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MCCNgbX0;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--00000000000078f1eb0623a48fd4
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Oct 4, 2024, 14:11 Alexander Potapenko <glider@google.com> wrote:

> On Thu, Oct 3, 2024 at 8:05=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gm=
ail.com>
> wrote:
> >
> > Hello,
> >
> > I need help with the Linux boot issue with KMSAN.
> > On x86_64 I've enabled KMSAN and KMSAN_KUNIT_TEST
> > to work with adding kmsan check in one of kernel function.
> >
> > Booting is stuck after this line:
> > "ATTENTION: KMSAN is a debugging tool! Do not use it on production
> machines!"
> >
> > I couldn't figure out the guidance myself browsing the internet
> > or looking for the documentation:
> > https://docs.kernel.org/dev-tools/kmsan.html
> >
> > Please suggest. Not sure if this is the right group to ask.
> >
> > Kernel config (linux-next, next-20241002 tag):
> > https://gist.github.com/novitoll/bdad35d2d1d29d708430194930b4497b
> Hm, interesting, I can't even build KMSAN with this config:
>
>   SORTTAB vmlinux
> incomplete ORC unwind tables in file: vmlinux
> Failed to sort kernel table
>
Hello,

I have compiled it with clang 11.

make CC=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-strip
OBJCOPY=3Dllvm-objcopy OBJDUMP=3Dllvm-objdump READELF=3Dllvm-readelf HOSTCC=
=3Dclang
HOSTCXX=3Dclang++ HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld ARCH=3Dx86_64

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxiD-_DqfK0ykNpGp%2BcRPNXS1--p1uk-TBp7kZR7574NHw%40mail.gmai=
l.com.

--00000000000078f1eb0623a48fd4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr">On Fri, Oct 4, 2024, 14:11 Alexander Potapenko &lt;<a =
href=3D"mailto:glider@google.com">glider@google.com</a>&gt; wrote:<br></div=
><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1=
px #ccc solid;padding-left:1ex">On Thu, Oct 3, 2024 at 8:05=E2=80=AFPM Saby=
rzhan Tasbolatov &lt;<a href=3D"mailto:snovitoll@gmail.com" target=3D"_blan=
k" rel=3D"noreferrer">snovitoll@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hello,<br>
&gt;<br>
&gt; I need help with the Linux boot issue with KMSAN.<br>
&gt; On x86_64 I&#39;ve enabled KMSAN and KMSAN_KUNIT_TEST<br>
&gt; to work with adding kmsan check in one of kernel function.<br>
&gt;<br>
&gt; Booting is stuck after this line:<br>
&gt; &quot;ATTENTION: KMSAN is a debugging tool! Do not use it on productio=
n machines!&quot;<br>
&gt;<br>
&gt; I couldn&#39;t figure out the guidance myself browsing the internet<br=
>
&gt; or looking for the documentation:<br>
&gt; <a href=3D"https://docs.kernel.org/dev-tools/kmsan.html" rel=3D"norefe=
rrer noreferrer" target=3D"_blank">https://docs.kernel.org/dev-tools/kmsan.=
html</a><br>
&gt;<br>
&gt; Please suggest. Not sure if this is the right group to ask.<br>
&gt;<br>
&gt; Kernel config (linux-next, next-20241002 tag):<br>
&gt; <a href=3D"https://gist.github.com/novitoll/bdad35d2d1d29d708430194930=
b4497b" rel=3D"noreferrer noreferrer" target=3D"_blank">https://gist.github=
.com/novitoll/bdad35d2d1d29d708430194930b4497b</a><br>
Hm, interesting, I can&#39;t even build KMSAN with this config:<br>
<br>
=C2=A0 SORTTAB vmlinux<br>
incomplete ORC unwind tables in file: vmlinux<br>
Failed to sort kernel table<br></blockquote></div></div><div dir=3D"auto">H=
ello,</div><div dir=3D"auto"><br></div><div dir=3D"auto">I have compiled it=
 with clang 11.</div><div dir=3D"auto"><br></div><div dir=3D"auto">make CC=
=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-strip   OBJCOPY=
=3Dllvm-objcopy OBJDUMP=3Dllvm-objdump READELF=3Dllvm-readelf   HOSTCC=3Dcl=
ang HOSTCXX=3Dclang++ HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld ARCH=3Dx86_64</div><=
div dir=3D"auto"><div class=3D"gmail_quote"><blockquote class=3D"gmail_quot=
e" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">
</blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACzwLxiD-_DqfK0ykNpGp%2BcRPNXS1--p1uk-TBp7kZR7574NHw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CACzwLxiD-_DqfK0ykNpGp%2BcRPNXS1--p1uk-TBp7kZR757=
4NHw%40mail.gmail.com</a>.<br />

--00000000000078f1eb0623a48fd4--
