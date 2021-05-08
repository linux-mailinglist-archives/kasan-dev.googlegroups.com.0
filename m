Return-Path: <kasan-dev+bncBCH2LVN35IARB36B3OCAMGQEXI3C3UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 42DCC3773C1
	for <lists+kasan-dev@lfdr.de>; Sat,  8 May 2021 21:05:21 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id x6-20020acae0060000b02901e5030d8682sf6669664oig.19
        for <lists+kasan-dev@lfdr.de>; Sat, 08 May 2021 12:05:21 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q8ayO5nKG9QmXGmYeoojG+1j0fuuGpIACD6TPWedLI4=;
        b=UMGytf9lhP36AQ80r923r3nGWu/vZGIBEZ+odTSGrTCVFiVAikKexDXQNVv+jlCBbj
         RMiOiTGgkWOTarNKuUsWkykkWPKFbM7GCm3JkdOrHWVGBjRIxyiMwZwr3bYQXVZ89/IO
         G8pf62mgnNTlo6BCUDgldG1MWzUf5Ma3OwpWSpJ/T3HMHY43lW4sqmQ+wO1lMYaBB0/5
         zu+cQoUHfYC0C8R9cArn5I+qyriQA16KMMe/H7JnB+M3SP866doiAp/CrdKh7lr82UUT
         0Bo+QxhkgiJUubn5+c+16asQqQjW+ttQVJqGP7CRKW7ZW9s5YfndPBx8/c2eFmYSNkkc
         81nA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=chromium.org; s=google;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q8ayO5nKG9QmXGmYeoojG+1j0fuuGpIACD6TPWedLI4=;
        b=Qph8AI8SleJNT+KjBc8XN0wsJcyOJBpb9EfNe6NEE4DhqhxYVAHA2aVgS9lQU359bd
         R+ht/SHNrY2ay1a1rPJUQhkeKeRYiRzDiKVQn6prYiYGaWMXoc/mLhD1hHRHHqCHiJdU
         sxlh8c6t+6MaSnGlvLcdNby+d0FaVNw+M4NAQ=
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q8ayO5nKG9QmXGmYeoojG+1j0fuuGpIACD6TPWedLI4=;
        b=f9+bRfymKK/cW6A498l21jwLZ2VCW58tJZzj/Z5HaOZfibJ8O2yw/FCAebGl/nNTzz
         7jzCU6kn6Lc8kheUMJzwZUFPrQsj/6glYTLUbO5UIwQd3FCtmry614mCuQ9RUnvJT02y
         +lfsJOTz9nRHEwrKi0M3OApTASYH+qg4ZGtVpdEIZ/stAWK8nw/unfoSa5t+UZ/QXwHw
         Q5SjI9rvVYLFSgUroEQpSOLSgKP2C/C4MJZXQOegJRvIBY0iC3MlBZkDZ+f5wOzjDfaf
         8w3sE/G0ciFJ1Lt9qVtYnS84MWNTr5DsU3YjTZQob3++BiqNFwdXnh7oOgw+wJRfyExZ
         Xg2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FcppKK/NAj/Uv/ILoI++kktVmm5bOrjz+K+Tm7QJcVXUudtWG
	Ki1G+yyHw0Zk4Vf3UEP/w8s=
X-Google-Smtp-Source: ABdhPJy19JK0o6/t4ToFSUB8FhdIcIwYfw9m0lcJWnMcoRsIWTKdJYwybmhnT4nxF7LfC+wThyUs5Q==
X-Received: by 2002:a9d:7b57:: with SMTP id f23mr13574425oto.150.1620500720025;
        Sat, 08 May 2021 12:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:103:: with SMTP id 3ls2120016otu.1.gmail; Sat, 08 May
 2021 12:05:19 -0700 (PDT)
X-Received: by 2002:a9d:2ae1:: with SMTP id e88mr13112885otb.265.1620500719531;
        Sat, 08 May 2021 12:05:19 -0700 (PDT)
Date: Sat, 8 May 2021 12:05:18 -0700 (PDT)
From: Venkatesh Srinivas <venkateshs@chromium.org>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <20640839-4e3d-4284-ae20-4cc7d45dd2acn@googlegroups.com>
In-Reply-To: <CACT4Y+Z-YdwcML7+JVOWNQ=38MqRzGkS47hKo4Qhqt6t7ZGHyQ@mail.gmail.com>
References: <0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n@googlegroups.com>
 <CACT4Y+ZHyat_KE+yQ5z7xpF+RfW39tbpYS6t=9A82dvbZcuuKQ@mail.gmail.com>
 <CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T+r4OQ@mail.gmail.com>
 <CACT4Y+Z-YdwcML7+JVOWNQ=38MqRzGkS47hKo4Qhqt6t7ZGHyQ@mail.gmail.com>
Subject: Re: Regarding using the KASAN for other OS Kernel testing other
 that LInux
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3704_364947294.1620500718951"
X-Original-Sender: venkateshs@chromium.org
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

------=_Part_3704_364947294.1620500718951
Content-Type: multipart/alternative; 
	boundary="----=_Part_3705_339947659.1620500718951"

------=_Part_3705_339947659.1620500718951
Content-Type: text/plain; charset="UTF-8"

On Monday, April 19, 2021 at 12:09:15 AM UTC-7 Dmitry Vyukov wrote:

> On Sat, Apr 17, 2021 at 10:27 PM Tareq Nazir <tar...@gmail.com> wrote: 
> > 
> > Dear Dmitry Vyukov, 
> > 
> > Thanks for the reply, 
> > 
> > I have few questions as listed below 
> > 
> > 1 ) I would like to know if there is any open source repo that has 
> adapted KASAN for running it on the BSDs or Fuchsia kernels. 
>
> There should be. BSDs and Fuchsia are open-source. I don't have links 
> ready. But it should be possible to find.
>

For Fuchsia --- 
https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/lib/instrumentation/asan/README.md 

HTH,
-- vs;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20640839-4e3d-4284-ae20-4cc7d45dd2acn%40googlegroups.com.

------=_Part_3705_339947659.1620500718951
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">On Monday=
, April 19, 2021 at 12:09:15 AM UTC-7 Dmitry Vyukov wrote:<br></div><blockq=
uote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px s=
olid rgb(204, 204, 204); padding-left: 1ex;">On Sat, Apr 17, 2021 at 10:27 =
PM Tareq Nazir &lt;<a href=3D"" data-email-masked=3D"" rel=3D"nofollow">tar=
...@gmail.com</a>&gt; wrote:
<br>&gt;
<br>&gt; Dear Dmitry Vyukov,
<br>&gt;
<br>&gt; Thanks for the reply,
<br>&gt;
<br>&gt; I have few questions as listed below
<br>&gt;
<br>&gt; 1 ) I would like to know if there is any open source repo that has=
 adapted KASAN for running it on the BSDs or Fuchsia kernels.
<br>
<br>There should be. BSDs and Fuchsia are open-source. I don't have links
<br>ready. But it should be possible to find.<br></blockquote><div><br></di=
v><div>For Fuchsia --- https://fuchsia.googlesource.com/fuchsia/+/refs/head=
s/main/zircon/kernel/lib/instrumentation/asan/README.md&nbsp;</div><div><br=
></div><div>HTH,</div><div>-- vs;</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/20640839-4e3d-4284-ae20-4cc7d45dd2acn%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/20640839-4e3d-4284-ae20-4cc7d45dd2acn%40googlegroups.com</a>.<b=
r />

------=_Part_3705_339947659.1620500718951--

------=_Part_3704_364947294.1620500718951--
