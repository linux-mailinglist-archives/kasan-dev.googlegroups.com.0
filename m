Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7HB72IAMGQE4UWG65Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 85AE74CACCA
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 19:01:34 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id n5-20020a5e8c05000000b00640d0a712d3sf1730740ioj.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 10:01:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646244093; cv=pass;
        d=google.com; s=arc-20160816;
        b=07AOG17QfxLOGVlhQJCYRtgLh18+c2KxfzyQGjSZWVYVThPRDTfYFMdmEAy77zfteF
         3shPDI1I/X68lxseBpxmeUPEAO76bvXlugVdtdg8a/zS3pLR81VPhlY08xlP0ZUi0ZnH
         HcYDRVenye805x2XSQb7MyP5lmJsAjTdADx0TPRbzuCqI3HlFoCPofxO22SwLKsssaaF
         TosJ/M/aSnH/QbeSDMk/hYW+cXmroX4yTaPapQQovF/SqNSDFN7wKhA/wvgIqUDzYjIu
         YMFVOjScmC+NfhgVoFf9IHuWY2xsWjERhFhufTqeUU2AUr948hCN3so8s4YH/yrEjHT4
         4RGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Wk1Fq7U9QNdM1fR02NbaZrw3D0Y1fRW8FjHjPnXq+6w=;
        b=Pitn0mtvxVKRRzayBY6utyipOkzEHpbFMJVn4425J2GdpI/ca5d+Jyr3X3blOgBwlk
         lpLZTlgiuHJlSbZmSUDuYBthYY69Bvnyt12U/wJ00Juv43hv6nKFld2lJhmaIa39b5B8
         yaH4agwaCcE14V5XXhcU4B7zP/vp9FjDOXPswRLjsYLaguhlDI4B7xl/cvPX6MijDhxh
         UMkWA61sgpl2Ei3J9RENO3otwF2QT2/oOfPCGcKPyllYhd/b9ht13s89VdbRR4AfqQhP
         gFYImFnnzuGa+pE3u8JIm63fxjlyJk7L4CzQoRSM8RxfBCJuTnJdcL7OWCgF+gYXM888
         fvBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qeQfXJy7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wk1Fq7U9QNdM1fR02NbaZrw3D0Y1fRW8FjHjPnXq+6w=;
        b=ofdSEA/3Psek1yUVxhGY/8LnJVZ8XRjU8bpXIEi9xp4Jrr/zsL4U8hDpeJA/diNnmt
         a5h8uSRsEct8dCYHFlekWBw6p+vpKEJvvJlSKw3qfMBA0GC5VTSaAK8KShMkyiiucTlj
         oMyZJKBDS33KcPUjQDkvExuuvJLzuzrn3B22OAmVw1jiDsmOwOo2WB8lnAaHh/sUbo5b
         tQUvNvQ2CtJsULWUqJGGaxAOJM50GRn4suviqFP3crdQMbZlchymroIZsUqAdvjhq8sy
         bAUgr8Aq1HzZIZhzE8t42rpZ8zJbeNChArsq1fWLbPdCXR42Kb8RXufdzdLmKNltQhyX
         /FUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wk1Fq7U9QNdM1fR02NbaZrw3D0Y1fRW8FjHjPnXq+6w=;
        b=Vd0J+jRSePrnDxpXhVO6linq0iO/UVPPvXY9Abywe9mQl+XA7KuWQUG/iHZkl6Sroj
         4MG5Mr+uGFxE174uamberju2BMZCeHkcqg/UqV6if8a/f3R+1FmZdyDfk6R7g3f0bsSp
         s2BRi1gVV4KbgVhmu2uGp0QjUyJoDdGteBb3C2GtoySoKa29UxfSpIRv5EczQz+cHuUT
         IVAv+KTfCKXYJpGv6Lzt38PCivXJJC1qkSHftfnJ9GbTDh5X+jvEuEOvLkWaKj/Fi7il
         xeKdTPrPnUMVq1fefKs09M3SWpeV1RX46PAIHOBQtnKaMvzBEaMFrrlHL3UHP8okT3I6
         b4hg==
X-Gm-Message-State: AOAM5308vGVby+URiRIPZtWegYNZ94jOBTdjwd6pn7I/ypAxJS0yFh8/
	f3/wZCjbj2CV0l+UU+uC5Qg=
X-Google-Smtp-Source: ABdhPJzfk+XSsTvHuW9SF8e/eq5gvHT+Y9ohw+b/pee+mDk9rS04bZTEWHvCZS+NDUZha103PlPQAw==
X-Received: by 2002:a5d:9c4a:0:b0:641:346:5a91 with SMTP id 10-20020a5d9c4a000000b0064103465a91mr23571038iof.217.1646244092271;
        Wed, 02 Mar 2022 10:01:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:328b:b0:311:84fd:8b1b with SMTP id
 f11-20020a056638328b00b0031184fd8b1bls3878548jav.10.gmail; Wed, 02 Mar 2022
 10:01:31 -0800 (PST)
X-Received: by 2002:a02:70c4:0:b0:314:1fd1:f143 with SMTP id f187-20020a0270c4000000b003141fd1f143mr25053824jac.18.1646244091849;
        Wed, 02 Mar 2022 10:01:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646244091; cv=none;
        d=google.com; s=arc-20160816;
        b=stNFZC7I1sLv/rmAuuuYBYenoJ8gUBqMblALuESBpkgDmZ7KPQOO+I2i5gZP4MvxbR
         ogGxLZKxYZZTuVtrRprKCLKv6jTLDxRE5S42un4LwWb/fpFwGMQRMcQOA5L74E7VHbM6
         9SJcTSLkPIv/xFcJCrX5zY7+ctKmcJH0jOcYHqISQwMyOodZK6KDk0EuJtnhvMTj+p4f
         N9b9n17vR5Q2f9qe7Uw4F2pluNX9aQJPkEiAmybsyChtBAgK40iGJNJqVfO2aWqRFLGz
         59WPQp+FKEKFBsMj+CYdDRvzXiaFO0MDCG7SOFwY/dGREowowluUQmpEXtsbROM9pJ96
         rl9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DTAbyaMudt3l/9xVxDZL18/DnPat4piVpWiGhUaAS30=;
        b=B3COca3WKNF49BsrhMoJ5pFxvOCk7+nLHP1hXbiQgpGtToDAVcIXZIYwGpQwmiZWNP
         g8g6Wx+bHQj9HSQUgFi/6a5VszYvwsRqH8zvb26+5HI012Z+IEjvbDngu7NgP5l+hRu1
         IHooLM0iikRmH06T8HVC3KL+aat2i8GEQHbYgOv/CqavHIa6XP2fP0EfzjEuKCCSJdvM
         fZYplsjbcYE6ww5h6oxfolosgPLXY6WO4ReLOFpFo7X93gTv5sNuwjszTQhhYC/aa7GM
         U0wz7p55uqZJQFre5dGzWnlAuW/WIjYDLmlTpp5njswQ7reQbrs9SoXwVvbJHxHZtnHy
         N1kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qeQfXJy7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id l20-20020a05663814d400b00314383860f0si781569jak.4.2022.03.02.10.01.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 10:01:31 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id bc10so2379386qtb.5
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 10:01:31 -0800 (PST)
X-Received: by 2002:ac8:5e4b:0:b0:2dd:dc99:d22b with SMTP id
 i11-20020ac85e4b000000b002dddc99d22bmr24638827qtx.165.1646244091282; Wed, 02
 Mar 2022 10:01:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <7c066c5de26234ad2cebdd931adfe437f8a95d58.1646237226.git.andreyknvl@google.com>
In-Reply-To: <7c066c5de26234ad2cebdd931adfe437f8a95d58.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 19:00:54 +0100
Message-ID: <CAG_fn=VPfooGr_Z+BSnde4FTLWrK3MrJghxsM8g+4NDUaZNUGw@mail.gmail.com>
Subject: Re: [PATCH mm 10/22] kasan: move disable_trace_on_warning to start_report
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="00000000000046cff505d940120a"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qeQfXJy7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as
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

--00000000000046cff505d940120a
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:37 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> Move the disable_trace_on_warning() call, which enables the
> /proc/sys/kernel/traceoff_on_warning interface for KASAN bugs,
> to start_report(), so that it functions for all types of KASAN reports.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>


---

>  mm/kasan/report.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0b6c8a14f0ea..9286ff6ae1a7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -129,6 +129,8 @@ static DEFINE_SPINLOCK(report_lock);
>
>  static void start_report(unsigned long *flags, bool sync)
>  {
> +       /* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
> +       disable_trace_on_warning();
>         /* Update status of the currently running KASAN test. */
>         update_kunit_status(sync);
>         /* Make sure we don't end up in loop. */
> @@ -421,7 +423,6 @@ static void __kasan_report(unsigned long addr, size_t
> size, bool is_write,
>         void *untagged_addr;
>         unsigned long flags;
>
> -       disable_trace_on_warning();
>         start_report(&flags, true);
>
>         tagged_addr =3D (void *)addr;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/7c066c5de26234ad2cebdd931adfe=
437f8a95d58.1646237226.git.andreyknvl%40google.com
> .
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
kasan-dev/CAG_fn%3DVPfooGr_Z%2BBSnde4FTLWrK3MrJghxsM8g%2B4NDUaZNUGw%40mail.=
gmail.com.

--00000000000046cff505d940120a
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Wed, Mar 2, 2022 at 5:37 PM &lt;<a=
 href=3D"mailto:andrey.konovalov@linux.dev">andrey.konovalov@linux.dev</a>&=
gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0=
px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">From:=
 Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com" target=3D"_b=
lank">andreyknvl@google.com</a>&gt;<br>
<br>
Move the disable_trace_on_warning() call, which enables the<br>
/proc/sys/kernel/traceoff_on_warning interface for KASAN bugs,<br>
to start_report(), so that it functions for all types of KASAN reports.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com" targe=
t=3D"_blank">glider@google.com</a>&gt;</div><div><div class=3D"gmail-adm" s=
tyle=3D"margin:5px 0px"><div id=3D"gmail-q_150" class=3D"gmail-ajR gmail-h4=
" style=3D"background-color:rgb(232,234,237);border:none;clear:both;line-he=
ight:6px;outline:none;width:24px;color:rgb(80,0,80);font-size:11px;border-r=
adius:5.5px"><span style=3D"background-color:rgb(255,255,255);font-size:sma=
ll;color:rgb(34,34,34)"><br></span></div><div id=3D"gmail-q_150" class=3D"g=
mail-ajR gmail-h4" style=3D"background-color:rgb(232,234,237);border:none;c=
lear:both;line-height:6px;outline:none;width:24px;color:rgb(80,0,80);font-s=
ize:11px;border-radius:5.5px"><span style=3D"background-color:rgb(255,255,2=
55);font-size:small;color:rgb(34,34,34)">=C2=A0</span></div><div id=3D"gmai=
l-q_150" class=3D"gmail-ajR gmail-h4" style=3D"background-color:rgb(232,234=
,237);border:none;clear:both;line-height:6px;outline:none;width:24px;color:=
rgb(80,0,80);font-size:11px;border-radius:5.5px"><span style=3D"background-=
color:rgb(255,255,255);font-size:small;color:rgb(34,34,34)">---</span></div=
></div></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px =
0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">
=C2=A0mm/kasan/report.c | 3 ++-<br>
=C2=A01 file changed, 2 insertions(+), 1 deletion(-)<br>
<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index 0b6c8a14f0ea..9286ff6ae1a7 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -129,6 +129,8 @@ static DEFINE_SPINLOCK(report_lock);<br>
<br>
=C2=A0static void start_report(unsigned long *flags, bool sync)<br>
=C2=A0{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0/* Respect the /proc/sys/kernel/traceoff_on_war=
ning interface. */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0disable_trace_on_warning();<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 /* Update status of the currently running KASAN=
 test. */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 update_kunit_status(sync);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 /* Make sure we don&#39;t end up in loop. */<br=
>
@@ -421,7 +423,6 @@ static void __kasan_report(unsigned long addr, size_t s=
ize, bool is_write,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 void *untagged_addr;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 unsigned long flags;<br>
<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0disable_trace_on_warning();<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 start_report(&amp;flags, true);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 tagged_addr =3D (void *)addr;<br>
-- <br>
2.25.1<br>
<br>
-- <br>
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br>
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com" target=
=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/7c066c5de26234ad2cebdd931adfe437f8a95d58.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/7c066c5de26234ad2cebdd931adfe437f8a95d58.1=
646237226.git.andreyknvl%40google.com</a>.<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4ls=
chlicherweise erhalten haben sollten, leiten Sie diese bitte nicht an jeman=
d anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet=
 wurde. <br><br>=C2=A0 =C2=A0 =C2=A0<br><br>This e-mail is confidential. If=
 you received this communication by mistake, please don&#39;t forward it to=
 anyone else, please erase all copies and attachments, and please let me kn=
ow that it has gone to the wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DVPfooGr_Z%2BBSnde4FTLWrK3MrJghxsM8g%2B4NDUaZN=
UGw%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAG_fn%3DVPfooGr_Z%2BBSnde4FTLWrK3MrJghxsM8g%=
2B4NDUaZNUGw%40mail.gmail.com</a>.<br />

--00000000000046cff505d940120a--
