Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPPA72IAMGQEQZF6PJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AAB14CACB1
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:58:22 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 7-20020a4a0007000000b0031d5b7742c6sf1714634ooh.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:58:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646243901; cv=pass;
        d=google.com; s=arc-20160816;
        b=FnVnNjhj+u6w+XUHuHsyj6lK0XSDS5mNbuB4Swxs0gXQwz308het5U8qqi5zdu8Ahd
         qq6nguYz1QDgstKEdeU/GpmbfUUj1jed5XG4eHrVQMdnmigNWGl8RkL5Rrja8h+gOsp0
         HZFgp5gSCDNT8AJkfKgDKakEtMeK5GKhKGAgIRIQWvQUCcbPwuBjd8M4Sz6vCV/fw1jD
         FUNdKiXP60buZcV646f2geedgZN0c0TcusAVZTB37zkm10qPmTFA/W6jv1TyFiQMWst3
         Qj3byTWUnM5gSq396gUIqfnBEmjnI550YM5bHzEPvDCEd4N8sViCa5kxrNJyeneLC67v
         LaNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uOlw0fKidfSf+X7HCdUqZiU5QZd7cluGU8slHGE44nY=;
        b=O9SUFtKoHUq9BmFx6AxiDLl+ugAIZyNGVEPOUUWqrVVbEcEpwc5jL+Hwj+r8+if8i5
         GzPy1Innzz+CkmBV7xHUzmxon6eOProaeZ7Qv9KW1nu59M0ywHfbR/15DMcumId7mPDe
         KEbfApevq+sPZnhzV2s2SA3NBFwZ5tLGAchhCHW80oLNG3pBoMlNVMF/VrMAz+7Xrre1
         NRixAR0Or+VfZ/DgoR8jwGAm55QyL0uM2lHEq9oyJ4ctXJclP15Cr1NorMrXg9p7Mlw/
         4rwlNlFF5rvLh/IDuHqwDN5nKz/F+Opx9X8dCDB3kLj2f5nVZXNeID1uyrr3svj3piM7
         jmVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o1rvRlbI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uOlw0fKidfSf+X7HCdUqZiU5QZd7cluGU8slHGE44nY=;
        b=TAO5sWFWbS8ek8tlsVKkTwdTRdnXoDlSdPTyUO0d6rAJz0t1VurRN7oTTz7zd0F6u7
         wTfAT0K7QJqKzGrreKk7Ah7OoP9l71die0v+KPHEDcoari8jajX7RuRCKS4Q0S3/mPRv
         cy1K3SYLR2aDDn/fd7ACbA5dtQQ7hCoR/yG/geojky1YDTYcCspqbHpp+m/PXeeQ+07S
         ix46PQfHP5vzWfL0pZA5w2v7qT8Z8X2GKQFpGzNJZbYQKHIPcYPZQWmWpFr7z1375Hr/
         asAtw9ETAA6yXMLfG1/UkZHkBbe0c9lC03D6wA9HtorAgEEfSbOZWitFAPEtnqNtPSWD
         tCCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uOlw0fKidfSf+X7HCdUqZiU5QZd7cluGU8slHGE44nY=;
        b=1mBdqqObUrHAkviV7Q1khZPFjdWj1apDzZIQvv516PMhHw+85ADv2ez1iWnsaDeso8
         NbbZ8ogFHNweb9Ie5OT5DahrLeeofUlR0m/aYDoU21r+1tBFJ8VyeIi58y2KouLwuQHX
         gUsTGj+Sc5DBZADYgXAQRd9bPKuzk3xcb3C0iuBpxf8opLHRd6vWV40j/4rKPPn9XLwe
         WFc/J6D7wgDjw+ICwjcm9htdId4VWmLCVCg6HB0XbOh9RHWzSTYIaoXaB9NU3jI+31Wc
         Ac9ijUPQ7nuopg/COo7OtUeLmQhSwRgDhCO6W/DDKf8jgdvkpmYios7Py9/hJWa6Q8ZG
         xyEQ==
X-Gm-Message-State: AOAM532dIzVGnMtPzJDBKWS2+GSGiAQ0WXtNhgkoLPETcgMfhoFkKj2v
	GR7PlQlnfo5qO3tRSrJOC6o=
X-Google-Smtp-Source: ABdhPJyyYuS7hZyytZ012OH4BJbIoTAQ280yQ3qHRmlkZwoTivPM9f26t83Z13cyzUuC7r5U2EaCYQ==
X-Received: by 2002:a4a:4f88:0:b0:319:244f:4b03 with SMTP id c130-20020a4a4f88000000b00319244f4b03mr16064429oob.77.1646243901294;
        Wed, 02 Mar 2022 09:58:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:60a0:b0:d3:7b7b:e67 with SMTP id
 t32-20020a05687060a000b000d37b7b0e67ls6258897oae.7.gmail; Wed, 02 Mar 2022
 09:58:21 -0800 (PST)
X-Received: by 2002:a05:6871:4086:b0:d7:1428:45b0 with SMTP id kz6-20020a056871408600b000d7142845b0mr829169oab.11.1646243900975;
        Wed, 02 Mar 2022 09:58:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646243900; cv=none;
        d=google.com; s=arc-20160816;
        b=tD8BmQDbpuyVXvhDYwTT8QnVE2ssM/nzhtR9QZlYkM+DYCrmitbi/ohIta42FP6/yv
         pijzPJG/RhqXFmPFRGWop/eN6GyP0C9DEgeD3LaCNaLuuvFebUe6w6W50jMnRzxnJcaD
         9uXnfRSUsLy2vGa9+YXxL5OgXbQJ7E8Pg/R1q8ey52hpbMEkosek8RNhQzEFdPcVHoN7
         ESguCA6xY1vY0kTfuX7qfb/v/FYdceIzFStjLXVOtGkvo0dS7I/133y5tzRdg/RLqt0i
         l4EmkkJ/nd1axzEC31Pj30rUvEgCKqXnalp1DgcRBXbyz6m0vlO1bdABN3RRTpqJHApr
         OC/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zvKlF5CBF/rkG5nSvJoUB04cPViOb4UlDQuxw1t5TK8=;
        b=XAIrB9tLWdLqKmstZVziB/DAGMq2GGN9V6Td2oz+b9SHvttQIH1nx4zItd7AeqcUQo
         xXE9zr2cuUK2Uu4yr/om/uc4fWJVy3n6OpKFubx4nKm/2xrmQOedy5qOubXSp2Pdkptt
         H6Afg3s255XAbEM4t3DO5se1JsnUHzUsaabiNfPCQePZpBrpVw/KmFyU3yLu++34K8aT
         udS/5UISPSd3lImJjNYvhHgJsfch8El3muftV6Ja5sbbpqB1oQXuqgvFdHztJsGaUHIs
         kEvcAcxOsSRAyNHjVHM44ZFBDQCp0GWl6/gLDxw5jng4vq2xEGmIQgbWKXty3cDYddKc
         qMBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o1rvRlbI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id c6-20020a056808138600b002d560aa6678si1974381oiw.0.2022.03.02.09.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:58:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id iv12so652313qvb.6
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:58:20 -0800 (PST)
X-Received: by 2002:ad4:5fcb:0:b0:432:d049:c6d with SMTP id
 jq11-20020ad45fcb000000b00432d0490c6dmr17606335qvb.39.1646243900457; Wed, 02
 Mar 2022 09:58:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <223592d38d2a601a160a3b2b3d5a9f9090350e62.1646237226.git.andreyknvl@google.com>
In-Reply-To: <223592d38d2a601a160a3b2b3d5a9f9090350e62.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:57:44 +0100
Message-ID: <CAG_fn=XGNbii2Q9Y6xUQHa2qw3nKOGV3gDaF39N6MC6+Q3yuUw@mail.gmail.com>
Subject: Re: [PATCH mm 08/22] kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="000000000000e6efbe05d9400642"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=o1rvRlbI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
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

--000000000000e6efbe05d9400642
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:37 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> Check the more specific CONFIG_KASAN_KUNIT_TEST config option when
> defining things related to KUnit-compatible KASAN tests instead of
> CONFIG_KUNIT.
>
> Also put the kunit_kasan_status definition next to the definitons of
> other KASAN-related structs.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>


> ---
>  mm/kasan/kasan.h  | 18 ++++++++----------
>  mm/kasan/report.c |  2 +-
>  2 files changed, 9 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 4447df0d7343..cc7162a9f304 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -7,16 +7,6 @@
>  #include <linux/kfence.h>
>  #include <linux/stackdepot.h>
>
> -#if IS_ENABLED(CONFIG_KUNIT)
> -
> -/* Used in KUnit-compatible KASAN tests. */
> -struct kunit_kasan_status {
> -       bool report_found;
> -       bool sync_fault;
> -};
> -
> -#endif
> -
>  #ifdef CONFIG_KASAN_HW_TAGS
>
>  #include <linux/static_key.h>
> @@ -224,6 +214,14 @@ struct kasan_free_meta {
>  #endif
>  };
>
> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> +/* Used in KUnit-compatible KASAN tests. */
> +struct kunit_kasan_status {
> +       bool report_found;
> +       bool sync_fault;
> +};
> +#endif
> +
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>                                                 const void *object);
>  #ifdef CONFIG_KASAN_GENERIC
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 59db81211b8a..93543157d3e1 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -356,7 +356,7 @@ static bool report_enabled(void)
>         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
>
> -#if IS_ENABLED(CONFIG_KUNIT)
> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>  static void update_kunit_status(bool sync)
>  {
>         struct kunit *test;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/223592d38d2a601a160a3b2b3d5a9=
f9090350e62.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DXGNbii2Q9Y6xUQHa2qw3nKOGV3gDaF39N6MC6%2BQ3yuUw%40mail.gm=
ail.com.

--000000000000e6efbe05d9400642
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
Check the more specific CONFIG_KASAN_KUNIT_TEST config option when<br>
defining things related to KUnit-compatible KASAN tests instead of<br>
CONFIG_KUNIT.<br>
<br>
Also put the kunit_kasan_status definition next to the definitons of<br>
other KASAN-related structs.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glide=
r@google.com</a>&gt;</div><div>=C2=A0</div><blockquote class=3D"gmail_quote=
" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);=
padding-left:1ex">
---<br>
=C2=A0mm/kasan/kasan.h=C2=A0 | 18 ++++++++----------<br>
=C2=A0mm/kasan/report.c |=C2=A0 2 +-<br>
=C2=A02 files changed, 9 insertions(+), 11 deletions(-)<br>
<br>
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h<br>
index 4447df0d7343..cc7162a9f304 100644<br>
--- a/mm/kasan/kasan.h<br>
+++ b/mm/kasan/kasan.h<br>
@@ -7,16 +7,6 @@<br>
=C2=A0#include &lt;linux/kfence.h&gt;<br>
=C2=A0#include &lt;linux/stackdepot.h&gt;<br>
<br>
-#if IS_ENABLED(CONFIG_KUNIT)<br>
-<br>
-/* Used in KUnit-compatible KASAN tests. */<br>
-struct kunit_kasan_status {<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0bool report_found;<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0bool sync_fault;<br>
-};<br>
-<br>
-#endif<br>
-<br>
=C2=A0#ifdef CONFIG_KASAN_HW_TAGS<br>
<br>
=C2=A0#include &lt;linux/static_key.h&gt;<br>
@@ -224,6 +214,14 @@ struct kasan_free_meta {<br>
=C2=A0#endif<br>
=C2=A0};<br>
<br>
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)<br>
+/* Used in KUnit-compatible KASAN tests. */<br>
+struct kunit_kasan_status {<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0bool report_found;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0bool sync_fault;<br>
+};<br>
+#endif<br>
+<br>
=C2=A0struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cach=
e,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 const void *object);<br>
=C2=A0#ifdef CONFIG_KASAN_GENERIC<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index 59db81211b8a..93543157d3e1 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -356,7 +356,7 @@ static bool report_enabled(void)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 return !test_and_set_bit(KASAN_BIT_REPORTED, &a=
mp;kasan_flags);<br>
=C2=A0}<br>
<br>
-#if IS_ENABLED(CONFIG_KUNIT)<br>
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)<br>
=C2=A0static void update_kunit_status(bool sync)<br>
=C2=A0{<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 struct kunit *test;<br>
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
om/d/msgid/kasan-dev/223592d38d2a601a160a3b2b3d5a9f9090350e62.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/223592d38d2a601a160a3b2b3d5a9f9090350e62.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DXGNbii2Q9Y6xUQHa2qw3nKOGV3gDaF39N6MC6%2BQ3yuU=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DXGNbii2Q9Y6xUQHa2qw3nKOGV3gDaF39N6MC6%=
2BQ3yuUw%40mail.gmail.com</a>.<br />

--000000000000e6efbe05d9400642--
