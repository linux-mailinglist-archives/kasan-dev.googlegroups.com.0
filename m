Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNGS72IAMGQEDQK5VHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 580CF4CAB9E
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:28:22 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id b6-20020a621b06000000b004e1453487efsf1597058pfb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:28:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646242100; cv=pass;
        d=google.com; s=arc-20160816;
        b=KX5DxSkGSwlr50B133uNydKtrZ3ZUV0xuttxLFkeazjmNn/UO9C+XI/DENOcggIIwI
         L/W5LB2ueEyt7LXx9nghMz//nFwrvlDMEHxS5rVro9LSGjEnK6xm99P2vA70mrYvQwcw
         enRA+ctLOy6b8r5OxiZGW5W/5Tu8f/6Cp58+SXqYONcznSn+sMXlV3BVR9PWz1BBtmhH
         dI+DeG0vZ2NeLgK/pCRhKUqa/I2nIayY6c7ZDaYnu6X1BijdOBVl1XKjqidega306Cw5
         3MPgV2yMD0qgARx+JeQWvpcnPeURXKgi3sEVBfGDwFjVmxSofA8FwuaGUSg2e4Kx5D10
         fQaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j4n2ThUoYwS3+S9/oCCb0ItMhKtYSjlvIY22xdNErVk=;
        b=bjTLKK5vV/8gVlK1Dz8Mhdx8EakxyV7Fyc/58m+5OkNLDcTsQ/+m7FKozj6/zoIWnG
         1STlUO20gXBmyn8iBoGsfgT3+Q33fqAefYlsQjPrceyt/ffP2OOLot0mFuIKjANI1A1L
         HzwcW8q/Tm6Qx731IBco2Ab6HJjvsto9YbKUAkNmIkL9Ej2AfgUGrDMiDjElHzSTPYD9
         0Xpj9mNAyYpo4R0wx1yHuAlOtFTtAUpPmyoNhgQ/XX50Zq781uNiiylNO+FM7Mopc+IT
         0AX9RWEHyUt0ciBbXm726MH4CImuROeWITqX9Nv+HIDYXqk09aRSZPF/SfgZ0J3JI6OL
         4RkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nc1cufbQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4n2ThUoYwS3+S9/oCCb0ItMhKtYSjlvIY22xdNErVk=;
        b=QQobkcGUVQh0v5SFnoo/0118Hq9Vue1gV2Vw8sW0d4s0Kb4j42GPxyxwo4PmLZfF8f
         o0l95UdXYLb8LMNChLAl7IrhVdUhvB7iq0CBj6Nl/QDt/LUl2pFX9rWo6qret5oBj4Gr
         xBJJH4rRTWTpy1Qo/lKWGU3Hm6OXaPZgmh/SdJzCen8Vd6geko90ddqlNcyHygigPe4L
         wVOe5ottI06Td/ZbQk6wcDLyCidd46S/o73e+Ns5eyrlcxrn9XSFPgmHbl2z//3bDKjn
         9FnY2OQldBrkuRGmqlpL8MGI0hY/V+pdhu1VyrrBmIhU2mo9uFfWnROTE/lohtwO17rG
         Jjpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4n2ThUoYwS3+S9/oCCb0ItMhKtYSjlvIY22xdNErVk=;
        b=NBIZtFFqx+HIgHWXr9SXTInNEZsyVI7BifFdNQLGD/k4E745HlYrNJh+bqJ2ZU9oKk
         V9C719ycWnVOVZ9g6DlSYLuI/XeqNNMa6RM/5Vm/M44R0KmDu2FExK2CVgXcZRlzkhZ+
         7NJIoas2e31tXR9FuxuUZPpM13+VQQ+TFgQ3FIVcA/JcRFIIosZLpOwyOkWDWCgkfVGJ
         CnTDaWGrBave7vlbTowD1et8QhWGptbrGW/YBGiSRrkUf2LgWZ9bNnuaj18CFwVhF1++
         jcsGZWEhz/ycWJ+qlMs3QSz7HOxBIezbPZ6e8FYzuATA4s9IO+LIeOGOaLNtC9VcH3rU
         BipQ==
X-Gm-Message-State: AOAM531lHyIitJf/MDOKg4xYbZhPVlDfsDdTWJDl3s02kkCAG0bmsJPC
	EL11/ox4p5mliZLkcZGUd4U=
X-Google-Smtp-Source: ABdhPJxPFUS8F7eq0VI7Hxe4h3CbICqoXbWVKvBKt/kCS7/RBtGlCgrEiuzYrNdcDk98w48dDuhbKA==
X-Received: by 2002:a63:dd17:0:b0:36c:33aa:6d5f with SMTP id t23-20020a63dd17000000b0036c33aa6d5fmr27030403pgg.300.1646242100682;
        Wed, 02 Mar 2022 09:28:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:52ca:0:b0:342:c47c:cfba with SMTP id z10-20020a6552ca000000b00342c47ccfbals8423757pgp.10.gmail;
 Wed, 02 Mar 2022 09:28:20 -0800 (PST)
X-Received: by 2002:a63:e241:0:b0:375:9f87:eb1f with SMTP id y1-20020a63e241000000b003759f87eb1fmr24543446pgj.216.1646242100033;
        Wed, 02 Mar 2022 09:28:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646242100; cv=none;
        d=google.com; s=arc-20160816;
        b=fKd6IO5GH2/xRGCsj6+2Y+/MS54d1i5xT0bKgaSrWvi0dtKNpMzFwhuJQuwWJOIg7k
         7ha7M0gxlQa6GbcWebp/M4Rg2PCPCYeUONHOe8Jj6GSj9ik3MIMtMDO5xmk6PmZTmvb9
         4sD0bNl+2oWgjA35bgFxlk7H+GCKdzSscYeTjVjzd6o7kJHXFJXKTiE9oqfsk7Ad5Y2q
         SCrNHhEVusFvCCIPXjnyD4+GT4uhsdfzdpE/ftuRnaIoMvGaCWMH8Jd+RedMiqUFx/Zj
         85/zjmpWOKfhLSf1tLhoL35stUI43RjNHBOV/tqq5wx3YGQFZ+/rK/GFct2Pc65i+GUe
         wlbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CZBNWFrU7HDZpRYaR09tiEFzTh6W8mr+GbWCgbi5qlE=;
        b=fN/idRjdZeu0XmbP6SmjPxoDwUMyylw6n8f2QNNPleO0at1sQGir+p1OJiu+fjjx5t
         yPq+aT6vi0U1Qcm0k455jfj5XqOTs0xsInCjW/vOVOpna8UqceGQsiwBHSewHUC3+faq
         IqlAglwYJf/CkQSY3lqPDuQsIq0BB7JZEld01VhmEU2z4iFCfdnYntc/0R//j2+OOSlc
         7oN0GLpAKiN29uRc3V/4DZ0Cl412rCdKxoyGhV/vAmaoLSO9eula6VSWUpSRZfht4oJE
         pgZY3wX+DObShjftJG0Cz1JV+L2qK3yClQRmZsF44xtbF/VS2t040Zfe1GiCm2Jljo7Y
         G8Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nc1cufbQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id i4-20020aa78d84000000b004e156ea5573si801325pfr.4.2022.03.02.09.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:28:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id bt3so2321440qtb.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:28:19 -0800 (PST)
X-Received: by 2002:ac8:5e4b:0:b0:2dd:dc99:d22b with SMTP id
 i11-20020ac85e4b000000b002dddc99d22bmr24535352qtx.165.1646242098973; Wed, 02
 Mar 2022 09:28:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <761f8e5a6ee040d665934d916a90afe9f322f745.1646237226.git.andreyknvl@google.com>
In-Reply-To: <761f8e5a6ee040d665934d916a90afe9f322f745.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:27:42 +0100
Message-ID: <CAG_fn=U12zm3woxOQSXuGRd91cr1fgOXVvh0X+Rub0GJEtEYEg@mail.gmail.com>
Subject: Re: [PATCH mm 01/22] kasan: drop addr check from describe_object_addr
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="00000000000086a27405d93f9bdf"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nc1cufbQ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
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

--00000000000086a27405d93f9bdf
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:36 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> describe_object_addr() used to be called with NULL addr in the early
> days of KASAN. This no longer happens, so drop the check.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kasan/report.c | 3 ---
>  1 file changed, 3 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index f64352008bb8..607a8c2e4674 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -162,9 +162,6 @@ static void describe_object_addr(struct kmem_cache
> *cache, void *object,
>                " which belongs to the cache %s of size %d\n",
>                 object, cache->name, cache->object_size);
>
> -       if (!addr)
> -               return;
> -
>         if (access_addr < object_addr) {
>                 rel_type =3D "to the left";
>                 rel_bytes =3D object_addr - access_addr;
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/761f8e5a6ee040d665934d916a90a=
fe9f322f745.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DU12zm3woxOQSXuGRd91cr1fgOXVvh0X%2BRub0GJEtEYEg%40mail.gm=
ail.com.

--00000000000086a27405d93f9bdf
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Wed, Mar 2, 2022 at 5:36 PM &lt;<a=
 href=3D"mailto:andrey.konovalov@linux.dev">andrey.konovalov@linux.dev</a>&=
gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0=
px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">From:=
 Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com" target=3D"_b=
lank">andreyknvl@google.com</a>&gt;<br>
<br>
describe_object_addr() used to be called with NULL addr in the early<br>
days of KASAN. This no longer happens, so drop the check.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glide=
r@google.com</a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"=
margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-lef=
t:1ex">
---<br>
=C2=A0mm/kasan/report.c | 3 ---<br>
=C2=A01 file changed, 3 deletions(-)<br>
<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index f64352008bb8..607a8c2e4674 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -162,9 +162,6 @@ static void describe_object_addr(struct kmem_cache *cac=
he, void *object,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0&quot; which belongs=
 to the cache %s of size %d\n&quot;,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 object, cache-&gt;n=
ame, cache-&gt;object_size);<br>
<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!addr)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return;<br>
-<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (access_addr &lt; object_addr) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 rel_type =3D &quot;=
to the left&quot;;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 rel_bytes =3D objec=
t_addr - access_addr;<br>
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
om/d/msgid/kasan-dev/761f8e5a6ee040d665934d916a90afe9f322f745.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/761f8e5a6ee040d665934d916a90afe9f322f745.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DU12zm3woxOQSXuGRd91cr1fgOXVvh0X%2BRub0GJEtEYE=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DU12zm3woxOQSXuGRd91cr1fgOXVvh0X%2BRub0=
GJEtEYEg%40mail.gmail.com</a>.<br />

--00000000000086a27405d93f9bdf--
