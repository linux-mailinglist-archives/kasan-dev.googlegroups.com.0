Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIFGTCIQMGQEGPBUMNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 286DE4D00D9
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 15:13:53 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id u13-20020a4ab5cd000000b002e021ad5bbcsf11560004ooo.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Mar 2022 06:13:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646662432; cv=pass;
        d=google.com; s=arc-20160816;
        b=SCQO9G2ATX+vTsns04KVOemZe2MCSistJ9H3DWjKFB1c3MLgUxR1aTomJ4h/pRUTXS
         idioqwoiFjCX+s/gPh85YGHErUTQsVQtjXxR8WojNIgZSOvUXgVuXMaDcImxZG2h1HjD
         BHQN5UtNEW7Tmyy4e8RgYtT/0rXlTJ5MWTOSlgDsdGA+HaIIRi2myN9JyTJaHaHoqVPB
         84ZyYEvMnblmnuIghQQx4ys1l1XgGxDyLkonscxZ51c3DhL8+XLbTDEu5wuSFahL7AbY
         j0oON/VSSIA/cP0ZYo8Kz5ELi10wpIa7WEAE7D7Xq4q2y9Usub2y6YQuq2M20bDmcedw
         K69A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0LBUblUPaT2fvKnxhLYAS2IzAdsz38+fe7xiomIojwk=;
        b=t8koBOgvaBktX9q9h9J54FPJcgjoV7/95eXXRID76dkRZ7bGDj356zw9Bk2Fe/6rw7
         HfGEAS1aNSo7+/ASoCRZDQRtN7LaeO3NdYXjrkRVijR0EcyY2EeYthTt8gwS6mo5t+PL
         BabGUnzXKgefRUEbdNabYj3oyK65oQPeeB3pZ4cs7XDSpxljqGGxspG+XnF1kh5/a3qI
         1vFNyaCpWAx83dqZ+ikkmCtUo8qA1WJ2Ukz4zH6uTcxu9ty0+9fgDDDnrMTjhsIrYl3n
         173pmlC7OLmJjIUTwaQ7vNUxVXt/7nqQrRiwFsWkLA9J0qmvAZ0cLkyr+4FbW7Nbyfnm
         PwLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=goleXkes;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0LBUblUPaT2fvKnxhLYAS2IzAdsz38+fe7xiomIojwk=;
        b=DUdb6jZzXJ6kK96C4UdvFrtMK6jtvUb0L6hKdEQYVtqCKZNXR62b3prEcS0qQ8gxLZ
         EOf80HrK8HgZcB732hDplNLKS/4hdAv5uVLkRwEGxtncbDssQF22TQeuCCXI/miDmOlu
         OxFGSWTy+lhWUNCISoxPfRjaBF/JrY14QsVXBS/msY2t5RnCmkj6CLxXJCYolQKwcp34
         irNLk1GlBi/E3tFSVv9N66awuyua2JQB7dxLWvWfxktqjvkfZIlRVLHFUD1SAzNLe68f
         nRALKsnwafte2KI8x6w36KSKAvl/8pRrR1ui/oXY6X/LEylIGXvsTv9hIavsHbq5EDTW
         9omg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0LBUblUPaT2fvKnxhLYAS2IzAdsz38+fe7xiomIojwk=;
        b=wwjJw/+ryQ7/bVFSVN0852oDhtTth8++x8lttBpVkVWWCbacjRvUEpMsv5Oc4bIxRf
         TA6xZf+5l0oxHrF5KZWvb1kOEFJXkaDOH71UL30QdWK2hsK+4o4vBg7VeDA5gv+IO+EI
         TbLuueARqgsieh8XN1ptMTl3FqgAvWqvx00GeUKsvqLPW8O5cgNrTgUWj3sI0A38UwMY
         CVQQltK3Kt2l4LML7hWYRajGtTLuP/KVl2EhNHTmkZ8U3SEsLau0srzOHJnknXUw0M/0
         Yztvers4aM2uUcg5Sj2MtxREXIwzLHiRI9/Ujf1hRqYaCcTWT8uq2F6ei48CspEA0KNq
         H2eg==
X-Gm-Message-State: AOAM532FIHrquyaBge/iYI1hGh8LKGriahjgrGws0IniZUwq1pyuorl/
	43nDM+Ai7OY7kI63BiRx6+Y=
X-Google-Smtp-Source: ABdhPJwTBh3ZNcgBwS3AXlEaoSB4LpfTEp3jHMaZhW2jcq20rPtN3sAjl6H0AaIkRUu3wucYb0jcXQ==
X-Received: by 2002:a05:6870:4998:b0:d7:5766:ae33 with SMTP id ho24-20020a056870499800b000d75766ae33mr5864351oab.67.1646662432180;
        Mon, 07 Mar 2022 06:13:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2020:b0:2d9:f709:2c08 with SMTP id
 q32-20020a056808202000b002d9f7092c08ls407817oiw.7.gmail; Mon, 07 Mar 2022
 06:13:51 -0800 (PST)
X-Received: by 2002:aca:6548:0:b0:2d9:ce64:bead with SMTP id j8-20020aca6548000000b002d9ce64beadmr3622173oiw.109.1646662431841;
        Mon, 07 Mar 2022 06:13:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646662431; cv=none;
        d=google.com; s=arc-20160816;
        b=LeUSbg1mCU+yv+H4sgPNVABJY7tAh2ecRTPvjj7V27CAoveBUan+b92cL/XojAZ+Y7
         KG9eS378zxIgN1xNGFTXbGYerVW4ZQ4KOMr4CRBUKCnwIAdisGMzMDX37EnJvghAloNd
         XFzo2USZChnCz1mOxJi/3Z+RrH3xOyIgSNkUBx6vbmWYgUEEl21j/FW5AR/3d9CE40ml
         mXDWydIoe8/1j6LaCavL3BQ1H0Zu2CDq8XP9wCgMR59XjqFXW54au2E1Y123MB+dy+mK
         pjYHdmqslVZa2aeYoVAFmW2tGRhMfGvl7k8xzBYLsqqwNBev4buOLxbnpKIzNkrINrZ7
         ODYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gGmnx14YtQ+A7UsJQ2e9RGYf4zsmCH66jJ5hYBKHlHM=;
        b=GfekacCa7GzOQY1yx2FeFuqK4Gir8zpxfFnnnbuahel4+dba0GqhhVsHL6kOaV9F9R
         d6rEO1/NaUNuAHhNm7JEMQiTPfUyp3jATIvuTF29aRmbi0IZRO2QMR7ulgMio8SEmYFX
         q9B8QcFIUG2zmCBTzw/bMZQy9yn90Vp9apaCPKXQ1/raKvRbijZ37g10ijIgL62vmouk
         jOoqAG3QnXZPdjPkFkzcBgoD/PIUvp8ppTWsSCB+L7oYRSamywIjlsEQZwEuI9NhD2fN
         vvuB92meM9gtf+4IrdM6Aw1KPxfd5vPeDRgjG66chAIQMPKL8Xy2P1+ZlAJNgpvlC6yp
         Y7hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=goleXkes;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id i3-20020a9d6103000000b005ad267a9a05si1710493otj.3.2022.03.07.06.13.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Mar 2022 06:13:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id f4so11717222qvd.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Mar 2022 06:13:51 -0800 (PST)
X-Received: by 2002:a05:6214:212f:b0:42d:f8f0:fca7 with SMTP id
 r15-20020a056214212f00b0042df8f0fca7mr8770443qvc.14.1646662431338; Mon, 07
 Mar 2022 06:13:51 -0800 (PST)
MIME-Version: 1.0
References: <tencent_D44A49FFB420EDCCBFB9221C8D14DFE12908@qq.com>
In-Reply-To: <tencent_D44A49FFB420EDCCBFB9221C8D14DFE12908@qq.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Mar 2022 15:13:14 +0100
Message-ID: <CAG_fn=W02BVqA_JhCF=Xzs5VkTZm4Caf_rnusT-RPD_r6=0U9Q@mail.gmail.com>
Subject: Re: [PATCH] lib/test_meminit: add checks for the allocation functions
To: xkernel.wang@foxmail.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: multipart/alternative; boundary="000000000000497d9705d9a179fc"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=goleXkes;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

--000000000000497d9705d9a179fc
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Mar 4, 2022 at 10:13 AM <xkernel.wang@foxmail.com> wrote:

> From: Xiaoke Wang <xkernel.wang@foxmail.com>
>
> alloc_pages(), kmalloc() and vmalloc() are all memory allocation
> functions which can return NULL when some internal memory failures
> happen. So it is better to check the return of them to catch the failure
> in time for better test them.
>
> Signed-off-by: Xiaoke Wang <xkernel.wang@foxmail.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  lib/test_meminit.c | 21 +++++++++++++++++++++
>  1 file changed, 21 insertions(+)
>
> diff --git a/lib/test_meminit.c b/lib/test_meminit.c
> index e4f706a..2f4c4bc 100644
> --- a/lib/test_meminit.c
> +++ b/lib/test_meminit.c
> @@ -67,17 +67,24 @@ static int __init do_alloc_pages_order(int order, int
> *total_failures)
>         size_t size =3D PAGE_SIZE << order;
>
>         page =3D alloc_pages(GFP_KERNEL, order);
> +       if (!page)
> +               goto err;
>         buf =3D page_address(page);
>         fill_with_garbage(buf, size);
>         __free_pages(page, order);
>
>         page =3D alloc_pages(GFP_KERNEL, order);
> +       if (!page)
> +               goto err;
>         buf =3D page_address(page);
>         if (count_nonzero_bytes(buf, size))
>                 (*total_failures)++;
>         fill_with_garbage(buf, size);
>         __free_pages(page, order);
>         return 1;
> +err:
> +       (*total_failures)++;
> +       return 1;
>  }
>
>  /* Test the page allocator by calling alloc_pages with different orders.
> */
> @@ -100,15 +107,22 @@ static int __init do_kmalloc_size(size_t size, int
> *total_failures)
>         void *buf;
>
>         buf =3D kmalloc(size, GFP_KERNEL);
> +       if (!buf)
> +               goto err;
>         fill_with_garbage(buf, size);
>         kfree(buf);
>
>         buf =3D kmalloc(size, GFP_KERNEL);
> +       if (!buf)
> +               goto err;
>         if (count_nonzero_bytes(buf, size))
>                 (*total_failures)++;
>         fill_with_garbage(buf, size);
>         kfree(buf);
>         return 1;
> +err:
> +       (*total_failures)++;
> +       return 1;
>  }
>
>  /* Test vmalloc() with given parameters. */
> @@ -117,15 +131,22 @@ static int __init do_vmalloc_size(size_t size, int
> *total_failures)
>         void *buf;
>
>         buf =3D vmalloc(size);
> +       if (!buf)
> +               goto err;
>         fill_with_garbage(buf, size);
>         vfree(buf);
>
>         buf =3D vmalloc(size);
> +       if (!buf)
> +               goto err;
>         if (count_nonzero_bytes(buf, size))
>                 (*total_failures)++;
>         fill_with_garbage(buf, size);
>         vfree(buf);
>         return 1;
> +err:
> +       (*total_failures)++;
> +       return 1;
>  }
>
>  /* Test kmalloc()/vmalloc() by allocating objects of different sizes. */
> --
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
kasan-dev/CAG_fn%3DW02BVqA_JhCF%3DXzs5VkTZm4Caf_rnusT-RPD_r6%3D0U9Q%40mail.=
gmail.com.

--000000000000497d9705d9a179fc
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Fri, Mar 4, 2022 at 10:13 AM &lt;<=
a href=3D"mailto:xkernel.wang@foxmail.com">xkernel.wang@foxmail.com</a>&gt;=
 wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px =
0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">From: Xi=
aoke Wang &lt;<a href=3D"mailto:xkernel.wang@foxmail.com" target=3D"_blank"=
>xkernel.wang@foxmail.com</a>&gt;<br>
<br>
alloc_pages(), kmalloc() and vmalloc() are all memory allocation<br>
functions which can return NULL when some internal memory failures<br>
happen. So it is better to check the return of them to catch the failure<br=
>
in time for better test them.<br>
<br>
Signed-off-by: Xiaoke Wang &lt;<a href=3D"mailto:xkernel.wang@foxmail.com" =
target=3D"_blank">xkernel.wang@foxmail.com</a>&gt;<br></blockquote><div>Rev=
iewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glid=
er@google.com</a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D=
"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-le=
ft:1ex">
---<br>
=C2=A0lib/test_meminit.c | 21 +++++++++++++++++++++<br>
=C2=A01 file changed, 21 insertions(+)<br>
<br>
diff --git a/lib/test_meminit.c b/lib/test_meminit.c<br>
index e4f706a..2f4c4bc 100644<br>
--- a/lib/test_meminit.c<br>
+++ b/lib/test_meminit.c<br>
@@ -67,17 +67,24 @@ static int __init do_alloc_pages_order(int order, int *=
total_failures)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 size_t size =3D PAGE_SIZE &lt;&lt; order;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 page =3D alloc_pages(GFP_KERNEL, order);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!page)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0goto err;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 buf =3D page_address(page);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 fill_with_garbage(buf, size);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 __free_pages(page, order);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 page =3D alloc_pages(GFP_KERNEL, order);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!page)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0goto err;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 buf =3D page_address(page);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (count_nonzero_bytes(buf, size))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 (*total_failures)++=
;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 fill_with_garbage(buf, size);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 __free_pages(page, order);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 return 1;<br>
+err:<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0(*total_failures)++;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0return 1;<br>
=C2=A0}<br>
<br>
=C2=A0/* Test the page allocator by calling alloc_pages with different orde=
rs. */<br>
@@ -100,15 +107,22 @@ static int __init do_kmalloc_size(size_t size, int *t=
otal_failures)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 void *buf;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 buf =3D kmalloc(size, GFP_KERNEL);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!buf)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0goto err;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 fill_with_garbage(buf, size);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 kfree(buf);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 buf =3D kmalloc(size, GFP_KERNEL);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!buf)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0goto err;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (count_nonzero_bytes(buf, size))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 (*total_failures)++=
;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 fill_with_garbage(buf, size);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 kfree(buf);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 return 1;<br>
+err:<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0(*total_failures)++;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0return 1;<br>
=C2=A0}<br>
<br>
=C2=A0/* Test vmalloc() with given parameters. */<br>
@@ -117,15 +131,22 @@ static int __init do_vmalloc_size(size_t size, int *t=
otal_failures)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 void *buf;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 buf =3D vmalloc(size);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!buf)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0goto err;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 fill_with_garbage(buf, size);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 vfree(buf);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 buf =3D vmalloc(size);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!buf)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0goto err;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (count_nonzero_bytes(buf, size))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 (*total_failures)++=
;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 fill_with_garbage(buf, size);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 vfree(buf);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 return 1;<br>
+err:<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0(*total_failures)++;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0return 1;<br>
=C2=A0}<br>
<br>
=C2=A0/* Test kmalloc()/vmalloc() by allocating objects of different sizes.=
 */<br>
-- <br>
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
om/d/msgid/kasan-dev/CAG_fn%3DW02BVqA_JhCF%3DXzs5VkTZm4Caf_rnusT-RPD_r6%3D0=
U9Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAG_fn%3DW02BVqA_JhCF%3DXzs5VkTZm4Caf_rnusT-R=
PD_r6%3D0U9Q%40mail.gmail.com</a>.<br />

--000000000000497d9705d9a179fc--
