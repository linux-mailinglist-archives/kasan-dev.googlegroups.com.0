Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD6372IAMGQEYDEAIAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 51BDF4CAC65
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:46:57 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id l6-20020a170903120600b0014f43ba55f3sf1363301plh.11
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:46:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646243216; cv=pass;
        d=google.com; s=arc-20160816;
        b=dZLBDbz+N5GbOTUvcSkDuXf+TWw0ZPTTVzjtm9vzjoULdb3VsG6b9/zxrflnsIkdxU
         ZC0EeChyOu0Srta67gyECqIy1yeefEENtPD+YKgr42MdDr7w8BDf5+r5+fGk5RJOoYqO
         lmcM2pkKxs0rAfFN9jLb6/GL8EODKfUFbIWqIJMdukWmY2SWnnyQ5CvCwqDIk1fUVTnh
         eVS7W/LJlGk/lQA9JiiH80eUaAWfq3JNo1zXWX0WbsRWik/oHdk+PqRTVwamJ6HTI9hv
         P0gISxMAkItDommrGAVqxgMhmwbjYT9YRdrogjvQ7Jnv/DZaeczDEGMFVeqTXtYyqCqF
         0E7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WhYCkX8DShqghZlAjrbki+isn0Z0F+TKeMJ7nWEfnBA=;
        b=GFab1hBxDnRnBcNveCGos5iQbEKHGAZtSuz7PhyPVDeWdfHXLkgO8lqyUmZ83GlBmL
         5wBGzPiZc4RBulZq4YnPS+KAJxfJijEz0nrxW3pgC7mIflK/VoeCDGqAvXq7siB8SyH4
         kzJW06Q2KqWWvUS8a9BfwxkaxcDbFZUq9MhZOOJTXXFJsBRD3qGtoxwe4wUes41nrOg5
         4vZhNSTwPhanxjbfvuEkVd7qaKTH/1RUuCYTKq3Acxpn5GzYr99ARpQjSU2gojBuUsjk
         BmFBty+BEBG/ownEFaokEhUNGMwxsCObBrF4aljVh8MviwdpqT9VLJMOsg6A49H4NtNE
         trZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bomc0j4Z;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WhYCkX8DShqghZlAjrbki+isn0Z0F+TKeMJ7nWEfnBA=;
        b=aKTVtjD4jbxKgvwAxB2HM8V2z8tO2wgsvNCeQvw14JHic/L/BYsAvOJVGEZxFXDqoC
         kwGZw2j3kkRIBteROD3ELEXZkeYGHDLGflwoZ9Nxy/69dtREjuZ2mebn9uK/1KcGfXHO
         OhB8HxGC1AFRy/N8fmdubMVQE97nDVUyv9HZ+kH+DFVvB7lbQ3VWLyon1psMXRcAK7em
         QQH0YwKFEINTvrS2X1nGy94RAa55YaRLtNTFCABvmlkcDRgmx71vcLlkIm4xb9IgWl+E
         CxgZ9L8KMKWH05k0BUyW8l8FMD3Iux9nEfBcg5mWKyQYj0apgtbiRgf+QT+JXuJDipcE
         NtZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WhYCkX8DShqghZlAjrbki+isn0Z0F+TKeMJ7nWEfnBA=;
        b=zo91EB/EE+/I4TwidScUT6fTThw9pQGiqBfZMsZwPH02ttzDXbxcW1loe+PsWP68a2
         rTigEF1zxofhgWCks0J0HEc7R5RteCgx2FlLkpdjed36XElH3zkVvIfNONFICa6Tagle
         asOKQSH0qpRI5HjbrfYArgI9JubPqVp2kYwN5jbf2CGqvd/IFuIkZsXc00WxUsRtSDQv
         6AXlA/jXWRXvJ5dO1DJZH/XxGbxAV4mb2+DUrSQAJh3PHXgV1HoYCgILm5vUiTpbDxJc
         CW4tyfGR0G87ScvIrCk0lFwvB2nTF4SYdIv/+OcF3XGPwiI1LekOxXxPL2g6dSahVcgZ
         M8+g==
X-Gm-Message-State: AOAM5323MN7hZm7kivgw1FxUMHa8UiL+fwYt4XQgR3pjoZ6lwvJx9VpV
	KEsfJMGmqEmDgQgrVX+Xov4=
X-Google-Smtp-Source: ABdhPJymLBTudHupdh5if+/7CDOQxTKkwtjJSQlh+bIv/gmaaLORFuWltjbR8gYHdpgGWvjLLaP8bw==
X-Received: by 2002:a17:902:ce09:b0:151:96e2:d4b5 with SMTP id k9-20020a170902ce0900b0015196e2d4b5mr4131362plg.3.1646243216067;
        Wed, 02 Mar 2022 09:46:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bb92:b0:1bc:46ec:e156 with SMTP id
 v18-20020a17090abb9200b001bc46ece156ls4723896pjr.2.gmail; Wed, 02 Mar 2022
 09:46:55 -0800 (PST)
X-Received: by 2002:a17:90b:2243:b0:1bf:a3e:9b9a with SMTP id hk3-20020a17090b224300b001bf0a3e9b9amr88224pjb.64.1646243215447;
        Wed, 02 Mar 2022 09:46:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646243215; cv=none;
        d=google.com; s=arc-20160816;
        b=iA0DiTmitrtuAt4GqRIkXt+4qqtHBos2/HANOPAMu1x7GD6kuy2+tnMnKWvMo5UhKZ
         FW3v8v7oHKVZbzJeWLsBSSNjKYDmzBnkFwcQEfGI6U9M0f2ukmpG+jEEWauenSxgvnBW
         YZrjr5P0QRzi6VpOFoL0dUmcdDymTW7LFb8XbIOTBHXWFP7ZKYI9CU2+RoaL2rQBTvf4
         IQGDEfZ+rpcEfiB9LCI2PrBDP2WkeO4JiEADVOBp7kAyGUsGjkUVktRtIN/nhe33RpO3
         lDz+/l74jKrhPvwyGwcM3qQEdy5bpwWVhV5fVjZXT0yGy0RJPyFV5YbDxYRAB0drlROR
         s3mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fZWesjVlnNPom3VAQBATiQ2w4HQw0ODH2qGAjfL9wDI=;
        b=k8Vb/pNm0xuuoI9oe3FmWpN/xRbSeWtOdMbWtnofPhnO1sEDSWvOAYOYWJq4uxVFjL
         bFkQK3CqhrSp5VvLzQLAUU76m6zbswN2kKZa3ximkbBSonnM27J7DMfz9HnZ6HycSWoX
         ZBPQ2d43xJgU9Mq7u4015W0xtFchhPtqblZv1f02h2IFh8wQWf3Pswx90daz7aQ6IUfh
         Vb2ChmmDSfAi7ODPbaEwpokJSbhYSEQD4+65tFluvX9mYnL7VQzODU3GP/HNQqwKuI8G
         H38L3YaN0uV4dX73kY6XJtpSgsrA+Y5ypm+MGt4a/AbSSCRBlkj4UasI+S2z/3PxfTtb
         er8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bomc0j4Z;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id d24-20020a170902729800b001514a005025si589593pll.5.2022.03.02.09.46.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:46:55 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id a1so2298073qta.13
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:46:55 -0800 (PST)
X-Received: by 2002:a05:622a:15d2:b0:2de:323e:e964 with SMTP id
 d18-20020a05622a15d200b002de323ee964mr24949794qty.79.1646243214418; Wed, 02
 Mar 2022 09:46:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <dac26d811ae31856c3d7666de0b108a3735d962d.1646237226.git.andreyknvl@google.com>
In-Reply-To: <dac26d811ae31856c3d7666de0b108a3735d962d.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:46:17 +0100
Message-ID: <CAG_fn=VSdymLH6sqeM41p0T8X1u4PrQqY6i6Us29mvJR--Z8Yg@mail.gmail.com>
Subject: Re: [PATCH mm 07/22] kasan: simplify kasan_update_kunit_status and
 call sites
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="00000000000002c57105d93fde81"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bomc0j4Z;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as
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

--00000000000002c57105d93fde81
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:37 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> - Rename kasan_update_kunit_status() to update_kunit_status()
>   (the function is static).
>
> - Move the IS_ENABLED(CONFIG_KUNIT) to the function's
>   definition instead of duplicating it at call sites.
>
> - Obtain and check current->kunit_test within the function.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>

Reviewed-by: Alexander Potapenko <glider@google.com>


> ---
>  mm/kasan/report.c | 30 ++++++++++++++----------------
>  1 file changed, 14 insertions(+), 16 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 2d892ec050be..59db81211b8a 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -357,24 +357,31 @@ static bool report_enabled(void)
>  }
>
>  #if IS_ENABLED(CONFIG_KUNIT)
> -static void kasan_update_kunit_status(struct kunit *cur_test, bool sync)
> +static void update_kunit_status(bool sync)
>  {
> +       struct kunit *test;
>         struct kunit_resource *resource;
>         struct kunit_kasan_status *status;
>
> -       resource =3D kunit_find_named_resource(cur_test, "kasan_status");
> +       test =3D current->kunit_test;
> +       if (!test)
> +               return;
>
> +       resource =3D kunit_find_named_resource(test, "kasan_status");
>         if (!resource) {
> -               kunit_set_failure(cur_test);
> +               kunit_set_failure(test);
>                 return;
>         }
>
>         status =3D (struct kunit_kasan_status *)resource->data;
>         WRITE_ONCE(status->report_found, true);
>         WRITE_ONCE(status->sync_fault, sync);
> +
>         kunit_put_resource(resource);
>  }
> -#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +#else
> +static void update_kunit_status(bool sync) { }
> +#endif
>
>  void kasan_report_invalid_free(void *object, unsigned long ip)
>  {
> @@ -383,10 +390,7 @@ void kasan_report_invalid_free(void *object, unsigne=
d
> long ip)
>
>         object =3D kasan_reset_tag(object);
>
> -#if IS_ENABLED(CONFIG_KUNIT)
> -       if (current->kunit_test)
> -               kasan_update_kunit_status(current->kunit_test, true);
> -#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +       update_kunit_status(true);
>
>         start_report(&flags);
>         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void
> *)ip);
> @@ -402,10 +406,7 @@ void kasan_report_async(void)
>  {
>         unsigned long flags;
>
> -#if IS_ENABLED(CONFIG_KUNIT)
> -       if (current->kunit_test)
> -               kasan_update_kunit_status(current->kunit_test, false);
> -#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +       update_kunit_status(false);
>
>         start_report(&flags);
>         pr_err("BUG: KASAN: invalid-access\n");
> @@ -424,10 +425,7 @@ static void __kasan_report(unsigned long addr, size_=
t
> size, bool is_write,
>         void *untagged_addr;
>         unsigned long flags;
>
> -#if IS_ENABLED(CONFIG_KUNIT)
> -       if (current->kunit_test)
> -               kasan_update_kunit_status(current->kunit_test, true);
> -#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +       update_kunit_status(true);
>
>         disable_trace_on_warning();
>
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/dac26d811ae31856c3d7666de0b10=
8a3735d962d.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DVSdymLH6sqeM41p0T8X1u4PrQqY6i6Us29mvJR--Z8Yg%40mail.gmai=
l.com.

--00000000000002c57105d93fde81
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
- Rename kasan_update_kunit_status() to update_kunit_status()<br>
=C2=A0 (the function is static).<br>
<br>
- Move the IS_ENABLED(CONFIG_KUNIT) to the function&#39;s<br>
=C2=A0 definition instead of duplicating it at call sites.<br>
<br>
- Obtain and check current-&gt;kunit_test within the function.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div><br>=
</div><div>Reviewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@go=
ogle.com">glider@google.com</a>&gt;</div><div>=C2=A0</div><blockquote class=
=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rg=
b(204,204,204);padding-left:1ex">
---<br>
=C2=A0mm/kasan/report.c | 30 ++++++++++++++----------------<br>
=C2=A01 file changed, 14 insertions(+), 16 deletions(-)<br>
<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index 2d892ec050be..59db81211b8a 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -357,24 +357,31 @@ static bool report_enabled(void)<br>
=C2=A0}<br>
<br>
=C2=A0#if IS_ENABLED(CONFIG_KUNIT)<br>
-static void kasan_update_kunit_status(struct kunit *cur_test, bool sync)<b=
r>
+static void update_kunit_status(bool sync)<br>
=C2=A0{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0struct kunit *test;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 struct kunit_resource *resource;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 struct kunit_kasan_status *status;<br>
<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0resource =3D kunit_find_named_resource(cur_test=
, &quot;kasan_status&quot;);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0test =3D current-&gt;kunit_test;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!test)<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return;<br>
<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0resource =3D kunit_find_named_resource(test, &q=
uot;kasan_status&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (!resource) {<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kunit_set_failure(c=
ur_test);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kunit_set_failure(t=
est);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 return;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 status =3D (struct kunit_kasan_status *)resourc=
e-&gt;data;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 WRITE_ONCE(status-&gt;report_found, true);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 WRITE_ONCE(status-&gt;sync_fault, sync);<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 kunit_put_resource(resource);<br>
=C2=A0}<br>
-#endif /* IS_ENABLED(CONFIG_KUNIT) */<br>
+#else<br>
+static void update_kunit_status(bool sync) { }<br>
+#endif<br>
<br>
=C2=A0void kasan_report_invalid_free(void *object, unsigned long ip)<br>
=C2=A0{<br>
@@ -383,10 +390,7 @@ void kasan_report_invalid_free(void *object, unsigned =
long ip)<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 object =3D kasan_reset_tag(object);<br>
<br>
-#if IS_ENABLED(CONFIG_KUNIT)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0if (current-&gt;kunit_test)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kasan_update_kunit_=
status(current-&gt;kunit_test, true);<br>
-#endif /* IS_ENABLED(CONFIG_KUNIT) */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0update_kunit_status(true);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 start_report(&amp;flags);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;BUG: KASAN: double-free or invalid=
-free in %pS\n&quot;, (void *)ip);<br>
@@ -402,10 +406,7 @@ void kasan_report_async(void)<br>
=C2=A0{<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 unsigned long flags;<br>
<br>
-#if IS_ENABLED(CONFIG_KUNIT)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0if (current-&gt;kunit_test)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kasan_update_kunit_=
status(current-&gt;kunit_test, false);<br>
-#endif /* IS_ENABLED(CONFIG_KUNIT) */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0update_kunit_status(false);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 start_report(&amp;flags);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;BUG: KASAN: invalid-access\n&quot;=
);<br>
@@ -424,10 +425,7 @@ static void __kasan_report(unsigned long addr, size_t =
size, bool is_write,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 void *untagged_addr;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 unsigned long flags;<br>
<br>
-#if IS_ENABLED(CONFIG_KUNIT)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0if (current-&gt;kunit_test)<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kasan_update_kunit_=
status(current-&gt;kunit_test, true);<br>
-#endif /* IS_ENABLED(CONFIG_KUNIT) */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0update_kunit_status(true);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 disable_trace_on_warning();<br>
<br>
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
om/d/msgid/kasan-dev/dac26d811ae31856c3d7666de0b108a3735d962d.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/dac26d811ae31856c3d7666de0b108a3735d962d.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DVSdymLH6sqeM41p0T8X1u4PrQqY6i6Us29mvJR--Z8Yg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DVSdymLH6sqeM41p0T8X1u4PrQqY6i6Us29mvJR--=
Z8Yg%40mail.gmail.com</a>.<br />

--00000000000002c57105d93fde81--
