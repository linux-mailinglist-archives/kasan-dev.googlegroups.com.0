Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUOS72IAMGQETHWX6ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 75D8A4CABB3
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:28:50 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id h25-20020a056808015900b002d6048692besf1433015oie.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:28:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646242129; cv=pass;
        d=google.com; s=arc-20160816;
        b=YBtkJWOjoEtEPkZDmGKwoAGPhUTAChIAf6Z0UT51FClIxfSwtvT6mk3bVj4thpCTVp
         FgSZfDu1nXTXa0bKD/xpK+DlHm+s+BvVWWxeINGehHb3EzMPxqrhT41aMTc2S4Wv1hPb
         fc19580EAT046Xq+IpKwjL4fWFBq69RpxvzxRU739s2XaW6d3i06FqZ+YWQrgX7L4S7u
         Ur9mZlzmI5uHgrZR3u7c73egjtSUxxGl6b8aFnUw1R85kAbPhlwVe40pSsHZ25eBujv8
         UdwRmwDWU+dyK+Aa552eFhmxiTHfYZl5a8qC+zVQUS7IgmpbPVHXHCNNfCaDSyQMPnMD
         HMMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fWEiMrhNNLJ719TULwow5RTvGaRys/By4SS/CJ5POpM=;
        b=kchjdImoS450NUdr/UNo1QTzuDtN9NBHBqAbzy4ot5HAYhw3i3mTo3P+YXXnzGwFhf
         cM5cBjb2e8+QR6icBaKC1+3EVw8mWzK4l079cMxb+Skj/iUIz3uN63LVlTj+QukZPaXk
         iXTHxg4YCvPSKB8gzlc4sjCf2D7NIpRzmlDGkmAKbvzQTI+UlzBnG5U0GJBPcO4jepR/
         G36JHPK/nMe4W7SHbO8oHf1FZsYChGDcfYWafygIjSedoAwB4wGmNS1GEc2lvCjZj41t
         XrdVJZs5lnfK7RcfdfuYO1jZZY/4gbOb1u5xEuMDMWKmGi8lKzWaTghsrQAz+ddcHaAP
         xQog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hoUQHly0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fWEiMrhNNLJ719TULwow5RTvGaRys/By4SS/CJ5POpM=;
        b=WkZYKRfXMjBkO/MsuNaN8+46fknSAEUcZmAv0tAHGb/wmAnC+CRWfihrVviz5idR+w
         zrH3aUf3jsaoZ7Qw8aCk3c/BTEiJGz6Ta2OWO4MDC5N54ucDzSeDnh1ymwxEtspHtq99
         XUk9EDKkD1dZSDryQy3YsKH0QMzgz15ApsJHHj4K20Nya1+E57fos9HXPx/0o9tzpkwp
         CFLhaZQhfBP9auYiJi/zuxQjrJUOsK2+Wm4va5XKl91Gp5x1Gi27aRbLpj/A//17Eo/r
         vP+ZvbqmxsklGe9JCAAb4KyF59WnCIoSysDGzqkSzmZF+pmXD9cqM3iM5BZhzt5ruavG
         AQfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fWEiMrhNNLJ719TULwow5RTvGaRys/By4SS/CJ5POpM=;
        b=BLeAc0nZBrbTHEIRdxRE9NXhmyKDPzC7sElizaG2ECGx0DBDmg4YZMIzCxwI7tuSAF
         bCihAv/6vzzaUfllI9GUhdciiEX87zdNYbFZ3DdR47bFdcGlM6nrYWLAzviyEubLizek
         OHZSN7DcsnUekxTZKV3JpWAERzFlupGK8pR0EaSctgJCyjcDMPdNlXOE3m6Mju47Kzfg
         cFjB96S5cMC3DzUFTdw6np1tIYAnCfEK741SYFd7SZR1+L/d8HpJs1fiberyAuaY0+VE
         BKx2APpIRUieLgvDIlxNj7JUB+wJRCTEFmmS1ur4UTTkIVLWrI1pj+O5Rnd3GfUbsMce
         PlDw==
X-Gm-Message-State: AOAM530+i5FrIBjqYkQg4cLa6qJ15IrIQT0FslzP3wG/qICIJGL3YciF
	N8RQ4Vp/tfMrv/hCr4iWeWE=
X-Google-Smtp-Source: ABdhPJzEYbsK6AfB7SFM9PqQmLg3DC66wBFumvpHyP+eixIdtogwzaYeNpenMQ4/V83iCpAP8edN7A==
X-Received: by 2002:a54:4f9b:0:b0:2c9:852b:7bdf with SMTP id g27-20020a544f9b000000b002c9852b7bdfmr836967oiy.52.1646242129219;
        Wed, 02 Mar 2022 09:28:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8991:b0:cb:4ac3:641e with SMTP id
 f17-20020a056870899100b000cb4ac3641els6231165oaq.8.gmail; Wed, 02 Mar 2022
 09:28:48 -0800 (PST)
X-Received: by 2002:a05:6870:c888:b0:d4:43c3:ed64 with SMTP id er8-20020a056870c88800b000d443c3ed64mr739604oab.110.1646242128859;
        Wed, 02 Mar 2022 09:28:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646242128; cv=none;
        d=google.com; s=arc-20160816;
        b=pO+ojpxgnf1s3PhFhs+PgsXAiSr2pryzbM5T5a3IcIV+nXHccOX7UnA0dBdD9Hcgqk
         wEfBUX2xQ9GQMNkrIP5FzAYFUMfB/BryEu2ZvX3+upHJl/hKDENMZJuDMtcpj5DSW59N
         TWWR/TiPpsVPUqz8+u24SxU4ivf9XMlikokgSSweOFLCDFrw/CKU8G49fpQTYyRF80tg
         HKVBJFnu1hHrA8xh879ZQghtAMp4jb403tGUHRNTi1s00MnMsfUrHXyRsfNWVFYqqDZl
         Dr6FEUbfPTLSGB4nZ7StLNVq3dLbE26STjjA4Jrpwgyawrnvc35j3gSC3VOjG8O8Hr4b
         jDWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Iq0rZlsMU4r+zqOLQvMXoooXg8dosVQwWXeWcKc1Jjg=;
        b=BvR9ICSYFT6kSJVoNlmg52rGY8xlw2YieUQAm/KLQt4N/eqKBrPqoVvHms5tx62tHj
         appoNisb8uqUjdvvosE+kOyM98tApE1ORf52ucoWjU1VavhZAZANp1o4vkRESPUjJHDq
         51yWRRAii6oZyEUY8dFdRheEtal3xpcMEQp5EbaV75HRM1ffq3rnU1dubl+arMGLwAIJ
         fnXmgQpXquOcd8KlvQjGBQ41Vqcor2sGO0JSbBqi+Td2nmDcwhqyRsrHCy0yAGuFerW9
         7yHPJt39+pklY1ALn5cO/FvXzsvp3DYZA1XJYuzFuPvc9SVeQz6q8BHQXwchVYNdGPZe
         AnyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hoUQHly0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id fr10-20020a056870f80a00b000d85965b19bsi280587oab.3.2022.03.02.09.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:28:48 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id bc10so2287149qtb.5
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:28:48 -0800 (PST)
X-Received: by 2002:ac8:5e4b:0:b0:2dd:dc99:d22b with SMTP id
 i11-20020ac85e4b000000b002dddc99d22bmr24536834qtx.165.1646242128126; Wed, 02
 Mar 2022 09:28:48 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <8682c4558e533cd0f99bdb964ce2fe741f2a9212.1646237226.git.andreyknvl@google.com>
In-Reply-To: <8682c4558e533cd0f99bdb964ce2fe741f2a9212.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:28:12 +0100
Message-ID: <CAG_fn=XJU=GU-1fxbLbJj-tGEo41kJ0HvLRX0EZd3TwNJisrGg@mail.gmail.com>
Subject: Re: [PATCH mm 02/22] kasan: more line breaks in reports
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="00000000000043522105d93f9de0"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hoUQHly0;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as
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

--00000000000043522105d93f9de0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:36 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add a line break after each part that describes the buggy address.
> Improves readability of reports.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kasan/report.c | 7 +++++--
>  1 file changed, 5 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 607a8c2e4674..ded648c0a0e4 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -250,11 +250,13 @@ static void print_address_description(void *addr, u=
8
> tag)
>                 void *object =3D nearest_obj(cache, slab, addr);
>
>                 describe_object(cache, object, addr, tag);
> +               pr_err("\n");
>         }
>
>         if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
>                 pr_err("The buggy address belongs to the variable:\n");
>                 pr_err(" %pS\n", addr);
> +               pr_err("\n");
>         }
>
>         if (is_vmalloc_addr(addr)) {
> @@ -265,6 +267,7 @@ static void print_address_description(void *addr, u8
> tag)
>                                " [%px, %px) created by:\n"
>                                " %pS\n",
>                                va->addr, va->addr + va->size, va->caller)=
;
> +                       pr_err("\n");
>
>                         page =3D vmalloc_to_page(page);
>                 }
> @@ -273,9 +276,11 @@ static void print_address_description(void *addr, u8
> tag)
>         if (page) {
>                 pr_err("The buggy address belongs to the physical
> page:\n");
>                 dump_page(page, "kasan: bad access detected");
> +               pr_err("\n");
>         }
>
>         kasan_print_address_stack_frame(addr);
> +       pr_err("\n");
>  }
>
>  static bool meta_row_is_guilty(const void *row, const void *addr)
> @@ -382,7 +387,6 @@ void kasan_report_invalid_free(void *object, unsigned
> long ip)
>         kasan_print_tags(tag, object);
>         pr_err("\n");
>         print_address_description(object, tag);
> -       pr_err("\n");
>         print_memory_metadata(object);
>         end_report(&flags, (unsigned long)object);
>  }
> @@ -443,7 +447,6 @@ static void __kasan_report(unsigned long addr, size_t
> size, bool is_write,
>
>         if (addr_has_metadata(untagged_addr)) {
>                 print_address_description(untagged_addr,
> get_tag(tagged_addr));
> -               pr_err("\n");
>                 print_memory_metadata(info.first_bad_addr);
>         } else {
>                 dump_stack_lvl(KERN_ERR);
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/8682c4558e533cd0f99bdb964ce2f=
e741f2a9212.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DXJU%3DGU-1fxbLbJj-tGEo41kJ0HvLRX0EZd3TwNJisrGg%40mail.gm=
ail.com.

--00000000000043522105d93f9de0
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
Add a line break after each part that describes the buggy address.<br>
Improves readability of reports.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glide=
r@google.com</a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"=
margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-lef=
t:1ex">
---<br>
=C2=A0mm/kasan/report.c | 7 +++++--<br>
=C2=A01 file changed, 5 insertions(+), 2 deletions(-)<br>
<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index 607a8c2e4674..ded648c0a0e4 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -250,11 +250,13 @@ static void print_address_description(void *addr, u8 =
tag)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 void *object =3D ne=
arest_obj(cache, slab, addr);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 describe_object(cac=
he, object, addr, tag);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quo=
t;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (kernel_or_module_addr(addr) &amp;&amp; !ini=
t_task_stack_addr(addr)) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;The bu=
ggy address belongs to the variable:\n&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot; %pS\n=
&quot;, addr);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quo=
t;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (is_vmalloc_addr(addr)) {<br>
@@ -265,6 +267,7 @@ static void print_address_description(void *addr, u8 ta=
g)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0&quot; [%px, %px) created by:\n&quot;=
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0&quot; %pS\n&quot;,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0va-&gt;addr, va-&gt;addr + va-&gt;siz=
e, va-&gt;caller);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0pr_err(&quot;\n&quot;);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 page =3D vmalloc_to_page(page);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
@@ -273,9 +276,11 @@ static void print_address_description(void *addr, u8 t=
ag)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (page) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;The bu=
ggy address belongs to the physical page:\n&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 dump_page(page, &qu=
ot;kasan: bad access detected&quot;);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quo=
t;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 kasan_print_address_stack_frame(addr);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quot;);<br>
=C2=A0}<br>
<br>
=C2=A0static bool meta_row_is_guilty(const void *row, const void *addr)<br>
@@ -382,7 +387,6 @@ void kasan_report_invalid_free(void *object, unsigned l=
ong ip)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 kasan_print_tags(tag, object);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;\n&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 print_address_description(object, tag);<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 print_memory_metadata(object);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 end_report(&amp;flags, (unsigned long)object);<=
br>
=C2=A0}<br>
@@ -443,7 +447,6 @@ static void __kasan_report(unsigned long addr, size_t s=
ize, bool is_write,<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (addr_has_metadata(untagged_addr)) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 print_address_descr=
iption(untagged_addr, get_tag(tagged_addr));<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quo=
t;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 print_memory_metada=
ta(info.first_bad_addr);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 } else {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 dump_stack_lvl(KERN=
_ERR);<br>
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
om/d/msgid/kasan-dev/8682c4558e533cd0f99bdb964ce2fe741f2a9212.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/8682c4558e533cd0f99bdb964ce2fe741f2a9212.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DXJU%3DGU-1fxbLbJj-tGEo41kJ0HvLRX0EZd3TwNJisrG=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DXJU%3DGU-1fxbLbJj-tGEo41kJ0HvLRX0EZd3T=
wNJisrGg%40mail.gmail.com</a>.<br />

--00000000000043522105d93f9de0--
