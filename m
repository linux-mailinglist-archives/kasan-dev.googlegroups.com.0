Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGWT72IAMGQEE6AA7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 256364CABC7
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:30:04 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id s67-20020a25aa49000000b00628b76f6148sf690010ybi.10
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:30:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646242202; cv=pass;
        d=google.com; s=arc-20160816;
        b=bp3ILa+wz0aJmTwZHhCT9s1N2RzP0h13riJxiRQ6w+sKifnihQbnjfcss7I28SNwHZ
         G77O3U8JZqrH8feqTRRV5DkXIC0T9qwGRh4eftae1nhmZGb4mDNhuX9S3ebEbnW4h85x
         MbL3WgRrBZGrO0/UCZJV3jUrXbe17Txy9/dOYWwl1AP2oOElSJR/bLcfB4CHM6NWeJFg
         O5lrduu9EaWOCpwbInk9z1FCVLkgS/tzxVwcRf0Yxrqxwy1tun0cX2esX97gRpJHpJOL
         n6v0kbZqIXV+11lOJlIrNYw56Ozh2FAS8iTmEBLc55ttMMvITsNw2usTNuqcsE9qq2Ou
         Qgaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TJSjyFB0uwWA/G0qtykmQEQ44r/iMOOpgHjvExp1UY8=;
        b=E+V03y91fky29ngGR1meCSeo/KvYAw//y6CmlPFLQH8ZU4aeoRZpdNezFnQIiZ32fB
         SKkShshaJOsKojmX/51QSoZ7xhyN1EQtPdcbsO5aFlNXZYedSZfErQLW68Ckbo0kszHx
         m+JJ6yEfRuguvnOqsdb6t1HWTYNI7XfpYe17kUzDILs69YIxfc0w7Vh4eN8rAqWuWitz
         R7wCyK3N1ArYLj9XYdoT3dtAtjq0uHZetdXFpQYpFLXYpXhThEoN7ZwkUKrMSpfyHvZu
         LdgjHtW48mex5JECResS6KI9NCzX3twVHdYeswISdLSTsfw7wz1SPJDjzic7pM/FjaJF
         YXBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eusAHOKu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJSjyFB0uwWA/G0qtykmQEQ44r/iMOOpgHjvExp1UY8=;
        b=imAKQVcungGZkeV6eGv6p9aW/vMLKyjtEzbXCruRUFu9rwJxmah65NpJ+6jmdzJ1AY
         AXmBB+YiW0AhIxcIsRZSC2FuvltP9zQwxeTgd/5UTH4xGz+IAr0A5CW4ygDonQUd1vak
         MjkldLvN2VsJiGMMHtrto6VdGSpmNBCnd0R43fM3Hz64zQpfk3Shsz1/c0ZFQ+5qOh1E
         kpm3j4W3PJhpJUM8hhsLCC2J5VzKkQKUn3X7yZmRWbuOeEo2s/piRPk0o4allLzQ7URx
         FBHardHC3D+DVokuUiClrL7G6ybfwEzX/ag7Oqe8YMofCXQfZ2S5t2k+AkvJnoTwcMGs
         46lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJSjyFB0uwWA/G0qtykmQEQ44r/iMOOpgHjvExp1UY8=;
        b=uFqG59E5RIhXwSkg6k6BHpzM+nSR57Q4TLlYWAB9ONjAAqnJL7sQWATeQvirVWKbXG
         Xkgy4+XZJXT9OjeBygHtdRtom3wrRWPsG2zFhel82KtGJ4UhqsWGQuN9rrFHVNf0/xNT
         +OkQrrgWnT0lUfFS1JyDcJJtzQaALEKZKUFax2DQ5gFhSqPrpGEbXID8vD1lOOIO2nUK
         H1C5KlU7Vg7iRsDCbcMSCHLMNu65K3EPYhyKpT+LEDOCp+kNvEKbZMgkAcg5TI45MYTM
         iqgg4nJGMYglgEQ4jgEBJ74/PhWJycy+y1FcqAAyDrrp9kwxgAz22dj0WVmzZ16n0DV1
         C64w==
X-Gm-Message-State: AOAM5316cE8kgoWcsRqaIq5k2qWwiUW6rRXApsvZBOt2VIK6KSlIEBLc
	/EOsK7eYRLMXEbCAuHVSEFQ=
X-Google-Smtp-Source: ABdhPJy4GzlPtRZLlgM/Kw6KNODm1mGjX9+oIb+Hy7g6FsdG3e7Yz/lCSMfRyR7tKvjK2b9GpwwKdQ==
X-Received: by 2002:a81:1c47:0:b0:2d7:5822:1739 with SMTP id c68-20020a811c47000000b002d758221739mr31488375ywc.502.1646242202768;
        Wed, 02 Mar 2022 09:30:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:3d1:b0:628:68d6:9466 with SMTP id
 g17-20020a05690203d100b0062868d69466ls5549344ybs.10.gmail; Wed, 02 Mar 2022
 09:30:02 -0800 (PST)
X-Received: by 2002:a5b:1cc:0:b0:625:2da3:cb6d with SMTP id f12-20020a5b01cc000000b006252da3cb6dmr28640924ybp.296.1646242202148;
        Wed, 02 Mar 2022 09:30:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646242202; cv=none;
        d=google.com; s=arc-20160816;
        b=sxWC4UH/MnYxDDeyAIwDPaw/KqbwROncymiKhMXaA295KsPIAJbDaC+zSdxu/agf9w
         9lQa8cc5D9D79oT7zh/xYVPqEDtrTdk1ZXrTy7hNzKuy46WXvZGEiYSMaM/O9PqpiC0H
         PSy80GXckb78L5uTI2cnCimGYq/WxPlLDDfwbcAWT9jASf2iigSbiLYPLFwh+HEAKZcf
         gRZGaIQB/9/0Y0q7y+IwzpBK827L+gCVRLVoPYpUorKPgWpWbRNNV8qDa3QuNfS3ExBg
         erhQmi73kxXRli5fQxElp+jSxbKDOxaSEmqgcjMTIKMIBy3ne6Wbeac16QFT0V2CpZYi
         sgGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OLg2W0bKVEV676ftdFrveZxXudZ89DnOZdQYznwvXt0=;
        b=IFj/LhPwxbLb6SN6A92ga5eisrXbswmhrVy1L3sV8gjmJ+64KEC8hiHrMqBKtIVbSB
         yEe3/9brIapZ2VWOkTT3e0Dps4NUt4nntw0qo8gwXq3wcyyeAyroHZz1tzvh4yvS2KEm
         kC0yuYYt2RHY3dNd0uEiRgoiE5fK7k/bY4B6qfaxeOgmIHHezkld30fbxHLuTBhFBBTV
         Rod4ryzTkB466uwSDwBqPIx6T+YGwZMHbkEXlnp6TLh43LuRCnBYuqAQVZu6xRbCKVou
         62KcCgXmFYW/+JBrSLAlx4AgONOHv2KrmpD52rgugKoX68kJBCHz5xiRhLHhYMesPULT
         GXUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eusAHOKu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id bg7-20020a05690c030700b002d7da374fa6si1459667ywb.2.2022.03.02.09.30.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:30:02 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id b23so2285208qtt.6
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:30:02 -0800 (PST)
X-Received: by 2002:a05:622a:1709:b0:2de:821:b3e2 with SMTP id
 h9-20020a05622a170900b002de0821b3e2mr24574927qtk.578.1646242201642; Wed, 02
 Mar 2022 09:30:01 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <1ee113a4c111df97d168c820b527cda77a3cac40.1646237226.git.andreyknvl@google.com>
In-Reply-To: <1ee113a4c111df97d168c820b527cda77a3cac40.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:29:25 +0100
Message-ID: <CAG_fn=VadWpZst5Vrvr-5h2L=zN9Jh=+17SnAUw96zDsUSV6vw@mail.gmail.com>
Subject: Re: [PATCH mm 03/22] kasan: rearrange stack frame info in reports
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="000000000000a533c905d93fa1c4"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eusAHOKu;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82f as
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

--000000000000a533c905d93fa1c4
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:36 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> - Move printing stack frame info before printing page info.
>
> - Add object_is_on_stack() check to print_address_description()
>   and add a corresponding WARNING to kasan_print_address_stack_frame().
>   This looks more in line with the rest of the checks in this function
>   and also allows to avoid complicating code logic wrt line breaks.
>
> - Clean up comments related to get_address_stack_frame_info().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kasan/report.c         | 12 +++++++++---
>  mm/kasan/report_generic.c | 15 ++++-----------
>  2 files changed, 13 insertions(+), 14 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index ded648c0a0e4..d60ee8b81e2b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -259,6 +259,15 @@ static void print_address_description(void *addr, u8
> tag)
>                 pr_err("\n");
>         }
>
> +       if (object_is_on_stack(addr)) {
> +               /*
> +                * Currently, KASAN supports printing frame information
> only
> +                * for accesses to the task's own stack.
> +                */
> +               kasan_print_address_stack_frame(addr);
> +               pr_err("\n");
> +       }
> +
>         if (is_vmalloc_addr(addr)) {
>                 struct vm_struct *va =3D find_vm_area(addr);
>
> @@ -278,9 +287,6 @@ static void print_address_description(void *addr, u8
> tag)
>                 dump_page(page, "kasan: bad access detected");
>                 pr_err("\n");
>         }
> -
> -       kasan_print_address_stack_frame(addr);
> -       pr_err("\n");
>  }
>
>  static bool meta_row_is_guilty(const void *row, const void *addr)
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 139615ef326b..3751391ff11a 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -211,6 +211,7 @@ static void print_decoded_frame_descr(const char
> *frame_descr)
>         }
>  }
>
> +/* Returns true only if the address is on the current task's stack. */
>  static bool __must_check get_address_stack_frame_info(const void *addr,
>                                                       unsigned long
> *offset,
>                                                       const char
> **frame_descr,
> @@ -224,13 +225,6 @@ static bool __must_check
> get_address_stack_frame_info(const void *addr,
>
>         BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
>
> -       /*
> -        * NOTE: We currently only support printing frame information for
> -        * accesses to the task's own stack.
> -        */
> -       if (!object_is_on_stack(addr))
> -               return false;
> -
>         aligned_addr =3D round_down((unsigned long)addr, sizeof(long));
>         mem_ptr =3D round_down(aligned_addr, KASAN_GRANULE_SIZE);
>         shadow_ptr =3D kasan_mem_to_shadow((void *)aligned_addr);
> @@ -269,14 +263,13 @@ void kasan_print_address_stack_frame(const void
> *addr)
>         const char *frame_descr;
>         const void *frame_pc;
>
> +       if (WARN_ON(!object_is_on_stack(addr)))
> +               return;
> +
>         if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
>                                           &frame_pc))
>                 return;
>
> -       /*
> -        * get_address_stack_frame_info only returns true if the given
> addr is
> -        * on the current task's stack.
> -        */
>         pr_err("\n");
>         pr_err("addr %px is located in stack of task %s/%d at offset %lu
> in frame:\n",
>                addr, current->comm, task_pid_nr(current), offset);
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/1ee113a4c111df97d168c820b527c=
da77a3cac40.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DVadWpZst5Vrvr-5h2L%3DzN9Jh%3D%2B17SnAUw96zDsUSV6vw%40mai=
l.gmail.com.

--000000000000a533c905d93fa1c4
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
- Move printing stack frame info before printing page info.<br>
<br>
- Add object_is_on_stack() check to print_address_description()<br>
=C2=A0 and add a corresponding WARNING to kasan_print_address_stack_frame()=
.<br>
=C2=A0 This looks more in line with the rest of the checks in this function=
<br>
=C2=A0 and also allows to avoid complicating code logic wrt line breaks.<br=
>
<br>
- Clean up comments related to get_address_stack_frame_info().<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glide=
r@google.com</a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"=
margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-lef=
t:1ex">
---<br>
=C2=A0mm/kasan/report.c=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0| 12 +++++++++---<=
br>
=C2=A0mm/kasan/report_generic.c | 15 ++++-----------<br>
=C2=A02 files changed, 13 insertions(+), 14 deletions(-)<br>
<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index ded648c0a0e4..d60ee8b81e2b 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -259,6 +259,15 @@ static void print_address_description(void *addr, u8 t=
ag)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;\n&quo=
t;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (object_is_on_stack(addr)) {<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * Currently, KASAN=
 supports printing frame information only<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * for accesses to =
the task&#39;s own stack.<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0kasan_print_address=
_stack_frame(addr);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quo=
t;);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0}<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (is_vmalloc_addr(addr)) {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 struct vm_struct *v=
a =3D find_vm_area(addr);<br>
<br>
@@ -278,9 +287,6 @@ static void print_address_description(void *addr, u8 ta=
g)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 dump_page(page, &qu=
ot;kasan: bad access detected&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;\n&quo=
t;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
-<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0kasan_print_address_stack_frame(addr);<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quot;);<br>
=C2=A0}<br>
<br>
=C2=A0static bool meta_row_is_guilty(const void *row, const void *addr)<br>
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c<br>
index 139615ef326b..3751391ff11a 100644<br>
--- a/mm/kasan/report_generic.c<br>
+++ b/mm/kasan/report_generic.c<br>
@@ -211,6 +211,7 @@ static void print_decoded_frame_descr(const char *frame=
_descr)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 }<br>
=C2=A0}<br>
<br>
+/* Returns true only if the address is on the current task&#39;s stack. */=
<br>
=C2=A0static bool __must_check get_address_stack_frame_info(const void *add=
r,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 unsigned long *offset,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 const char **frame_descr,<br>
@@ -224,13 +225,6 @@ static bool __must_check get_address_stack_frame_info(=
const void *addr,<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));=
<br>
<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 * NOTE: We currently only support printing fra=
me information for<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 * accesses to the task&#39;s own stack.<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!object_is_on_stack(addr))<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return false;<br>
-<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 aligned_addr =3D round_down((unsigned long)addr=
, sizeof(long));<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 mem_ptr =3D round_down(aligned_addr, KASAN_GRAN=
ULE_SIZE);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 shadow_ptr =3D kasan_mem_to_shadow((void *)alig=
ned_addr);<br>
@@ -269,14 +263,13 @@ void kasan_print_address_stack_frame(const void *addr=
)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 const char *frame_descr;<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 const void *frame_pc;<br>
<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (WARN_ON(!object_is_on_stack(addr)))<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return;<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (!get_address_stack_frame_info(addr, &amp;of=
fset, &amp;frame_descr,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 &=
amp;frame_pc))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 return;<br>
<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 * get_address_stack_frame_info only returns tr=
ue if the given addr is<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 * on the current task&#39;s stack.<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 */<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;\n&quot;);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;addr %px is located in stack of ta=
sk %s/%d at offset %lu in frame:\n&quot;,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0addr, current-&gt;co=
mm, task_pid_nr(current), offset);<br>
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
om/d/msgid/kasan-dev/1ee113a4c111df97d168c820b527cda77a3cac40.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/1ee113a4c111df97d168c820b527cda77a3cac40.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DVadWpZst5Vrvr-5h2L%3DzN9Jh%3D%2B17SnAUw96zDsU=
SV6vw%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CAG_fn%3DVadWpZst5Vrvr-5h2L%3DzN9Jh%3D%2B17=
SnAUw96zDsUSV6vw%40mail.gmail.com</a>.<br />

--000000000000a533c905d93fa1c4--
