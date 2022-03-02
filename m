Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIGU72IAMGQE5FBPBCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 636F04CAC00
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:32:17 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id a3-20020acab103000000b002d4be2314a2sf1420504oif.14
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:32:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646242336; cv=pass;
        d=google.com; s=arc-20160816;
        b=ha0YrdmqqHh9bamAHo6UKVydIwV9+B8MY5pCOkSMe+5JvswbUePqR3J7XERrx4shb+
         6xUxIjRIUfbGcl0JMaEsA+QR3ATHhIzJTmH/m4LpwYQjYqFZ6eU8KOdyCJiV6SFU6d+S
         Qc6zkgzbxhplXWFA8Yi3rIo95lbj7iy2eU4a548lfHmhPqA592d/pjBnAHaEjEwzgQCS
         26NQ9QSuiCqB4HT4QATSxvZXk25bKDVsW1C0AzUkDwilcbj2R0OK1TBdsmFDTbJZ2lz4
         YU4/XJOkVryudkP9fMkgOac8a4JSyEhui2sr4+97AzcvS0H0+Z46iE9JSd4/YrUVNAN3
         0zfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=p1Y7dtGrNRgo7daoTSQ0hfb44O7CMMON08dBtXwTXwg=;
        b=K3hwMIhuYcHvyPtnNgzhOskqonK0n3gKMPtVtUIeeJI2Oq7GSctJm42zfbUAjF+eyo
         7bgkXtxNFrzqJWR/p7koIQ/RlTBrtC4anntgGzOp5zVp3un8pB5Fxxhu/GdKoaxiBTYM
         kdOwnVg+CiOWE0CUHAfCiAWXUeIMdBtHSsJDL2G9oX56FIfNEmgaR21ysMnV50Ay0le5
         cUO3taP9ltJtaYxOhTfhuH44R2gTq7qkitDlWOKyL/Ho9wy0UeTyTXn7jCLj6gBe7ka0
         2hX2BjTRHLL5Jt9KXCLEm9QHEQzvmBvDnW07PtORq2ZSA932PRddJjd7Q6ilxqRLNx5l
         Amhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rnKI3HVR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p1Y7dtGrNRgo7daoTSQ0hfb44O7CMMON08dBtXwTXwg=;
        b=ggKCBRCXTZtLm3rC9Hsrp/TqToCFzx9f/Rb4k2SHNcaWqJlfOawOGsWbSWiDt5L3k9
         00i8HqOCkREAIw03K5oAhjWK75WKLUYng0wyK3RIqwf6RXdg0MxIeA2VifCjpYsHVrMj
         smXwjyCTXriytI/7/1EEGYUvCdxlXlPtQNP258uRtri7TS0lk4j+Pr/I+4W3mlEhEPSj
         Ax/U1cCwAzkNXcFP6v325WBCppHDSRwtcOWCq4r7Hp1BRNwv43W+GtSilW8fT7Ga8hYK
         471sNkkHg2gMmB409oMTQLWY5Hc6XSQTS2or0JS3/Hf7UvOK9M46fpTprbCvaPcxMgF6
         TDBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p1Y7dtGrNRgo7daoTSQ0hfb44O7CMMON08dBtXwTXwg=;
        b=dvFCsFOhyyKQrB2/1mJD+yY25Gk9viCHoy96CI1V3SJRsMzkD/JQWwtjIqJVTxlKZj
         gP7T5EvXH5oxOYZYMpneyO95AEneVzJ22wuSAiwYfg7TURoAs5HGtbbV13YsXIgRcr16
         xKw4/ar3MWkHUXBvhPVT/GlNNVV1MJmnklpEDVjl5Zv5nVjC69mJZ56gHC8p5DymOtHw
         OqHFHiU2mL7RgLc129IK0u8e91enkaRpkwLPBmXzL+KSvgdxBen6smjML8f58E47UfD6
         rz0DDchFpnV15ux2OkiMEgboKdP1TI2q96y0I9gxEzlJy76XGhfwCsyL+DcFx8qrwL5X
         +GtA==
X-Gm-Message-State: AOAM533rW8T/zGReZo2nNZJy1nsf9iVUnLuUPHJSVzBfcwWTj3m1BpXD
	Gn0aN677e/Lswibb6/RmG20=
X-Google-Smtp-Source: ABdhPJyS2wvA8bWFwNfMuiJZDrmn6SI5ePrY5fAYHt+nUSHqtR7OWbD80+IDjrkv8LmmOxOwnR1TyQ==
X-Received: by 2002:a05:6870:7c0c:b0:d6:c338:f5c3 with SMTP id je12-20020a0568707c0c00b000d6c338f5c3mr731350oab.63.1646242336362;
        Wed, 02 Mar 2022 09:32:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a1a0:b0:d7:1d2b:ec1a with SMTP id
 a32-20020a056870a1a000b000d71d2bec1als2917245oaf.3.gmail; Wed, 02 Mar 2022
 09:32:16 -0800 (PST)
X-Received: by 2002:a05:6870:8290:b0:d7:d88:7112 with SMTP id q16-20020a056870829000b000d70d887112mr726528oae.29.1646242335994;
        Wed, 02 Mar 2022 09:32:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646242335; cv=none;
        d=google.com; s=arc-20160816;
        b=veiVapp3Bm+MfHPfr7C8mp/AOxePriI8qqVZX307FmnfxJfwV9wSkboZu8nB0vhNft
         za7gbsR6r5eq853VuwLnjwLQO1LMGmv4ykPQcsMFAbda6P1DV62v5LHWR4gcXUKAQhIT
         Mbrqvi5b8aw0fFNJcZr/iiZ1IZrplY1aQ5sdgTpjk6GpYiW5kSyVOqtr9UgW3QOV0j01
         U9vj28Di6mbd3DgMhaLLz9xVOUfWpsAiHuEEfdxb5ubND8Ai5QscvMcrWpusBp6xIPLX
         MtK/b72XPnUd7C2TA+Q90FhtWXdmEkFXjg88y9syLCwRaNMsS3YN11xyFSIUTGANJ9h2
         Rftw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pIaLDYhEVyUGyAhkP9rhY6u4SsthLEVULPqNPjpQ14g=;
        b=c7LtjRkXuTT6Ovfd+jxw+CBQmqscuwHZOJVCSXIGSaX+9cIHFRm7SopBMc1zKCi62y
         /Ydl4gBSYeyYM3ASRW237w1PEQ4560jvPRo9na9mT2Zpm/qcq/lzeBWDbljcmktxCwiv
         U6JhENg4IuDNxHsO+8gnmePM1PCm5k4kGlLUlWA2GS+QSIy9I2L206QCGi7PeeLxGROp
         vkdnHvxiGECbUZ3SNGYYXCXmdlcDGjxrNu3Totw9AtgDzE2tWwNEU1ZsRF9+zW9w4068
         XuqL1XpRMk8knDOlDGhwghF9Xbwtpb/HtDxQQ74DVxwbrNtCrqnhfHzWwEN83YoSPXVI
         0wGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rnKI3HVR;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id y24-20020a056830071800b005af3a0effdfsi2588225ots.0.2022.03.02.09.32.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:32:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id g24so1890065qkl.3
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:32:15 -0800 (PST)
X-Received: by 2002:a37:a505:0:b0:60d:df5e:16c7 with SMTP id
 o5-20020a37a505000000b0060ddf5e16c7mr17131417qke.448.1646242335286; Wed, 02
 Mar 2022 09:32:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <aa613f097c12f7b75efb17f2618ae00480fb4bc3.1646237226.git.andreyknvl@google.com>
In-Reply-To: <aa613f097c12f7b75efb17f2618ae00480fb4bc3.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:31:39 +0100
Message-ID: <CAG_fn=VzWe6eMbgWNE5wbp9p+NQhS87DULPoXmDWQV7Fk9KFLw@mail.gmail.com>
Subject: Re: [PATCH mm 04/22] kasan: improve stack frame info in reports
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="0000000000009c7f1705d93fa9f5"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rnKI3HVR;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as
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

--0000000000009c7f1705d93fa9f5
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:36 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> - Print at least task name and id for reports affecting allocas
>   (get_address_stack_frame_info() does not support them).
>
> - Capitalize first letter of each sentence.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kasan/report_generic.c | 9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 3751391ff11a..7e03cca569a7 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -180,7 +180,7 @@ static void print_decoded_frame_descr(const char
> *frame_descr)
>                 return;
>
>         pr_err("\n");
> -       pr_err("this frame has %lu %s:\n", num_objects,
> +       pr_err("This frame has %lu %s:\n", num_objects,
>                num_objects =3D=3D 1 ? "object" : "objects");
>
>         while (num_objects--) {
> @@ -266,13 +266,14 @@ void kasan_print_address_stack_frame(const void
> *addr)
>         if (WARN_ON(!object_is_on_stack(addr)))
>                 return;
>
> +       pr_err("The buggy address belongs to stack of task %s/%d\n",
> +              current->comm, task_pid_nr(current));
> +
>         if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
>                                           &frame_pc))
>                 return;
>
> -       pr_err("\n");
> -       pr_err("addr %px is located in stack of task %s/%d at offset %lu
> in frame:\n",
> -              addr, current->comm, task_pid_nr(current), offset);
> +       pr_err(" and is located at offset %lu in frame:\n", offset);
>         pr_err(" %pS\n", frame_pc);
>
>         if (!frame_descr)
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/aa613f097c12f7b75efb17f2618ae=
00480fb4bc3.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DVzWe6eMbgWNE5wbp9p%2BNQhS87DULPoXmDWQV7Fk9KFLw%40mail.gm=
ail.com.

--0000000000009c7f1705d93fa9f5
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
- Print at least task name and id for reports affecting allocas<br>
=C2=A0 (get_address_stack_frame_info() does not support them).<br>
<br>
- Capitalize first letter of each sentence.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glide=
r@google.com</a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"=
margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-lef=
t:1ex">
---<br>
=C2=A0mm/kasan/report_generic.c | 9 +++++----<br>
=C2=A01 file changed, 5 insertions(+), 4 deletions(-)<br>
<br>
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c<br>
index 3751391ff11a..7e03cca569a7 100644<br>
--- a/mm/kasan/report_generic.c<br>
+++ b/mm/kasan/report_generic.c<br>
@@ -180,7 +180,7 @@ static void print_decoded_frame_descr(const char *frame=
_descr)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 return;<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;\n&quot;);<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;this frame has %lu %s:\n&quot;, nu=
m_objects,<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;This frame has %lu %s:\n&quot;, nu=
m_objects,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0num_objects =3D=3D 1=
 ? &quot;object&quot; : &quot;objects&quot;);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 while (num_objects--) {<br>
@@ -266,13 +266,14 @@ void kasan_print_address_stack_frame(const void *addr=
)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (WARN_ON(!object_is_on_stack(addr)))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 return;<br>
<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;The buggy address belongs to stack=
 of task %s/%d\n&quot;,<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 current-&gt;comm, task_pi=
d_nr(current));<br>
+<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (!get_address_stack_frame_info(addr, &amp;of=
fset, &amp;frame_descr,<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 &=
amp;frame_pc))<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 return;<br>
<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;\n&quot;);<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;addr %px is located in stack of ta=
sk %s/%d at offset %lu in frame:\n&quot;,<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 addr, current-&gt;comm, t=
ask_pid_nr(current), offset);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot; and is located at offset %lu in f=
rame:\n&quot;, offset);<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot; %pS\n&quot;, frame_pc);<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (!frame_descr)<br>
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
om/d/msgid/kasan-dev/aa613f097c12f7b75efb17f2618ae00480fb4bc3.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/aa613f097c12f7b75efb17f2618ae00480fb4bc3.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DVzWe6eMbgWNE5wbp9p%2BNQhS87DULPoXmDWQV7Fk9KFL=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DVzWe6eMbgWNE5wbp9p%2BNQhS87DULPoXmDWQV=
7Fk9KFLw%40mail.gmail.com</a>.<br />

--0000000000009c7f1705d93fa9f5--
