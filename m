Return-Path: <kasan-dev+bncBCCMH5WKTMGRBL4XTWIQMGQE7CWV3ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D9044D173B
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 13:27:29 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id x6-20020a9d6d86000000b005b22d043fddsf6359691otp.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 04:27:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646742448; cv=pass;
        d=google.com; s=arc-20160816;
        b=mWzlB/FQSPug+KfF9/Se2etOk4+hZy4spm9LtOdFPemPK9FE54C92cPBtO9QT9JLOi
         +jE2RSoHhDbeYV1fkM/46SSURjkBDeJz19x78gaA1sO/ZrcVKQ1ofvfSHDuwxV6q3k1J
         xIWge1U5qd33IIKzYwJB8SRfo/ecV+NzLxQHR1DyiPBjwK6cGCgWtxZfWLIpx0hH8OKJ
         b779ZZ4sXzJ64/X8W45DMBbs04uIwMDzMSeJXU2zUsEqgIKPn/HKRvboObphsRHS441E
         uch23kj108bYVZL+Mr6ym3rFX//y7oAHm/kzHbzwryWXIkB8V5MSR4WvnEGMaZ3tUykb
         Eu7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xImrbL6YOSAxORtRyxL1AX1Vnv5HuckDNBpv1bLMviQ=;
        b=Sfoh2o50Ns0kOpnW4qaRSlqIlxXl0lrzEL0V+qLDKztvjNOGXnLsHQsdH4jP5jnaMH
         l3uMXEGaORkq5YdQ5jMGKr8m12ZsOpTfk25JjieDTx+D9O9mL5zJqkOf3CTQOUmKQBMz
         XWerk6m9okC5bEgronTuWuFoN725+ToT+9mCl9Nuw2wxT1p65EegmSb4fuWpEZT/Bux7
         TZMvXb5kR6JdR0szEsxoncT12Gt9SYVuAy5r5DbFXbd0mxaKVmNYEdJuiEhGFX0KmeYL
         1RcXK4FONP4OgIHcfPqQxD/0SI9Rj9uBbXxVmmzZ7TZhmGvk3n0YbhPbPXUttAZdtoKJ
         sEgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kYwnMC10;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xImrbL6YOSAxORtRyxL1AX1Vnv5HuckDNBpv1bLMviQ=;
        b=azrkv9bzPiECFUF75LJViUcfV6KkW+RRkdP9MvBClAjHuKC6Pse9PuIFUWX5MiIexe
         0M9+q74OiUAR+aWfc4gPrdJJltwLDh59+Q+EvBakTdJE0Orpz0jE219F+/uDKtCa3Ddq
         st0sYxqs9RsUiYkakBOHrqRYAwEyr2nz6FJ9VjyGRDzfj8gf/RxU7E2823vm0zdc3rUx
         36mos7pnHo4ZEfUrpp0ymAJWBIFbG5Ige6G/gVaB3Uze1/OoS+mIUvj5s+M8GrL8mh5Z
         AlwFZzIGPWIi6Du04mKEtM5yMPZxJ/PI3rY/xYpbjilpl8jl8GI+xYBfU5xJVQSNfNPf
         2TKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xImrbL6YOSAxORtRyxL1AX1Vnv5HuckDNBpv1bLMviQ=;
        b=iL4j87S2ji3RzHHMaNvz4gZ9CF8vd1LkzdvHVVLhmKjTD5K939qOT/XdKsDaOtt6HY
         nnlxoVrHdlrE7iddSyipqtEbQQ7AeBZ1hqS7/P949DxnmTJCqAW1cwYHrk+d3FDnuTjO
         GLtuzwuRwLzEoBxkfY6RWLhWA88MzcU3Eb1gPnx4r59jcYL3KLYkKe4esJdSzUK0HyHt
         +cDhafLH/ADjRXMz48Tx3Mxy4MXTieiIEheN9lb755gq1S0PpbWEpH06CCMOENESYe15
         VwC9qmR+QgEil72RlrXr9S8wDmu+wIDJQ7VqnRn/4Z1myeSB/B0CqMDcyN16DyD2bGPo
         ftRg==
X-Gm-Message-State: AOAM530AMn5KtIBrvxlkaHdUIgqTgSoJ5dgqUMxp9SHTr4fU6bEVfzBc
	6NJWkCyOibQSEa8ivFashBM=
X-Google-Smtp-Source: ABdhPJy92mNF4xsFph/jyNNeMYhiElyOOfo+LrkN0inJHJ06lT/8al7yvLqZykde4hk+UIzmoZS4lQ==
X-Received: by 2002:a05:6808:1148:b0:2d5:2333:bbb1 with SMTP id u8-20020a056808114800b002d52333bbb1mr2411222oiu.130.1646742447909;
        Tue, 08 Mar 2022 04:27:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6017:b0:d7:2052:ce63 with SMTP id
 t23-20020a056870601700b000d72052ce63ls5312661oaa.5.gmail; Tue, 08 Mar 2022
 04:27:27 -0800 (PST)
X-Received: by 2002:a05:6870:a706:b0:d7:5f27:d83d with SMTP id g6-20020a056870a70600b000d75f27d83dmr2239046oam.90.1646742447512;
        Tue, 08 Mar 2022 04:27:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646742447; cv=none;
        d=google.com; s=arc-20160816;
        b=IMmRtc8Imd0BNwwAM7wb2J5u4E77wb/mNoHmU2XoiTvNt3/DOk36GG8eCf3IqF8Xu2
         tlDuECg5kryJpNj2lAjHftt2E/mxV8TK1gUpmC72aC9ibbDQQLyusV2EVeD0WREkq/Gn
         HuQWHrKJ1+oNUM9zQocmll+5dl8pvQ5mt+2sZoFEM8RYAAVyGYlMaesMR4ZHFmTnGbyg
         zzxFsQM8KTM45csEIHxk/x9P4mALMgEwE7QolGwlpcEfAwUwfunuYVixb+Or5fuv4URz
         DR57fAtPpNK1O45SGTPyYzQ4tdMbhW8sELS7OYPKV/uAScsJNeauhUn4BhEBEMwppyG1
         VWKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hTAK4h6I/f4aYr0uuTBK/wljPedCHuRUgXIuqUwShxc=;
        b=xSfcSPLXnH0F0HSFU8AlLXZBvAGWyQh1G+h63VrqjEmMc63Nr7h6U+K6+9aOKidbb4
         L75ZP6TM89oKftItbvkwva3YWbSFj8K9U84/k6vIPdDXyTtY0W12wF5+NyBxWJztQzEm
         YSVp9yF6fywoMYIRziENdVFz+qKQFISfDWNQn6Rqf9ylBlPDplmro3Z0yLgdXX6jl5+R
         AweMcAivKSSki1fJPRH/IbLF2zeRmQycl3XXV+PHX5n5cMLC4s6o6/6etJBo4gYXUPoQ
         20EewTPst+8aafKuDbIpoLVzAtQWfJpu7UZDPEpRfZNrx3cX6+1EAXa2t9H2D5rlnvOM
         82tQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kYwnMC10;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id p12-20020a9d4e0c000000b005afaa717a2bsi1863975otf.2.2022.03.08.04.27.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 04:27:27 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id v189so5642767qkd.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 04:27:27 -0800 (PST)
X-Received: by 2002:ae9:f712:0:b0:609:4803:51c1 with SMTP id
 s18-20020ae9f712000000b00609480351c1mr9590919qkg.745.1646742446754; Tue, 08
 Mar 2022 04:27:26 -0800 (PST)
MIME-Version: 1.0
References: <20220308122023.3068150-1-elver@google.com>
In-Reply-To: <20220308122023.3068150-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Mar 2022 13:26:50 +0100
Message-ID: <CAG_fn=X4JbFSHa1155CJasnH-4ECsqPijoT3WjYHAmJzK=AwFg@mail.gmail.com>
Subject: Re: [PATCH] kfence: allow use of a deferrable timer
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: multipart/alternative; boundary="00000000000093d64005d9b41a88"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kYwnMC10;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
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

--00000000000093d64005d9b41a88
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Tue, Mar 8, 2022 at 1:20 PM Marco Elver <elver@google.com> wrote:

> Allow the use of a deferrable timer, which does not force CPU wake-ups
> when the system is idle. A consequence is that the sample interval
> becomes very unpredictable, to the point that it is not guaranteed that
> the KFENCE KUnit test still passes.
>
> Nevertheless, on power-constrained systems this may be preferable, so
> let's give the user the option should they accept the above trade-off.
>
> Signed-off-by: Marco Elver <elver@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>


> ---
>  lib/Kconfig.kfence | 12 ++++++++++++
>  mm/kfence/core.c   | 15 +++++++++++++--
>  2 files changed, 25 insertions(+), 2 deletions(-)
>
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 912f252a41fc..1cf2ea2a1ac7 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -45,6 +45,18 @@ config KFENCE_NUM_OBJECTS
>           pages are required; with one containing the object and two
> adjacent
>           ones used as guard pages.
>
> +config KFENCE_DEFERRABLE
> +       bool "Use a deferrable timer to trigger allocations" if EXPERT
> +       help
> +         Use a deferrable timer to trigger allocations. This avoids
> forcing
> +         CPU wake-ups if the system is idle, at the risk of a less
> predictable
> +         sample interval.
> +
> +         Warning: The KUnit test suite fails with this option enabled -
> due to
> +         the unpredictability of the sample interval!
> +
> +         Say N if you are unsure.
> +
>  config KFENCE_STATIC_KEYS
>         bool "Use static keys to set up allocations" if EXPERT
>         depends on JUMP_LABEL
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index f126b53b9b85..451277b41bfb 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -95,6 +95,10 @@ module_param_cb(sample_interval,
> &sample_interval_param_ops, &kfence_sample_inte
>  static unsigned long kfence_skip_covered_thresh __read_mostly =3D 75;
>  module_param_named(skip_covered_thresh, kfence_skip_covered_thresh,
> ulong, 0644);
>
> +/* If true, use a deferrable timer at the risk of unpredictable sample
> intervals. */
> +static bool kfence_deferrable __read_mostly =3D
> IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
> +module_param_named(deferrable, kfence_deferrable, bool, 0444);
>
Could you please add a line or two to Documentation/dev-tools/kfence.rst as
well?


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
kasan-dev/CAG_fn%3DX4JbFSHa1155CJasnH-4ECsqPijoT3WjYHAmJzK%3DAwFg%40mail.gm=
ail.com.

--00000000000093d64005d9b41a88
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Tue, Mar 8, 2022 at 1:20 PM Marco =
Elver &lt;<a href=3D"mailto:elver@google.com">elver@google.com</a>&gt; wrot=
e:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0=
.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">Allow the use=
 of a deferrable timer, which does not force CPU wake-ups<br>
when the system is idle. A consequence is that the sample interval<br>
becomes very unpredictable, to the point that it is not guaranteed that<br>
the KFENCE KUnit test still passes.<br>
<br>
Nevertheless, on power-constrained systems this may be preferable, so<br>
let&#39;s give the user the option should they accept the above trade-off.<=
br>
<br>
Signed-off-by: Marco Elver &lt;<a href=3D"mailto:elver@google.com" target=
=3D"_blank">elver@google.com</a>&gt;<br></blockquote><div>Reviewed-by: Alex=
ander Potapenko &lt;<a href=3D"mailto:glider@google.com">glider@google.com<=
/a>&gt;</div><div>=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"ma=
rgin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:=
1ex">
---<br>
=C2=A0lib/Kconfig.kfence | 12 ++++++++++++<br>
=C2=A0mm/kfence/core.c=C2=A0 =C2=A0| 15 +++++++++++++--<br>
=C2=A02 files changed, 25 insertions(+), 2 deletions(-)<br>
<br>
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence<br>
index 912f252a41fc..1cf2ea2a1ac7 100644<br>
--- a/lib/Kconfig.kfence<br>
+++ b/lib/Kconfig.kfence<br>
@@ -45,6 +45,18 @@ config KFENCE_NUM_OBJECTS<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 pages are required; with one containing =
the object and two adjacent<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ones used as guard pages.<br>
<br>
+config KFENCE_DEFERRABLE<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0bool &quot;Use a deferrable timer to trigger al=
locations&quot; if EXPERT<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0help<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Use a deferrable timer to trigger alloca=
tions. This avoids forcing<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0CPU wake-ups if the system is idle, at t=
he risk of a less predictable<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0sample interval.<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Warning: The KUnit test suite fails with=
 this option enabled - due to<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0the unpredictability of the sample inter=
val!<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0Say N if you are unsure.<br>
+<br>
=C2=A0config KFENCE_STATIC_KEYS<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 bool &quot;Use static keys to set up allocation=
s&quot; if EXPERT<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 depends on JUMP_LABEL<br>
diff --git a/mm/kfence/core.c b/mm/kfence/core.c<br>
index f126b53b9b85..451277b41bfb 100644<br>
--- a/mm/kfence/core.c<br>
+++ b/mm/kfence/core.c<br>
@@ -95,6 +95,10 @@ module_param_cb(sample_interval, &amp;sample_interval_pa=
ram_ops, &amp;kfence_sample_inte<br>
=C2=A0static unsigned long kfence_skip_covered_thresh __read_mostly =3D 75;=
<br>
=C2=A0module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, u=
long, 0644);<br>
<br>
+/* If true, use a deferrable timer at the risk of unpredictable sample int=
ervals. */<br>
+static bool kfence_deferrable __read_mostly =3D IS_ENABLED(CONFIG_KFENCE_D=
EFERRABLE);<br>
+module_param_named(deferrable, kfence_deferrable, bool, 0444);<br></blockq=
uote><div>Could you please add a line or two to=C2=A0Documentation/dev-tool=
s/kfence.rst as well?</div><div><br></div></div><div><br></div>-- <br><div =
dir=3D"ltr" class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<=
br>Software Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, =
33<br>80636 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Li=
ana Sebastian<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz de=
r Gesellschaft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie dies=
e f=C3=A4lschlicherweise erhalten haben sollten, leiten Sie diese bitte nic=
ht an jemand anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge =
davon und lassen Sie mich bitte wissen, dass die E-Mail an die falsche Pers=
on gesendet wurde. <br><br>=C2=A0 =C2=A0 =C2=A0<br><br>This e-mail is confi=
dential. If you received this communication by mistake, please don&#39;t fo=
rward it to anyone else, please erase all copies and attachments, and pleas=
e let me know that it has gone to the wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DX4JbFSHa1155CJasnH-4ECsqPijoT3WjYHAmJzK%3DAwF=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DX4JbFSHa1155CJasnH-4ECsqPijoT3WjYHAmJz=
K%3DAwFg%40mail.gmail.com</a>.<br />

--00000000000093d64005d9b41a88--
