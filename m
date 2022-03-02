Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPGV72IAMGQE5MLQR4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id EA7B14CAC33
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:34:53 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id b20-20020a170902d89400b0015171e56800sf1353677plz.5
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:34:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646242492; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzjxzDJuRSr4pgLovw7wpTXLBxXMpwmiWAVS2CljA1aAObiB7zzR/41fahgsp5xP5p
         lubhT7BsjnLhKIruM3GERPMfo5OqYvOZSdsgAmhDmR31fxwJUaEJId4XHJirJY8Z175N
         MidighrNZAg+9zwtGPatJnjds8WrV3EgMnD52VsWhMF4jmBMgBd+hKL43ZJ5Zkrn3jlm
         FxIc/uEXlODrD//+pe7DIJN1zkEc3mtfnrklL3+OI1pqpO5MOQs9G1QgtlMfoCM7JOcl
         9Nnqh/y/78mDIeky8tNvCeMr9GwysNaa60Vk+myNf99YmQYc5n2a+jSWzKXTKFN9jCwE
         2MGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DtB8cFj63kkbYlLPXve3Ea/D9yZCrh6MKed+8wlDStc=;
        b=biDtixnxTkO+Y/oF/xqt7bRJ2jkNzZmTag3Z77BIgZk2zz4XnuY6sXjkKRBrMyp66n
         xIy42z5qirzgUS+dTq3tz3esDj0uzJ9ST0QW71cpJn849jUpCOSrV6KiRD+OcITg6HfW
         ayfaC+OWFxt4Z4Crrc67fpg6QrLKGAYiG8eaVhNWnM/v7FOGIWl9QfFKF9Pd/3rDqcbu
         5i3LLd0VV4MlZlRptW6QGPe1vUFPTva4w5odVBeIa3L3pyYLZMoty3WDe7EtGCRMUgFY
         l9mLqcAo1yzAtzw3t8uJPKwK+D9Rsj75utUUiWgt4a/MQlgKVDsl6E2GKQJW2bQh8WRO
         6IkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Rx21fTDu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DtB8cFj63kkbYlLPXve3Ea/D9yZCrh6MKed+8wlDStc=;
        b=Oq6Zmd5f6ZCh9bMmNHCWp9vUyS5iUhBLqoKA2sC3bk96PlE+JN6XEiWju5kNfIQU2Y
         ZDgxUVFTkkePIgSUblJlKBYgilHMiF/wq0Zi71cBJ/1OVBg5EJG0hIj2BVnPsJJzGlZQ
         v2z9S65SIdvcB7jn+qhp3cV+RYWQiFOeeEMrRiVLEyBeET63rAbC06jaYT/kzBHKO1EZ
         insyrYn/xwkfiWTD2Z85Mldq2BwKxPDLD8Hv0Wh4oH7qzkDU03BprYR0a6obEp6VZ4ea
         FuqSvDwBU5qC+Mnyy6a6S/Ft+J213LjP/PQzzsf41lcCj9uhlqpW99jCPfPtFJvZZYYH
         0uHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DtB8cFj63kkbYlLPXve3Ea/D9yZCrh6MKed+8wlDStc=;
        b=ql2Qp5DBBcYA90tD0E2mGgzDXnMMvrTAotFn0ph8F29bsb23ViWUnCS5cGbnrPRh6l
         y35LMblReyOoxlmoVVF7spWLfp9+o5lPgX/A3VKgA+gwt1QXcDSlmRkMB6/hVXOnSFUQ
         O6w+arO1rxsnC5CIJbTnJxTGaHb60mrOTq7tPjIObBJHxhKMMyFbP6gJHfGHynVhRMGc
         ZT8aYGch4CkYfr468sD6t9d8qX5aKathou0MHgu+YUrJxxf+fbHZZvhGk/Fi8FyVpOyq
         9CZUyUQBm/KZFxRWIWs9PTZhYqOL8q+pIWV7GYom/2x4ajhAeNZf898bu3fTIKkWoIuK
         3h0g==
X-Gm-Message-State: AOAM530nJQw7ypHWZGHO+o8VO6A+zi6bcxRwLwh4OO6y5AnqfiD43kwp
	1hzVArUnHR33UGSJo5kTF68=
X-Google-Smtp-Source: ABdhPJxKivbQqLdFMx9nqU81fhaijAf/+GwNnV0o8zSlrXVHcgW5YojiJVFoOmBl7v15hSaZB6oLUQ==
X-Received: by 2002:a17:903:192:b0:14f:ff7c:33db with SMTP id z18-20020a170903019200b0014fff7c33dbmr32044591plg.75.1646242492514;
        Wed, 02 Mar 2022 09:34:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:180b:b0:4e1:9065:eaf1 with SMTP id
 y11-20020a056a00180b00b004e19065eaf1ls10190979pfa.7.gmail; Wed, 02 Mar 2022
 09:34:52 -0800 (PST)
X-Received: by 2002:aa7:9f5b:0:b0:4cc:964c:99dd with SMTP id h27-20020aa79f5b000000b004cc964c99ddmr34249118pfr.42.1646242491821;
        Wed, 02 Mar 2022 09:34:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646242491; cv=none;
        d=google.com; s=arc-20160816;
        b=LUE45E0alTT8L1Wk7uShJ5PTTWV5qnGOo7qz3hMf+W8v2J164JNq0qWEhLqMcm3HbV
         Q0lM04P6nriZtQRz5UXcoGl6EO9+EWkAmgJBZuFCuS0NQyxYrkNWG6fGln8qXsUW6z4i
         BKoJwZvuQqmQfWIzFlhphGxsi6w7ZBvhzGwwHZZR/wflii5mqnvbO58i+8smMklKEl3J
         lTnI9js9WAc+RjL+Y0Efm8VpeBpSbuBvIBI2UOXUuGbJXTNr4GVtaMrfuVBeInEPnsO+
         vMFdtjybl93lmgCnfbAznCU1p1w2+6NCT5gANywvLsPZCm17faXBLJU0q9oRmZeEHsYz
         4bQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XxTS9UIes1zHmwkf6XZt5n6dw7Gf4KhSZz97KwsDpNo=;
        b=HRcKke849OlxKrPn8XR5UUh/j/BBJeZD+mFbxX3Lmn0X3Ho/EtWzkRu3oObjgUvEXV
         KvUcDhlBf89TXb98W0GvdnqrOO1c3AyufOfoDsDl0qJ0+HLbx8WoNhKOvNwRmX/EdIuh
         z7cu32sl3fv6cs+rKGMo7pc9sZSKz10doPF8jF8tsuLamF17yOHa4KPhiJjhCSQNo0jq
         7Nzec5Qrpt4qw/CkUD9OZzLEk6qR3CTDJrLTAMOnE6qL6C8ymyZyNDYSeIkfK8fJ5xnb
         4h36q6qJquPJOIs10qfeGqukkEWl6sUxHftK02ILODuTBv8Mvi5NVbVr6nX4qLhXJbbG
         n08Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Rx21fTDu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id e10-20020aa78c4a000000b004f65e89a348si50098pfd.0.2022.03.02.09.34.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:34:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id b20so1864584qkn.9
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:34:51 -0800 (PST)
X-Received: by 2002:a37:a505:0:b0:60d:df5e:16c7 with SMTP id
 o5-20020a37a505000000b0060ddf5e16c7mr17138326qke.448.1646242491221; Wed, 02
 Mar 2022 09:34:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <029aaa87ceadde0702f3312a34697c9139c9fb53.1646237226.git.andreyknvl@google.com>
In-Reply-To: <029aaa87ceadde0702f3312a34697c9139c9fb53.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:34:14 +0100
Message-ID: <CAG_fn=WE80ueUTC3EYjGNGJc8FvAG8Ph-La9cxBXGRBX17d-6w@mail.gmail.com>
Subject: Re: [PATCH mm 05/22] kasan: print basic stack frame info for SW_TAGS
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="000000000000e7d7de05d93fb216"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Rx21fTDu;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::736 as
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

--000000000000e7d7de05d93fb216
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:36 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> Software Tag-Based mode tags stack allocations when CONFIG_KASAN_STACK
> is enabled. Print task name and id in reports for stack-related bugs.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kasan/kasan.h          |  2 +-
>  mm/kasan/report_sw_tags.c | 11 +++++++++++
>  2 files changed, 12 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d1e111b7d5d8..4447df0d7343 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -274,7 +274,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t
> size);
>  const char *kasan_get_bug_type(struct kasan_access_info *info);
>  void kasan_metadata_fetch_row(char *buffer, void *row);
>
> -#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
> +#if defined(CONFIG_KASAN_STACK)
>  void kasan_print_address_stack_frame(const void *addr);
>  #else
>  static inline void kasan_print_address_stack_frame(const void *addr) { }
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index d2298c357834..44577b8d47a7 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -51,3 +51,14 @@ void kasan_print_tags(u8 addr_tag, const void *addr)
>
>         pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag,
> *shadow);
>  }
> +
> +#ifdef CONFIG_KASAN_STACK
> +void kasan_print_address_stack_frame(const void *addr)
> +{
> +       if (WARN_ON(!object_is_on_stack(addr)))
> +               return;
> +
> +       pr_err("The buggy address belongs to stack of task %s/%d\n",
> +              current->comm, task_pid_nr(current));
>
This comm/pid pattern starts to appear often, maybe we could replace it
with an inline function performing pr_cont()?


> +}
> +#endif
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/029aaa87ceadde0702f3312a34697=
c9139c9fb53.1646237226.git.andreyknvl%40google.com
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
kasan-dev/CAG_fn%3DWE80ueUTC3EYjGNGJc8FvAG8Ph-La9cxBXGRBX17d-6w%40mail.gmai=
l.com.

--000000000000e7d7de05d93fb216
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
Software Tag-Based mode tags stack allocations when CONFIG_KASAN_STACK<br>
is enabled. Print task name and id in reports for stack-related bugs.<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br></blockquote><div>Revi=
ewed-by: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glide=
r@google.com</a>&gt;=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"=
margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-lef=
t:1ex">
---<br>
=C2=A0mm/kasan/kasan.h=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 |=C2=A0 2 +-<br>
=C2=A0mm/kasan/report_sw_tags.c | 11 +++++++++++<br>
=C2=A02 files changed, 12 insertions(+), 1 deletion(-)<br>
<br>
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h<br>
index d1e111b7d5d8..4447df0d7343 100644<br>
--- a/mm/kasan/kasan.h<br>
+++ b/mm/kasan/kasan.h<br>
@@ -274,7 +274,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t size=
);<br>
=C2=A0const char *kasan_get_bug_type(struct kasan_access_info *info);<br>
=C2=A0void kasan_metadata_fetch_row(char *buffer, void *row);<br>
<br>
-#if defined(CONFIG_KASAN_GENERIC) &amp;&amp; defined(CONFIG_KASAN_STACK)<b=
r>
+#if defined(CONFIG_KASAN_STACK)<br>
=C2=A0void kasan_print_address_stack_frame(const void *addr);<br>
=C2=A0#else<br>
=C2=A0static inline void kasan_print_address_stack_frame(const void *addr) =
{ }<br>
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c<br>
index d2298c357834..44577b8d47a7 100644<br>
--- a/mm/kasan/report_sw_tags.c<br>
+++ b/mm/kasan/report_sw_tags.c<br>
@@ -51,3 +51,14 @@ void kasan_print_tags(u8 addr_tag, const void *addr)<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 pr_err(&quot;Pointer tag: [%02x], memory tag: [=
%02x]\n&quot;, addr_tag, *shadow);<br>
=C2=A0}<br>
+<br>
+#ifdef CONFIG_KASAN_STACK<br>
+void kasan_print_address_stack_frame(const void *addr)<br>
+{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (WARN_ON(!object_is_on_stack(addr)))<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0pr_err(&quot;The buggy address belongs to stack=
 of task %s/%d\n&quot;,<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 current-&gt;comm, task_pi=
d_nr(current));<br></blockquote><div>This comm/pid pattern starts to appear=
 often, maybe we could replace it with an inline function performing pr_con=
t()?</div><div>=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"margi=
n:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex=
">
+}<br>
+#endif<br>
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
om/d/msgid/kasan-dev/029aaa87ceadde0702f3312a34697c9139c9fb53.1646237226.gi=
t.andreyknvl%40google.com" rel=3D"noreferrer" target=3D"_blank">https://gro=
ups.google.com/d/msgid/kasan-dev/029aaa87ceadde0702f3312a34697c9139c9fb53.1=
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
om/d/msgid/kasan-dev/CAG_fn%3DWE80ueUTC3EYjGNGJc8FvAG8Ph-La9cxBXGRBX17d-6w%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DWE80ueUTC3EYjGNGJc8FvAG8Ph-La9cxBXGRBX17=
d-6w%40mail.gmail.com</a>.<br />

--000000000000e7d7de05d93fb216--
