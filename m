Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA6X72IAMGQEHVUUDCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D48B4CAC3E
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 18:38:13 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id fw9-20020a056214238900b0043522aa5b81sf1561011qvb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 09:38:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646242692; cv=pass;
        d=google.com; s=arc-20160816;
        b=mDQ8TN/kFJpVFXBy0+P7hYFsxEWGF/4NPvczo02sUF77nD5PI7/SwbFEFPhTmtBRUu
         +YcbYqbfdh0dS/driaisx3as1soKS7J84MMMA+Kit/Y3fmZ6YsVG4CJg4NGZ8pgulE1B
         O9V/k+V6WUOTHT+IOkEKdsn3weFzTYpme65Q0OCCED+gn1IQ8WEyuZ3F6OsAX7lkgF54
         v3N2mco391HwuRoLJFn0CjWi1ol9qT00PrmWz70fXBZBMsDXSpeWKHssrYCi90ARtR0C
         FvHg8qrBgJOkwaGgmooISu5NGdUpYfpEe3QDIBxYIOg52E/57dYxldslR7EP0caVa0n2
         SpCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EUD4zQpieJXi6hE30CGmrfACZF1i26ldUJYqPJxPOc0=;
        b=r5uFpOKKLc20odE87VUnsQVz/XPKUs09WZCcV3dyR2b5nu9IuRCKTmAep04tvDT1So
         TEW1oes8thlAh9VUMNQQyu/WEvc+ocjbwwzlcYO6pJRV6gUDHzaSZshrkkMPMfhVmie1
         4UopwiWghzUzOeK0s1YI9uhXfG8+HnmWp1uMc5jRwFp22fRSCRjNE7ugMXb7OXDa2xPg
         w99TWd8y6HTxVIvSOOIMT19FO/0e882nICQyWRDrzmQrXU6oRNO/6UEZZr/aI0y3xwIq
         MChP4JbytXF3knu3B4QLexHkn1nogsxJ38F0eTpP7UypCUe0uXhDhFwn+lw3mzZWynw5
         49pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pMy31EiU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EUD4zQpieJXi6hE30CGmrfACZF1i26ldUJYqPJxPOc0=;
        b=WhH+u8AN4SJCduDfwKFS0du4hVJ7aE+X+XYWMG9mmZauk9Q/AXAWEbegJHqoNj9v4f
         gWkPRWAcY8NKG0E8qmVKufFVfPHbAB/UQPkH/+r3lmd+UtZzOPU5+4xdlZEbZmw1B8IQ
         JmfFHWx0UdWBVgQhaDLyxpbAdxPxjwjW0u8iuJGhzDhlH9EtpI+rDs68Pk/9z5yWcjqF
         l1qsC/qX58rG8NIaSVVTaFH4EE+HavI6+NR85Nspmjy5aKJRjjU8bPknU+Tup8PMuQkW
         6sYReJPK92jzy0JWxh5nrAAqnSGCxNsdA0VFDIVDh1rrKOl8adbknbjmq6u3nQGv7Na8
         2+VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EUD4zQpieJXi6hE30CGmrfACZF1i26ldUJYqPJxPOc0=;
        b=1QYgSoLaF7hDfVIVnztNm5nMaZcJov6b7vnXntNSlQBVXAJ1RfVTzxWp1RngScvREl
         lo8UUTWCH5NIil/KeVC5P/TVxFCkp/kmJOdFJkDJUkhb2mDaDblg3tcnutYuD8Wz9Eop
         xilraZ+/U7ksbdztc+Mw3+rwUR2bWqDTlRVZVEaEGD8oKbDCndJh9dMb3YP/tXbFjjkT
         mRWOyNu2E++f+O6cqbvgPw9mrFToN9z1e6J3FFWidBHYlNF9XRYDrWe1xgMpCgthkwcy
         oa+NaqrA4KMukUkxT6vvNUyeitxyX7lk0FJJIzJXSXZBgIUXt6asLsRcTGYQhoCzv3xy
         OH8A==
X-Gm-Message-State: AOAM531zOLNhTV2voB8fykuVnoiw+FJ63+qbdIQzfu4t5ODW10P3AlG+
	OfErm4PU01fOcqVbKDjj014=
X-Google-Smtp-Source: ABdhPJwIs0QTfzkQYM5scxbpwsh21LK124m1M00uymmPVtZ85PcrDmrIaLls+sVLA8CK7xQeFuQTww==
X-Received: by 2002:a05:620a:48d:b0:47e:17f5:a33f with SMTP id 13-20020a05620a048d00b0047e17f5a33fmr17387279qkr.727.1646242691809;
        Wed, 02 Mar 2022 09:38:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6d:0:b0:433:2c45:ff3 with SMTP id i13-20020ad45c6d000000b004332c450ff3ls3443672qvh.9.gmail;
 Wed, 02 Mar 2022 09:38:11 -0800 (PST)
X-Received: by 2002:a05:6214:5188:b0:433:3463:709f with SMTP id kl8-20020a056214518800b004333463709fmr8531172qvb.59.1646242691380;
        Wed, 02 Mar 2022 09:38:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646242691; cv=none;
        d=google.com; s=arc-20160816;
        b=d5Wi7stAgVBaVb5p5ekXahEsh9j/mPk/ERJtcSldONoM8MrxdpN/jkgJGDOTKoDDtV
         2V+EoG4ZdD8wE2jOWJaCHMj1ceLpcOvvoa19fHbH4/bsiYcgG73poEUPBEXwHYV93xkx
         84cMamDJzcrgIoeeFN9/uHgbcxtdUk7CCdTYl6WwBovCBCIvzCAcjZSH8yBO0kx3l3Ne
         VzjHXz6Jxf4CoRerVZ0ueGm9+2ICnhezrqFOw+8KmW/XJnCZQ0hYoutrRLsyL0oe9n/Z
         q0wj0E/ePi6803t+TKW/F67B/WsPkpsoR9WuB+h3lyZcEmXsuhWGlhiAGU8ZqSVv6J2z
         ou1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3CWSfAWuGRM0DidB0ivDkq8AFKbglZjIAIWZXun6ksw=;
        b=gJZCTNC4UCsEAXMKz7lCLkr8DkzBZ5ff2waHpDSebLLpo1+sAfFPon2XGr4by/frnp
         8cIicrjeeIrqWQHj52kriWD0A0MG/s3GajZhFbdzIzI0PTHnV1BzfGi4CMBCqcicLlQe
         Iw91/fPhPuVvk3kqyDl+488/JCBhHPzBeWG6f8zrjuvxjgdTRS2kSGMlW0Bxk3dnGyuf
         uThzDYUUql1sRKR6G0wp1A4UKboHaKfJGbmTRYBne/Lc2EHB6xL5V2fEc12ThBRUj0XV
         9sfrFogsMZg/OPDCIX3+xyxiHqV7Ppf8C4humnLZqESunauGtq00ejm3/f+8D0zb8eRx
         RhRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pMy31EiU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id j185-20020a37a0c2000000b0060dd7b1854bsi723426qke.1.2022.03.02.09.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Mar 2022 09:38:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id b12so2089008qvk.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Mar 2022 09:38:11 -0800 (PST)
X-Received: by 2002:ad4:5fcb:0:b0:432:d049:c6d with SMTP id
 jq11-20020ad45fcb000000b00432d0490c6dmr17548321qvb.39.1646242690905; Wed, 02
 Mar 2022 09:38:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <1c8ce43f97300300e62c941181afa2eb738965c5.1646237226.git.andreyknvl@google.com>
In-Reply-To: <1c8ce43f97300300e62c941181afa2eb738965c5.1646237226.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Mar 2022 18:37:34 +0100
Message-ID: <CAG_fn=UX_hF4RYdCMy-NRC+=KySFLE4wOTiCmzFPBwhieWjz4w@mail.gmail.com>
Subject: Re: [PATCH mm 06/22] kasan: simplify async check in end_report
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: multipart/alternative; boundary="000000000000cecaad05d93fbe75"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pMy31EiU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
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

--000000000000cecaad05d93fbe75
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Mar 2, 2022 at 5:37 PM <andrey.konovalov@linux.dev> wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, end_report() does not call trace_error_report_end() for bugs
> detected in either async or asymm mode (when kasan_async_fault_possible()
> returns true), as the address of the bad access might be unknown.
>
> However, for asymm mode, the address is known for faults triggered by
> read operations.
>
> Instead of using kasan_async_fault_possible(), simply check that
> the addr is not NULL when calling trace_error_report_end().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index d60ee8b81e2b..2d892ec050be 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -112,7 +112,7 @@ static void start_report(unsigned long *flags)
>
>  static void end_report(unsigned long *flags, unsigned long addr)
>  {
> -       if (!kasan_async_fault_possible())
> +       if (addr)
>                 trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
>

What happens in the case of a NULL dereference? Don't we want to trigger
the tracepoint as well?


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
kasan-dev/CAG_fn%3DUX_hF4RYdCMy-NRC%2B%3DKySFLE4wOTiCmzFPBwhieWjz4w%40mail.=
gmail.com.

--000000000000cecaad05d93fbe75
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
Currently, end_report() does not call trace_error_report_end() for bugs<br>
detected in either async or asymm mode (when kasan_async_fault_possible()<b=
r>
returns true), as the address of the bad access might be unknown.<br>
<br>
However, for asymm mode, the address is known for faults triggered by<br>
read operations.<br>
<br>
Instead of using kasan_async_fault_possible(), simply check that<br>
the addr is not NULL when calling trace_error_report_end().<br>
<br>
Signed-off-by: Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com=
" target=3D"_blank">andreyknvl@google.com</a>&gt;<br>
---<br>
=C2=A0mm/kasan/report.c | 2 +-<br>
=C2=A01 file changed, 1 insertion(+), 1 deletion(-)<br>
<br>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c<br>
index d60ee8b81e2b..2d892ec050be 100644<br>
--- a/mm/kasan/report.c<br>
+++ b/mm/kasan/report.c<br>
@@ -112,7 +112,7 @@ static void start_report(unsigned long *flags)<br>
<br>
=C2=A0static void end_report(unsigned long *flags, unsigned long addr)<br>
=C2=A0{<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0if (!kasan_async_fault_possible())<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0if (addr)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 trace_error_report_=
end(ERROR_DETECTOR_KASAN, addr);<br></blockquote><div><br></div><div>What h=
appens in the case of a NULL dereference? Don&#39;t we want to trigger the =
tracepoint as well?</div></div><br clear=3D"all"><div><br></div>-- <br><div=
 dir=3D"ltr" class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko=
<br>Software Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe,=
 33<br>80636 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, L=
iana Sebastian<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz d=
er Gesellschaft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie die=
se f=C3=A4lschlicherweise erhalten haben sollten, leiten Sie diese bitte ni=
cht an jemand anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge=
 davon und lassen Sie mich bitte wissen, dass die E-Mail an die falsche Per=
son gesendet wurde. <br><br>=C2=A0 =C2=A0 =C2=A0<br><br>This e-mail is conf=
idential. If you received this communication by mistake, please don&#39;t f=
orward it to anyone else, please erase all copies and attachments, and plea=
se let me know that it has gone to the wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DUX_hF4RYdCMy-NRC%2B%3DKySFLE4wOTiCmzFPBwhieWj=
z4w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAG_fn%3DUX_hF4RYdCMy-NRC%2B%3DKySFLE4wOTiCmz=
FPBwhieWjz4w%40mail.gmail.com</a>.<br />

--000000000000cecaad05d93fbe75--
