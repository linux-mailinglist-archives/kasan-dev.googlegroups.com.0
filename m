Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVFI6GSAMGQET25CDIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id C2B35741567
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jun 2023 17:40:06 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1b81902eb72sf2074025ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jun 2023 08:40:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687966805; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYhDsDpPHa0MWNsu8LM9IPnK/FtE+a1jbxda8PsB/x2xqcWC6JVU/Yz2fIc5BzwqDs
         jHqoV5lC07SpiMfaQfEAp4WcVaUaOMaIiFKsuZxQAXpE0cSJmW8pXvv/VuczLgCVlJmE
         coWVu/9VSeitldrfHdNvIRTDf72nVcRaRpmGL8QxsQSmrQG/E4fmtsESkJTqRwG++EHd
         i+X14/pFDU8x8u+5jva+vCBdwRQsBKukwXdrLf5uQ4CRHu5oDOsY1ovFKDKniKuj6yhO
         R2fPo/3ATCHE5fyctxbDEqwzRtj97SbGSChX6bWfFJDwCeA/ZPbMSZP76ez0y6hTnGtT
         nhgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Csh+iCCkyZ0XzL9ztjKuPZzmAEgvybCE5snGaXUlL/8=;
        fh=tCXtaiaLcpypZrDCdeP0B1O6vPjpp+Iey9VlbYAaGGM=;
        b=bckrL3HK7E+ZsdZELj3v35exvAd2CsYQjCE8X+6OcPg7H7HL35zif9M1cW8C27vzpT
         qaXv3kwkHYhpJbmmEn1BWE+QtY7cRbnt3kVixTjoFtQjLqT9Rdgq/g4DNRGQ0wctBt9j
         v5MrDRlcJI1M5i2eWJwt0h3PEatphe86AWOfB62/GQSkDzV8OBa39WS4OigNLBkGtKMl
         NosM6H0NHVXBgsm/gez9GWYZH5/vFbLqsARtzX2t1f90cUXrixOP+lyEAcmpd0uIJsJU
         EanO929LqdDd5u3WggUUV4h1U0erBzqMMgG/sse9geg1+ZO3jBcRL5SKZ1BG3cndoQ5f
         sOlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=V8aAqZOo;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687966805; x=1690558805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Csh+iCCkyZ0XzL9ztjKuPZzmAEgvybCE5snGaXUlL/8=;
        b=d6GDw0aWa6D8fyCrIiShKCPrQDv8qxRs6VwBKaXH04kSkImVL/rg0E5AMmd3g6LWMN
         q42X3wKoZ8fCLhg3jm+5uZ61oEvJlCB+SrMLDBwMZGErh5u4xXbnnD2SFtNgdf0QXNFS
         6n2X9q3f//8UAb2qGW3m3Ke/mk1BHsAWlZns7fPo7xfF1n61tCvS8si/r9tWBXHed5O+
         BLGWw0L3SbnJDEkNBQhtM4dBhtd+jkUnbaPzP0W9f3LrWa12IXOpzJNWpImHMRFlsNxf
         WuusG3Hm71n6ZaOt5G520WpsOZwYSWZPepObeiAF3xhAjdrJXoEAJPAclVYa7z0IQ8ZF
         u5kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687966805; x=1690558805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Csh+iCCkyZ0XzL9ztjKuPZzmAEgvybCE5snGaXUlL/8=;
        b=DhAo6PLlaqNB6KDd9xCRmMgpka09p7ALSOcfHIBjkBdsyZ0owm4q+wfkA9LltBYl1p
         xBjBg3sTxXm+y9cIQRrRvFpQ1MYvgyoSutQWmdPBE9GJmFX4QXkZd+2dLhXQScMmb9LQ
         QhgqJVTfLDam4FU279jUIpVU201Oz7/pe/1+Yjra3p3eJBirgvK/eZ3nJJgkQLi+nQSK
         9UOXdaWXKj31zug8Kec4EHdBiD3IZcf+sTBx3J0EQdQ9hyQ0NqTocduitn28NWqXQMbS
         NDcRKP96rq0+F55USIebQAWEjekqtU8UkA71GGXMgWy4p+Z3t77nwJJf06ITnn04WmbW
         afGg==
X-Gm-Message-State: AC+VfDzkQL0niP5o+fbleaJ1NGiqwNSMosWxylJ+QPsSlTTBPVMsK+Gj
	G6AAbTb2fGSXJs5N2uSVWO4=
X-Google-Smtp-Source: ACHHUZ6b7XH6d/EvSR5+ir0GJodY9wxGD9yTP3C+XfuePyjwzrJkocU+vaGxqe6beZt46WJO/8YVDw==
X-Received: by 2002:a17:903:22ce:b0:1b3:c4c0:3aba with SMTP id y14-20020a17090322ce00b001b3c4c03abamr261353plg.0.1687966804733;
        Wed, 28 Jun 2023 08:40:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a4a:b0:263:25f9:657f with SMTP id
 lb10-20020a17090b4a4a00b0026325f9657fls1063492pjb.0.-pod-prod-00-us-canary;
 Wed, 28 Jun 2023 08:40:04 -0700 (PDT)
X-Received: by 2002:a17:903:1c9:b0:1a1:d54b:71df with SMTP id e9-20020a17090301c900b001a1d54b71dfmr2304463plh.0.1687966803896;
        Wed, 28 Jun 2023 08:40:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687966803; cv=none;
        d=google.com; s=arc-20160816;
        b=qmTRQx0mbaMiG9K9lhM1Q2FRRrdFHmjvwKCrJpcvkL6+pLPD7+5R+YosQdLekXpmlP
         lMhHys6GykIJKEyzB4iVrgIFXmTTvW/45U/tKnOf9zadavow0XRFlj0o6ud4rdknqD5m
         wR+E+WmCKVo1DKYL/bHL2rN0c7B1uFqn8sucgR43SHG1h791/2/Qp0rbNovoMcnRJ8Yu
         sVoLkdjZPoixX1UkV4k39qnFSlZjB46WtvtzGaKcUNj3WvD8K8/1w4ppuEf014eA1bIT
         FqI3ID+7V/KkzTmrfzc14uDmtJGqOPRXTWwU5n4UhaHI7R6cHhWbz59O0VZay1nrud7G
         TTpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KOSO4zVpvAMwe82RSNidD+tbsLnsOaD0mj0C5Zdtr28=;
        fh=vlGuFfUo3PuXsd2f6XSVCHjDTy5AiHRUpyGw8GCHk80=;
        b=jj+XKwB69vf2PSVUxv9RPLX4ixaKwX2S8oVA7++M5u4U+Xa39C0zohsG28DEJJEMAa
         vhHKMawY/k5bRh/j4JcMkSUXXR77NeB/hBJVhG09Fs4Xc6nN8+JRCsFeeYAZ1AyszJNf
         nlCoKyOyl++Iacx98yDVxHCtU5mDK7AGNvro5gvs+lxoXCXW2uX0mwua7oKJuHVDwdOW
         d6fSobYGkL5EOQbD6OeIWpv/FTu3kfoU1vDhCGSFXR9tJCQ9McDBC08N1uCo3mL9XaKa
         I9ni3mmB8KQV7R2wJoq96C/vr+OaBWOTrEkgj5qCvyRM3+aCiIi37tFXKAPSqjI+303r
         00UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=V8aAqZOo;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id v12-20020a170902f0cc00b001b816e24eabsi357883pla.4.2023.06.28.08.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Jun 2023 08:40:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id ca18e2360f4ac-7835ffc53bfso898339f.1
        for <kasan-dev@googlegroups.com>; Wed, 28 Jun 2023 08:40:03 -0700 (PDT)
X-Received: by 2002:a6b:7d06:0:b0:783:727a:8e15 with SMTP id
 c6-20020a6b7d06000000b00783727a8e15mr1146287ioq.6.1687966803127; Wed, 28 Jun
 2023 08:40:03 -0700 (PDT)
MIME-Version: 1.0
References: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
In-Reply-To: <20230628153342.53406-1-andriy.shevchenko@linux.intel.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Jun 2023 17:39:26 +0200
Message-ID: <CAG_fn=WjLDsnUPKFwF8XJiyqYP6M+Q9ZqUweRPzPT3dW0i_E+A@mail.gmail.com>
Subject: Re: [PATCH v1 1/1] kasan: Replace strreplace() with strchrnul()
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=V8aAqZOo;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as
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

On Wed, Jun 28, 2023 at 5:34=E2=80=AFPM Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> We don't need to traverse over the entire string and replace
> occurrences of a character with '\0'. The first match will
> suffice. Hence, replace strreplace() with strchrnul().
>
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> ---
>  mm/kasan/report_generic.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 51a1e8a8877f..63a34eac4a8c 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -264,6 +264,7 @@ static void print_decoded_frame_descr(const char *fra=
me_descr)
>         while (num_objects--) {
>                 unsigned long offset;
>                 unsigned long size;
> +               char *p;
>
>                 /* access offset */
>                 if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> @@ -282,7 +283,7 @@ static void print_decoded_frame_descr(const char *fra=
me_descr)
>                         return;
>
>                 /* Strip line number; without filename it's not very help=
ful. */
> -               strreplace(token, ':', '\0');
> +               p[strchrnul(token, ':') - token] =3D '\0';

Why not just
   *(strchrnul(token, ':')) =3D '\0';
?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWjLDsnUPKFwF8XJiyqYP6M%2BQ9ZqUweRPzPT3dW0i_E%2BA%40mail.=
gmail.com.
