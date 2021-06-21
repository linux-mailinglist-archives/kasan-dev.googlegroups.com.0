Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3MTYKDAMGQEDKINZPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id D03D43AE95C
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 14:45:34 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id n62-20020a4a53410000b0290246a4799849sf11148911oob.8
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 05:45:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624279533; cv=pass;
        d=google.com; s=arc-20160816;
        b=WgxR0gxgZS1RfIvVyWZSkBh9XdfMkeSG9/DZYbhDTGZWl30CcR4KT4hhgOkGeN540/
         K0et+lAXp6HgR9QDztjy5TAKjHdbNpcOelEsnUxPlVsvAJiloOjwleQji17nS/rcXAb1
         d9Qiw1WdXKQ1SnVSZ20V43b8A7YXPNW7e0xZ2NjlhpCYZOKl6EuCipC/3CEUc4ylG7qW
         xVGoiLWepvaKBXxwn3JGsohQAN6SUQClSYtQo1MAaTnhUwC/oXaW4R4P738QD0VOLgOD
         Gvo0TMGKq0BThngoL53yRZrmU+HSYEg+pariSjsJhYsNu8BPuUmXcoIL7vdu1NSOePX5
         v2ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A+7COybW4WqqSeIm0ngiHlulq2JeKWI/Nyhm+c7rQHs=;
        b=sEpGjQfvGp0STmXN2QliPem1ekiS5asBNd4LAi82X59lWwLYMgoM0PABBKurjOrtxT
         L8HE1ROvTSrdN2DMSKkz3FRpkEkMkXIIISf/siQ5iGBsC8c9R4Om8ewswjJ32IWcNKT5
         FCco7CGIwtZgT1IWFYUvYZSYXH/e5zMrEq2IMaTMkLlJ0rsW4V+IuYQRFjrc43951S/d
         O8CgBIflaIRqqijQgGGtZR/g6XN7J5UvxOSh4p+vxxxbZ7c3sWa0a//NG2CgKCMg4ygB
         OxQQI84S5RArMOeDT3gvphZwXbHsZGWs/iZ5QComiINUwzLCyCRvqV8ZrAgJ/qtRtck2
         JZTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CjH/y8Sa";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A+7COybW4WqqSeIm0ngiHlulq2JeKWI/Nyhm+c7rQHs=;
        b=LghRJOGZXQygwRQq2RSL5/VVxuWY8N0LWP8I4mGV1/lR7QFGmPFArUa2XrTZFK/SWl
         QSVHACiL2tSmYINP/8AtmsWd1kRtFLbTeVcFKHqp/V+zZNTQ1me4CMAuS0ZjfhlzWXat
         BaX6nrCu8Nsc0OKCkHrfBe6Goj0bqIzq/4oluZVtl8YwUim8IKBq1ZiRL7wbxBaWkciK
         ChhMslwNMsnQ0/IC+mZ2x+oNkhzwy9OBUlgDBI9HiaIIclKXik+h4peNM+VkhbYALn9w
         pfsxg/8Dlg6FQTvwRwI/dqsHUeQpun5rb0xhI78Ul06jMbOqc7uOwrnJ5YUIVEXomS1M
         9hLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A+7COybW4WqqSeIm0ngiHlulq2JeKWI/Nyhm+c7rQHs=;
        b=JFoWa5b3L+mcSL+Bqnsu2nhzqQz41YaOF7Q0DXn/FL2bMX6EYGRYNjNUTWuWn8Hdha
         wc3D3WqNMZAsYt2trjHKmNE4lmBU6wZGsPiOFo9UHr4HJGa25XR0MhT9BzUL9Ku4QIiB
         vlWv4hoz0o0Pe1CKY2Dk/7yafeRSh9Fy/pUrgI3J6sH8nINf+o7hjoyhAo8j4G8ANO9r
         FywySAwUEm5//JkDph+nugjQSNQDI7/uvoItlqdL5nZaMEN31odd6y3XLRFrpCY0xciK
         0Ocd9UxoyCFEEE4366+O61w2Y8sCtop8m7ju1otch93A0gHm4EBOfCosKo3bPdIfimct
         68og==
X-Gm-Message-State: AOAM531qtgCfL+6bAXAirtR+A1Yfv4jV9AKtq0Wv3Bu77zQwfwYRzN6X
	wU1g23dHBrb5OVUwE+zdsdM=
X-Google-Smtp-Source: ABdhPJwyqEGA4exGdCzx8YrfIklq+1FlLUnA5FGdim1yys14p7IvY7GjMOwOtokcG/Z/CHtKXJobIw==
X-Received: by 2002:a4a:2242:: with SMTP id z2mr20326394ooe.90.1624279533393;
        Mon, 21 Jun 2021 05:45:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:641:: with SMTP id 62ls6112146oig.0.gmail; Mon, 21 Jun
 2021 05:45:33 -0700 (PDT)
X-Received: by 2002:aca:da86:: with SMTP id r128mr4326969oig.150.1624279533001;
        Mon, 21 Jun 2021 05:45:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624279532; cv=none;
        d=google.com; s=arc-20160816;
        b=WMC5cLzr9gQ568gOTuDXO8xUgsOhsPWgEkCq6uR1Jm7UsoQuaIWNYmLzWyWgRkjN1B
         kXjb0cFesMcRAx6Gx7ouEt2NqblGkJxUpAnnxtpd4NHXT0AKjCeenMyPDmlNORW+mmov
         tuoPdlqvHLwU+dcdNafrFtojwJbyRjSJv7MbH3Ms8BKbJOn+zmfUGjoljH7Yq7zDlT1r
         HCF33to7ladCh6rx9YGiBOk+yyFn++Y56YeY8c2wZC7d2PUo9W1tpKmD8Sw65zvFD80r
         npCFDfwg86pd1T+oYFQdOFQFXxLP7WpEF/AdoGAErFMMHCyHmaARbq4fX89baeL3+Xta
         MSqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O21GciyTpaxqmDgMZPyp7BhBIp+OaBFdrCDg/nqizCw=;
        b=tRWKYPlwz/WI4wx6sSO5RRtTuPGK9QCohEfmnHtQZ6p9pa30oEO9jRab1kGRbdKV5y
         qVlUC2q5O5OBcw7HpauQLKaXwJ1p4j/TSWXurd2+fSA9cjijKt1MkDX+8VTz0+ND+UPv
         tw129fZ4GW2poR9eSCjbmxUym7JCm4F1O9r97zTEWcObx0GjIGjTB4XTtAPJjzKvg0i1
         orHUv8+02CUkIbrMm5lrXzQh1+TRuPOxiVDChGVuE1ECw67QDQYlCssd1CMVxZSbw0pd
         VHy7Vy0yhVmhGU72p8UOzXNWJk1SUFL30HyzGFNKo6a94sQ8xkDWQ3pPstQ0pdO8LExB
         UcfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CjH/y8Sa";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id i10si1553177oie.3.2021.06.21.05.45.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 05:45:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id v22-20020a0568301416b029044e2d8e855eso8360807otp.8
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 05:45:32 -0700 (PDT)
X-Received: by 2002:a9d:4e7:: with SMTP id 94mr21273799otm.233.1624279532556;
 Mon, 21 Jun 2021 05:45:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Jun 2021 14:45:20 +0200
Message-ID: <CANpmjNP9n8-m4MhY6Cdnfx_SYLVtG8NJ7raMUR+3rBoNyyfs+Q@mail.gmail.com>
Subject: Re: [PATCH v3 0/3] kasan: add memory corruption identification
 support for hw tag-based kasan
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="CjH/y8Sa";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 20 Jun 2021 at 13:48, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> Add memory corruption identification for hardware tag-based KASAN mode.
>
> Changes since v3:
>  - Preserve Copyright from hw_tags.c/sw_tags.c and
>    report_sw_tags.c/report_hw_tags.c
>  - Make non-trivial change in kasan sw tag-based mode
>
> Changes since v2:
>  - Thanks for Marco's Suggestion
>  - Rename the CONFIG_KASAN_SW_TAGS_IDENTIFY
>  - Integrate tag-based kasan common part
>  - Rebase to latest linux-next
>
> Kuan-Ying Lee (3):
>   kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to
>     CONFIG_KASAN_TAGS_IDENTIFY
>   kasan: integrate the common part of two KASAN tag-based modes
>   kasan: add memory corruption identification support for hardware
>     tag-based mode

I think this looks fine, thank you for your efforts. How did you test
this? Did you run the lib/test_kasan module with both SW_TAGS and
HW_TAGS mode? I was about to run that before adding my Reviewed-by.

Andrey, Alex, if you have time, please have a quick look at the series.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP9n8-m4MhY6Cdnfx_SYLVtG8NJ7raMUR%2B3rBoNyyfs%2BQ%40mail.gmail.com.
