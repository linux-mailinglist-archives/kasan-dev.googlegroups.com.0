Return-Path: <kasan-dev+bncBC7OBJGL2MHBB54VWOIAMGQEMQNR2QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 762874B850A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 10:59:20 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id t72-20020a4a3e4b000000b0031af9ab8cc6sf722609oot.18
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 01:59:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645005559; cv=pass;
        d=google.com; s=arc-20160816;
        b=S0j52ZQhyOeCAPih2RsA0Saq2ArP7U/b4EJ+NfgwDMLcfS/AXiRPdeQ07Gjw7lcs+r
         hPfjsHtTm5sKF3lEdgvtiJ0fa+fmusW6p3bTM5l9yBXBomTeUOXFIWLoU73czzNTTAnq
         Osr/fPNgNgODMjusB1/u3ND7JI7NIv9Z19YpJFSbEj+ZyBW38mYcwUYQ2JnRmCsynDD7
         elUenLYIHdhA5V1gIRgarjJZKaYWEbgu66uiIqVhZIPzsMqSfInwRExz703sLbmEQWgI
         dgVqp/OwYBMpiolOUVaPD68BwhNHCTdulI4TJtiM5eoyhmSgP6T0y6OvdhQKUkg7XTyy
         eZNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E2LquW1zHhT70hYSbyUraYDuogWOIrvntDQtrFTsKlE=;
        b=UUlYuDBRb3g+NM4Bh45KW0A6xjts2XrDoMjdVYV36GJXB+hwpOf0FvrWmfmC3CANTO
         qYVubUd+qoCzLWTWlt7aAELbB5iYZI1kBtsmenLFwtoycYBB0W6VRZw7Ff4rL/Xoskc4
         eqUYMuEEmSrx59erIc3KuqRTiyf+a8t3IEXG99gbbVwjhNu4TC7y6loLgDQwMDqUDPMI
         9+kNrZorpmFE6vlM1sT8dGcD2FLciWY5D5Jm2xjz+qjJ5pL/VxVJaYjP/TKh9hkIIgYK
         1Ubfsnb6mJEsSXfP4S4dZ9gbKswlWdoiOw8g8uDZJlzvYU1Jyi+9tSZVeHhwnuFIr5n1
         Y4tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XGdkv5sh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2LquW1zHhT70hYSbyUraYDuogWOIrvntDQtrFTsKlE=;
        b=JZzNp6zS8+PaHRkxw2WQgOtQPYd8Nx1OnQJxSzyiW1cVy854g2KKrJtFAg4v+iytth
         PuZNBoYActuXABz0FLtolgC2QjuOSqlQx6BlA3VTc57i+liahLzaLSP1FK/NHfNSZOYI
         a+hJLjP7AoUYhtM+nYifOAOe0/bui6LB43X78jmFU5PGe0EXtnAC1ZKLAgkQVDppQJwQ
         RfcS6cMKq2EntTgdyyHESRbqL/8f6TOYyHr3wFaHgCaHHQSex1gkzp0OMRk1Z1YYN1Cq
         LqCcFmfDy7Pw84AmNU+3uXJ53hi5zyaT6eEI3j+ZMvcosgrh+vOGfTGl7mfAWwU/2BtF
         /c0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2LquW1zHhT70hYSbyUraYDuogWOIrvntDQtrFTsKlE=;
        b=HJ5AdYOYeGv604mCM4BpX4zKELDnlla7CgZtzomCDfm4O57RqbzzA3TbbWY1z2GP7B
         EfAxoT5XyHTurM+z1s3xs/Pb7TlDcpRBOGKEyyMHDPhl3QqutVk4XwOYJ2jrUt8RYigi
         S57scY3iE/Bu68Fe4aCxs610OO2jtlvGETsM7Jv3nuTlFa1p8FVoLMaFoJ/37o9PVP6+
         L6y5CD26cBdkuWS9cTGr78VHMv1CwBROJO2QrPGJjxYYwqH4EOjILk/2uzwcy8MNlOeU
         8Yz9DCm2XKE9goIop2cRAygvLsL9/cZ3LV16N1Yw6UDvWFFYGOrt++PMIZrY5T1OyyPJ
         wF1Q==
X-Gm-Message-State: AOAM531YdCilDlmwv3x0+RiuXSv9Nzef8zuRJPF2frMxewthgfoWqb1c
	HtLy7FtnMfWM78E5NnB7Zbs=
X-Google-Smtp-Source: ABdhPJwwbLwtClzihyko4SBYn/dWB/GhCmbaSzEoqkdj1SQxofWg+H5/2xBq+hfxoW+E9ywfqIXCxw==
X-Received: by 2002:a05:6870:aa92:b0:ce:c0c9:5db with SMTP id gr18-20020a056870aa9200b000cec0c905dbmr188568oab.45.1645005559115;
        Wed, 16 Feb 2022 01:59:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:5c4:: with SMTP id d4ls1566772oij.10.gmail; Wed, 16
 Feb 2022 01:59:18 -0800 (PST)
X-Received: by 2002:aca:5b43:0:b0:2d3:fa59:9125 with SMTP id p64-20020aca5b43000000b002d3fa599125mr284376oib.47.1645005558785;
        Wed, 16 Feb 2022 01:59:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645005558; cv=none;
        d=google.com; s=arc-20160816;
        b=BRFSP5XPiWhO6Uv68WGDYCwQK3JfYgZezgtyqtTw0myalaFQMj8qvFE0QXTY6EAffQ
         ZIhgpMSsLTrAFdsDNwrRgCkxlUzBpdYkn7bKvpTwWnfwW0Au4VJzS/dSaLpvpFTSR0Im
         iNT9rKH4UcuKWl2Lyl+32sDPKAzLiYKlWnitzRrHakwGw386a8BGQ3KbRrq8q3IioIVi
         K9EMx8OY1+swHfldjHtGoP2gS8vIRLNDBp5USKP0oLc3o35hVq/QkxezBqHWcFpDqegU
         6EnoKRi5HYNaWBXuy3W9EkfGpuOaAPCd7o1Znh2dzv734P+4mkpmUi94zcG9d7sTpkL5
         grNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g6yc0CzjhZvL8asvAOjVxpZRVzWjAV26MMR3ayD0Jss=;
        b=D2lYpkjsOolAgiVURLzixKK+CvQq+T1EFEexDXT648QYjAX/taP3z9E7VWBcg8Wtni
         va5GyRq3l3sQ4wpJqLoBQ+8HuctE4KiIwOtukIzOj6GNWqxrYIBGDbCb50/Z+MmBDb2Q
         gtzsqVt/qvqfYCSS66XIdur48JZosgk6mAek8bVYMKJNSU3hue0VuJFivLhnTeFHEfXr
         PmKjviREGwmQ22hKcWBPMuuG1eTXxUiEinEXl/PpuguaUCzrHQq1RJgvfQpiJXKTLmuh
         m/OQVbiEPdeWguRyHzQ7n4OXMhrHdfxjjmbCDNnB85UFX6+ddcP/OpbQBpZ7pkGBHHvA
         L/dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XGdkv5sh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id u43si3395950oiw.2.2022.02.16.01.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 01:59:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id y6so4410621ybc.5
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 01:59:18 -0800 (PST)
X-Received: by 2002:a0d:ee41:0:b0:2d2:f0aa:d3ba with SMTP id
 x62-20020a0dee41000000b002d2f0aad3bamr1771660ywe.512.1645005558266; Wed, 16
 Feb 2022 01:59:18 -0800 (PST)
MIME-Version: 1.0
References: <f50c5f96ef896d7936192c888b0c0a7674e33184.1644943792.git.andreyknvl@google.com>
In-Reply-To: <f50c5f96ef896d7936192c888b0c0a7674e33184.1644943792.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 10:59:06 +0100
Message-ID: <CANpmjNPG2wP9xiGDJboMJzf-YD+skOO532O+bKkAz+tpvDsF=g@mail.gmail.com>
Subject: Re: [PATCH mm] fix for "kasan, fork: reset pointer tags of vmapped stacks"
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XGdkv5sh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
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

On Tue, 15 Feb 2022 at 17:52, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> That patch didn't update the case when a stack is retrived from
> cached_stacks in alloc_thread_stack_node(). As cached_stacks stores
> vm_structs and not stack pointers themselves, the pointer tag needs
> to be reset there as well.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Did the test catch this? If not, can this be tested?

> ---
>  kernel/fork.c | 10 ++++++----
>  1 file changed, 6 insertions(+), 4 deletions(-)
>
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 57d624f05182..5e3ad2e7a756 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -226,15 +226,17 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>                 if (!s)
>                         continue;
>
> -               /* Mark stack accessible for KASAN. */
> +               /* Reset stack metadata. */
>                 kasan_unpoison_range(s->addr, THREAD_SIZE);
>
> +               stack = kasan_reset_tag(s->addr);
> +
>                 /* Clear stale pointers from reused stack. */
> -               memset(s->addr, 0, THREAD_SIZE);
> +               memset(stack, 0, THREAD_SIZE);
>
>                 tsk->stack_vm_area = s;
> -               tsk->stack = s->addr;
> -               return s->addr;
> +               tsk->stack = stack;
> +               return stack;
>         }
>
>         /*
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPG2wP9xiGDJboMJzf-YD%2BskOO532O%2BbKkAz%2BtpvDsF%3Dg%40mail.gmail.com.
