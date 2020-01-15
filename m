Return-Path: <kasan-dev+bncBCMIZB7QWENRBDOK7TYAKGQEGVCALLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 4477A13C65D
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 15:43:27 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id o124sf6378894oig.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 06:43:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579099406; cv=pass;
        d=google.com; s=arc-20160816;
        b=j43GaqGRItq5kJiB6Yie52ph4FZDQXzN4Nbh8BP5QshzmgNN57gzupTzxuX/LClhjG
         W+H9LcKEkvAuCZQQZTEBZ4fP0wa/1bpc7BLqLajjP2P+YkgsavPtWEtnXbPxpaEHx84K
         nbpz0+F78ugK9ZjbCWIFPE70Ew/dL26CyQ4fU07VFpGVMXUo7gIfir+uNJVBmpjKHjKE
         jwRDpTVki60DJNPfLEa8i34D1Fle/UuRLnFS2m3/kUr2Rjs8Rjz0WUgp0zAO/oqOBEDz
         eGeNg/hXFnR/7ZClrqsVNdHkbM8UHaEx1tGdOmG/W6Tx38HpbZREFNATfRIi58AaBVja
         yS5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D9SyT5KlFR7AHQgdks+SJUGzCvHTTuqRu2KeTQrYVD8=;
        b=ie0gxmUeOml3N8L59Z8pq9k38h+5+p36/47jnvNfGocCcjF2ZZPQbY8BAh9goz7QBU
         pb1S8JC7UJe6OK2+sRP0yEQUhTooE/+Gr6CyoGRcFlH+XUYh2PXKliYQhVYRrxSC4zUH
         MsKUd2fvNreMk9f1apmcBWWeaeykQtMElgQ3Y1wdKTH4lE4NyLuVD8JZpqTuQd81hRxT
         CjXrqHmrH4lUxJnrV/C5TpFEKi38mWnXzunBJwBXKdwoQhxYQHbvCNF3DaWTopk6yrKq
         0ZQSsqISdwynGjdpikTntr0fqEQVsaKM+70ThX2ycG6QWA3Fhwwaxba/0RrsPmpR2ECr
         IZvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HAmEbppX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=D9SyT5KlFR7AHQgdks+SJUGzCvHTTuqRu2KeTQrYVD8=;
        b=b0Gb3Qje8Xkq36s+MKPFQ8FQoi2VNYtkyy/jcZ5O3AzpNPj7VXLg3lziX/XWbbr0OP
         NKESlqh9qbK7XLuLT//yLvDeK/Dxyo5kqrqrXkP2i740sx+OEdniLIfZW+8/1uMHVCt9
         mxnz7LDbZZYW3/LkdsQhFTGuwj7NLUVqglxQqzmFDUgcl98Y0r2iCzn5J9SPs210wTx0
         o9YT1apyyUfFI8B9dzhgTrgVXEqdIVQVvdhLpHgju2sQQQBhj/JKzoWesqXK3StuW6cE
         JAdum7S+jJHmxFDfjpW8OJZOEusfo3LnOe7Tjk/Ovzf5Cb8FZSKvez3b9UdDcIX9YzND
         M7Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D9SyT5KlFR7AHQgdks+SJUGzCvHTTuqRu2KeTQrYVD8=;
        b=et6Pg0fGdctJH4jBvuvymfYWTcPRLyTZwjSexxdOCtTA2pRrHRMCzxnEOeFFeLS6Dg
         1mDN9XEG5ihV5SVr/2rRYJOvW5P8yKA63hJCOxdu0SnKQXdmnd16zSiM6RJtg7K4HOUt
         xVrXnLqVpTDhEHH2+8TxMyvJ9Glbu3SZD3SnBp4abxoLGucZ/E+sBWT+Q/pT+q9cLu5U
         X8wIT1WIcz0EZJ2IQsMFG+aGUD2wb3D7HT7zMswgXwLADYH5i9ZbtcSSEO7zxaR8CP6q
         Igq4Qha5+1DvTQhmGutTuUXAb+2er+dletEtQpwZ+fY5wfFxCijtAUEPmCWyv+57JyuY
         OMpg==
X-Gm-Message-State: APjAAAVdkkmA7XXL5v9EhI2akpznMoSUHdmxfy9recpb6EBtxnzsSDy/
	Oo31c1FPqQppgEBT6W+lWLQ=
X-Google-Smtp-Source: APXvYqzGUOfe2pIrWdXbIL90YFg9VAeenIpNiVd76xNpVLNoge7ZyD9546Olz2t8Ajl8qtjrVdVoow==
X-Received: by 2002:a9d:6f8f:: with SMTP id h15mr2824198otq.1.1579099406037;
        Wed, 15 Jan 2020 06:43:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7198:: with SMTP id o24ls3441975otj.10.gmail; Wed, 15
 Jan 2020 06:43:25 -0800 (PST)
X-Received: by 2002:a9d:624e:: with SMTP id i14mr2946653otk.371.1579099405561;
        Wed, 15 Jan 2020 06:43:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579099405; cv=none;
        d=google.com; s=arc-20160816;
        b=AlafIQgaxGzOSy0DOfxrMgnrpyZAuy5gZ+7rh0RZ3ROlyhGe1QoW5Vc5uIKqAZSfH3
         5zQIFWbgo68QmDHRyEjCGdnMFQpFQKVNo1P7mJZZGfB601xWo5nQNmXJet1ho08+v/dw
         kwtgrJadvMaLBWpsV/ny9DD4g0UFDsi7z0mXF2P1SFQ4h1JBQC6vj+pD0fS9/pBU5kBT
         HX+HLl/XOPQ5QXVe3DpXAvnZrnEp7OqUgRJOJK8sjJbpDuBzKAA6xedu8Dj4r57OXqpC
         5HEvqkAfPlnh2rkVtRXxUiUK0uVLVPCnKt6P1xg55q9nRkwNd8e1GRQQtzB7+FUJ4y4N
         GoEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Dsov92auA7/G12RJ9hsAhzPgLmMj5NcPBeP6nNJDSO0=;
        b=mAeiaC2qIrx148UHjVhnuEoxqGd7KCcnqkfHxHEW0vkUJSewJzuypOkr9Ee7vkyazB
         gebwvLWIhpaF5vT5f+jIV60TFwHMNiWa1HHYcYXmg5QxB+VjRqcYUwbocZAlSsltOJl4
         QgV86oOaiw89XqcaH5FpjOFEX4I51cytzQ3K2PmJ/OrjvfMJhQPyC2jRIEKfezWLCXnL
         YEyYRLNZQpAk4tB1DcDaLRn6kbFsytBeLEOcuyFCl1/DdA+0jhTQUcqjvY19mKXicBKo
         scgoiB9a5u788V67MmTafzG8W4pmU9wh/aixnPUD+yX8/VFKPO624vI+moDpgB1s4+XO
         tyFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HAmEbppX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id e14si990419otr.1.2020.01.15.06.43.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 06:43:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id z14so15813494qkg.9
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 06:43:25 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr28110133qkk.8.1579099404892;
 Wed, 15 Jan 2020 06:43:24 -0800 (PST)
MIME-Version: 1.0
References: <20200115063710.15796-1-dja@axtens.net> <20200115063710.15796-2-dja@axtens.net>
In-Reply-To: <20200115063710.15796-2-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2020 15:43:12 +0100
Message-ID: <CACT4Y+bAuaeHOcTHqp-=ckOb58fRajpGYk4khNzpS7_OyBDQYQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	"the arch/x86 maintainers" <x86@kernel.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HAmEbppX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Jan 15, 2020 at 7:37 AM Daniel Axtens <dja@axtens.net> wrote:
>
> 3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
> memchr, memcmp and strlen.
>
> When FORTIFY_SOURCE is on, a number of functions are replaced with
> fortified versions, which attempt to check the sizes of the operands.
> However, these functions often directly invoke __builtin_foo() once they
> have performed the fortify check. The compiler can detect that the result=
s
> of these functions are not used, and knows that they have no other side
> effects, and so can eliminate them as dead code.
>
> Why are only memchr, memcmp and strlen affected?
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> Of string and string-like functions, kasan_test tests:
>
>  * strchr  ->  not affected, no fortified version
>  * strrchr ->  likewise
>  * strcmp  ->  likewise
>  * strncmp ->  likewise
>
>  * strnlen ->  not affected, the fortify source implementation calls the
>                underlying strnlen implementation which is instrumented, n=
ot
>                a builtin
>
>  * strlen  ->  affected, the fortify souce implementation calls a __built=
in
>                version which the compiler can determine is dead.
>
>  * memchr  ->  likewise
>  * memcmp  ->  likewise
>
>  * memset ->   not affected, the compiler knows that memset writes to its
>                first argument and therefore is not dead.
>
> Why does this not affect the functions normally?
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> In string.h, these functions are not marked as __pure, so the compiler
> cannot know that they do not have side effects. If relevant functions are
> marked as __pure in string.h, we see the following warnings and the
> functions are elided:
>
> lib/test_kasan.c: In function =E2=80=98kasan_memchr=E2=80=99:
> lib/test_kasan.c:606:2: warning: statement with no effect [-Wunused-value=
]
>   memchr(ptr, '1', size + 1);
>   ^~~~~~~~~~~~~~~~~~~~~~~~~~
> lib/test_kasan.c: In function =E2=80=98kasan_memcmp=E2=80=99:
> lib/test_kasan.c:622:2: warning: statement with no effect [-Wunused-value=
]
>   memcmp(ptr, arr, size+1);
>   ^~~~~~~~~~~~~~~~~~~~~~~~
> lib/test_kasan.c: In function =E2=80=98kasan_strings=E2=80=99:
> lib/test_kasan.c:645:2: warning: statement with no effect [-Wunused-value=
]
>   strchr(ptr, '1');
>   ^~~~~~~~~~~~~~~~
> ...
>
> This annotation would make sense to add and could be added at any point, =
so
> the behaviour of test_kasan.c should change.
>
> The fix
> =3D=3D=3D=3D=3D=3D=3D
>
> Make all the functions that are pure write their results to a global,
> which makes them live. The strlen and memchr tests now pass.
>
> The memcmp test still fails to trigger, which is addressed in the next
> patch.
>
> Cc: Daniel Micay <danielmicay@gmail.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Fixes: 0c96350a2d2f ("lib/test_kasan.c: add tests for several string/memo=
ry API functions")
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  lib/test_kasan.c | 30 +++++++++++++++++++-----------
>  1 file changed, 19 insertions(+), 11 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 328d33beae36..58a8cef0d7a2 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,6 +23,14 @@
>
>  #include <asm/page.h>
>
> +/*
> + * We assign some test results to these globals to make sure the tests
> + * are not eliminated as dead code.
> + */
> +
> +int int_result;
> +void *ptr_result;

These are globals, but are not static and don't have kasan_ prefix.
But I guess this does not matter for modules?
Otherwise:

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> +
>  /*
>   * Note: test functions are marked noinline so that their names appear i=
n
>   * reports.
> @@ -603,7 +611,7 @@ static noinline void __init kasan_memchr(void)
>         if (!ptr)
>                 return;
>
> -       memchr(ptr, '1', size + 1);
> +       ptr_result =3D memchr(ptr, '1', size + 1);
>         kfree(ptr);
>  }
>
> @@ -618,8 +626,7 @@ static noinline void __init kasan_memcmp(void)
>         if (!ptr)
>                 return;
>
> -       memset(arr, 0, sizeof(arr));
> -       memcmp(ptr, arr, size+1);
> +       int_result =3D memcmp(ptr, arr, size + 1);
>         kfree(ptr);
>  }
>
> @@ -642,22 +649,22 @@ static noinline void __init kasan_strings(void)
>          * will likely point to zeroed byte.
>          */
>         ptr +=3D 16;
> -       strchr(ptr, '1');
> +       ptr_result =3D strchr(ptr, '1');
>
>         pr_info("use-after-free in strrchr\n");
> -       strrchr(ptr, '1');
> +       ptr_result =3D strrchr(ptr, '1');
>
>         pr_info("use-after-free in strcmp\n");
> -       strcmp(ptr, "2");
> +       int_result =3D strcmp(ptr, "2");
>
>         pr_info("use-after-free in strncmp\n");
> -       strncmp(ptr, "2", 1);
> +       int_result =3D strncmp(ptr, "2", 1);
>
>         pr_info("use-after-free in strlen\n");
> -       strlen(ptr);
> +       int_result =3D strlen(ptr);
>
>         pr_info("use-after-free in strnlen\n");
> -       strnlen(ptr, 1);
> +       int_result =3D strnlen(ptr, 1);
>  }
>
>  static noinline void __init kasan_bitops(void)
> @@ -724,11 +731,12 @@ static noinline void __init kasan_bitops(void)
>         __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
>         pr_info("out-of-bounds in test_bit\n");
> -       (void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> +       int_result =3D test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
>
>  #if defined(clear_bit_unlock_is_negative_byte)
>         pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
> -       clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, =
bits);
> +       int_result =3D clear_bit_unlock_is_negative_byte(BITS_PER_LONG +
> +               BITS_PER_BYTE, bits);
>  #endif
>         kfree(bits);
>  }
> --
> 2.20.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbAuaeHOcTHqp-%3DckOb58fRajpGYk4khNzpS7_OyBDQYQ%40mail.gm=
ail.com.
