Return-Path: <kasan-dev+bncBDW2JDUY5AORB7WMSW4QMGQEMU3UVAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9E19B9B3A
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Nov 2024 00:38:39 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4315d98a75fsf15884305e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 16:38:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730504319; cv=pass;
        d=google.com; s=arc-20240605;
        b=eR7DlDzUAt6KuSf2TzHkAsGTwQitbCTBIqlMjniz6zML/jBuNYQ0GmrplwFhihZR8g
         Ui6k+EMVmXO7q/8G3DhsjLm8Y4pe0qGfxwisqRI1AcXYo4WGB3Gd4BpmDGjAlGwdMU0V
         GtBAG0EN7zP/L1WeZh2+p2pLshgtnUU7qiXSx5T1lJoKCwmtzdmmpwZKfyTryjxAjzjw
         NJ9S42VVH0TfQoqvursBhXmWrmgYippNvIazr6bIV7yoZ2sy+m1v8kl197vjPq6fmhbp
         8c9XWSzGcFVvAsOuRvuhsRcVEqPZGmNjNNkoTVkgf4gH0URnnMHmCaU7Uc7xY+T3nM6u
         0e0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=m5foUtv68hv7JVx4eEd+u1mO/CKPYfayN/tIEQe0sbQ=;
        fh=SRVRB2DYZA4qJr8PORC32GFUJX9OBgJHBzpd/FQ9MYk=;
        b=GTELK4eQiJ4EiJoJxMPEHdkRg/0KP/FUjRm+KVZEgGfCv8MPnUlX3fQtFhTql3YBPZ
         nXJERcy2MEyJcd6O7IzE9uc00oG0Zso32ijlYopZNWaVXiwQHjgA3x0jOaJE3Y492BI/
         xtOQ2iuFafUATkuVcuclXodTr507m8HWeD1e0FyOwM7wu5iMF08Lkty9sk3FXAl99Bxp
         xkGaKvSdfRAIJdjcHkYOYrtjDrlK2eU6KE/UT4Tro/HkjCqvqTySDXOBQ2rXGNA0ZYqu
         rZzad6NIWgOEeQ7qBwA+6vW5DqOL2129Zh1YjCpDqJ//2+MJel15XNe0ManJDMtUu8H1
         dubQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DqDM1vBV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730504319; x=1731109119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=m5foUtv68hv7JVx4eEd+u1mO/CKPYfayN/tIEQe0sbQ=;
        b=X1UJvMcKyFgxxoW1O+yOvXmekguo6HB0OIzBfY2iu0AaSgbZVz0SNJ34r/a2Wf1MOP
         DdMniMmNQO/rJKdP+fWRBd1lFaUpjE8ph89btJjpG2uT1Vu8a+tFK42jJ4hFc9r5+bNC
         HN8bHiNSh34cT8C9HZD5ccJbf9BRu8ioeN89aEeqUg7rHgicsfTB6QwfmBNK9xNm6l8g
         l/D4m9FhzQW/1lAPmp5gaMESLQJQm+JLgr37zE7FMIXEYnhafK/5GxpVBo4usi3qG90s
         BY1qoSawHpERA5JYZUrKf9+VIVMQwrvwDT6oy70pJUl5RtJ06vplcLk8yQ0KGr3cr/Ad
         yFeA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730504319; x=1731109119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m5foUtv68hv7JVx4eEd+u1mO/CKPYfayN/tIEQe0sbQ=;
        b=OE86GtPyS/xG7NszpSO6hLA7T2MRQk/U1oNzz0e3JwUAlE4QLiiMe1njZ6Av6XoIP1
         FRAIeQXDr58NcwQcPZW54VXFBfOvBKJ7nL+45OCcaTX31QcfEwNaVwcGDxV+6DWSV8Up
         lGFtUNV6e1DTqev6oGoGrCSgC3kPhICCkVcuVpJPksY8usnk8At6rf+PjSq1FsnkUiVD
         ocYybRgQISOiHCI+mdPiv24PoytTpmvOxqxXlGkKt2ceatSu/11KOTWetCaIeBQZzeLV
         teQginN8M01/F8s+0tJS+kAMLxblpIwQuonBZ+XXBn2hOzFyR6YOe9bgpWaqrFBY1npl
         yysQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730504319; x=1731109119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=m5foUtv68hv7JVx4eEd+u1mO/CKPYfayN/tIEQe0sbQ=;
        b=rGr6DixP5Fg0dGc2b7moeTvy/gK5lngIRoIlxY/krxUf8a+j816+7q56FZOkRW6ui8
         CYhR48uBLbMk5vsV2gn/zx30xcv5TT8v+zRu2ipXSiZY9wsCoWcMfY/Z/rHO0gFYwQXQ
         S9omrQIvmYYhRBF33uZDwYsSTfcBTr1Qon0GNwfV7r7nI8R0/WkMh/1mfKIU+3yQFnHD
         Ly/GWnRa5AgQQlUzhZKoeNTziq55E0IV7ECN/fZmMUmGWM1PTDEi+ofD/dOQ/d+G6ZVH
         qx19r+7ClWm9rop7ZEe4BBrGkCjUpUvn3Edebt5QnBFWIvq5/b3Tqc4PBhg2AlmcxcUF
         36rw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUc3gH2hdRD2y47+9GmLxA0OaPZMCFFv4IlRb6fzzUdRd+unV9He0HP1U7qF4oNmrYq9sEBdQ==@lfdr.de
X-Gm-Message-State: AOJu0YxREvZ6GNG7czQRTr9ydETlLx20yahk6ku/yoxuMJ2bUqFoBudY
	/HU28DMo5WiPuuVF28ttLHQKWydMOcBmwKAhrVw8bhFlGpnsCjqe
X-Google-Smtp-Source: AGHT+IHglfKs/EItKC6dAz4oReyEZR9Zg0CY2gKBwYgrTOUbadywPNm+DujdaNA6SlFS+TKrSVgw9g==
X-Received: by 2002:a05:600c:1d84:b0:42c:ba1f:5482 with SMTP id 5b1f17b1804b1-4319ad36a7amr188247145e9.35.1730504318860;
        Fri, 01 Nov 2024 16:38:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c19:b0:42c:ad31:3854 with SMTP id
 5b1f17b1804b1-4327b6d7593ls11841695e9.0.-pod-prod-09-eu; Fri, 01 Nov 2024
 16:38:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWv1HogFaLoQrXs8Nw2bkWLwtcIWbQqPJEHHB/ADK1Z9zxBcsX35zNbcHip+3Z5pnCwhET5Ugoysvs=@googlegroups.com
X-Received: by 2002:a05:600c:3b86:b0:430:5356:ac92 with SMTP id 5b1f17b1804b1-4319ac7642emr215475595e9.7.1730504316890;
        Fri, 01 Nov 2024 16:38:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730504316; cv=none;
        d=google.com; s=arc-20240605;
        b=HuoSjSaF9cfOrH9qcL8v0/iD6272r/4awiXpelLFatBaNLHnYFCA9iHAKFtFOk1eFI
         /Z2b057W3iVYDl5vfMkQcHCy0HGdJ4qssbh0luinDXamKxRZnsdAEjfUfHXkK7Fijq5+
         4AFarFCATKFzFbyGbjS8ukKXrLIOc8ymUFudx8hkw5Jh+f+HlPE/3cStswkE87KWxWdF
         TGFB6k7Oht07GenRzWHFU2b1aWywOROPT77yDHDVznDTJrCEJd9geRf/2iFwgCpI2XRw
         6EF0yoxBimCncTR9XYGI1JiAn73JpIw6XdqNTX960TqrI5w4zVymxrcViGKGY1vu5M2B
         NCeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z5rcjHrmlWR+LzcpKryq3ZwD/HvuZwE0xyR9heRD69s=;
        fh=X3cXKTE4ZETZ1KnbAdA/GKyLm3mxtiIphy2QEQSVMKI=;
        b=ee4oO9TKHXSS6um+yU1O3AOc+krmXsSjgIxBuK7jS14SFWjqZSBlJ82l5H+orVQCL9
         W72S7i3K/Mjuy2LTmRrMpf14HwoZ7Y5sKuqXbu0vhQV3aiuqHukHB5HbRHc61ruLXMrC
         Q7UeBjksgoDPVuv9A9xBL+7ngBoucBwQQ3mn+V6MLCkXF00kfEl9Jjn3BRtrlphp0cZ3
         slV92Ljqc8a+DcWldChirqRc6Hytu7x4pLtyYK3avk2pwtclPsO5gkrhxAsbRJEUxor1
         JSiRu9MEmfkO2Dx4+ThRnvZv3bqFcsZeaQSeZXDu0pO366yeSM4JCyQtyxeOCPXu8KZU
         NILg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DqDM1vBV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431b43ab92csi4714535e9.0.2024.11.01.16.38.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 16:38:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-4316e9f4a40so19462315e9.2
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 16:38:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBApfu8SGUvy0w0P1d21Kb85phEejuvN784TiHHezUZh4Un5627BCWhEY3qI4EAlBViNSCjHS23h8=@googlegroups.com
X-Received: by 2002:a05:600c:1d1c:b0:431:55bf:fe4 with SMTP id
 5b1f17b1804b1-431b17365ffmr149672825e9.24.1730504316102; Fri, 01 Nov 2024
 16:38:36 -0700 (PDT)
MIME-Version: 1.0
References: <20241101184011.3369247-1-snovitoll@gmail.com> <20241101184011.3369247-2-snovitoll@gmail.com>
In-Reply-To: <20241101184011.3369247-2-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 2 Nov 2024 00:38:25 +0100
Message-ID: <CA+fCnZchoBgJp417G8dtNkiYnSY75hBmM=beDrxhJJyuPw=7iQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: use EXPORT_SYMBOL_IF_KUNIT to export symbols
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, elver@google.com, arnd@kernel.org, 
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DqDM1vBV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Nov 1, 2024 at 7:40=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
>
> Replace EXPORT_SYMBOL_GPL with EXPORT_SYMBOL_IF_KUNIT to mark the
> symbols as visible only if CONFIG_KUNIT is enabled.
>
> KASAN Kunit test should import the namespace EXPORTED_FOR_KUNIT_TESTING
> to use these marked symbols.
>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D218315
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  mm/kasan/hw_tags.c      |  7 ++++---
>  mm/kasan/kasan_test_c.c |  2 ++
>  mm/kasan/report.c       | 17 +++++++++--------
>  3 files changed, 15 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9958ebc15d38..ccd66c7a4081 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -8,6 +8,7 @@
>
>  #define pr_fmt(fmt) "kasan: " fmt
>
> +#include <kunit/visibility.h>
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> @@ -394,12 +395,12 @@ void kasan_enable_hw_tags(void)
>
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
> -EXPORT_SYMBOL_GPL(kasan_enable_hw_tags);
> +EXPORT_SYMBOL_IF_KUNIT(kasan_enable_hw_tags);
>
> -void kasan_force_async_fault(void)
> +VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
>  {
>         hw_force_async_tag_fault();
>  }
> -EXPORT_SYMBOL_GPL(kasan_force_async_fault);
> +EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
>
>  #endif
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..3e495c09342e 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -33,6 +33,8 @@
>
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANUL=
E_SIZE)
>
> +MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
> +
>  static bool multishot;
>
>  /* Fields set based on lines observed in the console. */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b48c768acc84..e5bc4e3ee198 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -10,6 +10,7 @@
>   */
>
>  #include <kunit/test.h>
> +#include <kunit/visibility.h>
>  #include <linux/bitops.h>
>  #include <linux/ftrace.h>
>  #include <linux/init.h>
> @@ -134,18 +135,18 @@ static bool report_enabled(void)
>
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST) || IS_ENABLED(CONFIG_KASAN_MODUL=
E_TEST)
>
> -bool kasan_save_enable_multi_shot(void)
> +VISIBLE_IF_KUNIT bool kasan_save_enable_multi_shot(void)
>  {
>         return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
>  }
> -EXPORT_SYMBOL_GPL(kasan_save_enable_multi_shot);
> +EXPORT_SYMBOL_IF_KUNIT(kasan_save_enable_multi_shot);
>
> -void kasan_restore_multi_shot(bool enabled)
> +VISIBLE_IF_KUNIT void kasan_restore_multi_shot(bool enabled)
>  {
>         if (!enabled)
>                 clear_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
>  }
> -EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
> +EXPORT_SYMBOL_IF_KUNIT(kasan_restore_multi_shot);
>
>  #endif
>
> @@ -157,17 +158,17 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
>   */
>  static bool kasan_kunit_executing;
>
> -void kasan_kunit_test_suite_start(void)
> +VISIBLE_IF_KUNIT void kasan_kunit_test_suite_start(void)
>  {
>         WRITE_ONCE(kasan_kunit_executing, true);
>  }
> -EXPORT_SYMBOL_GPL(kasan_kunit_test_suite_start);
> +EXPORT_SYMBOL_IF_KUNIT(kasan_kunit_test_suite_start);
>
> -void kasan_kunit_test_suite_end(void)
> +VISIBLE_IF_KUNIT void kasan_kunit_test_suite_end(void)
>  {
>         WRITE_ONCE(kasan_kunit_executing, false);
>  }
> -EXPORT_SYMBOL_GPL(kasan_kunit_test_suite_end);
> +EXPORT_SYMBOL_IF_KUNIT(kasan_kunit_test_suite_end);
>
>  static bool kasan_kunit_test_suite_executing(void)
>  {
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZchoBgJp417G8dtNkiYnSY75hBmM%3DbeDrxhJJyuPw%3D7iQ%40mail.gmail.com.
