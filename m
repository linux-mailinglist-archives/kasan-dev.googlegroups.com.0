Return-Path: <kasan-dev+bncBDW2JDUY5AORBAH537BAMGQEQMQCKDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 38AEFAE3005
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 15:00:51 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-32b32ce581bsf12963501fa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 06:00:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750597250; cv=pass;
        d=google.com; s=arc-20240605;
        b=U1y5JRBZJU9Ub9kQfkOKCcGwtBPhQ3PePrSDGRZl6HfglpzVAG47+C6TpT4rVAyfTT
         zuGsbiTEpTUt6MhbqMBeLEfApmNMSdetoZAQozRxZLauv45iYHtHn979ImwvSzNpY/so
         kp4s83366BGOKkcSL5nf3g1Z/tV5Q5lh1CkVgOFJn1/FxRrE86hLTwNKQ1r3a66skL2s
         cCM7QuuR0HKyXZqPWkbj88W60gCmS4ZH5hVN2LcbRqD20VLYJfdfuz8lCyapXyGJMMHr
         maoU0COBpCwy0518KJfBBjVB6wwVen1Cy/hBtpiKjnxC3ukP/EOwYr9pBHq00PLcKsd0
         AnaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=eD89cBb0WTkv9Cc13sYuv3KKlG5VvxYiVrDcFxwn3uQ=;
        fh=zm7bcFoH+GFW1xfhkdwI3xHYeAvwxWm+NLDQoycCbHQ=;
        b=UlU/3rg9fJEeG6H42pVodF+E7w3+FM/lBOJbEHN8VosfxRZ7svHN2cUvmhK1w7J0qZ
         eKhbjTIO53P6VhTij6eG7dTMqVE/jJirDP141/IG6I1oY2tDXy0OymHRedMNpv/2qZzn
         UYC8SqkBY5/c/3ULtKlECpuUKXx4i45XBz72th9zAWFrALSA8XgcnhEQWvl6IM2SpL83
         054nQbTUNLW2pUEi3lcedi5CvQjXCZdzoM9du2ZDf4tl2v0Uz6WQpef56IJoXzkiizU7
         oKuzHocysHBPyr/ATfpO4a5WM8ICJneqf2V8KamewjBR0tTmsX4bOhkrZRScPxch7+fb
         PCcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d2K49FZo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750597250; x=1751202050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eD89cBb0WTkv9Cc13sYuv3KKlG5VvxYiVrDcFxwn3uQ=;
        b=WXN4Apwyj2uXDCv6OnIEZSkm4ajkPpMQrZPkpQhs0nu0ARXU+i+X08u7QUv4cDzgfn
         oiixQ3yRVx+ub/ss00YMggZ95Ng7xtNgxfQQrkHNCGN4cWj7W6ty/y1ooRlwSukiWPbY
         PjoH2/XGxrErNRsXbj4PMHzEwR6Sc9DeuUCMcAtclSBOwr1Su1p7Zqt+YNvpIUXTuM06
         igByYLGLYwoeIDA/bgYm2pWBRtPX/5LqkSx3KiQ1SnAUk3PGq8WASy1BqwPOO0S1tjKF
         T5kWMP11bV8YhMK/AZSUA7o7yKbXd8CDjY7/ufeOYMsk2VHkKZ5Ilo2RNfMu5UnvWm4l
         UVJA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750597250; x=1751202050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eD89cBb0WTkv9Cc13sYuv3KKlG5VvxYiVrDcFxwn3uQ=;
        b=STkLHX6p727eeqxS0TmUL2AN8B+tYjvNh3m8mMxGf+wAbJ3A3iAg2lH/i2cQQcZX71
         JdCF1RCHwSpnG7alJHrMqYN7+SQUwiMbX/qnhwyWogiCxlY3EAZn6zdst4M3zutcgfYD
         o05vcXk2+PsA0n6mlGWpmGGznpsszDTrYCvJLJ3zEUon0LRcCTHEFYL204QW7IZTpYrk
         7dhuK+RN51BnlgbyTAbIs+Fe+iK6paRFpuYBtqWLsR/6jRdlA9XQbDrTjPrO1v6alPkA
         YQhpg+untTG8CjRwkNH1vSSRlHw1d8C6ieG5aI9aX0VklWoQvk4AQqeIvkoWswDvncid
         Go9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750597250; x=1751202050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eD89cBb0WTkv9Cc13sYuv3KKlG5VvxYiVrDcFxwn3uQ=;
        b=QOF3DeNl/SUcNYQ4Y6TBR8GePICI5bHvDTzTsIVtCC6IIvpAo0vS3ZcpYc39rI0gFj
         6Q9itsQ3gwDA4UsMwU4S0y6uJ/iwJCQOrxvn29GJPP0L2BZImkY4KtcyAJsDL+wpO2cv
         i3iW7sLq5euuRWK8FeOSjynPDamUrz1X3fzgTTGGOl9QQ8mIJP0cEOTvQhzv/dv/hoGC
         GJg4S/aXKzYszdZf/afrWuzZw39bOjiGt6oq1SZci1RHhgeJIySxjebimb20/d4xP0QE
         +HDgKmBMOnw7zi92UTiAK41y6LH+haVq/f9a2HZJ2NDFst/m7NVSyls0AfTNJ6ogDHV4
         Qg/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUq5cr9CPeCUCcIVGC44dcd9T+eUAjgSJLMGNkRsnXK66FXdYj9Kz8vQ2gtucNeY8e53dhRVQ==@lfdr.de
X-Gm-Message-State: AOJu0YxPdWO3oHDJGPxoQRykr9ZwnicuP3EsKzC/VDlOPQ7VZWSC7kGQ
	PAXMwwZAlh+COzlv4vrzdiiamHPWKc3ZJPHjgPlMpXQjXgBA5elOPaQG
X-Google-Smtp-Source: AGHT+IEXTvb08u6tFVQ5s0BI5AcKKJX0hvYLh2+TPR6D2hymr6aGVd5usJYTasF6Cn0N4OuBeQBAfA==
X-Received: by 2002:a2e:b742:0:b0:32b:78ce:be8e with SMTP id 38308e7fff4ca-32b98f5ed50mr23338181fa.32.1750597249255;
        Sun, 22 Jun 2025 06:00:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcENE7MyvM68S1bIOowFwbm9a5d/X8kknBpAmHOF24aFQ==
Received: by 2002:a05:651c:f16:b0:32b:2c5f:c18f with SMTP id
 38308e7fff4ca-32b896c062els5439071fa.2.-pod-prod-02-eu; Sun, 22 Jun 2025
 06:00:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCOxyEzAPO+aN1CXGEppefS8MZy+ZNGmBpRvqApIQElZ2hs4mnTjBm5C7NWO4LRNduPTLVLsDiJoQ=@googlegroups.com
X-Received: by 2002:a05:651c:b10:b0:32a:ec98:e15a with SMTP id 38308e7fff4ca-32b98f72ab1mr29258851fa.36.1750597245751;
        Sun, 22 Jun 2025 06:00:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750597245; cv=none;
        d=google.com; s=arc-20240605;
        b=Ijm6OtOLyd8kKJz/LDfuHvw9InmtR6KVTjSmPFbF8HFgIYzgqtX9IMvM+Q6j88ONsP
         4tkGyl0/NNDUK/7+njO5+qYfODm1OTmEIyMmSzBaeODO+gNCtOh3sst1BvseBNsHjz1g
         lQDLI7pqE/VbaOzWUZ4aseZtXiLRx9V4y4i3tsxZfXiE0S7hqwkn5Wwbnz6GzLND4s3S
         0LsK2eeGDtgP7INTfzOaL3tyDrA2QBDoRo9FYpxY8NFQFr1ZlKVjZ06uuSXSjg8Kknbp
         E/hAIXLjCEaOoCPiF1l5pfu8K06Q1/fIqIcLPMZBEepkS+t/uZLZ7DUokCVxVX/8kjk6
         eVSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fdJCP3IGjFjNpzPk6xWCR4zsn18tfTf8CrLc1ojCZko=;
        fh=GVVfwI/5yZangKTgG06bARQcyTyIWNGV7fvQU6WkS6E=;
        b=gvN7ck27ljFPQup/qdamNmpdu+8z8XlyINnnPoB58c+CilBEb8fSPKKrpoCwpc+EUL
         FYHK0paRVHcCJ/f/SWaFtrDjM4OBTnz1QOju5+bdFiRp0L6lDjoqmTYXlLFV/FglV6+5
         BvHCxBJajAEGtWuOSsMqAIWaQ1OtQDwpIwYDfbrMme1ZRncVkmx1bor9xg6gr1AMuvIA
         /JjnJgKnHRAha/EssYEXYoXc3BcTeD9W8Wc6vWf557DT7HW7QTRWGoCFUIR5MI3k9v2N
         97LKO5JIf0FEYxfddqFT5/DAVk4fZn1At/7A/4NyjzFgNKVHhJ8DxZp8EuOf2uVgl5VQ
         4ARg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d2K49FZo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b980a016bsi1109431fa.3.2025.06.22.06.00.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Jun 2025 06:00:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-453749af004so325125e9.1
        for <kasan-dev@googlegroups.com>; Sun, 22 Jun 2025 06:00:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWQN3l4/2LrNrs2Bz7+ljdEJRrZihzmmqPA9a+w8uCVJ7ZBNBLPVbAmt3zy0J6r/Wa2WKWtvktsffI=@googlegroups.com
X-Gm-Gg: ASbGncuyMgYkn8ZlxwVIFBn5S9g8X70LuXYazyJnkW4GSG+4TN8sraGAjtHztZkvs7j
	EnELTibFHfTcBaSrOFkDAvTWH7YC25xdDukQCzPGDBVfQ9fCnKqgmTGI0byC/Mkcfr8dIvM0d+7
	grr2t2yNQJ3BwlVeSphvCjQcGbDCX5TC7CJ012YkLNGyBATw==
X-Received: by 2002:a05:600c:c4aa:b0:453:a95:f07d with SMTP id
 5b1f17b1804b1-453654cb7b3mr107100065e9.10.1750597244951; Sun, 22 Jun 2025
 06:00:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250622051906.67374-1-snovitoll@gmail.com>
In-Reply-To: <20250622051906.67374-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 Jun 2025 15:00:33 +0200
X-Gm-Features: Ac12FXwDCMDtes9nEuHZSX21IEb-3roo_RAemSxrzaRE-NRx5fyXMcdS_EvWEQc
Message-ID: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
Subject: Re: [PATCH] mm: unexport globally copy_to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, hch@infradead.org, elver@google.com, arnd@arndb.de, 
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, david@redhat.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=d2K49FZo;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
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

On Sun, Jun 22, 2025 at 7:19=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> `copy_to_kernel_nofault()` is an internal helper which should not be
> visible to loadable modules =E2=80=93 exporting it would give exploit cod=
e a
> cheap oracle to probe kernel addresses.  Instead, keep the helper
> un-exported and compile the kunit case that exercises it only when
> `mm/kasan/kasan_test.o` is linked into vmlinux.
>
> Fixes: ca79a00bb9a8 ("kasan: migrate copy_user_test to kunit")
> Suggested-by: Christoph Hellwig <hch@infradead.org>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  mm/kasan/kasan_test_c.c | 4 ++++
>  mm/maccess.c            | 1 -
>  2 files changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 5f922dd38ffa..094ecd27b707 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1977,6 +1977,7 @@ static void rust_uaf(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
>  }
>
> +#ifndef MODULE

Would be great to have a comment here explaining the ifndef.

>  static void copy_to_kernel_nofault_oob(struct kunit *test)
>  {
>         char *ptr;
> @@ -2011,6 +2012,7 @@ static void copy_to_kernel_nofault_oob(struct kunit=
 *test)
>
>         kfree(ptr);
>  }
> +#endif /* !MODULE */
>
>  static void copy_user_test_oob(struct kunit *test)
>  {
> @@ -2131,7 +2133,9 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> +#ifndef MODULE
>         KUNIT_CASE(copy_to_kernel_nofault_oob),
> +#endif
>         KUNIT_CASE(rust_uaf),
>         KUNIT_CASE(copy_user_test_oob),
>         {}
> diff --git a/mm/maccess.c b/mm/maccess.c
> index 831b4dd7296c..486559d68858 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -82,7 +82,6 @@ long copy_to_kernel_nofault(void *dst, const void *src,=
 size_t size)
>         pagefault_enable();
>         return -EFAULT;
>  }
> -EXPORT_SYMBOL_GPL(copy_to_kernel_nofault);
>
>  long strncpy_from_kernel_nofault(char *dst, const void *unsafe_addr, lon=
g count)
>  {
> --
> 2.34.1
>

Other than that:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeb4eKAf18U7YQEUvS1GVJdC1%2Bgn3PSAS2b4_hnkf8xaw%40mail.gmail.com.
