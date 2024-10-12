Return-Path: <kasan-dev+bncBDW2JDUY5AORBRHYVO4AMGQEIZ7EOPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 90FDB99B787
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 00:46:31 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5390f02e11bsf2622921e87.0
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 15:46:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728773191; cv=pass;
        d=google.com; s=arc-20240605;
        b=RZuwE/7bAFtXNuE+wCoBxP9MDxuKa7nD+Q8cYCXqohdGG+ArdMdFjx6k1f7jMhsCo6
         hR3CeHiI7ZNfQMqcjk1cLPrSHEsur+Y/wNXAcAMAxavKqQfPiPYjl0vxBqZh4w4/SNdW
         T3VqZc8C1/klOqQ8lVP3dIs8NRJzYC0iWNzkP1USdYDJZp3yTauWnB269VZ6CA/BbcKh
         rdRc9/fRqwWvSEmvSlHVtXyptyRMomr+Yty/+W6AjjoVyNEJV5i1Gn3VFzqqhS1xLvfC
         swiStH2TvxiRYwvPZv9Wcw39oAJgFmfWvT3FSUBpfQiCfZBt2FfC4dzPPXoY1WkIO2kS
         aUMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6esVwP6w6r0SyrKtXea5d9jyHp3slHmaGr3hH937+UA=;
        fh=fS/LHxOjcQVvbaeIe5Fiyp/f6uKwDL8uZQ89O4zXHpo=;
        b=GCgGM4nSeR6AhqG9eNRNFotNytkiOXuV9kH7OSjPMjwe3VvmbCDJnQFdUZCfJQUj3O
         Qlk8uMojDrPl42EFeBcGwV4QbvGIPmqB84xnIYQ2cRtpSRNQqbMbwE2yEmfjFqVPKDf5
         vleEX3wowLDyolhOB03fN5jhEgCG6EMF1UfPPnB9Bi4jDcKMTiE8bUInerLyhTFpqaOU
         DY1HT31k9E0c4sqnILtAJ8wmz/DiJ5hwbD97LPHmhPnajGZG7rflgxVZXjG45uUYv+2c
         UFyKJ9RTL19Veb4MWmZJTc9MzO1EXbyYeY55boKFNchtzIsSTfuImMbI9X/uWVtBdcWK
         bL9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IpKf2kvD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728773191; x=1729377991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6esVwP6w6r0SyrKtXea5d9jyHp3slHmaGr3hH937+UA=;
        b=sLyJv0OdU8qMdl97In7FAQywduc1Ch/mY3G+WABzEmlW8VTGhxBALgLedA7jb8OUTL
         kMISGRCmfjXhsNiVuYCGqTGGlJuMCf57OXhplsadV3uVdVFXd4vxbWAMglGjV20AsyNp
         KS8QFqadH5I10RiXyW2dfxVKRPnK0TjR1CrWsBGzqDjk8seKUdsRl+igL3tXZ0VwowpQ
         2TnQfWXj27H3vwjhfUQeVWuwMQCqMNDz7b/wCa342hXelu2+sgLm4JRCOh5NE2sQwVFe
         Tpgiw+tOpf7+MH/fn7HzYIDzcfvknGNPNF/I+y5LSVZFTyCieERtWzTMxrmTdgYOSYxI
         dHhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728773191; x=1729377991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6esVwP6w6r0SyrKtXea5d9jyHp3slHmaGr3hH937+UA=;
        b=Yy7+W5XR0M0oCndPcNyyiWcRg50VB88n/2NwelxdZ6KJERWkqIq/b6dhISBGRdYeU1
         YRjpmDRBCPvzAQu8fq/kGi7h2pgySXzUgBVc4/wREoCDR/DtGjmvDcOECY8VktP+atnC
         IO+Kc8ScIHIWkfIBq/ofuG74YswL+qEiP/pRfHeOmHobeo4h5UHHUr1UeDkojX+J56Ci
         l52+qmalzJNlQQju+IuanNRQeghicsqqt3o3CR+ruNQciqLoEZz5Q2x4c0whl+JMRb6g
         2VFazJEe5Ur5nY5kht2A33KaVOMtiIDstqSFFwvxWtzU7FN1ylWBpJwYELQFNIthJ6kO
         qbnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728773191; x=1729377991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6esVwP6w6r0SyrKtXea5d9jyHp3slHmaGr3hH937+UA=;
        b=YAfomT37F5mIvscJWuEo/YC1kD5jSFuzbb/N1OqoCLeQe+sv5kdpUc06Uy+/pWzUkL
         SCfoB7HIRVKAgy+WDh2Add2ISqwiiDAKFJ8HzbQ/s9MALaEbdeWGDwfwAAawH0Yzji/D
         RDQgm6SxTFu7vyDB9nI29Bc30qneGKbk6QulNzN0VUENMwrud1Eumj83OWS1L3+tOyU3
         2/wD259eCW6PQnY8BRytjc9/7aeXHFPqwb4toebpCr5uJxQ8sXy/3jjbzKIb3BnLHkzD
         viP83oyKzjnwGPTZQz+XSwhPf1DWiYgxQ3/Be7O1FzAgGIPxFqvb/w3Py9QcFiYhtrxq
         1uLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcdZUW4IyFrL01+j+vLrhhYSob5SFxcgtp/g/ACo4xpugN+eCnp5StqCQBLc+Ofgtshl8vFw==@lfdr.de
X-Gm-Message-State: AOJu0YxJIHOwbcQf2NHOuHWVS04zrfkxc9EVYCahHzPNJChi2VFwjzfZ
	bAe2mTYrB/67J3xFRGOlSra9D7/36e96TfrOUDJ0a39NX7QOrEPD
X-Google-Smtp-Source: AGHT+IGQeRLavIoJnz+/auXozdLRTsf395nO95jBdnPJCC7OEZHesr8IzcLF2MlVuput6Rt8i4IRoQ==
X-Received: by 2002:a2e:b8c1:0:b0:2f7:90b8:644e with SMTP id 38308e7fff4ca-2fb326ff6b6mr32505451fa.1.1728773189204;
        Sat, 12 Oct 2024 15:46:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f01:0:b0:2fa:c8ad:64ae with SMTP id 38308e7fff4ca-2fb21276da5ls7406041fa.2.-pod-prod-07-eu;
 Sat, 12 Oct 2024 15:46:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoTCRGnjnXPhmaWgTfHzJgIVV8QDsl6o94PjSwAMDpNc0vD6OBzJT1weAQc1lYdZAc2skL9vnbD3I=@googlegroups.com
X-Received: by 2002:a05:6512:3510:b0:539:e14b:309c with SMTP id 2adb3069b0e04-539e14b4496mr2137159e87.19.1728773187067;
        Sat, 12 Oct 2024 15:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728773187; cv=none;
        d=google.com; s=arc-20240605;
        b=T733SJl7B6tHZ0bC8FVNZokkLQab+Fx8OSQQUrsruVuyIl43vSTh22kfjB6JchOtkG
         QJd93MXyzgEWxIKOgRMLRcAiT1mHjZomBKsXzWngafCT3F6go22vrCl5PfUuLrL3UtuF
         1Q8jmjsX22BokKL6sqroxR+oKMdvNQgnt6UpW6fUGQKWDYpFjcQmydPbIjE+Qo5EBS6r
         80vSu3FBrwV4bPmUWRIcZMu3Rf0e3Ig3BmGtw+/3SOJKNlzac8tvM6oHVvXtuLuHVEB9
         mfILAoz88nso/n6fTI/LUa3ME5d5llw0gfmz1WfiUNx4EoU6JyRooICHvUYR1hB4esdz
         bMew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=g/aqTd2ota1+xNkB76pwMkxv208Q7EfGMyB/sMwBaR8=;
        fh=nVW9FjqZWuyLKUps18lRloJd+TbkqbItUmKN/h5qo4Q=;
        b=U1zOixuM3IGd9fW10PMWXxFPiuRB5DGK55MSnVzr7fmZdyrl4G8ot75Ka+3XfEi7ba
         snewmA+JgSlNHyokufnYj+ObshZcOSJAmpiOWwj3BidZ7H74I4uaI7mZhYG88Tqtr4wT
         nv+qDPGKJPDsf+fiz28dFHz4aYjE5TeszqbQZRTfuYJNdl7S/JA9hsZrrcVMSQfXTbme
         4I1J7MA7aUG9tT53GwpaRstQepsYlZiLOrCGs7nBHWAqobahvUMEP4G9QTG3o+jnzJit
         XCqccw5u8+lCrxdOWtPpQmZawGIb5VFmhWuSv4bh35iK7OqnDbJlv2qd/Wabj6rvzykL
         hZKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IpKf2kvD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539e429101fsi46007e87.13.2024.10.12.15.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Oct 2024 15:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-43115b31366so27906155e9.3
        for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 15:46:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXayGv3y2ObY9YMg4HG8xUcy3eC4Xtt62sY4FBsjIxM0J40ymUnUSxIPnLNuP1s5eaK+rjlxXsvCic=@googlegroups.com
X-Received: by 2002:a05:600c:3589:b0:42c:b55f:f7c with SMTP id
 5b1f17b1804b1-4311dee58dfmr52756185e9.15.1728773186082; Sat, 12 Oct 2024
 15:46:26 -0700 (PDT)
MIME-Version: 1.0
References: <20241011071657.3032690-1-snovitoll@gmail.com>
In-Reply-To: <20241011071657.3032690-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 00:46:15 +0200
Message-ID: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: migrate copy_user_test to kunit
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IpKf2kvD;       spf=pass
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

On Fri, Oct 11, 2024 at 9:16=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Migrate the copy_user_test to the KUnit framework to verify out-of-bound
> detection via KASAN reports in copy_from_user(), copy_to_user() and
> their static functions.
>
> This is the last migrated test in kasan_test_module.c, therefore delete
> the file.
>
> In order to detect OOB access in strncpy_from_user(), we need to move
> kasan_check_write() to the function beginning to cover
> if (can_do_masked_user_access()) {...} branch as well.
>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D212205
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  lib/strncpy_from_user.c      |  3 +-
>  mm/kasan/kasan_test_c.c      | 39 +++++++++++++++++
>  mm/kasan/kasan_test_module.c | 81 ------------------------------------
>  3 files changed, 41 insertions(+), 82 deletions(-)
>  delete mode 100644 mm/kasan/kasan_test_module.c
>
> diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
> index 989a12a67872..55c33e4f3c70 100644
> --- a/lib/strncpy_from_user.c
> +++ b/lib/strncpy_from_user.c
> @@ -120,6 +120,8 @@ long strncpy_from_user(char *dst, const char __user *=
src, long count)
>         if (unlikely(count <=3D 0))
>                 return 0;
>
> +       kasan_check_write(dst, count);
> +
>         if (can_do_masked_user_access()) {
>                 long retval;
>
> @@ -142,7 +144,6 @@ long strncpy_from_user(char *dst, const char __user *=
src, long count)
>                 if (max > count)
>                         max =3D count;
>
> -               kasan_check_write(dst, count);
>                 check_object_size(dst, count, false);

I think we better put both kasan_check_write and check_object_size
into do_strncpy_from_user, as the latter is now (post 2865baf54077)
called from two different places.

Also, please put this change into a separate commit with a Fixes:
2865baf54077 tag.

>                 if (user_read_access_begin(src, max)) {
>                         retval =3D do_strncpy_from_user(dst, src, count, =
max);
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..e71a16d0dfb9 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1954,6 +1954,44 @@ static void rust_uaf(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
>  }
>
> +static void copy_user_test_oob(struct kunit *test)
> +{
> +       char *kmem;
> +       char __user *usermem;
> +       unsigned long useraddr;
> +       size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       int __maybe_unused unused;
> +
> +       kmem =3D kunit_kmalloc(test, size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, kmem);
> +
> +       useraddr =3D kunit_vm_mmap(test, NULL, 0, PAGE_SIZE,
> +                                       PROT_READ | PROT_WRITE | PROT_EXE=
C,
> +                                       MAP_ANONYMOUS | MAP_PRIVATE, 0);
> +       KUNIT_ASSERT_NE_MSG(test, useraddr, 0,
> +               "Could not create userspace mm");
> +       KUNIT_ASSERT_LT_MSG(test, useraddr, (unsigned long)TASK_SIZE,
> +               "Failed to allocate user memory");
> +
> +       OPTIMIZER_HIDE_VAR(size);
> +       usermem =3D (char __user *)useraddr;
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D copy_from_user(kmem, usermem, size + 1));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D copy_to_user(usermem, kmem, size + 1));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D __copy_from_user(kmem, usermem, size + 1));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D __copy_to_user(usermem, kmem, size + 1));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D __copy_from_user_inatomic(kmem, usermem, size =
+ 1));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D __copy_to_user_inatomic(usermem, kmem, size + =
1));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D strncpy_from_user(kmem, usermem, size + 1));
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -2028,6 +2066,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
>         KUNIT_CASE(rust_uaf),
> +       KUNIT_CASE(copy_user_test_oob),
>         {}
>  };
>
> diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
> deleted file mode 100644
> index 27ec22767e42..000000000000
> --- a/mm/kasan/kasan_test_module.c
> +++ /dev/null
> @@ -1,81 +0,0 @@
> -// SPDX-License-Identifier: GPL-2.0-only
> -/*
> - *
> - * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> - * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
> - */
> -
> -#define pr_fmt(fmt) "kasan: test: " fmt
> -
> -#include <linux/mman.h>
> -#include <linux/module.h>
> -#include <linux/printk.h>
> -#include <linux/slab.h>
> -#include <linux/uaccess.h>
> -
> -#include "kasan.h"
> -
> -static noinline void __init copy_user_test(void)
> -{
> -       char *kmem;
> -       char __user *usermem;
> -       size_t size =3D 128 - KASAN_GRANULE_SIZE;
> -       int __maybe_unused unused;
> -
> -       kmem =3D kmalloc(size, GFP_KERNEL);
> -       if (!kmem)
> -               return;
> -
> -       usermem =3D (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> -                           PROT_READ | PROT_WRITE | PROT_EXEC,
> -                           MAP_ANONYMOUS | MAP_PRIVATE, 0);
> -       if (IS_ERR(usermem)) {
> -               pr_err("Failed to allocate user memory\n");
> -               kfree(kmem);
> -               return;
> -       }
> -
> -       OPTIMIZER_HIDE_VAR(size);
> -
> -       pr_info("out-of-bounds in copy_from_user()\n");
> -       unused =3D copy_from_user(kmem, usermem, size + 1);
> -
> -       pr_info("out-of-bounds in copy_to_user()\n");
> -       unused =3D copy_to_user(usermem, kmem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_from_user()\n");
> -       unused =3D __copy_from_user(kmem, usermem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_to_user()\n");
> -       unused =3D __copy_to_user(usermem, kmem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> -       unused =3D __copy_from_user_inatomic(kmem, usermem, size + 1);
> -
> -       pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> -       unused =3D __copy_to_user_inatomic(usermem, kmem, size + 1);
> -
> -       pr_info("out-of-bounds in strncpy_from_user()\n");
> -       unused =3D strncpy_from_user(kmem, usermem, size + 1);
> -
> -       vm_munmap((unsigned long)usermem, PAGE_SIZE);
> -       kfree(kmem);
> -}
> -
> -static int __init kasan_test_module_init(void)
> -{
> -       /*
> -        * Temporarily enable multi-shot mode. Otherwise, KASAN would onl=
y
> -        * report the first detected bug and panic the kernel if panic_on=
_warn
> -        * is enabled.
> -        */
> -       bool multishot =3D kasan_save_enable_multi_shot();
> -
> -       copy_user_test();
> -
> -       kasan_restore_multi_shot(multishot);
> -       return -EAGAIN;
> -}
> -
> -module_init(kasan_test_module_init);
> -MODULE_LICENSE("GPL");

Please also remove the corresponding entries from mm/kasan/Makefile
and lib/Kconfig.kasan and update Documentation/dev-tools/kasan.rst.


> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui%2B8RQ%40mail.gm=
ail.com.
