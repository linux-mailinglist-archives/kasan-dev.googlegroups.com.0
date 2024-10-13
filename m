Return-Path: <kasan-dev+bncBDW2JDUY5AORBHW6V64AMGQE6AWGJYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3113499BA3F
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 18:02:40 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-43114c476c2sf23430985e9.1
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 09:02:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728835359; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZZYtsjR/OgDfxCltxlMSIrwx0aGFekodNiePddpd+k+l/qxm/BvS1coEOL5XRpPhxM
         dpJu8c1ioKx5D3Xqyt+k9tYO820Hb2wrfRa6FGZ+QJSq5k307CNq3e+cEuiuACchlUGG
         SVU7Ed2EwSeGN68nIvYRcxMu/W2ztKdj3bRhMMmMEekmLu8UkOfMij/QoEvjnrI/ZbAp
         n3eYwteC6K/z1aXjVgH8OGzp4FHIJC5RjFkDW0AwSLRWQy64wD/gY8k0pwlahPqR/OaH
         f/4efZoHeCI02gEJUr0hzfQ/ivck9D7M+p99KrswDEJ9l7VSFTrBl33v1NEZmwTnNMcM
         k+HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zTdet6b80tWX0SIGq14D8K//LPwSfk+pcYhT00ERlhE=;
        fh=hmj71vy9D+tjGzalrPa8F/rHhHTmX4epYglgML2IESo=;
        b=Crqwf3UBhqTSEutX/RDEovni2Zco12YN0Ln/FZJhjBeoRxWqehu5c7N6wMH7VfQe8h
         6Ii+440cGXa7JtlUUJfrT8r7uwIn4fDEf/r4PohFwN9dQPucFLATwcfl4r2UlrJlw4PY
         8GJF9SKbY7ltu/I47tE78G5H0BwytayLlca0oB+V6BTC1nGosw0aOELb36E5ta/yQNUn
         SVH8RdtYfJtQH/0doHrUjrnvxqiN0mvNfqvJY4GV7NLEQAlKcbTRKItEgzGYPfrpzsYq
         TUGaNU1dXNHnUvoYwzMUvgyw5C5qMDThtdwiM9Qyr09fe/nKsy1Gfel59Fgi13yOPRgA
         HwRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WVUB/oRz";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728835359; x=1729440159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zTdet6b80tWX0SIGq14D8K//LPwSfk+pcYhT00ERlhE=;
        b=JJOE3DgwxWvW03/8lVNcQYQZh25kJkkpGEiR4g7FFy10Y4vGYx+uQLvIxf6Dt7YFo9
         PgEZAtzhGy2DrQmjm29LhwIJMrp5YSFqg4FqqXn6xHq7Cs43vpVIUCJEiJPGCQGJgsPH
         3d+XkjE5nhaOX2dFrR3cujC0d5K6c8I0Kc2BYsNgHNP37wd5F5tVX/8bO2agNXBWUrDo
         6uT3rw7aDRq6LK+qjR1Bw0xTj2kEkeV4BZU3gBxgvEj5JzS9NY2yb2w3YvIssUkX2QLS
         lz6vH7dPpUQI1sUyWAhl1XbHqRx57DS17BhhT4FA37NJSiFkH+m8djnopIe4PriY8yhj
         rpmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728835359; x=1729440159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zTdet6b80tWX0SIGq14D8K//LPwSfk+pcYhT00ERlhE=;
        b=BZrtXSbZgiSdu6nI995oOw9HWXNGbLkHa1AZkb/+DPq9uS9lLZchSKXtXAevGkEaIw
         Ye2ke00QyHe6CtfAEhKpwP7QnXU8l+BQV6Zr2UH9QqBAMUjx06ahfu8mTK86v1Q6H9Rw
         3PU/DxNDUruYNm1np5MkvpIpOowYjDrTQl0/5VjKbIf+biSJo+tIvUEsjpGbCVBvazao
         My2682lhxZp+7oDKzeJiMOVaFbFEL8dpATchKY3EsdBCpLgPmLHbMAH8oehZDHC+FrLw
         xT8j057ct/UWMbJWip6+FYrdQ+RQb0eflDgt86z8EOB25LtoG0phKfvACnDm5A2+2J/F
         Mfgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728835359; x=1729440159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zTdet6b80tWX0SIGq14D8K//LPwSfk+pcYhT00ERlhE=;
        b=UMPTODP4dvCnZk4xLjghOeQvdg0ApZs0PBkjE0jZnfxs396UXTj3Sn8VX28ZC6dLW+
         BitsF39WmrfOv1DuoItLVBYbd1ghtwBUVdIHGYrmcqzrEqvM8AocjbhfzBjI1WEdzCL2
         YU45tnTDP+LVErlf/IRoV1LstrZ9oeBxtss9RQYLxkjFBFY4hecFbmsKx07c52sIIfZN
         N6ptcwqsbMrsVSmgW48w4NKPVHYjPtFYW1QCoAKiQg7ae9wJgYyh6BEghfqecj2upRum
         GwoMK74qyB6PyPWGxqhH55u746Ky66vif1lcbszdXPotv9zrbvOsYFR4Rovuo9QgXs4z
         +pUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqWmk3grgGvpeOWyiJ6U3+sbo0dLcVqxd2sf8ybSz92iAAwzT6Cben8zHG/RPWU7DVVjnHlg==@lfdr.de
X-Gm-Message-State: AOJu0YzURsr+7hpQPQURKnXgIpsRx5/AvnhiPTLIO+I9yKOKgbzxXXOf
	y1Lc3CIugqhJy4XuC8oChl0Nux/Q3ixLsSFfUsMBAw8Hg5f9NbIT
X-Google-Smtp-Source: AGHT+IFaX8ElfPX8gXyJB3qhvVIyaNRxYj/40P047R7hWo0z30WzOmIdYzIU+rEfn67bi6yOrBO3tA==
X-Received: by 2002:a05:600c:5122:b0:42c:b22e:fc2e with SMTP id 5b1f17b1804b1-4311dede4efmr71437625e9.15.1728835358584;
        Sun, 13 Oct 2024 09:02:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9f:b0:431:155e:348e with SMTP id
 5b1f17b1804b1-43115f179e2ls7219005e9.0.-pod-prod-02-eu; Sun, 13 Oct 2024
 09:02:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBTgj9p69ciSNeKot2t9bzLDf0Ka004oZeLEUQbTgKdSldYikCGo2ZELe9YhqxE6tt9hJa2earRrY=@googlegroups.com
X-Received: by 2002:a05:600c:1c06:b0:42e:d463:3ea8 with SMTP id 5b1f17b1804b1-4311df5c482mr75116875e9.34.1728835356928;
        Sun, 13 Oct 2024 09:02:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728835356; cv=none;
        d=google.com; s=arc-20240605;
        b=TLE6A5whXj5CXg9fRfHhVJ+AKqv5ldtNzOxNgqyb9yjuqEyZoZAHtXyPfWmxz+59W6
         mPSfi9tS5TNIMFJR/EeBMoGbxkTHXchbttu/WJ2VAAWn8Hg6r6XkAtnWrYjg363m7j77
         3wJOpE6wUcRNGOqBk5+eOl/6hThHb9ocT7R518BXfGX+yPLMDQG1rUj0RbCWkSw/+JoX
         dzLFE2VpT7mS4lVYrTUsdTitO9dvEWPkYjiEWaCJYpoIJZH3RgfSrwI454xHNQRO8BCY
         nUONWPd4NOEREbhuEOmGmQAKkMR6onLpURt74Cxc1N2AHktaslLVHj7GwN+jqAJYID5u
         Hbhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gtZxueZi13H6/At0/KFVJVek0RE4B8mMqip4J0nMs5M=;
        fh=f3nNs8cnz/QdUYJLqIKngO3fT367ESDpLW9D/WHkZU8=;
        b=dqyM0X2aAgbXapq/d5gizXTSbbwTvCc6hEAsLFgvzuxCIsiyAnRn0KeFU+pJ+IPyac
         lFxgroZzeOIo6JHPJhP4C8qLtGaRA9CmngaEUplDhqPgQyDbgSpIUNsHIfhlutPYiuvN
         tMg8QqidnnLS8KhBqDslDR163SxZ7FkuU6ny28PtkHMl/BS2J5NhjxEP/w6MnhSHOSSM
         sM8FY9vkxVpDmK3NbP2V9a2dO55NZvT27kSyLj7Qm0pvn7gbP5wH0Y7ZQqSYjffr/EhR
         I8j15vbxkZW2dg7LPSqaeDz+lu9JuRnQT0Bx8nXtK3ybVoY36e8F62r+37ypf2a43G8F
         xmvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="WVUB/oRz";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b6a434asi145017f8f.2.2024.10.13.09.02.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 09:02:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-37d447de11dso2509647f8f.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 09:02:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZtQC/r2ENjgucgdAqLJRay0Yt3DB/CptnLse10Rffc0xO4kguq+yUa0qKZopbPXfzzmVQt/a9bkQ=@googlegroups.com
X-Received: by 2002:a05:6000:4f0:b0:37d:5103:e41d with SMTP id
 ffacd0b85a97d-37d5529f022mr6528622f8f.39.1728835356135; Sun, 13 Oct 2024
 09:02:36 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
 <20241013130211.3067196-1-snovitoll@gmail.com> <20241013130211.3067196-3-snovitoll@gmail.com>
In-Reply-To: <20241013130211.3067196-3-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 18:02:24 +0200
Message-ID: <CA+fCnZfL2LHP7rBqCK5ZbsYu-jJ+2YbV4f0ijjDd_gQGiivNWg@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kasan: migrate copy_user_test to kunit
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, dvyukov@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, elver@google.com, 
	corbet@lwn.net, alexs@kernel.org, siyanteng@loongson.cn, 
	2023002089@link.tyut.edu.cn, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="WVUB/oRz";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Sun, Oct 13, 2024 at 3:02=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Migrate the copy_user_test to the KUnit framework to verify out-of-bound
> detection via KASAN reports in copy_from_user(), copy_to_user() and
> their static functions.
>
> This is the last migrated test in kasan_test_module.c, therefore delete
> the file.
>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  mm/kasan/Makefile            |  2 -
>  mm/kasan/kasan_test_c.c      | 39 +++++++++++++++++
>  mm/kasan/kasan_test_module.c | 81 ------------------------------------
>  3 files changed, 39 insertions(+), 83 deletions(-)
>  delete mode 100644 mm/kasan/kasan_test_module.c
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index b88543e5c0c..1a958e7c8a4 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -46,7 +46,6 @@ endif
>
>  CFLAGS_kasan_test_c.o :=3D $(CFLAGS_KASAN_TEST)
>  RUSTFLAGS_kasan_test_rust.o :=3D $(RUSTFLAGS_KASAN)
> -CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
>
>  obj-y :=3D common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o shado=
w.o quarantine.o
> @@ -59,4 +58,3 @@ ifdef CONFIG_RUST
>  endif
>
>  obj-$(CONFIG_KASAN_KUNIT_TEST) +=3D kasan_test.o
> -obj-$(CONFIG_KASAN_MODULE_TEST) +=3D kasan_test_module.o
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9..e71a16d0dfb 100644
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

Here, add:

+
+       /*
+        * Prepare a long string in usermem to avoid the strncpy_from_user =
test
+        * bailing out on '\0' before it reaches out-of-bounds.
+        */
+       memset(kmem, 'a', size);
+       KUNIT_EXPECT_EQ(test, copy_to_user(usermem, kmem, size), 0);
+

This fixes the last test.


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
> index 27ec22767e4..00000000000
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
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfL2LHP7rBqCK5ZbsYu-jJ%2B2YbV4f0ijjDd_gQGiivNWg%40mail.gm=
ail.com.
