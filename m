Return-Path: <kasan-dev+bncBDW2JDUY5AORBT6ZWC4AMGQEMWMG77A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E2AA99BBA3
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 22:25:53 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-37d67fe93c6sf413165f8f.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 13:25:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728851152; cv=pass;
        d=google.com; s=arc-20240605;
        b=LJ/RL0JhV2lmTFo8SArYWaZgI0k/OQT05rXCFkHRXXO82FFIyFqH/1LOIwD5usFzC5
         jjFirf1mX54gdvT02/BUR90Fui5GZhDtksX+bkrKdyYwOlTV9idNoQxiNlcpVmkzdEpj
         EKGA12IYCQA3D2PME6SRvak4S4HS4vL8Io9HLF+gkeG4ZoWNaTWrDVRzFlmpJK9wNzVu
         dpZf7r6HFWQnwjULbIwZRPorWoI0yo1p/EmCZhgOJosvvwMJnv8q0K3ZFzt7sldaTJi2
         L2vP7gVIJ+mhuvRufghgRuuVTCOALqClLthpHW4+tjurr12SSC9cYzHMr+JmwCN65JJi
         fG7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=czDJ263UgIbcjs4ZAATgyXwPP/aNM/k/2Eg2alESiPI=;
        fh=4qDQXBWCvt9KLp4FnDT0SkSijWfpSglXbul6kxOvPRk=;
        b=h58vJcx563/nGVEoe2h92a52xzX9NySsSViyD7aoEnzLt/XMRKRHF97zp/ISrwZOi/
         foqG8nYj4RBJjHBm0CC+bcQ+qYJIv+4OJJ1Q3q8ayy9UTE6oefOxy/3grUx48WOdosbz
         drYIFrRv9mF6crNGHEcve3WJTkwYdO7Pqw97mdXxOb53PO+NY+WWCZHhw4HGzyLTWTYl
         iDZ6tD1IBq0Tl4oiyU4Lj7bTrvhwT/WVZpQ/AsYhD7PdVXWhJc+1N1mq8mnGrNlw4vFm
         cmWRsu2KGtzNFr+nbo+1xX4oAzYHHk2s3f75KvNVQ6Ok0cjb3i4hpgHbe9E7oVWkvIUD
         rieA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mSNiz1E5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728851152; x=1729455952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=czDJ263UgIbcjs4ZAATgyXwPP/aNM/k/2Eg2alESiPI=;
        b=GAMHkslS0QzXTz2V9iwR4y2gbtQm4mmzD85GqJBbCeHFwOL0uqN0RkyWOcJpONNY6H
         vE6q1F31EiNQ1+A3kugQ4PaQwfw63QHCyb6pkSulyxyVjZgHBqR5ACm7GaQlpNIzG6w5
         vnTwJfg9NRzGlxde5qJLu9mWRILn+WB9HbwHuZJKJ+FWUGmaYP2wBnOOS00Nou8sJTnb
         Vhv7fw73GueCwKhiU4NF+SCGFhnWXknDJqTYeWD4WY2TpyCozIs7IJ+h6OG0HdVH8hIn
         QFJhlodaQnnRRt2PTHXyDgDOqgM9G2yaIs2tUSHYvoDndqfXpl+F73jwb0UhHQth1cCZ
         cQ2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728851152; x=1729455952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=czDJ263UgIbcjs4ZAATgyXwPP/aNM/k/2Eg2alESiPI=;
        b=VTk8FHOgc+lqcY8q+GVQ1XViVH2zv6/eCmvU4ZoWqQ1WtghyfdT2T9kiRW+E1cBYQy
         Lp8gJjLW+eXx5xNh6N6+dybmhKmPe1XktWZFgycJ4A+7xxuH9HyM2GWLZrWBZHK1gZJ0
         Z/FSxgp40Q3Wze6YI6XzogmNGKtOtHlNXCFPZPzYtxHYmp32m/ZGPAavQMZ5AFqhj0/X
         c6PnyXWDvAenNKeCQeyv5P0J8PxkgZkIGYYQQMVp1ZITk72mNvKF1pqfBmfAQxGb3ADq
         0dheIKECqQsgLECOcYDzPa53joxxqVx2FEetHnpVNeRxvDMzlGpH4wpJgmpMOVL3hY+c
         9tKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728851152; x=1729455952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=czDJ263UgIbcjs4ZAATgyXwPP/aNM/k/2Eg2alESiPI=;
        b=fH5J087gkp7+UyVoY8cOMAhbrXQNH/bmu6fWMS/lzkg4X5kr+nVwtDYTaLi5RU107M
         Ebc1jN+UAwAH73irhHmMUS+Qbxm0hg6jFpZtygFulp4WfnryjynpM+Z4X+9mBJPlJfiG
         JgSRQKRVRj1Txm3msOgqqvDejAgYbDjhoNWjuDwHPd4btLYSJc5iNHdLq7B6J4Us1XXA
         oQd6LkKwRLCvySR6hUP8b0S2X/lIgyOBB49n7sFd+OlDZZdcN2PD0qOYDrIrtqcoWeHN
         mfs2EiHtkXmVkfPHRgxRhrXOBFEddL/BojqblegdZG6475BoRmSwQhBZ9CAoVhxqLn4h
         ZUrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0SNQ9h1rjs+caGlUI6lh/ohuM2eIVcrj4TmkOPHmu3sxlxT85EEECnzBzQIBERB0RSUKw6w==@lfdr.de
X-Gm-Message-State: AOJu0YyJh6XHWtBrn8UB+FPvfR1u9We/aOZZpayM4dNeynZjsBmQJWwL
	nqAeCbufJD9Vy2oNRBUxKPFvsK72S4Q8+45eMlthsuOxNKg3JBYm
X-Google-Smtp-Source: AGHT+IF70hcVkohp1N3uJMXEzJbife+EoRg9dhd5CJhSxDZYMJ4pj9HUxxMdWSkSzO63yCC5JRrj4w==
X-Received: by 2002:a5d:6112:0:b0:368:37ac:3f95 with SMTP id ffacd0b85a97d-37d551fda4dmr6793349f8f.31.1728851151773;
        Sun, 13 Oct 2024 13:25:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9f:b0:431:155e:348e with SMTP id
 5b1f17b1804b1-43115f179e2ls7709545e9.0.-pod-prod-02-eu; Sun, 13 Oct 2024
 13:25:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcJhs7Gk9Ln1+WWnifF4vRrraqttjqo0eoODIYqkT1iUanYjruYHMqoiXlOxhDMmKGXcP4SqdluGA=@googlegroups.com
X-Received: by 2002:a05:600c:4f0c:b0:42c:b995:20d9 with SMTP id 5b1f17b1804b1-4311df57091mr90747505e9.28.1728851149877;
        Sun, 13 Oct 2024 13:25:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728851149; cv=none;
        d=google.com; s=arc-20240605;
        b=Wk3Zh+2bpH0Topwk+HIC68ktX0muSBQDymota5nrCZ3JiS1yDEPVbEPDu7d8W/luyO
         qFwJhsyGIzP+nRDnkOgneX97a+HwWJTOAjRiqbKfcdAOxy7UNe/bmkK5D8vyIXhigOlI
         w4woLudF4HM6aO3ZVIDcYxIJOZBDt4rMRT0/Jfy/xd3YVsSFY6YswmmhoG117azUK5GT
         Zfj50e1sQviRaIenB8ZCcAws5Gf4HLf9a+cEHcijeXEOWFWHzbwItDPi35A45DG+eY+K
         EMgOrN2y8oB+XYCG2r1qiEtLA3kumzOAJNtH6bX6AwpB3YQXNff85c45rSlwuUjNg3lN
         bKMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=f5zRtO73AocajQx7Xa+tWyH6u9NWSUZX7hX+fOXXues=;
        fh=uTfZQoL+gLR3ytfAeKErJg9dH8aoKxEauu8pPVF7Cm0=;
        b=W3fyq6VbzNhX+vqI9hbFSp11VAev+L7Jzdr3AAYSqDhimWDnol6MrGjUhARVH9ehPz
         JTLNwRi7U51r3MwMCOEPEyWLTKUFjwwc6vPAwKHTCTLFpSfstP6fehzy1h4Q4dX23oW5
         6buRd2HAmTyGwhSf7aaWUTTmkO0UPB3SeVYGcOKXcwaNreojbmAdljW3+dle/gfzKp8R
         B5YzTM8TQYqPiVm/O30ggIwiKWY1gJYlwqVcsf4lFGYGQAEohHoWX/p1D/SnZweJUsOH
         3RIOlK4XzaS0j2oiF2hxq22hfqxdlzuaFbMQgokzrqdcNcD3gkTgmAhZ0FpXyW4abN0c
         XbxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mSNiz1E5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43017462dd0si2989265e9.0.2024.10.13.13.25.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 13:25:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-37d447de11dso2608483f8f.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 13:25:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWMbz8jQ3yzvaIrg3Hij+DEC0pcIrwLqbStZmCIb0DKPog90Bpx1lViDTLjO6bzjhXXgA/nI+rshLA=@googlegroups.com
X-Received: by 2002:adf:b351:0:b0:37d:354e:946a with SMTP id
 ffacd0b85a97d-37d552d8d62mr6067449f8f.50.1728851148978; Sun, 13 Oct 2024
 13:25:48 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfL2LHP7rBqCK5ZbsYu-jJ+2YbV4f0ijjDd_gQGiivNWg@mail.gmail.com>
 <20241013182016.3074875-1-snovitoll@gmail.com>
In-Reply-To: <20241013182016.3074875-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 22:25:37 +0200
Message-ID: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] kasan: migrate copy_user_test to kunit
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: 2023002089@link.tyut.edu.cn, akpm@linux-foundation.org, alexs@kernel.org, 
	corbet@lwn.net, dvyukov@google.com, elver@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	siyanteng@loongson.cn, vincenzo.frascino@arm.com, workflows@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mSNiz1E5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Sun, Oct 13, 2024 at 8:19=E2=80=AFPM Sabyrzhan Tasbolatov
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
> Changes v2 -> v3:
> - added a long string in usermem for strncpy_from_user. Suggested by Andr=
ey.
> ---
>  mm/kasan/Makefile            |  2 -
>  mm/kasan/kasan_test_c.c      | 47 +++++++++++++++++++++
>  mm/kasan/kasan_test_module.c | 81 ------------------------------------
>  3 files changed, 47 insertions(+), 83 deletions(-)
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
> index a181e4780d9..382bc64e42d 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1954,6 +1954,52 @@ static void rust_uaf(struct kunit *test)
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
> +
> +       /*
> +       * Prepare a long string in usermem to avoid the strncpy_from_user=
 test
> +       * bailing out on '\0' before it reaches out-of-bounds.
> +       */
> +       memset(kmem, 'a', size);
> +       KUNIT_EXPECT_EQ(test, copy_to_user(usermem, kmem, size), 0);
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               unused =3D strncpy_from_user(kmem, usermem, size + 1));
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -2028,6 +2074,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

However, I didn't get a cover letter for v3.

Normally, when sending a new version of a patch series, you need to
resend all patches with the new version tag (even if not all of them
were changed).

Since you didn't resend them all, as it seems, at this point, I would
recommend to resend the whole v3 series tagged as [PATCH RESEND v3].

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcyrGf5TBdkaG4M%2Br9ViKDwdCHZg12HUeeoTV3UNZnwBg%40mail.gm=
ail.com.
