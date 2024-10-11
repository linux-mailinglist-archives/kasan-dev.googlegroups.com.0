Return-Path: <kasan-dev+bncBDAOJ6534YNBB3OXUO4AMGQEPASNTZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 903F5999FD9
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 11:12:14 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2fad27f65bfsf14396711fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 02:12:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728637934; cv=pass;
        d=google.com; s=arc-20240605;
        b=lVIMWdUVVX5ro6MsdAaSPzYpH4jatqXv+oy78BtN4UDDiygSDv1Xump+bHJWw7xMwT
         6wKceiJlcF4WNfU2GhaOkB3Jt8uQrAI+9c5xyq7XWtObHYflERMDMQFtG0BVNxX99l6s
         ElqYpnj9txbw4V/7/PE937D1wUg3pSZKcqR6ZPufBRKVhEB1ezDTT6YZupQ0pOR6iKs6
         0VLn4gA8mcaWyQGglmyEayuaqJ8Rug6ZCMatuPh4J1f2fzmZdSmzrN+yk7NFfgLhxUG+
         ze81z9QOJyMIVK5Xgp3vlQl2VVv2yIb4cRfwXhCHB5q30ReB0BmqATf/UMchWDHiVaU1
         1wBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LNZohQek+9BCllCIi3J03VkxY+AkUWs9eUAN9bDX2KY=;
        fh=RsbCQPrYhwZVPbnOp6d0qe5mm7Y43LXVk0ILJQw4K40=;
        b=eGrksQiQSI27gJkmLnErKDbx56QR5mdrphxsr5cZh8SpKTR8FvbaS5dH6GSD1jdLLv
         zAVhRAPDWUi5L3sZmKaVelTf0RVixy9lye12Ay384KncRC/aUJnxJ5Qn/Djpu3nCAtEY
         vCO5oxuQ5A/m0u48TUo/d9H1t4eqnKrvLXSgLsefCK3lY/KJ1ieGzeYclw8oeYQ1qUxO
         cnng7VsYBpNGr+vRT07o7qWQnwnIq9G+RGL2pUiJBAQJp8BTHcelg8ZkMoDAhQlwUeWA
         JjljJcIEMa/IvHXgUwvdby51y9qscQa/YK7hLYxPKY7imQR6+s3CD/YMpji1PI443u+s
         h1Ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eNcKAicS;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728637934; x=1729242734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LNZohQek+9BCllCIi3J03VkxY+AkUWs9eUAN9bDX2KY=;
        b=eDvHXSYFDSu5tT1r4bJzr+1zlvMSsKwF58xdg+dazuBMaqGnaHRgzxsGG8dZelzd5F
         uB5zK2/g7ZD7f06DnQOrgkFzx0cI9j4ovZ4ncz5dfC2k4cs6800jYSMLm5awAWQl6QA1
         JWCT9HDUoTYgYiOHubdCGrIuVd7LAlgkL5SDcYW24wfTLWyh9+o2h9VmVTP4pinncvo2
         zk5LR5PcsP1/Q7juZYff18RyEurc/0h8EJQy03Dea129CiykC8hV47NKHbK/eNeH0rBZ
         afQjhIXm1kYac2agzSM3o6QP9YEUmzjZMr6Qw9Cl2l/un+U87QmY+0VMMBqjGwvX9lWJ
         Sbcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728637934; x=1729242734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LNZohQek+9BCllCIi3J03VkxY+AkUWs9eUAN9bDX2KY=;
        b=A7ILlT59S0TYUX3yestYRIQOUqaoyKltjxThcd8ryolqAvVRcRAN2/kkfxst6+ZYBJ
         8QT85IVFzT+L18rbxPE+8hvqIpN8KLc+CFZufzWX+QBPYkO1bCNE6tQ5QqIgsrTvR/oo
         C8iiX0n7xkKl73p6VQCyL/Kmc5SM61ef1SyCqcx6ZEEVQMYgwzhvOcdms2JXY7cVKrE3
         Ob3M5Y0JB6pIfYJMXg+O+wel2G3DAsVGhHBP76LAe1YcyECc8A1fIXa2ENDDizkSpB5u
         0Bd7BqAdMWW3OtSApp98BngriLheRC3dFhp66VZsk6s930Fm78P9e6306cp/Ro6fE1W1
         4biA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728637934; x=1729242734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LNZohQek+9BCllCIi3J03VkxY+AkUWs9eUAN9bDX2KY=;
        b=lggs943WZVqATQoKHHDvzYh1wRVMJV5ApkBEajdQC7q5rLyRpRhFHex5g3o80or3iu
         nwPY3PdzzTFz+Cfqf6TjmZ6EJAG62UQt3MLY4lx5788cpyeVb52slyezLV5jpENelquq
         f+SP+CLvGRr3dR4stAy8ApXw81Of6ZD/HQGp+PMwHu0Z7p8O/8NEkjlqYVmkDTczbIOI
         CSVwDbyDBnGC0spMC8tVYEogzhA0L6XUkESRLiyQA4IhbcVP4bMzIFk97SJtp9JjH2C9
         0SCnD/E0ykug12Ye80yXcXnfsXEchhW6LlKRGxfuTof2DJqjtuGz6AgwJkjDGeAuqZIQ
         ZROQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmQ5pQwaJEh9c8OsOEJq+u8kteLYnyq4rGaHPnMtC17X17qc8hmuaOLp7DBeJ0JsUeWf6seg==@lfdr.de
X-Gm-Message-State: AOJu0YzjOb8DGkZhB1osxI1gsc6mB8VHyCAQ5xWU7QdKIw2b2ilcSwTv
	++SIwYBkuefFlBpPe6pNmNq3JXz0GuscNmZHgSTjY2RBOJrWeiL5
X-Google-Smtp-Source: AGHT+IGu007W74Uf1ecsc8cRUA9Xoh2C10f7OPX/jMtwjDLiUbty0fl4ksc07nxs8CdpRqAG4Aykwg==
X-Received: by 2002:a05:651c:1547:b0:2fa:ca74:7e11 with SMTP id 38308e7fff4ca-2fb326fc8b8mr6070121fa.3.1728637933266;
        Fri, 11 Oct 2024 02:12:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8952:0:b0:2fb:3543:61e2 with SMTP id 38308e7fff4ca-2fb354367b8ls1359041fa.0.-pod-prod-01-eu;
 Fri, 11 Oct 2024 02:12:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpnvtwZ7YBLmMwaCLx0i3ihbpTxIVaHth6LrJG98r9gADLdoOxGbHAmWllNyk4x8VPnfL9Xgdtl9w=@googlegroups.com
X-Received: by 2002:a2e:be13:0:b0:2fa:c0fc:e3d6 with SMTP id 38308e7fff4ca-2fb326fc5a0mr8124851fa.7.1728637931117;
        Fri, 11 Oct 2024 02:12:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728637931; cv=none;
        d=google.com; s=arc-20240605;
        b=KvVCW4solqg54swka29dex0Gta03xXU9BiZbGbWVGlZoa1NtxHBI0fI/aBAjRkKDu4
         2JzWquwosB8hQLQqnHKOipMQOC5tWLQsFy4ER5gcLiVOKokucEYkpNTQuFKGbQdjxxqx
         sC46EVfQhhMDqJxASO3LmD2AAUGtVGO+QGJl56mookN0bcfcVLXBIl5vS8R3KZHLblfO
         GNPdiKRWJk1KXWlCBM6RhWIEz36jFGIP7ODGJtDn8FVbmEgAFsfgZG1kd+8NWQj5C0IM
         0yaqUzsX9nYAr3abD1f4PmH6oSQYCmHCogCXZxAugHfjE+vRpDhYMRiHLkUtepvGU8wK
         1srA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dmyCPxp3PGxPiT0sfsdtuyO7wyt4DIIzCTNUesZj7zE=;
        fh=tidhAygKxiunSVMf9Jr8KiLp90p0Ba0YFcNmn3ZEHBo=;
        b=LnHZZ+KqpyEotIO0sm7HnfsBoWHcYjTMOFEjm908CmtSyeexk5Qmym9rvCzIx9lw5B
         R5qBVv1WCWY2wvAB3HSLVx8g3CA33YbxzrqPaJSPkxZ0gCHCVvxIWqoOf4qmp6FI8x+x
         hA+o0Z0XFA5dNB6MHpvDJdi+H1XsNyXor+GOBhjsM4ISgDyMjrPeJ+s66seN5Bn/iKQN
         B+klNj06coJGfvz6j5ikXEJQVR5GrHXgEvI+BhjyfYQQu/sqJxsey0WvxLeEhYh3obsv
         e9JVLv2276PK/l9UO7dapY7g5MZOuiAs9dcweunHU6xwaAcnVULPSA5vEirw2RUD87WH
         yBQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eNcKAicS;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb24706434si603441fa.3.2024.10.11.02.12.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 02:12:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-5c42f406e29so2140875a12.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 02:12:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXb4DmrKZa2GD12UzDK4VbSBUdQ+kInm5FAEngiaY29hTz2UcW5KtPQjgfnqZ9uEWwQ63mHC7e0m4Q=@googlegroups.com
X-Received: by 2002:a05:6402:350b:b0:5c5:cbfd:b3a8 with SMTP id
 4fb4d7f45d1cf-5c948c87a44mr1077977a12.1.1728637930115; Fri, 11 Oct 2024
 02:12:10 -0700 (PDT)
MIME-Version: 1.0
References: <20241011071657.3032690-1-snovitoll@gmail.com>
In-Reply-To: <20241011071657.3032690-1-snovitoll@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Fri, 11 Oct 2024 14:13:01 +0500
Message-ID: <CACzwLxj21h7nCcS2-KA_q7ybe+5pxH0uCDwu64q_9pPsydneWQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: migrate copy_user_test to kunit
To: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eNcKAicS;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::535
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Fri, Oct 11, 2024 at 12:16=E2=80=AFPM Sabyrzhan Tasbolatov
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
> --
> 2.34.1
>

This has been tested on:
- x86_64 with CONFIG_KASAN_GENERIC
- arm64 with CONFIG_KASAN_SW_TAGS
- arm64 with CONFIG_KASAN_HW_TAGS

- arm64 SW_TAGS has 1 failing test which is in the mainline,
will try to address it in different patch, not related to changes in this P=
R:
[    9.480716]     # vmalloc_percpu: EXPECTATION FAILED at
mm/kasan/kasan_test_c.c:1830
[    9.480716]     Expected (u8)(__u8)((u64)(c_ptr) >> 56) < (u8)0xFF, but
[    9.480716]         (u8)(__u8)((u64)(c_ptr) >> 56) =3D=3D 255 (0xff)
[    9.480716]         (u8)0xFF =3D=3D 255 (0xff)
[    9.481936]     # vmalloc_percpu: EXPECTATION FAILED at
mm/kasan/kasan_test_c.c:1830
[    9.481936]     Expected (u8)(__u8)((u64)(c_ptr) >> 56) < (u8)0xFF, but
[    9.481936]         (u8)(__u8)((u64)(c_ptr) >> 56) =3D=3D 255 (0xff)
[    9.481936]         (u8)0xFF =3D=3D 255 (0xff)

Here is my full console log of arm64-sw.log:
https://gist.githubusercontent.com/novitoll/7ab93edca1f7d71925735075e84fc2e=
c/raw/6ef05758bcc396cd2f5796a5bcb5e41a091224cf/arm64-sw.log

- arm64 HW_TAGS has 1 failing test related to new changes
and AFAIU, it's known issue related to HW_TAGS:

[ 11.167324] # copy_user_test_oob: EXPECTATION FAILED at
mm/kasan/kasan_test_c.c:1992
[ 11.167324] KASAN failure expected in "unused =3D
strncpy_from_user(kmem, usermem, size + 1)", but none occurred

Here is the console log of arm64-hw.log:
https://gist.github.com/novitoll/7ab93edca1f7d71925735075e84fc2ec#file-arm6=
4-hw-log-L11208

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxj21h7nCcS2-KA_q7ybe%2B5pxH0uCDwu64q_9pPsydneWQ%40mail.gmai=
l.com.
