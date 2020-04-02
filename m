Return-Path: <kasan-dev+bncBCMIZB7QWENRBK77S32AKGQEGWNZWAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 110D619BF63
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 12:34:21 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id y84sf2522006pfb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 03:34:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585823659; cv=pass;
        d=google.com; s=arc-20160816;
        b=l6qGVzCDtbs73Q6cBsq7BsE7tDxT15Ko1IDWvPKxASJNROwPx6uHTFdWaJz7PBa/nr
         kFFTzG+i2yQ6i5qDz0w7Bnnrqp1AoF16b8TN5a9V90qyrR4OEwRGkLkkQqdxm7sUbT6p
         +fmz34gWO9M4FjULCSz10P8ku+3hKuQwZiByFxOHDASm0gwWV63s5FrnAa3jxDSVKgci
         SGvzhD6/cfUAN6H+jffBYP9qFSAZKdAiye+dPR25Z/JvCeCaCsID7jaFgm8azYWr25Cu
         QHZ+lTQfwbnXe9PQgks6+ooCixHjaIEE3frXIxPfcUg1QAhO6Z9KckZyfKV+RxJVeXlZ
         CxLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YQ6FFYtbh/Kg5E5rzg00cTI27lR/1E2AA0q4N/PNiSw=;
        b=W+YWTYAxbvOhEP9QktuJXGexSk5TDut/3Qg3hG/RcPq37dPum8qU4GRoHYs34EDR/k
         MCSud4wTpRlAnnpF+x2jeFKaawCxGMJfmePu9KUrmh9BKHdMTiLEhCNoOSBxzPzLI3EJ
         xASJIcYYeFHQge6wp7Vd9a1faH/5Sqq1Ya0lhbpQYW7Pe8imXUFdW2tlpTHJWCkDP0hF
         d9ehljpCvtxlzg0uVEpRmAzyiTobObYzLG9R2d2VCMW4UKsGNukJlBZ0x/54+Uhj7sLT
         os9q352pd0yl9P7i3GzSikaBO39WwtBl89nZ4PvSxFTkM79KG1auyagTDddZAwCLuKo4
         DAYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wNmL09Wq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQ6FFYtbh/Kg5E5rzg00cTI27lR/1E2AA0q4N/PNiSw=;
        b=d2V5RVQgMyq5i4QcutLYN8Sln+6QlD1bHvaFeehVHbQECgjX+aKAOJpufeBTY5gH/h
         OZhRcu93vOxazkHJgKGRvnFBuwi8j09SK/dl1ld957j/6NXAhDjqfedpGvx2L+JSodGr
         voKA5IBvl7hRMb9OXp2Jsxa6gErzb1q8DrW8omL0g99r+tVQTlv+cPffIlZmLp43iEbH
         713IdK7iG4AT1aymZCa0s2vhdug7gqU5/uoTO2uBPYTrW4OydNKNQFUgk/SYop5tSW/r
         hkJXymeBU4iC1daTIUO1x8bONyWx375RrpbkQWZcAlS9pKRuypuHTL0LralRzIPofCse
         RYeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YQ6FFYtbh/Kg5E5rzg00cTI27lR/1E2AA0q4N/PNiSw=;
        b=hUxE6rRNuKUxvvp0MNT9zWqBK0vCWkwF+GVXJaenwb7do1Lkst0Rg+oFLWhlOuG00P
         fe2bn6tvikvFtRmW7tanxgEmycsyysGvwmMCrVuUYgeF+1Of6f1trmcCm1GkgAGDGBOu
         BKqjpuKo5WpQV9NZAP5DhqHalEhaSM1f04/zy09pTlDqmXLvsHawaL29+x9RVvj+UI+r
         pbFTWwIJ7+tNe2U75wpmhkOMsLmk1iwC20RQIv+leKhIStEWNd3dLtWFCrvp1Rov7zO+
         8RLuajipSitkghp55GqDdZbBzciSs+sodFbNvHwlT2kVy+6Uf2MNaslw2lwQS08UgH5c
         jCog==
X-Gm-Message-State: AGi0Puaood6gZDFTJg6ByzgqKThd3Jpe+7BY+yrX/8whcF5j7YFFDWh1
	nW8YkHB0jbbgbMe9XEax+HI=
X-Google-Smtp-Source: APiQypK2iGauUd1ZC9ufjGVwRpmW19TyqvRp9XkFUKy8WuvmKEJ0UxJbUVNIFbsLUfezp/qDCrc/LA==
X-Received: by 2002:a17:90a:7785:: with SMTP id v5mr3128359pjk.120.1585823659389;
        Thu, 02 Apr 2020 03:34:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6816:: with SMTP id l22ls2270072pgt.1.gmail; Thu, 02 Apr
 2020 03:34:19 -0700 (PDT)
X-Received: by 2002:aa7:99d1:: with SMTP id v17mr2623538pfi.165.1585823658934;
        Thu, 02 Apr 2020 03:34:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585823658; cv=none;
        d=google.com; s=arc-20160816;
        b=RDkhVxxo2E3gdHKUdwAecyuhrtBJfcAHax8i3jjyzr8/tMaRJpf1YwqNMAaFxv3UdH
         P4iAnPR2RG8Q6pogoWAnODZdnr5YcgvsdLSSUZJthbdQQ98hpd52Klilm/bGJyJT/QxD
         iQDIiqvufocQcLJ6YdB11Raxdp0LceRCH1r9h+VqQZ9dJM0jbvdfmYXubUsFLplkSGCF
         egZdjwN1LIYjeUxH0pOxkPxDb52PNFJ2haR70G1g0B2TRrd5hSxZGXkTiI96NI80F2mF
         DeeMbOBvHCILN6C7Vds1V3uPB0rTOkh2sbhIqZD3OT0p47VkuqWrxPdHLulRnJPSATuF
         tExA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LEP3RMsbwsrI38M6GC4MFJAeeR3HIT91ewh4ArtAzP0=;
        b=dLh1GG8271qD4/ZToG6b6mXgfAA7RJ7Sc39QSvovJlHFQ6JWB+qM22b2xIc1Qoh/JB
         pXdFlKx9fPJiawQX1gpfDDLP8BmpN8uM7M2MHDcY+1TId1u+JzE3+Xl3Wu7vBDBGyaDl
         m5GqYZ20D0oHgX17Rh8T3Is3PXJxvPpFebM7tHpqWj5cA1QaFtdvmBh2dAC+fhu0GV5i
         y/+yuxba5aeTZuntBNKvIUP4QGp7k5Uga6np6p3fmw8KbyBxpfn8ccOWYtvvW+6tEEdS
         8QcyPMGeiKgt9+KeMiipCCubdy60KtHaD7rQuYc9BTH4oMsZC+ALvS97krx5Jq0OcgoI
         Su0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wNmL09Wq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id ne6si428392pjb.1.2020.04.02.03.34.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 03:34:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id o18so490155qko.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 03:34:18 -0700 (PDT)
X-Received: by 2002:a05:620a:348:: with SMTP id t8mr2337035qkm.407.1585823657756;
 Thu, 02 Apr 2020 03:34:17 -0700 (PDT)
MIME-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com> <20200401180907.202604-3-trishalfonso@google.com>
In-Reply-To: <20200401180907.202604-3-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Apr 2020 12:34:05 +0200
Message-ID: <CACT4Y+a6ijfY9styijimkxw2dd7xXTobw1vbj2kY_=GjhiUOZA@mail.gmail.com>
Subject: Re: [PATCH v3 4/4] KASAN: Testing Documentation
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wNmL09Wq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Wed, Apr 1, 2020 at 8:09 PM Patricia Alfonso <trishalfonso@google.com> wrote:
>
> Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
> CONFIG_TEST_KASAN_USER.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
>  1 file changed, 70 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..287ba063d9f6 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
>
>  This allows ``VMAP_STACK`` support on x86, and can simplify support of
>  architectures that do not have a fixed module region.
> +
> +CONFIG_TEST_KASAN & CONFIG_TEST_KASAN_USER
> +-------------------------------------------
> +
> +``CONFIG_TEST_KASAN`` utilizes the KUnit Test Framework for testing.
> +This means each test focuses on a small unit of functionality and
> +there are a few ways these tests can be run.
> +
> +Each test will print the KASAN report if an error is detected and then
> +print the number of the test and the status of the test:
> +
> +pass::
> +
> +        ok 28 - kmalloc_double_kzfree
> +or, if kmalloc failed::
> +
> +        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
> +        Expected ptr is not null, but is
> +        not ok 4 - kmalloc_large_oob_right
> +or, if a KASAN report was expected, but not found::
> +
> +        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
> +        Expected kasan_data->report_expected == kasan_data->report_found, but
> +        kasan_data->report_expected == 1
> +        kasan_data->report_found == 0
> +        not ok 28 - kmalloc_double_kzfree
> +
> +All test statuses are tracked as they run and an overall status will
> +be printed at the end::
> +
> +        ok 1 - kasan_kunit_test
> +
> +or::
> +
> +        not ok 1 - kasan_kunit_test
> +
> +(1) Loadable Module
> +~~~~~~~~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built as
> +a loadable module and run on any architecture that supports KASAN
> +using something like insmod or modprobe.
> +
> +(2) Built-In
> +~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built-in
> +on any architecure that supports KASAN. These and any other KUnit
> +tests enabled will run and print the results at boot as a late-init
> +call.
> +
> +(3) Using kunit_tool
> +~~~~~~~~~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN`` built-in, we can also
> +use kunit_tool to see the results of these along with other KUnit
> +tests in a more readable way. This will not print the KASAN reports
> +of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
> +information on kunit_tool.
> +
> +.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
> +
> +``CONFIG_TEST_KASAN_USER`` is a set of KASAN tests that could not be
> +converted to KUnit. These tests can be run only as a module with
> +``CONFIG_TEST_KASAN_USER`` built as a loadable module and
> +``CONFIG_KASAN`` built-in. The type of error expected and the
> +function being run is printed before the expression expected to give
> +an error. Then the error is printed, if found, and that test
> +should be interpretted to pass only if the error was the one expected
> +by the test.
> --
> 2.26.0.rc2.310.g2932bb562d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba6ijfY9styijimkxw2dd7xXTobw1vbj2kY_%3DGjhiUOZA%40mail.gmail.com.
