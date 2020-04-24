Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2OQRP2QKGQEQ3PBMSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 41E861B76E1
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 15:23:55 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id g69sf6455434pgc.11
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 06:23:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587734633; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/eMKLyOw8a65ve0ZH8iB5QnryV9G+buLqKDMJgydaPteRGtkF3N14TtB/Tg3/G5SR
         Fc3i7JaExIWef6i2Hk41UL85Wfc1ip9IZr+3vRbJh9GkXomwKTsV+s0GGKsjnIHMxVgR
         rYO4qC748XYbtOuuZY23P7MVLhlRjs7XGutxBX18bUAyN0QcZIkDg103Y+ouoi3jREve
         VMHjorXhyn2J6pHIhsveZD3sDtGGAfpfGt0IoIwN0loK2/wBgg+/84irBCZDSUfs7ZT0
         Hmvv43nT9T0pUTeg0x+cuvxlzsu0fTaswX1FNf2sy938oz8AKleZn0phV+xv7JIrBCSy
         79ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WI0uJg60gbVe+KBSI3pWU5AlKiexdEb20TJRepI7LU4=;
        b=g/x32r2GYi7JLd8Qmoz2pgcIChfINz27fZTyXRbXuTMqTAcbYvx1wyfQ1Odud6VIvn
         degvC260KrjvhIL226gMdA/Zf2o7KTlR0s1NKe8h/F87dtAS5CQfabiBoUbwWtjQeUQW
         WkYN872U3hWmrPpdmEIMQ8TB0dSKNd98sk/QbZVZEmKuN8bujYoxuhKlca0V1dZJdorM
         8eMBKvpBAg5AQrSg9YJr5Y6mqAid6mN1TZTnBtST95cftEPL7jPPqM44vaJgdYqwkI0+
         wMKB7N1IRJ5+E7bMQp3VySY+MXpcx19Lg+aAB3VXAHDxagUfAZabp/LYr2R/9bFTO5hS
         JKvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNp4FkGy;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WI0uJg60gbVe+KBSI3pWU5AlKiexdEb20TJRepI7LU4=;
        b=SzOFBMzygMiWUC51GOUtEBPtXVqvjMi/ZQWe0tB0rAxFTznqjDIJzKmKHJNHYoa9QV
         +NpYC8CBmAp7JXi6eeocd0hdljrq1aj+efQf/DTD6OSgslFxeYMvPWZjud2GXc9FqH8k
         Km0u2zEdTqchgGgitVF58P2p5jyrWICEgBCSYbDzRRhshrZa+ZkM6QBmMqEB0iejsipR
         Y4xlBAYWzy+fAnmrfoqiW/4bdMhi8ifdIUtqhBj7LGz1+XEa/1H0PCf70qTvsYsL2d+S
         Q5R80Fj4lhef7hIT8y4yS1ptK4CEQcenHBu4QT3+IrcIueAzU1CwEW3j6a65Klk8vBPw
         SEPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WI0uJg60gbVe+KBSI3pWU5AlKiexdEb20TJRepI7LU4=;
        b=b5/INHmHJI1Kl5EGwN7MSb4xuUgyJkrzJCaLABbz6GCLugwT5H/tkbP76MwuOwOm9r
         PA8QKXmNFD3yKi+b7m0iJgmsJiSuUkgxGHk3cSw4+5q9XEc2sp6fiz+WZaISgCici2g3
         eDZNXI03de1Lkd9opJUgYwBgCHKIRkAWnFCQoEX34QJ1Knf+15IFTKFwNstdf6Ld2v/Y
         ZYUUUr92e71Q09547K5N/1SmdCQ7GfO0EcbShncvXr6J+SDsxuTg4qkyc3ckopAqzcNu
         eIGE9ZrRNHmrocu5mK0FhUFQMdstunZmpq9fTBrTZsGfcFZxxVUharEfngSYpIgGZnz1
         BpAg==
X-Gm-Message-State: AGi0PuZmMPGSZnaSOufH5EyHk5sQ1DEY8nvGQnrJre1GxINdeIawbkWf
	MRE1Iu4yxZIuvvBqf47RlA8=
X-Google-Smtp-Source: APiQypIhM0htc2pjsA11EYfBMMH6linWX2zOaFsdz+qzEk+rsuJaAP6KaynCrTXz3EZwQoCXSviTvQ==
X-Received: by 2002:aa7:9e07:: with SMTP id y7mr9764511pfq.257.1587734633673;
        Fri, 24 Apr 2020 06:23:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:63:: with SMTP id 90ls6678424pla.10.gmail; Fri, 24
 Apr 2020 06:23:53 -0700 (PDT)
X-Received: by 2002:a17:90a:7d16:: with SMTP id g22mr6161502pjl.179.1587734633253;
        Fri, 24 Apr 2020 06:23:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587734633; cv=none;
        d=google.com; s=arc-20160816;
        b=Tb+uZPFwSFqaLHM3uEqI6agNIUqsI0EJk22/b0yaRD61F5RGlD09BmNDbPPb8rPL67
         3sO2jegnuCOs3d5SbX41aMOogoYxFRQwY4yx5MB7MtPqbqB/q5njo4dtgzQ7dw6oZENB
         Xyvazpk0cgQMi0C8wAUzg8ux4orbstvoy+vHD/WMLeOZDlX9tO1qJXwJ+ApQ3GIEI2ot
         T/1VZxLEwfrWjaQRA7eFCaoM0QFHErZ3Ze2iB2ESRBHW3fK3YJdyhE/h2HwyLosEM7qX
         xsKs/JdcSoci6HtvWb7L+2NHLwqbRTV8c+2yx8NWPnYNYC030BxE+YQw7t9U7xcLB6Dk
         qxXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6dprDbD5oVepTVxkb47166PR8KYatnNe9atjI73cFB4=;
        b=jnJo/85p9S3eURX1I5QACzb/4h8hpUYoP3O4yLli9+kDmNSMBvcLlgdHBzkf8h4OTa
         76FxlKy5eGhHOnrY6eDO8d86mfL2a62H2iT38LchaIjwSpCuF2RE31zxgw867Zo0N9GB
         bYC3PQcXfvTrmrQvpolGUd5e3uQiFJV4ICab3VFzrrR9ZQNoKiSUgq3cqs64jRaYlPpB
         zWMvFXD8FuktWGNUKe8i+RWAtFDi8M9Gtu9Bu+QBC/W/gt2kwM+gEDiH0i85naLrdkKW
         EpqkwtZhYGWWzLMq/5sk/4gKhyJd2gplR7wgxcSCnZxbXew+AwY6iTu43pMUkciFJOCX
         /J2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNp4FkGy;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id gn24si965572pjb.2.2020.04.24.06.23.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 06:23:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id ay1so3744643plb.0
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 06:23:53 -0700 (PDT)
X-Received: by 2002:a17:90b:198e:: with SMTP id mv14mr6180426pjb.69.1587734632657;
 Fri, 24 Apr 2020 06:23:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com> <20200424061342.212535-5-davidgow@google.com>
In-Reply-To: <20200424061342.212535-5-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Apr 2020 15:23:41 +0200
Message-ID: <CAAeHK+w+y2zAQzmm-uXyFhWBm0VunB7wKPekhjBxajZCD=xEng@mail.gmail.com>
Subject: Re: [PATCH v7 4/5] KASAN: Testing Documentation
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PNp4FkGy;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Apr 24, 2020 at 8:14 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Include documentation on how to test KASAN using CONFIG_TEST_KASAN_KUNIT
> and CONFIG_TEST_KASAN_MODULE.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: David Gow <davidgow@google.com>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
>  1 file changed, 70 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..b4b109d88f9e 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
>
>  This allows ``VMAP_STACK`` support on x86, and can simplify support of
>  architectures that do not have a fixed module region.
> +
> +CONFIG_TEST_KASAN_KUNIT & CONFIG_TEST_KASAN_MODULE
> +--------------------------------------------------
> +
> +``CONFIG_TEST_KASAN_KUNIT`` utilizes the KUnit Test Framework for testing.
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
> +With ``CONFIG_KUNIT`` enabled, ``CONFIG_TEST_KASAN_KUNIT`` can be built as
> +a loadable module and run on any architecture that supports KASAN
> +using something like insmod or modprobe.
> +
> +(2) Built-In
> +~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN_KUNIT`` can be built-in
> +on any architecure that supports KASAN. These and any other KUnit
> +tests enabled will run and print the results at boot as a late-init
> +call.
> +
> +(3) Using kunit_tool
> +~~~~~~~~~~~~~~~~~~~~~
> +
> +With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN_KUNIT`` built-in, we can also
> +use kunit_tool to see the results of these along with other KUnit
> +tests in a more readable way. This will not print the KASAN reports
> +of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
> +information on kunit_tool.
> +
> +.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
> +
> +``CONFIG_TEST_KASAN_MODULE`` is a set of KASAN tests that could not be
> +converted to KUnit. These tests can be run only as a module with
> +``CONFIG_TEST_KASAN_MODULE`` built as a loadable module and
> +``CONFIG_KASAN`` built-in. The type of error expected and the
> +function being run is printed before the expression expected to give
> +an error. Then the error is printed, if found, and that test
> +should be interpretted to pass only if the error was the one expected
> +by the test.
> --
> 2.26.2.303.gf8c07b1a785-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424061342.212535-5-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw%2By2zAQzmm-uXyFhWBm0VunB7wKPekhjBxajZCD%3DxEng%40mail.gmail.com.
