Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLVG7T2AKGQEX6SPHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A14C71B2B43
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 17:37:19 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id s62sf5476541vks.7
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 08:37:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587483438; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDGCYD+WmYoy5lJYE32ywIod3kIvcmlkypiRpFsreCtNYNtIcrhfaTu0YQw4yhDv+C
         cmAz0rqJRL8ukwg75Z+nKRIeBLQHGbet61tDs4DEzkYEblawGXIeRTHsXNPSLLrlhgZi
         lQJwdvUDszy9khHLcM+Qa6Cbhvmrd5RIr7zLBN0UzsXolYY30meD/edUxuBH3Av4c3PN
         D2gOaulZGzVI+c7aYSfwKr/BS7r7wmeIPvL3+jy8m+hskj/PViY1iXmSaQxPsTFa7HRT
         81W20YnkkCFHhzW8kJV8sJJqMVmn7BsasKhjbvg+KQS8863rvLsdxgvABQraiWRVb27W
         JjAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hgdBb0R261TTOsPygcCp6UJmVvRj/NV2wV1K2HWLh9E=;
        b=TR3MEUgX+Ih5OTaR6w0nYnLnG/m6yOv34zpX9ZlXJPZQYgQf+701uM4fpZFbak5baZ
         kpac09R6j0Ezhb++dDWeYuustu3Gf/Xl2TzMA91M6GflcUxHaSb/FI5cPXTDv/VYoZE/
         ziRRXJ8U/roI0hD43e43cu/FQOZAuC5gD/rTnpFMG/LVJhk4mlkn0hJaTvt0KaTy01I7
         P6qM22CZTq2rEXlC+rLsSckHlZnkmS6DfSwxPDCFiFPAIpYSMyy3E4BMmxEiqAQeWOom
         oa8w/FAm1U91+VnIRY02yFrcO9zURRbhrt2D1Ifhh5pwcUlhpKvYshGNFK1oudjW7vGj
         SnpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VlF7JCo+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hgdBb0R261TTOsPygcCp6UJmVvRj/NV2wV1K2HWLh9E=;
        b=NWdYr0cWfFEY2fdboTlUwaH7V+5i4mFp5aLrGVjRei2eU+awjWkTY55BF6AEiP7Q0z
         XZiDVEp/w1UF66eF6Ctel2qFKxk1gllS01Vg2uolACkWzt6PNpmSdtvoSA0dB3uynP06
         QfDUXFJDR7RcQvNQdoiWjnvDkQ0bXtQC7/tpWSreVO6YVqSX9eDoMkmvS7l+Qkhgd6yV
         XfGCewDIeaITs3O9bKvCUpCT+KG5pxhexMrazpoZGq0YuQ07ErYdbrd8njwOLLKNvvUt
         U80cD6cj4qthx7l/hoeRkLvkgSzl5hBLdVFc8KJ55IzeZ9QiK/sHhBJju0UlQSKDFjWX
         trEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hgdBb0R261TTOsPygcCp6UJmVvRj/NV2wV1K2HWLh9E=;
        b=FK3Gupa3+t0CYxNoQ92YCApnS2rmSqkqsK2/+Ubm0XFix55EW3qXWDQcDs0KMEPDPE
         MxCAKORLLT5pO3CcoOBchgFOi3L8Ag1GlUAt7yPcn9+6Xg4mxFidXzrJdUyQQHaNKm/N
         YqPG6TUy8eGwDabT3/qUVyHKHshpE2mXR79ofA626443jQu3eIfJU3/0bIwv3E9ZAJIG
         MHR19aKH87r0iDj00S/igKmWrbkguwdUzgo9DNe4fJrE1hZLjvIzG5sCVA7Fra20SOqC
         5zvjs2cXNZsLcq3N/LvSBmPE0QlzfqrzePf2iEX+4EvfxCCBq3ma5yTAhEUDhWQ4mqhW
         3s5w==
X-Gm-Message-State: AGi0Pua5kE5CigFL1YxQ7CUx3LDfBX/TJeEJ6u0OhXjj8M4CB/uT1vRm
	6YH2pzsmraBvbur/m6vJWeU=
X-Google-Smtp-Source: APiQypL2OKkWS1q2YZaOnlrnDG8F1XlHGkngGGLzCShcsxADcfCdIh6fM9UGipVrFYRITvOv/xziEg==
X-Received: by 2002:a1f:d182:: with SMTP id i124mr15134980vkg.26.1587483438426;
        Tue, 21 Apr 2020 08:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:54a:: with SMTP id y10ls475651vko.10.gmail; Tue, 21
 Apr 2020 08:37:18 -0700 (PDT)
X-Received: by 2002:a1f:ff11:: with SMTP id p17mr6396018vki.25.1587483437958;
        Tue, 21 Apr 2020 08:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587483437; cv=none;
        d=google.com; s=arc-20160816;
        b=mPIk7FUWpxEfwlkyUQhXH3imnsLy8k90DBeLDWBH+bROAPNvCqqUM1hRbTkg614kZ1
         0LNVjulOqgCmwPJqgy5AYYsRsp6rxxep58zMUZbO/lOeP+BI7eaRmMb0xfvzbR0GT0Tl
         xbwF4XcrsS2yle3VuueClalDM1WCfssAq3h3udiiIFNsmS7MSevxmF1p6Gu+3GL5W8Yq
         cdD6R4nV8W+8hwwRwyScWdhCrhVpaDBNc1muZTVBxAn4wgptDIekJ1BLaYoRe1rG7tv3
         yT1DvRP4hGUIT3POz2v48ON629aw7MGitIA3hQk05VuO0QiAjsQEHemMXEjq7WXdGrV6
         lhQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dvnUaepumbrX3tLwN7T+aV2zw9enslYEEKwoxp15Rbw=;
        b=xuFm3ozTu0djIGWfGhbcvoOlEb/R6j9iEcmOmaH5EMktBLeT/2fryLD+F90AuDOilN
         h1ihG4jU8PL3FmhKCEjh9vqbJES3+CjkiZB0rtYbAfmlXps+mNmGCy5mpAiXtAs+o5Ld
         0gPlTBJrKolqczy87cxAbxbeJJHWDIslKzO32sP8/3J41BnBm0aHCWKk6F3cHtk3DaPE
         +KFnoFCHbLBokQIt/G6txRiRj19xw/LZNRnTS4SHDiQH85+uLuXqf2B6lAE0pJAuaR5W
         RXlvs2Vy0eRe7HaAzEX4lGdYlmdeCDZrldd38NjsWs/4LfFSzwDlaUsARxNtU96u+p2e
         EHyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VlF7JCo+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id i26si110904vsk.0.2020.04.21.08.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Apr 2020 08:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id a7so1498633pju.2
        for <kasan-dev@googlegroups.com>; Tue, 21 Apr 2020 08:37:17 -0700 (PDT)
X-Received: by 2002:a17:90a:26a2:: with SMTP id m31mr6207645pje.128.1587483436814;
 Tue, 21 Apr 2020 08:37:16 -0700 (PDT)
MIME-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com> <20200418031833.234942-5-davidgow@google.com>
In-Reply-To: <20200418031833.234942-5-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Apr 2020 17:37:05 +0200
Message-ID: <CAAeHK+yQqyw4GNTkk8eQMFU5baCmVQyQTrvSAk+zBNHDaJKwvQ@mail.gmail.com>
Subject: Re: [PATCH v6 4/5] KASAN: Testing Documentation
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
 header.i=@google.com header.s=20161025 header.b=VlF7JCo+;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a
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

On Sat, Apr 18, 2020 at 5:18 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
> CONFIG_TEST_KASAN_USER.

Hi David,

Please update commit message too.

Thanks!

>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
>  1 file changed, 70 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c652d740735d..74fa6aa0f0df 100644
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
> +With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN`` built-in, we can also

CONFIG_TEST_KASAN_KUNIT here

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
> 2.26.1.301.g55bc3eb7cb9-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-5-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByQqyw4GNTkk8eQMFU5baCmVQyQTrvSAk%2BzBNHDaJKwvQ%40mail.gmail.com.
