Return-Path: <kasan-dev+bncBC6OLHHDVUOBBA4GZKJQMGQEVT3ESGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 293C551A12F
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 15:43:32 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id l16-20020a2e5710000000b0024f0c34eff1sf354795ljb.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 06:43:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651671811; cv=pass;
        d=google.com; s=arc-20160816;
        b=DteystaT+5TwvxK5baqiCVIL6Qj22uv4SmZF9OzyaVZaNETEG6horxjvxCVWB5vdjv
         bdJ9L6z7qPY1GTfw2pPjvQfe637+fGD0mmkvaJVozr9kmOShcOwpFLq77OMPj3Vhhpbn
         JqreCAdNpsU9ugwZ3iCM1WH7mFjpcKyRGuGUrFYdNHW/UGu0OmhnCaVer7v65FxQBEzy
         lCZpd6S/VAT0oIbEhP+6uMEi2LG7QGZB39aQkGYMup8R5My1Y8u/tFr54bCpokSyXq2o
         TrqIOyYST/GjUfc4zZ36vww514P+NW0ohBrM5EaKNO/i4SPRBEhPx8RywjswSsCdiMqh
         bOjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pPEW1TDrKF33fQ6xbQZl0Zv/RdMwcYCqEsk5SLpb7Kg=;
        b=VllM5jiA060nbiL26rF2qNToYBytu/3RmSjeJ2myQKHaKV60mxn/fCUWzFxl8u8cTT
         YG81NIQCIECCZZHPKO7qu2975LNwc86lIxCjjIaGy12luZbh2MTIhsuXnOZO/ZE3YrNB
         Ig+B5M8Abpni9CVIC0QYNdJtoooHlN7BcjzByzA+uUyd9DJQXSKCvRWPqoPsp7V9nkyI
         Y1t5yjNVoD1sDRWvQF93YN42gNKhBlK6ChfslbdID6doTVodY3vg3rHWruQWa4d7u90x
         w2k53HSWjjWfcfNW7T/HLiasouGaeZ+aerEYex5EvdN7xGyTw5eEgR2zv8lJuFlyxdJU
         QtIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RwgLbatb;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pPEW1TDrKF33fQ6xbQZl0Zv/RdMwcYCqEsk5SLpb7Kg=;
        b=O46Uy5HrPesRWaAnnqtjUxYZYpdkHcZg+GlABeZhVGYd3iNCAa0C1j4Y412Sqyda0p
         Op9JJ0vWHaIFUspXbnlwzZPQnCNm6z7E0PkklhAWlbxgHgkhG7s0143CDXhhJvDnlsAJ
         kzHuaQsS0ZyNVnj5XatZZrQWEHllY8lNvAY5fuwd51f2UrY2Bi5qfArLjvNR+garlY0X
         CuCOOsoW6sQZ3fbuHXlFmbNYHCzgHsOQuA4FzHk8wzrOdr4yJ+p2M6GQmfYotXGTGClr
         GVayJSJ9MHvCEMNEVQdL3BzbDYf23f+Mp5uN37zcWdnfOv3/aRmcZwf6VIC8DhX22AJW
         9RRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pPEW1TDrKF33fQ6xbQZl0Zv/RdMwcYCqEsk5SLpb7Kg=;
        b=H0/nbq9soBmFLNsP4wy3AaSUthVQnFDb6KnYhywODOx4Av1zchclsM4y8XlQf+M3jH
         /ikt3gCPtFVjBN9QblETRe//l5iaxibCpCRgUjOyCq4biUnB93f3AnHTmf/Y5Z1vchJT
         3DGNhaFTbtW8P8fSiMV4X3nCgAzJ/XmTIBsJDNChknJ6zDOiR8kcHBVO0x5nWQWFyJxc
         cvWe1hd0igX7mcwoYC1DFq0kWNBie6YaiS0I/Nkp/zlrSZGCaSRspx49zGN8eoYPygET
         LZEBwCggDMKHRu0ZaXUf7QQmlWp/YZKXZ/nKqmNuoICWec3xL/W7s9J7KkGWg+GYcvnW
         iAVw==
X-Gm-Message-State: AOAM532b/esFsUIT+KYbQvU2TmGV/+b0ErR4lUw+za33WvMuuNIERSM0
	49hDG+nb801Bpc6PmtlvswA=
X-Google-Smtp-Source: ABdhPJwck/KaZT62fNq1PmmtuGihn6dGn27O22Fxz6lR3CaeuwjsZWYBvBS5J5o4Fm3uezWwCKPw5Q==
X-Received: by 2002:ac2:5192:0:b0:471:fcc4:b3ff with SMTP id u18-20020ac25192000000b00471fcc4b3ffmr14588921lfi.488.1651671811397;
        Wed, 04 May 2022 06:43:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls841987lfu.0.gmail; Wed, 04 May 2022
 06:43:29 -0700 (PDT)
X-Received: by 2002:a05:6512:132a:b0:471:af97:77b7 with SMTP id x42-20020a056512132a00b00471af9777b7mr14021877lfu.115.1651671809879;
        Wed, 04 May 2022 06:43:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651671809; cv=none;
        d=google.com; s=arc-20160816;
        b=0DQDqOiEAJNzwChcWX42nvLvkKbY41BjbOlKuEOdlOeqTZEUL3B8RAuxSRHP54hOvN
         h6VcYXu2GwrO32sLRKA7d5uhZ0R5mfVexDtrvJDjjJ4vOwt6hjHtGDqwKq/5fsv522by
         jwwGNh1Tkz2GfHQwZ9N738FBqufbd4NQ8JYb9bWPeeUFQSboWqTl5LA3h1XoHEuf+Rq5
         OxAvVcLG1KeFJwLGbY4yCpEuiioIfKDZgDrIdY16v1Kal0+bt3LLiRD/UMW27YyNFMir
         PNmkPeeXCdeZYYrGu4YDnlCzT3rj5kC9wUTSMeJKR8dZ3rB8qXNGT3UQk1B70OCVQsrR
         zPJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cBqq6UprR1Yrhinom9y32Umswbttty4rMVtulmJXvwU=;
        b=dHb3wOWm7U6v1TcibS3JJxnvJnYtI9Xt+prQ5AYC/pJu5cW+GxIJlWosaHAaADao9V
         AzJX2a3u8iGf00J07hwIYe9uQg7iDtlUhBsirtLzXF0BRP9ChNL4No8DcZ/wkvZMJamk
         b4IuNBU/npju+lDjPLGMaZYYoKdz7hsdWMPLCZqUvFccEmajsVY/ZvkD5iXvuCjUqF7J
         8pxQG29PE4ae5Klkrrv41BzzD3/57SR8c9a5FwX986Hk2sr9Ys6td8WoZqL7ykwCH0gM
         vUrPJY4dJTOHJYyJqdpqYQDbQzvNwCpIsmYvg1XFIxNaVD+vDuRvD3814qTwxZAuq1Ju
         fYdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RwgLbatb;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id s1-20020a056512314100b00471902f5be2si1200831lfi.3.2022.05.04.06.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 06:43:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id v12so2074513wrv.10
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 06:43:29 -0700 (PDT)
X-Received: by 2002:a5d:6b0e:0:b0:20a:dd17:e452 with SMTP id
 v14-20020a5d6b0e000000b0020add17e452mr16461520wrw.501.1651671809318; Wed, 04
 May 2022 06:43:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com>
In-Reply-To: <20220504070941.2798233-1-elver@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 May 2022 21:43:18 +0800
Message-ID: <CABVgOSnkROn18i62+M9ZfRVLO=E28Eiv7oF_RJV+14Ld73axLw@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RwgLbatb;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Wed, May 4, 2022 at 3:09 PM Marco Elver <elver@google.com> wrote:
>
> Use the newly added suite_{init,exit} support for suite-wide init and
> cleanup. This avoids the unsupported method by which the test used to do
> suite-wide init and cleanup (avoiding issues such as missing TAP
> headers, and possible future conflicts).
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> This patch should go on the -kselftest/kunit branch, where this new
> support currently lives, including a similar change to the KFENCE test.
> ---

Thanks! This is working for me. I ran it as a builtin using kunit_tool
under (I had to add an x86_64-smp architecture), then use:
./tools/testing/kunit/kunit.py run --arch=x86_64-smp
--kconfig_add=CONFIG_KCSAN=y --kconfig_add=CONFIG_DEBUG_KERNEL=y
--timeout 900 'kcsan'

To add the x86_64 smp architecture, I added a file
./tools/testing/kunit/qemu_configs/x86_64-smp.py, which was a copy of
x86_64.py but with 'CONFIG_SMP=y' added to XXXX and '-smp 16' added to
YYYY.
It took about 10 minutes on my system, so the default 5 minute timeout
definitely wasn't enough.

(It's maybe worth noting that kunit_tool's output is pretty ugly when
this isn't running on an SMP system, as the skipped subtests -- plus
the "no tests run" errors -- take up a lot of space on the screen.
That's possibly something we should consider when we look further into
how the kunit_tool NO_TEST result works. Not really related to this
change (or even this test) though.)

No complaints about the patch: I'm just really glad to see things
migrate off custom init/exit code!

Reviewed-by: David Gow <davidgow@google.com>

-- David

>  kernel/kcsan/kcsan_test.c | 31 +++++++++++++------------------
>  1 file changed, 13 insertions(+), 18 deletions(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index a36fca063a73..59560b5e1d9c 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -1565,14 +1565,6 @@ static void test_exit(struct kunit *test)
>         torture_cleanup_end();
>  }
>
> -static struct kunit_suite kcsan_test_suite = {
> -       .name = "kcsan",
> -       .test_cases = kcsan_test_cases,
> -       .init = test_init,
> -       .exit = test_exit,
> -};
> -static struct kunit_suite *kcsan_test_suites[] = { &kcsan_test_suite, NULL };
> -
>  __no_kcsan
>  static void register_tracepoints(struct tracepoint *tp, void *ignore)
>  {
> @@ -1588,11 +1580,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
>                 tracepoint_probe_unregister(tp, probe_console, NULL);
>  }
>
> -/*
> - * We only want to do tracepoints setup and teardown once, therefore we have to
> - * customize the init and exit functions and cannot rely on kunit_test_suite().
> - */
> -static int __init kcsan_test_init(void)
> +static int kcsan_suite_init(struct kunit_suite *suite)
>  {
>         /*
>          * Because we want to be able to build the test as a module, we need to
> @@ -1600,18 +1588,25 @@ static int __init kcsan_test_init(void)
>          * won't work here.
>          */
>         for_each_kernel_tracepoint(register_tracepoints, NULL);
> -       return __kunit_test_suites_init(kcsan_test_suites);
> +       return 0;
>  }
>
> -static void kcsan_test_exit(void)
> +static void kcsan_suite_exit(struct kunit_suite *suite)
>  {
> -       __kunit_test_suites_exit(kcsan_test_suites);
>         for_each_kernel_tracepoint(unregister_tracepoints, NULL);
>         tracepoint_synchronize_unregister();
>  }
>
> -late_initcall_sync(kcsan_test_init);
> -module_exit(kcsan_test_exit);
> +static struct kunit_suite kcsan_test_suite = {
> +       .name = "kcsan",
> +       .test_cases = kcsan_test_cases,
> +       .init = test_init,
> +       .exit = test_exit,
> +       .suite_init = kcsan_suite_init,
> +       .suite_exit = kcsan_suite_exit,
> +};
> +
> +kunit_test_suites(&kcsan_test_suite);
>
>  MODULE_LICENSE("GPL v2");
>  MODULE_AUTHOR("Marco Elver <elver@google.com>");
> --
> 2.36.0.464.gb9c8b46e94-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnkROn18i62%2BM9ZfRVLO%3DE28Eiv7oF_RJV%2B14Ld73axLw%40mail.gmail.com.
