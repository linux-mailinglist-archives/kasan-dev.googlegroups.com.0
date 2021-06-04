Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2NY46CQMGQE5ZACMOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 563FC39B464
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 09:55:23 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id b17-20020a63eb510000b029021a1da627besf5549174pgk.12
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jun 2021 00:55:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622793322; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ddyo4V4Z7Tmu+/C8u7CIhze7TPZcLM/B4ebRBJLAL36cmfuOjI1YG7gm9eGUtQ2D2W
         kEfmiLIOqNCXXm44JCwURb8/hlwO5O4UFcesHjbnugWp6+eIs2PfhHaI/gA8RxyKEN6R
         bTOjvpR10J2NfuP8PMklRddmNyjD62itDAw7LVBsNi0DQovHxrHVBLYEZ/FPktF5gNb5
         9DWNl4GKA6n6KEZrb4kLcMfeDicqmyvjL5az+3nOwzR6ntlpyinxLLiywVlf2sycMUp9
         q07BrJ3rbsm86/ndfuEXJKZOblL+QKAdCU3pVQJvCn2uzSXxuOlMBfWsKM+UMHNK+8No
         jO5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UVlQEcnOfgjsPtHtCyBukFvSL9VgKstUsN5NL4TRsMw=;
        b=hfcSevTl/O4jso9YACAnt4HX3PRUzMk27lfWRChC9Hk1rskr51korUtIXjj9co7uK3
         Kov0XmyTOEF0ucE4LCw1cGeAHRiRhzzGvC6rU37yro+UpKAlOMpWvvdz33tfJWydbNbe
         y5NHAttoureZsU0gumEK0gQWRklAf3pVrbbQmidQ0jTGi+yiMuxEJ0bdod6WSGJsdiZj
         ptd8M1kbJERy19gr5+vj7oHG4HZ+RRRIHrNmMxfBHwPIpSHgzfEk4U5SPXNTcNaVjzE+
         hJkH9krzzRgibA5fGI7cSwlv9zur7AZWcTUxguxG7weduf6xGw1Ni3mspJceAKcxaguc
         Ym8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="MyR/FzU2";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UVlQEcnOfgjsPtHtCyBukFvSL9VgKstUsN5NL4TRsMw=;
        b=pYbDKEE6M221/WOBrrFlaWvqgeY10hGDo4GDvLKH4t/yDTSS9r68yBP+zu++A5PI2R
         UfQr7/yUvhGMtj5Ll3IIV/9LmGKNso2Hl6gQ6ZH9GIS2D3hZ+ZbKiz+gHfuhz7TcEdRT
         LOOEPWGpFnPX1hdTnI1rcG3iZ1rbwtdvNlzuB+mi6O3Vx7SUsbJ6I0LQ0dhYCCAW96UJ
         6iM7ljaexiGfgmq40P05QDjceeD1gnJv9C+WQRSQC9VTMMZfTpUqjvBMdpMJ0Pbyj51C
         x7IysmoYdYeQ30X9pMmkEKhb4nDfUfwIlDNF27zpR1WyESIMrI6CNHz3pRr8aj+dsWmQ
         E8UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UVlQEcnOfgjsPtHtCyBukFvSL9VgKstUsN5NL4TRsMw=;
        b=tjnfpygcGCswlC26+Wh/iQScw1Onr1wSlTe92IKPLI2zd8p25/QEzMZBLtXpSoAGzr
         wtZHKCpTLQwCBS2qqzajHXdtt4angmVMCVro00QGYnLN0Vo+Qg7EXyCiVbcWM+CuOX6L
         U9rQx6SxRUp89SrXca7Saxv1V2y5I2nUSOVHNKt/mZYklrUoc5GZJB+XBTsWVLkCYC69
         jyHwB8+QmDJt7+xa+jhHnAZ/llJkfUyvib0S+LfdGy3NUZhX/TF06WmSBylD3uzr5bvM
         CZwvPHVFa5nzTB3SNFR+XxeF8K+mUf6Z+OR+EDCZKMLRFkg4UuNkbN49sAqa9IvMb5Fg
         ROpg==
X-Gm-Message-State: AOAM5327lailMV6dWakmCAAoXnUWtE0OdYg6UIeiJbjuHxL1QA81xsLk
	f/R44vT/bIwC0kC4eRx885E=
X-Google-Smtp-Source: ABdhPJxKJS1YVMxWxUrWzyj/KIcvOOObigfAR6e/KHKopXsjMANupkWlMjgHbWMYTbHyvpkjbX6FUg==
X-Received: by 2002:a63:79c5:: with SMTP id u188mr3752545pgc.198.1622793321825;
        Fri, 04 Jun 2021 00:55:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd47:: with SMTP id a7ls3326193pgj.1.gmail; Fri, 04 Jun
 2021 00:55:21 -0700 (PDT)
X-Received: by 2002:a05:6a00:23cf:b029:2d5:302e:dc77 with SMTP id g15-20020a056a0023cfb02902d5302edc77mr3496558pfc.63.1622793321240;
        Fri, 04 Jun 2021 00:55:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622793321; cv=none;
        d=google.com; s=arc-20160816;
        b=sIaNHvJ76ZL2bjTKNaJjAdRSdhnfKI02JXlVlFstf0nnsc+pjdtiHgI1meV6D7CqV5
         ae3TIogdyTK65cmHw3LUlBUIbDL3RHazUVpfr30xjtMDTxe4ImztPbpPiyAxkqVd77Br
         grvPiLHcI3HGptnP+Gu56I2/Xfe6SXiIdMXgfFPPSGr7xLhBdZ+It/R1j7wUrwIs+RU9
         fmzWXdzRKv8bahcXo+gAlrAm5ElM8hn75K0SW4VJyEw4bpKVG3J7IvVkJ0/1ztc5WoY+
         8skA8AC/2eVIRCr7Il0lNYQDkDY8LNBSuK6P9TomZlTdi9IUcSzx9Xd/K3eiVDGUAFlK
         uUnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7FYrxsp7/ivfFHEEK/eqHTg8vJEKdX7/HfrYwN3SLOs=;
        b=nBsfXW5mdocpYEjgkffkl3ievOfmONT7ValgLwQZst+U1vtqwvvPQlA+Vr7kwMnjik
         rCnc7FKxSWFpqqlcgAE/IFGsQRqm5TKRlJwvczoJ57Wb+QCwIfb8QhZhOT4l6xsWCcDP
         3xDO87eSfXrPVlEOBQOREBXBL6vnPmjuu2MfFqQMQD+Hc8TWUF0yyw7SkQX9aUUsPhl9
         qe/bEYbvJgn8+GhR0x6ghKhxa1quw240o1t19Uu8WGX5IwNk4NpzNYVSezzJclHsz70J
         3PZzklC1ugGSoBS68Mf5JJ/A/SolO2ftCgK8Ip2SWvzIBDEokURh7avMg4s0B/V42lM3
         XBow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="MyR/FzU2";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id r7si535784pjp.0.2021.06.04.00.55.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jun 2021 00:55:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id w127so8935497oig.12
        for <kasan-dev@googlegroups.com>; Fri, 04 Jun 2021 00:55:21 -0700 (PDT)
X-Received: by 2002:a05:6808:10d4:: with SMTP id s20mr2243065ois.70.1622793320658;
 Fri, 04 Jun 2021 00:55:20 -0700 (PDT)
MIME-Version: 1.0
References: <20210604052548.1889909-1-davidgow@google.com>
In-Reply-To: <20210604052548.1889909-1-davidgow@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Jun 2021 09:55:09 +0200
Message-ID: <CANpmjNP3kK=YWEacvPr5RRen4YkSKL9akLn06Eq6H+azqSGimA@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
To: David Gow <davidgow@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="MyR/FzU2";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 4 Jun 2021 at 07:26, 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
> compare fail_data.report_expected and fail_data.report_found. This
> always gave a somewhat useless error message on failure, but the
> addition of extra compile-time checking with READ_ONCE() has caused it
> to get much longer, and be truncated before anything useful is displayed.
>
> Instead, just check fail_data.report_found by hand (we've just test
> report_expected to 'true'), and print a better failure message with
> KUNIT_FAIL()
>
> Beforehand, a failure in:
> KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
> would looked like:
> [22:00:34] [FAILED] vmalloc_oob
> [22:00:34]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:991
> [22:00:34]     Expected ({ do { extern void __compiletime_assert_705(void) __attribute__((__error__("Unsupported access size for {READ,WRITE}_ONCE()."))); if (!((sizeof(fail_data.report_expected) == sizeof(char) || sizeof(fail_data.repp
> [22:00:34]     not ok 45 - vmalloc_oob
>
> With this change, it instead looks like:
> [22:04:04] [FAILED] vmalloc_oob
> [22:04:04]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:993
> [22:04:04]     KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
> [22:04:04]     not ok 45 - vmalloc_oob
>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>
> Stumbled across this because the vmalloc_oob test is failing (i.e.,
> KASAN isn't picking up an error) under qemu on my system, and the
> message above was horrifying. (I'll file a Bugzilla bug for the test
> failure today.)
>
> Cheers,
> -- David
>
>  lib/test_kasan.c | 8 +++++---
>  1 file changed, 5 insertions(+), 3 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index cacbbbdef768..deda13c9d9ff 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -98,9 +98,11 @@ static void kasan_test_exit(struct kunit *test)
>         barrier();                                                      \
>         expression;                                                     \
>         barrier();                                                      \
> -       KUNIT_EXPECT_EQ(test,                                           \
> -                       READ_ONCE(fail_data.report_expected),           \

What do we have fail_data.report_expected for? Could we remove it now?
I think it's unused now.

> -                       READ_ONCE(fail_data.report_found));             \
> +       if (READ_ONCE(fail_data.report_found) == false) {               \

if (!READ_ONCE(fail_data.report_found)) {
?

> +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "  \
> +                               "expected in \"" #expression            \
> +                                "\", but none occurred");              \
> +       }                                                               \

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP3kK%3DYWEacvPr5RRen4YkSKL9akLn06Eq6H%2BazqSGimA%40mail.gmail.com.
