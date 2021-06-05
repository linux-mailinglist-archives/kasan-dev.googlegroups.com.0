Return-Path: <kasan-dev+bncBDW2JDUY5AORBZMP6CCQMGQEWEHCAPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C19E739CBB3
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jun 2021 01:25:25 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id l13-20020adfe9cd0000b0290119a0645c8fsf3113510wrn.8
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jun 2021 16:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622935525; cv=pass;
        d=google.com; s=arc-20160816;
        b=ifVVDhwAV0xgcenZmK1TMOIPiAkBR/4iiJwF+CQOB/mJT82aF+SlUL69/4r3YskFI3
         OkoENCTyL5FO9Bou3uoEXAjvyWBiBZygO15TEAycsn18lsyKRmDJFatjQP8j9msjqe+k
         /sadMuo3b7MdflgDbnULYpvd1kmQ6pOLjc2c/ANQkgYgKYMkU6ZHuWiucVP1Zjt5a6Qr
         6dM36Gf0TVSnvnu6CzJ+fPfQlN5ztVfYo3NHYroLMIVVPabxhLmukyEBSZ/aoA0wRJ2f
         Tj2mpJEpSJWAyWEiQEBVyGZTdqcTs6667fcSWSLswbgKlMrAR9BIbs0wqH9eDG8rHxHj
         YAIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=5cmJwVnUUn+dkh1EEvL6TQk9r/7rrpAdiXSSmFHkXsw=;
        b=LOVowrHHLJC8HtR467okbNiKYWDYe9+k4CySsb3s2n3q8M3LGbx4dEG6hjAiIsCjHy
         miENlcDL73UFFAAQNQcZz75ky03JQycA8iWDZ43JYmeMYXaZIvL5QG0QERGL0qMOAVYh
         K6NO7V1VmrKFUFpKAR0pTSOq/+L0SIXvQdutEHJrm3eqAInmlRuyZkHaoeDqH/qXa/lu
         PA+KbzOg1GRfkVlUZbd1gmZJDdVcjI6lzIJAzcT+3WYc6Ge+isJdvY2+vOpp3rcufyXL
         ty0TAu9xowuL6EXgG1bv6rDGCfMvgoiBoLZlmny4st4bEtkIf5ir4QJo7YyJ9eXuYUqY
         /PFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=E4P2pFnl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5cmJwVnUUn+dkh1EEvL6TQk9r/7rrpAdiXSSmFHkXsw=;
        b=Vocz2U0ellSvODuPBm1fB2V4CZdv0j9nVUny+nNS7YLO/OY+CmUJ6cXN57l+B8uNbD
         UjtBsm1/s0E9akaCGHgeDClza3RgCd6eRR52SEIFqyo6FwRxtQsPLHXqEZSl5AtpfG1Z
         1fhoMyaP2XQwx0m8T2y4jYKd6X1xRffluZrfg3clKdvG1BfjZL32zDp92YH7qlBpcQap
         Jnxca4NwGSo0NJafZjqHfXAifQYib0fhfdb/baVg2pmd5CKIUq3cY+JPQ+OoTDlP8zEG
         wsaXiBW4FdBJWzQUmTLJVB9VpTegLjxV/REYGde0cfw9QkFttzIpM7uc9JaqLUad12cE
         N15Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5cmJwVnUUn+dkh1EEvL6TQk9r/7rrpAdiXSSmFHkXsw=;
        b=MYrybse4EUg9OVmQa0ASIEnxfg641+0HR7BKvMomAQ6x1Koc9WvAH3PmUyfPftgujX
         wy8nQVcGSN/vOGrgu+/1q4LJTiTpQedw3A2+o14+c3kuG7e+d6OlqmPNg2ru3WccPXIv
         bzboINoXTelKE69yWnkKP5jaCbxfAOf+7DHaCIpWqXCxwWZiPRQ78+rfs1GDTOwvNCNZ
         bTTzgNIfenLUzGd0L2smJISjTA9y7qzvXU5r4QvEP4hboFSx6RgoquY4ayezXNThir2O
         ILuyvipXb7w6bxKvFYR3oGbPVzCBM+F7Bx0oNyU9k7ATSMJuJs455Na+hp0IrIiOaUzx
         SRSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5cmJwVnUUn+dkh1EEvL6TQk9r/7rrpAdiXSSmFHkXsw=;
        b=naNvxblUyxDxT++CNFYyF7J9g6BnMCwzM1JeFHtLFF8HHJICHzZnPmL3xYPLb93r6a
         AZQpqrgTra+objCmYag1qvKy6C8FQVjqHz3aoCvg4CC4KlYl7auEK5IFzpv+ORiweNWJ
         NbYuc9otO2ZDTY8lyskDO9ngZVoJ6Sv8jhK5kwTIcKTISQS7yBZw1mbFeVAyW8nV6GhN
         7x1cFK9cgtFsYzl2UkySdVMmXVljOJIXsgdykgqx8MFheIUt3ka4bnPYwXtrBztGA47c
         YvMqiCiCiwZTM8kuK/cN4IpPNyMdC55/lTEywRPqbE0hsvj230w6aR8EJDStOYcXKQ/D
         sPzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PCcie9yjG966PSS/52su1ykUCxfeNQZEafMaSI0dqMMe6tYJS
	3Qoq3/N3CGU00sd/ElvsoAo=
X-Google-Smtp-Source: ABdhPJwo00XVTPhWo82AxPSvzsYscS9DmWIoUh8Aptja8e2S27N1FlvFoiNLbK8c5XkpB4xSWhVYtQ==
X-Received: by 2002:a1c:cc17:: with SMTP id h23mr9692423wmb.129.1622935525526;
        Sat, 05 Jun 2021 16:25:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:19d3:: with SMTP id u19ls4331421wmq.3.canary-gmail;
 Sat, 05 Jun 2021 16:25:24 -0700 (PDT)
X-Received: by 2002:a05:600c:19d3:: with SMTP id u19mr9942359wmq.100.1622935524754;
        Sat, 05 Jun 2021 16:25:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622935524; cv=none;
        d=google.com; s=arc-20160816;
        b=HYtrb/I537TjvpqyeQDFEekrwSH0SlH/rPcZkpUT1hdTNEczX+1fi10BwYMCcSOd1K
         3D8utZ96Ib5+CJ09fBkd22mT+Xrdexz/VWNfdK7vHOB/TpSqYR3/AqHQqP2cFljt0tg2
         EVYv7g4TlqB3nRjJ0ZTz0uAhmBF0VvCi4H15IlwNaHsoLejYFI3Lt5X6S96QPGAW7pf1
         57jjHLkDf5p2DsSDDJjP0oDojmPEl9YvI9dF5WC0zXu9z6M3zL2hfoxy20AxxqUo26ec
         kIPJnqfimDuFi3yZEg0a+DuekvUIBPgprXYNMGj72pbkaJg/m/nKPHKveDjwwEatc4yN
         et4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=InZrcKArztFFxV4PZAOd+BMerw3Nx/ldUFLAqxjEv+o=;
        b=tD8nPY1CVQ1eJrUGKEobgk8cVq+nKEnA3UguxrWc/B+HzqfifL/zeUYArr7btACKQ1
         dAnHOPzl5i8BkzcUWZJ2fHyMl3L1Rmcf1Jd+Tyo7WSBYZs6qpL/JZ9O4WkAmbVo84seL
         2lG6tYJkCy3EgHrE6JuXUfNpR2LmjJSAqv8+r0eoG4cuUPO8rU6ZFpRfOp9QCY/wRazm
         oy3bIoy+upCR/nfqotGdeV2kqJdhoIYQb/EHv9ojPUO11iHJqFeerW2CiHsSYrpGg+/Q
         gB6y5srVozsuIEelFJDpFohI9CTJBoRTjYVTTAlUHDMMd1tsLUW9k5gdATvKc9/MC1xW
         aDUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=E4P2pFnl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id h7si696900wml.3.2021.06.05.16.25.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Jun 2021 16:25:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id b11so15583740edy.4;
        Sat, 05 Jun 2021 16:25:24 -0700 (PDT)
X-Received: by 2002:a05:6402:42d2:: with SMTP id i18mr12403960edc.168.1622935524421;
 Sat, 05 Jun 2021 16:25:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210605034821.2098034-1-davidgow@google.com>
In-Reply-To: <20210605034821.2098034-1-davidgow@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 6 Jun 2021 02:25:13 +0300
Message-ID: <CA+fCnZdAmVoGjTEQBoKQF0x_NtUau0jydSnF8bYHwDGRNFddHw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
To: David Gow <davidgow@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=E4P2pFnl;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::535
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Jun 5, 2021 at 6:48 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
> compare fail_data.report_expected and fail_data.report_found. This
> always gave a somewhat useless error message on failure, but the
> addition of extra compile-time checking with READ_ONCE() has caused it
> to get much longer, and be truncated before anything useful is displayed.
>
> Instead, just check fail_data.report_found by hand (we've just set
> report_expected to 'true'), and print a better failure message with
> KUNIT_FAIL(). Because of this, report_expected is no longer used
> anywhere, and can be removed.
>
> Beforehand, a failure in:
> KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
> would have looked like:
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

Hi David,

Please also update the failure message in Documentation/dev-tools/kasan.rst.

Thank you!

> ---
> Changes since v1:
> https://groups.google.com/g/kasan-dev/c/CbabdwoXGlE
> - Remove fail_data.report_expected now that it's unused.
> - Use '!' instead of '== false' in the comparison.
> - Minor typo fixes in the commit message.
>
> The test failure being used as an example is tracked in:
> https://bugzilla.kernel.org/show_bug.cgi?id=213335
>
> Cheers,
> -- David
>
>  include/linux/kasan.h |  1 -
>  lib/test_kasan.c      | 11 +++++------
>  2 files changed, 5 insertions(+), 7 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b1678a61e6a7..18cd5ec2f469 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -17,7 +17,6 @@ struct task_struct;
>
>  /* kasan_data struct is used in KUnit tests for KASAN expected failures */
>  struct kunit_kasan_expectation {
> -       bool report_expected;
>         bool report_found;
>  };
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index cacbbbdef768..44e08f4d9c52 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -55,7 +55,6 @@ static int kasan_test_init(struct kunit *test)
>         multishot = kasan_save_enable_multi_shot();
>         kasan_set_tagging_report_once(false);
>         fail_data.report_found = false;
> -       fail_data.report_expected = false;
>         kunit_add_named_resource(test, NULL, NULL, &resource,
>                                         "kasan_data", &fail_data);
>         return 0;
> @@ -94,20 +93,20 @@ static void kasan_test_exit(struct kunit *test)
>             !kasan_async_mode_enabled())                                \
>                 migrate_disable();                                      \
>         KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));    \
> -       WRITE_ONCE(fail_data.report_expected, true);                    \
>         barrier();                                                      \
>         expression;                                                     \
>         barrier();                                                      \
> -       KUNIT_EXPECT_EQ(test,                                           \
> -                       READ_ONCE(fail_data.report_expected),           \
> -                       READ_ONCE(fail_data.report_found));             \
> +       if (!READ_ONCE(fail_data.report_found)) {                       \
> +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "  \
> +                               "expected in \"" #expression            \
> +                                "\", but none occurred");              \
> +       }                                                               \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                         \
>                 if (READ_ONCE(fail_data.report_found))                  \
>                         kasan_enable_tagging_sync();                    \
>                 migrate_enable();                                       \
>         }                                                               \
>         WRITE_ONCE(fail_data.report_found, false);                      \
> -       WRITE_ONCE(fail_data.report_expected, false);                   \
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> --
> 2.32.0.rc1.229.g3e70b5a671-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210605034821.2098034-1-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdAmVoGjTEQBoKQF0x_NtUau0jydSnF8bYHwDGRNFddHw%40mail.gmail.com.
