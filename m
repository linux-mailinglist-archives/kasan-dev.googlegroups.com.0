Return-Path: <kasan-dev+bncBDW2JDUY5AORB4NX6KCQMGQEQRJNHTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 946DE39CE7B
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jun 2021 11:57:06 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id m3-20020a2ea5830000b0290109369442e2sf6215023ljp.18
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jun 2021 02:57:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622973426; cv=pass;
        d=google.com; s=arc-20160816;
        b=JgACji20vLAGaiTznrl6Mvx/wZ7d0dIVdZaGFnhXX4owgtzQLaFzOZ2RAyIbf3gQWS
         YNFWnbRVqO+SS9e/IPX+7GeQ+R5dcCj7c34Uv0JIq5jC/aJtL+dfWaM9T1Ssoqsv4CzW
         B9GFpHNUEgvTbIGu+ejY4g2D8BDKbOKoX7rPmUbmCzGWy8xnXCDAeg6/LLgViht1FJJZ
         1i7sHpbTHhHBxLUF8UfX5hOz3Kmv5GM+EAGU3nXi2VMt3V/FeE72u37z4eGt1kN5IqSd
         +EU/sikRPdUpCjVXXNagd+Syqiu2vyaWfcJrDCqR13aZQJ8fCWFHon1ykR50WNql2R83
         ySQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=t4A5TK+zK/30/SwRVRYL7kUcJgpkzvLhSR6rUlqf1yM=;
        b=YuYFvRSzuHt6p7MIK7cnuvZZbyVOcR1gOwOu68mf1VOEtGpl3d+ojmnb/ODdH9POrO
         RCNmjrvC5eJ5r3wuws+ailfvjtOcAI967BPIkm9Dl68YzQ7wZsuJwjVNb8W6KJq0xXb2
         XlfH2TffNygCuI94OVAPTilsmXhfHN0ABnmQsku9AuzfHNgiNwaQJbaYfBx3VBvLzXEn
         iNXL9mtv0SQ3tlUAlGf3jy1Io/Y6seZlW5kakg0y6+o3nWXGsBUDXI85Wpc/8RxFUWlc
         jn3EZ5O25EJtTioHx8a2gPZsUzCzCp8tU7geGcZAPRVVri8YXuakQ1LkFkw+bRCtEOSa
         XZtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gyHuPdhr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4A5TK+zK/30/SwRVRYL7kUcJgpkzvLhSR6rUlqf1yM=;
        b=DIPzmj2189s62mSvwUoRFnVUCccregsgwZob5yZ6Ph41bfTducq/hGnlr2DH9ma4aU
         Hd1Tx4BfLMGqj2EMX0jHD2cVgit6t8LiVpusyA/E+lh4w9hEPDnJu3ZEzEkt4TZgjX5r
         SpaPtscmjHvGZ8t3pBKrP/NUMwGyoOGUD5TVOFt2PBI1YTKEp3s7wSl9CydPzyKL6quP
         bxC9cSnYYUjUiZ7Kb7yepcjrOcxNU+7rxys+waF5iO9+o/BzP/eOQjpKFnWfKxZhoLDO
         L4PjR5whWMGlr3LkOmG/OmbCWq/0Q1axFngtASHqgDOXUIILJM5nhKk0nJxQ7Dc6uMma
         0kRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4A5TK+zK/30/SwRVRYL7kUcJgpkzvLhSR6rUlqf1yM=;
        b=qMYjdvmSsTHJI7kUSFLynFZMApZ8nH+MrqN72VfjXwsaxL5Le3bVfXuCH3pFcLYb1h
         dNv/DJIT7gTRI1ScX7H79fv4PJS28RP0Sx9+aUmU1qUhC+so8cp2ipkBisr4v6qYYCAn
         1jHH4TRaX9v+IQlxFazGlbnubAEN0e8OYFUIY6vQvu5x8l8Yo1pt0X7jF08rFQkTVQ3G
         ZF6gzzDRqHef5MJ6mJYI5+l8rzRFbPfvhLT2Rw6aByTB3MvbQMyQHiHKbN1N7S5ih5rY
         tg3OWFJNQKRLQ5TOCcueHW6XAIGCXcAp7PbuyPqVvU3rBqaqWK5DU9429L4oXzWY9a8T
         +/TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4A5TK+zK/30/SwRVRYL7kUcJgpkzvLhSR6rUlqf1yM=;
        b=KSJi04Rgx8+Rii50KgM1LUv3sM6WBpX5LeEwbHBTCtoIwCbJVrKM4bThGFWHuYsarJ
         k8ok6z4deQm35DaUUUDrhZnxh6X+CXJ44s4rwl0VyWFpdsxLLBikM//Tzi+F2Ov+uQVh
         iZgQSwQAG/ZoRnKZzd69sowtU5nHfYt8bqkTr5AauxGftaYA8Xc8ACJ42bUZQr7bo1u2
         nFdBjroOvGc1dRB0lBTViSglFqFCDpKWRo+gQHv8Io3nr1fgTYzDQxF8KUcF2ykBCgnA
         D2EafipxwScGzbjr/o0+hdaiplbexwi64Nsrl0aqacJ8erT2q+t0a1XuJZglerM5plLz
         o2Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uEfbZAb5wxPnVX3dpoMpH5RISrz0hTl5I3tbqzy7mkVpmKiSl
	ENK5KWvVp+XmTAYttI4Vdic=
X-Google-Smtp-Source: ABdhPJwG6OSsbgPQoiQJh0vFpq1hiKEFWis6J43AUEuGTPa2mhVQG5YI5YWy6C3t0dHljr8oZT8BiA==
X-Received: by 2002:a05:6512:3c91:: with SMTP id h17mr8730869lfv.214.1622973426020;
        Sun, 06 Jun 2021 02:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:: with SMTP id f14ls2724189lfv.3.gmail; Sun,
 06 Jun 2021 02:57:05 -0700 (PDT)
X-Received: by 2002:a05:6512:46c:: with SMTP id x12mr8452699lfd.203.1622973425042;
        Sun, 06 Jun 2021 02:57:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622973425; cv=none;
        d=google.com; s=arc-20160816;
        b=eiPI0wwuK6iQVO1r8fnN7esT7Pe0cvCq0mSwLZfh+15N2D+tItU/DCfWzV4ecYvbJO
         Mh/mbBaShk6DEQockbSBCnbYKrCoT3Hd0lpGIDkKnndMFo3kGHZrr0EaP4ldtoi/hL3/
         lvxdNAvsV3irhQov1Lj1HHXzR9cZY6uV06/QdENcKTwQ5EhC9PSJCsGt9QdrfDTxpccO
         lj6z0cAD1KgGRpAQOXT8eYy8ZRFpgTHomNX/L5paAFvDEwq5F54cdhVFiLoatA/B2TTS
         g4e+fIIAHmZ631FYe/91rlJqRZ0aUFQOeyt0GG1HskOQraER2ONYDF9r8xwsNDfoN++u
         Mqdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GC1rujwsbQmamgvNRPbIbF24joJdDinHk/7XHINbO0c=;
        b=hGgCYgogCBYEv5YJPInPuKy8aY88OxMS8o1CtT30y0UW33ZuqCYRBJ0NfiSkUFKWhg
         3dfRTKcQu+CGi+Poj1gBd2itYOIUBsNkIYZpRBPVb3bEM0TgEdkvj6M+j/RNI/QS/sSy
         2qQ91hzgHLjctP/xB8s+sUC8qnsEXC/mk+7zV98aEnk8OIE/8nLIg/nlySXMgXgV8fti
         E54BFiT8vy8knACA+tzSnB0SGdbg5iHXLAcJnnXjqbHOp6tw3o4iwwp+tHjdvWQDxZCe
         Tssa3O47O9Do49CHr0MhwIOGcQsI4hHS33A97/Gmz4N0M5fKk/4B/iQGwc1f3612VaM2
         bBAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gyHuPdhr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id j2si476905lfe.8.2021.06.06.02.57.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Jun 2021 02:57:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id g8so21611122ejx.1;
        Sun, 06 Jun 2021 02:57:05 -0700 (PDT)
X-Received: by 2002:a17:906:a945:: with SMTP id hh5mr12949705ejb.227.1622973424580;
 Sun, 06 Jun 2021 02:57:04 -0700 (PDT)
MIME-Version: 1.0
References: <20210606005531.165954-1-davidgow@google.com>
In-Reply-To: <20210606005531.165954-1-davidgow@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 6 Jun 2021 12:56:53 +0300
Message-ID: <CA+fCnZdzki-0vMgbsjrXBz7Uqwh+vo9L6tXCAfiyMpVjV3tV=g@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
To: David Gow <davidgow@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>, Jonathan Corbet <corbet@lwn.net>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gyHuPdhr;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a
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

On Sun, Jun 6, 2021 at 3:55 AM 'David Gow' via kasan-dev
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
> Also update the example failure in the documentation to reflect this.
>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>
> Changes since v2:
> https://lkml.org/lkml/2021/6/4/1264
> - Update the example error in the documentation
>
> Changes since v1:
> https://groups.google.com/g/kasan-dev/c/CbabdwoXGlE
> - Remove fail_data.report_expected now that it's unused.
> - Use '!' instead of '== false' in the comparison.
> - Minor typo fixes in the commit message.
>
> The test failure being used as an example is tracked in:
> https://bugzilla.kernel.org/show_bug.cgi?id=213335
>
>
>
>  Documentation/dev-tools/kasan.rst |  9 ++++-----
>  include/linux/kasan.h             |  1 -
>  lib/test_kasan.c                  | 11 +++++------
>  3 files changed, 9 insertions(+), 12 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index d3f335ffc751..83ec4a556c19 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -447,11 +447,10 @@ When a test fails due to a failed ``kmalloc``::
>
>  When a test fails due to a missing KASAN report::
>
> -        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
> -        Expected kasan_data->report_expected == kasan_data->report_found, but
> -        kasan_data->report_expected == 1
> -        kasan_data->report_found == 0
> -        not ok 28 - kmalloc_double_kzfree
> +        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:974
> +        KASAN failure expected in "kfree_sensitive(ptr)", but none occurred
> +        not ok 44 - kmalloc_double_kzfree
> +
>
>  At the end the cumulative status of all KASAN tests is printed. On success::
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdzki-0vMgbsjrXBz7Uqwh%2Bvo9L6tXCAfiyMpVjV3tV%3Dg%40mail.gmail.com.
