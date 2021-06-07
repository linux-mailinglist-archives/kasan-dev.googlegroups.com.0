Return-Path: <kasan-dev+bncBC7OBJGL2MHBBROH66CQMGQEGE3GJRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id E594739D867
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 11:15:50 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id n3-20020a378b030000b02903a624ca95adsf12373377qkd.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 02:15:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623057350; cv=pass;
        d=google.com; s=arc-20160816;
        b=OAKbWs6XgbN8On1rM1NiUrleGTRdBMP1DFte2RHt4V+XnY/sM/QCwvjOD0ZS+3Q2aW
         SDAgegiwiXV1Q72q6lXZlXakXcOnqAT7CEvqGm5Bjfvhd1gkAkrErRaLuBrAcaN7yUuf
         XnJ6aiNRG8ox6dQZ5LxjS5aVCurXfl9atpXHbYyJet2Hi2iEEEmw+FN4Bv3iMeMfs+Gr
         8PNQxh81NV1ic/hGuiCqDtVDl8O1NJujrfeeIS77PzVwN7XWgdOHcfchM+/g7skcMgvb
         1029ujFCvOOE0e71GheOlZpUflKRmsx2n+e1Md61I58DB7JVtEAG65aS6gxsA/rOvEfm
         mRmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=M9d4k1qtIKoaDe9ArbAY1X/iURhKZ6Ar4hpSorTuHBg=;
        b=npZo5bMbqWbqDavp0FcsCw+fFpGBl/7HRlO4qbGSHoN3+qmOTPbUjNzGNo994qdZ1j
         fN+2KzOzB9rK9dOtYmAru6xb3WmWo7qsWBGfQgfaxw8AgWmaL1GD76vh0f+IKTWFLOmm
         npipvBOryXdtoLo+opvnJBgTnuhkZLjyVBICkocR2HAHSxLt5PZagbczq8FqECIOlENK
         aFt6arkCXaPp2eptCObTY4hfSoO1kxwFeQBIpcg6upNoLYTEedSpJYmp6JexZhvLpssg
         tarLM2TG8ZXfQ4rpyfW8lVZ0t4MRXWvqLbKnBy/o1iANPYcNujQgt7LQW68bHUpHi8hy
         F0zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SlECEHPD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9d4k1qtIKoaDe9ArbAY1X/iURhKZ6Ar4hpSorTuHBg=;
        b=qKICRpgvaouRRKxhVCP8dB3UdI9/XSdc5LQP5u+3ZuvrUOtovZe8KlzVEx7JyAq9pS
         du46GppMu4cdBTlhXWt2R8BDAmUP0urx30+QgkPzt/y+Ow7wIZpQCxW5cOdeyqG0Ejl1
         vbsic48thVIdoWazueJ86Qf8G40N7rUS/IA2gNd+KwX9CaNT1MTwVwu+THmVna0limK5
         I1eQDSFEe6akdp71xQwH4BPcuiTHHvijbQx88N4CAveqqDmr+RZS1BP5+H6QCpns4KGu
         zAEzUkFRWKXGGdGjx1s8HAMQCQ8B7m9RM6GmcczG7D0QnPGqk6sFRizhcIX6DLVEk36u
         HXMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9d4k1qtIKoaDe9ArbAY1X/iURhKZ6Ar4hpSorTuHBg=;
        b=BEHYYf4ajOtz3Nh0Eog7dsoRyj6z6D5sXtwWp2qO5woFk+o7P+HRcRWu2N7c9vghNh
         moxouWFqgcBA3IgZnVn22JWdFXqrhp9UMTv976M9tdM/2SQwtqew0QvcLeZeayw02z0a
         Mcjyvoch5hda43L8Amsxcc4s2xdh3voMj6KUlfUnOV7Ar3UeLGe2K//Y0TAXsppfjPoI
         tsCQLCSIjOwQaodHpS6qgLIO9eKPIZwK/U1ZdukJO1Bl0CAj24sWb4s5bjVkA5JKC7fY
         r/roI6X6shKTEIHBl8BgalPgTRXHrE3dmGhXW8Wxlovjxi5E0CFD1338fhTOhCwDK9wZ
         MhuA==
X-Gm-Message-State: AOAM5329flSuowBdImrM74xs5fUuo3pxyb+OvFM7VxILYQn2aeqVXO+6
	+9/X9JfRZY+owyFthPKEMqE=
X-Google-Smtp-Source: ABdhPJxVOrxgNb6wrP8rzrlMBE0zO0khrl2uG2Nh1zdGa5iFY1uxtBkoWdCy0IpcB3ZB27bPkj9ajw==
X-Received: by 2002:a37:b3c5:: with SMTP id c188mr15656071qkf.242.1623057350010;
        Mon, 07 Jun 2021 02:15:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f017:: with SMTP id l23ls8184038qkg.2.gmail; Mon, 07 Jun
 2021 02:15:49 -0700 (PDT)
X-Received: by 2002:a37:a404:: with SMTP id n4mr678973qke.296.1623057349522;
        Mon, 07 Jun 2021 02:15:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623057349; cv=none;
        d=google.com; s=arc-20160816;
        b=VlEFbuXmXOpZczgt1yoFNsyhICGrJRi3Hc78mzGk9ZZxO+uN77p8pLtCJb90lc9PtF
         TkBqZ+2/HTTTjSbNYJluOHD1dP2VHTAV67ou1OLz00BGnLFqvrc/YqY+a477krTUVhyW
         4kU0aX5KwenPmzog8t73BgFronaJYiVAGQGQeSruoNu9fs5YOznTs5mUjALk5nsKrZ60
         wF2CzDeIZIs4ppJpRaIW/pTT95A0V8nkIF69feC0rsInbJQKD4aehvVwcX2idgEYmmP2
         54KyAIVjAfLJLTWyvujKvyXeNeF6WtV8SdURgjAJUhwsWLm6GPjbXeSi8hXp5BjY62If
         X+MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XUfDIMDCYmEA5qA3F9WnU83CptP8nZGrHCEeaSa3FvE=;
        b=u0Z8PCHId8tc4QYHWx5WXITdNApZEa6UmZ55fDevAg5gkVTHP+yOUStqZpophX+90R
         ldQ4qojpNewGPs6rDige2obZJavxblHfyY6ZYiWEj3Jjk3GoIFMPjo3Q8ZmhIXAFcNY/
         IvG+w1c5dc4qun2k3ti3OvTrBKXF9fr/4wObdaeiAVOf3O27rOyY5Fp+QvUzFN3KFK4H
         LskyIExHki48mjAuT22tMIDOSiX2YyWy5AU8RdY39VT1avfCtJpT6kki58nQTfMddQ7o
         zebI9d6rj3QmfXXnit4FsIynfoF2HQ9NdT9484KR72yZ25Rohq9Tzb0P5UskqvH0hsJx
         qIsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SlECEHPD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id x24si1326714qkx.3.2021.06.07.02.15.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 02:15:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id d21so17351569oic.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 02:15:49 -0700 (PDT)
X-Received: by 2002:a05:6808:10d4:: with SMTP id s20mr11061334ois.70.1623057349040;
 Mon, 07 Jun 2021 02:15:49 -0700 (PDT)
MIME-Version: 1.0
References: <20210606005531.165954-1-davidgow@google.com> <CA+fCnZdzki-0vMgbsjrXBz7Uqwh+vo9L6tXCAfiyMpVjV3tV=g@mail.gmail.com>
In-Reply-To: <CA+fCnZdzki-0vMgbsjrXBz7Uqwh+vo9L6tXCAfiyMpVjV3tV=g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jun 2021 11:15:37 +0200
Message-ID: <CANpmjNMu3pwhAq4DdKpgsz=qTzB6v5qW6A2FWo9CaYstKcWkqw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: David Gow <davidgow@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Daniel Axtens <dja@axtens.net>, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SlECEHPD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Sun, 6 Jun 2021 at 11:57, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Sun, Jun 6, 2021 at 3:55 AM 'David Gow' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
> > compare fail_data.report_expected and fail_data.report_found. This
> > always gave a somewhat useless error message on failure, but the
> > addition of extra compile-time checking with READ_ONCE() has caused it
> > to get much longer, and be truncated before anything useful is displayed.
> >
> > Instead, just check fail_data.report_found by hand (we've just set
> > report_expected to 'true'), and print a better failure message with
> > KUNIT_FAIL(). Because of this, report_expected is no longer used
> > anywhere, and can be removed.
> >
> > Beforehand, a failure in:
> > KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
> > would have looked like:
> > [22:00:34] [FAILED] vmalloc_oob
> > [22:00:34]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:991
> > [22:00:34]     Expected ({ do { extern void __compiletime_assert_705(void) __attribute__((__error__("Unsupported access size for {READ,WRITE}_ONCE()."))); if (!((sizeof(fail_data.report_expected) == sizeof(char) || sizeof(fail_data.repp
> > [22:00:34]     not ok 45 - vmalloc_oob
> >
> > With this change, it instead looks like:
> > [22:04:04] [FAILED] vmalloc_oob
> > [22:04:04]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:993
> > [22:04:04]     KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
> > [22:04:04]     not ok 45 - vmalloc_oob
> >
> > Also update the example failure in the documentation to reflect this.
> >
> > Signed-off-by: David Gow <davidgow@google.com>
> > ---
> >
> > Changes since v2:
> > https://lkml.org/lkml/2021/6/4/1264
> > - Update the example error in the documentation
> >
> > Changes since v1:
> > https://groups.google.com/g/kasan-dev/c/CbabdwoXGlE
> > - Remove fail_data.report_expected now that it's unused.
> > - Use '!' instead of '== false' in the comparison.
> > - Minor typo fixes in the commit message.
> >
> > The test failure being used as an example is tracked in:
> > https://bugzilla.kernel.org/show_bug.cgi?id=213335
> >
> >
> >
> >  Documentation/dev-tools/kasan.rst |  9 ++++-----
> >  include/linux/kasan.h             |  1 -
> >  lib/test_kasan.c                  | 11 +++++------
> >  3 files changed, 9 insertions(+), 12 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index d3f335ffc751..83ec4a556c19 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -447,11 +447,10 @@ When a test fails due to a failed ``kmalloc``::
> >
> >  When a test fails due to a missing KASAN report::
> >
> > -        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
> > -        Expected kasan_data->report_expected == kasan_data->report_found, but
> > -        kasan_data->report_expected == 1
> > -        kasan_data->report_found == 0
> > -        not ok 28 - kmalloc_double_kzfree
> > +        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:974
> > +        KASAN failure expected in "kfree_sensitive(ptr)", but none occurred
> > +        not ok 44 - kmalloc_double_kzfree
> > +
> >
> >  At the end the cumulative status of all KASAN tests is printed. On success::
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index b1678a61e6a7..18cd5ec2f469 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -17,7 +17,6 @@ struct task_struct;
> >
> >  /* kasan_data struct is used in KUnit tests for KASAN expected failures */
> >  struct kunit_kasan_expectation {
> > -       bool report_expected;
> >         bool report_found;
> >  };
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index cacbbbdef768..44e08f4d9c52 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -55,7 +55,6 @@ static int kasan_test_init(struct kunit *test)
> >         multishot = kasan_save_enable_multi_shot();
> >         kasan_set_tagging_report_once(false);
> >         fail_data.report_found = false;
> > -       fail_data.report_expected = false;
> >         kunit_add_named_resource(test, NULL, NULL, &resource,
> >                                         "kasan_data", &fail_data);
> >         return 0;
> > @@ -94,20 +93,20 @@ static void kasan_test_exit(struct kunit *test)
> >             !kasan_async_mode_enabled())                                \
> >                 migrate_disable();                                      \
> >         KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));    \
> > -       WRITE_ONCE(fail_data.report_expected, true);                    \
> >         barrier();                                                      \
> >         expression;                                                     \
> >         barrier();                                                      \
> > -       KUNIT_EXPECT_EQ(test,                                           \
> > -                       READ_ONCE(fail_data.report_expected),           \
> > -                       READ_ONCE(fail_data.report_found));             \
> > +       if (!READ_ONCE(fail_data.report_found)) {                       \
> > +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "  \
> > +                               "expected in \"" #expression            \
> > +                                "\", but none occurred");              \
> > +       }                                                               \
> >         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                         \
> >                 if (READ_ONCE(fail_data.report_found))                  \
> >                         kasan_enable_tagging_sync();                    \
> >                 migrate_enable();                                       \
> >         }                                                               \
> >         WRITE_ONCE(fail_data.report_found, false);                      \
> > -       WRITE_ONCE(fail_data.report_expected, false);                   \
> >  } while (0)
> >
> >  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> > --
> > 2.32.0.rc1.229.g3e70b5a671-goog
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMu3pwhAq4DdKpgsz%3DqTzB6v5qW6A2FWo9CaYstKcWkqw%40mail.gmail.com.
