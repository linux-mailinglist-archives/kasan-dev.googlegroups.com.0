Return-Path: <kasan-dev+bncBC6OLHHDVUOBBBOL46CQMGQEFBRP4SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29D0339B4EF
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 10:34:14 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id t4-20020a195f040000b02901dfc7237858sf3401480lfb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jun 2021 01:34:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622795653; cv=pass;
        d=google.com; s=arc-20160816;
        b=HxPwcdNyzJgVIdvVIx9lzW/2d4A53E6gkrpG36NDvZt917aHKZV72QbDsRFmGcjhfR
         e57+S5OhPSJ2jUvUv97ZU6rF9bb5dLpoRB52r3gwMmOAXo29swcvIMBmHK3Yuj+MYXrd
         kmhkNM99waRxiR9MxOaC9kaD5N3ypNBubmV20244MM7wYy5BFVbzra3+nsqRgpNemp6Y
         8ys1L3Pp7rZtOVkmbP2H4VLeIxoBA4kFo0Tcf1XNngN7fo/T99IzvrhVsgJKyieRCYln
         B+SayArO7qIWQRUJ6t9jsVZHQEP6kN42AU6uyi45lkgazhXNs4E+A6B6Pr7yoi+zfVeR
         lXqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d2d45MNVvpp8hhtKLcq07wryWj4hy3RY2ApAlUXTaSw=;
        b=Kd78R+JZwfb3CbQmAYFxpGjOdecsFQKSswzH1H8dljR2bC2FutRCpdrTdqwDRijwuE
         D/l/Gs6GPm5W6k53U8jKKlXKjm1902VO3DS55pRI3unoMSb8lwpFutxh35KTFiAV+U7D
         FvVJS2m35CaqqGbc+CjTSSwG8fSecl9htvTWgoG7cRGlq0XAZdJJJY9VFKgc7B9m815Q
         aBUrG4YAi14wK/OFY7p1P7Xsacw12LYMxDX+hnKdERuApOmMhtPry7J37xibb3TYWeug
         wv45unJd4t6UqfJ9QjI8L6D0NPCdEA2U3no8nfbZPjHBMbHPLX9oaQZnSSeGJxGP4dmg
         lgqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F+l7vS9m;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d2d45MNVvpp8hhtKLcq07wryWj4hy3RY2ApAlUXTaSw=;
        b=WXdS7FgqG6KGojK1OVdm/1kqvDIh8QgSxC6o2UGcHML6Abjq6WvwuY3E041/BrALpc
         yI6G/EgwsuwtCkYiWssb3BguMo6Mzp28QOwkbCW9MlXkF+GD5e2zidmVPT24s0+1neru
         AFYn45JZVF8h9gGQr8XhNl6XXAJCUlcOHGHHaYXyJlGLDxvZBO8r/cg0/0iP4kZOXfxs
         xA9Qg/IjsZ0Dw8ViH6UJdUuKlZEnLQexuK19+eiR/mZsEDiYmIY6VrPdybGyPK0QFd4a
         keLMOKK1eHjuaQIVFoNH289zvPm723HnClCY/PTtfvWC5bTEChcmM1AR+FGIo3TwkkYF
         qAfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d2d45MNVvpp8hhtKLcq07wryWj4hy3RY2ApAlUXTaSw=;
        b=UdGIxzo9KMHFVRtzba2+pKEnhKYflE2KoQ+Ox06resVxWQrSwzJvHzO/oV4Z7BRjR8
         Cn9qm91nQ28XYsxLBCmO7834QED1XRTETAFObHDCZcSLMkccXNB7a6rFumWzkanhOjzO
         +FipKnAeganiVa4KDc9eRpJextjlvOR4csS5/6P4r32/zyv9WWCrKWRyx59uGQmMNapu
         K1+v+WkEBkPEkcUOZucXGbvBctuPIJlKNYN8zDGRM6rd7gUEAzOKNVVbhbNnsF7p5l1u
         BXjCgUS8l5LV9Ug/vJTGpqEkahHmIX2kZGh2cMJf8lhnmCznsUROK8GZ4wd1bt60TNHa
         zajA==
X-Gm-Message-State: AOAM532zIej/rHUt/Erf64F3FwH8KQs+6ZZEnFNXsYSkYaMbZxzt5uOH
	OhErw/0xv2IHBGlNGbEA91c=
X-Google-Smtp-Source: ABdhPJx35w5QgJv0Gl2pODVAY22pTyq+WPs1AHHB/RPIkgevQb8afLRygBS9IgGZbbfcQT24rjO4Ng==
X-Received: by 2002:a05:6512:3044:: with SMTP id b4mr1994089lfb.289.1622795653592;
        Fri, 04 Jun 2021 01:34:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a371:: with SMTP id i17ls1446465ljn.11.gmail; Fri, 04
 Jun 2021 01:34:12 -0700 (PDT)
X-Received: by 2002:a2e:90c5:: with SMTP id o5mr2640379ljg.7.1622795652403;
        Fri, 04 Jun 2021 01:34:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622795652; cv=none;
        d=google.com; s=arc-20160816;
        b=Q9cFbFx9OjViqjPrGx7Niw2yUgRP0y6yrvGiPA+wwtOGlZUHWaNIOpMfDVqfiyMXIc
         ZH3lkElP3iu8IT7aIe0bUk8NQ+sQZh4VpjHFyBmfO2qMnm5UiC5orAjLTOtBalCqhV7n
         4nPD+t8G2QQHj9/d24r8MN+B97hKrE9Q7mggXwcgYScOZ1JBejBsW977gaDTnqqGr0p5
         cCYt1PH7+dZbD9jwLD6olGRrEFFd6+ad9Z3N8XZ8rJW0vkluqzkj0yaLfA8LAvWYyK9n
         21+ZwpD3wJZT9dS3zgVF4iIG7Tf0CFbLJ8mrAXepyb7zM28Uo4rRg2ZwZ0HY9XU7gbwS
         iv3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2b0T1Sxej99eruw62S3x3NVpggwE8s3zSnQ/kAj+v5M=;
        b=ffpGK9VURh4eIu5M0Z222uq/RBhgYrjhZ6so/VIp+Hrh6Rgt8NFviN28t+CrAS4eib
         /ej+dmgIO7ZPtet5L38RpN7b33d77SwFMEO0LVDr0aZU4ci7mmECJ2Xv34+OYUQSmlxT
         Pt3k+CVa38w38mFCTFeh11YfB5/QwUGDL8lQfdRf+isT73RZowS3JUnj2z0Mql83X+9i
         0pXdnCKLAurIXwsi6b4fjdFBGIx1juWChoBvqSv2sBGEXS7gTGPi9OdjaDnBQ+JX49tq
         yCegt6NkdfhvJRnczlucLxx8dK+eL+l/p6JWoH6tCMXoiwXS+QOf5p1w//oEgGkNuL2h
         sjoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F+l7vS9m;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id z2si170244lfb.13.2021.06.04.01.34.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jun 2021 01:34:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id v206-20020a1cded70000b02901a586d3fa23so861682wmg.4
        for <kasan-dev@googlegroups.com>; Fri, 04 Jun 2021 01:34:12 -0700 (PDT)
X-Received: by 2002:a7b:c44f:: with SMTP id l15mr2466292wmi.151.1622795651753;
 Fri, 04 Jun 2021 01:34:11 -0700 (PDT)
MIME-Version: 1.0
References: <20210604052548.1889909-1-davidgow@google.com> <CANpmjNP3kK=YWEacvPr5RRen4YkSKL9akLn06Eq6H+azqSGimA@mail.gmail.com>
In-Reply-To: <CANpmjNP3kK=YWEacvPr5RRen4YkSKL9akLn06Eq6H+azqSGimA@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Jun 2021 16:34:00 +0800
Message-ID: <CABVgOSkEGWZx=Cojx4d9+VdjFHNN4=HVmvcO7k6tZ_w5gcA0yg@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F+l7vS9m;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::335
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

On Fri, Jun 4, 2021 at 3:55 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 4 Jun 2021 at 07:26, 'David Gow' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
> > compare fail_data.report_expected and fail_data.report_found. This
> > always gave a somewhat useless error message on failure, but the
> > addition of extra compile-time checking with READ_ONCE() has caused it
> > to get much longer, and be truncated before anything useful is displayed.
> >
> > Instead, just check fail_data.report_found by hand (we've just test
> > report_expected to 'true'), and print a better failure message with
> > KUNIT_FAIL()
> >
> > Beforehand, a failure in:
> > KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
> > would looked like:
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
> > Signed-off-by: David Gow <davidgow@google.com>
> > ---
> >
> > Stumbled across this because the vmalloc_oob test is failing (i.e.,
> > KASAN isn't picking up an error) under qemu on my system, and the
> > message above was horrifying. (I'll file a Bugzilla bug for the test
> > failure today.)
> >
> > Cheers,
> > -- David
> >
> >  lib/test_kasan.c | 8 +++++---
> >  1 file changed, 5 insertions(+), 3 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index cacbbbdef768..deda13c9d9ff 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -98,9 +98,11 @@ static void kasan_test_exit(struct kunit *test)
> >         barrier();                                                      \
> >         expression;                                                     \
> >         barrier();                                                      \
> > -       KUNIT_EXPECT_EQ(test,                                           \
> > -                       READ_ONCE(fail_data.report_expected),           \
>
> What do we have fail_data.report_expected for? Could we remove it now?
> I think it's unused now.
>

I thought this was being used in kasan_update_kunit_status() (in
mm/kasan/report.c), but it looks like I was mistaken. We should be
able to get rid of it, then/

> > -                       READ_ONCE(fail_data.report_found));             \
> > +       if (READ_ONCE(fail_data.report_found) == false) {               \
>
> if (!READ_ONCE(fail_data.report_found)) {
> ?
>

I'll change this for v2.

> > +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "  \
> > +                               "expected in \"" #expression            \
> > +                                "\", but none occurred");              \
> > +       }                                                               \
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkEGWZx%3DCojx4d9%2BVdjFHNN4%3DHVmvcO7k6tZ_w5gcA0yg%40mail.gmail.com.
