Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB67Z4WNAMGQE3VXIYKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B9B0C60E773
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 20:31:24 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id k36-20020a05600c1ca400b003cf497cc5c2sf1450160wms.5
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 11:31:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666809084; cv=pass;
        d=google.com; s=arc-20160816;
        b=OKjaOg4TaNV3RtetAEsVsSUHoGPVfq5CFgT61z3ct0fPLPilUkZQcgNKxOPzfPRQei
         4jL7T7q9HKF8Yf0tSBU7rCWbiHGOdZlBqp2rq09d4IJQrjF98Yf2bGeC/BBBcYsi4Is+
         29X9ZEBhk7MBnQDXzHjRu9AhsDsZHpVY9HGnwM+5SRsJxTflPamXV2frpjRM2XC4BYSb
         GD7o5fsa6KTpBO6FILyTEvnwdRTydXGN+mLLzsa0Fa672ep8lGkouIOXsvu5KmejlSqZ
         IcmfPh1m8yCz86gmwOs7g7E9mx+q9MwMMAM1J61BeAVMphyieQQYPAFJyOhyMyn1bOnz
         OcUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YOTwlBihUSYd9Kk4aRT6Xmhb5yyCE9Wz3N75G/qvcfE=;
        b=eXzjBhuiTmTLcQB4VWYl8ecN6PZ43sC7mBYjRvLhgDjTvtKFB2t1+X5AZOj5ggQE9L
         ml7/dlQYtoyWgKjT2nGxIuq6qVYcd5BlmU6ieGxyt642ZJYlfLizgzyLXfP6rc1Ai/tB
         zd/zyD5blfcV//wt7y230Wu1PA7Gc13VNUNHPafOzDqvK7D8jhs2vgpjECeHztllux8h
         E49tjtFGoWBLL1GTit5Q3OKqPxEpf7ZOZmHmdfMINWLic+hVd6xV0Vg3H9e6GJuxfNjH
         2qqt0mduCVzIKduouSaX8BzaA8THdc/BxR8Hsb6ISILc3MYBNpEZE5dCmAXrVKZBdTFr
         1Jqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DA6R5PRs;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YOTwlBihUSYd9Kk4aRT6Xmhb5yyCE9Wz3N75G/qvcfE=;
        b=bHDbKrBkxbgw/9UszHf2XNFW4r6i2DE1BgGy6jDyzRKu+yf6coYoyY+jtOMWiU64yW
         y6L23v/9l0lHblj2dqanP+yQz+wwH5yKye3a10nnkSBzwYdASJ4pTBpJcJBHYCVWxOMW
         /OaR3C/v702suvOXZ5Vf3EUl2rVrxxteCNag67JtVvz54yl8wHajpc2krTuaZGRfVuak
         M5tBysE6pX2unId0GF9vb34G7WlyRzune304dgFweyUX6vM6Rn9R5/AVXHjK4DBc0+ma
         Bz0CY+HA5fPLgiLKm29oHMUQiN6fSJFgBw+g+VskPPwdhclOQoniIl9ZxS1mxdIXfEbR
         H0bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YOTwlBihUSYd9Kk4aRT6Xmhb5yyCE9Wz3N75G/qvcfE=;
        b=knANcX0JZhS8yLKQiYoLnFa0gKF9R6aFZ6ce8KKrV0Fop9hnpjsSufsqhELUDUOtu5
         sC/f5Q3+zDQkT+e1+caLb4QcrPvDuLXBB8OAPMrPK/H1HfGbdtK+XzfEO13G+KLIk4xc
         j4gnYOM40826fGQLCdeBiTAa+cl/4nwDJw0moLP4zsWl5QAAL7N7y4TaeP1nGXhauLzA
         KiHrdu7fjMygCKwklYNcX5tTlDRwKT0RmOylz75t+2vTuwW1vMoIVjzQ14RtUOGG6VpF
         T5mteSkZsF1edJE+f5e0oKHdLA/MaEdRvsp3rFCKPP2RsQd4JiEPItsl8jt8DgwKZuhH
         2Y8w==
X-Gm-Message-State: ACrzQf08UdiLB+h/Rq6yJv6qm+2IJHwZYIyh2A1YI2UxXLKdix/u7Oz2
	tzsfNeaA5yhmu6a00Dz3V+w=
X-Google-Smtp-Source: AMsMyM4/OrW+mW7bwbFL9a3XkLzT4F85Tkd2tNX25wV7KP+AN7vWCZ5s8v33mAUFJa03wHF89MwMIA==
X-Received: by 2002:adf:ff89:0:b0:236:67c3:2d72 with SMTP id j9-20020adfff89000000b0023667c32d72mr14674406wrr.0.1666809084029;
        Wed, 26 Oct 2022 11:31:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e4e:b0:3c5:a439:23df with SMTP id
 e14-20020a05600c4e4e00b003c5a43923dfls1354977wmq.0.-pod-canary-gmail; Wed, 26
 Oct 2022 11:31:23 -0700 (PDT)
X-Received: by 2002:a05:600c:3849:b0:3cf:4d99:fd1f with SMTP id s9-20020a05600c384900b003cf4d99fd1fmr2395192wmr.128.1666809082885;
        Wed, 26 Oct 2022 11:31:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666809082; cv=none;
        d=google.com; s=arc-20160816;
        b=tU6oHodMv81UqmHRxCbez3sYye5i0HEQAkfcHizofi6GQBOuABrZOYil14wRenUQIT
         lDBFOFwTe1j6ce56qbNvF8BR9p25WrZdxuMLF8FjksEYjA2VOJ5gzd8cHygGkn6f2ayi
         1OsFQs+irQWLNM1r+zu6NXiFgAJkW5AFNj7ZXCtfwMelQfFvD2BhHaG0cQlZEraGqCwi
         w9mRS1u5NZTOLgqnmnxj3QKTGkY1+llwedmp4XrU/yPVlp25UFKKG490x4AYtRRDBjz8
         A4TozcN06m5LSJs69e+RLmg1BBGHFkxuX8HN5m0AULdfBdQ1T6IV9/XC4zYBQCnmhIPS
         WG2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KGZ+b7AE38d+5UwfXCy0/gevM/R3+Wu+DeyQvG3oHGU=;
        b=ICk8zWJWkKy6hVmZm45FdBJgPw9gZvNTYdzdmUi7BWtTRgcY7JyfF2MSeLS5B1KIVi
         /V0LVgMMVXAj2865Qd6bIYSCnp3juJ5eoVVlK7KIuJt79pdPEJ/j2ftQh9BOuJH2j8lN
         JXBwaUCHvtdRKte+UFQMzsN0tNvyeFh++ZnYUtbBqBPJdQGnkOT3YwbxvKgaP2otIbld
         wpHwb4NgUeZDgs+uaJ2DNxhZyygJLHMWVJBmpuA9XIRZon2MSFkKDYCeeiqdSfsi9apO
         je9Vw1djhAmXxaLb4wbH2QAGcIpZt4mvUbQeJdNLB8/G0+wJCNBSvN3jdLk422aP97nl
         3zvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DA6R5PRs;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id p5-20020a05600c418500b003b56ce98812si305379wmh.3.2022.10.26.11.31.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Oct 2022 11:31:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id d3so16951426ljl.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Oct 2022 11:31:22 -0700 (PDT)
X-Received: by 2002:a2e:7303:0:b0:277:c7c:9c61 with SMTP id
 o3-20020a2e7303000000b002770c7c9c61mr6631853ljc.274.1666809082407; Wed, 26
 Oct 2022 11:31:22 -0700 (PDT)
MIME-Version: 1.0
References: <20221026141040.1609203-1-davidgow@google.com>
In-Reply-To: <20221026141040.1609203-1-davidgow@google.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Oct 2022 11:31:10 -0700
Message-ID: <CAGS_qxrd7kPzXexF_WvFX6YyVqdE_gf_7E7-XJhY2F0QAHPQ=w@mail.gmail.com>
Subject: Re: [PATCH] perf/hw_breakpoint: test: Skip the test if dependencies unmet
To: David Gow <davidgow@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DA6R5PRs;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::229
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, Oct 26, 2022 at 7:10 AM David Gow <davidgow@google.com> wrote:
>
> Running the test currently fails on non-SMP systems, despite being
> enabled by default. This means that running the test with:
>
>  ./tools/testing/kunit/kunit.py run --arch x86_64 hw_breakpoint
>
> results in every hw_breakpoint test failing with:
>
>  # test_one_cpu: failed to initialize: -22
>  not ok 1 - test_one_cpu
>
> Instead, use kunit_skip(), which will mark the test as skipped, and give
> a more comprehensible message:
>
>  ok 1 - test_one_cpu # SKIP not enough cpus
>
> This makes it more obvious that the test is not suited to the test
> environment, and so wasn't run, rather than having run and failed.
>
> Signed-off-by: David Gow <davidgow@google.com>

Reviewed-by: Daniel Latypov <dlatypov@google.com>

This patch makes this command pass for me.
$ ./tools/testing/kunit/kunit.py run --arch x86_64
Since this test gets picked up by default, having it pass for common
uses of kunit.py is a priority, IMO.

(Note: if I add --alltests as well, these were the only failures)

I agree with Marco that TAP/KTAP saying "ok" for skipped tests can be
confusing at first.
But a SKIP status feels more appropriate than FAIL, so I'd strongly
like for this change to go in.

> ---
>  kernel/events/hw_breakpoint_test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
> index 5ced822df788..c57610f52bb4 100644
> --- a/kernel/events/hw_breakpoint_test.c
> +++ b/kernel/events/hw_breakpoint_test.c
> @@ -295,11 +295,11 @@ static int test_init(struct kunit *test)
>  {
>         /* Most test cases want 2 distinct CPUs. */
>         if (num_online_cpus() < 2)
> -               return -EINVAL;
> +               kunit_skip(test, "not enough cpus");

The only minor nit I have is that I'd personally prefer something like
  kunit_skip(test, "need >=2 cpus");
since that makes it clearer
a) that we must only have 1 CPU by default
b) roughly how one might address this.

Note: b) is a bit more complicated than I would like. The final
command is something like
$ ./tools/testing/kunit/kunit.py run --arch x86_64 --qemu_args='-smp
2' --kconfig_add='CONFIG_SMP=y'

But that's orthogonal to this patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxrd7kPzXexF_WvFX6YyVqdE_gf_7E7-XJhY2F0QAHPQ%3Dw%40mail.gmail.com.
