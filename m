Return-Path: <kasan-dev+bncBDW2JDUY5AORBLGX5XCAMGQEA2QW6CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 00005B22D7B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 18:28:29 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-458b9ded499sf37746485e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 09:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755016109; cv=pass;
        d=google.com; s=arc-20240605;
        b=FvvyzVEB9lNmbGAXZQ+rWt20A7d0qCCSVMEg/h7rj3Pj6JJyNiOIwhEEIAmvioppX1
         KRQqvX3XKG0PZ9di7r/Tehr+EYJGPXSvkFRefZAupboVNpF+dAVBL+N4tA28jMUnXShE
         56xwxdNakqR2HQ8aEIycDQ5YyKNnA0fnZWjCurxzk1Gb4LT8mSCYx1dDdzBLU6qp6rss
         sqkwoPQx/1bJStE9vctovvWeRhW8A2cH1DylzoobrbkIVVtKTi6vu/fVcQ7NMJ6mUG9g
         S/0tT+/W1AEYxKJ4PZeMwGmdOO+B9HxTqg1v+OUHWhSCHOB+/a9wmWjCTNWZvEvzc5R7
         BUAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=IOZ/7D/m7SmXOnWCvbNqBKSL/jsaBTJ8Q8yp56Y+H2s=;
        fh=zM4uVSt1B3LZynZWtITcXxiEWJ37401JyfnneIYCYXo=;
        b=Wi+pLSFlS0m/Eod0YgixwzMjZdCEe3MFG3VvCnxBwZj7cYjDC8FeePsOGmfO8IzwSp
         2VescZ57KTJd6RZmNttHtwRch98AUA6gMpRx+3/JWJT9qW0rCaTiIWWPc68hFYFMr7DN
         hxVWOZgi3tYSdO8V0xAbAO0S19j7v2rSs8SgYL0SREnGslEWwLH+IjZC4Nym7Fe2nIfr
         jiFZpti45drWkp8R8dJmMv4G0vySjTDYIEGfTnyTN2fjZem3X6ZI90o2fXBFwPzeRHvX
         VmUI5IGW1fEtBVKKFlHswPyZGc4SFRhpHLy+h5KkthGruD+EKmlZEz6KXyCCmVLqMPuG
         Iijg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="UK/P/UPX";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755016109; x=1755620909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IOZ/7D/m7SmXOnWCvbNqBKSL/jsaBTJ8Q8yp56Y+H2s=;
        b=w0nxFhrfQ8nfP6tqThOD9I2oTpzO8FQTsDYP2Oye3rOJ7tJ+XT/rYprTmcDhe3UV2d
         XhfB8nA4kN9NO1TR+WyrD9DyZJo3WoXI6k5pmay+O+aMVNwnYNOEaYVACEDxbaC+V4fR
         qb2Ze089OxTZSKLzHGKKYWiWiTfCR+F2SJLVvgJ6CK6PH7LpUtexJ1JjDjxOZVzH90XN
         X6/f1LyEUEtIQqtSnySFzIHPbDGnuvY4RPL6tcAzPFC1I7rV/Twm0gRR9R5fR/2FsCNy
         wtr7U+C04NBVu3kSljD7/F/lhczjNphyCDyu6LG5Q15VVKEJDF/PuwsMUJNXNO4+Iwd3
         o+3w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755016109; x=1755620909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IOZ/7D/m7SmXOnWCvbNqBKSL/jsaBTJ8Q8yp56Y+H2s=;
        b=k4c/el//OtXDs3IZIsFpk5WysM1YgM/nBzAlH9+0gxrWrddrlSvlJUzEMANcr7x9F0
         HZn2sHh/Fxmij/PlxwfAiuHwxeF9Y/3WqH5gzNHrTSEavUNSx9uXGTzv13o3Fm5JG83G
         kHwWmZw+U6o7jbVhSgZNiKfw3yVCK2aiwzuJNRK4eDBrohYjpZmQW7s7D/Y3tDLzr+mS
         2Ea/P5/V/Wp3nhFcrCGEwwv9TWXI0sxLuNhrU/caC8hSN4VjJhNTBVQcUVgS9AyCQYXw
         OzviLCH7aXtOvPcyPelnfp05gCPbXaQa/EKMV3UzD+ySjX4vMmFcB5Y7/pZkUcD1eUNm
         Ivug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755016109; x=1755620909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IOZ/7D/m7SmXOnWCvbNqBKSL/jsaBTJ8Q8yp56Y+H2s=;
        b=FObmdRKiZxXna2z+YnSWaGSnHMUvSLOKq15++tHV+7uF7rrdOJmR0nh8VsilVtJ4KX
         xun7nCHrGKJ60C9X4GnDi6YzdJKV/1unuG6xHtX28TgcwhK+zZgnd3ItSoXXE8tEnxkn
         Vn6RW5X3DjLYTgqvAqOHLKhRziwJF5z7b2TptJFmoqPxrOnX7u/TKcHvSuEa9Km5unRB
         SlwnUKQbMQ6pg+SN4uOY/odVs37PKSXn8mMR5yaMKqWzBCZtImR1Z62LEAJ0x8z3zGzf
         jcX2Syaxc68z6LMelughxRYyjH9F2deQkCQVI3PhOOtISgjGUFiQl7RDKk3/Wsg96ekb
         6V3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoRGzX3Bi1jKKuwYVGAMtXisKiv7NOS4UVcVhBIxkUsCyXjHMdsbeX22npT7xNcwzsrhZvPA==@lfdr.de
X-Gm-Message-State: AOJu0YwAYxZZ2ezb/DmwybF5Aur5DHyZQLbtg+6wzGdSqROk0gTDkNhq
	AUUsGLgFP0Q/P/+3XIqL0MFfnuJ+UC+FSSFb1wBtb3zlh4MCOVIWyUmX
X-Google-Smtp-Source: AGHT+IGiE2DM2UgZ5yzQ2t6cUGCg/Iy7BtRfnQjzIkffAOh3jvG+Mx5n0EkFAZAa4BpPQq92AXlGWw==
X-Received: by 2002:a05:6000:2501:b0:3b8:d16a:a4a5 with SMTP id ffacd0b85a97d-3b91716f8b4mr121317f8f.0.1755016108835;
        Tue, 12 Aug 2025 09:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfqptS/OptqFR6mIyMeJmEQYe0o5RHjQo7G/mGm2Qn2ow==
Received: by 2002:a05:6000:18a9:b0:3b7:89fd:a285 with SMTP id
 ffacd0b85a97d-3b8f946939els2788709f8f.0.-pod-prod-02-eu; Tue, 12 Aug 2025
 09:28:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo6dL58ECj7W+BZa2UPHmsFsne8QC1/r5u0K8Oyo8T0JW3j1ABrfcKCD+r2tcF0WI2GaHrJh+4GB4=@googlegroups.com
X-Received: by 2002:a05:6000:2013:b0:3b7:735f:25c9 with SMTP id ffacd0b85a97d-3b917274fa8mr35527f8f.21.1755016105916;
        Tue, 12 Aug 2025 09:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755016105; cv=none;
        d=google.com; s=arc-20240605;
        b=a7yLbURychbBMB9EaCwu1IEf74EQQw6SXjqOiO7re6PNbzYCTmVkIApcmPC8hXkRPj
         I+HdATCSVGLMgMiZ+ePU2HxsWAH8FezzMq+kEcd2vBcjDs+F7FYQTjfh+jj/eBJhfRtt
         veJpBZEJqyW318XGp5wII5V31HNwSsaWXqzO4juxTxD/YmrNFFP47Fm10o2SD7R34D+h
         LeL7kusqZkLi0SI/SsIEiviRlH7qXiAzD0irt1VsjNBvAFL4tmVlJg13VfnGbvoDqqky
         rmWBqikAH+aXyEY+OL+yZYYzXkfSyE/HYFpNQpxhIz1WbKU6/jrp35CeaVK7giUfy4Ai
         Br8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1DEQJQSXLAUts9QuH9e8jbi6NmiQPvWx/N73fs3TVeM=;
        fh=8KsFuFw33UM/mUOn6Ra2XSb2wndV1BWr+kMEk8sc7z4=;
        b=lIBIfY0Nwm2hhcCBFduZkevwg0fm7NLJLIuKGp2j095lTU4IeyRH1Pj+X3Sa69TWEh
         p3gOQEh/TkusUptCwtA4MGYq7nzONwElg/SJWUAfG1N2rnSCheTWuH47QoTQgmUnqMmP
         eYv2H8AsLNoWlxEDqZUTmUsa7mpORVC+EXRh9iWEmu8fdQjUUyqiSjBbMjRUa6lK2uaw
         a8BKcj+ADgSnPQ2+nKTWMiR1X9XtFYDlrFlp9IOfX1b2xZwm9IRQ26JymFsu+7tPq3zh
         NDbU08fzjpWJZ8x+YWfaLVSexhEPIxo4v2J5jwDffvaGfgC0AKwOKYlZ4XOzXRWnuGqB
         VRDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="UK/P/UPX";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c339ca7si662844f8f.0.2025.08.12.09.28.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 09:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-459fdc391c6so28906275e9.3
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 09:28:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUnI0WByClmXf82RHQGAETzHAZChznB4wvlayxWmvmrMGg0sU9edy+P+xzJLRNGaL0m2LAUGQz41E=@googlegroups.com
X-Gm-Gg: ASbGncvcGx5FOnKiBp2fUm2AzOHMOJWERTpn2L/2XkGTBX7qkc517NnidkCVhxfOL8B
	EIYeseRw0Knp6lVwOSEjEVDfB7DXersTX58W0q1gPZaZAf8jRDjH8kXd/4WwnK9/qtNr6zv1sou
	iS/oBp57F8FIIAF9cMa+3t5pX1TjCcITkHcBx3Xe4YbfBsuYivl99mSD22Ee/6f/NClneaa1ZPY
	WwwIhjHjg==
X-Received: by 2002:a05:600c:4585:b0:458:b01c:8f with SMTP id
 5b1f17b1804b1-45a15b1f996mr4788815e9.8.1755016104985; Tue, 12 Aug 2025
 09:28:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250811173626.1878783-1-yeoreum.yun@arm.com> <20250811173626.1878783-3-yeoreum.yun@arm.com>
In-Reply-To: <20250811173626.1878783-3-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Aug 2025 18:28:12 +0200
X-Gm-Features: Ac12FXwkg1JQz-u0IFfkfNxUBQy7VDQUXrQz_SW_sB6Boita2CZHjuZOWhhTDCM
Message-ID: <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: apply store-only mode in kasan kunit testcases
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com, 
	will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com, 
	jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org, 
	kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org, 
	oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org, 
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com, 
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="UK/P/UPX";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 11, 2025 at 7:36=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> When KASAN is configured in store-only mode,
> fetch/load operations do not trigger tag check faults.
> As a result, the outcome of some test cases may differ
> compared to when KASAN is configured without store-only mode.
>
> To address this:
>   1. Replace fetch/load expressions that would
>      normally trigger tag check faults with store operation
>      when running under store-only and sync mode.
>      In case of async/asymm mode, skip the store operation triggering
>      tag check fault since it corrupts memory.
>
>   2. Skip some testcases affected by initial value
>      (i.e) atomic_cmpxchg() testcase maybe successd if
>      it passes valid atomic_t address and invalid oldaval address.
>      In this case, if invalid atomic_t doesn't have the same oldval,
>      it won't trigger store operation so the test will pass.
>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>  mm/kasan/kasan_test_c.c | 423 ++++++++++++++++++++++++++++++++--------
>  1 file changed, 341 insertions(+), 82 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 2aa12dfa427a..22d5d6d6cd9f 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -94,11 +94,13 @@ static void kasan_test_exit(struct kunit *test)
>  }
>
>  /**
> - * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces=
 a
> - * KASAN report; causes a KUnit test failure otherwise.
> + * _KUNIT_EXPECT_KASAN_TEMPLATE - check that the executed expression pro=
duces
> + * a KASAN report or not; a KUnit test failure when it's different from =
@produce.
>   *
>   * @test: Currently executing KUnit test.
> - * @expression: Expression that must produce a KASAN report.
> + * @expr: Expression produce a KASAN report or not.
> + * @expr_str: Expression string
> + * @produce: expression should produce a KASAN report.
>   *
>   * For hardware tag-based KASAN, when a synchronous tag fault happens, t=
ag
>   * checking is auto-disabled. When this happens, this test handler reena=
bles
> @@ -110,25 +112,29 @@ static void kasan_test_exit(struct kunit *test)
>   * Use READ/WRITE_ONCE() for the accesses and compiler barriers around t=
he
>   * expression to prevent that.
>   *
> - * In between KUNIT_EXPECT_KASAN_FAIL checks, test_status.report_found i=
s kept
> + * In between _KUNIT_EXPECT_KASAN_TEMPLATE checks, test_status.report_fo=
und is kept
>   * as false. This allows detecting KASAN reports that happen outside of =
the
>   * checks by asserting !test_status.report_found at the start of
> - * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
> + * _KUNIT_EXPECT_KASAN_TEMPLATE and in kasan_test_exit.
>   */
> -#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {                 \
> +#define _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, expr_str, produce)    \
> +do {                                                                   \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
>             kasan_sync_fault_possible())                                \
>                 migrate_disable();                                      \
>         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
>         barrier();                                                      \
> -       expression;                                                     \
> +       expr;                                                           \
>         barrier();                                                      \
>         if (kasan_async_fault_possible())                               \
>                 kasan_force_async_fault();                              \
> -       if (!READ_ONCE(test_status.report_found)) {                     \
> -               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "  \
> -                               "expected in \"" #expression            \
> -                                "\", but none occurred");              \
> +       if (READ_ONCE(test_status.report_found) !=3D produce) {          =
 \
> +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN %s "       \
> +                               "expected in \"" expr_str               \
> +                                "\", but %soccurred",                  \
> +                               (produce ? "failure" : "success"),      \
> +                               (test_status.report_found ?             \
> +                                "" : "none "));                        \
>         }                                                               \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
>             kasan_sync_fault_possible()) {                              \
> @@ -141,6 +147,26 @@ static void kasan_test_exit(struct kunit *test)
>         WRITE_ONCE(test_status.async_fault, false);                     \
>  } while (0)
>
> +/*
> + * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces=
 a
> + * KASAN report; causes a KUnit test failure otherwise.
> + *
> + * @test: Currently executing KUnit test.
> + * @expr: Expression produce a KASAN report.
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, expr)                    \
> +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, true)
> +
> +/*
> + * KUNIT_EXPECT_KASAN_SUCCESS - check that the executed expression doesn=
't
> + * produces a KASAN report; causes a KUnit test failure otherwise.
> + *
> + * @test: Currently executing KUnit test.
> + * @expr: Expression doesn't produce a KASAN report.
> + */
> +#define KUNIT_EXPECT_KASAN_SUCCESS(test, expr)                 \
> +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, false)
> +
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
>         if (!IS_ENABLED(config))                                        \
>                 kunit_skip((test), "Test requires " #config "=3Dy");     =
 \
> @@ -183,8 +209,15 @@ static void kmalloc_oob_right(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] =3D 'y');
>
>         /* Out-of-bounds access past the aligned kmalloc object. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D
> -                                       ptr[size + KASAN_GRANULE_SIZE + 5=
]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] =3D
> +                                               ptr[size + KASAN_GRANULE_=
SIZE + 5]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test,
> +                                       ptr[size + KASAN_GRANULE_SIZE + 5=
] =3D ptr[0]);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D
> +                                               ptr[size + KASAN_GRANULE_=
SIZE + 5]);
>
>         kfree(ptr);
>  }
> @@ -198,7 +231,13 @@ static void kmalloc_oob_left(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr =3D *(ptr - 1));
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, *ptr =3D *(ptr - 1));
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, *(ptr - 1) =3D *(pt=
r));
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, *ptr =3D *(ptr - 1));
> +
>         kfree(ptr);
>  }
>
> @@ -211,7 +250,13 @@ static void kmalloc_node_oob_right(struct kunit *tes=
t)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] =3D ptr[size]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D ptr[0=
]);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +
>         kfree(ptr);
>  }
>
> @@ -291,7 +336,12 @@ static void kmalloc_large_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         kfree(ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0=
]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[0] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void kmalloc_large_invalid_free(struct kunit *test)
> @@ -323,7 +373,13 @@ static void page_alloc_oob_right(struct kunit *test)
>         ptr =3D page_address(pages);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] =3D ptr[size]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D ptr[0=
]);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +
>         free_pages((unsigned long)ptr, order);
>  }
>
> @@ -338,7 +394,12 @@ static void page_alloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         free_pages((unsigned long)ptr, order);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0=
]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[0] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void krealloc_more_oob_helper(struct kunit *test,
> @@ -455,10 +516,15 @@ static void krealloc_uaf(struct kunit *test)
>         ptr1 =3D kmalloc(size1, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>         kfree(ptr1);
> -
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr2 =3D krealloc(ptr1, size2, GFP_=
KERNEL));
>         KUNIT_ASSERT_NULL(test, ptr2);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> +
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, *(volatile char *)ptr1);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p=
tr1 =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
>  }
>
>  static void kmalloc_oob_16(struct kunit *test)
> @@ -501,7 +567,13 @@ static void kmalloc_uaf_16(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>         kfree(ptr2);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 =3D *ptr2);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, *ptr1 =3D *ptr2);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, *ptr2 =3D *ptr1);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 =3D *ptr2);
> +
>         kfree(ptr1);
>  }
>
> @@ -640,8 +712,17 @@ static void kmalloc_memmove_invalid_size(struct kuni=
t *test)
>         memset((char *)ptr, 0, 64);
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(invalid_size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> +
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       memmove((char *)ptr, (char *)ptr + 4, invalid_siz=
e));
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test,
> +                               memmove((char *)ptr + 4, (char *)ptr, inv=
alid_size));
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       memmove((char *)ptr, (char *)ptr + 4, invalid_siz=
e));
> +
>         kfree(ptr);
>  }
>
> @@ -654,7 +735,13 @@ static void kmalloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         kfree(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
> +
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[8=
]);
> +               if (!kasan_sync_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[8] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
>  }
>
>  static void kmalloc_uaf_memset(struct kunit *test)
> @@ -701,7 +788,13 @@ static void kmalloc_uaf2(struct kunit *test)
>                 goto again;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr1)[=
40]);
> +               if (!kasan_sync_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr1)[40] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]=
);
> +
>         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>
>         kfree(ptr2);
> @@ -727,19 +820,35 @@ static void kmalloc_uaf3(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>         kfree(ptr2);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr1)[=
8]);
> +               if (!kasan_sync_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr1)[8] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8])=
;
>  }
>
>  static void kasan_atomics_helper(struct kunit *test, void *unsafe, void =
*safe)
>  {
>         int *i_unsafe =3D unsafe;
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, READ_ONCE(*i_unsafe));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, smp_load_acquire(i_unsaf=
e));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe))=
;
>         KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, atomic_read(unsafe));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> @@ -752,18 +861,38 @@ static void kasan_atomics_helper(struct kunit *test=
, void *unsafe, void *safe)
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42=
));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42=
));
> +
> +       /*
> +        * The result of the test below may vary due to garbage values of=
 unsafe in
> +        * store-only mode. Therefore, skip this test when KASAN is confi=
gured
> +        * in store-only mode.
> +        */
> +       if (!kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, un=
safe, 42));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe))=
;
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe))=
;
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +       /*
> +        * The result of the test below may vary due to garbage values of=
 unsafe in
> +        * store-only mode. Therefore, skip this test when KASAN is confi=
gured
> +        * in store-only mode.
> +        */
> +       if (!kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 2=
1, 42));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe)=
);
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(=
unsafe));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(=
unsafe));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsa=
fe));
> +       }
> +
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, atomic_long_read(unsafe)=
);
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> @@ -776,16 +905,32 @@ static void kasan_atomics_helper(struct kunit *test=
, void *unsafe, void *safe)
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42)=
);
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, saf=
e, 42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsaf=
e, 42));
> +
> +       /*
> +        * The result of the test below may vary due to garbage values in
> +        * store-only mode. Therefore, skip this test when KASAN is confi=
gured
> +        * in store-only mode.
> +        */
> +       if (!kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(saf=
e, unsafe, 42));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe=
));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe=
));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, =
42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(uns=
afe));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(uns=
afe));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe)=
);
> +
> +       /*
> +        * The result of the test below may vary due to garbage values in
> +        * store-only mode. Therefore, skip this test when KASAN is confi=
gured
> +        * in store-only mode.
> +        */
> +       if (!kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsa=
fe, 21, 42));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(un=
safe));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_nega=
tive(unsafe));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_posi=
tive(unsafe));
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive=
(unsafe));
> +       }
>  }
>
>  static void kasan_atomics(struct kunit *test)
> @@ -842,8 +987,18 @@ static void ksize_unpoisons_memory(struct kunit *tes=
t)
>         /* These must trigger a KASAN report. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size=
]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - =
1]);
> +
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[s=
ize + 5]);
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[r=
eal_size - 1]);
> +               if (!kasan_sync_fault_possible()) {
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[size + 5] =3D 0);
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[real_size - 1] =3D 0);
> +               }
> +       } else {
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size=
 + 5]);
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real=
_size - 1]);
> +       }
>
>         kfree(ptr);
>  }
> @@ -863,8 +1018,17 @@ static void ksize_uaf(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0=
]);
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[s=
ize]);
> +               if (!kasan_sync_fault_possible()) {
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[0] =3D 0);
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[size] =3D 0);
> +               }
> +       } else {
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size=
]);
> +       }
>  }
>
>  /*
> @@ -886,7 +1050,11 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
>                 container_of(rp, struct kasan_rcu_info, rcu);
>
>         kfree(fp);
> -       ((volatile struct kasan_rcu_info *)fp)->i;
> +
> +       if (kasan_stonly_enabled() && !kasan_async_fault_possible())
> +               ((volatile struct kasan_rcu_info *)fp)->i =3D 0;
> +       else
> +               ((volatile struct kasan_rcu_info *)fp)->i;
>  }
>
>  static void rcu_uaf(struct kunit *test)
> @@ -899,9 +1067,14 @@ static void rcu_uaf(struct kunit *test)
>         global_rcu_ptr =3D rcu_dereference_protected(
>                                 (struct kasan_rcu_info __rcu *)ptr, NULL)=
;
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> -               rcu_barrier());
> +       if (kasan_stonly_enabled() && kasan_async_fault_possible())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> +                       rcu_barrier());
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> +                       rcu_barrier());
>  }
>
>  static void workqueue_uaf_work(struct work_struct *work)
> @@ -924,8 +1097,12 @@ static void workqueue_uaf(struct kunit *test)
>         queue_work(workqueue, work);
>         destroy_workqueue(workqueue);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               ((volatile struct work_struct *)work)->data);
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       ((volatile struct work_struct *)work)->data);
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       ((volatile struct work_struct *)work)->data);
>  }
>
>  static void kfree_via_page(struct kunit *test)
> @@ -972,7 +1149,12 @@ static void kmem_cache_oob(struct kunit *test)
>                 return;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, *p =3D p[size + OOB_TAG_OFF]);
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, *p =3D p[size + OOB_TAG_=
OFF]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, p[size + OOB_TAG_OF=
F] =3D *p);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, *p =3D p[size + OOB_TAG_OFF=
]);
>
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
> @@ -1068,7 +1250,12 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
>          */
>         rcu_barrier();
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, READ_ONCE(*p));
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*p, 0));
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
>
>         kmem_cache_destroy(cache);
>  }
> @@ -1206,7 +1393,13 @@ static void mempool_oob_right_helper(struct kunit =
*test, mempool_t *pool, size_t
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 KUNIT_EXPECT_KASAN_FAIL(test,
>                         ((volatile char *)&elem[size])[0]);
> -       else
> +       else if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       ((volatile char *)&elem[round_up(size, KASAN_GRAN=
ULE_SIZE)])[0]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test,
> +                               ((volatile char *)&elem[round_up(size, KA=
SAN_GRANULE_SIZE)])[0] =3D 0);
> +       } else
>                 KUNIT_EXPECT_KASAN_FAIL(test,
>                         ((volatile char *)&elem[round_up(size, KASAN_GRAN=
ULE_SIZE)])[0]);
>
> @@ -1273,7 +1466,13 @@ static void mempool_uaf_helper(struct kunit *test,=
 mempool_t *pool, bool page)
>         mempool_free(elem, pool);
>
>         ptr =3D page ? page_address((struct page *)elem) : elem;
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0=
]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)p=
tr)[0] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void mempool_kmalloc_uaf(struct kunit *test)
> @@ -1532,8 +1731,13 @@ static void kasan_memchr(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               kasan_ptr_result =3D memchr(ptr, '1', size + 1));
> +
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       kasan_ptr_result =3D memchr(ptr, '1', size + 1));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       kasan_ptr_result =3D memchr(ptr, '1', size + 1));
>
>         kfree(ptr);
>  }
> @@ -1559,8 +1763,14 @@ static void kasan_memcmp(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               kasan_int_result =3D memcmp(ptr, arr, size+1));
> +
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       kasan_int_result =3D memcmp(ptr, arr, size+1));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       kasan_int_result =3D memcmp(ptr, arr, size+1));
> +
>         kfree(ptr);
>  }
>
> @@ -1593,9 +1803,16 @@ static void kasan_strings(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, KASAN_GRANULE_SIZE - 2,
>                         strscpy(ptr, src + 1, KASAN_GRANULE_SIZE));
>
> -       /* strscpy should fail if the first byte is unreadable. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SI=
ZE,
> -                                             KASAN_GRANULE_SIZE));
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, strscpy(ptr, src + KASAN=
_GRANULE_SIZE,
> +                                                     KASAN_GRANULE_SIZE)=
);
> +               if (!kasan_async_fault_possible())
> +                       /* strscpy should fail when the first byte is to =
be written. */
> +                       KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr + size,=
 src, KASAN_GRANULE_SIZE));
> +       } else
> +               /* strscpy should fail if the first byte is unreadable. *=
/
> +               KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GR=
ANULE_SIZE,
> +                                                     KASAN_GRANULE_SIZE)=
);
>
>         kfree(src);
>         kfree(ptr);
> @@ -1607,17 +1824,22 @@ static void kasan_strings(struct kunit *test)
>          * will likely point to zeroed byte.
>          */
>         ptr +=3D 16;
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result =3D strchr(ptr, '1=
'));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result =3D strrchr(ptr, '=
1'));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strcmp(ptr, "2=
"));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strncmp(ptr, "=
2", 1));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strlen(ptr));
> -
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strnlen(ptr, 1=
));
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_ptr_result =3D str=
chr(ptr, '1'));
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_ptr_result =3D str=
rchr(ptr, '1'));
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result =3D str=
cmp(ptr, "2"));
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result =3D str=
ncmp(ptr, "2", 1));
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result =3D str=
len(ptr));
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result =3D str=
nlen(ptr, 1));
> +       } else {
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result =3D strchr=
(ptr, '1'));
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result =3D strrch=
r(ptr, '1'));
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strcmp=
(ptr, "2"));
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strncm=
p(ptr, "2", 1));
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strlen=
(ptr));
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strnle=
n(ptr, 1));
> +       }
>  }
>
>  static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
> @@ -1636,12 +1858,27 @@ static void kasan_bitops_test_and_modify(struct k=
unit *test, int nr, void *addr)
>  {
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> +
> +       /*
> +        * When KASAN is running in store-only mode,
> +        * a fault won't occur even if the bit is set.
> +        * Therefore, skip the test_and_set_bit_lock test in store-only m=
ode.
> +        */
> +       if (!kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, a=
ddr));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D test_bit(nr, a=
ddr));
> +
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result =3D tes=
t_bit(nr, addr));
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, set_bit(nr, addr));
> +  } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D test_b=
it(nr, addr));
> +
>         if (nr < 7)
>                 KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D
>                                 xor_unlock_is_negative_byte(1 << nr, addr=
));
> @@ -1765,7 +2002,12 @@ static void vmalloc_oob(struct kunit *test)
>                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[si=
ze]);
>
>         /* An aligned access into the first out-of-bounds granule. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5])=
;
> +       if (kasan_stonly_enabled()) {
> +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)v_ptr)=
[size + 5]);
> +               if (!kasan_async_fault_possible())
> +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v=
_ptr)[size + 5] =3D 0);
> +       } else
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[si=
ze + 5]);
>
>         /* Check that in-bounds accesses to the physical page are valid. =
*/
>         page =3D vmalloc_to_page(v_ptr);
> @@ -2042,16 +2284,33 @@ static void copy_user_test_oob(struct kunit *test=
)
>
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D copy_from_user(kmem, usermem, size + 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               unused =3D copy_to_user(usermem, kmem, size + 1));
> +
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       unused =3D copy_to_user(usermem, kmem, size + 1))=
;
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       unused =3D copy_to_user(usermem, kmem, size + 1))=
;
> +
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D __copy_from_user(kmem, usermem, size + 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               unused =3D __copy_to_user(usermem, kmem, size + 1));
> +
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       unused =3D __copy_to_user(usermem, kmem, size + 1=
));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       unused =3D __copy_to_user(usermem, kmem, size + 1=
));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D __copy_from_user_inatomic(kmem, usermem, size =
+ 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               unused =3D __copy_to_user_inatomic(usermem, kmem, size + =
1));
> +
> +       if (kasan_stonly_enabled())
> +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> +                       unused =3D __copy_to_user_inatomic(usermem, kmem,=
 size + 1));
> +       else
> +               KUNIT_EXPECT_KASAN_FAIL(test,
> +                       unused =3D __copy_to_user_inatomic(usermem, kmem,=
 size + 1));
>
>         /*
>         * Prepare a long string in usermem to avoid the strncpy_from_user=
 test
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

This patch does not look good.

Right now, KASAN tests are crafted to avoid/self-contain harmful
memory corruptions that they do (e.g. make sure that OOB write
accesses land in in-object kmalloc training space, etc.). If you turn
read accesses in tests into write accesses, memory corruptions caused
by the earlier tests will crash the kernel or the latter tests.

The easiest thing to do for now is to disable the tests that check bad
read accesses when store-only is enabled.

If we want to convert tests into doing write accesses instead of
reads, this needs to be done separately for each test (i.e. via a
separate patch) with an explanation why doing this is safe (and
adjustments whenever it's not). And we need a better way to code this
instead of the horrifying number of if/else checks.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7%3DNXQ%40mail.gmail.com.
