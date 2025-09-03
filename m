Return-Path: <kasan-dev+bncBDW2JDUY5AORB3PS4DCQMGQEICBSPGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CADAB41FB9
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 14:49:51 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3df3e935ec8sf285681f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 05:49:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756903791; cv=pass;
        d=google.com; s=arc-20240605;
        b=P1ZXxABG9ADcgjBevfPuxut7MdUcNfMxDSJh/YRAuXqqASEtwHZVkkqZ86z+Ce6I0p
         5QpgaLJkDKgsLrQPdf/4eFMwowxWbWBhsCX8SrK0jLEBMXk+clBkWwVnJouPwppQGwtP
         TQzoMlVP7nrzCGGTIeduLXT47nRKuaWhKbIiXV9aJdCtJsJP9JJ+0r+XokbCoiodRE/s
         ZUiNn5+9pnKp9g5my6u5T7G0tqx0LrYSEr8Ncma5jQIjnxrRMRgivKRYNeZG/Vx3/9xM
         HwuP5JLbeBNimnGL4Uw7ody/IPwbrdfIliZq9Psnlal2OiHmDESYggjqkODJYdd2lHVd
         17yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JZJhnUYgmXdE2tukiagj8McqUT5247ANaxKuGgVDPo4=;
        fh=Oq36AozXHLEiJQg4QPg8ry40M6bY3zhE6Yy6ob3Dk/Q=;
        b=ikbZkwYp8CHYCGt/6fBg76tn2e3fNulaSEXmfSs/se3PTgiEfGxBAddQnfrAsZourd
         7op/K0hGxZRLpiQX5SVVNL8I+ZracYFQ9TGeSIZ78+Y1hoJpRowmrKnxQAs1UfA9RBLz
         1badbPe2xoKmpFhZNRNO2PaVzKYRT5RqZ1ti3QXpiomGRIg4qS3eAGgOhirgkzDswsQ4
         4H0rhZTTSTWhkhGfHAotEAnFhwpjqzPFI7rk9jZcSK8eCPic75tqGWOTb6q03QqxJuw6
         wnJqja3BI6vcggrI9SG4o9SBzuGVNu3J/cstgY802DxFHhrOP5hA+mKWuj7tkeTvfkt8
         F3PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d6LTDMP5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756903791; x=1757508591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JZJhnUYgmXdE2tukiagj8McqUT5247ANaxKuGgVDPo4=;
        b=YWCecPbuy+ENofb0A86T+bYuZCw5N3Fx0ZV7zuoTUWoBbGuqogqsyq4L/oNC+JyWA9
         eqDsJB52VyxE84YBdvmINt+hRlutL8Lmc1bsHcG/d8PRPqnsEXczybC9Vm3XD/iZfd3d
         QjAP5WbAQ7yle98wFfEuFRsaE+nGlbXG9ykk1c4ZzyzlupeFr3+/okqP4Qlnkbc5Fv6c
         6WO1dhm8j5IB41N8Qc0c7yhHTZYwPaECWxjAiumlLQUFqSsU7kacaYzFoKhpVk3XsN7y
         pSwlS+dvz23xp/8YcCfbaOAZunKpdjrsOCgPxg7LBX77GPhNRsJ/xvVt62usqWasOdAP
         VTkg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756903791; x=1757508591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JZJhnUYgmXdE2tukiagj8McqUT5247ANaxKuGgVDPo4=;
        b=nFY7XxHO/nf21TYJSXMYJONAwK1bxoP0IGKiD0JFV6SPwabZJsr+4oYTiwwC+QXd+4
         b32mbA6rDUi1izYf/aLInAXRs3VyPPa9Vturix8jRqEgKMTw74kkSvj9J9mYNvL54q5l
         YyhXOpR57mFSIXCQLfnf1NcFfWpqN7zB92KEZuhRIdIAl59sa3cWy/czCOWwUuutmgrI
         lGEq9RAroywUZGgKG8eGZ1VFYPF8Jy5LmSBixYCZ3d2PczUiie/nM3qJ66cUOixVId9L
         adZlzaNtT2jbmW8brdhwPoiTovjqh3LUYNZnIxymo1V6Ta9jLD/IRa5OKkkKd3Kqo/8U
         Wggw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756903791; x=1757508591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JZJhnUYgmXdE2tukiagj8McqUT5247ANaxKuGgVDPo4=;
        b=M5HtiPzmzVeXCTO5hDqZsHajqAS8G11MexNA04kpLKjmE2d7RBukAluiVl73UOZayt
         /3kp82GmVggb1myfiaZ44+Xkgxjiy6n/W+5Ym/VT2JKct8U8InZMH1X1nWlPV956mG9U
         7ulx1aKGH8MYVg+sVkqH/d/Ga8IRkMySz4CtmEARisz80WsBxffSm/qHIvcMtq6VG0B2
         KNKhWUPHeXSkfaNBL7iqISZ6WHcHelI8FmTS9ZNCzsqWeUvsjfbuafXQcvaAcCk5bGRo
         wBerAaxMr2J51IF+kgbt3WE1rjb3lUlZPYdiCCVdCj5JrirKQIz8yP5id7g8OVEJDDHL
         8xAw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmexspgPzgC0PsTxnrQW5r4Upe4QK+M7E00drczLRgTOPb6/7Nr+yAA4rxlsdd253/cAYG2g==@lfdr.de
X-Gm-Message-State: AOJu0Yz8Axfteq//Zc5d/4hjqGUKL7137PFU3ZVmTd/DSaJp6QQjgGqo
	E4CSYMhzD1e7NTSp80YE8cxnVcqypHRRIoEp9qOrC6drtyGmnx/7WoIQ
X-Google-Smtp-Source: AGHT+IESuI9aspUvximvWai56LSLRZLTx908z+zsdbVl7IderdsqwKENvu/fe4gYNWGDo3deTDhiSA==
X-Received: by 2002:a05:6000:26cb:b0:3ce:f0a5:d581 with SMTP id ffacd0b85a97d-3d1dd81d1cfmr11130289f8f.7.1756903790568;
        Wed, 03 Sep 2025 05:49:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe7O5aqVZA8bct6k0bHHFGM6NIbCzwczx93Knjn/3Vldw==
Received: by 2002:a05:600c:1993:b0:456:241d:50c3 with SMTP id
 5b1f17b1804b1-45b78cabfbals34096185e9.1.-pod-prod-08-eu; Wed, 03 Sep 2025
 05:49:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDOI7l+yw7/jdkihaFOg0ZSU0EIqbeDS80JUD6iPr0aL+pk3ymVqI4GIyXSE4h0TGMSeavuCpQS+0=@googlegroups.com
X-Received: by 2002:a05:600c:3b10:b0:45b:8f38:8d36 with SMTP id 5b1f17b1804b1-45b8f388f6bmr91366945e9.30.1756903787220;
        Wed, 03 Sep 2025 05:49:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756903787; cv=none;
        d=google.com; s=arc-20240605;
        b=XkjMTTNO5wv0v5BBwVRnETPQCoub8CqC0S30GVbdDfM6dsDpkE7t6DtDHQDgnodQ6/
         zvvnwaTHa+coBPRLD3pugzb4/92IW+AIVY+QOG60EJBMMHd1wnSyo+2vYcHDEjA+OoG1
         PzzdHva6MOcr8sGwCX6NypoOoFXzrSr3zLvmDNsVIwb0IjoIcRnqOYtOxnLpOOjfJFt/
         qV8LNmgMsHIk3J1AvroHTJyDftZ0265dRXmpmzawt+NHYrGvdiVXGfbJjjTfsqtXFrae
         yvCB6wOGF1XqXTd6qQJr9D0ex/Mcu4o3He9GE7OnKv0YgisH2GmKY8eFbGWZFvYd2xD6
         Z9pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qioTky0DA20wU3b9bBxL/z2sHC6Vqg3Be64wxGFGkZs=;
        fh=FYS6u/FgtZnBtJ8RlT+DzOv9DwoAPtZyZAIEnCl+Dv0=;
        b=TYZpcbeO/mpATGD4nnRdTShGeRdvpdP/Tue+mwUYpKm+VQ3/kAVRSi7LvjyDV/vIQp
         9h8xHw/qFzSiPC4NHtjXqWQDBFki67QgtckfIErpkGXKUA/1cEw/EEoDZptbfNyZ51pQ
         1R5WFCvCnrIePBQuTQrAU5MKuaq8yXbKLfjLb4fePWp3N17vXSI0ltL3M+vj+BMymgeC
         g4nReMPR8hhvFY6w0FoRaREdU18RoVtLGRDYSalZVYk+Cz6FTsUawlCRQguep1bUXH0h
         ZB+ps8EDUeM233Rw6auffJMPM4RrkFzTwFBjLpQmVD7X21IoZlqH1DM3EuWczokEwYaD
         WMEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d6LTDMP5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b883aa486si2042665e9.1.2025.09.03.05.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 05:49:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3df2f4aedc7so370351f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 05:49:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVv9XQhfOqnjFq+pM2Cg7FcCemYH24zogZhk3dZSmN0RzcY7gsLieTmA3ov9ig4uBp5L6UMEUnkkzA=@googlegroups.com
X-Gm-Gg: ASbGnctKBf+GqGy4EnxuthW8LjhChHQYWztv8Fgj8VEASta90ETnl+1gQ1OCOJhNuiM
	rCiQnNBi9wLBAlSabPA0yEYO3+Z9AFfPUMW85jF9Yl2ar9Klks+WiP5UDuhzOTu7Sgr2Yx916Vy
	Iwwcaayg3j6zcYNydCSpbZT2dVFvSDwj5LBkSfbC4kMo8RlwEdkFFIU2extxM1qJJ068rmuLMo3
	iTdL3Kx
X-Received: by 2002:a05:6000:2890:b0:3de:c5b3:dda2 with SMTP id
 ffacd0b85a97d-3dec5b3e033mr1667450f8f.34.1756903786262; Wed, 03 Sep 2025
 05:49:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250901104623.402172-1-yeoreum.yun@arm.com> <20250901104623.402172-3-yeoreum.yun@arm.com>
In-Reply-To: <20250901104623.402172-3-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 3 Sep 2025 14:49:34 +0200
X-Gm-Features: Ac12FXyu_2MW1p9hqzVMXrUjzZRBuRkpC_vIzVYx2h5zKsSvlwoHHiBIosQjurc
Message-ID: <CA+fCnZeyKuet2XY9=jOdiK4Z6f4_=Xb5ZBzBaDL-2gFPv9yJ5A@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] kasan: apply write-only mode in kasan kunit testcases
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
 header.i=@gmail.com header.s=20230601 header.b=d6LTDMP5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Mon, Sep 1, 2025 at 12:46=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> When KASAN is configured in write-only mode,
> fetch/load operations do not trigger tag check faults.
>
> As a result, the outcome of some test cases may differ
> compared to when KASAN is configured without write-only mode.
>
> Therefore, by modifying pre-exist testcases
> check the write only makes tag check fault (TCF) where
> writing is perform in "allocated memory" but tag is invalid
> (i.e) redzone write in atomic_set() testcases.
> Otherwise check the invalid fetch/read doesn't generate TCF.
>
> Also, skip some testcases affected by initial value
> (i.e) atomic_cmpxchg() testcase maybe successd if
> it passes valid atomic_t address and invalid oldaval address.
> In this case, if invalid atomic_t doesn't have the same oldval,
> it won't trigger write operation so the test will pass.
>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>  mm/kasan/kasan_test_c.c | 204 ++++++++++++++++++++++++++--------------
>  1 file changed, 135 insertions(+), 69 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index e0968acc03aa..8b3bb33603e1 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -94,11 +94,13 @@ static void kasan_test_exit(struct kunit *test)
>  }
>
>  /**
> - * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces=
 a
> - * KASAN report; causes a KUnit test failure otherwise.
> + * KUNIT_EXPECT_KASAN_RESULT - check that the executed expression
> + * causes a KUnit test failure when the result is different from @fail.

What I meant here was:

KUNIT_EXPECT_KASAN_RESULT - checks whether the executed expression
produces a KASAN report; causes a KUnit test failure when the result
is different from @fail.

>   *
>   * @test: Currently executing KUnit test.
> - * @expression: Expression that must produce a KASAN report.
> + * @expr: Expression to be tested.
> + * @expr_str: Expression to be tested encoded as a string.
> + * @fail: Whether expression should produce a KASAN report.
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
> + * In between KUNIT_EXPECT_KASAN_RESULT checks, test_status.report_found=
 is kept
>   * as false. This allows detecting KASAN reports that happen outside of =
the
>   * checks by asserting !test_status.report_found at the start of
> - * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
> + * KUNIT_EXPECT_KASAN_RESULT and in kasan_test_exit.
>   */
> -#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {                 \
> +#define KUNIT_EXPECT_KASAN_RESULT(test, expr, expr_str, fail)          \
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
> +       if (READ_ONCE(test_status.report_found) !=3D fail) {             =
 \
> +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure"   \
> +                               "%sexpected in \"" expr_str             \
> +                                "\", but %soccurred",                  \
> +                               (fail ? " " : " not "),         \
> +                               (test_status.report_found ?             \
> +                                "" : "none "));                        \
>         }                                                               \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
>             kasan_sync_fault_possible()) {                              \
> @@ -141,6 +147,34 @@ static void kasan_test_exit(struct kunit *test)
>         WRITE_ONCE(test_status.async_fault, false);                     \
>  } while (0)
>
> +/*
> + * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces=
 a
> + * KASAN report; causes a KUnit test failure otherwise.
> + *
> + * @test: Currently executing KUnit test.
> + * @expr: Expression that must produce a KASAN report.
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, expr)                    \
> +       KUNIT_EXPECT_KASAN_RESULT(test, expr, #expr, true)
> +
> +/*
> + * KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression
> + * produces a KASAN report when the write-only mode is not enabled;
> + * causes a KUnit test failure otherwise.
> + *
> + * Note: At the moment, this macro does not check whether the produced
> + * KASAN report is a report about a bad read access. It is only intended
> + * for checking the write-only KASAN mode functionality without failing
> + * KASAN tests.
> + *
> + * @test: Currently executing KUnit test.
> + * @expr: Expression that must only produce a KASAN report
> + *        when the write-only mode is not enabled.
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expr)                       \
> +       KUNIT_EXPECT_KASAN_RESULT(test, expr, #expr,                    \
> +                       !kasan_write_only_enabled())                    \
> +
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
>         if (!IS_ENABLED(config))                                        \
>                 kunit_skip((test), "Test requires " #config "=3Dy");     =
 \
> @@ -183,8 +217,8 @@ static void kmalloc_oob_right(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] =3D 'y');
>
>         /* Out-of-bounds access past the aligned kmalloc object. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D
> -                                       ptr[size + KASAN_GRANULE_SIZE + 5=
]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D
> +                       ptr[size + KASAN_GRANULE_SIZE + 5]);
>
>         kfree(ptr);
>  }
> @@ -198,7 +232,7 @@ static void kmalloc_oob_left(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr =3D *(ptr - 1));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr =3D *(ptr - 1));
>         kfree(ptr);
>  }
>
> @@ -211,7 +245,7 @@ static void kmalloc_node_oob_right(struct kunit *test=
)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D ptr[size]);
>         kfree(ptr);
>  }
>
> @@ -291,7 +325,7 @@ static void kmalloc_large_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         kfree(ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void kmalloc_large_invalid_free(struct kunit *test)
> @@ -323,7 +357,7 @@ static void page_alloc_oob_right(struct kunit *test)
>         ptr =3D page_address(pages);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D ptr[size]);
>         free_pages((unsigned long)ptr, order);
>  }
>
> @@ -338,7 +372,7 @@ static void page_alloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         free_pages((unsigned long)ptr, order);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void krealloc_more_oob_helper(struct kunit *test,
> @@ -458,7 +492,7 @@ static void krealloc_uaf(struct kunit *test)
>
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr2 =3D krealloc(ptr1, size2, GFP_=
KERNEL));
>         KUNIT_ASSERT_NULL(test, ptr2);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *(volatile char *)ptr1);
>  }
>
>  static void kmalloc_oob_16(struct kunit *test)
> @@ -501,7 +535,7 @@ static void kmalloc_uaf_16(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>         kfree(ptr2);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 =3D *ptr2);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr1 =3D *ptr2);
>         kfree(ptr1);
>  }
>
> @@ -640,8 +674,8 @@ static void kmalloc_memmove_invalid_size(struct kunit=
 *test)
>         memset((char *)ptr, 0, 64);
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(invalid_size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
> +                       memmove((char *)ptr, (char *)ptr + 4, invalid_siz=
e));
>         kfree(ptr);
>  }
>
> @@ -654,7 +688,7 @@ static void kmalloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         kfree(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[8]);
>  }
>
>  static void kmalloc_uaf_memset(struct kunit *test)
> @@ -701,7 +735,7 @@ static void kmalloc_uaf2(struct kunit *test)
>                 goto again;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[40]);
>         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>
>         kfree(ptr2);
> @@ -727,19 +761,19 @@ static void kmalloc_uaf3(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>         kfree(ptr2);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[8]);
>  }
>
>  static void kasan_atomics_helper(struct kunit *test, void *unsafe, void =
*safe)
>  {
>         int *i_unsafe =3D unsafe;
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*i_unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, smp_load_acquire(i_unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_read(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> @@ -752,18 +786,31 @@ static void kasan_atomics_helper(struct kunit *test=
, void *unsafe, void *safe)
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42=
));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42=
));
> +       /*
> +        * The result of the test below may vary due to garbage values of
> +        * unsafe in write-only mode.
> +        * Therefore, skip this test when KASAN is configured in write-on=
ly mode.
> +        */
> +       if (!kasan_write_only_enabled())
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, un=
safe, 42));
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
> +       /*
> +        * The result of the test below may vary due to garbage values of
> +        * unsafe in write-only mode.
> +        * Therefore, skip this test when KASAN is configured in write-on=
ly mode.
> +        */
> +       if (!kasan_write_only_enabled()) {
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
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_long_read(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> @@ -776,16 +823,29 @@ static void kasan_atomics_helper(struct kunit *test=
, void *unsafe, void *safe)
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42)=
);
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, saf=
e, 42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsaf=
e, 42));
> +       /*
> +        * The result of the test below may vary due to garbage values of
> +        * unsafe in write-only mode.
> +        * Therefore, skip this test when KASAN is configured in write-on=
ly mode.
> +        */
> +       if (!kasan_write_only_enabled())
> +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(saf=
e, unsafe, 42));
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
> +       /*
> +        * The result of the test below may vary due to garbage values of
> +        * unsafe in write-only mode.
> +        * Therefore, skip this test when KASAN is configured in write-on=
ly mode.
> +        */
> +       if (!kasan_write_only_enabled()) {
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
> @@ -842,8 +902,8 @@ static void ksize_unpoisons_memory(struct kunit *test=
)
>         /* These must trigger a KASAN report. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size=
]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - =
1]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + =
5]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[real_si=
ze - 1]);
>
>         kfree(ptr);
>  }
> @@ -863,8 +923,8 @@ static void ksize_uaf(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size]);
>  }
>
>  /*
> @@ -899,9 +959,9 @@ static void rcu_uaf(struct kunit *test)
>         global_rcu_ptr =3D rcu_dereference_protected(
>                                 (struct kasan_rcu_info __rcu *)ptr, NULL)=
;
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> -               rcu_barrier());
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
> +                       call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> +                       rcu_barrier());
>  }
>
>  static void workqueue_uaf_work(struct work_struct *work)
> @@ -924,8 +984,8 @@ static void workqueue_uaf(struct kunit *test)
>         queue_work(workqueue, work);
>         destroy_workqueue(workqueue);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               ((volatile struct work_struct *)work)->data);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
> +                       ((volatile struct work_struct *)work)->data);
>  }
>
>  static void kfree_via_page(struct kunit *test)
> @@ -972,7 +1032,7 @@ static void kmem_cache_oob(struct kunit *test)
>                 return;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, *p =3D p[size + OOB_TAG_OFF]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *p =3D p[size + OOB_TAG_OFF]);
>
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
> @@ -1068,7 +1128,7 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
>          */
>         rcu_barrier();
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*p));
>
>         kmem_cache_destroy(cache);
>  }
> @@ -1207,7 +1267,7 @@ static void mempool_oob_right_helper(struct kunit *=
test, mempool_t *pool, size_t
>                 KUNIT_EXPECT_KASAN_FAIL(test,
>                         ((volatile char *)&elem[size])[0]);
>         else
> -               KUNIT_EXPECT_KASAN_FAIL(test,
> +               KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                         ((volatile char *)&elem[round_up(size, KASAN_GRAN=
ULE_SIZE)])[0]);
>
>         mempool_free(elem, pool);
> @@ -1273,7 +1333,7 @@ static void mempool_uaf_helper(struct kunit *test, =
mempool_t *pool, bool page)
>         mempool_free(elem, pool);
>
>         ptr =3D page ? page_address((struct page *)elem) : elem;
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void mempool_kmalloc_uaf(struct kunit *test)
> @@ -1532,7 +1592,7 @@ static void kasan_memchr(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 kasan_ptr_result =3D memchr(ptr, '1', size + 1));
>
>         kfree(ptr);
> @@ -1559,7 +1619,7 @@ static void kasan_memcmp(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 kasan_int_result =3D memcmp(ptr, arr, size+1));
>         kfree(ptr);
>  }
> @@ -1594,7 +1654,7 @@ static void kasan_strings(struct kunit *test)
>                         strscpy(ptr, src + 1, KASAN_GRANULE_SIZE));
>
>         /* strscpy should fail if the first byte is unreadable. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SI=
ZE,
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, strscpy(ptr, src + KASAN_GRANU=
LE_SIZE,
>                                               KASAN_GRANULE_SIZE));
>
>         kfree(src);
> @@ -1607,17 +1667,17 @@ static void kasan_strings(struct kunit *test)
>          * will likely point to zeroed byte.
>          */
>         ptr +=3D 16;
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result =3D strchr(ptr, '1=
'));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result =3D strchr(pt=
r, '1'));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result =3D strrchr(ptr, '=
1'));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result =3D strrchr(p=
tr, '1'));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strcmp(ptr, "2=
"));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strcmp(pt=
r, "2"));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strncmp(ptr, "=
2", 1));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strncmp(p=
tr, "2", 1));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strlen(ptr));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strlen(pt=
r));
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D strnlen(ptr, 1=
));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strnlen(p=
tr, 1));
>  }
>
>  static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
> @@ -1636,12 +1696,18 @@ static void kasan_bitops_test_and_modify(struct k=
unit *test, int nr, void *addr)
>  {
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> +       /*
> +        * When KASAN is running in write-only mode,
> +        * a fault won't occur when the bit is set.
> +        * Therefore, skip the test_and_set_bit_lock test in write-only m=
ode.
> +        */
> +       if (!kasan_write_only_enabled())
> +               KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, a=
ddr));
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D test_bit(nr, a=
ddr));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D test_bit(=
nr, addr));
>         if (nr < 7)
>                 KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D
>                                 xor_unlock_is_negative_byte(1 << nr, addr=
));
> @@ -1765,7 +1831,7 @@ static void vmalloc_oob(struct kunit *test)
>                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[si=
ze]);
>
>         /* An aligned access into the first out-of-bounds granule. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5])=
;
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size =
+ 5]);
>
>         /* Check that in-bounds accesses to the physical page are valid. =
*/
>         page =3D vmalloc_to_page(v_ptr);
> @@ -2042,15 +2108,15 @@ static void copy_user_test_oob(struct kunit *test=
)
>
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D copy_from_user(kmem, usermem, size + 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 unused =3D copy_to_user(usermem, kmem, size + 1));
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D __copy_from_user(kmem, usermem, size + 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 unused =3D __copy_to_user(usermem, kmem, size + 1));
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D __copy_from_user_inatomic(kmem, usermem, size =
+ 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 unused =3D __copy_to_user_inatomic(usermem, kmem, size + =
1));
>
>         /*
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeyKuet2XY9%3DjOdiK4Z6f4_%3DXb5ZBzBaDL-2gFPv9yJ5A%40mail.gmail.com.
