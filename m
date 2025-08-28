Return-Path: <kasan-dev+bncBDW2JDUY5AORBNXRYLCQMGQECQCIRPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CDFA0B3AB56
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 22:14:47 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45a1b0bd6a9sf7491935e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 13:14:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756412087; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gc5C/DRLOzktHCVLnX9ipqEEBxtgWhqJIvFSycqtwvbUwxHsKPhLvKyWgJFNEqtezy
         uq0GmrYmZ1aw7SVYDv2IDuNDxnvUncZ7jqC6nq0BTUXNP3cmd8pTR82joD+OkCxwfA0B
         4zl0C711n7Z/sUDYJID75UIISE0t7dTNCsANQMVMkLv9+5Urvu6Zw+0IkcLwzi90/DyZ
         xiqSOq633ikxUORKDSt6yetB6tsoHA0HCIk0gjxfsjdlozhfcgIr9XzFDGKEUBOAUGBk
         tfqDOKEbc/zmd4pGUFQqbgSoMNFNHe2UuK3rphybUCcSA/XMx9Q2Oo3gj7UEWf8cRvph
         Ij8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=z2nhikkdMoz6FTUSFL0NpA/kS+QA+vJaWmavDH2ukW8=;
        fh=w0HOqF/lBNVKv5CLVNNL+lBcODgFxnke5hHCSMgaqRg=;
        b=hXF1eNtQRSrmO/tQKhWyG6/3SKT9+yOqkDsZVPkBgxrDUsUJOZ2/jSdFbPtO2va1tQ
         ARZU2KORjIm5a9TDPD10rJifqEQuID8ld8gV2hm9Ci7i/F1jpGpERqxeQ3CmdRcAcsav
         qtWRitIRsZ3Q7KHejEqwHWT1PeEL4DSJEegxPopvO3ZOh73Ru5J8gQzSdED/iVXlgh6v
         j5S77Hoz22n11nKqrCi4na23orcK2rZQ+CiwL9ptRbm2gyA4M61jwjMyvdk2Umty3TTF
         UjtzL9Fa90DWBytG5Cju/BOapMyR+YxQ1Fe2+LroxDcI66CpfiyyLvSh5mhaAszFhYlx
         ZgAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Z1zcLtfb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756412087; x=1757016887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z2nhikkdMoz6FTUSFL0NpA/kS+QA+vJaWmavDH2ukW8=;
        b=OJExWXcd+5BG3gOid9LGAQDEYOKxNhNSlrAucfGDnRR0WcIgVrhx9d6IEe4OSvoesi
         l2T7ACwsZHBFxzUxvuHRmzR79BTqQDq8kpdgSg7SVVWU77YeJs503vJpvWIGml7SGLfa
         bHNPeHjcLIXvieIhbuIVUsWXbc6kDeellTIK87u+u5ZUH4HrHHBJAgz4ilGeh1EKsaMZ
         SkOvh0PkDwAN36CpqeDfHysj3hKTVIOJj5cEBcietnqLLZD1BJXUGhQ2lFJ+UbwL2G4M
         ofN8HJK8U5MM98Ldu3uoSYyw2xOtlqANUBMxtJCCFkZQfXipcx+MNbvLAS1+745AjBw+
         iCgg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756412087; x=1757016887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z2nhikkdMoz6FTUSFL0NpA/kS+QA+vJaWmavDH2ukW8=;
        b=BbEj4uZMK1NgdK7vpe65/rzsuxy+5W2m3JMl4HqCWXAj6LLl4/eaQS0lgw3Qq/m01n
         J1u7My++eVRuQmyZGABjj1Kwa6RA79zLtheOzh7Wrvq+tOlVyr9AsIuFp76Jc++OZfph
         HKiW+H2+GOkr7DEpubtyNtY0oXGamU4BDXqexZm4DbxVUvTOjUKqMsPGWXQQoLQNaFh/
         niR1XkZNpaZFroVX6NyKrUHEhH7h6gyN9uhp6uease0aghfF/J8DGaV/rpOMWXl/XoxJ
         xyfbQdLoNsl1OHwVboQU99MpOoahxDN+SMJK6kkiKqO9jqbOSLgAZJ8V9IPhk22fKGnU
         6S7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756412087; x=1757016887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z2nhikkdMoz6FTUSFL0NpA/kS+QA+vJaWmavDH2ukW8=;
        b=twagjgthE4LmY4X23iwDROY26A8KLqBUbiwpxFhVaVHxHzB/rs0XQSNsOHVWtf3BST
         Ku6GlJX8cO4II7wzR/ujSd9mXuAsCpDA3c0731CLYOhliqNPYf+aTiF1fKpELUMkUd+2
         h27Y1p+0TGf6ljcNp8/bamE6b/qf1v76sYnsrLPZBWu3+p6PDzL6UZMig2VUksu5/ay4
         3JcrZ7QqruZPm+bkviWDEgVmsrITnduClgHKTRdRbhS5CRtC0JYvqqTh0qsDFKcwcW04
         IFHxLLdWezMUsTg8+j2/wZKZHF8Oy+edOk7rxnj56ojwjx+zjPpsVF3aiPDSaimCz5ic
         hNRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKLwnnzL409Ii/AUB4yNttKyRIEdaTJTYgX8dr35HBhxKLiiMvDFNvq9qXVH48uQ4yTnVB7Q==@lfdr.de
X-Gm-Message-State: AOJu0YwFlo0HoLFVruEH1cYH16LXEbpy2NoTxgaWymEIH+U7p96gFjWG
	vzBougJOv3ko4OVeELGNcz7TWd6LW3krkHMSs2UBsaz5x3Ptmlno3/xf
X-Google-Smtp-Source: AGHT+IH9+NLk7QvC+EVhxprtuWGOw/GRg0oFpkKP1S6XKkufi5vtpAYzm/nrmCJ8z9N1I0APM9VcTA==
X-Received: by 2002:a05:6000:43cc:20b0:3c6:aa87:d959 with SMTP id ffacd0b85a97d-3c6aa87dab1mr15684720f8f.26.1756412087120;
        Thu, 28 Aug 2025 13:14:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd51RXC6vgjsLxlFyrQrXDZ4/HHx4c0vkqu2dzENG70Rg==
Received: by 2002:a05:6000:40cb:b0:3b7:9282:b6ee with SMTP id
 ffacd0b85a97d-3cde38fee54ls653779f8f.2.-pod-prod-06-eu; Thu, 28 Aug 2025
 13:14:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNcANNbqYiFCJ55Q3c1a+27n+60/WQaiKsC1I/jowQhAYnDFcu5GxkL5Km2zV+O9/tv7jyw2zR6rk=@googlegroups.com
X-Received: by 2002:a05:6000:25ee:b0:3c7:44eb:dd77 with SMTP id ffacd0b85a97d-3c744ebe211mr17647590f8f.12.1756412084524;
        Thu, 28 Aug 2025 13:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756412084; cv=none;
        d=google.com; s=arc-20240605;
        b=jKoKNonbwv6diLDscwJLHXGyP51vGs7bcnD+ypmLVReSp38zKE4r6d0TXPVL8N8K1V
         GnclJYgXTyiIbdOyDmC5QOwgpUHygx9E9ww/8n2zTNvBQjatYmXgBNkBn04J0LBuXP6w
         VYRZgRIUyQg1Fs8WbcV6dPY/U5sDdxF9P0dPbudoImMpOoxBnx7Zo5ORSwK0ehXK2qsC
         veSeZCgzwuZvyC8k7YSLgl/5a5v/SDXkLCGKMCFUcmeslXt1qedqFP6DHAfE5u6HO+nH
         5oZ/8t4N3pvI7oy+7IbPcDM2JldZ3qAyLh4v9Sv5G3P/mGSrBzmwEo1iVLBGFaRe+l+z
         ofTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Vjm8Lxm33RDNh68uuSoVcCWhNBv32fciRIR1UYiBe9Q=;
        fh=u3rKYj9LqiiOX9UJIPcEIONMwPEaEYY5G53dxLQa3AA=;
        b=LL5XGoxSnrrpn2zgWqWGuo3ZSA6wQB4Yw/LVv8GfAsMUc9fvEfjwz/H6QeDn6vpVwZ
         /PHv9sPpKMLApQlNGPKTfZLJouOpv/JI//9UL8PAGQxHkBVwh1MFstRmToGDzAMW0Dhh
         aunXSllpq+l3/Cx2b9IAS1ggsaEjIJdevhs6i3k6MTik8htR6t1j4UrjHo3N0RBS4faH
         V3pbR+AfoJXCwQU0/vNLPO2aIgA8yNBzBQscl8EblWl3/zf25wief68K5iaiBB6YofUr
         RCXtpjVX7cAANfVanK20abLJTm9P/+xONbr9mNSIprxyctsVsp8ePbmkFcEoVHgqDq5o
         cYew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Z1zcLtfb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cf26c281f7si10197f8f.1.2025.08.28.13.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 13:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-45a1b05ac1eso7412595e9.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 13:14:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyBrTnCJbJS5lfc22SlWELmW64b56malMm06ARRokxYd7cpV5l0Q9c/ocW6qDoouVEUszqqXgit3I=@googlegroups.com
X-Gm-Gg: ASbGncuoft55Zhyae32Vv6urLEVCwAme2aMQF69jCUmtwYTfCdHhjBKxlndBFbhZwkT
	9rGyze8/i/9G/8s2JX0egSsUNX3aF8eP69NCkVxy/UE4Nlboi30vNmP9+4ueD2g7XppHmZOHDOW
	n20+WHHBE2NGB2hIN1OjeWWOTMIBTjFCLOdd5ZDWaofZYUXDfk53wBddfb7AmnzOrADgJbeB2RP
	HAa/Bbcag==
X-Received: by 2002:a5d:5f8d:0:b0:3c8:d236:26aa with SMTP id
 ffacd0b85a97d-3c8d2362b89mr14409036f8f.58.1756412083727; Thu, 28 Aug 2025
 13:14:43 -0700 (PDT)
MIME-Version: 1.0
References: <20250820071243.1567338-1-yeoreum.yun@arm.com> <20250820071243.1567338-3-yeoreum.yun@arm.com>
In-Reply-To: <20250820071243.1567338-3-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 28 Aug 2025 22:14:32 +0200
X-Gm-Features: Ac12FXw4bc7WhGV15pNer-clBCZfyRwT3DSN0R6PuwxC-KzCPndNwcaBAIW1SFw
Message-ID: <CA+fCnZcAgW1iVKJ-MyzzdFoaDpRpA+CnTt2y22uZcUbSegc8CQ@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] kasan: apply write-only mode in kasan kunit testcases
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
 header.i=@gmail.com header.s=20230601 header.b=Z1zcLtfb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Wed, Aug 20, 2025 at 9:12=E2=80=AFAM Yeoreum Yun <yeoreum.yun@arm.com> w=
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
>  mm/kasan/kasan_test_c.c | 237 +++++++++++++++++++++++++++-------------
>  1 file changed, 162 insertions(+), 75 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index e0968acc03aa..cc0730aa18d1 100644
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

Let's name this macro "KUNIT_EXPECT_KASAN_RESULT" and the last argument "fa=
il".

> + * a KASAN report or not; a KUnit test failure when it's different from =
@produce.

..; causes a KUnit test failure when the result is different from @fail.

>   *
>   * @test: Currently executing KUnit test.
> - * @expression: Expression that must produce a KASAN report.
> + * @expr: Expression produce a KASAN report or not.

Expression to be tested.

> + * @expr_str: Expression string

Expression to be tested encoded as a string.

> + * @produce: expression should produce a KASAN report.

@fail: Whether expression should produce a KASAN report.

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

Let's keep the message as is for the case when a KASAN report is expected; =
i.e.:

KASAN failure expected in X, but none occurred

And for the case when KASAN report is not expected, let's do:

KASAN failure not expected in X, but occurred

>         }                                                               \
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
>             kasan_sync_fault_possible()) {                              \
> @@ -141,6 +147,29 @@ static void kasan_test_exit(struct kunit *test)
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

Expression that must produce a KASAN report.

> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, expr)                    \
> +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, true)
> +
> +/*
> + * KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression pro=
duces
> + * a KASAN report for read access.
> + * It causes a KUnit test failure. if KASAN report isn't produced for re=
ad access.
> + * For write access, it cause a KUnit test failure if a KASAN report is =
produced

KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression
produces a KASAN report when the write-only mode is not enabled;
causes a KUnit test failure otherwise.

Note: At the moment, this macro does not check whether the produced
KASAN report is a report about a bad read access. It is only intended
for checking the write-only KASAN mode functionality without failing
KASAN tests.

> + *
> + * @test: Currently executing KUnit test.
> + * @expr: Expression doesn't produce a KASAN report.

Expression that must only produce a KASAN report when the write-only
mode is not enabled.

> + */
> +#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expr)                       \
> +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr,                 \
> +                       !kasan_write_only_enabled())                    \
> +
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
>         if (!IS_ENABLED(config))                                        \
>                 kunit_skip((test), "Test requires " #config "=3Dy");     =
 \
> @@ -183,8 +212,8 @@ static void kmalloc_oob_right(struct kunit *test)
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
> @@ -198,7 +227,8 @@ static void kmalloc_oob_left(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr =3D *(ptr - 1));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr =3D *(ptr - 1));
> +
>         kfree(ptr);
>  }
>
> @@ -211,7 +241,8 @@ static void kmalloc_node_oob_right(struct kunit *test=
)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D ptr[size]);
> +
>         kfree(ptr);
>  }
>
> @@ -291,7 +322,7 @@ static void kmalloc_large_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         kfree(ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void kmalloc_large_invalid_free(struct kunit *test)
> @@ -323,7 +354,8 @@ static void page_alloc_oob_right(struct kunit *test)
>         ptr =3D page_address(pages);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D ptr[size]);
> +
>         free_pages((unsigned long)ptr, order);
>  }
>
> @@ -338,7 +370,7 @@ static void page_alloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         free_pages((unsigned long)ptr, order);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void krealloc_more_oob_helper(struct kunit *test,
> @@ -455,10 +487,10 @@ static void krealloc_uaf(struct kunit *test)
>         ptr1 =3D kmalloc(size1, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>         kfree(ptr1);
> -

Keep this empty line.

>         KUNIT_EXPECT_KASAN_FAIL(test, ptr2 =3D krealloc(ptr1, size2, GFP_=
KERNEL));
>         KUNIT_ASSERT_NULL(test, ptr2);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *(volatile char *)ptr1);
>  }
>
>  static void kmalloc_oob_16(struct kunit *test)
> @@ -501,7 +533,8 @@ static void kmalloc_uaf_16(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>         kfree(ptr2);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 =3D *ptr2);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr1 =3D *ptr2);
> +
>         kfree(ptr1);
>  }
>
> @@ -640,8 +673,10 @@ static void kmalloc_memmove_invalid_size(struct kuni=
t *test)
>         memset((char *)ptr, 0, 64);
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(invalid_size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> -               memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
> +                       memmove((char *)ptr, (char *)ptr + 4, invalid_siz=
e));
> +
>         kfree(ptr);
>  }
>
> @@ -654,7 +689,8 @@ static void kmalloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         kfree(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[8]);
>  }
>
>  static void kmalloc_uaf_memset(struct kunit *test)
> @@ -701,7 +737,8 @@ static void kmalloc_uaf2(struct kunit *test)
>                 goto again;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[40]);
> +
>         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>
>         kfree(ptr2);
> @@ -727,19 +764,19 @@ static void kmalloc_uaf3(struct kunit *test)
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
> +

No need for this empty line.

>         KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> -       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, smp_load_acquire(i_unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> -

Keep this empty line.

> -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_read(unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> @@ -752,18 +789,35 @@ static void kasan_atomics_helper(struct kunit *test=
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

store-only =3D> the write-only

Here and below.

> +        */
> +       if (!kasan_write_only_enabled())
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
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_long_read(unsafe));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
>         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> @@ -776,16 +830,32 @@ static void kasan_atomics_helper(struct kunit *test=
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
> +       if (!kasan_write_only_enabled())
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
> @@ -842,8 +912,9 @@ static void ksize_unpoisons_memory(struct kunit *test=
)
>         /* These must trigger a KASAN report. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size=
]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - =
1]);
> +

No need for this empty line - this shows that the comment above
applies to all of these checks.

> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + =
5]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[real_si=
ze - 1]);
>
>         kfree(ptr);
>  }
> @@ -863,8 +934,8 @@ static void ksize_uaf(struct kunit *test)
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
> @@ -886,6 +957,7 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
>                 container_of(rp, struct kasan_rcu_info, rcu);
>
>         kfree(fp);
> +

No need for this empty line.

>         ((volatile struct kasan_rcu_info *)fp)->i;
>  }
>
> @@ -899,9 +971,9 @@ static void rcu_uaf(struct kunit *test)
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
> @@ -924,8 +996,8 @@ static void workqueue_uaf(struct kunit *test)
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
> @@ -972,7 +1044,7 @@ static void kmem_cache_oob(struct kunit *test)
>                 return;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, *p =3D p[size + OOB_TAG_OFF]);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *p =3D p[size + OOB_TAG_OFF]);
>
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
> @@ -1068,7 +1140,7 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
>          */
>         rcu_barrier();
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*p));
>
>         kmem_cache_destroy(cache);
>  }
> @@ -1207,7 +1279,7 @@ static void mempool_oob_right_helper(struct kunit *=
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
> @@ -1273,7 +1345,8 @@ static void mempool_uaf_helper(struct kunit *test, =
mempool_t *pool, bool page)
>         mempool_free(elem, pool);
>
>         ptr =3D page ? page_address((struct page *)elem) : elem;
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> +

No need for this empty line.

> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void mempool_kmalloc_uaf(struct kunit *test)
> @@ -1532,7 +1605,8 @@ static void kasan_memchr(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 kasan_ptr_result =3D memchr(ptr, '1', size + 1));
>
>         kfree(ptr);
> @@ -1559,8 +1633,10 @@ static void kasan_memcmp(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 kasan_int_result =3D memcmp(ptr, arr, size+1));
> +
>         kfree(ptr);
>  }
>
> @@ -1594,7 +1670,7 @@ static void kasan_strings(struct kunit *test)
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
> @@ -1607,17 +1683,13 @@ static void kasan_strings(struct kunit *test)
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
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result =3D strchr(pt=
r, '1'));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result =3D strrchr(p=
tr, '1'));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strcmp(pt=
r, "2"));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strncmp(p=
tr, "2", 1));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strlen(pt=
r));
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D strnlen(p=
tr, 1));
>  }
>
>  static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
> @@ -1636,12 +1708,22 @@ static void kasan_bitops_test_and_modify(struct k=
unit *test, int nr, void *addr)
>  {
>         KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
>         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
> -       KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> +
> +       /*
> +        * When KASAN is running in store-only mode,
> +        * a fault won't occur when the bit is set.
> +        * Therefore, skip the test_and_set_bit_lock test in store-only m=
ode.
> +        */
> +       if (!kasan_write_only_enabled())
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
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result =3D test_bit(=
nr, addr));
> +
>         if (nr < 7)
>                 KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =3D
>                                 xor_unlock_is_negative_byte(1 << nr, addr=
));
> @@ -1765,7 +1847,7 @@ static void vmalloc_oob(struct kunit *test)
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
> @@ -2042,15 +2124,20 @@ static void copy_user_test_oob(struct kunit *test=
)
>
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D copy_from_user(kmem, usermem, size + 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 unused =3D copy_to_user(usermem, kmem, size + 1));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D __copy_from_user(kmem, usermem, size + 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 unused =3D __copy_to_user(usermem, kmem, size + 1));
> +
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 unused =3D __copy_from_user_inatomic(kmem, usermem, size =
+ 1));
> -       KUNIT_EXPECT_KASAN_FAIL(test,
> +
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
>                 unused =3D __copy_to_user_inatomic(usermem, kmem, size + =
1));

I don't think there's need for the empty lines between the checks above.

>
>         /*


> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcAgW1iVKJ-MyzzdFoaDpRpA%2BCnTt2y22uZcUbSegc8CQ%40mail.gmail.com.
