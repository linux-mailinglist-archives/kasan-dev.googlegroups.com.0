Return-Path: <kasan-dev+bncBDW2JDUY5AORB6FKUWXAMGQET22ZH6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 80F9B850C32
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 00:17:13 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5114e915d99sf2480897e87.1
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Feb 2024 15:17:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707693433; cv=pass;
        d=google.com; s=arc-20160816;
        b=BP4ybE+p0wIN5m06LIIMJaD8+ox57HETS3K2MRZtipfaoUwnlNTOPCahfOvlCbHWyK
         6Ew1x/t1CQoVeUXzlj0YNc0GdBDyjTVQS8807HqNSBvq9q1qaj0TAWwX/bSvMeROWz5Y
         KoRi4lcGH2znV3DxpEjkV4LGd4KRzjWhRzNz3Z+SjzkhglG5g/XL7ZLD9VO0uno/Z0F1
         NKIa3Vkzg+tmfpB3i5sCgX8Jq9sk+txLsR40JqFl9NEsl9+5nMK8oNUn2Y1UUn41ncM0
         xVx6zYF5+gVZbi6FbGEgPJ613dRWEgJsiSykB7ODdGS6RtqTmE/69yb5Xx42HQfC/Dg7
         bDyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9DkerB4GNUjcxl1qFSr21OB1Q4RwTnrreilQe2+khSs=;
        fh=lx+F2m1oU1voYbwBQLW/0n1Dw/sdiGFkW7rVPjyPsA4=;
        b=RCb+hUTLYNxA5Fo9trUIk+8/w4ZhBaTcOZ4g0chySygniEI7TpkGySgtzHBab3l3Ce
         aRm6OeExiYwJ6svOCLhWgo4Do5qZpbsBBl9GSZ9339v43qkcw3GpK9F80vWfB+veIJTH
         9spvqmTY5R8PCWRto+Yreo4lQP8bQct9EFKSrawRFGnJGW1IL/c+lURSF/iI1/JCVVBD
         CyBN3JU7Qnya7PcHwKPwgwUNEFJiBhK/9d0E2t/PllmgUA2qD4mutte5PQv0ih/N+pDV
         P42ZZWZzyXbrr9P+5xalFYViIbdBVTtMJPe2VizRd4Y0/otAjgGLor8IYudUNaXcpWes
         Hrsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ngE8aXS5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707693433; x=1708298233; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9DkerB4GNUjcxl1qFSr21OB1Q4RwTnrreilQe2+khSs=;
        b=jmYja0c+9JaG7RefM2eEuxDrxsxuSwTvQ6hXkMQdyAe8n+REFGzXbrzi8BYgVEAuz2
         8SQ41AGfNEtibsF3hJOVcvCqSyimANV31JBYQtDPOLQW9a8Y8aHJvM1DQ9RrmhSJGcwA
         8kHnYLgm1w/Eo+q1SOOCZ+FGxsNR4yzB0u1xNGLdOP0wWaEPTJsZ5YS8nCpjlIRyKv43
         aR/rhVKN3uR85k6VSdFk2jqgN/MwQ0xGPxS8UuPmMIz886mnNq+DI0oymYm2Ztvpm6a/
         CXoPgeiorznVLLQxcI5kMhezkZ8ZP8R4ntC8iBttQ7eNOEBy76RtFIHTyiHq7QPnTYo+
         UXtw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707693433; x=1708298233; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9DkerB4GNUjcxl1qFSr21OB1Q4RwTnrreilQe2+khSs=;
        b=cYLmm/X77s4So+EgdlIg1cAp+4INxMtHQbAknMK5RN0HzsAdTT1pSublsfct2hs18U
         6R2vs5onoIbLKE+5FcnAj0o73e9PkxZN+5O+suZv0TQ5FqhaZn81uS0Vpk67fyhpxs5Q
         an+tMDjJkajbGghleS1SzBBI2ZblFKJR+xSuGo2cdiOxJOhm10T3bfA7Ue70ugcjHI2p
         nIgFGqdUVTnT7rx/9CrETiZ194Oprhn7wOSd8xiQQBcn8UyxopnsN6h1biX3wvst3AB6
         J6keclwGmwf0xHtR6Uc7mhRKX0YBNUOGj9r4dC10sGDJaC3pQC0hMgTOLbZICp+eEsmg
         MraA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707693433; x=1708298233;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9DkerB4GNUjcxl1qFSr21OB1Q4RwTnrreilQe2+khSs=;
        b=AwiNR7vzGTBH4b49YNYXmBXfQ2VXcWwp8wOjjAS+pDEmHEhDq19cLT/t8eXmuVsqFK
         uB2d1ZjY2cd7uker3aZP1akb9Z3mXUMo19RnupBQ6HWmgyuqZY2tLCQjEcBmHenf9dTi
         mjDhxoYlAFhe86zZLwSszsMFfWnc8tLiZ+7nGb5eMtg6NrNzHl/88BjL3aWpKU5MQEp0
         szUUnC9tYfMnzpwnj/3Lzpeb++iTNCRDw6PQMcQjl1cdOWZi9i05ufu5uOiW/9O+XOBl
         CVON5jUCCgW/QfkxLTSsMFKi2rLtM7nEu7CHPQwMVTTvwmEJcAvsd3F4zfNcvPF2gkDu
         Fmzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy0QOnSybGHtuRz24rpvCIZ5jP+XTDQOKyvreJHCNCYfWMeVQOj
	GYO0JcJ0MoJguYuOJzMwvtms+KPy6V/AiNvV1QRVyNmw5IcwOUTY
X-Google-Smtp-Source: AGHT+IFwiYP0sCija78+ekmg2OdI/XPGD/vpdcVYa7jxLK1PN3yd5UauXYUnsl3A4jmu3lPzQgmRYQ==
X-Received: by 2002:a19:645c:0:b0:511:612a:c633 with SMTP id b28-20020a19645c000000b00511612ac633mr3226016lfj.52.1707693432309;
        Sun, 11 Feb 2024 15:17:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3da1:b0:511:5b43:6c1b with SMTP id
 k33-20020a0565123da100b005115b436c1bls1554302lfv.2.-pod-prod-08-eu; Sun, 11
 Feb 2024 15:17:10 -0800 (PST)
X-Received: by 2002:a2e:9d87:0:b0:2d0:9322:7496 with SMTP id c7-20020a2e9d87000000b002d093227496mr3521280ljj.43.1707693430371;
        Sun, 11 Feb 2024 15:17:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707693430; cv=none;
        d=google.com; s=arc-20160816;
        b=SOtlzX7QIZrTbl1FUv4LFto3yTZ2sq/mUqxM++uX5jrONbGIR89Qx4PGBQ3Jpa14yT
         1IsLi8c+cmGDcA9wCF7hL39/DG4YxG1skWNpsXH0fxVgxcwaa2hiQouw6wXhlPKkHqcu
         SVRt67mGp7nmlnJw/dl2IzAe7yzRuJjpudfF8ZwDUU8n72SEsmwdixEvS6A17kh4u9Hr
         us1baYvT3DppxNm5OcFwk9ylDt6FsnBQF+P/tcwc3KxgX0p5RZ/FKSnPHcea+hgF9TDp
         2xBGrMYX9IGthywizrX+/Kn1FUSYb7HiTPdwvcmwwtA2fKDoRfqkACa/Dduht+1MiA0L
         L5Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8BelCqyqaTU+jGU/MDi1SS3yrhgj8pP4yG8n+9l1MNk=;
        fh=lx+F2m1oU1voYbwBQLW/0n1Dw/sdiGFkW7rVPjyPsA4=;
        b=sF7E/xxAeD3w28b23kWL6YwVqfdObb/UH0u9QfK1+oLlpBKZbh+fcA1MPq0i6yjHh0
         4N0pcQPKKsXo1EuiJ9TijAJBQdxG4GX4Cjm5C/skOfGgAQtpazU55y23AzF6d+HjjSnr
         kndjVIb0uiiAiTi2NBnoo1xnYQU6WOdFYR5MeeTHKI/zky8b6+9VXLeSEZzmwKPmjF4v
         orajprKCOh/AQnPiNHTimSrfImZNhMfv5Gz19CvzLgZ+sYDm58/gPQstCXNAhENbKayE
         0e3EnqhgOfnGdMyuvQEzH6XpmID+OlpfAHThi+NSdMWfwzMJXFgcpxgWANwZEFx1NK+H
         YDXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ngE8aXS5;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=1; AJvYcCXkXxv4OXaewZzo+qrhZDWB0EQNniPxENQulWoFzc1m4DWVHnJJd9fRg+Kezcoi7MfAmMQ8vqirnelzXFQWyhWkTnQlw3wrZbTpyA==
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id n7-20020a2e9047000000b002d0afeedd11si428210ljg.8.2024.02.11.15.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 11 Feb 2024 15:17:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-33b0ecb1965so1401477f8f.1
        for <kasan-dev@googlegroups.com>; Sun, 11 Feb 2024 15:17:10 -0800 (PST)
X-Received: by 2002:adf:f812:0:b0:33b:66a1:d3d5 with SMTP id
 s18-20020adff812000000b0033b66a1d3d5mr3951831wrp.19.1707693429624; Sun, 11
 Feb 2024 15:17:09 -0800 (PST)
MIME-Version: 1.0
References: <20240202113259.3045705-1-paul.heidekrueger@tum.de> <20240211091720.145235-1-paul.heidekrueger@tum.de>
In-Reply-To: <20240211091720.145235-1-paul.heidekrueger@tum.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 12 Feb 2024 00:16:58 +0100
Message-ID: <CA+fCnZcfUyqzok0yV2uvsDdhiT95Y-KYnozY77y04YDBwKhj-Q@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add atomic tests
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ngE8aXS5;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
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

On Sun, Feb 11, 2024 at 10:17=E2=80=AFAM Paul Heidekr=C3=BCger
<paul.heidekrueger@tum.de> wrote:
>
> Test that KASan can detect some unsafe atomic accesses.
>
> As discussed in the linked thread below, these tests attempt to cover
> the most common uses of atomics and, therefore, aren't exhaustive.
>
> CC: Marco Elver <elver@google.com>
> CC: Andrey Konovalov <andreyknvl@gmail.com>
> Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueg=
er@tum.de/T/#u
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> Reviewed-by: Marco Elver <elver@google.com>
> Tested-by: Marco Elver <elver@google.com>
> Acked-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> ---
> Changes PATCH v1 -> PATCH v2:
> * Make explicit cast implicit as per Mark's feedback
> * Increase the size of the "a2" allocation as per Andrey's feedback
> * Add tags
>
> Changes PATCH RFC v2 -> PATCH v1:
> * Remove casts to void*
> * Remove i_safe variable
> * Add atomic_long_* test cases
> * Carry over comment from kasan_bitops_tags()
>
> Changes PATCH RFC v1 -> PATCH RFC v2:
> * Adjust size of allocations to make kasan_atomics() work with all KASan =
modes
> * Remove comments and move tests closer to the bitops tests
> * For functions taking two addresses as an input, test each address in a =
separate function call.
> * Rename variables for clarity
> * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_sto=
re_release()
>
>  mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 79 insertions(+)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..7bf09699b145 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
>         kfree(bits);
>  }
>
> +static void kasan_atomics_helper(struct kunit *test, void *unsafe, void =
*safe)
> +{
> +       int *i_unsafe =3D unsafe;
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe))=
;
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe))=
;
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42)=
);
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, saf=
e, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsaf=
e, 42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe=
));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, =
42));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(uns=
afe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(uns=
afe));
> +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe)=
);
> +}
> +
> +static void kasan_atomics(struct kunit *test)
> +{
> +       void *a1, *a2;
> +
> +       /*
> +        * Just as with kasan_bitops_tags(), we allocate 48 bytes of memo=
ry such
> +        * that the following 16 bytes will make up the redzone.
> +        */
> +       a1 =3D kzalloc(48, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +       a2 =3D kzalloc(sizeof(atomic_long_t), GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);

This should check for a2, not a1. Sorry for not spotting this before.

> +
> +       /* Use atomics to access the redzone. */
> +       kasan_atomics_helper(test, a1 + 48, a2);
> +
> +       kfree(a1);
> +       kfree(a2);
> +}
> +
>  static void kmalloc_double_kzfree(struct kunit *test)
>  {
>         char *ptr;
> @@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kasan_strings),
>         KUNIT_CASE(kasan_bitops_generic),
>         KUNIT_CASE(kasan_bitops_tags),
> +       KUNIT_CASE(kasan_atomics),
>         KUNIT_CASE(kmalloc_double_kzfree),
>         KUNIT_CASE(rcu_uaf),
>         KUNIT_CASE(workqueue_uaf),
> --
> 2.40.1
>

With the mentioned change:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcfUyqzok0yV2uvsDdhiT95Y-KYnozY77y04YDBwKhj-Q%40mail.gmai=
l.com.
