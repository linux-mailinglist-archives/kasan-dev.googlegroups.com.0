Return-Path: <kasan-dev+bncBDW2JDUY5AORBBFJSO3AMGQEMKRFEUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42E9C958D80
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 19:38:14 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-428e48612acsf62789395e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 10:38:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724175494; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAsMIgcnfkCg4KFi6hy68q9CeacQzA32e2sl6q4W030C/3l7zodTadFeoWNadzqht9
         q/vXYQToctkIOV7lpB2Kt1JlRdq0ZSNajQQSxACfQaMAo9lwd1dz0AqOYAMDCSf5XGpK
         yTl7zKoenwVJlpWxYixJzY2RdwutazZFcA//jqAqVtTWRQl1frrhS8afyQc+8ey0cG1b
         CMC10jSTBf9JTHYsWHMSD/9S+NOJ5kDJh3wgqgmBBKACb91ZLzjvbX2O93pITWLNz0Ot
         elXkIEjcO7wMGHwuESnqAARQ9GIQEzEacHAabGzCcverl8IVlSXDmdKz36JWEh/SDaTj
         C6rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=EB+73iCUc57b7jtChdBBKdnKE/NGx+tyjpN6tEucJ6U=;
        fh=jmsEm2199shosFLP7gATeOMn5swTMUqYMAsJO6S9h7k=;
        b=WQxhgJr5KKCoSosm88t9J2RvpDB5jyPXu+YrRSTWX7rLjPkHH+aag6on+46SFmP4dE
         7B20Y+bW14Xa/ppr1Zumtx5s+BM3fmEUOahYSO5L98Kmg2xFOBPePn+1w1dNRsgXcRJl
         WPzdHulXBTlWBOSJxxsGAkzcuKDmpsG6z8un+qPtkRXEN+NRW3UEMQqqoJHxAPOfvBOw
         Nf1yXOo4mvh5r0Q4vOudRKXqcSC7AtWkQOoO2JwHib2jt9W+mPTYhyVZgEX/wBoqdIRJ
         9mj4azAYz8+CqWG+jM6NES+ifEZwmPvb6VGVBfDINA8tO9yK25Vp20wyhsGea9KfeAvD
         7jVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=X4n5Pcm3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724175494; x=1724780294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EB+73iCUc57b7jtChdBBKdnKE/NGx+tyjpN6tEucJ6U=;
        b=S1C/UXJZNdHc2NNjaLzgzWgVtu7UoA5fdhvmBfPFBPEsCqwe6OWZidl00BB9OxX1KX
         4HfOnhZ6Zmx/xOW9AYbMFCqHiXU9cgifbBrr5JHTYRR28A6YSf5j0WlIZbTvduG/41Q3
         7VDQsKXYeS1ylBFKmM4ZsLrjFXwgLKMzCBJpVz52eZUsBzZM43orTpe8NqBiVy1+dbv/
         KPW0F+ro96rSyWx0XWW+ciQtdraL28G3OkE4Jcm/6Gn11uWN+QC3sI8L6kG1/F7TVRjS
         jQ1FbgSRhbBoI+Ncd2d1kTC6Cj+GkpOxo/aqTr/jjQw9+kkRrdBucvDsLMebaMoW6ITY
         84ew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724175494; x=1724780294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EB+73iCUc57b7jtChdBBKdnKE/NGx+tyjpN6tEucJ6U=;
        b=CHcR9xZMD3o/LV0yZP1VX1k+XAtVNETFwrIXH0LQb6CTIh7ZJQ0puT6d9RJT2JvxDo
         NfkqulKsKjcKcrF0Un8Qx1jurMWPDs23cgEi0rH2BaSKHTcdXm89uADFmUhxDl/+IX6Q
         CmXP/5lOncfwjXhbXDC31gdGFpBo9MjEtNd9VFvTe72ddBOY3+aTA4mg6FXx1E/52sf4
         TC068RE6MMRMi/BAxbBky8Tvnrp4uuw9ZDNxXzFbp4BzmU1ZLjk82SFkh4cC1cvN2pzg
         IJWBUtHr90dHsBT841WTBGkHOLs8/D2d8Qt4kacGjBwn2JWPvdreS9+Kznxyg0v03pDM
         m1zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724175494; x=1724780294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EB+73iCUc57b7jtChdBBKdnKE/NGx+tyjpN6tEucJ6U=;
        b=dLLjL7+WCreWUkMePaHBqWgbX0DE9WTlzHyax4tsXo30XYt3OPTaQ+oWzVbpBgp+0T
         lXbwXBTAvuRg8Dt5A4PKfSffMq3fmBInLxu1a8vgdCJABY/HHClOyp12bWubXwuyQQot
         h36UCWfdQSxcj5gD+hbTI8r2/w1p4UCQ2LeZU4YamjoyhOJr7Hd/kcPRJU5/yZs8aDGU
         pFk6tCJfOL0K+lzqb/wa48TnlXj0pVRzVHjjFKx5SItFPare2lmmm7seqIX9Ufc9H61x
         6CY50uVPmhkXVxnD7YQGMqi6PCS/x6f51eBhw5hXnC45MPMiDksffanJg0T0HbdO6sqM
         l/Jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtxYFQiuCaWsr/YPJLj+59LiumPYrCW2TJ2QNMVlnGJWb6aZn2ixVY1PRSPTeFanX9YyxHaguTRFHNfZNOjPaZYnW4WFN1gg==
X-Gm-Message-State: AOJu0YzSp1BcUD/iQpFyIxbvIIr84gKoJlQaOtrwIEk7JRJFku5CrXVm
	JRG+FF2CNpZTMMVYqm1ug8pZ3d/9QzRF4uXJqgUjkzj0yIagE/q9
X-Google-Smtp-Source: AGHT+IH6abHAd0EDSa6fM+uKhQeFOquMQbvlETQbfEg5oaggnoAHekMZWSiAkYnRjmmHeCZLc7N1eA==
X-Received: by 2002:a05:600c:3d0e:b0:426:5c81:2538 with SMTP id 5b1f17b1804b1-42abd21551dmr923105e9.14.1724175492980;
        Tue, 20 Aug 2024 10:38:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c88:b0:427:9669:d780 with SMTP id
 5b1f17b1804b1-429e227d38bls12349915e9.0.-pod-prod-05-eu; Tue, 20 Aug 2024
 10:38:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAlxQQ/UDxnC3Vxcu3azVaCXNxu4UnaEbNzPFSpOxieWdzLD4ihcRFVPGvPPdvrlfLrFcb5HV3nYiBcVZpBob1zJh9diqd7IySyw==
X-Received: by 2002:a05:600c:5106:b0:426:59fe:ac27 with SMTP id 5b1f17b1804b1-42abd2466a3mr925755e9.26.1724175491001;
        Tue, 20 Aug 2024 10:38:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724175490; cv=none;
        d=google.com; s=arc-20240605;
        b=gET0zIeHVhF4j5fycFeSF9EAaBy7OkO9iWBzetCIxsv2Ny5RMVp7ozqPgei3aq+Dep
         ZNPG/GpVqOJ2u1VIF6mPgsog4dBPq02+OJtPZxucYMmLnjSaLiNDuk1v+MRUcUWVfc5V
         dDX6lZ7YgeFucTbMHjdu3OjxILDSKi6JWQIPviCf+wYyaGLPtX9yJhS87LQTaAGWqjAe
         ck+5606R23TbTIIzIWn0HkVDUEua1tx7VhKPy8zdrXILpvc0QsWM01toIAyLFUayw1R9
         COAW7RPPFa1MVAsoD4s5p1MKyQ3aMEYbOydcSD2smbqZ/2GzpNxxkYHgvN2UXANDM63Z
         Odyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uex0Zu5XeJjzbTzovpQP7F+VLtXX34oK2fmnyZ8I8+g=;
        fh=eDHl/qYxb7ARuc19wlnOdKrC6cwNpdC9xztRp8HPPiw=;
        b=JRiXUpVTvlDubr1WpWFp/siUm6cMmlo2aABU6CDXJiNXbnr2U5uP6XS0nQNyH75gJ1
         A7MT91Iujq/2Ct3kwDGxrz+dDh/9aCWJUlgI73I3Q8PjyIaJ6P9PLFSL42EAksyaFo1x
         gFimzYFUPIog6aZawVBWD9SiWMF78pIhpssJt+Fgdrx3QwzwYguh3xM3+MV30L5FQ6nR
         PpAFTvAibaZ8LwHds2PnfJEyEKE5dDRAqQEmw6sN4f+P4PSGCyWwilZMqyCqCqYOYEGh
         nYrue9gExWgm+ks0EtWvWxHRxIHgGklCQoxFLd/YtyBgMzIbji3eYnoBwx9xO4Ecnnxe
         2YgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=X4n5Pcm3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42ab87f8fc3si1088715e9.1.2024.08.20.10.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 10:38:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-37198a6da58so3434625f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 10:38:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9KWUVvlKlqmzmZ7I767QCQ+xHklk6vfMPhxZ0Bz7ct0x7JbYhh9BN8EmMmu0XV53e8Evik2bD/17aN9lec+tuWtRPts2esgZJuw==
X-Received: by 2002:adf:e907:0:b0:371:8e24:1191 with SMTP id
 ffacd0b85a97d-371946a4455mr11698109f8f.53.1724175490194; Tue, 20 Aug 2024
 10:38:10 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <20240819213534.4080408-5-mmaurer@google.com>
In-Reply-To: <20240819213534.4080408-5-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 19:37:59 +0200
Message-ID: <CA+fCnZc9XeNTuD9nVVDqrF_1W1Vv26SVEwu1bCQ2usqfSPpiOw@mail.gmail.com>
Subject: Re: [PATCH v3 4/4] kasan: rust: Add KASAN smoke test via UAF
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, aliceryhl@google.com, 
	samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=X4n5Pcm3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
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

On Mon, Aug 19, 2024 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.com=
> wrote:
>
> Adds a smoke test to ensure that KASAN in Rust is actually detecting a
> Rust-native UAF. There is significant room to expand this test suite,
> but this will at least ensure that flags are having the intended effect.
>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  mm/kasan/Makefile                         |  9 ++++++++-
>  mm/kasan/kasan.h                          |  1 +
>  mm/kasan/{kasan_test.c =3D> kasan_test_c.c} | 11 +++++++++++
>  mm/kasan/kasan_test_rust.rs               | 19 +++++++++++++++++++
>  4 files changed, 39 insertions(+), 1 deletion(-)
>  rename mm/kasan/{kasan_test.c =3D> kasan_test_c.c} (99%)
>  create mode 100644 mm/kasan/kasan_test_rust.rs
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7634dd2a6128..d718b0f72009 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -44,7 +44,8 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
>  CFLAGS_KASAN_TEST +=3D -fno-builtin
>  endif
>
> -CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> +CFLAGS_kasan_test_c.o :=3D $(CFLAGS_KASAN_TEST)
> +RUSTFLAGS_kasan_test_rust.o :=3D $(RUSTFLAGS_KASAN)
>  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
>
>  obj-y :=3D common.o report.o
> @@ -54,3 +55,9 @@ obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o report_sw_tags.=
o shadow.o sw_tags.o tags.o
>
>  obj-$(CONFIG_KASAN_KUNIT_TEST) +=3D kasan_test.o
>  obj-$(CONFIG_KASAN_MODULE_TEST) +=3D kasan_test_module.o
> +
> +kasan_test-objs :=3D kasan_test_c.o
> +
> +ifdef CONFIG_RUST
> +kasan_test-objs +=3D kasan_test_rust.o
> +endif

Let's put the kasan_test-objs directives before
obj-$(CONFIG_KASAN_KUNIT_TEST): they come first logically.

Also, I wonder, if something like kasan_test-objs-$(CONFIG_RUST) +=3D
kasan_test_rust.o would work to make this shorter?

> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index fb2b9ac0659a..e5205746cc85 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -566,6 +566,7 @@ static inline void kasan_kunit_test_suite_end(void) {=
 }
>
>  bool kasan_save_enable_multi_shot(void);
>  void kasan_restore_multi_shot(bool enabled);
> +char kasan_test_rust_uaf(void);

You need ifdef CONFIG_RUST checks here and an empty definition when
!CONFIG_RUST.

Please build-test and run the KASAN test suite without CONFIG_RUST
before sending the patches.

Also, I think it's better to put this declaration next to
kasan_kunit_test_suite_end: CONFIG_KASAN_MODULE_TEST is not tied to
the added KASAN test.

>
>  #endif
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test_c.c
> similarity index 99%
> rename from mm/kasan/kasan_test.c
> rename to mm/kasan/kasan_test_c.c
> index 7b32be2a3cf0..3a81e85a083f 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1899,6 +1899,16 @@ static void match_all_mem_tag(struct kunit *test)
>         kfree(ptr);
>  }
>
> +/*
> + * Check that Rust performing a use-after-free using `unsafe` is detecte=
d.
> + * This is a smoke test to make sure that Rust is being sanitized proper=
ly.
> + */
> +static void rust_uaf(struct kunit *test)
> +{

KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_RUST);


> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
> +}
> +
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -1971,6 +1981,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> +       KUNIT_CASE(rust_uaf),
>         {}
>  };
>
> diff --git a/mm/kasan/kasan_test_rust.rs b/mm/kasan/kasan_test_rust.rs
> new file mode 100644
> index 000000000000..7239303b232c
> --- /dev/null
> +++ b/mm/kasan/kasan_test_rust.rs
> @@ -0,0 +1,19 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +//! Helper crate for KASAN testing
> +//! Provides behavior to check the sanitization of Rust code.
> +use kernel::prelude::*;
> +use core::ptr::addr_of_mut;
> +
> +/// Trivial UAF - allocate a big vector, grab a pointer partway through,
> +/// drop the vector, and touch it.
> +#[no_mangle]
> +pub extern "C" fn kasan_test_rust_uaf() -> u8 {
> +    let mut v: Vec<u8> =3D Vec::new();
> +    for _ in 0..4096 {
> +        v.push(0x42, GFP_KERNEL).unwrap();
> +    }
> +    let ptr: *mut u8 =3D addr_of_mut!(v[2048]);
> +    drop(v);
> +    unsafe { *ptr }
> +}
> --
> 2.46.0.184.g6999bdac58-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc9XeNTuD9nVVDqrF_1W1Vv26SVEwu1bCQ2usqfSPpiOw%40mail.gmai=
l.com.
