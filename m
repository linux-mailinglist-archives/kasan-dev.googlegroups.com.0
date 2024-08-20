Return-Path: <kasan-dev+bncBDW2JDUY5AORBLPKSO3AMGQETE24YZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C50E958EF1
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:57:34 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3718c0b4905sf2626750f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:57:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724183854; cv=pass;
        d=google.com; s=arc-20240605;
        b=IG7xILZM5HW9dORieR20UKjkYR2r8hka3HsWKMpfbZUYegkeFKav5ZvR0Wn9kY0wd3
         PaW8fMDxtzu1UJgfoB9KMbdXhN2ZfnlOj85a6L/Lbn45aHhXcV4OZYpZY8V1zZSVzAF0
         7y8e412cKs9zv5u+qYek8dnzPU0vRD/Yo4oFp5YgFSyfZ5fslX5q9P/0Ufsh7KKj7q6p
         KpSX1rFa3qiXvpbqc+lNffruPwyEI2PlPfdHzYMWmEDc4gZVie2nBYSmKLpmLKJH1fsl
         mXqnELsxmgR9feN89djWzwE2cASczMaKwqMeUqGRGGGY7ya36MPMxh434AQ24L0jfFKi
         AX3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9AKvRhkO1lb6CGvveqFCTtE07b4l00fg4yJeBATuKRk=;
        fh=ZqUPJh+rXHj9U3kUU40eFnIxk1IhBN/AiOsE343knVw=;
        b=iXZvTdOX0V4jnvex5aTdL4ssWSRGpj/DbwthBmehoHFH1KTqdhE3i6HwQg8u50e3jP
         PaHarS5WKXq2joQeX4GT0zazkOJGP5cJmySHCd0C6hjN5FQ0lEpW2wYQCBXVsqP+sLr1
         GzsacWuBLbKD6LcFXlumOfJPrgXI9fIcZ1varnXDEVmbwaKP7Ipaw8Awc6QhwFRnvO8P
         3LIER7rekHV0gOpzZxZa/opRINSE6N8RHj5sjFnp1r5fUVriq3mKpTq0OQlXpVD3EqJZ
         X9rpSuqF35PcxD/Qhv9BEbkHmcSDk6LY/ZHnGFRYCNxQV4mu9XDQjLNNoa4kjzizoe9c
         3atA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ddp3WqCi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724183854; x=1724788654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9AKvRhkO1lb6CGvveqFCTtE07b4l00fg4yJeBATuKRk=;
        b=mshKmUtAPNJpUOBPKb/JH1/Dg+yHttvnRR24ZWaF3Sg6l0qZQha26E25zQEj8xjYH3
         H8F9ylEbVmPxuvN9ZwCP4/q9UCSDgqnJBNp1BK/cAgSxnlhkJbWzhEckbcsmAzKHL/Zv
         SyMs+/DX2BUdcEGakbUibyh1R57oh8MqNXbnBdMcqTMFLAy7K/pT9uVIazHuorDGVf8f
         iAtcinzI8BhpJkGgRDlb4Hvtp3S/HMoMnn2fIVi9Je+pRdNdzubVk06ZhjOnieQenTW4
         ncZ0tZp9KNGj/M3wlBBxvRpvGxDjDJxRV2lLWhnYickujABGJ6njNjci0Bycje5VIqIg
         UVIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724183854; x=1724788654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9AKvRhkO1lb6CGvveqFCTtE07b4l00fg4yJeBATuKRk=;
        b=H4eqGX5RZrzqRe+IB2XQxLxZGA7UQ3RpXtayQJwniyukqYR1U7St0Kk40PgnIemFpr
         W7d6zxwxd0Su1EIBCAwxo1JGoTTz/h5vWuRXHTvDgKI+fVP1l/yIafMwt4vvc77u/F/m
         W197cDi1ctFCtQ25XhB8+SxKl7DkfoqLzEotoB2gr7UHQmRWr4BSwpryprPk1oE8t/G6
         PtJvMStapVC6VFkdreHNF0koWw6Q/1CCj9nzBmwcOfg84WUax46LxnXIOLrBUAsl1kSR
         USNXiUVrtgAen9hAFvo6/GpKIGJtSFi2+YS1DvqXmIUVAIepi0f0vR5AACz9KqkBXReM
         igJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724183854; x=1724788654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9AKvRhkO1lb6CGvveqFCTtE07b4l00fg4yJeBATuKRk=;
        b=uYSPWq/bUz81IgtPgtY+ltDBCnS4MnfZjjmVYmPRdb5AaUdhS/8Vc3fYdqz+n99LcT
         0T0geXK+jBVKuXE9PTYkmZxcyFBu11aFoRpNcSnJFvoB+U9Bbaw3njCvyBDy9MdJZfr0
         qIMe4+qQnEGUTlzqonbzM1EHiQLRamMWnayj2szZdtVS/FEWF7xCalXz/BEFULr0ZbbQ
         yVort89ep1jyoP64X5o9vYKbZLT8DXF+wOOzS5GFpsCuSQObv1oMfGBdbgHx6coxVb51
         bOvBx7W929tJS8jRUE6N5ssnJ158ZWN4LzYs/H7VlhMIZ0mVI5xrM/HO7OXuZfXkac/b
         nmGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW028eB27Vmsgd6glOD1OB9AWBjgcRU7Ssm5NIumBwbXdH42hajB24Z3bjPD3/tueMBsDN+TA==@lfdr.de
X-Gm-Message-State: AOJu0Yzo7ILbExmOVhQDM7hTuh4vaVO+TTnO0nQhZPjCPkvGqA1/RD0B
	gsk/4Y7ZK7F8ue0X/wj88XFbJ39gLLseKezfzXXWx16O3yoZzymY
X-Google-Smtp-Source: AGHT+IGrRRAv9/DOJ30hnKp0SIW0ogVR7gaAmOdG4xNQU7prT5mIivlmqL60DQVqVeRiiyLsW3WLOQ==
X-Received: by 2002:adf:fe90:0:b0:371:7e46:68cb with SMTP id ffacd0b85a97d-372fd713099mr35767f8f.50.1724183853371;
        Tue, 20 Aug 2024 12:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3152:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-429e22786f0ls4730755e9.0.-pod-prod-02-eu; Tue, 20 Aug 2024
 12:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFZDbtelkRkE6Y2t5jDSK6SC1C+vE2RsTvEOohNUCryOAfPWjRc5yEYDeUlM8OxzOyPpsZMyuhPLA=@googlegroups.com
X-Received: by 2002:a05:6000:4593:b0:368:7583:54c7 with SMTP id ffacd0b85a97d-372fd576901mr59866f8f.8.1724183851599;
        Tue, 20 Aug 2024 12:57:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724183851; cv=none;
        d=google.com; s=arc-20160816;
        b=S1/nIlXA7iM80UEswWfYmADKxKlh9RYnaA+q3UUqAdKeyWbPbHfnk3L5jYg86qN93n
         jPispGypUFRUoCiuX0oXd82onb2/TLdoLx201zfEz0lIs/HGJqadFBb8y7lTIP6eWj8I
         K0xnYZ87x8xdUAb7RMMT8oUO91TfXuS2K7NKnUkjb8+SzoWc0i/PBEWlfgypYgw++Vzu
         MvCq/YRnTdTYOmLQ5slsn7r4TscRyIw+2QqNlqTqCN9yEVenIxJTtKEirjdeRjIeL4VQ
         peCc3TTEWKGUR/yumHWXzjocGtfmEoV6nU5+69oVoOlrp3SkfzERW7QASLs2D3lMtpzX
         zRfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UaL9zj6zB1sI38i5Boy36u4I8G4LxBoHczpTGYKeAio=;
        fh=83hrNg2EYGzSLOOaIc0h5V9DWdRnhPc35Bzp0k1Ly/E=;
        b=I5/GXztyoGwBk8MDcKwfhwYdar7uDkNMhpi1r6n0yZfQ5JMo1+5q6YLuLgmiFQdj4V
         OnlBN/JkxZucoAY2jvY1jGOTrkNmQ+bIR5obVXU8fAXblYrLNm5lukMVdjYY2Trw+CmL
         R5HNthR6HdCtnDGeGOx14jtIPb6TnB88QrEKhqGdWftw7XVYBBVZjj0U7XIDu04e1bih
         rIuiT10e09b17w2C6VIZHsBjOYXkzNySmo3VjkbbB4X2WPIG+gQZUZpkpcr+00+L392M
         hrcc8qFPbs7Y0BqpaFLbSTb/xrT1BhNzG6Ana3grXI4dz+O5yZfiuliwnbw8MqKAikuc
         PpOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ddp3WqCi;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-371893b76cbsi474111f8f.0.2024.08.20.12.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 12:57:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3717ff2358eso3194582f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 12:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqr3Iewz3IBOTp0QbN/riC2PUepnbMHWwErtFRBLKPNVN24NuRNmUV43k+tcyKb2pkwmBb7/n+Z78=@googlegroups.com
X-Received: by 2002:a5d:474d:0:b0:367:980a:6af with SMTP id
 ffacd0b85a97d-372fd727b4amr37670f8f.59.1724183850741; Tue, 20 Aug 2024
 12:57:30 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com> <20240820194910.187826-5-mmaurer@google.com>
In-Reply-To: <20240820194910.187826-5-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 21:57:18 +0200
Message-ID: <CA+fCnZdCqt=eN6vWJ93K8dK8yO_ThV=pcaYT=a92XqUYdReuUg@mail.gmail.com>
Subject: Re: [PATCH v4 4/4] kasan: rust: Add KASAN smoke test via UAF
To: Matthew Maurer <mmaurer@google.com>
Cc: ojeda@kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, dvyukov@google.com, aliceryhl@google.com, 
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
 header.i=@gmail.com header.s=20230601 header.b=Ddp3WqCi;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
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

On Tue, Aug 20, 2024 at 9:49=E2=80=AFPM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Adds a smoke test to ensure that KASAN in Rust is actually detecting a
> Rust-native UAF. There is significant room to expand this test suite,
> but this will at least ensure that flags are having the intended effect.
>
> The rename from kasan_test.c to kasan_test_c.c is in order to allow the
> single kasan_test.ko test suite to contain both a .o file produced
> by the C compiler and one produced by rustc.
>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  mm/kasan/Makefile                         |  7 ++++++-
>  mm/kasan/kasan.h                          |  6 ++++++
>  mm/kasan/{kasan_test.c =3D> kasan_test_c.c} | 12 ++++++++++++
>  mm/kasan/kasan_test_rust.rs               | 19 +++++++++++++++++++
>  4 files changed, 43 insertions(+), 1 deletion(-)
>  rename mm/kasan/{kasan_test.c =3D> kasan_test_c.c} (99%)
>  create mode 100644 mm/kasan/kasan_test_rust.rs
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7634dd2a6128..13059d9ee13c 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -44,13 +44,18 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
>  CFLAGS_KASAN_TEST +=3D -fno-builtin
>  endif
>
> -CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> +CFLAGS_kasan_test_c.o :=3D $(CFLAGS_KASAN_TEST)
> +RUSTFLAGS_kasan_test_rust.o :=3D $(RUSTFLAGS_KASAN)
>  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
>
>  obj-y :=3D common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o shado=
w.o quarantine.o
>  obj-$(CONFIG_KASAN_HW_TAGS) +=3D hw_tags.o report_hw_tags.o tags.o repor=
t_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o report_sw_tags.o shadow.o sw_tag=
s.o tags.o report_tags.o

Nit: empty line here.

> +kasan_test-objs :=3D kasan_test_c.o
> +ifdef CONFIG_RUST
> +       kasan_test-objs +=3D kasan_test_rust.o
> +endif
>
>  obj-$(CONFIG_KASAN_KUNIT_TEST) +=3D kasan_test.o
>  obj-$(CONFIG_KASAN_MODULE_TEST) +=3D kasan_test_module.o
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index fb2b9ac0659a..f438a6cdc964 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -555,6 +555,12 @@ static inline bool kasan_arch_is_ready(void)       {=
 return true; }
>  void kasan_kunit_test_suite_start(void);
>  void kasan_kunit_test_suite_end(void);
>
> +#ifdef CONFIG_RUST
> +char kasan_test_rust_uaf(void);
> +#else
> +static inline char kasan_test_rust_uaf(void) { return '\0'; }
> +#endif
> +
>  #else /* CONFIG_KASAN_KUNIT_TEST */
>
>  static inline void kasan_kunit_test_suite_start(void) { }
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test_c.c
> similarity index 99%
> rename from mm/kasan/kasan_test.c
> rename to mm/kasan/kasan_test_c.c
> index 7b32be2a3cf0..dd3d2a1e3145 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1899,6 +1899,17 @@ static void match_all_mem_tag(struct kunit *test)
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
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_RUST);
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
> +}
> +
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -1971,6 +1982,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
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
kasan-dev/CA%2BfCnZdCqt%3DeN6vWJ93K8dK8yO_ThV%3DpcaYT%3Da92XqUYdReuUg%40mai=
l.gmail.com.
