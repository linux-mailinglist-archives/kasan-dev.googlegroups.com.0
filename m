Return-Path: <kasan-dev+bncBDW2JDUY5AORBBGI562QMGQEFN4OOKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id D5D0C950FEE
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 00:53:57 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-52f0108a53dsf7783591e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 15:53:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723589637; cv=pass;
        d=google.com; s=arc-20160816;
        b=TY5aUHzQI0FnLORvRnaYg+n+p1yI656fTazd6bs/atclNE3bBNnQ9Wz8pAuT8r3RaS
         CXFjU3ay5TNXJBcayPA3UFLPkA8de3B5KWegWxzizIRSL6vU/Sud9pQiHSijX2JJ1WL/
         WrFi6iBQVdEkJUjtBGH+VgqhGuAgMXnu3SxpoNuNeSPPKL56TK3Rgq752PrYRypjvH5Y
         uwtwfAzxpiKjFfdGFeIH0uunJPUs8njh64dEaGSm8DDO2m9MZMuYkCYaOaW2gcaak1Xd
         mQScKi9/U02tnmTg038vkDJsEaxZkDx/0ubldjzeFbyIbyqFa/1BsmYZZXYXdbMaNVhk
         hG2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=99pbf6n2xrHlwDA338QfGO6wpGbwlgZi0Jjj8/7oF+8=;
        fh=+LfInMCIoEIl47NCeSpwepick1E0GrEn3worFtutSyg=;
        b=0l2xpWIbe3xuKVLF+woB4ZVcXVj93yvrqPGzWjBf3qJnL6XL0FspocVCJLPYi0BMBf
         KrXIveirmsm8wKgJFCDiBFOe57Pi2l8h5z06z4Yb7I0pKvgVlxjaGFnsL/bqEeAMP3jO
         lqs/kWuwJVD2dEsB4ufDSUTQcWuzpB1rfQw/9P4rp1S9WuyLELnQDAzYxJ4kkJTmeBPz
         do4JTTBxPmUntmJeKjkNpwUrCWAguK/vNaN5yFRqD4FL+cVeOuq9D4EgRpq7U0K3UCso
         0z3C3LMo4kmGmVg0+oTE4cCyN+v4/cq9dutYipx3AvLFqRcZyfilPCXqnzq1sqziKGIc
         ynQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AWpgZIeX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723589637; x=1724194437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=99pbf6n2xrHlwDA338QfGO6wpGbwlgZi0Jjj8/7oF+8=;
        b=NofzW47gn4TqyhG5PfHHfGc15pMMjMOgymODQ3Enl0TrX5jAPAk1bq3A+NADSE/ZOw
         +EVy6Y5wU8ua2JRFB2qh47YVCm7/rcR7F3H6ER6mqzssE7RlaZlM0pN/LY5/MEtYK8yO
         EH99sMSOsOdXCbKC6M8YTi8QWtmvVAfxGNpTfhslEQaWJ5sc04c1HHzZkWt4vsU6lasQ
         KxoEEkR0FNoVqXoZZwqwhH3N5Hv/AdKT7ttkadWLgko5dXdG0dWOMWSZuYtDjPcGYJAc
         qnu2yJKjbH9TgruxRoprm/bF5Z4ON30jXIeFvMg+9T61xulMCT41B/NwTOtfvOpky1n0
         QkrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723589637; x=1724194437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=99pbf6n2xrHlwDA338QfGO6wpGbwlgZi0Jjj8/7oF+8=;
        b=maW7nFk/MxGf5grq3WZ/JDW5oihs3EV0I0JShpo1Iy7puecbBp1jaHoQK4mo2a/Szc
         nrdg9OhUPlRL7Qt5yMkoRMh6sOQVDQfcpCzWGn0SC3q3k0fp1mmfNq+av2ksu+Oof0Hs
         KJIN8FUPdgoMDo9sepwIE+3ibAT2164LULZzpE/hkvUcYCNJCPojq56VB5Eo/DLfm6On
         ZuAhLkw76/Wv0/vQWPjt7pNmTnP/6RolaQ12U7mvNMZHsOH7p0gGMW1wubs3X49PWB88
         MpaK52BWTq6wEI6MXQsjGR7+0GR2zokiJuyLgimEIe+Ink6eGS7T8SFNWtZJD3Y102cx
         N8BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723589637; x=1724194437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=99pbf6n2xrHlwDA338QfGO6wpGbwlgZi0Jjj8/7oF+8=;
        b=ouQMuOU7gmaGWSxF7hEnxOzzDj67B790kyV4UXSu8mZmobkdt+KVV8v+W60gzlkfgD
         IEY/ro7H7hT4xHQpTsW/xdY5pPRfbdRUR1AcWUuiouWHtUNACiTFfUWlIC4Cfgqo/Y2O
         oQ7bkTiu7m5ZESeL4Tr1XjCBm7oh/M75HQV+/UO03XEkDaCTygDlPnMyDd+yw3CDqVoj
         5pKl51YmUtrF+c3fnCqNP3vxIpUdNo11Bgje7PZETIc+LBmjHqHbiJd2LXnpCgSPtfvv
         iJ9BkYMtb5AfOFSKBbWtrlQGc0ZSLrdN2tL+qySDolO1DVRUMQOMynpHrB3j4ENYyAE9
         cONA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXi98N9NabpvDIl9N62cc/En7nDQ+jiuMlWNIKTqgDA5xWbeFiKoZA9kUB8MF0XC1e7m5PETugUxmXkgsedKhrD44CfGV+W9g==
X-Gm-Message-State: AOJu0Yz6ZP7/HlGSTuUoN+mMUNHD0WU/Jq3zFkV3+PTTXekVBPAs4YEw
	R+cl3Yab/gd6J02OK4alkx96vEJLnc2vio1G/I51N84Bq5FTQMcq
X-Google-Smtp-Source: AGHT+IEfgMj1iMNxU4ILozDqepzUtbi2MioIPgsLXyGSFkzjg4XBCysA02wj3BxddwD9IMrY8Y3xDg==
X-Received: by 2002:a05:6512:280a:b0:52c:9468:c991 with SMTP id 2adb3069b0e04-532eda6d284mr488429e87.14.1723589636592;
        Tue, 13 Aug 2024 15:53:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e27:b0:52f:186:fddd with SMTP id
 2adb3069b0e04-530e3a14f67ls2260818e87.2.-pod-prod-06-eu; Tue, 13 Aug 2024
 15:53:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUD1EYh3R7qG77jqbe0b1WHj+Q3U+sLEDuOnj9Yi5UR55Y60y9xDHVXGq7S3vPzKFUJRqyDaZszAmydDV3yHxHdXHjCB0FrrKZE5A==
X-Received: by 2002:ac2:4c48:0:b0:52d:8356:f6b9 with SMTP id 2adb3069b0e04-532edbacfe5mr416202e87.38.1723589634301;
        Tue, 13 Aug 2024 15:53:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723589634; cv=none;
        d=google.com; s=arc-20160816;
        b=XW8Z9kNSfcDMye+i5trGWu8amRcOj2z0WKcm5jr4Qz2r1jD8iTqKbmmQW9gnBk0zrZ
         HUzrUB6Pv8RncMiFo2jWK/TkKBWeAObWazaTSjBvGd1DQTherOWpcqYIxcEIHSvQgccK
         RX9qSJTmkCp/hFxPQYzH9lkHaiafIAjvaHscp/W8305jtxkAW5SVhpgEmx3F5oZxEPUR
         WQ7JeIqVpVzBLfdZ+SPhZstSN9+P77oQ9tZKQbiXI7CcU6t8VsjX/ac3DcTasBHSyvOR
         KNLjSQS4/P9yalgMEhVCb/pVOWL/JCoDwHwBNlVpreyGVt+ks3/nvYKS4rKQFa+VdThx
         6/vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4cttOyHmXr3Ka8gJTh+VvrIxgAB9wJeCTQuXopG67ZQ=;
        fh=eT/dmDya2MISiJ8CMfnVCSEXMBigJG3IX4+Qf9QKWa8=;
        b=dHy2KEBLSsrWx6XVH7HdF/7+J4e6+U7MvijndXzBbtyPEzb72ihBZVzSHExGGeMF5r
         BfT+18YP2zYwnqaO4v++um7QcvfYraqa6mEfqwtvXLdgUt3XAeYwR3X/yAGE31nFo8uH
         MoHyPQ4sfrPt7t77h0QzrcxvlcJe30BT/qfFXqhmWompK2BcDQ8hOL0V9OKWweK3KAKs
         YW5mTJuHbqbJ4pCA/ek3ysrCuZPYcQjt1wtpdH+UD3QpyPnAhJ+TlUptb2cTxlDg961R
         Tj+nlAlrgT5/M+zYzv9aKj9jRCGn6fJuVkbdtb7+mSkQWKNejrEYKd3d9YEkaVd0pst2
         vRlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AWpgZIeX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200e91918si162356e87.2.2024.08.13.15.53.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 15:53:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3685a564bafso2733513f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2024 15:53:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVfXWxSxuToD39u6C/zmADTZlGDq7W9nlZJIwOAV/CugaHKKykdzD4SHL+qGQslI1zHX2b/kUydEiAELFpaGo8b5/cQVd5DCySfmg==
X-Received: by 2002:a5d:5223:0:b0:367:99d8:70 with SMTP id ffacd0b85a97d-3717782761emr565874f8f.61.1723589633180;
 Tue, 13 Aug 2024 15:53:53 -0700 (PDT)
MIME-Version: 1.0
References: <20240812232910.2026387-1-mmaurer@google.com> <20240812232910.2026387-4-mmaurer@google.com>
In-Reply-To: <20240812232910.2026387-4-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 00:53:42 +0200
Message-ID: <CA+fCnZfWpCsW-mkKLc55+cRoBQJTeB1ecuown45zchRneNFLhg@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] kasan: rust: Add KASAN smoke test via UAF
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, aliceryhl@google.com, 
	samitolvanen@google.com, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AWpgZIeX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Tue, Aug 13, 2024 at 1:29=E2=80=AFAM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Adds a smoke test to ensure that KASAN in Rust is actually detecting a
> Rust-native UAF. There is significant room to expand this test suite,
> but this will at least ensure that flags are having the intended effect.
>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  mm/kasan/Makefile                         |  9 ++++++++-
>  mm/kasan/{kasan_test.c =3D> kasan_test_c.c} | 13 +++++++++++++
>  mm/kasan/kasan_test_rust.rs               | 17 +++++++++++++++++
>  3 files changed, 38 insertions(+), 1 deletion(-)
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

Let's keep the kasan_test.c name for the C tests to avoid changing the
module name. Naming Rust tests as kasan_test_rust.rs seems to be
sufficient.

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
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test_c.c
> similarity index 99%
> rename from mm/kasan/kasan_test.c
> rename to mm/kasan/kasan_test_c.c
> index 7b32be2a3cf0..28821c90840e 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -30,6 +30,7 @@
>  #include <asm/page.h>
>
>  #include "kasan.h"
> +#include "kasan_test_rust.h"

You forgot to include this file into the patch.

But I don't think you even need to create a new include file: just put
the new test function's declaration to kasan.h next to the other
test-related functions (e.g. after the part with
kasan_restore_multi_shot).

>
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANUL=
E_SIZE)
>
> @@ -1899,6 +1900,17 @@ static void match_all_mem_tag(struct kunit *test)
>         kfree(ptr);
>  }
>
> +/*
> + * Check that Rust performing a uaf using `unsafe` is detected.

uaf -> use-after-free or UAF

> + * This is an undirected smoke test to make sure that Rust is being sani=
tized
> + * appropriately.

What is an undirected test? Let's drop this word, it is confusing.


> + */
> +static void rust_uaf(struct kunit *test)
> +{
> +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
> +}
> +
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -1971,6 +1983,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
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
> index 000000000000..6f4b43ea488c
> --- /dev/null
> +++ b/mm/kasan/kasan_test_rust.rs
> @@ -0,0 +1,17 @@
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
> 2.46.0.76.ge559c4bf1a-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfWpCsW-mkKLc55%2BcRoBQJTeB1ecuown45zchRneNFLhg%40mail.gm=
ail.com.
