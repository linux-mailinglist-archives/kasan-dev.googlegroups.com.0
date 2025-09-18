Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJVIWDDAMGQESALO47Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 983C8B851E8
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:16:08 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-792f273fd58sf14508406d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204967; cv=pass;
        d=google.com; s=arc-20240605;
        b=fEpclGA379YjXJQR2BULgVxi77kj5UNF/MafOxFiEddDYOLX0+0GBSWzidnrmGC0PT
         JtcYHYb9464ffrOXuCJsFQ0EZKxHorjpEs3Hl7so99QJXkBCWR5NO77zV4k2ORW3MWc4
         4f2O4V0hczYn4dJPjsSiAZPcJoaz1tcC3WRLSaSxceZ/PFLis55CxlTmMKy++Js73YUw
         F0si2k7n0Cz4NtYjdhLLsQo3Oi2uviQUl9yINvaDWHbx4eWV8yGMFWsRd2beccgoXQKD
         hlxOZhvnZ/CqFqWw8Ra48taSh64B5QZ2iUYVM2vCkU5pRoR1PMMN4D/vUtXrYSJ1NJJp
         MDvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cq3wmgCeh4DPrelaK+CRtiFYpkZwPKOGsNqph3Ikq7I=;
        fh=uZNyzyRHJVp2J6Jirs1ncTXHzUUCTOBokB37CWdHOSE=;
        b=evVJrOPh77VpNaRJiKusMdrermVlF9xW5qySs05n3ZijF5Db02AGo6NaWyhL95/GaZ
         L7xTSwbvChS/FY/NEe8IXZDMtmr9GZEZZf+lX8GzpUhd0SIvrXACB7ub6apwBLt6Bn0c
         /LiFqXUTuaV1XnRWahmsuxppZFCCq4eTg5pOXC4FV4oRY+Tm8QlV8/UEvJnxBJeozF+0
         qLj6ykbuq4gJch+TBkH6rhMDX03+23Q0tCPzqay7Eaui6lbrACtvTNYqTcXazXTEJ0Za
         yfnzDACNbHHnixtPHkRWMFpkId9FwuYVsyQxUzOFg0z02HOd4aclHc/cBdn2jtW5U06m
         3ROA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aRFfF4wW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204967; x=1758809767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cq3wmgCeh4DPrelaK+CRtiFYpkZwPKOGsNqph3Ikq7I=;
        b=LkX51n5boqHBxqBbES4GecIkYD7r6kYuDXYRnfIByD8thSDudSGtiXbdwS1indJeC2
         5HM92kdGmmptwoaXAcTF+DwVLm8xklDAqoCTnHyip3dyZb0JHVIuX6GOHI5lAG4EIgSs
         zLYfgQcWCNEX5kndpAUMeFvrxLylxEFRi7VPuQl0O3QkLxaz7jKt23uMPun6C/b6Vu6K
         ZFHvzwbwYv0tZl1yJnL+HswPdVc4v9chbHjP7GsIW8s3OiOjETmHsv6d2JZ3A37BNe00
         uRWjz+N7DCCrtW2Sk+rY51rYei5G5JfpQxPXYR//lKP7sW7O6/wCYyZrI7vligateNwX
         qo0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204967; x=1758809767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cq3wmgCeh4DPrelaK+CRtiFYpkZwPKOGsNqph3Ikq7I=;
        b=dhOWyH6cE0Q+LzoMU7N7Kasli6au6GMNlrr4rve4OAGx+NyN0SmizQuGomjImtFssX
         wWLHaO84dhOSiiiU3UL70JUJUtNLZw9k8kaY5+bosacW12lGuwmJyuFPc6si4MmtbsCg
         8cRhlEO4wC7rPSORNIv9+sBkLgjplsLOxYRoOg7CDR4VxSj0vQ4AfHuNW1bOUyZ5uqNw
         z2bjc+ZlEyOGctWJJWPHb9O/perXpH5pNxTpJbzyj743h/DJ4BjBqVzwYBd0BY6JAjzf
         ha+Y601MOM5KlecxxrSj1exVnwONxKojC0HM5RNULiAtSJwlQsT+4a4U4y+JTOakL6hg
         iB8w==
X-Forwarded-Encrypted: i=2; AJvYcCWVmjB2mpi1F/jlSZB3SfDw44RSCnVr7IYOtD6edtYjtQv1rQCKSD2woqMJeEzQ9Vz7AI4Rvg==@lfdr.de
X-Gm-Message-State: AOJu0YwVJWG8OB3uQt6mUlpYIwtIRlnQxIle7Vpn6weYZpCiI459rG99
	30FIXv4UrbDmGa+gOdB9BIyI8sUk1mLwTk7Wlh+0jYcUNGLlMynh4oqM
X-Google-Smtp-Source: AGHT+IElQFbn9/fGFuf6EZWruyUP4v5bGzzdyhPai0E8KgwCJlBe5auzmyfW8vVewLg85flN2Lkwbg==
X-Received: by 2002:a05:6214:21ee:b0:766:13cd:2988 with SMTP id 6a1803df08f44-78ecef1b1d9mr67426556d6.60.1758204966920;
        Thu, 18 Sep 2025 07:16:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5e9ZO/za63SW07i8A27Mi5DaCk422rh7GvLEHpOh+AKA==
Received: by 2002:a05:6214:2245:b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-7934da6748bls15653846d6.2.-pod-prod-01-us; Thu, 18 Sep 2025
 07:16:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxbYY6SeghZ9gQssk2KPAUha6t97akolsXoQ6kX2RtDATxPBwhRhtcww3+ubuA+pS86KlK7cpdg0A=@googlegroups.com
X-Received: by 2002:a05:6122:4591:b0:544:93b6:a096 with SMTP id 71dfb90a1353d-54a60a2cda8mr2112463e0c.8.1758204965522;
        Thu, 18 Sep 2025 07:16:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204965; cv=none;
        d=google.com; s=arc-20240605;
        b=OdlRhTVYo79vgKAcqDNGK2HsCatRp5tTKZWWqUZMZlxnHun8XcOUnqcSK135Lu4cWa
         I8PSxuJB7rPs36iGRwupJ+6TaOIE5GsYRH5XIbcPRLzhl1ZHKksVj/OXtQQha2W20e6A
         YwQRLrW8f6jQPNBz7FEgNua+rI3fBiku0K1VNIVMZriu70ai80AtNDSBBMDhckg2rtIe
         cHJHKKAAUsFgBnwXLphheiZuk6xv/UlA1H6R6wv0LKBkhqt8qPW7nPhgyT09VpDuf782
         WhE8qEg6Umm/uBxfk0TKV7dnQm/Bhy392Tvg5jsY3qgxktiJvghR67lrGn6sLVRrOvNN
         mjfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W1m9V0QnucGw1fYjnWnkHTlkfdmFSylGoU4nkl6jTtY=;
        fh=KowvN1UBugv2wTPfqT5n0w88a7Pm/EOm43EvOmshlVE=;
        b=QbYRyWqc04G4urromCHogfxFmNM6Wzj3cYPEuetQXFJXHbVRl4xPO3gjBwPCsrWmM8
         H9vxMXzJh8vUrrO5vGLuQDcKjGIqG3ybuJxeTmnEdDubUtfF7XuXDccom42VaFOZk2k5
         I2ndS2W2Ql9LEHryuQno7XqrEgR2y9rUz62VtNSf8PFyov5OdndU5BXo96bGBJ+YMw3h
         kGhTJ3kygFsDnMXOSK9e5FWSaAIs4zJr75tkLBMVEHpYD6fNa9Jr7oJlE9pzT2HY3vQB
         NPOui9IebzP1gyhP5upyswoL6tsLDDRcQWQ1w5d/iCGsF/BXfKxjMHB/GN/BcPmGrgDG
         bAiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aRFfF4wW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54a72974075si114844e0c.3.2025.09.18.07.16.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:16:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-78f30dac856so11905466d6.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:16:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVdi+7F31T7Ngp/Aw9bxNa4lKbLM2lyVYPTh5DSU+Sb2vOhxzkmiMM6RAZWFsy2gwa/i9kefaoTVRw=@googlegroups.com
X-Gm-Gg: ASbGncv450yI8TOZc/5DURqujIYmXIovROfmtS6mHz/Hb+7U/sE+BSwh1aAe4TsMjfd
	9PO1J+FabndcnUvN/V7FS9g9co63KStKV3iMKLB1JfpAVbpYDyaKQ/kzVEJNJbuxIVUEz7Nx2rZ
	arzDHitXahkonJ3tl9TIJhtIHEh/0BRCnkIeg5hcKjK0t+7Ad/5dIf3R4ZafR9T02nnxJNBItTF
	qy5xgZyGWpEHF3XMGdroSvO4HTjGmciVLD5bUwOCEm30H11ZEQWGP2/WZ1BaWA=
X-Received: by 2002:a05:6214:2aa5:b0:782:1086:f659 with SMTP id
 6a1803df08f44-78eccb0cae7mr65869736d6.26.1758204964157; Thu, 18 Sep 2025
 07:16:04 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Sep 2025 16:15:27 +0200
X-Gm-Features: AS18NWDFBwLJ1l73cBf4HqMXnx0YeCt1p-LK845oN4Qc3Ee7lXGT_Tt4s1Okcjk
Message-ID: <CAG_fn=Xkig71cn1xCUP1t=OLAbk+YYLsec0HhciROuiTD6AELg@mail.gmail.com>
Subject: Re: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ignat@cloudflare.com
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, jack@suse.cz, jannh@google.com, 
	johannes@sipsolutions.net, kasan-dev@googlegroups.com, kees@kernel.org, 
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aRFfF4wW;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 16, 2025 at 11:01=E2=80=AFAM Ethan Graham
<ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add KFuzzTest targets for pkcs7_parse_message, rsa_parse_pub_key, and
> rsa_parse_priv_key to serve as real-world examples of how the framework
> is used.
>
> These functions are ideal candidates for KFuzzTest as they perform
> complex parsing of user-controlled data but are not directly exposed at
> the syscall boundary. This makes them difficult to exercise with
> traditional fuzzing tools and showcases the primary strength of the
> KFuzzTest framework: providing an interface to fuzz internal functions.
>
> To validate the effectiveness of the framework on these new targets, we
> injected two artificial bugs and let syzkaller fuzz the targets in an
> attempt to catch them.
>
> The first of these was calling the asn1 decoder with an incorrect input
> from pkcs7_parse_message, like so:
>
> - ret =3D asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
> + ret =3D asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);
>
> The second was bug deeper inside of asn1_ber_decoder itself, like so:
>
> - for (len =3D 0; n > 0; n--)
> + for (len =3D 0; n >=3D 0; n--)
>
> syzkaller was able to trigger these bugs, and the associated KASAN
> slab-out-of-bounds reports, within seconds.
>
> The targets are defined within /lib/tests, alongside existing KUnit
> tests.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
>
> ---
> v3:
> - Change the fuzz target build to depend on CONFIG_KFUZZTEST=3Dy,
>   eliminating the need for a separate config option for each individual
>   file as suggested by Ignat Korchagin.
> - Remove KFUZZTEST_EXPECT_LE on the length of the `key` field inside of
>   the fuzz targets. A maximum length is now set inside of the core input
>   parsing logic.
> v2:
> - Move KFuzzTest targets outside of the source files into dedicated
>   _kfuzz.c files under /crypto/asymmetric_keys/tests/ as suggested by
>   Ignat Korchagin and Eric Biggers.
> ---
> ---
>  crypto/asymmetric_keys/Makefile               |  2 +
>  crypto/asymmetric_keys/tests/Makefile         |  2 +
>  crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 22 +++++++++++
>  .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 38 +++++++++++++++++++
>  4 files changed, 64 insertions(+)
>  create mode 100644 crypto/asymmetric_keys/tests/Makefile
>  create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
>  create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
>
> diff --git a/crypto/asymmetric_keys/Makefile b/crypto/asymmetric_keys/Mak=
efile
> index bc65d3b98dcb..77b825aee6b2 100644
> --- a/crypto/asymmetric_keys/Makefile
> +++ b/crypto/asymmetric_keys/Makefile
> @@ -67,6 +67,8 @@ obj-$(CONFIG_PKCS7_TEST_KEY) +=3D pkcs7_test_key.o
>  pkcs7_test_key-y :=3D \
>         pkcs7_key_type.o
>
> +obj-y +=3D tests/
> +
>  #
>  # Signed PE binary-wrapped key handling
>  #
> diff --git a/crypto/asymmetric_keys/tests/Makefile b/crypto/asymmetric_ke=
ys/tests/Makefile
> new file mode 100644
> index 000000000000..4ffe0bbe9530
> --- /dev/null
> +++ b/crypto/asymmetric_keys/tests/Makefile
> @@ -0,0 +1,2 @@
> +obj-$(CONFIG_KFUZZTEST) +=3D pkcs7_kfuzz.o
> +obj-$(CONFIG_KFUZZTEST) +=3D rsa_helper_kfuzz.o
> diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetr=
ic_keys/tests/pkcs7_kfuzz.c
> new file mode 100644
> index 000000000000..37e02ba517d8
> --- /dev/null
> +++ b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
> @@ -0,0 +1,22 @@
> +// SPDX-License-Identifier: GPL-2.0-or-later
> +/*
> + * PKCS#7 parser KFuzzTest target
> + *
> + * Copyright 2025 Google LLC
> + */
> +#include <crypto/pkcs7.h>
> +#include <linux/kfuzztest.h>
> +
> +struct pkcs7_parse_message_arg {
> +       const void *data;
> +       size_t datalen;
> +};
> +
> +FUZZ_TEST(test_pkcs7_parse_message, struct pkcs7_parse_message_arg)
> +{
> +       KFUZZTEST_EXPECT_NOT_NULL(pkcs7_parse_message_arg, data);
> +       KFUZZTEST_ANNOTATE_ARRAY(pkcs7_parse_message_arg, data);
> +       KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
> +
> +       pkcs7_parse_message(arg->data, arg->datalen);

As far as I understand, this function creates an allocation, so the
fuzz test will need to free it using pkcs7_free_message() to avoid
leaking memory.
What do you think, Ignat?


> +       struct rsa_key out;
> +       rsa_parse_pub_key(&out, arg->key, arg->key_len);
> +}

Do we need to deallocate anything here?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXkig71cn1xCUP1t%3DOLAbk%2BYYLsec0HhciROuiTD6AELg%40mail.gmail.com.
