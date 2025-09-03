Return-Path: <kasan-dev+bncBDHIHTVCYMHBBPEG4DCQMGQEL7PRMIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E63C1B4196A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 10:58:37 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45b990eb77csf4861495e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 01:58:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756889917; cv=pass;
        d=google.com; s=arc-20240605;
        b=aNyU6B9ytwqfax5+At0YuN8pA6c0uJbAKQfilqTGQYytAm7sfWmlg/uHUBAYPP/OJR
         lYePqbsFrIOkXbJoxu3KC8hNwtWVplY2Z+7P8z2PRdo63PceATQgGXCxoAyhQXTmmf4L
         pq/N1SxMRreT58lyRsPkxoSBXABDBhqtxegw2uZAkW1byMMmh5k1uvM+75qLC01A5zcp
         mDPzl6bayotSGArbr91GmVi+VyL5zayk0F2+lpv97p3jmKBLtbcTmHJ5wKJ7O0R6aFlt
         VQpROBRxRNlgxjDYQzNE/nw85+bp+YliS9tBza0u85xguAjR14EETNr92IIfGz6S2lKk
         NuPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8UyPNfnCpfaxLKDSXcUI9hZoSqCXYWjdx6wKhg6nS6A=;
        fh=OV9bMJ3U8Tv9dK2mcJ3eZ/a8M27evlrSsLpZi+s8Lz4=;
        b=D2dAUw3adBet0TZ9SNFfWY+CEt1tG92+VkEfiJb3f7UUFh4nMQlo3aqFo9F8BgYYXj
         gfNzJuZpx+1aPZu6/kbwdJTCZkr/GjDm2BFYOALHmhIOg6WZLJ8Gp2/aJiUtOeJcyGAd
         pS1IZkYulFchA4v6/YiDvfKzfivEZ1KrFp0PZIZt4iggln62OIbn5vCNbZteTFzKfxAY
         nWWt2PPVsSXjBfg4YE2ABNQZ5T1r96PxyAiMBH2cIiJUYP6TnbA259ULS3H+kutIA/D+
         VRm4ccF/ZWdAw3OgaiUqSN6ggLX3FxTU2gZoS+9Tr9OvBxVhTD6r1HcwKO4pl3PKHJmS
         8bcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b=YpqWvREP;
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756889917; x=1757494717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8UyPNfnCpfaxLKDSXcUI9hZoSqCXYWjdx6wKhg6nS6A=;
        b=dsl+mGuN8p0AC+ZxphygFmd/ls91syDzqNj9nURv4BpER0ab+I6QKVkJ6AR/1HaH4W
         dCJFR14vQzyJvUvuv2XG6tEE8xXMVhWPvqNppvqCZQRaNwj1YVZuxYo6axPATdVUFAXU
         lfBVtgmEaX/Kdj5qDPAiOGVcGh48yh9SfZeW4Dq1XpSD8knu/7nEINY04DeSfBeSiax9
         goZIQSc9JnzqMZ90EF+NkI7HJPnbMOhx4X5G6tUOWjhSPr7HOmm7BeeeTxU/rds/ULEB
         AABpn6M/yIqWNpbAP/u/HYxKTQxn+QXkMVxyg3R/1m9IckL7ogSwR3pjUeP5Gs+kh0o/
         0fLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756889917; x=1757494717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8UyPNfnCpfaxLKDSXcUI9hZoSqCXYWjdx6wKhg6nS6A=;
        b=r9Yzx9WO5dRJ+JZmTzWIPRw6fxfUQXxwP4nIyKdXURi61r9SbR4YCrRSr3AcP4RHts
         DagmkcOroy9V3frSYtU39dIwvZmzVCom4b0j08IUfY3S+DrePKKnJCPN4FwTcGAlY7F6
         yB9yX4ZeD+MTtzRuXtT8QybqMJsSEj92+B2cajR0bM8MWhi723QF/1VhldStyxtDLzTi
         CUiOfqWmjhDmsCKas3PsIVHOcFzj4Djvykk/8VG6jTaTwexJMhBb3aXZBmiApuXGPjiA
         21r7vIKWrLvK4HU5SYuypTCb91CvDvynQ5y2+zA/zPkp1PvuK2MZpfMEQkYH0XaT4G1d
         pGuw==
X-Forwarded-Encrypted: i=2; AJvYcCWpAu864SM1lJ/gxnXmhC5SPLjvO1LlNRXqeSkMWDH+Bzc7cqlDye0jBVGF0Bow6cVUkNx+Bg==@lfdr.de
X-Gm-Message-State: AOJu0YyOs0KB+p0hQJ/oiQwlbcKJLfusFaXBegERBSfHt4cU09/kImWb
	JYmYyVNM9dk+6l0Wj4X7q/yHhIzqa8fPI5WYm7pgPxRUNd1a++fwWBhw
X-Google-Smtp-Source: AGHT+IH6VLs/vCK/mdFQ4HEfFQaglD+tjzmSmogikWNaIm5coPbqJO3iI+LsnabUAq2NsGjD2YUfMw==
X-Received: by 2002:a05:600c:810c:b0:45b:92a6:63e3 with SMTP id 5b1f17b1804b1-45b92a665f4mr49767255e9.9.1756889917049;
        Wed, 03 Sep 2025 01:58:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd49MQpWjMpzo2XSD5tvqwQXTqjW6Jpzx7+H6yNpJo8Yg==
Received: by 2002:a05:6000:ad1:b0:3da:687:d9f1 with SMTP id
 ffacd0b85a97d-3da0687dbe3ls309233f8f.1.-pod-prod-00-eu-canary; Wed, 03 Sep
 2025 01:58:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3jMavtQwsWfeH2rSJSZVms6LQbDb01vDtkBy8cUlaiVxpo8+eqzCFHNR1v5D5dp+YTdGXj+qXb9o=@googlegroups.com
X-Received: by 2002:a5d:5712:0:b0:3dc:db:89f3 with SMTP id ffacd0b85a97d-3dc00db8a77mr2403348f8f.16.1756889914440;
        Wed, 03 Sep 2025 01:58:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756889914; cv=none;
        d=google.com; s=arc-20240605;
        b=Vl3dkoRdekmGtyWak+DGc/wnc3yoEGvW3/rOcEY0cW0Fc4WrWd3GHYDt3Du+ffKJxp
         m7RxJi0grBu2zhUFX9lq3wNi8goE5mIlaYkCC7wBfM70yAAsbiXAqcNPaED4vGDSTEKk
         Ca4eHFRLyOn0n+oAyNJ5gzXIr0WEPnbhH2m9dU/MXhVC4W7qDe2e+Q3TgE5BYTdl1iZ1
         biYVjPosoWFT/WhZkRHJlH+tm3WudMTsXmHdHbJMBzG4X9P8z3ta/yqqgOo978wIC0e0
         a/RAeMWKXWVwwW1ZbpdkIlCf225kCGlG1zFMoFnQGUq0y2xh/L9VPAQ9mfQR44mEEnmg
         NaJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o7DZbr5IPE7KPqwr8CmuJ7G0mqK+7ozrUki3YjXg8lg=;
        fh=kJFUn/Pd3MApjesUh+Agt0ktS1hpIRkLPxllSsxUl7I=;
        b=i4v6LSl29vBDq3IGFhLuIQefQBTqc85GBMPykVrBBzJt26fQthlJbshQU441I7mkSz
         iNKrgyeD0uhXH53zrLdTnGUhp0icpy2n4kokBcqZnwPNaqHgBjZQ4yjJ31+DDmPVI8Ku
         SnjXADNb11PW5RuHCZjfczmdO7m+Jvqr8r80oM9V0Gu13h0+VCMNGIdMGCnKjEYMd2Ly
         ImCbsmtUcPGsFMjBGrrzgkcVOFySkONc4uvwCQFZExeRcwUoEThmJB0EufS/O9J94O6q
         WUShjhmcJp2c+RjS7aY6fRA/OF8FNfS4bm4wtxSTuj4dzkQ0UJhNNU8mCE0fHlnd9WN7
         R9Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b=YpqWvREP;
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cf28e07747si222964f8f.6.2025.09.03.01.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 01:58:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-336dc57f562so6344051fa.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 01:58:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6BBq7aHCbEmLC88raR1ub4BLoARbOo+cQuI5XTfCl+cKii02ONo+Sv1if/ACrj5VKIgc79IExAWo=@googlegroups.com
X-Gm-Gg: ASbGncsVEni0zOz1NCbtTqVri5d+eNBBCxjgM60St79Iu6rB3DcruoSejyFcsB2Xhuq
	CCL+3sdWtUwa7bsmIwpUkfcgWpf6b2bhb8HORZ2JU/M9K/hbgdVboZxo+mDWesdMQ2EDjC38UVN
	X9ykzjP1b6D1Ad99nuGdVAejqw3ZVfUpZRb5phKQpG2fmWFKFIKR6LZhUNR/7glLaMg7dppOmo1
	eJI7DXcVLNieGm2axL/iRnCx2BYkOZwzJpD
X-Received: by 2002:a05:651c:410c:b0:337:f40b:ceff with SMTP id
 38308e7fff4ca-337f40bd6b0mr10888081fa.0.1756889913537; Wed, 03 Sep 2025
 01:58:33 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-8-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-8-ethan.w.s.graham@gmail.com>
From: "'Ignat Korchagin' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 09:58:22 +0100
X-Gm-Features: Ac12FXzBn0vfVPWXT-oRg7YFxfn5ZjyJ_zA4MQI9Ke7h9u6mEjL9U6otTFUfOcM
Message-ID: <CALrw=nGkk01xXG7S68FggsWQXygTXnXGz8AvseQuRE9K-OE0uA@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 7/7] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, davidgow@google.com, dvyukov@google.com, 
	jannh@google.com, elver@google.com, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com, kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, herbert@gondor.apana.org.au, davem@davemloft.net, 
	linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ignat@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google09082023 header.b=YpqWvREP;
       spf=pass (google.com: domain of ignat@cloudflare.com designates
 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Ignat Korchagin <ignat@cloudflare.com>
Reply-To: Ignat Korchagin <ignat@cloudflare.com>
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

On Mon, Sep 1, 2025 at 5:43=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add KFuzzTest targets for pkcs7_parse_message, rsa_parse_pub_key, and
> rsa_parse_priv_key to serve as real-world examples of how the framework i=
s used.
>
> These functions are ideal candidates for KFuzzTest as they perform comple=
x
> parsing of user-controlled data but are not directly exposed at the sysca=
ll
> boundary. This makes them difficult to exercise with traditional fuzzing =
tools
> and showcases the primary strength of the KFuzzTest framework: providing =
an
> interface to fuzz internal functions.

nit: can I ask for another real example? AFAIK this subsystem is
rarely used (at least directly by users). However, one user-controlled
widely used parser terrifies me: load_script() function from
binfmt_script.c, which parses the shebang line for scripts. I would
really like to see what this framework can do to fuzz that.

> The targets are defined within /lib/tests, alongside existing KUnit
> tests.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
>
> ---
> v2:
> - Move KFuzzTest targets outside of the source files into dedicated
>   _kfuzz.c files under /crypto/asymmetric_keys/tests/ as suggested by
>   Ignat Korchagin and Eric Biggers.
> ---
> ---
>  crypto/asymmetric_keys/Kconfig                | 15 ++++++++
>  crypto/asymmetric_keys/Makefile               |  2 +
>  crypto/asymmetric_keys/tests/Makefile         |  2 +
>  crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    | 22 +++++++++++
>  .../asymmetric_keys/tests/rsa_helper_kfuzz.c  | 38 +++++++++++++++++++
>  5 files changed, 79 insertions(+)
>  create mode 100644 crypto/asymmetric_keys/tests/Makefile
>  create mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
>  create mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
>
> diff --git a/crypto/asymmetric_keys/Kconfig b/crypto/asymmetric_keys/Kcon=
fig
> index e1345b8f39f1..7a4c5eb18624 100644
> --- a/crypto/asymmetric_keys/Kconfig
> +++ b/crypto/asymmetric_keys/Kconfig
> @@ -104,3 +104,18 @@ config FIPS_SIGNATURE_SELFTEST_ECDSA
>         depends on CRYPTO_ECDSA=3Dy || CRYPTO_ECDSA=3DFIPS_SIGNATURE_SELF=
TEST
>
>  endif # ASYMMETRIC_KEY_TYPE
> +
> +config PKCS7_MESSAGE_PARSER_KFUZZ

I'm a bit worried about the scalability of defining one (visible)
config option per fuzz file/module. Is there a use-case, where a user
would want to enable some targets, but not the others? Can it be
unconditionally enabled and compiled only if CONFIG_KFUZZTEST=3Dy?

> +       bool "Build fuzz target for PKCS#7 parser"
> +       depends on KFUZZTEST
> +       depends on PKCS7_MESSAGE_PARSER
> +       default y
> +       help
> +         Builds the KFuzzTest targets for PKCS#7.
> +
> +config RSA_HELPER_KFUZZ
> +       bool "Build fuzz targets for RSA helpers"
> +       depends on KFUZZTEST
> +       default y
> +       help
> +         Builds the KFuzzTest targets for RSA helper functions.
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
> index 000000000000..42a779c9042a
> --- /dev/null
> +++ b/crypto/asymmetric_keys/tests/Makefile
> @@ -0,0 +1,2 @@
> +obj-$(CONFIG_PKCS7_MESSAGE_PARSER_KFUZZ) +=3D pkcs7_kfuzz.o
> +obj-$(CONFIG_RSA_HELPER_KFUZZ) +=3D rsa_helper_kfuzz.o
> diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetr=
ic_keys/tests/pkcs7_kfuzz.c
> new file mode 100644
> index 000000000000..84d0b0d8d0eb
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
> +       KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
> +       KFUZZTEST_EXPECT_LE(pkcs7_parse_message_arg, datalen, 16 * PAGE_S=
IZE);
> +
> +       pkcs7_parse_message(arg->data, arg->datalen);
> +}
> diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asy=
mmetric_keys/tests/rsa_helper_kfuzz.c
> new file mode 100644
> index 000000000000..5877e54cb75a
> --- /dev/null
> +++ b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
> @@ -0,0 +1,38 @@
> +// SPDX-License-Identifier: GPL-2.0-or-later
> +/*
> + * RSA key extract helper KFuzzTest targets
> + *
> + * Copyright 2025 Google LLC
> + */
> +#include <linux/kfuzztest.h>
> +#include <crypto/internal/rsa.h>
> +
> +struct rsa_parse_pub_key_arg {
> +       const void *key;
> +       size_t key_len;
> +};
> +
> +FUZZ_TEST(test_rsa_parse_pub_key, struct rsa_parse_pub_key_arg)
> +{
> +       KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_pub_key_arg, key);
> +       KFUZZTEST_ANNOTATE_LEN(rsa_parse_pub_key_arg, key_len, key);
> +       KFUZZTEST_EXPECT_LE(rsa_parse_pub_key_arg, key_len, 16 * PAGE_SIZ=
E);
> +
> +       struct rsa_key out;
> +       rsa_parse_pub_key(&out, arg->key, arg->key_len);
> +}
> +
> +struct rsa_parse_priv_key_arg {
> +       const void *key;
> +       size_t key_len;
> +};
> +
> +FUZZ_TEST(test_rsa_parse_priv_key, struct rsa_parse_priv_key_arg)
> +{
> +       KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_priv_key_arg, key);
> +       KFUZZTEST_ANNOTATE_LEN(rsa_parse_priv_key_arg, key_len, key);
> +       KFUZZTEST_EXPECT_LE(rsa_parse_priv_key_arg, key_len, 16 * PAGE_SI=
ZE);
> +
> +       struct rsa_key out;
> +       rsa_parse_priv_key(&out, arg->key, arg->key_len);
> +}
> --
> 2.51.0.318.gd7df087d1a-goog
>

Ignat

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALrw%3DnGkk01xXG7S68FggsWQXygTXnXGz8AvseQuRE9K-OE0uA%40mail.gmail.com.
