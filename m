Return-Path: <kasan-dev+bncBDHIHTVCYMHBB3PXUTDAMGQE3QNN3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A6B97B5939D
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 12:29:03 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-786c3986579sf30456426d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 03:29:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758018542; cv=pass;
        d=google.com; s=arc-20240605;
        b=cGB2Ip16Nh9oEQILkn59txdMyKRpDoq36CMxS7dvr77GcP33nSfAQ/qvBPCIvt50J7
         WAJWaNdTDVgsdC3TrmFbbqC4bMP4Jo1V1UhKhLHhdsMBrj4WArAw33dwQkztNx58SGwW
         fMcDmYfVYBRzdv3oQj8lQRAknpFlS5e5IoUinwVeqMYZV05ibAe210KXvKAoOfJ599o9
         WGjtitWPhqhH3FsZemZIdy1ri2zjPBebszQ+WJ23KaltQApIOlDvzfzaeFuC9Z9W780r
         sp9QfFwqztl+6SWIJx8ECfsotJ5Y+uLItKGQAQfF2qFh+2MwSnUvsoX1hKfe9gSMlk3T
         jOvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wg3YVzbQXf38x1uXsFw1+Aw6/XpPZ/7hEYmeoiZFFu4=;
        fh=Pwavja6uqlYf7QYlRAGh3TcxvBLDGhZAggBqwjQWr2s=;
        b=iT0zQJM3oZ5/5zeNkwdIEYLzIYJfom1Ps/Agsf8EQTMV8IRF1Xy92+tbSIrPFu0bh7
         seIGDKyBM92HtlAN1K5FXJewkUIb4AbI8lGhLs36gbr3cGnEMIuDqWbkL6YFTzbvLGgT
         cthlMUfJ/ThePFhXLaQEvcdEXld6NTDG+J7xP3ugJC6Ujd1VdxYN0bw7BucDONkyWsGV
         0A+HFxGXoy71G820R421Qwl6UhezTmbmm3ajfCZBt06+QHin1kq2De5T8pJ/8VF1LEsy
         5gUkRbMweN202/5auNt/WaDxJ/elqn+Gr9IeTSzFn3TpG3aDpVDuTfMuEmXFr2vGgKPQ
         ffsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b=fWr5OwRA;
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758018542; x=1758623342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wg3YVzbQXf38x1uXsFw1+Aw6/XpPZ/7hEYmeoiZFFu4=;
        b=F9rlyhagwHcjxnahMWEJsBYStg1HJSg+8S34n77JXlbYdhZJ5K08vDlxFLKSkQ4LrJ
         +8iIhKxPMjyVuquhNfW9ZbUwjAIzgeA7EeJHO03NYgqBIHv/jCk3eg/WyIceL6t3C+wa
         MND1CgsnDSYYMWQQ2MIxGKwMsOjSkjf6T+dpTaye9kkQxtgX7kypYNgQiC6uWPWSl8sr
         ngtLSIXfrIoydlA7Jf5ryBDtXFX3ojcg4nZJQn2V8bmc3d/cSxUi7vC8lPxi77QPSP0w
         1na3PC8AVtiDz0DM/Tf8mobD38UeWgHm6e3lRzPne9KxD/jGKDpZVk4RiNuF4TSLVZ4b
         u+Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758018542; x=1758623342;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wg3YVzbQXf38x1uXsFw1+Aw6/XpPZ/7hEYmeoiZFFu4=;
        b=wNLxl+LNEKYe+N64+OFzjEBSRHIAB66shtGBhgT/Bol+xm7XF4q9n+C6ihZ7UdJF4m
         blKYhR6qh3O2QJOsrmpGm6jfQBgQbGMqO7kHJiBIjsc3U5xvlDonz30jeCsA2tT59SAR
         JB/iPbRQOU1jiN2X9itdHJAvK/39Ne/ROd+HMMHGLMqQ6uYz/EwxtAJdH6A7PyqCIIRG
         OwKqCGOfdoj7gHoudPB5t+JdcQlcbe1xZXi58T6yVTUbaoWkJ22rQ6cEjy32yTrgGfQ1
         PQwvxTOh9lmCxJrKk4UC05GjNi102lFouh0wIq9gQZhoiSS3X8/lKBmc74pTo55IlV10
         26SA==
X-Forwarded-Encrypted: i=2; AJvYcCWT/vx2gXgESQPdnwqE0jJIGvsuGb5qMNvP/XusFJKgVDJdXr6hOFlAKk34iANen36Jozix+g==@lfdr.de
X-Gm-Message-State: AOJu0YxptLr6fx3D9X0P5LGFLZwF8QVLFng/iLROgLQd8P+ET8zBKKtY
	q758hc77ABuimGRr4dsT5qHiFjVAKIr06SBo/oCJkqNHpuXWNWHoe7ls
X-Google-Smtp-Source: AGHT+IF1pWYp9ShoIlxzKlLojbOVQLcn8K0lwCo88FtuAx7MyHr0fB/hujmcLwUGKpIAZSNsROKACg==
X-Received: by 2002:a05:6214:cc4:b0:784:4f84:22fb with SMTP id 6a1803df08f44-7844f8423ffmr77688026d6.24.1758018542016;
        Tue, 16 Sep 2025 03:29:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6ssqGc6Gci6r9Tdg6FlIo0B2wEAehnHgcZWH5OE+6CNA==
Received: by 2002:a05:6214:5287:b0:70d:9fb7:7561 with SMTP id
 6a1803df08f44-762e590fce0ls89606126d6.2.-pod-prod-05-us; Tue, 16 Sep 2025
 03:29:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbMfEXab7n/irCXWfxYI24RTIxlfHDCtNifJbq9d9u9w/kYFuPQWGXmPXvScVjdN9wr1l2nXc+tt0=@googlegroups.com
X-Received: by 2002:a05:6214:e4c:b0:77e:c0d1:11d with SMTP id 6a1803df08f44-77ec0ef85e6mr92599106d6.48.1758018541229;
        Tue, 16 Sep 2025 03:29:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758018541; cv=none;
        d=google.com; s=arc-20240605;
        b=aA4JVKeVUZyY5oCTZw5hWRYf2kIZa8qJg0kLXJ1mIonrytuPOIWoDSSPt9T/AqK9gc
         buD1tJI/A8gNq4QvsUeMbeEGDs2pRnCxy3yik2mRX2jibA2xDPGFj8fS+V+HHrEpSosC
         kKZwrIZpJ1XwStQGlv/HkScI3TbSuMitS2MFXSW5KnXHfPA6Se8VEHogAZYpR/DKIHj1
         eC4TcAIhKPvslanKj1fDGuXYochW84kk47jrsZ/Yp2IA5AaAQ5lOIt0G6A3Fsd0HWaPD
         XAGddRDd4rxNQSjZ6+8IcPzanwqRQ9IsvKfAVuWpidXFeqOmWl/smdhavuP3FvsyZ+SQ
         NIVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dVtnxKhUzhBsXhVoc6XgCECsqL2+mal6aWmAQ944WSU=;
        fh=j3p4FisFYyJq+oOIkVrvcfWzES33VjLNM5NtLYFDack=;
        b=E7Lrpw1+4NwzL0PINBhYqav+v4bBRkXtkRvaGctMVIhts8S79cgThOzDwqbJezAxqE
         gAPdqdaVKTCBU+HEPxetYUK4OtfN2K0f8ArRmIE8tIPsEQohWp7Vd9eH8mp8TWvZW08F
         oAHZAQi1g5sYcu9mCdTMcShetCy7Y7xK8Ja933/h9o3t6SbjvIzILKN1rRXEE/INStSi
         1HUvBiBRu++2GTBNHJ8zeMhBWteomEBwFW35FnAfB1b3lZqLlrhDl0mfy/Gq7xtgz5x5
         eAoK3dTsE7HeXjpL50DKItDdUv9gmgOr8yU9pldJuoaPC2heGDJDZu0h38cFYmq0ZSqQ
         kWBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b=fWr5OwRA;
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763b1f6ee87si235056d6.1.2025.09.16.03.29.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 03:29:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignat@cloudflare.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id af79cd13be357-80e2c52703bso467108285a.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 03:29:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV5pL1S3mhUH3wRDBc5Jj5KkQC/RKtjTL6dWE9gXdf5/vhIXvewxYJpOBRH+ZKHUC18nCUVzsBbWpk=@googlegroups.com
X-Gm-Gg: ASbGncvwbJSsosITDOYUXOnOo6ilwR3ISME4lNJRrSAsG+s4tPihdHY9f3Nqok3WLdj
	tIxOg2jFIIYzZ4cHlvyOKh3E7un/wJIXBV5h5hDMOlGsRBcefYFc2TC8x/JYMX/hX/VPi4qmmrk
	/om3KO+Pg0dIsVUw7cp34I8l2lhP5gft4yBjoqap7SjaCrs6zNOkfwCoRnaUmqyJshY/NEh23rK
	H7DREdJ908tc4DfIV/LHO4=
X-Received: by 2002:a05:620a:4107:b0:802:78a5:a86f with SMTP id
 af79cd13be357-824047c8dd0mr1779923485a.79.1758018540609; Tue, 16 Sep 2025
 03:29:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com> <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250916090109.91132-8-ethan.w.s.graham@gmail.com>
From: "'Ignat Korchagin' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Sep 2025 11:28:47 +0100
X-Gm-Features: AS18NWCkhNpkebAoSzpi6YfP7wdFTOupUdzVBrFWuQqh8FgNjyJdBm5a2YlrxX8
Message-ID: <CALrw=nE9jYhHZnix8RV9UHApOZaF7otRLPHn3cmvOPaqQLzrnw@mail.gmail.com>
Subject: Re: [PATCH v1 07/10] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, elver@google.com, herbert@gondor.apana.org.au, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ignat@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google09082023 header.b=fWr5OwRA;
       spf=pass (google.com: domain of ignat@cloudflare.com designates
 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
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

On Tue, Sep 16, 2025 at 10:01=E2=80=AFAM Ethan Graham
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

Reviewed-by: Ignat Korchagin <ignat@cloudflare.com>

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
> +}
> diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asy=
mmetric_keys/tests/rsa_helper_kfuzz.c
> new file mode 100644
> index 000000000000..bd29ed5e8c82
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
> +       KFUZZTEST_ANNOTATE_ARRAY(rsa_parse_pub_key_arg, key);
> +       KFUZZTEST_ANNOTATE_LEN(rsa_parse_pub_key_arg, key_len, key);
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
> +       KFUZZTEST_ANNOTATE_ARRAY(rsa_parse_priv_key_arg, key);
> +       KFUZZTEST_ANNOTATE_LEN(rsa_parse_priv_key_arg, key_len, key);
> +
> +       struct rsa_key out;
> +       rsa_parse_priv_key(&out, arg->key, arg->key_len);
> +}
> --
> 2.51.0.384.g4c02a37b29-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALrw%3DnE9jYhHZnix8RV9UHApOZaF7otRLPHn3cmvOPaqQLzrnw%40mail.gmail.com.
