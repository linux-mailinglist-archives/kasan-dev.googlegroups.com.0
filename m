Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBVM6PCAMGQECKSY2ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C5C0B252DA
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 20:14:32 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-24458194d82sf447895ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 11:14:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755108870; cv=pass;
        d=google.com; s=arc-20240605;
        b=SjutHOIZ+rOI816VB5Q2bei/l0JnYqS6e/9WtuYbvyr6+xiD3Q492GN5yYpC1LIpgE
         5ep9PakYiuByd7Y8KPpZ3pS85DhPPxAMm1Gyn/fVlbhf+cZ4tNUiKgd4OnE+ImO1jhdf
         AjpzzeSLY2gYwWuWELqRuPbuF9csp4sRewgcGcB6HwgVC03xNIFTe0AV7YPcTaXqOJYz
         SpFeDTjpaSD36zr9AFjGiubxk7Kw2kbV+s6WRKgAyiXGQLcKmta2cmpnfimGHukgAFK8
         I7a7/+6Xxq32Sd31/JIDozRln7jx/cq+zkqkV/Z8hNL90OVfa1ASl1AuRNyM5vPR7nBK
         ehdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zIazgtHlzAZz+LHcbrfHcOW5o49JDglzrMK6dT7hdoc=;
        fh=SsRZ1q5fra8abaDL1E9dHANDKPP9vxrqHg5vdmkQqJ4=;
        b=BZsE5y2t22hXLf6jK7V8MtC4034j0Hpm92S/586h19X2m25fbcgBXmdyHU9cuTU6ZL
         MhLr5SZWhQTkqy30gEZHffkIMBX5kFNNbncfrBG0AUcNrUNYbAs7gE3enFFxun7Ilu9P
         1WyN5vcuA7VI9ese45Dd/HGGNCucQUroMiFx7unZhSud7e8cdOIEizxdmQ4XAs4kxPH2
         I05lTvl8pQyAaWhj8yOtqG4oztSuTWkzc6rcvh/wzSQIUuEuOep2+oagTruRr65BRJAB
         J57uE2p6Mv5pWSmvs5lqANKC69BoJ5UiLKRq+6FwB4rY8kp1WvwhtTAVQsPCXAGXCEE4
         rCOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ldH8DWYG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755108870; x=1755713670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zIazgtHlzAZz+LHcbrfHcOW5o49JDglzrMK6dT7hdoc=;
        b=t7qVBvPU/TXpU1a3hXOuUpv5l07UN7BayhdQ1HS0VJEmUEwbyFCTFuRpK+LEAhJjk2
         UUIYbBuzeWBFQrns1Y1L+sRZX6WiyaxmrANiQGsqN+zadMWA+JnKIXR9vCHQHM7YdktM
         aLM045dcHa1Yf/iBzNpYyMWyCZ1hQl4g+2Lnr502/mYtemXP+65XG50ZZfVTGZRPTkW3
         90t1k0tXAfQwE3yQOot7AgDiwGORV9/noE444Hr4xNVpAG/7imHfZ9UH4pNdIzP3fjTy
         jAPcRVqXf/xxBgd/9gi713dfel3+nrpzSgGisGJgAklkkUNWLt6WOJYe9rIzH+rBAb74
         k3cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755108870; x=1755713670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zIazgtHlzAZz+LHcbrfHcOW5o49JDglzrMK6dT7hdoc=;
        b=PP1virIoVIqpPv42IRPz1yMntYq8hiC7m9wLcxuoU3Z8nJEa7yFxMmRJdHhLXsWfxT
         fyHr/uUmOPUMOdFDNoqH7EJJN3DhQBmvrcwnZTlvBckTc1oeNjOnoul4CP8LOOAY+CXm
         F/j8TS3FREAt50St146w4A42M0LdPeckTSTG6VzKW+eTxVlsRsjh+jd7N7yJi4FFWgJ5
         ojUUe+uPa9kmA0IU6vAbpix9UOFxBByWsrKk9dosSKa8bXTfE+nqkpAIIKRmXOvczHTs
         V0ylw7tdiCXkZDvMDhpQ6RaChnQkewLDp71rGFOF4VdMMlyK9Ao9+mDpALRY8657gVb0
         AqAA==
X-Forwarded-Encrypted: i=2; AJvYcCVfoSGG98oHay97L7zTwPTxWdoOuCiY7AwCJVpfibnpzRI2YEYqbJEAfbLldb5wXmeYaotR5w==@lfdr.de
X-Gm-Message-State: AOJu0YxqFNMylBs/jWIlLe4gXdphXI4eCVkQIsUEESGkk+qgKhVwWtjC
	LOUGHerpxIxijFST+ZfQ8m/mOviw0EC21EPRG7SHbYGlXlA/lj+iP1Yz
X-Google-Smtp-Source: AGHT+IHUI0Joo1xFzKqvVaM7pJxEjd548uA8cDq1TDtjFpw/RSAvLl76t5ROQEzsU/L0eRVWzPisaA==
X-Received: by 2002:a17:902:d542:b0:240:41a4:96c0 with SMTP id d9443c01a7336-2445867ed19mr702325ad.29.1755108870444;
        Wed, 13 Aug 2025 11:14:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdqUI2jNn5NPqsY73Hc+uBM2pn3lCe6859XiDmQHjZvZQ==
Received: by 2002:a17:90b:1890:b0:31e:f73d:d1a4 with SMTP id
 98e67ed59e1d1-32326649fe5ls148066a91.1.-pod-prod-09-us; Wed, 13 Aug 2025
 11:14:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVypc+1Byd56vuOSHWWqKT/qWLkqsBPbMXsVQMLL3FdXG3smNr05+TpRnjOqOsd4bjrIq1DDmsZRdE=@googlegroups.com
X-Received: by 2002:a17:90b:5643:b0:31f:42e8:a899 with SMTP id 98e67ed59e1d1-32327ab08f4mr419844a91.13.1755108868967;
        Wed, 13 Aug 2025 11:14:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755108868; cv=none;
        d=google.com; s=arc-20240605;
        b=bfm3AuIK1+0d429DRANjpHJTWXfcI+sF8wvt0VutakEJGXNhLJGMsGSMTK3xFQDnhL
         BHkOrQB+NwW5GhTZOkgT24Qy+XWYlbvbvrB9Yjdd3JoWnnAWTlBt6xSWcvZMtXlgddqs
         tSzQCYoYB3suHAXAuDzmYOzPduxGiW8wM6W9Ed9Oe4/uac/2dITrgkk6v87p5b0VeRCU
         665zn1kYf7nWEIUH4fpc/yXvqGSOrsI5jBpSbPXfHa4Bb5qCKQjGrKExH8joU/5UAhou
         TgMaFJvXZWYp13O/S6jj+4LJP19n6gsUt3TPJr52iJm1DzMfBTdBg+Nn60gciF6ygsx4
         UiCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4hxBfzmvH2TsE+jx0zUQqB7m43IVHQfBxYfENPa1oII=;
        fh=aQ2vtOkiWvpsj5oOHAT6mWgqKoTW9RGgQ35zN/s7SY8=;
        b=PNAXKADH2Cl08scjw+ZXJHV5QHyEUz45O/5K6/AAIXQFv/96aslosE3wUkW6kZg9wk
         ijv3PzbfwEVlhhIACLLkk8qN4QJCyDD2AdcyFCr6zUMMLmRik0/4hSC3trm4dQ/gGrIk
         uisFa+9yFJXE9HDU48MwJrZHxGKatPstBh02t/3SSJ8XdfkzV5g3uSv5xX+dZ5taAtDa
         84OjBdaQHvt8zap8E5X1UJzyq5VMx8jAKgMH+q5uAWEpR4BPJ5efGfRzlQJY2edJDzvB
         E/WW8LzC09b5PHZLUDHAPJarTmtbxVas9MV25CafYgv2nqHQTuURKmPOi6nkTjXwkLlN
         2/YA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ldH8DWYG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32325563d3fsi51753a91.2.2025.08.13.11.14.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 11:14:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-2445811e19dso420875ad.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 11:14:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWBIeE1MR3GqXBJr9HwBEPsp3LIdYE0CeGZRzxZyGkLsfiWdcvA6hFNMpM3dLEBGLHcr9y4pK+KIso=@googlegroups.com
X-Gm-Gg: ASbGncv7QwOhgBPuJ4cEIHDbAA42/noWkJUmsAXFWAKAs2c57G1F4vIdx8ChkvwxDdD
	GuEQHP5AvfF8ARqakNdOdH/DzsVE3GYiL54x6xFU95poJ+seEgcpNwXwExtt7ZvTkrAy19NS+t9
	NoqIqvU7uIll4TbMWbANo5Otjp0O7rD/wjq3qtS6EMFxN5IMN4nsJouyejGXWy9ScyCrVXbCWQI
	8SvJDBq8hD9I8xFJDRaV3lEP51Y7Hwl/qr/jancIl+NYPOi
X-Received: by 2002:a17:902:d542:b0:240:41a4:96c0 with SMTP id
 d9443c01a7336-2445867ed19mr701285ad.29.1755108868210; Wed, 13 Aug 2025
 11:14:28 -0700 (PDT)
MIME-Version: 1.0
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com> <20250813133812.926145-7-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250813133812.926145-7-ethan.w.s.graham@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Aug 2025 20:13:51 +0200
X-Gm-Features: Ac12FXwt2pSL7dVwRutKcMu_hFjjWXkjb4Jh6zDHbgaT8hltdL3d-RuGkNjKm24
Message-ID: <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, davidgow@google.com, dvyukov@google.com, 
	jannh@google.com, rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>, 
	Ignat Korchagin <ignat@cloudflare.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	"David S. Miller" <davem@davemloft.net>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ldH8DWYG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

[+Cc crypto maintainers]

On Wed, 13 Aug 2025 at 15:38, Ethan Graham <ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>

Should also Cc crypto maintainers, as they'll be the ones giving
feedback on how interesting this is to them. Use
./scripts/get_maintainer.pl for that in the next round, and either add
the Cc list below your Signed-off-by so that git send-email picks it
up only for this patch, or just for the whole series (normally
preferred, so maintainers get context of the full series).

> Add KFuzzTest targets for pkcs7_parse_message, rsa_parse_pub_key, and
> rsa_parse_priv_key to serve as real-world examples of how the framework is used.
>
> These functions are ideal candidates for KFuzzTest as they perform complex
> parsing of user-controlled data but are not directly exposed at the syscall
> boundary. This makes them difficult to exercise with traditional fuzzing tools
> and showcases the primary strength of the KFuzzTest framework: providing an
> interface to fuzz internal, non-exported kernel functions.
>
> The targets are defined directly within the source files of the functions they
> test, demonstrating how to colocate fuzz tests with the code under test.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> ---
>  crypto/asymmetric_keys/pkcs7_parser.c | 15 ++++++++++++++
>  crypto/rsa_helper.c                   | 29 +++++++++++++++++++++++++++
>  2 files changed, 44 insertions(+)
>
> diff --git a/crypto/asymmetric_keys/pkcs7_parser.c b/crypto/asymmetric_keys/pkcs7_parser.c
> index 423d13c47545..e8477f8b0eaf 100644
> --- a/crypto/asymmetric_keys/pkcs7_parser.c
> +++ b/crypto/asymmetric_keys/pkcs7_parser.c
> @@ -13,6 +13,7 @@
>  #include <linux/err.h>
>  #include <linux/oid_registry.h>
>  #include <crypto/public_key.h>
> +#include <linux/kfuzztest.h>
>  #include "pkcs7_parser.h"
>  #include "pkcs7.asn1.h"
>
> @@ -169,6 +170,20 @@ struct pkcs7_message *pkcs7_parse_message(const void *data, size_t datalen)
>  }
>  EXPORT_SYMBOL_GPL(pkcs7_parse_message);
>
> +struct pkcs7_parse_message_arg {
> +       const void *data;
> +       size_t datalen;
> +};
> +
> +FUZZ_TEST(test_pkcs7_parse_message, struct pkcs7_parse_message_arg)
> +{
> +       KFUZZTEST_EXPECT_NOT_NULL(pkcs7_parse_message_arg, data);
> +       KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
> +       KFUZZTEST_EXPECT_LE(pkcs7_parse_message_arg, datalen, 16 * PAGE_SIZE);
> +
> +       pkcs7_parse_message(arg->data, arg->datalen);
> +}
> +
>  /**
>   * pkcs7_get_content_data - Get access to the PKCS#7 content
>   * @pkcs7: The preparsed PKCS#7 message to access
> diff --git a/crypto/rsa_helper.c b/crypto/rsa_helper.c
> index 94266f29049c..79b7ddc7c48d 100644
> --- a/crypto/rsa_helper.c
> +++ b/crypto/rsa_helper.c
> @@ -9,6 +9,7 @@
>  #include <linux/export.h>
>  #include <linux/err.h>
>  #include <linux/fips.h>
> +#include <linux/kfuzztest.h>
>  #include <crypto/internal/rsa.h>
>  #include "rsapubkey.asn1.h"
>  #include "rsaprivkey.asn1.h"
> @@ -166,6 +167,20 @@ int rsa_parse_pub_key(struct rsa_key *rsa_key, const void *key,
>  }
>  EXPORT_SYMBOL_GPL(rsa_parse_pub_key);
>
> +struct rsa_parse_pub_key_arg {
> +       const void *key;
> +       size_t key_len;
> +};
> +
> +FUZZ_TEST(test_rsa_parse_pub_key, struct rsa_parse_pub_key_arg)
> +{
> +       KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_pub_key_arg, key);
> +       KFUZZTEST_EXPECT_LE(rsa_parse_pub_key_arg, key_len, 16 * PAGE_SIZE);
> +
> +       struct rsa_key out;
> +       rsa_parse_pub_key(&out, arg->key, arg->key_len);
> +}
> +
>  /**
>   * rsa_parse_priv_key() - decodes the BER encoded buffer and stores in the
>   *                        provided struct rsa_key, pointers to the raw key
> @@ -184,3 +199,17 @@ int rsa_parse_priv_key(struct rsa_key *rsa_key, const void *key,
>         return asn1_ber_decoder(&rsaprivkey_decoder, rsa_key, key, key_len);
>  }
>  EXPORT_SYMBOL_GPL(rsa_parse_priv_key);
> +
> +struct rsa_parse_priv_key_arg {
> +       const void *key;
> +       size_t key_len;
> +};
> +
> +FUZZ_TEST(test_rsa_parse_priv_key, struct rsa_parse_priv_key_arg)
> +{
> +       KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_priv_key_arg, key);
> +       KFUZZTEST_EXPECT_LE(rsa_parse_priv_key_arg, key_len, 16 * PAGE_SIZE);
> +
> +       struct rsa_key out;
> +       rsa_parse_priv_key(&out, arg->key, arg->key_len);
> +}
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A%40mail.gmail.com.
