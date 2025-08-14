Return-Path: <kasan-dev+bncBDHIHTVCYMHBBHEB7DCAMGQEBPSKF3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 81D45B26AF2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 17:28:30 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45a1b0060bfsf5888865e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 08:28:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755185310; cv=pass;
        d=google.com; s=arc-20240605;
        b=FJsgtJ0dmTY9ZgJH+sBSiMHDNPcxgsrdo3sXQ5ccPAD/GMPZ3yNEwDLaPeNTCF/IXu
         jY5I3pLn7Y4zhKr7HTEw8fRQgr/R80/5T2nl5Doibl2lI7+ZiYLNUnjYMAQI+DEiNOE/
         HR0xwnO9i0YvjmpN8uV6eoNrIGPYiyru4x/IYvaEPXNAPRdv5YBHsQkVOkpg7iXyi33R
         kDiDS+t+CsSbwbuuYmpp560AEPY3yOEsGQPoZkzxDfE9qPofOdZdb/W7nMl2GHIZj4K2
         mXMSSOdSiKyu6SLddOSaDWPHYCQIzdgI2MhVwbNgS2+/PksCyrdGRlFkDiTpC8/5g6L1
         kBVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rOoCvKc4k+dV2d0tGm7LR2P0QL+lfHJ4ZLDc34lp2s4=;
        fh=e2SpEqevgGJ/fw6/0ZlIcg2rYJ1Iogqfpe0b1nGZP7w=;
        b=UY4NwBO7LAJiSNkqt0VYa0gJpFoaHQD3LKGygvdoXgRS7LZTel0e1+oQXPGdA43xcW
         E+DacPww173SU1nnQkRRdJdbAjNBLxSJk/7/4T+L7Pja6xhojOEwgQK0BdHKZbj0ezPC
         4KrG7SgHgtymVkWO5myiuYKWf/bv8airlyUUAi7QnyFkVJb/l3VOCHRE8hAYOxXmuy1j
         0BRiXOD0WV7WQaPstAA0d9JREUrduyS+e9u6gW+CeUJ/ZRISD84pw2eSVK9a/943w4Tt
         0zdWQgLbqUDW7FSps20zhBg7+jJsQShHx4avxzXx4THmgAM3e/zT6h5YHufCicm6lrBu
         MSVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b="d2mt6W/a";
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755185310; x=1755790110; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rOoCvKc4k+dV2d0tGm7LR2P0QL+lfHJ4ZLDc34lp2s4=;
        b=b1zyF8hv5gfIOcWih9RCX72gf/10rQjqtQPqYJT8kxiYlfkiSWxRazljbexF8vLC/h
         dSr4qAPxztqYG5n3/29aRajzwDUTrbDoiTaxAW8d+olwDrjCxLuPtwSJd85p1B6XyRjb
         QQiMhvAAbEmEFLNFNs+AphFl6loJeECaacijNWYTWP6+cLOkH0nKNK6FJc9Av/yBif27
         Ncd762JZpOPyPDK4su+XGM8eb0lqskiOy5/kJ1EbuTJG4523TIh5AkR/vWOsRciSSfB2
         2xDRCh6iG/d6LDwpW0KlaNE2rHpBfy1eW9IP6/vIP7/vHHw1Qw39yMCXjJo6UsiM53Th
         ME9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755185310; x=1755790110;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rOoCvKc4k+dV2d0tGm7LR2P0QL+lfHJ4ZLDc34lp2s4=;
        b=a+BHuDKyPq5O9CurDaezyVJNrLCptNoh2NT29IsE3RWKFTNf6i3RRNC3ng8E9eytC/
         LZWth00qYoQ0CQS9dC4EYT844qx3igIP0mqhpiwFMpVP6plDRPazGbNwwlT4jkiFOnag
         Id6zuQX5JexYTi1PqMWgitRGI+tVRO79DMunrBoAZFC4vGDfRPz1JySNvchaZicJ1+Tq
         RxQRQqs3KaVsNiFFNfnNHz8iVHbAGki44GUTaxZN9sWVd1c4H0KuNiVZaNsF8CGz6N1m
         WRjxiNykI3WkUUvcmjVtLKnP/aWL8iwqKQOdnz2XVgJxkq6EF5tamWh3UkYxgv6OMIzX
         hKqw==
X-Forwarded-Encrypted: i=2; AJvYcCVNlWQSNR7Z0jONJTDujZmcFLZilwHrpk+1pKwY2iFyd9OnFpyaTC8Yc2JjVQq5DoGsNVWj6w==@lfdr.de
X-Gm-Message-State: AOJu0Yz+AxJQQj7E24PKsBUUGsCaQNpvwA78RGR7IFb0I5fxRIwF5AD+
	vmcW7+GjRX9EeA4uyriPv9O9owPaSwG9U1HYJY7LW7CVkLax/3JSqRui
X-Google-Smtp-Source: AGHT+IEcHpt3XQHVkovzdlD6Jemy7OeOl2Z7R0xX5NK9kgOybdHWehusGqBo4CgYiuFPJNa+LEHd8A==
X-Received: by 2002:a05:600c:4450:b0:456:f9f:657 with SMTP id 5b1f17b1804b1-45a1b656260mr26356415e9.27.1755185309402;
        Thu, 14 Aug 2025 08:28:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfWi0Bc8L4oD6JTIBnftCmDoeAkKtcob/50ga/74iU04w==
Received: by 2002:a05:600c:1c12:b0:459:d42f:7dd5 with SMTP id
 5b1f17b1804b1-45a1af9b525ls4410355e9.0.-pod-prod-09-eu; Thu, 14 Aug 2025
 08:28:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFbUPAnO4yzCJefCoP3BwbyC2fRNDHgHf0JtAd8ucuhzi4ir49Cd49JQXutuYWXPOASCUg6qG4+Aw=@googlegroups.com
X-Received: by 2002:a05:600c:3509:b0:458:bd2a:496f with SMTP id 5b1f17b1804b1-45a1b646dc0mr26760405e9.21.1755185306545;
        Thu, 14 Aug 2025 08:28:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755185306; cv=none;
        d=google.com; s=arc-20240605;
        b=BU14IBQeeuuMYY61F6rQbNzXq28i2gnbJgF/GNw5e0qxz+4ZphJroSoZJ6aiZZaePC
         CKkqhdlkb8VVP8hZan2c6n7titdw63Cojt+o81voB8Bqc8sMOBla2BJ5r4zYXlhl9h75
         KusgnnozhOOjVgPmCCq/oh9mGM2hvUon9HeDlTS+Z7LTgprowE9V6BUvqSyVGFlx4K5+
         xJ6YFa+BsebyVb41wPp9AszSWRIwjYcC4Bg7Fkh8z6wqRn8rAVCU7EhHa+yvx6EuXqjM
         6om2A8Tsp1WEh0rIizPi2b+ocIb4gNZEReNA8h5DhVmls2S+26J7HK8b0b9CAwBgP1km
         Y0nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CNZq1Plf7qYhg3FaQgA7s7d5l7vZ/mBnFNpSg0zUHLI=;
        fh=YMBqAbRcM5pI2w9JIlKyjFK0m9QK8mge/enxaAuo8DA=;
        b=kExWJL92R381CFJG4A7t5snJ95ugJvpseJ9UjdnZ4XQ0rquyXcBKwD9WqEIcwlrcro
         +BsZNRUjtKbLXafWGDcRvK8b99+rZqOLshp385VP9If9qYS/TxEOIba8BAV4W784KUS6
         4Td0D30q3yluB9OHSzonsxCxAroH8PpM+25ni6phWZFPjzexl/mDkS3RUnj6IixeB8ys
         X+UBOlJO0ST4vD0/cdMLImHmoAV7ZOrdA1TtzsmEjlOXIScdMnY2qOL3FYHseE+Sq7g0
         KPfYfBGhBd1cwZhlNWRq58FjM5ZbpX2eoiWLzS0y2wFJdSZrfB9QimcwEe6IYoxr5ohR
         O7Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b="d2mt6W/a";
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c339ca7si781358f8f.0.2025.08.14.08.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Aug 2025 08:28:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-55ce52ab898so1168612e87.3
        for <kasan-dev@googlegroups.com>; Thu, 14 Aug 2025 08:28:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW6gb7HHdrQrn4t8bXdTDvBeZhnYSaRnO1lEWw0oFYjuK4196eus+Ij3zSe3OqW5Ew2S5NmYksO0SM=@googlegroups.com
X-Gm-Gg: ASbGncu5x7FrlA3KWu1yL8Z4bd1ZVyhNncMEKSQBX6EAUXlpSzfalhDuN6GusIgKFGg
	S/aWxNA+jKlTVbr1MqWlDIvdqKOUbsAQOn3eg1/C1Vrhsutv93kt1ofwlAclEteZXXjGuoAQcRL
	ArF8EtKE2f3kAlwolRMsVCR9TR5LSOwuc/z/Zoz8qmPbjCN7ViJtHf0UiQhVtA06UADqFNBMrqN
	wtEWF6UmRc9w6YuznOXzt1EOA==
X-Received: by 2002:ac2:4e16:0:b0:55b:8540:da24 with SMTP id
 2adb3069b0e04-55ce50133c8mr1226637e87.20.1755185305657; Thu, 14 Aug 2025
 08:28:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
 <20250813133812.926145-7-ethan.w.s.graham@gmail.com> <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
In-Reply-To: <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
From: "'Ignat Korchagin' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Aug 2025 16:28:13 +0100
X-Gm-Features: Ac12FXx9I9MrbtuwHaesyssft3AApB1lCQVaDorKwBHz1btfjTXbPnGjfwlVOBI
Message-ID: <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Marco Elver <elver@google.com>, Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com
Cc: glider@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ignat@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google09082023 header.b="d2mt6W/a";
       spf=pass (google.com: domain of ignat@cloudflare.com designates
 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
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

On Wed, Aug 13, 2025 at 7:14=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> [+Cc crypto maintainers]
>
> On Wed, 13 Aug 2025 at 15:38, Ethan Graham <ethan.w.s.graham@gmail.com> w=
rote:
> >
> > From: Ethan Graham <ethangraham@google.com>
>
> Should also Cc crypto maintainers, as they'll be the ones giving

Thanks Marco!

> feedback on how interesting this is to them. Use
> ./scripts/get_maintainer.pl for that in the next round, and either add
> the Cc list below your Signed-off-by so that git send-email picks it
> up only for this patch, or just for the whole series (normally
> preferred, so maintainers get context of the full series).
>
> > Add KFuzzTest targets for pkcs7_parse_message, rsa_parse_pub_key, and
> > rsa_parse_priv_key to serve as real-world examples of how the framework=
 is used.
> >
> > These functions are ideal candidates for KFuzzTest as they perform comp=
lex
> > parsing of user-controlled data but are not directly exposed at the sys=
call
> > boundary. This makes them difficult to exercise with traditional fuzzin=
g tools
> > and showcases the primary strength of the KFuzzTest framework: providin=
g an
> > interface to fuzz internal, non-exported kernel functions.
> >
> > The targets are defined directly within the source files of the functio=
ns they
> > test, demonstrating how to colocate fuzz tests with the code under test=
.
> >
> > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > ---
> >  crypto/asymmetric_keys/pkcs7_parser.c | 15 ++++++++++++++
> >  crypto/rsa_helper.c                   | 29 +++++++++++++++++++++++++++
> >  2 files changed, 44 insertions(+)
> >
> > diff --git a/crypto/asymmetric_keys/pkcs7_parser.c b/crypto/asymmetric_=
keys/pkcs7_parser.c
> > index 423d13c47545..e8477f8b0eaf 100644
> > --- a/crypto/asymmetric_keys/pkcs7_parser.c
> > +++ b/crypto/asymmetric_keys/pkcs7_parser.c
> > @@ -13,6 +13,7 @@
> >  #include <linux/err.h>
> >  #include <linux/oid_registry.h>
> >  #include <crypto/public_key.h>
> > +#include <linux/kfuzztest.h>
> >  #include "pkcs7_parser.h"
> >  #include "pkcs7.asn1.h"
> >
> > @@ -169,6 +170,20 @@ struct pkcs7_message *pkcs7_parse_message(const vo=
id *data, size_t datalen)
> >  }
> >  EXPORT_SYMBOL_GPL(pkcs7_parse_message);
> >
> > +struct pkcs7_parse_message_arg {
> > +       const void *data;
> > +       size_t datalen;
> > +};
> > +
> > +FUZZ_TEST(test_pkcs7_parse_message, struct pkcs7_parse_message_arg)

Not sure if it has been mentioned elsewhere, but one thing I already
don't like about it is that these definitions "pollute" the actual
source files. Might not be such a big deal here, but kernel source
files for core subsystems tend to become quite large and complex
already, so not a great idea to make them even larger and harder to
follow with fuzz definitions.

As far as I'm aware, for the same reason KUnit [1] is not that popular
(or at least less popular than other approaches, like selftests [2]).
Is it possible to make it that these definitions live in separate
files or even closer to selftests?

Ignat

> > +{
> > +       KFUZZTEST_EXPECT_NOT_NULL(pkcs7_parse_message_arg, data);
> > +       KFUZZTEST_ANNOTATE_LEN(pkcs7_parse_message_arg, datalen, data);
> > +       KFUZZTEST_EXPECT_LE(pkcs7_parse_message_arg, datalen, 16 * PAGE=
_SIZE);
> > +
> > +       pkcs7_parse_message(arg->data, arg->datalen);
> > +}
> > +
> >  /**
> >   * pkcs7_get_content_data - Get access to the PKCS#7 content
> >   * @pkcs7: The preparsed PKCS#7 message to access
> > diff --git a/crypto/rsa_helper.c b/crypto/rsa_helper.c
> > index 94266f29049c..79b7ddc7c48d 100644
> > --- a/crypto/rsa_helper.c
> > +++ b/crypto/rsa_helper.c
> > @@ -9,6 +9,7 @@
> >  #include <linux/export.h>
> >  #include <linux/err.h>
> >  #include <linux/fips.h>
> > +#include <linux/kfuzztest.h>
> >  #include <crypto/internal/rsa.h>
> >  #include "rsapubkey.asn1.h"
> >  #include "rsaprivkey.asn1.h"
> > @@ -166,6 +167,20 @@ int rsa_parse_pub_key(struct rsa_key *rsa_key, con=
st void *key,
> >  }
> >  EXPORT_SYMBOL_GPL(rsa_parse_pub_key);
> >
> > +struct rsa_parse_pub_key_arg {
> > +       const void *key;
> > +       size_t key_len;
> > +};
> > +
> > +FUZZ_TEST(test_rsa_parse_pub_key, struct rsa_parse_pub_key_arg)
> > +{
> > +       KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_pub_key_arg, key);
> > +       KFUZZTEST_EXPECT_LE(rsa_parse_pub_key_arg, key_len, 16 * PAGE_S=
IZE);
> > +
> > +       struct rsa_key out;
> > +       rsa_parse_pub_key(&out, arg->key, arg->key_len);
> > +}
> > +
> >  /**
> >   * rsa_parse_priv_key() - decodes the BER encoded buffer and stores in=
 the
> >   *                        provided struct rsa_key, pointers to the raw=
 key
> > @@ -184,3 +199,17 @@ int rsa_parse_priv_key(struct rsa_key *rsa_key, co=
nst void *key,
> >         return asn1_ber_decoder(&rsaprivkey_decoder, rsa_key, key, key_=
len);
> >  }
> >  EXPORT_SYMBOL_GPL(rsa_parse_priv_key);
> > +
> > +struct rsa_parse_priv_key_arg {
> > +       const void *key;
> > +       size_t key_len;
> > +};
> > +
> > +FUZZ_TEST(test_rsa_parse_priv_key, struct rsa_parse_priv_key_arg)
> > +{
> > +       KFUZZTEST_EXPECT_NOT_NULL(rsa_parse_priv_key_arg, key);
> > +       KFUZZTEST_EXPECT_LE(rsa_parse_priv_key_arg, key_len, 16 * PAGE_=
SIZE);
> > +
> > +       struct rsa_key out;
> > +       rsa_parse_priv_key(&out, arg->key, arg->key_len);
> > +}
> > --
> > 2.51.0.rc0.205.g4a044479a3-goog
> >

[1]: https://docs.kernel.org/dev-tools/kunit/index.html
[2]: https://docs.kernel.org/dev-tools/kselftest.html

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALrw%3DnFKv9ORN%3Dw26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A%40mail.gmail.com.
