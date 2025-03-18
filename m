Return-Path: <kasan-dev+bncBDW2JDUY5AORBM5E427AMGQEKGTDFTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D6364A677EB
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 16:33:08 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-5e83e38d21asf6132348a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 08:33:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742311988; cv=pass;
        d=google.com; s=arc-20240605;
        b=XsDWYzdY5iDWA43p6VdfbyEedcCkI8rC8jBGrBGI4zNqjnysbjmXBqHTiI5piAxB5O
         EaLtSbGFtW7ktFV7iuHtRenLv0P4VrF0oYuoWFKK+vITjcHfPkirPEYJQV3noHNEjmHf
         VxFlpdypY6yHxu5Tlk9BUIdMV74uOoIAJ02VQ+C3TZfyyrQVY5NXRtPcfI4URognTj2a
         sGe/Uy1PXa96B1vw9ft74tQi8P8WDojgz2qmZz8dJIjxWw5IU39MortjivJzo1NkdG3h
         IS78RJVywS3OKG+G3GT+3RsUrvkQPYBp3il+wb3STtnFeV3NN+FK+YXFFQGemV94YqjM
         srWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=mhEGWsNtQdmd1V/5iJvYOk3W6+jhBD1G457AhszTmDc=;
        fh=j5tcG9m56SbDuP7OlkzItUHav8o/x6IhstzmVaCeufI=;
        b=EabDcClPoypq5RtkfBHXp4QyIf9YGAiJ6vTq8xcflIRvl0LwfAy66yBqLo8SEQkNwM
         dhWZdZBNdnw3YLPBaCTRWpbfxzBZlWYLwteaNOUeTB6qRJO/Zz6R6LeqEadtAIPyPIWb
         j6/FjgtOWR00dBQkhiYLDJW+Lf1XlBViM0snYIls5Wp4EcXdtceW7pyQA7tHX23GFXAU
         RtHtTKHDh/X57rQULORIU+Dr7VdwT+SY2YtFgudUO95qgyZYk8/gAmckp+QZtwqywd8D
         vs7Cq19kRNpMO/VDu1WnO7PeZl3IXn4YdRLNGghgIEhGrEXCwFhsZ24Gcp2/ZJTe6C2e
         MX+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mwouRKcr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742311988; x=1742916788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mhEGWsNtQdmd1V/5iJvYOk3W6+jhBD1G457AhszTmDc=;
        b=wVT3eFdn9p68fgHzeJ2BgfX5gkp+3E0OITVavCixM71TurID3zacVUTtdfO9AV8QUr
         73R4aWGjhbd6KYOqqS1JZvlM/o8J4kF0Up/9MFXbs4pIn3Pvgm4Ijx2JL0Krhbc5v51F
         ZsQprBhzUVjuvs2qJoBq5I+EBYRDm6k1HDD6NCNY8nuUvU4365VRPGzLZrN3GauixdvD
         O7Vl7iW/ab0WNbfR+Ujq3Z4RIL6Z+BibHG1GK8PBclxXoSyfut1n7bS31UibZlN4Ditu
         7kKuePwDoDDaaacrWLHsC2RtTmdz4HwKujmdYzjqeduAWUjK2bVM9nuW2gnotyvh6GsR
         W9bA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742311988; x=1742916788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mhEGWsNtQdmd1V/5iJvYOk3W6+jhBD1G457AhszTmDc=;
        b=SsJ/MRzqMaSfEWWdnm8JUXkDA0487n7/pc5B8OKqlKrgBedeKn0Hm82l3RcYFYQ9o+
         zTGNyITt31vs97Eg4LdcqEnWSi2VlPUA4qFtIIcIEL7cesfU4DnIvdTJleGyNo//260V
         NSEl2ifT4ZuIrfY0onFbli/F0jbQKJUqgsJQCDKajrxEwhbn4kb5A4R5yasmu6AKIij3
         bUXdpEt+R8PbbPNYtHTLV5uV0IMcO1jBZ4WL56tmVAGjwMk/5hN2wkXwOEUjgyxNdL9Y
         yCkGpq0oC2p0y9SIa9AKxGEcMZmvjdakLFe360NiAJ+OdLdjuXLKoWpL5diV9IkJU7gI
         /SJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742311988; x=1742916788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mhEGWsNtQdmd1V/5iJvYOk3W6+jhBD1G457AhszTmDc=;
        b=be5nfRw8XKJXsHNHv1Xmw0HJ6B+7PVBjcOxBNG3nZmJlYE2mDvyAOR6a/a9WuroX+n
         4Ay8LyhHtp9/Ulr3BF1pofXYNlVKy80hpMs1nxvow84Qln3trq8DNb1IIbt89KDY26Ye
         j1iHX5UmXM04U+bOHSYH2X5L52R9IUKX8z1rXsW6NJcn5UbYZDrUacyzLR8M+oe+4nLb
         Nu4ETljN8bPrNYkmSc5lrFbxt1KzUv8Ckf7SGNKLiwCGvEAj77Og7QYwZFZ7zutZ1yQS
         UyDfSD+Bt34P8g1yBn4bZIpSp7DqhQUKt9LiN2dkOUOAHw819xZ5HXamDS3CWklJci5x
         m7cQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdRs1puB3ONfGzmrixtTJyxQYejyBSThlSoDrIDEvIKeXUvfBr7vOagznsW1vqmKBArYHz9g==@lfdr.de
X-Gm-Message-State: AOJu0YyM11ktogUjzQN+r5mIjmRwpKPEVxNRPvTLP/cpbVGNcJbi3QiO
	oxLfggiq1TLocK8t2HIoQr2pxqhmNSBplTFqAdt7dRs10luVlwY+
X-Google-Smtp-Source: AGHT+IFjM9pqvWZZhMC7j2oMMvg9Nd5HJykOWpjFi+liH48iwcZM5bGiPHRoJtpgJcOolPN/SphZVQ==
X-Received: by 2002:a05:6402:2554:b0:5e0:82a0:50dd with SMTP id 4fb4d7f45d1cf-5eb1dfabb24mr3867055a12.27.1742311987451;
        Tue, 18 Mar 2025 08:33:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI1Ni4tPDOVZ5NqJIZYdM/FiRpbw42Zbhx2CSWJSuTKNw==
Received: by 2002:a50:a411:0:b0:5e7:7251:5a1a with SMTP id 4fb4d7f45d1cf-5eb7cd72d21ls88348a12.1.-pod-prod-03-eu;
 Tue, 18 Mar 2025 08:33:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVw4ciw6GnrXnwKPqRfpL8HY9LnDNXMS7/ZWJX15TUdjp+Q5UOhigMq4mEa1TGqhiGk6F/RyZYZH3M=@googlegroups.com
X-Received: by 2002:a05:6402:1d49:b0:5e0:60ed:f355 with SMTP id 4fb4d7f45d1cf-5eb1df090f0mr3965286a12.18.1742311985035;
        Tue, 18 Mar 2025 08:33:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742311985; cv=none;
        d=google.com; s=arc-20240605;
        b=ICqexBtcHpkYLyCrKqeX9G615y9NIYhdmOx7vVv7+m6yEgSGPYpAsu4qI2aJzWK+Xc
         6R0OTY5Q+X9aErI8aB5549m0bmGcO+DNar4iwiGpXiy7Ln3r0FDEFHbQK0HMjwJ+5t6y
         t1uUUbz1AkeRUrwuIAajOiBptyd57MfFz6+qIK1/oaA0V/9nk+HJmCg4VibbtrBF5tII
         gya0R6l7SLe7vkhbnk7tV5+MYzjCQOao1yuhrb4ZTGsa9PA2iX/9e4kNjK5sMn9S/Mfz
         qFLhAuF74pNFQCg6/fYwNvDF9tvdcqRwFTTfaUvR1zpXJpiqUobpGegv4gdC79fucnJ6
         I46g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pQedOYF0JbGhNTsRLu/QrPIdEyMAq9Lyufwf1HjqHkU=;
        fh=5Fkz83hD4uWwG/0YO2h77mnFgPW+Pundswy0ghxUlaE=;
        b=XldpkXY/0cWvVYkXc6Euszh89wHSJ5O8146JKTsmQWtz+0T4dsBMLHqRRqcC+DaKns
         mlwN6xChQ0FaF1lHi8XzlIW/nvy6JlBtA8aej6RdTQe/07jZOVTbuQIgLXAl7S9KhpRZ
         c7kf/RVebN8qk+ilxyCSKRzAeU/lvrhY8W9ufey1LwDG7eNo77QTFPk9J9ojTBgz7dZl
         Xz9MBkW6XY1bA9vwrzSyqtx+X/lFbzoHAv9LQg1GfVcsuNOIz3p4s/LpzGKLGkU1PmYT
         kzkZaNlzHNODFLVv/b3eaoW/f9TXvxfH5dpIjjjQM5EJU9YYjlsPtW9U3psjQpnswh/t
         z9Lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mwouRKcr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5e816ada5c5si368073a12.4.2025.03.18.08.33.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Mar 2025 08:33:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-390e3b3d3f4so3540658f8f.2
        for <kasan-dev@googlegroups.com>; Tue, 18 Mar 2025 08:33:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXIn1XImE+jdxThHVvO7A6/ow4Rz771DCJBIAkGvnW7FCV22pY87kH+d9yqhiJP1WJKyPRSPJDwsgo=@googlegroups.com
X-Gm-Gg: ASbGncu+ok35t6w23LM/T6DvIXscabcsNuY7v1QMpb4CBK20BToz7J1e+SGDVzjfrXT
	+AJicIdln4d8B4Nhtdcfji9wB6gKXSuMjoqpfL4G0dKY1/TKgg88UrACVH3oCS5vSsmmGbcLwt0
	FW+2x19cSaHxNcBUgPQvyKbFKoxlOvc3pv9iRCvg==
X-Received: by 2002:a05:6000:402c:b0:38f:37f3:5ca9 with SMTP id
 ffacd0b85a97d-3996b4a1f12mr3500096f8f.50.1742311984401; Tue, 18 Mar 2025
 08:33:04 -0700 (PDT)
MIME-Version: 1.0
References: <20250318015926.1629748-1-harry.yoo@oracle.com>
In-Reply-To: <20250318015926.1629748-1-harry.yoo@oracle.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 18 Mar 2025 16:32:53 +0100
X-Gm-Features: AQ5f1Jp2LdhedIBpqplA-ibdx9fucHDmyRIqhF4hweSMbvA5brq57w8VLaw2NDA
Message-ID: <CA+fCnZcnkL4g1Do0MjwzEUMgQuS+5oWkcK7yaWy8Xvfd4uJxPg@mail.gmail.com>
Subject: Re: [PATCH mm-unstable] mm/kasan: use SLAB_NO_MERGE flag instead of
 an empty constructor
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mwouRKcr;       spf=pass
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

On Tue, Mar 18, 2025 at 2:59=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> wr=
ote:
>
> Use SLAB_NO_MERGE flag to prevent merging instead of providing an
> empty constructor. Using an empty constructor in this manner is an abuse
> of slab interface.
>
> The SLAB_NO_MERGE flag should be used with caution, but in this case,
> it is acceptable as the cache is intended solely for debugging purposes.
>
> No functional changes intended.
>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> ---
>  mm/kasan/kasan_test_c.c | 5 +----
>  1 file changed, 1 insertion(+), 4 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 59d673400085..3ea317837c2d 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1073,14 +1073,11 @@ static void kmem_cache_rcu_uaf(struct kunit *test=
)
>         kmem_cache_destroy(cache);
>  }
>
> -static void empty_cache_ctor(void *object) { }
> -
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>         struct kmem_cache *cache;
>
> -       /* Provide a constructor to prevent cache merging. */
> -       cache =3D kmem_cache_create("test_cache", 200, 0, 0, empty_cache_=
ctor);
> +       cache =3D kmem_cache_create("test_cache", 200, 0, SLAB_NO_MERGE, =
NULL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
>         kmem_cache_destroy(cache);
>         KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
> --
> 2.43.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcnkL4g1Do0MjwzEUMgQuS%2B5oWkcK7yaWy8Xvfd4uJxPg%40mail.gmail.com.
