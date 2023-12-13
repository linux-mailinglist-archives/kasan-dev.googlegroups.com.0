Return-Path: <kasan-dev+bncBDW2JDUY5AORB6MB46VQMGQEL6TRN5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43EE88114B0
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:34:35 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-20329a8f16bsf392715fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 06:34:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702478074; cv=pass;
        d=google.com; s=arc-20160816;
        b=h4+o/LfBUPVDyknNz6FMJ4HaDXZ1q26uY96YEgg7rhx0mEXTaTbS15GZOwsygZE4h4
         s3V4Gn9s+Qi8M9zLqvYtWiCqHyTVxxq2bd+9zoyz3CXh8dfAq7cr0QqjoUj2suwH1IxS
         i7m7954X5Mmmyfjfj6eRtiVQUO198h6YuX36vdQjKhWfV/BNcjSBIXj8lNcUOnjanacC
         nfzfwq71nGPdfXlk74+amuJshAgym+jM1Z+AGgRRs1m8sSTTNJ6i0ZXjlonZEeV6DqCw
         yzca1MnJAagSURwwojKaQSgNWGJRbBYRlNdnkoc+9zQdpEP5e85QBwbyKdbhgOFxHc3s
         wLgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=U/qSCfMF6Pyg0g1r/VWEp24VqGdBNmL2gm57e595kZk=;
        fh=mcsOkjSKiIVqZTSI0nnbwoKVuIQQbBRaZcAvv5Fi9PY=;
        b=H3nQxN6oPevk+YI7h59d47BISZNjLaUBp9vMk6+q571Gk1vTx/8rGviF52wqfQIRFI
         OteJ9pCrbe90jX7Xomrz9ytvPDV+p3ENUif9Fn9epjiUJ8k7osZ9tQX2Dv+M0Xx6PE3Q
         6t9KL9mi0R1YxiAetDdM5I9hLr1J4CQNhkbNO+pqCOc0/7RT0FN322uh1Ldk5y2boC6k
         yIPlEgWsPpO9sBKcoxfHZOGD1AAXQb92iZq1sS8Asq1767+9O3jtDsXZyh3woqiACKUa
         3bMnwcbioIWlBPJ2QT1NvvQSX9+9Skb2SXBTipPha7U9q7xXbnIw8z58tQ+jLLKAi3Zb
         Stug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OVcmu+jk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702478074; x=1703082874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=U/qSCfMF6Pyg0g1r/VWEp24VqGdBNmL2gm57e595kZk=;
        b=SbIZqM6pKg9mxLGRboIbjvYYKQz+7LMUNrA1jRQvkumpEa+18XC9DI+Wnz03YCrSO5
         FAMWfercsEtrPBN9pulcazu+866YaZxxCpKqzYSAtJ8bQ//qyKhTO6BJnfQ/zaEWNpH8
         KFqaiyl77AUvJiZU0Q3fGbiBO8Wjm95KJsxT2R8+GMoIXf9gQI8com+KwttfkJxAYvBw
         66qUpToE1sd0lOegL3aW9NJNyxb+WeIKnUJmsKNnk5OSIxeCU1qQXAY3MihfxnMAey6A
         p8mLXS7d+fpZv3VLx5Okod7jT3bkLfSI1Htx+Mk2ABDGCvUFPXFVRHR6rmuoMrLtrmVd
         Hpow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702478074; x=1703082874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U/qSCfMF6Pyg0g1r/VWEp24VqGdBNmL2gm57e595kZk=;
        b=K7NF18QLSv1bFIgoZcqYMFVKPkIzExKQU2RbtU2jzBp/I/NpwpaL+O44Eyxj1oOzEm
         3aUOPEMqjqh2hnntx9ss1YEiK7Qq3k9CUrKRyuvMQzGWE0p4UL+qTpRKWq3IJFQjr37l
         vbapoLI5iLEMTj85MOWb3BJM2mfjzDYhFoB/WM+npffMidcLhF7jxG9YoSiHXcquLhYt
         odAgnkSVZIRb48HyrUBwI905LJ0mRpe40O4AXKI3PyP9Vjd4o19O2Ma68gM05MDUFIvs
         HC6GxWvdeWqamZFt512V6kN0aDr6aitVYQkNtCnzXx1C8Y0TFGWnJo2KcZlZzk2eEGfp
         asiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702478074; x=1703082874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=U/qSCfMF6Pyg0g1r/VWEp24VqGdBNmL2gm57e595kZk=;
        b=Pzlhtb+CpgHJDfPoBbDCmbiC87HffUzs0LgurXMfQ2WcA4V4iCQUHX/67iqhnUI7/1
         bpP/g6vk90WRqwtHu/a5CIsUxRBq4/Qs2t0Oup+cBwdJ0nPv/WVepJbKR1N5zsrl/poX
         jLV8lAHo4PQEdewiyEAaTHcpEPl2DEW5+JjmtD0cjkzyKCImWoG2kkDKNR7HqAb34GoN
         ktcIeL5z7YPsaX3wRKnvC+7/Srs4a4U3LGQ/tzVcBtm7EN4dg5KwxcRuXTrjo7+zbqQF
         sK0Hs43vNHh8XqKBB0UX6FKkH8PZFYNqFxMGiszzS8VnkfW1giKNZ7h6zH/IGjTk6Hrt
         rIUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzkRmDdfUHYgTca3kbqElsgfFGwSlDqGpq0/DkU7gOk9XKyQebQ
	g8VAAN2hISyNVCZvumxZjMEPTQ==
X-Google-Smtp-Source: AGHT+IF6VgKIcw18lR2TLHGTU25u0La4e+03izKoqxzms6Ca37LcA+8q6fde/mAx8+wuFTkh0qA5Bw==
X-Received: by 2002:a05:6871:4390:b0:1fb:75b:2b8f with SMTP id lv16-20020a056871439000b001fb075b2b8fmr5987962oab.75.1702478073851;
        Wed, 13 Dec 2023 06:34:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3a26:b0:1fa:1efd:f65a with SMTP id
 pu38-20020a0568713a2600b001fa1efdf65als885931oac.1.-pod-prod-06-us; Wed, 13
 Dec 2023 06:34:33 -0800 (PST)
X-Received: by 2002:a05:6808:3209:b0:3ba:3f5:9b60 with SMTP id cb9-20020a056808320900b003ba03f59b60mr5709680oib.110.1702478073214;
        Wed, 13 Dec 2023 06:34:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702478073; cv=none;
        d=google.com; s=arc-20160816;
        b=GccZ4b28RTbsSlSk9bdpdXYIobZppnktEVHEJ7QT5jxnrCHzCAi5xfwg8aeKr0oSBa
         aIjFj+FiZGxSPkfa9B8iYUR52G9Jk7I2qNgb9xiKqbqI8no1wFE4/DrAxdpHkeY+9Nwk
         trr5RYXJHVpIGG8JWxIVwmGM14NWFXs5/qN/aTxtkEpPtZs4J8mAJFG3CHPvAF3a4vTt
         3qsJb33zzQcfNySthTqiK99BUZpt8EV5uXDwZQ6G2avf5GePnfSY76VZVOoBk7gyzz9s
         i9YO0qyBEDUY7XWDV62N3GBbPGU1uatDeEzSKveRKKodyWnDMTGCPdzNiCnOnTzE3h9l
         jqPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cbOaPVmJ7E4boaoj6IocNcjRghNie5jLjB39Y35NZkE=;
        fh=mcsOkjSKiIVqZTSI0nnbwoKVuIQQbBRaZcAvv5Fi9PY=;
        b=jtcmHQHrN2xDNcetNSW1iPdMASUPrAm5GVBuo3JgxlcoIoOd1l4akF/J27UnXWS/Ww
         I77Q+vTthA4KhO8tnDuOUHaKUv+Q89clOYnTZA6xt3oHKkMCeUhF11KWHpVSej3j1UNE
         KMt+cBN+QDF4FZFIVOvk45AcAmweoW6v62brmo/twBNuU1lmf0ofPqXXffw/33pqYw20
         nsZnjD6zU61NgwBceEHJ0lATrA8i+wWwJ7I16DOTnJc1AJwIWa0j6IeSxYRauHHXLzKN
         ZK68twUXC0Frl+8M4cjfR8xoaYN8tdrzuUiOpsdZdw8tMRj15HvsbKMSfafNIuVYbB6W
         Ghxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OVcmu+jk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id h37-20020a0561023da500b004649987350fsi2976406vsv.0.2023.12.13.06.34.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 06:34:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-6ce72730548so6201875b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 06:34:33 -0800 (PST)
X-Received: by 2002:a05:6a20:2590:b0:190:7d54:f0c4 with SMTP id
 k16-20020a056a20259000b001907d54f0c4mr10315674pzd.87.1702478072405; Wed, 13
 Dec 2023 06:34:32 -0800 (PST)
MIME-Version: 1.0
References: <20231212232659.18839-1-npache@redhat.com>
In-Reply-To: <20231212232659.18839-1-npache@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Dec 2023 15:34:21 +0100
Message-ID: <CA+fCnZeE1g7F6UDruw-3v5eTO9u_jcROG4Hbndz8Bnr62Opnyg@mail.gmail.com>
Subject: Re: [PATCH] kunit: kasan_test: disable fortify string checker on kmalloc_oob_memset
To: Nico Pache <npache@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	vincenzo.frascino@arm.com, dvyukov@google.com, glider@google.com, 
	ryabinin.a.a@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OVcmu+jk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::431
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

On Wed, Dec 13, 2023 at 12:27=E2=80=AFAM Nico Pache <npache@redhat.com> wro=
te:
>
> similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
> FORTIFY_SOURCE") the kernel is panicing in kmalloc_oob_memset_*.
>
> This is due to the `ptr` not being hidden from the optimizer which would
> disable the runtime fortify string checker.
>
> kernel BUG at lib/string_helpers.c:1048!
> Call Trace:
> [<00000000272502e2>] fortify_panic+0x2a/0x30
> ([<00000000272502de>] fortify_panic+0x26/0x30)
> [<001bffff817045c4>] kmalloc_oob_memset_2+0x22c/0x230 [kasan_test]
>
> Hide the `ptr` variable from the optimizer to fix the kernel panic.
> Also define a size2 variable and hide that as well. This cleans up
> the code and follows the same convention as other tests.
>
> Signed-off-by: Nico Pache <npache@redhat.com>
> ---
>  mm/kasan/kasan_test.c | 20 ++++++++++++++++----
>  1 file changed, 16 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..5aeba810ba70 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -493,14 +493,17 @@ static void kmalloc_oob_memset_2(struct kunit *test=
)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t size2 =3D 2;

Let's name this variable access_size or memset_size. Here and in the
other changed tests.

>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
> +       OPTIMIZER_HIDE_VAR(size2);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, size2));
>         kfree(ptr);
>  }
>
> @@ -508,14 +511,17 @@ static void kmalloc_oob_memset_4(struct kunit *test=
)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t size2 =3D 4;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
> +       OPTIMIZER_HIDE_VAR(size2);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, size2));
>         kfree(ptr);
>  }
>
> @@ -523,14 +529,17 @@ static void kmalloc_oob_memset_8(struct kunit *test=
)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t size2 =3D 8;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
> +       OPTIMIZER_HIDE_VAR(size2);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, size2));
>         kfree(ptr);
>  }
>
> @@ -538,14 +547,17 @@ static void kmalloc_oob_memset_16(struct kunit *tes=
t)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t size2 =3D 16;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
> +       OPTIMIZER_HIDE_VAR(size2);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, size2));
>         kfree(ptr);
>  }
>
> --
> 2.43.0
>

With the fix mentioned above addressed:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeE1g7F6UDruw-3v5eTO9u_jcROG4Hbndz8Bnr62Opnyg%40mail.gmai=
l.com.
