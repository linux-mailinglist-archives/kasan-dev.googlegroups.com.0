Return-Path: <kasan-dev+bncBDW2JDUY5AORBWXF5WVQMGQEPAV7G5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 580A3813C90
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 22:25:48 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6d9ecd37a4dsf37837a34.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 13:25:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702589147; cv=pass;
        d=google.com; s=arc-20160816;
        b=ega4P4wEIEOw3PR7wem86+8V/fH1aaB1P1NbSW6gMq23yzgA6r94M2RYhkc33uwV3F
         NFk7Bkyec8WD2u2sJjYeOqwPJ7tlgjXBw/X4rle86ErCLKEsbezSrDwvNlpq9CYrN73C
         tjFoDwGrWHlntb7k0bdhvGA+fEiUZC1vC35Kqu9Jddwbty3Ztqji6YkOZHbl3qNO9SOK
         qU3zV8Qfbsm94mbaseXmqAwnrwkkpZ+/JQv4X9GwbGL8bjW+/fGmMuy6Ovh18QhQ/weL
         uxnNNCujlOD3ntMEb/DxfYNAkGj5a9hLDD0tLnXBrV1aJJRssXbHW284aQ/suDqatnc8
         t33w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pHGVqbFOGxf6xg0bWJZdHr7AW8FKeP1sL59RdTXEF3k=;
        fh=mcsOkjSKiIVqZTSI0nnbwoKVuIQQbBRaZcAvv5Fi9PY=;
        b=WThK0uluWtZRLdvmBUxSUbK6juti8cxSFGkRy2azmGexTDOj7Bfu6m0Jldc7T+Gzqj
         iETINIHpKGuvUVA+NIM3jfVeI8Ws/GWQvjLQVl7yUNQ9anwp+6Aa+8JB2VlhPbuEx+IV
         XJqFQtBdh4mHnI6ViN6rkmecWipoFK+O+Y6SCrhpXonYxy0ApOfG7sdX1auNg446zl5Q
         131/dqQCbEDXPItlHVLEkdLLfXnmbl3vlnfAZagsUguQaBfXs/ewzRgtRUZmRJrVXHlw
         G2pOGzhqSDxJu9b6j4mikAD+uX0xinyiJ4E6qCZj6vKnIh7mLxgh9JR4VFV4wN3Nk2RN
         5PYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HSZgqjDR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702589147; x=1703193947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pHGVqbFOGxf6xg0bWJZdHr7AW8FKeP1sL59RdTXEF3k=;
        b=ZW5bpJyTmTjobip/ETQZqbyIRtewDEhpiCe3pRHZh/s3CISeZ/SQoj/TOea2NYn3su
         6XXCFKMbvt9nt+71eZTXrXqAcTK6aTgbiZWorj/zrwgbgUutZz4/w4NWsIuIy3waIWDE
         z1j+pxoGqHWjdtMUxj2Ap/gB2ypOF86RnGiA5AXN9viSeECSB6P7fyxt6YcJM+Jfk50I
         D3fI2DcxexavlozRjFl5JNZr2JVeLEXN6XRr1sh6nzS6PMx3YC39GFPxaarlQOUH1g85
         /IBGI8OoSNMp4v3aD0cE8gFep6v9WnpJVzAqDXMUBQ2QCbEhNM13bOeP+9rGxwCzpfYA
         7dOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702589147; x=1703193947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pHGVqbFOGxf6xg0bWJZdHr7AW8FKeP1sL59RdTXEF3k=;
        b=Jt7KwENrjX+tuDDr77ToTVeSu8H+GiqchLlEU8E+F0BafSnnvc5a2giGq0ZaocKWVY
         diP0KsnDnB8C/jXNdUgW3kGfLNHwNc0+BDTIhnD1uczdZroCnsmo3ViVhpFuZY8SvLbZ
         gkJaTji+8va5PvHFPGxcdTjd0u8E8Q/D9cCy9BImY2fadEbFtNSHkR1VvP1X9LExknih
         6+VcaQpUMLyzvsvoBoHn95DVcsGShhRexic5ko7b5wa+qa94zL+sqGV1WUIMNBJ520Vz
         bRYHkbuSgh5poty+htsSZaxKiSfkcLjNSgarLgf3r08yVR2EB4XGW3RX5EoIjHG+4eoL
         V39w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702589147; x=1703193947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pHGVqbFOGxf6xg0bWJZdHr7AW8FKeP1sL59RdTXEF3k=;
        b=xGxViKbZn5v9w2DwjLWp+eNqr2lTjfmG53q0m1HdS30nVArHASp1FMESai1TzggibO
         dLCDh2h5cazsWDRcXB0RGsG1boQpXtKBo1VaT1o4E6NU0YswOFGHTAs5r9kfLIx/7nkZ
         QwwE1bMIMPhMsfNrhUO7Dd+BjdSQuBwyNGTNd3iTv6JBPZRd15lSrM/3AIPf8uNJrMkS
         r3APJxxrXedHcdqNb+h9uRn7DqZx3MikVy206ZMQFAJZehdOduVNXNhuaLRaR4HWCGmv
         dDsnzFhnC7AiePlTJqNIyhNCtRvbCBHZ0zW4j5+IF+p4AlSoy6ZvcsTGJbnYgxubbNhY
         mT2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw2Cycfbx2nYQHZ5eKyGlVEyvrL+UeUNKvSDGUGxVMZhfR6S9Bo
	j7S0x+0YkxkJcgPe1V6OCCY=
X-Google-Smtp-Source: AGHT+IGO3XxTj0E/L31n3tSFiijfPtALAgRAchOKUTg316U3CZWkdmuepTzvLVjV182qVXZ67CUwwQ==
X-Received: by 2002:a05:6870:210d:b0:1fb:51e:bc17 with SMTP id f13-20020a056870210d00b001fb051ebc17mr12012417oae.30.1702589146885;
        Thu, 14 Dec 2023 13:25:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6c11:b0:203:2714:10f1 with SMTP id
 na17-20020a0568706c1100b00203271410f1ls55207oab.0.-pod-prod-07-us; Thu, 14
 Dec 2023 13:25:46 -0800 (PST)
X-Received: by 2002:a05:6870:c1cf:b0:203:89b:4597 with SMTP id i15-20020a056870c1cf00b00203089b4597mr5227665oad.40.1702589146306;
        Thu, 14 Dec 2023 13:25:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702589146; cv=none;
        d=google.com; s=arc-20160816;
        b=SevAsgt6mINPYRf5sVCyWX0gVqGsj4y83OKqFLYnM9n9o77rIkUL/9Uc9m/3rcciaC
         iSjy8Acjf55AgQjwgZrHMPlhNYgABdZff2LOn6B1Q8OTTEQrNC5rVkr6TOnwtEEAHNBD
         mQRFDUR4AbLl/bcgf/NuirFrF+VQ7Mcpdp02629TGVDz2kQDosnrEIP/NOggqypVVCxz
         aMBcKIVM1j+Q3aFRzd40f5uHE+JcfTnUwmoEuN9dv+CZjJPshFC8xaUPyec2ciRSSF0z
         BSGmuxyTB4URIJSmSKpLy2JJvg75wrDed43b+LN9sZYQQFFAn2f5/ojSqpO8q9MR6AeE
         +7uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KxuQnaXteQq89l339+5l0KY/hocadQszL6EzwA8eJ60=;
        fh=mcsOkjSKiIVqZTSI0nnbwoKVuIQQbBRaZcAvv5Fi9PY=;
        b=eJvGR1wJjJw4WYLpfSfu0xVooEsD+d+9CnubIJM4f5wj2PwM+4ihWeunxwNhZF8MaG
         /Gc3IRqT8zd61n3lpZRrQndT64zThUkl3Zmd479fY5IyJaQXoBr1ErPOkhY4bMH5+LZF
         tci+E0H7l2ibeGR3UpYHgH25OlKWZxZgOmvOs7xqZ0adPinM8KMOLd0JbuVoWD9N1nH3
         28Cdutg4FRtlrUNXUwyuDAoGP0STVo1F/mEN7ZobatC9Scd9NZ0NV9k0PNoMvLdLghfL
         NiWqzZzzEwgzhyqxMroJaPx0MURthSeawWIBrlt/L3h7HjhB71MuncMgmD2ikPtjD+LV
         yX/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HSZgqjDR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id he25-20020a056870799900b001fb044ebe0bsi1629212oab.0.2023.12.14.13.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Dec 2023 13:25:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-28aeacb2dfdso1584550a91.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Dec 2023 13:25:46 -0800 (PST)
X-Received: by 2002:a17:90a:4942:b0:286:bf89:5db7 with SMTP id
 c60-20020a17090a494200b00286bf895db7mr5229758pjh.39.1702589145408; Thu, 14
 Dec 2023 13:25:45 -0800 (PST)
MIME-Version: 1.0
References: <20231214164423.6202-1-npache@redhat.com>
In-Reply-To: <20231214164423.6202-1-npache@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Dec 2023 22:25:34 +0100
Message-ID: <CA+fCnZcwS+8CKQEQGsNHU0zzkAVMBy7yiP=2wSuXMa2REzniKg@mail.gmail.com>
Subject: Re: [PATCH v2] kunit: kasan_test: disable fortify string checker on kmalloc_oob_memset
To: Nico Pache <npache@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	vincenzo.frascino@arm.com, dvyukov@google.com, glider@google.com, 
	ryabinin.a.a@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HSZgqjDR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
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

On Thu, Dec 14, 2023 at 5:44=E2=80=AFPM Nico Pache <npache@redhat.com> wrot=
e:
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
> Also define a memset_size variable and hide that as well. This cleans up
> the code and follows the same convention as other tests.
>
> Signed-off-by: Nico Pache <npache@redhat.com>
> ---
>  mm/kasan/kasan_test.c | 20 ++++++++++++++++----
>  1 file changed, 16 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 8281eb42464b..34515a106ca5 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -493,14 +493,17 @@ static void kmalloc_oob_memset_2(struct kunit *test=
)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t memset_size =3D 2;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
> +       OPTIMIZER_HIDE_VAR(memset_size);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, memset_si=
ze));
>         kfree(ptr);
>  }
>
> @@ -508,14 +511,17 @@ static void kmalloc_oob_memset_4(struct kunit *test=
)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t memset_size =3D 4;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
> +       OPTIMIZER_HIDE_VAR(memset_size);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, memset_si=
ze));
>         kfree(ptr);
>  }
>
> @@ -523,14 +529,17 @@ static void kmalloc_oob_memset_8(struct kunit *test=
)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t memset_size =3D 8;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
> +       OPTIMIZER_HIDE_VAR(memset_size);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, memset_si=
ze));
>         kfree(ptr);
>  }
>
> @@ -538,14 +547,17 @@ static void kmalloc_oob_memset_16(struct kunit *tes=
t)
>  {
>         char *ptr;
>         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +       size_t memset_size =3D 16;
>
>         KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
>
>         ptr =3D kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         OPTIMIZER_HIDE_VAR(size);
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
> +       OPTIMIZER_HIDE_VAR(memset_size);
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, memset_s=
ize));
>         kfree(ptr);
>  }
>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcwS%2B8CKQEQGsNHU0zzkAVMBy7yiP%3D2wSuXMa2REzniKg%40mail.=
gmail.com.
