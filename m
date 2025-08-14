Return-Path: <kasan-dev+bncBDW2JDUY5AORBRO76XCAMGQEEGHME4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DF5DB25AB0
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 07:10:31 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45a1b05b15esf2785705e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 22:10:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755148230; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZFie2XV/h2lW5zMxmI8qQAMrWYNAYiEpCAvuen5aWErwaNqClofj87duvhPmCxpt8J
         cFuFJ03Oa9jshcNS7hLcH0APkjiIAZVvDBbdXg6NT1oMzw+wrpzzCFrkgJVU2671EUKZ
         b7WlYwokjwgn4OTWt5xfsnadM8SFBkDUbyynMXc31PinpMW+S3qYXFePHqcARtjKclP4
         p8nhAhGv1XntYF0MbghdL9hzEMbCE16GCOo2EyAwy/e7QZZ4Y3TbAAiPcFCDpn4tYmPq
         HpdMb4CAZupofHBwmKxgoMhL7q78ENJg7qEawAuzHvtdYE5Eeh7bfHGol6rNPK44DjFi
         w3yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6rhOraMl51oMIFqTOAY1A+ROUBTlnJNgX91BiqxCVng=;
        fh=bV0rTn/++pWY5zXV/B61b/1bepS3TRVVg/usEEFOaH8=;
        b=CO/Dr9eAgE7tPdHv0TRI4ts5i9uL00YLLwffCdyJSxEkWhfX/uIFl7qgE+6bFal/W+
         8vBEG0FXZ8odGbqkrsAW9Fn9wN7/Y7bdxqgXhhZ3bYUnf0yz2wQnAc4PByG6IPci1QgZ
         CyVMHn5I0Rkzygp0HjnjR7YEKDAyeMZQZDEEOV+Az3tXm0YjOY2G8CdlGLVbrEnODhD6
         nVDQdWg/at2LSPMLmpLNXQzKq9LHoq+vHapIN2CTiSmrJoaJDwrAwopU/qbIWgeRc3yx
         WleTBYr0XqBstRG8QHzCjeBJFMBsh3aRMJE3sE4HrDC+YH9QNswb7SLFpqi81t/QjVHq
         0kGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SL4V5of2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755148230; x=1755753030; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6rhOraMl51oMIFqTOAY1A+ROUBTlnJNgX91BiqxCVng=;
        b=Y7sbz4RK3G516hXQCv/PoVV32AGE6TruWIgfyxLbdo4ro1hh/QIpmsYDMyNzwLeELT
         bKx9jexFcyV1sJP1HbZjej+Ogw8q7Mt57iis2Bk+3QJpPTmGMNPFObELkHLvVPpjT+rB
         /YcbwyhAxcx5cwwukxj6X9oUOHnafgG0wGjQqV9ar2Q3TBDAtEdm5g07Zn1bcWMTogtc
         LXJpuAZioMaDAf6WlnwQJfD5WLtByPpIqv73GBJjAWDmPBfmfYLbaBHBwJGDSUP22AjF
         3nM5PijfqCxhcfl7k3TYalDuoXnI4qUT3WDhGY4WSY0wSi1CPJmSe5MKYgyxeCO6dmGV
         92CA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755148230; x=1755753030; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6rhOraMl51oMIFqTOAY1A+ROUBTlnJNgX91BiqxCVng=;
        b=aH9PIOazUYDWdjg0+BCmbkHtDm+KUSDlAbUz25umlIAZn/btOcXT4AuDEW3nlM+tZM
         55bvTT0CE0G3TD/xGg6dmqIJUn0EYbRTcCMjexAL1ODej66WwfXXeTyVAZv0Mhvp2K6Q
         vWVo5DBkcmRQy3b4djY/tftWSj1BeNtLKqV6rtDvRpq8/yez0Lk5ECdhhkFFAc0v+aOo
         dmly6KxCN8Tk6YCUaAPyPxRy0s3UlQwjKirh1rY1+VsvW5EjUmgLHcGcsDF50912qSEp
         VtScMxOuK8oNRISErD6XD6zKlUL74TBZzXuWMhDjTAo4nD+v4qOOjUi5KVflxGAflBrp
         GuEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755148230; x=1755753030;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6rhOraMl51oMIFqTOAY1A+ROUBTlnJNgX91BiqxCVng=;
        b=ifiWFTfRGEjnOYEHQog7cBXpfwXtDoTyE5Dl8RDTBr8T8gLs54A2PSedVUPeS48Ukm
         pqX9SS+HN2qzblDj2Wnd1eD/gX4YTXcDbaB8AWb5xSXgRLs4bVsEGPFaP1tdaSzle4Fd
         xJoV+gSrRTGgfDwdui8BNZ/syatuM5LM/0o7U+6frS0emQn/XklqXYFIePm7yEHKgTXq
         FAuTvqJ6y0Kqcwc55vJ3YQO4dhdm9JeuTx4nGbRGR5+QefnVkSRk3vsL+le7qVIZVRI7
         SnC8djBJp6HZGoj4RGKzQm2D55qbET1eXPB0HlUmCgwnQN2GYhrWX97MspBhhZNpzeYe
         8gjQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsjt6qqmQu5KB4OV2qNX2zgizDDZ5ZcmjDw5QTEwnHGXW+yL2OXZPeKkbzjnx55c+tSOs5zg==@lfdr.de
X-Gm-Message-State: AOJu0Yy8llNY00zd9BZRWKadr91mQSaFfcmIYYKDHZIqNZEBkbpcY9/s
	c3n+QIPSaoELjE+88zdZZphfAIBcIdo40+/sJnRO7iVsAShRJXLRcNoU
X-Google-Smtp-Source: AGHT+IH6c4um/LxTZHTZb7mZXKEdSFq6U8uxHWWzoSz58Aae/Rfrgf0055YxrAGWA4bVzYvGJutYVg==
X-Received: by 2002:a05:600c:46d0:b0:458:a7fa:2120 with SMTP id 5b1f17b1804b1-45a1b66e423mr8517825e9.25.1755148230249;
        Wed, 13 Aug 2025 22:10:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdXhB4YVAKVYknPhwG4Lr3ASYFRherXh2IMJfSxEzxi/g==
Received: by 2002:a05:600c:8b2a:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-45a1aebe787ls2463475e9.1.-pod-prod-05-eu; Wed, 13 Aug 2025
 22:10:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtoGMBMrQCNmrp8bQ+C7dlQO74EqsXpjurP3/Su8RU2bKD5rdOYCDIPQMtUjWkMx5JuApHwR/nZFc=@googlegroups.com
X-Received: by 2002:a05:600c:8b4b:b0:456:1006:5418 with SMTP id 5b1f17b1804b1-45a1b61eaf8mr10886555e9.13.1755148227695;
        Wed, 13 Aug 2025 22:10:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755148227; cv=none;
        d=google.com; s=arc-20240605;
        b=e1/khDfHLKVS2eAVcOuBO/tlFh5x+i4hkPxvZxsPCHSRC74etwTyzAdM63ca1KAjmj
         VkNLvJmkos/XwVnmsj74FdJiyiQNcQw6lRZ9Gmi7CdSBYliAh5vHmaVk5P8Y0c9MXrHy
         7VYZyaC/ussuZWBwaNGVcNEzjcelNhD3ZhW0C4oLnzrLJcNMteXGW7t24sJuamC0ORUL
         N5rvoTZRkSfU3iFP2uJefNsVj9TsQOFPyHtjgHnpRPXBH/NVRkqunSSdF/DwtNI081MQ
         A4u/4LAB/nGxADnSaCNhOu0UAdv1X5hJjF/5dg9Jo7Br/JZyJwbOvcJ3E7TlLhA7lx0e
         Q7aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YG44M8DAsMWfH02qr68MhJtAMxD1cxgjmaznwJ5KLJg=;
        fh=PB+no2Ym6ZKoZn4wv1yrwgp+Dd/mqV6CXAhgG4ZhUqc=;
        b=RhuCw5Qzak/D6Sqh5XEx0C5xuVnKh4PVpQGtEDPj1C7J7E/BMQMGLTqH9MGkVXTVdU
         VLyld8dTKT+Vh9wTs05Adu9+ceXN2d7MD6z8b6f4iQKsWyBbs31T10oAS5Uf6W0f6k6W
         Yp0U2L+Vb5BsM4x0D4kx144hCJ3w1Ashcsn475m/WBZ2vcJPOl0hzyuHdvSIBM4h+f6D
         c4+diuAt3c57NWp09pDfjoinlJVxWIrNysUNgRjqiI5sbCuKpY+tEL1J0oDuY1UezOHa
         lB7dPLCnqwbboX4VM0BO0z06/0B/HX5Tc4Uj3b5j+WppQHHxg9i9DMaqicM2OM3RDALa
         0Vig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SL4V5of2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45a1b8f93f0si208545e9.0.2025.08.13.22.10.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 22:10:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-3b9e40e27dcso340266f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 22:10:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUMKh7prPxoJKnvdzC9vrRFljbWNiO7JXQ9tq49JT8tD4lEtNY0b4AfFOu5zohpBlz/QUM9j9JiM8=@googlegroups.com
X-Gm-Gg: ASbGncusUy9qJR+CRlh6QZ1Sd0REUkEACR2LhvEzI7yM13JLia3z4+KbsD2eNV/UmYV
	BcrL6uUvJkqLvCpUyTGrIoHlTOnHdqJgnBnPEV4BLtBmP9iOEdizf+JJ/1HnmRPyD7BiFg1Pi0M
	tdrVRy/7Dt97TCSAIbigd+7l+2ttQRCDZo2svKRTvQvZgX/pPzxrfvuDQ6twOe6UyY4SPb1hVce
	R5JBeFGaA==
X-Received: by 2002:a05:6000:402b:b0:3b7:6d95:56d2 with SMTP id
 ffacd0b85a97d-3b9edf1ad3cmr1303620f8f.7.1755148227128; Wed, 13 Aug 2025
 22:10:27 -0700 (PDT)
MIME-Version: 1.0
References: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
In-Reply-To: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Aug 2025 07:10:16 +0200
X-Gm-Features: Ac12FXwk3idO9PD5EAG_isCaljN_b1Avcx5rr-Mcqh7uJPexNYhAO5AIw0nkzeM
Message-ID: <CA+fCnZeuewqXSW0ZKCMkL-Cv-0vV6HthJ_sbUFR9ZDU6PmzT-g@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine skipping
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SL4V5of2;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Tue, Jul 29, 2025 at 6:49=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU sla=
bs
> if CONFIG_SLUB_RCU_DEBUG is off.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
> changes in v2:
>  - disable migration to ensure that all SLUB operations use the same
>    percpu state (vbabka)
>  - use EXPECT instead of ASSERT for pointer equality check so that
>    expectation failure doesn't terminate the test with migration still
>    disabled
> ---
>  mm/kasan/kasan_test_c.c | 38 ++++++++++++++++++++++++++++++++++++++
>  1 file changed, 38 insertions(+)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 5f922dd38ffa..0d50402d492c 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1073,6 +1073,43 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
>         kmem_cache_destroy(cache);
>  }
>
> +/*
> + * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
> + * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.

Would be great to also add an explanation of why we want to test for
this (or a reference to the related fix commit?).

> + */
> +static void kmem_cache_rcu_reuse(struct kunit *test)
> +{
> +       char *p, *p2;
> +       struct kmem_cache *cache;
> +
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_SLUB_RCU_DEBUG);
> +
> +       cache =3D kmem_cache_create("test_cache", 16, 0, SLAB_TYPESAFE_BY=
_RCU,
> +                                 NULL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +       migrate_disable();
> +       p =3D kmem_cache_alloc(cache, GFP_KERNEL);
> +       if (!p) {
> +               kunit_err(test, "Allocation failed: %s\n", __func__);
> +               goto out;
> +       }
> +
> +       kmem_cache_free(cache, p);
> +       p2 =3D kmem_cache_alloc(cache, GFP_KERNEL);
> +       if (!p2) {
> +               kunit_err(test, "Allocation failed: %s\n", __func__);
> +               goto out;
> +       }
> +       KUNIT_EXPECT_PTR_EQ(test, p, p2);

I think this might fail for the HW_TAGS mode? The location will be
reused, but the tag will be different.

We could mark this test as Generic mode only.

> +
> +       kmem_cache_free(cache, p2);
> +
> +out:
> +       migrate_enable();
> +       kmem_cache_destroy(cache);
> +}
> +
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>         struct kmem_cache *cache;
> @@ -2098,6 +2135,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kmem_cache_double_free),
>         KUNIT_CASE(kmem_cache_invalid_free),
>         KUNIT_CASE(kmem_cache_rcu_uaf),
> +       KUNIT_CASE(kmem_cache_rcu_reuse),
>         KUNIT_CASE(kmem_cache_double_destroy),
>         KUNIT_CASE(kmem_cache_accounted),
>         KUNIT_CASE(kmem_cache_bulk),
>
> ---
> base-commit: 0df7d6c9705b283d5b71ee0ae86ead05bd3a55a9
> change-id: 20250728-kasan-tsbrcu-noquarantine-test-5c723367e056
> prerequisite-change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24:v=
1
> prerequisite-patch-id: 4fab9d3a121bfcaacc32a40f606b7c04e0c6fdd0
>
> --
> Jann Horn <jannh@google.com>
>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeuewqXSW0ZKCMkL-Cv-0vV6HthJ_sbUFR9ZDU6PmzT-g%40mail.gmail.com.
