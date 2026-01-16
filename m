Return-Path: <kasan-dev+bncBAABBMESVLFQMGQEPSQ5SZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id EAF78D384F2
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 19:53:37 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-430f527f5easf2029130f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 10:53:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768589617; cv=pass;
        d=google.com; s=arc-20240605;
        b=fk9IATcEHSx+jScrgh/iLlJ9M6TMv7ry6UBwlb1S3o4q/Mm28Zc+yvSaEjFXzcBYOL
         VHwaF0MfBFHY8BSzd14WlKc15U+L28kGW036qyJEAFYXq8OSRPZJIIT+0pMPhd6yGqHH
         6o/m4NbYR1g67Las84SlUlcUX3MEnCJJg4xKPC2NgmOEYapdPSITXoHPCGl5prmRgs20
         JMGhGwVc9UhjPJAAAtsmeBfx1D4sdwNPHFdO3tW7XhMKL7oz/A+7VzWjOv9EQF3j8vH2
         eud1Scn56n9MMAR0BDHM1diWRa2XvdcEUlnucb9dpG/AGwzljCo3Bv7ddq7GbhkNl88V
         W35Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=4OA4B2jpZiLXuUIsg7GasLY/tBVTM/0GUuCMOuk2VUk=;
        fh=l/hJJJ35UMR7ujcplktv8SXqVyeVOqaDVStu5F7JfVk=;
        b=RNftkDjplbwhnkAFNP7TDwboAWRjk88Mlxydiut5+Dpz5OTY1Z9fRtRKxKTd8GBWdf
         Qqcg4IoKc8sVT2daiFdMvSagt16NTGbZoZ0aDyjMzCbgjWAWuMZdKpxWreRiyCTiYTD+
         wmp0LvEi5+U4uik6jrWvXbBaG7WGign3ZePYZTJfRBXgpV7qjXKx8nmN7uYMjL/sy47y
         m3EHW5I87sT8vaLwxMKLgHK9IUytDW6YuBk0qxsbG1y07igJAxyNOemDtANgHtE/eauh
         MelstuT7DEl5uxIXGxQW/vCdq75YEYsY77Fm0ZBqXHd7bE7F0G8IYWImP9AdY4eqVdyl
         2nVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=bisfo0ae;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768589617; x=1769194417; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=4OA4B2jpZiLXuUIsg7GasLY/tBVTM/0GUuCMOuk2VUk=;
        b=T655wlJgntEY6OR36suP+h5kklpobPZzO2AWk8omaEWMsUARRXehrTtM4UTdtPIEr4
         Wufe6f26gZij00zNFCGHwp8mK8rPAoiSb9vIHZea6H5YMRiLWPc06ufdwpOZXbR7+QD/
         9fZRHNOShp0m9TC920+8LZ9JkonV40d/RS5Y54pjh7AZGdKJsFkuDFtd44TQKZFUH4v+
         8RcC5qC/UXySU82SWRerlU/XMWw+BgfbFmfiYf+/LKeqBw7m1JrdjPqmpfL9LcRzeg8X
         Fdd54fzX76k7B3Ym4mGeG3NgdcrBSLE5J/N0DyeV5asq/TQ3wje7ArjMTgkbeU2h8rhf
         8KXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768589617; x=1769194417;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4OA4B2jpZiLXuUIsg7GasLY/tBVTM/0GUuCMOuk2VUk=;
        b=RzHIUTgR5NJ6ze6FcfyL+Wat3yGSyHUen6WIUuqHBaivlGaZu3M+wU9aQrHIQ+hop1
         AfjxzpTCmwxqds4sMiFTR2n5JeBhT8/JxgNvy+Hp15LkRESjD6XM23aGuDt1s3MIm8+n
         YwdsQF52X8Zr4H/1vekSdVVnWZx3qyXqlPxDdKfJMZkDx0H4AY5iQV5Yjhv8gcUsULEN
         kzi9UD+fVslLlwEvdr0GCo3/JAmcg0T58218PtVO8WTCTeecbgzZ+KYxq/B9yofngjBn
         n3SyCjfGOf8rISN0c6rObqXK2KL8rdghu4mN8w7bniGxIH48lEshLqljAaXteVHjoole
         lRzg==
X-Forwarded-Encrypted: i=2; AJvYcCWW/7Bt2tMEREIazngG/ynqNZUZpFRxzA9hj1KE4GzNjhfmFaNkmN1UTOthtBkNGRDGgO3F3g==@lfdr.de
X-Gm-Message-State: AOJu0YwOI0GqaCilBtnLJbgKyRvLNZdr0DFmMLc5YwX+ROQ7pkNocR5U
	GUaHoGndT3guaRFm/2q48lqCZAC/efJa1Q4TD1AiV+C1YbryzG+fPKus
X-Received: by 2002:a05:600c:5912:b0:471:793:e795 with SMTP id 5b1f17b1804b1-47f3b7a4005mr57973805e9.0.1768589617142;
        Fri, 16 Jan 2026 10:53:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gka7ei44bOtr28qBFIaktjTfgloSqA/u7RTTPaEkxgEA=="
Received: by 2002:adf:fa8c:0:b0:42f:8916:c430 with SMTP id ffacd0b85a97d-4342b993aa4ls806457f8f.2.-pod-prod-00-eu-canary;
 Fri, 16 Jan 2026 10:53:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX8+u3BcHQOiroI1Ww4XJi9GDGdgTCipBdnXpxWYt+cobPIoJ7ezWGTVLE+pqS4ThF8n+3XSzaTbrA=@googlegroups.com
X-Received: by 2002:a05:600c:8b6c:b0:46e:2815:8568 with SMTP id 5b1f17b1804b1-4801e66fcc5mr44617515e9.10.1768589615413;
        Fri, 16 Jan 2026 10:53:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768589615; cv=none;
        d=google.com; s=arc-20240605;
        b=OqMgCRgqU+2dTF0iW62c+VQu/nxlkh1wZTsO38+hix1BTy1SYiwY+kNdSjBWx58m5N
         UQESVw9fT7kXfj4N3oV7rTmc1af/3QReoEYHk+0My+y98/sVn0GQIxgB7zgWWmCHLd27
         RZt77EF12N6teYSQQsGXgLjLwJJIu9ZJB1ZnKib6jJdzXFJG+P86gu4ddkyPGMo6jlnz
         zV6eBxLrVDos6ake/t6lihG32HwGqqZYDUIRr0TUCqu8g/HajKymQLPsqoicrDusEZ2L
         FKkjpwYjrY9EAPk+Hj6uT37mPFEm763Yp872wvSpBaWqvRG8pE0UmQFdLhrK+EbH1SOO
         vlZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=8Vb5KvAHg8eYsrtAoPd2yZc38LdM5JAqjNAqcpLPBhw=;
        fh=tlcHQVp+IU3syTgAnGiqypMft3v6EKz6lEfgovlSjHY=;
        b=a6PpNjdYmMLGs8ETKetrtDvwyxd5jiR1JeiVtBRMi03jQcPFl9aZjAFkl4wh3+uzAX
         wf4lpJzN8uGozVHlvQeLRSy9nUZ4Iks95yZrC4mmlINHnaKTP8fGNUbw6q4tnKEzbWyo
         UQZ0O3IkYN9np7qiREjKOK+9iwQ9tJ4k/VOBVA1fYTciOQGZjLa73166/eFjNYBNrcRJ
         l2DfYNVtN2mFzPJCbNsHYWfI5YCscxZ8/bf1jTVQhJo7C5pyf3ktyasrp7klDzjRh+B3
         imJptoWgE8ISpYZd8Ci9gZbNwAcex5+k5p+8ijLNPGHeDjietDyImWRfHm0S2D2i3GG8
         Klnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=bisfo0ae;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106120.protonmail.ch (mail-106120.protonmail.ch. [79.135.106.120])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-480260a9529si32205e9.1.2026.01.16.10.53.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 10:53:35 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as permitted sender) client-ip=79.135.106.120;
Date: Fri, 16 Jan 2026 18:53:28 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?utf-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH] mm-kasan-kunit-extend-vmalloc-oob-tests-to-cover-vrealloc-fix
Message-ID: <aWqIYkx-jrjbIXeS@wieczorr-mobl1.localdomain>
In-Reply-To: <20260116132822.22227-1-ryabinin.a.a@gmail.com>
References: <CA+fCnZeHdUiQ-k=Cy4bY-DKa7pFow6GfkTsCa2rsYTJNSXYGhw@mail.gmail.com> <20260116132822.22227-1-ryabinin.a.a@gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 3874665bea8ab7c2cb4599aaf8b989a7f96e26d8
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=bisfo0ae;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.120 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Tested on a Sierra Forest server this time, still no issues both on generic=
 and
sw_tags.

Tested-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

On 2026-01-16 at 14:28:22 +0100, Andrey Ryabinin wrote:
>Adjust vrealloc() size to verify full-granule poisoning/unpoisoning
>in tag-based modes.
>
>Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>Cc: Andrey Konovalov <andreyknvl@gmail.com>
>---
> mm/kasan/kasan_test_c.c | 4 ++--
> 1 file changed, 2 insertions(+), 2 deletions(-)
>
>diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
>index cc8fc479e13a..b4d157962121 100644
>--- a/mm/kasan/kasan_test_c.c
>+++ b/mm/kasan/kasan_test_c.c
>@@ -1881,7 +1881,7 @@ static void vmalloc_oob(struct kunit *test)
>=20
> 	vmalloc_oob_helper(test, v_ptr, size);
>=20
>-	size--;
>+	size -=3D KASAN_GRANULE_SIZE + 1;
> 	v_ptr =3D vrealloc(v_ptr, size, GFP_KERNEL);
> 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>=20
>@@ -1889,7 +1889,7 @@ static void vmalloc_oob(struct kunit *test)
>=20
> 	vmalloc_oob_helper(test, v_ptr, size);
>=20
>-	size +=3D 2;
>+	size +=3D 2 * KASAN_GRANULE_SIZE + 2;
> 	v_ptr =3D vrealloc(v_ptr, size, GFP_KERNEL);
> 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>=20
>--=20
>2.52.0
>
>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WqIYkx-jrjbIXeS%40wieczorr-mobl1.localdomain.
