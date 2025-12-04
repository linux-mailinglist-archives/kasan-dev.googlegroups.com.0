Return-Path: <kasan-dev+bncBDW2JDUY5AORBBOHY3EQMGQEPE6HJRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id CA8E4CA4268
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:06:46 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6407e61783fsf1091707a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:06:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764860806; cv=pass;
        d=google.com; s=arc-20240605;
        b=DkP8YBv4F1ShRXvy9gwkVYm15RxWzrFyRR+4ta8Z0yo5H+ni0Aw52Yor4/lQ1EiWGy
         MUPEQTew8lSaiBcCLO6vcGJARai+CU7F0nJRK1X0gPMygfwqTNYHbohFtwzOsicKwAtz
         R7IvbeCPOFi8NpWtAO3IQoNbpm0rzspdaD2mMW8fyoZOSQ2xu+xLN5KSQI1lYX9g/Fso
         xuxx043V+XjNrRlQaHHUJSXRZVG8sU5q2B7wTDSroLK3WNS6GMJVA7tyhoKRnzjrhDPv
         QmSsZc4soSE35A9kS3cdpVoUSuyNvj8WiquYd5RPTlzRHHERm9Lsnw/TB5cXHiS0P1mG
         TPvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=tGvaE8jC6cNeZSbZwwzCtQXgwOqdhfARtldWr7/ghrI=;
        fh=Muue66pVRuYuTcGqk2huEDi6FbQ0J3DpodxH2iaK6Og=;
        b=WHbpKh12zZ4wa/IzOyyC6B1GwQmFY9D5+qdGFeIR5fR/2V++XliHD6YukNgmLTzEQd
         BcBxi42u2VoU70T8gzvdmnDI9EDRbKz8ENhgGAUFfm/lP8UW+khAUGQtZWXa38WRhH1L
         WSlHZO1tWrviyxdKG5Yx/vVCDda5c4cV+BMwqLCYEN/4k3mP0/95x1A1iwMFD1FYn0Q1
         IkbbxMcvsc9/g6gHtJur8RiAmc94DjT9VrvcU4Q3fD0u52YVad86JJE4TmfCFHbWKYS4
         kNt59kwemDtweRpKDpt9E2QiOF2FxRh66tUxlE1hWuezEJAvxRcQDsCUe5QONEd9jRp9
         cGtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YbhcyXxj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764860806; x=1765465606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tGvaE8jC6cNeZSbZwwzCtQXgwOqdhfARtldWr7/ghrI=;
        b=OHJo9/AxjSegRvseF+uW7kRlVYc3HVUVO+jdPcHnFhrjj4M3W00ZDX+xOqxIzRSjdQ
         pfBlYK0p4RwrQe6czwqTEitYt53twtmy7W+n1fmZu+KiM9K3GVm7b7Ikx57alAyjbdLU
         wfncLCCUKMdJS3a7Tzcn/m7Gngj/IvgerHQ3MYkl1nEXZFPPPI23l0sykSO2ndmJwz4q
         9BZXvFIDKyYJCywibfJN/0FvMtESHiRRmymemvtDkRopXwJ3HVUQBBy3JxVlYw/kqT8b
         u0k/HS4ua/dQlH0T/N/HnFXf0jjZpbcSIWmQXW3aZjkj9sLFYNsFFSZzs+J90Ljj9Tpz
         fgUw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764860806; x=1765465606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tGvaE8jC6cNeZSbZwwzCtQXgwOqdhfARtldWr7/ghrI=;
        b=Sy0dlEqMEBd0JjGl7fps3c69n4IBlx0PSyGRORtOHiGDc/Y3uB/5DPpW4XbxmX91ec
         taLY86otLm2Xl5jJ75xkjIq8GCvQsiiUJSC3Xxn5nPrcEFEyEsSXEkKLHxw8DWtkV153
         5zEUgUcJK9cOQNYlMlmCBWaD8euvRFO7RY/lk44a59d1zA4JIrxBpqjM2b0dm/Brl4Vl
         mk8R3Ac1fTB2BE1bFZzOKEVLYRtrM2hEdE004t/GkYwLI8JxzjKARpb4vjti0bTFgKz0
         EKeZHx+w8rNKpccrJ4WAxlyJarMyqufqSFPTTtkEqKqJHTrynDgKepoP40hdcDOdNUD4
         yBXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764860806; x=1765465606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tGvaE8jC6cNeZSbZwwzCtQXgwOqdhfARtldWr7/ghrI=;
        b=BQ1tmqiignWEISaemVyJaLmh+5bqeUOpdKBe8y6wsuYLIeRrJTWn1qqQvRUGC2apWJ
         iPsjIwPhOyjMrvYMxX0GhhiE1xmcY3/BmnlfekeQQK7jyhX3tT0ufgo+WsNtEVAqI1u0
         f3r+/NAkOzuQLZQbbsRCCryUOHdb5pJDigRmiIs5Ey78eTM0cnYrkyZY8CsVOnWd8Qtx
         F/ZawzuSVuvFN9MLgB9+5L1DQCwg5kzv7wNahe45y3yIuNLDepSufM/9gNvcpAdv+UrK
         6YOBfy2AA4PkXXQCwVmVGzTbEofIBzmImCef9L50Uf69HHV+Yz66xodzChbs0dZOAQbd
         sLYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8g8QU4chYSwWaYly97pSoAc3p99gcm0kzBCIbB4bUMkaRrEnvxadCkuX0Ogv1wBewHQr9Nw==@lfdr.de
X-Gm-Message-State: AOJu0Yz0ok26rnEtXvAelTWyF9fEBuwJfuHORMLj3a+ycXib2CuoaNP8
	I2ig1Hwb0FuZkq9gboRcU9X3xNR0DmTiWiTQE+MQghIwJc8dN/ySU0pU
X-Google-Smtp-Source: AGHT+IE18fFLuVHGHLWV0r1/LW3f0N91i3h7t2uAAG+zNvylYBN7tvGjcQZF5AlLqia/4+3vXdMIlw==
X-Received: by 2002:a05:6402:5254:b0:640:8348:6a82 with SMTP id 4fb4d7f45d1cf-647abdd938amr2608725a12.24.1764860805906;
        Thu, 04 Dec 2025 07:06:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y/Rp3ZM+VUzs5wgGiQ0/D8P8dU5XFoKpv8uR5G11JhoA=="
Received: by 2002:a05:6402:f15:b0:644:f916:3bbb with SMTP id
 4fb4d7f45d1cf-647ad5b1cd7ls631179a12.1.-pod-prod-07-eu; Thu, 04 Dec 2025
 07:06:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXEivra+GzkTGmVsmYz8cJdQKOJXsx7yvLa37xNLe64KL8+BW5Dzb6JS5ufUGDyBGz9/v2flaUFK0A=@googlegroups.com
X-Received: by 2002:a17:907:3d42:b0:b71:ea7c:e509 with SMTP id a640c23a62f3a-b79ec6cdfc4mr385108366b.41.1764860803079;
        Thu, 04 Dec 2025 07:06:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764860803; cv=none;
        d=google.com; s=arc-20240605;
        b=az8eUawq5cH97OZ6GSSkfx3HXA7ANHcNMyCtX8x2u7hBtk49X1C9VpqFTQvv0yCCZe
         RGWvztkWZbswBIlvf0YLyhICDvDjVjn4arTJdaSdIMe1lUkzqlJK1z0/YrvOW/y/UTLP
         TZ75K0KXpu/CFt7CYQNHVWr6Vgko9oF0zgYQMg1ESCvEAfT2AMaDeDKZt7LuWfnNuKLo
         N7aFm2d3QivySfNI7KPPHH53iafggq8o3CCvgFQBJyg5+FB9d0ot8VU4xfY6redm3kWo
         JH4s/hw4pijQXlY+jMFWrOaywnzBWo/9MoLJpD1HdIxnm1LX1TRS09hVXPCW+5l8UKxb
         HPXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5I1HHFjP+dmS+OWCaDviDx1a/C2VrJBVgYWkPX6+djw=;
        fh=98lZ3MC3FwT8okhM/oJP5oQNzzSeMaBr7yrdPqEb5gA=;
        b=JNBaK8lHKieOW0igaFUUYCY2wx12TjGArlZJBqryvTwjbfwwIpqqI21EDrDLvC/ccW
         8XC02MrpS+tlkIQjbx7Q0MbIqQtXJCWFPWJvmW8vmZAW1dt93MdvoDWtUYo5Cx9HYzcp
         CRXSfN3rlhPl04apvexJ4K1rXQSlDGFJlj7OX5TP9jIdPDXbVASuNKYEQhodrTps6hBD
         IKfpGN5XpWtrT899qYPPvJvJpE++XZDihxJz2i7pGXLZXWETvPMinTGb8U7AmO4w8OCR
         twkRksyI9+XesMW4RAk2p/rBF8w7Y1bSd2+o7QNeIZKlHsMzQtodoGgOcpE0t6Q2iuWl
         hxeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YbhcyXxj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b2ec0ce5si22619a12.1.2025.12.04.07.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:06:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-477bf34f5f5so8598475e9.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:06:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUcndPni85pDaudAB130mYS0JrW1AfZVhjG2MJzN0Hb0o4xGy94tzPm1RavrO3jPtDNv/8IWVq9+Yw=@googlegroups.com
X-Gm-Gg: ASbGnctxbEskujWEUvTI96y+Khg/hW51J9o87NMmBaSMQJuur4JtdhvOiQweYTA1aLw
	fm75WXvJNKcU/Z8Yiu30uD5B88UHU4FoE4upewlTXCpmXHLaxvY8KYhOD0BUl/HWy+I+xqCABuA
	FIbm068Q3wLCnIGTDKVcCSC7S6HFnIcH5PFda33cyDeKkxSVmh5wvoH4ohI3ET2+rVvzx9+JUxt
	avXUzAAxWkfZVRwDF6KLdyLjob1R5rcN2l8fyDthr6mIrKsWDY29ZABX9/mNfD8wCO8YNtqr8nt
	Tlzgj6s4tI0ovaTdz4pkDdEAYyxQ
X-Received: by 2002:a05:6000:4014:b0:42b:39d0:6377 with SMTP id
 ffacd0b85a97d-42f797fdf66mr2936033f8f.17.1764860802318; Thu, 04 Dec 2025
 07:06:42 -0800 (PST)
MIME-Version: 1.0
References: <5o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6@yn5rmfn54i62> <ef40d7bb8d28a5cde0547945a0a44e05b56d0e76@linux.dev>
In-Reply-To: <ef40d7bb8d28a5cde0547945a0a44e05b56d0e76@linux.dev>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 16:06:31 +0100
X-Gm-Features: AWmQ_bnaUQ25kTdEWv00pQqNAPpKBXdTjclujxDMcVwZh7_yFWZPsNiD0hppyoY
Message-ID: <CA+fCnZfn+bu15DPwawApE3DXrEz_wkYzHdjbjbTD0n5KLEQfsQ@mail.gmail.com>
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN
To: Jiayuan Chen <jiayuan.chen@linux.dev>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-mm@kvack.org, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Danilo Krummrich <dakr@kernel.org>, Kees Cook <kees@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YbhcyXxj;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Thu, Dec 4, 2025 at 3:38=E2=80=AFPM Jiayuan Chen <jiayuan.chen@linux.dev=
> wrote:
>
> I think I don't need KEEP_TAG flag anymore, following patch works well an=
d all kasan tests run successfully
> with CONFIG_KASAN_SW_TAGS/CONFIG_KASAN_HW_TAGS/CONFIG_KASAN_GENERIC

Thanks for working on improving the vrealloc annotations!

But I think we need to first fix the vrealloc issue you discovered in
a separate patch (so that it can be backported), and then we can apply
your other vrealloc changes on top later.

So please implement a version of your fix with KEEP_TAG -- this would
also allow Maciej to build on top.

>
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 1c373cc4b3fa..8b819a9b2a27 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -394,6 +394,11 @@ void __kasan_poison_vmalloc(const void *start, unsig=
ned long size)
>          * The physical pages backing the vmalloc() allocation are poison=
ed
>          * through the usual page_alloc paths.
>          */
> +       if (!is_vmalloc_or_module_addr(start))
> +               return;
> +
> +       size =3D round_up(size, KASAN_GRANULE_SIZE);
> +       kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);

This does not look good - we will end up poisoning the same memory
twice, once here and once it's freed to page_alloc.

Is this change required?

>  }
>
>  #endif
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 2cafca31b092..a5f683c3abde 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1840,6 +1840,84 @@ static void vmalloc_helpers_tags(struct kunit *tes=
t)
>         vfree(ptr);
>  }
>
> +
> +static void vrealloc_helpers(struct kunit *test, bool tags)
> +{
> +       char *ptr;
> +       size_t size =3D PAGE_SIZE / 2 - KASAN_GRANULE_SIZE - 5;
> +
> +       if (!kasan_vmalloc_enabled())
> +               kunit_skip(test, "Test requires kasan.vmalloc=3Don");
> +
> +       ptr =3D (char *)vmalloc(size);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       OPTIMIZER_HIDE_VAR(ptr);
> +
> +       size +=3D PAGE_SIZE / 2;
> +       ptr =3D vrealloc(ptr, size, GFP_KERNEL);
> +       /* Check that the returned pointer is tagged. */
> +       if (tags) {
> +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN=
);
> +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KER=
NEL);
> +       }
> +       /* Make sure in-bounds accesses are valid. */
> +       ptr[0] =3D 0;
> +       ptr[size - 1] =3D 0;
> +
> +       /* Make sure exported vmalloc helpers handle tagged pointers. */
> +       KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> +
> +       size -=3D PAGE_SIZE / 2;
> +       ptr =3D vrealloc(ptr, size, GFP_KERNEL);
> +
> +       /* Check that the returned pointer is tagged. */
> +       KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
> +       KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +
> +       /* Make sure exported vmalloc helpers handle tagged pointers. */
> +       KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> +
> +
> +       /* This access must cause a KASAN report. */
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + =
5]);
> +
> +
> +#if !IS_MODULE(CONFIG_KASAN_KUNIT_TEST)
> +       {
> +               int rv;
> +
> +               /* Make sure vrealloc'ed memory permissions can be change=
d. */
> +               rv =3D set_memory_ro((unsigned long)ptr, 1);
> +               KUNIT_ASSERT_GE(test, rv, 0);
> +               rv =3D set_memory_rw((unsigned long)ptr, 1);
> +               KUNIT_ASSERT_GE(test, rv, 0);
> +       }
> +#endif
> +
> +       vfree(ptr);
> +}
> +
> +static void vrealloc_helpers_tags(struct kunit *test)
> +{
> +       /* This test is intended for tag-based modes. */
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
> +
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
> +       vrealloc_helpers(test, true);
> +}
> +
> +static void vrealloc_helpers_generic(struct kunit *test)
> +{
> +       /* This test is intended for tag-based modes. */
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> +
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
> +       vrealloc_helpers(test, false);
> +}
> +
>  static void vmalloc_oob(struct kunit *test)
>  {
>         char *v_ptr, *p_ptr;
> @@ -2241,6 +2319,8 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE_SLOW(kasan_atomics),
>         KUNIT_CASE(vmalloc_helpers_tags),
>         KUNIT_CASE(vmalloc_oob),
> +       KUNIT_CASE(vrealloc_helpers_tags),
> +       KUNIT_CASE(vrealloc_helpers_generic),
>         KUNIT_CASE(vmap_tags),
>         KUNIT_CASE(vm_map_ram_tags),
>         KUNIT_CASE(match_all_not_assigned),
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 798b2ed21e46..9ba2e8a346d6 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4128,6 +4128,7 @@ EXPORT_SYMBOL(vzalloc_node_noprof);
>  void *vrealloc_node_align_noprof(const void *p, size_t size, unsigned lo=
ng align,
>                                  gfp_t flags, int nid)
>  {
> +       asan_vmalloc_flags_t flags;
>         struct vm_struct *vm =3D NULL;
>         size_t alloced_size =3D 0;
>         size_t old_size =3D 0;
> @@ -4158,25 +4159,26 @@ void *vrealloc_node_align_noprof(const void *p, s=
ize_t size, unsigned long align
>                         goto need_realloc;
>         }
>
> +       flags =3D KASAN_VMALLOC_PROT_NORMAL | KASAN_VMALLOC_VM_ALLOC;
>         /*
>          * TODO: Shrink the vm_area, i.e. unmap and free unused pages. Wh=
at
>          * would be a good heuristic for when to shrink the vm_area?
>          */
> -       if (size <=3D old_size) {
> +       if (p && size <=3D old_size) {
>                 /* Zero out "freed" memory, potentially for future reallo=
c. */
>                 if (want_init_on_free() || want_init_on_alloc(flags))
>                         memset((void *)p + size, 0, old_size - size);
>                 vm->requested_size =3D size;
> -               kasan_poison_vmalloc(p + size, old_size - size);
> +               kasan_poison_vmalloc(p, alloced_size);
> +               p =3D kasan_unpoison_vmalloc(p, size, flags);
>                 return (void *)p;
>         }
>
>         /*
>          * We already have the bytes available in the allocation; use the=
m.
>          */
> -       if (size <=3D alloced_size) {
> -               kasan_unpoison_vmalloc(p + old_size, size - old_size,
> -                                      KASAN_VMALLOC_PROT_NORMAL);
> +       if (p && size <=3D alloced_size) {
> +               p =3D kasan_unpoison_vmalloc(p, size, flags);
>                 /*
>                  * No need to zero memory here, as unused memory will hav=
e
>                  * already been zeroed at initial allocation time or duri=
ng

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfn%2Bbu15DPwawApE3DXrEz_wkYzHdjbjbTD0n5KLEQfsQ%40mail.gmail.com.
