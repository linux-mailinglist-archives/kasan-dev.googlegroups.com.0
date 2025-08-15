Return-Path: <kasan-dev+bncBDW2JDUY5AORBCU67PCAMGQEAZTI4MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B6F1AB278DC
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 08:09:16 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-55ce524a96asf909903e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 23:09:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755238156; cv=pass;
        d=google.com; s=arc-20240605;
        b=R5jfk7KkQxchR5wTVPo8XW3KV5SeCWSRoE6wVwvF2/PHqilFmDwhV/UD9mAZmcvyCw
         tx9h23f+Oi8lYL829qZDTSW/JAWHh9d1OS00aP5LdyzECicU80WLxG63EI34t+nAtNQh
         AHMU+Jm31pLN1v/Ioli/Urb4AvBX/Cpbc1ondXc7WKhZALDW1khpukk4Obzo/XSx8AWF
         azA2R7RpGGr3O/dqfichvO5f6mATQZDIbVr21f5hbKt8jjMWWKOhovQ8pkvNTjlcP2nE
         GqmN87aXq4jFiUXT37zh3Y14jag1owAgwAw9oSWjrJ78oxgPOC4HyPdu6D9ERTrtfUR5
         iU4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Y2TxX13wMcoKfZu3ImNQuayMOM/Qd5PKt6L3w++oJH0=;
        fh=I44LWE0Q8TFiUUzLWoQ4pVPxrYPhoY7Ss0d8tulsT9I=;
        b=lSYItQdY2lpUazLQOqIkyUdxdDETgov7Uq+xRQ6/p5dttOFzDBjbTGSzh7Qj4U8dKm
         /65EvAL0/bZJy5XRGgWr3Yp1gKGXMe3XmeuKX4Pv7Cwod3QZKRz3auHGuSy/OftQir20
         alqddQF13Sjb2pUL+RKYzbv4+NOhqfaUvtpO0oE8a8spQPEOAUyPAH7djlG717yxVHSr
         Rs7LxF5MWuPXaxaLH5p6HAf09Klou4OYejh/n1fT1S5x7s9zUQ6zaloVe9QwV63/5rOJ
         PtiXUeA0eEEFJ0UA/q9UENKKS0RpV4CIW+ApM2sz13shS6m364TXfeacqI0jnqwNrqnp
         wKJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="lT6wxv/7";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755238156; x=1755842956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y2TxX13wMcoKfZu3ImNQuayMOM/Qd5PKt6L3w++oJH0=;
        b=oYlQcFnKRf5oOtQSigVoq9g6T6dTtewTMZEHnLuQysLiEaAaUDBjCNsWxLc4eK0wiJ
         P6CKnHcBJbv+xfoRqpWKfc/ZrUF02bNxsusya2N9uIEA0ieiOUtYMPPT0FJkACTzAzY7
         AOB0ofyrPjVVaHkWP+mJ74GJN2h2MUstQsk2fTFuSRNaz7r/1tiW/3dclgfO2TECCfTh
         1bgbEU8kvHLd/wtReUM3OzSbWExhM+Pa57Rzp8pjpGW5QPME2ZKpwqL0/8RoHJrszba6
         n3bWce+y2yv6uDanqkYj0g5ZNzs5daKtZtdIGjpPKHfIOaJgDqIsNeoppmYXRoO51swa
         oD3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755238156; x=1755842956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y2TxX13wMcoKfZu3ImNQuayMOM/Qd5PKt6L3w++oJH0=;
        b=byhsmZ1lzxHP3ab2w4u+u//EC7/d0bNxm2/tarQkfsvnrjDpgJnfvGSt8owXCh87ZD
         e0Ij5qKRqnu5d2d7eg9NDuQjzjKya0JdN/lx/WffoqZ54Dp01p2E6wDTVZGswoRwBCLV
         Xdq/5/IxKIq672r1LissD9v7qtSP2sut4HHK7sYvSej54Y7uhO9I3W8Xih/ddj8w5qoj
         RXgGQru7ey60/pa0/oOBeqoQdYVhIm/KshezgNXuW1zOmgfDPSBfizHJ9H+iPngciM4C
         ez+LAvH/JcS6joUh79Lx0ujm+vbhQXInd4Bkaa0LqsS1Fug/E4xHoRcJPNASF27zXYuQ
         0lLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755238156; x=1755842956;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y2TxX13wMcoKfZu3ImNQuayMOM/Qd5PKt6L3w++oJH0=;
        b=bF/grhG9Riyaph7ePRIG4zoAI/kk6/9zFcSFYgpF0W9LDSV2HBLRO72OdIQ1xE8PVr
         Mt6d/DvR/uB9juncxHHzn01Fy/GwOLm+QB0QzNcGlJQKs1/nVCoJs+EWR5pm3b5PlBCW
         dQM/NEuTGeeflfkbh0Cp6co6uQspZcB1N7KGvpV/uAFa5O8di9uA+TMxSVMAQmT7Rukw
         s8rXDEdrxM8v78UfObnC3lfhXSotxamTV/l+JXb+a4Ofadgn/E1QAZ6isqSENQsiObo6
         3OzC2em3Km71a1t78C6q0hVSsBvegM0TRqGBxxhBU2CTt1Be7+qjd5IdYdJnhu1OYuvc
         EkuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8Zp3uuMRqTOo3rtXt/LA8zB37C/SFSZKXwoi3IncwrwYQOs/KXr/+cjInbPS6bMDj1c8hhg==@lfdr.de
X-Gm-Message-State: AOJu0Ywle9OVaaG9qzcTncqpcKD2wehWEo1VswuK3JSRxxqXN495OWwG
	NWkRwOdZn7ATEmh+3BphbtjkTvJwMWfDhH8pIZN8N3hLWwSiauOylKwa
X-Google-Smtp-Source: AGHT+IFfiMko67RkY60kbTwzHzFE0SMl7x/xt9J2iIaGR7dS0mGcG8RGYh1+0ksuw8D1uC6TqvIgnw==
X-Received: by 2002:a05:6512:3c9f:b0:55c:e752:e9c6 with SMTP id 2adb3069b0e04-55ceea3fc3emr288745e87.10.1755238155040;
        Thu, 14 Aug 2025 23:09:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd6+NOyGs8uWPV4vxpTKh0PqX05QFa1LV+elD1K5UkWow==
Received: by 2002:a05:6512:690:b0:553:214d:2e12 with SMTP id
 2adb3069b0e04-55ce4b97fefls427163e87.0.-pod-prod-08-eu; Thu, 14 Aug 2025
 23:09:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlMn6yh4bupRuYOur3q7wAkoWDaVKyCj+Mj4bQVRl0gfOMla4PP6Kz9BKpPq9bMG4cm0QBIazAQQg=@googlegroups.com
X-Received: by 2002:a05:6512:159a:b0:55c:d6e0:c1a2 with SMTP id 2adb3069b0e04-55ceeb8ddaamr230442e87.42.1755238151678;
        Thu, 14 Aug 2025 23:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755238151; cv=none;
        d=google.com; s=arc-20240605;
        b=IWKoYiqvkc1bQhDiStpCxH18P11Rt7KOwKS4jRjaI+FLUrUL5y7y8M+7eSJb1krJnH
         Q61i4Uxsovi8lVG3QjBzD9gPE42/MtSaAKe6MGEDKGI5ntt3xo7am/qCpsQyCYHQqYPc
         5OhM/abYwTwVm38wUbbCqiyiwmsDq0E0/fmn++AiSXmkaUDBwC6DnOyaeeTHw98Xz/1s
         VV33Grc6608eBKtVky688q7/6o6JpwSQdRufmYusQafYjxjyVM31DTkA0Rpg21Sih4FZ
         5cAjj4sL9dHq8iI8wNrdJxAyE3yfcox1j+5HR610Afoi3arxrr0Lb7UuKgxsfpWahnC2
         j5fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wACT+FdhCtuGzqGpHgePPwt5rag7S82b8o2EOM9TWRM=;
        fh=A5OATVi4Spqe2ebEz0s6nTkdZTrNxkZmhUjVGDCQ93c=;
        b=G4ScseKOesv2w+vnXhflS55a0Dqx43dU/ioEjGTiTynHfxQno0HxyjmdbwGHbbzsCF
         sqRlrT084VSYBouIhS5zNJ68WvzVAV73ABkCl+o8PFIzkm9j4+fW2Vt/QZvUtNNs/6d9
         kFmYwt6AuqlkkuaovOxH4TQcdx9s7aOJGfdN7bZPEOCn3IbgkUFAkUp7+BJ3QOBSLqzG
         0uFcLIMsuljahN/8HMTB8SjVCSyNnnU10s3ELGCr7by19Yb57lIhezOcOY3zfAqINUp9
         pxTBIrTsQze+tTPMNRvqB2raUWtS8EXGRkmKkWPhX5drDOgNr+fY2AHnOaG1enYlJ0gF
         e9ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="lT6wxv/7";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55cef3bebd4si10369e87.8.2025.08.14.23.09.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Aug 2025 23:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3bb2fb3a48aso111542f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 14 Aug 2025 23:09:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2Oe9mqggWkKfWHzeCpmqYgNfZTagaycTNEFG8qrRZ03H9xO8et/yQa9LiokShUMHUzF/qVbU+TGA=@googlegroups.com
X-Gm-Gg: ASbGncs6KCLx8ogwv9jargP9RRg+IaqTEaHd8331uPy+5X9iR7+57WJSJLnihy5UHth
	S2YvspoEqUnOxKTO3CZJ0XyWCBW260vhsBZN68cgkRHKcJlqtjAdNKhb1LeCgfmt/jEuBnVhQqS
	m1AmiHs4LQ1tT5UOzIj+UKqKSZgYSPN/wKdmVylodSSENhaR4LSIGYr5F9hDBaNjoYdIb2Sv7lh
	Ch8qlUt
X-Received: by 2002:a05:6000:25c2:b0:3b7:926f:894c with SMTP id
 ffacd0b85a97d-3bb675d3c7bmr406864f8f.23.1755238150774; Thu, 14 Aug 2025
 23:09:10 -0700 (PDT)
MIME-Version: 1.0
References: <20250814-kasan-tsbrcu-noquarantine-test-v3-1-9e9110009b4e@google.com>
In-Reply-To: <20250814-kasan-tsbrcu-noquarantine-test-v3-1-9e9110009b4e@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Aug 2025 08:08:59 +0200
X-Gm-Features: Ac12FXw5QESzTXxkbg4UmhQH3TfIEeRhPi07Vg1NeAqS36aDi6tcJzP5tYrOvmc
Message-ID: <CA+fCnZcNy5NGL38YdKiqTVYeO2dAp_VEKHe6iOEo49H15X8gzw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine skipping
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="lT6wxv/7";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
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

On Thu, Aug 14, 2025 at 5:11=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU sla=
bs
> if CONFIG_SLUB_RCU_DEBUG is off.
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
> Changes in v3:
>  - add vbabka's ack
>  - make comment more verbose (andreyknvl)
>  - Link to v2: https://lore.kernel.org/r/20250729-kasan-tsbrcu-noquaranti=
ne-test-v2-1-d16bd99309c9@google.com
> Changes in v2:
>  - disable migration to ensure that all SLUB operations use the same
>    percpu state (vbabka)
>  - use EXPECT instead of ASSERT for pointer equality check so that
>    expectation failure doesn't terminate the test with migration still
>    disabled
> ---
>  mm/kasan/kasan_test_c.c | 40 ++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 40 insertions(+)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 5f922dd38ffa..0affadb201c2 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1073,6 +1073,45 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
>         kmem_cache_destroy(cache);
>  }
>
> +/*
> + * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
> + * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
> + * Without this, KASAN builds would be unable to trigger bugs caused by
> + * SLAB_TYPESAFE_BY_RCU users handling reycled objects improperly.
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
> @@ -2098,6 +2137,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcNy5NGL38YdKiqTVYeO2dAp_VEKHe6iOEo49H15X8gzw%40mail.gmail.com.
