Return-Path: <kasan-dev+bncBDW2JDUY5AORB4OKUHFQMGQEF7O3Y7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C12DD22567
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 04:56:35 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59b686eaeafsf427567e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 19:56:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768449394; cv=pass;
        d=google.com; s=arc-20240605;
        b=MLVUl99zAC+T5hWEKPvF/nu55NBZI+KbCUxpmHH1az6NsXaRMoR9G+pUu+f7OmsT35
         7iD5A+jSiGRlo5PNn68cUTg3jUID1eNCUrj2keKgQMwXTU8iamyGokzHXIweSmwWcXms
         NPNs0I+phBBAOzTUAJUJNjNkh80pHwMLHAcdeCRDo2hFS3YX0sOdSu6bX495hVXYQTEm
         TQPU9VTlzYxMr5UhR4BL+rruc2fOprKv9eJe7en5vFId/tLV2EjTNeE44lv+CYFSt6C/
         0yAVUy+aNtl5O+PLqrGqTOEbWElzI7VDrznzLbUWxq9Yy4f8pAkvkC/M+JGRozsXfjfr
         78cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=VYnMz/7mhdkmVaj7RQB3aCxmGNk4iMiQhHr8hN0lFWM=;
        fh=6gI5RjMlEainLgcmIIf70qpQOk67ePCQabjUVYKAKps=;
        b=ggjqwerd9mRViCYJXE219SwVLMnspnxDyEB0ro9cE/n5qFoupMB6JnElU34M2JE50d
         aJlb1HZ+VzrUjIkOZNLAi1tHdZ4E/kqHtb6kB/0MFf9KCoanA/T87evW3CXCkaF7VNSD
         4hQL2bqTqz/RDbctJAlVAG3Sv+NdywXnIADWvIsKOViWfnu3HLSijUww+D0fX9wn0vOA
         Yt9COAV7U0Q2Kni1AMhVgUJzwEHEAljoaqOeUUUxpVa0bgct6kPPqJdgtynRGHvI8LW6
         hv3B7bnj3smV/N3rsnOGaaJFz6zjATvXwZzdc536tx5+F3cirVELbA1BMYFV/K+EVChq
         bmqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eD1LXDT0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768449394; x=1769054194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VYnMz/7mhdkmVaj7RQB3aCxmGNk4iMiQhHr8hN0lFWM=;
        b=i1JkCYFRAeKYdgyDv4ExaBxNbJKcWsrMuXgeI4wp7inC6EKN81+F6mucpt52IzgICU
         3eZ9KoERK1JwVKco1fRfYF8i7dmQ09E5mwtq0eAn0qF7jpfHvXwqBwj+iQTvUD6kHUUm
         BLhDD0rdG2Tc3w4gFbl3n0LtgGUFR1mZNnGazNWwjsIG1DjxojyEBb6fIGpoHxV9tdsf
         OH6Q67TsnGgn0KiohyQh++NaxAtyLkPoiDfAQjSgf/qkHXzc0URP6r1k9zjzsExcy59G
         gCHKNoPtfvUO5xolnlIuvBebdVe1IBlCYmKHfvAlQLkZWlsQ4uRQzyNtBnOvG6ba5rFZ
         T0nw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768449394; x=1769054194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VYnMz/7mhdkmVaj7RQB3aCxmGNk4iMiQhHr8hN0lFWM=;
        b=Hv44CadMiS51JSL2hSYEHc/s3lxpF2iYmTKEcoETib1oN2PnnwzLaaCwXY9Xoqc7S0
         tzcDsSakfme5l8+/U8ck1DhR4qPlltDIyP9hroAaMFicY5lqeoR3E+LbC2PbnybafiSA
         MWA2jSUfMhVRguQL01lRrsv0GhRc4hkqxI1BAY2W02o0TRgzD7ueygSA3hf7BRV09t8e
         MBI2OeyyJtPWn1p1i+Dd2uvb9Z/DfreuPZtcM/BKSRpkk+sZZNvZIL3M5KhytnU58ovm
         lMJsCfVokbdPMudtbRvbUJD+iFRakv3HtWYw3mmkFALEtFCxhZVoGzgwcC84he0Pcakv
         Fvtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768449394; x=1769054194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VYnMz/7mhdkmVaj7RQB3aCxmGNk4iMiQhHr8hN0lFWM=;
        b=mkTgriQOKDv1bcJjVTU/jBnQpZATufZZ1sZ7+kFle/UIu1bI1PGdyn/0LrQ9nuYV05
         Tw+Gr5sx4DepKIE8DqU3UEN6ModEGmgAt0M774yQyMGf5pL1yG5rn3J3Z8zS4Ijt+bm3
         4TkHue4Zx0P/CAqNxvuJ9amUqv3/RmMsdK9ahAkK8sRxBJXgaiqT4CWCFcbPX6UN44ZO
         uqMF8xOqIMtWIaorvasVDJMYmPpO92IWjehbYoViteu9XZs54SwAadtT2zgno7vL1NaH
         PSJ5mQgNAQHqYVbv1lymv6lxPs6Pm7QlVmedjb6zP9OQqT9d4w58dVG/7VSuxIBpPNy0
         2Xhg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVINMiHYsKLx6OhMuivSeTuvlxTDaOD+EvJCWStxVGGDyJaYbY9px+e+VByiltjPGhFEqwyhA==@lfdr.de
X-Gm-Message-State: AOJu0Yy8+gO4l87Lu3FLGC8BPeDj8DvIahzbVY33hquYOPt/9vEHA/vU
	olIsBCpHiGJaX0Aai3PSO0e9A1TYYqIXptCcYgg+nPvYlq3okyw5z0tx
X-Received: by 2002:a05:6512:108e:b0:59a:1203:2ec9 with SMTP id 2adb3069b0e04-59ba0f5f1a9mr1727695e87.3.1768449394068;
        Wed, 14 Jan 2026 19:56:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eo81h7NJVVIv/eI7OTYtwEWMDOAWCpRArBecdjWsqJTg=="
Received: by 2002:a05:6512:318f:b0:59b:7c74:ce9 with SMTP id
 2adb3069b0e04-59ba6b4b407ls242684e87.1.-pod-prod-06-eu; Wed, 14 Jan 2026
 19:56:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWBQZGkZqQNyinEAKPieptIa4sXj2QbnlkxFOdE3OkxLc4oy+wRD//fQ3i0pS0KH3RMkF2nWaGcwMg=@googlegroups.com
X-Received: by 2002:a05:6512:b90:b0:59b:792c:b21b with SMTP id 2adb3069b0e04-59ba0f5eef7mr1726938e87.10.1768449391395;
        Wed, 14 Jan 2026 19:56:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768449391; cv=none;
        d=google.com; s=arc-20240605;
        b=kSw47FeRuFveJwMXV2VVWHJQnAzVps7ltRGN8TXIr27WrsyW0lDSjhj1op1il/Ove2
         4vIUiPCAq9zVlOJWaWcKZhgRTlgUeeCo8xlcLF9ap2dQTg0UDqT/ifF9Ku3TlDwdB4Tl
         Hfn4cGrY5tFS34vjpAYoWoJovyXi03NrUbbC63C70DFcIYdAJDj/AiA2Vw0WFpGkp1BT
         CCPRpE4n4SDkfx+qIMxKvGuDXd2oI5ltWYClEehHWe4UQBo8sIfDqDm3n0k0WTCgKnH8
         2TPvRh5yUcSKw3TwhIMB2Iy1A9dBI4jqXDmRVjrIRctxTRXf7A6pqp9jkhBTxsaulp+K
         NpSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6wDChulrCCyYHOj2zKt8skhqhOtaxdzyPo+s0kBuBo0=;
        fh=+wqozo3f6F7Q0mCZJMPn8CbYQr+xnGN91dDwYFWRjAU=;
        b=NY/vxeE5oYxm0vhwmHj21Rd+2b5zCj1QZ/QzxbN9TxDDF6BXqV6kv6mGXkXFmkLnyQ
         2YjWCE9xi+W5ona4hKn7+aQ7CxTeSHYe2pVyctmGfmxH4J116Kl2XFGXWf1Sh7xKVrFj
         LwadJ+UEE+WzzwZ+1z1OXyO5MSc9PST/kLdkp03PsBeylLGWQW1oP+PzNepyOzD8Quay
         ayGrdLQdCxHPrBrncEDNBhS9Yh5+WbmLgW4gfGttR2ZXruS2/JOkkYFcuwxZZxIcbHLR
         spNOn5lbsRXgJWPhkzAQf+zdAAcmBFvqSRuUHMZkN5BgGbXA4IVjqXjqJfeO7BFVSNGi
         O+FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eD1LXDT0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59ba0fe6e89si97186e87.0.2026.01.14.19.56.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jan 2026 19:56:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-47edd9024b1so2547195e9.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Jan 2026 19:56:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXlls0Wv5v54v96yBVRhG8MDwcZepg4mjTATw0a8r2j4GCQq9M7mxHhRsZ1hfLwUyIAO9NJEcUdRsY=@googlegroups.com
X-Gm-Gg: AY/fxX6PiMk/PmsKXDa8zuXhMZANBGN47+fSsR/cgIkEj5QEVaChL1DTnXkvhtDQqix
	5gAtuVy+KF6RbFVQscIaIu3UJkwAwMtQGpka5I0ViG+k/1KBm0H1pyLQk4jHSEHHveeX57jBODZ
	YlPP0lV6sdLqmQFRkflKSHzcBJjnyRhJtWtLQ+Q7iusZ1jPP0uI2F/UCMWuUvF38Bgd6snIJzGX
	sYvztl/NstBjU6eYrLGVL8I/imitBEPTPJe86hNFVp3Xw9GinHkEsWTRI3L4X8UiKndc/xwepFb
	klUmasqOmtPn92HwoKfRNxbufKSN5g==
X-Received: by 2002:a05:600c:3f12:b0:47e:e20e:bbb7 with SMTP id
 5b1f17b1804b1-47ee3371b87mr56339005e9.25.1768449390456; Wed, 14 Jan 2026
 19:56:30 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com> <20260113191516.31015-2-ryabinin.a.a@gmail.com>
In-Reply-To: <20260113191516.31015-2-ryabinin.a.a@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 15 Jan 2026 04:56:18 +0100
X-Gm-Features: AZwV_Qi3K6USsjyPImvxh3Fek-pWdiQdbQKJ5dGAgy4-AqQ7tvitC_QRJhvnXmc
Message-ID: <CA+fCnZeHdUiQ-k=Cy4bY-DKa7pFow6GfkTsCa2rsYTJNSXYGhw@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm/kasan/kunit: extend vmalloc OOB tests to cover vrealloc()
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, 
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eD1LXDT0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
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

On Tue, Jan 13, 2026 at 8:16=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> Extend the vmalloc_oob() test to validate OOB detection after
> resizing vmalloc allocations with vrealloc().
>
> The test now verifies that KASAN correctly poisons and unpoisons vmalloc
> memory when allocations are shrunk and expanded, ensuring OOB accesses
> are reliably detected after each resize.
>
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> ---
>  mm/kasan/kasan_test_c.c | 50 ++++++++++++++++++++++++++++-------------
>  1 file changed, 35 insertions(+), 15 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 2cafca31b092..cc8fc479e13a 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1840,6 +1840,29 @@ static void vmalloc_helpers_tags(struct kunit *tes=
t)
>         vfree(ptr);
>  }
>
> +static void vmalloc_oob_helper(struct kunit *test, char *v_ptr, size_t s=
ize)
> +{
> +       /*
> +        * We have to be careful not to hit the guard page in vmalloc tes=
ts.
> +        * The MMU will catch that and crash us.
> +        */
> +
> +       /* Make sure in-bounds accesses are valid. */
> +       v_ptr[0] =3D 0;
> +       v_ptr[size - 1] =3D 0;
> +
> +       /*
> +        * An unaligned access past the requested vmalloc size.
> +        * Only generic KASAN can precisely detect these.
> +        */
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[si=
ze]);
> +
> +       /* An aligned access into the first out-of-bounds granule. */
> +       size =3D round_up(size, KASAN_GRANULE_SIZE);
> +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size]=
);
> +}
> +
>  static void vmalloc_oob(struct kunit *test)
>  {
>         char *v_ptr, *p_ptr;
> @@ -1856,24 +1879,21 @@ static void vmalloc_oob(struct kunit *test)
>
>         OPTIMIZER_HIDE_VAR(v_ptr);
>
> -       /*
> -        * We have to be careful not to hit the guard page in vmalloc tes=
ts.
> -        * The MMU will catch that and crash us.
> -        */
> +       vmalloc_oob_helper(test, v_ptr, size);
>
> -       /* Make sure in-bounds accesses are valid. */
> -       v_ptr[0] =3D 0;
> -       v_ptr[size - 1] =3D 0;
> +       size--;

Could do size -=3D KASAN_GRANULE_SIZE + 1: I think this would allow to
also check whole-granule poisoning/unpoisoning logic for tag-based
modes.

> +       v_ptr =3D vrealloc(v_ptr, size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>
> -       /*
> -        * An unaligned access past the requested vmalloc size.
> -        * Only generic KASAN can precisely detect these.
> -        */
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> -               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[si=
ze]);
> +       OPTIMIZER_HIDE_VAR(v_ptr);
>
> -       /* An aligned access into the first out-of-bounds granule. */
> -       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size =
+ 5]);
> +       vmalloc_oob_helper(test, v_ptr, size);
> +
> +       size +=3D 2;

And then e.g. size +=3D 2 * KASAN_GRANULE_SIZE + 2 here.

> +       v_ptr =3D vrealloc(v_ptr, size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
> +
> +       vmalloc_oob_helper(test, v_ptr, size);
>
>         /* Check that in-bounds accesses to the physical page are valid. =
*/
>         page =3D vmalloc_to_page(v_ptr);
> --
> 2.52.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeHdUiQ-k%3DCy4bY-DKa7pFow6GfkTsCa2rsYTJNSXYGhw%40mail.gmail.com.
