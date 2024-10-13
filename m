Return-Path: <kasan-dev+bncBDW2JDUY5AORBBW7V64AMGQEDBIZMMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A5999BA45
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 18:04:24 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43057565db5sf18498705e9.1
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 09:04:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728835464; cv=pass;
        d=google.com; s=arc-20240605;
        b=g5ofkrqLpXrLXnLmWr/RDYJb3T+ViTCsQM9FEuZCo+HKrTJEpwV4mm+Pf9CbdEiDpM
         U7vYR1Z4xfrJYzNXj+Cdyxgg/hvsByr/RNSkJjzTqLiMMQ3s363JUTFKhjJBc59losyI
         5ShdWhkgWCHLQK2/haA/c914UCnQbq13xXdAIAXeFpaDuIO5eAxm3IkwpWZv0QwoHsXh
         zBxXTP2FIVVaIcMsFUNWIMFiC1qO/QiU1N8RJpdQnXmRvbOXhV58myAG4TBuxsXtVG/w
         PmtM5jwaknTLCF/b0HQAPG2eJpWqBkiet+CYaDNruOJVFAIf8jo29h6LctEXs6Ontlgq
         dQtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=fKLXOMzQC7OMYP/x61zT9Dglg8S8Ts9bw2DEvI+JYUI=;
        fh=qT5Gy77Y74QVWGpikjctGO3uAuKi7zVoe+15T6L8msI=;
        b=ImmGw3SkM9DJQSYolWU+B566hF6FLQhLCQOZv7Dd08qDYWCmlwlwLaPqxp5ME2cJIa
         JhQWaKbwELqhRHNl/DV2xWfiXLMkSLr8RUUijHaTQ8VknDDan4KZmI1rvfgZq2ZnsaT9
         G8ZuoDwDmVtTPtnu8X/5mRcclbNtkcMhyMO8QKp/VhUmrI/miT0/LE8IyDXSSknwSt5I
         Gt1O0CFpCiXmhWiQhhhHVq1ht1wRB+H+RGtfQQse5ZQBrqXdRCW/fc5NoGh4PdDgUPbE
         O+IzIB/OnlqfgIHI89ecpt42CLbTfVkfHUNraJFkSztzE2noMVTjy//A7j9bBNwjgB7g
         3uuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="THx5C/in";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728835464; x=1729440264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fKLXOMzQC7OMYP/x61zT9Dglg8S8Ts9bw2DEvI+JYUI=;
        b=AruucPrUjcKMiP1DL4wHVK5vl0/m7IOIfMRSM5nOzK6Q0fKV9b2vzIp2IU39va0b0q
         l/681SFr6SZkug9jddZwdpK3OGpGkohnz3xLgsD4RvBTgsbbAIwqtd5yk06JUA2RisBw
         xcb11OuEuU3dfn/MGx+dtuc8KOvt/uivwp2yrRLG0AO78mhErrVwXGjb9OCneykHrbhS
         ZD+wkRhElnPkPJmq4Us2V07SkIZI3NLJdCoe5cnxoR6z93T/fmCVA6yk5SHZ2pM+WDFn
         rlDPrJMuqJojI4ypXatrt+cvzzAI48VxHPLoi/7s3vdwsHqOJhf7zvjAnRIGaupEfdTA
         Hahw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728835464; x=1729440264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fKLXOMzQC7OMYP/x61zT9Dglg8S8Ts9bw2DEvI+JYUI=;
        b=CVqP0d1gHRVyHlnJx8Bd8y7w/EpWzES3DYv/k6KBTupmjVn/iNQWziChODVjNJ+SPg
         2HArxoHo6tg2JCKnk5s9xtU8DM16SqFmmpCZja8dgW8gm2S/K9hqpLpyiKCYUZfh8bXy
         O30Bjgbni5twtWPQhBD2iOjw++ynPGjDNUuJx0NnDb3k2XKu47BC3gn7qL2kgry68VPV
         Gwxc2+Zi+JQ9N9+zPcaGIIVBTI4YfJmgVFl3xyzBXgSVW2TjFV81Ed/LrRy/1LPQBLxu
         JzsMSiLKBf4vb0rXJkPCFldBG56nkChPezLwZxJjIj/MyZebMz1ngUlQtyWu4YLP2hxD
         bA2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728835464; x=1729440264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fKLXOMzQC7OMYP/x61zT9Dglg8S8Ts9bw2DEvI+JYUI=;
        b=DC8CCfOG8SG7Aj7yGRUo7R0AFOukyHoAWu3N27/U+UcoN6tz7/xH5IaRe4GsToa8FA
         24X2ac0haW7M/NgdqdMD4BtnROVTwpnasmds55UbG+rEPktZusIXphslVvxflOnxX8D1
         jXzOheuX0lY7rYlzEky1WwYA1lHbrTLX/yiEA5GBFWMed2X9r3IINmVuhyquMvxJBDjS
         nAX9sevHWTzmoFxNN7xTswYyhXc5ce8ZSlh02uVu8PstayZi1qFDOHDLH/3MFjInA0Qj
         pTsZ4hlCChYddZL8XkGkr78tiVHy9mpGxix4nzD7i5zSObl2qLuorNuAXXRC/Yntl5Ji
         jAdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXE4znvpFXmnyjpoNNO+tu+aYSxz2/jBVvQKuK4tRb1TjTWp9HYsHNwkdzhza1ADJxSRTwA9g==@lfdr.de
X-Gm-Message-State: AOJu0YyJQUg/yjy2d5WZUxSxa34S7gBDoZESq8SjNPFM86KSwGnJMC0L
	XQBAizfFv9tkmkvG9Cw5MkJfh0WGq9pxxuCHq5QL4Ykz2JYmXaWM
X-Google-Smtp-Source: AGHT+IGVxOIutqHkLTtyJ23c+TjeANKSXdBG0LKPwu1/c+VmDUjpj0MfsZAF57oCX19cL12ZndpCCw==
X-Received: by 2002:a05:600c:4611:b0:42c:b7ae:4c97 with SMTP id 5b1f17b1804b1-43115ae9a6emr96598405e9.11.1728835463193;
        Sun, 13 Oct 2024 09:04:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5121:b0:42c:b037:5fb1 with SMTP id
 5b1f17b1804b1-43115fd9c61ls12525045e9.1.-pod-prod-00-eu; Sun, 13 Oct 2024
 09:04:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIcNnH9PslqKDAbV3u+q9v2zxdqlZ8ASdS0WBAHmEORh51JEqMxWcHPqFtYo2X/SanI5/7HNeVmqQ=@googlegroups.com
X-Received: by 2002:adf:f3d2:0:b0:37c:fbb7:5082 with SMTP id ffacd0b85a97d-37d5529bfe7mr6849352f8f.25.1728835461341;
        Sun, 13 Oct 2024 09:04:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728835461; cv=none;
        d=google.com; s=arc-20240605;
        b=bfZ7/do8GiF0KtTTvtuCp1lsU6zNrVgprqUjOJwlPnox6CNnhqEnZxOfJEo/SIzw6p
         Xqw9olxKiBnUDRRrAv7DSKEXZDD+CG77XVoz5OxTPzeiuNWDCsbG+trM9V9eP/H4ejtn
         rnT4QwWHJR1QkVvxMJYJsYyLTDZSFtSWVi4Q5Z4ZTcpkaobjaC9mna3WVnr2+eMDceUf
         6HBZuD3ZCXrvUolJoecLbuRKntD4Pkzkau5CIE3xg3yOZM2xcwepdkSESwKbecvyer+m
         vtHWucffMrSvC8ot9QhA+0yPOpK4XCzW3hfPM1nPbVqvCoCSNoCDHK/ZXBEr2s3msqtx
         DQQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5gMpna/8AYXdCR0wRcOc/2xASvv+nmGVic53OMYWL0o=;
        fh=9etmeuTv69H29Zfo4bxUUhS3dFejlraAfvjGaJKETPk=;
        b=E748ceTVBziazsl8gNZR1eJGHgpqs0WEBPvXumSK2FKlwmZHBTlNxgrZws2LE6pvtg
         Utps0XJPX0E5Y+8WCmG59A9ShjlR32yX0ed4iXvQfi6cC95eIC6C0RoSJIncD/xLrNjk
         wOYMv1kPudL+g6Ps2FAskccIR+KXxx3bSRjf+d/7at87Hba31a/ABaa9sIhtmBSwoSJP
         UcH1/ae+BJxAkuImxgPyDaKye031+bJGYR1yHcg0un9mGZKgfoSaBIEX13IbGKlLK52i
         u+C3O4DR0AqhtHcclxpCY3X2KzaLk9YK89/qbn6t2dyfUR+oAMcmXSXOqIaZNl0rQkDD
         yNXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="THx5C/in";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b77884dsi116110f8f.4.2024.10.13.09.04.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 09:04:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-43115887867so23111825e9.0
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 09:04:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVe16l6mMSD2M1GgvFsM8Yb41BwqMXVtDWvXfkgvwmqNNKOj66dB1RMRblUghtMJM8AjzdbablXQag=@googlegroups.com
X-Received: by 2002:a05:600c:1c9f:b0:42c:ba81:117c with SMTP id
 5b1f17b1804b1-4311d8914ecmr69774385e9.6.1728835460697; Sun, 13 Oct 2024
 09:04:20 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
 <20241013130211.3067196-1-snovitoll@gmail.com> <20241013130211.3067196-2-snovitoll@gmail.com>
In-Reply-To: <20241013130211.3067196-2-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 18:04:10 +0200
Message-ID: <CA+fCnZd2pANBuapU4akh3a1+K2ytk+7t2B64Z_x2Xj4Wh_ELSw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] kasan: move checks to do_strncpy_from_user
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, dvyukov@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, elver@google.com, 
	corbet@lwn.net, alexs@kernel.org, siyanteng@loongson.cn, 
	2023002089@link.tyut.edu.cn, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="THx5C/in";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
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

On Sun, Oct 13, 2024 at 3:01=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Since in the commit 2865baf54077("x86: support user address masking inste=
ad
> of non-speculative conditional") do_strncpy_from_user() is called from
> multiple places, we should sanitize the kernel *dst memory and size
> which were done in strncpy_from_user() previously.
>
> Fixes: 2865baf54077 ("x86: support user address masking instead of non-sp=
eculative conditional")
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  lib/strncpy_from_user.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
> index 989a12a6787..f36ad821176 100644
> --- a/lib/strncpy_from_user.c
> +++ b/lib/strncpy_from_user.c
> @@ -31,6 +31,9 @@ static __always_inline long do_strncpy_from_user(char *=
dst, const char __user *s
>         const struct word_at_a_time constants =3D WORD_AT_A_TIME_CONSTANT=
S;
>         unsigned long res =3D 0;
>
> +       kasan_check_write(dst, count);
> +       check_object_size(dst, count, false);
> +
>         if (IS_UNALIGNED(src, dst))
>                 goto byte_at_a_time;
>
> @@ -142,8 +145,6 @@ long strncpy_from_user(char *dst, const char __user *=
src, long count)
>                 if (max > count)
>                         max =3D count;
>
> -               kasan_check_write(dst, count);
> -               check_object_size(dst, count, false);
>                 if (user_read_access_begin(src, max)) {
>                         retval =3D do_strncpy_from_user(dst, src, count, =
max);
>                         user_read_access_end();
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd2pANBuapU4akh3a1%2BK2ytk%2B7t2B64Z_x2Xj4Wh_ELSw%40mail.=
gmail.com.
