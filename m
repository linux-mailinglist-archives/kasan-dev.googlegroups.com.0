Return-Path: <kasan-dev+bncBDW2JDUY5AORBJ6SZW6QMGQEG5IYTBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E08DA38A0F
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 17:51:52 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4394040fea1sf26706355e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:51:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739811112; cv=pass;
        d=google.com; s=arc-20240605;
        b=MVAlAnn8j5e9VFY1pVMMXnDJfYaXgDyGkiTcsg4SMNWSdsq5wYCwpKRr8FUFAYf19w
         dyvaKPPqhqC4RhAII/7D8cxBgoCCs37TMVuVbNydbz6p/vBrV1ubhHnGWIknreA29Nud
         9W9eJb0dq8Wq8atCoP5gmyrNIjWNAYGBs9KbBaj5FPD6e0WWYE9aEE9QCZJEtPjb2kvb
         6yWrw5uPjTtEEvnCwPIqEHwof58K1HSEqGyHLfHyettYy7G8+A9gjmn2QWPp8UaFB3li
         Tq7ndre+ePH+sPRtbslpF8+PRQAKOpLInODIxsR6NXaLLT1/v4l1jmvJFoT/6J9rOJWk
         Smgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=36xTxXNqCRuwx49oPr0PTToB+9rFqlx06RUFteNAKdY=;
        fh=+VuX9q9ityW3a+EBlIogXsBILhSuH55uOh339XB58WU=;
        b=b0EPpLk4vTwBiC+yoT/EHGcFYFACLRhK96RaKeBpHJ3ewxeYD0e/1+EbF8m7rfs0iv
         Ve0iGjsuEM7Ns/wObwmgngO7LxSumhc0Z/wXVhAqxI420BQtI/cvRMDDORyFEvX4MVzz
         K9X+KT74sGbAB1jEvy/5cBe8vSAiYCe8hoh22luPxO9oI+qcASWRLhfM5Agqh+WNNTFN
         RCvnbP+Zx5/bRLeuMmUpGzk4RjAiS0x/R+ad4/odXRWjwPJKDSAh/fCYH4fuOEMjkGHp
         14oN6/Q9L4l4VQdrtGYu5wDx9Kxuf/YezI/xyMjLbZZzQ5KCkHxJZ0FTsqyAFX7eYxzp
         80yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JbG5rE2H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739811112; x=1740415912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=36xTxXNqCRuwx49oPr0PTToB+9rFqlx06RUFteNAKdY=;
        b=txSPK0woDFLi8vq7TDOsqqwfMxYdz+W29diMRLWUt9W4uzys+w+xhLoDalYh9cHvhX
         fRJuiYvM/2/Xsr6mHiprHJSLEjGhlGxBhT6SBOu1gcHzVeuIWmmIgG02f0oPHfJBRmgN
         IXmrhQnlAuR3uKRG4oknCaAnIcyUFeuK8cUk2PvE/RkvkiUXotZZHYEUqWJHUq/RtiQm
         UaBCdkG3k2GbHhREy5FuBqAbdQugZs5wYp40hGe5Q2OqvrlZiZFXYhLVwc0dnI64ClPe
         jdnfVtX4jpOGLyitoTiJLNLe2Q7IUzKb/VSaf1F/Eh211Orzp/bKyATEX7A+lMtgfTso
         g08g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739811112; x=1740415912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=36xTxXNqCRuwx49oPr0PTToB+9rFqlx06RUFteNAKdY=;
        b=haXB+bdBeGY3DQ4ujWakcdnFtVplggXDOWBPnJ2KOXsxF8wtBtnUzDd7X+I8uHVaKm
         0SoJSkolTyrleRFovJyLntZ1kVKEVg3NYUe3OxlaKHExsU1eu6dB+6PgkTME9g1TK3QQ
         mHlsy8DOFo92U03Vqa1eq19erbaJPzBFlU+bj++T0eEoXxsqAupbaJ0FbJmrjYjCz0CT
         JCw/zXmC8FAQdut55TogDZUZ0jsX4gyCAnkslCEwtK2uIvWY6AcpKuHYj4QCSAfYGb7O
         6wlYHthQTz8Gf3MScMW00JpE6yNoqKDmrZ7QYLknlfqgqRZok+C8QlG8LH7nYf2P4SbK
         VOKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739811112; x=1740415912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=36xTxXNqCRuwx49oPr0PTToB+9rFqlx06RUFteNAKdY=;
        b=SKVU/ZINjtUzETdc/klZEi9AmdJonibkU4Ph72nu6J4A619OtEBA1I0on5Fz7Hv8se
         zUTp8fuMsIlHsUTJANqWM4Pk/EuJjasaT7P987B0rsIq4tYzN5w0+fro4kCQ+o01/+Cw
         mFrWvclTiXC1lMHTf3/CNtrPk6Cfbuo2vSDj8mDiYN1MleXVAsN1A9PwGFJmuYUUdGMx
         SQzViv9CLSZIs0Cz0gwwYnXOs7km/FcevVFQ4m7a854IpRQ/7C/wT9qVldoJLOAaWtJT
         9qNIHdHLUhBwmUTZw990IPNOVMR4qDR/vIx6nlLBNy8CzOjvO6uM3EQWXSNYSMVXlCdi
         NXog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUq4AFwogGlcCBUH/GPdZn+GVTdYv8g25P+L/LxE7lwSEfccS3ev5pNNIlXEF/eXAT9f8EOeA==@lfdr.de
X-Gm-Message-State: AOJu0YyE+HLTi23Dy64XfJeRQvCfwuC4YFv4tY+Dc7TnWjjREkf1FaDL
	9TjzJEmMcLZF+3e0ytR97NzA95OaOR76V94NNbpnoAEpXnIchq4W
X-Google-Smtp-Source: AGHT+IEgE+fVx5rx5gCpM6SSzKQCLeuwr8oMfOXd61XuRfhgGb/2rCvlIOU0wu28NfI+ux2qSFJcLQ==
X-Received: by 2002:a05:600c:3516:b0:436:1b86:f05 with SMTP id 5b1f17b1804b1-4396ec7cb6fmr97848945e9.11.1739811111453;
        Mon, 17 Feb 2025 08:51:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEixLLQ3Ymbf8FF7PhVCNt6PX6A6oWwKefMGaQmukhOnw==
Received: by 2002:a05:600c:4212:b0:439:806f:c2dc with SMTP id
 5b1f17b1804b1-439806fc3bfls3496025e9.1.-pod-prod-00-eu-canary; Mon, 17 Feb
 2025 08:51:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUztDC7jH20A5ZrwK3vyeLlG2J5/wzAedVRgJdsSGvv6ExhCtD1GTo8j5eLutx1HGCTj9Z9UAYZzLo=@googlegroups.com
X-Received: by 2002:a05:600c:3516:b0:436:1b86:f05 with SMTP id 5b1f17b1804b1-4396ec7cb6fmr97847825e9.11.1739811109164;
        Mon, 17 Feb 2025 08:51:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739811109; cv=none;
        d=google.com; s=arc-20240605;
        b=CFy4s5KV8qAitxFORIJPe2Fm9OFjsdjEXwApCAXR0yyd8lZnUHemPD1q6eZU5v+8de
         GX0qIzTl2xycCN6GY+6EToZRht4BTzgUQbf66+QeUGzJW3XoSgKe6zuia/QfmJnG0xFo
         R56Yi5EhvALXCG6HzhBmE2tdyZ49FlCT4hcGX1eeapNfUesVvH0R54hQbZRrZwKULfRI
         Kh+uew4tG30WiMxx8VvwKSRBT+dwTrIwScxodiHvc9uovp2zIY3gL0a/kE7Br0dD520N
         epr2HTUvDq5PDu6LvMnaBvRnd+SX5bcUlfRc0S0vTJYxAmIuEkj9fb0ZkScBjGFvz5k8
         T5cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=w2oH6tzTSJsdgiOYfb4nxFSWGTiJy2ivK4rT2/V8PqA=;
        fh=gam+7wEUno6l30GTvlSOVxSEX1Uu1zbg0XcXt/9dgbY=;
        b=O2Ejbbqk1+In4Ehh0450c7yahNQEosghdZtOBu9SSNw6tG7hCpNoCfVoecR07E1mrF
         9xoLqBaz1ioj2xYKfBA5N8fcR2/RB1t4uE6z0ahTqPNQBDHwjGJZMkaZcMEcDCs76Vfk
         2BQQf0q6+gYj4GMWHsM7GmHgFDsZvTeIoBxv9XrmDMkyG48NWbticEeCgUJOI1/oGNs/
         xTTTKD5ovw0vyj/DzkGesZYHwZVnhtl775+VgSQrP3nuLBMmGV5GcfBbFiNLOnsWu6D+
         yazHS835NBWCM3Cxp/LQgtypAqHCZuwea7dYYXK7q6C4v7//5Oy2iT9OeHRN01M3r5GW
         7rQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JbG5rE2H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4396787ca3asi3111825e9.0.2025.02.17.08.51.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 08:51:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-38f3913569fso1082931f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 08:51:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVA3c8yiCsUE3acLbr13zUZWyuM7j/l9DTn4m++T9wF86cqp63SuudZDHvOwBuhtsX0wb0/AOqhCZg=@googlegroups.com
X-Gm-Gg: ASbGncvNnuoPuc5/5h1NiLR76/S3Pn48BYhVvuQPDchq1AMYGfMNNeUAdob+STN6uBG
	Pu4kX9w9DHMUX8X2LUciBUr69ql3QWwDBDKGtX8DVlKTMWfF4ue7Kpegt11kyOHbm9k9Puz4NYY
	4=
X-Received: by 2002:a5d:64e6:0:b0:38d:e3da:8b4f with SMTP id
 ffacd0b85a97d-38f3398735amr10306508f8f.0.1739811108606; Mon, 17 Feb 2025
 08:51:48 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250214195242.2480920-1-longman@redhat.com>
In-Reply-To: <20250214195242.2480920-1-longman@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 17:51:37 +0100
X-Gm-Features: AWEUYZkOL6ftniWInMbuFfxoX1PJLv06k4--glS_oxL3qhOErs8KcVkmUmvHj7I
Message-ID: <CA+fCnZe=LD0h-0F9tQ=7=b3JbNEfEbp3C7j4w18nK3gAs3Ac9A@mail.gmail.com>
Subject: Re: [PATCH v4.1 4/4] locking/lockdep: Add kasan_check_byte() check in lock_acquire()
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JbG5rE2H;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Fri, Feb 14, 2025 at 8:53=E2=80=AFPM Waiman Long <longman@redhat.com> wr=
ote:
>
> KASAN instrumentation of lockdep has been disabled as we don't need
> KASAN to check the validity of lockdep internal data structures and
> incur unnecessary performance overhead. However, the lockdep_map pointer
> passed in externally may not be valid (e.g. use-after-free) and we run
> the risk of using garbage data resulting in false lockdep reports.
>
> Add kasan_check_byte() call in lock_acquire() for non kernel core data
> object to catch invalid lockdep_map and print out a KASAN report before
> any lockdep splat, if any.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  kernel/locking/lockdep.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
>
> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
> index 8436f017c74d..b15757e63626 100644
> --- a/kernel/locking/lockdep.c
> +++ b/kernel/locking/lockdep.c
> @@ -57,6 +57,7 @@
>  #include <linux/lockdep.h>
>  #include <linux/context_tracking.h>
>  #include <linux/console.h>
> +#include <linux/kasan.h>
>
>  #include <asm/sections.h>
>
> @@ -5830,6 +5831,14 @@ void lock_acquire(struct lockdep_map *lock, unsign=
ed int subclass,
>         if (!debug_locks)
>                 return;
>
> +       /*
> +        * As KASAN instrumentation is disabled and lock_acquire() is usu=
ally
> +        * the first lockdep call when a task tries to acquire a lock, ad=
d
> +        * kasan_check_byte() here to check for use-after-free and other
> +        * memory errors.
> +        */
> +       kasan_check_byte(lock);
> +
>         if (unlikely(!lockdep_enabled())) {
>                 /* XXX allow trylock from NMI ?!? */
>                 if (lockdep_nmi() && !trylock) {
> --
> 2.48.1
>

I wonder if kasan_check_read/write() would be a better fit here. Those
are intended for the compiler-based modes and are no-op for HW_TAGS.
But I assume lockdep will access this lock variable anyway, so HW_TAGS
will detect memory errors.

On the other hand, detecting a bug earlier is better, so
kasan_check_byte() seems the better choice. And lockdep is not
intended to be fast / used on production anyway, so the extra
instructions added by kasan_check_byte() for HW_TAGS don't matter.

I guess we can change this later, if there's ever a reason to do so.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe%3DLD0h-0F9tQ%3D7%3Db3JbNEfEbp3C7j4w18nK3gAs3Ac9A%40mail.gmail.com=
.
