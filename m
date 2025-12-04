Return-Path: <kasan-dev+bncBDW2JDUY5AORBEOMY3EQMGQEEAXQVUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id F31FECA433E
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:17:38 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-42e2e447e86sf602870f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:17:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764861458; cv=pass;
        d=google.com; s=arc-20240605;
        b=LLj2izh3qm1D7jkvnr4LNLgHG8BmalfTvF3zBjWzuRcXor0ZU4JicPuptD5ysAAQER
         geNhGWsRxYn24yziu2FLnzH/Bg2yLrFZsI1YCvk5HjEwLdvOkT3FrCkYKLYG31ZDh2ro
         9x2vaTAAsYtULC4BPhbD2slvXvC5nSXBm3hIU3/+7wrPOnBiy/Gv8hB3YYt0iMCcZHjc
         +mefYBdUge5X/amMWrodtC/tZTKV0lTyhJR8sBd9ROGCdisA2p7TJ0KJHOd4Uo2HqTHr
         7jLstenuhyxDFk73w93bD8F318V1JOvCpkgDYrOCwwFSXKYNt1qNf3ZMzxoWEz6ltTw+
         xsJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KTKUkASJelQL2otzgfCXJbVSgCEwhMr4Yrz9Q65QCTM=;
        fh=w7xqiYe11elYl9Glg9UPnmFq9MAjwap8n87P7Ypt/9E=;
        b=bWdjz/sUKmjVd/hiwahxX73Mnmld/KB6WxXOY1FF4h0ZXFcFGpy9o0/SsVmTdRYtQ5
         nyVyFrXBM99RnMxnxchTzfKuHSZJFJDz3ZYLWs96pusvZqWMOJ1oEAaRd1EnAUsJsCQo
         J04q+bcPLY/0s9M9iAun4sdL5XhktX7RLgmCgde4fmC6ESoTAjiJRIChIno3U4s4WwZj
         OoQi3b3Q4X9GGkMMtY9YsVoNeFKXipRhwY0wOtU++UbkP0Nr17kmZliekYCGZuR6LWkf
         W/Zl23e9Ju96LatuALJ5pusnu4O1yVOImV93xaR6AP+noS147fHehTaxxakGPwttkjGY
         fC+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EXZDfVbj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764861458; x=1765466258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KTKUkASJelQL2otzgfCXJbVSgCEwhMr4Yrz9Q65QCTM=;
        b=N33i301egv8WGYIYCdwYZTkAs5zlJ/nTl0gq9vOOoedtAvNhsQpvOE4c2BPSw2t9Ho
         ev+o6nGElagzExTw0ypVk3DEAYEE2CRYcU3ISjKwuV5eFMk9WXsfHD1/Wdnj5zW3kSL5
         vjM1K9P9b3uqHi4oSI9WfFNcMMNFxBateXRIfNojQIBId0uwaCUj5AkImuG2f5YqTWbc
         6jrEHJPNRq65tv7w90pm+tpoDAeRqkG8AMgoCEE/dX14fQqSzPvCnkPZ8+gHhNJd5ta6
         6QfZz/+8uO6PHSWdYIea5aF2j7qad1s3gP7eiaUVnC1DStk7a5QVfU5O0QxorEl2hZSN
         ThMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764861458; x=1765466258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KTKUkASJelQL2otzgfCXJbVSgCEwhMr4Yrz9Q65QCTM=;
        b=OU4AkJIlsiJUWgC+SphVYf2NIiYIOTL8nItDe9aRwaCPJWG6JxxGGmWbylff99qOtl
         LR8F9jHuwnVZuRPpdUZfKLCaMv1xrY5Hz70BUgDLvHaWrvUbLJWE65WbBXJHyQxgq9EK
         X6M8jMQPouOuDaGlr4/0GseCDVKmU9OYxr1xm5ON4/af1x6BwPaxhxXVisILP+IKQjiA
         T6Gj04j1KyZlPTINZNZ1CrbSDScIPl+LVe3m3N2T/2jts/hnUu0eu8TmUjWLyKDi6yu+
         Ryu80+izGeS1IU2lyFE7quHJkxL+ee9h7CLLueS/vIPijlzAHYc7X1Flqga5MmS00wdj
         8sIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764861458; x=1765466258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KTKUkASJelQL2otzgfCXJbVSgCEwhMr4Yrz9Q65QCTM=;
        b=cWbye4zT4gJrGx7NdYDvyakx6ZVPm41Pg8qaevUzkg1ex8sovilwWM+Txv7YSSDwJA
         aVzgE3l1zORwPX+puYYjpb/SrJYkuoQU45MHNBVZ7y1SiBhzWSMj2YGj+AJjkd2xISEL
         cZiQ0mjseH3zCXvD93qT57tvAW0Tz6NeHofMBgVrYArn74wSa9I5pgd+uK7Vvoy1HsFW
         yqPKRSaqGmMEHqfTASdQxA0cLmldem4R3LdWdskybRsl7CVQbmUk+qatBaIG0TGaucYn
         PaI71CWjxKjosH3kquFi+a1Rry6Av8Q5ntG97dgSNZHXqBmq3iS7dD9bm0lnTE7uTWJK
         GDyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWy/fwph++U17LWLZnZbo9hx9NseLUexLJwDF440k63tfSZl45AlrF3M0gyNMsnf6Tn0B5Cyg==@lfdr.de
X-Gm-Message-State: AOJu0Yxdtsb+Loek7nSOTpWF2lVFVIQa27O3yC4ZFrnjU4tsO0kMcm+S
	VXxqjOlB2L6nj3dTdJkqxlpNCKWR7q48L+binplCcT0wS+ttRefGKWaL
X-Google-Smtp-Source: AGHT+IGWxzJy6tKqIHu6abFQpf3NBSb65tt3NFlVqXMF/I8tZfdCJPHYioQ+Ffnnuk/KjLKEiSCEvA==
X-Received: by 2002:a05:6000:40c9:b0:42b:3746:3b88 with SMTP id ffacd0b85a97d-42f731cc0d4mr7281814f8f.57.1764861458342;
        Thu, 04 Dec 2025 07:17:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZabbdW7ZdgXFj4+0yin0lixrIKuwNUWtQBO95xXi5aBA=="
Received: by 2002:a05:6000:2f85:b0:426:cb20:6c35 with SMTP id
 ffacd0b85a97d-42f7b0337a4ls515677f8f.0.-pod-prod-06-eu; Thu, 04 Dec 2025
 07:17:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVmRJsO2BbuEnMn0ys1xAWblGsy3eVjiIRreWz17txmTSesPPIht+4eVvdNqvKh/O/Ur29ojSXGWYY=@googlegroups.com
X-Received: by 2002:a05:6000:200c:b0:42b:2e39:6d45 with SMTP id ffacd0b85a97d-42f73178ec2mr6969403f8f.15.1764861455441;
        Thu, 04 Dec 2025 07:17:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764861455; cv=none;
        d=google.com; s=arc-20240605;
        b=GuZf0oKHM7OgpG6aovK6Wite5qSOqJ9p3QGz4oADyzUXfK+o4CUcxTw02tbs2M79DD
         iT+Q8sL4iCXUgZ2DpYpp8Af89K0k4oogk0k3bYvfVD+wnNWekUtCwKpCeE/cF+7fI4ZC
         5zGv5NyEyIWnNpy+enj5hcg9OPvnYyU5hXycJeMH1mr/h0B2/K9OMNIiCziJoRtnfzdK
         TJWe/fgramXXjuvBfVBv+NHxncdZXUtr+dUPDRFfI6wV/kUp5qtFsnrzjW7+qxKwr4th
         WyUhP5bNERLTh1APr7wOxQNfz/EK1G7i4PX2aVYIIyfp66vXo2O6LXKC0wS+Q3/j95xh
         IuhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WSesA1513PF1RTOpQ3ExDpK6F+FkeLsbkbgvrO0OXrA=;
        fh=3oxF0RnbmgbKHd2j3w/ClfZ20TgpYo4Mw5yQQ6hO7jk=;
        b=hxhckaxUrn8j0OraDMskYBGC6ZX0bXS0Xxqtzco2FmU0POda1zzdLPKtvfxjTv63w+
         tMjX/5vJ8hSysZB9ADrcY7huverlIbEVdf7Lw3Z4MBgSg0rqMZ4mez8iW58IoqTwTyNo
         aNq5DU6XRpeZjyKQ82KRKzzWx4hWzDqFlFNVBoveTTibmbdCNECJ29hKJyem7WosRSEE
         JmCC174SZUlVOZgBHK8Z0bDNeDfs8tSlAKQ15jC+JuMKq+Rt/z1d++zZM3voM3hMwD4N
         Ao3YbvC321ROJ4nre6Wxoq7VcXo+1DRGOCdHhPmyG0x00T81olQzWoXzcT9Ag7vgZZTl
         IyPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EXZDfVbj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d325b82si24087f8f.11.2025.12.04.07.17.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:17:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-4779cc419b2so12597325e9.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:17:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW0HodNkyZ3Rpxz5SSYzlwlXSzBVUsomX+xobrGP58REbUQELfWrO16BQer8e2N5DLxO0hpyS8j3o0=@googlegroups.com
X-Gm-Gg: ASbGncsOW5kuRgNL22tVkQh3U6mZLIk3owPn4WP8UzfzCfmHG6GRYpAsYjSScKOf8Vy
	DAXBE08yT6eXRh8r6MtLOwegV/IiL8kiBXQQuslfp9Ga5e0nJGG6hTdonk0y/U/fwlbWOvhkkGc
	AbZi8G9dAq6Tlq2QwZaUB5Q0nPhdqrob/6EKHxipu7KdUAM2T9Dx5JFkxxNnuDSGgYM+9Vy5JfR
	cEQ3Lntu+wmknA2gIbOEVzRer1v827lkKGf9hVchf8u2fX196x1CJejhNSXdlbJSyfVVM3m4wqj
	wTPYh5K9wrJJ4ffthMWObQauH9CR
X-Received: by 2002:a05:600c:3b05:b0:477:582e:7a81 with SMTP id
 5b1f17b1804b1-4792aed9ab8mr67560995e9.4.1764861454794; Thu, 04 Dec 2025
 07:17:34 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com> <20251204141250.21114-2-ethan.w.s.graham@gmail.com>
In-Reply-To: <20251204141250.21114-2-ethan.w.s.graham@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 16:17:23 +0100
X-Gm-Features: AWmQ_blzpwZ5TwYvwfzPgYjtrBP8LQtIvLje7Y_oBdFacKxiRRQT788M4KRtDnc
Message-ID: <CA+fCnZcvuXR3R-mG1EfztGx5Qvs1U92kuyYEypRJ4tnF=oG04A@mail.gmail.com>
Subject: Re: [PATCH 01/10] mm/kasan: implement kasan_poison_range
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: glider@google.com, andy@kernel.org, andy.shevchenko@gmail.com, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com, Ethan Graham <ethangraham@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EXZDfVbj;       spf=pass
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

On Thu, Dec 4, 2025 at 3:13=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Introduce a new helper function, kasan_poison_range(), to encapsulate
> the logic for poisoning an arbitrary memory range of a given size, and
> expose it publically in <include/linux/kasan.h>.
>
> This is a preparatory change for the upcoming KFuzzTest patches, which
> requires the ability to poison the inter-region padding in its input
> buffers.
>
> No functional change to any other subsystem is intended by this commit.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> ---
> PR v3:
> - Move kasan_poison_range into mm/kasan/common.c so that it is built
>   with HW_TAGS mode enabled.
> - Add a runtime check for kasan_enabled() in kasan_poison_range.
> - Add two WARN_ON()s in kasan_poison_range when the input is invalid.
> PR v1:
> - Enforce KASAN_GRANULE_SIZE alignment for the end of the range in
>   kasan_poison_range(), and return -EINVAL when this isn't respected.
> ---
> ---
>  include/linux/kasan.h | 11 +++++++++++
>  mm/kasan/common.c     | 37 +++++++++++++++++++++++++++++++++++++
>  2 files changed, 48 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2b..cd6cdf732378 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -102,6 +102,16 @@ static inline bool kasan_has_integrated_init(void)
>  }
>
>  #ifdef CONFIG_KASAN
> +
> +/**
> + * kasan_poison_range - poison the memory range [@addr, @addr + @size)
> + *
> + * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE, d=
efined
> + * in <mm/kasan/kasan.h>: if @start is unaligned, the initial partial gr=
anule
> + * at the beginning of the range is only poisoned if CONFIG_KASAN_GENERI=
C=3Dy.

You can also mention that @addr + @size must be aligned.

> + */
> +int kasan_poison_range(const void *addr, size_t size);
> +
>  void __kasan_unpoison_range(const void *addr, size_t size);
>  static __always_inline void kasan_unpoison_range(const void *addr, size_=
t size)
>  {
> @@ -402,6 +412,7 @@ static __always_inline bool kasan_check_byte(const vo=
id *addr)
>
>  #else /* CONFIG_KASAN */
>
> +static inline int kasan_poison_range(const void *start, size_t size) { r=
eturn 0; }
>  static inline void kasan_unpoison_range(const void *address, size_t size=
) {}
>  static inline void kasan_poison_pages(struct page *page, unsigned int or=
der,
>                                       bool init) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 9142964ab9c9..c83579ef37c6 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -570,3 +570,40 @@ bool __kasan_check_byte(const void *address, unsigne=
d long ip)
>         }
>         return true;
>  }
> +
> +int kasan_poison_range(const void *addr, size_t size)
> +{
> +       uintptr_t start_addr =3D (uintptr_t)addr;
> +       uintptr_t head_granule_start;
> +       uintptr_t poison_body_start;
> +       uintptr_t poison_body_end;
> +       size_t head_prefix_size;
> +       uintptr_t end_addr;
> +
> +       if (!kasan_enabled())
> +               return 0;

Please move this check to include/linux/kasan.h; see how
kasan_unpoison_range() is implemented. Otherwise eventually these
checks start creeping into lower level functions and the logic of
checking when and whether KASAN is enabled becomes a mess.

> +
> +       end_addr =3D start_addr + size;
> +       if (WARN_ON(end_addr % KASAN_GRANULE_SIZE))
> +               return -EINVAL;
> +
> +       if (WARN_ON(start_addr >=3D end_addr))
> +               return -EINVAL;
> +
> +       head_granule_start =3D ALIGN_DOWN(start_addr, KASAN_GRANULE_SIZE)=
;
> +       head_prefix_size =3D start_addr - head_granule_start;
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0)
> +               kasan_poison_last_granule((void *)head_granule_start,
> +                                         head_prefix_size);

As I mentioned before, please rename kasan_poison_last_granule() to
kasan_poison_granule() (or maybe even kasan_poison_partial_granule?).
Here the granule being poisoned is not the last one.


> +
> +       poison_body_start =3D ALIGN(start_addr, KASAN_GRANULE_SIZE);
> +       poison_body_end =3D end_addr;
> +
> +       if (poison_body_start < poison_body_end)
> +               kasan_poison((void *)poison_body_start,
> +                            poison_body_end - poison_body_start,
> +                            KASAN_SLAB_REDZONE, false);
> +       return 0;
> +}
> +EXPORT_SYMBOL(kasan_poison_range);
> --
> 2.51.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcvuXR3R-mG1EfztGx5Qvs1U92kuyYEypRJ4tnF%3DoG04A%40mail.gmail.com.
