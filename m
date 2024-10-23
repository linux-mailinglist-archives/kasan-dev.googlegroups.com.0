Return-Path: <kasan-dev+bncBDW2JDUY5AORBL4D4S4AMGQE5ATRFEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F2219ACBD3
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 16:01:21 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4315b7b0c16sf50644705e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 07:01:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729692081; cv=pass;
        d=google.com; s=arc-20240605;
        b=JBljDLy+zQYweUAYuMOJ7Mp/Fyzb9GI1uO8sdKzOiIqD9I0o1QsilSu1qhMxd66VP/
         YD2d0qcfrWsxGxOYXUJwidgkcRSuf9YwBMviuhQzEhEaTSIsJZcBRO3h0SqkUX3P10cy
         izDANbUbo1HKbjDp2PTgpvxL0fx9hJ7AhDVIkLFgU4MQ4IwwimaGJVc49AM8TokG4qTx
         NuhkHrDuv/nZLKqqXPx7A/7+XbvVVafIFZkOKmBalbbXlHNZJPyJK09/LGF3+R2Ml0AB
         p3bNGEZ6vN/Qqp2/SV7UymiiXMnFBHMGy6nydthrT+ns7iuPgcMJ8d51rYGLp54qa1q5
         BwZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=GF16b51HTohGrWGf3h0jJkGOUuHQNO690XyIxpcuKGc=;
        fh=EptueXJBBkazqO8eOQHWiDxYyNv4EIkwTMzdhVL/zcw=;
        b=TDrb7Gmenr5yISQ1AAszYkC8J138makTJqMLdDdC1gxMvGdqxowOyFIP39VkVN7iAC
         ymWL2LnLU/o1ExwHLsVX81ZdbCxMHYkTpBB7ck1jOU29jTgsNhrlm9mR7tkxQDik22SQ
         EjPpqO/2HiNDRCKgFIgeR/Wo5sD0DG86SJBqSH4uoUEe1hGZ3wz9+p9C48nFcdJ1YtHE
         F9aM2OUCSYcK7RlZ4LYjoatpiUDzbulgqd+IidDLQxLGCU/u9eTOUFO9bblE0aTn4x4n
         f5t3G01OaTWxJ8D6hpwGT/jxH9/XMJIOATuWm7dyBvxjTPJdBJOV77Q8Kz7MXY11+kEg
         mjzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MiLP+z6W;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729692081; x=1730296881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GF16b51HTohGrWGf3h0jJkGOUuHQNO690XyIxpcuKGc=;
        b=NFSrbRASQbIy6IIhqPkPbTi/k5liPEfuY4EQ+Cd4Il35FWKWNVFPDNjuGcjhvkpVlT
         1xRRW+XHOw+/iphX1cmvnVbI/DwaLF1j9GWtLYqZh5hsYjBSN8azDwXTGPaOIlqWLBj0
         M+INbl5W4jKwvhzv+tChEYeO3huEs0TcAF5GttHBRS1fxKe34VjiyTOgAWyWaQtyQk7X
         3aALgiINKok6wK3Xr09brMPARr7NFAiFnPRNejzHaiGyOsDAYWUNZCIEi0RTrhVkqwbu
         AqaVJJFxBLvweW57arlnXNMeWLsBvin/XS8LsAeKA80Zj9saVrD97l6Va9RKRDAHZYfV
         Ayxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729692081; x=1730296881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GF16b51HTohGrWGf3h0jJkGOUuHQNO690XyIxpcuKGc=;
        b=ZcRpu0KNgBSUYBiKG+45tx+pxRRjaWeitzxYzbCddpH8q0U+kveqjMNYATB/9/FUT2
         dQ53u5aqDjo4giwcvD6HkQn+m+IitW+0vCZZxKbfrsA8k9Ubd0NsjfevykdP8q69aYo9
         K1jnzp/gGPk3XeexTT0mfrqTi7WP9Z90GnooMwSwtUFteXOZmcLXhtxN5JwxdjvFYx//
         4BIAqqFpGWJCRCQy0AtEXg/1ENxu/kKObQODIfoMp4aCB616sZ/niOWs0ye2Yg7DnuHV
         82wxm/461GgS8jc4q8pEsKMYd/mdtqPP2EqgfJBrynF9mGM6wCiy5LBNjwpEp75cHwyu
         DxfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729692081; x=1730296881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GF16b51HTohGrWGf3h0jJkGOUuHQNO690XyIxpcuKGc=;
        b=Z6Za07q2eOmhxlbkJsD1ByS2CjQlHc/yFoa93M/BR/kL6UOP6j1zscIoMmjoi/KWBu
         B4uzgGdH7JHZyx82l9nRS16KJLHtMnmXWX3cl6DKwB6tfV5H8Z6sUJKbgw2Izs1a4VPu
         ZMq0GOYkn3t/D9U3EeO+juNfW9KQLvK0Qe6QbP/bZcZ7mVBcQWbHsbXFG+OjZLt2SUoP
         lhitI2VLwetO8LDlt//0jAYW5oU7oDv7mCAPzLzcEnLJWDrEQZd6l8+6vOXtO+4eaKBd
         VGwDyxrftT9NgqneZv5m/lGajSE7x0HllVtvckvdCm8FRuLNId0MGee5zmJzoRhI12dw
         8y9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXiDCuUAE5uHpUAf4Z4N+oJTi3RsZ8fMCyUFtKEmxeWDP7LvA1ysaWU21FJNnX8Q+dqW5oBvQ==@lfdr.de
X-Gm-Message-State: AOJu0YxnHH6R3deKm36IphiwhuIbSQKckHcuk+rrgJEhA+Pol+GG5o3x
	Ld1OKE9RmzZn9yUX3Ub8FwRDFPq/QsTZgvX1LaHrPbpp/l289GLs
X-Google-Smtp-Source: AGHT+IFW2m/KEVrKVyk0PKRcFBRtz9GzA9yx5vwM4O85bybJ92kKsZQlLY+K1ghAjzOw093n51A4GA==
X-Received: by 2002:a05:600c:19c6:b0:42c:de34:34be with SMTP id 5b1f17b1804b1-4318413211emr25513895e9.3.1729692079693;
        Wed, 23 Oct 2024 07:01:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c94:b0:431:4fa0:2e0a with SMTP id
 5b1f17b1804b1-431584eb95els10861555e9.1.-pod-prod-09-eu; Wed, 23 Oct 2024
 07:01:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVckr7FwuNXlTquAvizS7cV+Mdh7DG4aEGVfa8I8qEkngzGvy4etZmPeGKVcUJyXw+v0yqvwCkf68Y=@googlegroups.com
X-Received: by 2002:a05:600c:45cb:b0:431:44aa:ee2e with SMTP id 5b1f17b1804b1-4318413209emr20625785e9.4.1729692077152;
        Wed, 23 Oct 2024 07:01:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729692077; cv=none;
        d=google.com; s=arc-20240605;
        b=dSLcPKOapiX/TD6ngJTMa9JBu9UjDOunppPcRT+P3lzlU8XjkGVI+F7YIq+aZSqK02
         60seAnCg96a4uvlDai1WXjIQfjjGL+ZM5yiV2+BQ4TBhyXjtviMDoH3f65BWjCM+AV6w
         hDUo6iUnw/++5KeyUCp2CWUYEIlODtXp5Idkbt9O0ScRG9TuPELMmkPOiUDP33jjAu93
         ZhWhmV64lwSvA4aylvkU2JG0U9IFChw+0iR0aBI/dFVeVQ/wv7LnS1j/ZHi52MsN8i3C
         m/u6N9PaVueQ2X1L1tBrWli1SjXGsnLcsMVrIqengD9G2aDNo1WOLOCMcpaQDBMvDnzL
         dfPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bfi+jVS09oVwJMiUCNMkt7OYW0ltkQ/uQFM4w2BHFdo=;
        fh=TgaZE86EdYdxUNnenX0P9WbJJonrhBTjF7kVOrkwFSY=;
        b=ISKkhWIpDdhJsxBfEJHRJzABCpDoWX4bezlMy9gRCTPwRCuz8jzt5C7IHssV82CfIg
         Ft7IhjuOXitxpfV7f94ttFUzlVnnvkWS5TnTSRtkLw57k2Z+AxxYaiA1kYiynntQWubI
         O1lv8HZmjUzlDJFrsd3tOR/iNOlXAKyvpbjxeSNRfG9ouHx8HNl55enHGYjfilM+0F4q
         glDWkSXIpBAYAPz4ZfvdJ/VRpl1I8Jqr2nLXu45RMC37EGCO7Oq3JtTlpG2oeWJfkBAD
         AJJ8AVi5A0HjEFwIzRy5U1EKLoiVTYEU1tT0TNezwc/0gEc9SWr3snaoX/GeJAIAVYbS
         JvTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MiLP+z6W;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4317d030db8si1838755e9.0.2024.10.23.07.01.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2024 07:01:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-4315df7b43fso69553095e9.0
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2024 07:01:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU84DKhZs00G8oG6AySvD0Ad6+eEckEafF3JTK7akrnSgOywXvL4sKXdMW7yaFW/QWPoHQGXz+ixxk=@googlegroups.com
X-Received: by 2002:a05:600c:468a:b0:428:f0c2:ef4a with SMTP id
 5b1f17b1804b1-431841440b5mr24527045e9.13.1729692076156; Wed, 23 Oct 2024
 07:01:16 -0700 (PDT)
MIME-Version: 1.0
References: <20241023132734.62385-1-dominik.karol.piatkowski@protonmail.com>
In-Reply-To: <20241023132734.62385-1-dominik.karol.piatkowski@protonmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 23 Oct 2024 16:01:04 +0200
Message-ID: <CA+fCnZfW_7aFR+q-0=umaP8wYEqDU4im0vE5vkqu74fBbgVvVA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix typo in kasan_poison_new_object documentation
To: =?UTF-8?Q?Dominik_Karol_Pi=C4=85tkowski?= <dominik.karol.piatkowski@protonmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MiLP+z6W;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
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

On Wed, Oct 23, 2024 at 3:28=E2=80=AFPM Dominik Karol Pi=C4=85tkowski
<dominik.karol.piatkowski@protonmail.com> wrote:
>
> Fix presumed copy-paste typo of kasan_poison_new_object documentation
> referring to kasan_unpoison_new_object.
>
> No functional changes.
>
> Fixes: 1ce9a0523938 ("kasan: rename and document kasan_(un)poison_object_=
data")
> Signed-off-by: Dominik Karol Pi=C4=85tkowski <dominik.karol.piatkowski@pr=
otonmail.com>
> ---
>  include/linux/kasan.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 6bbfc8aa42e8..56465af31044 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -153,7 +153,7 @@ static __always_inline void kasan_unpoison_new_object=
(struct kmem_cache *cache,
>
>  void __kasan_poison_new_object(struct kmem_cache *cache, void *object);
>  /**
> - * kasan_unpoison_new_object - Repoison a new slab object.
> + * kasan_poison_new_object - Repoison a new slab object.
>   * @cache: Cache the object belong to.
>   * @object: Pointer to the object.
>   *
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfW_7aFR%2Bq-0%3DumaP8wYEqDU4im0vE5vkqu74fBbgVvVA%40mail.=
gmail.com.
