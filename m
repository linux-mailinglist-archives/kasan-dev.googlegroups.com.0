Return-Path: <kasan-dev+bncBDW2JDUY5AORBXU5ZPDAMGQEPLROCQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 48A72B96DEE
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 18:46:24 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-46da436df64sf16138655e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 09:46:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758645984; cv=pass;
        d=google.com; s=arc-20240605;
        b=dDvhfEYoIbK638MKiuVMMDE3/Cva4BuMqTMJL1vIfJreY3kEGc8s8GYSdsrVHXvdeZ
         FFe0QD5/n49D3FK+eHlqhGniaGagZvtGdxWQiwd3dGPEZsJhfdx+wIsBZ6Ry98X7G5RQ
         IudsFf3uko94MgI6XyUmQcoDv71tHFaRarnrAtygiq9viJKa0xAu1Wbay0sywAgWQDwK
         0B+7mwOTxOFVKai6vRA5TedeLLqp0nxMN8uA1qktmE+KQTQlsW60YytxW15uYo8tgKqA
         fuS3D4RBFI7/FaNWRq/o17J2Fgi8XdD6K8E4cnG/KrAkwIML5/6hsUxj/ffLXCA79fi2
         Ncmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9nEq+BOrvIGv0CPVsaMgDu8sDLxh9Wno6R1Q7BlLTck=;
        fh=Un6+sMg9Wyl69PwM2zwGpk4wT4uby98bQirMBFZkjuQ=;
        b=XnzQfF4W9r45bDyvcgqF19wOOp/F72vwnMEZd2Cjs14n7RcPsUT/xSg26I0SdVrw6H
         LoC2xWvladYwnaXT96WaMAKvsry/tdfRtn/Jx6co2DMrnLjNiHDhOmipJKR0HD6GaQFk
         AOPuSYUHRrTZfElC7Gb1/zYAIQKXEY+UlhJ+HyDqgWL2pUXviUvJpXXQIkh/ZO5zWMma
         YkC0X2J1Zt3wHkq6QADsl/pB9++WsPbqtmYCCD5zC/4ALZ9JS9VAfDiNqkkDzsujEsvf
         m5S9jgUEaJMNgaFs0WIjtn4e9oDjgdsFbweYCJ47XL6ytc8/ToDE9IcGewmHokO7ykFg
         quHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fWORMpd9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758645983; x=1759250783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9nEq+BOrvIGv0CPVsaMgDu8sDLxh9Wno6R1Q7BlLTck=;
        b=vyH1E2kZBD3a+BJQFfNbrA98ivuhOIeY5xb07ecvjVs0pr4nTkUf4qMXbdgZtEbB5w
         CIfQAMQFL7U2lSg9TO1GVzpyVzlidNALbgtqO0Kt+YO4xiURfyfAlzVZnGT1U6bUCgEt
         QheusQrbUBfFM4OdlMv8zEWrYZDXU3XIJ9hv/c0SRr1SeaPdEH2+wUKl7INuYFRmedjC
         S8Qh+Z3MhCrAaeBTOoMISUgmtr00nQZKCgjHfkygTkoRsfZ4lU7LF0i/L7ngYFueh+jF
         dm0yjf0fWpow5wb/uKkTc8wtBzrNhifkb4OWyTAUOSBDZiWgGyTOMwADB3u9k3HQAfIE
         prUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758645983; x=1759250783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9nEq+BOrvIGv0CPVsaMgDu8sDLxh9Wno6R1Q7BlLTck=;
        b=OQPG28XyuRwSkId/d220FIa6IDqMCJjkwn/7RU+O8njx2bKo/qcjwSf+hn/fMSHp8F
         5cShe2o7L9IFyIa6UVqCJZptBYKOfJ9ieniJdobndqAhPhH0ncSZzFpym02yQL4wpxpR
         8mbZd1/pVTCt3loSc8KWOUY2ZkI9/wxoqZOLVRLuDL4mav/vWKzC+5CG9tHL5yStzxvx
         eV9aAVFhFe8ZPxu+/rGaC5dRcmgVj17fTc3RAn6Da3lfBq4c2EZYJ3k5O/9tuIj02fm0
         mSMytE4gUN3ZkcCRXV6P6G4uySXMNZf0ZQYMxuD9h0hVOiIS1pNrmF+PrM8601zqZMCK
         3+dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758645983; x=1759250783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9nEq+BOrvIGv0CPVsaMgDu8sDLxh9Wno6R1Q7BlLTck=;
        b=gzzLKRV6cUsgj6JiQfTrY48fI3GopfJXyKN16J6gBiucDImLr/x5vDYazr8MBwkHzk
         WpfT+pvZN/CjmxUK4sONLi9rqXtRDIA6h/4TX7BfutUdZx/FdNcAMJUAvHrFOReQ4EIL
         kCXL5ZLQ6d9RyD0iq7fqFw+R6KEm4ylo2DGC75NOaDJ4f3vNSLeNqBz41snOFCK3WSwt
         gUwDkRYqy5XquuBQo/Ym/yXHDaRpH3BF9SRRwz5zxm4Cxk16zWDe8lTlwXPyGKfM8HXz
         G/2/Q6wLv7/9MCLyBa3wmvCTJMeqVuu20C0JXhhU1GU57H6ZbHzoqEl5yT0ad+6sJ41M
         V/nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFVlQDNJy1vuo601fn5tbLoGsbECr7b0ptky3vJrtllZGtKnwowgCSEK0BISKplMoRKXO4Qg==@lfdr.de
X-Gm-Message-State: AOJu0YwAnHib3CoclQenWg59BxdNgiMDgDTvQ2Il3xiRV3MczH6m3yBK
	PCmvfAz73vxmlwYNiXBaz/QOVFH7rmmvKEMnICkV21Z88okYGLeWDDxt
X-Google-Smtp-Source: AGHT+IHLpmaAd12SwZUWvvOB/O0w5OuhlbXf/e8eLjJ3y09/OeVCK824nbmU9j2BAjJtmi4Ey/205g==
X-Received: by 2002:a05:600c:4683:b0:461:8bdb:e8 with SMTP id 5b1f17b1804b1-46e1dabfaf3mr36480765e9.30.1758645983224;
        Tue, 23 Sep 2025 09:46:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd57JpO7/8WtW/vI0wgAlmjVki8eE5ZxGZVZpSltRH6aPg==
Received: by 2002:a05:600c:8812:b0:46e:1d97:94c3 with SMTP id
 5b1f17b1804b1-46e1d97965als3805305e9.1.-pod-prod-09-eu; Tue, 23 Sep 2025
 09:46:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAdmkQTGkeg0MYXw8GTNZjmWk7hYB4HIZ6Z6J4F/0XEAmpclxZBow4gB9yEkVdWiuPACt/z/b3+Ec=@googlegroups.com
X-Received: by 2002:a05:600c:4f52:b0:46d:996b:8291 with SMTP id 5b1f17b1804b1-46e1dac8b19mr33809775e9.34.1758645980480;
        Tue, 23 Sep 2025 09:46:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758645980; cv=none;
        d=google.com; s=arc-20240605;
        b=TKJuOxuFmILqiqyXCLsYxucHUeq2Su0zVa9EcQ1mqx59Y+SAUnt7zn2zznbxr/GYbi
         7fuz5FXvVQAWf0GRpti9Nr9vesOrDYKvqhMzW5TcUwqUrB8LbJORCpeB7nSLBng/SJLw
         ysUuc+RmSnuMPjPjY5SEbv79HxXXx1tvE6vYBAezYtzoErxTo/K3+8bCU8CxfF2a+k2i
         ySd3MiSJCAEur6jeDXzpGGPR2U9dameM/UJYQmzouGy3e+hYGChxUW83OASl2bbtlDCQ
         bU+l/Ris0wr/H8HmbV4tKHe+LEbFZ8hHkgcswZUU9AZDVnd8KZJG0LDNaI+mcFJIkrpf
         LBSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=imzMF9eGcF1IvmXHD33jpPta8P3x9Urk2l5tDJ26VmM=;
        fh=RiZIuh8KSb1q0vFPVBRod9fTxTeoE/UP4HMoIFPUAgE=;
        b=Pk/hXJc5xx2o4NQR0Vr5aNaGFK0Sx7xFcVKjIijvq2mYjJTGxFe1MPAzwy5RemET/4
         MJIGMjviJSUYc3r9xox2kUBrDXU4dBOASf8BvB1B+dJL/aPrHZOWZ/44Plsmx/uWZU0y
         xVoqCqQEF02/sgpjpZms8ZUjRoEaOGrE7W8WPsXL06LFtiSegDt4a8aDpB2oasVl0feY
         Qb5K0wyqnBEiQMHJJco47kvJgEiJPPbJ1lLz6NtAsa+VJ/BnoRXi/Z1X53ymwD2ev6v4
         mmOgSIWFNSVmEu82A26rdzEmYOy35hxNclQBsL+haBeKhU2szfoC+zHX7Gu6nuk+Dlz9
         rfrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fWORMpd9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-40431251d96si75204f8f.7.2025.09.23.09.46.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Sep 2025 09:46:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-46e1e318f58so9251175e9.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Sep 2025 09:46:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW1lXofYTwlom+AnUaUigBN9fqaHMCnPvauxfVkmyyBpW6KYXiACyeUWX3Trqq3F5EYff7KGGqcIzs=@googlegroups.com
X-Gm-Gg: ASbGncsvIVnhBGsX+3A1ywLWSvE4Epg70BYOnuWflslJHxVqlNwPVvT7BWfwK3iG7It
	GbFa6ttTR9Vip3uJidu9hYL7MLMHlEvWagSqhlQgf9AutI62JYhvSAmGoWNfIogoYw5khb4qMN1
	clPSkzdr2e+cztsvmPqBaPfHGpLo4C/c2I/2+kYpB4uAAjO05pymUJ38O5PI+0EY5FvH/676YPy
	GBfOM62ig==
X-Received: by 2002:a05:6000:25c8:b0:3e7:1f63:6e7d with SMTP id
 ffacd0b85a97d-405ccbd6d4cmr3017672f8f.45.1758645979885; Tue, 23 Sep 2025
 09:46:19 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-2-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-2-ethan.w.s.graham@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 23 Sep 2025 18:46:08 +0200
X-Gm-Features: AS18NWC3Zatya8SBoZMxgc3ReWws0f2Kk0nbCOoRpJZnpr-tGokn7pV_jWkKaCg
Message-ID: <CA+fCnZegSdAeLkutKP54BH19Kv+FAaFbW1oOvAgbTZZMsyu0sg@mail.gmail.com>
Subject: Re: [PATCH v2 01/10] mm/kasan: implement kasan_poison_range
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fWORMpd9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
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
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> ---
> PR v1:
> - Enforce KASAN_GRANULE_SIZE alignment for the end of the range in
>   kasan_poison_range(), and return -EINVAL when this isn't respected.
> ---
> ---
>  include/linux/kasan.h | 11 +++++++++++
>  mm/kasan/shadow.c     | 34 ++++++++++++++++++++++++++++++++++
>  2 files changed, 45 insertions(+)
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
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d2c70cd2afb1..7faed02264f2 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -147,6 +147,40 @@ void kasan_poison(const void *addr, size_t size, u8 =
value, bool init)
>  }
>  EXPORT_SYMBOL_GPL(kasan_poison);
>
> +int kasan_poison_range(const void *addr, size_t size)

This should go into common.c, otherwise this won't be built with the
HW_TAGS mode enabled.

Also, you need a wrapper with a kasan_enabled() check; see how
kasan_unpoison_range() is defined.

> +{
> +       uintptr_t start_addr =3D (uintptr_t)addr;
> +       uintptr_t head_granule_start;
> +       uintptr_t poison_body_start;
> +       uintptr_t poison_body_end;
> +       size_t head_prefix_size;
> +       uintptr_t end_addr;
> +
> +       if ((start_addr + size) % KASAN_GRANULE_SIZE)
> +               return -EINVAL;

Other similar KASAN functions do a WARN_ON(bad alignment). I think
printing a warning is fair for this to force the caller to enforce
proper alignment.

> +
> +       end_addr =3D ALIGN_DOWN(start_addr + size, KASAN_GRANULE_SIZE);

I don't think we need to ALIGN_DOWN(): we already checked that
(start_addr + size) % KASAN_GRANULE_SIZE =3D=3D 0.

> +       if (start_addr >=3D end_addr)
> +               return -EINVAL;

Can also do a WARN_ON().

> +
> +       head_granule_start =3D ALIGN_DOWN(start_addr, KASAN_GRANULE_SIZE)=
;
> +       head_prefix_size =3D start_addr - head_granule_start;
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) && head_prefix_size > 0)
> +               kasan_poison_last_granule((void *)head_granule_start,
> +                                         head_prefix_size);

Let's rename kasan_poison_last_granule() to kasan_poison_granule()
then. Here the granule being poisoned is not the last one.


> +
> +       poison_body_start =3D ALIGN(start_addr, KASAN_GRANULE_SIZE);
> +       poison_body_end =3D ALIGN_DOWN(end_addr, KASAN_GRANULE_SIZE);

end_addr is already aligned.


> +
> +       if (poison_body_start < poison_body_end)
> +               kasan_poison((void *)poison_body_start,
> +                            poison_body_end - poison_body_start,
> +                            KASAN_SLAB_REDZONE, false);
> +       return 0;
> +}
> +EXPORT_SYMBOL(kasan_poison_range);
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void kasan_poison_last_granule(const void *addr, size_t size)
>  {
> --
> 2.51.0.470.ga7dc726c21-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZegSdAeLkutKP54BH19Kv%2BFAaFbW1oOvAgbTZZMsyu0sg%40mail.gmail.com.
