Return-Path: <kasan-dev+bncBAABBNPVWK4AMGQEUPRQUIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id AFF5D99C008
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 08:31:18 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-45f2775733bsf106514331cf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 23:31:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728887477; cv=pass;
        d=google.com; s=arc-20240605;
        b=TgKAcQJKJ3n3TgLLr1/aOP7AHLK+AJNFvBD9PLx4VjQDPh5UU3QCYVhmuXSx3mvbGy
         UlOi5fVKirT3sxSlF1mHFykdvc8c5PHXQGOiVTW4XT4FR8GBFftcATzfWN5IkE72ASh1
         rdJ5ciDnhDyMScXzoPdmQ/rG7b89sxkOhwEhLMpf+QvaI/Dwj9zQeODlVt2vDm/wk8yX
         JWif42NOt6INdrR20/poM+IJG5Q/3mQefIQ2b+MZ69WPIS+0MqAa+CEi7rFTI5BbI4M5
         UMj6kfnJBG43WEQsDuUyZeZ2/8UyVzx+QObRexw74Nlfv7LmoeFfsX+PWAss+aXHU2zc
         vHCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Njk6kUVyHlSrjComzxqU0PDX+APsFgAC7DD9+sTBB/k=;
        fh=Ow3R4Nb+eGB5S09JKQWhuXlw98NIDo99PMt75RXwM38=;
        b=MD5qMXSWgICMlskt8ZNPOWeAl50pI1Z+RKF2PIsCkVkmFqmMviVCQiIySmHlN37u/q
         iO2Lhh5Gsq0jvgNDD/UzfEAGOdhlPsIbb89sbx4sGhhXo2Y/XntrTW+HxGc1QufoytdA
         88GmKEqCSGBFRTaUMemu4smQbuQIh1G5poH5y+Exf8iP9gp422dzHc6vP8YgZTTn9FJu
         Pn+GVHCtz042F1veBiuQLO3z2sD0DHlqoOGR7dx4ZSZ/TRQXI8xwbesP/ay3Lr/uifNA
         iSyLuNEgJUABlYfbA9ZGUuJPwuGJPPlWpqdsfm2sJL0Qpn2D63TEbdr0SSN3uYzV1Fs8
         WNOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HuQhmyUs;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728887477; x=1729492277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Njk6kUVyHlSrjComzxqU0PDX+APsFgAC7DD9+sTBB/k=;
        b=ARZVtMciWKlJ4xnEtsqw05mOSS86UGvjCBVN7+k3HkmSvKAvT+YVkgc9nXbKlGBtef
         AHX6bW1DOR6UC4hwo7v5i+vhWKcKdz35lAiRWhgmLiNivciZwiJwqXq3s1OAr96OWLZJ
         5Qb9K+tGp/fSgPF46RD2a18e6DpxFFnqMoL2QKc3/9/zmiHCSPONNvMCIcFmLcEBrbwt
         rlUObLn1nE098QdUNvkv1q4oZXC0f2SSrzRKXHBliOTHOzRikKzQs6J4Dxcn4Zvp1veq
         UHlMfXCHrR/UpywcUe2EZznfuAmb4563rAMDpmXuDgDuFEXU36F0mXD2QGiG41v6fgTC
         xwUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728887477; x=1729492277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Njk6kUVyHlSrjComzxqU0PDX+APsFgAC7DD9+sTBB/k=;
        b=k7TjIlpsYSvYqfX50WKzA+w838u5dgsByUoNBHXbME6APZ/f1OKtnmgTnwnBqL9HHt
         Qjc4s36lGnWCyaswykBWHIwQtgXFmRoD6ykKh5y3vd3Sif+tMtis0H47jPOjzCSDLhet
         63flMuLRpot7qyiAMHK8O/Jif5vuJW3bu+jdCuQI92+mvtTMZBZ6cTtQ5NTnP5Zl9ysI
         fp2zYhNalykj7pBkufF3cT67Nx6LRKbuR7XxNLsP9HhuIzGnbr1LQOpvhPAoGoxEmcrh
         3l9LWTvztj3UTWlAtRboCQG3CwtIDVpb7hdFjkRv3TTPlSH0V83OAxRDhjaFOojGZfGV
         ATug==
X-Forwarded-Encrypted: i=2; AJvYcCXVrr1H3I3mCHynnwYzcuEHn2iiX6u7a7uus7Qj1d1IDIJQUXSlih6IIQJn8JwKukimwoFz1g==@lfdr.de
X-Gm-Message-State: AOJu0Ywkp3eoyKv3FbQ24Ub4TWTqXmxpSGYqqQuJUHdnxq5+RfIAuK5b
	telcVRiliMII6HOBlNBI83ukuTYbA2ZbqVNAMe5bZPaZ+8kwsqBG
X-Google-Smtp-Source: AGHT+IEgSwmLYjdKIH6EALvKry5UA3xO9dvCAso8BFLz3SdqcWLhVttXRsyiGZmpecFmGE8gtHBcvw==
X-Received: by 2002:a05:622a:4e04:b0:460:62c0:6077 with SMTP id d75a77b69052e-46062c0610amr60936741cf.4.1728887477248;
        Sun, 13 Oct 2024 23:31:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5755:0:b0:447:f206:4e7c with SMTP id d75a77b69052e-4603fd6ba83ls64416311cf.2.-pod-prod-07-us;
 Sun, 13 Oct 2024 23:31:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtd1ZCDLD1EzEdqNkNrk/51+QwiSt5f7P0YCAAE3qOgyCueulHQGrWl651pfj0VqIsTRVzyno2yTo=@googlegroups.com
X-Received: by 2002:a05:622a:4083:b0:45d:93dc:bda7 with SMTP id d75a77b69052e-4604bc49808mr172516881cf.54.1728887476237;
        Sun, 13 Oct 2024 23:31:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728887476; cv=none;
        d=google.com; s=arc-20240605;
        b=klmSAUeW6qYA+syEt871BpR3yJP06Wj/VM5zdlXYHwaXtgICvnU87JJ9nsIkcXcJOP
         A1m7Dd/7U/LTWmyZb94ocrzwCzOi3FaWh+oRyEenNhYNSl7TNrYn/f+VUbYwaCBllG6l
         W8Mjwcr1FNSvG1A7DD43NkEt3Dz5GfmanAa5I7kRkOm6q3tbU3kn/Kfx2hFlAS/EUENx
         o9yFLXXRPaP1W5zZIsXHud4P+mP5IoEyXhie5guQez+gyXLihGpbDz5Ez0lyaMP7TV9n
         si5xQC0lOXb8GLVUL0Dca1mA+qIq7KiQ9nCZD5kPeiYFrBD8uH7DMYkTm2HwKdoUbS2D
         GIFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SQmEFW7STiOc3KKW8fprzn3mBCo6X6T822so98r9IJ0=;
        fh=hiRm+r6m9vk2vRh3j3qUe/8G/fGTd3olxL2K7GS7mfY=;
        b=Nfe6U0B/fH43D+5qu8HNQo/Cm4fU3T75vtIV2eOYwpLl02JneLFWQ1lg71GuCMGMh/
         dxuOLmJT9D+W8sVh4ED6Kb9l3LQdLJ7g9+1NN4Jqvkj6xMdcT4D2aAcuzr7aru5QzRfU
         G4CIIqT6MAoPEK1FUB7tS9fObFyjqhg3v+hXDNfj60SRQGvhLgEl3vdCy/mHgUy3dO2+
         HXNz1YSdw7fQeS2b9bzwB2rNdXjKp9tFq3XIllwhnpCm1D4QT++qfys3Gd1sRiov09Y8
         UBvx1W4Y33znW9fxMeXyQp58CqxS7Mr6Rxd7bDk2IpltOEQ13KW3rG4KM803IWklx1LV
         AW0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HuQhmyUs;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4604be1effdsi2954371cf.3.2024.10.13.23.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 23:31:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 634535C5A4C
	for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 06:31:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 72F0BC4CEC3
	for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 06:31:15 +0000 (UTC)
Received: by mail-lj1-f179.google.com with SMTP id 38308e7fff4ca-2fb4af0b6beso6733861fa.3
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 23:31:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVMGHiCx+y0mJdM6e06Won2VzbO/wZQSjkmhnNR7SSJ/yQPyryKJxkTHaMNKbTFPn0H/LZB64K2cvs=@googlegroups.com
X-Received: by 2002:a05:6512:1598:b0:530:b773:b4ce with SMTP id
 2adb3069b0e04-539e551a25emr2964252e87.33.1728887473738; Sun, 13 Oct 2024
 23:31:13 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-3-maobibo@loongson.cn>
In-Reply-To: <20241014035855.1119220-3-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2024 14:31:02 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c=SnPhJTOyKkQ@mail.gmail.com>
Message-ID: <CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c=SnPhJTOyKkQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] LoongArch: Add barrier between set_pte and memory access
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HuQhmyUs;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Bibo,

On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> It is possible to return a spurious fault if memory is accessed
> right after the pte is set. For user address space, pte is set
> in kernel space and memory is accessed in user space, there is
> long time for synchronization, no barrier needed. However for
> kernel address space, it is possible that memory is accessed
> right after the pte is set.
>
> Here flush_cache_vmap/flush_cache_vmap_early is used for
> synchronization.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
>  1 file changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarch/inc=
lude/asm/cacheflush.h
> index f8754d08a31a..53be231319ef 100644
> --- a/arch/loongarch/include/asm/cacheflush.h
> +++ b/arch/loongarch/include/asm/cacheflush.h
> @@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long start, un=
signed long end);
>  #define flush_cache_dup_mm(mm)                         do { } while (0)
>  #define flush_cache_range(vma, start, end)             do { } while (0)
>  #define flush_cache_page(vma, vmaddr, pfn)             do { } while (0)
> -#define flush_cache_vmap(start, end)                   do { } while (0)
>  #define flush_cache_vunmap(start, end)                 do { } while (0)
>  #define flush_icache_user_page(vma, page, addr, len)   do { } while (0)
>  #define flush_dcache_mmap_lock(mapping)                        do { } wh=
ile (0)
>  #define flush_dcache_mmap_unlock(mapping)              do { } while (0)
>
> +/*
> + * It is possible for a kernel virtual mapping access to return a spurio=
us
> + * fault if it's accessed right after the pte is set. The page fault han=
dler
> + * does not expect this type of fault. flush_cache_vmap is not exactly t=
he
> + * right place to put this, but it seems to work well enough.
> + */
> +static inline void flush_cache_vmap(unsigned long start, unsigned long e=
nd)
> +{
> +       smp_mb();
> +}
> +#define flush_cache_vmap flush_cache_vmap
> +#define flush_cache_vmap_early flush_cache_vmap
From the history of flush_cache_vmap_early(), It seems only archs with
"virtual cache" (VIVT or VIPT) need this API, so LoongArch can be a
no-op here.

And I still think flush_cache_vunmap() should be a smp_mb(). A
smp_mb() in flush_cache_vmap() prevents subsequent accesses be
reordered before pte_set(), and a smp_mb() in flush_cache_vunmap()
prevents preceding accesses be reordered after pte_clear(). This
potential problem may not be seen from experiment, but it is needed in
theory.

Huacai

> +
>  #define cache_op(op, addr)                                             \
>         __asm__ __volatile__(                                           \
>         "       cacop   %0, %1                                  \n"     \
> --
> 2.39.3
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c%3DSnPhJTOyKkQ%40mail.gmai=
l.com.
