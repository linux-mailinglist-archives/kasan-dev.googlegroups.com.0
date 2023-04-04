Return-Path: <kasan-dev+bncBDW2JDUY5AORBL6AWKQQMGQELFJHEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id A6EB86D6FEC
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Apr 2023 00:09:52 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id g34-20020ab059a5000000b0068fb77b4fccsf14741464uad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 15:09:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680646191; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQMm6W8vu9YE1iUuPcdWUu/RSfg51sY2SeYlAmJfAqyQ1q6K25IAr1qEz7FPi5DRFl
         r83qA8pz4RoubTO1ElhfnkF6vi0urLHHo+/nrPrTsG3i/YMObamjy80yvks1l5O0AWQN
         StfEV1LT4SB7iyHNko8+fT31UUsTwyf9EjSg3pUIXHmqu/QoWo/HPC/FMRMCshOyFkbW
         OzYm0VnKDB9h2u8/hBj1SUJLiiR9f7ZIP6jt3506+JSAZtEW54wdnb+uAT7uX+A2Zu1P
         pb0B9dRe0x5vIzMAsaBhVnu7TXnHDKKgwSYnY10OFYWPVXrALL1hPEzvjOCNlftrabs5
         9vzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/x3Ou7cm7L3V1tr2L9bEUtcIIGBoDeuGuKVjMMEqGTA=;
        b=0U+o5TRniFg0fW4/gNSCOH7OhhR3jDjnw8WcegOGvDDO94fWkXTRobcbtLguSK33TK
         qjpTaahRp9R4YuO0y7ZjtTaCce4LmJSDepfDnnCfOT0gDda2f/guy2roGQkTmBOo8Spo
         vuAYcBhSt2FDAV/wocpLin+W7gOVJ7mcQtTdUWiYxOhZph03s55ZWJi/xAdwwKA6j4YI
         7YO5b+Zy72B4J5l6rPfQC+HTmDHW/d66KiLkCRx5aRPLRgnY13VtuFon9/C4p9WcTSlH
         VchYM4VQVamM2lL1MHNSh24/uP1N1GJkbITRlJxdavE9xN/4F8YfqNfFghOKLT1e3eSB
         XfUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gUnEta5Y;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680646191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/x3Ou7cm7L3V1tr2L9bEUtcIIGBoDeuGuKVjMMEqGTA=;
        b=jpikVAikLd0zOAWThFbmbuWsZHFjyQJyrvusgcf1fvuwtcNQgPHknbU3DN3frRWo+9
         XxKOWdyKO4wfKYRUx+mEZVWDZAdhLeURZi7k/lYkn1unpeDJTn2C5dwfwx5lEQGe5D5I
         lthMfhhErLKI++7gEWFCf2nIu2t9R4ZdS9v7KRtgsZg1xf2ShXKoWxT9UKpKpuaDCh/h
         HxunEtsIIUz5Az6h1rqJXYMno/Fphi7XJP4wdggC/koRftMbaIuiqTuGAtBR3MiLAVSX
         Wi2ve4Nr8dJYvdrZlc4zwXq4BmdUUYwokTRk6bLczM86CZwI/HLMsLNuNlneRQIkxj0U
         AZqA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680646191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/x3Ou7cm7L3V1tr2L9bEUtcIIGBoDeuGuKVjMMEqGTA=;
        b=qT6CU80g5BVgJbme242oVJK8kyHQ4nOxoga9eyyV+NeQybH1BlSJn6MNOqvn4+ZRYU
         vmNAMXPFzDsbBgoMczkhVB6J1DielE1IBSbvl4C0upeX0gj/UJHPptEhAQQc0fmBVZZn
         tWrV7+SjJXKazr+yNC/GqVJ3MTR/Au/aB7CCtMbPoYOgwcUT16C+C4lZ/7wmO/V+VLnH
         3tVfxRTwrY5auQ5VNTjBecdjoL+knyUkh4z//NBgsZHQ2Ea8JpqrnmIQIvyrCWszlbRs
         R6DYvo379Mt3isVv+kQUJoUafJOsK+DiCWXSUkRKv6nURGid2aVvhpcj8A9iv08hwSM+
         /lsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680646191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/x3Ou7cm7L3V1tr2L9bEUtcIIGBoDeuGuKVjMMEqGTA=;
        b=WBXmNjSNJ19DETdWYSOg/vMA1wBrY1Uvd4Hv28yn//3rawsj4hEebqcMA5I9S2RKrU
         t+W3nUXGiu0L9APy/sy6XPxzlSSwPjvMF1PQQRHVLWTRWKvO21UrE/ICkyvtHs2yWwXH
         TNUtBswEmNEEtDWVYnwvPMOb4Y8Q/l3oyBl1ewxYmD9xF/lFUFFdw704xDCOR7X8I4jI
         CLHtQpFG5T/mNvLQg8r6AJZ3kyGPPKRsUIdKhyk4nqJZsvjCLf1YRD0K29gUO2VLivtG
         B4gAzEpBT4HdLnSXReQe+UvOEs/4e+TKvSXOThMyqbnV3KtJxLP6zqqseQQyW8RWJO+G
         N+Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dyJz968Cbc3qhyjtAzK+yMB3+iY73HgSzLpnubuFSVfJ21F6o+
	hwPb4DXfRzamsQMaWonzA4A=
X-Google-Smtp-Source: AKy350YZjxK5gW8/T4rMU3XBAnZJQQGhDTqqtpos9yIEgm1Ob8i1xrHAu1A3ysKm4sh8nJk0suDn8w==
X-Received: by 2002:a1f:acc9:0:b0:433:7ae0:6045 with SMTP id v192-20020a1facc9000000b004337ae06045mr3502695vke.0.1680646191397;
        Tue, 04 Apr 2023 15:09:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a8d6:0:b0:431:f7a2:156e with SMTP id r205-20020a1fa8d6000000b00431f7a2156els2023685vke.10.-pod-prod-gmail;
 Tue, 04 Apr 2023 15:09:50 -0700 (PDT)
X-Received: by 2002:a05:6122:c9e:b0:436:f1e:6097 with SMTP id ba30-20020a0561220c9e00b004360f1e6097mr2690740vkb.7.1680646190601;
        Tue, 04 Apr 2023 15:09:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680646190; cv=none;
        d=google.com; s=arc-20160816;
        b=SBxf5NIMt+dK4ROtHGw7deEVhZK6UHefPXr6L65HFQSlm9mkWK+2LmN4dEu6CPeA8u
         1c/97ACBIdq07Axq8ybNAhmIkeTCmyp8+X9nGT5DmXxFKroNU1jhWh2el2i7G/KBvnNh
         RGV/NzIEYoGDz+snxP0hOrwaLX8yuoidQEHiRQTrhcs+U20jGl2HyyW5t1+hSt9JBdwU
         5IvdTzUywKur2v6kAGHEaQKVbbHqnEpXRV2AI5ssrJS+qbeL5EwpYXAo6+3juCN4fwI/
         HsH3FhFhGQ0rOtFGDiDm9l8bS0SNLOujKdGJTfyV+nBiTGLRCfPQg71DIXzyR9MTiAZN
         9eJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FhW41Lz+Mez52y9+7Sqb35hmOmVdAZ3fg2uw11nAPAE=;
        b=wbVcLOs9lVi6blbUuANNI7620s9LoErVokp1r5U7/lBGLfopUX36BtcKTXA5R+eoTn
         VD1gkH/UX2sr976lv0dOkO78YYjuvIgy/+jq+L1+vkAFP3vKV9z63arJSAYvKk8c8WNT
         bYbj/LNDxKn0mmPpMIycotRi37lAPCqJ1tlasLsQGkNUiS+ulCVar1Lcnp1xOCgL8QgH
         ELbLK6YAf9qV1VfQEHNeJx32MpNQ/qvnG4fjGfsPob2e0Jt4iU3Sj0xOReTW5Sork55J
         aWUqBJG4UOs05ESErwIfAUzaYjhf/Vk1PRfSXhZRe7wRAUSTRy9LRSFjbIrlhQbb7poJ
         lVxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gUnEta5Y;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id e29-20020ac5c15d000000b0043c402f9047si699046vkk.3.2023.04.04.15.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Apr 2023 15:09:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id h12-20020a17090aea8c00b0023d1311fab3so35410701pjz.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Apr 2023 15:09:50 -0700 (PDT)
X-Received: by 2002:a17:90b:e09:b0:240:228:95bd with SMTP id
 ge9-20020a17090b0e0900b00240022895bdmr1533929pjb.5.1680646189645; Tue, 04 Apr
 2023 15:09:49 -0700 (PDT)
MIME-Version: 1.0
References: <20230404084308.813-1-zhangqing@loongson.cn>
In-Reply-To: <20230404084308.813-1-zhangqing@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 5 Apr 2023 00:09:38 +0200
Message-ID: <CA+fCnZentBDXuyyrZFzPLpt8Vdfo7YyAyxbgb506LFrR+v-D9Q@mail.gmail.com>
Subject: Re: [PATCH v2 4/6] kasan: Add __HAVE_ARCH_SHADOW_MAP to support arch
 specific mapping
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet <corbet@lwn.net>, 
	Huacai Chen <chenhuacai@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>, 
	Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=gUnEta5Y;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Apr 4, 2023 at 10:43=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn> =
wrote:
>
> Like the LoongArch, which has many holes between different segments
> and valid address space(256T available) is insufficient to map all
> these segments to kasan shadow memory with the common formula provided
> by kasan core, We need architecture specific mapping formula,different
> segments are mapped individually, and only limited length of space of
> that specific segment is mapped to shadow.
>
> Therefore, when the incoming address is converted to a shadow, we need
> to add a condition to determine whether it is valid.
>
> Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
> ---
>  include/linux/kasan.h | 2 ++
>  mm/kasan/kasan.h      | 6 ++++++
>  2 files changed, 8 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f7ef70661ce2..3b91b941873d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -54,11 +54,13 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D]=
;
>  int kasan_populate_early_shadow(const void *shadow_start,
>                                 const void *shadow_end);
>
> +#ifndef __HAVE_ARCH_SHADOW_MAP
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
>         return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>                 + KASAN_SHADOW_OFFSET;
>  }
> +#endif
>
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index a61eeee3095a..033335c13b25 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -291,16 +291,22 @@ struct kasan_stack_ring {
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
> +#ifndef __HAVE_ARCH_SHADOW_MAP
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>         return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET=
)
>                 << KASAN_SHADOW_SCALE_SHIFT);
>  }
> +#endif
>
>  static __always_inline bool addr_has_metadata(const void *addr)
>  {
> +#ifdef __HAVE_ARCH_SHADOW_MAP
> +       return (kasan_mem_to_shadow((void *)addr) !=3D NULL);
> +#else
>         return (kasan_reset_tag(addr) >=3D
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> +#endif
>  }
>
>  /**
> --
> 2.20.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZentBDXuyyrZFzPLpt8Vdfo7YyAyxbgb506LFrR%2Bv-D9Q%40mail.gm=
ail.com.
