Return-Path: <kasan-dev+bncBDW2JDUY5AORBKNE4DDQMGQEEMZ6TMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EA246BF92D7
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 01:07:22 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-47105bfcf15sf33909925e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Oct 2025 16:07:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761088042; cv=pass;
        d=google.com; s=arc-20240605;
        b=LZUJkE7oeVn5ZSs2Id9vDOJfidm3eo+fSDiLV2FadLlxoJ555RDVqg2kexngJ5vqXD
         cXGcROsX9WpwoQsuN5YiB2Oby+ZncQT3tb5aTB0QEkEFW2QsbA5/bj132Fy1u5T+PNsw
         6vNJBwhwUwdKDCTm+OH7++fD3bFvoS/P15LHDjDH+FU6r/s5Lun7Dl+a4Ek1LyAtPvk9
         BlbjaItLTPTd43+K2UasPYFSWhgHCtd+8npHZvxs0ZrBnyyHBEUro9EYQ7sOc1irtWYf
         S4uZ5tAfNXBh1OfJYXjKeMtEEfD1sDmyRLD9EbFbmc9vcPj20Kv8mtA2bN49XycDhk/C
         7DTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dyHfbGCaW8NNBj/KFjJGZwgjgZBpsrcNDUOzO89yv1M=;
        fh=jrgHSBm8a+ESuf/98+yTdtx91QQf/+8nKOmgcBlLtv4=;
        b=aEo3pA588+PNMkKlkUZ9mCWI7VpbtubY1KL5i4SygwkGEkXeMzvoDVEJ7590Qm61v+
         +RaagM923tQawwfQwCq8TB7lgipKuYOaGfhc7qJx0jOXUExWnTe03a48pgxOpOIbtEvv
         zrmqR/chE8O1czK8sgEtcCDqGKzNJ2LL4InRaVkVuroCIZL8PRcuiYEpiLBIejKJoINB
         CoD0z8rveh+OhRUmRgM+m6Lhy3ZPmm9plwAN1ZcoLobonbNBPwnY2AriY95OAWQZpCBE
         AuJmRDhwHlSYIqzXS0ufnWE/0W+5QPpgILgERYaO5r/e4hvir/5JjpiiGA2YfBZa6053
         IhEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kJjXR2mn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761088042; x=1761692842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dyHfbGCaW8NNBj/KFjJGZwgjgZBpsrcNDUOzO89yv1M=;
        b=hnKfSqlUl6P4JS+9jMPiwMYNf4cXvT/sZR8QlxMxXJY6Q5O8jRCnWpM9lWjyaFJEg+
         ydTDU/jVG+CJ2vJpLskc2TT1x8vgb0PvYnzoDwfqWil0dgeuXPK3MOfDZiWUuiq1vnFK
         WrT5OhrD/5NiMBmahz0QS0wDdEUc5AxvbQAaGNYVuQt/fc2YyQmEHIQnNfbrsFECvTX+
         1n2pScjNZdgZF78pfKDFVRNg0ZZtGVS8QGww7iKpGdm5ccze8ZgdDGulfaWo1STrcwPo
         yjxX+jpl2HRa7lUsrDPkPz6IZhBXbupWOIuTtQO+Li3qGUG/6Jqsi9yWEExJtyAc/usN
         hviw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761088042; x=1761692842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dyHfbGCaW8NNBj/KFjJGZwgjgZBpsrcNDUOzO89yv1M=;
        b=WFQoapXGn7h08XC3lkpdCbTAxt714wHvJyRvkEPsO3pxI61qKO+my+gfxrOlme5Cxo
         55vV5A49FLdXqjC9VeDbdT1CATy0eIwti1lzh6gsZx2vPIrNLORf450PBzEO/DzeIjN8
         9KwscOCg9lVGhypMk01w3cwvVrcbB1LRIELcvCqxF+J9xvUWi6jdOA9InAZ6echT7+GI
         zirMgQmf+lKlYXTigLhTZnn6EDniJoafQhGARqlMTma3Ng2hpaRan2kO2ZrHIIAGpaYa
         U5LM4W0sM04A7uQnQQilFTxjklwlLeD3CGH4C4gfvXar0Pll5iWWmWgCeYhMkv9vBSlj
         w7EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761088042; x=1761692842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dyHfbGCaW8NNBj/KFjJGZwgjgZBpsrcNDUOzO89yv1M=;
        b=pdST9KAL1GxyfG2+GiGOSxYMcLog6VJiO9umSRviI5OOM9mqT+TPbQHuETKFxpCfq5
         jvuoFgAJXC1ikzFFym+4SJZlR5N4y+vhxIgU38IQjoLld06gHI3CWYGjndTi3kqyWkiC
         s1/vyBDfKb3xNC7Zt+dwDW9gY7m1tAi01pUZLRzhunKBa7/uPW7aVjFomqbTpPHR/5Yv
         GgJAKk5CyGch/f31P+pS689kO4a2REHcq/jeTar4jZ7jSQiVBKZqm9bCK6EMwaThqWKy
         J0KXJlIsJCqddT651dljShfjBafoQ01PBeAkH+hboFhkEejUIkSQ/xslccEW1SVUidhB
         yQdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUEkK5spBsx0xz2Qpg2CjoJxK6Eu/xNJe8p8kb1tPrX7LE9j9U4EQu4jQp0IiKdpjBY/MBgg==@lfdr.de
X-Gm-Message-State: AOJu0Yy3aLepniBmf7PDX5uyQ/aVEcm7OEXDd0y7JcMHVYhQnpjNRbAR
	juHcjTmY6Mz+7QRTv5OBDGXjoAch85yHzVxRLSW94p9Rm4yZ9Pyjv9sQ
X-Google-Smtp-Source: AGHT+IG7845Q6DUwpt2h5J9leq52ogQdDG7xyChF0ZtZCarAFXlhGAM6fotqDmsSbdKOxkWCxw3Y6g==
X-Received: by 2002:a05:600c:34d0:b0:471:1717:409 with SMTP id 5b1f17b1804b1-471179071b4mr119909615e9.23.1761088041898;
        Tue, 21 Oct 2025 16:07:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5Jo4c7jAsszmU5uiLZofxZxtD3FSltLi2lWghMlNInlw=="
Received: by 2002:a5d:4ec1:0:b0:428:52bf:bc00 with SMTP id ffacd0b85a97d-42852bfbc39ls241658f8f.2.-pod-prod-06-eu;
 Tue, 21 Oct 2025 16:07:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbjR//omXbv+4UbLToJUw/ZHvKh3xpIahrXOT0N/Rr5upbosUyTxuZLcyeqtB/qrekSg/XEl06qF4=@googlegroups.com
X-Received: by 2002:a05:6000:290d:b0:427:9d7:86f9 with SMTP id ffacd0b85a97d-42709d787bemr11755011f8f.47.1761088038990;
        Tue, 21 Oct 2025 16:07:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761088038; cv=none;
        d=google.com; s=arc-20240605;
        b=c7VBTHd90/ifvg3wnX3D8sg8Pd69ZV/G80AkJh8wztX+wyA9OUUt27mbzmPk3Wxl1Q
         xAnHhKMFnSFnKiMNQSRanWI1rZFMooIuRWx4q+oSddnBMKbCosgLreQtlG7w48RGK+KA
         rjb+dtu8vKH/Vehucl6TRNbMSlaO3eKUP9eNgr4Z/+0JOZIg3Rd8irT1wU8aRdXOIyfW
         vpXJRnWsXzwXJ8AR/B2iMV1RApxlxjMwa94N9TqK/Jeb+71jhEaTYzxGslR+Rq8eMFXK
         HCAhA3H9xiuryCmo1IxxsxAOjGu9sukNWIc9Nmcwow/mPyX0CnM0t5thdK5TDtEr5hYu
         BPcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TUs/wuT0kfUsxmbimw3WNKm4HpGep0rE6iJ3jKWwffE=;
        fh=vmFZ5ca5RWEsADKdE3oFtwGT6YAsfME7X/FaR0zE1Cs=;
        b=iPige28qkg0jmLOwXjax4WHGz1np0ZkZzoUVplRJStsdFj8jK+dLtMCnD0RneduBRW
         ZyuyObIWk4iPhMkRfWCsLHNfGyCC9SpcmIL4evuIW5+0CkaORNk6hdApPX9HQx7SVc/b
         uZZSMs5IsuTzs5r1TA/ugCfbLNDrLme7SEPYFrDDqD2Y3QzymxC/jd6fJCtK8jKSMbS5
         /A99Vxm62ZvFP626IXbRVh5cgM+x/1AJvCW/bhEyVis79mAZLyL7s8UReTH+rmUiOAGv
         AtiGaQ+pgZvQetOXiCmEAfMGAeIjiL5Vma3bH13xRsM3H0HCODbjJpBlJk9eDZCuwSgq
         LpjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kJjXR2mn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-427f0097904si362887f8f.7.2025.10.21.16.07.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Oct 2025 16:07:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-4711f156326so47667605e9.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Oct 2025 16:07:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWwp1JuAdws8UEvHpPE9dMgq+pg7CXL20CtoBQg/lAEf9JOxDOa1aXz3LPwT0RA7QVfgSFSJL0vYtM=@googlegroups.com
X-Gm-Gg: ASbGncsaiIigYoJx2sEHZZovS1HeHGI+vme73To8yWcY8QYeguQFx3xKThwix2KDE4Q
	ejn4XTx7ZtR28Q+gJnXuKqb4vRWX3o0RlqYnXxtDrTewdJi3fegJynv0b5glzlgxsWVvJ2V6w2h
	cSHqUmVh1+PFpgsyh96S/NsgMRhQtZTvdDrXWXBStpJe1dbJNQKs80Z4pBqRgxDlzZv7KdCfXtd
	1RqU4HUZC0jQr1SfddaogYEwmvpc4si8Z/gFvgPgPMW8LmpVFlREfAksOWpb40Nr5/Q/N5cTOrY
	yQsQcD8bSGA0F9yMb+Q2iZKna1uukmVARZh4W50x
X-Received: by 2002:a05:6000:4703:b0:427:690:1d84 with SMTP id
 ffacd0b85a97d-42706901d9fmr10929644f8f.32.1761088038428; Tue, 21 Oct 2025
 16:07:18 -0700 (PDT)
MIME-Version: 1.0
References: <20251009155403.1379150-1-snovitoll@gmail.com> <20251009155403.1379150-2-snovitoll@gmail.com>
In-Reply-To: <20251009155403.1379150-2-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 22 Oct 2025 01:07:07 +0200
X-Gm-Features: AS18NWCmo3ddiV-eCF44oMWKYeYFjMfIoy4ZgUCJRQ4FNMTlti9w47Jhqig1JNY
Message-ID: <CA+fCnZfwPU0_LJQsCbatD3kd8vLE-ep06vZikNaR0W6-6UrkDQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: remove __kasan_save_free_info wrapper
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, bhe@redhat.com, 
	christophe.leroy@csgroup.eu, ritesh.list@gmail.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kJjXR2mn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
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

On Thu, Oct 9, 2025 at 5:54=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
>
> We don't need a kasan_enabled() check in
> kasan_save_free_info() at all. Both the higher level paths
> (kasan_slab_free and kasan_mempool_poison_object) already contain this
> check. Therefore, remove the __wrapper.
>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> Fixes: 1e338f4d99e6 ("kasan: introduce ARCH_DEFER_KASAN and unify static =
key across modes")
> ---
>  mm/kasan/generic.c | 2 +-
>  mm/kasan/kasan.h   | 7 +------
>  mm/kasan/tags.c    | 2 +-
>  3 files changed, 3 insertions(+), 8 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index b413c46b3e0..516b49accc4 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -573,7 +573,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, =
void *object, gfp_t flags)
>         kasan_save_track(&alloc_meta->alloc_track, flags);
>  }
>
> -void __kasan_save_free_info(struct kmem_cache *cache, void *object)
> +void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
>         struct kasan_free_meta *free_meta;
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 07fa7375a84..fc9169a5476 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -399,12 +399,7 @@ void kasan_set_track(struct kasan_track *track, depo=
t_stack_handle_t stack);
>  void kasan_save_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t=
 flags);
>
> -void __kasan_save_free_info(struct kmem_cache *cache, void *object);
> -static inline void kasan_save_free_info(struct kmem_cache *cache, void *=
object)
> -{
> -       if (kasan_enabled())
> -               __kasan_save_free_info(cache, object);
> -}
> +void kasan_save_free_info(struct kmem_cache *cache, void *object);
>
>  #ifdef CONFIG_KASAN_GENERIC
>  bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index b9f31293622..d65d48b85f9 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -142,7 +142,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, =
void *object, gfp_t flags)
>         save_stack_info(cache, object, flags, false);
>  }
>
> -void __kasan_save_free_info(struct kmem_cache *cache, void *object)
> +void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
>         save_stack_info(cache, object, 0, true);
>  }
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfwPU0_LJQsCbatD3kd8vLE-ep06vZikNaR0W6-6UrkDQ%40mail.gmail.com.
