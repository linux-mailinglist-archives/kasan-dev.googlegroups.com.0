Return-Path: <kasan-dev+bncBDW2JDUY5AORBJVFVCMQMGQEA3BZIIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 469AD5BED84
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 21:21:13 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id a16-20020a170902ecd000b001782ec09870sf2298558plh.12
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 12:21:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663701671; cv=pass;
        d=google.com; s=arc-20160816;
        b=sTaAz0J47nHzctsUy2KLKqg0G+SWTVKcRaHleH3zAY38XgyxH0pv8YSzjgXMZ/fd05
         jQ+gdqn3IIouHxgoapM1Oq8l6ZMguxTRFj24A90QP0nGKEl+I8vntctCK77SiU8Ga8gE
         AEQL+Qf2RMxI62mfD8dxugjHQ+jjv1f5uVvCYYsfUqSmsGvocqM9IyXkkht85QPWEPGh
         FeHZsw+L6dD0MGEdY3Hasgj+xqLfkfGJrwno5BoOzY/UnUxg+2dzIneKh8WUFbNyHv4O
         7NQRIzz0R39uobkz37ODdMsL2/AL6JpzMVUx5Eux4I3zWaf8JMdSOhrxdnu5OElDXrCB
         0D8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=pWm/t7vaZ7CKiPAJx0B63iSp8Qjnp9RwLV3dVfQG/q4=;
        b=ZzO/9NHGt1hu5rQ/SW//C2ae+/HtgXjTvghcqhPKzB2n+2WNIJ0+q2if2uZsCNlL/G
         NaTbS5Ed1w6WPH67PFZVh1g2kbNnYX2FUE9hFHP4e8YIUtd9VbBMfcm5UE8wJC4BH3fK
         ZYXiKCqxEbe2YkaPf2kQ86/KcvZB0Iv23Kja4kBX6h+LrNqydghjvgFisRCwGYP8r1e3
         EJVyLPv3/nYI0XH71T7sGF1zfnN3+vpGH3vCIb72BGdwVPDdDN+9el2H5YShQFjqyi1R
         wA5I8PJSLLK0XwBR1BGtULLyaOApm0hq3+u/VleV9N0clVG0z7alD4EPbblyt+B0HE/J
         zB+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DaxAZMRn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=pWm/t7vaZ7CKiPAJx0B63iSp8Qjnp9RwLV3dVfQG/q4=;
        b=eH4Dqt84jSfzSKqBXsumVgpnJo7Wl5ENnyRc5/33lXM3b6CYnnmnw74zzYQwnPonqI
         GnkNSijWeaOkHGyXAKKDCfbDBQBNyeoZaz9Te/pbTKDJKcx9dJRx+blWKVjWr6HZZNdn
         7airRVw876MVFVGukjQr0vdpYNx/gGOl+eb7ST7RaPMlVyPqsLIMIHuOM+xq/AInfiE/
         xq+8YCRixK38um6YAbBrYixjTtkCP4viZWGrPLtuQG+rZVw2bHNTTaDnQbWpZsngfmiC
         c7EHzpSDWTEGvLkM3pJdp8jbDjyCRutHDmpiwJ8gurWbuG/Ys43x2Plc1uqHtGzSeKIy
         h/+Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=pWm/t7vaZ7CKiPAJx0B63iSp8Qjnp9RwLV3dVfQG/q4=;
        b=kTm8m+fJNxmcpDHX8LSKg6U0qBK9yQl1cY3xhUiJ7f7FYiptUhtiVeGbzIIi+50so6
         2PN0wqLPlMJD641/mwlEumOQf6brSv1Lmhwv9JutYAvQx6Y/9Av5QLcxjRx6xmp8yaa4
         3dxl+9O65n2Uzml6eJQ6i1YreH8qjHFP6wRnNn8QRsLExVLXvZQ492tUt50QYB6ScU4v
         5rsVEF6LERrE2UIJXiYvI/Q61jCmfceGeWch6irHDNYw4baAScoS14RAeew+8LlzBo0W
         lLOdFu5J4KFkmCE9qP+445Ov2tAJmVscm2C3d+h0PWVUYsc3xNvU16UbSsPL+SaRHUy5
         RWmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=pWm/t7vaZ7CKiPAJx0B63iSp8Qjnp9RwLV3dVfQG/q4=;
        b=Xas2LIp/K0wB4ul+92qiCgh4d/AvPKqivWnQewtz/7q+ijnZGkNnl1y3KIYrKToGT5
         3pKFTQjPgbtr/O6HPEgGAABklsqp+Y+u+rSAmwWiMmB7Gbg7jhUJZKZghYxP0D8e2MQa
         GgYRBkB+buTziOQ+l/bOigJ/I5Ikn/2glXiZ8drAe+4iHM6cSLqSh+7BknSrfEiAzycl
         xSd/yBHKBO3kDlB2yNK5b4A3xgc5Osd0eASnx2Olgt43trmI/AR9Rp3EyMLL9ks2UbzH
         b8JVXBaOi9uVB7tcj0fRVIikXeg4KC3YLI/02Qr11ZI2p6S7I0QqL/91rcEenB6TTc/x
         diuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3BEPBNxpCOg7oa9vzL4wd8J8V/mxlUGLQsL3uyq0g6xjBo6TIy
	GBmKBhG8v4J/tRG6RMYpLcI=
X-Google-Smtp-Source: AMsMyM6fp8vCL77qRv2HmGniojjr+eODDhV2JKgSh4LgzIcJTyCOYevIcyDnAHZXkWRNbEeXg2X7jg==
X-Received: by 2002:a63:585c:0:b0:439:61d5:17fc with SMTP id i28-20020a63585c000000b0043961d517fcmr21079579pgm.364.1663701670811;
        Tue, 20 Sep 2022 12:21:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:788d:b0:178:5938:29de with SMTP id
 q13-20020a170902788d00b00178593829dels6503959pll.2.-pod-prod-gmail; Tue, 20
 Sep 2022 12:21:10 -0700 (PDT)
X-Received: by 2002:a17:90a:fc96:b0:203:86f:5a86 with SMTP id ci22-20020a17090afc9600b00203086f5a86mr5476930pjb.108.1663701670144;
        Tue, 20 Sep 2022 12:21:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663701670; cv=none;
        d=google.com; s=arc-20160816;
        b=rFqOiyCy774kejG0WZCB7FemyHYEUKsUP3f/5Q/j6Ql6/vuY8Nf92ge1nNifVwc3/B
         ni7dPvvKH1r4RakLvaus6q0eLawauGKX1V/5hSp9uha9Kh13ZaEdqZuVNnuN845QBQjg
         OwIZz8qPqj8TukE2fdxymSEjXlujeBYxCY3l+TYJfDJxpLJ4fvy/xVzKs5Ndh7dmaqA9
         nnbiZB/ETbXYiuKYrJkRqEgn7iaJhThsN+5zaZ//AdlA3y3YGlCjZs2+miDs6o4OxvfM
         EPwP+I+pRSM23WqEmPjJa8BL16VXcy4LY6oPc633ZrMe5Wk3LGKwtH4VHclQ3Nq56FwM
         10LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2fFnFfvF7l44JixGUwp4lrsIFX8DjQoBBv2Lr/mkNP0=;
        b=S2V9TO8liTniqOa2WAdcPDTteoMMoAHIVQwOUGRkhWhvQu1VlPz9eKj8DX0Pvu4ewW
         GWyYoaVueOaDNH6G2WHwhO1DxkgrVUM6CsZtYvxfsKkPboheuWuPENei6cEvChVs+/qc
         abev7aJugfuSW3KwE3wEvSeFg3ExlfrmAYw24QjNjmJZp9AfSVPUqNn7QbfGrWpCUOl3
         U5jbdMyZuKDUHtnnR0oVNhW9L8Z1TA1aEa6qz8sM4ePy5df5SBaySdIHICk9OjgiKafY
         GdaHbPG0vwIfIWqE9a40QIWqF34ctG1Gxh3DefziL3GhejwbAtjrH6jlo1qylSeTNlBt
         1HIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DaxAZMRn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id n2-20020a170902d2c200b0016d3382bc9asi22326plc.0.2022.09.20.12.21.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Sep 2022 12:21:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id w4so2791270qvp.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 12:21:10 -0700 (PDT)
X-Received: by 2002:a05:6214:c48:b0:4ac:b18d:c101 with SMTP id
 r8-20020a0562140c4800b004acb18dc101mr20513445qvj.107.1663701669341; Tue, 20
 Sep 2022 12:21:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220913065423.520159-1-feng.tang@intel.com> <20220913065423.520159-4-feng.tang@intel.com>
In-Reply-To: <20220913065423.520159-4-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Sep 2022 21:20:58 +0200
Message-ID: <CA+fCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ@mail.gmail.com>
Subject: Re: [PATCH v6 3/4] mm: kasan: Add free_meta size info in struct kasan_cache
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Dave Hansen <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel test robot <oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=DaxAZMRn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f2f
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

On Tue, Sep 13, 2022 at 8:54 AM Feng Tang <feng.tang@intel.com> wrote:
>
> When kasan is enabled for slab/slub, it may save kasan' free_meta
> data in the former part of slab object data area in slab object's
> free path, which works fine.
>
> There is ongoing effort to extend slub's debug function which will
> redzone the latter part of kmalloc object area, and when both of
> the debug are enabled, there is possible conflict, especially when
> the kmalloc object has small size, as caught by 0Day bot [1]
>
> For better information for slab/slub, add free_meta's data size
> into 'struct kasan_cache', so that its users can take right action
> to avoid data conflict.
>
> [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  include/linux/kasan.h | 2 ++
>  mm/kasan/common.c     | 2 ++
>  2 files changed, 4 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b092277bf48d..49af9513e8ed 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
>  struct kasan_cache {
>         int alloc_meta_offset;
>         int free_meta_offset;
> +       /* size of free_meta data saved in object's data area */
> +       int free_meta_size;
>         bool is_kmalloc;
>  };
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 69f583855c8b..0cb867e92524 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
>                         *size = ok_size;
>                 }
> +       } else {
> +               cache->kasan_info.free_meta_size = sizeof(struct kasan_free_meta);

Hi Feng,

I just realized that we already have a function that exposes a similar
functionality: kasan_metadata_size. However, this function returns the
size of metadata that is stored in the redzone.

I think, instead of adding free_meta_size, a better approach would be to:

1. Rename kasan_metadata_size to kasan_metadata_size_in_redzone (or
something like that).
2. Add kasan_metadata_size_in_object with appropriate implementation
and use that in your patches.

This allows avoiding exposing KASAN-internal details such as what kind
of fields the kasan_cache struct has to the common code.

Sorry for nor realizing this straight away.

(Note that there's an upcoming patch that fixes a bug in
kasan_metadata_size' implementation [1].)

Thanks!

[1] https://lore.kernel.org/linux-mm/c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl@google.com/



>         }
>
>         /* Calculate size with optimal redzone. */
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ%40mail.gmail.com.
