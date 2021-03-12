Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSEHV2BAMGQEMPACQPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B41A03390C6
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:07:52 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id g2sf11281727wrx.20
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:07:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561672; cv=pass;
        d=google.com; s=arc-20160816;
        b=VDCBDvoZNmgsERWrA38wzesRyMOPX8INsxYKI3cUM3yLHr/hVJvufaoV2YMUhxclPN
         XlpDAf/uy08qdHNa+nRpj9Fcp6XWiY/ibDYapYsOgw4SThUoFZkiZCslCU3IBOpf0Dyi
         nno3gfD/tXKBDMK5IYi0CtoF4Py0m/GPjLWILS8+XYE0q3bnySWjibgyD697Smzv0jXX
         PvLuBoZEyswR88zDI+s8nMgbUB34AmtimQxizkXLHYBY2hu/Z1J/21EH1OFCxddTZkln
         b4zSSAq1bLlTqMXdYRN7c0SxBzpsyrPc7rFBjr+ufCSKExhRH1WBJWNxUvfTNHX/PBRZ
         ZPFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pWZkenQ+NNfpQ77LPvVmp1MUIPf8QBrXFPbFNDBvhw4=;
        b=qrKisgq6xi3pO5Lr/FGMoMQKiOLVh19r9952DO+v7asv4cgOoPG77NWn2lAlJVWJK+
         FRdpngLTQVGMmuTdBQkC2m4cHCf/aLrFZHy4m5nClEZGoacuNmxmIBy+odT7T+aCmH+v
         +LMsjfO8TtWaCKIMNZCCOZDAFjQ9PSA5YJ7LnXXmLnp2WQjHL69ky4s1IV8OEpDDJfdc
         mQkgiPSSxm5XXz66WPn4X0S5phn/8kmh+irysCLIn3wui4gBBen9qOxFha7E+DW0gP4G
         KD8WsIxRFNiDqlY/7uoVYaIx0jysxt+rA65db1WEKv+0EIt8qJ2HiE5/hwCMcJkpiuet
         V6Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PVXNJnwS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pWZkenQ+NNfpQ77LPvVmp1MUIPf8QBrXFPbFNDBvhw4=;
        b=BiSOIxsH/jnU39jCg157Eha69qJ1lDRS4LJdGipb1z1KgkQQYWggdbrGD2rJ8RS/y9
         5ymE24Aa85TG8Y6ch89BvWK6KFXqt6j+4H8jgkbctW2Tx2QDPcrog1lWN058MBmi90K+
         IGl40AHn501P+mgm+1ttg1AwJXTsYTZtag1x46FuLvd1RmfgtT70ivU37sguGHlb4EvV
         SfHReBKBabnPULOCq/8WO2MXuSBh0JzK6w1MGExdGR/m2MMpEPnuqEcNASk1Ve0mP0/f
         QPvxlJaWihFAmFXnWjLY4zYfH2adTPIT8S3+IpWZXoFB+xWviIhXSoujqgROEaAXk4JQ
         J88g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pWZkenQ+NNfpQ77LPvVmp1MUIPf8QBrXFPbFNDBvhw4=;
        b=FRUJx0jRVuuWHHYz2srKfAmsiVmWBU8EoMdOCtedtaiGURfXR3iww1K5DfeWjuFCQX
         xXZBJqvDBURb/bPUeZU7DWiNxH1lf8wnOgIM0MK+CDPV8HbLUsWSZHFPFv8yACnkt6Yb
         xO+75FmtS9pgXmSdjhRWsUd6bH57nkqZHTksPNnYgFDVyr8j6/l/BVcTgrgxssHCjzGJ
         AVOWLTd3yMRTqh22kUM3ETGf3VdbyfAuHDgxvkr692zxk3lwYD3atnQmL9yIx6tTUeS5
         c0WeoD52Ig+0tMGdMAxofdh0Su0EMU7WzdH8fVr1uqabbRJTBkgkZHkWsWdpVk3c1zJI
         Hkzg==
X-Gm-Message-State: AOAM531BUL+/KhFFyZClHV9JCqHAwCnbOqgujoAzDAc4GdgqyQRqpJ6v
	SfoPiLumLvj8Wbqp4XMBQU4=
X-Google-Smtp-Source: ABdhPJzEv8fHJL1Cig4iJRufVlbDZQgXpd9uixC6Ze5Rkv718vawPrLVNRKdSfX/ovciP8l289b5Ag==
X-Received: by 2002:adf:e34f:: with SMTP id n15mr14502474wrj.224.1615561672470;
        Fri, 12 Mar 2021 07:07:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:98d3:: with SMTP id a202ls383116wme.0.experimental-gmail;
 Fri, 12 Mar 2021 07:07:51 -0800 (PST)
X-Received: by 2002:a7b:cdf7:: with SMTP id p23mr13692984wmj.26.1615561671154;
        Fri, 12 Mar 2021 07:07:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561671; cv=none;
        d=google.com; s=arc-20160816;
        b=lmFNKqG8iO4cRdmlWfijwWCLyd+vAyKbsASRe7yKOtaWo4GdDAp/eU8QdGgTV9OGUL
         9I+UDXPfC8q3xhh1JvQP4PzTNOtfTR39TI6p1DeSBgs3cXzrTWZ9IzAeK2B9Uc6zlczn
         bLU2lFN4oJcC+gZ2rspeGod8uGAYXqYrxYLfkg3XNfQfKrYhcB02EKGQXxG7GEc163yT
         3WIS1VR2EsN8SsUy+czKoc1NnDerJQoJyPP5aaIbaaRiXUYzG7AIkk/V/gc5NziaKvIV
         xK1pvtoGf2en4Vj9Xt/3M4gqoYHKrhD9QOv0/5NxuhyakD0G/NHeO/n1bz8DJD0SSmBu
         7XLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fwNR/esNVxm8bvX0S5OWeZlTokgAgw+YxcDuubZWv9Y=;
        b=OdWD26qRvfbFv9N2do2a9X8jBJ1rHbVNl0PvogM59BQj8hvBCdxnOA0ZRRn1m/a/5G
         Y8kfYb9mlVZ7yUjdsc755L2BFeAxTQ0MnwgTPRA+yN6DxH0uJ+WlIvCYi16uhTcbjJqJ
         RsvIIaZesKDMo3kckcSha9AuE7rxXP9TvuSbvNwEWQl9k0cF4w78v1QQn4jmj5H+5rIG
         8Qrj69f9mWUTqECaUcrfVtK8I5vUOecJseVqBeIENzRCMUOSVs7V01Dpvbw5bT6Yj+90
         u/eh/+zN6Go8OtWFggm3Wt5cCtcBlaNXo6lqPd3OcrdbTs5FhXjX5MU/WZ18dVjUMsp5
         8+rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PVXNJnwS;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id p189si228549wmp.1.2021.03.12.07.07.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:07:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 124-20020a1c00820000b029010b871409cfso15998116wma.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:07:51 -0800 (PST)
X-Received: by 2002:a7b:c931:: with SMTP id h17mr13781890wml.4.1615561670668;
        Fri, 12 Mar 2021 07:07:50 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id h10sm8125546wrp.22.2021.03.12.07.07.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:07:49 -0800 (PST)
Date: Fri, 12 Mar 2021 16:07:44 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 03/11] kasan: docs: update usage section
Message-ID: <YEuDwG6NqbNlCXL/@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <48427809cd4b8b5d6bc00926cbe87e2b5081df17.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <48427809cd4b8b5d6bc00926cbe87e2b5081df17.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PVXNJnwS;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update the "Usage" section in KASAN documentation:
> 
> - Add inline code snippet markers.
> - Reword the part about stack traces for clarity.
> - Other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 23 +++++++++++------------
>  1 file changed, 11 insertions(+), 12 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 2f2697b290d5..46f4e9680805 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -41,22 +41,21 @@ and riscv architectures, and tag-based KASAN modes are supported only for arm64.
>  Usage
>  -----
>  
> -To enable KASAN configure kernel with::
> +To enable KASAN, configure the kernel with::
>  
> -	  CONFIG_KASAN = y
> +	  CONFIG_KASAN=y
>  
> -and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
> -CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
> -CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
> +and choose between ``CONFIG_KASAN_GENERIC`` (to enable generic KASAN),
> +``CONFIG_KASAN_SW_TAGS`` (to enable software tag-based KASAN), and
> +``CONFIG_KASAN_HW_TAGS`` (to enable hardware tag-based KASAN).
>  
> -For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
> -CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
> -The former produces smaller binary while the latter is 1.1 - 2 times faster.
> +For software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
> +``CONFIG_KASAN_INLINE``. Outline and inline are compiler instrumentation types.
> +The former produces a smaller binary while the latter is 1.1-2 times faster.
>  
> -For better error reports that include stack traces, enable CONFIG_STACKTRACE.
> -
> -To augment reports with last allocation and freeing stack of the physical page,
> -it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
> +To include alloc and free stack traces of affected slab objects into reports,
> +enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
> +physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
>  
>  Error reports
>  ~~~~~~~~~~~~~
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuDwG6NqbNlCXL/%40elver.google.com.
