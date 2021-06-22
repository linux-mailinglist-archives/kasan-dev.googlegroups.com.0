Return-Path: <kasan-dev+bncBDW2JDUY5AORBU63Y6DAMGQEJDCVLKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 494F33B066D
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 16:04:04 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id b42-20020a05651c0b2ab029016b628e5f99sf2921209ljr.5
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 07:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624370644; cv=pass;
        d=google.com; s=arc-20160816;
        b=XHOv3vPjJAs0RAw3xZSNlwzRtxtel7kLD/FyEXJv+rFmhR3fsZfzH71VJiLphI0Y3w
         ATzDZ2kBkwGUbr3BWFs//ipJe68UxyOrwEchWN1LsOKGhqbO1+u5sznZIsAlinlBhtpL
         L/btx/5rjONk8CJJjt6yGI/lN7kZmU/Wap2M693tktNhza0/o2CibM0AQv5mBbGXRtf8
         H4K6wWCU/o2Tckgxyj5l6VG2+Mqqj3RVU58q1S6rp/Ha0sNUzk3v9hIZhMDyPqyK3FHB
         ZeO8IbSvCSVu3Jkf+QzCbe5KDXVX9Gxs6OEpUrm1wfdDFIC3YypWx/QZkcnClzndH6NG
         I8dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bUDNsBM/0gOeCsf+kRLK8NywtNECeRg4QBVXGR9Xm7E=;
        b=vHrkd3+5yyiqNWPm4LciA8G8u6AXMHNHJOhP2eCaKBSSLQmFONTjtfUssJDqP+1g5Z
         NfrH1X9+TslxNowjljnnMihHREsxz42bXNCbw8AxKCRLn70r2Ytks6navDt1iZ6IF/l+
         rJinLCmWsAOYanDiU31LGKxoJM6NOgPBqh9GzXETy0oSChJJ66Lx5d+ZHCUr8njFdPZp
         5nowVaCjHqw3rB5DJ0YmjwWhJqDWBfxMc2gNa9qrZ3rqplHvsIgRU0qWdUjl1v8iqEbA
         I+1ebqwaXf2+t5j+PYDsB7SUhOcBJKHsKgpmdfUe0UFM0P7HSqDzUzQn3N08khOMBPSW
         hDXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="fZ5quJ/G";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bUDNsBM/0gOeCsf+kRLK8NywtNECeRg4QBVXGR9Xm7E=;
        b=AUwq7kgl4RwEdrz2oP1fvo1sFinz3zDO1gxT8YsQGDWgGMxMFjyWNgvVr/WKRTwPE+
         DseUmjAsEAou5qsquFCyop8phJGlvIrUunhg0gsxlPcgoQLSyj0Qebc9gz27lwoqkVty
         i0tDiYynRVgtK9ofIrfmUNuyyHrTIIlHK4E0b5SuxIWBHr44lFFCIdmi1vQ7IAZybqgO
         FbyXtmtLgFr1JApyWeIfzfPtz8i93Ojj7MDMuQU8b+3/Jk52hojiNUPZGF4LXLj1Ru+l
         onMpfygsGL33W9/mV3LC6Nhhy7Ri6EzekVnLnnYMmxPyEsLcbzLeRSlFoLtAQFluyQ86
         392g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bUDNsBM/0gOeCsf+kRLK8NywtNECeRg4QBVXGR9Xm7E=;
        b=vWXDMD2ilEE6M2dzZww5RT6yckxVJjPSB9DpkFCg0Gynr7dM98mSCRKHDQbnowTXbF
         BHi8L3HOjRx9NYkCm2Rgl9vXbK7lRm43ByyQrACQ2PRbTw91R0CBk4hhhDMNEiro2ly3
         iCuiWUjBGQaEcowtV6POE4u09UXVzKYaXltGRv2y+BzL1esRG8OcXPWbwGUrnRB4HgBF
         +FVF9TWdWBjbcM8GQYoCHtvTO7Ql43/EaK5EaTtIt85z8RmNNyt7kpb50wa52d14DyLP
         LdznNPBpdL6rDLC2U2aTW/rA93GcFO73/8UTqmvC2/4D6ELIIKprl+JWXEBZ4dVlaIFN
         tH3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bUDNsBM/0gOeCsf+kRLK8NywtNECeRg4QBVXGR9Xm7E=;
        b=ITxPi47lxC1NZ6RBKL3Aq241pDwbcuJnj7PA0Ongt/++YFJATQKmKpVbHwxt8it2mv
         m+eC6rPA5bj1y1bzWszCnXrWBEJXuxTiRO9Y7Qx+4AghAiB+y8xrAPvxVAtDyv8x3yiq
         GOxwKn+etYWzRawoGQ2uyFanLuDUsOVvrmgZGoc/eT2NNB2+xlrRLbEOr+ukvXRhWohX
         njr5wjqla95xImrs9gJFfoC7wuozPZI8C33QhBT3/LLCFqXrn70HW4EHaCO4y7VEcJV+
         NPF9XK20gnbCHUKssN5BBMGXfDuR+2T1K3upqJlTLt+1oWvOPczlOgTYBq7qxyJ5gt2Q
         u90w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LmLFEBysmR4lX3v3N6XrALW5b8nuXTqgVg3jc3F8iNcNxN7Pg
	IPeTCyx3GD/fmgwdTSBMUPU=
X-Google-Smtp-Source: ABdhPJzmZSGbiLzs2hL5iK/JEKIuzc2k3MesXIO5EXF3+lhJOllUyh81JRoQlIU8cix8yMYBf+xWCA==
X-Received: by 2002:a05:651c:112b:: with SMTP id e11mr3357912ljo.39.1624370643923;
        Tue, 22 Jun 2021 07:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3196:: with SMTP id i22ls1348374lfe.2.gmail; Tue,
 22 Jun 2021 07:04:02 -0700 (PDT)
X-Received: by 2002:a05:6512:1041:: with SMTP id c1mr2922283lfb.364.1624370642920;
        Tue, 22 Jun 2021 07:04:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624370642; cv=none;
        d=google.com; s=arc-20160816;
        b=gTpIj80o6JwgzepqSksV/6J2/Yv3fS7U2nkfq3Ewqfp9Yd3ZyAHKgaTG9GxFvoxuDe
         qSwg3RhQhte2GO6aaz8pbt8ZQvgURo7MJfVDewHwKi1YvE8ZVqHDufmiSl1gJw0tE45j
         eqjrC7pR7WZ3RRYEDDytjGyinc5iFFxezvfL6fbQ2YyqXyuIN165NcgUr/CelHUt1I06
         LDn2Cafw7vuELltIGamL++HnK9gTeRn0td7lLw70YNwdvQyy/Og/lciJaWpY2zs0OpLS
         nEgqf7venx8tZjA37m2xJJQgBPmdML4PDKggHPYGw0S+GnqJgD3BIbCPcu2DiFImxert
         PxnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iPbarU+l9m1KwGWUNyzhJZ595uUBAZXAe0wQ6HeHGxQ=;
        b=BXj+bXfiIG6mIr8LIq3AXqvba5vbExSGE/m7QjsAqoI54OpxvW1EKBJDmj2eCGrzjn
         3pRWBA24ReyBHLh8MzC73ItYdhBKIoMYGzxhu9/j7p8rl2JaeK1bKNmla/ZD5rbYlcVW
         FsraJ8VLtzNTOvIfd0bz824+ndJW7iBSvYhHvekCvPSwKrH/0I+L3N3zQ1rEVFWmvO5s
         rcogDfb+NSUfSsXiYmXn3J2OTHoG6O6dbv0k9gvRH8cnQu2947T0mi+VKRa+oa9Ftd1V
         /G9EHB+lzdtK/YG5bPS3Hd0f/fltmmkXl4oE9NnqhdSstqgMPWGyEbW0qpPrHYPAlcx+
         RjtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="fZ5quJ/G";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52b.google.com (mail-ed1-x52b.google.com. [2a00:1450:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id d11si120178lfs.2.2021.06.22.07.04.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 07:04:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) client-ip=2a00:1450:4864:20::52b;
Received: by mail-ed1-x52b.google.com with SMTP id r7so23799743edv.12
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 07:04:02 -0700 (PDT)
X-Received: by 2002:a50:fd83:: with SMTP id o3mr5199829edt.95.1624370642532;
 Tue, 22 Jun 2021 07:04:02 -0700 (PDT)
MIME-Version: 1.0
References: <20210621154442.18463-1-yee.lee@mediatek.com>
In-Reply-To: <20210621154442.18463-1-yee.lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Jun 2021 17:03:42 +0300
Message-ID: <CA+fCnZdPwKZ9GfhTYPpWGVEO7bS6sSrh8cioZmRJet2maUjSVQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: unpoison use memset to init unaligned object size
To: yee.lee@mediatek.com
Cc: wsd_upstream@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="fZ5quJ/G";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52b
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

On Mon, Jun 21, 2021 at 6:45 PM <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> This patch adds a memset to initialize object of unaligned size.
> Duing to the MTE granulrity, the integrated initialization using
> hwtag instruction will force clearing out bytes in granular size,
> which may cause undesired effect, such as overwriting to the redzone
> of SLUB debug. In this patch, for the unaligned object size, function
> uses memset to initailize context instead of the hwtag instruction.
>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..d8faa64614b7 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -387,8 +387,11 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> +       if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +               init = false;
> +               memset((void *)addr, 0, size);
> +       }

With this implementation, we loose the benefit of setting tags and
initializing memory with the same instructions.

Perhaps a better implementation would be to call
hw_set_mem_tag_range() with the size rounded down, and then separately
deal with the leftover memory.

>         size = round_up(size, KASAN_GRANULE_SIZE);
> -
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
>  }
>
> --
> 2.18.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdPwKZ9GfhTYPpWGVEO7bS6sSrh8cioZmRJet2maUjSVQ%40mail.gmail.com.
