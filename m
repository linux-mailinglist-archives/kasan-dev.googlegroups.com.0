Return-Path: <kasan-dev+bncBD4L7DEGYINBBQHZZSDAMGQEQLEY7RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D6273B1B9A
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 15:53:05 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id b125-20020a3799830000b02903ad1e638ccasf2574430qke.4
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 06:53:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624456384; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rd4yHPclVT4CDVReSJJ6n2Ih+7Ydyn1W2DV41PugozzG21mkAowcmr7xdVtVzw4bFc
         HOehkeiUwWDPkMNFfLJoAMQJlmVgWuRlrC4VfOpP25JU0bNTLRADB/X1vYC4SUaMkcPR
         swD6fGED+OYDd5RfTjtQm4koAF39Q+dAbfAjitrHnaG1/eYcfgThPgiVRJJVClqE//6M
         tYiErnNyXB0+b8NGUmi01HYJ6Djrnmn7HE960kzpGl1GvbUdZiVU3Ck5KjtsD3FbHLDC
         43HYcZNqQQ3pu9pICwyiLGZDEu4eLZOB3K8FaC1jwS5oboY2/W+g3a72o5ionYfb0fvA
         /2oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=8dPHUviy7jsaTF5QZQFhkEzdRrujC3repYyTfcdsCAs=;
        b=o9NAzqoKa0r2uDXhHEXC8dFkzLmfrxxtFjXRt4RSlKEb9ftciTv/QXRChEI7ST+ZdM
         4fdcnVQd0P+34LRODJF+c/bHiRAbUWBw97Z2lQSHWWTmg6kj4mKxYEA2ncUZA63dVBAr
         nrT/NRNv/8fbZ7sSW/w2XuEdX0ZGVsZf4i541oAe2kA/TRNK1p1WWP/EosmOqn/gjIgN
         mn8MW2RcvBicrTHg8XIDGamDaweYrPdjcaAjD+ZDYJzEp+Kln6ZagdZA/QHOJjwrDQqv
         +LJiiwu8LtKQfZ6wIrzGovO+bEbCwEPj5b0+RrOil3SaBpObz49+GPwo/qhds6BHt5As
         IMOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=jjXHYD8K;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8dPHUviy7jsaTF5QZQFhkEzdRrujC3repYyTfcdsCAs=;
        b=MzCyH/zMBs1bBdOerdXPnvMv3ATvzvRLqfWuHbQkYpXLr5VqRg8bEMYrknAkafHwK6
         uUyD3BrynRGXQr8CPGyeBq/hqB456zD1IXS0eJm2OnMH94Xc/F1724Lvwy2T9wzGhG/9
         2l4bUcuflR86+sa7MdFsbHfzSiEanG2VMbs8ANA+w0txQXfZ9QgK+dIvWmxssP4ygFiz
         9zgfg/sAzEad3/6yb/Bf2xSVM+3VH4zc8nim2ixPBYO3BQbGUIQNqNoubgeQ1whBbtoI
         koq/mv78b9Ce6a+wI+3jSR6PyV02Bo+FDA78VfHZUJmdexLhmm9YwRNRUdwWTGTrKyPP
         5vlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8dPHUviy7jsaTF5QZQFhkEzdRrujC3repYyTfcdsCAs=;
        b=XwrR4rXhr0Z6Yvv7Z+6tBMPTVuGNPR7ACzXy01eTFGBU77B8q+fSV7AeYnyi0kUcm0
         aVgO+k6Udok6zBWzdm6gGDcbW3/jgxxYxVt+M2FqjRlxDrZRadj+S2FWTddU5Ss+LNiD
         7a63jHDFeRorU+8Qx8bCA8mh7wUbYnq2gccon1txuENOYuoZwnouipZykt+fETSPjENh
         onMTNAaAlisUmI2tV3APZf3KN+ozUV7fXiY6hqucwDyl/gSSO2Ftb4YGZZZKRLrvNELa
         CLHtIDChQApLmXRhtSYwXP+divK+e5GoY4Ld0ODnA+RZLJrFKOaEaEtBIJbpvKSg/lDe
         YbSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/7xrS5osFSIFT7tCCbz86n3FRRggpdM9f7IrQWZLvnfAed2La
	FhcuMKDvWPWMLx7mGykUHkw=
X-Google-Smtp-Source: ABdhPJyVdwHt2HwMYLWG0a46X9pVAs/Ua93DjchJaEM4pQCjVfur/AKMpOc9fK7Yp1g4nzZh2Nn4hg==
X-Received: by 2002:a37:4096:: with SMTP id n144mr83772qka.271.1624456384341;
        Wed, 23 Jun 2021 06:53:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:da7:: with SMTP id h7ls892045qvh.3.gmail; Wed, 23
 Jun 2021 06:53:04 -0700 (PDT)
X-Received: by 2002:ad4:4a12:: with SMTP id m18mr4783521qvz.26.1624456383952;
        Wed, 23 Jun 2021 06:53:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624456383; cv=none;
        d=google.com; s=arc-20160816;
        b=dkFKqxLsqqAf4xNK49X0h5vSgNW7tTRdRceZKFJuZu951a3xmos1FwDxcJiDphIEzt
         w0t5vF1BAh6psMjrwJbT1qbfNpRLYSX5sWp8k3FIBC6NNgNTQN8MemRHrVbOPKYcNpID
         GFXn5I+9w0hyo1NaGd7PA7474MIjFNbBQeGCI/4t616p85I9KImTS/tgvNMBYKxZUw3u
         C+4u/uFStGdQ0bZlHGrEuZLAIwbSKV93mk7uthlsIaxLmktjQQtSLSw3lN8gipPxygMc
         98tQLM3GENjYN88p7Nsd6/MfXdr6cfHYtmDApb6wD+LsdtrL8iVWV4b9R/iIvPtsWnpz
         eL6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=HAjT4udO57t+rw0LhCJdv0l55D4KZ+MMoREZAkGCEQU=;
        b=Mpwoc8CmQPf8mG4VTkktxUJ4KHpS5xdEwn+IS3GrdsCjAIz1zejh1qzeQCoac6hQdS
         NfNWNlKlLjXy3p5zBZPqHfetCtwu+c7PQyQx3lJBXY7EgsHvRv4BaCTFpbAf9WS/UTkO
         06P8I7Gr1W742ZWc90slTAFX+ob/X8Y0HCiYae4rwBz2UrGXxM6gltiymd18P6pftl6k
         Y4ieBqc4veJWbPUUbEsIC54TzIqbP1oF5B7X+MD3g2y+clI7zIMwkuGVCBty9aMHGrsF
         //xGt81MSQjBGd5rGg6hfYOZIakgl/1z5uqiyk1ZK/L249D/eSUTjAdLQ8zZFQpxwFog
         xhig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=jjXHYD8K;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id c15si8292qko.1.2021.06.23.06.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Jun 2021 06:53:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 041a74b278754e9596b573f8f57eb514-20210623
X-UUID: 041a74b278754e9596b573f8f57eb514-20210623
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 282718694; Wed, 23 Jun 2021 21:52:57 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 23 Jun 2021 21:52:49 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 23 Jun 2021 21:52:49 +0800
Message-ID: <9a77839314b3c33970925b5127182c97914c185d.camel@mediatek.com>
Subject: Re: [PATCH v2 1/1] kasan: Add memzero init for unaligned size under
 SLUB debug
From: Yee Lee <yee.lee@mediatek.com>
To: <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, "Matthias Brugger"
	<matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list
	<linux-kernel@vger.kernel.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Date: Wed, 23 Jun 2021 21:52:49 +0800
In-Reply-To: <20210623133533.2246-2-yee.lee@mediatek.com>
References: <20210623133533.2246-1-yee.lee@mediatek.com>
	 <20210623133533.2246-2-yee.lee@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=jjXHYD8K;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Sorry not a completed patch.
Please skip this mail.

BR,
Yee

On Wed, 2021-06-23 at 21:35 +0800, yee.lee@mediatek.com wrote:
> From: Yee Lee <yee.lee@mediatek.com>
> 
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone with unaligned object size.
> 
> An additional memzero_explicit() path is added to replacing hwtag
> initialization
> at SLUB deubg mode.
> 
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>  mm/kasan/kasan.h | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d8faa64614b7..e984a9ac814d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -387,10 +387,12 @@ static inline void kasan_unpoison(const void
> *addr, size_t size, bool init)
>  
>  	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>  		return;
> +	#if IS_ENABLED(CONFIG_SLUB_DEBUG)
>  	if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
>  		init = false;
> -		memset((void *)addr, 0, size);
> +		memzero_explicit((void *)addr, size);
>  	}
> +	#endif
>  	size = round_up(size, KASAN_GRANULE_SIZE);
>  	hw_set_mem_tag_range((void *)addr, size, tag, init);
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9a77839314b3c33970925b5127182c97914c185d.camel%40mediatek.com.
