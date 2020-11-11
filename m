Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGPSWD6QKGQEFMYECGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8924B2AF8DC
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 20:18:49 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id y99sf1254172ede.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 11:18:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605122329; cv=pass;
        d=google.com; s=arc-20160816;
        b=aZ06biIQrJ3qado6ZZoAZpJti4P4zM+mP3PRy3MNlnECy3bPlGWW0948wYbPvHDojA
         Blupq+aiupgyKD/gs3Ab1xDo8uLXRKeOgTMJTk3m7ORFYDVTsxRFrHPsjtXIYTMX04Ws
         xQRUgt7Jq5ipu4bVFKW2mW8m5N0r9d3bZPg1G3waD4Gee90ihh1kj1jkQ+p81Cvqjt9W
         TIUQHXw7cGQPBQNiod4YqMcn6R0tEYwebrpj+W9uOHUHHYuQD7WTXeHf8CGyorSIJRtj
         h0B1Hzk+jS9EROgs3X9RLJEzx+3Lr/9+wb0IH2DR+Ke3esBHjxt0PPw3H9ER5w2luOpo
         Ux0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vIFTMunaJP51Xo4TKUkHCj+FCSENvR9LnYy5pd6I+XM=;
        b=iD26bDfNsbYGAO8q5kZvG6kX6ABSZN1hBpd4TaTlL2mF/yggElNpKQgjE22BZ4LUOU
         6m2l3XqiP+gCBNdSa9UwoaxLARWd59pMCCcUZN5m89z6JWR1aPPm3lDheq372pLxogI4
         k3nppufo7+JLilTz0kC0N9TCtvY2yziaSQ31JjiNKyi8XX5BsBYnupfMauwvjEokuefO
         QTWQ4Mq7pYGzwOisEnjPcqVPfTuNRWpHXwTq0UkNUqPknCjwjL6hW673kgGm5VU5XL46
         A6Dq4hgZ/KiDz+PrM3DM7PbqIjIDiPD9aSLAKQSZ3qznrY9UHF9lwsMPXcN13x+jaTQZ
         nBBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QIq5tT27;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vIFTMunaJP51Xo4TKUkHCj+FCSENvR9LnYy5pd6I+XM=;
        b=A8Xpi68K6HIn9cuYgNHaKh6Y4VbpYEOb9fRAOj8A8fpBT+i05MsK3+u4VVOkFXjfqm
         8ZIhsAplwn1AbNmaKtuWW4J+ZxaxN1l53dksSDx0edBxcbQQfcvanf+PYDsOCb8CbLgx
         1OwSPiivb93Dt78H5H4iHCTbKIfkhTf+Hup4xTrPndbTHSiAfJkgK2vd7BE9L3fvl8/k
         XEt+QM1wv4hCkPZTBDx7M2+cy7WatsZ8FNLopJwyKKLaVE1DzQ/jM4dLaeujMqFsgX7x
         GJpMI3EAX9cfozsZHWcyPH4SNrKKbccR7axXFd0OF458UV8mdL3yLldBaPjHh1u65/5X
         syzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vIFTMunaJP51Xo4TKUkHCj+FCSENvR9LnYy5pd6I+XM=;
        b=Ae6KyG3RgXF0gWDIZM0or/6fsrLUetJ1C98ia8C+kc2PJtLtRIFXQtnoqN9y05kl/i
         +fZHn1S1GFJqeGyItwg1b71xCf+7dqD3BaJdtTWBYOdv+ne37Xp0P27d6bSPat9AwcRn
         M/WEyfOEiD2yOv2tY9+C10f3z5RKmucSe4Od+lBa/kR5j+qfSP2iUSITZ01uUs6FjRWX
         +eDO+97XD7weBLph61lhTr+onmUmUPH7HoNGUSZEDJ96exUtf1kcFoNGayEMYKECYelz
         WIXxyDVvVlkrEZmjOKH/o+xKiAh8DMEl3+7vDcc4NVWysR/9pdziV5PKZ+nRzz4Q00dG
         GuAA==
X-Gm-Message-State: AOAM530admrRlfWSkGN7J/lb/ZSFKIY0ldBB4S1YAgsv6ue18IhH2ctY
	3WKGtS5wW4VUr0A/QHFu1Ww=
X-Google-Smtp-Source: ABdhPJycztyejlwiphbj/FcR73emTy7ilufx6z+RKHbNX7a50//P3KdO4pY/ov0zBWWguBrgRzu3BA==
X-Received: by 2002:a05:6402:1245:: with SMTP id l5mr1148974edw.68.1605122329376;
        Wed, 11 Nov 2020 11:18:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:417:: with SMTP id d23ls159509eja.7.gmail; Wed, 11
 Nov 2020 11:18:48 -0800 (PST)
X-Received: by 2002:a17:906:e285:: with SMTP id gg5mr27208831ejb.7.1605122328283;
        Wed, 11 Nov 2020 11:18:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605122328; cv=none;
        d=google.com; s=arc-20160816;
        b=kCXHBeOmJ3TDvm/1spxulh0//R0SU1dzYKvrG2kIAFB34ZMOPdfO0ljf1lSO/jyVZr
         Rna5FQ8WvSwoO/CKaiaehJj10QQXi5jrwhBoqK4hMSSAWnG7wkd7olvDmuGHvEKssDUH
         HgNS8yAVqZ86OB+Y9/zMyCnUUBAMJ6JbCmawAHqf290RHhPO/XkY1Q8pnEB97e7qmX3t
         WBADmjAFPCeu278aSlvQoPhQxQNaLWmHLtu+JgE/e5oaV0bUTE6X7lUitP6Mm+dnKiwF
         y+xe/T9hkkTYu43uEnnOTKB2fh+cQX4GfqPAKvwOm30m3HEBMq7LRqAg0E8fU6gCfRCo
         YXGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OKGISrzawD1j8o64KuvlnCYWWA4Vpka6a0oknsEcZJw=;
        b=sbyuKz4b6sP+cppoNXjrpGUdQbAOB21NdaX31sdNe2YnOr0heIbuQ6CwjPsTF3lXUC
         QjCOdH69mCmsE4ALATVCScwROqaib2DEv58jDRm5gfmUIipR6oa2LJvCxQsNHn3Eu+WV
         2bhoFFUhB5aH8ilbbtNbsoTDWspj7Gn9H3/PHCxvIlwJabq3RPAPUtoWCt639puMbVdt
         XRSfIzAidHPOR7WmS9aueaIvIAdCOIOtTiAHb1JpEtOQHUEuaKSNBe9OeYOk+ndT+V2W
         oL6j+2m71pFO2ab3x4iVPXUNk0GAM/MmJveEJ1DPiOmzEGfFa23H+SCgiAQFiaExolh7
         nqaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QIq5tT27;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id v7si168822edj.5.2020.11.11.11.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 11:18:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id p8so3627350wrx.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 11:18:48 -0800 (PST)
X-Received: by 2002:adf:f644:: with SMTP id x4mr32047323wrp.5.1605122327874;
        Wed, 11 Nov 2020 11:18:47 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c6sm3806761wrh.74.2020.11.11.11.18.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 11:18:47 -0800 (PST)
Date: Wed, 11 Nov 2020 20:18:41 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 17/20] kasan: clarify comment in __kasan_kfree_large
Message-ID: <20201111191841.GS517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <dd492a97ed68200b1d7e2dce55ed9a7790525396.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dd492a97ed68200b1d7e2dce55ed9a7790525396.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QIq5tT27;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Currently it says that the memory gets poisoned by page_alloc code.
> Clarify this by mentioning the specific callback that poisons the
> memory.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725
> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 40ff3ce07a76..4360292ad7f3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -436,5 +436,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>  	if (ptr != page_address(virt_to_head_page(ptr)))
>  		kasan_report_invalid_free(ptr, ip);
> -	/* The object will be poisoned by page_alloc. */
> +	/* The object will be poisoned by kasan_free_pages(). */
>  }
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111191841.GS517454%40elver.google.com.
