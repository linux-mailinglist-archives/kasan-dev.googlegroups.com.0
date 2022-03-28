Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBJETQ2JAMGQE7T3EE4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E8744E9255
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 12:10:45 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id do20-20020a170906c11400b006e0de97a0e9sf1555173ejc.19
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 03:10:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648462245; cv=pass;
        d=google.com; s=arc-20160816;
        b=BCnVGWL3SBZNAeUaJiKYrJ0Cx0QhLqqcHLiydYfvjC/SQMBfTRwcY7MfE64gbRFmxf
         AsxiLGjsz4JH5IL5TDOSCcFQH20cD6Kun43TpwmIP7K9UlTQxyKu4R3w8GAMFphV2Cor
         ApFH9Da3BzcLsleE1sA9MotyQ0Nhb5PkDmxXOSYnYtPPgKt4aeglkmRsfiG0bHPg+f3M
         8iZWO/IkMbETYh814/iOgP6oqmGVCmZBHDG3fJt0qzMyPWhJBfi/2/cNg66v4yw3MCmE
         XaKLjpPNMdrD34Enf7e+Ujj7xW80CRMMiizHnwOeNLnAN6esp48SPLadBnwFBkVLNMKz
         +/wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6insArFVPDw+f0a6ua7dABb4jkjubXNlOd2LUHM4Wfc=;
        b=mUCPFhfWPbfiRlm2L3JQ7O1Hur01XlrESuaD6OFMK5oMEVoRsJQPhKNWh8hftFWFZl
         6l2XHrtFrSDy96w92bnLnfd7/UWAZFdtAwpIFowuL16exaLiRychOu85KFW8YyONC+KW
         2bjDhiHoNh2gl1+82aXX2Xqxdzr1EM6U4oGz2sM181GmWE72YNgEuly/MW/L53GUfMRq
         XATwiXNcbrg5qfWnK9B6/nm9RXIB5SFfBZHCa7g75/jB2cezzMEn53Lc+HIITbzjOgrk
         c1XILUr2g3RmsDPtfXmapmbdEfAp1V2CSd9rV/etFZZA3YonTc/UnfY6kHbHCskeAJeU
         5YHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VGijNzoI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="b23bF/+1";
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6insArFVPDw+f0a6ua7dABb4jkjubXNlOd2LUHM4Wfc=;
        b=MtKDO4xEYGQA1Kbj3BZB/QnNu2jxQiSpVh/vYCE/ehYR8C71veQhRl0HvndTZgbTk0
         fgRqP/ibOQDlYh3JaWXebWASAcjyUjutC8DYII8oKHjwpNUYdwh+rcCnUIY5Ag9Z4xDV
         EWy/vyOv/d27W774zT5gOWpVTIEDdm5KwzvNtTSlDQitIyL1jGo7W2ncrbQbBYvJoLGN
         U7Wv0W4O/chVQG8ar76WvuBWXnfVgkpFLBuf2Q9G5wfZqiiAGrslIUVUnAGnErsI83E1
         ogfdVVOSb0+CBRz9lAoXWVV0+qPNX7I1jPSxgpQdgG+I3Y5lB2MSFQ7dupc+/qblJWv2
         qvNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6insArFVPDw+f0a6ua7dABb4jkjubXNlOd2LUHM4Wfc=;
        b=ptNVhXJ1Z0YlQJY65lW3vyiM2JTbQlr//byhCkwHEqrlp6F1GY43GTWdvzPdysM/Fk
         rycWsyEYdwzfuL53TF+GQs0Z2ogfBRpCwDm/VhQjFwNgjnMx/0lqpzhrLAXM6IqnUDLi
         183Gu8b2hGKIsTK/D7WJ72LEsBx7YRps0Lk4VRj5Rt9vRDS+GEng5SS54/M0eAkPQi9V
         3MIcyMma2H/aLe5o4g9Lk4r3w6g6Qr/UJQfgAJGEaXtuQT+KZ4u82ouQ0fyZCY4NhJf+
         wxsXolpk6kSDv95JQD8bttdJpCSGyqobTp+pscSAnyjzASHQwZECK4BjBSfRMu77G+jb
         pkNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VWGrC1qXqtehVs2oD/vQbUKFs/g1/m2L4pCNIRgGGiSasi2j9
	5NijpQs3/udhIEz1xsu/FLQ=
X-Google-Smtp-Source: ABdhPJwEZw30b9DessoAOnZGUUHxph63Q6EH+evAopBYhrNDeWMnJshq5NmkymfsamUVQlbG1XHiyw==
X-Received: by 2002:a17:906:7950:b0:6e0:6f49:c90 with SMTP id l16-20020a170906795000b006e06f490c90mr27130889ejo.156.1648462245009;
        Mon, 28 Mar 2022 03:10:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:742:b0:419:7c76:8e7b with SMTP id
 p2-20020a056402074200b004197c768e7bls1609374edy.2.gmail; Mon, 28 Mar 2022
 03:10:44 -0700 (PDT)
X-Received: by 2002:a05:6402:1d4a:b0:419:7c50:dcbf with SMTP id dz10-20020a0564021d4a00b004197c50dcbfmr14913589edb.340.1648462243953;
        Mon, 28 Mar 2022 03:10:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648462243; cv=none;
        d=google.com; s=arc-20160816;
        b=dbrQjkgNNRKf8/CH/nN/hiWQM6vdrtxaCbdp9uWOcoPDwxVsP2SyYpk31ReIEgIHvX
         joTJvpicdLongk1olrW+S4w3ngmV5Cx738ZF0FTBBetYb9zPjaT6+xlotOnXTSWlWfvc
         dNJkuhCvqY02MS0wGRRzRuJ7VX4etfFBjFxVD4Q6jMnu4fm8rv/rvEv5hmr9LsGfITH0
         8mrF4uLsvLJ1clEUJECEQA51mJ64bgcxQvuUnn8zVsMP7GdWav89cyKhpOHycZjP9EHe
         rypUgfGCHC5GIqU6rgfwB9WdlIbKJxLBmswno5fqW7puBJQ7juq5OxqCez0TBIoFMmDb
         /86g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=MEUjP7knGa/NIjIdm17InHHeis0a7CbD1Zy0ms8KFt4=;
        b=rO6S54eCYT3WP5OKfCmdXmG1w1PtwsBDtXxBK6vhRmOJpknS+eJXKnkjHIvAxykyl4
         DRMzzesYTSj4j5jyI60h/pHHwDc5sZo/Kby+WQhKR9mLjLfHE3WphSW5fTySBU5pX6Gd
         65aVC51cWvta5n24v/J/AVgBy9wcu+RGkwqNiYITd6jfYWsP7X4feDiKxRkTOhBh7HQi
         e3uedgnqfgbLDgjxxp8Y9xzF2E96BNGxdFeKLcA6rqutgSNUh7ZmGLJpK2RKW5LJI7is
         tB98A7CVdJaxcxjC08y/G3XLcTLsMsEUyEe0dUHH4vNwKWhlAKM21XeCnSzyiEYuTP1T
         LtBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=VGijNzoI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="b23bF/+1";
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bm16-20020a170906c05000b006dff891c710si772964ejb.2.2022.03.28.03.10.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Mar 2022 03:10:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 841381F37E;
	Mon, 28 Mar 2022 10:10:43 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4E80413215;
	Mon, 28 Mar 2022 10:10:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id MN8rEqOJQWLlPQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 28 Mar 2022 10:10:43 +0000
Message-ID: <0b22192a-b5e5-93a3-6ed7-7670ff15844d@suse.cz>
Date: Mon, 28 Mar 2022 12:09:35 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.6.1
Subject: Re: [PATCH] mm, kasan: fix __GFP_BITS_SHIFT definition breaking
 LOCKDEP
Content-Language: en-US
To: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Matthew Wilcox <willy@infradead.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <462ff52742a1fcc95a69778685737f723ee4dfb3.1648400273.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <462ff52742a1fcc95a69778685737f723ee4dfb3.1648400273.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=VGijNzoI;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="b23bF/+1";
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/27/22 19:00, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> KASAN changes that added new GFP flags mistakenly updated __GFP_BITS_SHIFT
> as the total number of GFP bits instead of as a shift used to define
> __GFP_BITS_MASK.
> 
> This broke LOCKDEP, as __GFP_BITS_MASK now gets the 25th bit enabled
> instead of the 28th for __GFP_NOLOCKDEP.
> 
> Update __GFP_BITS_SHIFT to always count KASAN GFP bits.
> 
> In the future, we could handle all combinations of KASAN and LOCKDEP to
> occupy as few bits as possible. For now, we have enough GFP bits to be
> inefficient in this quick fix.
> 
> Fixes: 9353ffa6e9e9 ("kasan, page_alloc: allow skipping memory init for HW_TAGS")
> Fixes: 53ae233c30a6 ("kasan, page_alloc: allow skipping unpoisoning for HW_TAGS")
> Fixes: f49d9c5bb15c ("kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS")
> Reported-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  include/linux/gfp.h | 4 +---
>  1 file changed, 1 insertion(+), 3 deletions(-)
> 
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 0fa17fb85de5..761f8f1885c7 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -264,9 +264,7 @@ struct vm_area_struct;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>  
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (24 +						\
> -			  3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
> -			  IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
>  
>  /**

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0b22192a-b5e5-93a3-6ed7-7670ff15844d%40suse.cz.
