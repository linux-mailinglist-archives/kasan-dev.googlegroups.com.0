Return-Path: <kasan-dev+bncBC6LHPWNU4DBBOWGST6QKGQEIFHUBSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D17F2A93F8
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 11:19:39 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id d14sf344951qvz.16
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 02:19:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604657978; cv=pass;
        d=google.com; s=arc-20160816;
        b=iJFedmzH1oya8ew16Pe1UGASB+f/bNn1qV/p8eP0ocCfQ+CAyU3frOzHrxYfLLQbBm
         iXcbpXcomL8eIQvJQbvvGhE0M7AXIiZ6jG88/ar5yFcAryquYt12ZUs3wkCcwknPnM2m
         BqOLjoZ5WhTEo33dXLmxM5B8gioEIYroUBRsAKKilolXOV7h4edsJf2c1JJa9BwX6jo7
         5yu3MQHcvE5fg8svoOwU6uQduPD2qPgDq7MRw/fjFpp4gMMSapazvBeA/cKTKRjPCvCw
         Kwg7SB9ozYFqzDBSxh812utL7I1fWFG4hd69N7RGIB/jocGcicpTz9SPet7cv8I+5x3B
         Tt+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=RlV+0WMlXyllIOaT5yqAWR+4KgWIAJ2t3i5ui5lv1i4=;
        b=R6ylm8f4Gx9p2bfa0/eExaf9vwBMkbiRNNUUEP9QbOL5iz/4qCbi4JIzdNAUf0gB/J
         wp1Q5aXnpBRCyqf0ggaH/MG+LK/6/8sEhXRONbcvVuvKElLd3DNHLTOtag+zOLM+T21T
         JkGH9k45yymgTl95xDHtMM+IFAVG/Ie1ulbmtALK82K+W4U0S6NT+qPbuq3R/PEuoA+d
         a/ntaqN1fJElGwBn9IAbvJKBnN+wWdcWRU0BuWUwZoHf8sgmBMtReK0dDRcTaIrCT4W5
         g9IvpPTBXVa0xwVYZRnFewvyJqUi2W042oC1bC1d5KIk8TG7QMFaA8XvC2DzKFU6/vao
         meug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iEoLJtq7;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RlV+0WMlXyllIOaT5yqAWR+4KgWIAJ2t3i5ui5lv1i4=;
        b=h8CgA79na3FF8dB4r5I6s1lCKd295lsF5PHCR4jGxd4g2PAJWXyFsPeXuCOaAcIwHy
         sg8MKpu7qjxnh9swZRwPoQH9ULUzJpQk9xvMvMnz5TBz89MtUDodiglYRcjbPRuQu341
         IGmzQvf+oLk/ahLWLZvqWYelOtoLQbIM5YGo3AxS2XMIDOXSeJTg3eqZuKantAspeIG7
         RqsSmNQ3UiJsMwqxUtN7QOjpK3gllmUIXsnlmnhFsdhVaDDKHXyJKyZSX/jpCzljbaxn
         j/gUhzKkEh/Xlz7QU01HbpCPDEJKzb5L2Iyc7UqlJ9tfRdWRBX9RVtkq5NqRjz9VG7OP
         jK/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RlV+0WMlXyllIOaT5yqAWR+4KgWIAJ2t3i5ui5lv1i4=;
        b=lY+VeBHgO/SIhzq/ii+V1SUjz/m4LTxlxO1o7GYfKct/oEYjxWKgr3PPIYvI6ZWo0b
         HIyvrz8Q5oDSBPcBENUGI4OsxfNanT6+zQj3qX6t6CH2cJTmPM2m405s6zuH9YroTosG
         ZC71fMAkaSamkuTw+doHaRisZgaj/JOZwCsWNR0sC+KVNFh9lPsfnNHFZFDlvkKFYXv1
         nsQcNmEaOE3+dR3fLZFqIxV8m2OO+0pmryvRfxAhrUvrptjQLD2guQymSsu1bcYtqo1B
         KeBeKCYH8OX1qM28deB9eZBpNI54pSHJhRCuhnwMKgVw1FxsSgohJ7HF5YiNvaichpnq
         4MaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RlV+0WMlXyllIOaT5yqAWR+4KgWIAJ2t3i5ui5lv1i4=;
        b=bZS6Tm9zG1ji5nNcO87VIhjbGCWQBomCZU2NFjU8gIuQGx2+zJUjwerLuV9YFT7C/X
         2C3kA2EYmwB879UG9Lv2il+2drXujVK17a+fIFC+XMvKqzHHs+U0Zj3JGXy1ReLsI3+h
         QSKCPK+EwOPM2L6oEDFGBbCxiK/igUCyL6r3pP2JQS9jW6yvSMDg67JsrHNFInnXKjs3
         hVN9az9uN+Qvaj8RKH6GEBOIKeNmUg3SkA5ArOtEs1jaOdrfef5mTbesstRlLyw3DFUm
         as5sYdcM18TvvrrR2NCnWG87BE3CGGaOIJoix5fKeEQvWBokvgeeAOFNweh3UnCYp10q
         3U5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326ZFXjQOlGGYaMLVAynR54SkHiP+bG74LZNA3kxRQnbgb7w66o
	1P5HYjcOcAXsHWRUxG3ISKw=
X-Google-Smtp-Source: ABdhPJwSW+sh9EYq1PlXjbUihkGoR3jnTj+rlufS3jWcdd8EZNm0ZiwlRy04np/LIvGGhA1lbFAmjw==
X-Received: by 2002:ae9:ee01:: with SMTP id i1mr777979qkg.10.1604657978310;
        Fri, 06 Nov 2020 02:19:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:240d:: with SMTP id d13ls368086qkn.6.gmail; Fri, 06
 Nov 2020 02:19:37 -0800 (PST)
X-Received: by 2002:a37:9ed7:: with SMTP id h206mr769415qke.426.1604657977825;
        Fri, 06 Nov 2020 02:19:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604657977; cv=none;
        d=google.com; s=arc-20160816;
        b=TPusRq1Wq57i2K6VonYtUw76HpDv0mWLiEDVGssxOyAlRN12GBdq/8IERo3oWZ4ocV
         b8sTr5Tz0CRcfVl7NUkn/yfSAIZ0zlYW3RCnGssSyM6FXOmBpALLWaW9nhMHNQdPnAHh
         fwHtfCMO/nKsrhunYlSFQv9imzzUdF19kUGyenGj8W5MboB3iJ+Xu1nqVFGdI7ZQVf6n
         NhtnMiIHy5j6XlloPxY2wF5eFGsTcqJ21BIOy0GgLw3ONa9YxJL/RUq0aZvm3FkBfTXd
         Q41HpPyfrAJKUiJ6HnfLEdCCTpSYmJA5PIGuh94mOvBBVixYKHiTDkq0HubIuTrRIs9O
         TSAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5QBJe5lX3IDD/Nb41CDBzkfjHyizFuCqEuWd5FfCo5w=;
        b=BtkLgqKkVtzQNlWhPNJ/GYSlKGgreqDtrP8CCaB+ZhaBjpJ7NV8UbrcEjkYwzvP07E
         L2GPESaUjhIhFDqDgAn81TxC35m6u79YmwZTQb+A5X6XzCDFW1Yk1efdCsWR6Q3Nyh3Z
         /a3aOF2nie7B/QG2O8qU9lBlxau5FqmcotQFknmmhtaNMbCn4/+PQLLv0RwN57rvq5bT
         nRGLt+MmVU3KJlpJ0DkRioybmCqSdGIJCURb9JofvDHorJ6UvsSNFMIgWII7JlceKzG9
         mQgHim6kMRPcSqxEAoPWTk6k6/PSYJeD3YVR+BwUc9WhdINb11KPYonr63Nq5Gg9Y+eU
         ZAjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iEoLJtq7;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id g19si60270qtm.2.2020.11.06.02.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 02:19:37 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id u21so899823iol.12
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 02:19:37 -0800 (PST)
X-Received: by 2002:a02:1349:: with SMTP id 70mr1020628jaz.130.1604657977371;
        Fri, 06 Nov 2020 02:19:37 -0800 (PST)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id w81sm803656ilk.38.2020.11.06.02.19.36
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 02:19:36 -0800 (PST)
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailauth.nyi.internal (Postfix) with ESMTP id 1E4FB27C005A;
	Fri,  6 Nov 2020 05:19:36 -0500 (EST)
Received: from mailfrontend2 ([10.202.2.163])
  by compute5.internal (MEProxy); Fri, 06 Nov 2020 05:19:36 -0500
X-ME-Sender: <xms:NyOlX7Umc1o6UCfXT_ssS6LWvP_3n4J6kOtBdkUTB0p0U8myLHhr2w>
    <xme:NyOlXzk1oOT9AgYiB84OiHvP9uDAXRMgqVEZj0Kl9znHn-yuoUY14lMyANJ56aN8t
    u-__ayDUB2CRdxElQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedujedruddtledgudehucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepvdelieegudfggeevjefhjeevueevieetjeeikedvgfejfeduheefhffggedv
    geejnecukfhppedufedurddutdejrddugeejrdduvdeinecuvehluhhsthgvrhfuihiivg
    epudenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhh
    phgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunh
    drfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:NyOlX3Y39L0-z03RJ36vWGjP6javzKfLo1ODkF79Cnd1VOiQeYPLDQ>
    <xmx:NyOlX2UNewSQf5MhknixbPxsAG2g89T1E5gFAArRQNkPAOkRMPrTkA>
    <xmx:NyOlX1k2zaEjEg0R7Z594kJAxbK4dZ5I5C_xCQwPtIMlb4mcR-YR9g>
    <xmx:OCOlX37pl7wl2w1WOffu2hqHae-UNpJCC9B1TyJLdH75YV11mAQYIgCQFg8>
Received: from localhost (unknown [131.107.147.126])
	by mail.messagingengine.com (Postfix) with ESMTPA id AC58C306005F;
	Fri,  6 Nov 2020 05:19:35 -0500 (EST)
Date: Fri, 6 Nov 2020 18:19:32 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw
Subject: Re: [PATCH v2] kcsan: Fix encoding masks and regain address bit
Message-ID: <20201106101932.GD3025@boqun-archlinux>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
 <20201105220324.15808-3-paulmck@kernel.org>
 <20201106093456.GB2851373@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201106093456.GB2851373@elver.google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=iEoLJtq7;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d41
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Fri, Nov 06, 2020 at 10:34:56AM +0100, Marco Elver wrote:
> The watchpoint encoding masks for size and address were off-by-one bit
> each, with the size mask using 1 unnecessary bit and the address mask
> missing 1 bit. However, due to the way the size is shifted into the
> encoded watchpoint, we were effectively wasting and never using the
> extra bit.
> 
> For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
> bit, 14 bits for the size bits, and then 49 bits left for the address.
> Prior to this fix we would end up with this usage:
> 
> 	[ write<1> | size<14> | wasted<1> | address<48> ]
> 
> Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
> size and address respectively. The added static_assert()s verify that
> the masks are as expected. With the fixed version, we get the expected
> usage:
> 
> 	[ write<1> | size<14> |             address<49> ]
> 
> Functionally no change is expected, since that extra address bit is
> insignificant for enabled architectures.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Boqun Feng <boqun.feng@gmail.com>

Regards,
Boqun

> ---
> v2:
> * Use WATCHPOINT_ADDR_BITS to avoid duplicating "BITS_PER_LONG-1 -
>   WATCHPOINT_SIZE_BITS" per Boqun's suggestion.
> ---
>  kernel/kcsan/encoding.h | 14 ++++++--------
>  1 file changed, 6 insertions(+), 8 deletions(-)
> 
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index 4f73db6d1407..7ee405524904 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -37,14 +37,12 @@
>   */
>  #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
>  
> -/*
> - * Masks to set/retrieve the encoded data.
> - */
> -#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
> -#define WATCHPOINT_SIZE_MASK                                                   \
> -	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
> -#define WATCHPOINT_ADDR_MASK                                                   \
> -	GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
> +/* Bitmasks for the encoded watchpoint access information. */
> +#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
> +#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)
> +#define WATCHPOINT_ADDR_MASK	GENMASK(WATCHPOINT_ADDR_BITS-1, 0)
> +static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
> +static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
>  
>  static inline bool check_encodable(unsigned long addr, size_t size)
>  {
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106101932.GD3025%40boqun-archlinux.
