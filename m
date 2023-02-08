Return-Path: <kasan-dev+bncBDBK55H2UQKRBG6LR6PQMGQEIQYBWBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id EB29E68F6A5
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 19:10:36 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id cd3-20020a05622a418300b003b9bd2a2284sf11082728qtb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 10:10:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675879835; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q9fv3yk7gh+SZP4+Y1bE+ALqpUlkPd0qdVe12Fe3/DzT4avaskMIJWQ8/uee4BmMap
         HZ0sumhl/IFy7F3uHV9nYR3WBi1mxNph41O/8Ys36hLaX3ZF2O4Fxj5MXACs/MzLFO2L
         YyCRJ0MYYBbyN29mA5R66nzKhWQ2FpMi0l3f43lUa46ljFA1rTi0zWI3FrCKmlxCsIDL
         rOEkQvtgNiQlZOi0ke5ULqByu7/UHjpaF40ZwykzRGXHNLxy5zgKiS6wZdJ8PXh/ap/M
         H0Hicp9+FUOo/LIjkxdGla5nDSYXaIeBFdR0cZ4+VgBQVUwtwcXSYbGMAqyoA0Zoq8Nj
         4Vyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HZUYLOF0x7BF6RpoEOYTTBCXG/8oEVGG+DTeJ4mFjzo=;
        b=yahm9JJ+/SzgnYZeKJVlTUDmhEMTiVRK+6UoXDWQTzbrCVlP2+mckvQGBqAuEhKsZ7
         Xx+TRCBIXkyCmuxWS2AqJzxcQhjk2Chs6mMjLbgCwn8iyWu52nln9MZylZ3afvWhRbuo
         gxDzScMOe+fj+oBavcaysUqtvkLG/uXTdDE8aiKCKg00GKddawO0HHGRtVXai14yfudi
         0LhXqs9JRZizCfF5UDJNg1eNsm+kgWEy10yLoBD21MnaQwJ9FpHb930TF2tlncSXJpOH
         Td5uS2ts/wy+jUv35PWuRIwE4l3wSR96x7wYl+DSy4jJ4OPJ3Ol3F7Xv/bS/2ne6/7Vk
         zA6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=JMPfVqhJ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HZUYLOF0x7BF6RpoEOYTTBCXG/8oEVGG+DTeJ4mFjzo=;
        b=soYVlLbQrdidRR8nLbvGA4ZG87bjXaLeXxOinerxXwRwP1oi53uIx6D6eRilfjc6Xb
         K12sUVLsDCH+MH5nSmEKXcWWrs9tH6m2yU4a1Hze3QfN2IRv5uzgZRs2Gk6MJyNOIET1
         HbJmbAskoGlvDgizKpH7kpvH1XvbOXJOEdPNMy8WWpuN8K4BthHB2Y177Rn59wdwqbLy
         DlKDmiTwuipS0h87iHWgXVPnwlpgkFc/OFeqE5D8RSH1wgNWwoXxIM88AaA6KpG0Xjz5
         546sGPCPCVEJr16HYApGm3aEAVbMzd309Q+kMoyOUKmruY1G9n3KYHcLT/GnDeFDwP5s
         rLog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HZUYLOF0x7BF6RpoEOYTTBCXG/8oEVGG+DTeJ4mFjzo=;
        b=YqqzfCHVt5LNL7nHhyuVT9slKm4l3hkjKtbJU7iyGx9mGM93Y+NX1z1tiUgs6PVL2m
         NrfN/ACoc9SlXu+tde8x59Tu/egECAFpPcXGKVrHXufWz5xhkLxJ6cwOojJADfhY1IOw
         96qBP/LYG4lXMh7zgKvIhdysRiBboHdVohR5Hs/K2DXF6ruvvdtS0xya6qbDofsvXpxM
         EbD8Lgj173fV5yhEJPRJ8R0hM8L421eq+I9C371G/3tOjSnI20yxiKg2ttAUwUhvDOru
         UqNn2BFTyVi8elNSk3w+bMRie91TC55C9rKeF1FIN8d0+4Fr2XTo2mcQJCZBqBHBqL50
         M2lA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUDGwuoNK3+XX2AJQh8iSKhqV8f0NkC+47zblRO7NilWly0sM7c
	CaeJxkL6MhQb7MHEqdrw1uY=
X-Google-Smtp-Source: AK7set8dv4/fg7BEQ88IoRcKiCoRodlAqxNPP9fEVahE1PN3A7WmR+mVnJmY53JNX3Tx3+n7QB2BUg==
X-Received: by 2002:a0c:8e4f:0:b0:56c:61:bd5d with SMTP id w15-20020a0c8e4f000000b0056c0061bd5dmr1046528qvb.65.1675879835554;
        Wed, 08 Feb 2023 10:10:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2309:b0:3a9:8ab2:1bab with SMTP id
 ck9-20020a05622a230900b003a98ab21babls20496678qtb.5.-pod-prod-gmail; Wed, 08
 Feb 2023 10:10:35 -0800 (PST)
X-Received: by 2002:a05:622a:3c6:b0:3b6:3040:a2fc with SMTP id k6-20020a05622a03c600b003b63040a2fcmr9290953qtx.9.1675879835000;
        Wed, 08 Feb 2023 10:10:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675879834; cv=none;
        d=google.com; s=arc-20160816;
        b=Thz315+zJfi7tqDI9xFSuYU/U8CDmz4Am7nHZ0fcKGDZ0Zjn0PunD11uvzrHwxRTi9
         DseNZEBEt2hwEb0slmlFXuhdjUfh0pZveQKuhzVF6ZKHoESGclvmp/Ga19YH1LZoBJyX
         kwqBgbbCIqhKvRm458KNK50LrgfuQCyA0JgkFcm+GrDLhRY8zS/W0alF6hjJLb4iBSQS
         /++CNN3oP7oR5qEExO8z4aYPDs7pwljTSu8d3/E5XvgbiSNtzHTKRlmhVcFe+wDqqD8P
         QPdocvGr+hMqsZeO+91VhwPQRVfojYeD6beXWgmw65hgJ/S/E8vbOAwJV8OzHVTaCeYd
         2Z6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6ckI3WTqph30NpxWFPDE4cvDOQBvbkyW3uZldKIaVSY=;
        b=bXmiV4wZ67WxRAOzUg3Asy3190c695PxD1NYro9pnfDDNI+5PrJHe3ooGb7ezhvHjC
         FFowSXmzZ/fRUYxpPVvvMcDw0wCo11ZIcZ9ozRZi9HqAOLcMtLdzzm9dhawK15MUr5bq
         Cmwu1QvVbbiutQD0nnqTKRY7x/W0zmgju5LbEDYZMOgR2sOGSXXZgX0VdWAUxkHfNlVd
         ri0W9EP10NwQXxcVQXK5gG18lo/p+zBBDNwe+5nKZRA5CVE/fswEsItdhlQebWpXlSbD
         p0bAqUsnhKlQsgZINGzH7Oolk4AK5WFHkfWO7qxIePapJFWdp+medv/58Q1Yc29MqtAH
         z+QQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=JMPfVqhJ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id cb6-20020a05622a1f8600b003b82ce6a004si1501137qtb.4.2023.02.08.10.10.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Feb 2023 10:10:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pPotn-001RIT-AH; Wed, 08 Feb 2023 18:10:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 228CB300129;
	Wed,  8 Feb 2023 19:10:27 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 128FE20F05D4E; Wed,  8 Feb 2023 19:10:27 +0100 (CET)
Date: Wed, 8 Feb 2023 19:10:26 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/4] kasan: mark addr_has_metadata __always_inline
Message-ID: <Y+Plku4Cf5Xkzq10@hirez.programming.kicks-ass.net>
References: <20230208164011.2287122-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=JMPfVqhJ;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Feb 08, 2023 at 05:39:55PM +0100, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> When the compiler decides not to inline this function, objdump
> complains about incorrect UACCESS state:
> 
> mm/kasan/generic.o: warning: objtool: __asan_load2+0x11: call to addr_has_metadata() with UACCESS enabled
> 
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

> ---
>  mm/kasan/kasan.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3231314e071f..9377b0789edc 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -297,7 +297,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  		<< KASAN_SHADOW_SCALE_SHIFT);
>  }
>  
> -static inline bool addr_has_metadata(const void *addr)
> +static __always_inline bool addr_has_metadata(const void *addr)
>  {
>  	return (kasan_reset_tag(addr) >=
>  		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> @@ -316,7 +316,7 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
>  
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>  
> -static inline bool addr_has_metadata(const void *addr)
> +static __always_inline bool addr_has_metadata(const void *addr)
>  {
>  	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>  }
> -- 
> 2.39.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BPlku4Cf5Xkzq10%40hirez.programming.kicks-ass.net.
