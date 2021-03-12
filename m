Return-Path: <kasan-dev+bncBDDL3KWR4EBRBXURV2BAMGQEH2OSIYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 302B833913F
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:29:35 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id m22sf14903593otn.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:29:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615562974; cv=pass;
        d=google.com; s=arc-20160816;
        b=TBC50n+a7Rt/vVqjg0pC/3zKJD61Ro/cjbuEMjecHvaz+pjL/ln0iXzH7+81Olcnrf
         H5qGAz7aymP1PKKd1oP8B7g4r4sJnNTkbMlFQPaL6A3OIisLggBYLZQGX+taZSJHm4eC
         ggWVdbzvZpHqVdd3QQklkqg+XpcnU1fqjHjkHjBIS6UsbzpLSfrGuhePHlt+arE0FbCM
         m1ngZV+wUT8g4AMeblKt2Ytsektpcvpog3gP+/scQnfuFn/v71RX0rgUvpUdBCzlJT57
         RjkSl4hTWmV7KuDhVymF8OezHd7bekjwM442/rm440+krkccrOUjX7GFtRQvZizgIqy1
         zf8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=+6n1uQIHZB0YVXGEvwgG6C0GEsBq+9tXtwcmS1kuZuo=;
        b=Hij8SYv/99FsIauFHXjTED1Z7Mnl6+dMGomGF9awnYlTzvKIkixZDy0izsO6nx0Za6
         rZ88YA8v/iCbHDPfCSXWwVc2yK5BEJ7j9v0tQWqL7DF1Oc2kvsQf2BmOC812RiSqpRFQ
         SDLotTWaobjTiNDQPu7SS0Ay3Mohv3y0syXFQ5wWRsgj8j9ySGX+u5+QDldhvgQRIbd1
         vEGsBR5rF2z8a8Ye9KAubPu38dpcsLX/c4J44RSJDROwzvlsb+DwBkxF7tW49QyWZJ8d
         DGnRNPaXecGXyLwXlF4q45U9DCOemV12XU5C5Ph9HKi8AqZkpklOr0/NmWyDsJ9qMeS6
         4FPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+6n1uQIHZB0YVXGEvwgG6C0GEsBq+9tXtwcmS1kuZuo=;
        b=amP6E5C7224hnWYnCNbUyMXfXoayDCL94WhN/4KHZEZPTAdKP5/uuO4LAyiZgRtPp/
         T5ZxihrbnmNk8QSjUOYTHg6qz/i/LkvOmH/Po+AS7knlAGj1CmX7CJlImStbEwyvMrGp
         YNRe+Jnlo4W2/ZO8RhFiNAJy2l533Aux9kUFhSIyuDnVSnNGBnIl2pS7yhamOzxNJhf0
         7puyCNYdZlKOKVBcYuNXaGsmIyiSbMR49OhaWRjBlnDpkfetaMRMtyhs4bBev+zj/py8
         9c88Dx3ns0tZ0ysjaWQ58n2puvPmHfQKKJOWh+Bsf4DG5Cdr8G/BB+PHO2Xvy+9YsWpz
         +dSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+6n1uQIHZB0YVXGEvwgG6C0GEsBq+9tXtwcmS1kuZuo=;
        b=IfoCdIQ0TOl8sNaTwHO8GPLpftFu2kBDsl+WCgCJ0ns6WWfdMjte1XAZaOpqEootgm
         uQy+supCbHKHHBBV0DxwH738JSbehy4IIiAatFt0YcooM/MFoizDhqbx4vS7KU09/BGf
         wJHrQYLB3NvAMtJ7UotSIp6jIjIhfqOJCoaj/hzWJM8P0kLfBX29V62t7AKuKC30OeCx
         KHuqYG/prw2TwAUjRRlJmp9xX+E82fSZjxbmCHG98i7dX1+KEAhZvKjzzTzLRSMc4hS2
         41T6pYAm21Pls2JMKUuk3JuUHjduWljRa7eDFIKpy1aBoB+ZgJCocuUr2cdzx7+UXTCp
         IvVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MOmoZn9vPT2ZvRejJHSkl2y1eDyhmcfbsT4GaceMcmPqsJE3u
	54z1DjnnpimTbJn36glR9qw=
X-Google-Smtp-Source: ABdhPJw87c09joiroMA+deT3iNl1A02yFty8bEqKivmVayOzicYrUd22SqJpCH75A5xZvA/lwFW4rg==
X-Received: by 2002:a4a:8c4f:: with SMTP id v15mr3705259ooj.25.1615562974153;
        Fri, 12 Mar 2021 07:29:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:71cf:: with SMTP id z15ls1230248otj.2.gmail; Fri, 12 Mar
 2021 07:29:33 -0800 (PST)
X-Received: by 2002:a9d:3f08:: with SMTP id m8mr3702373otc.344.1615562973790;
        Fri, 12 Mar 2021 07:29:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615562973; cv=none;
        d=google.com; s=arc-20160816;
        b=tcGiBFqZw7Z0cpQnsTaPstqW9exB4woqbIh5iY0PbIDiaX1JzGDAw7UUbARoFIPqEr
         uANZSSP2PhqhcmPT8JVUcdQoNATkHv6P4r3NLm9uilFnAcv3dCFpqC85fhBrMxSDMHoE
         xDsohIN5T9ULK9l8sM5iD47ITNgSDr7ozP7xHc9zAjrQSJrgHsoxcruXsXAeEI8RI3tF
         cd4fn/VIOKUYoAlNaDbf7+0jAezt++aRrVjl2lWIXfLb4jV8j8/YwNBOhyiSzC+RCmXB
         iFeqvAgkEWLYrffpWz2/ywOLJCx1ldurs6GeH1SaiVCU/6V5a5eMpVtov0smzmi7IhqH
         OlOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=chGfDjI2axUnQCsAVaBlaUVUOleFZ+hrs2yvxzqkHr0=;
        b=tg93c/CYfomTRJ7QPuqzmTmfonZeerW65upChC283MYj3l8yP+4qujWzTTAnv0hrWc
         ELtmFoQtzRjgKYvWKuEMaIKgWLU/rKSDMsFokXgctq7ZZ1tcAFE9cPZyglcbtNs5aoC2
         oN06VV0UIGHGVXJVq2DPO+5+JVcZNGGd3o6YgNoq/4v364B2zPNSw45CVcp7Rj3qPLcg
         affRC0GQlPYJ/pFTzG8BX5CMv6tGdSffaetmMCh4a5AY41thfDcp87EyNPqV+Do9aJ0t
         ociBf1PqKrHRdcGByMqIcI6DaN2DaIbzsMiY90jkXS8DeY3FQJb1rH2Oz+QG2CcRRemA
         0XeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h5si484790otk.1.2021.03.12.07.29.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:29:33 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B769664FEE;
	Fri, 12 Mar 2021 15:29:30 +0000 (UTC)
Date: Fri, 12 Mar 2021 15:29:28 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v15 5/8] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210312152927.GD24210@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
 <20210312142210.21326-6-vincenzo.frascino@arm.com>
 <20210312151259.GB24210@arm.com>
 <31b7a388-4c57-cb25-2d30-da7c37e2b4d6@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <31b7a388-4c57-cb25-2d30-da7c37e2b4d6@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Mar 12, 2021 at 03:23:44PM +0000, Vincenzo Frascino wrote:
> On 3/12/21 3:13 PM, Catalin Marinas wrote:
> > On Fri, Mar 12, 2021 at 02:22:07PM +0000, Vincenzo Frascino wrote:
> >> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> >> index 9b557a457f24..8603c6636a7d 100644
> >> --- a/arch/arm64/include/asm/mte.h
> >> +++ b/arch/arm64/include/asm/mte.h
> >> @@ -90,5 +90,20 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> >>  
> >>  #endif /* CONFIG_ARM64_MTE */
> >>  
> >> +#ifdef CONFIG_KASAN_HW_TAGS
> >> +/* Whether the MTE asynchronous mode is enabled. */
> >> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> >> +
> >> +static inline bool system_uses_mte_async_mode(void)
> >> +{
> >> +	return static_branch_unlikely(&mte_async_mode);
> >> +}
> >> +#else
> >> +static inline bool system_uses_mte_async_mode(void)
> >> +{
> >> +	return false;
> >> +}
> >> +#endif /* CONFIG_KASAN_HW_TAGS */
> > 
> > You can write this with fewer lines:
> > 
> > DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> > 
> > static inline bool system_uses_mte_async_mode(void)
> > {
> > 	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> > 		static_branch_unlikely(&mte_async_mode);
> > }
> > 
> > The compiler will ensure that mte_async_mode is not referred when
> > !CONFIG_KASAN_HW_TAGS and therefore doesn't need to be defined.
> 
> Yes, I agree, but I introduce "#ifdef CONFIG_KASAN_HW_TAGS" in the successive
> patch anyway, according to me the overall code looks more uniform like this. But
> I do not have a strong opinion or preference on this.

Ah, yes, I didn't look at patch 6 again as it was already reviewed and I
forgot the context. Leave it as it is then, my reviewed-by still stands.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312152927.GD24210%40arm.com.
