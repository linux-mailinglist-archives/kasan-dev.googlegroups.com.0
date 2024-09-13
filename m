Return-Path: <kasan-dev+bncBCZP5TXROEIJPJ4QW4DBUBDU5U5K6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 00AD3977D51
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 12:27:37 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2d8abc9b3e4sf1982270a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 03:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726223255; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fs2Yg21V9UflJVOtesIKV6vuqiV7IltEWBpyYkUX9stS7JFM6pO8nCHjH2yn9KjrwF
         Glv94w3jcsWTntkeCyvdbeVdihDyHnKj/rjvPItrqdPU1ze6KdMcIWcb0LdcvhwXLYpJ
         qH5PN4RFEYA1SgeaZ7g05s6Hjus9U0DO195jw8nrhkaAd3wj0+PUo/nEV89ZG4x3c+es
         +yJeBMn8wgft8ZlrzWs/R+k+rytXzRVlBGdiMA0ro+L1Txj04RYLLEEFdXs9IwC/Ba3o
         s00qR8+JbPjGqF1gLuQyLzRqmKg5UlBR+MH2wm/RDEjNtp1MrCI2rtUyA8f6lIZuABic
         fW6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VBxMPJpX0R81jYvrm5/+PBN0vYu/thnA3rc0H8PdBOY=;
        fh=xn0mMw2EpWD6kt39I17H7QQIbCW2nPmCry5TDHAyYY4=;
        b=KxejDyj0vTav2soAqu23NxRLs7HP41J54myVhL0720yNX+DEMhphyp6TmMgr2t3Nvw
         x93dtFcK1CCifn+YUcN06IWs5zUlIlMKC0vXVlu9MzY5mA97R/LiXJCRPGabLy/V+S0i
         uplU32PXdbuS5RbG9R9JtvcMrF3ssKQccGKce8EAPOnbrs8q+7ll9Yy77vx6ZRXIXJQq
         rivamlrDkKNTazzWvGxtFQ2WXqPH1v6NFXupcZ4oBoHcAyp4T1lgdSI9nItkuBw+Sl+R
         RpZeMi07JbihkJf2eMzKjkLEUxw6MBF3HUUNMe6lUlFY2gwdQaMzvqNRzPssOf9Nflx9
         9NJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726223255; x=1726828055; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VBxMPJpX0R81jYvrm5/+PBN0vYu/thnA3rc0H8PdBOY=;
        b=EZDeeQW9zUCrBY9CS+UofqZpeew/kFwmgUnHqY9pFp73Frera1QvMJ+KBHt+zo0ymG
         YbjrEG6pd0/B2H3lW0H/TM05UIidKjLCpDnT1cIMkJw9dYR0Nb5Pc4YldxKeANdL/aPu
         mqB7KOz6dWGuibBwi5uSU6RppcLM9JlSJqfhtr+VJclN4OgfRmM4bCezuniSFT8jiHJm
         Sz9SrFbH5UiTSM27OjNKHpRLDwKwp9kqOQkgtLrCM++xtPNZdGbJnqY/fLEZhHDRA7zh
         04SH6861rAHq1QxnZ2jIHODbkiPmeWC9sczI0bQbLLFI6YlR2Iu8d1Lrr0AtgZ/rx+dS
         gP7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726223255; x=1726828055;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VBxMPJpX0R81jYvrm5/+PBN0vYu/thnA3rc0H8PdBOY=;
        b=VG7jPXClcfFV2wDDEVWYKEU7AJs0Z57zrmh0OxnfGzjMuMmoAoL0iVryUpPN7EjQBT
         prNBS8ghe87lY8k2KgRqLd5ULpi1NVAusOyQh5sN0F/kBpTjQYmbNORugwQ7gdNFi1qk
         jU/JZfO+aacu8hH+K9wF2AlvmpTLSYXCmU6KHiPhRO3Bp1m/6yfOvTk/cdAEIyQW0MZR
         nVLkDGHZbJDBxapVk7VO7hsSRUmzhZmJMaThORIqT7ZUqSk5eJii/R6vuzDdj7mdlW3V
         8IlmPdu96Jn5nYUhiieAaECANIXil5TB84oFmMoXYHR+VCU9wA3tZIWsYTJZSCVPU+Rc
         cqQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSUIK5dNJlerlhRsD+VQy5l7DjzMrCiPT+y+By7HctsZfhUNUPwAwdOQycw5u25zoA0hZ6yA==@lfdr.de
X-Gm-Message-State: AOJu0YxrTC5PVEU6r9REwXTc8PSzemGdX4rIaJOc2ThQfMD3EFdTdN9d
	8X/ieBr8ZPFXjOGjDbDxuImWWNpH8pzsr/JmjTFVL5MWW73kwwrb
X-Google-Smtp-Source: AGHT+IFiiH2GZqxbfHcjhLuIYmK1XDUGXiXcWiOrWUJJwyWyHAr0lOe9mJMdgsDTYmKdGaAZeQE3Hw==
X-Received: by 2002:a17:90b:1c0a:b0:2d8:f11e:f7e with SMTP id 98e67ed59e1d1-2db9ff93003mr5831101a91.12.1726223255332;
        Fri, 13 Sep 2024 03:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9103:b0:2da:7aa5:fc90 with SMTP id
 98e67ed59e1d1-2db9ed34fc7ls30625a91.0.-pod-prod-01-us; Fri, 13 Sep 2024
 03:27:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVPBslTnELJ5DTezefStjRI34kCqMJG/w1HXSjRdQQCzafEJjH6NBE6v8cpBPYuA/SQIipN79Xtnpw=@googlegroups.com
X-Received: by 2002:a17:90b:815:b0:2d8:7572:4bc1 with SMTP id 98e67ed59e1d1-2db9ff79cfbmr6311371a91.1.1726223254031;
        Fri, 13 Sep 2024 03:27:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726223254; cv=none;
        d=google.com; s=arc-20240605;
        b=kD0tbFaoMlxmpdVgLCXc0LcxgEgBWkPc0CxQQnXFlp+lc4oK0/wMj4IRW8Z83t1Uvk
         T+Qgs2DV7w96As2L0Z3cxGJIZwSxhiFNVTKD3XRmOQE1j5bDh6F4keMjesiDPsl3GL27
         sPNKrP3leVk2JPWbFMO6rYaYvdjpD+qdvNG/8nNv5x4x/UEHHzXvucR8iI0HKs73+ZI9
         CmEppL0m2Do2f/ussqjm1nUiSe3tzoMhgQoFLKU66n4r6M3PzLrijnqs9qe7+6rod0er
         7e14+NTjq+vh0DprHpDNkTDUPju83bvcZnEDpj13mmwfUS6wrZyCbtEvdvReMQP50aUR
         DdWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=eMRx992McytR4E5n+Q7d+FxYWJ0qSxot7IY4Y/f0x3s=;
        fh=DpilCRW1lPr7EFgXA81j18rCwvjwIZ1eQiX7tELTdDE=;
        b=W3PN1n6rH0gLyHMlpfrM7MKGn9sKHLKn9BH1t8jMYdKNT4EacdF5DFABc7NzyY5r4M
         FOOIVcNE/MncKPN7ha5OXN2qKu60Exw+qZwVRNElTstvod62l/Br419IWDAcnm/gK6U0
         H+EWOAue1+SGPjgu61vraiJ9crRnw0MQToQNoDaDijyILnx6WWQCCrbIKhJ2Ak5BYRaR
         CiJQ/GEECe5GyMIk6Ai0Lv/6rPyH9jkAWuszeL98cHtkcJ1b60KEPu1z/AT55k5d/6yG
         sc72XLnVYdPWUIrdrEmMqhiyHjoYX82lKjr7T4IgZuVTMy7EsXlnHLAF30XxttM/W7XC
         CJ3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2db6c1a8676si396748a91.0.2024.09.13.03.27.33
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 03:27:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 372AA13D5;
	Fri, 13 Sep 2024 03:28:02 -0700 (PDT)
Received: from [10.57.82.141] (unknown [10.57.82.141])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F132B3F64C;
	Fri, 13 Sep 2024 03:27:30 -0700 (PDT)
Message-ID: <f7129bab-4def-4d64-8135-b5f0467bf739@arm.com>
Date: Fri, 13 Sep 2024 11:27:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 3/7] mm: Use ptep_get() for accessing PTE entries
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
 <20240913084433.1016256-4-anshuman.khandual@arm.com>
Content-Language: en-GB
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <20240913084433.1016256-4-anshuman.khandual@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 13/09/2024 09:44, Anshuman Khandual wrote:
> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() but
> also provides the platform an opportunity to override when required.
> 
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Hildenbrand <david@redhat.com>
> Cc: Ryan Roberts <ryan.roberts@arm.com>
> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
> Cc: linux-mm@kvack.org
> Cc: linux-kernel@vger.kernel.org
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> ---
>  include/linux/pgtable.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 2a6a3cccfc36..05e6995c1b93 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1060,7 +1060,7 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
>   */
>  #define set_pte_safe(ptep, pte) \
>  ({ \
> -	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
> +	WARN_ON_ONCE(pte_present(ptep_get(ptep)) && !pte_same(ptep_get(ptep), pte)); \

Suggest reading once into a temporary so that the pte can't change between the 2
gets. In practice, it's not likely to be a huge problem for this instance since
its under the PTL so can only be racing with HW update of access and dirty. But
good practice IMHO:

    pte_t __old = ptep_get(ptep); \
    WARN_ON_ONCE(pte_present(__old) && !pte_same(__old, pte)); \

Thanks,
Ryan

>  	set_pte(ptep, pte); \
>  })
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f7129bab-4def-4d64-8135-b5f0467bf739%40arm.com.
