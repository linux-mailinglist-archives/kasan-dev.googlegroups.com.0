Return-Path: <kasan-dev+bncBDGZVRMH6UCRB6HD4XCAMGQEPR6QZGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D4D4B1FE5A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 06:30:50 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-23fe984fe57sf64462405ad.0
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 21:30:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754886649; cv=pass;
        d=google.com; s=arc-20240605;
        b=NbjMGdHOmbUsK1ziJ/aNLHqGt4QvThffga7RETInWg//kttOUCeSIwNSI7UUOKI4/f
         quhaA9uf6grqgRdBp/G3ITvJvu4wWXtg+mVros84XSFVyRaZV7QwwOwa2al/tlujLy5Y
         K61mymrQ80HL7BoAMejmB7+0HKlaV38NRhsVXhlDaQjy4NhqZUlPvZjT88Uw4S/MoQvh
         YnZTS5TOVsD7m+3IwmJydW7Q7bn9JeIyWA8VpF8n/NwLdP6Gx4QeIEi/NKVyo+3ygsIF
         HZx5b9vrLobO5bMVNcRku00+ebZuhgSwzkddFHl8lRqftxUsTNO0G3/eZSXg1oXdaTJQ
         cG5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Twly8rreVemD6A4V2IGJt4JI2opIeCRSLHYAR5ixzF4=;
        fh=Zc3q/MGlZD+KGiGJsvewi/ZgPIz/3X2OrUZMJSz7e40=;
        b=CZJsUiClJqNyeliwCTkjHK6Tkp9JJDCniqbF+3X7EjNAqfyhDAljN23h8VpmSakkRf
         H+jOJFLOuPgI5vjTslnPzLUX69vK23+RM+FVR03xYDRZC50Jjuidr0NkDxpqUwrN1y2e
         jXWwnw3x6/Q47W+1U3OTje0Lmo8xI9hYyuQxwWXDo+DgW4evOuX8RVxCMnZRfrvY+TWc
         7hRHns5MwtiicT5oIslrffcmd/9XXRvj4/wdjWb0aidhmqIH+rvisaNwHjftYYNHItEb
         1l8Eqxyc3VwqPcajWz+G/1JVdjrsS3M5E4p0rt8Tes2K+LpsskmPrV4nT/Lb/bzCMxZB
         MGYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754886649; x=1755491449; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Twly8rreVemD6A4V2IGJt4JI2opIeCRSLHYAR5ixzF4=;
        b=D2DAZfr9GHBMPL70K8DYWTxIQEN9OO4gnEUL7B8N5/NkAAtGMZrijJ7hzyoIr3jt75
         kFOPid3W7HBoCUhZ2X7+ckkDyTwU35l37MjrWcFwuO/5jK11OFrPO5HI9SUkYrS7gzK0
         iz1lvhrPcHjbe+IEehbfwgcpCoPrKOmDrK86LBXyh3yZUNYFLNBY90m6ZT0PAFrmsbO1
         kQ1AA4T+ZDA1S3FVW0MnAkIftwgIfzy/JEhEq57qQQOLc9lzReoxP0L+bejUjOOl2UKq
         0FMSY+WGfsaHlZQHmkyoPSy7V8sdN1PxDBAR78f1V9db8r2EF6KrT867sFqrHbUZsCR/
         kSdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754886649; x=1755491449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Twly8rreVemD6A4V2IGJt4JI2opIeCRSLHYAR5ixzF4=;
        b=Ks0xph5oQ5Ui0QVxg8i1nMEca7/EFtKSFtt4mA2p/1qOFFD1Xwu52P6OpgxAFQNx/i
         3BrNZ7rpQvEv0Bfdda/mDemKeRLAXAfHPBLIV2YqLd6RMbZyWf2e4WvBby8hogIzZSGK
         x5lGZFC9PLeag1RT5eS5h/1xu/dM10qytqz2gnpZFw7uwbRzSfqzKi2iTPt+TOQ3ZPvg
         E6jJQ8crqsAGIM+QYpuVg+H6cKiPmzTf71Ey+HQOYBz1CP9wGNjBl2JatVYzTSXH75rR
         h2axkuNjwuX7am7xkXxQ6K9H+4iQivvqdT5ogU3p26Y43PCdjba8AKSG1gZpalIvz1hx
         nI0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQfqFAwNiHstEAr+at2Wm36rhYq8zG6AMVpWkEYPpFBsK+LcKs3SLwmrwKhfZgDNOgzhlsVA==@lfdr.de
X-Gm-Message-State: AOJu0Yw5ls3lmVLDG5glEULzZSMZr140EdMOqzTpOL3IVivzBxBNdwr4
	rK1zYLFbdbBPuJiBvO5DbUVa5iNjTHuc1+DQHl3WLMFbnjJlQmzvKPQg
X-Google-Smtp-Source: AGHT+IFAEJmtByXrwMkgMD5i7pYM1MwLFxCG7vGVq9JUFbhdyRwC7wz8VZOAcJNZZ4ZZmAY0ZM8Fpg==
X-Received: by 2002:a17:903:1a0b:b0:242:9bbc:c776 with SMTP id d9443c01a7336-242c2297161mr162496445ad.57.1754886648723;
        Sun, 10 Aug 2025 21:30:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZee5XIDSTJy4nNNgtxj9qLZNomD433e8IvThDNhsxpL+Q==
Received: by 2002:a17:903:3c6f:b0:224:781:6f9c with SMTP id
 d9443c01a7336-242afb99c40ls41928015ad.0.-pod-prod-08-us; Sun, 10 Aug 2025
 21:30:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqGwQBdbXZ83h3sE/NPsiTDY8OJxwhzmvK7pW9GfAEWhPfkreEAOJr0UpVaOEF55wh5wSAI1fchiI=@googlegroups.com
X-Received: by 2002:a17:903:2451:b0:23f:f3e1:7363 with SMTP id d9443c01a7336-242c203dfcemr144158955ad.23.1754886647328;
        Sun, 10 Aug 2025 21:30:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754886647; cv=none;
        d=google.com; s=arc-20240605;
        b=cnGN+Tna6px2pPf34Lq2v/8UT0h5ywC53A2ihjxKaB+ZKNaz1QZdngFd0fZjbUkqNY
         oTno+2imKFJZTFInSKsoZx7eFTd13H5VCoQgRflqA0DZAXNw5DnE4eYASx3NRvff2716
         YQutnT9Kj9YzXmWzjoLUnb2i9gqzwCcapvkudwoTNLu8KPShQq6wjlSbJdN6OpJsYyV2
         PDR40NSSgTUA5FCYS2+SqrC1w/SD1p9s8phD0UMkVipdaFk53gHA7bqeE0hTGo9Gwjsa
         pu/NSI3wKujmn2AbfxdmJmq0LnHKylnxKv8ghyC79uDOfbuV/7X9hQEZZPfy91leNOI5
         gLRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=m15gzroEbAXR3x36rb1zzxajxa7shxO60kZkG+X08iU=;
        fh=r8vG/bvgBDPJ1PgjXPKBcnldoIqFZiwTvm3l63KEsng=;
        b=VOJ3SNyrf+YkQfxWkRYvHg65KCeTH/86kdOdNaTovBPIr8H6o04HVRktTglWgKawED
         O6c9IHHk7wzQUWhaIoKbHa7OXxDNOd/ku7olzjh+nOoHlOhN/N92GWwkcQsL9PZarL1B
         fZ43oCiNKWff+JnBrqZHfcPYzwxqXTtO59hIZ5qDVyZrz9yhE9G8PARQ4i2TUNJxuexa
         q2I+KE69AXR09CbFplEeOJs09Xfch4wVnC1GNke7U1tI5MqbBB0qcuRz1uPeV5fs/i0I
         qpOw2AGjMCxL5yLWuaosxZzU59lfazfFHJ8JTxS0Qx6vfR/WUjeP/fjZdwL8s1Olm7bJ
         ruJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-241e893b7casi10977155ad.7.2025.08.10.21.30.46
        for <kasan-dev@googlegroups.com>;
        Sun, 10 Aug 2025 21:30:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C1630152B;
	Sun, 10 Aug 2025 21:30:37 -0700 (PDT)
Received: from [10.164.146.16] (J09HK2D2RT.blr.arm.com [10.164.146.16])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 695A93F738;
	Sun, 10 Aug 2025 21:30:42 -0700 (PDT)
Message-ID: <b33b6dfe-8270-4cee-bd66-1940f86b6e09@arm.com>
Date: Mon, 11 Aug 2025 10:00:39 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] mm: remove unnecessary pointer variables
To: Xichao Zhao <zhao.xichao@vivo.com>, ryabinin.a.a@gmail.com,
 akpm@linux-foundation.org
Cc: glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20250811034257.154862-1-zhao.xichao@vivo.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <20250811034257.154862-1-zhao.xichao@vivo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 11/08/25 9:12 AM, Xichao Zhao wrote:
> Simplify the code to enhance readability and maintain a consistent
> coding style.
> 
> Signed-off-by: Xichao Zhao <zhao.xichao@vivo.com>
> ---
>  mm/kasan/init.c | 4 +---
>  1 file changed, 1 insertion(+), 3 deletions(-)
> 
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ced6b29fcf76..e5810134813c 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -266,11 +266,9 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  		}
>  
>  		if (pgd_none(*pgd)) {
> -			p4d_t *p;
>  
>  			if (slab_is_available()) {
> -				p = p4d_alloc(&init_mm, pgd, addr);
> -				if (!p)
> +				if (!p4d_alloc(&init_mm, pgd, addr))
>  					return -ENOMEM;
>  			} else {
>  				pgd_populate(&init_mm, pgd,

Agreed that p4d_t pointer here is just redundant.

Reviewed-by: Anshuman Khandual <anshuman.khandual@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b33b6dfe-8270-4cee-bd66-1940f86b6e09%40arm.com.
