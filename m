Return-Path: <kasan-dev+bncBCZP5TXROEIONAFFW4DBUBHI3ADAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 305F697ACF4
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 10:40:09 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-27ba6712e9bsf2928356fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 01:40:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726562407; cv=pass;
        d=google.com; s=arc-20240605;
        b=OsnHYm65A/i9VLyAuYBpK7WCjlf43T38v/4SgIvMmXi4AomywFPQy8pXYpyfxrmfl1
         Ifg4Nr0uflnFQSvlrWW776TRFb/Z6LICJLzjL/7Aq+P2Lct9YcVE68FmrBDOQ9bhEVzB
         03fpk0H4mIZm5KiIZvV+iq/ke0iobto0T25Uky04fGNk509QKTsNmxZAUFsfG60RU0T7
         iqfrGtxzzhwCOh2R1CeiTr5qweLIbZhqZ7ROgbpBLnYGWGkWjmWc4V9TnyERm6UuVF2+
         UMO5u9g0Q+3NRpxPls80CdCwEosbw888vm71dH+k8/Bf8PlvhKKmEt401c7tzph8kQz6
         0w5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=W6j5T6JXwHBrFXA7rG97BuzP5OHYAjjv86q/h9A1grg=;
        fh=y00EWZbC4EuDf7XZ6EOQXrZSOu+gDPuKn0Cr11ODtXU=;
        b=ffYIc/KHYT0dMyxCUFa5GeuDFVhy1UmKWjwh8igXzuu/rF+MGUkhLT4Wpytg/V9g4h
         xmneLhxnLuo/ryXDF6malSbrs+zcrHiviVhcRYmL7sdGMJY4RykhPi7hi0c/IRk+yhFo
         k69+Vp3sOVSaL8PhJxqSctUVJX+algOf0Nd8tI0YyHATDOIg2ShJlJJGaxc5UKH3amBM
         +ZtaqqlxixjDBNrV/707Ps8AfXUUs/jst5TpzoEa/3Al5+3G6t3KRgUoYylnxbATjRMr
         oGhlw+ulqUjaUbsDTwRGqIiuospz29+jQ/25C8k7ybrmhOeKfHxgGTz8qxndccblLL0F
         SNrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726562407; x=1727167207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=W6j5T6JXwHBrFXA7rG97BuzP5OHYAjjv86q/h9A1grg=;
        b=mOZTxexbrDDXy0Udau/Fw8nbkeIje65HatvGHw62uBNeZqc53+iX8NqW/6dmzNKL/r
         SSQ2TJQuubIDufWORgmhGACeWnKAUrnKZdHsnCnef1a7e7c7WHqC7XiFkqXkRwYNWEvg
         Jx6tBJwT3srgGDEzL51caT0zBtry5Sn2eaNdZz1DeBddPJBr1kGpX32emorD2zDxs58Q
         kutVBQ8Rq+6EjIDhavacKjePo3IRzoBmj/rOgw5CqGrylQv5bazNCWuabho3l/za9h6o
         bz4/tPJty3g2GTHGVTCitRI+F6WK7RaqE5dYVpnNsm7BS6iqF4G//bjV3B7jz592SK9m
         2B2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726562407; x=1727167207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W6j5T6JXwHBrFXA7rG97BuzP5OHYAjjv86q/h9A1grg=;
        b=wxl5ovUt7+GZnV4WTGQEcj/K/x2DNbrssbvJMefhYeVN+zXv3YwWJ7pez1UpwphHLI
         zOz77JGcDkjivxpeSja9lOcjxdFMu2T7FCZKtLdMdWIo9/tQ4ACWR/YlM1gdDBfnuith
         PWnDm0VWR53/Fuz0z7wlESkGZb7gODPEn7PUwRAbfnNLRWC8yNNGj9sUs3W9WpawAhaf
         TJcvazdmW93UVXTobp8JGSZwNy55tiqbM/rT2kYIXgdQ5LpruI6F5DQyYW80RohmrS4r
         gLczE8plibofuBJJmNmIdTIz8K8IfIep2/IXgcBgoZ1P83lDMe3yCyHeO23WxDdw58mz
         lufw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhSFs00himWU/jTUo1vJN0P5bGaQzx56k4py+OxXneEOyPe0s3VFJH8cS8902DeTUVaG85jw==@lfdr.de
X-Gm-Message-State: AOJu0YyO5gMrS4VK/7O8PzT7R4uXJTQEG/eYRp4SrlB8iiENu8Sb+CbN
	UWicrrqGD/CeMuFYTT3GFSqyEubabUeJvPXSIRjambtEt0XsqBOZ
X-Google-Smtp-Source: AGHT+IFUcbl83o+8x+VrXRXxiP9uqdoSVINPvJsqWcnpnwIZfzxkUdYDCZSAlgl7CKYlaVKnH5IdoQ==
X-Received: by 2002:a05:6870:330b:b0:261:360:8e26 with SMTP id 586e51a60fabf-27c3ed6897bmr11092138fac.0.1726562406977;
        Tue, 17 Sep 2024 01:40:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f811:b0:277:c40a:8a68 with SMTP id
 586e51a60fabf-27c3a805930ls3266479fac.0.-pod-prod-03-us; Tue, 17 Sep 2024
 01:40:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWNzn3i8kpFkcABX7qvmKJmRog2l2+4nmA7UjBukuCDTY1NSVTjdESA+eG6iijiFO+RcVsQTE3ecI=@googlegroups.com
X-Received: by 2002:a05:6808:23c1:b0:3e0:4076:181d with SMTP id 5614622812f47-3e071a9315cmr11275677b6e.8.1726562405068;
        Tue, 17 Sep 2024 01:40:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726562405; cv=none;
        d=google.com; s=arc-20240605;
        b=hIwyhfMZYEqA9IE2QWWmcBDyTkC6NKvn+V0/GWRPJny0sro4tGKRLYlfjeHzOwr5a3
         hmI31ahJ7KNs0Fs+pcB+yQ5Tnsow/aXaMYfwtdMdH+UMC6PBUdLATc1gClfa5RknOw9j
         OntxZh1cZxlaAxTmpKcZX4p48/DdV+lbl4I9FKtPmiAedg7guZNahSqMuihojY2JNXJy
         NGaxcIAL/9pZsFI85AXpx51aGje0us55u2nDHVTiYn+ubi/8lBSEE7WuCDodljbDb1IQ
         YuiY4YOBH+fejO4c3NYuJBo6tt2LowLFHEiT6YqYXf50R4uUY7DrzQLy+FgR4KdvDCvX
         FtkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=qZxKFIEkaG0cqASqRcAUn2WjBLK0YX/S8/dHkMtk/vA=;
        fh=4m+ZZ+HsfF5bge/phhit3TYIOnKXtrl1PtGcdJQd8NQ=;
        b=R1Wmb6ckCqhP00DlzmE6BOsmutsfevw/YOeS/cHIZdwuqxl6jxm0pBBLXsj6xMav4x
         9ajtmru/nFCV+fUNJqA5wpuACLSkID6i+VjFshdAcYr0UmyQb9GflOJJa17Ucwp896xO
         kVA9lBwehoYjRq4eeemVRjEdIlIeds4u+2DgdjGvu97NsDsjbI55yXsCmZ8m/gUJTuVP
         lrS279TER8ztu9pkpD6n0AcmmOY7t2CyZu22V//alHhGJyJzm6oIqcOr5n/fyFCPotiE
         yKosjSRSRHlY67BoMAJ2ZSo7m4lPDLa3Km49/P6SecfaajDSu6Tsv74jwRke1Wq+jbNT
         YrSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 5614622812f47-3e166d35ea5si274768b6e.2.2024.09.17.01.40.04
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 01:40:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E3231DA7;
	Tue, 17 Sep 2024 01:40:33 -0700 (PDT)
Received: from [10.57.83.157] (unknown [10.57.83.157])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5AF643F66E;
	Tue, 17 Sep 2024 01:40:02 -0700 (PDT)
Message-ID: <6800a37f-8a37-4a9b-9e22-a78943d1ecf7@arm.com>
Date: Tue, 17 Sep 2024 09:40:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 1/7] m68k/mm: Change pmd_val()
Content-Language: en-GB
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Geert Uytterhoeven <geert@linux-m68k.org>,
 Guo Ren <guoren@kernel.org>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-2-anshuman.khandual@arm.com>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <20240917073117.1531207-2-anshuman.khandual@arm.com>
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

On 17/09/2024 08:31, Anshuman Khandual wrote:
> This changes platform's pmd_val() to access the pmd_t element directly like
> other architectures rather than current pointer address based dereferencing
> that prevents transition into pmdp_get().
> 
> Cc: Geert Uytterhoeven <geert@linux-m68k.org>
> Cc: Guo Ren <guoren@kernel.org>
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: linux-m68k@lists.linux-m68k.org
> Cc: linux-kernel@vger.kernel.org
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>

I know very little about m68k, but for what it's worth:

Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>

> ---
>  arch/m68k/include/asm/page.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/m68k/include/asm/page.h b/arch/m68k/include/asm/page.h
> index 8cfb84b49975..be3f2c2a656c 100644
> --- a/arch/m68k/include/asm/page.h
> +++ b/arch/m68k/include/asm/page.h
> @@ -19,7 +19,7 @@
>   */
>  #if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS == 3
>  typedef struct { unsigned long pmd; } pmd_t;
> -#define pmd_val(x)	((&x)->pmd)
> +#define pmd_val(x)	((x).pmd)
>  #define __pmd(x)	((pmd_t) { (x) } )
>  #endif
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6800a37f-8a37-4a9b-9e22-a78943d1ecf7%40arm.com.
