Return-Path: <kasan-dev+bncBCZP5TXROEIPLAVFW4DBUBHK3ZI5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0228197AD04
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 10:44:41 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-718d6428b8bsf6894826b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 01:44:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726562678; cv=pass;
        d=google.com; s=arc-20240605;
        b=gKFyPruClD4aXR2svH3CmjPcF4EsbYzeezgICZ41GOHkirvWs/+AmVNntbclhaVy1o
         t+7Hnvlbhyl3uejMilVUdTS1w/SsFnkz4mt1/rpFsRO1B1h5YXpG1IWmtKKvbMrEEK7b
         6c5uwMY68oEtXgMJIfVRwh08hbgPlNnaGG9dLiagO10wv0EEb26hQJNfSYr9ItgmDuoy
         2CFxV91fpbyZBr/tYnm7Zwtn4lGGTlVgeuozscfQDz2vX+pHw5LiOe0tlfqMnj3X9zVb
         aIS0T0gGOsi9xTNSxNLQQJlHosz8SRUngtGakqgwvsaxuxdL1kCfpW/Wmp+W5R9uAp80
         0jFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=4EINoM/NM2r8F+ZMQUO4qW0vdPmLjatPfFSXtiIoI88=;
        fh=zzKyPrW+sQz/4nahronU2iA/rK4AqhwmWM0t0LzI3aQ=;
        b=HR0TQpyIq8Qg77jqbh13zktu45RiHP+h/ENcK2wOImy4QQyhSViuGasnbCDDR5EsM1
         qlO1e1SMum4VVNVsv/WqT+XvtsURzUtATUUOM2XkHuY4Aua2IB87lj2v2lx5lgr+kJ5V
         ignoW2LftQ69SzG+NBGGuKBHomwtV11u+4juLnYgVLxhDg98ob0Za6HZFwY1LFI1/Zdm
         XruiaGqeEdRqdAP8IskWj2pt39Ahge0WuPk8o7p58FBJEupd2VLWCy0lA4hNQKRySy9V
         DsVUnzIOJ1KVlAySUwvYaG3eT3LXbT4t/8BSLL3fBNlhtW3Xp0BQOfBbv9xcbdMywFIu
         SdIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726562678; x=1727167478; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4EINoM/NM2r8F+ZMQUO4qW0vdPmLjatPfFSXtiIoI88=;
        b=OWWfBoeF2YJsQ2KkXFQ0nWZ79JM3u1LPubrQRGDHguMqBR7ywOkUaGUIB2hQf6GYmd
         sohoAvrBUbAg44sHw/Pt7gRZMNRIN/ELpCY9rCtY9sus7HErAc0xcFTDlWVHymdcJVyX
         NR1DQCLOtbdzPpDyUMkDZ+2V4DlYmwNUgvKLWmbtOUazjY9bIa3yavgs4L/CnFvB50zK
         wVg63ut76DJQwKvRA393UcQ8U7P0CAY1qietVXFrE7svpmhqrgQGArWI7wuQu6ASAI1h
         C2vlLD09iOaIGNJjpV2xsSAgzjmG9IxUxK2800YuxMJhlvZCMxxOzLt2fdTV1ojbu0Ww
         Ok9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726562678; x=1727167478;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4EINoM/NM2r8F+ZMQUO4qW0vdPmLjatPfFSXtiIoI88=;
        b=QEx8mdr+o/m1QdXxUVe/eTCKy/9n5zmPWh6fcafrlDf8J59EcpdOzqJYxw93ti7wFm
         Req8/ASqtZwcGTZzwGcLjgvA2P0G+J7HTQ25vSlkHlWceGb+OOIJVst2X+bOaTZTgoGe
         viMvW8jEpyoExj4Jz8EfrXm7ovZWvJ5HPco1UZQpFj0yBYhj/TDKeyDu1dleRONBR3d9
         hs9LLKD4bMEhmM7KA+5kZ5NNo9e0a7f7jWxy0OQAy/nuBHiaK6ZlRZ5ktp87ysgDa6bl
         niSjppGiLzzjHZXH5Ez5xAMh/3Irb2OoqLgl0Aw2dnLHq/F3kt6DtjeHVmurg12Hquqh
         u4Bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXq+jdrWTld77mLz8GwaOjP6UM8Um0nJqnqip6qDxNcUNRuf1CqxYjW35kUoB/M/c23k1vF7Q==@lfdr.de
X-Gm-Message-State: AOJu0YzGwKLfmrPUA7eAJja8gXg28oSxcbp0Oqeh9gdtSfM23S7huhvP
	f1KkNvdvAwsKtxzM544slNcENwJ3K1nm5d1Nn70aa6NFNdO5AtrO
X-Google-Smtp-Source: AGHT+IFpqBL1HixOhHpAyvQ+iPxJSLLRo3SphwQOjvkdFqLpv5Y8MhCSjHtetfHzS2LysG8dYRgD6Q==
X-Received: by 2002:a05:6a20:c999:b0:1c2:8af6:31d3 with SMTP id adf61e73a8af0-1cf75e79c20mr24298312637.10.1726562677591;
        Tue, 17 Sep 2024 01:44:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1804:b0:714:37eb:eb5d with SMTP id
 d2e1a72fcca58-71925a0c623ls4619221b3a.2.-pod-prod-01-us; Tue, 17 Sep 2024
 01:44:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZWwGCJVQZC9gYc1JcOOxhqP5nbu7dqc21B4+4s/1oHEwk8totwADpC94j7T/BqwiVogcPgzOymrg=@googlegroups.com
X-Received: by 2002:a05:6a20:b40b:b0:1cf:359b:1a3e with SMTP id adf61e73a8af0-1cf761f9914mr25178098637.32.1726562676365;
        Tue, 17 Sep 2024 01:44:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726562676; cv=none;
        d=google.com; s=arc-20240605;
        b=lHV7g5lUSbFAiJHzQu+WT5VsAnaNIq2aGG60LDI5ADsIqmstP8cztl2/ctlwrEULNL
         0kU0k8cQKeyUaW2MOFhuVLw0+hR1xmzme5GRApG/A+Frvv8pbZv1GuEVxevYUJcc1hhc
         LvPgs8dogJFTLwt/C7SuS/Cdq/GgEVZc3jzEV+cVe84XoNulSe+bqeAMjLUHLlbtxK7+
         pXfxlnAgDOeP97odgDXG/CO8JEumPaH3IMSto/QmuckPVL/hOuxq5bmR1zzYwH0H/0LJ
         8MdAyF4yx2R8BjU8/E/pgOy0aNQCKYtmLMk/S5Yk4Y+XcnTKxJ9vLaRbsZoqM23KY0Q+
         JzDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=8MoBY2qcuoA5Z94WXm5yDqlSxud4TgMUS+E92tZ4kSQ=;
        fh=DpilCRW1lPr7EFgXA81j18rCwvjwIZ1eQiX7tELTdDE=;
        b=KtW8C8pld4RyjvktEq3s2FbW64Nx14k9TTbOnqJTtYHSqP4fgTefjWl+NFRlAi/NgQ
         Toxr+hdYNA7+T9cN+YT7mBF14+ZS4W2AA8XyRBkdmK7XhKaZsuZcV6Yg9qQVSWy5SVba
         LUVbyuoPENK0YPPW4dU0bppunMNr7RijVONez2yhSE+uQ3/jPvpCSOfyIVKiWJeyerkb
         Ydpy0z/u88Xq4F/nDggbWMxSyK9nqntwG2XcFec1nPrdzRU4rxRq1tNf601q8Q9UWd9W
         Lcttc7oWIKg0dTM+EKhpjCnXosJYgU7tBqWjLV2bmlPn/D9LIVI4la4afiDyx+esXtQC
         /mnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-71944bbc35dsi273432b3a.3.2024.09.17.01.44.36
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 01:44:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F0B8EDA7;
	Tue, 17 Sep 2024 01:45:04 -0700 (PDT)
Received: from [10.57.83.157] (unknown [10.57.83.157])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EBC1D3F66E;
	Tue, 17 Sep 2024 01:44:33 -0700 (PDT)
Message-ID: <45084868-0a09-4c57-81b0-f59a1ca292db@arm.com>
Date: Tue, 17 Sep 2024 09:44:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 3/7] mm: Use ptep_get() for accessing PTE entries
Content-Language: en-GB
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-4-anshuman.khandual@arm.com>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <20240917073117.1531207-4-anshuman.khandual@arm.com>
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
> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() but
> also provides the platform an opportunity to override when required. This
> stores read page table entry value in a local variable which can be used in
> multiple instances there after. This helps in avoiding multiple memory load
> operations as well possible race conditions.
> 
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Hildenbrand <david@redhat.com>
> Cc: Ryan Roberts <ryan.roberts@arm.com>
> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
> Cc: linux-mm@kvack.org
> Cc: linux-kernel@vger.kernel.org
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>

Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>

> ---
>  include/linux/pgtable.h | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 2a6a3cccfc36..547eeae8c43f 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1060,7 +1060,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
>   */
>  #define set_pte_safe(ptep, pte) \
>  ({ \
> -	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
> +	pte_t __old = ptep_get(ptep); \
> +	WARN_ON_ONCE(pte_present(__old) && !pte_same(__old, pte)); \
>  	set_pte(ptep, pte); \
>  })
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/45084868-0a09-4c57-81b0-f59a1ca292db%40arm.com.
