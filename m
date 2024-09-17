Return-Path: <kasan-dev+bncBC32535MUICBBPVTUW3QMGQEALDSLUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 1762397AEB8
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 12:28:16 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-458278ff48fsf122897651cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 03:28:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726568895; cv=pass;
        d=google.com; s=arc-20240605;
        b=BR4KyFAbHIt2MZa4zKCc4RQBFpwertWgH/QByzSqK+uJFBC5H8P+6xbzqqADmbC7fR
         Ii2pMtc/6009byTEVbcWAqNNvEtKiOEFxCq4RlLel2niy92wPmVt6TRuuxNKfjA89t4E
         /xwVc6BMeL5hKoC8J7ddXW7g+psFDZEBPuZdlyH3HDMXf9GJQP6D86sXSGRvCdSg2Qcu
         IeX052kmx+FUzlyVlRCermegIM5DZmnGn7Djhv+HfPn0Nf4v+3weQ9Ba1OyvfhZaOgrB
         te61F2w7VDn2N2N3WUhtPI2O52C0xbG5nljMYftT7euV7jPblhDBcEXowGk9Jl4vqO7G
         PE6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=7+NQ1opATbHPOry130KuACfrTsn+KP31N2Meu0KPa90=;
        fh=QO7n9N+jEFylDDrNGW6acsKk2lK9ENGzEvrblQRpNeU=;
        b=TOzzLPTnwKoNPKOzSMJ1oePk3P/XREc7mEvCWA8NX1V1hYZ4lHkbQagTByjBFPhEzt
         KVyTxzQWIS8SJZlIfL4BA/pXMarnabRhQ460jgxnvvemYI+sAIzyjHN9M3oJx5vMmPmy
         TurNB7/bovWyH7imO2upCTPv5TrgfB18333e+VP989JSjpGljpSrLqJMfLxu62TksJWr
         cjbJRzcMK/K/xomJPKU/KvK2sWdTZe3hRJxpb8gbUKyo1KcxQ24LhxYww46d8EC5tY4u
         y4xkhwAmAxZN66Rs19MXdmBDDGdexeIkyJPhBrrcZMNunRvZBZYpeGJjVW1sHx5APlXf
         ShiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NjsK39U2;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726568895; x=1727173695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7+NQ1opATbHPOry130KuACfrTsn+KP31N2Meu0KPa90=;
        b=SVXCI2rZil902OSIlD5uKIkrNb/7W2j+P3y6JQSUYntrpdjx2wTOiTlDJWuht5LeYn
         kkz08EudE7ok/H4NG+2fa0lUsEsz9B2XIq32bfzPQTWlapsws3cbOAPUnKeYj57HLXZs
         VMjLFSPGyPUYnw2+zagsnadjFKTNnm/ZDNAfQ5zox5jCsUv9iuseXGkVArNEAmL1MKkM
         A+/uNzSyUy531aJ35lU/pxLxHu4BifH5Y3bltVAGWRGO6DikKjv9VUQRIKayqMYm1AgD
         uobhn5f2YK93Jf0oPFwyfAYRnwIUhX5ope0VT0YUZqnUdG2ZDuv+aEsvNSdpK9+huGAC
         SM3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726568895; x=1727173695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7+NQ1opATbHPOry130KuACfrTsn+KP31N2Meu0KPa90=;
        b=isaIHlFmft74ZXeWhcuHYDrhidxC493XG+geNZZ9/v0Zu/7B1Q9za6GsFuWQSVugHD
         ENrQ1D+Rdq7vLynpQAvLF0duBaI+Wes0qTAxDmch9HoP6bzTrwjnZkkIEASLoywGRHOq
         IV36zbnNbCdA6cZFieOcUx22Z9DZZeXHgAbTSiXxCMgOi/B8RJNu7dyURWrn190hUJ6F
         tlNz/k93ouCR5Hp0lIE9AG3K8APX7ILd9OvvdA6NZYOTdxoPtg6t3NTRRdyc+SVYxImr
         O3qJzNkDcKNAfdYSFsmZmSn4w30wm3wPePGdDAkxfwHWOI3VEj+Cyq5k2R0/aPDbOVd9
         Nmpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKvbpHfKleZn6J36JLRdZXL/MIvXOGq4UvcKHgG5Y3Lw9yT8L5kTw87kR3kUc5WINhSuNY5g==@lfdr.de
X-Gm-Message-State: AOJu0YzuD+bjnHrrSOIcq/ZV6FHuAne+FbjPSk2Y9KN+gMhxDp7IVpdz
	i4tcoON+zmcyzc3CWdOAnGIhaZggpl10qZVznWvtxP50d/0EWNtR
X-Google-Smtp-Source: AGHT+IH8zQ8qN/XLbiYv0/oJJV7CqCLcrA1uuPN80sQYLVQVwqEYvsqxdbWznvVi3I/q+k5+F1W80Q==
X-Received: by 2002:ac8:57c5:0:b0:458:35f7:3952 with SMTP id d75a77b69052e-458603ec0c3mr295650641cf.40.1726568894545;
        Tue, 17 Sep 2024 03:28:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:14a:b0:458:27d0:f7c4 with SMTP id
 d75a77b69052e-4585f7fcf23ls53789131cf.0.-pod-prod-09-us; Tue, 17 Sep 2024
 03:28:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWotkEq1Xg4Um81FgHYAy8qKzJaydI6A/SpvrHeGyLbFlU1nTb3kNOBq6OzVgM+K2ywmpuOAsqQWxM=@googlegroups.com
X-Received: by 2002:a05:620a:2988:b0:7a9:ccb4:b737 with SMTP id af79cd13be357-7a9e5efa336mr2984589885a.14.1726568893866;
        Tue, 17 Sep 2024 03:28:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726568893; cv=none;
        d=google.com; s=arc-20240605;
        b=SbcDojIFO2Spi2el0kCGrCqTsJX9fndnqYmnkKC9490lQxLfh4eGbqM0SEvliEqToj
         bHstQu2tZATcsmf665MG+X9zdfe0jj5C+IXEooK9CtmlMCE0DYil+/VMRFsVnYFzzSyH
         0pABzE8MJZkG421YwP7Z8139xxmE004pTweX1fm3Qu7+nNDHhx0HBLT9jxXDQkt5KcPl
         eEvBeDOC/Wnd9EvbwjMP0k+t+99yj4HPf8qtjBD0WHAC2f4pUfmDeXf6E2+myuIs2nJb
         9v+655V4bNA9mQHCz5PFQyi1L8D3Eupx9trnHBW0Imu/wkstcCRihWSZVX9RudLj0QZ8
         J8fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=O4o9FiZpED9lrRymb/v3EzHKuXxo+xVGDeJxVxBPzk0=;
        fh=ut+OhPlIOEJmst794jiBwT5d4mr9tNeOMyC4q2vpFA4=;
        b=gC9wEz5brvEeHIodE6tEAx2LKBNVvkkNHD1Flj4iijXEKAJVFm/E2dxmYh4FISDzBX
         OSQpt/GOqG4accfWXfbdEkuZQlIenK7HZk33vUM+AOGwNf24cYng4pSJqPqw1LEn7cQI
         nBUTT/CfeCUfaajCvUyCoX6bqEDkQG63HucqDiqO0VW7mrwDzEiXYGOg03f3USTrzlLJ
         0GuRg52S+59tb1M8PL3GjN1ZGRFDvur7K7mwdeG+5R8IjMmR0xcFZyD4HIrU2zn2ODn7
         A2eg/2H5nRetz4uE8JozLEE1ty30DetttUNwhnow6BgYxsW8q3ugv56oJoD1snVSSDiU
         qDPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NjsK39U2;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ab3e964016si27019185a.1.2024.09.17.03.28.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Sep 2024 03:28:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-lf1-f72.google.com (mail-lf1-f72.google.com
 [209.85.167.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-100-tL5WyMi7M6mGK7oMxc9F-g-1; Tue, 17 Sep 2024 06:28:11 -0400
X-MC-Unique: tL5WyMi7M6mGK7oMxc9F-g-1
Received: by mail-lf1-f72.google.com with SMTP id 2adb3069b0e04-53691cd5a20so1769128e87.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 03:28:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWuAP2/vIBaxrewizQt81TKhzHjethr8i2U7YFu1ssTSENH3sF0Lqk5+ga9N19K4R2wVAnnxugjL64=@googlegroups.com
X-Received: by 2002:a05:6512:110d:b0:536:5816:82ad with SMTP id 2adb3069b0e04-53678ff4b27mr9247035e87.57.1726568889437;
        Tue, 17 Sep 2024 03:28:09 -0700 (PDT)
X-Received: by 2002:a05:6512:110d:b0:536:5816:82ad with SMTP id 2adb3069b0e04-53678ff4b27mr9247002e87.57.1726568888853;
        Tue, 17 Sep 2024 03:28:08 -0700 (PDT)
Received: from [192.168.55.136] (tmo-067-108.customers.d1-online.com. [80.187.67.108])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5c42bb49a4esm3560295a12.9.2024.09.17.03.28.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 03:28:07 -0700 (PDT)
Message-ID: <f9a7ebb4-3d7c-403e-b818-29a6a3b12adc@redhat.com>
Date: Tue, 17 Sep 2024 12:28:04 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 3/7] mm: Use ptep_get() for accessing PTE entries
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-4-anshuman.khandual@arm.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240917073117.1531207-4-anshuman.khandual@arm.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NjsK39U2;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 17.09.24 09:31, Anshuman Khandual wrote:
> Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() but
> also provides the platform an opportunity to override when required. This
> stores read page table entry value in a local variable which can be used in
> multiple instances there after. This helps in avoiding multiple memory load
> operations as well possible race conditions.
> 

Please make it clearer in the subject+description that this really only 
involves set_pte_safe().


> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Hildenbrand <david@redhat.com>
> Cc: Ryan Roberts <ryan.roberts@arm.com>
> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
> Cc: linux-mm@kvack.org
> Cc: linux-kernel@vger.kernel.org
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> ---
>   include/linux/pgtable.h | 3 ++-
>   1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 2a6a3cccfc36..547eeae8c43f 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1060,7 +1060,8 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
>    */
>   #define set_pte_safe(ptep, pte) \
>   ({ \
> -	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
> +	pte_t __old = ptep_get(ptep); \
> +	WARN_ON_ONCE(pte_present(__old) && !pte_same(__old, pte)); \
>   	set_pte(ptep, pte); \
>   })
>   

I don't think this is necessary. PTE present cannot flip concurrently, 
that's the whole reason of the "safe" part after all.

Can we just move these weird set_pte/pmd_safe() stuff to x86 init code 
and be done with it? Then it's also clear *where* it is getting used and 
for which reason.

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f9a7ebb4-3d7c-403e-b818-29a6a3b12adc%40redhat.com.
