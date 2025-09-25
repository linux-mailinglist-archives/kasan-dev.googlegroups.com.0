Return-Path: <kasan-dev+bncBC32535MUICBBCHT2TDAMGQEOSB7CUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 1177FB9F513
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 14:46:03 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-252afdfafe1sf10848525ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 05:46:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758804361; cv=pass;
        d=google.com; s=arc-20240605;
        b=D6ggqoJC7391Hi9tYVem2+02d3l/ujS/MToC8XVAWPNMRcpQc3yyf5SWfkM1QoNWZS
         6vy0SIQR/n4F0NozVsZ6hLZFLkzRZzb/gvhExnhk0M7jBpIHezY38Fk+HaKVO/4gt8h0
         IAhaq/S5au4HiwBFS360LX8tXR/Vg8Zse9Pf0OkGkUl89n32uaHsPYkOCxCo2lGjsE6+
         aHh5/vEjH21zNN+2jNOFOI0Tpa49MOVwhF5dUia8NXbOm/b/DN0OPMuf3vtq/22wbd2b
         OpdUx8AVTddONPwSa9Qs9sA11b3Ju0rHTBf03hh1guk1s2u7NcfwU+E+XRpqfPHDZnuU
         nK6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=8IwlsUryFdIIy3QeomXFhvTXKvquDir+c5pEcfAg0eE=;
        fh=YRqaNwDbZewkn5FiB64A2fGh/OaZTUUcFjBBGhqi1l4=;
        b=eE4MHMNtAyf4WKM0wjdkjK4dARDubnf74YjFj5ZKzsJ1u5sSbrLgWHqkeQ+4kXJgWV
         YAszYexKxCAt5e9+5GuBeUXIQJFGjdRtpXO9mZQVrHVFaRSUt64jlOgzF2vGMrZ/4wyZ
         DvBmNGqq/wH5s16ROicdvC/G+FvgG8oxjDA1SKEUXcgk3ghXD9qZa1b+cO5W5ag9LN8j
         MMTRBG5NBy8J4vDRLBgWxGMVFAb7w0EL7eroV7kqSxebZcmHOFIWCTefYjbajSdOaqqa
         h2dYeyB1IZxOkY0kCViYfpL8lmOcmhpgwnNrV2hf+bdzmmetqj7naObE6srMviZia58+
         yKfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dz1ckDCz;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758804361; x=1759409161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8IwlsUryFdIIy3QeomXFhvTXKvquDir+c5pEcfAg0eE=;
        b=iZQNuf87PVJImE3nISN0c/4SPEdpao+F9vv6K25z1m/WVVhDzXnYtkCOt68aS4J55g
         JqgA2FMrlR6/X/z3K88n58MiwzdCoRa0X7eqhXdK3F2m/rBjr9fQEk11BTk+NlH8RzX4
         v4Xnea3OHe4m09cZkYLnqb3wduKA5lEuFCExJDd1akKhw+WNUm8JsX18MZkh9UcDnYZ8
         PkQj0Akejw3bhUICUOt5LAo7tzfxaPp2zefxz2eDmXGilg4D4gFYF3xgsVcngVh3Cnp7
         +olwxw/xMd9X50wQFLbyieOPv2+CrImwryzasx7qTeehCMCNU2ToXzB9NDKLnGXPYAJE
         inTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758804361; x=1759409161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=8IwlsUryFdIIy3QeomXFhvTXKvquDir+c5pEcfAg0eE=;
        b=CYCuVW8oluahwm74Gq1tPLTXTyIvhwkKIOZXh/et+VJ5C5yyafnFCRedXloxhWqKUZ
         bujphf5XCoJvEjsDWHHfJLcEb8M43AT7hUMcXEt1kM53L/ZYuFmZ5n3NWlyCxbq8p3zT
         LGP7lDHikKwILzeqzX+tatVc1mMLg5rVvv8AaAA/ZZhc42v3aCkj5HinJI76sLwXIvmf
         So10vQECLkUGs+u/yp/Wm2N5DnZD23KOq/Gmkph6HgzUIb3piDGt5ru6wq7ya2rb6dNk
         0bIPDD/nD43qyUXkPoDmMpH6nvV3embZTfx338nRnZDbFhakkolhEBpU2ZdXcuReTUHH
         BqHw==
X-Forwarded-Encrypted: i=2; AJvYcCW/ClzO8GXEYltQ6UCms8FZkAFOCAnnmkkTC1F+VNX9bHbaogn1tvsa20njCy10+pShvc4X/g==@lfdr.de
X-Gm-Message-State: AOJu0YyBuS+eHUsQYCSFHhDkt5K004QP/nSN39ppoIAa4+Flm9rc/S0b
	aTNkM+9jm9mXEQWfTPfXrrA+mLTvx6onNU9+bE0qruxsEUU2DXk6mC3I
X-Google-Smtp-Source: AGHT+IFFHmJ3EPejan8J6vZR1X15Ualyx6RBWpwt3/UAlcuZ2GykqYCVl0krAFBGKYhU/kgSeWqI+A==
X-Received: by 2002:a17:902:e5cc:b0:270:e595:a440 with SMTP id d9443c01a7336-27ed49e1af2mr43853915ad.25.1758804361191;
        Thu, 25 Sep 2025 05:46:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5vp1mOsv7h1EiOxWuqaZX3f8jgFEkOSibrJNv6s3bu8w=="
Received: by 2002:a17:90b:4ac1:b0:32e:a38e:18e4 with SMTP id
 98e67ed59e1d1-3342a497c2fls1045473a91.0.-pod-prod-09-us; Thu, 25 Sep 2025
 05:45:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6oCFfjsWTD9T3ctaEduWhpyrG2BAqTi4/QGv+NHwywtbn4pkm0m2B9gK2dOXYeeNeoCQF0305xy0=@googlegroups.com
X-Received: by 2002:a17:90b:3b87:b0:332:1edf:a694 with SMTP id 98e67ed59e1d1-3342a2c1429mr2706052a91.31.1758804359697;
        Thu, 25 Sep 2025 05:45:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758804359; cv=none;
        d=google.com; s=arc-20240605;
        b=JFmdkDRc4sMnace6iWR0NNozdOlZq9BBqAngOSXBItPzUnuIMswLKASFSvWP8kZ4Kf
         VzOdiCnSAqB1+DLberwpXWgKD4r1xpUa/Co1Nqg4CQuT60BSAZh2pU63DcteuUup2d0A
         Cni0SFx2Z/7q1lysfkcEaQUdR4ATxufVekGZMuAxX/AwrCRRuBH2WZxFpK1dT8kZbQlj
         PFoxbyeQNxhNktpe+9mstw7r+66KRr5cx4nH3TFpCE+vM8JpuboQiJnAguEZMKgBctZ5
         IGbOaDL+7ZLV3wPiczGmX2UZoedSFiE5UMZKRxm9SGEay3g42mAr0Uz5zGq7m+ncTvBu
         xXww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=tliHUGl1NX2itzYwArqZpvvubj/ojpB0Xta8m0g/P9c=;
        fh=xfi3UgSJCKN+Kg6ZrhDBby4dblXlD4h3S1vMi0gqa5k=;
        b=XeNx2hN/cWOgB3ZFKIBIumsKRG9qwgD78FFV9Rk8ill8eEgvGbMQH4naj9p2DwSjAY
         wTesHRRysEZjbrX8dbwrgo+XGmNsM4EiwDQfzufMlSktL/7GlHc4f1n92KkmjxQgfplR
         2qtH1Y/Am/vvAhbhTozmJnsF7NAuvU0fFz9tqlmv9d+dKkmRuOeEoW9RzmR7vkQ844Sp
         APlfThk0NMUGdUNLe4ohO603Jk6inOitcYXjZTZAVZJj1F1Ez+JfmnHC3XgK/lHxURhm
         PSSucuFsj96ce3c1dY4Uu3W2jRMwHGOIWn/pQsdZh385QPMas6siVyTPT01LusadprAU
         zEdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dz1ckDCz;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3346b74286asi66491a91.0.2025.09.25.05.45.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Sep 2025 05:45:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-308-oExgKxE6MsuUWdZxI27GYA-1; Thu, 25 Sep 2025 08:45:57 -0400
X-MC-Unique: oExgKxE6MsuUWdZxI27GYA-1
X-Mimecast-MFC-AGG-ID: oExgKxE6MsuUWdZxI27GYA_1758804357
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-46dee484548so5415615e9.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Sep 2025 05:45:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKZWef7mw61MF1A2Ma4HKJYzZHLHhr0kOGD+Er6nFGO9RDhn0uAkqW2ZIKRQQquPs3qMCnUQibr0k=@googlegroups.com
X-Gm-Gg: ASbGncvmYh0k3MdwfmcWtM7VCgZ6kTYLjJfxstO9owyN1SwWMMwEgu06WGeqysHqJ89
	8Kb2+zUA+ax0AdDxd2xAdo9CEJIQbCFu0cwoBFTXn/2qU7TaRvHYKRv9QhSG5CIsDxwrxYkZxcj
	fhwjZnHgPKLHuAC832umy23azakAEgJONsch0zEBJUMHqtU3il07DH1Kf6eYeii5JPVjKEBPIlO
	EeDVi+rfcOOc5nubsRT8fTv0rZXZuLjFTiw84SjzjbbEUgx9ZcS8+aSk0T4qa7DOZTZ0O4fdifM
	z5jNnDTl9XeIWTNde/1yvJ4All8D1WXeGLLm/S3fSGqypecUn4M7nECiVGn7bSwbbCvC9iE8RSK
	Fbo2FDbzDAaqBJP3ITlzsDUYAioQxN4+70NjnQwLoB1Nk1q1HZKDAzsDTIr6pM6sdUaaS
X-Received: by 2002:a05:600c:4743:b0:459:d451:3364 with SMTP id 5b1f17b1804b1-46e329eb11cmr37972685e9.24.1758804356473;
        Thu, 25 Sep 2025 05:45:56 -0700 (PDT)
X-Received: by 2002:a05:600c:4743:b0:459:d451:3364 with SMTP id 5b1f17b1804b1-46e329eb11cmr37972425e9.24.1758804356075;
        Thu, 25 Sep 2025 05:45:56 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f3f:f800:c101:5c9f:3bc9:3d08? (p200300d82f3ff800c1015c9f3bc93d08.dip0.t-ipconnect.de. [2003:d8:2f3f:f800:c101:5c9f:3bc9:3d08])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-40fb74e46bcsm2945522f8f.8.2025.09.25.05.45.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Sep 2025 05:45:55 -0700 (PDT)
Message-ID: <43ae76b9-14e2-45b9-83b0-4e5fdb6bfb3e@redhat.com>
Date: Thu, 25 Sep 2025 14:45:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with
 KMSAN
To: SeongJae Park <sj@kernel.org>, Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, vbabka@suse.cz, rppt@kernel.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com,
 dvyukov@google.com, kasan-dev@googlegroups.com,
 Aleksandr Nogikh <nogikh@google.com>
References: <20250925123759.59479-1-sj@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250925123759.59479-1-sj@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: lDOYXiOh-gjUL3MW36OCUBjKMqZmAem92fuolgXNANk_1758804357
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dz1ckDCz;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 25.09.25 14:37, SeongJae Park wrote:
> Hello,
> 
> On Wed, 24 Sep 2025 12:03:01 +0200 Alexander Potapenko <glider@google.com> wrote:
> 
>> When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
>> for metadata instead of returning them to the early allocator. The callers,
>> however, would unconditionally increment `totalram_pages`, assuming the
>> pages were always freed. This resulted in an incorrect calculation of the
>> total available RAM, causing the kernel to believe it had more memory than
>> it actually did.
>>
>> This patch refactors `memblock_free_pages()` to return the number of pages
>> it successfully frees. If KMSAN stashes the pages, the function now
>> returns 0; otherwise, it returns the number of pages in the block.
>>
>> The callers in `memblock.c` have been updated to use this return value,
>> ensuring that `totalram_pages` is incremented only by the number of pages
>> actually returned to the allocator. This corrects the total RAM accounting
>> when KMSAN is active.
>>
>> Cc: Aleksandr Nogikh <nogikh@google.com>
>> Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
>> Signed-off-by: Alexander Potapenko <glider@google.com>
>> Reviewed-by: David Hildenbrand <david@redhat.com>
> [...]
>> --- a/mm/mm_init.c
>> +++ b/mm/mm_init.c
>> @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
>>   	return table;
>>   }
>>   
>> -void __init memblock_free_pages(struct page *page, unsigned long pfn,
>> -							unsigned int order)
>> +unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
>> +					 unsigned int order)
>>   {
>>   	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
>>   		int nid = early_pfn_to_nid(pfn);
>>   
>>   		if (!early_page_initialised(pfn, nid))
>> -			return;
>> +			return 0;
>>   	}
> 
> I found this patch on mm-new tree is making my test machine (QEMU) reports much
> less MemTotal even though KMSAN is disabled.  And modifying the above part to
> be considered as free success (returning '1UL << order') fixed my issue.
> Because the commit message says the purpose of this change is only for
> KMSAN-stashed memory, maybe the above behavior change is not really intended?
> 
> I'm not familiar with this code so I'm unsure if the workaround is the right
> fix.  But since I have no time to look this in deep for now, reporting first.

Good point, I think there is something off here.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/43ae76b9-14e2-45b9-83b0-4e5fdb6bfb3e%40redhat.com.
