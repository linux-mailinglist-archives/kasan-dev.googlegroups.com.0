Return-Path: <kasan-dev+bncBC32535MUICBBJGWU6ZQMGQEFVJTAUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F4A7905B27
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 20:38:31 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1f670202deesf354195ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jun 2024 11:38:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718217509; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPZ7UcZJIVFs9hPccoqT9rP0x6Wcu51/8HNTenoGShM3SW+QbC56J/TGe0ci7Ncd3e
         QKpDac1dUbBcsATX22l3ZAj9Ez5yEV592OkXm6lChhHw1VgdngNYSBXJy7MQgF1oo4Ak
         aycT8b+NGg7EEo61Ssb17NZreotjbK2dGFvbRiLHVmxRNvtN9eF25cqdmSuRSFGFGPDm
         7meB8/eGLUMCZM1mQTJB8RugkM4xuQBBvjyltbS76OjBiFd4sxDcNRablDN0ac8k29ZH
         VtoNcRlEY2Vu6Nf/ilur63U6MtJTaJ1NB5QZ+bhk+CKdHr3U/H2Zo9inLiSKdSOawUjA
         qQvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=pBG11mL0pbkSPVhXH3PAGz5eEzPQ5d1jLSIUF2HbS7w=;
        fh=idD9AukgH2dTKTNwFVEGbXoZVIQMklWig5mlAMgBO7M=;
        b=KpbrhNFQwhHjhH5v7ZfLUWHrcxxYtDitoez+8acbb8It3YKyNv67BzR2k5HIgBOjv2
         lctIYAEC7V9cWcFI4evoSyrat6N2Jd9uPoZvZZW2Jkbdn9stVCMWO1pC7G78lgSwHYqH
         Z41qdaSnbv/pfVXZ2i6SNf/nH+WjNhTiRI4Xe8NH22C6L2h0DWWc0GbdZmPG0RfPCwFB
         cdTMyEEI+GQ/hiwPpXu0TgATAFIyXOf1k0LMQsNSnzIXIwb1EULu9c7Mvc3FobPqmdB3
         F1o7eqIQAIArGFKtlQqiFVCwfzTS/JsFCSnvmcdyo+02CxG0Bk1VNR9gh5NXEBYovi/C
         hAIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=H7EoFCk4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718217509; x=1718822309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pBG11mL0pbkSPVhXH3PAGz5eEzPQ5d1jLSIUF2HbS7w=;
        b=Om1ZVQRtj5btT+twezMNxHJbPE+rgN+4xmJK5YT2Uo+uDaMB3QvZIISygSBwKhhZeD
         xti82/VbfX/pw5yARnnxZoPUvD2xc0u45D1KsrLehH/7y8JqkNNdCryNVnF778H8TOXq
         m9XQCmNHeO+NG6PYqfPmS0+lWauAIGFFM31D/cVAToUfDdfimwjmJiCSxPDHQmSiUJUV
         +7fr0UK5I8Ewqwxk1lDkjicA73ucp1V3HKdIio8qMqQVVSq0kggOPqwvvUUKXsbSElja
         JNjuV4mZCTWqh887TCf/+yRDijlmcZYV1kry9INrNpT9d3ow0edsM7cmqB7PQPe7H7EJ
         nLdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718217509; x=1718822309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pBG11mL0pbkSPVhXH3PAGz5eEzPQ5d1jLSIUF2HbS7w=;
        b=KukQo+QlOQ5/4PPnIuQJfWxQ0YA7yVPA9ijk4xL5M4QTkJCzW92ObUSPCwGSrd4qt+
         Y2zPGOsyQaegfT1tqqc+lbAG9wRCZ64Zay5fNQTc1tFSOaWGgSk9kWBUy+n03KpwuvVb
         /lM55UxLOZxu5cWjNb0rhC/7dLd58fkhL4DmnUbXVOVXHK6UWG+2iu/GHHqqTjPSnhKP
         yLnLAP8ju6udr1ZX3xlXxUdzA9xF8IaPjQBkkvvIdk1rZcF7ZWDkpIgKi0aKGpHM7GAc
         v+7UW5vg4OGKJkf+74kwRby4vHlBjkFKsUyM5Le6EywTLI93n7D097u5aJCO/KdM5+NG
         YNaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV55aE3Kn1468axVfzdlt9d9tNlEctQ0R6r86I6yCTsMDZAzGkjOst+0zcO+2mySBYq0mjysLlWB1cqDVeBdj0UTYg71XQHlg==
X-Gm-Message-State: AOJu0Yyj3MSkAdacqaqVRO36JhRepexyVMd5dxEW1Tho93bA1wMYStk1
	6YKVds+Gq5oS9DBX5+Dz97HPU6VUVSSg8bpWORtzWxvuEEIepdI5
X-Google-Smtp-Source: AGHT+IF9dXxKNK+DGMEN5R4dkSGhe/+AIqIzYkag+N3Qj4+g4ugWZEx8raRjscpGp2h/nWsfH6ITMg==
X-Received: by 2002:a17:903:2805:b0:1e0:c571:d652 with SMTP id d9443c01a7336-1f84fe3b7b5mr285225ad.1.1718217509167;
        Wed, 12 Jun 2024 11:38:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1142:b0:702:6dc7:234f with SMTP id
 d2e1a72fcca58-705c94925e4ls100331b3a.2.-pod-prod-06-us; Wed, 12 Jun 2024
 11:38:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwkQlSn+sHsweiOaEioL6chqjiGb/kd9qOZNdtlW3Xa0HpKQf32Z8fi03trVOH6up+1k776oM90o6E1NL3xTsGZAKXy3j5jbtNsA==
X-Received: by 2002:a05:6a20:3c8c:b0:1b6:73b1:b177 with SMTP id adf61e73a8af0-1b8a9c553a7mr3335055637.38.1718217507766;
        Wed, 12 Jun 2024 11:38:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718217507; cv=none;
        d=google.com; s=arc-20160816;
        b=vkGV1xP+ImGAxEJREMfovqNlG9c5OfeR8FXc5ahWA/1sZrJO8BXH0nTXHAA+3s8P8w
         InUOLXt+fC8QFE7eyswfR4P9Yfh2mX2qAzM9Af2Q4ZgoBYpQcTIde0OsBNpwiiZ7Dmvu
         k2c3NhWlRQq8F42U41OxEvL5hvXSCevXZwY24/ESuvTco6kHY8YTn7OYkB8W4pVimCuM
         hsTb7CVp4LPBy0lPjMMq33E+Gv7vx+5zdg+vIWBqLPbv3QKmiCVAWk+jTuZa9ZnOvKBZ
         Ksd3vZwFgZ6VdEy0Sr4MMvRuBKHs4PAhgPQnghL8bML5bNRrxv56YT+yR9DEnjyfK+L7
         ITFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=eHkiYypujAnwSi5QrP8pZu0qQw3cLgJft3y7PW/t9t4=;
        fh=ZB/HZ379NFgcaYE5ZHGnWS/WxxmB7NdnndVMeOh6g7Y=;
        b=su1ZY6eyHx6pqwdnoGDmTC6iLMEl52OmYQN1RTYJJ7BGEjxlnimOiA/benJxZdUPGU
         jxVRCMEjBOtmNUw3u/D9x5z1dKcC6OsP24EaRRBPQiSUXxGTJYhMyLgDHc2fY1DSBM5u
         5RK6jFxvCT3mFGj1LVuW6YRCxtkJUPe2UdrcA7ED6YilJJEuCyeNKQcGYcEAeOe1ADP4
         0jsjqoKNTNIEDZzX0r518jjCVRP30eaM+5CUDjDR95KgURLw/Crl6x5XcdDrJbEunQWs
         FNabdmjgJUrtPctdre4k5dx/vg/5kqw+ljn88zD9pMWpgGlwqDc6CLWo7vWJrAO9oPbo
         WfJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=H7EoFCk4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f83e4f544bsi762555ad.5.2024.06.12.11.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Jun 2024 11:38:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-629-Xk_WYRUNPjuvV66cSarNOw-1; Wed, 12 Jun 2024 14:38:25 -0400
X-MC-Unique: Xk_WYRUNPjuvV66cSarNOw-1
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-42183fdd668so1052415e9.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Jun 2024 11:38:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWd8oXlcbCdNYK/q7nanqqxzz8OaUPXQnKPZP9NJYrDxJ+zO3zUj7ewh6W23cDV7SGz2CWyFecW0PpRHCAvOf9pKy9rkaRJwUD2Zw==
X-Received: by 2002:a05:600c:358b:b0:422:683b:df4d with SMTP id 5b1f17b1804b1-422862aca70mr25635715e9.8.1718217504322;
        Wed, 12 Jun 2024 11:38:24 -0700 (PDT)
X-Received: by 2002:a05:600c:358b:b0:422:683b:df4d with SMTP id 5b1f17b1804b1-422862aca70mr25635525e9.8.1718217503744;
        Wed, 12 Jun 2024 11:38:23 -0700 (PDT)
Received: from ?IPV6:2003:cb:c702:bf00:abf6:cc3a:24d6:fa55? (p200300cbc702bf00abf6cc3a24d6fa55.dip0.t-ipconnect.de. [2003:cb:c702:bf00:abf6:cc3a:24d6:fa55])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-422870f760fsm35980815e9.33.2024.06.12.11.38.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jun 2024 11:38:23 -0700 (PDT)
Message-ID: <ca575956-f0dd-4fb9-a307-6b7621681ed9@redhat.com>
Date: Wed, 12 Jun 2024 20:38:21 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Mike Rapoport <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
 <2ed64218-7f3b-4302-a5dc-27f060654fe2@redhat.com>
 <20240611121942.050a2215143af0ecb576122f@linux-foundation.org>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240611121942.050a2215143af0ecb576122f@linux-foundation.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=H7EoFCk4;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 11.06.24 21:19, Andrew Morton wrote:
> On Tue, 11 Jun 2024 12:06:56 +0200 David Hildenbrand <david@redhat.com> wrote:
> 
>> On 07.06.24 11:09, David Hildenbrand wrote:
>>> In preparation for further changes, let's teach __free_pages_core()
>>> about the differences of memory hotplug handling.
>>>
>>> Move the memory hotplug specific handling from generic_online_page() to
>>> __free_pages_core(), use adjust_managed_page_count() on the memory
>>> hotplug path, and spell out why memory freed via memblock
>>> cannot currently use adjust_managed_page_count().
>>>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>> ---
>>
>> @Andrew, can you squash the following?
> 
> Sure.
> 
> I queued it against "mm: pass meminit_context to __free_pages_core()",
> not against
> 
>> Subject: [PATCH] fixup: mm/highmem: make nr_free_highpages() return "unsigned
>>    long"
> 

Can you squash the following as well? (hopefully the last fixup, otherwise I
might just resend a v2)


 From 53c8c5834e638b2ae5e2a34fa7d49ce0dcf25192 Mon Sep 17 00:00:00 2001
From: David Hildenbrand <david@redhat.com>
Date: Wed, 12 Jun 2024 20:31:07 +0200
Subject: [PATCH] fixup: mm: pass meminit_context to __free_pages_core()

Let's add the parameter name also in the declaration.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
  mm/internal.h | 2 +-
  1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/internal.h b/mm/internal.h
index 14bab8a41baf6..254dd907bf9a2 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -605,7 +605,7 @@ extern void __putback_isolated_page(struct page *page, unsigned int order,
  extern void memblock_free_pages(struct page *page, unsigned long pfn,
  					unsigned int order);
  extern void __free_pages_core(struct page *page, unsigned int order,
-		enum meminit_context);
+		enum meminit_context context);
  
  /*
   * This will have no effect, other than possibly generating a warning, if the
-- 
2.45.2


-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ca575956-f0dd-4fb9-a307-6b7621681ed9%40redhat.com.
