Return-Path: <kasan-dev+bncBC32535MUICBBR6DUCZQMGQE2CT2CHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id D32ED90385C
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 12:07:04 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-7955b3dd7b3sf235463785a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 03:07:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718100423; cv=pass;
        d=google.com; s=arc-20160816;
        b=e9oSYr9rU+rceeatR7orOQ1DqTD7bY2GqvJgPPI22CJbd0N/6u7WYHuKuUzHti/dBf
         L55El1VfOyBAFN6aTdpiS5YoKt9GqhUyTSFz8WCRG7zMuNhhWwiIGJViDuzJGrzYO8YS
         mExyLosAaj+OBuCRsesf6on5vmbjp1SlhQCesV7R5HupmGkcOJNd+VrtMDEa6AdQ+E40
         1lokCa+UBLiEsjsxIb+8GEIz2et3RD5x0KLs5zuEzuwnABQLDFWNHdFVKr/7MXlrwu9K
         o54VsFyvDDcEnbKkdJcMoxxCa2EKatysP8Snj/daDcyqR4ev5JlEZ1Lz3u1RMYgomNFf
         tJwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=OJhHy1OV45aPTcChmQkf7bsVrApFS2LE2uG1RlYH9NY=;
        fh=/37rVvyXg/lzhn9bfUqKOrgmPSSATegqj+fssdAacIE=;
        b=NFi6oevLg+Wg/s1dfdrRGZG2uFIx4nZBhTSR+jQdHJXCiUKY9sltbg80OUoaj+QJ5p
         LmhSc7Sf/QwYr7MO6LPQTCgyHiqHhDtJZMksXKQSbmx4unMKIc1MFhOSERDuDtcrNTFI
         GboR+g+ngIRzlAjtOk2zuzIhD9ggeKYuUW9xnOPUIWxtClKOyPh58RDgAILRaNLiD0ie
         gyn3spphS/8mpMLbuI2shQnbeMMI0BgsYHC3FzOF5HShwwxA9UDcUS2nS5W33LH+eLeM
         WsnTVkLUbwJ3/O99fafYVNQF3rZwJVcGPpl+/KPrT1RHrd4OeVPyvY5fEtYt9Qr8g5Td
         PKkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DgkinS2x;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718100423; x=1718705223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OJhHy1OV45aPTcChmQkf7bsVrApFS2LE2uG1RlYH9NY=;
        b=O0cY8wqzodBNZ69UDWj2flxOyZGh6lZexR0Hn/nFIHq+oHez+xRj4wdx7f7P2H9yNu
         QDKTV/qerUqJVPqEWonB2tVcT3lwJ4glzF1HmHYi1q8iU68zyGofANKYVTeeL5NuyyPV
         GxY2EJgfRyjS+kKrd/a+yHYv3z5uUmk2+uvQGUKwZzaOZuPiW/N2joYxDFBFZIMYj83V
         UHnUDcbIHnAGVsegPY/5NNAERA1rzy0r/wI3OMluRwmiodJ6ZziuLKR5i6DVAwMiVkNx
         AnBlsH3cfvr/l5iSfFgSCaA2VszqPRYNjvo7KABCn2U1EIWeVdZ9YjUcEeHCxZ6c06TL
         MEwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718100423; x=1718705223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OJhHy1OV45aPTcChmQkf7bsVrApFS2LE2uG1RlYH9NY=;
        b=ZcghUTGWIx2gALdZtNdBwSPSPUhJ0SB11IMxpvQ5pJXh7Vv8RrZxNoIxOeIykamJ1S
         znhe7ebaonGJF6O/A4xPL2TOvGj2CCbkUo1PC8+3Z/sdOyvKn58XajhU9wgDWXrqOVpy
         Kidu5/CjYSctT+SN0WMsf9aowMeY02ZM6TIFrgjkRWXenxZL4ssjM9PJaqT//WsWmVB8
         suoBu16oPoK1sOVkSX+MaFbp+Kd7XMspAY/2teBC6Jc39ruccsTyiAWDHJUfnF4DTX24
         A7snVnfy0e4EvCaT1KdfkqtmNEV3qCjXczTVEz+Eme7y7xljvxK0eQvxnEYzTngz8V4N
         Hc1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVBpPPxly3Lx3gs6Jk/l21wOLjiYob1w5PC5/Knpg8YXNSOCto+Fwr3nWoGDzVPdB0inGttO39Olw+nMI1MloyVaHuW+gNAg==
X-Gm-Message-State: AOJu0YxNbBPCJe7hFWSqUuZO6K9O2lr/VT/zyk8nlNzQTDU2UaX5IW+g
	6btXZkbPpBHAmEdVp854pbZhb5tOx2XyGyExbXA2uZmy0q4Xhaxv
X-Google-Smtp-Source: AGHT+IEe7fcI3JdtQAgkxCvBKeYamrf51saC1H9ComeUp3NBdHGMdEcuWfAZM6chgijFqKbrJUthUw==
X-Received: by 2002:a05:6214:319a:b0:6b0:6bcb:d9d5 with SMTP id 6a1803df08f44-6b06bcbdef6mr91225036d6.14.1718100423348;
        Tue, 11 Jun 2024 03:07:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5ae5:0:b0:6b0:862d:978d with SMTP id 6a1803df08f44-6b0862d99bdls23196306d6.0.-pod-prod-06-us;
 Tue, 11 Jun 2024 03:07:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+uJ1AdI29P0ZnNt1ametq/1lKC37L9e4SX+pbddNIZz204jKHwmXrVTFLRiUU403ktP1MHKBZcIFHWHKzsWf+TMjwOpkAITY+mg==
X-Received: by 2002:a05:6102:3182:b0:48c:380d:e6fb with SMTP id ada2fe7eead31-48c380de883mr8936469137.31.1718100422424;
        Tue, 11 Jun 2024 03:07:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718100422; cv=none;
        d=google.com; s=arc-20160816;
        b=xDQQMHqVJfbl+ubqMHUEhY/DJ3R61TOsl3F4jYumhFvacEM7SEVZOgNlcAY5RlF5U0
         vKkHWNCb823BAX4hMi5nbz3SR0S2oyga/whuSA9wC40+3ldtALxVpupHmKom3V2foL7s
         QteGYx2IMxGNv30eIINA7Be4HFtyS3TFFDi/jIarhtn1bDidJfpKD/nk8ROOofodBzYb
         oK6fx8jHOBE66YECl3IJLKZXqZgssFUwazYmNOYhTS8CBrht2QXTIXAb4Fi86nMHgLIG
         XLMY46nS33CTpqs/56moumzUdfhV/3biJ+MGy1Ynp7J7sQ0lAge4IrbrA83M33E+CLqg
         02bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=F/H/c4fGsFUdJRDofZpCfuHa+2bAf+RkO1DuZv3WdgI=;
        fh=jjrbczAzDyZGUhrJPMhH7mBbrOnDj0cIo/gbFMNshQE=;
        b=b8U9LvNKlOXNYhKuWRDG/ENwtjX0/l+8R4TFmfLA2E9Oz+WmjQKuncCQeasTh0JUjS
         YUtNbwU6xzbhRrkJoT1nRGLP3UuB/LkGyZ4fxc4yz/yDyxWOQ1NibuCVgNrqPKPyR6Zw
         hrgkFhZsIIK/Zag+eUI7Q25DpIrowCe/irbHP8b4OtQA762kf6xhMV8hNKQWDSUwUA3P
         l2I5K0VaiRWiHFYwV85MCBoKAQtdE+fzggVc0FS26i3Dxxj4yGW9KgAi39Pi7nFB4Sq+
         bO13raiodTSJxAlV98uOPHZkCCzJkSzN6K5Deqf4KmghNeplGZLU6QLOSiwemth4nVXP
         mt6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DgkinS2x;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-80b8458a51asi338737241.1.2024.06.11.03.07.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 03:07:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-lj1-f198.google.com (mail-lj1-f198.google.com
 [209.85.208.198]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-650-0zodGSk_PHuLQdRGc5Wuyg-1; Tue, 11 Jun 2024 06:07:00 -0400
X-MC-Unique: 0zodGSk_PHuLQdRGc5Wuyg-1
Received: by mail-lj1-f198.google.com with SMTP id 38308e7fff4ca-2ebea9b7822so12824351fa.3
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 03:07:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXomJiSuP5cuoF0njZA680BTsMqUWdN2t4YPAEHRCvRJPw1UrAN3myYhUC20K1aFkHYjoeNpsDfRHc0s5itRVRtl4gZAYwLq7Tzbw==
X-Received: by 2002:a2e:908e:0:b0:2eb:ee64:1e19 with SMTP id 38308e7fff4ca-2ebee641fb3mr18566641fa.42.1718100418968;
        Tue, 11 Jun 2024 03:06:58 -0700 (PDT)
X-Received: by 2002:a2e:908e:0:b0:2eb:ee64:1e19 with SMTP id 38308e7fff4ca-2ebee641fb3mr18566441fa.42.1718100418548;
        Tue, 11 Jun 2024 03:06:58 -0700 (PDT)
Received: from ?IPV6:2003:cb:c748:ba00:1c00:48ea:7b5a:c12b? (p200300cbc748ba001c0048ea7b5ac12b.dip0.t-ipconnect.de. [2003:cb:c748:ba00:1c00:48ea:7b5a:c12b])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-421818907b6sm86762715e9.27.2024.06.11.03.06.56
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 03:06:57 -0700 (PDT)
Message-ID: <2ed64218-7f3b-4302-a5dc-27f060654fe2@redhat.com>
Date: Tue, 11 Jun 2024 12:06:56 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
To: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hyperv@vger.kernel.org,
 virtualization@lists.linux.dev, xen-devel@lists.xenproject.org,
 kasan-dev@googlegroups.com, Mike Rapoport <rppt@kernel.org>,
 Oscar Salvador <osalvador@suse.de>, "K. Y. Srinivasan" <kys@microsoft.com>,
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
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240607090939.89524-2-david@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DgkinS2x;
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

On 07.06.24 11:09, David Hildenbrand wrote:
> In preparation for further changes, let's teach __free_pages_core()
> about the differences of memory hotplug handling.
> 
> Move the memory hotplug specific handling from generic_online_page() to
> __free_pages_core(), use adjust_managed_page_count() on the memory
> hotplug path, and spell out why memory freed via memblock
> cannot currently use adjust_managed_page_count().
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---

@Andrew, can you squash the following?

 From 0a7921cf21cacf178ca7485da0138fc38a97a28e Mon Sep 17 00:00:00 2001
From: David Hildenbrand <david@redhat.com>
Date: Tue, 11 Jun 2024 12:05:09 +0200
Subject: [PATCH] fixup: mm/highmem: make nr_free_highpages() return "unsigned
  long"

Fixup the memblock comment.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
  mm/page_alloc.c | 2 +-
  1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e0c8a8354be36..fc53f96db58a2 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1245,7 +1245,7 @@ void __free_pages_core(struct page *page, unsigned int order,
  		debug_pagealloc_map_pages(page, nr_pages);
  		adjust_managed_page_count(page, nr_pages);
  	} else {
-		/* memblock adjusts totalram_pages() ahead of time. */
+		/* memblock adjusts totalram_pages() manually. */
  		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
  	}
  
-- 
2.45.2



-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2ed64218-7f3b-4302-a5dc-27f060654fe2%40redhat.com.
