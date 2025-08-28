Return-Path: <kasan-dev+bncBDJNPU5KREFBBQVVX7CQMGQEUKH3F5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A86EDB39286
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 06:27:48 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-74382040c94sf123516a34.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 21:27:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756355267; cv=pass;
        d=google.com; s=arc-20240605;
        b=E7fEEa/vNin0Jy0zN4zC3RQaoBOYSsO+ryJEAOVa1Gjjm+KKWKP21/oyEqrfTy17C0
         f7HcOiLZF8/7JiJDFdM4S/CxDoTFq9e7FrS7w/+nyQK1bN+kE6cUQOdVMQe3VryGMoj0
         5lsgT0pHiX1a6wlpAmeoX2U9FRcaZ/UPWgH3jUoW80pqvH7pNOlBRCCgRaXz9j0dAr/p
         aIgJ+h8OI2x12qc61bATh41FZjIOCDZsuBxlWFMaiWhVOZB50w9ZhMJlaVJHZI2/v6fw
         DJ4oyCgo4L8NBJW6OjHMOGzc/sKYpEmOp2460NopsqRtacgnL9Y3sQLA60b0+GYBgL9b
         oA/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:organization
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=kBNm7u1C9LLuDRgnHYaV8u/QyQBcryyBDOh4O/cD0SM=;
        fh=NEYKrXrJtvlmf4oiFq0z/wAZiFojq3BeDW66fJz0CLY=;
        b=it/1l5+0m+kxTfmI7kMyVgWyRHYXZtumwZHjvwO6QE6CYgAvwA7EPmz23tYspNhaSU
         PtWaO1U6ThZVlVOmVR5Goq0ozBCqOcIZaWzjZLROEOQuNMAEr9U9a6DfWrqZm++kuMBS
         SgN1WBzb543m25tFJmbgqpJwJX3+WykPnCsR0/KAaIKZ+aRF/eudF8Qgs+t8hihS/Qny
         yd+HOBvCzzpe2uH2dg6Bg8MGw92VX61+OQ3PVywjgaiMUMp588LlfmQVJg+leW/sRe9A
         GBhRYa6nZocXu6alLe+wkllmeIT3HK3bi8hWWaZKGKglhEaN0HH7ms5t7lFLkdWPf+qn
         Nrtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MDOpy7Q7;
       spf=pass (google.com: domain of dlemoal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756355267; x=1756960067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kBNm7u1C9LLuDRgnHYaV8u/QyQBcryyBDOh4O/cD0SM=;
        b=ItnT8f61PQvNyCaa7MLp1Z7x3fZ4cyl5BugbbFVRXWLUgb2wX1z83YPRbGo/RxXuwH
         AWZge1P9P4tUyLHLDbrUqQ0yLqIS+lN7eKbvtiIILvoJ9/Cts3gaRWYkA3yBVxXpS++d
         /3RMSIFDkDSfGb2AaPPKLWGdxyOADm9qSu3p6vpxWwKq7p2eUSmGGD78ih1g6q1jCwjM
         lUdaVivwzGcRxKV5Q20G+Zryf1Cxf/pWJ7yPRLl3yEI2+8+AfhxkmypOGIImT4efHyMJ
         tzm2lDegZtc6BUWEcOjRf2wfClqn7lbPBUI1UdWcvfiCm/xEXymHLs9eghPD7P4ONB6x
         N/CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756355267; x=1756960067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=kBNm7u1C9LLuDRgnHYaV8u/QyQBcryyBDOh4O/cD0SM=;
        b=Lyq4a+GbPB7pd/KR9xga/DkyFK0jlTX1tb5Aq9miXFVFludx46gvOoBhZQCyZzsvyU
         Vstez+W0ywv1F4g+ihd3rLUm5DIeyOvDeYdox7Dr7RZoct/Ep8w6sKAIe0mW4WmTxfTt
         gEVPmN6+OZB56p89WXyz1b7/PGpp2JsDnWsym73NFIb5z5ClK8CJrq6PruG0JZhXPfOI
         +1AfDO+oit/QVzalUoxU2eBkPHDnX0aE7AshmZnaxyOc6hw6Ynv+0cwJ8rPTPXy4nfH0
         /BygrEstInN2I//PvrdB4HfCq1TTdlHY/CyhrHCMA1H3ILYHWTmjY319uNB7faAoT4/O
         5IjQ==
X-Forwarded-Encrypted: i=2; AJvYcCWGmtrJdlQROxULxVG3ULBOxnrFWBbhqsm7jnVC3vi/fRI8Xl6iRt5TQBZemDgIztpyd2tJXA==@lfdr.de
X-Gm-Message-State: AOJu0YzIWXCkBM5PEYVZ76cGydTEMfrwuRMq6tP8Xxc/xs5P5EQCs52o
	5V+aerLdizAS9AjtCTF3Y7OAqjJVyEcPZ1ZhUTjMaKqt3XXqu0O+s0m2
X-Google-Smtp-Source: AGHT+IGzkI5f455wnYzm/Y8xI06BVP1a56XvWsfM6BaqrF04B9hnPjZhec7p2plasVGByP/fxnTjOA==
X-Received: by 2002:a05:6820:22a7:b0:61d:9adf:eecc with SMTP id 006d021491bc7-61db9aa6f56mr9533379eaf.2.1756355266778;
        Wed, 27 Aug 2025 21:27:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcGbn1+fsP+dj5Ki0aQYNsCfICM48FETf4DpOVX+5vF5A==
Received: by 2002:a05:6820:270d:b0:61c:1311:37ab with SMTP id
 006d021491bc7-61e13901a90ls70178eaf.1.-pod-prod-04-us; Wed, 27 Aug 2025
 21:27:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUqLw0m2KAhVgRN+XBC5KCfHL9ky/HafNs+GKVSNclcislmAfAGzpMCGoCh9TY99EbOkWsiz0QWG0=@googlegroups.com
X-Received: by 2002:a05:6808:118d:b0:435:6cc4:9753 with SMTP id 5614622812f47-43785190f04mr9167385b6e.8.1756355265967;
        Wed, 27 Aug 2025 21:27:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756355265; cv=none;
        d=google.com; s=arc-20240605;
        b=TuA6djlVxhw6qdX/BQND8kgMM67l9t39op9fcuzE6Q8IbcR46h2Zmebu4yCKXlI3PH
         4+O3sHek89tnEkE3bE/dkOIUXOf1t0EPZq78O+myPIUm97XO5PhSGAKznbv4QVhdyIql
         op12tuOa5yGIFodCyIplcbTHyHt7XfYJPENFnkXbGeip1tTpELmKe/jj28x42aUMN0hA
         wUCpIbXEN5OlxPMZi81eS2hrOpffOVqadd0V+XMk1tgJ3RZEG5Ll3gGohkmj67yiUiYN
         mGOZV9OUFKLBu/VgvbftWXUP+iZ8JDOAnI2R+iDgtzXgRyeL7lg4S9jJX++negFDcnsz
         44Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=/EGtfRPpOEF/pcMPNuO7jUOw177R7tpiZ1QWNeD8W7E=;
        fh=5d33eUqZhnjKuOEMCh02bLvMmuDu/YvoDMUZh+hQz0s=;
        b=TTtzShmS7F925sRwKaFh1kcUlBkLEauWyrAPcLovYrXjiDKm62/bdKGp6TTMFwGZ08
         AiYMSLrl1FgKyx+nI6FjiReJoFTE1OF/zV1Z3gyra6G8AMdstvFRNwEeKH4m2fF0U2l/
         WSI3opGaULA9CnSGk9YxMVTBo0aWm31rEUWO9RfP3uWw5YiKJoM8Mu7qMJqdimfsy/a2
         EXjrJkIP+OabRmVlVoaLuDoJ0QTZe5s4kxh2WwSZNK9ZRG04XLJ/pDA2PN7XAfZt0sYC
         Lu1q/SXh6SQvF3DLBU7LPohrJZ4yCKIAhr4iv/KTw9yN/c29notgJUDVZxWd+I6bCcx1
         PMXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MDOpy7Q7;
       spf=pass (google.com: domain of dlemoal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e26e812si61247a34.1.2025.08.27.21.27.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 21:27:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlemoal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id EBB9A60204;
	Thu, 28 Aug 2025 04:27:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 33984C4CEEB;
	Thu, 28 Aug 2025 04:27:37 +0000 (UTC)
Message-ID: <c39104cf-f066-45d8-a13c-cad558312b6e@kernel.org>
Date: Thu, 28 Aug 2025 13:24:45 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 24/36] ata: libata-eh: drop nth_page() usage within SG
 entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Niklas Cassel <cassel@kernel.org>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-25-david@redhat.com>
From: "'Damien Le Moal' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
Organization: Western Digital Research
In-Reply-To: <20250827220141.262669-25-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlemoal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MDOpy7Q7;       spf=pass
 (google.com: domain of dlemoal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=dlemoal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Damien Le Moal <dlemoal@kernel.org>
Reply-To: Damien Le Moal <dlemoal@kernel.org>
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

On 8/28/25 7:01 AM, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
> 
> Cc: Damien Le Moal <dlemoal@kernel.org>
> Cc: Niklas Cassel <cassel@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Damien Le Moal <dlemoal@kernel.org>

-- 
Damien Le Moal
Western Digital Research

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c39104cf-f066-45d8-a13c-cad558312b6e%40kernel.org.
