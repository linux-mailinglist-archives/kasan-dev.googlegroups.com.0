Return-Path: <kasan-dev+bncBC32535MUICBBSEXUDCQMGQEA4KAR6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C8E92B30EA7
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:18:50 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-244570600a1sf21773795ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:18:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755843529; cv=pass;
        d=google.com; s=arc-20240605;
        b=SCK2HpvFFeIJGtTAfyawNNfua41vpbDL2/7I8vd2w1vKQLasybU4EN+W+s04TRiQKm
         cR9NEohyWXhpcEj9pT4FVKJnxLRR0/H0R7yJ9GBD2VfE7PSgr6RHqEcdZlteB53ELRMk
         dLtcDCStLQCblvQK/lgFX+iNNA6v/vAoesqxbwl5efRsCwAaaPW1yecBEf11t26DaaPr
         Hmq7ysbxXUKtvPGIVLvOYeoiV4in2B4gzkyGJwXSkXt54Mst7hxv0VmUxiQtmnPIONl1
         hpb+7eZDN5hLf+L9cmukuXRKggcZQhwIo+z/brSEHt9nTl2GCEqyrHsaI/pA5QkFeKnq
         3XwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=ckByAz2vRIAvOTDiurvxHriwX5Ijqh9aq2Xd2mqHMqg=;
        fh=2+miWrAEza3sOnc/kkJ9K9rHvHHADnhTiDLfRjNRQLg=;
        b=fPE2GeBgzTlX1Kh4aExUs1y2+ORDT6d2oK285iioEj+6y1QwDQMj0By7DCaTomg9aY
         GuhDWUXb1nkHocMk76L9Gkq+ZiDL+9K4HBamicVTBZKa1gvP1pcMb3ieOlNFxpVYndTu
         MbcQ6QS53nsdokBqt7FP2sFria6wng2x3OawunG9Ox7BUxu/0ofrVAU4ye3Ss+AzokN4
         cDYgYVzdCA+Y2CR6n+SIl2lAfVHuL8WL7CmX9Lgddt9FnP8flaOoHNS9UPSV2cEAJNKy
         3Qx7t99kd0WMlGmPFmUi07o50c1gA4IL0BMunQpMcGmBXVtZKic1xxyvmxz4ALgYqlQg
         zOjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=CDPw+Cgl;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755843529; x=1756448329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ckByAz2vRIAvOTDiurvxHriwX5Ijqh9aq2Xd2mqHMqg=;
        b=T20EzBcgMIty27I6h4SoePzv91sQnzZuBQZ/RqWi6diFF+y37HbgIgzU8/LBKbmRUb
         4bOqxdkePK12o/AV235mORSuHKFnV1iUJgOXitpxmg1ueBttF0QQ1RfrxeSvoOaFs0ZB
         hgQWHHGdLBuksDdRpSWC0kJXNG7kUYf/AbMf4hJ63euA08w9CJUMVk+JlAKvHX/P9dDs
         93Gw4Ygvc5RyrvTVRuyzZv7d3ZhMFh/L92OxgPN1M0QxtJ5wRWGOVoPd2EMyBOYMoUCy
         /yV1yshIxbtIBL8HNERO+yTkbLYd0L89LSu+XKHNvfG0HZQNfmf+xvmzBkG3wNSlBqJz
         qTZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755843529; x=1756448329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ckByAz2vRIAvOTDiurvxHriwX5Ijqh9aq2Xd2mqHMqg=;
        b=Cl9pRk3MQTbYE8BCsjGzXQAf4w/gEPCQWd7dEhjKbNkDX6pUKnUgQTiFWtLZUhHbId
         yBSucHHHT+ukWwa9Bxa9U83MMtr2PgB0JH/ugS/QYK//Gxk7AbExXs8IueTBHBm+2DOx
         /VdThlvVRgIQnHF4B6w43KEWrW25XPbH1rql1XMvUS94S3V1ptG4UCWP8Tx8BXPO2fmn
         WWey/7WTpqc1dDtEPUqyYyokNz0sFxBJ7JQ6i3Ql+axuZNaYSn2qkL6qmCBng3tXzNnN
         ZwtZg2w14PE+K/LSudMjtbCcDPQSXWzq7yXYtmKBwgEuqL8yPmSRjLkLcyv0T6nbEh7g
         TyEA==
X-Forwarded-Encrypted: i=2; AJvYcCU4AyVatlOVsyEPEPT48tGfO6D4eaUeoPD4fGy9A+L8csdJ1DIhachg7WZVvUSWPTMyM+qhrw==@lfdr.de
X-Gm-Message-State: AOJu0YzdHS5Zw4vlYCfuJCX+J6vmhGjhzzgs8yJkdAStHmEV0ijXB867
	5DMsIZQ2P/H/8ephxaKM3KvRTjPh7lIlt0anCs0mHJAvft22V5cngci+
X-Google-Smtp-Source: AGHT+IErvf1DzU0eolx1NFKTeoy+VU1IBj2mvmxXcpemCkeDvNyXZUoCC2oXeWny/D5e7POaN0vQ9w==
X-Received: by 2002:a17:902:f54d:b0:235:efbb:9537 with SMTP id d9443c01a7336-2460238be4amr56917135ad.3.1755843528925;
        Thu, 21 Aug 2025 23:18:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4y/3bDnKS627cR03n8RwRgJEfg6jURheoftrKlNlGYA==
Received: by 2002:a17:902:e883:b0:23e:2147:4c78 with SMTP id
 d9443c01a7336-245fcc07c06ls12193965ad.2.-pod-prod-00-us; Thu, 21 Aug 2025
 23:18:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjVyk+0o60yErGDoZ9o7LIHtycWen5mVaze6EO9F85hmmmh8j1L8+JlYAyeBsUzVzMLueWKkLQG5A=@googlegroups.com
X-Received: by 2002:a17:902:e54a:b0:237:e3bc:7691 with SMTP id d9443c01a7336-2463299c52cmr23417115ad.13.1755843527521;
        Thu, 21 Aug 2025 23:18:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755843527; cv=none;
        d=google.com; s=arc-20240605;
        b=QJM9as3+GYcPgspYWh8iOdI3I83afEhuXNmgqQeCavBwqfsNySlaf+EM0g6SR87fc5
         1sL85IAtfLIQ1dvGiTIH0SO+Jfvc2db+CGtQiNbdnlTcfFlvoazfT4TvPNvabInUi2PW
         y4oHeNLCW1uU2fljRd2DHFf3ugSFX3N/IzILvmSoQ6M8bxuQ9lUny2rZklSdcxeJ4DW4
         bfQ63l4qQwkLnhFA4JnBiK4IrcT8DK+zHweNAYWLpkzDPIOameU/SAx6+aVVJ1sUdCqz
         UtjDEzhrHcLH84DzbMs6EPGv2rkIjeemNKuOnJ9P3EVwu2/mgEjPcWjlOzz2wUm6qkAQ
         60yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=niXcAgzmbCLTQjKBYxU2ktBBprjtNy5MGdyac9sGLRc=;
        fh=DJ1euw7BbFwIQhFyl5HOz+lQxN/6KBIIq+mHpT4U+pI=;
        b=N0TDq6zHZufLDkv9ZhG66zXijYZhvDIAvRepwVD9Z3KlPD9iMbwVp8yhqqE69C1lCE
         saUvR4XF3qPmFbadrMHOtz+gVhKhf3jZE4EwX9/om4o1YfEINb4JFFDQpwmulh1OUC8A
         +CZOQQf0P7/NCIJjptxgEdD5c7PKAcmy43sEVTHg40P6YEdriDsSWfmQeEQDoBe1sJ4r
         wd9wPuhh89BjHh3xHP17EykAsKl5yZG55SaNDmr5CPQ8oUYgmldN/Q3ApGiskKFSQDKa
         IMpMIt1qLHibibLn+JwNO2QJCaiqR0LNZbkCrkIeyT3f3mdlTiqvY+poM3g/Hds71QFx
         lcSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=CDPw+Cgl;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-245ed3a7c59si3228835ad.3.2025.08.21.23.18.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 23:18:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-118-htQtAFSlOmK9i9F7qr-sTQ-1; Fri, 22 Aug 2025 02:18:45 -0400
X-MC-Unique: htQtAFSlOmK9i9F7qr-sTQ-1
X-Mimecast-MFC-AGG-ID: htQtAFSlOmK9i9F7qr-sTQ_1755843524
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45b467f5173so11869895e9.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 23:18:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVgY67hYC14KZPDkv5vXPHUaD0wE5XgudlNF+q/smAvE6aDJ5hWq7cVORABzYst0+mk5M6V/7tIflA=@googlegroups.com
X-Gm-Gg: ASbGnctuX+YrkV2HqqTQiKckL8svFFUhtyIi9uvmWouUb9V0upCYVVOVJ7WCuqyQj9/
	2MZDAIM/c7XNbYRkj3xgqrZGAdiQuEDfdbw2+pOrThHvwyh6ya3zC6VNedltTlLiH1lZbaeZKTE
	ZDODdqJhb7JDUzZ2MtBXrOuExhuTegqB9lEkT46QoB1qLhyBpW4mmldrJDtbXh8Xx5AHODad5St
	Pxk2goG2+hG+6NgEZaSQQPeYOJGaaYP3oPIXf36idEGOIiIekPKWuw1D1rdZVYL7NlQqC+r98KX
	bpFE1AXfPUbYibMHyXviPGn1/ZU4tiY0HHT0Y6VbMLrJmsPsNEhfPrZlEgiJZG2hpQ5Hvg==
X-Received: by 2002:a05:600c:4e8c:b0:456:1ac8:cace with SMTP id 5b1f17b1804b1-45b5179e7e8mr12435565e9.12.1755843523899;
        Thu, 21 Aug 2025 23:18:43 -0700 (PDT)
X-Received: by 2002:a05:600c:4e8c:b0:456:1ac8:cace with SMTP id 5b1f17b1804b1-45b5179e7e8mr12435175e9.12.1755843523431;
        Thu, 21 Aug 2025 23:18:43 -0700 (PDT)
Received: from [192.168.3.141] (p4ff1f25c.dip0.t-ipconnect.de. [79.241.242.92])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b50d62991sm24078285e9.0.2025.08.21.23.18.41
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 23:18:42 -0700 (PDT)
Message-ID: <6bff5a45-8e52-4a5d-81cb-63a7331d7d0b@redhat.com>
Date: Fri, 22 Aug 2025 08:18:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 24/35] ata: libata-eh: drop nth_page() usage within SG
 entry
To: Damien Le Moal <dlemoal@kernel.org>, linux-kernel@vger.kernel.org
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
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-25-david@redhat.com>
 <3812ed9e-2a47-4c1c-bd69-f37768e62ad3@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <3812ed9e-2a47-4c1c-bd69-f37768e62ad3@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: h9-z-e3nf27HrzrDfL_5D0RVgwMKyBtwtrGgGfvz7DE_1755843524
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=CDPw+Cgl;
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

On 22.08.25 03:59, Damien Le Moal wrote:
> On 8/22/25 05:06, David Hildenbrand wrote:
>> It's no longer required to use nth_page() when iterating pages within a
>> single SG entry, so let's drop the nth_page() usage.
>>
>> Cc: Damien Le Moal <dlemoal@kernel.org>
>> Cc: Niklas Cassel <cassel@kernel.org>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   drivers/ata/libata-sff.c | 6 +++---
>>   1 file changed, 3 insertions(+), 3 deletions(-)
>>
>> diff --git a/drivers/ata/libata-sff.c b/drivers/ata/libata-sff.c
>> index 7fc407255eb46..9f5d0f9f6d686 100644
>> --- a/drivers/ata/libata-sff.c
>> +++ b/drivers/ata/libata-sff.c
>> @@ -614,7 +614,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
>>   	offset = qc->cursg->offset + qc->cursg_ofs;
>>   
>>   	/* get the current page and offset */
>> -	page = nth_page(page, (offset >> PAGE_SHIFT));
>> +	page += offset / PAGE_SHIFT;
> 
> Shouldn't this be "offset >> PAGE_SHIFT" ?

Thanks for taking a look!

Yeah, I already reverted back to "offset >> PAGE_SHIFT" after Linus 
mentioned in another mail in this thread that ">> PAGE_SHIFT" is 
generally preferred because the compiler cannot optimize as much if 
offset would be a signed variable.

So the next version will have the shift again.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6bff5a45-8e52-4a5d-81cb-63a7331d7d0b%40redhat.com.
