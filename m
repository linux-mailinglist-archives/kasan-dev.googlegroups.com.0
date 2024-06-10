Return-Path: <kasan-dev+bncBC32535MUICBBLP7TKZQMGQEQEYY7MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8095901D5B
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 10:56:14 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6ad706fab2asf66791276d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 01:56:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718009773; cv=pass;
        d=google.com; s=arc-20160816;
        b=MhMaQAOxQrYsvU9WVVvIk1yYMoabQZTW0ZbppV86J2OB1ZRApmPwCasT/nGDcZ1bV8
         GTvucPlTFJi+s0L9oqHBg5IgfnPEEvdUytbkNNPtCrSC++4rf9tm3tMAE7drRGgIYIIE
         TrNYQfkWckdcGUXRFq1WocYIh+xQXkCg5QZlv8EDH1SM86S6yRGRX52R6VDcSxcPagRG
         J53VHB+CVtnD2AP8AJTJ4RwlbJVB294bo76DNBJ3n4aDKXciABTAzm97V+qQmZiPCg+K
         rTS7WxbXgN6rxsUnyQtJmf0kRJeRAcK6PU3skq6/uu66uAIBqcP/RYhrU0NHSJIb/yRD
         Vnrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=TqSQFmySJy7inQLkJEU4TK3Mm08XY7YM9194K3pPYGQ=;
        fh=YbnKYFWlgwhvfFEg+sMAxIWgd5wNwCW50VJUn1v9i3U=;
        b=CY78jGxMvfkQOECMp4n6UrGAoizxRGaeDc2C++mDDvcG/eh7Q6o7VLVLmdwpTQSG8Q
         H6Zs5k8fBdV4VTvisnfEoC4+raHQoITM4XujewFov/ohy7F1240wDada1dGrbwJiwKDM
         KEhVUyRE4Icn2FQg0bOA1nmQy8w5dL6lhpPkgjWQxE4r1Bb5gJAenEA8JOGUnb9AuFmd
         sEMlUgi4u8KhUBVnrxZhnJTkYh67E5sRuRyPm4RMwRcIpmTfBoioqF/88RJmaqlMD59J
         kbOqZ6G6MNvl6AijqipoXySZYYe2goTMD0WzPWbqKejK3mRsXYyL5BAXI3Gbz4MNPBJI
         fwPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NXU1EbLT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718009773; x=1718614573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TqSQFmySJy7inQLkJEU4TK3Mm08XY7YM9194K3pPYGQ=;
        b=P5lyePVzUAVFkT1stYTdSnjS3/DcBnXhJnJTrXdsir+9yvIA5JGpE5kAa658jp0Cn0
         EVbq1hyyRX9v9L/xbroimPClq+gR2HEgwVTsy46FkOnw8jX5ee8ug4uad1x4wrjBFWH/
         G5tAluG54VA3S97+hXM20QnF/f73U21xeS0b55KAcOrBc3Q6pS5l+grD8MCnWG6Odmcp
         tm5/W03zXQuCH/fC+e3CypbLZ8EBYH4Swymm+2H2fWZ9yF0eEU7sssOLCpGyROHM5Y3O
         cNIBZTaTtNhag3+xOo7lk/iQvKSkz40ks7IVmGtgEIqFmZEdYuJDswfSIZcS7zzJLc16
         arMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718009773; x=1718614573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TqSQFmySJy7inQLkJEU4TK3Mm08XY7YM9194K3pPYGQ=;
        b=XHdcmGiDmAtsCmi1FlG25ekjxEbT8HHlwBEcGrXuMmwyJxRhdkMEntL6/rvIwbqDRC
         D7im95VINedWf06cxzQp6g5+iOKHhBSjd4gRVw+LmwT2RLhctU/QyBknANUxAyN+cjj+
         IE8fr1BGUB+V4qh1/mcQmKr6WAIQ7sHERTPAGpO53eJqbBx6fHEU3URNhKzBBWroA2N8
         9WoC0Y8icCfOt1/fCUkPW4CKcUZq8oELrEbMgvNTM3SGvDp73sc0zQXWxCvvrYwOHktp
         aC+sez5QBC05pOmt7ii7CsVBr/kH8lsdbTmhmy6xVDjqy8M/2btdQ7VmFzIcnN5Gigbt
         qxTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhgpcYaez79yGEOU40QljU2IgDjdQjjI3tKrMR5aI8mxnQBx5K31muSl8Q8/JFXH6IXth37ynnj0Y3fqhE2QMPIWe2ZhECNw==
X-Gm-Message-State: AOJu0Yy7OvYpjOu6nn8CoqS5Ftx3g3mt6a0Fuk/DIKz+JdauI2brt36k
	Uj24FX57M8dRBLJt5JjPMvvoaywjByK93f3kLAmSmQw6nhRlrfeI
X-Google-Smtp-Source: AGHT+IF5jgpr9g2xdxlrbVD/Jqh8nX4/59OS2/lVpyzxE/FBaTCcEnmfDP0OtcVnZrnX+toITD8ZJA==
X-Received: by 2002:a05:6214:3111:b0:6b0:70df:4a94 with SMTP id 6a1803df08f44-6b070df4dd3mr50100746d6.26.1718009773573;
        Mon, 10 Jun 2024 01:56:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c21:b0:6a9:2a:cacd with SMTP id 6a1803df08f44-6b05726d06bls47945776d6.0.-pod-prod-08-us;
 Mon, 10 Jun 2024 01:56:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtgDKhnMcRrdeMLuIFLz1Tfot1ySPhNJ0MzjIwFIwn/iXXzsip35n/hllU3xEuPbdgBWhjkqt4KV52h05SKSyCErNnxd+YE15qzQ==
X-Received: by 2002:a05:6122:3089:b0:4eb:499a:2453 with SMTP id 71dfb90a1353d-4eb5623f1c6mr7362968e0c.8.1718009771261;
        Mon, 10 Jun 2024 01:56:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718009771; cv=none;
        d=google.com; s=arc-20160816;
        b=KQqO1ryjfAUR9U2VWl51CHO6ZiyLLMiTYoHgmcMTbu5DDW2fd6JlzP8/UjD2mvonDJ
         LA2LMh15xSmWQNgMVRSqV4Eznd74y6abABCSHoFMUEyko/HvunD7gFZ46WeuckQYEkK9
         +RtSgYisc/L0DbzUl3HRjyvtFeKk40375Gkfga8Rl4k+tcUaeOnIwO6OzMslyJ2zynx+
         BM+Y9H2eqAQLFyOdjnpa8wWRhU0cYGsXhzUYtRTn1ZxgGR18rEzn+his77D0O7REeASk
         sv3Pqh3KPAxN8mh8oQu0Ttg7wVZy5+al5kTAPoWyyDqVKcIIVzhBdlAZcGASVHGA6niP
         gxQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=K7xP27zKqY4v47zLxGRsdu26ar7Ig8tqaIa+76/1NNg=;
        fh=xEoRpH1TcfvH3CCdR/wjv76UQtxtMD1WOkUVic2CL3c=;
        b=YwWWXHXqHVhdpx4MbE6WssTv9/BJ5hbaMH3pjNpieqaM0Q9QEqmGMtNqPZIyVXttKH
         fvP8RejGsYieRMr/1JyQp99Rd5AaMsOrPB2uN7EJcbG83fruowilbazpTKWUbnqUH2eD
         I+Ux7JYdypN2oWwtdi6W9iwW0Pdiqc0Hk1FrkzCPrrOKiiT9wR1e+O1SGmUwY3XkELTr
         iGrP+q/4mSXUdL5a7nzqiK0ftlU5G2lTgCM20Gs9cDUGXudmP3vW59hDy7nKnCi6pSd4
         Rh+mXcAKUV6qkxCuDWVybzmI4eFjiUWKRQyfiNInXLisp2WmIV/KRGpvzLA8PhAzFutw
         yWLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NXU1EbLT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-795591f4939si24115885a.1.2024.06.10.01.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Jun 2024 01:56:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-135-bzEBqR68Nd2N4jLdwGK0MA-1; Mon, 10 Jun 2024 04:56:05 -0400
X-MC-Unique: bzEBqR68Nd2N4jLdwGK0MA-1
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-4219cb14a23so7382765e9.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Jun 2024 01:56:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJDK4Enusg5+webfIGEIayUOQxxu3Cj7unskKtHcMMW53U3ItnpN0jNj9HBazNumOIN4wr1fhDvDHNYrWO+UUvAx2qrMuBuuagTA==
X-Received: by 2002:a05:600c:4fc1:b0:422:aca:f87e with SMTP id 5b1f17b1804b1-4220acafc07mr8547105e9.19.1718009764150;
        Mon, 10 Jun 2024 01:56:04 -0700 (PDT)
X-Received: by 2002:a05:600c:4fc1:b0:422:aca:f87e with SMTP id 5b1f17b1804b1-4220acafc07mr8546975e9.19.1718009763680;
        Mon, 10 Jun 2024 01:56:03 -0700 (PDT)
Received: from ?IPV6:2a09:80c0:192:0:5dac:bf3d:c41:c3e7? ([2a09:80c0:192:0:5dac:bf3d:c41:c3e7])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-35f23c67e70sm2326824f8f.33.2024.06.10.01.56.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Jun 2024 01:56:03 -0700 (PDT)
Message-ID: <5d9583e1-3374-437d-8eea-6ab1e1400a30@redhat.com>
Date: Mon, 10 Jun 2024 10:56:02 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of
 !ZONE_DEVICE with PageOffline() instead of PageReserved()
To: Oscar Salvador <osalvador@suse.de>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>,
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
 <20240607090939.89524-3-david@redhat.com>
 <ZmZ_3Xc7fdrL1R15@localhost.localdomain>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <ZmZ_3Xc7fdrL1R15@localhost.localdomain>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NXU1EbLT;
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

On 10.06.24 06:23, Oscar Salvador wrote:
> On Fri, Jun 07, 2024 at 11:09:37AM +0200, David Hildenbrand wrote:
>> We currently initialize the memmap such that PG_reserved is set and the
>> refcount of the page is 1. In virtio-mem code, we have to manually clear
>> that PG_reserved flag to make memory offlining with partially hotplugged
>> memory blocks possible: has_unmovable_pages() would otherwise bail out on
>> such pages.
>>
>> We want to avoid PG_reserved where possible and move to typed pages
>> instead. Further, we want to further enlighten memory offlining code about
>> PG_offline: offline pages in an online memory section. One example is
>> handling managed page count adjustments in a cleaner way during memory
>> offlining.
>>
>> So let's initialize the pages with PG_offline instead of PG_reserved.
>> generic_online_page()->__free_pages_core() will now clear that flag before
>> handing that memory to the buddy.
>>
>> Note that the page refcount is still 1 and would forbid offlining of such
>> memory except when special care is take during GOING_OFFLINE as
>> currently only implemented by virtio-mem.
>>
>> With this change, we can now get non-PageReserved() pages in the XEN
>> balloon list. From what I can tell, that can already happen via
>> decrease_reservation(), so that should be fine.
>>
>> HV-balloon should not really observe a change: partial online memory
>> blocks still cannot get surprise-offlined, because the refcount of these
>> PageOffline() pages is 1.
>>
>> Update virtio-mem, HV-balloon and XEN-balloon code to be aware that
>> hotplugged pages are now PageOffline() instead of PageReserved() before
>> they are handed over to the buddy.
>>
>> We'll leave the ZONE_DEVICE case alone for now.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
>> diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
>> index 27e3be75edcf7..0254059efcbe1 100644
>> --- a/mm/memory_hotplug.c
>> +++ b/mm/memory_hotplug.c
>> @@ -734,7 +734,7 @@ static inline void section_taint_zone_device(unsigned long pfn)
>>   /*
>>    * Associate the pfn range with the given zone, initializing the memmaps
>>    * and resizing the pgdat/zone data to span the added pages. After this
>> - * call, all affected pages are PG_reserved.
>> + * call, all affected pages are PageOffline().
>>    *
>>    * All aligned pageblocks are initialized to the specified migratetype
>>    * (usually MIGRATE_MOVABLE). Besides setting the migratetype, no related
>> @@ -1100,8 +1100,12 @@ int mhp_init_memmap_on_memory(unsigned long pfn, unsigned long nr_pages,
>>   
>>   	move_pfn_range_to_zone(zone, pfn, nr_pages, NULL, MIGRATE_UNMOVABLE);
>>   
>> -	for (i = 0; i < nr_pages; i++)
>> -		SetPageVmemmapSelfHosted(pfn_to_page(pfn + i));
>> +	for (i = 0; i < nr_pages; i++) {
>> +		struct page *page = pfn_to_page(pfn + i);
>> +
>> +		__ClearPageOffline(page);
>> +		SetPageVmemmapSelfHosted(page);
> 
> So, refresh my memory here please.
> AFAIR, those VmemmapSelfHosted pages were marked Reserved before, but now,
> memmap_init_range() will not mark them reserved anymore.

Correct.

> I do not think that is ok? I am worried about walkers getting this wrong.
> 
> We usually skip PageReserved pages in walkers because are pages we cannot deal
> with for those purposes, but with this change, we will leak
> PageVmemmapSelfHosted, and I am not sure whether are ready for that.

There are fortunately not that many left.

I'd even say marking them (vmemmap) reserved is more wrong than right: 
note that ordinary vmemmap pages after memory hotplug are not reserved! 
Only bootmem should be reserved.

Let's take at the relevant core-mm ones (arch stuff is mostly just for 
MMIO remapping)

fs/proc/task_mmu.c:     if (PageReserved(page))
fs/proc/task_mmu.c:     if (PageReserved(page))

-> If we find vmemmap pages mapped into user space we already messed up
    seriously

kernel/power/snapshot.c:        if (PageReserved(page) ||
kernel/power/snapshot.c:        if (PageReserved(page)

-> There should be no change (saveable_page() would still allow saving
    them, highmem does not apply)

mm/hugetlb_vmemmap.c:           if (!PageReserved(head))
mm/hugetlb_vmemmap.c:   if (PageReserved(page))

-> Wants to identify bootmem, but we exclude these
    PageVmemmapSelfHosted() on the splitting part already properly


mm/page_alloc.c:                VM_WARN_ON_ONCE(PageReserved(p));
mm/page_alloc.c:                if (PageReserved(page))

-> pfn_range_valid_contig() would scan them, just like for ordinary
    vmemmap pages during hotplug. We'll simply fail isolating/migrating
    them similarly (like any unmovable allocations) later

mm/page_ext.c:          BUG_ON(PageReserved(page));

-> free_page_ext handling, does not apply

mm/page_isolation.c:            if (PageReserved(page))

-> has_unmovable_pages() should still detect them as unmovable (e.g.,
    neither movable nor LRU).

mm/page_owner.c:                        if (PageReserved(page))
mm/page_owner.c:                        if (PageReserved(page))

-> Simply page_ext_get() will return NULL instead and we'll similarly
    skip them

mm/sparse.c:            if (!PageReserved(virt_to_page(ms->usage))) {

-> Detecting boot memory for ms->usage allocation, does not apply to
    vmemmap.

virt/kvm/kvm_main.c:    if (!PageReserved(page))
virt/kvm/kvm_main.c:    return !PageReserved(page);

-> For MMIO remapping purposes, does not apply to vmemmap


> Moreover, boot memmap pages are marked as PageReserved, which would be
> now inconsistent with those added during hotplug operations.

Just like vmemmap pages allocated dynamically during memory hotplug. 
Now, really only bootmem-ones are PageReserved.

> All in all, I feel uneasy about this change.

I really don't want to mark these pages here PageReserved for the sake 
of it.

Any PageReserved user that I am missing, or why we should handle these 
vmemmap pages differently than the ones allocated during ordinary memory 
hotplug?

In the future, we might want to consider using a dedicated page type for 
them, so we can stop using a bit that doesn't allow to reliably identify 
them. (we should mark all vmemmap with that type then)

Thanks!

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d9583e1-3374-437d-8eea-6ab1e1400a30%40redhat.com.
