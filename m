Return-Path: <kasan-dev+bncBC32535MUICBBFHRRWRQMGQEYXFUT4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 55FE2704DE0
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 14:35:34 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id a1e0cc1a2514c-780d1c6574csf4135383241.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 05:35:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684240533; cv=pass;
        d=google.com; s=arc-20160816;
        b=p9aJKAD2QpDDUTzwkrVz+k6WADYXxNGAu/Q3LIlBkrNq1xiJLTWPuQcXnBXcSFbhXy
         f/hRBH/fEg20PmgqhWKuqKtOsSw2IkQCYaPj8V4YOuf9xoI8EpwwSSgIjBIJCbb7vOQ5
         rgoWi0jTafjy0IG/5vreJAvIRYzoCVeHgxIvimfzXZtOfoyCI1E/ff/0N2+RuiZOf5Az
         d8qZKlOgSXWtdo2Tx7NUr/AGIVSw7u3YmeZ/+nafcwYu3vvlUl/olVyVnrOofbZlT3lI
         HwIUqsjEbaWYvHvrjvBVRWaH8vj+FeCsXylTubJ2Ap0gupAIgQTgB8NjCG8GtBjjUMBE
         iz9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=fuU/aIua3Lc+WOcfgZmd2L0jHnQJuszyAbAyH4pIm6o=;
        b=hEicr+RBWiLCgDhGNMvSLBycuVuO3tuSOFH0z+lua3DIIEcvYBrKNfBE4vWgvEaX7v
         nkMkFHHMbh/yB3oR/sv4yMmrXZpJN/5Yb79mNLtZBU0aRNHgm9Tw/sMi4CIE1uVijfJf
         I1vfnbgt66Ysz2TBssINCM5UpVI7jnO2f12gEAizunwqSiBB7c/8WSoPObch1QyyVi1G
         GSX9dQi25p4BzrRRM8GS8om74vgGvPZKodFzGbFgkZE6WpG8Cxy5C9tyEl71JRPBTfR6
         BZMNdJmxzTi7qVm9qkvtvTlwXfUfSJsiMCGYuDzIuD1W4ZRpWVEDXp6f9j1SRgP49OqU
         Le9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Y84TDDDW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684240533; x=1686832533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fuU/aIua3Lc+WOcfgZmd2L0jHnQJuszyAbAyH4pIm6o=;
        b=ReYIUCcFSObXJUijOOrOejQZxkVg3Vkj/GW0HtimFQq/uFFNoiCWDuD0tEV2msEqOM
         GXZfHC3kjhkgkX33+R1qr6PB7rojqyEh6PrsSMQLbf13MQ/jOzZhQBnr8NosNmmzVWe+
         FzkzjT9iGyD4MbQmboIByBX8BkUad/IVR5jcQyWJ7ooHb2/RocoKM5ZUGfNHT69skKll
         QOiUZubO/6flIEOWIRSJPN0tNX8fexbYOnLOjE9BR+61hZfPmdYP3K3GbRMtoAKfGxUD
         pTTJzmiLwImAhmsBUihxxySmjJMH4rIp2Vsdtw2YZJTvnhD5dA7n4Brx0j+5QP2y/4iw
         5u0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684240533; x=1686832533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fuU/aIua3Lc+WOcfgZmd2L0jHnQJuszyAbAyH4pIm6o=;
        b=caMHGyfyC3SPZuQgoJg0b5YFRTqERQMNzGoXWENRA0Ka04g6abugiHXrRbRid0jMdk
         MEQa1PejJ2ccoZk+hjjlGFNAXby1rqDXGpfPv1mS8RlmmqBH44pMQ9JQV1zzZy5xwNKb
         zojhZ9KDcTm31Z9k2HEXQzXzEgKr3Zgzw3u0uWF2qV3jhdvr9hDDG8MBoG4zFQ3aE4Jy
         8Ib+E21CnW79IotnyADIO1kuvx7tI85dqSynJu9vQZmMq40jR/iyFUBo1tTp2Z+ICng7
         PQooO5Wozpp7DGoUC7SxBmANYS0E0FVMgZdCvxD/abzPYAJZGDQZQaPaUxD9bcgxmMbm
         l7VQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwrLvBZiWWMgL+Qt+qV96qMyvX07wMosBl8SDnkK04jS3t1zTLZ
	Qv0oO3+oTmcUvv3YFV7PblQ=
X-Google-Smtp-Source: ACHHUZ70Uk386Dt93qugnoswv5PmGreE6RzKRpjkQ4DaI5w7sexaZJOgWROLh9EeVieyXRCuGOwx3g==
X-Received: by 2002:a05:6102:fa6:b0:436:2c61:bcae with SMTP id e38-20020a0561020fa600b004362c61bcaemr11947113vsv.3.1684240532936;
        Tue, 16 May 2023 05:35:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3b07:b0:434:5385:c48d with SMTP id
 x7-20020a0561023b0700b004345385c48dls8452770vsu.3.-pod-prod-gmail; Tue, 16
 May 2023 05:35:32 -0700 (PDT)
X-Received: by 2002:a67:eb53:0:b0:42c:900f:8486 with SMTP id x19-20020a67eb53000000b0042c900f8486mr16116512vso.27.1684240532141;
        Tue, 16 May 2023 05:35:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684240532; cv=none;
        d=google.com; s=arc-20160816;
        b=ydC3/q+Z1Dg+qVUSqlsnYGWQJeg4IwInpi3y3zSMqxvC92PS/QFY31yUJRSWsGN0Bn
         wLGC28kO6C/Pvw1QcHd9ZNoAuURZK9IfmAiD6Ms+UrCx0vQJbJ9erK5S1rPp24ucorb7
         O8hRh1qvZbcw31pw1l5VuuAT7vRAJ8YC2J/8Tljx1r4e8yAmObQFYoZ/j2LNlnZDuYaQ
         4yBlF+hwKJso3ZtuoAy4tv4gTDXO+P9aBe5EgiulF83jxQyfooqPZ+Trqdzj79y5xJbs
         QfGHdfOEiB0JgRXnF0IBlbpipaumr6KumOSkW5MnGeJb74y7DwUUik1ZMXnh60Rbzh1c
         uz9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=gPcSQRk5YWCF8SG/bxTTXXNa/kiYw7+TxfeC8KMSgkE=;
        b=hs4U+AWjYCbDrteehBLagnJ7Pu7M1wN0dPzRYxnFUGEaYEqvtkfmRhI6WZTQBXJLDP
         JvcXaAoA9/dHpXM+ndAG4ess9Ofxg+jbGcygE4A5z0qFkgigbx/STr8QXpHG60dsBefl
         4E52GkIqeVGa/BT91i2snb42f7vdMttbVEfYsil2VClM+fJKhQNzL+G4jfGYSVuiK6rn
         KJ+nPS9XMpRahCAzxI/LpOeHtDEWQ+oiZLhfSUOKvckoB9OfX+PCD68mZmXP/z+C3px7
         4u3UvfbMs/qm+vjAGCidb6dM1yfI1aglXxor3vJo71yGGvAvLlNSTpdI7i4ofTxv1vcd
         9XZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Y84TDDDW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id i25-20020a0561023d1900b0042c41134c2asi2060021vsv.1.2023.05.16.05.35.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 May 2023 05:35:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qt1-f197.google.com (mail-qt1-f197.google.com
 [209.85.160.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-349-kBNzzBJDNei2VAOriDujAA-1; Tue, 16 May 2023 08:35:28 -0400
X-MC-Unique: kBNzzBJDNei2VAOriDujAA-1
Received: by mail-qt1-f197.google.com with SMTP id d75a77b69052e-3f52eb10869so27877601cf.3
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 05:35:28 -0700 (PDT)
X-Received: by 2002:a05:622a:1750:b0:3ef:61d9:bc6d with SMTP id l16-20020a05622a175000b003ef61d9bc6dmr58465836qtk.14.1684240528261;
        Tue, 16 May 2023 05:35:28 -0700 (PDT)
X-Received: by 2002:a05:622a:1750:b0:3ef:61d9:bc6d with SMTP id l16-20020a05622a175000b003ef61d9bc6dmr58465796qtk.14.1684240527879;
        Tue, 16 May 2023 05:35:27 -0700 (PDT)
Received: from ?IPV6:2003:cb:c74f:2500:1e3a:9ee0:5180:cc13? (p200300cbc74f25001e3a9ee05180cc13.dip0.t-ipconnect.de. [2003:cb:c74f:2500:1e3a:9ee0:5180:cc13])
        by smtp.gmail.com with ESMTPSA id p3-20020a05620a112300b0075902dffce7sm553768qkk.100.2023.05.16.05.35.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 05:35:27 -0700 (PDT)
Message-ID: <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
Date: Tue, 16 May 2023 14:35:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com>
 <ZGLC0T32sgVkG5kX@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <ZGLC0T32sgVkG5kX@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Y84TDDDW;
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

On 16.05.23 01:40, Peter Collingbourne wrote:
> On Mon, May 15, 2023 at 06:34:30PM +0100, Catalin Marinas wrote:
>> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
>>> On 13.05.23 01:57, Peter Collingbourne wrote:
>>>> diff --git a/mm/memory.c b/mm/memory.c
>>>> index 01a23ad48a04..83268d287ff1 100644
>>>> --- a/mm/memory.c
>>>> +++ b/mm/memory.c
>>>> @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>>    		}
>>>>    	}
>>>> -	/*
>>>> -	 * Remove the swap entry and conditionally try to free up the swapcache.
>>>> -	 * We're already holding a reference on the page but haven't mapped it
>>>> -	 * yet.
>>>> -	 */
>>>> -	swap_free(entry);
>>>> -	if (should_try_to_free_swap(folio, vma, vmf->flags))
>>>> -		folio_free_swap(folio);
>>>> -
>>>> -	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
>>>> -	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
>>>>    	pte = mk_pte(page, vma->vm_page_prot);
>>>> -
>>>>    	/*
>>>>    	 * Same logic as in do_wp_page(); however, optimize for pages that are
>>>>    	 * certainly not shared either because we just allocated them without
>>>> @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>>    		pte = pte_mksoft_dirty(pte);
>>>>    	if (pte_swp_uffd_wp(vmf->orig_pte))
>>>>    		pte = pte_mkuffd_wp(pte);
>>>> +	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>>>>    	vmf->orig_pte = pte;
>>>> +	/*
>>>> +	 * Remove the swap entry and conditionally try to free up the swapcache.
>>>> +	 * We're already holding a reference on the page but haven't mapped it
>>>> +	 * yet.
>>>> +	 */
>>>> +	swap_free(entry);
>>>> +	if (should_try_to_free_swap(folio, vma, vmf->flags))
>>>> +		folio_free_swap(folio);
>>>> +
>>>> +	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
>>>> +	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
>>>> +
>>>>    	/* ksm created a completely new copy */
>>>>    	if (unlikely(folio != swapcache && swapcache)) {
>>>>    		page_add_new_anon_rmap(page, vma, vmf->address);
>>>> @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>>    	VM_BUG_ON(!folio_test_anon(folio) ||
>>>>    			(pte_write(pte) && !PageAnonExclusive(page)));
>>>>    	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
>>>> -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>>>>    	folio_unlock(folio);
>>>>    	if (folio != swapcache && swapcache) {
>>>
>>>
>>> You are moving the folio_free_swap() call after the folio_ref_count(folio)
>>> == 1 check, which means that such (previously) swapped pages that are
>>> exclusive cannot be detected as exclusive.
>>>
>>> There must be a better way to handle MTE here.
>>>
>>> Where are the tags stored, how is the location identified, and when are they
>>> effectively restored right now?
>>
>> I haven't gone through Peter's patches yet but a pretty good description
>> of the problem is here:
>> https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/.
>> I couldn't reproduce it with my swap setup but both Qun-wei and Peter
>> triggered it.
> 
> In order to reproduce this bug it is necessary for the swap slot cache
> to be disabled, which is unlikely to occur during normal operation. I
> was only able to reproduce the bug by disabling it forcefully with the
> following patch:
> 
> diff --git a/mm/swap_slots.c b/mm/swap_slots.c
> index 0bec1f705f8e0..25afba16980c7 100644
> --- a/mm/swap_slots.c
> +++ b/mm/swap_slots.c
> @@ -79,7 +79,7 @@ void disable_swap_slots_cache_lock(void)
>   
>   static void __reenable_swap_slots_cache(void)
>   {
> -	swap_slot_cache_enabled = has_usable_swap();
> +	swap_slot_cache_enabled = false;
>   }
>   
>   void reenable_swap_slots_cache_unlock(void)
> 
> With that I can trigger the bug on an MTE-utilizing process by running
> a program that enumerates the process's private anonymous mappings and
> calls process_madvise(MADV_PAGEOUT) on all of them.
> 
>> When a tagged page is swapped out, the arm64 code stores the metadata
>> (tags) in a local xarray indexed by the swap pte. When restoring from
>> swap, the arm64 set_pte_at() checks this xarray using the old swap pte
>> and spills the tags onto the new page. Apparently something changed in
>> the kernel recently that causes swap_range_free() to be called before
>> set_pte_at(). The arm64 arch_swap_invalidate_page() frees the metadata
>> from the xarray and the subsequent set_pte_at() won't find it.
>>
>> If we have the page, the metadata can be restored before set_pte_at()
>> and I guess that's what Peter is trying to do (again, I haven't looked
>> at the details yet; leaving it for tomorrow).
>>
>> Is there any other way of handling this? E.g. not release the metadata
>> in arch_swap_invalidate_page() but later in set_pte_at() once it was
>> restored. But then we may leak this metadata if there's no set_pte_at()
>> (the process mapping the swap entry died).
> 
> Another problem that I can see with this approach is that it does not
> respect reference counts for swap entries, and it's unclear whether that
> can be done in a non-racy fashion.
> 
> Another approach that I considered was to move the hook to swap_readpage()
> as in the patch below (sorry, it only applies to an older version
> of Android's android14-6.1 branch and not mainline, but you get the
> idea). But during a stress test (running the aforementioned program that
> calls process_madvise(MADV_PAGEOUT) in a loop during an Android "monkey"
> test) I discovered the following racy use-after-free that can occur when
> two tasks T1 and T2 concurrently restore the same page:
> 
> T1:                  | T2:
> arch_swap_readpage() |
>                       | arch_swap_readpage() -> mte_restore_tags() -> xe_load()
> swap_free()          |
>                       | arch_swap_readpage() -> mte_restore_tags() -> mte_restore_page_tags()
> 
> We can avoid it by taking the swap_info_struct::lock spinlock in
> mte_restore_tags(), but it seems like it would lead to lock contention.
> 

Would the idea be to fail swap_readpage() on the one that comes last, 
simply retrying to lookup the page?

This might be a naive question, but how does MTE play along with shared 
anonymous pages?

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/851940cd-64f1-9e59-3de9-b50701a99281%40redhat.com.
