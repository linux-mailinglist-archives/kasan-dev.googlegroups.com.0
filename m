Return-Path: <kasan-dev+bncBC32535MUICBBCHPRWRQMGQESWXZQQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C64CC704DCF
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 14:31:05 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-3f41dcf1e28sf39462085e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 05:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684240265; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cv9/QXAi6jciWw0pUNyIFat65LuHvyI+l0yE3F+iTmyVmT+sRlUfGTGiJ7s5LMpQ1z
         snVV8KCcbrRJhhaAMhyhBhvd98ZH1FnSNzmfZOr/aX/hsLWLEOmgzUGWn9PPTP/4v2D7
         /9BIgMfpYXWor512Yx0bCPXLr2MP4fKnfk5FMHxcls8GCsDjSeeqrppbgSP4xzuiS/ys
         CSQyUkabAaGIQ4E3t8FEurPFcmT1lDWyYeK+0B/a5U0s1AECjNT8ZX/AFhz+emNcv2Zc
         JiOBPRThgcmgUG/y2lkZtaF7ZWFm0vrzP9ILqcdl/tWPjW+tQQptFeJ9G3YASz3wbZsP
         GlmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=r8hBGJVkJRDgEMgUkw7DW4P75P2Vvwvm6WMaifzG7YQ=;
        b=JiLX1uMpAmOT3GS7QjQAd9Dg5wT3ceu7rjKW9q9s6ycmZSaBlsHoOLkL3KV1VmYvMc
         cScPdy0vsllnOX1VZpoPrOdanFoE1TvjZLzol/gUHdtk1f9Gmfh5RbsIbU03XESQGd+t
         gM1EkYQE/dDJJM9IA+L8hQ/H5CaHZQtvmJjxzT0xOCUSGiGR5+6yAOBXF8O47kboGDY7
         9Ngooa2p2zUaUfEkIjbp+vGHqkRg36ujT+67b4l6XdFr1iKAiA6fh7LbMrfhOgX94hYV
         +jxg1b7uZO6LQqWMUndcZ3LZtBN8gacVqsof7/xXs/xiudNSyEZUdCqeWtKLjVpUo2mT
         Ei7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MrORSBVn;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684240265; x=1686832265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=r8hBGJVkJRDgEMgUkw7DW4P75P2Vvwvm6WMaifzG7YQ=;
        b=Yoae9fwg6DYSb2HYwB9chrYR7keFVt67DOYiIiVXd2vo7PTS969JAGZEsDT9ndHpab
         DFOCDuLMNLerecgiUzPpvrslKiKZGuQh7Dhzbx06/xyl1eIhfX4JvTCSUgCRIjWP7NuU
         mHmoU0Lh24zPwhSoxRyQ9xdBJcrO/4l9Tp1TpZiLsG4TCBJnU3c2CM713/LzUAmvLljb
         x6DNKgC38AJhVM9eR3EI88wvWl10vzZGAETE0HnQ5PrJ8bivb8ifEBlXf1QyachPoY28
         +9r+4B3W2PE5endiHgcDSf50FXuuhgXEw+iCAnheUNHidJMZmo7jpQ7oeSCqgROEnS99
         OKPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684240265; x=1686832265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r8hBGJVkJRDgEMgUkw7DW4P75P2Vvwvm6WMaifzG7YQ=;
        b=j68tafn00D0w36QML7cYNhUpR3OB6pwAvAZCCV7X9jTtIhqofwiRbQ3igbiLmE2npl
         kXIgZGpiG9vxkg+VidVIyvMC6i59o40ucKeQWQojHFoIVcDU0iMGCN4lMRTf+KC/DmYi
         FRXsPca7MlYeNTjLuUlppXcg43FGDsDx6NfPQfC40cXd4MQCDJk6kSnllMzIXhWRjLXk
         NhxLnjJcO9gpIZDq9HbP343ihnXKES6469ozCOXN3iuhU1py0KnA98vRnsTA/iwe9WZV
         EtvAr6A4oJ8dhWZiy2g6FDmRDsj+NjJJv4LhkxzkW3SgJjSW/I/xMEUPLGldv5UBwQ6V
         JheA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzsSF+8bgIFR4dKv9bnJp1rs3e/EU8atGTrD2KHRXIUB6ZEvgUA
	14XOlbvdbdfkyfTWGjTIdS8=
X-Google-Smtp-Source: ACHHUZ7BLGOUywnRsFdK8OnbSt9K+GzY9M9eR1rH2BIWQVc6jRFGujlomDKTSU+x+TIGhdtS4ylQTQ==
X-Received: by 2002:a5d:44cd:0:b0:2e5:756b:8e77 with SMTP id z13-20020a5d44cd000000b002e5756b8e77mr4888041wrr.11.1684240264998;
        Tue, 16 May 2023 05:31:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b13:b0:3f5:1738:4eef with SMTP id
 m19-20020a05600c3b1300b003f517384eefls534588wms.3.-pod-control-gmail; Tue, 16
 May 2023 05:31:03 -0700 (PDT)
X-Received: by 2002:a05:600c:cf:b0:3f4:2a70:b38f with SMTP id u15-20020a05600c00cf00b003f42a70b38fmr17559184wmm.24.1684240263180;
        Tue, 16 May 2023 05:31:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684240263; cv=none;
        d=google.com; s=arc-20160816;
        b=fdQlo7990H2lI/c57didb3hGKxrBT+CCS0DJGFYUcp6OLiBUCYljiosYRVOO1rFviZ
         quJFSbvsV/h200Iqw8UejNKcuq+ViWYBIzETLS2dUy6oY63OTB/0uonFRov3iUQpMgB9
         jRDoaEAeFnqDwT5TAiE1oaAI1EmZPwT7h21X49S6p561cuL4o93uyOiDnALbRQrePdmb
         wvXXCteM34jCXsOGgeCcj5ZqAnE1DJnnUj8REkvJ8iYRNBFJyg0MvS7VDMDAisPQAj+W
         rB0TRMWgKxWmoKsa5GM1fcLsfBAAArN2yvFKOI3J22my1tGs85FMcsG7ChI7IHvVGOUY
         LS5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ALMVvYlZxEE1m2+2KXk6OCrrF6yVXPnBatrbCWbyCNQ=;
        b=Z1Tk46c9iukmwX/VQJ4n1suClxk+uIjTBXUWInfAky6AL4JwHipW8YovO9G35ZtTvp
         bEAaoVmbaIPvx55FY6vR4eI7qSiKtVmYvvkppkf4XhJLp8Zd7DdAaslq1+SBrraX+C6y
         cbEL36WWcx1oES3ulJU7SpgL2/byrZDWRvsUXL9fnzf/E6LMb9AOEcCP2xhh2VUvjxpm
         EMlUJMiVSPLrWvXc2ROZblfNljZ2ssOZ2GuaXOt1dW3LOyyimvuhTRH4EsA7kBueopGx
         1hThbp3RMSP3+yV23V51Q/x4S+58zGgOc/NRYGOARFC+am7ljE+Xw0JlFXtG2Pi5NBDx
         gssw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MrORSBVn;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id fm8-20020a05600c0c0800b003f4276a712bsi116993wmb.1.2023.05.16.05.31.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 May 2023 05:31:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-588-ewaWtIkgOlayba8JIqg39Q-1; Tue, 16 May 2023 08:31:01 -0400
X-MC-Unique: ewaWtIkgOlayba8JIqg39Q-1
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-3f426d4944fso35177895e9.1
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 05:31:00 -0700 (PDT)
X-Received: by 2002:a1c:7507:0:b0:3f1:9acf:8682 with SMTP id o7-20020a1c7507000000b003f19acf8682mr23702006wmc.17.1684240259567;
        Tue, 16 May 2023 05:30:59 -0700 (PDT)
X-Received: by 2002:a1c:7507:0:b0:3f1:9acf:8682 with SMTP id o7-20020a1c7507000000b003f19acf8682mr23701988wmc.17.1684240259166;
        Tue, 16 May 2023 05:30:59 -0700 (PDT)
Received: from ?IPV6:2003:cb:c74f:2500:1e3a:9ee0:5180:cc13? (p200300cbc74f25001e3a9ee05180cc13.dip0.t-ipconnect.de. [2003:cb:c74f:2500:1e3a:9ee0:5180:cc13])
        by smtp.gmail.com with ESMTPSA id v10-20020a05600c214a00b003f50e88ffb5sm2233741wml.24.2023.05.16.05.30.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 05:30:58 -0700 (PDT)
Message-ID: <91246137-a3d2-689f-8ff6-eccc0e61c8fe@redhat.com>
Date: Tue, 16 May 2023 14:30:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
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
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
In-Reply-To: <ZGJtJobLrBg3PtHm@arm.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MrORSBVn;
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

On 15.05.23 19:34, Catalin Marinas wrote:
> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
>> On 13.05.23 01:57, Peter Collingbourne wrote:
>>> diff --git a/mm/memory.c b/mm/memory.c
>>> index 01a23ad48a04..83268d287ff1 100644
>>> --- a/mm/memory.c
>>> +++ b/mm/memory.c
>>> @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>    		}
>>>    	}
>>> -	/*
>>> -	 * Remove the swap entry and conditionally try to free up the swapcache.
>>> -	 * We're already holding a reference on the page but haven't mapped it
>>> -	 * yet.
>>> -	 */
>>> -	swap_free(entry);
>>> -	if (should_try_to_free_swap(folio, vma, vmf->flags))
>>> -		folio_free_swap(folio);
>>> -
>>> -	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
>>> -	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
>>>    	pte = mk_pte(page, vma->vm_page_prot);
>>> -
>>>    	/*
>>>    	 * Same logic as in do_wp_page(); however, optimize for pages that are
>>>    	 * certainly not shared either because we just allocated them without
>>> @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>    		pte = pte_mksoft_dirty(pte);
>>>    	if (pte_swp_uffd_wp(vmf->orig_pte))
>>>    		pte = pte_mkuffd_wp(pte);
>>> +	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>>>    	vmf->orig_pte = pte;
>>> +	/*
>>> +	 * Remove the swap entry and conditionally try to free up the swapcache.
>>> +	 * We're already holding a reference on the page but haven't mapped it
>>> +	 * yet.
>>> +	 */
>>> +	swap_free(entry);
>>> +	if (should_try_to_free_swap(folio, vma, vmf->flags))
>>> +		folio_free_swap(folio);
>>> +
>>> +	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
>>> +	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
>>> +
>>>    	/* ksm created a completely new copy */
>>>    	if (unlikely(folio != swapcache && swapcache)) {
>>>    		page_add_new_anon_rmap(page, vma, vmf->address);
>>> @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>>    	VM_BUG_ON(!folio_test_anon(folio) ||
>>>    			(pte_write(pte) && !PageAnonExclusive(page)));
>>>    	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
>>> -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>>>    	folio_unlock(folio);
>>>    	if (folio != swapcache && swapcache) {
>>
>>
>> You are moving the folio_free_swap() call after the folio_ref_count(folio)
>> == 1 check, which means that such (previously) swapped pages that are
>> exclusive cannot be detected as exclusive.
>>
>> There must be a better way to handle MTE here.
>>
>> Where are the tags stored, how is the location identified, and when are they
>> effectively restored right now?
> 
> I haven't gone through Peter's patches yet but a pretty good description
> of the problem is here:
> https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/.
> I couldn't reproduce it with my swap setup but both Qun-wei and Peter
> triggered it.
> 
> When a tagged page is swapped out, the arm64 code stores the metadata
> (tags) in a local xarray indexed by the swap pte. When restoring from
> swap, the arm64 set_pte_at() checks this xarray using the old swap pte
> and spills the tags onto the new page. Apparently something changed in
> the kernel recently that causes swap_range_free() to be called before
> set_pte_at(). The arm64 arch_swap_invalidate_page() frees the metadata
> from the xarray and the subsequent set_pte_at() won't find it.
> 
> If we have the page, the metadata can be restored before set_pte_at()
> and I guess that's what Peter is trying to do (again, I haven't looked
> at the details yet; leaving it for tomorrow).

Thanks for the details! I was missing that we also have a hook in 
swap_range_free().

> 
> Is there any other way of handling this? E.g. not release the metadata
> in arch_swap_invalidate_page() but later in set_pte_at() once it was
> restored. But then we may leak this metadata if there's no set_pte_at()
> (the process mapping the swap entry died).

That was my immediate thought: do we really have to hook into 
swap_range_free() at all? And I also wondered why we have to do this 
from set_pte_at() and not do this explicitly (maybe that's the other 
arch_* callback on the swapin path).

I'll have a look at v2, maybe it can be fixed easily without having to 
shuffle around too much of the swapin code (which can easily break again 
because the dependencies are not obvious at all and even undocumented in 
the code).

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91246137-a3d2-689f-8ff6-eccc0e61c8fe%40redhat.com.
