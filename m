Return-Path: <kasan-dev+bncBDQ27FVWWUFRBXP5SHWQKGQE6F34DEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 68B20D6483
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 15:57:51 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id i20sf9835930oib.5
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 06:57:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571061470; cv=pass;
        d=google.com; s=arc-20160816;
        b=cbC4tDFcRuiuD7MeokunyDBMSsl21n+TW87yVqBSqZNB1bswG5bn5n30VwBcJa2rog
         1Ww+EG7MtTTB2R3LJPM2G77yIHkc1XYMKEf7Inlkxw39b4ta94/Htcge9ktNGoGSi7fP
         L9a2mFLd9V5M97+GorZSq0s1nRbOSmVUu99G7DdE0MKHD/OkqraC3NmDLczeWObqpKW8
         vM4EudB/E+kXa8mWDOupkqa6PJTIv56hdYS6YPWgk4OTTFjSCp4EotUg6OlY+ERaq8+X
         O663f993/7NU3Z0YpstaEm/8FaQBb1zGYBWeeKw7sxErEbRrAL2jlM30FtWBxCrV2nxy
         7d/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=HoP1YUGFNkbVlZWmwLK/yW29Ek0C65dzRqoqCCsdatw=;
        b=dPmja4v90DsB+BPogMcleTL2pRmHN6fPFVOIu8lbbRUv1943/Wvj7pHUTMcRSuGacr
         VDZ4Ggs0MP/+CfNV6Z9Eu//mpBqoY52ZiSeH+xh/m3HDxW5s8VJsWRvdCfzeQoxMlFdF
         +Rro7EJuHaQE9RTpfO9AktSnRcv9b+teco7bkIJo0d083Gn5gtKvjYUjnqDXRh6tKsoE
         KaZuZiMOmy60jiS24XYqAES4FsVC7L+D5HiMNzPZbLBXXXYQFK/ffrOsYq2sQ1wXTlge
         jFFY14Q5mmKu0wEoLzbkQvuKthfwqvdUy3GplDCJ1kOX2nMfTZIxOCwd/HmBGscZs9M8
         Ixrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=e19PdnTI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HoP1YUGFNkbVlZWmwLK/yW29Ek0C65dzRqoqCCsdatw=;
        b=ouVMW16rftCBffyjWOyQAsr6+oansiMV/vYKfiPTqHctryecfmhYccYGOopWM04CRj
         Edps/kVQNSU2EjzkILw5JhEV64+l63iusdyWaDfIdXrpeRwAxXBgSw6OL105Va7WkVe0
         pJkD5JIjS5bh1x54BpUbO8usxq08SEkWBbDzPzB+d7VkBm81g8wJ1KnQvIsv6/7D6EzI
         aLp8jLFx1BrFK0i1SjU9btzjwJfJ7EXhf16MfylMoyAzBFs2oOECbyt9CbbhbIuE0L0D
         eg9yW4PpeCS5E8k06YSrt7yPSo6pJQYIIrC12Fb4zsksue9K3tPtB6fKN4ebEvI2WuSj
         0JVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HoP1YUGFNkbVlZWmwLK/yW29Ek0C65dzRqoqCCsdatw=;
        b=FQD7ppb1ebZUEYbhKkpTy4ZVwg0dAquk7YgrCxywsB/gykM3UAq65HvTPabLCMdS23
         CHne0mN4ncCIMmAlPI58WTy67rL96RqzL56TJVjAlWvtCtOo1wSZlz5in2sCFiGCv2I+
         Wfgsihff26KRcoWZiGErZd4K7PgWIpPKRAX4ClJ1xrm3VPhFd1/EYzY+UuUIUyAYxI3Y
         OGi0BnRKLwNz4KtzH9PCS2eumxEKdWeExFQspXbs3fcGeKjVGFaKFQ6KdeQdJQdkv4QN
         JgABxlZuCx8JaSBIsC+ay3g0yvqxXHXiiniZ3AA8Qc1p79Mi5wUUH6VwoCdRSdF1b+Wn
         Kslg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWVWLRW/ixiMIyYNeZ5Mu9dUpIce7klo+p4Gu6Nb6nIJbOFZfva
	h23UzPz4viscFLjCWXKOsyA=
X-Google-Smtp-Source: APXvYqzyK1tISti4neJUgbn8RXhY0XJ9pmNRloC8Y/x4QZ1wU2dKCVaI0Z0QwOrDxWMjOJ49fcYDJA==
X-Received: by 2002:aca:4dc7:: with SMTP id a190mr24757389oib.176.1571061469935;
        Mon, 14 Oct 2019 06:57:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ed43:: with SMTP id l64ls2614272oih.3.gmail; Mon, 14 Oct
 2019 06:57:49 -0700 (PDT)
X-Received: by 2002:aca:1b04:: with SMTP id b4mr16888191oib.81.1571061469532;
        Mon, 14 Oct 2019 06:57:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571061469; cv=none;
        d=google.com; s=arc-20160816;
        b=BDfnkCVEik9whj5z/uY1jJTKlA4jS7FJTVYQe91iG2DA+xh7R/Vzzl7+6xLxowCmAK
         ZJLLKvim+gQ7noNYsRAxdRVTGCnJxrD9bAwUSDChEbeM6LtvgnKqsR6H0BzYS23cBV4k
         AmHubMR/Z+GnPj3cq1gvbcKrn4R7Vk6JZBdkDSsfJ7x4g/aXGaQBLrqqnOvTcnmmKGkQ
         Ge23zWCRLL69OSl7PdP2acW+hegtclb3RNpeQdVeXSl5FdnNISyoKmiPR+4Ah9H0Ld14
         /J1OxY5ej8afoAD/rm8WgtrhS1X85BC2TKqjfh/EgfIHExCeLLhuQWfFO81jIE6kR/Id
         3CvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=w+qQ12zqF6/LBMHQ5Fp2IFcdj8n4Em4zE18BXC0o5qc=;
        b=PiLaeE3l/DGqwKZPY2DXE95WLnx7UlT7SmqhswGLD9250QwaB8yTFvNsFSV9rVlAMU
         PPuipujgZCR9wClirdtPajl7YLkciPxo7SElkJhpgnKM3HZMPLCnO5TAIOOJ7OFKzJ08
         eUD30kV3hM/kCIdj0f4AvaG7dXWR9PbVzLZzLwA/G1zOggbpjFkI85g2weEMED/i33aT
         gwRsLFRGGP5IghvTFtgef+1x9D4EFjGFVe+3b7RUOs5GM2HfzlDgfQhxsr/uan5QxBVI
         EcLJko9VKSFqLNoqGnDE5+4JAlXdmIvzGaR+kOUl4J++G2s9LceYqPReTdX6c/OHRXVV
         eM5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=e19PdnTI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id n10si398502otf.2.2019.10.14.06.57.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 06:57:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id k20so2828263pgi.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 06:57:49 -0700 (PDT)
X-Received: by 2002:a63:1d8:: with SMTP id 207mr17320083pgb.366.1571061468959;
        Mon, 14 Oct 2019 06:57:48 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id z4sm15608752pjt.17.2019.10.14.06.57.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2019 06:57:48 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
Date: Tue, 15 Oct 2019 00:57:44 +1100
Message-ID: <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=e19PdnTI;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Andrey,


>> +	/*
>> +	 * Ensure poisoning is visible before the shadow is made visible
>> +	 * to other CPUs.
>> +	 */
>> +	smp_wmb();
>
> I'm not quite understand what this barrier do and why it needed.
> And if it's really needed there should be a pairing barrier
> on the other side which I don't see.

Mark might be better able to answer this, but my understanding is that
we want to make sure that we never have a situation where the writes are
reordered so that PTE is installed before all the poisioning is written
out. I think it follows the logic in __pte_alloc() in mm/memory.c:

	/*
	 * Ensure all pte setup (eg. pte page lock and page clearing) are
	 * visible before the pte is made visible to other CPUs by being
	 * put into page tables.
	 *
	 * The other side of the story is the pointer chasing in the page
	 * table walking code (when walking the page table without locking;
	 * ie. most of the time). Fortunately, these data accesses consist
	 * of a chain of data-dependent loads, meaning most CPUs (alpha
	 * being the notable exception) will already guarantee loads are
	 * seen in-order. See the alpha page table accessors for the
	 * smp_read_barrier_depends() barriers in page table walking code.
	 */
	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */

I can clarify the comment.

>> +
>> +	spin_lock(&init_mm.page_table_lock);
>> +	if (likely(pte_none(*ptep))) {
>> +		set_pte_at(&init_mm, addr, ptep, pte);
>> +		page = 0;
>> +	}
>> +	spin_unlock(&init_mm.page_table_lock);
>> +	if (page)
>> +		free_page(page);
>> +	return 0;
>> +}
>> +
>
>
> ...
>
>> @@ -754,6 +769,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
>>  	}
>>  
>>  insert:
>> +	kasan_release_vmalloc(orig_start, orig_end, va->va_start, va->va_end);
>> +
>>  	if (!merged) {
>>  		link_va(va, root, parent, link, head);
>>  		augment_tree_propagate_from(va);
>> @@ -2068,6 +2085,22 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>>  
>>  	setup_vmalloc_vm(area, va, flags, caller);
>>  
>> +	/*
>> +	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
>> +	 * area with real memory. If we come here through VM_ALLOC, this is
>> +	 * done by a higher level function that has access to the true size,
>> +	 * which might not be a full page.
>> +	 *
>> +	 * We assume module space comes via VM_ALLOC path.
>> +	 */
>> +	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
>> +		if (kasan_populate_vmalloc(area->size, area)) {
>> +			unmap_vmap_area(va);
>> +			kfree(area);
>> +			return NULL;
>> +		}
>> +	}
>> +
>>  	return area;
>>  }
>>  
>> @@ -2245,6 +2278,9 @@ static void __vunmap(const void *addr, int deallocate_pages)
>>  	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
>>  	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
>>  
>> +	if (area->flags & VM_KASAN)
>> +		kasan_poison_vmalloc(area->addr, area->size);
>> +
>>  	vm_remove_mappings(area, deallocate_pages);
>>  
>>  	if (deallocate_pages) {
>> @@ -2497,6 +2533,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>>  	if (!addr)
>>  		return NULL;
>>  
>> +	if (kasan_populate_vmalloc(real_size, area))
>> +		return NULL;
>> +
>
> KASAN itself uses __vmalloc_node_range() to allocate and map shadow in memory online callback.
> So we should either skip non-vmalloc and non-module addresses here or teach kasan's memory online/offline
> callbacks to not use __vmalloc_node_range() (do something similar to kasan_populate_vmalloc() perhaps?). 

Ah, right you are. I haven't been testing that.

I am a bit nervous about further restricting kasan_populate_vmalloc: I
seem to remember having problems with code using the vmalloc family of
functions to map memory that doesn't lie within vmalloc space but which
still has instrumented accesses.

On the other hand, I'm not keen on rewriting any of the memory
on/offline code if I can avoid it!

I'll have a look and get back you as soon as I can.

Thanks for catching this.

Kind regards,
Daniel

>
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/352cb4fa-2e57-7e3b-23af-898e113bbe22%40virtuozzo.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ftjvtoo7.fsf%40dja-thinkpad.axtens.net.
