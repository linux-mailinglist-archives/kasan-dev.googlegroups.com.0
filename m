Return-Path: <kasan-dev+bncBC5L5P75YUERBSN5QPWQKGQEVVCNLAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8335CD48C6
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2019 21:58:01 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id t84sf2117014lff.10
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2019 12:58:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570823881; cv=pass;
        d=google.com; s=arc-20160816;
        b=VL3AjKBv1ufyTZwqKJUHh7x23SPJyM2Z4j5RpNxE+4cYBmZIUByBfrF5z8pjGAfp0z
         3iUwFpsTIkPT3WdAWoP9IeaQxnei5MMK0azZX3JXQgu3K83sdG4/O4A9EBHZjGxSJpUa
         Os8FWr/zlDm/E1C/hvK0loZdHOTUCgJz9YuF5DjfqB2edFGWJyBl3JyZy2ffdAJTL5Ho
         4o7QcGy5/QMgqRcBRUsQ6SGXNXhnvNZEgwlhickgCCsIWKeadXyL5BVtFOdVGi44W1On
         Bwbv14D4ddXaGfSsEqHHxgGZNgfRy1vgM44ligvD44nqutkiCnFjMC2gJE5oKPC76i6z
         FRvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=gAjnQ04Yx9jAkkGsrNbHTV1uo1oZ5wWA37Ld9ogPv0M=;
        b=Z9ROckC80QQm+lhg5VKFAQ420e8NrT8tE1FDjXSr/C9ChLCvSIws5+KRY58c5+44ao
         AbvaX4wVpfJkJFLz5kWhTOb1OupTemBqurac3HEdTQ8hgP9t70Q3RmR2bacx94T76tyG
         03v9avXDSV0pFoRGXSJMCRJQTrz5cpzjfqaGNDNG6XkE20nX5O6zSH3GNtY/LqEGdMaY
         /6EBKAyelcaTqlRuwVQvk7U3ZDVI1Hp9O3fMnf5isqMsq+MyyBhOJ0bjt3sdMiaBunaD
         o9vkJzLzjITF/akM2cjVcCM2JUnkBBpBvIiGAgLKqs6RflL1NcJ4RhLxsuysuSHgUSZG
         AhDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gAjnQ04Yx9jAkkGsrNbHTV1uo1oZ5wWA37Ld9ogPv0M=;
        b=l0k8p3TdtHu8OQ108AS8s4fBzc2PZx6lsDIEQBAQbJXPOnup4ampLeIQwF5ngiOv8a
         5EOymtNW6eyqne8T+POJKrrovICpQhEMaxMPSUzog1zWuNuN77+HUnfS+2zu0QGAAa6g
         C5hOkZfzpe+8dN/CHjAqzXxvHOQQOEbpRNksb1VyZlJUJx7O+bkbQNLBRVPoUF6lvbeC
         luu7m6n4U1x+2S5hbeWjPvTWltop0r4Knd0pMXOm4xVR3PMEFv99xG2DR2K+iFXtA64z
         wEY9Z4/XET4mIGtcABpIblfWHQuBEoUQuxIAvCoE/+Mqcocgail21tN8OqFbLIy9R3Yi
         tnyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gAjnQ04Yx9jAkkGsrNbHTV1uo1oZ5wWA37Ld9ogPv0M=;
        b=ZuyqHPeu/sa3QOSKY2QByhcqaJb6x0Z6csVqdq15TTxzgwRMDZ9gtIWCLCkeFkDQMh
         IVu2lcvVUmuVOKqEt8eOIwmQEXB6Gs3Vatf1/pwgnYhKmEO/Jj6TzxWtGnVTJcaTFCjC
         z+0Mqv1cI6pqVdON4cK1yYQob5tgRaeX/zUn+yA3G4ljnTtrp2IU6Cz/yWNXz/fWjbBJ
         6KJHMGIiGSrfVCKpO6xyIBpX5zAFtTkSWl12z0+ppBDH3ZPmm/k8b5aOayyqd/KiRnoH
         Ta865PSyTuQgignk9BBNNWCNY2LA0hpsFO/zv/ljXlvaUeKOuzOWef07H0H9i9LXvxbX
         gF2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVMOqOiCTJ69GCw8mI0n64MRc0y+G840P3114fBZaqZzOOH0yO
	jTY4wN1s4LxvJl5+2UwxX4I=
X-Google-Smtp-Source: APXvYqzsdu8hbguKvH83LGpGc9XWSwH21KOevEBh0IdNcEYPB64q69+nJBh2xpKiu7dlRubTmhRX6w==
X-Received: by 2002:ac2:46ed:: with SMTP id q13mr7107386lfo.187.1570823881138;
        Fri, 11 Oct 2019 12:58:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2286:: with SMTP id i128ls1122673lji.7.gmail; Fri, 11
 Oct 2019 12:58:00 -0700 (PDT)
X-Received: by 2002:a2e:9695:: with SMTP id q21mr10258368lji.105.1570823880615;
        Fri, 11 Oct 2019 12:58:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570823880; cv=none;
        d=google.com; s=arc-20160816;
        b=UYF2H+zbXNXw58O7Cu/ddw+weqV8meP+CaycV0rHe26tciOsf4e9eVVAaHH4Gpccc0
         Gzz8j586V7ROKDYtwZVMJVbJsHi9RV73KkMmMUWC8cia0KAUg4bOdMc0kuwdBnFPu5Hy
         erbTnLh0Jd8IV+pGSsWSKbx6YzIpDzotMCokN+AtVIt+Uhc8r5elqr4aMTHemeCKdH1c
         l23Bk5HGWJX6ZH2eND8uqxnz+c7qBFraitGuCuwq0qhEJToXMpK0xO6HOalPWNIuAB4U
         rlRDccPHVRG1+UT10cJaOknD28hfWBb5luADLugvek+XcYsUnd/tzaS4kzcBSVLYeYdY
         +BoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=R/hHiMZW1/sCbcWTSv3/PUDpwhmhjmnFIf+gkWTJHT8=;
        b=CW+ssuucM26C51ZwO4NefxYA6hrtV94/lZ4/Hhoq9vzyqOyxvz79fcBba08FqNqihG
         DS8Bk9QkY2X6t0QFAcI75S2AagGhob/xxTUwBVaKcjH2AElW3OlL3XDpHgaX16Lx90IW
         yvrSMo4oi4taHurhfksfnHLOhKWl1D0VGYOoOl1Bwl0S5WADl4OBXWUG1SvRpckZlM+i
         /fhUA1kVFSS/1Ob4Q1I9FIGvKEZj7tBfOH2uRxuhOaivC75oemg/mZOIHj3SOEf+ldDx
         AIEXih/Y4fyVUrB/44IjM2W6BDXNTEsMoNy+1ByDZvVHrM/Z+YsE0Alg06Xx1isvldwd
         upfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id a9si214481lfk.5.2019.10.11.12.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Oct 2019 12:58:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iJ12k-00055b-MW; Fri, 11 Oct 2019 22:57:42 +0300
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
Date: Fri, 11 Oct 2019 22:57:28 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191001065834.8880-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 10/1/19 9:58 AM, Daniel Axtens wrote:
 
>  core_initcall(kasan_memhotplug_init);
>  #endif
> +
> +#ifdef CONFIG_KASAN_VMALLOC
> +static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +				      void *unused)
> +{
> +	unsigned long page;
> +	pte_t pte;
> +
> +	if (likely(!pte_none(*ptep)))
> +		return 0;
> +
> +	page = __get_free_page(GFP_KERNEL);
> +	if (!page)
> +		return -ENOMEM;
> +
> +	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> +	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> +
> +	/*
> +	 * Ensure poisoning is visible before the shadow is made visible
> +	 * to other CPUs.
> +	 */
> +	smp_wmb();

I'm not quite understand what this barrier do and why it needed.
And if it's really needed there should be a pairing barrier
on the other side which I don't see.

> +
> +	spin_lock(&init_mm.page_table_lock);
> +	if (likely(pte_none(*ptep))) {
> +		set_pte_at(&init_mm, addr, ptep, pte);
> +		page = 0;
> +	}
> +	spin_unlock(&init_mm.page_table_lock);
> +	if (page)
> +		free_page(page);
> +	return 0;
> +}
> +


...

> @@ -754,6 +769,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	}
>  
>  insert:
> +	kasan_release_vmalloc(orig_start, orig_end, va->va_start, va->va_end);
> +
>  	if (!merged) {
>  		link_va(va, root, parent, link, head);
>  		augment_tree_propagate_from(va);
> @@ -2068,6 +2085,22 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>  
>  	setup_vmalloc_vm(area, va, flags, caller);
>  
> +	/*
> +	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
> +	 * area with real memory. If we come here through VM_ALLOC, this is
> +	 * done by a higher level function that has access to the true size,
> +	 * which might not be a full page.
> +	 *
> +	 * We assume module space comes via VM_ALLOC path.
> +	 */
> +	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
> +		if (kasan_populate_vmalloc(area->size, area)) {
> +			unmap_vmap_area(va);
> +			kfree(area);
> +			return NULL;
> +		}
> +	}
> +
>  	return area;
>  }
>  
> @@ -2245,6 +2278,9 @@ static void __vunmap(const void *addr, int deallocate_pages)
>  	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
>  	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
>  
> +	if (area->flags & VM_KASAN)
> +		kasan_poison_vmalloc(area->addr, area->size);
> +
>  	vm_remove_mappings(area, deallocate_pages);
>  
>  	if (deallocate_pages) {
> @@ -2497,6 +2533,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	if (!addr)
>  		return NULL;
>  
> +	if (kasan_populate_vmalloc(real_size, area))
> +		return NULL;
> +

KASAN itself uses __vmalloc_node_range() to allocate and map shadow in memory online callback.
So we should either skip non-vmalloc and non-module addresses here or teach kasan's memory online/offline
callbacks to not use __vmalloc_node_range() (do something similar to kasan_populate_vmalloc() perhaps?). 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/352cb4fa-2e57-7e3b-23af-898e113bbe22%40virtuozzo.com.
