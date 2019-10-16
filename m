Return-Path: <kasan-dev+bncBC5L5P75YUERBCUWTTWQKGQEWMAWO7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 378ECD90A2
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 14:20:27 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id n14sf14172711edt.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 05:20:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571228427; cv=pass;
        d=google.com; s=arc-20160816;
        b=ndOcX/yTo0fvLUD8w0y9+BbVwiqn9WkTFCg9XKnqZ94P8m/Yk66vMnwOxCY+8+/NRe
         22kR8KAELe+eOWDGGmkxrpVTECQwnlxmRqXUJqELf+UpLSMP5xUDhqRy5bHA+eIJU8Dj
         ICoHye5j9dupWPBmsGR2o5RcRApXZBKS9XXPHnnyuLzPvcbW6pyjh+WXj+bdMeB1ZRXS
         Ym9xG8iuOYv7ltsI00A/cbQAOSfDIAQ3Z/4VFh1IPVXdIKDu2aJvK3NZSMo9FK9XivJ2
         9KdrwawrK8TYYHeJpUKVgu5O9iDoDRkiD88t8wo8slMrwRy2hngZvESBfFDxIK1g81wq
         Z8Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=m/K8fN9AVZMktjhRXglnbBR0ConAI+J6zwUlnO+IEF0=;
        b=TEm/F5u20DqA8MiIzM/GlmeYDdwiBY7jG604B+F1r9t92UDk7R+ALWPOi3kXpGvY7o
         U+gcF7lHjKThNfB0l+y8eVIFRDro9nPZqy8+XZhvJQiVs3JEJBv5j/t2I/6SaorMRsk+
         JqYfvu6LvkLYYuYKVdl17LVOuebSDRzGUhlJiFgr10Gbf0QQdHZrTGdsFrrOdcyt4/lw
         1Ku142TG5UYYHRmGhUdckpvOJJA2b/CucQXEinTmuGhCLqRqy2xMK101/X+x5AtDP1nf
         8lJokClMG54/CrfCf5K8Payxw7bJA47YrQa8L6BHVLLpQZdB5gokKldPW3Wd5iSnAXzw
         58OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m/K8fN9AVZMktjhRXglnbBR0ConAI+J6zwUlnO+IEF0=;
        b=rp9SPgIa3uMCBnDI5a/i4H0pZjn2l9AnMnza3ruyWvz8C3H0n0KXCa9iIW/4hJP9me
         44PWo9ASAK7Cl85ATgB9PbJb75KxbWjBjSfMBx8fxdK6K5Bj6tu8US+YZVlJWaBVGbWA
         1rVjk31yVC1ThUG37X7jjtY9K7Wr7aV50aNz6b8lAsYTuzFc8bVF8QkI7w5PsS0p9UkM
         FffeCxlZgpxuyCd6NGNo0xf30LL5Xg0ktkNAfrsU4XQjEveIQlKF30QmqjdXtC7TIR2x
         uHCmP7bKoslYamj8DsZQiRqXArGzLYT2zcxzOgyUqsUW0rZmdFf5Y1mBH4wQlnptuJ1T
         VCnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=m/K8fN9AVZMktjhRXglnbBR0ConAI+J6zwUlnO+IEF0=;
        b=dD+JF/6tZ3MbCL9erjGEuJq0OTyy2PKq8BScIq7V9V0WvfGlnY9zwT5X/ro0DynUxX
         uK3T1Q+3jJnQ0PKAIoGOTAFTKyXZSvM8dOZPSGNKN+G7yd0P8QyVwP24c5MmAkWRscbe
         HZtsnlQCMcOa/vQJPiu1s90a8Wg2QNJe9PsCkndACJjx1b3C8ybiZ3V0A3WOqZ5BC+5l
         fFEmCJ6n3/tRxCtDShhzfkFvdFst1BKTn6wZqBuQB4iKUTnv6Bwu+Wi6Hjgtxfbq820D
         YZg+xYuAO85RxCnaLSZHm2bI3hJPAYgButjgPZcaW/qFs7FIaWo1pkroGehBSYUCy14g
         kj8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX2NCkPkZeEjzJ4pRGrLsvI7mwz+xH2YsGYKvwcvjMu5D/l0fPA
	5cbntPCW/2q2dG0ku7Bx/vo=
X-Google-Smtp-Source: APXvYqyi/839lgjE8l5UTrByrYNS0GoFi9ucQsOHJCUBO0m7Oi9vhn5o61G/b5oA4Ei2K4QULkCdjA==
X-Received: by 2002:aa7:cb55:: with SMTP id w21mr38567017edt.163.1571228426912;
        Wed, 16 Oct 2019 05:20:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1114:: with SMTP id qu20ls5505631ejb.7.gmail; Wed,
 16 Oct 2019 05:20:26 -0700 (PDT)
X-Received: by 2002:a17:906:6b88:: with SMTP id l8mr39198269ejr.26.1571228426416;
        Wed, 16 Oct 2019 05:20:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571228426; cv=none;
        d=google.com; s=arc-20160816;
        b=HWq6JMPCmf3AbVpH27mAWwQY87dVZEkkZLoqWRCf0kG0jOHuivsmDVbV0jPHVSiuLm
         GRB1EZmXNX/2TURD0mPNoK/PjNlA6iph6c4qlnz2Du+/oeZMLKRC1JSx+j/G8FWy7Nse
         F8/BTIeWvPcanCzm+g3MPwzSyF0LYw73PLO87kjJuEJGjGko0skz7dftGeaCVFHyNhVk
         rk3r8CyKfcSEloq51WdZlDiBSIozyJuACB7XNGIiA3Tz3Rm+IptbaGCpVi7Rtqu+SCqc
         7ZK5Ng761PYlnk/rrz0B95Kcsp6W6rymj+uK/wmaw1LWLneY16dxvptE0r36xxBmvsu8
         mivA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Jq/tsV7Lm5n8084E0gIIIWYMGCTHrmGAB5HYKC5b4TM=;
        b=A5zlp5UdlQkwWTUYQx1oqdCqzw1MOxBN+T3PGGs7JyUxq5FxIn5yQ1efVQyrMmIJOV
         Cc/wKCanxwBauQPupgqN5m+GnUmSx+jMU0utAQgQ7IYEPwKSLwXBbHDsxZjRNjE6N9H4
         H3O05BvEf+LyxHF+YphNhnoZGbpw1YAObVPYHrvBs2TV8e3dbUfYSbzi4sMGBMvhrxNJ
         88NuqaezjGgDwLnSmI8gR51yYM7HbFejr7bvCMFfrUv+kFnlZtToSCPMve5GB4MXqdyL
         pDn0bW9XmMwL5Cesc6ZWquClJ0zWdK4Z5jLkLVQ2wIZo0PIFCZuQk5BNN77qoPakDtWD
         szwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id d14si1351333edb.4.2019.10.16.05.20.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Oct 2019 05:20:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iKiHd-0008JI-Fd; Wed, 16 Oct 2019 15:20:05 +0300
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
 <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
 <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <8f573b40-3a5a-ed36-dffb-4a54faf3c4e1@virtuozzo.com>
Date: Wed, 16 Oct 2019 15:19:50 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
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


On 10/14/19 4:57 PM, Daniel Axtens wrote:
> Hi Andrey,
> 
> 
>>> +	/*
>>> +	 * Ensure poisoning is visible before the shadow is made visible
>>> +	 * to other CPUs.
>>> +	 */
>>> +	smp_wmb();
>>
>> I'm not quite understand what this barrier do and why it needed.
>> And if it's really needed there should be a pairing barrier
>> on the other side which I don't see.
> 
> Mark might be better able to answer this, but my understanding is that
> we want to make sure that we never have a situation where the writes are
> reordered so that PTE is installed before all the poisioning is written
> out. I think it follows the logic in __pte_alloc() in mm/memory.c:
> 
> 	/*
> 	 * Ensure all pte setup (eg. pte page lock and page clearing) are
> 	 * visible before the pte is made visible to other CPUs by being
> 	 * put into page tables.
> 	 *
> 	 * The other side of the story is the pointer chasing in the page
> 	 * table walking code (when walking the page table without locking;
> 	 * ie. most of the time). Fortunately, these data accesses consist
> 	 * of a chain of data-dependent loads, meaning most CPUs (alpha
> 	 * being the notable exception) will already guarantee loads are
> 	 * seen in-order. See the alpha page table accessors for the
> 	 * smp_read_barrier_depends() barriers in page table walking code.
> 	 */
> 	smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */
> 
> I can clarify the comment.
> 

I don't see how is this relevant here.

barrier in __pte_alloc() for very the following case:

CPU 0							CPU 1
__pte_alloc():                                          pte_offset_kernel(pmd_t * dir, unsigned long address):
     pgtable_t new = pte_alloc_one(mm);                        pte_t *new = (pte_t *) pmd_page_vaddr(*dir) + ((address >> PAGE_SHIFT) & (PTRS_PER_PAGE - 1));  
     smp_wmb();                                                smp_read_barrier_depends();
     pmd_populate(mm, pmd, new);
							/* do something with pte, e.g. check if (pte_none(*new)) */


It's needed to ensure that if CPU1 sees pmd_populate() it also sees initialized contents of the 'new'.

In our case the barrier would have been needed if we had the other side like this:

if (!pte_none(*vmalloc_shadow_pte)) {
	shadow_addr = (unsigned long)__va(pte_pfn(*vmalloc_shadow_pte) << PAGE_SHIFT);
	smp_read_barrier_depends();
	*shadow_addr; /* read the shadow, barrier ensures that if we see installed pte, we will see initialized shadow memory. */
}


Without such other side the barrier is pointless.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f573b40-3a5a-ed36-dffb-4a54faf3c4e1%40virtuozzo.com.
