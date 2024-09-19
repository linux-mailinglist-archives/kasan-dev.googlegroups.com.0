Return-Path: <kasan-dev+bncBCZP5TXROEIKHSFRW4DBUBASWK6M6@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B718D97CD4C
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 19:49:24 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-277f652d348sf1366623fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 10:49:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726768163; cv=pass;
        d=google.com; s=arc-20240605;
        b=a7N0YTZUJwzzAbSxYWKewz03l4U6z/9jy7RSahbQqmbqOdowbsJo7AThHcAiAYah4T
         OwnIdbDEtzdV2hrBBpsok/VQaZNgfq1yPj9OwvtYgODSNhYmukAI5fNy+YXbzuodeQg8
         71SO1STmRRO5toDrpUp62bROI/DsiZJo3LfHlwLji2HNFQuePWO5qmuL94FAcaJTXnt9
         nSPORNZ9RL9GKf8+aG3xcd4alr0tqQKC/CRE+znxZMSEgdPcc5E4XkVqpJqXrBDutcty
         hBd27RUu8hhqIfAyYMFj8x9INqEePJToxWFSJGNq5jLctGCcdoBSXdIwiniDUj+0pAti
         1ZHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Sds40FxAM74dvhXyJ9+Eff666zXaebJ2EoxonWDwfps=;
        fh=npGEmREy2Ly4S6KlcD/X9l3k2RZVVH8DLbIa637KREk=;
        b=QLSyR35Z3N41B+dWbrV6rAToghZeOA1oh2fSChduaoXpieL2WdMHhavq/WF8Ix5G7A
         +BGuF3fNhfpQ12H92DCQBS6FqmCLitd4RTtd5YKZDTWlxr7iisY7rTD91SUD+M8PX6Q/
         UryqOlhPn3F+Kr3jcUFwuyuzWCbDtk6q+8sPqJjIDzUyjqV8iLvq2EDLE/Qfqr+elXBt
         +32suEFHoeXh6XzMKLBTmJLqjeB/WpKd9AqOF8CuLv5aOtI9Eplqdaq9PEb6JM0Oyf5n
         Lk1Mj7WGb0UB+ZQ9mXczzL9z8c/G44B43jJ8EW+oyvS16dsEktc07NVnbC3pPWodro7o
         IQfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726768163; x=1727372963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sds40FxAM74dvhXyJ9+Eff666zXaebJ2EoxonWDwfps=;
        b=PdiR1aPUqOlHBQ9dNKbh9fyCKtzJoRQvuFvrL8IdRzE56x6/c/bi9HDwGJZp2vHZX3
         qp4ujnXY3A3J/swJzJutHGmlksNhhVsHweSSWr3PxuPYRaXg5/WkAKqcXcULOe+ITLPY
         IrOHgwexHYo0kIN7lqkPbpsujBL0zXo1ZV4El7j3m41W0NmHUyYtEL51iqtKiNH9/4S5
         +fhYQY4g0ziP6wCXe/V5cF7HuHgRtlZCHufdDFBKyIErJmAZMijz0ieYT8ET9b8ZiFvp
         1/1oOGGR95VEBWM126vYMoRucz5++Q5JUhGH0ICK8xydDAzzb6yerFQf+ALNc5cnRppS
         +2Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726768163; x=1727372963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sds40FxAM74dvhXyJ9+Eff666zXaebJ2EoxonWDwfps=;
        b=BtZ6i/oYpPnhYcmQyEiGwPesYbMFRdeyM7YhZvxb9y7MImqB85Wrwg6pTEds8XBIiL
         NCn1LkBYpOX7l9lykNBsxOiZP6dTIWlBJav9vW8jKJkGdOTOUW77CK+YQWzkLn3E8Qj4
         YJ1lGxKi+bJ1WW89ZMu7/5d9bI+h2o6YtFvC5y7rrjJduumlocNQi48bnX1uXgoDwpFz
         3SJuX3dClGubRPzbPF2M5zsjmE04Uejg4YXKn3+llDFhEk3cWIU78yN8L0gZEktygDPP
         pCr1pECLLNQNqIzqTqfugqbURDzPqWf1FBX63L4ev4WzExTdUBR+MKZn5dLGsvbErewk
         NP3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMcJA64qy2QPGB5ybU8UWAC6fKRIkZ52vIjVoibEWqQIi6J2LD4wWWfcECSKQLQ2pmBoXaWA==@lfdr.de
X-Gm-Message-State: AOJu0Yx9B2x85tOmg8u7r08q55cGSh5/yX6WgyRVDgax4+o2RIL0G0Gt
	K3u1bczhVdy1KugRy/zynILj+ugKc8T78cYxnv+s4G7AGbPTkSZP
X-Google-Smtp-Source: AGHT+IEF7V58iMiEQhtXJ8bKrRYrd637YdqJLaTeZVpHCG8Kg6licNwMT8IVSSMkFNaewL0B/vxsJA==
X-Received: by 2002:a05:6870:1494:b0:278:209d:49c8 with SMTP id 586e51a60fabf-2803a6301f0mr120528fac.27.1726768163186;
        Thu, 19 Sep 2024 10:49:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9d94:b0:278:233:d36c with SMTP id
 586e51a60fabf-27d092d70ffls64898fac.1.-pod-prod-03-us; Thu, 19 Sep 2024
 10:49:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbEiLeEEbKdY8mcqkRS/63keRfRHKL6k83bmOXGpcqE5Q22lYwpY3zDhh3l30gR6pv04kaciqxtRY=@googlegroups.com
X-Received: by 2002:a05:6870:610b:b0:270:1fc6:18 with SMTP id 586e51a60fabf-2803a57a0f1mr167716fac.3.1726768161593;
        Thu, 19 Sep 2024 10:49:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726768161; cv=none;
        d=google.com; s=arc-20240605;
        b=LZDEY60c+fuVMn0OPrBGbTZ/9soo3Nx+zyGNzwEtRwFoWELuzzC+Dp8Y4+cyQAs4zp
         hSr0idAYi+hx6rrP+saC8p93inD8uMjfyP7x5FzXUhfoMbu6Yfb6HHLCtPfLLSldavC0
         64v+ci67sfc3QHJJduDUbOZqclxxCkNv1iV0Qjc7KQNJwzKxCAblk/1TUu4Hqiv7CMRA
         DrtQItwd7ec5YH6tqAS6vlJa1Gx3XZuhVOKYuN5U/EisRRhq7om9qhnar9/Cxw1EJeAH
         VaYo6F0q92VF2lPTpU+RHSg/Re2gmx6K+fEmUFnVOqVU0HtzZSfZfgjvZZ6QXAjH30Ue
         oQEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=OBrtwX2GVE6dCu0mnw4wcEfpxmnF7kPLipqIHnc/mmo=;
        fh=GF0OURt1aobVVYo7M3iRXWSqWc1A5XkS9a4tiebN1YY=;
        b=WQBzKIme0gC3rOiPngD8hWv9m1Kz4MEv1pmL1gkdembCtKNv+EEblbveryvrk8Yt/i
         pLXPkcZqAGPY6rxcaz0Yth7m0vZPFQ92n5IKnzBgwaogtUTjtPNIH+BuHw2ViUCcRA6g
         U9h4ql/3yo84rxqu+hsXk53rSJqmZDLetOTFvm1aBQVIr7VRPPhbxdewUdrYklV2/4VG
         CGY33HXFsozt0KuRqpxb9u0qh7Z/4AQ91w4123l3A7yrg+ywoXcujwUh/13bjc9yGVbn
         8oS4JBmLceoxG2LtQRkUeq6k3DZfx0cd+CUrVw8bdNoNfOZPIekS9cMyPs1B2c+ray24
         5u7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-27d0b3adae5si124095fac.1.2024.09.19.10.49.21
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 10:49:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 10F3A1007;
	Thu, 19 Sep 2024 10:49:50 -0700 (PDT)
Received: from [10.57.82.79] (unknown [10.57.82.79])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 973013F64C;
	Thu, 19 Sep 2024 10:49:12 -0700 (PDT)
Message-ID: <5bd51798-cb47-4a7b-be40-554b5a821fe7@arm.com>
Date: Thu, 19 Sep 2024 19:49:09 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Content-Language: en-GB
To: "Russell King (Oracle)" <linux@armlinux.org.uk>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
 kernel test robot <lkp@intel.com>, linux-mm@kvack.org, llvm@lists.linux.dev,
 oe-kbuild-all@lists.linux.dev, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Dimitri Sivanich
 <dimitri.sivanich@hpe.com>, Alexander Viro <viro@zeniv.linux.org.uk>,
 Muchun Song <muchun.song@linux.dev>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
 Christoph Lameter <cl@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
 <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
 <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
 <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 19/09/2024 18:06, Russell King (Oracle) wrote:
> On Thu, Sep 19, 2024 at 05:48:58PM +0200, Ryan Roberts wrote:
>>> 32-bit arm uses, in some circumstances, an array because each level 1
>>> page table entry is actually two descriptors. It needs to be this way
>>> because each level 2 table pointed to by each level 1 entry has 256
>>> entries, meaning it only occupies 1024 bytes in a 4096 byte page.
>>>
>>> In order to cut down on the wastage, treat the level 1 page table as
>>> groups of two entries, which point to two consecutive 1024 byte tables
>>> in the level 2 page.
>>>
>>> The level 2 entry isn't suitable for the kernel's use cases (there are
>>> no bits to represent accessed/dirty and other important stuff that the
>>> Linux MM wants) so we maintain the hardware page tables and a separate
>>> set that Linux uses in the same page. Again, the software tables are
>>> consecutive, so from Linux's perspective, the level 2 page tables
>>> have 512 entries in them and occupy one full page.
>>>
>>> This is documented in arch/arm/include/asm/pgtable-2level.h
>>>
>>> However, what this means is that from the software perspective, the
>>> level 1 page table descriptors are an array of two entries, both of
>>> which need to be setup when creating a level 2 page table, but only
>>> the first one should ever be dereferenced when walking the tables,
>>> otherwise the code that walks the second level of page table entries
>>> will walk off the end of the software table into the actual hardware
>>> descriptors.
>>>
>>> I've no idea what the idea is behind introducing pgd_get() and what
>>> it's semantics are, so I can't comment further.
>>
>> The helper is intended to read the value of the entry pointed to by the passed
>> in pointer. And it shoiuld be read in a "single copy atomic" manner, meaning no
>> tearing. Further, the PTL is expected to be held when calling the getter. If the
>> HW can write to the entry such that its racing with the lock holder (i.e. HW
>> update of access/dirty) then READ_ONCE() should be suitable for most
>> architectures. If there is no possibility of racing (because HW doesn't write to
>> the entry), then a simple dereference would be sufficient, I think (which is
>> what the core code was already doing in most cases).
> 
> The core code should be making no access to the PGD entries on 32-bit
> ARM since the PGD level does not exist. Writes are done at PMD level
> in arch code. Reads are done by core code at PMD level.
> 
> It feels to me like pgd_get() just doesn't fit the model to which 32-bit
> ARM was designed to use decades ago, so I want full details about what
> pgd_get() is going to be used for and how it is going to be used,
> because I feel completely in the dark over this new development. I fear
> that someone hasn't understood the Linux page table model if they're
> wanting to access stuff at levels that effectively "aren't implemented"
> in the architecture specific kernel model of the page tables.

This change isn't as big and scary as I think you fear. The core-mm today
dereferences pgd pointers (and p4d, pud, pmd pointers) directly in its code. See
follow_pfnmap_start(), gup_fast_pgd_leaf(), and many other sites. These changes
aim to abstract those dereferences into an inline function that the architecture
can override and implement if it so wishes.

The core-mm implements default versions of these helper functions which do
READ_ONCE(), but does not currently use them consistently.

From Anshuman's comments earlier in this thread, it looked to me like the arm
pgd_t type is too big to read with READ_ONCE() - it can't be atomically read on
that arch. So my proposal was to implement the override for arm to do exactly
what the core-mm used to do, which is a pointer dereference. So that would
result in exact same behaviour for the arm arch.

> 
> Essentially, on 32-bit 2-level ARM, the PGD is merely indexed by the
> virtual address. As far as the kernel is concerned, each entry is
> 64-bit, and the generic kernel code has no business accessing that
> through the pgd pointer.
> 
> The pgd pointer is passed through the PUD and PMD levels, where it is
> typecast down through the kernel layers to a pmd_t pointer, where it
> becomes a 32-bit quantity. This results in only the _first_ level 1
> pointer being dereferenced by kernel code to a 32-bit pmd_t quantity.
> pmd_page_vaddr() converts this pmd_t quantity to a pte pointer (which
> points at the software level 2 page tables, not the hardware page
> tables.)

As an aside, my understanding of Linux's pgtable model differs from what you
describe. As I understand it, Linux's logical page table model has 5 levels
(pgd, p4d, pud, pmd, pte). If an arch doesn't support all 5 levels, then the
middle levels can be folded away (p4d first, then pud, then pmd). But the
core-mm still logically walks all 5 levels. So if the HW supports 2 levels,
those levels are (pgd, pte). But you are suggesting that arm exposes pmd and
pte, which is not what Linux expects? (Perhaps you call it the pmd in the arch,
but that is being folded and accessed through the pgd helpers in core code, I
believe?

> 
> So, as I'm now being told that the kernel wants to dereference the
> pgd level despite the model I describe above, alarm bells are ringing.
> I want full information please.
> 

This is not new; the kernel already dereferences the pgd pointers.

Thanks,
Ryan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5bd51798-cb47-4a7b-be40-554b5a821fe7%40arm.com.
