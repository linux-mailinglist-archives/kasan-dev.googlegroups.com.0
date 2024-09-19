Return-Path: <kasan-dev+bncBCZP5TXROEIPLD5RW4DBUBDHKDZ2E@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id AC63997CBB4
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 17:49:10 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-6dbbeee08f0sf32113727b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 08:49:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726760949; cv=pass;
        d=google.com; s=arc-20240605;
        b=SpGdYEPlUC/0sIF0985v/knAMcWwZzYBA1/O2b+DLOCZib5NvEQ2K9cw4t3/17TlYF
         yfPvUCdcprenRR0N69gyXudIWb/wrUgnf9HAOzj9aEFrJtdboKbGp8f7WT6PKzxXtSEo
         jDlWtc6QG4DAv9r8yT+AxBPBPSp1RAaKCQfSdl2ahe+upUp7SJpWqGWziIRFVVR6iqiO
         mHlLeiwNeC8sG0zv3GCxth8LHwr0t2Vzi6F2aSciPrf2qIbb5XlknpOQDhEEGN9OXYAu
         TR3DdZm3Uk3Q/IS0rav4ORmEgo1NG1/K8Cgs1IaPl3um5uGh8xCrzhhSVthP78M+6v7G
         7tuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=LkfuRRwOTWS3v7KgOcH2nPLNdoGXoGgP4awqJAl7pXA=;
        fh=mqC4Vb++J3NTSf/nvGtPExFmgH2iyy/Fe2M7dNs1BdY=;
        b=X55m3ERiFzhayx7PiNxUI4ymwEx98hhDvxPLdZkeHsnHboU1dY7UG/K8p8BdCspcQH
         WroIok0oP/qZYh46ZzrQLWNyPM9MsgQMh9KQBbbJFporuDQS50UGKsew7v5Oiuio8Wz5
         QZw3qmX1va97x6jZgfeIpH/cn7yTQ/AlHDNETWrHOFZCRSv/U/sQk863TD8KIpl6bhCz
         qeHV0+lZ+7yvvijPjbA5DYKfySq3HGbk6UtublEH3SsLBQEr4HUMqh7L7xRMShqeuGGw
         hFrZ9RKp99+uIgN7bFMg+cYY5u68SuoyjzJ2K6ECSakPJkn5xopVJWwj3OkpZzW8xQUc
         /KFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726760949; x=1727365749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LkfuRRwOTWS3v7KgOcH2nPLNdoGXoGgP4awqJAl7pXA=;
        b=vw2w7B+vT6AONUm6bAb4nMqTAXptx9W3ev5vZFvl7/wNUsix8Js3HI063CdPafsvj2
         S0GZPLPDewN7SgkyZcVxRB7pNTpOwz3H2etFKQmlEcgtd3kFuqqV3PG8jq/zlPyKSY1o
         j6j1w67jCxelc2fHOHrg+fIVMGq9glt6ag7qmcl4Q9ONUOljt2YLAiJ35ktHdIoyF+l9
         bOW0nTGL5QOH1RzahcmRZvPzcZePmK3beXwGf13C9p7k/rDHUIco9cj1Yn7xJWMrattC
         MFXSm6KitS/6BVfcaPQAAYYJMrVppV2X8W9wi43w/Tyd54hEX3D0Cu54PT5v19qFjh9r
         7yoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726760949; x=1727365749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LkfuRRwOTWS3v7KgOcH2nPLNdoGXoGgP4awqJAl7pXA=;
        b=kbZryK5hUiXYudlQvJQwGQaxvxGOtOWMuiVskHuXiwY6YyWolEIVy2nh+qimmD88Na
         EOiL8GL7ZeH9n2YWE3Tx8FhtivDaMr+KjnzKaQWn6bTvYROIPgg8WCyonmvm+Lvezqwy
         sOblDuQq/x7kC5VM+oDRZsD514vU2BVFfGA58iiltwdVsbEJwCvGkyDj0GpdDz+aGekP
         eZGBnJiabv/1PNXrng8MUpYiIm/8R42oabAizkm8ZAvJMgtKqqswv3cxJ3YOdRxrsyQq
         Ummwv9NatcGoCF+JUiczvvgV+0QxgdoLPNi8+r5MQWqEYTkZ+bI1FaXOlAcasW9zUc1W
         0fKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXxNEGkmKQMxjyxBoQYMe2g7XiMp58xv+gdlZCkBY5Vwsyfp1VVygQ2FavyOuoqoZuo/oBqQ==@lfdr.de
X-Gm-Message-State: AOJu0YzkDK+8XWxoO/RAYG6jVhcAFo7Ip+Ic5q1Nv9K6ET2K7W7kMe2B
	rK4u6LUZfcHJaj6seVGIsAIxZ58Yi/vgYgK661e58mK00dWp8kOw
X-Google-Smtp-Source: AGHT+IHykLmsAUdkYxjyliGdS9+edougHx9im0Y9fbb05Ke/uVBRE8Poke5lq19SPcM4zBoCxJ4CtA==
X-Received: by 2002:a05:6902:2b81:b0:e1c:fbe6:b11a with SMTP id 3f1490d57ef6-e202809fce5mr2400438276.0.1726760949172;
        Thu, 19 Sep 2024 08:49:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:707:b0:e20:1ba5:d65 with SMTP id
 3f1490d57ef6-e2027e64e67ls86871276.2.-pod-prod-00-us; Thu, 19 Sep 2024
 08:49:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQf2ABtRtPR1J3R1X3+BChoPYt6uhojMc0lNMwnF/u3gUgWujSEsLLyq8LNgL9dZYkhovb1xSSQfM=@googlegroups.com
X-Received: by 2002:a05:6902:1801:b0:e1c:f1f2:20c0 with SMTP id 3f1490d57ef6-e202769cbd4mr2934763276.12.1726760948425;
        Thu, 19 Sep 2024 08:49:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726760948; cv=none;
        d=google.com; s=arc-20240605;
        b=K+Ax90GthyIvwF9MVVwJWzqzHleOVibhkHnwnF3kgoxMxlfbBg077N1MjCslpt4Kxr
         sD8WiQ0xZQbZzynS7RWE2FGdbmILK6GUrUAWvpPc0+8mHKBJws61+V6JAp52fLEJV7aI
         dnM7SlJEcULiPT6HmFzG6CT/YztfIoaHJhF//3ks3rk72OKgKu6APGa5DvFql7zq5SDi
         Qg/3fbvoJXc7Hzl+RakxE4eK0IEz77pAyzTI74uQinlDhsPgljGkMZPPFGW2K1mWzMkU
         MCrlOvSkBjSCDnPL0BdocJGl9M5UNbEuEjkC7E+5s1aJO2I0hZMCCwmQIQrfx3m92/19
         fPAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=kg/TDUOyxQVvoJj+SaV4+ITNnLyD7pDUx+3Sukv02tg=;
        fh=1YI10qQyj2lQc5vTzJ6su8TMLR5Ri0tahK8GJoaM674=;
        b=ABgmdh5p56P9ccnxMZJLsavv3Yr4/PjYr7SzROpPynYD+IkIeqPHL6gLNKaKbP+ijQ
         L6dXVJkLeMK8+3gMXbk1jH4RjUrU2TQAXzifAEZGaOHNIkFXq5gTV5EadUYwAg3zu0XY
         CbpKKlKmLgHGg4shnFAQlD6eBSSZQHL8EfR14SvSZE1e5GFJT770jjP/Itj+svd8QfH8
         m3evNFeTvmffANdzr/rqOfIROm8Wwb2hShVHtYJs8wNAR1BelvyN/eoK2P9oE/lsrR0T
         XP+HU4JmG9W+mEJUnFUgr7KDKoZ4sLrLdr3g59kbJ+K4mJBDB6C5Yx0DjtUSc10vNOMb
         FIAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e1dc1389d1asi688132276.2.2024.09.19.08.49.08
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 08:49:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 41B6AFEC;
	Thu, 19 Sep 2024 08:49:37 -0700 (PDT)
Received: from [10.57.82.79] (unknown [10.57.82.79])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E30043F71A;
	Thu, 19 Sep 2024 08:49:00 -0700 (PDT)
Message-ID: <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
Date: Thu, 19 Sep 2024 17:48:58 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Content-Language: en-GB
To: "Russell King (Oracle)" <linux@armlinux.org.uk>,
 Anshuman Khandual <anshuman.khandual@arm.com>
Cc: kernel test robot <lkp@intel.com>, linux-mm@kvack.org,
 llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
 Andrew Morton <akpm@linux-foundation.org>,
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
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
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

On 19/09/2024 10:11, Russell King (Oracle) wrote:
> On Thu, Sep 19, 2024 at 01:25:08PM +0530, Anshuman Khandual wrote:
>> arm (32) platform currently overrides pgdp_get() helper in the platform but
>> defines that like the exact same version as the generic one, albeit with a
>> typo which can be fixed with something like this.
> 
> pgdp_get() was added to arm in eba2591d99d1 ("mm: Introduce
> pudp/p4dp/pgdp_get() functions") with the typo you've spotted. It seems
> it was added with no users, otherwise the error would have been spotted
> earlier. I'm not a fan of adding dead code to the kernel for this
> reason.
> 
>> Regardless there is another problem here. On arm platform there are multiple
>> pgd_t definitions available depending on various configs but some are arrays
>> instead of a single data element, although platform pgdp_get() helper remains
>> the same for all.
>>
>> arch/arm/include/asm/page-nommu.h:typedef unsigned long pgd_t[2];
>> arch/arm/include/asm/pgtable-2level-types.h:typedef struct { pmdval_t pgd[2]; } pgd_t;
>> arch/arm/include/asm/pgtable-2level-types.h:typedef pmdval_t pgd_t[2];
>> arch/arm/include/asm/pgtable-3level-types.h:typedef struct { pgdval_t pgd; } pgd_t;
>> arch/arm/include/asm/pgtable-3level-types.h:typedef pgdval_t pgd_t;
>>
>> I guess it might need different pgdp_get() variants depending applicable pgd_t
>> definition. Will continue looking into this further but meanwhile copied Russel
>> King in case he might be able to give some direction.
> 
> That's Russel*L*, thanks.
> 
> 32-bit arm uses, in some circumstances, an array because each level 1
> page table entry is actually two descriptors. It needs to be this way
> because each level 2 table pointed to by each level 1 entry has 256
> entries, meaning it only occupies 1024 bytes in a 4096 byte page.
> 
> In order to cut down on the wastage, treat the level 1 page table as
> groups of two entries, which point to two consecutive 1024 byte tables
> in the level 2 page.
> 
> The level 2 entry isn't suitable for the kernel's use cases (there are
> no bits to represent accessed/dirty and other important stuff that the
> Linux MM wants) so we maintain the hardware page tables and a separate
> set that Linux uses in the same page. Again, the software tables are
> consecutive, so from Linux's perspective, the level 2 page tables
> have 512 entries in them and occupy one full page.
> 
> This is documented in arch/arm/include/asm/pgtable-2level.h
> 
> However, what this means is that from the software perspective, the
> level 1 page table descriptors are an array of two entries, both of
> which need to be setup when creating a level 2 page table, but only
> the first one should ever be dereferenced when walking the tables,
> otherwise the code that walks the second level of page table entries
> will walk off the end of the software table into the actual hardware
> descriptors.
> 
> I've no idea what the idea is behind introducing pgd_get() and what
> it's semantics are, so I can't comment further.

The helper is intended to read the value of the entry pointed to by the passed
in pointer. And it shoiuld be read in a "single copy atomic" manner, meaning no
tearing. Further, the PTL is expected to be held when calling the getter. If the
HW can write to the entry such that its racing with the lock holder (i.e. HW
update of access/dirty) then READ_ONCE() should be suitable for most
architectures. If there is no possibility of racing (because HW doesn't write to
the entry), then a simple dereference would be sufficient, I think (which is
what the core code was already doing in most cases).

There is additional benefit that the architecture can hook this function if it
has exotic use cases (see contpte feature on arm64 as an example, which hooks
ptep_get()).

It sounds to me like the arm (32) implementation of pgdp_get() could just
continue to do a direct dereference and this should be safe? I don't think it
supports HW update of access/dirty?

Thanks,
Ryan


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82fa108e-5b15-435a-8b61-6253766c7d88%40arm.com.
