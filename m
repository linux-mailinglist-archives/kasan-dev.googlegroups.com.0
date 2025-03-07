Return-Path: <kasan-dev+bncBDGZVRMH6UCRBHXAVK7AMGQEAHCOQQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 200FAA562A1
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 09:36:48 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5feb2ce9b27sf1136189eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 00:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741336607; cv=pass;
        d=google.com; s=arc-20240605;
        b=lQlvD88j6PLeic907Frx1sBG9AH3r9bMJ7zWjqGILuMRVKqHjTergh2kKVHPCXXrA9
         iRvWjgXSrvggaIUeTWQUaJ7vr4ojU3o/6W2kOr4Qu9SL7g9kOh2qxvKdTu9VdvZ1qeDa
         n4LScU0Pv7CUmM3FSAc0xVxqsTzCbpDIgGtUr7MkEJhxOzvhU5CRRY4dAcPCJsq+Xubo
         v0zr23xl7NzxVT1WNUjwE8I55MJwZXYoEN4OWZ7o6+nUt9n+lC12PUkDdwSEnl3/wvYi
         7WuQ25g1dwmiFsjHpsQuObkEmq1pB9OseBqmCl6sDO1gQK7E5cAOJueChGlbiZ2ajw8M
         LRiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=HYyGiIGXNoxYwNRsSOAqTT8kKJMUFretnNhRgsu/+fI=;
        fh=74ECM6yTCsh0paN846pMYIlX4wCQNBt9OaU9VQSPBC0=;
        b=TdiGONHKvJvyLhAqqfBYU7QTFbk0mdCsiJzj+8Yw5tyh3/fHQxHR1db1LgKEhesGvT
         5R8lEqMQCSOLuZTsSzaxllO3mjHrjg7qeVvB2kjeEWCt9hoaNACNHBLbRjmUv5LuxcsC
         7I++5smq6Y3nglvEBdxbAXuLAtLRqfDlnzqTiN154S4AavmXp2XL1gI8v7TwzObrMb05
         sIqztjqUy5Dbgx6wtBq2e8g57Z5kl2NsYfSpocqUHOa0bLcV5oKSaSSUAMQQvIbfUBqJ
         uT1qYp9SaSjdQp3LXy2FnxBVPm1spkJXc6os8yahSFigkye+e9kvTclyC5qWFHvxCdvU
         QhDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741336607; x=1741941407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HYyGiIGXNoxYwNRsSOAqTT8kKJMUFretnNhRgsu/+fI=;
        b=pZL2CLD4bXXQsI029JPxyDpCrEFYiot3iLBHuSXfpK9t1KCvTcme/WtybEP+Jt0nH4
         Ge2ph/98qizzwyD9vx9p8HUKQHtP/ajrUCfp/LCiOM8Sbyg9Ehr8L8W7MaN9HXzvKCdw
         2dlsy9Qze8mC2nhhbXISNvJLNMkoO16qjlFtvZYMndYzHbW3OPksjZTiq6qXoAr0wRaa
         u8JG5Bcy8cMEDm3Bwdb/fD9YPdSMfTJHBe/aFoOSMxP0Ni6DkNnB4L6meprjbroitjjS
         9aGbSD6AFQcVeRcslD7KR71LM1HKVCU8E7RqRMlu3khN0dKcSvhSTPkfrS3dB5R+szG3
         5AKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741336607; x=1741941407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HYyGiIGXNoxYwNRsSOAqTT8kKJMUFretnNhRgsu/+fI=;
        b=bie5gtlCBT2ItjIRMYSB8DPcvplVB/aPjrWq5iimG8CTjj/1O8LOFqUHMS85poQqbt
         bk8scuPRzn1PP40mZuCW6ah0rEBy9UR8NB8yElW6Iu7yn47rs0a0QA+qTi1er4iHZ1jd
         fiT7m04UifZSiLyN1H97GenZMq3Dk6zxv9M3fVdymJFJFszyQHboIxK2VhSZQg5aasKN
         y5wT23JwIfn8BpQ6XtfpGC3uQYp6etqaj7k5bGYN5mfxN2Bq0Km3f79Tp+DeUenokNiI
         JO7m1547vX3RuDYKtK9KDIXG8JFWjCcO+NJG4SHwdzgcGVP263sl1OjnEkDw2HYYwx7l
         D+DA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyOgZUNdpdlL5hffOjenM+JB853tMAauWWpjY+nXd/SSVtO6iH0KeMebefYRYXO7hErg+9Zw==@lfdr.de
X-Gm-Message-State: AOJu0Ywl99NICHM6l7jabDRCQPPVqH+/mTVIPbOrQLr6amxXcksQVz1K
	axBI1EM0mbBA/iXA7B0lqdlacNAmOZaIPrX9mm6K0IizF0y+rRCs
X-Google-Smtp-Source: AGHT+IH463mh5K686cIhsxiRex0/96T7CqUOQLcFAhRikWf7jrQ1wBMYhY9YfLqcQAj2dejmJ02I2Q==
X-Received: by 2002:a05:6870:bb17:b0:2c2:371a:2b4e with SMTP id 586e51a60fabf-2c261386dd0mr1228669fac.32.1741336606896;
        Fri, 07 Mar 2025 00:36:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGs4j4I3jvPO0KQ4T0ulf1pLLzu9oSdbehUIKI15EOPlw==
Received: by 2002:a05:6870:5b92:b0:2c2:33d9:946e with SMTP id
 586e51a60fabf-2c23f92a011ls421754fac.1.-pod-prod-08-us; Fri, 07 Mar 2025
 00:36:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/C8+5TUQfyYcufmuCpBGczfeQOr/e5CZ8wqe3owuKGTicw2oeNZdqMA0lUdw8fsj/slX4EHFMxG8=@googlegroups.com
X-Received: by 2002:a05:6871:7583:b0:2c1:7289:d62a with SMTP id 586e51a60fabf-2c2613911cdmr1416584fac.36.1741336606138;
        Fri, 07 Mar 2025 00:36:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741336606; cv=none;
        d=google.com; s=arc-20240605;
        b=QXM64i+XREkvi4HYoAy+ulVJPlbpqmamngGogh4Ai/C7jD8uWOaQ+RO7Xd5ysoorVx
         3fR7/GIRyPbkBeoEGjhKTkbecsjBEAqMc1VktJYUK5/LIUXTi//IXSGSzLmoQugYS+1h
         PwCHEkIOti6ybPsOaUXj1sGQpRwtKV/u7L+D/6qk915aT5jpa9a6P0tY8dgbrkjT+bgL
         fOxoz1PFzawhFY0jXcTpYXoeJUWa4NrIMaiymnOnpkhmnUJ183cyoiNOc6VGfyPj4aez
         +p2X+TRVMcgpxSwZ4IsjVEl4ceRqITjpFFshlU35LBi1bcg1BgSRAGijaYOggTng1JHC
         HGSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Pz6hhnjy6Q0c/EI0y9S8Ui8Ufow+cSgxpKkylaFjJJM=;
        fh=P0/iR11wrVcxOE+knHbmVaJDmkrcisqgPheQKfkH59I=;
        b=ZXCbdgAohuyDLEwAn/3OviPp3Xosv6HdtBCDeT0arfQXPZfwH4wr2JNEn7ZgCSyncY
         y/5z0vTDv4MGwSjn6wS/GmkYoGwdXcExzPjRQMs0zvy6mmYZwXTpqaPzr2gNhF+sJ+Jv
         4c/32eFN+K3DcMtv9MsxshrX0sOFikSvoQwozy6aYbKNOa4T0fHwrLyta+aI7mkIh7S7
         +BrIK8/tvzviVhLk236ifN6/NwSPJf7maaXsWh2HbwZpxlJSAK54oOy7XZMx+Bp1llZt
         eACRtBVB6c4eQEiB9I0NSeqEKxGIBPvuv/Sx9l3pj9z+fds7Ew4e6qBh5uQfXqgex3f1
         gZdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 46e09a7af769-72a2d9688absi140870a34.0.2025.03.07.00.36.46
        for <kasan-dev@googlegroups.com>;
        Fri, 07 Mar 2025 00:36:46 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8AEF51682;
	Fri,  7 Mar 2025 00:36:58 -0800 (PST)
Received: from [10.162.42.6] (a077893.blr.arm.com [10.162.42.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 48E973F673;
	Fri,  7 Mar 2025 00:36:41 -0800 (PST)
Message-ID: <ad54eb36-adfd-4182-bec3-fa73ee5a5778@arm.com>
Date: Fri, 7 Mar 2025 14:06:37 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] arm64/mm: Define PTE_SHIFT
To: Ard Biesheuvel <ardb@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ryan Roberts <ryan.roberts@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20250307050851.4034393-1-anshuman.khandual@arm.com>
 <CAMj1kXFufE9UPGMsqv1ARWm6SyUCcJL+m4F4mWa0jCyhJqf2Jg@mail.gmail.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <CAMj1kXFufE9UPGMsqv1ARWm6SyUCcJL+m4F4mWa0jCyhJqf2Jg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 3/7/25 13:08, Ard Biesheuvel wrote:
> Hi Anshuman,
> 
> On Fri, 7 Mar 2025 at 06:09, Anshuman Khandual
> <anshuman.khandual@arm.com> wrote:
>>
>> Address bytes shifted with a single 64 bit page table entry (any page table
>> level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
>> is not very readable or easy to reason about. Besides it is going to change
>> with D128, where each 128 bit page table entry will shift address bytes by
>> 4 (aka 2^4 = 16) instead.
>>
>> Let's just formalise this address bytes shift value into a new macro called
>> PTE_SHIFT establishing a logical abstraction, thus improving readability as
>> well. This does not cause any functional change.
>>
> 
> I don't disagree with this goal, but PTE_SHIFT is really not the right
> name. Given that PMD_SHIFT is the log2 of the area covered by a PMD,
> PTE_SHIFT should be the log2 of the area covered by a PTE, and so
> defining it to anything other than PAGE_SHIFT would be a mistake IMO.

Makes sense.

> 
> Given that we are talking about the log2 of the size of the area
> occupied by a descriptor, perhaps {PT}DESC_SIZE_ORDER would be a
> better name?

Originally we had this as [ARM64]_TTD_SHIFT but being a generic
construct, a preceding ARM64_ probably does not make sense here.

How about PTDESC_ORDER instead just to keep it bit short ?

> 
> 
> 
> 
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Cc: Mark Rutland <mark.rutland@arm.com>
>> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Andrey Konovalov <andreyknvl@gmail.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Ard Biesheuvel <ardb@kernel.org>
>> Cc: Ryan Roberts <ryan.roberts@arm.com>
>> Cc: linux-arm-kernel@lists.infradead.org
>> Cc: linux-kernel@vger.kernel.org
>> Cc: kasan-dev@googlegroups.com
>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>> ---
>> This patch applies on v6.14-rc5
>>
>>  arch/arm64/Kconfig                      |  2 +-
>>  arch/arm64/include/asm/kernel-pgtable.h |  3 ++-
>>  arch/arm64/include/asm/pgtable-hwdef.h  | 26 +++++++++++++------------
>>  arch/arm64/kernel/pi/map_range.c        |  2 +-
>>  arch/arm64/mm/kasan_init.c              |  6 +++---
>>  5 files changed, 21 insertions(+), 18 deletions(-)
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index 940343beb3d4..fd3303f2ccda 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
>>         default 18
>>
>>  # max bits determined by the following formula:
>> -#  VA_BITS - PAGE_SHIFT - 3
>> +#  VA_BITS - PAGE_SHIFT - PTE_SHIFT
>>  config ARCH_MMAP_RND_BITS_MAX
>>         default 19 if ARM64_VA_BITS=36
>>         default 24 if ARM64_VA_BITS=39
>> diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
>> index fd5a08450b12..7150a7a10f00 100644
>> --- a/arch/arm64/include/asm/kernel-pgtable.h
>> +++ b/arch/arm64/include/asm/kernel-pgtable.h
>> @@ -49,7 +49,8 @@
>>         (SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
>>
>>  #define EARLY_LEVEL(lvl, lvls, vstart, vend, add)      \
>> -       (lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
>> +       (lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + \
>> +       lvl * (PAGE_SHIFT - PTE_SHIFT), add) : 0)
>>
>>  #define EARLY_PAGES(lvls, vstart, vend, add) (1        /* PGDIR page */                                \
>>         + EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */  \
>> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
>> index a9136cc551cc..43f98eac7653 100644
>> --- a/arch/arm64/include/asm/pgtable-hwdef.h
>> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
>> @@ -7,40 +7,42 @@
>>
>>  #include <asm/memory.h>
>>
>> +#define PTE_SHIFT 3
>> +
>>  /*
>>   * Number of page-table levels required to address 'va_bits' wide
>>   * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
>> - * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
>> + * bits with (PAGE_SHIFT - PTE_SHIFT) bits at each page table level. Hence:
>>   *
>> - *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
>> + *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTE_SHIFT))
>>   *
>>   * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
>>   *
>>   * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
>>   * due to build issues. So we open code DIV_ROUND_UP here:
>>   *
>> - *     ((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
>> + *     ((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTE_SHIFT) - 1) / (PAGE_SHIFT - PTE_SHIFT))
>>   *
>>   * which gets simplified as :
>>   */
>> -#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
>> +#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - PTE_SHIFT - 1) / (PAGE_SHIFT - PTE_SHIFT))
>>
>>  /*
>>   * Size mapped by an entry at level n ( -1 <= n <= 3)
>> - * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
>> + * We map (PAGE_SHIFT - PTE_SHIFT) at all translation levels and PAGE_SHIFT bits
>>   * in the final page. The maximum number of translation levels supported by
>>   * the architecture is 5. Hence, starting at level n, we have further
>>   * ((4 - n) - 1) levels of translation excluding the offset within the page.
>>   * So, the total number of bits mapped by an entry at level n is :
>>   *
>> - *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
>> + *  ((4 - n) - 1) * (PAGE_SHIFT - PTE_SHIFT) + PAGE_SHIFT
>>   *
>>   * Rearranging it a bit we get :
>> - *   (4 - n) * (PAGE_SHIFT - 3) + 3
>> + *   (4 - n) * (PAGE_SHIFT - PTE_SHIFT) + PTE_SHIFT
>>   */
>> -#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)        ((PAGE_SHIFT - 3) * (4 - (n)) + 3)
>> +#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)        ((PAGE_SHIFT - PTE_SHIFT) * (4 - (n)) + PTE_SHIFT)
>>
>> -#define PTRS_PER_PTE           (1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PTE           (1 << (PAGE_SHIFT - PTE_SHIFT))
>>
>>  /*
>>   * PMD_SHIFT determines the size a level 2 page table entry can map.
>> @@ -49,7 +51,7 @@
>>  #define PMD_SHIFT              ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
>>  #define PMD_SIZE               (_AC(1, UL) << PMD_SHIFT)
>>  #define PMD_MASK               (~(PMD_SIZE-1))
>> -#define PTRS_PER_PMD           (1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PMD           (1 << (PAGE_SHIFT - PTE_SHIFT))
>>  #endif
>>
>>  /*
>> @@ -59,14 +61,14 @@
>>  #define PUD_SHIFT              ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
>>  #define PUD_SIZE               (_AC(1, UL) << PUD_SHIFT)
>>  #define PUD_MASK               (~(PUD_SIZE-1))
>> -#define PTRS_PER_PUD           (1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_PUD           (1 << (PAGE_SHIFT - PTE_SHIFT))
>>  #endif
>>
>>  #if CONFIG_PGTABLE_LEVELS > 4
>>  #define P4D_SHIFT              ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
>>  #define P4D_SIZE               (_AC(1, UL) << P4D_SHIFT)
>>  #define P4D_MASK               (~(P4D_SIZE-1))
>> -#define PTRS_PER_P4D           (1 << (PAGE_SHIFT - 3))
>> +#define PTRS_PER_P4D           (1 << (PAGE_SHIFT - PTE_SHIFT))
>>  #endif
>>
>>  /*
>> diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
>> index 2b69e3beeef8..3530a5427f57 100644
>> --- a/arch/arm64/kernel/pi/map_range.c
>> +++ b/arch/arm64/kernel/pi/map_range.c
>> @@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
>>  {
>>         u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
>>         pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
>> -       int lshift = (3 - level) * (PAGE_SHIFT - 3);
>> +       int lshift = (3 - level) * (PAGE_SHIFT - PTE_SHIFT);
>>         u64 lmask = (PAGE_SIZE << lshift) - 1;
>>
>>         start   &= PAGE_MASK;
>> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
>> index b65a29440a0c..90548079b42e 100644
>> --- a/arch/arm64/mm/kasan_init.c
>> +++ b/arch/arm64/mm/kasan_init.c
>> @@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
>>   */
>>  static bool __init root_level_aligned(u64 addr)
>>  {
>> -       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
>> +       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>>
>>         return (addr % (PAGE_SIZE << shift)) == 0;
>>  }
>> @@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
>>          */
>>         u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
>>                                                         : vabits_actual;
>> -       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
>> +       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>>
>>         return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
>>  }
>> @@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
>>   */
>>  static int __init next_level_idx(u64 addr)
>>  {
>> -       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
>> +       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTE_SHIFT);
>>
>>         return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
>>  }
>> --
>> 2.30.2
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ad54eb36-adfd-4182-bec3-fa73ee5a5778%40arm.com.
