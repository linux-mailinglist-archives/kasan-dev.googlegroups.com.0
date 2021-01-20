Return-Path: <kasan-dev+bncBDDL3KWR4EBRBBVJUGAAMGQESTYK7AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 79F962FD4D8
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 17:04:23 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id q8sf19213676otk.6
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 08:04:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611158662; cv=pass;
        d=google.com; s=arc-20160816;
        b=jZJ3KgZq5HCwdxBNJjMZrEwiXBMuP8Fa17N2AS37/FjwnepWBlD6oTEzJCPzuOsRlB
         MCSquSJk8r3xmtJn+cKQRJLQ5ALltLRL2YyjfHHA8IW77o2QjLiAX6XciTxk/6SLrN6t
         DLBSwbKywUqlD3k86gyqnTDLikayhY/1qmmTvHBgMMtq5U2fp4n0q7sOExPe2OlJCb2A
         claTUJro1vUv+GQsHkF5WfnbgMx5/Q81xzauGBZc3vYSsm7FHVarYu7jk+NEbEoQXkio
         SzB5Z0NXx/8fVU2/oBVSss+C0YgENI3cj6KBf7g62488yTBRlVkGVrVNGKz2IMP9VC3F
         QDXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6PeQ/nyudRjQk/jnhkZfRZVO+Gm1fHyMu22qKrE64Dk=;
        b=DqAPeQN3ibf88n2g9J8Idz8tXNvnT7UOGE49zv9AYBB9tNX9vAPdMFiYWfupOEQ+0i
         uDeebiqI8tmpyL58uyuG3YABOVeEXTMAaoxgKJPCJMxClAxgqOyPhx7QdAgMFlRlVD10
         o1apqluC4ETv8Fa5rBiIc/Du9iJz81B6kyfQ7ebZepz67fi5xjiKBCPnInWTALDHdj92
         FOXuO+Q+My2ZMTUIgigPhRfydPV3cjzh4YmTUfDuC3BAx78oxmBHnK1tXZSNt8N2ArFb
         h+oDrrsTMVxcplSUePs94APE3DNdb4Gw1zcNCaokuPEBemoF5iHktUoPq3+F/3+n1oED
         qzqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6PeQ/nyudRjQk/jnhkZfRZVO+Gm1fHyMu22qKrE64Dk=;
        b=ZJWpFK1F2FEgalG+gHvVRGeYAwHDhAIYG3WH2Wu8CV/JNKVifumEVs9Ci2DYa8uB3y
         FEF8fUBnqPEEPYpo5aykQ8aAhL9HQ2KiqxNNyf7e4R97yfRNmKk/AW6eNAlS8igt/MfF
         FEoF8FN1tb9UxQVM9N/XAItfrRS5nA9+GLTiAxqPxiXwwI+KTX7A8hwubYYaJX6M5yAx
         IX/beBP0jJSnmOfe8Dx4GB8Fwje6lrEnwb10Z2fa+bbqCMO7KwN7/SqmN6uYqGw+UPrX
         Ma8m0dU3kQfnu4z10zF3b2W1KuVUQN4RuhB92TCIs8I9N5mGGsMF0i/GIV9K0o4UC5yR
         z+NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6PeQ/nyudRjQk/jnhkZfRZVO+Gm1fHyMu22qKrE64Dk=;
        b=kgSO6gq7Hsyk3sQ5QUhz6kpHSmpaszL7OO0sLfPmnoiNzni40wAIl14vLiFeNDJUPN
         9H67L1rXqc7wkXtIvQuOBLy1QPuQ+p6r7wY87+4OXthHvTXJ/LrBym48ys+wWywFxMSi
         egjoUcYknLJ/hjhJYV+399K5X6Wdlac0bUGEGZO2aBXHHbGfYEOD5wlVwXP8fXjjaMgP
         skQOAqWLf1pSCnZ/bcZmUMQ2iuZpxncyrJgwQJaqVnkHFIVMfiwHf2q/Ti34LlupDRVD
         54+X5QgRZysrZLZT7AMa+BdrLWBHvEMbiRgZzl/rm5MpaBAHdgiW6Ru6rIzCWY1vmkE6
         GN9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eyYzlhlDaD7AnUrLJqe1gGmQ2+23/mTkBSz95q8nLlafX8wdN
	jswA5EMjN7j2jB9a6hO2Kd4=
X-Google-Smtp-Source: ABdhPJyyQGw7DF0xYk/atrS4te0m00SwgxTH1lF+/ECwzczmjIOR4JOK6kZHTWepcrzrLATL+yz8gw==
X-Received: by 2002:aca:5e42:: with SMTP id s63mr3300915oib.96.1611158662438;
        Wed, 20 Jan 2021 08:04:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1309:: with SMTP id e9ls2294717oii.4.gmail; Wed, 20 Jan
 2021 08:04:22 -0800 (PST)
X-Received: by 2002:aca:c188:: with SMTP id r130mr3382940oif.99.1611158661994;
        Wed, 20 Jan 2021 08:04:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611158661; cv=none;
        d=google.com; s=arc-20160816;
        b=kKfHUvnWHyiazhZtm4QjocmeoFlNN6US4gGCeZg4mYo+8rDAyt7II2BH06n9Bfi0/K
         eCM6K5tkWsGiWAJ2l/DlRFOXk395Mf1bzLKJ/1dEppVVO7Gca49qLACdFALHj2RfyB7+
         7Aa3G4nUftteuB4Z9AT/QBy2sVSNY0ECSVhy08q9AX9oljCfZ8vse5s2Q7WP+ECZ1Pg9
         vLF5IIbhd9x2pHb5HurnYuoXWPjT4aTpvXidA6ESw3d2uIwfSq3GTMLVicSgVwsv//YW
         HQzf9QXiS8EK4ts1sMpuRAKjJ1Ytm1iREMUXfSQOXbYheA5vT9zKaX7Ft+z3GxlPEX5b
         o3Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=pO9/NsVotOSFiSb3FQwyMmZZhvQbXEZKwXL/05KiJ2g=;
        b=v7SaLxTpUGzHfjQtQpCUmvBX62c6phNS5f7S1uA/RWSyqtB7q6KbJvfgcxh3BOmkpV
         5RI7JMfd3SlupLXJeRyOLcpQ++cYUyKKImKqnDZHv4fY4Dzx6JY2RDGSkErt9wMaFJEW
         oMSY5fDttRsS2+l1V5aMED8kB1b/W8aBW12rNS3RbzgP4mdYAdhwfoZVhsU+mDuMnCxo
         Li3vPpPQCAhxrdRDft+hNT+h2HrJ4nOvb6amd5k31+kull1026nWGf8IA0L7HyraiOdh
         qDm51eA5YmaM2HeBgZCpt8sVmykiR5/zrZaTVnRCUlFQVhcCx7dQdFLBmqMYblQItXnX
         wgUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b124si201681oii.4.2021.01.20.08.04.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Jan 2021 08:04:21 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6D8012339E;
	Wed, 20 Jan 2021 16:04:19 +0000 (UTC)
Date: Wed, 20 Jan 2021 16:04:16 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Alexander Potapenko <glider@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
Message-ID: <20210120160416.GF2642@gaia>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia>
 <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jan 19, 2021 at 08:35:49PM +0000, Vincenzo Frascino wrote:
> On 1/19/21 6:52 PM, Catalin Marinas wrote:
> > On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
> >> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
> >> <vincenzo.frascino@arm.com> wrote:
> >>>
> >>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> >>> the address passed as a parameter.
> >>>
> >>> Add a comment to make sure that the preconditions to the function are
> >>> explicitly clarified.
> >>>
> >>> Note: An invalid address (e.g. NULL pointer address) passed to the
> >>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
> >>>
> >>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> >>> Cc: Alexander Potapenko <glider@google.com>
> >>> Cc: Dmitry Vyukov <dvyukov@google.com>
> >>> Cc: Leon Romanovsky <leonro@mellanox.com>
> >>> Cc: Andrey Konovalov <andreyknvl@google.com>
> >>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>> ---
> >>>  mm/kasan/report.c | 11 +++++++++++
> >>>  1 file changed, 11 insertions(+)
> >>>
> >>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >>> index c0fb21797550..2485b585004d 100644
> >>> --- a/mm/kasan/report.c
> >>> +++ b/mm/kasan/report.c
> >>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >>>         end_report(&flags);
> >>>  }
> >>>
> >>> +/**
> >>> + * kasan_report - report kasan fault details
> >>> + * @addr: valid address of the allocation where the tag fault was detected
> >>> + * @size: size of the allocation where the tag fault was detected
> >>> + * @is_write: the instruction that caused the fault was a read or write?
> >>> + * @ip: pointer to the instruction that cause the fault
> >>> + *
> >>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
> >>> + * the address to access the tags, hence it must be valid at this point in
> >>> + * order to not cause a kernel panic.
> >>> + */
> >>
> >> It doesn't dereference the address, it just checks the tags, right?
> >>
> >> Ideally, kasan_report() should survive that with HW_TAGS like with the
> >> other modes. The reason it doesn't is probably because of a blank
> >> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
> >> guess we should somehow check that the memory comes from page_alloc or
> >> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
> >> instruction to check whether the memory has tags?
> > 
> > There isn't an architected way to probe whether a memory location has a
> > VA->PA mapping. The tags are addressed by PA but you can't reach them if
> > you get a page fault on the VA. So we either document the kasan_report()
> > preconditions or, as you suggest, update addr_has_metadata() for the
> > HW_TAGS case. Something like:
> > 
> >         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
> > 
> 
> This seems not working on arm64 because according to virt_addr_valid 0 is a
> valid virtual address, in fact:
> 
> __is_lm_address(0) == true && pfn_valid(virt_to_pfn(0)) == true.

Ah, so __is_lm_address(0) is true. Maybe we should improve this since
virt_to_pfn(0) doesn't make much sense.

> An option could be to make an exception for virtual address 0 in
> addr_has_metadata() something like:
> 
> static inline bool addr_has_metadata(const void *addr)
> {
> 	if ((u64)addr == 0)
> 		return false;
> 
> 	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
> }

As Andrey replied, passing a non-zero small value would still be
incorrectly detected as valid.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210120160416.GF2642%40gaia.
