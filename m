Return-Path: <kasan-dev+bncBAABB2MX3GOQMGQEO6MPVJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B70365E450
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 05:02:51 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id x17-20020a170902ec9100b0019294547b06sf14973786plg.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 20:02:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672891369; cv=pass;
        d=google.com; s=arc-20160816;
        b=cVnxqBsDUyYGhRb8rYnaw0bcNTFQ9aJR+aS8sOfjO78AvvA7K8dVTkx7tCooIW8TbQ
         DdSXEAsfFwj1J9QRkx1biRgyCwh1j23Z+hH4ST44PVynPNLO6z9omWr+IE48PSzoj7++
         /Ra5ct/so3jfsyGD7V4W/OG3l1iadva1eEi4C2bYk23YUpHU+yx5iRyWxwj7yIvL3Loj
         qoD9CG+W1hvrXuwOKipZdL86Cmhic2FQ/sRC2RQZiGQBo22OfQF3kImvkV0ummD0LTWN
         q8iJxs0pkAEeX7mYaZ3y6uw4bDXPTfkcOvsVl8WCJv9Ncr2aSsmmYvvE+Gc3lOTF1jEh
         y0Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:message-id
         :user-agent:references:in-reply-to:subject:cc:to:from:date
         :mime-version:dkim-signature;
        bh=vtNBKBeE7d3OLXFt2K/4ZlSimgT/So99RlHMyXeN93c=;
        b=MbvQjSt6bf3p+TsJWCCgwsDkdUats6/5lTfxAVRPag7ZUz5whICAR3ksHN9/opqliN
         iIOqoL2hoA365PFuVp87aHgZmCdR33oPxwlf/A/HqR/OSzQ2XE5NEQq70z33UAKxcFxI
         7+cb6SBPxqRAvI0V40rqed1wOoTOn+yEzE9FRNT7uU/OYjCJDzpCSESibbLVbFNuDCW5
         QRjDZBcrszUL7FRRyk0AQQOBCt8XTfXTe3AiNqsLR8qHA2nbDoHqsGMc9q6z3wdCEo3C
         tO4/ZvyuTGodNtgAisrxb5XplBYqYYxZOE9bNwn7MT3ZKrONShJF6+YQsVkZrl/3gqJ7
         eDwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=A2eIR5Z+;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BsiWU+dJ;
       spf=pass (google.com: domain of 01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.20 as permitted sender) smtp.mailfrom=01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :message-id:user-agent:references:in-reply-to:subject:cc:to:from
         :date:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=vtNBKBeE7d3OLXFt2K/4ZlSimgT/So99RlHMyXeN93c=;
        b=D7ubTS55AXHHwJDaRM2LJGvSlfSHnnJSt0PakYjuK2Nr4WQJ5Qn7mstUHly5mEAzmH
         l7XlU+rF/vahUcHKr+/wlGlso6HiQ0bu0zMfI04ToV7gyblD3SbuJzSxyidRLVZrTPPI
         qWDBuTxuVv1xIJGfhIjHPVJZ6jzWvG9Ec2KId/Pm7d+KGYW4PlMiUcclSiD9drZEWDxy
         65jp9nm/Xcb2Ojdk/b7E+CZtKwE/2QTrlLalrdtb7xJdznnYKjSvWpupApB10heb+R2/
         s/OxFQTeXXXfR7V8sMC5aAY6e0sUW2HrTZOgL7TI6I6L5cg5yyJ4Q+cggeWh4dksvVaY
         wgkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :message-id:user-agent:references:in-reply-to:subject:cc:to:from
         :date:mime-version:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vtNBKBeE7d3OLXFt2K/4ZlSimgT/So99RlHMyXeN93c=;
        b=dwNdHudUHGoeDL93t21fRO2OT47QaviDqmNBCSA4ZqbSYjst/Cr7lQOWI9+FNrK3MW
         yNrC9Xv9PMqDzpMW6bFnpNTjYDxHgCwqUfPk9DdWJbXvoWBiY6kvqSwJB80PO3ulRGJv
         WF1ITqlB9wg0h2KfEo6j9awpbRUsQ7lg3H6c+wpVs7XYhBquFW5H5duzLA3hS4/o47GO
         ubMouTTIouO9PbkynMCbMms5XXPZ6Jysx2hJxiG0dQR3l8haNcMKM/8OuVv478Uv5KPj
         1c2TiqQmiEa7oiYvwcbecem5OhB7zb+xJLyGL5AD1uQcyuegs//szF5y8nEXkkvXCgGp
         QoxQ==
X-Gm-Message-State: AFqh2kpoKcth5lv7Y3MSv/mkfjsdIkeBArGGiQV7dVVXVtfQkASJSylV
	C27gd/0nAq/rax0wBrns92k=
X-Google-Smtp-Source: AMrXdXvmCUQdwHEhHdEtdgsZW3XUHc+TceoU36TcxapAgBSAVrqIt4KegXuyyufK566kg2zcQrhXlQ==
X-Received: by 2002:a63:6647:0:b0:479:1f46:a451 with SMTP id a68-20020a636647000000b004791f46a451mr3844469pgc.363.1672891369477;
        Wed, 04 Jan 2023 20:02:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a13:b0:1fa:bc38:b125 with SMTP id
 w19-20020a17090a8a1300b001fabc38b125ls1594956pjn.1.-pod-preprod-gmail; Wed,
 04 Jan 2023 20:02:48 -0800 (PST)
X-Received: by 2002:a05:6a20:6704:b0:a3:d847:c776 with SMTP id q4-20020a056a20670400b000a3d847c776mr49226220pzh.0.1672891368866;
        Wed, 04 Jan 2023 20:02:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672891368; cv=none;
        d=google.com; s=arc-20160816;
        b=006MVAjSINrN4Fm3fSJ5OKX8Mz+YKXLg+B1RkV4Rul+Ti8CL89g6OHT0bE9K0Qiqtb
         9RBsb1PAQzIpuDEUhLURiCJuW4lZFlmAl/Qst2hspLYHd9ky2uSiwlj/oJioruF48tG1
         m5NzD7TIQKqfmrDGxGJjWNd/VhHrttZU9BYizFydyE3PN3IDtP2u4i7qVBoMwV+dWe8w
         yvakWZBM3phz/73DAryREC4nlrT/d5KEu+K9RBQi4n44QiY3eGI9vv25bIppcD3VFNrb
         7yRdIYYWvq4+Huc49qiBkpeZoqQNqnDNgIgyXb5rwAVOUQr5WIwYBKb5Nr0+CM6noqwB
         6xrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:message-id:user-agent
         :references:in-reply-to:subject:cc:to:from:date:mime-version
         :dkim-signature:dkim-signature;
        bh=EwW7mhioEl6+pqxpuJNZ/UvndZUxFCljFPe17HDDkoU=;
        b=E+00+yQz1tzR5L/waUnEh4wK93EShVpOo1qrG6yAaa9V8shHXDqQvIrUT1M1egUyFX
         DDaO+txZAlJSu684zuj3p8DkRxlPng2lAIGfNnpvafHDpJYv1bQ1atBlkXQNZOSd9sAR
         KNyqYQm4HNMQCkDvULyvoStARju4hW77fNMKf35g73u3lMoElV6V8I3o5HSZl1fYuAU0
         tw8sjaCkwEKsMTbVVyaampmen07hAwWriHJQuBMM0wIJNMdfIdeJP3h9hW44vKUSuqnB
         VLklmCrVoszGJRItLQZicDEf6oN8pgINeCLQdEyC6HqAuea6kX6tWkj5/1623Rndt+88
         ZE5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=A2eIR5Z+;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BsiWU+dJ;
       spf=pass (google.com: domain of 01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.20 as permitted sender) smtp.mailfrom=01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a27-20.smtp-out.us-west-2.amazonses.com (a27-20.smtp-out.us-west-2.amazonses.com. [54.240.27.20])
        by gmr-mx.google.com with ESMTPS id em10-20020a17090b014a00b00225f8c9bf80si202996pjb.0.2023.01.04.20.02.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Jan 2023 20:02:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.20 as permitted sender) client-ip=54.240.27.20;
MIME-Version: 1.0
Date: Thu, 5 Jan 2023 04:02:47 +0000
From: "'Aaron Thompson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>
Cc: linux-mm@kvack.org, "H. Peter Anvin" <hpa@zytor.com>, Alexander
 Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 Andy Shevchenko <andy@infradead.org>, Ard Biesheuvel <ardb@kernel.org>,
 Borislav Petkov <bp@alien8.de>, Darren Hart <dvhart@infradead.org>, Dave
 Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ingo Molnar <mingo@redhat.com>, Marco Elver <elver@google.com>, Thomas
 Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
 platform-driver-x86@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH 1/1] mm: Always release pages to the buddy allocator in
 memblock_free_late().
In-Reply-To: <Y7XU4Wf2ohArLtvs@kernel.org>
References: <20230104074215.2621-1-dev@aaront.org>
 <010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@us-west-2.amazonses.com>
 <Y7XU4Wf2ohArLtvs@kernel.org>
User-Agent: Roundcube Webmail/1.4.13
Message-ID: <01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@us-west-2.amazonses.com>
X-Sender: dev@aaront.org
Content-Type: text/plain; charset="UTF-8"; format=flowed
Feedback-ID: 1.us-west-2.OwdjDcIoZWY+bZWuVZYzryiuW455iyNkDEZFeL97Dng=:AmazonSES
X-SES-Outgoing: 2023.01.05-54.240.27.20
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h
 header.b=A2eIR5Z+;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BsiWU+dJ;       spf=pass
 (google.com: domain of 01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org
 designates 54.240.27.20 as permitted sender) smtp.mailfrom=01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
X-Original-From: Aaron Thompson <dev@aaront.org>
Reply-To: Aaron Thompson <dev@aaront.org>
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

Hi Mike,

On 2023-01-04 11:34, Mike Rapoport wrote:
> Hi,
> 
> On Wed, Jan 04, 2023 at 07:43:36AM +0000, Aaron Thompson wrote:
>> If CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, memblock_free_pages()
>> only releases pages to the buddy allocator if they are not in the
>> deferred range. This is correct for free pages (as defined by
>> for_each_free_mem_pfn_range_in_zone()) because free pages in the
>> deferred range will be initialized and released as part of the 
>> deferred
>> init process. memblock_free_pages() is called by memblock_free_late(),
>> which is used to free reserved ranges after memblock_free_all() has
>> run. memblock_free_all() initializes all pages in reserved ranges, and
> 
> To be precise, memblock_free_all() frees pages, or releases them to the
> pages allocator, rather than initializes.

As you mentioned in the comment below, whether memblock_free_all() does 
any
initializing depends on the particular deferred init situation.
memblock_free_all() does ultimately call init_reserved_page() for every 
reserved
page (via reserve_bootmem_region()), but that only actually initializes 
the page
if it's in the deferred range. In either case, all I was trying to say 
here is
that we can be certain that all reserved pages have been initialized 
after
memblock_free_all() has run, so I'll rephrase that.

>> accordingly, those pages are not touched by the deferred init
>> process. This means that currently, if the pages that
>> memblock_free_late() intends to release are in the deferred range, 
>> they
>> will never be released to the buddy allocator. They will forever be
>> reserved.
>> 
>> In addition, memblock_free_pages() calls kmsan_memblock_free_pages(),
>> which is also correct for free pages but is not correct for reserved
>> pages. KMSAN metadata for reserved pages is initialized by
>> kmsan_init_shadow(), which runs shortly before memblock_free_all().
>> 
>> For both of these reasons, memblock_free_pages() should only be called
>> for free pages, and memblock_free_late() should call 
>> __free_pages_core()
>> directly instead.
> 
> Overall looks fine to me and I couldn't spot potential issues.
> 
> I'd appreciate if you add a paragraph about the actual issue with EFI 
> boot
> you described in the cover letter to the commit message.

Sure, will do.

>> Fixes: 3a80a7fa7989 ("mm: meminit: initialise a subset of struct pages 
>> if CONFIG_DEFERRED_STRUCT_PAGE_INIT is set")
>> Signed-off-by: Aaron Thompson <dev@aaront.org>
>> ---
>>  mm/memblock.c                     | 2 +-
>>  tools/testing/memblock/internal.h | 4 ++++
>>  2 files changed, 5 insertions(+), 1 deletion(-)
>> 
>> diff --git a/mm/memblock.c b/mm/memblock.c
>> index 511d4783dcf1..56a5b6086c50 100644
>> --- a/mm/memblock.c
>> +++ b/mm/memblock.c
>> @@ -1640,7 +1640,7 @@ void __init memblock_free_late(phys_addr_t base, 
>> phys_addr_t size)
>>  	end = PFN_DOWN(base + size);
>> 
>>  	for (; cursor < end; cursor++) {
>> -		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
>> +		__free_pages_core(pfn_to_page(cursor), 0);
> 
> Please add a comment that explains why it is safe to call
> __free_pages_core() here.
> Something like
> 
> 	/*
> 	 * Reserved pages are always initialized by the end of
> 	 * memblock_free_all() either during memmap_init() or, with deferred
> 	 * initialization if struct page in reserve_bootmem_region()
> 	 */

Will do. Thanks for the review.

>>  		totalram_pages_inc();
>>  	}
>>  }
>> diff --git a/tools/testing/memblock/internal.h 
>> b/tools/testing/memblock/internal.h
>> index fdb7f5db7308..85973e55489e 100644
>> --- a/tools/testing/memblock/internal.h
>> +++ b/tools/testing/memblock/internal.h
>> @@ -15,6 +15,10 @@ bool mirrored_kernelcore = false;
>> 
>>  struct page {};
>> 
>> +void __free_pages_core(struct page *page, unsigned int order)
>> +{
>> +}
>> +
>>  void memblock_free_pages(struct page *page, unsigned long pfn,
>>  			 unsigned int order)
>>  {
>> --
>> 2.30.2
>> 

Thanks,
-- Aaron

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010185801881b4-2dd5c952-d967-414b-9dc6-7edb04436342-000000%40us-west-2.amazonses.com.
