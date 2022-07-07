Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJMOTOLAMGQEMWOAQWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 62E6456A136
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jul 2022 13:44:38 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id i7-20020a198c47000000b00488777cf5basf735156lfj.5
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jul 2022 04:44:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657194277; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0KoLzn/AFtFn3ZsZEfsOfj3DJoW0yTkLxntkipa7Jzvkc0trE5M/syiK3H2+1TEtW
         xvJcoDIF0JecYRadaXOZQG2uRr7WecbCTAW9+gLYGG+ICA+pP9KpoghOZzfMv3LMnrbJ
         yNwTWbU4DsCYw0yyXVBUNmQLIlWp5YCKsH+VRhL4W5GDgxMkUnJ459IxO4Sea7stspOh
         63/4TVwK+nkWPg51GA5oDroqODhEwvtW3F7NrQOmUshbqVMaNlhPYII+opk1cH8uOtum
         P9vh+31c7SXrHWEvwdN7NWNlcYKWeTsUglM7V2lw1/wNmlSjZ7kHkT/TORBifvmRLIpX
         IxtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=02VTW+3N3o9lWKAyVIhYePmPdSjKJOZ+qNPurfwzzR0=;
        b=txqSsd4mnAvkVCQvVQe5QXYyUtky9IrbrM7/aRfALpTqfO7kBvVWn+/DJDBL4Jqf4E
         C3l8P0Su/7+pExAen6XAhFFUx3tIOE/HkD0Tq9Nhdf3iWORwXxdMKgCyNpQybbdX9hMn
         kYhoFnOCTFtHbSBbDs0s4OEZpAfiRKAolQkT4Ko6lIvFrY9BWqXV5HzJkyLoxaoq6jcR
         8ZKYfgfnQyYA45gVGy6Clrz57PnDxDAgBCJJQ0WGZ7Ws56o5RtfEYzvDqAG6KVCVb20m
         PXjI5FC6FtNHsTSNKdlW8M4mtY7MeK3RQhU8yohLmJDyJDILQ5fQmOL6zdn6MrWyRaJ0
         DUsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=02VTW+3N3o9lWKAyVIhYePmPdSjKJOZ+qNPurfwzzR0=;
        b=U8yfEs+61hn7Nl9VkOlSNfVgH3wzw7Vzo9zBekWLhgXK7RElqWcryC7kaVKkfotDaq
         4daigfim3dlCrTyV18AfkFXeGYbmLJ3+XYLozYxE4HnVCOGM0TzJOvc4HCuzW8gan++Y
         vHBVIUPCLZwsrBuYRlWtQWVjC9T04/etWG4J7aoMET2pfQfztRPltNr/gPrqkqwuyNHE
         rAJU/ZYQFHWriaKB6pmfj+I6TBDojxZjtg4vQk3Y1Q3qjpuWqAiLV/EvKvK+mlIaltxM
         ULvNeBI5gW0dHXWj7uSTE2wiOMe0qggTy0a0Ds83o5dh/NTkR5BMNHruwweDDt5SO5mx
         ICKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=02VTW+3N3o9lWKAyVIhYePmPdSjKJOZ+qNPurfwzzR0=;
        b=vdfooNorKlsIEYjowTM6UXfVHIS3OJpNd8rmv8tVB7s334nikR/FM7IKbxygwr8Tvv
         zVmY8iCLDCIWPOcgNfMltJbsd3/yDcXSs5df4PO0GL1QVb5Yv2aVyo8jG2Zk8mNCDW8S
         /HBlny3pFG9zE2ON/Bhz4e8eBHImYpREIyX7OHElo1USu3V5sGbdzVamnLV1xx+s8TAr
         /GtcjkzYuDKisgZsVFHJAvPZushPIYAwkMWcWzfyEm7iRgYkNOIeJO3qnYD+3AzeZy6F
         5mTYMxJAaoA3mfXbKDElI5QKoUGXUVHbclANL7R3zBhhrD+KpZs69SZTqkDsU0NkMzAR
         HDgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/Hd8PxXdQUW/oP5WX0J5rF4tn1hUlltZhl+NyQzFZ8tv9hG9FS
	9/dZJJfVzcvzi78R22qR6v0=
X-Google-Smtp-Source: AGRyM1tFataKoCYBLnoBg8grj8VAQPURikF49cmH7o2oZJpx25mEwz68osqb70/UtqTmRavzQApdAA==
X-Received: by 2002:a05:6512:1399:b0:486:2ae5:be71 with SMTP id p25-20020a056512139900b004862ae5be71mr5379086lfa.246.1657194277642;
        Thu, 07 Jul 2022 04:44:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c88:0:b0:25d:3a42:174a with SMTP id x8-20020a2e9c88000000b0025d3a42174als1222840lji.5.gmail;
 Thu, 07 Jul 2022 04:44:36 -0700 (PDT)
X-Received: by 2002:a2e:8696:0:b0:25a:7673:d22a with SMTP id l22-20020a2e8696000000b0025a7673d22amr25871828lji.494.1657194276134;
        Thu, 07 Jul 2022 04:44:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657194276; cv=none;
        d=google.com; s=arc-20160816;
        b=DFAX4sNv28A6VRLz4G8blRUzR30gBub4AEyGJH1gKG2u2uC1ZjXGk8SYHQP5XSdY06
         YD28ptn4yeoZlEwxJRe6Fry2yygxyt13xNx8V6Iw1SwdJNgAcs6HWfLB3Yb35Mq9DwEe
         QTXQx5inpi2NjDrenUMLSjALjFm7CkHL5KQb69NIkKSC/ZZt/k7XjzNdav8pa/BPhIml
         sZUR5HZsp2APvEMu9g8bcZduhaPqJ8csEl9SQtyGMEIhp+FnEWvFGB4ejB6AslAiSCPG
         MhkUUJ5i/kk/HHCgyE4Lr1siU5jX+x6ZPEmUSkZEE+eE9cbitsaACnNJ8zEx2IeYXAZ9
         zbeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=wyhNe3mfr/pF43Nxat/aKYEI3d0n5RzaEwenkSVEsGU=;
        b=TnUXufnBjQ/tSTHRaPnWCucJqtK0W1iolqxbjOUz/o1CUVtFEBXUhIngERdyZyhZCX
         NzIKzB3ioS5fFIHH4bv5XtUIgeXsHG7ioCUGYVeCTpw8xXIKc9lYdoJb1cb45oOmhcAM
         e6P5kHVo1wgQl18mjhcgzdwcxcx7EI/nqojJpJIeqrynFYhaIOeGuVwajIllut7GLcji
         nZYqajF+iVpV1LuQ9DBJZmcMCg0CmTQwPmD6GzBpf44KRBVJMHZxPZLR03BQzzqcABSw
         CCqCmxyosxwC8I57oEvYvK3BGREvFIEdQSB+E1FAr0JKXjzzk1Fo2Czjdj+OC3fes1rZ
         A5Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b0047c62295117si1672117lfv.8.2022.07.07.04.44.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Jul 2022 04:44:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9B686B82139;
	Thu,  7 Jul 2022 11:44:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9EE3CC3411E;
	Thu,  7 Jul 2022 11:44:32 +0000 (UTC)
Date: Thu, 7 Jul 2022 12:44:29 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Will Deacon <will@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v2 1/4] mm: kasan: Ensure the tags are visible before the
 tag in page->flags
Message-ID: <YsbHHZZLsZgurxKW@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-2-catalin.marinas@arm.com>
 <20220707092236.GB4133@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220707092236.GB4133@willie-the-truck>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
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

On Thu, Jul 07, 2022 at 10:22:37AM +0100, Will Deacon wrote:
> On Fri, Jun 10, 2022 at 04:21:38PM +0100, Catalin Marinas wrote:
> > __kasan_unpoison_pages() colours the memory with a random tag and stores
> > it in page->flags in order to re-create the tagged pointer via
> > page_to_virt() later. When the tag from the page->flags is read, ensure
> > that the in-memory tags are already visible by re-ordering the
> > page_kasan_tag_set() after kasan_unpoison(). The former already has
> > barriers in place through try_cmpxchg(). On the reader side, the order
> > is ensured by the address dependency between page->flags and the memory
> > access.
> > 
> > Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> > Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  mm/kasan/common.c | 3 ++-
> >  1 file changed, 2 insertions(+), 1 deletion(-)
> > 
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index c40c0e7b3b5f..78be2beb7453 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
> >  		return;
> >  
> >  	tag = kasan_random_tag();
> > +	kasan_unpoison(set_tag(page_address(page), tag),
> > +		       PAGE_SIZE << order, init);
> >  	for (i = 0; i < (1 << order); i++)
> >  		page_kasan_tag_set(page + i, tag);
> > -	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
> 
> This looks good to me, but after reading the cover letter I'm wondering
> whether the try_cmpxchg() in page_kasan_tag_set() could be relaxed to
> try_cmpxchg_release() as a separate optimisation?

I think it can be a try_cmpxchg_release() (I did not realise we have
one). I'll post a patch later today.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsbHHZZLsZgurxKW%40arm.com.
