Return-Path: <kasan-dev+bncBDOY5FWKT4KRBMUXWWUAMGQENXBUH6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 280687AABD2
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 10:09:25 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-503555a717fsf2254730e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 01:09:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695370164; cv=pass;
        d=google.com; s=arc-20160816;
        b=amc5ar+TlgVUlJ38fdMLsJiBk4J9yQKXN8MmRLjpIot+fFhcZgjtwhKJF0d5l9EShL
         MPjIGbJ5q1LVXZKD/+4om6FTaBwiDbEa0HGrmI6jb+YieesQ/ntlJkpP6rfBL9vHgHRT
         iYWqcm44kjgz+GbXN9SpxWn+1bMcAPRDdKuuhpS048ZrQBgA4AsAn6nyYRkYpMliYVmH
         V2wmFzs0uq5rLig6HGcFGNobsITAm/YKvC9Rlw8k8sDp01YZ/k6RHQXRRKjl96UFJW/5
         7fPf1PEZ8CHwAkXYLOeQiPnZS9Xks9BspQSQIi5iFjFpe1QORDOus5H3IVbx+OxfWi8Q
         FNRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0LJ6OwOER4Jc+WXBEtZm5QHwojsvi7/qKQ6/f7gGTp8=;
        fh=CfbhsxpMlsA9bNz+SoXMCJCmvia5cpGZZdpAujZktvc=;
        b=VkdlQFxAJ0cvyfOuEkVyUVYgGo59eesVJ9Uak63YIqpmDuhTE5XpuSC+68J5U6wrGt
         CHRZwjZqTJUMWY3JbPwLHi84XyXux16pL+wSNhAVvfAUqfMfAOZwn1WaqLQ5vR2DiuWA
         dG0MCnkD5EhxJO+KxSjtKg3xHbEPXAHaT0T8FwkjJZdvBvCUshdK7pOR1WvLrc/9k4Em
         07cgbioFzRarrzhXF/YCSgVX5LS6HTERWh8smOapTNIFfDrfMTE+/HKw3k+imSHiEk6G
         D5lUTR9qMkIBPUcCt4Is0ASLKOfo+22Z/aPm8zOifrfuqckxFSFMSN4wOZb3b0YPniv1
         Ll0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kXI++VKq;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695370164; x=1695974964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0LJ6OwOER4Jc+WXBEtZm5QHwojsvi7/qKQ6/f7gGTp8=;
        b=AgKUTPM/BC1gqJyobX+Kztrnl/KO2200WNNgB9MSlcqDhi8pprg48hfb/0Lx78pmWR
         W9ZlWZl0yfk7Es6jqvJO/7oumvoZF7Xlq1iMBwhnjtXrhadn9NQu1kDvqFTDLkNvKKVp
         tGnFUMAasStwFDnAp+zJv6EY/P5CKd6rZEyJ61qHrY0pIkCBbzBwQfhx5sbVG6PdlDx/
         n2CZQq6BywEu9NrkG/kiAGisRcY4ZnarV1s1qHQtWqiYAqYPsLlswc9SpBN74NurPMYW
         setZcVgpmr+9OPOzKFDlpz3aMar2P8BzPd2FzOKf7vpSwJXgGroXoQcFODEzKC4ORBSE
         t9xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695370164; x=1695974964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0LJ6OwOER4Jc+WXBEtZm5QHwojsvi7/qKQ6/f7gGTp8=;
        b=XdRQQttbBGrjEkkPw7j2uXVtJ/yyDRk55Yofs10Z7HK2Vce2UN45OmAtpMkKZkDKdx
         O9beKhiJopKGcz1mKZkUlRy3niF1DBz/VbMMJSw/4XAzMClYAxphQLLMCMN/JWwR7uY1
         /hqth//ZhKvhcwqpUIo48ITPm2NUAreDzva/YiX/ZOwvjPvc923BWM0UNxltmwY7kqpu
         +DqhLA0146sMpZwq08F0AG/lFQZbPZtMZlFKrsKsP2LLKusDjID+vS+MniI1yBx4rJ0k
         SxA20HZn1klmtV6NfOWU2lQPnMcnjom5O5w596dvXP9pY+RuYWY7YUglKgmx1acF1l9l
         +ikg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz9wZvqAioA6tCkf5QfTqbsF4oOVhUhZWpF7tTrctbq2huE2/06
	6hDv7A+iZzU4ZcdtLpqxEtA=
X-Google-Smtp-Source: AGHT+IEYlXy8XTEyHePASlbPds1At5fDomPh6fqBtcMJi5QtG8ZgiPwOOCsG0UgMZNHYv2m++S39Qg==
X-Received: by 2002:a05:6512:3c98:b0:503:2dce:4544 with SMTP id h24-20020a0565123c9800b005032dce4544mr10605728lfv.59.1695370163218;
        Fri, 22 Sep 2023 01:09:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2fa:b0:500:7f17:b77d with SMTP id
 m26-20020a05651202fa00b005007f17b77dls114716lfq.2.-pod-prod-01-eu; Fri, 22
 Sep 2023 01:09:21 -0700 (PDT)
X-Received: by 2002:ac2:58ec:0:b0:500:75e5:a2f0 with SMTP id v12-20020ac258ec000000b0050075e5a2f0mr6325231lfo.51.1695370161394;
        Fri, 22 Sep 2023 01:09:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695370161; cv=none;
        d=google.com; s=arc-20160816;
        b=XQyLpJ1FDvAsQKuBHxTHGvo/WPkjH49EGy85ptL+Al5JCqRCxw2LBJMQsZ9jQhzPq6
         blbakg6I+oTcGZus8WHF8fsvDH6EMCBlmYbUYSdw268qR1MEUA8I6nkLdFhxbZOyLOh/
         oSHuvYgqi/C0e1B3eUB9vwolqUjm0bY/3Rra+zNg02yIxwRg9zuo9+Q8itCsAsK0+mcR
         R+ysQMbObsTNnz9wKxf1z+PCVBryBr3AJnWyR8sW56aFVcNhdhFt5AaPKLD3LcIatmVY
         qMFz+0f0/7lCXjSgmSyT14PYOyLEMMA/znQ0GhifcsWunuPT7VhkJNtLMBwJOIK25CkI
         n8hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OQolIfhh7homJyMPEX9/UxsWMWPQ/P/HantJlm/8pUE=;
        fh=CfbhsxpMlsA9bNz+SoXMCJCmvia5cpGZZdpAujZktvc=;
        b=E5JHU7Q7H6BnH+DmCeV63C5QpfB/Im5Cs3NsrdfgyiICD0ls7tDAzJ2teL+OgfkayV
         Y1ru9FJQzRjWVHoDKBdhqY4JDBj0l46ZQ0CMx4/BjXGKpiPCkrDxaRVpwGcGajGGOdtY
         /1hufppnr1pHQXw19aMmRU7sxo+NW4BiP1/paYh3MA/YFKSMgYqKUWpkYP05euKK3ySc
         28+/mh02i2CMP1LLjdyePHjDOSyTq7OawyZECdtpUBHRl9JCDyL2guTluCVmR5+yosis
         1WhO/iURrOlc065VZO8NLiYIBihl6hjsdHyFLurkf3Btdqib5jao55tElEL8rYjXT/1Z
         oEkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kXI++VKq;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id a18-20020a056512201200b00503119bd626si227058lfb.1.2023.09.22.01.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 01:09:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id AE0D9B822A6;
	Fri, 22 Sep 2023 08:09:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 03E04C433CA;
	Fri, 22 Sep 2023 08:09:14 +0000 (UTC)
Date: Fri, 22 Sep 2023 11:08:31 +0300
From: Mike Rapoport <rppt@kernel.org>
To: David Hildenbrand <david@redhat.com>
Cc: Matthew Wilcox <willy@infradead.org>, Yajun Deng <yajun.deng@linux.dev>,
	akpm@linux-foundation.org, mike.kravetz@oracle.com,
	muchun.song@linux.dev, glider@google.com, elver@google.com,
	dvyukov@google.com, osalvador@suse.de, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/4] mm: pass set_count and set_reserved to
 __init_single_page
Message-ID: <20230922080831.GH3303@kernel.org>
References: <20230922070923.355656-1-yajun.deng@linux.dev>
 <20230922070923.355656-2-yajun.deng@linux.dev>
 <ZQ1Gg533lODfqvWd@casper.infradead.org>
 <2ed9a6c5-bd36-9b9b-7022-34e7ae894f3a@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2ed9a6c5-bd36-9b9b-7022-34e7ae894f3a@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kXI++VKq;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Sep 22, 2023 at 09:48:59AM +0200, David Hildenbrand wrote:
> On 22.09.23 09:47, Matthew Wilcox wrote:
> > On Fri, Sep 22, 2023 at 03:09:20PM +0800, Yajun Deng wrote:
> > > -		__init_single_page(page, pfn, zone, nid);
> > > +		__init_single_page(page, pfn, zone, nid, true, false);
> > 
> > So Linus has just had a big rant about not doing bool flags to
> > functions.  And in particular _multiple_ bool flags to functions.
> > 
> > ie this should be:
> > 
> > #define INIT_PAGE_COUNT		(1 << 0)
> > #define INIT_PAGE_RESERVED	(1 << 1)
> > 
> > 		__init_single_page(page, pfn, zone, nid, INIT_PAGE_COUNT);
> > 
> > or something similar.
> > 
> > I have no judgement on the merits of this patch so far.  Do you have
> > performance numbers for each of these patches?  Some of them seem quite
> > unlikely to actually help, at least on a machine which is constrained
> > by cacheline fetches.
> 
> The last patch contains
> 
> before:
> node 0 deferred pages initialised in 78ms
> 
> after:
> node 0 deferred pages initialised in 72ms
> 
> Not earth-shattering :D Maybe with much bigger machines relevant?

Patch 3 contains

The following data was tested on an x86 machine with 190GB of RAM.

before:
free_low_memory_core_early()    342ms

after:
free_low_memory_core_early()    286ms

Which is more impressive, but still I'm not convinced that it's worth the
added complexity and potential subtle bugs.

> -- 
> Cheers,
> 
> David / dhildenb
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230922080831.GH3303%40kernel.org.
