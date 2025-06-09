Return-Path: <kasan-dev+bncBCS5D2F7IUIPJ3U3YIDBUBFLGADNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA986AD21A6
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Jun 2025 17:02:13 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-606e35c3627sf3636945a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jun 2025 08:02:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1749481333; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZVxB/dKlwFIagPU83Wgw8BeOschn5vihM2tZwqQy67Uvxgcn22FRJgwuoOmtXSGp67
         a6oEbow3slYdiyReGo2MIi6Jgs9bSJ8iVTAtlk6tASqRdihPzDWblFvlZoZzmQ4LOO4B
         4mvsUDWSr4H4eNsa/1mae4MjQ0VKTJAyTL4UuDhBN9yZHBeJy1RHd2Dms3UH9sP4za+k
         oOx+vfxhu8JGjmKnU2KJE2hvN/B5yU3j5tMgg7Z4T2OdVJ7Dq15Z+NyfO2uIM7I5nPOm
         I/ziLVfN15sduNzIx8kukBgRo1q0smSKpdfgSVqr4tuZkITtQ2CS4q7J9NfqDGgIFzHG
         hM5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BOUROe6g2kYoZdr6yxqtq2s2XEEYKQY4u77YQa8CY1Q=;
        fh=27HOIGX/OeiuSLbi7vofOizxgMcXmWZeg1xU8QrHLeI=;
        b=e/OLL5fo9sOw2HjT2bZYvmsJx2Ca8HB7bgOPwqbjhjTa83Dp3vrMvz9V7CmYEMbrTK
         MFeJjxOM0SKUYkbBaENDWcWDuFGbcTFBPOPg0vfvhgaUQaWKwSWF/hYx93EsLFbh8+JT
         ouW5fblLcnhP0dOc6qn9JC9zT6PkDC92VK97GHvEt6QxB3cH8ZOZXWP0/SV1avFytqWM
         xoixT+2qM8X5QGnEdIdJL3sms1ME4CF8dfo/EPQRvffsuj8/zrILTCLXpLKBcPqWGyBN
         pni5PdEqzXsWaaBGhDyMTEt9uxm/6fA1NnZQowjymkC6sT47OEwDq2fXqRopSclifxEb
         W4MA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gP9EvWq+;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749481333; x=1750086133; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BOUROe6g2kYoZdr6yxqtq2s2XEEYKQY4u77YQa8CY1Q=;
        b=OAm35fe2eEOHe0dmwdtgQZJlUQwdJT7nVywL4vfadvOp6lXgD4KIsLS7lpmrh26rud
         k6xe8RIOGKlT07OfO2v5gEZKdKaYdOpqJK3pwX4DdW+at1W20MzuXq3o5STU0HKoanfM
         /wWMdbQftmook/Ta2aELhS41+aC0fDWWi0mBc1COJBkNxvqqmCb9dyawsXoTsdC9LaMM
         C1tz5V9pGWH46hLSsa8qYw+b6QneqaPmp56JsAAzl4zYZbvcVmerY1mokh3xKfPiWJuE
         2DlgKI3KjJgoBHDK2leS3iSbWMLWmqR0dlixViUnR1n3+Zy+xtrLnYDh8uidgjajJo6q
         x8Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749481333; x=1750086133;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BOUROe6g2kYoZdr6yxqtq2s2XEEYKQY4u77YQa8CY1Q=;
        b=DFHcJQhc5w07ZOe7qZ/G1Nfy00JBmNlmDqHjS2e0p0tUDLkPd6MVeLDUeTU9CI7svm
         Z138B1FbN5BCDZTMkXQGcZg5VtwmlpkA/u99U+P+wcZDXYljylMczFHF5QNoEfLM9SZt
         QIrKd8xAS2ulCUctY9zI/GrF3zksjKAABazVRMNfp2pa57WfTJzkscrdd4Hl82ynV/Nm
         IfvF9F9yUOfTfuR1ChDGh/FlUmNdUGUbjyik3QGgMFM+0l4LPbiXeVzN5tsLBDPtJnwi
         XxDlIV+LewtjOAFuoojwWjDcBTrK22LSFZ/OcXsqJzMik333piCd8YhldDteifEELIvG
         KVtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUXYZe5VLmml7Aoq6q6zBKXMTCXPhyk1jOE1vL8dbMD9Cd6dvCjRmwY6WsoJg6vqCeiWGY1/Q==@lfdr.de
X-Gm-Message-State: AOJu0YxjWKAXYS8UxbKAin7U9cbw6NIT9DbMpdKfkb5i2CXKqBSHrtu8
	2ul22UEF6PZatLtpiCEff6E27wVfXgberYrLkOtNc+CxOhjdZDK5ckja
X-Google-Smtp-Source: AGHT+IGoYXReZQzn6KfJXA3GJm5fd+knSBEwOBL3EJXECAXNo+So2D+iGUpcQ3NLEHJxoRn8sfAG8A==
X-Received: by 2002:a05:6402:254a:b0:606:a77b:cca3 with SMTP id 4fb4d7f45d1cf-60773510343mr13162067a12.7.1749481332537;
        Mon, 09 Jun 2025 08:02:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd6sw2OukcpSqqDQU+6P22WVU3yh2LFv0mTiA/mUls2HA==
Received: by 2002:a05:6402:350a:b0:605:d962:5e1c with SMTP id
 4fb4d7f45d1cf-6072412d28cls3289313a12.0.-pod-prod-02-eu; Mon, 09 Jun 2025
 08:02:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLsr7dr4sst6H5L8uXGB314K96m/yrOeeUDNL9EM51r2pQtSxDsrtkFRn1LGS+WwL8sKiuYAlwwXU=@googlegroups.com
X-Received: by 2002:a05:6402:350e:b0:604:e99e:b78f with SMTP id 4fb4d7f45d1cf-60773ed04a8mr11700402a12.16.1749481329316;
        Mon, 09 Jun 2025 08:02:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1749481329; cv=none;
        d=google.com; s=arc-20240605;
        b=aeXmFJc63g8piIwe3//+1fO/7PJWpvBAb5xdmy2Kf3UKUOe4UlRCVuN7c9+MJZBQE9
         RBq03lamWLm+6cMHDI381SL+6wh4rwP0GVQC5MP4tS5EVXegwQ09u8XQvXq4Gg1i6p1c
         knoK2x5G29O5O52gpsamYYwBmDupZDTjCgXNJwJ70XGUUxdlyuUxPZ4dM1yJB0OC3dcv
         IFVIYc4085hApK7Z9h1yudkSG82zDRDEIVcJ6Mkd5Wv62xKKb9TO4nx8eZFaIMViOcya
         +jasQfyAoKCfI14p+iwW2olgThLwQX+inGxUh/l63oM+MbDEUxesOaiSJEv2NOjd2WJY
         aLQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1TW5/EX1uIByMYpPlUTd3RK8aCzmnNLsk9YRhlGE5g0=;
        fh=DnsaqAsjLp8ryqUMS07Xwk3jfsyvUtqIz4G1w7cNaT4=;
        b=f//FZ1xydr027Fh661b5Sd0c0rbhp7bGuB0gHlxrTJT/rXH66oqQc/V4Ur9agTZcP/
         YuPiD4qDO1FdOkpefnVRs7LoXMxzx/GjetG6wWiWPqq0PVsbAF2wPcRqskVztwnWFJOV
         DzbcLS3loeKeX92iV6metpfVFTGMp5+dGJKXx3PVrR9E8OvimOARezVgI2LXqoGiDcoA
         VfkCi1zAYEjlsmZJB0oN03PPsMHwnXLmkVAb5sL/cwJiABaXSVOLr3sX/c63QUBPsUyP
         5Uyxcov+I6GhkP19CWA21c5DPaMNqCUyH6yv7v8VuVSWsJUJ8AvacUi1sDS7c4YPLGZX
         qroA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gP9EvWq+;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org ([2001:8b0:10b:1236:954e:22e3:a3e4:ae29])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6077812469asi311727a12.0.2025.06.09.08.02.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Jun 2025 08:02:09 -0700 (PDT)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236:954e:22e3:a3e4:ae29;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uOe0i-00000008KyD-45bi;
	Mon, 09 Jun 2025 15:02:05 +0000
Date: Mon, 9 Jun 2025 16:02:04 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
	linux-mm@kvack.org, Harry Yoo <harry.yoo@oracle.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH 08/10] kfence: Remove mention of PG_slab
Message-ID: <aEb3bMaMoROWz3Pk@casper.infradead.org>
References: <20250606222214.1395799-1-willy@infradead.org>
 <20250606222214.1395799-9-willy@infradead.org>
 <ff370b8b-a33f-47a2-9815-266225e68b8a@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ff370b8b-a33f-47a2-9815-266225e68b8a@suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=gP9EvWq+;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org
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

On Mon, Jun 09, 2025 at 03:33:41PM +0200, Vlastimil Babka wrote:
> On 6/7/25 00:22, Matthew Wilcox (Oracle) wrote:
> > Improve the documentation slightly, assuming I understood it correctly.
> 
> Assuming I understood it correctly, this is going to be fun part of
> splitting struct slab from struct page. It gets __kfence_pool from memblock
> allocator and then makes the corresponding struct pages look like slab
> pages. Maybe it will be possible to simplify things so it won't have to
> allocate struct slab for each page...

I've been looking at this and I'm not sure I understand it correctly
either.  Perhaps the kfence people can weigh in.  It seems like the
kfence pages are being marked as slab pages, but not being assigned to
any particular slab cache?

Perhaps the right thing to do will be to allocate slabs for kfence
objects.  Or kfence objects get their own memdesc type.  It's hard to
say at this point.  My plan was to disable kfence (along with almost
everything else) when CONFIG_PAGE_DIET is enabled, and then someone
who understands what's going on can come in and do the necessary to
re-enable it.

> > Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> > ---
> >  mm/kfence/core.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> > 
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 102048821c22..0ed3be100963 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -605,8 +605,8 @@ static unsigned long kfence_init_pool(void)
> >  	pages = virt_to_page(__kfence_pool);
> >  
> >  	/*
> > -	 * Set up object pages: they must have PG_slab set, to avoid freeing
> > -	 * these as real pages.
> > +	 * Set up object pages: they must have PGTY_slab set to avoid freeing
> > +	 * them as real pages.
> >  	 *
> >  	 * We also want to avoid inserting kfence_free() in the kfree()
> >  	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
> 	

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aEb3bMaMoROWz3Pk%40casper.infradead.org.
