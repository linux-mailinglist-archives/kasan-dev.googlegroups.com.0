Return-Path: <kasan-dev+bncBCKMR55PYIGBB5G6YGMAMGQEFHOKIYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F43D5A9231
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 10:38:13 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id v4-20020a2ea444000000b00261e0d5bc25sf5045779ljn.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 01:38:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662021492; cv=pass;
        d=google.com; s=arc-20160816;
        b=MZBPL6Dp7ZA/DjLnWacFGcRYHxNiQdV7qmozaBqE48D7SPoSo1VZIY9Rv2nqw4BxaE
         5MliSpu4suCDpy8/YOLsT1ZKpFD+T9/vkqDvOfvuxdzjEnPlhtgUHcUKnt2xN6vwkcLc
         bJF/P3NpxIY4vtQ5AZjbST1cH6dmn5XZV6vlz2BvCQgOExT517earHkfm+mCkUIO9DVt
         c5ch8HAzimVmxhNmlbObXbXa0VS2uHG7cq/4O82xkruGXGrusRyACnjLmeQ2KXymC5TP
         435hHA6NdaY2O3uZrihFCpElL6HENhbCBENEQYTJ+ABO7W8JNqYWDkKNQ3roW8SA5Xdo
         UOFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QjdzVN/e61Mqr9pHIO7hz1y+HM820fOzfC6nJfgKc+w=;
        b=G6oDJ+2hsNmc54RLU2pIbgjxgMFN1Mbik5Tk+bqvuAgjnniglOuajDb81jBLWSO4XI
         2oAatbffHmOJxhGV7zPdKcZTA1fl50Ur9kKf8SvPzfhc7V8KnvDTGTHNSjE2rmJxbuyA
         eWTOJ1+8cb2w9asw9IELZ/534tVlqaDbon7HFh2Sg3FBnn1ofU2qn69xCIaD+aVHts0b
         WjG2JDE4hnAredfTtr3RyFkvSKyKVX0VzITfOkn0WNLT/RdszwpQ67vxBW75JzY3ON9E
         ts9sq2lFoRf6Jm2APM6m6xHKSGmGhez1UnQYCFjcu/uM2YcqaZ5+JSQ2hpUudCjXZrOS
         X0GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=tZeFnsBg;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=QjdzVN/e61Mqr9pHIO7hz1y+HM820fOzfC6nJfgKc+w=;
        b=czLqPf5GdxJyvxSMObgxHfZE1YJ+XimMAh339iAy70CxrYhZSM8gnVqen8p1FpMDgs
         SzixiOkqTi1MdbfwzdstXQoJ/G6M8xUi4R+lGjjbpWANVtoduN661PBDR0NfBFTs3CWS
         pWbSAPMSW2Fip5UZxfDqMw4oJeFhOH9NwC4BVi4Qa04c/eQIjg6eCQyjiByq7F+5UIfm
         FzUUzq0JUDAQNTTi6tY3jbYV74sarU9E6tGwDR13sO8aaGWDtl3BMxms/UtMvExqX/33
         FIxsdoHc7NMlHjJXHIroeLS3wiUPY55Rrhb7SoadM1OeujMcIZ3vXC3XyIWOwoYTdPyk
         kfRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=QjdzVN/e61Mqr9pHIO7hz1y+HM820fOzfC6nJfgKc+w=;
        b=EmSAYZDbG9Mw2a4hdK/hNfGfI56xB9rJ6T++v34iJ/NrZcXGpvqHkm0i4BBkHjxLdc
         rfkwpyIh4GyjEn/eEhWKMjGNV8u9o+/2+EKDseDAgpkGDCEneCF7/abQ6OWxPclRTAvI
         J5PrKkCmFats/SQXXbUlIiAtEeNWfjAsl4+pzjZJ5NtynPwX9Z1dtnKpN1/uJxbqIoei
         5x/YQgZQPE1Yz+u84saIcMFSKmabhq8mdNfzO31P//qYrhRm+9/nzErYeJLq9D8OVDk6
         DM2NBrd+F0LwGu+WzdVgfs+BRveFE3KkWQM2XiZbtlKEk/eBdPC/upL7Hsv1bs3lAHX/
         PgkQ==
X-Gm-Message-State: ACgBeo0gdVLVd9nKTD1WJb7j/lQ1ElPCzW1KZGYgGhV3K1e4Fgk8Q7eH
	AEoeDmOqZAqaEDbccClNkUo=
X-Google-Smtp-Source: AA6agR7rEeH/LXiPIPBGI4PVEnUk9UShNLGJ1qoxshoIAzFiAFZnWzKr9+G3UE1Y3id5+BDH1mqVIg==
X-Received: by 2002:a05:6512:2807:b0:494:6cc8:d31e with SMTP id cf7-20020a056512280700b004946cc8d31emr5372004lfb.82.1662021492654;
        Thu, 01 Sep 2022 01:38:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls931367lfo.1.-pod-prod-gmail;
 Thu, 01 Sep 2022 01:38:11 -0700 (PDT)
X-Received: by 2002:a05:6512:6c8:b0:494:796e:93b6 with SMTP id u8-20020a05651206c800b00494796e93b6mr3795015lff.213.1662021491126;
        Thu, 01 Sep 2022 01:38:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662021491; cv=none;
        d=google.com; s=arc-20160816;
        b=aoa6fGLNXf0H7txFyLSnPlzkhfBkNaaRobiUiNYELjCGPgCgbCe+5j7nR930La/R0R
         gziFwboYM+q8iiX5Sj8sOBW1X+EcxU85YhzWKoq7+8bOeaDyl6ljmGejDG6pMtdOvYDD
         VMzc2xQt1fHB1SoLC8md1/AXhSvNiAa6ZQMsuNaxauDYYm724qM8yv9ovyyJ8WFcVG88
         ZjV4GcJdyqoCncKf+i8Cb3zww89lljAg5mFGcz8ntHOeSotYi4iibW7IRpsiHIlDd2oT
         PYYjOFThuK+4gZoQ/5+7Yw5tRKCKsMsrT0SVLpy/34DAnMCz0MkS/7d+KZloy+aH5t46
         lQ7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NrHpzMz41QmduVOHpV9GnZB1kYyiHKDCqktpestefcU=;
        b=gJJdu55yfgiu+SqoOGSJiux7AhYnW39yfnJ8omwZ9cSm7pzsrzELqZ4Pk4rmqpT0Wq
         ZjXlbnDTpr1bUfOttFjaCkqVPJiFjsNfeiO3M9D7DBNv3sJGtnLOnZzpx313cfZJoi+/
         Io736ti57vPGJbAZuK7G9lFksm8ZSRbeZ4GbdWz4YDNBUDXoiMCkikt1+3l8GneiftNv
         kSMqfxShcylyryxr4i/2NjwP0MxjLwbkcF9Z5HSzo/G1sGcAPwPPXf9u9rBM72syrd6M
         QANBq+d/UoKMDLyBhD0uYaN2m2VB+4BujQGi0xHKxusj6xeD6F+/lcNhoU9GDv3HgF2Q
         WymQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=tZeFnsBg;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id c16-20020ac25f70000000b0049465aa3228si204233lfc.11.2022.09.01.01.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 01:38:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5E08B1FB58;
	Thu,  1 Sep 2022 08:38:09 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3C1D713A79;
	Thu,  1 Sep 2022 08:38:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id KlFtDHFvEGPpNwAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 01 Sep 2022 08:38:09 +0000
Date: Thu, 1 Sep 2022 10:38:08 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Vlastimil Babka <vbabka@suse.cz>,
	Eric Dumazet <edumazet@google.com>,
	Waiman Long <longman@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
Message-ID: <YxBvcDFSsLqn3i87@dhcp22.suse.cz>
References: <20220901044249.4624-1-osalvador@suse.de>
 <20220901044249.4624-2-osalvador@suse.de>
 <YxBsWu36eqUw03Dy@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxBsWu36eqUw03Dy@elver.google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=tZeFnsBg;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Thu 01-09-22 10:24:58, Marco Elver wrote:
> On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
[...]
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index 5ca0d086ef4a..aeb59d3557e2 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -63,6 +63,7 @@ struct stack_record {
> >  	u32 hash;			/* Hash in the hastable */
> >  	u32 size;			/* Number of frames in the stack */
> >  	union handle_parts handle;
> > +	refcount_t count;		/* Number of the same repeated stacks */
> 
> This will increase stack_record size for every user, even if they don't
> care about the count.

Couldn't this be used for garbage collection?
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBvcDFSsLqn3i87%40dhcp22.suse.cz.
