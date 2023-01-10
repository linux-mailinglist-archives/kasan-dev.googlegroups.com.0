Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB6736OOQMGQEUS6BYJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8F156638E9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 06:56:12 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id g1-20020a92cda1000000b0030c45d93884sf7740676ild.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jan 2023 21:56:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673330171; cv=pass;
        d=google.com; s=arc-20160816;
        b=vabh6lN3YejXJWfcWwsKTdcUNljIM73WJJll3pDaR/s1Z3TKrkpTtbFy7Y9zDQFEO6
         nEBLrzlnaQWK/rLr5Qq13GF6xXHcFRSa1v6W0ONem7wASmsBQ1piwY6LkonZR19R52yd
         IeOFdcuRBw/zLE7IKdpMA6ZJMbaksfUyDM8zeeMVqWifyQyvr5RaFTbayU950WsbLnwi
         bVHYAni/tmyoxuw4DAXkoiA2pVENUQfmMBkSVJD2j05p9NOBe9C+QYfVw37AfnMZW88r
         oE1sNcGKRWC5emZ4tLdxmwBsy8aZEBisk7+MEYeuwOMYgv/v0hMF6uMsbqC9jKGxDuIo
         kqCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WTjQzyL+byCBTd/kNiAOPTPe9KZidM3YW3F4tDWU6Io=;
        b=VJ2CMPyXBnRFMk/wNEWRN3AltJMqxo6Ls8FOIUr4kxAY21qNcA9Z7jbmnbfM3qhsa8
         CLP03fNtfBOqYVkOO7ZhzR5bGs6j5vzzyOXmC6biJvLpxVIxsupYo0qJl55uoV5/2UEq
         34Yon8HvxmOwNQfy86YK1nyIDQVCEnV5jTYX4Cn9XRfPcqqb0t6Ds1Q4NdW5iaxdhbHw
         UbBY7eTSJzd5rUwM6S297sK/Wna8U9/bTbZ+WhEPFbpJjYU56peqnhddpYkRNKqljk4L
         xJ2c/o5Lbt9oxX7XvpAbVH+Sm9m42vZIzZ0e0NgL5Gml0z30/RDJpn5rmtp0ogVaO1pa
         iWlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=FbAmOZqB;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WTjQzyL+byCBTd/kNiAOPTPe9KZidM3YW3F4tDWU6Io=;
        b=tOycUeClkzCzSEIawuJVcWrn85nTr0Lr7cPp+6KjMxgdQ/umEXVSjq1KHuOTS4mxI2
         +NYsAsCrKT8n3dx+VJlKHaGhF3IRuO49mLPl4yThwFLqP03Hx76ffcFRwqZaIL41n40z
         iPKr302Vt8bZFHj3QyxVjqMXCxbe9688H/lrp3pWYU7ld1huXk/Ks6KnqdbwYcQ8TtB7
         Ra9Q4OgtNiYBGMlz3I0Oo55Qb3nnGDjWMYSqt74DOlbL32OaWaHh9mUmTuL21pV8ChXI
         f5Ck+LcgjXCQt7is58DShXZ5xnMHaQycSz8y0+Sq7mmmbPdKHeyGLr6rLOPcxQAVZEb7
         NUxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WTjQzyL+byCBTd/kNiAOPTPe9KZidM3YW3F4tDWU6Io=;
        b=WVrLt2pGRhTOB7bLQ3NACk0bEF4f5/gcpgAmJRLJ0jzt45EqwH0s+RCesRjJeGND6P
         zLP7cCmnIDWm8tqdHH5csVmvawjousjojE4ibI1UNQDauMWyFolAT9o0XwWYArM+4/v0
         4BwdJvR6TsPZe5tol2w9P+/cxZ0UQnelfmOk9P8HylCUvIcESl3NzJcHsQIWAvTqnlTZ
         1Rb7BF7ZntT5U5a1qrLVWF3+xykU0/iTE2tSNCxbUX+/hT7+WhibmvwlG3g7U3oEjyRk
         ZF1UvzpKSU6axuxOmkI512/0KzjfyjiDhzCHt+qbft54frZsTpkLg34ODcAWif9c5GIV
         2oAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koazBbLUyB/L0tQzyOcvqD4L1GG/9cggxhgXXd2cOs7u8rHR4pQ
	zvYDKIPZ2JF/ZOvT9/c0fP8=
X-Google-Smtp-Source: AMrXdXsUyLwwOtaw4JOqewZIBKvzk2vKKjMoYW8M1EYYvCA9HJ8d5/OkAUve/1zRNlXntyGy8tF75A==
X-Received: by 2002:a5e:8808:0:b0:6e2:bed4:c2d5 with SMTP id l8-20020a5e8808000000b006e2bed4c2d5mr4643158ioj.177.1673330171400;
        Mon, 09 Jan 2023 21:56:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ca3:b0:30b:f63e:3073 with SMTP id
 3-20020a056e020ca300b0030bf63e3073ls2207285ilg.5.-pod-prod-gmail; Mon, 09 Jan
 2023 21:56:10 -0800 (PST)
X-Received: by 2002:a05:6e02:14cf:b0:30b:d94a:a4f5 with SMTP id o15-20020a056e0214cf00b0030bd94aa4f5mr57808295ilk.7.1673330170857;
        Mon, 09 Jan 2023 21:56:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673330170; cv=none;
        d=google.com; s=arc-20160816;
        b=0RN8EXX3xtHB8iBJXMZbQAuE5ORHo6omIx6uYrRORjOyGe1KvrbEGE8o2XsA4C4/UC
         ksDRMVtDd/hq1fjLW1VAfcv4ofm7H94z+aYkX7eoXNzXzV7HaFAoyUo8QqsHCF8bof2d
         iv5vhw/FK2/uDmjLwAlRyTV38uA1QsurUQOi9/grWOOnrR3glnPGzhyHQhGDKOBbSzEd
         XntvSgD2jU+TeKOA2lHYlGFUmY7bnp9g/eF9eC5mVRBwD8ldTU5o7KWVulLbhtfR8mCQ
         /JPoaIaiQlWvSNstY+GBOv97e39wPOrT5oEkJMmvrJQyKenuO/s4upolec03c+v4PBHd
         DQvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=s2ChCMDuxQhXRuUDd5ZhtrpWDdMa62Kg9unijH8xHac=;
        b=u5ykRDbPwIK6nkfBtbB01ODyvKBvi8+/FI/h7+8HMyGSV8UsvI2Wb769cuyK3sqPbB
         lpE6Q/mlIBasAGXhhZ7Fa6u75AUWC7jZ2zBJQlC0OrSExTeRaz6dO/bDyx+KZ0oyscz/
         l+wbZN9gxE6v4h8fMUkKsdON1FlPVSt6BryXzb843JDWFd5sLvTJN18s/+xIBkStUcAL
         501vinOW8ajndgm29GD8IyPg078Ro8JtFdRPMYqc96OfMoAAIKpzKS2P7nVDC+F5avo3
         360ceaUI+q3g9diexzsw2XMMH1VR2Qby2jzMovh+kRE9IdUOah0/rUakfMopm5aVr3C0
         4C5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=FbAmOZqB;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 7-20020a056e020ca700b0030d87b97b25si822877ilg.4.2023.01.09.21.56.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Jan 2023 21:56:10 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6D834614D5;
	Tue, 10 Jan 2023 05:56:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9AD6C433EF;
	Tue, 10 Jan 2023 05:56:08 +0000 (UTC)
Date: Tue, 10 Jan 2023 06:56:06 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Dan Williams <dan.j.williams@intel.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux-Arch <linux-arch@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
Message-ID: <Y7z99mf1M5edxV4A@kroah.com>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
 <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
 <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=FbAmOZqB;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Mon, Jan 09, 2023 at 02:06:36PM -0800, Dan Williams wrote:
> Alexander Potapenko wrote:
> > On Thu, Jan 5, 2023 at 11:09 PM Dan Williams <dan.j.williams@intel.com> wrote:
> > >
> > > Alexander Potapenko wrote:
> > > > (+ Dan Williams)
> > > > (resending with patch context included)
> > > >
> > > > On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
> > > > > >
> > > > > > KMSAN adds extra metadata fields to struct page, so it does not fit into
> > > > > > 64 bytes anymore.
> > > > >
> > > > > Does this somehow cause extra space being used in all kernel configs?
> > > > > If not, it would be good to note this in the commit message.
> > > > >
> > > > I actually couldn't verify this on QEMU, because the driver never got loaded.
> > > > Looks like this increases the amount of memory used by the nvdimm
> > > > driver in all kernel configs that enable it (including those that
> > > > don't use KMSAN), but I am not sure how much is that.
> > > >
> > > > Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be?
> > >
> > > Apologies I missed this several months ago. The answer is that this
> > > causes everyone creating PMEM namespaces on v6.1+ to lose double the
> > > capacity of their namespace even when not using KMSAN which is too
> > > wasteful to tolerate. So, I think "6e9f05dc66f9 libnvdimm/pfn_dev:
> > > increase MAX_STRUCT_PAGE_SIZE" needs to be reverted and replaced with
> > > something like:
> > >
> > > diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
> > > index 79d93126453d..5693869b720b 100644
> > > --- a/drivers/nvdimm/Kconfig
> > > +++ b/drivers/nvdimm/Kconfig
> > > @@ -63,6 +63,7 @@ config NVDIMM_PFN
> > >         bool "PFN: Map persistent (device) memory"
> > >         default LIBNVDIMM
> > >         depends on ZONE_DEVICE
> > > +       depends on !KMSAN
> > >         select ND_CLAIM
> > >         help
> > >           Map persistent memory, i.e. advertise it to the memory
> > >
> > >
> > > ...otherwise, what was the rationale for increasing this value? Were you
> > > actually trying to use KMSAN for DAX pages?
> > 
> > I was just building the kernel with nvdimm driver and KMSAN enabled.
> > Because KMSAN adds extra data to every struct page, it immediately hit
> > the following assert:
> > 
> > drivers/nvdimm/pfn_devs.c:796:3: error: call to
> > __compiletime_assert_330 declared with 'error' attribute: BUILD_BUG_ON
> > fE
> >                 BUILD_BUG_ON(sizeof(struct page) > MAX_STRUCT_PAGE_SIZE);
> > 
> > The comment before MAX_STRUCT_PAGE_SIZE declaration says "max struct
> > page size independent of kernel config", but maybe we can afford
> > making it dependent on CONFIG_KMSAN (and possibly other config options
> > that increase struct page size)?
> > 
> > I don't mind disabling the driver under KMSAN, but having an extra
> > ifdef to keep KMSAN support sounds reasonable, WDYT?
> 
> How about a module parameter to opt-in to the increased permanent
> capacity loss?

Please no, this isn't the 1990's, we should never force users to keep
track of new module parameters that you then have to support for
forever.


> 
> -- >8 --
> >From 693563817dea3fd8f293f9b69ec78066ab1d96d2 Mon Sep 17 00:00:00 2001
> From: Dan Williams <dan.j.williams@intel.com>
> Date: Thu, 5 Jan 2023 13:27:34 -0800
> Subject: [PATCH] nvdimm: Support sizeof(struct page) > MAX_STRUCT_PAGE_SIZE
> 
> Commit 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
> 
> ...updated MAX_STRUCT_PAGE_SIZE to account for sizeof(struct page)
> potentially doubling in the case of CONFIG_KMSAN=y. Unfortunately this
> doubles the amount of capacity stolen from user addressable capacity for
> everyone, regardless of whether they are using the debug option. Revert
> that change, mandate that MAX_STRUCT_PAGE_SIZE never exceed 64, but
> allow for debug scenarios to proceed with creating debug sized page maps
> with a new 'libnvdimm.page_struct_override' module parameter.
> 
> Note that this only applies to cases where the page map is permanent,
> i.e. stored in a reservation of the pmem itself ("--map=dev" in "ndctl
> create-namespace" terms). For the "--map=mem" case, since the allocation
> is ephemeral for the lifespan of the namespace, there are no explicit
> restriction. However, the implicit restriction, of having enough
> available "System RAM" to store the page map for the typically large
> pmem, still applies.
> 
> Fixes: 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
> Cc: <stable@vger.kernel.org>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Reported-by: Jeff Moyer <jmoyer@redhat.com>
> ---
>  drivers/nvdimm/nd.h       |  2 +-
>  drivers/nvdimm/pfn_devs.c | 45 ++++++++++++++++++++++++++-------------
>  2 files changed, 31 insertions(+), 16 deletions(-)
> 
> diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
> index 85ca5b4da3cf..ec5219680092 100644
> --- a/drivers/nvdimm/nd.h
> +++ b/drivers/nvdimm/nd.h
> @@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
>  		struct nd_namespace_common *ndns);
>  #if IS_ENABLED(CONFIG_ND_CLAIM)
>  /* max struct page size independent of kernel config */
> -#define MAX_STRUCT_PAGE_SIZE 128
> +#define MAX_STRUCT_PAGE_SIZE 64
>  int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
>  #else
>  static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
> diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
> index 61af072ac98f..978d63559c0e 100644
> --- a/drivers/nvdimm/pfn_devs.c
> +++ b/drivers/nvdimm/pfn_devs.c
> @@ -13,6 +13,11 @@
>  #include "pfn.h"
>  #include "nd.h"
>  
> +static bool page_struct_override;
> +module_param(page_struct_override, bool, 0644);
> +MODULE_PARM_DESC(page_struct_override,
> +		 "Force namespace creation in the presence of mm-debug.");

I can't figure out from this description what this is for so perhaps it
should be either removed and made dynamic (if you know you want to debug
the mm core, why not turn it on then?) or made more obvious what is
happening?

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7z99mf1M5edxV4A%40kroah.com.
