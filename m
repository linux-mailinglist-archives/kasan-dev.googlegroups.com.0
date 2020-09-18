Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCG3SL5QKGQE6K7HZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E14426FD8E
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 14:52:25 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id y18sf1436871wma.4
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 05:52:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600433545; cv=pass;
        d=google.com; s=arc-20160816;
        b=e3YTi2YwK9yUKdOI++W3Jm2OiwtiqNIhfy+5miIKr9fp5YrTST3QAyQJ+K6LxTQS6u
         O2ISpfVvWcT+30AOUzudWf5LzA1bJm+ujvwEEi+OccpCFOBAvQngcOkyBaF64I9zz98z
         kg+jD8xEJPkc0uZm37u9HwaY2/EnQqRdf+7MxlE1JWAg6DqPHMOe9qA3bhjqLlF4eYsK
         ze3hOMJjwBlYc7l5Ub99zX9MzNtma8EO4WhDVLx3Xr7e4mJ15jNX2kFcpJ6AQhQQh8O2
         GPrtydkfEAzpr4fGBVjvREuqPDXUinBOEm09/fG4mOWUmaSi+YjTG7i1PsnFX7b+PR+R
         UdJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=s8AqJA8pDlY4LgOQMQpl+ZjkLMHQIoYT/48aZKC7BZY=;
        b=YYx8H2okaKzA91wX6bphmoEBcakIaNtXhP4F8ieVcyrn7gVH4T+P7NAvZJ26aRyYAj
         sCFvhXTfNjBmUh7VTY0TS79qDAtiVapWCnuwb0hsKnWOlQD+sfM3ktJ7bA5Cbd2FHUcT
         +pQ47exIAPncU4W4WYmeAxbab71Uh0fMwWPzpsZEJwjEdcUoMLwwjoPM2Kv826zjgsVD
         5gU+4r2fmSBC1sTuVGb3NXb6PZdTVgQAukcswPyhdVVO6pAFGvDqXh47FJdsheVFHMcN
         i01+A8MWYFIWhCK3XAel50BqjpD4BHYR3jA1x8PWpbeSb43q1mmlUfSHx9Ix0FEsgLzt
         ebMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OPEfNMvD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=s8AqJA8pDlY4LgOQMQpl+ZjkLMHQIoYT/48aZKC7BZY=;
        b=HblT1s+72d54mvcgsFlvvo2rMhqudCgRyUx8k3XNYkeD1XlmBPzE0MtXyIf5ElahpF
         99KcpMtHiqHB3UmCikCmLm+qq4UMsrybuCIQvPugnP0WG30gvNOf1ur23pVFYVBu/ZTa
         rBluu9j0fz8wUnnk9gl2hkAhAlpt19b8KovAqjmv+/1VbPpL6NxQk7Hu5OR8LKPjzxXU
         m/jN+71AeEaCncRtHjkzVut8DCuEtX0AqHi/aJ0bu9UixMTJ2WrlF8NRWd0tEN6oIWoz
         mnAhYPYG4+vdgNZ1Dn/vKu7doOu8KJwAl0ID5gGim/AE8bjIFzLT/x3Bhf0h+ASDdjLv
         oyvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s8AqJA8pDlY4LgOQMQpl+ZjkLMHQIoYT/48aZKC7BZY=;
        b=e2HEdHvRcl12WbEFG+8WwD/aehvbYxBiXGtSAe2NvuQsWdPC3P3PqQsTnVfJL36TqB
         QwJ8E32eCAhjyT6X5Sx9n2glNuz4hIixoZT3T6hRe+/6zm961K0I2NXCJ3kVH3VN73QH
         HQwRxAFSE+OKBiWdmVQz+UVdZ6qzquTFiYfsgkD0XJ8Yvk4R48hLJGunDJwEDffDOluZ
         Lq8VKk2zNXE0HEuPPAdgzNjcCzwP0rcpDfCdgFY6pvy1QZnAogtFH4uRJz20H9WXvvLe
         4wgYqUpoSp6nSltKqMRR0HkynZLjcnUsCG6kh3ArermJOoZwsEDrkVyn4n/q8w+syhfc
         gK2g==
X-Gm-Message-State: AOAM531z0a6k3spzDpBfpOwK7tX1i+wo1mWAzuCdll1Edc7dEfPXiGnm
	LQjlulZ6n/pizB+vYr7MOE8=
X-Google-Smtp-Source: ABdhPJxbrum/EaEC1kvy/fE8rcyfobeAveBldzwv5ze6dY8VfkNbyYc/tsIgbAZUmcjadZRpxZA8SA==
X-Received: by 2002:adf:f552:: with SMTP id j18mr40168204wrp.128.1600433544939;
        Fri, 18 Sep 2020 05:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd0a:: with SMTP id a10ls6560642wrm.2.gmail; Fri, 18 Sep
 2020 05:52:24 -0700 (PDT)
X-Received: by 2002:a5d:4448:: with SMTP id x8mr40202859wrr.207.1600433543958;
        Fri, 18 Sep 2020 05:52:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600433543; cv=none;
        d=google.com; s=arc-20160816;
        b=bKnK1fdSZSkT4vCLEoS5itcRL9WhE4w2d5CLxEtoPAfM+PGh1sfLrwNnUO5e4IhWpr
         WSFRnFvRkmaBYoGgKwVbQM2Sz3ocLPvd7fiSqgwXI3qaF8PJu7p6YdJoXIcScg2j97+e
         99PHQQGNxXo26XH7siszaCVe/c5YQ3Dfk7OzhnnXAcSGcKZ3LYTAzZ51lwnTqvtOOjlF
         Qd9uUcxRkTal51iS6XMVOd01ycnOGGXEdk9KbzHYCj0gwAaq7Adg/SDsIDneJmQNmvY3
         fJ+zOl+TsL35QOZVEVrIBOf6SJ5FNlMlhKP4iWnR8LCZpZAsOUKRrNPqLfplvKGo6npz
         6EvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9QeHCUfQyRWNLF4v5BVGx0mOMMB1DfrWlk1Da5oWEr0=;
        b=o81WxlLictv6C3fn0LdDM8SXNHyJ/5Jm9gURCt1TDtyf9dEhT8rb50aZDFok4RJwav
         FTwmSH+oX0CGz2PXjgjP7lIFoYlEHmV8yws9tpZoc5kXL67UvNx9fLGcpyEq8ce7Nikh
         SlxoJ+df5WrVWomCdGDXOUBXg4vsIq5EF8aBgrwqGzz9PkNkoV6+LnE+lQrQG6liN2PX
         mShE79Revz3bRF24isefqg8didZ+cpP2GLjnYi/e2eI6Ityf0u7sz/N+43oLsmINrktH
         pzIgh8rPTTbvNscF7Hd0VtmxXFnjJlhphnCjNCGCbrX3W3Fmi4+ld+tP9rDGvj9pNmZ8
         9k1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OPEfNMvD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id g5si427068wmi.3.2020.09.18.05.52.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 05:52:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id k18so5464350wmj.5
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 05:52:23 -0700 (PDT)
X-Received: by 2002:a7b:ce96:: with SMTP id q22mr14478150wmj.132.1600433543383;
        Fri, 18 Sep 2020 05:52:23 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id i16sm5028940wrq.73.2020.09.18.05.52.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 05:52:22 -0700 (PDT)
Date: Fri, 18 Sep 2020 14:52:16 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
Message-ID: <20200918125216.GD2384246@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OPEfNMvD;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

[ Sorry for the additional email on this patch; trying to consolidate
  comments now. ]

On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> Provide implementation of KASAN functions required for the hardware
> tag-based mode. Those include core functions for memory and pointer
> tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
> common KASAN code to support the new mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
> Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
> ---
>  arch/arm64/include/asm/memory.h   |  4 +-
>  arch/arm64/kernel/setup.c         |  1 -
>  include/linux/kasan.h             |  6 +--
>  include/linux/mm.h                |  2 +-
>  include/linux/page-flags-layout.h |  2 +-
>  mm/kasan/Makefile                 |  5 ++
>  mm/kasan/common.c                 | 14 +++---
>  mm/kasan/kasan.h                  | 17 +++++--
>  mm/kasan/report_tags_hw.c         | 47 +++++++++++++++++++
>  mm/kasan/report_tags_sw.c         |  2 +-
>  mm/kasan/shadow.c                 |  2 +-
>  mm/kasan/tags_hw.c                | 78 +++++++++++++++++++++++++++++++
>  mm/kasan/tags_sw.c                |  2 +-
>  13 files changed, 162 insertions(+), 20 deletions(-)
>  create mode 100644 mm/kasan/report_tags_hw.c
>  create mode 100644 mm/kasan/tags_hw.c
[...]
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 41c7f1105eaa..412a23d1546b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -118,7 +118,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
>   */
>  static inline unsigned int optimal_redzone(unsigned int object_size)
>  {
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
>  		return 0;
>  
>  	return
> @@ -183,14 +183,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>  					const void *object)
>  {
> -	return (void *)object + cache->kasan_info.alloc_meta_offset;
> +	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>  
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>  				      const void *object)
>  {
>  	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> -	return (void *)object + cache->kasan_info.free_meta_offset;
> +	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>  
>  void kasan_poison_slab(struct page *page)
> @@ -272,7 +272,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>  	alloc_info = get_alloc_info(cache, object);
>  	__memset(alloc_info, 0, sizeof(*alloc_info));

Suggested edit below (assuming the line-break wasn't intentional; this
should still be within checkpatch.pl's 100 col limit):
------
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
-			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object,
 				assign_tag(cache, object, true, false));
 
@@ -343,8 +342,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
-			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		tag = assign_tag(cache, object, false, keep_tag);
------

> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
> +			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>  		object = set_tag(object,
>  				assign_tag(cache, object, true, false));
>  
> @@ -342,10 +343,11 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	redzone_end = round_up((unsigned long)object + cache->object_size,
>  				KASAN_GRANULE_SIZE);
>  
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
> +			IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>  		tag = assign_tag(cache, object, false, keep_tag);
>  
> -	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> +	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
>  	kasan_unpoison_memory(set_tag(object, tag), size);
>  	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>  		KASAN_KMALLOC_REDZONE);
[...]
> diff --git a/mm/kasan/report_tags_hw.c b/mm/kasan/report_tags_hw.c
> new file mode 100644
> index 000000000000..c2f73c46279a
> --- /dev/null
> +++ b/mm/kasan/report_tags_hw.c
> @@ -0,0 +1,47 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains hardware tag-based KASAN specific error reporting code.
> + *
> + * Copyright (c) 2020 Google, Inc.
> + * Author: Andrey Konovalov <andreyknvl@google.com>
> + *
> + * This program is free software; you can redistribute it and/or modify
> + * it under the terms of the GNU General Public License version 2 as
> + * published by the Free Software Foundation.
> + *

I do not think we put the "This program is ..." preamble in new files
anymore. It should be covered by SPDX tag above.

> + */
> +
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
[...]
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 4888084ecdfc..ca69726adf8f 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -111,7 +111,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
>  
>  		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>  			*shadow = tag;
> -		else
> +		else /* CONFIG_KASAN_GENERIC */
>  			*shadow = size & KASAN_GRANULE_MASK;
>  	}
>  }
> diff --git a/mm/kasan/tags_hw.c b/mm/kasan/tags_hw.c
> new file mode 100644
> index 000000000000..c93d43379e39
> --- /dev/null
> +++ b/mm/kasan/tags_hw.c
> @@ -0,0 +1,78 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains core hardware tag-based KASAN code.
> + *
> + * Copyright (c) 2020 Google, Inc.
> + * Author: Andrey Konovalov <andreyknvl@google.com>
> + *
> + * This program is free software; you can redistribute it and/or modify
> + * it under the terms of the GNU General Public License version 2 as
> + * published by the Free Software Foundation.
> + *

I do not think we put the "This program is ..." preamble in new files
anymore. It should be covered by SPDX tag above.

> + */
> +
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +
> +#include "kasan.h"
> +
> +void kasan_init_tags(void)
> +{
> +	init_tags(KASAN_TAG_MAX);
> +}
> +
> +void *kasan_reset_tag(const void *addr)
> +{
> +	return reset_tag(addr);
> +}
> +

To help readability, would this edit be ok?
------
 void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
-	set_mem_tag_range(reset_tag(address),
-		round_up(size, KASAN_GRANULE_SIZE), value);
+	set_mem_tag_range(reset_tag(address), round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
 void kasan_unpoison_memory(const void *address, size_t size)
 {
-	set_mem_tag_range(reset_tag(address),
-		round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+	set_mem_tag_range(reset_tag(address), round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
------

> +void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +	set_mem_tag_range(reset_tag(address),
> +		round_up(size, KASAN_GRANULE_SIZE), value);
> +}
> +
> +void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +	set_mem_tag_range(reset_tag(address),
> +		round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +}
> +
> +u8 random_tag(void)
> +{
> +	return get_random_tag();
> +}
> +
> +bool check_invalid_free(void *addr)
> +{
> +	u8 ptr_tag = get_tag(addr);
> +	u8 mem_tag = get_mem_tag(addr);
> +


Why not just:
------
-	if (shadow_byte == KASAN_TAG_INVALID)
-		return true;
-	if (tag != KASAN_TAG_KERNEL && tag != shadow_byte)
-		return true;
-	return false;
+	return shadow_byte == KASAN_TAG_INVALID ||
+	       (tag != KASAN_TAG_KERNEL && tag != shadow_byte);
 }
------

> +	if (mem_tag == KASAN_TAG_INVALID)
> +		return true;
> +	if (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag)
> +		return true;
> +	return false;
> +}
> +

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918125216.GD2384246%40elver.google.com.
