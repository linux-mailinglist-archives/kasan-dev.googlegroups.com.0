Return-Path: <kasan-dev+bncBCKLZ4GJSELRBS6E22XAMGQEKIRG6AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E3FA485D0F2
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:12:12 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-410d0660929sf30882415e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:12:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708499532; cv=pass;
        d=google.com; s=arc-20160816;
        b=MAhb4pOU7e2hRAKlvaM9YXvsMi6nOvtnnom3Od7Bn0g6YuRLfUDdUbMKM57bbsFmaa
         emfuW2HuNj8tHwRREBLjrL+s9pktF6iS4iOzWOmYuo0oDltQ1U/Q2BvyG7EwsSSx0J3B
         FteNJnXaOFfQqskcqDnCQWZASiilyzhwSpmwNJw3Cwl9CW4qAB3ztFJlXRghMzmnBkwV
         eXW2byAlZjydH3glZt58+VNo+8RxXJXoyDtPAotDDrz6lvYB5UpmBe9039RaCQFK+v6w
         GzlfdLUD4MeeYU1TdMJbiUx9NVBxt4/J7XSbWGTnshrbGEvvLliznVtpI+ofTK+AaKmD
         yuHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=u6aI/VSDqpmlWz0U/WdyfF9+Wvv6HDyU6CCyuRTZdoE=;
        fh=lbjpZ2wnEQh4TsR9u1xr5WkDihr45wenaZbp/NlsET8=;
        b=YmVlDhyKVZsodAVhu7iEBwPcPqfFfiw/Kti1zv+N597ICTdnYlhQS03g+Zl59k0ClS
         u6OrsyB2PwUaP+5Ycs0gevEkV6upD94y1Qy/hYb85aufnEz0HCNmcDrNEVBV3hNvIIXx
         26vifGubfZRky2uMb7iLT9o1VnM+WVPqVY48UFgzvnSq8fLust2e6shACY93f7ORMPOd
         I8MJU+xd4qW754QWy3vgBIL2ThnbhXzt9StUG2hFBkRUGrE5Ns4TPQHTsev/MO+6Xpsl
         7JA1qsgTORA5Y5GzmaZ9tVl8u+HEdBVNRj/3xiNcwOW81clBZoE1uua8NkPEPT9Cryo5
         dlmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Con9hWh/";
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708499532; x=1709104332; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=u6aI/VSDqpmlWz0U/WdyfF9+Wvv6HDyU6CCyuRTZdoE=;
        b=lQSLPCCeqFu+ROoGFIOTNjbSC7CbVloLY+zLgRTRU+G3Ir2UbVlaTERTZACmbeHTdv
         ubZP/tXUSMGcg+wGxw9BRJ6mI9xHZy/fezvPrWe7ZC9W2T+km8cbQqbwy91z7IJEyDuY
         czM9M7i5jslA9YZdhSIffqLk9xCfZjAoxwIvDzz4IIo9EymOlaZKZswp9Tv8OvmKYPky
         rpQfeO19vQUtAgeso/L5q45eHNcns3jKy/Qp5ppCKTMkoqgGmIgKT+DBL+ThMqnLedSu
         qCOvPVE8k6Z9UuMCjJFDsy+ekKKnWwMcJ3w/S5MnPVMwKrDDlb19e2PfO8lpm2iT5eTB
         PWbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708499532; x=1709104332;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=u6aI/VSDqpmlWz0U/WdyfF9+Wvv6HDyU6CCyuRTZdoE=;
        b=MzPAF3NymPEKxMP55wboInX0HkkVSJ56pzSOdzVt5namQ6A8qUnGMvGr3tHIgy1rN+
         uxQc6B7O2B+JIxVShpcIi8aXzFsfkb1z8lVnJQl6B5jmU8rSYWw1TObuMb/w7rQX2itS
         FjQc5gG3QaFmCFm91Z34KKOJJtL21/2kTJPRrZTXeK4Wh8CH3zwrznpLq+mBO2cHHv4Y
         E1KqiGbwVwovmkA8K+jSlTY2Qu7o+2FNzpUlejWXNYWc6i1/a6c52c8p+KyQeL4B3eHP
         x0cduvNCAOxxzUzfOQxMogMYJMQFSKDxdwuNKneKszLI4uGbAPqr8bXHr8n9O4IjmCZR
         FJ0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXM4cWVbpXROm0ECG1TJvPcj/blE9mb46PTrDRqH8uUuqjnFvyz0WyjbpKsH2mDP+AAcyZ+Hj3gOj1Mr5hrkz9874NgVQavsQ==
X-Gm-Message-State: AOJu0YyfZPgADXioN9EEK/nZI7qx7ykFlOZe6DQCkd9o4kCE2ShWnqnn
	oIQA3SG6xIvcth55H8fOQkz5eSZ5M2hXBYqvqqG1rVVAxwtXYuHg
X-Google-Smtp-Source: AGHT+IHCvDWpZbMf8oKTMN76iXNbb0sIKAo8UVm3m0uP7tgiCPEZkatgWOWXPKXhcr0h7RW1HWiNIg==
X-Received: by 2002:a05:600c:3b26:b0:412:5a8f:3dd7 with SMTP id m38-20020a05600c3b2600b004125a8f3dd7mr10004713wms.5.1708499531667;
        Tue, 20 Feb 2024 23:12:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e23:b0:412:7878:6231 with SMTP id
 ay35-20020a05600c1e2300b0041278786231ls14972wmb.0.-pod-prod-00-eu; Tue, 20
 Feb 2024 23:12:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX8spXZhRpMFAe5lGzOhG9j22BCLnXa23gAxMW7uvoQzGRIEe1tvhYbM0emRny3Qax2WqhCnW8t1S5SrRlM0UmgWyDi19zKj0tBnA==
X-Received: by 2002:adf:e409:0:b0:33d:31ec:e097 with SMTP id g9-20020adfe409000000b0033d31ece097mr10498891wrm.17.1708499529613;
        Tue, 20 Feb 2024 23:12:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708499529; cv=none;
        d=google.com; s=arc-20160816;
        b=UibthsATQTZUd+OUBoPHK2L5wZtdfhtUfIKwKrZHE7zVrTeNGSpQ97LfO8xvuPNr9a
         XwBaSZ6KGJxjpThPktwHlNEKOtoiRf18AkvagtXopO/izxUYMqh+jYFZr2DvTUP1uU5h
         lqygMA31sD1iH//JtIr/DItXfIxM3Gtb8bkKXQUHrmoOYeC+GTNzvzhUUF1DmOFeZIxu
         bBFe0l4x/WJ3Iar9e6agX1UZU9/fygoYnSxKFrPJWbhlnvxJD0PY7vG7L7Zh9UG3B602
         rT/bvk9os2Kd2D9sIKpX0/y8PKCWzQAG2QD9nNKmJ7lJ6inqvw7wWApvTT3La8h5eClz
         qCxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=WSnP/0YdPJWcrqeadRLJ8c8YxbEnoLRUfscJ82NzOdg=;
        fh=4jlCtkhVU5L6grSyLZC2NUWCYKYWf3GrqY8EQOa4vcc=;
        b=rMaZhM3BzgkHGVr6rO1ibLfKcDvjIcMXfQKhIu+WzT9MO86tEDrld5w2vfPIrSak6P
         3MYjPMOn75UMl8EVRUT+JiIlo43xpyr+iyi/kti7hHxVZE8RZzYLB4gMLtCvvJ29/FRh
         uNnLWMu0OlXKhMlixRKpIouysvliYtXcGouzBsggJllU5rgBjb4599VPerT726RRi3mv
         Sx2+OR8/Xlv8jDE+2yuC437Y1jtzR8Ob28mZUkSTdcCTGLT+A7FIXunJnAqlP/PYVsMA
         qCcE4SOqhpqpIKnR+Br//fG8UX3OO2qnloOtOD0jYDVeZLSG872ppwDsI9s4kaDgvJDu
         nqYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Con9hWh/";
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [2001:41d0:1004:224b::b9])
        by gmr-mx.google.com with ESMTPS id m40-20020a05600c3b2800b00412684b960csi19460wms.1.2024.02.20.23.12.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 23:12:09 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) client-ip=2001:41d0:1004:224b::b9;
Message-ID: <f75362d9-eea1-443e-8997-45a7b98b7915@linux.dev>
Date: Wed, 21 Feb 2024 15:11:33 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>,
 Xiongwei Song <xiongwei.song@windriver.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 Steven Rostedt <rostedt@goodmis.org>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Con9hWh/";       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates
 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2024/2/21 00:58, Vlastimil Babka wrote:
> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
> removed.  SLUB instead relies on the page allocator's NUMA policies.
> Change the flag's value to 0 to free up the value it had, and mark it
> for full removal once all users are gone.
> 
> Reported-by: Steven Rostedt <rostedt@goodmis.org>
> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>

Thanks!

> ---
>  include/linux/slab.h | 5 +++--
>  mm/slab.h            | 1 -
>  2 files changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index b5f5ee8308d0..6252f44115c2 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -96,8 +96,6 @@
>   */
>  /* Defer freeing slabs to RCU */
>  #define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
> -/* Spread some memory over cpuset */
> -#define SLAB_MEM_SPREAD		((slab_flags_t __force)0x00100000U)
>  /* Trace allocations and frees */
>  #define SLAB_TRACE		((slab_flags_t __force)0x00200000U)
>  
> @@ -164,6 +162,9 @@
>  #endif
>  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
>  
> +/* Obsolete unused flag, to be removed */
> +#define SLAB_MEM_SPREAD		0
> +
>  /*
>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
>   *
> diff --git a/mm/slab.h b/mm/slab.h
> index 54deeb0428c6..f4534eefb35d 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -469,7 +469,6 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
>  			      SLAB_STORE_USER | \
>  			      SLAB_TRACE | \
>  			      SLAB_CONSISTENCY_CHECKS | \
> -			      SLAB_MEM_SPREAD | \
>  			      SLAB_NOLEAKTRACE | \
>  			      SLAB_RECLAIM_ACCOUNT | \
>  			      SLAB_TEMPORARY | \
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f75362d9-eea1-443e-8997-45a7b98b7915%40linux.dev.
