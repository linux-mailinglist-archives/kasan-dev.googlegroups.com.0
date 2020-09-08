Return-Path: <kasan-dev+bncBD22BAF5REGBBJOK335AKGQESCUSBEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF1852613A3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:37:10 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 78sf7919278pgf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:37:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599579429; cv=pass;
        d=google.com; s=arc-20160816;
        b=wejuE/tDnXh5dt9BzeMHjPoJNjjkzOqj8+hQ6lcq2fjAQ45H5nXdUymdxXJvJIkUL6
         28n/4pLdJlpIOIzxOc76K9F7N1t3C0uttMhUYITVEK4OTAjBtVidX7c+LTB0zeLA/yEg
         65fGjPq38ZkB9v4rO/c0Ty21sorrqRtHG7sCPPumICJQbipViWvNSDFXIbHQS9S97VJF
         yd2wJ9DiZG2Sv4NT/W9Z0cex5Pi2m4Hu6O091e0eWOvz7HUQXJkUW8xgkpN9fOgsXiCB
         BDicmE5ehIAeRuKcn+VjZfk9bYuSUi4OAxpPLHVWtCHrBiKrBlZ1BLWR85m8rstEE7jd
         6Tkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=B2YMzT6sqlPsAgpw/5lwXCN6dIHutwIneZgRuD0nlRM=;
        b=psm7D+yzGFx1YK4yphJuw29yyoahGdRbfxfgmV9KmbHzymLQ0vpYLVgBKNf0Wlt/4V
         mry13o3+M/pahhrTOc/wfPpAdGy0ApJQZGRidpg0+EBUCdxAIKSPND7v6CJC+zzPKhzY
         /6dBklPD+NoscLF0Gc/i+1iqEmmwn64JEzG6E1mvLKgq0minOI+2j1sAf3FheQi5Qo5S
         hPQx0Aoy7v0EJx8Wn02oCTg0E1gOiuYWRNLUGgSbey5G2IZsX9HF4/e4ILdgW8zjVky3
         USvYRl5ZYv75hIvL1p4M82rXAVhpqXcP7NnFT+BjEl0lnnDg3iht4B1srI9lspIPGzfy
         b+Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B2YMzT6sqlPsAgpw/5lwXCN6dIHutwIneZgRuD0nlRM=;
        b=i1iPhzC8ZyMPkz4ez3zE2aV4TO8rSorZxKHoaqGrqGC8iSsVMuGHW8Wq67y7/13y8A
         nx7U8Z9dhOvQCHz7cQ0NwxyOJDlY4EhLEU/aw3bLUL0nelsOb8yWhXB5/tbXvVHy2mSE
         ncy4WJ7G6Iy1BCcp+49xBct/HZAh8F6BqvCWzam1K2OIsV1byFz1Da/qfO7Z9ZzPOqN1
         kOqTd5SUnHL5lnzzAcTbOqh1l5NpI6gEp1SLw0TngNTXPbHuq4kZLwIBh55MzENvOFab
         c9roSGjbG0pXbPbe2LjNFCIdBi//w3hosjYVVrN5Q3iZmW0pzVpsgQbgy3OIUwUaCAG/
         ox1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B2YMzT6sqlPsAgpw/5lwXCN6dIHutwIneZgRuD0nlRM=;
        b=EOL7VlGrYg+Z7sGgre6fuJvL9WO0ckfFPxOZF8zfVbXWQGNv1R9CCBKbrATJfOXAUC
         M3qsSQMI5UnE2i8fQ7NZ+2nkCNs4OH1oORCAv0kAsoEjZMiSfK7+FB3cXLiqZdhbUikn
         dq5wZXxD8mI5h6OsG/X7xWA60oxfMdaA/ugb/+yb5h3/mI/fye+AacBOjYwFN2lAYbQ+
         /18mZoONQTIbxnbxcOyntNFu1uETG9wYL50dp/CCKrYRX1UJcRmIw4cGzZp3y0y1QZSp
         c2MWeI30fIQ4sFigerBEarQGg8Tz45X4rqY3DsQFPIJ6iogTXPxdUHabLlSre8FmummO
         1e0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YNaoLhNqGoCGWXXXogmpaiOn97XSpcuVe6ih0sIfdcf/P/NFW
	iIXIBoP9DjPGIzG4GAoa5AI=
X-Google-Smtp-Source: ABdhPJzEtu8poz2cL32MHNHHQorh2+eoIaXsVCpwpOsWyVEgLbvozJw8593TLRdezIPhmGbXzIJIcw==
X-Received: by 2002:a17:902:6941:b029:d0:cbe1:e76b with SMTP id k1-20020a1709026941b02900d0cbe1e76bmr1761880plt.18.1599579429586;
        Tue, 08 Sep 2020 08:37:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2154:: with SMTP id kt20ls1430758pjb.1.gmail; Tue,
 08 Sep 2020 08:37:09 -0700 (PDT)
X-Received: by 2002:a17:902:bd81:: with SMTP id q1mr24212034pls.70.1599579429082;
        Tue, 08 Sep 2020 08:37:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599579429; cv=none;
        d=google.com; s=arc-20160816;
        b=bvKUbFd5UhRPL9Ei44eFoMli5oxQEIo6B6ZbfCIEncIt0B+TPbWuq57J+mr/VyiakS
         MVRUjE0F8IBmKwIqqUZTVjUsvG53oIFnNG4oJsKg8syvpqtqpDW7IbqTI5/Rj35AbqLG
         LojIykgE3mBaYh4PDhn/mluhnfgNlAxHQKA1dEnn5xD3AEYat80Z4LnfDBrDfq2og/17
         /EkiLis/dSpnbAvtsLZY0xMLSIBy6zAdD2O3HkchaPyXeIulZv58P+mhoyh14XWb5RHt
         nbN5J0OC5h7mk4iq1SzlYAAh9MwXP+aeNGzxT1qjYtpuJO82K7gsVSiQJLDWl/8/Hej2
         jnhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=OuTCrkXRwFQzgG012Lx2kHulmSfYN+I2E0+2ZxzK8CM=;
        b=cqLHZFOQ6lKpYdLMPG1b7PUeQvQhWAuGh3zdvLPPDmPdMbrQGl/9BBDtFvwbCEPC89
         70CDo2iqg+B75uxE9XL+Mvbs/tlYITPR9730HDIsjREbgS6raqTrtmat4ladbhtuoVj7
         9Rqu1NyoGHFpjWKreofPsVuUJ/dLtfr69alsamGuImH7WPt48Sc/aTXWCEGip2/Cb1e3
         dKCvX4EROmfhKxeJH84CdXHMmmAf6zqtcJrJuQbSPIHZu8hnqW/eSBGMJIwm+FDnYQkR
         3yF2Nv/R9ynrY6X92JlY2SV9SLgFOOyPhlIcQjEzTE9h57iepByDuVe3rJObM3/MVkdB
         ZUSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id o185si1223294pfg.4.2020.09.08.08.37.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:37:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
IronPort-SDR: vHD4JMp4LVMMNJW/RWoUQ1M/Wmfrgsl8v0GjEuflU3ji9Ih8XvixMmtSc3wnEZE/s5+iLgBrtg
 YG2/1/tBhD5w==
X-IronPort-AV: E=McAfee;i="6000,8403,9738"; a="155559004"
X-IronPort-AV: E=Sophos;i="5.76,406,1592895600"; 
   d="scan'208";a="155559004"
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2020 08:37:08 -0700
IronPort-SDR: tEuD/aiTH64kMPCpNHzoq4kb76tMsuT7l1VLEn+gTQdqcJxwA5+08u0Li5KDx327AAB9cRCVx7
 u6eyuINTvZEA==
X-IronPort-AV: E=Sophos;i="5.76,406,1592895600"; 
   d="scan'208";a="505113686"
Received: from sparasa-mobl1.amr.corp.intel.com (HELO [10.251.10.231]) ([10.251.10.231])
  by fmsmga005-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2020 08:37:07 -0700
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>
Cc: glider@google.com, akpm@linux-foundation.org, catalin.marinas@arm.com,
 cl@linux.com, rientjes@google.com, iamjoonsoo.kim@lge.com,
 mark.rutland@arm.com, penberg@kernel.org, hpa@zytor.com, paulmck@kernel.org,
 andreyknvl@google.com, aryabinin@virtuozzo.com, luto@kernel.org,
 bp@alien8.de, dave.hansen@linux.intel.com, dvyukov@google.com,
 edumazet@google.com, gregkh@linuxfoundation.org, mingo@redhat.com,
 jannh@google.com, corbet@lwn.net, keescook@chromium.org,
 peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, will@kernel.org,
 x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
References: <20200907134055.2878499-1-elver@google.com>
 <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com>
From: Dave Hansen <dave.hansen@intel.com>
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
 z5cecg==
Message-ID: <64b65b4b-639c-ea99-182c-5091c5fa1938@intel.com>
Date: Tue, 8 Sep 2020 08:37:06 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200908153102.GB61807@elver.google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 9/8/20 8:31 AM, Marco Elver wrote:
...
> If you can afford to use KASAN, continue using KASAN. Usually this only
> applies to test environments. If you have kernels for production use,
> and cannot enable KASAN for the obvious cost reasons, you could consider
> KFENCE.

That's a really nice, succinct way to put it.  You might even want to
consider putting this in the Kconfig help text.


>>> KFENCE objects each reside on a dedicated page, at either the left or
>>> right page boundaries. The pages to the left and right of the object
>>> page are "guard pages", whose attributes are changed to a protected
>>> state, and cause page faults on any attempted access to them. Such page
>>> faults are then intercepted by KFENCE, which handles the fault
>>> gracefully by reporting a memory access error.
>>
>> How much memory overhead does this end up having?  I know it depends on
>> the object size and so forth.  But, could you give some real-world
>> examples of memory consumption?  Also, what's the worst case?  Say I
>> have a ton of worst-case-sized (32b) slab objects.  Will I notice?
> 
> KFENCE objects are limited (default 255). If we exhaust KFENCE's memory
> pool, no more KFENCE allocations will occur.
> Documentation/dev-tools/kfence.rst gives a formula to calculate the
> KFENCE pool size:
> 
> 	The total memory dedicated to the KFENCE memory pool can be computed as::
> 
> 	    ( #objects + 1 ) * 2 * PAGE_SIZE
> 
> 	Using the default config, and assuming a page size of 4 KiB, results in
> 	dedicating 2 MiB to the KFENCE memory pool.
> 
> Does that clarify this point? Or anything else that could help clarify
> this?

That clears it up, thanks!

I would suggest adding a tiny nugget about this in the cover letter,
just saying that the worst-case memory consumption on x86 is ~2M.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/64b65b4b-639c-ea99-182c-5091c5fa1938%40intel.com.
