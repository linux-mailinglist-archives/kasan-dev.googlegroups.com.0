Return-Path: <kasan-dev+bncBDM4BTMC5MIBBAWRUKZQMGQEDJODJVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C212904515
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 21:41:56 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4405b0b5720sf34027591cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 12:41:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718134915; cv=pass;
        d=google.com; s=arc-20160816;
        b=g06EH4y38PnsPRa+DnskZUWwhKihNEpCA0DziKgZXO5nYUmP2BOu8kyL2eC0HZGxkc
         y+Z1dxfcG2cC8DC42tLVO+Ol0nObMUQtSXl7gXl+wX2R2kGoAFa/Bk58c2G8zwko/UpT
         4MKCYcaVqbs3hp21WEqY3bUUyFJGR/BqSFa0Vxi6xITBncXa8QPBwKaQEHk+zr68q7Oc
         rDX0UV0zfTSe72U71yOqzc7EFFCUA33qdi+x80ly1eJbeaMuku5+i5Haw4GP96CjMICt
         UngvmzuaLbiJiWyWNZZcl8J09GbgYMs+MqN9SuIm/O0ofPPB+F8KKnLtREfhZ2zGD0U5
         Si+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=ZGy39l7cRNCfd2pA9aBhdQEP9PR/ruxidtCkJSACzzU=;
        fh=kCtp4ntH9r9Y3lvTkqI3MFvfVZ/LurzzpEqY6Z5OTPc=;
        b=jvh/gwnUbliryDRkNA8VfboAIgJhN9V7uHcYXK+QX2lwKNxwHh7btrXDvKnWKXFXyF
         zDf0LaYIHRIRB0E1ui8D+TIFbgpoYpmNkWb98ov3tpF3CT0yTvl/NmmOHwrsh9Sf/fki
         ZjxyCUw7NWWkw/lvUp2QoC2n9LV/zFJf3r6Uv+Y09HN43NJBkLlyboapqWnUXrYMu92C
         PduLe9u4/dAJbq3QaMeY3SNUzI9yMGoQdl2DoBaAkcDr2GKch7l+3bTqzXqZRM+zCbfY
         0chkUgkqLg7E0LYoblxL8eu3QI+gJYQE3Sq43VxDVsEzSY2mJMNdK+t84MvYQt0G/Mct
         uILw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=AO+gqqlC;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=tim.c.chen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718134915; x=1718739715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZGy39l7cRNCfd2pA9aBhdQEP9PR/ruxidtCkJSACzzU=;
        b=pSFP6Sj92ySLpOUZvekcJgx65t0fv0LPr4IVZ8cEfjDGW0BcrIjG7eImqkGjeb8aA4
         yza1jFDBANyW13bp5YgY58mFLr9bWmC9hFEkDxDdfcG9nFpsaxdrU796Hx2k6D8wo8Yo
         fDVUP3kZWk6iLkOQZYxUddkSwQYcjdOAo/Ry4HH2DgZPHzpV2WABE8BDqHgisiHXC35U
         9HzzqaAx8Wb/A2CVB03AiqSwK1JzYeTm3Ihobjd+YBv/Gj03HZAYCZFaEnRGdd5VgrBr
         Hif/dfZsVZ1c9SJswdS6FRjTnGdHzHN2hUIhGTjZypkleRqYNeZ+ux4/ILU/rRJt4xDi
         7JKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718134915; x=1718739715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ZGy39l7cRNCfd2pA9aBhdQEP9PR/ruxidtCkJSACzzU=;
        b=i/7BJJ6Dw/zFPNGBxlFS8mTcgbhx8+Gx3fnoLMO94owg+0jC7u+J8s/l1IPXkjdJ/S
         Sp2ggMapVp+dCAx140pMXB0tBfxLcUaAfvqiGPNYLFS+HPVIAibokeZ+RMhTq0nmmFgb
         M2xbb3WdasODf/byBH4174Fmyt0tCzwC0dxIjBnbnUPCo6nF7p4V4RsaIvgJpvgu87Cp
         dGldrojjnRl+Lk4am1NLF0qxHhIfaLX+T+sXDg+zhNnKPZkbyvYOYqeXPa7uWbTt099g
         y4KA7UKJjnsq1XF3yt5DtRNyWxXPSRJvWygHMH6YbonL+FjtNwOeY4CfU6yucRt6bBMy
         92Vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcNYFmmdelOuTap77dVdnAIUmwt5/a5RzClv3E726fdhw7iMUBTpdaryDJbRfypa94F7LIYOhNbtHEaWZ5YFduvm/yIMq80g==
X-Gm-Message-State: AOJu0YwChwoQFRQf8CLtfjK+oAmSDmaA+JqeyyuoC3cbvT6EEHrC0maW
	QwoEs8NHPEsmIZ+oY8erpjNrQXy3fOdlMN30cGpwDuJB0L5gQvRU
X-Google-Smtp-Source: AGHT+IGvvSz4X7/hE2zHrghQ5kAiEo3oqr1Co9e6sYL6LGIHDNfazckvMsPb8O8/2O4H7jyXrN93fw==
X-Received: by 2002:a05:622a:3d0:b0:43a:b9c9:a25c with SMTP id d75a77b69052e-44041c7a712mr155115331cf.38.1718134914684;
        Tue, 11 Jun 2024 12:41:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5fcd:0:b0:440:29:dfd9 with SMTP id d75a77b69052e-44064cb427als37093681cf.2.-pod-prod-03-us;
 Tue, 11 Jun 2024 12:41:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiNZQayj8JiiFXLx+BiQuB2mcsMY7DXkRqGSLgVc/Gtc0Ql0QkN9CgFkq/GtQzw3EDCYJaiRI2AVMWnFl9lbu+z35YmTEUIQ9c9w==
X-Received: by 2002:a05:6122:d0b:b0:4d4:21cc:5f4f with SMTP id 71dfb90a1353d-4eb562bbb45mr12500895e0c.11.1718134913986;
        Tue, 11 Jun 2024 12:41:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718134913; cv=none;
        d=google.com; s=arc-20160816;
        b=icb8nEMcX1CSHG/cIRuon2TKUBwh4U1rYtcNlMYQBZCx0LROw5cX8zOY7itv5LbrZB
         9X+7BTEiQmWAeTlvh8FM+y+IeZE0wm3OkUIVhbTclUnZJfbHVdjFxpQqx9SMSzvT/m5p
         u1P2L6IlRP6ufOCLHWfWQxCPmYsVR/NQqGKfcgNmlh+CwYcvUXHp+SHubA2I4UskdAuT
         35gppVy4tk6R8/wTX5eHvzsA+PsjU3bh2Qr3VI7PL31SBRbg6DFH/kuZnh8YyMOIJe/h
         AFHpS5g3cCsAlTIBlGsVh+LyYyuP4jJF2dbm/Azhp4tRgj1Y82xHubXr9++SvbmEaykW
         3oWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=MhkW2O8X5I+Ga1WlB/SZjoU4nb26bE0rceGQZam5faY=;
        fh=pud1nSMiiNwPuzTdKUg/TJhyPj5oVb1eGI3KVuLQEl0=;
        b=BObnnMAAvu0UNGGkKzwYC4FMjgEJgBp65PSG24t7S3MWgR+ZxwllU7D/JMCgpbjUu4
         EZNfGx2TMIz51BlSLAp5aUWlBXlTQNOB/Fur+vYefdf0oaFc5C/d4LpjliowZsIbzD00
         HMV6iNP1K9okA8Jtg356o5/eEzp0nMJAdZZ1DbZLvorCz9R+6wJTCfYxtSJnPDHloIu8
         sQs4aZopYT0UlgNkCCmW/KCWhqjcvoYO4gCMqqWsSEvoNvYsBl3YYKLJscB88mhcQkIS
         pJ3C7R6oWpY//mlUlEDWuYFj3xEUWATlAikpw7Ez6WOXMuzeLgDgifms+OQA5cOyt9Td
         JqlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=AO+gqqlC;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=tim.c.chen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4eb5e6a5c48si272466e0c.1.2024.06.11.12.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 11 Jun 2024 12:41:53 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: uEcIxYPuRHyKd0xZ72ZMow==
X-CSE-MsgGUID: UnyXojMTRVipRjyofAp8tQ==
X-IronPort-AV: E=McAfee;i="6600,9927,11100"; a="14826590"
X-IronPort-AV: E=Sophos;i="6.08,231,1712646000"; 
   d="scan'208";a="14826590"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2024 12:41:53 -0700
X-CSE-ConnectionGUID: RmVZgz1VRteabv7gZ38CIw==
X-CSE-MsgGUID: YWjwba72SB6sl89EETJtkw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,231,1712646000"; 
   d="scan'208";a="39643390"
Received: from mmasroor-mobl.amr.corp.intel.com (HELO [10.255.231.206]) ([10.255.231.206])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2024 12:41:52 -0700
Message-ID: <80532f73e52e2c21fdc9aac7bce24aefb76d11b0.camel@linux.intel.com>
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
From: Tim Chen <tim.c.chen@linux.intel.com>
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org, linux-hyperv@vger.kernel.org, 
 virtualization@lists.linux.dev, xen-devel@lists.xenproject.org, 
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>, Mike
 Rapoport <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>, "K. Y.
 Srinivasan" <kys@microsoft.com>,  Haiyang Zhang <haiyangz@microsoft.com>,
 Wei Liu <wei.liu@kernel.org>, Dexuan Cui <decui@microsoft.com>,  "Michael
 S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, Xuan Zhuo
 <xuanzhuo@linux.alibaba.com>, Eugenio =?ISO-8859-1?Q?P=E9rez?=
 <eperezma@redhat.com>, Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>, Oleksandr Tyshchenko
 <oleksandr_tyshchenko@epam.com>,  Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Date: Tue, 11 Jun 2024 12:41:51 -0700
In-Reply-To: <20240607090939.89524-2-david@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
	 <20240607090939.89524-2-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.4 (3.44.4-3.fc36)
MIME-Version: 1.0
X-Original-Sender: tim.c.chen@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=AO+gqqlC;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=tim.c.chen@linux.intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

On Fri, 2024-06-07 at 11:09 +0200, David Hildenbrand wrote:
> In preparation for further changes, let's teach __free_pages_core()
> about the differences of memory hotplug handling.
> 
> Move the memory hotplug specific handling from generic_online_page() to
> __free_pages_core(), use adjust_managed_page_count() on the memory
> hotplug path, and spell out why memory freed via memblock
> cannot currently use adjust_managed_page_count().
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/internal.h       |  3 ++-
>  mm/kmsan/init.c     |  2 +-
>  mm/memory_hotplug.c |  9 +--------
>  mm/mm_init.c        |  4 ++--
>  mm/page_alloc.c     | 17 +++++++++++++++--
>  5 files changed, 21 insertions(+), 14 deletions(-)
> 
> diff --git a/mm/internal.h b/mm/internal.h
> index 12e95fdf61e90..3fdee779205ab 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -604,7 +604,8 @@ extern void __putback_isolated_page(struct page *page, unsigned int order,
>  				    int mt);
>  extern void memblock_free_pages(struct page *page, unsigned long pfn,
>  					unsigned int order);
> -extern void __free_pages_core(struct page *page, unsigned int order);
> +extern void __free_pages_core(struct page *page, unsigned int order,
> +		enum meminit_context);

Shouldn't the above be 
		enum meminit_context context);
>  
>  /*
>   * This will have no effect, other than possibly generating a warning, if the

Thanks.

Tim

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/80532f73e52e2c21fdc9aac7bce24aefb76d11b0.camel%40linux.intel.com.
