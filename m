Return-Path: <kasan-dev+bncBC5ZR244WYFRBPXZQGFAMGQEHW4FNQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8772A40ABEC
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 12:43:10 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 75-20020a1c004e000000b00307b9b32cc9sf1021095wma.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 03:43:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631616190; cv=pass;
        d=google.com; s=arc-20160816;
        b=cR+vG3TdDJ6ORZgxBnhqgUVsJY0OyS7ccGbmU8+tKt8TflbSAg4quW5CM7gs5KZ+g3
         3ILl0s8VqiVbD4v0+pIfOnCEDzjWJVmXg/WBxZEcTjUxOYd0/izMQDfhA72RblpZ3BYa
         hAq6T0GLyr02ESqI1MZOInt9OJAI8ytWU+SUDUHfBrfe6/rFHLg9i6ueeveXtR7Zh/07
         p9rmeDlDCLHYnvzGxPCY8aAVCAOZLunSXSSd1iJkOw1aP1EWNuGSIM1MKQGZlRVbkkKh
         Q/mu7fsPMkD0VzGkHYjItfN5y7Cx3AfxvgiC7gxe6WQER0AsB0w3wR7/4W6eXEXWJVRl
         Sq3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Kld8I6tb5yrQcD4DMWW1NFutIaxCrowwiamG4kbd9Vc=;
        b=awxeiTF8trHp8fkvJZR3MPeT4gpDBI3gLuDr2F7OB/RS2+nsW4gySwzCFxiRHElJX+
         yKUgeb3RiMxNAeh0TgBEkc3Qx5UdE6XHuYGQBu46sdMdx+DmHaU98ziUUWpe3xE0QGkT
         LVJJaCgfka6CN56lR1VczeDMKOB0Izis6lL9e3E2jLBiwdo1TMeWWk5amPvaR11Har7+
         eljdFO9hAI0jH9E/t1TXU6ivL+d0faUmiMFcsRco46Kr+te1JrvGK3O5M8CA5v048RSj
         d2QBmpOfvxdxi4F4ZxoisYfLn+XNsZtYiQvz6SyX3Wv5fjsnoTTZD6juNwbfKcAXyDeL
         SBQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of kirill.shutemov@linux.intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kld8I6tb5yrQcD4DMWW1NFutIaxCrowwiamG4kbd9Vc=;
        b=DfvGQYLNAAD/Xsp1PCi3Dsdh2p36HqjBe1E/RD4taEbRDMFtuSgjXeX0WOhhtDPFrD
         o0WjIajf66c+3QolKuiLHar7G4pyJVDUyep5+Trl+KLrX4Pb+ccjmmShTx0Cg1LPU+Fd
         rCf/FOVw2hbWKDxX44JyeJFfJiKhiXodybsYLjfZN8qSSEyzjgagMbJaObGVZN5Ojrvh
         w/VTK9R9tNOXTpYmTWRa/+bXC6gtGyqfxIX2qFj9pkLP61ZIpcyocwfxIdlzsZdD9aLt
         XBbjOcOYEAVUb0bfLnKC8BGb+SkcgmDCq1TdRb/tjZjxSP8Bk8hdvuzHQRrdRJ6KyF6l
         wLMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kld8I6tb5yrQcD4DMWW1NFutIaxCrowwiamG4kbd9Vc=;
        b=FPI5OdiMAv1DnIeNaAvz4Wje0PmE3oaPlSEvKR8erSiZJnx++w6SDb9/KtuC8kOFbi
         /PCMdR1n7WSuHGqCk6iBn7MW2g7EdT/8u5zt2W5LD1urrZFY+kfN/ubAuOsmjIuh7xwm
         CltQid0KJ/r3CFZC//KQk3tCOYlrud0OLqx6p93tVv7pQuSDhAFycY59g+JA0vSjLBFY
         HgS5zQR1gidTD5y3aKyyuI9+EaxIOC1G/EN4CdVa4pLlygfIif6kC+EopKc6KGqUhsw9
         cEj4AtfkFri3gghZJ6nQByIFrr+YL7E1zfxDqT7tf6MnwFi3l0cWJPumJUyK2s3T5g8f
         1Amg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323HKF9gpqsJ1UIVrM29/5werbp+Yx0+Gbl637YTs78o2AcAAJL
	3tkCp5g2GA8sYIzLVq9x7os=
X-Google-Smtp-Source: ABdhPJw7buvdRPkCkrD4GBOCoLl3+DPX2eeNw6OVomT409byiWm2DZqSHOZPUGxFmG/cKavi0N9xbA==
X-Received: by 2002:adf:fd12:: with SMTP id e18mr14046062wrr.275.1631616190254;
        Tue, 14 Sep 2021 03:43:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c3:: with SMTP id g3ls524672wmk.0.gmail; Tue, 14 Sep
 2021 03:43:09 -0700 (PDT)
X-Received: by 2002:a1c:acc8:: with SMTP id v191mr1388956wme.146.1631616189405;
        Tue, 14 Sep 2021 03:43:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631616189; cv=none;
        d=google.com; s=arc-20160816;
        b=CpQN3UfG5g9KVhHRqOJiLuAjS5znFCPssqbl7iiOAlgBvDr5et7d7KfLnWpMxp+wHh
         HyZmcEdM8UUcVSXx4sV/6CeeKsS4OH611sZem5nZ0dxGlIqzvljB36yOLE0xLgU8n3vt
         MEuxBW2wtXKMdzJ0Wsywo9yIqAiLq7XzUqzAkJ2F8syu2wO4bSBJT6HfT6SUqtwaee1i
         V8KSGeNRKzZzI+ps2HU8VZoyp27G3yFegd7ooqaK0vZ2VEvndRhCNby/iajp/a2pDDKn
         23d5sKWuNJ0oya1JzLqvU0k6k1XWKB5ZH6tAB10SJYxaaIdaiwd6xxHFuxGcT5yMbUZ/
         tmuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=lsP6wBXTAi/IM6ObGafgPcs4O9L1k7I3rJuHxbZU0LQ=;
        b=WS3zm1PJRCBGilA9VyQxpZL2Q3aY78h9gvSWmZBExsfIf4b33Ga51sUroy2U2sFUYf
         t9rCsgzpSgSuVBh/ZB1zGtSDQhE2q4/F5uh0/eeDGrRCy2CdSkt3vbfgTrU14uXsdQZZ
         gPIUmm09ZeNsGt29uluFxnopJwv9s83AmMUCkVxr4Wfgmb7LVvERobFhx1F2Bvs3FbLL
         CS9pEl8NAd7YARK21jZqeYrMly4tGUyfAMIb5t5EzBiM8To1deZFr+MObAMhy1yk19n/
         sKAVQIMK3MP5zZ5sbbOPv/iiGGSzgUw9eLPQdy2UiDWTr5OH2oz50Lw2w/UMEzqhLfDM
         V89A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of kirill.shutemov@linux.intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id z20si88681wmc.1.2021.09.14.03.43.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Sep 2021 03:43:09 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of kirill.shutemov@linux.intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6200,9189,10106"; a="282958075"
X-IronPort-AV: E=Sophos;i="5.85,292,1624345200"; 
   d="scan'208";a="282958075"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Sep 2021 03:43:07 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.85,292,1624345200"; 
   d="scan'208";a="528733499"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmsmga004.fm.intel.com with ESMTP; 14 Sep 2021 03:43:04 -0700
Received: by black.fi.intel.com (Postfix, from userid 1000)
	id 948D9FF; Tue, 14 Sep 2021 13:43:08 +0300 (EEST)
Date: Tue, 14 Sep 2021 13:43:08 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel test robot <oliver.sang@intel.com>
Subject: Re: [PATCH] mm: fix data race in PagePoisoned()
Message-ID: <20210914104308.hi55o2f4jfxpmswg@black.fi.intel.com>
References: <20210913113542.2658064-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913113542.2658064-1-elver@google.com>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of kirill.shutemov@linux.intel.com
 designates 134.134.136.31 as permitted sender) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, Sep 13, 2021 at 01:35:43PM +0200, Marco Elver wrote:
> PagePoisoned() accesses page->flags which can be updated concurrently:
> 
>   | BUG: KCSAN: data-race in next_uptodate_page / unlock_page
>   |
>   | write (marked) to 0xffffea00050f37c0 of 8 bytes by task 1872 on cpu 1:
>   |  instrument_atomic_write           include/linux/instrumented.h:87 [inline]
>   |  clear_bit_unlock_is_negative_byte include/asm-generic/bitops/instrumented-lock.h:74 [inline]
>   |  unlock_page+0x102/0x1b0           mm/filemap.c:1465
>   |  filemap_map_pages+0x6c6/0x890     mm/filemap.c:3057
>   |  ...
>   | read to 0xffffea00050f37c0 of 8 bytes by task 1873 on cpu 0:
>   |  PagePoisoned                   include/linux/page-flags.h:204 [inline]
>   |  PageReadahead                  include/linux/page-flags.h:382 [inline]
>   |  next_uptodate_page+0x456/0x830 mm/filemap.c:2975
>   |  ...
>   | CPU: 0 PID: 1873 Comm: systemd-udevd Not tainted 5.11.0-rc4-00001-gf9ce0be71d1f #1
> 
> To avoid the compiler tearing or otherwise optimizing the access, use
> READ_ONCE() to access flags.
> 
> Link: https://lore.kernel.org/all/20210826144157.GA26950@xsang-OptiPlex-9020/
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Will Deacon <will@kernel.org>

Acked-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210914104308.hi55o2f4jfxpmswg%40black.fi.intel.com.
