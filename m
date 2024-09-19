Return-Path: <kasan-dev+bncBDGZVRMH6UCRBVU5V63QMGQEUQ67LQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 68D2A97C4AC
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 09:12:23 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4584cfbee5bsf36387661cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 00:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726729942; cv=pass;
        d=google.com; s=arc-20240605;
        b=fbjxWike3ZfmD64j8fRzz9IWY5aP4Xq+mhoy6dSlbGsHO/lMJ0ogKWS43WIb9F8bGP
         4y0s/Dbhy5QkXRMJcBgHUO+SeBQ4LDN0rYeJvMrLoTXdwfwFRYFsR5jtxPttK5TkIEk1
         pFKcBPsL6cgdvHDZfXupP2l+APkZHW1GacC+m8KkZdM3uTSGbhl1FdfqLFS09Wh3O1rY
         J+HDNsf+zHaYTxm7VVJgDK291rHVZyXXmeGVzxoNEYHFMbZNtHlHkGEL0FwKCN1DSy14
         sC+Z4v5bzXY1cyPKhNcun59mJgZis5Ha3Brnd49hvayOHiogyTqmcOo5YFwvA5ajW4J+
         B1HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+RbdfBiOtktXUzkK2OO6Dpb5j7bNQXl6WcQw/XUBUqg=;
        fh=B8yuQDSnqXhLkMnym/48BQiTKLrep/Bjc5AzV/umjhg=;
        b=fe85aWXjuBeEwqjbRKggjPYi8WnrpNGDAl80g4ogGCkQ/FfD2VBFj3kIUzvLans7ZC
         6XvXcgzMFFvbtMiaPqAnOpVPKfhCq6q8wZyle9pPa3p97cl0V3ab56adhHkDyN6iKNmS
         geDXxGG2VATG4UJYKNNseGEv7PlixHjn282RkU3y1d5281//ENQ9dx7FRHBEFkYo/FMb
         UH/q1bih5fp/5337zkF0En4VBU20RmGN5aWfV98iyEVxPA5xiiDUPdiFKhSnVIHwelAs
         jA6rheo87Y5/p7FMvycQ4tv3A60jZ0dkSsrT7V5K3C3iXgk3rtyYi84x68+1P1eArjVB
         6dIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726729942; x=1727334742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+RbdfBiOtktXUzkK2OO6Dpb5j7bNQXl6WcQw/XUBUqg=;
        b=R7n7hreQ+/pXCaLciucRLE+yFkutngNATETrofq01YyLox6WDA79QvO1iUdTKpHdis
         jbUP17j7LeqOjDBEEQsORN14f+HB8txOgbrwDpD+KmZNj562H5bLNtrVJCdM3pv45Qli
         7W0fqgfPweFNlNwfJtFxAh2+DinEfhUvCma4h29XiN30RBb51BfrHUwaMsDkKBwQCNCy
         b7BPTG/msv7fWmm5vFz/e4t9u8/VqjxVgzdYnPb8pwSJwgrqN5yLqxG+RaVcIly0LVMw
         Bw8m39MeSHt4XqpWkdgpK9HFBJpbDqvUlaDoIPFHoua6Ywufj9Or020MFSYtKUsnG/pA
         5Njw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726729942; x=1727334742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+RbdfBiOtktXUzkK2OO6Dpb5j7bNQXl6WcQw/XUBUqg=;
        b=cxGznIV8/2GjdfFOBEUsGMZAK4frOiymyNJLau3XqJQpkPe2hhGRmfmMvy7QVnG5UL
         HhHuiEVEhD016kx9na+FwUCzYaSxUrLYhKtja6YANAb1VRTFxuOe6PKU5sIjyoA4vPTI
         zcbz0yGRoH9EWReXRC/nuc6Sm3Pq49QreMNuDhWRR2IFPFfq+y8v/aeeORvY6Y3kFYPX
         Yk3fOJVftGou3c58QAVpLDpRSdmeCbR7inMZ2ozS9Qv/mHZkTLfovVWtaWpJmCLXyAvZ
         O6bdmqrkA1Cd9Vcw/WPqNrr1LA5mh700qE1tmlswyKA/OyaSLocGzLwLAX38b1JjQu/m
         iltQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVipFNUcleMAoCDrMZkXr1kCmi+P1jff8rScS/PW2pR2aJ9a6d0l9IMjA4xjVltA0uGuBdZig==@lfdr.de
X-Gm-Message-State: AOJu0YzHQFyZMaU6HDKhXQkYFVqGwt5lJlTvfPLFSaCr2wBrxLy1MvNY
	Jso2sK2xPYVlu21hJJo0leDMqstXDslQBnBjc5rwFz7QK0LpuIhk
X-Google-Smtp-Source: AGHT+IF17xtzMj0+Ksy3R7ijDOBh6sKEaUltVZzrPFsQ+J71xSmn5tqv7DQ3HHWzw2TBMqo6NitSqw==
X-Received: by 2002:a05:622a:1189:b0:458:209b:5ec2 with SMTP id d75a77b69052e-45b160b7f08mr31813591cf.29.1726729942153;
        Thu, 19 Sep 2024 00:12:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:507:b0:458:2b02:700b with SMTP id
 d75a77b69052e-45b16698b62ls10078911cf.1.-pod-prod-00-us; Thu, 19 Sep 2024
 00:12:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2a7ZkQIbjP0jswWTaxTe0UwND2Rns3cRx+6fXiHNxCOYqooYnRgJXmfUIKF6AP50OOqBlK+Dwx0k=@googlegroups.com
X-Received: by 2002:a05:622a:1995:b0:458:32ca:a306 with SMTP id d75a77b69052e-45b1603b6c6mr35282431cf.14.1726729941349;
        Thu, 19 Sep 2024 00:12:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726729941; cv=none;
        d=google.com; s=arc-20240605;
        b=Xq1SK1nI7N1eGjTLtBOhl0q2+2984XeyAcdzvqnXNz7PL/Ku/WAh9y30tdcsKkfRAM
         LZhNPRaFqMWF6zZAd3iaHiarbnVjA3tSfIIOjkkkXlPYNl5GK7hupKTJNFiQPCMCYydt
         MEpewW+PuVzU7eqPeo+X1yW1vG0KrZvwT9BrcDY3w6nNC6Aep6yLROIxCtG3959pTyle
         hRD9QvvLwwHtYPz+fWbcbp9iSn0u3WTqSboG52ZpWDifUJ6k3rglcHCfb+Oy/xcntHMW
         QqVSVZtftYPIDE+QNwZIvAG8s9eX6cos7WBeX7zn3xia21CIDOoBMYha0YGjMD0gpZe2
         OdWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=VfvmTILgdFtcSVTD5VawbOnNN+7L2DqOz2QZKDFkEeE=;
        fh=3Jl9QiNPalj7/0ROfaGA9IG3PfEs+XI3AiXzJO/kGSI=;
        b=S6cFwBicKRnJ76M9HTlvbMnE+UFJvV1YZnSwjvCVwPVY7zV01U+hNXBBg+emcUmBLZ
         sPvkjra7mfLE2cRJ+zoZsLWCg9eiIO2KjUphEQpmbkCSTM9JGVcLoKobJBgcCr9FnRih
         dkpWwJNUOMO6YN8SeXgvsACVz38qDQ6c70fCL0vPTDVbdaRRghzPASOEuu8oK/uP+58z
         TMRUax4/tN+um25nNgN00qcPEjXyCeaSjtdFwDVcDFTdD9IBBb2HVH5IUXLAdBn8x8T7
         Pb5791XcgjJrqNRZByTwsvlT77uCO3jz4mCOqmz9l5h6MWW3cc13glr4TPG+o9eXqb8j
         HCPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-45b1793e274si583291cf.5.2024.09.19.00.12.21
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 00:12:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 190C81007;
	Thu, 19 Sep 2024 00:12:50 -0700 (PDT)
Received: from [10.163.34.169] (unknown [10.163.34.169])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 109FE3F64C;
	Thu, 19 Sep 2024 00:12:11 -0700 (PDT)
Message-ID: <6191a730-1a0f-476e-8041-a0a51094b6b3@arm.com>
Date: Thu, 19 Sep 2024 12:42:08 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 4/7] mm: Use pmdp_get() for accessing PMD entries
To: kernel test robot <lkp@intel.com>, linux-mm@kvack.org
Cc: oe-kbuild-all@lists.linux.dev, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Ryan Roberts <ryan.roberts@arm.com>,
 "Mike Rapoport (IBM)" <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 x86@kernel.org, linux-m68k@lists.linux-m68k.org,
 linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 Dimitri Sivanich <dimitri.sivanich@hpe.com>,
 Muchun Song <muchun.song@linux.dev>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Naoya Horiguchi <nao.horiguchi@gmail.com>,
 Pasha Tatashin <pasha.tatashin@soleen.com>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240917073117.1531207-5-anshuman.khandual@arm.com>
 <202409190244.JcrD4CwD-lkp@intel.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <202409190244.JcrD4CwD-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 9/19/24 00:37, kernel test robot wrote:
> Hi Anshuman,
> 
> kernel test robot noticed the following build errors:
> 
> [auto build test ERROR on char-misc/char-misc-testing]
> [also build test ERROR on char-misc/char-misc-next char-misc/char-misc-linus brauner-vfs/vfs.all dennis-percpu/for-next linus/master v6.11]
> [cannot apply to akpm-mm/mm-everything next-20240918]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
> 
> url:    https://github.com/intel-lab-lkp/linux/commits/Anshuman-Khandual/m68k-mm-Change-pmd_val/20240917-153331
> base:   char-misc/char-misc-testing
> patch link:    https://lore.kernel.org/r/20240917073117.1531207-5-anshuman.khandual%40arm.com
> patch subject: [PATCH V2 4/7] mm: Use pmdp_get() for accessing PMD entries
> config: openrisc-allnoconfig (https://download.01.org/0day-ci/archive/20240919/202409190244.JcrD4CwD-lkp@intel.com/config)
> compiler: or1k-linux-gcc (GCC) 14.1.0
> reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240919/202409190244.JcrD4CwD-lkp@intel.com/reproduce)
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202409190244.JcrD4CwD-lkp@intel.com/
> 
> All errors (new ones prefixed by >>):
> 
>    In file included from include/asm-generic/bug.h:22,
>                     from arch/openrisc/include/asm/bug.h:5,
>                     from include/linux/bug.h:5,
>                     from include/linux/mmdebug.h:5,
>                     from include/linux/mm.h:6,
>                     from include/linux/pagemap.h:8,
>                     from mm/pgtable-generic.c:10:
>    mm/pgtable-generic.c: In function 'pmd_clear_bad':
>>> arch/openrisc/include/asm/pgtable.h:369:36: error: lvalue required as unary '&' operand
>      369 |                __FILE__, __LINE__, &(e), pgd_val(e))
>          |                                    ^
>    include/linux/printk.h:437:33: note: in definition of macro 'printk_index_wrap'
>      437 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
>          |                                 ^~~~~~~~~~~
>    arch/openrisc/include/asm/pgtable.h:368:9: note: in expansion of macro 'printk'
>      368 |         printk(KERN_ERR "%s:%d: bad pgd %p(%08lx).\n", \
>          |         ^~~~~~
>    include/asm-generic/pgtable-nop4d.h:25:50: note: in expansion of macro 'pgd_ERROR'
>       25 | #define p4d_ERROR(p4d)                          (pgd_ERROR((p4d).pgd))
>          |                                                  ^~~~~~~~~
>    include/asm-generic/pgtable-nopud.h:32:50: note: in expansion of macro 'p4d_ERROR'
>       32 | #define pud_ERROR(pud)                          (p4d_ERROR((pud).p4d))
>          |                                                  ^~~~~~~~~
>    include/asm-generic/pgtable-nopmd.h:36:50: note: in expansion of macro 'pud_ERROR'
>       36 | #define pmd_ERROR(pmd)                          (pud_ERROR((pmd).pud))
>          |                                                  ^~~~~~~~~
>    mm/pgtable-generic.c:54:9: note: in expansion of macro 'pmd_ERROR'
>       54 |         pmd_ERROR(pmdp_get(pmd));
>          |         ^~~~~~~~~
> 
> 
> vim +369 arch/openrisc/include/asm/pgtable.h
> 
> 61e85e367535a7 Jonas Bonn 2011-06-04  363  
> 61e85e367535a7 Jonas Bonn 2011-06-04  364  #define pte_ERROR(e) \
> 61e85e367535a7 Jonas Bonn 2011-06-04  365  	printk(KERN_ERR "%s:%d: bad pte %p(%08lx).\n", \
> 61e85e367535a7 Jonas Bonn 2011-06-04  366  	       __FILE__, __LINE__, &(e), pte_val(e))
> 61e85e367535a7 Jonas Bonn 2011-06-04  367  #define pgd_ERROR(e) \
> 61e85e367535a7 Jonas Bonn 2011-06-04  368  	printk(KERN_ERR "%s:%d: bad pgd %p(%08lx).\n", \
> 61e85e367535a7 Jonas Bonn 2011-06-04 @369  	       __FILE__, __LINE__, &(e), pgd_val(e))
> 61e85e367535a7 Jonas Bonn 2011-06-04  370  
> 

This build failure can be fixed with dropping address output from
pxd_ERROR() helpers as is being done for the x86 platform. Similar
fix is also required for the UM architecture as well.

diff --git a/arch/openrisc/include/asm/pgtable.h b/arch/openrisc/include/asm/pgtable.h
index 60c6ce7ff2dc..831efb71ab54 100644
--- a/arch/openrisc/include/asm/pgtable.h
+++ b/arch/openrisc/include/asm/pgtable.h
@@ -362,11 +362,11 @@ static inline unsigned long pmd_page_vaddr(pmd_t pmd)
 #define pfn_pte(pfn, prot)  __pte((((pfn) << PAGE_SHIFT)) | pgprot_val(prot))
 
 #define pte_ERROR(e) \
-       printk(KERN_ERR "%s:%d: bad pte %p(%08lx).\n", \
-              __FILE__, __LINE__, &(e), pte_val(e))
+       printk(KERN_ERR "%s:%d: bad pte (%08lx).\n", \
+              __FILE__, __LINE__, pte_val(e))
 #define pgd_ERROR(e) \
-       printk(KERN_ERR "%s:%d: bad pgd %p(%08lx).\n", \
-              __FILE__, __LINE__, &(e), pgd_val(e))
+       printk(KERN_ERR "%s:%d: bad pgd (%08lx).\n", \
+              __FILE__, __LINE__, pgd_val(e))
 
 extern pgd_t swapper_pg_dir[PTRS_PER_PGD]; /* defined in head.S */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6191a730-1a0f-476e-8041-a0a51094b6b3%40arm.com.
