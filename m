Return-Path: <kasan-dev+bncBDGZVRMH6UCRB2NRV63QMGQEZ5HVXCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id BBC3497C565
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 09:55:22 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5e1ce60337esf415383eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 00:55:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726732521; cv=pass;
        d=google.com; s=arc-20240605;
        b=XmGqnBrG7mvCpCr8pz3jZexIyhuPutfxad+9kzgRlIXUWPns8CFR97NGBrz5ZiRs83
         wbG/JLrXT/LOIPyUMyXYfxRD5bQDuz0oH9+Rp33fNzWgtt8mo5Kgh9fjWNphpfKazQBm
         1WGgU9xRd19jXwAZy6HzkwD8fr2Jm8djC1PAsJYsBvOByq9Ay+DVqMn5HDrqQlz65i7u
         fhRin+QQB2n4kjC1RbOOLu1milkcKar+Ia2gCoua5Myyl8Nj7x7ZEJufwXtqohs/kpok
         LmaJNaGg2b2wxocZEUsz7RwzFhybJMEZ1ioVaac+tnZDGkn/Imv8fzgBCHhu64P9JWGu
         7OiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+da92H4cGGPw6Xz172smOVeA8sWduNDhotqGhMZYXBA=;
        fh=ysfDX5SYRTBFE2EejSGD5cmlO6jPLVjxY2dqIHkaaBo=;
        b=j54080Q7F8JO3IsEyb9paQM3vWjjzDEbSYapK8qfHdYuPizQC05hvm/0VXd/M9q4MQ
         UOkAOgyi7Nf5kSHHyF6l55k1cS0tP96XTVFuG4Rhiu5MMp/b1z3OKozpRRQffLf78WkZ
         JfyEZ7hjFRd7nt05Iej0oAQgRvCx8RXxDeOt9CzQV7fciSLntq8w6aoMtyoBiv7sozbl
         DUneBOYIrNB24q9OcJbe06FRUUQGuETPV9z0VY5ZpGmFZBWcnf1FtJEqKV2m4OAgMubX
         FVSneUT6MPN4TxLtt6QxRK2j1JhiwL+fs2AR3AqaguxrKnIsEqtIr65BJ3UqteitWZZy
         C3RA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726732521; x=1727337321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+da92H4cGGPw6Xz172smOVeA8sWduNDhotqGhMZYXBA=;
        b=Dl0q9Go7BofYd2XCvjrfMGyctD3S12VZWY4qAqgZODscnbjCDhKfvrhDrykeyir54S
         UXdtYAMx2cskUTBZSPeJHP4SGY+J4l48SVrHWXfG4EoQCw2AtP9pZqNzRTHrlHs4ONBY
         jeuDJaBNkfwvWU3A2R6+0BUhy/4U62nRHHSXWvoW52sYgU0YIRvLVZZYKZ6j8plAngMf
         GAtovmefQKCG4yDpLWKuKhS9PqaK7JOn4BEQit+lfVFpZMHonwukN6fzctv2gfla2y1n
         apW30uUQam9ITVXgJqzfga2KKPceDu0oxi1ynR9LLkz4jOU9wP1v4JIGJkHuHCFkgCEy
         Ryjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726732521; x=1727337321;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+da92H4cGGPw6Xz172smOVeA8sWduNDhotqGhMZYXBA=;
        b=D8KEota7O6J0yYiReOuoGofL1N7OZR+y9O/mrBegSK0pvC3ZbhqLOsGMBg8wok2SQh
         r8ygNEEPWRQRxKwmqyIY3oPD7tgSfOzn1Rbw5LseBUUC0FGY10LjLDLMVJ5gkxxDfgts
         ZNJw4Rqaj1JFSXpS0egsiMjXlstW6AJ2Y3sAOGadMaaF1FvIIaQSwZqnj/UFnNT1G/ro
         oFveax9En8MDLkcplJ2FQ68+/6A/HJssCODoDh1f7s6AiEolTP/P//6Rtyeb3GDUsWRQ
         Nd07/ihcFKT1FGFhAU/IW5ur9PLF7OMKsgCbCi+AHKswUvrrpyJ1OvyBFTiGNyMuKWnC
         xbSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVe7WlnfaA8gO0KdCA25PiYI3DWvged/LdfVsrHyLv0sd7VeXu7RtAi8/mpYIbWOjMkOKe+OQ==@lfdr.de
X-Gm-Message-State: AOJu0YzwB/NZip40NOk+26oOHkQJHMbzk9waMEalTlVbzZtRF52YUxOA
	58gabEU+SjYYlGzavkWRHYjIoGA60YKBw55vfPuqovAImW4u3EGi
X-Google-Smtp-Source: AGHT+IH5so/eKycp/aaqX5FH0U66ZR4y1S0YwdlaUZxeAnnKeb3HXuq/tIRns7iB3dgh8HsiGtntYQ==
X-Received: by 2002:a05:6870:7b47:b0:277:d7f1:db53 with SMTP id 586e51a60fabf-27c3f2c3db5mr16017148fac.17.1726732521178;
        Thu, 19 Sep 2024 00:55:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:d209:b0:270:5705:a448 with SMTP id
 586e51a60fabf-27d092df278ls438457fac.1.-pod-prod-07-us; Thu, 19 Sep 2024
 00:55:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWM08dWYAnU/FQT7FJjL8xrnvqFKzS3KPx6Gzd5/EQCzHCtci6tlMGxBFz6t71v3VsxXdw3TcsBrnw=@googlegroups.com
X-Received: by 2002:a05:6870:56aa:b0:25e:b999:d24 with SMTP id 586e51a60fabf-27c3eeb92c1mr15253026fac.0.1726732520329;
        Thu, 19 Sep 2024 00:55:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726732520; cv=none;
        d=google.com; s=arc-20240605;
        b=Yu0i4yOBB2p4n1sI31zzv7K51JwjCw4uQtiE8sZ3s0Nc8+tyxs/TGb7vbBxffI2cSE
         PTQSoeB+dzpyYiCGan0JrFy4afkabPLfhEeSTuV32MboaNm2fu5/ImLp8tNeSaERPme5
         mcZG6ERvaqMYK7JxuuTunXBNW+ttqO1QkcpF+BqTktN31tqssBdAtCyQi96pOAVOHDWb
         C6GSCHpYR8oaaIXd0+qtjBWXZRCFDlff/1h0+dPIYsQ27IRg127nGOEYnZmJ42BywlyQ
         E5YwEQcXympbT3b5fpYpmIZWb3ifguExwHJNLgpULZRFIZEL6+BKMODBaB3zDvWlQmoU
         pRrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=00GyeIpQiVrRLmk5/aXY8FNlHVW8nZ/1kuIlcJVwo48=;
        fh=6PQ0+YiNs7jWb4+11PVNRLJtg1D6DwdmoKKvgLHbb8o=;
        b=GNGDWAOan7WmjOXuunrZxBDjUNYJxE8LCfCR7L2IYvZ/iPDe4nKeWd1CkyCOWszM8E
         4ILI+INmyohmEOGrsA8nxj/e6F9UsJZ3yME4H/QVc028GCuq7a4qevSRT257njrlkHUk
         2HcLNjUncTGRiOB0Lj0GaLm0Pa/hk17Cyd3XzGEoBjkMuR/AB9KnzHKxl4m3WXU8Z0BW
         rBT50u/g4SOEBjk1WjCMaXE8uWiULnAnuTRCrAu7yATmdKl6BoLvGTSzWE85dG1Aglfe
         mQWokaNqJF5CmMkjT4yxY6uTGX+MKYMw6dqrXqYZsNElY39y1lY9NffMzyQDP7DTW0AG
         9JzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-27d0b5e5a48si75326fac.4.2024.09.19.00.55.20
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 00:55:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 157351007;
	Thu, 19 Sep 2024 00:55:49 -0700 (PDT)
Received: from [10.163.34.169] (unknown [10.163.34.169])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1D82B3F71A;
	Thu, 19 Sep 2024 00:55:10 -0700 (PDT)
Message-ID: <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
Date: Thu, 19 Sep 2024 13:25:08 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
To: kernel test robot <lkp@intel.com>, linux-mm@kvack.org,
 "Russell King (Oracle)" <linux@armlinux.org.uk>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Ryan Roberts <ryan.roberts@arm.com>,
 "Mike Rapoport (IBM)" <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 x86@kernel.org, linux-m68k@lists.linux-m68k.org,
 linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 Dimitri Sivanich <dimitri.sivanich@hpe.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>, Muchun Song
 <muchun.song@linux.dev>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Miaohe Lin <linmiaohe@huawei.com>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <202409190310.ViHBRe12-lkp@intel.com>
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

On 9/19/24 02:00, kernel test robot wrote:
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
> patch link:    https://lore.kernel.org/r/20240917073117.1531207-8-anshuman.khandual%40arm.com
> patch subject: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
> config: arm-footbridge_defconfig (https://download.01.org/0day-ci/archive/20240919/202409190310.ViHBRe12-lkp@intel.com/config)
> compiler: clang version 20.0.0git (https://github.com/llvm/llvm-project 8663a75fa2f31299ab8d1d90288d9df92aadee88)
> reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240919/202409190310.ViHBRe12-lkp@intel.com/reproduce)
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202409190310.ViHBRe12-lkp@intel.com/
> 
> All errors (new ones prefixed by >>):
> 
>    In file included from arch/arm/kernel/asm-offsets.c:12:
>    In file included from include/linux/mm.h:30:
>>> include/linux/pgtable.h:1245:18: error: use of undeclared identifier 'pgdp'; did you mean 'pgd'?
>     1245 |         pgd_t old_pgd = pgdp_get(pgd);
>          |                         ^
>    arch/arm/include/asm/pgtable.h:154:36: note: expanded from macro 'pgdp_get'
>      154 | #define pgdp_get(pgpd)          READ_ONCE(*pgdp)
>          |                                            ^
>    include/linux/pgtable.h:1243:48: note: 'pgd' declared here
>     1243 | static inline int pgd_none_or_clear_bad(pgd_t *pgd)
>          |                                                ^

arm (32) platform currently overrides pgdp_get() helper in the platform but
defines that like the exact same version as the generic one, albeit with a
typo which can be fixed with something like this.

diff --git a/arch/arm/include/asm/pgtable.h b/arch/arm/include/asm/pgtable.h
index be91e376df79..aedb32d49c2a 100644
--- a/arch/arm/include/asm/pgtable.h
+++ b/arch/arm/include/asm/pgtable.h
@@ -151,7 +151,7 @@ extern pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
 
 extern pgd_t swapper_pg_dir[PTRS_PER_PGD];
 
-#define pgdp_get(pgpd)         READ_ONCE(*pgdp)
+#define pgdp_get(pgdp)         READ_ONCE(*pgdp)
 
 #define pud_page(pud)          pmd_page(__pmd(pud_val(pud)))
 #define pud_write(pud)         pmd_write(__pmd(pud_val(pud)))

Regardless there is another problem here. On arm platform there are multiple
pgd_t definitions available depending on various configs but some are arrays
instead of a single data element, although platform pgdp_get() helper remains
the same for all.

arch/arm/include/asm/page-nommu.h:typedef unsigned long pgd_t[2];
arch/arm/include/asm/pgtable-2level-types.h:typedef struct { pmdval_t pgd[2]; } pgd_t;
arch/arm/include/asm/pgtable-2level-types.h:typedef pmdval_t pgd_t[2];
arch/arm/include/asm/pgtable-3level-types.h:typedef struct { pgdval_t pgd; } pgd_t;
arch/arm/include/asm/pgtable-3level-types.h:typedef pgdval_t pgd_t;

I guess it might need different pgdp_get() variants depending applicable pgd_t
definition. Will continue looking into this further but meanwhile copied Russel
King in case he might be able to give some direction.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f43251a-5418-4c54-a9b0-29a6e9edd879%40arm.com.
