Return-Path: <kasan-dev+bncBDGZVRMH6UCRBC5CV63QMGQEXIAVKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4679B97C4C8
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 09:21:49 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5e1c26c85c2sf478969eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 00:21:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726730508; cv=pass;
        d=google.com; s=arc-20240605;
        b=OLr03Iv73SJbat3D26crzdsrH/04qO/4bXmo7Z4uhcZAVq/wVBOcinJYKoDE55qsKh
         s//UFXJ/1iAzg2aULtOHln7koDdij+wjK7KNdrNdkl91COXw6NKe4ORN2RljTz3mJxLp
         TVZRUqHtOqUGASGxoLHOda4bZamaxPufNCyWzxZtwoVamiN2c2lT1Fre+AmyrzNJoc/Y
         W8pwcZRpeq4OEVb04TfvV3U6FMrm2S/mqeyGqbtJG0qWUJ6m4QeJxpuucj5kWGAMOT3Q
         GpNKmLN6oauEHWVHHsiZyVrmo7kKhXE6DF8xI2JAz+coPePbLHC4FxI9YCqwO69TN2Jy
         lMVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ABTPiAMeHkA6aVPwxJMBQivBoM0zPLD0ckihCEpLkPw=;
        fh=YWiHTy8HxAqskW3yeky/zqX8CVwCoPYQSY727VQp7js=;
        b=jmqi5rHUOOrko7xQ980DDB83dQTfrnCPx3/x5cSlvka9ulOqJQ2ozY65V63Rc2uQzF
         5CEVMGsSIlkfFRdHJMBHvnAy/CsZAl1uP7Z7KmhN3m8+DZXlXe4nDm62uYAk407EzAJ+
         JCMJAWNMNom8ykEESLVevJ5DMjSSGhcfrxnUcceLPxbnFRq0md4o2v4XYpUPQxmk++ub
         9njbqShyQQSY7qIRW0Nm5pKiSgjZPdDa4EaF412rwyqiSYq3wqO2H3glw1ad16bwE20s
         O6/bPY7Yu7gExIIfSusy3MbQ/V0FKv94bdg/fsOwJupd3eCGSKIFqxXQNnIqASaJUcMW
         qzAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726730508; x=1727335308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ABTPiAMeHkA6aVPwxJMBQivBoM0zPLD0ckihCEpLkPw=;
        b=JS6ClKsvPwTje9OtesLsEUE7/NxjQUSvhE9/aCYCdsDHB9EkRbbfzLWG2nto/LzBMT
         LxvMd6NqDAos0r1ebJ4MJwyRjWBQjDGk4z9qJIsxh7U+6ulRxbpt5eBDEPBLHzc3RPp3
         t3yORMW9U/z/Q91d7NZISGBlxPUWJlHpSdWMza6+SGjr0GxOxA49p6q41iQ5loYjeXCi
         ipf+EfX78oIf27VQiL2HMvhmBjC9qZ1BjbP0FIBeFEhZ+bkxJi1hpx1Yc2dsxUXu07AR
         3VvtGSjvxp19Y5rYjaoLljp2feNZrvqhnwFFZac8jc6NoHNv72o+oQiPw6pye8R4nTm2
         PlnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726730508; x=1727335308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ABTPiAMeHkA6aVPwxJMBQivBoM0zPLD0ckihCEpLkPw=;
        b=ke76GjtvK+B5FWnKGuQOvaSh9wspZyVeSjyXexBUjrzlGak7PMc3DKeaT0iw2Qe4jA
         J80DCEDUb1CnNsTloede5gaYWQ7xymLBXRLIrHEk1cEy7xQYCuliSfqkUQjIaNpy1/R9
         V84pXRIwnx/+sQjkczjUia6WXPsj4fOoHrdriV/k8XICkkq2MVYG8w3Ki9J63/Qsn0eu
         KTx613SI1iU8FJFHOHZex98zm6IZAduX/t5MhInshBs0yme40agpbFo21WlKfcayH3ta
         j0WYaqW7xVQwxYFO8Juck6Jiy7GH3PdkIym5h75HsvfnSXzKI5QYF5tFfvnLb9AGod2S
         QUGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTVvWLWZCUVnHEYft+EGc6IgFC8i3zyFz1tI4o80j6OMnMjpo69R6pgu9PvoyaZTtn7K6hnQ==@lfdr.de
X-Gm-Message-State: AOJu0YzvWzCtIUYWjh3+Ec7zLaBxp1FYLBftn+9cbEw7DU/PfMImHtdl
	m9eHsk2YpLOmHB+wDu7bdZxjNlBVDDME7kNDW1ieZvHRTlJZUQBY
X-Google-Smtp-Source: AGHT+IGp0OCH+vJBw1is4mjz/2iCKbn2xAliM3Lp+k9+KTZkmnoXTqqI54U7zo84GAHwhO05CKHU5A==
X-Received: by 2002:a05:6820:1c85:b0:5e1:e65d:5146 with SMTP id 006d021491bc7-5e2014359c7mr13057372eaf.5.1726730507694;
        Thu, 19 Sep 2024 00:21:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d34e:0:b0:5e5:684f:4567 with SMTP id 006d021491bc7-5e57e9abba6ls240352eaf.1.-pod-prod-09-us;
 Thu, 19 Sep 2024 00:21:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFNMijZa/HWQkLZGYHEmfVmsiNW7WDLnnT6czdElzmybfafIJLaQHiT7pEGgpltsZ+RwFtwEn3Qdw=@googlegroups.com
X-Received: by 2002:a05:6830:2692:b0:710:f3cb:5b85 with SMTP id 46e09a7af769-7110946408dmr15256720a34.6.1726730506911;
        Thu, 19 Sep 2024 00:21:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726730506; cv=none;
        d=google.com; s=arc-20240605;
        b=V5O5gluHcVW2mTHdzPSbptHS3gScND6tnoc/fe2qO6rvuCZrKpLHp7Ei91GealSVa2
         N2fiJxD5PaXGiJQO18Mqn9alW2qJmkWy+GhzuWEFE59Fh/YIDdCv365ys7eirc0kwojv
         KudeXSNm4yMG8GZ2b+utFT+KxseH8gFqvGx50ZDHNHeNVMi/zjT8VF2hEdsfemyTYbK6
         zRcyLbM8yZgEQPCMn+JuTOKdswYA3G6iO/eQDY7uC+shLr1+OezU51bbxdWvvEUO4c+W
         SNO+GjWGVegX2+QPsKwVDp+S5wmCLTm1PDY/guaLYerUk2fCwEWX0xR0eY70NUF4/BD4
         sF/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=LPOvVFiFxkp8wPIQ25B+uct6N3jvyLIyr6Qy+Wyn0lw=;
        fh=Dlts5TV2gQ0clhDQDCpspghuSeM1+Fekc1fhwnL+v/c=;
        b=WfT9t7wG5+/7RNSUHG2VUQ27f5xs0cfIEiOOGumEwtwEMIVTvPzTeTPZ30y/rtHsoG
         Mg3t3wsO2EucPhG+JpTMQNbB6/KydZxk3oNYgTet2PP40XlTzVGWjNlMSmAnu8S2cu/F
         EV3UovR5/fkXdpzjdrDBdNLMfAAi5gQIKsNG6AZFwbMpejl0ae2D0BaNUzF05bMHTQOG
         1z5it8b9OgVI2rLLHU7HXE3U/pt8uAFMM41n7JsovBBcQWxm06iZ9OPqwO9RzsQhg+H4
         MsVOiGbmnPd1BDnXlHtHi3eBigBr3nL609MYwvw7klZASfw/rMCg3vpTyT0GrnvY+B1b
         VAsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 46e09a7af769-71389c030a8si51322a34.5.2024.09.19.00.21.46
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 00:21:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 56B1A13D5;
	Thu, 19 Sep 2024 00:22:15 -0700 (PDT)
Received: from [10.163.34.169] (unknown [10.163.34.169])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6A5A43F64C;
	Thu, 19 Sep 2024 00:21:37 -0700 (PDT)
Message-ID: <b0548a9f-6201-47e3-81cd-0d3b1de0a8e5@arm.com>
Date: Thu, 19 Sep 2024 12:51:33 +0530
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 4/7] mm: Use pmdp_get() for accessing PMD entries
To: kernel test robot <lkp@intel.com>, linux-mm@kvack.org
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
 Andrew Morton <akpm@linux-foundation.org>,
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
 <202409190205.YJ5gtx3T-lkp@intel.com>
Content-Language: en-US
From: Anshuman Khandual <anshuman.khandual@arm.com>
In-Reply-To: <202409190205.YJ5gtx3T-lkp@intel.com>
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



On 9/19/24 00:27, kernel test robot wrote:
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
> config: um-allnoconfig (https://download.01.org/0day-ci/archive/20240919/202409190205.YJ5gtx3T-lkp@intel.com/config)
> compiler: clang version 17.0.6 (https://github.com/llvm/llvm-project 6009708b4367171ccdbf4b5905cb6a803753fe18)
> reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20240919/202409190205.YJ5gtx3T-lkp@intel.com/reproduce)
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202409190205.YJ5gtx3T-lkp@intel.com/
> 
> All errors (new ones prefixed by >>):
> 
>    In file included from mm/pgtable-generic.c:10:
>    In file included from include/linux/pagemap.h:11:
>    In file included from include/linux/highmem.h:12:
>    In file included from include/linux/hardirq.h:11:
>    In file included from arch/um/include/asm/hardirq.h:5:
>    In file included from include/asm-generic/hardirq.h:17:
>    In file included from include/linux/irq.h:20:
>    In file included from include/linux/io.h:14:
>    In file included from arch/um/include/asm/io.h:24:
>    include/asm-generic/io.h:548:31: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      548 |         val = __raw_readb(PCI_IOBASE + addr);
>          |                           ~~~~~~~~~~ ^
>    include/asm-generic/io.h:561:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      561 |         val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
>          |                                                         ~~~~~~~~~~ ^
>    include/uapi/linux/byteorder/little_endian.h:37:51: note: expanded from macro '__le16_to_cpu'
>       37 | #define __le16_to_cpu(x) ((__force __u16)(__le16)(x))
>          |                                                   ^
>    In file included from mm/pgtable-generic.c:10:
>    In file included from include/linux/pagemap.h:11:
>    In file included from include/linux/highmem.h:12:
>    In file included from include/linux/hardirq.h:11:
>    In file included from arch/um/include/asm/hardirq.h:5:
>    In file included from include/asm-generic/hardirq.h:17:
>    In file included from include/linux/irq.h:20:
>    In file included from include/linux/io.h:14:
>    In file included from arch/um/include/asm/io.h:24:
>    include/asm-generic/io.h:574:61: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      574 |         val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
>          |                                                         ~~~~~~~~~~ ^
>    include/uapi/linux/byteorder/little_endian.h:35:51: note: expanded from macro '__le32_to_cpu'
>       35 | #define __le32_to_cpu(x) ((__force __u32)(__le32)(x))
>          |                                                   ^
>    In file included from mm/pgtable-generic.c:10:
>    In file included from include/linux/pagemap.h:11:
>    In file included from include/linux/highmem.h:12:
>    In file included from include/linux/hardirq.h:11:
>    In file included from arch/um/include/asm/hardirq.h:5:
>    In file included from include/asm-generic/hardirq.h:17:
>    In file included from include/linux/irq.h:20:
>    In file included from include/linux/io.h:14:
>    In file included from arch/um/include/asm/io.h:24:
>    include/asm-generic/io.h:585:33: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      585 |         __raw_writeb(value, PCI_IOBASE + addr);
>          |                             ~~~~~~~~~~ ^
>    include/asm-generic/io.h:595:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      595 |         __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
>          |                                                       ~~~~~~~~~~ ^
>    include/asm-generic/io.h:605:59: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      605 |         __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
>          |                                                       ~~~~~~~~~~ ^
>    include/asm-generic/io.h:693:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      693 |         readsb(PCI_IOBASE + addr, buffer, count);
>          |                ~~~~~~~~~~ ^
>    include/asm-generic/io.h:701:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      701 |         readsw(PCI_IOBASE + addr, buffer, count);
>          |                ~~~~~~~~~~ ^
>    include/asm-generic/io.h:709:20: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      709 |         readsl(PCI_IOBASE + addr, buffer, count);
>          |                ~~~~~~~~~~ ^
>    include/asm-generic/io.h:718:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      718 |         writesb(PCI_IOBASE + addr, buffer, count);
>          |                 ~~~~~~~~~~ ^
>    include/asm-generic/io.h:727:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      727 |         writesw(PCI_IOBASE + addr, buffer, count);
>          |                 ~~~~~~~~~~ ^
>    include/asm-generic/io.h:736:21: warning: performing pointer arithmetic on a null pointer has undefined behavior [-Wnull-pointer-arithmetic]
>      736 |         writesl(PCI_IOBASE + addr, buffer, count);

Not sure if the above warnings are actually caused by this patch.

>          |                 ~~~~~~~~~~ ^
>>> mm/pgtable-generic.c:54:2: error: cannot take the address of an rvalue of type 'pgd_t'
>       54 |         pmd_ERROR(pmdp_get(pmd));
>          |         ^~~~~~~~~~~~~~~~~~~~~~~~
>    include/asm-generic/pgtable-nopmd.h:36:28: note: expanded from macro 'pmd_ERROR'
>       36 | #define pmd_ERROR(pmd)                          (pud_ERROR((pmd).pud))
>          |                                                  ^~~~~~~~~~~~~~~~~~~~
>    include/asm-generic/pgtable-nopud.h:32:28: note: expanded from macro 'pud_ERROR'
>       32 | #define pud_ERROR(pud)                          (p4d_ERROR((pud).p4d))
>          |                                                  ^~~~~~~~~~~~~~~~~~~~
>    include/asm-generic/pgtable-nop4d.h:25:28: note: expanded from macro 'p4d_ERROR'
>       25 | #define p4d_ERROR(p4d)                          (pgd_ERROR((p4d).pgd))
>          |                                                  ^~~~~~~~~~~~~~~~~~~~
>    arch/um/include/asm/pgtable-2level.h:31:67: note: expanded from macro 'pgd_ERROR'
>       31 |         printk("%s:%d: bad pgd %p(%08lx).\n", __FILE__, __LINE__, &(e), \
>          |         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~
>       32 |                pgd_val(e))
>          |                ~~~~~~~~~~~
>    include/linux/printk.h:465:60: note: expanded from macro 'printk'
>      465 | #define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
>          |                          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^~~~~~~~~~~~
>    include/linux/printk.h:437:19: note: expanded from macro 'printk_index_wrap'
>      437 |                 _p_func(_fmt, ##__VA_ARGS__);                           \
>          |                                 ^~~~~~~~~~~
>    12 warnings and 1 error generated.
> 
> 
> vim +/pgd_t +54 mm/pgtable-generic.c
> 
>     46	
>     47	/*
>     48	 * Note that the pmd variant below can't be stub'ed out just as for p4d/pud
>     49	 * above. pmd folding is special and typically pmd_* macros refer to upper
>     50	 * level even when folded
>     51	 */
>     52	void pmd_clear_bad(pmd_t *pmd)
>     53	{
>   > 54		pmd_ERROR(pmdp_get(pmd));
>     55		pmd_clear(pmd);
>     56	}
>     57	
> 

But the above build error can be fixed with the following change.

diff --git a/arch/um/include/asm/pgtable-3level.h b/arch/um/include/asm/pgtable-3level.h
index 8a5032ec231f..f442c1e3156a 100644
--- a/arch/um/include/asm/pgtable-3level.h
+++ b/arch/um/include/asm/pgtable-3level.h
@@ -43,13 +43,13 @@
 #define USER_PTRS_PER_PGD ((TASK_SIZE + (PGDIR_SIZE - 1)) / PGDIR_SIZE)
 
 #define pte_ERROR(e) \
-        printk("%s:%d: bad pte %p(%016lx).\n", __FILE__, __LINE__, &(e), \
+        printk("%s:%d: bad pte (%016lx).\n", __FILE__, __LINE__, \
               pte_val(e))
 #define pmd_ERROR(e) \
-        printk("%s:%d: bad pmd %p(%016lx).\n", __FILE__, __LINE__, &(e), \
+        printk("%s:%d: bad pmd (%016lx).\n", __FILE__, __LINE__, \
               pmd_val(e))
 #define pgd_ERROR(e) \
-        printk("%s:%d: bad pgd %p(%016lx).\n", __FILE__, __LINE__, &(e), \
+        printk("%s:%d: bad pgd (%016lx).\n", __FILE__, __LINE__, \
               pgd_val(e))
 
 #define pud_none(x)    (!(pud_val(x) & ~_PAGE_NEWPAGE))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0548a9f-6201-47e3-81cd-0d3b1de0a8e5%40arm.com.
