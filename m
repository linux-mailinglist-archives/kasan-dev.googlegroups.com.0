Return-Path: <kasan-dev+bncBC4LXIPCY4NRBFVYTOKAMGQEFKZCJGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 56BC852E0F9
	for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 02:08:55 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id bi5-20020a05600c3d8500b0039489e1d18dsf5247389wmb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 17:08:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653005335; cv=pass;
        d=google.com; s=arc-20160816;
        b=AEbH1jImJbMUCr++8Y/9mcdb0yMkldFSSoCZiHkUyztuVM8Gp/2A0DfFa+5aBUMs7i
         P9rqThI+a0ehy0Q4iPkOTy60yX9MJ5FqG+rcnNDZcHIP/wWWd83kbQnN0754SLM6mVCG
         wCG/X4lyXX7AdupmyN7W1jS7bH3B2r4zbLQD4a3zzRq/K1+vhk0Bq260QX/ND4rgouSk
         r/ZPIpBHn/9eK7gY72Xj7swxhg38g7psC+ozqlXkUZP4jrwWCrBXfLlxNkyyW5kL5Vqd
         1JEVt+s7I+2ZzxYoaDdKkGaRLhLKsMosi+GcgijBUSNkL+kT+GxmvB1YsPFK+0H0sqzB
         8pLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zmr+8AWl+1jxk84WOYtRJG/q7tTR8jElqAMFnbPICTk=;
        b=jmvTIBXIf82U1ndKWw2ZxXtBWfDw38WLAz3BXudhtX1LEfgjNXyo4NvOa/DSE5PZe3
         hQxLn8J5ciAMnvQbpuKjsfhUrQOX33JNGvs3CehkiSKSDH6CxQ238/K8VH7Edca47oVq
         ePkRV94EzMJonNXqEBKvVP7sNs+g5byLTxn62GhGbG2YaAuSLcBbb9sD4/XhCIMJ0tBI
         R7lejpSLzjEpxeOYs9MKfUsW2hBPetxuOpL4q/hs3okIepkFCXN2RFYvo00letnxRD+M
         zBLVv/1o7GXk3Fb5CSNcETbMpVg3pu0Dr+oOURlFnDyyKVXagmJQknWIqId5x+31y39o
         XrFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=RGinbJMi;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Zmr+8AWl+1jxk84WOYtRJG/q7tTR8jElqAMFnbPICTk=;
        b=rsN5OyFAj1ySoU8J40hlKn/A5MSIAK/7LtvqiSBe9vlfcsZA9ZrRmaGiMJLPxAQ4/M
         0Oq3ITOOrF+aEpapfyiEthA7DHf7jkZGoE3L52wpiVB8bNWnefooZidycOkQavRs+zpJ
         7plnniCn97xfIh8DM+OpZ7somzPH0I9yfNKhM49c52PZvXNBhw24hoByARsHP+qyhY+G
         2WrOLB6//3o0eZiwHwxgxNllYNAeVW6DnMo+lZq5mRfGBSZyvDNm8NcSBmBQiRvsOnHj
         gGVEdOlqqBgb7oCeubTtQ0E4SUDdGp5Ql549XIoKVbXKUfYuB15UGeblpCiiDX9sdQY8
         KerQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zmr+8AWl+1jxk84WOYtRJG/q7tTR8jElqAMFnbPICTk=;
        b=QC/783DrvGdIaby6ezaWA4tmmHnrFJ+owJE2jDOZcyxZ6h27ZUacEABqsh8Euh19cs
         PO7G/lMzWJH6aq7rmEwMUeGWMj174RhrbVpwc/+1Zk88IpyfoVVSmM4Aq6xDiowM3GV8
         PgpxcyX9AY3/HKCHcojNcHrHo0V6WHx4GoVlSrdgXlluNwoRxm0Xb5DcTFL6AkGjmwYk
         enSXwvuFam87nvaYsrZwtfEDuapCs+xBfiinaYrgom1E78XPsch3WSdgk6qosvljRLZ+
         LmnECJ4QuHT+7GHab+TeTC9eZKnMZRHj3XSJYeJfhJ1eCcuSKVkLltqhQ/PeoKAj9B6B
         hlUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MfCj/fZpzwVwQxSE2KidawrsEuNqbmf6PPEVUAZVe92oRHy3w
	ETQcYeEXXqk0T8UhbLOOgsE=
X-Google-Smtp-Source: ABdhPJxzuDdauQT4LSH2QdbLJ5iWhuXDVAqc+m4IPe8k0wqCEQtQLW3zKpze4y/8/AJQIGwaJ352BQ==
X-Received: by 2002:a05:600c:3ba5:b0:394:6a82:8dbe with SMTP id n37-20020a05600c3ba500b003946a828dbemr5725008wms.185.1653005334842;
        Thu, 19 May 2022 17:08:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b0f:b0:394:7348:9f2b with SMTP id
 m15-20020a05600c3b0f00b0039473489f2bls1854959wms.2.gmail; Thu, 19 May 2022
 17:08:53 -0700 (PDT)
X-Received: by 2002:a05:600c:4e91:b0:394:89c9:a4bf with SMTP id f17-20020a05600c4e9100b0039489c9a4bfmr6489365wmq.81.1653005333859;
        Thu, 19 May 2022 17:08:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653005333; cv=none;
        d=google.com; s=arc-20160816;
        b=FXDimS+ZdYBp9ZWVBEBJOrBr+5vcLypAOZ+3d5EDemACliKiSjbeg5rrB8MtWThHTU
         nroEauqtMCw0gYnAtKoZHmQUrUuP0lgtv/WR4ir5IzIkBEJlnKtYfxpTuRKLVpi4tNOO
         jKBOl2CX0y872cSnWj5Js7ZdMbPexNbAY/kpJCwc8ygNQ7S1ovk6fok1sfbvUnao1lkE
         t05E4wNefu41PYZgLclUTkdoojPxHKoaZfVdA6aIoStThFe0yltAXuRhhjHF3e+tThVb
         fg9Wbl7ZeWBUrJKM7py1PHC8CL9uZSRxSW51755Gm7Wizdj/FgC95TrhX5OnTaAi6AxU
         ucLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u2Fw+rmLZIS6tt41Hu45URyg55lczs6vNe/MHvCqx18=;
        b=wJJ9sPI2Y88XA6qkMTr6hPyQRRS9rMEXd9uggBdCvtGy17QM7Mxq3pVxG/YFiYx0Cn
         PHyLSQd5OOABG6cuyskC2CdTYPx3OX+ZY37ERRyj1Cs0Wxzowc5Sj9c8jpJOw6CJ2F7V
         9ikjuw3bgre8uNsCeiv801vG8pdrWFsvmrjfYc6aYgcDHUwOIWsOMJ4plUXNTVDVo+pp
         YsN30YamqVN5PWYGn7q4VwJYZ8moIF74EVyKaaqq9f4q+xSXlnZPpsy5R2YvGJheBRRr
         EGc1Vd1ZuLuwgOaHOe0qab0EbwCibr96KNfx1UqwNQJ8S/sJKDkobTHvXyEOB/NgUTvQ
         1bgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=RGinbJMi;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id h15-20020adffa8f000000b0020d02df3017si36887wrr.6.2022.05.19.17.08.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 May 2022 17:08:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
X-IronPort-AV: E=McAfee;i="6400,9594,10352"; a="270014775"
X-IronPort-AV: E=Sophos;i="5.91,238,1647327600"; 
   d="scan'208";a="270014775"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 May 2022 17:08:51 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.91,238,1647327600"; 
   d="scan'208";a="743203165"
Received: from lkp-server02.sh.intel.com (HELO 242b25809ac7) ([10.239.97.151])
  by orsmga005.jf.intel.com with ESMTP; 19 May 2022 17:08:47 -0700
Received: from kbuild by 242b25809ac7 with local (Exim 4.95)
	(envelope-from <lkp@intel.com>)
	id 1nrqCE-00044d-Q7;
	Fri, 20 May 2022 00:08:46 +0000
Date: Fri, 20 May 2022 08:08:02 +0800
From: kernel test robot <lkp@intel.com>
To: Jisheng Zhang <jszhang@kernel.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Anup Patel <anup@brainfault.org>, Atish Patra <atishp@rivosinc.com>
Cc: kbuild-all@lists.01.org, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key
 for RV64
Message-ID: <202205200851.XPf3TixK-lkp@intel.com>
References: <20220519155918.3882-3-jszhang@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220519155918.3882-3-jszhang@kernel.org>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=RGinbJMi;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.93 as permitted
 sender) smtp.mailfrom=lkp@intel.com;       dmarc=pass (p=NONE sp=NONE
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

Hi Jisheng,

I love your patch! Yet something to improve:

[auto build test ERROR on linus/master]
[also build test ERROR on v5.18-rc7]
[cannot apply to next-20220519]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch]

url:    https://github.com/intel-lab-lkp/linux/commits/Jisheng-Zhang/use-static-key-to-optimize-pgtable_l4_enabled/20220520-001459
base:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git f993aed406eaf968ba3867a76bb46c95336a33d0
config: riscv-allnoconfig (https://download.01.org/0day-ci/archive/20220520/202205200851.XPf3TixK-lkp@intel.com/config)
compiler: riscv64-linux-gcc (GCC) 11.3.0
reproduce (this is a W=1 build):
        wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
        chmod +x ~/bin/make.cross
        # https://github.com/intel-lab-lkp/linux/commit/d052c69ebaf48ac2925d6f9fa033d9e394da1074
        git remote add linux-review https://github.com/intel-lab-lkp/linux
        git fetch --no-tags linux-review Jisheng-Zhang/use-static-key-to-optimize-pgtable_l4_enabled/20220520-001459
        git checkout d052c69ebaf48ac2925d6f9fa033d9e394da1074
        # save the config file
        mkdir build_dir && cp config build_dir/.config
        COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-11.3.0 make.cross W=1 O=build_dir ARCH=riscv SHELL=/bin/bash fs/

If you fix the issue, kindly add following tag as appropriate
Reported-by: kernel test robot <lkp@intel.com>

All errors (new ones prefixed by >>):

   In file included from arch/riscv/include/asm/pgtable.h:112,
                    from arch/riscv/include/asm/uaccess.h:12,
                    from include/linux/uaccess.h:11,
                    from include/linux/sched/task.h:11,
                    from include/linux/sched/signal.h:9,
                    from include/linux/rcuwait.h:6,
                    from include/linux/percpu-rwsem.h:7,
                    from include/linux/fs.h:33,
                    from fs/char_dev.c:9:
   arch/riscv/include/asm/pgtable-64.h: In function 'pgtable_l5_enabled':
>> arch/riscv/include/asm/pgtable-64.h:19:13: error: implicit declaration of function 'static_branch_likely' [-Werror=implicit-function-declaration]
      19 |         if (static_branch_likely(&_pgtable_lx_ready))
         |             ^~~~~~~~~~~~~~~~~~~~
   cc1: some warnings being treated as errors
--
   In file included from arch/riscv/include/asm/pgtable.h:112,
                    from arch/riscv/include/asm/uaccess.h:12,
                    from include/linux/uaccess.h:11,
                    from include/linux/sched/task.h:11,
                    from include/linux/sched/signal.h:9,
                    from include/linux/rcuwait.h:6,
                    from include/linux/percpu-rwsem.h:7,
                    from include/linux/fs.h:33,
                    from include/uapi/linux/aio_abi.h:31,
                    from include/linux/syscalls.h:77,
                    from fs/d_path.c:2:
   arch/riscv/include/asm/pgtable-64.h: In function 'pgtable_l5_enabled':
>> arch/riscv/include/asm/pgtable-64.h:19:13: error: implicit declaration of function 'static_branch_likely' [-Werror=implicit-function-declaration]
      19 |         if (static_branch_likely(&_pgtable_lx_ready))
         |             ^~~~~~~~~~~~~~~~~~~~
   fs/d_path.c: At top level:
   fs/d_path.c:318:7: warning: no previous prototype for 'simple_dname' [-Wmissing-prototypes]
     318 | char *simple_dname(struct dentry *dentry, char *buffer, int buflen)
         |       ^~~~~~~~~~~~
   cc1: some warnings being treated as errors
--
   In file included from arch/riscv/include/asm/pgtable.h:112,
                    from arch/riscv/include/asm/uaccess.h:12,
                    from include/linux/uaccess.h:11,
                    from include/linux/sched/task.h:11,
                    from include/linux/sched/signal.h:9,
                    from include/linux/rcuwait.h:6,
                    from include/linux/percpu-rwsem.h:7,
                    from include/linux/fs.h:33,
                    from include/uapi/linux/aio_abi.h:31,
                    from include/linux/syscalls.h:77,
                    from fs/io_uring.c:45:
   arch/riscv/include/asm/pgtable-64.h: In function 'pgtable_l5_enabled':
>> arch/riscv/include/asm/pgtable-64.h:19:13: error: implicit declaration of function 'static_branch_likely' [-Werror=implicit-function-declaration]
      19 |         if (static_branch_likely(&_pgtable_lx_ready))
         |             ^~~~~~~~~~~~~~~~~~~~
   fs/io_uring.c: In function '__io_submit_flush_completions':
   fs/io_uring.c:2660:40: warning: variable 'prev' set but not used [-Wunused-but-set-variable]
    2660 |         struct io_wq_work_node *node, *prev;
         |                                        ^~~~
   cc1: some warnings being treated as errors
--
   In file included from arch/riscv/include/asm/pgtable.h:112,
                    from arch/riscv/include/asm/uaccess.h:12,
                    from include/linux/uaccess.h:11,
                    from include/linux/sched/task.h:11,
                    from include/linux/sched/signal.h:9,
                    from include/linux/rcuwait.h:6,
                    from include/linux/percpu-rwsem.h:7,
                    from include/linux/fs.h:33,
                    from fs/proc/meminfo.c:2:
   arch/riscv/include/asm/pgtable-64.h: In function 'pgtable_l5_enabled':
>> arch/riscv/include/asm/pgtable-64.h:19:13: error: implicit declaration of function 'static_branch_likely' [-Werror=implicit-function-declaration]
      19 |         if (static_branch_likely(&_pgtable_lx_ready))
         |             ^~~~~~~~~~~~~~~~~~~~
   fs/proc/meminfo.c: At top level:
   fs/proc/meminfo.c:22:28: warning: no previous prototype for 'arch_report_meminfo' [-Wmissing-prototypes]
      22 | void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
         |                            ^~~~~~~~~~~~~~~~~~~
   cc1: some warnings being treated as errors


vim +/static_branch_likely +19 arch/riscv/include/asm/pgtable-64.h

    16	
    17	static __always_inline bool pgtable_l5_enabled(void)
    18	{
  > 19		if (static_branch_likely(&_pgtable_lx_ready))
    20			return static_branch_likely(&_pgtable_l5_enabled);
    21		else
    22			return _pgtable_l5_enabled_early;
    23	}
    24	

-- 
0-DAY CI Kernel Test Service
https://01.org/lkp

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202205200851.XPf3TixK-lkp%40intel.com.
