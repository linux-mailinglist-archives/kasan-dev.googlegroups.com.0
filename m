Return-Path: <kasan-dev+bncBC4LXIPCY4NRBGU23KVAMGQE4I6B5LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 15B507EE8DF
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 22:43:57 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1cc1397321fsf17567695ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 13:43:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700171035; cv=pass;
        d=google.com; s=arc-20160816;
        b=HtLpAD5bASN4uEvyVWZ1dCf5mxsPjV514n2VV+RkVfvIJTWtf93hdE17e2ooXTh1kB
         9WoNkXEJWSGnj9N2n/c3eHM9e7HeDlkLy1DG2WzvWQ6OjIkTLv78c4grJu5PTW/64X6q
         aIT+U2e2cFs+EoxAj6ac8/MDepa6OE+mOf2LACyrtc3JzFdA9+aUw/Vh9XppxZdfk7Ez
         IDWl5fVafSaa2ukh5+H8DXwpcjrgVKe1iWffpaXMVUprPWyBaf2pqWBfnvgEIxxRmEAf
         dDnrsfLqiHBwNllG4lfv9KHcE9b0mw0HkQ64C0JD9u/eMCHdpcbAwDe3PRZ+GPpaFp0g
         UTZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=p4+w6qgBulCwPg+Et5NzmOor6ZdD32qvoUryaQXDZAw=;
        fh=GG8SP+cHSIDzfX/H90AFtFjxN9jdMtMMVbd5If2pPeI=;
        b=MVSJr2Xnp3hvQIIUadhx4jvvM2E5tKHFNfwiDOupIdekQHlmSOZJnKeC1X6xpj5iHH
         Gw0M5s7ADvDgW31CXODxjfq0kbwTCJVfSBabExVTpIKHbyyklII+v2FmFlAyecNWgeNZ
         8Abo/wFoKZavuNRpriO5ZHehtAVoR2KbNv904z79c1UfYVw+v4YPHGZG9Ku01udkE36l
         phqdQBKqTp0Md4Gug1WJIiR9WzEAlk0YJvHcl7XbDMRIizZoHBSPjbx08NekvqIFLZUp
         zpBqBQvN9nQ6uQT0uS6AK/zB5htSv9nIGr4FjTZz3NBhrrd0RpPDCFJF4Y+UwQq2GzGr
         y3Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LlEBMIRe;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700171035; x=1700775835; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p4+w6qgBulCwPg+Et5NzmOor6ZdD32qvoUryaQXDZAw=;
        b=Xy4BfLHwzhC0sxZ+J7htTi8yqhfbWJmlPr3qtvhhi0DfQRnjvMUhxZvJ5E5Vcs4ic0
         RyrahDedYYGPBVQTsTvFKkfbumNR1v/1aI3LpmUayzC7r+yxpAba+E52v95PUgspo8fn
         an72OcmodTaG/F8y6DdE1UpvZlz+nUCyCXg3uUp8SkpUHS2/y1M1D5xYDmM6/LBjCe9k
         d9hnlAeCrtVvViCFgOFkrYT7XkhCoaPfvS/BnXpvYbg92YjOTtv21jKt69FQnZoSCgoi
         jxnCrmfIDOLZm/53bKAGqwptFQdmoRiFl21XlK8egH1zj69VeG46p4WnGsxHHKlx0wJ9
         B4cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700171035; x=1700775835;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p4+w6qgBulCwPg+Et5NzmOor6ZdD32qvoUryaQXDZAw=;
        b=N77QEF8nVrS7QQ7wEegCvSaWP046dK3g9zL6BDBYnaKdGbNBwNMZcIsWUbO7tkURUh
         njchQMjGnbLRmSj7JYjSytxzmH2CtMFF9YeTBI9KXaJFtiHCEu/0lFIqj0Vu7c4HaVr0
         1AoCvyr/La0cIqfhTowqCkX/oafcYVJrCbcveKvdOmmH03NtMiKkYGutUVWbJmg2kIbt
         7+mYhoXg12gmn/Pkqeatk/TyKkVzPXXAddfm0On+6EjFEpmzkTIGNEzfamYCHdJBf/5A
         gNqEUX7imY3cqwFIot7DKBY/zstBeOdSBGo1QQN8mHwYEtu7U8dxyEx39I0okq3bkd/V
         jqFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxJuPylCBgp4tEHOcKal+K4hj97qA5Q4XizM/fX0+9X7BQOl+cW
	kuATs0peQCxDCrZYqR/Sc1Y=
X-Google-Smtp-Source: AGHT+IEWXmbq86VS7B+NlRNmRNPsEzFs/NzJ7Bhxx0gPpXOXiN+7mhp6Spp4K4XkPHGVhW4NtgVVHQ==
X-Received: by 2002:a17:90a:1a10:b0:27d:7666:9596 with SMTP id 16-20020a17090a1a1000b0027d76669596mr14059209pjk.11.1700171035153;
        Thu, 16 Nov 2023 13:43:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:520d:b0:279:2e2:5bf0 with SMTP id
 sg13-20020a17090b520d00b0027902e25bf0ls1098101pjb.1.-pod-prod-07-us; Thu, 16
 Nov 2023 13:43:54 -0800 (PST)
X-Received: by 2002:a17:90b:3b43:b0:27d:6b5:9e07 with SMTP id ot3-20020a17090b3b4300b0027d06b59e07mr15411379pjb.1.1700171033500;
        Thu, 16 Nov 2023 13:43:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700171033; cv=none;
        d=google.com; s=arc-20160816;
        b=cQQqbUzGwpUcamNf3NIJw98CIAeJ6ndfiwbJc7A42RM+RBFxGTMIigUqi0X18pKrJP
         XzsRiRKssC0X7b//hX0WYiOs6bG+rhoyHgBgIimmGX32imVWyI0OFVxA3U4QBGsS9SCa
         IHZNXkiSoxASV7pZASoXb8o3NWRf0XEWK1KVnxbQSJYEHARZgoyKUDCGkVBOCYeBNQu1
         6rQwAAAmmVS/nX1yY3Amrom+05RcC65oHQrUxDhRmDUAmavcdyGAocD0ylzWJzTNAmuv
         0ehvDI8Tq0hdgDhCc0Vtu1zEcloUaUqGFkFIn54U1Gv2mZb8SFajItF97ZvfpSYMUfS9
         psVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NqxLOzAzqwaeLgK/IX++BqcA7Bsbq8OycaFVdZ0bNsg=;
        fh=GG8SP+cHSIDzfX/H90AFtFjxN9jdMtMMVbd5If2pPeI=;
        b=l2Cimf0Yyeemdfc954xISDX04GqOq0QPOv6w0NNV6QuoL602l+eRo0RhsOM9yDvc3A
         LLVdoBn4JCbCw3FbbL4DWu+QuZ9sNd2w7ZU1VcQNykqNTlH3Wxbld2RJh5tgtx5LsnKT
         vRxkZ3roHc0DyWLLAMkqfxTuhq9djjwivqebZ9Wa1nnR6GTvJsxHH0gHwVB/L7pym4aI
         l4QmMVRrbyF78/9g5K5x3hxXLo8p9y4WNq8YARNjnijyYi2RsSuMNu9XovfIMVzWka37
         I7eVNTqN6OY5g3uB2ZHGT15D6kmhJ/30gKo/h7n25xWtjJWYp1jhXbafZFyoQUtZbkLJ
         k12Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LlEBMIRe;
       spf=pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id lw9-20020a17090b180900b0026faea70bbdsi127608pjb.0.2023.11.16.13.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Nov 2023 13:43:53 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10896"; a="390043757"
X-IronPort-AV: E=Sophos;i="6.04,205,1695711600"; 
   d="scan'208";a="390043757"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Nov 2023 13:43:50 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10896"; a="835874525"
X-IronPort-AV: E=Sophos;i="6.04,205,1695711600"; 
   d="scan'208";a="835874525"
Received: from lkp-server02.sh.intel.com (HELO b8de5498638e) ([10.239.97.151])
  by fmsmga004.fm.intel.com with ESMTP; 16 Nov 2023 13:43:43 -0800
Received: from kbuild by b8de5498638e with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1r3k9F-00025L-2N;
	Thu, 16 Nov 2023 21:43:41 +0000
Date: Fri, 17 Nov 2023 05:42:42 +0800
From: kernel test robot <lkp@intel.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Marco Elver <elver@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Pekka Enberg <penberg@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	Mark Rutland <mark.rutland@arm.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Sven Schnelle <svens@linux.ibm.com>,
	Ilya Leoshkevich <iii@linux.ibm.com>
Subject: Re: [PATCH 27/32] s390/string: Add KMSAN support
Message-ID: <202311170550.bSBo44ix-lkp@intel.com>
References: <20231115203401.2495875-28-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231115203401.2495875-28-iii@linux.ibm.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LlEBMIRe;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.55.52.120 as permitted
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

Hi Ilya,

kernel test robot noticed the following build errors:

[auto build test ERROR on s390/features]
[also build test ERROR on akpm-mm/mm-everything linus/master vbabka-slab/for-next v6.7-rc1 next-20231116]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ilya-Leoshkevich/ftrace-Unpoison-ftrace_regs-in-ftrace_ops_list_func/20231116-045608
base:   https://git.kernel.org/pub/scm/linux/kernel/git/s390/linux.git features
patch link:    https://lore.kernel.org/r/20231115203401.2495875-28-iii%40linux.ibm.com
patch subject: [PATCH 27/32] s390/string: Add KMSAN support
config: s390-debug_defconfig (https://download.01.org/0day-ci/archive/20231117/202311170550.bSBo44ix-lkp@intel.com/config)
compiler: s390-linux-gcc (GCC) 13.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20231117/202311170550.bSBo44ix-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202311170550.bSBo44ix-lkp@intel.com/

All errors (new ones prefixed by >>):

   s390-linux-ld: arch/s390/mm/vmem.o: in function `crst_table_init':
>> arch/s390/include/asm/pgalloc.h:33:(.text+0x1ba): undefined reference to `memset64'
   s390-linux-ld: arch/s390/mm/vmem.o: in function `vmem_pte_alloc':
>> arch/s390/mm/vmem.c:68:(.ref.text+0x1ec): undefined reference to `memset64'
   s390-linux-ld: arch/s390/mm/pgalloc.o: in function `base_pgt_alloc':
>> arch/s390/mm/pgalloc.c:241:(.text+0x184): undefined reference to `memset64'
   s390-linux-ld: arch/s390/mm/pgalloc.o: in function `crst_table_init':
   arch/s390/include/asm/pgalloc.h:33:(.text+0x3e8): undefined reference to `memset64'
>> s390-linux-ld: arch/s390/include/asm/pgalloc.h:33:(.text+0x568): undefined reference to `memset64'
   s390-linux-ld: arch/s390/mm/pgalloc.o:arch/s390/include/asm/pgalloc.h:33: more undefined references to `memset64' follow
   s390-linux-ld: lib/test_string.o: in function `memset16_selftest':
>> lib/test_string.c:19:(.init.text+0x94): undefined reference to `memset16'
   s390-linux-ld: lib/test_string.o: in function `memset32_selftest':
>> lib/test_string.c:55:(.init.text+0x234): undefined reference to `memset32'
   s390-linux-ld: lib/test_string.o: in function `memset64_selftest':
>> lib/test_string.c:91:(.init.text+0x3c2): undefined reference to `memset64'
   s390-linux-ld: drivers/video/fbdev/core/fbcon.o: in function `scr_memsetw':
>> include/linux/vt_buffer.h:36:(.text+0x30f6): undefined reference to `memset16'
>> s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x320a): undefined reference to `memset16'
   s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x32c4): undefined reference to `memset16'
   s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x33b8): undefined reference to `memset16'
   s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x4f60): undefined reference to `memset16'
   s390-linux-ld: drivers/video/fbdev/core/fbcon.o:include/linux/vt_buffer.h:36: more undefined references to `memset16' follow
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_copy_area':
>> drivers/tty/vt/vt.c:464:(.text+0x107e): undefined reference to `memset32'
>> s390-linux-ld: drivers/tty/vt/vt.c:471:(.text+0x1104): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:471:(.text+0x1118): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:471:(.text+0x1140): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_insert':
   drivers/tty/vt/vt.c:374:(.text+0x13a4): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o:drivers/tty/vt/vt.c:385: more undefined references to `memset32' follow
   s390-linux-ld: drivers/tty/vt/vt.o: in function `scr_memsetw':
   include/linux/vt_buffer.h:36:(.text+0x2844): undefined reference to `memset16'
   s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x2932): undefined reference to `memset16'
   s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x2fe8): undefined reference to `memset16'
   s390-linux-ld: include/linux/vt_buffer.h:36:(.text+0x319c): undefined reference to `memset16'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_line':
   drivers/tty/vt/vt.c:393:(.text+0x3f78): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_lines':
   drivers/tty/vt/vt.c:401:(.text+0x3fb8): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:401:(.text+0x3fe2): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `scr_memsetw':
   include/linux/vt_buffer.h:36:(.text+0x4018): undefined reference to `memset16'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_lines':
   drivers/tty/vt/vt.c:401:(.text+0x40de): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:401:(.text+0x4114): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:401:(.text+0x4134): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_line':
   drivers/tty/vt/vt.c:393:(.text+0x417c): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_lines':
   drivers/tty/vt/vt.c:401:(.text+0x41d6): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o:drivers/tty/vt/vt.c:401: more undefined references to `memset32' follow
   s390-linux-ld: drivers/tty/vt/vt.o: in function `scr_memsetw':
   include/linux/vt_buffer.h:36:(.text+0x46d2): undefined reference to `memset16'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_lines':
   drivers/tty/vt/vt.c:401:(.text+0x4736): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:401:(.text+0x47b6): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:401:(.text+0x47f2): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.c:401:(.text+0x482e): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_line':
   drivers/tty/vt/vt.c:393:(.text+0x7b1a): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `scr_memsetw':
   include/linux/vt_buffer.h:36:(.text+0x7b30): undefined reference to `memset16'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `vc_uniscr_clear_line':
   drivers/tty/vt/vt.c:393:(.text+0x7c7a): undefined reference to `memset32'
   s390-linux-ld: drivers/tty/vt/vt.o: in function `scr_memsetw':
   include/linux/vt_buffer.h:36:(.text+0x7c9c): undefined reference to `memset16'
   s390-linux-ld: drivers/block/zram/zram_drv.o: in function `memset_l':
>> include/linux/string.h:168:(.text+0x1860): undefined reference to `memset64'


vim +168 include/linux/string.h

3b3c4babd89871 Matthew Wilcox 2017-09-08  161  
3b3c4babd89871 Matthew Wilcox 2017-09-08  162  static inline void *memset_l(unsigned long *p, unsigned long v,
3b3c4babd89871 Matthew Wilcox 2017-09-08  163  		__kernel_size_t n)
3b3c4babd89871 Matthew Wilcox 2017-09-08  164  {
3b3c4babd89871 Matthew Wilcox 2017-09-08  165  	if (BITS_PER_LONG == 32)
3b3c4babd89871 Matthew Wilcox 2017-09-08  166  		return memset32((uint32_t *)p, v, n);
3b3c4babd89871 Matthew Wilcox 2017-09-08  167  	else
3b3c4babd89871 Matthew Wilcox 2017-09-08 @168  		return memset64((uint64_t *)p, v, n);
3b3c4babd89871 Matthew Wilcox 2017-09-08  169  }
3b3c4babd89871 Matthew Wilcox 2017-09-08  170  

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311170550.bSBo44ix-lkp%40intel.com.
