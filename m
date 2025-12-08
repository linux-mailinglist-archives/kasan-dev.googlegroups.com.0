Return-Path: <kasan-dev+bncBC4LXIPCY4NRBRWF3DEQMGQEV2MBSKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 111CCCABB4F
	for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 01:58:48 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4ed782d4c7dsf66809381cf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Dec 2025 16:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765155526; cv=pass;
        d=google.com; s=arc-20240605;
        b=QlKc64LOJY+Sr2pM4fSfAwNt4C6TrwYXfJd4Dcbxt4D8Nxgxj45ujo3FZjh8lQJhsu
         b5QhAK9dwDN97+04WFT06AAXUE6ilsJwTis4fwe0OmePGyG/cULBdHLU7eOIAOuhw0Ik
         oDPQ3qtUlUR6T6gbu8TOwDJcE73T0KDauyGrzM9XybH/0QF5uh7Uh3LxnHGPSAqdxCOm
         BmAHdjwWaYB+5wwX7FvjS8xpuDS3o15joit0WonZN9mgn8Ep6mUpjG7vGF5dPUUSqa9k
         xGfJ6p89UXXieGFqa8mvI+j+PtXeL0rtYBwzbfPzjgaWCc/xQRxshJDYLf9Y/iZtndLf
         UZYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sksixPOhYykjdpyDOR5H7XYfbSo8COzGKtBk12psP8Y=;
        fh=9hPCo5x21zVBPUmvIc1rpiLzplqJYNxQ9t/8z3q6IrY=;
        b=g1B/aSTdnke2N0OLLuUTT98lXkyXcKievR7OtiJ8dBhhA4FGtna+E1GSV0AKrCty57
         gML2FhAmGp4IMJ74B3yvDEu9hUUhPNGghDZ8Lk8UBEbU+cIf8WfWBjTb7y00tKDtS+uu
         D/C8g499DYTtkrsxCNufhZjXVq8M2psuEB1MPijRWt3ZB8ORyxTyHhjK5erarQGgDJoJ
         WvUm9epBrvLW8+PMYb+ayC09iG7ywGfwoILCPM50cu8eJCSB5o4oK5YuMjgYIw3mY49P
         prX69PklBQkRjqE9dNip3v2qBzDFGNP+5+YxVwacUzO0ZurAelM/HGQOtU2H3aw0qxER
         wU0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jJTyYo1r;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765155526; x=1765760326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sksixPOhYykjdpyDOR5H7XYfbSo8COzGKtBk12psP8Y=;
        b=sGcRX4BtpfHyvEmnTOA6v682FdgoHO5ZSvwDt9L3Qy/8PStEhGEhgPclP8wyqVSyag
         To6v63H0Ss7xsVBRsOqeA6XoE5ln/vV0LBUPoOvnO+HXD97B5IpUdXYCWKHSSo/f5uVc
         cuALXdiZEizgzNmRURuDFAp1xhI8FyA2XNd0M6EXpnNrGVzkzp13P/fRi4ahy6PrDngk
         Xxhx273OHtOKLX2RnZW/+igPv9+00V1BFhRNztkIJmWWPfOrm6IeYUzF12ySteN7ltKS
         pwuKQUBfjkCe+6ExaRumSPMW+BLa4SPcRvg1/l2UJYwAQ4lZM4Y9bouqLI68g9d63X6Q
         oqow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765155526; x=1765760326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sksixPOhYykjdpyDOR5H7XYfbSo8COzGKtBk12psP8Y=;
        b=XJFQ3S67iIMKM4aeGjQSDXZAAJ2/R6DzBpSf11vcLSUuT2c7qX4NwG+IUONQVdj1iQ
         WxPC/KBV8NRjqOeZs/coNNLHIvgfXWYY7Z4wSwq8ylLd8qjb1OldebkYDWsM0JlRH66s
         fLf+sfl99WIsu5AxpdnNEJanfidEGOXYYASpWco/+l8ECbZT4dnbwDNfE48I2IybqH4z
         lV3TfV5+H+8ht/XD88zt99L7PSrE9x2lkwQanaUVPn8R7LLahcfnqa1qhKyk5B8O6uJD
         rSGFv41RcgN/dIbhropL4Om3gkGmAIiGLbEGtSIiipJzYYb99O7qvalbKx/C1Z/rK5q5
         Q3BA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwhgbtC8YYjfStNQWEWvD2VuDWWC1+D2yVlzGmhigBt7MhXN5M5mlgNMG3uMMSaGFQBv1/2Q==@lfdr.de
X-Gm-Message-State: AOJu0YxqiUsQiyWcXmjrjm3hTLtgjz62zFYLoV6U0021pDOBNx8D2Q99
	r1Z6MOuqOMX6B7wD7Fgmpt0l7ERQ2nzMWTTjKzzOEm04M92k1TRLF0OX
X-Google-Smtp-Source: AGHT+IEJtBrsR6zq0utizsyRLyRGydGC1RS5B06iEikxFdIGZnw7pG88d2RHGeSsxfbrVKkPkKQJyA==
X-Received: by 2002:a05:622a:2599:b0:4ee:1301:eba9 with SMTP id d75a77b69052e-4f03fe1baa8mr100582331cf.31.1765155526454;
        Sun, 07 Dec 2025 16:58:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbpY7/E+eMBkrgeeMpkSo2G8nL5pRVdbHQGxEpjBKMcAA=="
Received: by 2002:a05:622a:1882:b0:4ed:e411:4bf5 with SMTP id
 d75a77b69052e-4f024c39658ls84600961cf.1.-pod-prod-01-us; Sun, 07 Dec 2025
 16:58:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUKgFVQ8ZNSs4W4uIW2Ub1/IW3OI2v4qkqApmdNeCkSgYHseKE0prbF/ZYDGDXjmpWlKGgW1Bs4iWM=@googlegroups.com
X-Received: by 2002:a05:622a:5808:b0:4e8:a442:d6b3 with SMTP id d75a77b69052e-4f03fe28133mr98421131cf.37.1765155525675;
        Sun, 07 Dec 2025 16:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765155525; cv=none;
        d=google.com; s=arc-20240605;
        b=Czxik7hliOoyR1kE29wMZzYIwLb7Yu1QLHeUnJ6LbOBYtj3JYdytrtoTSQtjp79vC8
         /nFfzEdtmxlw7zlH9WKsPxZlB6nfv+P++ued4pwsrBv5lH9N+pTX2VGWOiaZZVzkFvIl
         WCkp+Sw2bOHuHEhDdVesJxdnM6UxcbF0YmTmCn9rQOVD07rbzSrFFvgiygREcHB6WcU6
         WC+lnfwzrBtKkIVOSbgAtz46xIdy5zhO9/TdvkrYM+OCk+ECIhhEzRtzzIpsHU0xqAYB
         PcDherb5abNSYOykTwoFQIMYb3uEOxsq3ayigQRH4MTthVGcdL7312xfnURFm1GUaGZ7
         n2/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LFVMojQ3Vh2BILTu1t6IFrfKeeykv15sdEd15zYZaiA=;
        fh=kcPaEjtLbRgMXGuDHtmXdw1mznW1VyPnCvTxk3dMG3A=;
        b=FHqmSNDJ+lNfkYPpG8NWTD0rsGRWS+kIE0jJXAsqCc+IBc2uCssy8Yq4aSw/n9yaUI
         4BpY+6BDKSmBwXQ9K+22Mczy55LGHtZp6WpxTuvaue52R2w0ngMydegIYsdWVZlv6EOo
         Zggrqgdf1SEbWlpRwCvqleo9hprc42MIE7UCS2NVM7noLILZONrNVVmHtDEdxICOIihg
         HXKhZ9axPa9dGcDMHk9XSWCSZxycsvYLFEH3lhGCVUyohSWVeFM3aHFzRKGNM74t6tuA
         Z51nCDdyFsRU/8rbpHwPb7jaB6mIjFjStZVimyatlugA5WnPN42E5t6A3n0lDGF6qUwJ
         fKnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jJTyYo1r;
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f027cec230si4424571cf.7.2025.12.07.16.58.45
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 07 Dec 2025 16:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: HmZQBY9aTY2WDXd8yT71bg==
X-CSE-MsgGUID: sM+rMLDuTkSfJwCvBuKEnw==
X-IronPort-AV: E=McAfee;i="6800,10657,11635"; a="77419566"
X-IronPort-AV: E=Sophos;i="6.20,258,1758610800"; 
   d="scan'208";a="77419566"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Dec 2025 16:58:45 -0800
X-CSE-ConnectionGUID: BKqEMDGdRcSJTkPM7/7ErA==
X-CSE-MsgGUID: 7D6Fkr6YT/a08RrtUmbsOg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.20,258,1758610800"; 
   d="scan'208";a="195827665"
Received: from lkp-server01.sh.intel.com (HELO 4664bbef4914) ([10.239.97.150])
  by orviesa007.jf.intel.com with ESMTP; 07 Dec 2025 16:58:38 -0800
Received: from kbuild by 4664bbef4914 with local (Exim 4.98.2)
	(envelope-from <lkp@intel.com>)
	id 1vSPaF-00000000Jkf-2Xiw;
	Mon, 08 Dec 2025 00:58:35 +0000
Date: Mon, 8 Dec 2025 08:58:22 +0800
From: kernel test robot <lkp@intel.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com
Cc: oe-kbuild-all@lists.linux.dev, andreyknvl@gmail.com, andy@kernel.org,
	andy.shevchenko@gmail.com, brauner@kernel.org,
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com,
	dhowells@redhat.com, dvyukov@google.com, elver@google.com,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, sj@kernel.org,
	tarasmadan@google.com, Ethan Graham <ethangraham@google.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
Message-ID: <202512080828.Gxjg6av3-lkp@intel.com>
References: <20251204141250.21114-10-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251204141250.21114-10-ethan.w.s.graham@gmail.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jJTyYo1r;       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.11 as permitted
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

Hi Ethan,

kernel test robot noticed the following build errors:

[auto build test ERROR on akpm-mm/mm-nonmm-unstable]
[also build test ERROR on herbert-cryptodev-2.6/master herbert-crypto-2.6/master linus/master v6.18]
[cannot apply to next-20251205]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/Ethan-Graham/mm-kasan-implement-kasan_poison_range/20251204-222307
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-nonmm-unstable
patch link:    https://lore.kernel.org/r/20251204141250.21114-10-ethan.w.s.graham%40gmail.com
patch subject: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
config: i386-allmodconfig (https://download.01.org/0day-ci/archive/20251208/202512080828.Gxjg6av3-lkp@intel.com/config)
compiler: gcc-14 (Debian 14.2.0-19) 14.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20251208/202512080828.Gxjg6av3-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202512080828.Gxjg6av3-lkp@intel.com/

All errors (new ones prefixed by >>, old ones prefixed by <<):

>> ERROR: modpost: "kfuzztest_write_cb_common" [drivers/auxdisplay/charlcd.ko] undefined!
>> ERROR: modpost: "kfuzztest_parse_and_relocate" [drivers/auxdisplay/charlcd.ko] undefined!
>> ERROR: modpost: "record_invocation" [drivers/auxdisplay/charlcd.ko] undefined!

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202512080828.Gxjg6av3-lkp%40intel.com.
