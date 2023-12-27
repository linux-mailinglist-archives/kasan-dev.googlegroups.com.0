Return-Path: <kasan-dev+bncBC4LXIPCY4NRBAOWWGWAMGQE65M64NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F98A81F124
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 19:20:50 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-427b10db31fsf61323641cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 10:20:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703701249; cv=pass;
        d=google.com; s=arc-20160816;
        b=cVp/xj2cqAjqkkJ46M50y8buQtt0U8VI5nfRbf7/svCBuWiGFMj6ILxAIPwy8CQ7Og
         TIxrGKBe3RWGZ3/rW+bZz+OgtsA6zAahmTlK974J1Z1OHus6tO2p802/fG/6HzKFyOVf
         YJLxi0u3n8CXnb4MplPSB+FcUOEMsrxkSFpbzgfv45xk1Wf35tvvd78yXCG7goaNWIw/
         RsOg2JjMxZz1OigkMShj2tCm1Ua8acNS5eEeabYBtbAtvEmurJwgccInXFTh7vTVxXRp
         bk5etQEdqWelOatXGXVtcYwdksUaAfsDYQIMXrbUkFE1QQvOB1itaKSR+rgBTxauTx2Q
         iwEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7p+WlUdIQsGR5KiGGpuCDty6tAPibnPwnTERKikgwWk=;
        fh=tnDYxqpkETDW31Lri5Vz6y8L2440j55+2J5CFJX3t2k=;
        b=DuiraUZKg3/YW+EtqZ72q2stb5QjtLwzM4LhKS1D6UADiuPJSQ8C0LtwvZzDQyZXdv
         YsL3BAxeQfcUY0Hc4ADyaKlbZiSoW1iDpPAnPzxsk2hFijv9tZdVber7XW98YZOXVybK
         bCJZzIi/jtD9YXx5ITwLPTC4Kgqw2IaLW/AUcVvkGbdmT2z+wProdwfTZXRLDqJSJx5y
         t3jjDE3AvxrY54xxrQt+NLvBdo+TznQa+5KQlkUgI2CMw+LM2xm1ZqKOyoMjSR2hsagm
         xEGlPMqL/en5Dohuya9mjH57e1vpyzpFFp1otL/+qbqiO2a1FmWk6NYSKu4g1M7c8izi
         f8ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="RrL9/+Vc";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703701249; x=1704306049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7p+WlUdIQsGR5KiGGpuCDty6tAPibnPwnTERKikgwWk=;
        b=FfiwwCo7w6/pCiovQKTd7pPIcIzJf51vcHT/TiCI4ZckNa1uzgXi+Oi2eY4OTYIZki
         RxZ403iRCJmHiaCXJ9vTQFsm4wml705Sqmj1oV66GxNakDoKCXkLPD3GEmjuWmD26UUt
         EX6skAc9N8IWnoTeQie/GOinyD49a/FIsiYgOhY4A5zuvjxYVLsylMbsVG3D9XbfFMUq
         GszQLMXqIqOTSJtqb6zp2lZBWq3kuLlQrqXAwKqxuHyc7dkgh2b3oWK1HEKgwCqJdVlT
         uZA6dUKkqmK/EC1VgzGKa0NVFCfav8otzShcLYJwS05TyZFJybub4yR3FuAjtfO/6efl
         IbQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703701249; x=1704306049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7p+WlUdIQsGR5KiGGpuCDty6tAPibnPwnTERKikgwWk=;
        b=abA3ViZhS26TXxgWxKMw6nGvmYspLwfFwXSmcNlm2eJk/IO2pYAMJ0Ul4aaIDB0/xm
         5u1AafStGxzWgbrJ9js6GMXzId3Ffh+JNlGJ4DLZbzfcxaBmpAah0R1WL9lWt+AJLaAU
         Pc9d5rsKBJ19n4gKrcNLRIJp3cNydESD3Dgd5OsZ0wbj5e81gW/CynIox8bbXZ+iJ7Cg
         /Aq+dX4WjUE7vWDZl4ZdPFW72FTlN/j1yXoWnPiwow/LcSBKyU98gJt6SKzL14FzPV2T
         4EZFOrGZCU0xSl1XmrPB9Z1PnLUlCUzLgZZOeHRmoYG9Ai3jNT9FmMHB1aRCoQDMkBNv
         9FUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz/hYM+fM1ajKp5Cp1tJMxaAb+MK4p+ngxXsfCXUXKl4IA4eZTL
	hCdzfXHHQjPCGW6iaL4vmKI=
X-Google-Smtp-Source: AGHT+IELoQXVB2Qqh3wdpXttgIjijTlDYBMBdW4WV9814aCenDF4vFQG0LaQGmi7WGucVfFVVWZ8BQ==
X-Received: by 2002:ac8:5915:0:b0:427:8c57:598c with SMTP id 21-20020ac85915000000b004278c57598cmr10105321qty.15.1703701249176;
        Wed, 27 Dec 2023 10:20:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:190d:b0:427:e844:a959 with SMTP id
 w13-20020a05622a190d00b00427e844a959ls355173qtc.1.-pod-prod-03-us; Wed, 27
 Dec 2023 10:20:48 -0800 (PST)
X-Received: by 2002:a1f:da43:0:b0:4b6:c1bf:e164 with SMTP id r64-20020a1fda43000000b004b6c1bfe164mr1928295vkg.2.1703701248186;
        Wed, 27 Dec 2023 10:20:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703701248; cv=none;
        d=google.com; s=arc-20160816;
        b=f9TH2VXMTp00UvMQKk2a3zNxG6gcFTUor8/Y0IwD64VIbBC32wr5ka0oDLm3ZpjZrN
         0G8mRhDpLB3N29pHpOGcoNfQfGd7gO+xtFlQ2dUgUugWF6dTBMrAP/TsAehenkTQ2yA3
         5n+9n+eLQjaQSlkT3KiOn1MihfOk1FqnvKTgupP8nVO7sR4UHQ2jJkch4jayrIyPEVJN
         qAhCLY0TPUei4F+xnqEsZzs5nQfuBu1SLm1buZRed3t/1aQcT+oxbNg0jR3oWf3SQ/nH
         8uHqFm7FXz7WNQ5JL6jMvdwiXq1ILQrhDA/F9dhygRr+L9q664IOgr1iRrh04bVnMF5B
         tRxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YQsdU81FO8QZ//YhB4haWFfdWlODEwiL0uBDMRviR0I=;
        fh=tnDYxqpkETDW31Lri5Vz6y8L2440j55+2J5CFJX3t2k=;
        b=mL8ekWmEoWOKNXy4Dra5SbX61VgZlonK8EsADaxOfVUL6aaDQQXWH6R+xA1BVglF3j
         /2hRDzfba1k6csEe8MhofYJYWCWYwmrUl5qL6Ycek/s8z87i25nSUR3dOA36p/pFvR/6
         LQZWjzXD728LUGEvIX/DPgDlpnCoKkB6cpboY7ORUceaBTkoXEraaJx6np6DXg/jt+hb
         Rk+pAoRcKy4SompK1dPTx7KYmclZ3V72OaYoeHv2aPj9Hri6/iulO4rWSnJ50FFT010U
         2ympjCcyKqI3U1LE09DKQMynxNPW5nNAfgxV7xj25Lv90dIZ5CB8c1EYGwTEH5YZAqOu
         MYOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="RrL9/+Vc";
       spf=pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.9])
        by gmr-mx.google.com with ESMTPS id ft7-20020a0561223bc700b004b7487bda5asi559918vkb.3.2023.12.27.10.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Dec 2023 10:20:47 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted sender) client-ip=198.175.65.9;
X-IronPort-AV: E=McAfee;i="6600,9927,10936"; a="15140594"
X-IronPort-AV: E=Sophos;i="6.04,310,1695711600"; 
   d="scan'208";a="15140594"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orvoesa101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Dec 2023 10:20:24 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10936"; a="848740859"
X-IronPort-AV: E=Sophos;i="6.04,310,1695711600"; 
   d="scan'208";a="848740859"
Received: from lkp-server02.sh.intel.com (HELO b07ab15da5fe) ([10.239.97.151])
  by fmsmga004.fm.intel.com with ESMTP; 27 Dec 2023 10:20:21 -0800
Received: from kbuild by b07ab15da5fe with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1rIYVv-000Fez-2M;
	Wed, 27 Dec 2023 18:20:19 +0000
Date: Thu, 28 Dec 2023 02:19:51 +0800
From: kernel test robot <lkp@intel.com>
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] kasan: stop leaking stack trace handles
Message-ID: <202312280213.6j147JJb-lkp@intel.com>
References: <20231226225121.235865-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231226225121.235865-1-andrey.konovalov@linux.dev>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="RrL9/+Vc";       spf=pass
 (google.com: domain of lkp@intel.com designates 198.175.65.9 as permitted
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

Hi,

kernel test robot noticed the following build warnings:

[auto build test WARNING on akpm-mm/mm-everything]
[cannot apply to linus/master v6.7-rc7 next-20231222]
[If your patch is applied to the wrong git tree, kindly drop us a note.
And when submitting patch, we suggest to use '--base' as documented in
https://git-scm.com/docs/git-format-patch#_base_tree_information]

url:    https://github.com/intel-lab-lkp/linux/commits/andrey-konovalov-linux-dev/kasan-stop-leaking-stack-trace-handles/20231227-065314
base:   https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git mm-everything
patch link:    https://lore.kernel.org/r/20231226225121.235865-1-andrey.konovalov%40linux.dev
patch subject: [PATCH mm] kasan: stop leaking stack trace handles
config: x86_64-randconfig-123-20231227 (https://download.01.org/0day-ci/archive/20231228/202312280213.6j147JJb-lkp@intel.com/config)
compiler: gcc-12 (Debian 12.2.0-14) 12.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20231228/202312280213.6j147JJb-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202312280213.6j147JJb-lkp@intel.com/

All warnings (new ones prefixed by >>):

>> mm/kasan/generic.c:506:6: warning: no previous prototype for 'release_alloc_meta' [-Wmissing-prototypes]
     506 | void release_alloc_meta(struct kasan_alloc_meta *meta)
         |      ^~~~~~~~~~~~~~~~~~
>> mm/kasan/generic.c:517:6: warning: no previous prototype for 'release_free_meta' [-Wmissing-prototypes]
     517 | void release_free_meta(const void *object, struct kasan_free_meta *meta)
         |      ^~~~~~~~~~~~~~~~~


vim +/release_alloc_meta +506 mm/kasan/generic.c

   505	
 > 506	void release_alloc_meta(struct kasan_alloc_meta *meta)
   507	{
   508		/* Evict the stack traces from stack depot. */
   509		stack_depot_put(meta->alloc_track.stack);
   510		stack_depot_put(meta->aux_stack[0]);
   511		stack_depot_put(meta->aux_stack[1]);
   512	
   513		/* Zero out alloc meta to mark it as invalid. */
   514		__memset(meta, 0, sizeof(*meta));
   515	}
   516	
 > 517	void release_free_meta(const void *object, struct kasan_free_meta *meta)
   518	{
   519		/* Check if free meta is valid. */
   520		if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
   521			return;
   522	
   523		/* Evict the stack trace from the stack depot. */
   524		stack_depot_put(meta->free_track.stack);
   525	
   526		/* Mark free meta as invalid. */
   527		*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
   528	}
   529	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202312280213.6j147JJb-lkp%40intel.com.
