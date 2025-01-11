Return-Path: <kasan-dev+bncBC4LXIPCY4NRBZHHRC6AMGQE7AOJZ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 48BE8A0A21D
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 10:03:35 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2167141e00esf47756755ad.2
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 01:03:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736586213; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jha45RTGsRrj+xleABGExzoBUy9ZFOO3bTwjKKB/c2sjJr6tgcSLKpeWw/l1kDBkd8
         dZtJpiZtxME6Udeq9HOBEyyM8PeUO1UT/hob2NvgD9V3uj/7kTCNh08icG5smm73x4Vd
         KB6p9UwzQt7YoeVsnG/h7FO7xtt+PVvjwXFmBF2ubtlzkXXbUZrs6Be59deQOuVqRIUV
         /vHy0iEu+jYUgOnGBikyyZWUDVgr7h5GYRIPsC+Uw2qw86F7QvZB23a8pjQQ4koZzepQ
         YBZ7F+SinrSeeKN9nlSakHgRukNVkp+llw/U/UM4TX2fQgkyIw0j7xbZtFYeQpn2Dk0Y
         1aPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wc6s56wK2QL6qrnXitmgHEPA1zdi853ruH3q1t1GL3Y=;
        fh=rB2+buP3r0D0MXhwml+qsSgTlFzl8U3bQQrlx4UiXOY=;
        b=LaBBdQaAzjGsSCXbcQnsC4dn+N6YZsp/ygXxYlpGCrpkrPNc10RgVixMbHh+yDZ3yG
         loM4C/pr22M7/KEch4U6Y6gZC7KYgoQBkojAkNlvcAxubUKpPaQVLtx/YNihSd1M1/4P
         vEZlRtN3oomCu/1VQhMA9ia9/sSq0DWXcE3PXaSFy2nIEs4Eo2JYT0jDWH2P0Edat8Ef
         SxF6VT4+vu+7+d8CltY11fSz6y0fHmDSIT9715EQJjLzuURET2HLd7mEi5CWmQTkkUeo
         w4YiIbigBcx/6Swbd24vX6Jpx2TS+qR1TZ4lZ8ZSnoPo3D/fRBaLBCcdxwyOT4MNJ9g8
         1e4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cLrDHk9L;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736586213; x=1737191013; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wc6s56wK2QL6qrnXitmgHEPA1zdi853ruH3q1t1GL3Y=;
        b=Z1ItaMU+FjU3Pv1aUOzvPg7UBOJWXjGyjzKB92fMTm/x6tZdcQ/wctJ3KBv43x8nIm
         D+I9r8eK2kXfzBJj5de3nMd/it3c1PKB3OrZG7jBBUjElQEjwapbvZeQNFItDV9G7xNy
         qiOvXjJ9cwLrAWcml9IZulnWH5/O+ubO/hXI7NA+x67eeK6LqvfrFTRS6ySlytcGSzhv
         EqmxCUEgkXsOzVHdEXg+fKSsOrpf3p2lMIJPcHbW8cI86GgjOdnmnZhKxqLe0FtUuvY0
         3MZ9L0jLLfy8YsCRD14dRGX/Zg5vdn7iWx9zuup+zQmK1baNuVAmHHHUMVLPW/mypXfY
         ShIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736586213; x=1737191013;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wc6s56wK2QL6qrnXitmgHEPA1zdi853ruH3q1t1GL3Y=;
        b=Gn5bb1hxtYib029G5OceJs1l8QWQFKYRHs0leyLsB6LrTmheU1EMw7iIf3Ju8o6GAy
         kZMBK57YVfP5ESRyZWVHXtFdoEP68qcLSGRrNCVH5O5rYtBImHgpbofF0uV5U6XsRSji
         HPxV5ioIv43/lk9v22XmpZmnjhTezZkoNzm7vGQgmPMCBEJxMSB2HCIFAt06Ogz9Eeon
         xOGrmwRan0kbq+kIsQ1g6UwT2tHa0OdL5XH59ycH9gg6O71ygg8cLd7Td3FDXeecV6s1
         02rJ2gQRWpVdQsC1Z+h6NBGPrg57fRinekrm0Sr94JP6lrkVnE0nnEq5EdhsOF0+MJ/s
         ocRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUuVmNWh4pOsfpY69nZkQkcTIMgK7T+a4N9cO3SOCOOLpHfGFQKsfEdo8wvak6JeTrMgcs19g==@lfdr.de
X-Gm-Message-State: AOJu0YxO/slsOMKJKNF0zjtJI+QCzopQ6McZWyE5a0GGHggq0yLspVBw
	b8J9mshPzOzh1KIqQb5gJISLdukgvLBV9+Q5rdID8kIDQrtgKaMC
X-Google-Smtp-Source: AGHT+IHjBf++liIawSwentfjIFoo/rf9rrN/c4WirtWQcqzKxPkZDeR18VGV6gODCtzi+Lg+Ny8c0g==
X-Received: by 2002:a17:902:ec83:b0:215:7ce4:57bc with SMTP id d9443c01a7336-21a83f54a5cmr199475735ad.16.1736586213037;
        Sat, 11 Jan 2025 01:03:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2cd:b0:216:56be:c7bf with SMTP id
 d9443c01a7336-21a8d38d762ls14223625ad.2.-pod-prod-09-us; Sat, 11 Jan 2025
 01:03:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWHYV4c4XI5vxfhwmf17S8ongt/qeJ8Wy06yJKfAaD4WiMgAmEN2wTC4PHpnFo42fJ/DEs6tqI8DgA=@googlegroups.com
X-Received: by 2002:a17:903:3385:b0:216:1cf8:8b8 with SMTP id d9443c01a7336-21a83f69643mr145084305ad.27.1736586211459;
        Sat, 11 Jan 2025 01:03:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736586211; cv=none;
        d=google.com; s=arc-20240605;
        b=h9UqMVNcxXq7ymOEi389o7xVmnX+pVsga9qAzxJnOEK7yRA6/jQWlpV/GHivdua9+A
         Wq5AUi0zNXRJQeuckFsAU88G/lNgQKSsT1dgeV7FopcOHt2HxLHPj7MTiFS3l13q4DG4
         78ko4107PAQA8hJrKFRS5CZRKsEBJ5zagH3QQSBDURavEGuBUQ+0ifOmtVOrzBXTA+mB
         ThfDup0mnMkNeYc05LA3kVK4Q4p0FTISx3TI5UNyTKLz61DMINgfnqKRj59Sl02kxxUY
         2nSk3F3fpjGOrI6EgJgEavnob51yWTX1HScVNpcoxRcNlqBqKSCS5CVOcyAmLokB6aKV
         cXFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sNHBvQzc/B7RKLXIl7O+AVKGv13HnfX/8OcD1tdtv8k=;
        fh=fOBqYGHuRYaixw3JJKMZTTVx+EKO2KznsKaGJwN4FU0=;
        b=eZqJpfyaASRv8/xaYuMYyjgAnmbUV/KLnF3WVsDgqEPdfs0Otg8X3T6r48R0xwdDTC
         IFb++WEPSSX8zBjvZbWbr8CvJF/S04p4BkkacIj93LPTdjvsRN7UpdZkU88EXGmKpwLB
         /iKa5//LavTocVUPsrlpLTLdnDetYo++FhxqWHE8G4+iLymu6+y8zdChVqesJ82wV1gj
         QERB5/s436Q5YgL+RxjQKmFjnjdEz2svhWSMyX2FtPB6cAjhmes3REioIdKgAXPN78zu
         FaI8M9C7PuEvuIS2Br+WN35Wgs101HOZgnM19ZNp0anpKyakFbcTuC8LIGFLQ/JpZ3kM
         TBag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cLrDHk9L;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f5588d0cdcsi218827a91.3.2025.01.11.01.03.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 11 Jan 2025 01:03:31 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: IVey7uZaRbO5DwYUTp4cYg==
X-CSE-MsgGUID: Hgi37XBLQVay4DQp9XiWnQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11311"; a="47539401"
X-IronPort-AV: E=Sophos;i="6.12,306,1728975600"; 
   d="scan'208";a="47539401"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jan 2025 01:03:29 -0800
X-CSE-ConnectionGUID: oCQrinvrTZCo4PAjo8jItw==
X-CSE-MsgGUID: wYkb33BGSESFvAVOOYwQgw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="104829956"
Received: from lkp-server01.sh.intel.com (HELO d63d4d77d921) ([10.239.97.150])
  by orviesa008.jf.intel.com with ESMTP; 11 Jan 2025 01:03:22 -0800
Received: from kbuild by d63d4d77d921 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1tWXOo-000KPn-2r;
	Sat, 11 Jan 2025 09:03:18 +0000
Date: Sat, 11 Jan 2025 17:02:40 +0800
From: kernel test robot <lkp@intel.com>
To: Joey Jiao <quic_jiangenj@quicinc.com>, dvyukov@google.com,
	andreyknvl@gmail.com, corbet@lwn.net, akpm@linux-foundation.org,
	gregkh@linuxfoundation.org, nogikh@google.com, elver@google.com,
	pierre.gondois@arm.com, cmllamas@google.com,
	quic_zijuhu@quicinc.com, richard.weiyang@gmail.com,
	tglx@linutronix.de, arnd@arndb.de, catalin.marinas@arm.com,
	will@kernel.org, dennis@kernel.org, tj@kernel.org, cl@linux.com,
	ruanjinjie@huawei.com, colyli@suse.de,
	andriy.shevchenko@linux.intel.com
Cc: oe-kbuild-all@lists.linux.dev, kernel@quicinc.com,
	quic_likaid@quicinc.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH] kcov: add unique cover, edge, and cmp modes
Message-ID: <202501111600.ojBvC1LF-lkp@intel.com>
References: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cLrDHk9L;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted
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

Hi Joey,

kernel test robot noticed the following build errors:

[auto build test ERROR on 9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe]

url:    https://github.com/intel-lab-lkp/linux/commits/Joey-Jiao/kcov-add-unique-cover-edge-and-cmp-modes/20250110-153559
base:   9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe
patch link:    https://lore.kernel.org/r/20250110073056.2594638-1-quic_jiangenj%40quicinc.com
patch subject: [PATCH] kcov: add unique cover, edge, and cmp modes
config: arm-randconfig-002-20250111 (https://download.01.org/0day-ci/archive/20250111/202501111600.ojBvC1LF-lkp@intel.com/config)
compiler: arm-linux-gnueabi-gcc (GCC) 14.2.0
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250111/202501111600.ojBvC1LF-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202501111600.ojBvC1LF-lkp@intel.com/

All errors (new ones prefixed by >>):

   kernel/kcov.c: In function 'kcov_map_add':
>> kernel/kcov.c:309:60: error: 'struct kcov_entry' has no member named 'type'
     309 |                         if (entry->ent == ent->ent && entry->type == ent->type &&
         |                                                            ^~
   kernel/kcov.c:309:73: error: 'struct kcov_entry' has no member named 'type'
     309 |                         if (entry->ent == ent->ent && entry->type == ent->type &&
         |                                                                         ^~
>> kernel/kcov.c:310:34: error: 'struct kcov_entry' has no member named 'arg1'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                  ^~
   kernel/kcov.c:310:47: error: 'struct kcov_entry' has no member named 'arg1'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                               ^~
>> kernel/kcov.c:310:62: error: 'struct kcov_entry' has no member named 'arg2'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                                              ^~
   kernel/kcov.c:310:75: error: 'struct kcov_entry' has no member named 'arg2'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                                                           ^~
   kernel/kcov.c:343:48: error: 'struct kcov_entry' has no member named 'type'
     343 |                         area[start_index] = ent->type;
         |                                                ^~
   kernel/kcov.c:344:52: error: 'struct kcov_entry' has no member named 'arg1'
     344 |                         area[start_index + 1] = ent->arg1;
         |                                                    ^~
   kernel/kcov.c:345:52: error: 'struct kcov_entry' has no member named 'arg2'
     345 |                         area[start_index + 2] = ent->arg2;
         |                                                    ^~


vim +309 kernel/kcov.c

   290	
   291	static notrace inline void kcov_map_add(struct kcov_map *map, struct kcov_entry *ent,
   292						struct task_struct *t, unsigned int mode)
   293	{
   294		struct kcov *kcov;
   295		struct kcov_entry *entry;
   296		unsigned int key = hash_key(ent);
   297		unsigned long pos, start_index, end_pos, max_pos, *area;
   298	
   299		kcov = t->kcov;
   300	
   301		if ((mode == KCOV_MODE_TRACE_UNIQ_PC ||
   302		     mode == KCOV_MODE_TRACE_UNIQ_EDGE))
   303			hash_for_each_possible_rcu(map->buckets, entry, node, key) {
   304				if (entry->ent == ent->ent)
   305					return;
   306			}
   307		else
   308			hash_for_each_possible_rcu(map->buckets, entry, node, key) {
 > 309				if (entry->ent == ent->ent && entry->type == ent->type &&
 > 310				    entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
   311					return;
   312				}
   313			}
   314	
   315		entry = (struct kcov_entry *)gen_pool_alloc(map->pool, 1 << MIN_POOL_ALLOC_ORDER);
   316		if (unlikely(!entry))
   317			return;
   318	
   319		barrier();
   320		memcpy(entry, ent, sizeof(*entry));
   321		hash_add_rcu(map->buckets, &entry->node, key);
   322	
   323		if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_CMP)
   324			area = t->kcov_area;
   325		else
   326			area = kcov->map_edge->area;
   327	
   328		pos = READ_ONCE(area[0]) + 1;
   329		if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_EDGE) {
   330			if (likely(pos < t->kcov_size)) {
   331				WRITE_ONCE(area[0], pos);
   332				barrier();
   333				area[pos] = ent->ent;
   334			}
   335		} else {
   336			start_index = 1 + (pos - 1) * KCOV_WORDS_PER_CMP;
   337			max_pos = t->kcov_size * sizeof(unsigned long);
   338			end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
   339			if (likely(end_pos <= max_pos)) {
   340				/* See comment in __sanitizer_cov_trace_pc(). */
   341				WRITE_ONCE(area[0], pos);
   342				barrier();
   343				area[start_index] = ent->type;
   344				area[start_index + 1] = ent->arg1;
   345				area[start_index + 2] = ent->arg2;
   346				area[start_index + 3] = ent->ent;
   347			}
   348		}
   349	}
   350	

-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202501111600.ojBvC1LF-lkp%40intel.com.
