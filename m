Return-Path: <kasan-dev+bncBC4LXIPCY4NRBTO7RS6AMGQEGVTDA2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 00A7BA0A706
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Jan 2025 03:58:23 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-29e2bd938a1sf4443531fac.3
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 18:58:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736650702; cv=pass;
        d=google.com; s=arc-20240605;
        b=iSV9I2zobv3uyDH9DeyGNgop9Wvj4PV3FwX0m6mgVV4JMoXRGRK/wPaPRgyFoMtITU
         AYrvS+ANBd+vjfezzHdeYsx6ANuCxg/EFvCuwoF+auf3GcwXy659OQ3094KpNmlBTftH
         rxqVzTIFH3RiipkmoUWp4tJgcSTB4D9AAyQlCb4N7aogRMYgk6RJOZ/U4B5MGr/unJeC
         NdYIycalPXHfyLqkGR2oi0kmdBifOMNOOuM94SCTA6pOPZSy1T+PnpvA9lmAml4a42A5
         Cybwrc4fnTCoogiHRQ3eI/FAD9tQR39597dHtxiwGv+VNgQjlt/S71R6qaS09z1P4NE/
         s3Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hlylj2vytrM0CuqtYN+5LoRTo8r/0KXjL5N2wIFCm4o=;
        fh=uXIEKIlqn2/ZD1H6Ko1tain12lpCDSeaMEcxOaVMwII=;
        b=k6MGQKn3i4nnedherHhaCLCKMTDjwFMccTgGU+qt/F6p/OL9gnFZ9fLXtbFs8l2ywK
         LJ1/t4LWV4Dm3b0VaXuq9YDiNdy31AgYhnO6EJ2sPzMQ1iNxUWNFafaqSG7BSZZtndZR
         PrvEBr6JEywMPkIwgdkAcgbvqs7QjcaafP10B9Yg29FO8qQiqrGfT8/CWm9zfg5sbXNg
         ptkkAzE+n4le+JAWeQNKyaaOIJ0hUnS9ouFRyDHcVO7t2le5F9V3KCDM6k33m+4qmuh1
         t1JUGgJIvLGZyLidN9EaLeGqyTN9v2b2k2bbwLw6wkfMcQNbYTdE7s8UH+mMCDYaCo5z
         r8tA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="blTn/G0/";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736650702; x=1737255502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hlylj2vytrM0CuqtYN+5LoRTo8r/0KXjL5N2wIFCm4o=;
        b=lnsowIPU4T29UoXYC/GnecAy/PJi8pZ6rnFW8m29iiU45+aH8+p9cf2xNtxhcL+vM9
         gMlSCrgPeYhFp7L2cT4JphM+q3xPYyvtoCD+z4oKW4k9dL9xSErTweJAkfShOcCXE3Fb
         Zo5S11WHYX6lXrZ253J0SNRn3AQBxymm41ggFYroSYuXia8yWusqb214vJfi/s0HLWhm
         45sifZJyh/8Ac4M33cUEuT+JRpcZfhRRpWOl/agdq3s0lOgyPOq5272ve0mjtfzyqZDp
         sX6xmR3RNbvRKB5YBExEHqWLyKbv7gbKjkhTqhUIodlHumijxziyQSyrbMJI8T4GhDUF
         4UeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736650702; x=1737255502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hlylj2vytrM0CuqtYN+5LoRTo8r/0KXjL5N2wIFCm4o=;
        b=i/5xkbwXUj6/qSrLSVubKX7Wa9KdEB611flc8066Qh6CXb6C7gtGl+MyZEcTV/bV5A
         WZTTySYMlG4RbObr4+4AonmMQPfYXj8KwZD6PQCEnvhJ2BdTT6gyEPaC1CuTOPcYq7ss
         SQdVy3xMLVL3eVUqJzJa8of7XYAE8ywacEEgPQrltTi0gn36h8APzZkOaXqxIOdvPhOh
         +SshidT+qkiwjIkrdZGYBmtxqG2L16R8zupFuczp2KsJoBMd0Wyw0oYExSOmWJekmWYI
         YhQ3EZm0oKHbeGtSyuDoBOWXTHuI5yMxo2/+hVQ0fAK6TNMQ/sxw17kHPz1iAnsZEYjX
         G4Ng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4+6FPqhXu4PQ3/rzGZTKI5yqe0C7JWe85EmDUPJwMWqBAEwpNFvf7Q3ivykL1/8cBjSAb7g==@lfdr.de
X-Gm-Message-State: AOJu0YxBylsGErtDDqHXXMXkj2CXQGQikoYVkkgK0oUbsUmk/heJfqnu
	EpQ40eyVqTEQUZh+v6JJtz+PCuF8QaQRP6pxN9LKqXJBGmjHEmUN
X-Google-Smtp-Source: AGHT+IG9PH/Qux1EuPw5SJo9gvPPJapIiJVUssoQTDCi28Nn6a9jKqRG83A40MBGkfM8XX0R7Helfw==
X-Received: by 2002:a05:6871:8083:b0:29e:5a89:8ed8 with SMTP id 586e51a60fabf-2aa06687b11mr8625836fac.11.1736650702326;
        Sat, 11 Jan 2025 18:58:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ad93:b0:29e:3655:1970 with SMTP id
 586e51a60fabf-2aa8a43a37fls1386189fac.0.-pod-prod-08-us; Sat, 11 Jan 2025
 18:58:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUEkL/3cMTI/6NzvF6YIdOM40UwmWTRkLA6A+VOD+6ip9NS8Dn9ZXsuqAgdGV7edVlglxSit/LcIHc=@googlegroups.com
X-Received: by 2002:a05:6808:1301:b0:3ea:4bcc:4d9b with SMTP id 5614622812f47-3ef2ec67c24mr10466781b6e.18.1736650700543;
        Sat, 11 Jan 2025 18:58:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736650700; cv=none;
        d=google.com; s=arc-20240605;
        b=kZUyE1OVw91QlYw13st1kdI4RFi3Fwtorc+/yqBXsSQ8UlG2wscCbSqGclABpN4Ckb
         qooxXBEbVEJOoMzZtBkAFwIY/3lj1Ctn0VlLcS3JWx9iTE5YKOnmb5eyX7kKqCDCCKc0
         LCDJ9htqAvDkA8J9eU5M68DipS/Gggqldir6dlVzUAFHQwmaEC60b4PEtNB87WwvIFEV
         bTDY7TaDZoqRf4/3ghD6O6JHaOjGZqWTK+OgHvggyZbhj0+7d/cuic9sCQ0EqUxn4Fle
         daRysszi0ICn86oHPxY62gmM4WVv1qDlEe4Tp68lTm4c0Zo4HzsiQVj7EfO0wrixlGyK
         l1nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nktFJcOtaVX8NVdbE5/yFPnZAwpR5/5dm34yZRTL6YY=;
        fh=ENHgzHJbTRneMaJ2xWF7Y25CtpwnWejydPVMA8VjUw0=;
        b=KX04lssmZRMz1KRyb9w29iVqO5V2Gyp8koDcWjUlsqzSpnZcXHR4wp2rWT5czMmNF/
         bbhobJ60GJ/NQ2paCUq1CebVCpbJYyOf+EXkmrRFurqdoieZqcE+lT+X1narGCSQvN8a
         Q1zKP3EBIutJ99zEcpDLd6QEI3RxePveqOeH36xNMcMnt9gt+EWH749EUwDh5MOEQK5E
         K57+fGESqhw6BIha30wRxN9zQje91siPdQ+RkbSgD5cERMFD1s8OZ1zgl2T6ruFGIiYJ
         Wm+A4YQD8rXcBvpXKYjNjjQrEAv7XyT0tw796t25V5H71rFoAPmxy4E9hp0cK1iSwHhS
         tXXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="blTn/G0/";
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f0379979ddsi246486b6e.3.2025.01.11.18.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 11 Jan 2025 18:58:20 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: Ax29zqc3TwCkySdnRWgmNA==
X-CSE-MsgGUID: py9AO9AeTVaPNlKgIhlsEw==
X-IronPort-AV: E=McAfee;i="6700,10204,11312"; a="47567873"
X-IronPort-AV: E=Sophos;i="6.12,308,1728975600"; 
   d="scan'208";a="47567873"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jan 2025 18:58:18 -0800
X-CSE-ConnectionGUID: 9W+LehN2Q+ybaFdfBxKJFg==
X-CSE-MsgGUID: Ji1haj5NSwahhisAC/YH0w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="141387404"
Received: from lkp-server01.sh.intel.com (HELO d63d4d77d921) ([10.239.97.150])
  by orviesa001.jf.intel.com with ESMTP; 11 Jan 2025 18:58:12 -0800
Received: from kbuild by d63d4d77d921 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1tWoAy-000LVl-38;
	Sun, 12 Jan 2025 02:58:08 +0000
Date: Sun, 12 Jan 2025 10:57:26 +0800
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
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, kernel@quicinc.com,
	quic_likaid@quicinc.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH] kcov: add unique cover, edge, and cmp modes
Message-ID: <202501121036.JNteuRXG-lkp@intel.com>
References: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="blTn/G0/";       spf=pass
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
config: um-randconfig-002-20250112 (https://download.01.org/0day-ci/archive/20250112/202501121036.JNteuRXG-lkp@intel.com/config)
compiler: clang version 20.0.0git (https://github.com/llvm/llvm-project f5cd181ffbb7cb61d582fe130d46580d5969d47a)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250112/202501121036.JNteuRXG-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202501121036.JNteuRXG-lkp@intel.com/

All errors (new ones prefixed by >>):

>> kernel/kcov.c:309:41: error: no member named 'type' in 'struct kcov_entry'
     309 |                         if (entry->ent == ent->ent && entry->type == ent->type &&
         |                                                       ~~~~~  ^
   kernel/kcov.c:309:54: error: no member named 'type' in 'struct kcov_entry'
     309 |                         if (entry->ent == ent->ent && entry->type == ent->type &&
         |                                                                      ~~~  ^
>> kernel/kcov.c:310:15: error: no member named 'arg1' in 'struct kcov_entry'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                             ~~~~~  ^
   kernel/kcov.c:310:28: error: no member named 'arg1' in 'struct kcov_entry'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                            ~~~  ^
>> kernel/kcov.c:310:43: error: no member named 'arg2' in 'struct kcov_entry'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                                         ~~~~~  ^
   kernel/kcov.c:310:56: error: no member named 'arg2' in 'struct kcov_entry'
     310 |                             entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
         |                                                                        ~~~  ^
   kernel/kcov.c:343:29: error: no member named 'type' in 'struct kcov_entry'
     343 |                         area[start_index] = ent->type;
         |                                             ~~~  ^
   kernel/kcov.c:344:33: error: no member named 'arg1' in 'struct kcov_entry'
     344 |                         area[start_index + 1] = ent->arg1;
         |                                                 ~~~  ^
   kernel/kcov.c:345:33: error: no member named 'arg2' in 'struct kcov_entry'
     345 |                         area[start_index + 2] = ent->arg2;
         |                                                 ~~~  ^
   9 errors generated.


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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202501121036.JNteuRXG-lkp%40intel.com.
