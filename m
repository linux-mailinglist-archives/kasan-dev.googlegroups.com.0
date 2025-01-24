Return-Path: <kasan-dev+bncBC4LXIPCY4NRBQEOZ26AMGQEO7PD3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D642A1B5EB
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 13:27:45 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-46dd301a429sf39540861cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 04:27:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737721664; cv=pass;
        d=google.com; s=arc-20240605;
        b=R8+d3O+6p7PIZ2DngHBwNaDtuyuD1zR0gWsilQYkbcl5gCJJ/wb7oifib0DwmjjGEc
         0oqvxXx7i1L8H0e1p/gX78sG0cwjhxwvOHGkQ3i6+6EBw4g2GJVChQk/sWSMUYRnoUl/
         63D8hlh0HUpAWwDPNDDpyBq3qJh7ovB3TZUptTRr2iRetihru1ZjggfeIjcSdQxtpckX
         5BSUZ0AQSQMLuzfbThtBXKl0anaJtOzLjUMCG48F1Qo/+q9MYWqqPPtgR2DV5ErMEx/k
         rweBkeYTrdvxFVv0i0qngMCSSE0m9Z1mHhjruTkXSaVUe/t4s5xuyFdrUK5XNbuhzBaf
         oWaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fwAeB28M0j698jGv0TGsOr3fVkRU+GzFet6l1w9kZyY=;
        fh=uujcKmJWfzIQSvHRmEDAjeWgbKfCiyJquEgatd9X3/4=;
        b=jqXS6+BfiMrk4obBYwqtc7VpKkOEJ45lDYuO0S3V35j4FLf9ZVcFHKeKfJgShN4g3c
         Hl6zOEhLHBOJ9loGr7AGbAeyjJ8MBXwTmGncE5+R/f62lqe1pyKpaSe1PHpIgOnvhK1n
         amq/PiGnii0qrNBnc+GyoLR1HKkTJQU83jvFkc+Y/ZuuOhboX4jikfnRjWLlmlqk5J6z
         UCdlRPrulOWW3OZ0MC+3Trpra0nLwYQ/AGtgBGhjj0/P++hEOI1svL0Mw1Wg1bcYkUSW
         mwop+bluYRsYM07fm5qVIW03ZElZuifnxgeDRzjZSuLD4T8YwqavtMIH4plI9D54OlDe
         QypA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GuvECqFX;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737721664; x=1738326464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fwAeB28M0j698jGv0TGsOr3fVkRU+GzFet6l1w9kZyY=;
        b=YzaIHPX5fKqHF0OgZS0TJmcvIUa/q5C83PfgMROX+GfcOrD4TBqWOFMQcfLGn2afAg
         /n0c5eKOLHrrRb7Mab/YEloYJ5b5AlvQxi+PYq8yFc76w0BVaHp+PVfjWdCrb0xu8sOd
         x3xdWTYsEUL6zS4S6ETpgr82c7swpZgu82WuyptauxIjmVn43AYPZRdd8sTOdGb1VcrX
         FKL7LWDpikaR8uCmHTKY3m+rQpgsm6mOUE6Vd1g3f3Vz87Ur14NiQ6uCinAzi6vjfv+U
         IK1RODBxPJJV5jzQ49MHAoe/+HjEPwxwwe9+8yKUbmfsuaasPhocrateSdN3aVig8XnD
         p/8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737721664; x=1738326464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fwAeB28M0j698jGv0TGsOr3fVkRU+GzFet6l1w9kZyY=;
        b=ieN/mCYemP3nV8RMnJoThj0OOJjk7QM1Vmr3ZcPaT3XQYb6mSKfzBrncEgx/YmTAdL
         itJWk105W/OqENrw+ltYnY2vF/4CGFa+E1XgHTR3E8TWMmo10+iSfGsyJ2BrrEDoMo3y
         NAiOc0swbJcvcxv7gdmGbdQ0IrnL81MWEE2CbeHyvNj69Y9sY7J3+m2fDJKA/u0PDSJO
         ivU+wli7BElRRb1+3xBe6IGwMyHPxggVL+sZxwuwhsHesbpnVO81TsYHBfkUUNL7riYD
         snGAr6TyGrBZoalnqzaFXLKh3SA1PjZ9hr1Ydy8qrJd5ZnK4iGw2WzdwVWUvWawEySwx
         oUew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFdO3czEmO9Ulbqj9y91VEsQ3kYWY+aw87dXmqbnxVJQ7lKn1wguGqSPTm+5Blf4QN8XQw1w==@lfdr.de
X-Gm-Message-State: AOJu0YwijpFBgoyP+YJaC8SYgvbdFTFPwG2JhUlRDZffteaUERLmxFo8
	dLZKM0hb2fOAIntO0SbV7LLJyw8dr/+mi4GIAPm+XOk1Epagu9n4
X-Google-Smtp-Source: AGHT+IFUYgTkZ4Lh55Egg52WtEXjKSRe40lj1lgaZZJixiX8JvvL58cKTpJ6FBuCAnj8Wm3O3W+pCA==
X-Received: by 2002:a05:622a:199b:b0:467:5367:7d09 with SMTP id d75a77b69052e-46e12a582c3mr496973161cf.16.1737721664344;
        Fri, 24 Jan 2025 04:27:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5b0c:b0:6d8:89a6:8447 with SMTP id
 6a1803df08f44-6e1fa15c963ls4810086d6.0.-pod-prod-02-us; Fri, 24 Jan 2025
 04:27:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWtIZaaMyDKFW228dgs7wXwKrN1DMlVVRNOKPgGKGOk90n+HPTNpAZL0ao4fHAH7MlSx6aqXAedVSU=@googlegroups.com
X-Received: by 2002:a05:6102:5043:b0:4b1:1a11:9628 with SMTP id ada2fe7eead31-4b690cf43b7mr28034146137.24.1737721663592;
        Fri, 24 Jan 2025 04:27:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737721663; cv=none;
        d=google.com; s=arc-20240605;
        b=RZkOI+de3gkoljbQChgrOPE4FTxqWy/0OBVXGDQiC/QoLAUPqkqnsIbhxRhsVCxu1c
         GKmz3y2yCyYtBdHJMD+DpZewmknM2sqDGa62SOnpbs4lJ+ss9elj1y4cAbNCRMSYqHzM
         +wb16yQngKM6n4nPsmph/TtmSiwVl9FTroO8KNeYjjp8SEmHJtqFZbO5cCw8+e/4V7fA
         xl8hk8oycxZIp9OXG8Lf1tgtkjX8ywtfueEJ5Dj0xr/ZeWCOtsU744b5XvzzNzYRwarB
         AzuX5967HWh4dNqyVm9dvLTKehXNRMT0638+w9NCbh6b9OvMyAdlCHaWOhAxpDOjjAeO
         dfsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=U4t1qrmSWuyCgBrcgPjWCCn3uT3usz5k+UseZyM1xIM=;
        fh=kO2Wz6azUdraqHit+LrwOS06I11zlrWkPQZKBqMuKeU=;
        b=S9+buqFdt64MiMQ93sG0cIKHJTZO6RkMBI+UnL0rzOU4+trts63EizOjssY5hPJo0D
         0YekIwX3AOwK6swzKISVmj2M9UI1PXREv+W3vjpeQyXhAshWTss6MzWGGHkeCdKQluM0
         OKf2t97R0jkN47mUtCbUVrJPbbmiz5wSdPXr7sRWXwKTpuVO+tZAjemmyLEftEJ76jkB
         jQKId/YUjgY2aO6MTlrA+N1Cei8cGjqWQQ9g57fbVATb39jj6SxM7pzu67HphCGfT8o1
         8/1GeuwwOXBVGL701eiWXG+clp79aBpQWUPi3/ioocT+2GK02DQDI469KJO3mOd0GI1S
         8k+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=GuvECqFX;
       spf=pass (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=lkp@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-864a9b3afdbsi61308241.1.2025.01.24.04.27.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 24 Jan 2025 04:27:43 -0800 (PST)
Received-SPF: pass (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: yGpcTc1WT9Gbn6A2iOT1oA==
X-CSE-MsgGUID: Sa/8ODePTBKnpZKnV7PsFQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11325"; a="37458576"
X-IronPort-AV: E=Sophos;i="6.13,231,1732608000"; 
   d="scan'208";a="37458576"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Jan 2025 04:27:42 -0800
X-CSE-ConnectionGUID: TcKqrqbOStiT63Vx3rUJ8g==
X-CSE-MsgGUID: 5YTnTvwzTZiG18df72xk5Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="112390003"
Received: from lkp-server01.sh.intel.com (HELO d63d4d77d921) ([10.239.97.150])
  by fmviesa005.fm.intel.com with ESMTP; 24 Jan 2025 04:27:38 -0800
Received: from kbuild by d63d4d77d921 with local (Exim 4.96)
	(envelope-from <lkp@intel.com>)
	id 1tbImd-000cfL-38;
	Fri, 24 Jan 2025 12:27:35 +0000
Date: Fri, 24 Jan 2025 20:26:40 +0800
From: kernel test robot <lkp@intel.com>
To: "Jiao, Joey" <quic_jiangenj@quicinc.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Cc: llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, kernel@quicinc.com
Subject: Re: [PATCH 4/7] kcov: introduce new kcov KCOV_TRACE_UNIQ_CMP mode
Message-ID: <202501242043.KmrFufhL-lkp@intel.com>
References: <20250114-kcov-v1-4-004294b931a2@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250114-kcov-v1-4-004294b931a2@quicinc.com>
X-Original-Sender: lkp@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=GuvECqFX;       spf=pass
 (google.com: domain of lkp@intel.com designates 192.198.163.19 as permitted
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

url:    https://github.com/intel-lab-lkp/linux/commits/Jiao-Joey/kcov-introduce-new-kcov-KCOV_TRACE_UNIQ_PC-mode/20250114-133713
base:   9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe
patch link:    https://lore.kernel.org/r/20250114-kcov-v1-4-004294b931a2%40quicinc.com
patch subject: [PATCH 4/7] kcov: introduce new kcov KCOV_TRACE_UNIQ_CMP mode
config: x86_64-randconfig-001-20250124 (https://download.01.org/0day-ci/archive/20250124/202501242043.KmrFufhL-lkp@intel.com/config)
compiler: clang version 19.1.3 (https://github.com/llvm/llvm-project ab51eccf88f5321e7c60591c5546b254b6afab99)
reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250124/202501242043.KmrFufhL-lkp@intel.com/reproduce)

If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <lkp@intel.com>
| Closes: https://lore.kernel.org/oe-kbuild-all/202501242043.KmrFufhL-lkp@intel.com/

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202501242043.KmrFufhL-lkp%40intel.com.
