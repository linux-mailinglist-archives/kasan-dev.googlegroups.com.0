Return-Path: <kasan-dev+bncBDJN7LGB5QHBBJEK5TFQMGQEDKPDT5A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +IVeFCYFe2maAgIAu9opvQ
	(envelope-from <kasan-dev+bncBDJN7LGB5QHBBJEK5TFQMGQEDKPDT5A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 07:58:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E1917AC5D3
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 07:58:45 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-47ee3dd7fc8sf5611255e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 22:58:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769669925; cv=pass;
        d=google.com; s=arc-20240605;
        b=T7buL6zYDFiKSMgS6sBlCY4rNc5dKeDW1Fpsrg1MNkA8nShR6SRb7sXFhNQWhZIc5D
         cuSW7076He8C6MKFx121I4n98ImS9ITKUZWqTXX540GWIGyfrv7np3Tb1QHRuEx/hurl
         KVNIOy+48dtyHtO90FJPDznj0XC4/OykIBFmfBTwSDr05HlDctZMndB8c9ke8JvUI309
         c8akju48NeKNUufsvt6mdDC+A+DJ43I87Anws054th4h67ne9Xvxqjf3kDaomT5xoB1s
         VZnVvr6/A+4gNfQ8OnSDCW3Pq1K3a7afVHi/Uunowsph1Jg/vAZPuH5apGtoNPyz74OP
         ayHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=V7nT9NgUaSnJiT8guyQJ7YaP7lCqS8bopLZjRz5tEHQ=;
        fh=+DZ6gvIvQWHZeG4xAnsZEzdOBXHgOI/yjcnORGKdph4=;
        b=S3Uqj0k/FLEPgu2Fk+LjOXNfn1dWr2n82SIjSWSQhlIYWxLMxu1bd8bIZbYxYuR1/6
         XqN82z/DyGCMDBYhBN7BwrPuacb/fmCXJZ+QUMM4K7yFVyOeqpE5r5TKx2JKe9AZKplY
         6R/D4RQOmorTIfPHbmyzonNw9SOEvyDJzWZiS7gBrNxw9FNK3zqRC/BZaj2ABLjY1z08
         GLkRiMwDSoQo6Lva0Nzvo00rgAaQAO9CvN0unXeT9roNAgc1ZMJTODMWQHxzWMx0MV7x
         s7rY8aUOdfEnnZQ5ibqg2KTaB0EaPsMPNehRz3yh6t8WALhZUBy6CnCx9RbAwu6TdDjX
         SKmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jOeYHVmm;
       spf=pass (google.com: domain of zhao1.liu@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=zhao1.liu@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769669925; x=1770274725; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V7nT9NgUaSnJiT8guyQJ7YaP7lCqS8bopLZjRz5tEHQ=;
        b=qpFyz/i0tKw4gs7Lx6n9QL1P4iI9irw8DKb7FwS3JLg4O3icllJWNgG9MiBDMIxFmb
         456+3Snv94jpJky2IFz3r3mwyVlYUjrcm4MOdjw0OAP734QeJk0j8KI3CpoQUZ0w71zE
         Rc7hKMtS8U4f6y0MWi6awAFj0pz22eOxjszSixWwkCwxfLfost9TDhS66tBRbLg6+dIb
         h+MawnNOBj3KT4p5avoh61Q1L5v9qdZJbOXM94LTpwhDmd8fqjgsJSN/1Gd5JulsUnZm
         YNCpD0R6432MEiinhoncHTr70V7TDqvD6Fv8KCEdVLeGUfpwxUPsJ0Rn0SRbo9XQh+BK
         NomQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769669925; x=1770274725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V7nT9NgUaSnJiT8guyQJ7YaP7lCqS8bopLZjRz5tEHQ=;
        b=ODjX690QEPkYpWsbFgq7z5MZ4xP3HtFat+yZOtO8l7ZKeGq8FNpnFFPzDYbbfceygQ
         LrANQ6qA4jyQ3JZDq+Rrnv9GxSaYsyT4kIQX968l0jEGt2ux5DHdBGuYRGVBlcK7bBt0
         /4SJuNtxoG6l5lmYtGq+8N0nCuZTEXk9NcqqttmuYPGyEDRTj+/pwww+JYX3VK5Sb+q9
         12zfQ79fcXBV9bUBoBFtyTWv65MhaQRR1b9NqpZKYD9FodAcjGilyQkTMDZVRdTzIaFo
         zUJ9RD8e8qoa5nb+EQgTwcqKaw0/I7zHmAqO/nmxRboSmCJHe/ivpJTBE7TKSOn4HyWF
         m0ng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzxODq/Pi3n3zbSl5ST54WY2CYe4SCZSgv/wVTvn0GebVSDTMZRDoEOmOuZrM5paiOzVZLjg==@lfdr.de
X-Gm-Message-State: AOJu0YxAHNR5dBF//2Qo330eiM1yr1vCqRS8uYXs7d8wDw9cMwCuFsd4
	G9mWRa38nMQ7w24QvWMNgOuhjOGiuxV94tZkDci6yLTkX7Wu62SNLrvG
X-Received: by 2002:a05:600c:450a:b0:477:2f7c:314f with SMTP id 5b1f17b1804b1-48069c3968amr98964305e9.10.1769669924578;
        Wed, 28 Jan 2026 22:58:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E6s6KBGOVMOpZpahHubSUyBnM8BP229o02+6aNH1j/FQ=="
Received: by 2002:a05:600c:35ca:b0:480:6ce4:66ee with SMTP id
 5b1f17b1804b1-48157682992ls2356985e9.2.-pod-prod-06-eu; Wed, 28 Jan 2026
 22:58:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvl1npxSp4dbOZE5y4QtASkZFtJGHXHuEtFVthUx6XXiX54m7PIhOqcD03RQ8N1MR195sfgUkMPpE=@googlegroups.com
X-Received: by 2002:a05:600c:3e16:b0:477:9b35:3e49 with SMTP id 5b1f17b1804b1-48069c2c0bamr94506605e9.3.1769669922387;
        Wed, 28 Jan 2026 22:58:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769669922; cv=none;
        d=google.com; s=arc-20240605;
        b=KeEZRBdR9gtZPL5KkKDOHHr1hTw7uNtHOME44+WjXYUCfO1gmPetMw8/kHdDzYSeOW
         9TKUvFwZPCbWGnV8pn/YxyZf1D5kMjKEp4G6R3HhYt2lLIJeU6v7y+TrZW9OFGlIN5VE
         pY5G5Wht/YsL3XO9ppJ2PQoimzNxe0qCUsBdY+qwrkfotF18WdGDMlILbmuir5q7R2rD
         gJJ1UZMefx5HC2q2Kp25HsChaU8HQSxCBGzdqyppN1od14xQewiSnR+NSpzawXAs+9ts
         P6gbbusB1zCw7RzyHv1iOCaX33UDYRkgnSVIO65bwg6nAd+mfriV8pD82HeBig9EEr+2
         F+qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=amjRWMpaEMjLDf3MZKS4cBxTUgjJdzny4u+rmxhl3fo=;
        fh=KwC7Jum6N/o025Yv5BbBtrdUqOkm0+yynzCyRrsFo/Q=;
        b=Xp9VSdLaln1UMUPNmy5ilBbLLTTaXOpyNzQly3aY8znOUtoiKbajymnykzNwSge5yl
         B7qdMurD3Wb9QqN002P4uRJaBsa17J12A7mrvYSSYuACeh3jauZn63wa6ZbIVnZjy1oj
         PfnWkn5U/pOXl1BeYEWwhP9TKw2IRcWZTF4RMauAHkmZebqP72MTlbFuXROw99pyP/g2
         Cya9rz4UxPG2PSJKAg6/AUyT2Al8q/3PVF+o7UA1Do1HPd6JVjDpkRmr3MhhArVSWE+w
         grwrlsfTcgCgj/2cbvhL0fZrQb85+mv62tAEbiUl+KnAZebtAl6RffPAYDkLJnG69413
         G5MQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jOeYHVmm;
       spf=pass (google.com: domain of zhao1.liu@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=zhao1.liu@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-481a5cc9c0asi25865e9.0.2026.01.28.22.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 28 Jan 2026 22:58:42 -0800 (PST)
Received-SPF: pass (google.com: domain of zhao1.liu@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: 9NaCUKNvTySie6GebyiXAQ==
X-CSE-MsgGUID: 74xxEg0fSReuL7JLmwsV0w==
X-IronPort-AV: E=McAfee;i="6800,10657,11685"; a="88472765"
X-IronPort-AV: E=Sophos;i="6.21,260,1763452800"; 
   d="scan'208";a="88472765"
Received: from fmviesa004.fm.intel.com ([10.60.135.144])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Jan 2026 22:58:39 -0800
X-CSE-ConnectionGUID: Ph1sbCvuRqGMBhv8WnM2IQ==
X-CSE-MsgGUID: DLGKmnjlSyqn8GrIn4Qipg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,260,1763452800"; 
   d="scan'208";a="213360551"
Received: from liuzhao-optiplex-7080.sh.intel.com (HELO localhost) ([10.239.160.39])
  by fmviesa004.fm.intel.com with ESMTP; 28 Jan 2026 22:58:35 -0800
Date: Thu, 29 Jan 2026 15:24:27 +0800
From: Zhao Liu <zhao1.liu@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hao Li <hao.li@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Message-ID: <aXsLKxukv60p3QWF@intel.com>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
X-Original-Sender: zhao1.liu@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jOeYHVmm;       spf=pass
 (google.com: domain of zhao1.liu@intel.com designates 192.198.163.8 as
 permitted sender) smtp.mailfrom=zhao1.liu@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.61 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[intel.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDJN7LGB5QHBBJEK5TFQMGQEDKPDT5A];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[zhao1.liu@intel.com,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:mid,intel.com:email,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: E1917AC5D3
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:44AM +0100, Vlastimil Babka wrote:
> Date: Fri, 23 Jan 2026 07:52:44 +0100
> From: Vlastimil Babka <vbabka@suse.cz>
> Subject: [PATCH v4 06/22] slab: add sheaves to most caches
> X-Mailer: b4 0.14.3
> 
> In the first step to replace cpu (partial) slabs with sheaves, enable
> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
> and calculate sheaf capacity with a formula that roughly follows the
> formula for number of objects in cpu partial slabs in set_cpu_partial().
> 
> This should achieve roughly similar contention on the barn spin lock as
> there's currently for node list_lock without sheaves, to make
> benchmarking results comparable. It can be further tuned later.
> 
> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> even for !CONFIG_SLAB_OBJ_EXT.
> 
> This limitation will be lifted for kmalloc caches after the necessary
> bootstrapping changes.
> 
> Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
> recursion with kmemleak tracking (thanks to Breno Leitao).
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slab.h |  6 ------
>  mm/slub.c            | 56 ++++++++++++++++++++++++++++++++++++++++++++++++----
>  2 files changed, 52 insertions(+), 10 deletions(-)

vm_area_cachep's capacity seems to be adjusted to 60 and
maple_node_cache keeps 32 as the args setting.

I still use will-it-scale to evaluate the impact of this patch, and
performance results appear to be on par with previous ones (*) - doesn't
have regression on my cases.

Based on the results of previous capacity adjustments testing, I think
it shows that the capacity of the maple_node_cache appears to have the
significant impact.

There may still be room for optimization in maple_node_cache. As a
general-purpose algorithm at present, I think it has achieved its
intended purpose based on my test results. So,

Tested-by: Zhao Liu <zhao1.liu@intel.com>


(*): The previous ones include 2 cases:
  1) w/o this series, and directly based on the previous commit ("slub:
     keep empty main sheaf as spare in __pcs_replace_empty_main()").
  2) w/o this single patch, and based on the previous patch 5.

Regards,
Zhao


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXsLKxukv60p3QWF%40intel.com.
