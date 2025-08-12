Return-Path: <kasan-dev+bncBCMMDDFSWYCBBK4D5XCAMGQECH4FIMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C9808B2286B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:29:16 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-7073cc86450sf95352946d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:29:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005355; cv=pass;
        d=google.com; s=arc-20240605;
        b=TiPkcUM+DnLsyArWbPfpCk4Xy2P8lIH0gIiHMrJsWUg5HA6a9htJlajuc/bN+K3jgS
         hxmVYYR1eI9E41hcJIuslj1ynfDIFc2LPctahohl2vaHON/4A40zZapScKa9NLlfUtzr
         I9M9aqqVP5Tv4lS8Ra2RnaXuP5o9s8DmqJ9s2xp2XPXpRo9As8llX5sF+xHTwLA1/f5v
         KsJj7riQcVUK7MgnGC3XXOB11XbKy+Wn8+aeayXOIdxr8wkkh+/g+VuPvZxjcC/bNJjE
         0RDnPDBhxyCjwDS98TKXKVRD/9c1xNC/SJvAA3RO2VthTWauSaMrW0dCD1Q9o9zAJDoY
         B3Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TWIqAaWoaGNdEYMrA/O2UyxAjYJ8Ac9ilm5IoI/o65Y=;
        fh=nVL6FJWho/BdUDsFllS9UBP7htRA+ShSM8S42HXWQWQ=;
        b=g+ryaoSr04zoXQ5kwTaWGfiltC8b4z9HiCh668dE/Y+rSDrAK+rmevqGK9LNic0d8N
         Md6KuUmoQbH1ntJkAAd9HKhQq6Mv8fp68JTrnxBbsOSjVGqMJSWcjAkB9ZBhZCYmi2YK
         F4dpQEnFh8GLKJkat/6coGDEqnsMRKObFFm4s+2fWgM127nN7H9ywy+OKY8mybZhQJtb
         qTHWBc7yriIlbQ9Vk6bKdMLS5Y1rDw6TxTvBNs3/qwvN/+LhoBVBRPxFxJhfZDrodyBh
         yGTPVNuH9ZhJdGSvUZyj44QApIyf8VmJ2vwO9jCEbr4p264yc07Vp/siRewSnZyXYFnq
         4qmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W1Jxq65g;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005355; x=1755610155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TWIqAaWoaGNdEYMrA/O2UyxAjYJ8Ac9ilm5IoI/o65Y=;
        b=OWGkgqe8HGqw+RZKBTVszyzN25TqZb/8hDsSe3yGA4h9TYJy3J07AxFaeNpZRCgOws
         5B/xEVhovxC8nxQhj72riNYhHrmZ09v/xvxwLeRYKFLum4hSWQZnha5qpgdUVOmZX7WL
         NkUuTNLOmmeTcYM6tagNHjplqJQIhBbN4U9CMadvYGvo6JetySkM7wfodiG9EP7HkU/k
         tm3jaB8uW6GwvZKr0yZ6stWzxCyEA51lfeItAzLPfAJytgom9LjKGQmGHUeyZX34ijdJ
         x+Ov7TuyBp2AOd5xJ3velPM8p8dryR84H+oTi1aZ5mAjVDhP4o2FMq+aw4n7029KVp3i
         Xe/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005355; x=1755610155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TWIqAaWoaGNdEYMrA/O2UyxAjYJ8Ac9ilm5IoI/o65Y=;
        b=R/V0ABkWmtqFR5/qyTDCdgmYo5lIBObr6ykNH8lHZucC1E4aaCIm947FdNu3naILrh
         ENm0Xq4rVxay33Vv5Ed+ZIiQyAWZOiZ5h1ppxAEldnZzFzcxL/ZNiorABKoXdJk7pfND
         riLNBZvhpbog+cZQEGGKiLB/v9gFNCheyK75APYnom02U9zdyh69oznZPih9dRMv53om
         DFu7ZMHvlQ8s2mBFUXZJtBFUyIFVkhEonQwPh7G/iPjTLUpIfkgdbmjBs2pE3KrhBRJ7
         pVHHFVEjcd1wPuMDFql/NOPEkfiDmFLVdV2smkwAA2evMvSdMe+b0jPJXX5JPacdwKQa
         ojpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXP7gzuL1qcAr4FumjR/QwiGWiuXG3l+AbAEAfNuJ/IwsCWmZab/X5idzvGqW1oloSs78kJhA==@lfdr.de
X-Gm-Message-State: AOJu0Yx+QvhusKT2ba4t6DqA2zMyxxrue7e9Mqd8McGa9gOMs6OdJhXY
	XaIp//l9QSUslbkIBeiTd3tHcz+Oze22ihtETLua43yOZT+yV0nZSKP5
X-Google-Smtp-Source: AGHT+IEl3R5YwuAggaTnU47gx0qkK2BXnc4Kkn/cllWtcmLcDoqJRJYU5fWJ51J85f4+77vyFEcxkw==
X-Received: by 2002:a05:6214:2343:b0:707:4aa0:2f7 with SMTP id 6a1803df08f44-7099a22a566mr259166096d6.19.1755005355472;
        Tue, 12 Aug 2025 06:29:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd37VZcm7o4ctTshcbX27FxhY04+HYNL8eCIFEC4vTuCw==
Received: by 2002:ad4:5765:0:b0:707:4335:5f7 with SMTP id 6a1803df08f44-7098809e338ls88873506d6.0.-pod-prod-09-us;
 Tue, 12 Aug 2025 06:29:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQSVG6dQL1W8o4BxV5BNizyFRapJHDyQFBRO23KiHb+kOxd97p0Nbp1d519vRnHIt3jftrf+DJMmM=@googlegroups.com
X-Received: by 2002:a05:6122:829a:b0:537:b2b6:e387 with SMTP id 71dfb90a1353d-53a52d9cb7fmr6613721e0c.6.1755005354478;
        Tue, 12 Aug 2025 06:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005354; cv=none;
        d=google.com; s=arc-20240605;
        b=HK9MCH/3V5VfT6DWKUGtvPmpxGbIQJ7aGSP1xjqEAdVDtKC8WLqFgqBtSznNd9fDsi
         Bxd2Hsu4zvzX0UdYbWwfjNJvNyjfq6eZTw+JgCiuaBbZplPTpsY36/p8/HYdmXJnnhXk
         QtYMW8mriLGE+EP1PlKDlXwe2UdbzOmZ6vAFspfTqjZd5ol9N2uFZjZjx8zbs3E5f4Su
         wfei8u3ZJrLvvpvRM9UAltxp2ijj/n/NzemBvycgrMSbgEqUfQB3+uzGqBVGQ93lfxFS
         /GNSqYKv93FUjjLJsF27SGehzjLpRjlQMmpK6PmdOZVZtnXs8tWUdg8Xu8tBbDu3UGJX
         Vm8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Vtq72QdDzuyXtvGk9IlmoBuW1v+doc629hK/mnAoeUQ=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=NqR0ooQIRAUbrG/aMElpUW8dzO2CdIRYjTDR+m0SUDzwF7I8vC5KxIazwF5r6pH+Mg
         q1o5ulotEvHZE2Wm02ffHtdUh4W+iCRy/fscXWA8uDweeKdmHL3/u2EHxtf/eofZ7weQ
         eFPM7io5h5csyUa6oabe20V+B35Q/kOtamvinG9gCUPYB0y6H/wp5FKvDqBg9/XxkLNC
         JWr5ChvfGWNfIRWAA0R4off7w1OZR441EqdXoORKVwia47bqDfomB/lxN/DA7+Mu2GnD
         ru+uU3p+ZAGDHs3BzVXE6wBxHxxUG0hVngxRE2LtYEr/NwacLxT41o+38iOpD+QU56I2
         CDzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W1Jxq65g;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b027ab2asi631604e0c.4.2025.08.12.06.29.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:29:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: jZZv+gJ2RW68j65jk5bkCw==
X-CSE-MsgGUID: By18k/+jQVqbh+6kywW4Jw==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903732"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903732"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:29:12 -0700
X-CSE-ConnectionGUID: QX9ghsjwQgadzn721t5Dqw==
X-CSE-MsgGUID: JxTTgOkVRwaxXFC7TVl+Qg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831554"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:28:48 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 11/18] x86: LAM initialization
Date: Tue, 12 Aug 2025 15:23:47 +0200
Message-ID: <94461b3ac97f13073c8db552f90952aa7edf503a.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=W1Jxq65g;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
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

To make use of KASAN's tag based mode on x86, Linear Address Masking
(LAM) needs to be enabled. To do that the 28th bit in CR4 has to be set.

Set the bit in early memory initialization.

When launching secondary CPUs the LAM bit gets lost. To avoid this add
it in a mask in head_64.S. The bitmask permits some bits of CR4 to pass
from the primary CPU to the secondary CPUs without being cleared.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/kernel/head_64.S | 3 +++
 arch/x86/mm/init.c        | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/arch/x86/kernel/head_64.S b/arch/x86/kernel/head_64.S
index 3e9b3a3bd039..18ca77daa481 100644
--- a/arch/x86/kernel/head_64.S
+++ b/arch/x86/kernel/head_64.S
@@ -209,6 +209,9 @@ SYM_INNER_LABEL(common_startup_64, SYM_L_LOCAL)
 	 *  there will be no global TLB entries after the execution."
 	 */
 	movl	$(X86_CR4_PAE | X86_CR4_LA57), %edx
+#ifdef CONFIG_ADDRESS_MASKING
+	orl	$X86_CR4_LAM_SUP, %edx
+#endif
 #ifdef CONFIG_X86_MCE
 	/*
 	 * Preserve CR4.MCE if the kernel will enable #MC support.
diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
index bb57e93b4caf..756bd96c3b8b 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -763,6 +763,9 @@ void __init init_mem_mapping(void)
 	probe_page_size_mask();
 	setup_pcid();
 
+	if (boot_cpu_has(X86_FEATURE_LAM) && IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		cr4_set_bits_and_update_boot(X86_CR4_LAM_SUP);
+
 #ifdef CONFIG_X86_64
 	end = max_pfn << PAGE_SHIFT;
 #else
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/94461b3ac97f13073c8db552f90952aa7edf503a.1755004923.git.maciej.wieczor-retman%40intel.com.
