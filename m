Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJUF2G6QMGQE7UQHEWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BABDA394FB
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:19:52 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2b8fdf98b0esf9318161fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:19:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866790; cv=pass;
        d=google.com; s=arc-20240605;
        b=b7sN5dvQ0bQ+Wy2sHXtdkJNuFm5feUobbVVjZT96EqRrhJ4Y6jCQOWdCoj4FQzQXju
         4MN33T4SxbfxtzlRpUdDg24OOmLbKrjdhtbfj9JlFlY7kl3YMS6kv1H+8Z/M/X0MIifk
         bYhPMIoJNIt3g/a1LdrIAgThgnQl8puYK0ii8f3kOW6murL16ZFHP4KkrAK9zDjBuiZY
         9GyqEQyaMdgQyJb436mefkolH22AE6ohRN8a+M+NjOrFU6zn0y7MfuUOZw0l34YSXEad
         /yWbLevFMsfIw+EChUA0jle6YIl1FhQgjve8ssBxNIrT45uTx+k9XpDm/l1q4xzTQWhT
         Wddw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9ZULI9OQYZ2W/Yi2KV6IY3S3iBycmlyN+hsPoaXlwPA=;
        fh=4cC50+x6mTy+9t3m1cIPk4z9e5BQYgo1BA5Yz8i364M=;
        b=NWJ7zZMw2pXk0ZsdPSTSFb8wozvOiZigev2G4vNtZ1TJPmYgfqJ+ASJLOdEgijFmUo
         bhXHf9HMZxK+v6DIri7ocbtGJsDQ54HIX1uHJlgQECoUMbT99NKpLV/rc9ZGBjdoQ3bD
         NY8QQuNCejRcf/ePDMNspEhbGOOZQH5ZEH7guI+Xbc/ejnR0Nad/XuzVbNJ5fcmQVuGR
         t0u99+oJjuw8FiKIYDxssyfR6xR2OFhEbA1Nl8CLVLbQDLttOsDcB/GNvJC3xd/JjzY2
         d8fGlzPb9lcxYkXgWf4PkJO3cSYWVDWwfbAQNgNpY2a6xqUyrtsAcZO85B5NZ8o0pcP8
         CNiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ndc5y1eP;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866790; x=1740471590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9ZULI9OQYZ2W/Yi2KV6IY3S3iBycmlyN+hsPoaXlwPA=;
        b=CYa8PY1oDeHlpein2bg2x+mttMcvvpUlGb4sJ4LlNQYAmlG23+bQYFSMH7Xb24ttHl
         Wnn+hFKq6ngJntxXZxsvoCzVDaKXWYdqRdXBWBvMOYtRJiORg2rIhhLjz1uv88pXdEAH
         fjYF3N/kIkonuSiMLsnswpueA7l2o1B4wN+2ej/LX02mDufIYKFAVC0LSk+QSFyW+iRG
         kWqFq6rrDMkSLwCCDRTAp1QmM4GVrD2gw3D3A4WrGA8gq2g7nJUxQktoZbnLsQrVtUqP
         lBvqTC09BQYOeS1a22hEwf+/BUnVT12uGEl8KkOaCsL65IzSXyG8mFG/YEt0skgoI0gh
         1MBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866790; x=1740471590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9ZULI9OQYZ2W/Yi2KV6IY3S3iBycmlyN+hsPoaXlwPA=;
        b=fvosDUpOkg7/hKo9ddUlgnV15AK3NaH9gM7mpYE7EB41A74qEpJeiAHYiQgVHWnF3w
         tQDF9wRcefZkpAT0PrSYPVOa0y35i+4b9U7a9W/uWqVXm3a+ZPFFghbWLW7DMmy5hkEB
         Be0QUJkPld1BAuRAVtFaSL1UkOjgJS2ZwJMJLwxomYh07D7sNGVANlilbAH7txxzJy5D
         XyAsfgMo3NfWU7ACxcTgrYgVTbaOfO4Vcrp+YtXRr/fh5Hy593iCJeYewEpIQqWkbB6+
         +wKnwoPGL6KIF4RxQMBwlB+JNcRu4leFgLmTYngsvV2afcKMAZquMTjaoLkiO/wCyoCz
         oS4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZsbvZrdhhf1+wT5Us+KsHtoOC/VvneOvnQDmMPHSrpruh6AfTTvUJWCi/F5jBrBivImWFGw==@lfdr.de
X-Gm-Message-State: AOJu0YxiehoAm+Jq45D8ozclATU8FLbReEazsJ5Um725v3fSE3Snhcku
	Sp1znQ3GUsvypP++mNYrGgTLiUgy/vd+aOlxSkGf94V44mWs9JND
X-Google-Smtp-Source: AGHT+IGiC3Yn9T3ZQc1/C9tNAZ0Wrd3CnVf44hU+FY61lfoG1EQPa/oE5SY/hM9MUppPEDzX0oKZfA==
X-Received: by 2002:a05:6870:7a0d:b0:29e:5897:e9ed with SMTP id 586e51a60fabf-2bc99dddd6dmr8572874fac.35.1739866790660;
        Tue, 18 Feb 2025 00:19:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHtQIVMDHd7IlkuiQbkhF3tZMQ5saouHeYwuOAVSIjv1g==
Received: by 2002:a05:6871:210e:b0:29e:3655:1970 with SMTP id
 586e51a60fabf-2b8f7b29127ls2911861fac.0.-pod-prod-08-us; Tue, 18 Feb 2025
 00:19:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIO9Amo0qXWHQ9ObIJMYsDoYHVGXiLXC3eQc7qmG8aZbAECJi8PKp8Hq/jpFa6MfPuvqSjvMOCM6g=@googlegroups.com
X-Received: by 2002:a05:6808:1886:b0:3f3:d9fd:7ff9 with SMTP id 5614622812f47-3f3eb0b11f2mr10314023b6e.11.1739866789964;
        Tue, 18 Feb 2025 00:19:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866789; cv=none;
        d=google.com; s=arc-20240605;
        b=Kqn9YwMzocxUjNcCKaGbOGgz5Z1byBC/W1YKUhgCCR+xwmmJAC0UT/XV778LGnG/ip
         YYmhPm5J+19MYsMsxvK+rWTAHnQOMxuQEu9rhUq21NWUkp5+3d5SLsTXkDa80hi1wpWs
         aJBdLe7ysEpJHEEORX4kD3MJpG0ArnRcggPJ7OKq/LB0kfpL+AOxYDhtt4Sz7xlZv+3m
         PcNO4CLL/iuyWqPgyRRqxc5YoAuWJCrqFyDyyIHne8ZSId7JQN1BhKsyM5rLLV+7WMGh
         mIKmnQT+ZwsfBKS3Ix62BuVOd2oH6HOx70MSnefOJcsMk/U+1FVLX9PH2dyGlX2Fzqyj
         pogA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JU4QLoaDROMi+mjFEZexr7HHDWstJFVdYTBk7lWlpYc=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=JbhaVlk8rTBGdMkGIJ3dF+O8EtodpYUGMix4/cmm86iZyuHYC5VNO7KKp9RVzy9y27
         DiLnhCAgP7lDRlSKRq9gpRj2IP2osUFVbAUcwMQ+5jJ7LqblLWmDBhSNi6T8bku+Kvok
         D+gaVMseSCDgRWjsosMuaW/3kZ/o6LSouUwgSvcheeo/oOS1eLNr8s4+jsPUCco2Gxq0
         j+1aX/I7ugG+rklfb1jp89P8uNPTUR82cjkVXkvCFbPVErOdQ7DKLQzQtbIiXY3ALeoy
         8t91QA9ybSewodYeutGLpTDbIzxC5oCWzLtpOVsZYCxjdoWG490j45ypiib69uL7cDHB
         crYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ndc5y1eP;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f40bda05b2si11764b6e.0.2025.02.18.00.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:19:49 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: KgQ6raI5SMmz1XcID8ogxA==
X-CSE-MsgGUID: k93ecvfnRPaIIhANp75rxA==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150482"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150482"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:19:48 -0800
X-CSE-ConnectionGUID: IYj6E66YQH63xLaNCe56vw==
X-CSE-MsgGUID: fqGS+T4jSJq734ReKLPe/A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247941"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:19:28 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 11/14] x86: LAM initialization
Date: Tue, 18 Feb 2025 09:15:27 +0100
Message-ID: <e1a92159d657d1f389a8ee799a33ee2173098bb6.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ndc5y1eP;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

To make use of KASAN's tag based mode on x86 Linear Address Masking
(LAM) needs to be enabled. To do that the 28th bit in CR4 needs to be
set.

Set the bit in early memory initialization.

When launching secondary CPUs the LAM bit gets lost. To avoid this it
needs to get added in a mask in head_64.S. The bit mask permits some
bits of CR4 to pass from the primary CPU to the secondary CPUs without
being cleared.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/kernel/head_64.S | 3 +++
 arch/x86/mm/init.c        | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/arch/x86/kernel/head_64.S b/arch/x86/kernel/head_64.S
index 31345e0ba006..87158729f138 100644
--- a/arch/x86/kernel/head_64.S
+++ b/arch/x86/kernel/head_64.S
@@ -206,6 +206,9 @@ SYM_INNER_LABEL(common_startup_64, SYM_L_LOCAL)
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
index 62aa4d66a032..5499ba683b53 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -761,6 +761,9 @@ void __init init_mem_mapping(void)
 	probe_page_size_mask();
 	setup_pcid();
 
+	if (boot_cpu_has(X86_FEATURE_LAM) && IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		cr4_set_bits_and_update_boot(X86_CR4_LAM_SUP);
+
 #ifdef CONFIG_X86_64
 	end = max_pfn << PAGE_SHIFT;
 #else
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e1a92159d657d1f389a8ee799a33ee2173098bb6.1739866028.git.maciej.wieczor-retman%40intel.com.
