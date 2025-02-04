Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZ5ARG6QMGQEOWAHEOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 86E2FA278AC
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:38:28 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3cfb3c4fc77sf80605ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690663; cv=pass;
        d=google.com; s=arc-20240605;
        b=cKP5zHOvj7hP5tzJJd/cjJ2cg080Zm293llWQ5DaJ82Q3maPYURjZUh3zKCMmLF1Sr
         F53o+ZdvB6rsFOccykdXiSxXSo9zcfoykzp4eTtoHxul2LA9OmcDEvMGHmqg+p+nXMJt
         CJlPMSl3fWfUQUZAen49Gb0knpbO17F4PTubwVDA9fdun5uu15QgXZcmWYHA7vL/ZMCv
         cO31vmJqXtLofhXpYtfuRaGC0GmsvQhFc9cgLhv21dmbvYVKrOGK16R64sr1RI2I0KUT
         35PdsDqtgZnWDybixxZuleje5avTaUKRwnXhTFki7c1NVwf4b5plUVVSg9nZVteLv5MC
         20+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E+bE7ZzMU33DhoA7OTyOz/tVAM8BOwDDMj6PBcyKGHU=;
        fh=66GeZv3XNKYCgS8MnjERXQsMyENaJa0cqg8eJ9gO+qw=;
        b=BJR552FmKHp+j3stZp61RXdTDT+N9FlsstG6mU9mPV0DNNwyDrWHMRe4LkqaUsFQbY
         YDvlIrW7aFL5uwzcDSvMk6L+Yhn+wykiMu+5JMHr+zPirOKeGq1QENBE+3GeydxMCT9y
         KPqA4quY7OcOo5rolr+frcZOwQWWRO+U9Ex6hrbh6HGHbD6RQ4FElkx6bPO3m2vpikjt
         6Qm2ruj6CkLf1Z2bYTrowr5qPdaPOv7NUJh1HY99gz2Dkug+IzHW8VI8Rq6Qjp5M44ys
         T8cVvMP+S5HgXpZGRgL2RcydlATnEDZdmR9efht+HsxZ9PLPCdHIfgxfHmG52immSX2d
         z7Xw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=F7XPcWxS;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690663; x=1739295463; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E+bE7ZzMU33DhoA7OTyOz/tVAM8BOwDDMj6PBcyKGHU=;
        b=UUourKHwDaImPltbepMSlIvOmT6bmfk36gst6tUWhBOXIb72+/qls1xX2AiEzyYYe8
         UhvhBMfROvneioOTlZi9XyOSSVrDSN9LCTqOsbQibq25o5XFOkp1LeuIBTOrKhmGJ5/k
         g+MC7ORRrLTVlzfMtTgtJQ9ItgZLysTQaooR/N/kjC4ve2Y4U2+1SN4JEks1AhwkFWBK
         fdDDuEA99cHyLziIZcv4O16nhOhDKOHs2nkDOX5Z/lN+BGlhjBipCpCtwj4Yuy5l8Dbm
         14EwkinEtoYIWJp++fH1Bfsl903qiPo3Y2Uk5k3MmYcZOrbtP6wRx+7dDncTguu1fGl1
         BLZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690663; x=1739295463;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E+bE7ZzMU33DhoA7OTyOz/tVAM8BOwDDMj6PBcyKGHU=;
        b=whtizVYI7QX2uENWZeVlNZ/G+RxIKskxoP9MXK7+wxHJ2DE1l6pFnB6FZ7Zw/hmBbg
         Jj7TDTyA/ejyE/fO59INg1HWOW09VWHvnYmT18NxbgfJvb6bqs/UO/wabKfZdjKaM5GJ
         PhitU7jDIcesNToKSkUKFdx+3/+JbWFJ+NqpsqVPnO2BYo+IYJ5/AxjaZ+Ce2sabEsno
         hH/WrfsYzofeFt8HsHEirl/Kz0uIVHWMV0qf8ILhJ/eEgov8M80i0BYVevWvBHON7D0J
         77C+dCJwWNbapzQw6W9XAou0vyXgC9sno+qILBAF8+NwNsIcWN+AC37OI/nA50qAFFtm
         zumA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkLUo77gNiyK8spIpwfIUIhPbVmekJ5k6Y3MpnDbuZ08OeDM0pHRhPpYv0mSYx3r7+tIjKhw==@lfdr.de
X-Gm-Message-State: AOJu0YxGUpOzKBhdYK3MSrz6pRu8VcSmbBJddvzISovF2Ggojnng1zzs
	/dVPnI9398j8HAPwMrEnkJY3Zzo4ZZ6enzC4jPBkcV5HjqZtE9nj
X-Google-Smtp-Source: AGHT+IGSYwoRJC4IpSgpFyKyu0EP3+z7e+6BbhK8k7UZrdHArJnxoNqjZnqezCaEmNoNijh18R+0xw==
X-Received: by 2002:a05:6e02:158b:b0:3ce:7da0:6fe2 with SMTP id e9e14a558f8ab-3d03f38738emr38854185ab.0.1738690663453;
        Tue, 04 Feb 2025 09:37:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2307:b0:3cf:fe9c:74ca with SMTP id
 e9e14a558f8ab-3d015ac0aeels6199645ab.0.-pod-prod-00-us; Tue, 04 Feb 2025
 09:37:42 -0800 (PST)
X-Received: by 2002:a05:6602:460a:b0:835:39a8:e201 with SMTP id ca18e2360f4ac-854ddf23b46mr345172239f.0.1738690662522;
        Tue, 04 Feb 2025 09:37:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690662; cv=none;
        d=google.com; s=arc-20240605;
        b=lnRNA5B5DTOYmeezsyydMa0/TGFFMU5mEh/SR0IG2flnBYkzQ1YheIMDS4mSTUItNx
         ZktXxqixgXPZTAVk/HXDvh9QT/jbxOyMGuwnfevrBL9NRKlaOXJEQjLCJb7i2wl3zhsh
         xbq+qt3zr+WfmpT+RRxfL5hj3rIZDiioJJRfqqrv/csy5Uw8/c9Jb8oTuMA5qBr25xQh
         gkZHzfv0BVsN9Wm6sJGhuzvnfn4P4Be5cDyuQNkz7ebi7MJ/hDVM6nnCIQh4R/cZszTr
         gJxGBVSB1GsugWCvHOm9oJQxHUHwxkgIPpZoIFH93V8ICPc1fs6ECU7DcRgrjmJJGIFo
         +xVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qK1chVyWc3x+ocpxBgge4/JeZPmwM7T3xKM6CHzx0Ts=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=KlNnDG4wmWZEsC7vapRI+OMq8tAt62RL2pMjEvnBsgVPCfpuTr1S2ioJI5aruWBRUc
         YQj28jQ+2EClqtHSAZF5I78nve8bsshullz/ZDsOymBvJT2S/b9FbD/yEgWnNC4dNOCB
         gTjVLvjGkhymkUzOXDl82No2UGYgBOM3Zntof2Io3Kb9Tb2f6iakoCcRLbDw2GJ7/s07
         Aybou0GgPLR25l+GRVk1zZTdhoEbeHWkzwB53alouMWwquwv/JyCmd2/uSiGQcGORxcR
         Qhgjl0kmydIwaq8TbLTUTSnBL9qhm36W5K+t4pBZE/era8Aokhi+tC2DG5p9U3EVwxHb
         h6zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=F7XPcWxS;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ec91061fe2si273376173.4.2025.02.04.09.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:37:42 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: EqBA1QbHR8yH/IR+9SiREA==
X-CSE-MsgGUID: 5pIUocCVSFOEttooL49YSw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38931209"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38931209"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:41 -0800
X-CSE-ConnectionGUID: UAr5/zW7Rha56MjtNiYK0Q==
X-CSE-MsgGUID: 2nPTC7p0TeC/cQLyC4Ywqw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147867266"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:29 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: luto@kernel.org,
	xin@zytor.com,
	kirill.shutemov@linux.intel.com,
	palmer@dabbelt.com,
	tj@kernel.org,
	andreyknvl@gmail.com,
	brgerst@gmail.com,
	ardb@kernel.org,
	dave.hansen@linux.intel.com,
	jgross@suse.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	arnd@arndb.de,
	corbet@lwn.net,
	maciej.wieczor-retman@intel.com,
	dvyukov@google.com,
	richard.weiyang@gmail.com,
	ytcoode@gmail.com,
	tglx@linutronix.de,
	hpa@zytor.com,
	seanjc@google.com,
	paul.walmsley@sifive.com,
	aou@eecs.berkeley.edu,
	justinstitt@google.com,
	jason.andryuk@amd.com,
	glider@google.com,
	ubizjak@gmail.com,
	jannh@google.com,
	bhe@redhat.com,
	vincenzo.frascino@arm.com,
	rafael.j.wysocki@intel.com,
	ndesaulniers@google.com,
	mingo@redhat.com,
	catalin.marinas@arm.com,
	junichi.nomura@nec.com,
	nathan@kernel.org,
	ryabinin.a.a@gmail.com,
	dennis@kernel.org,
	bp@alien8.de,
	kevinloughlin@google.com,
	morbo@google.com,
	dan.j.williams@intel.com,
	julian.stecklina@cyberus-technology.de,
	peterz@infradead.org,
	cl@linux.com,
	kees@kernel.org
Cc: kasan-dev@googlegroups.com,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org
Subject: [PATCH 15/15] kasan: Add mititgation and debug modes
Date: Tue,  4 Feb 2025 18:33:56 +0100
Message-ID: <450a1fe078b0e07bf2e4f3098c9110c9959c6524.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=F7XPcWxS;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

With smaller memory footprint KASAN could be used in production systems.
One problem is that saving stacktraces slowes memory allocation
substantially - with KASAN enabled up to 90% of time spent on kmalloc()
is spent on saving the stacktrace.

Add mitigation mode to allow the option for running KASAN focused on
performance and security. In mitigation mode disable saving stacktraces
and set fault mode to always panic on KASAN error as a security
mechanism.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 lib/Kconfig.kasan | 28 ++++++++++++++++++++++++++++
 mm/kasan/report.c |  4 ++++
 mm/kasan/tags.c   |  5 +++++
 3 files changed, 37 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index d08b4e9bf477..6daa62b40dea 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -244,4 +244,32 @@ config KASAN_SW_TAGS_DENSE
 	  ARCH_HAS_KASAN_SW_TAGS_DENSE is needed for this option since the
 	  special tag macros need to be properly set for 4-bit wide tags.
 
+choice
+	prompt "KASAN operation mode"
+	default KASAN_OPERATION_DEBUG
+	help
+	  Choose between the mitigation or debug operation modes.
+
+	  The first one disables stacktrace saving and enables panic on error.
+	  Faster memory allocation but less information. The second one is the
+	  default where KASAN operates with full functionality.
+
+config KASAN_OPERATION_DEBUG
+	bool "Debug operation mode"
+	depends on KASAN
+	help
+	  The default mode. Full functionality and all boot parameters
+	  available.
+
+config KASAN_OPERATION_MITIGATION
+	bool "Mitigation operation mode"
+	depends on KASAN
+	help
+	  Operation mode dedicated at faster operation at the cost of less
+	  information collection. Disables stacktrace saving for faster
+	  allocations and forces panic on KASAN error to mitigate malicious
+	  attacks.
+
+endchoice
+
 endif # KASAN
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ee9e406b0cdb..ae989d3bd919 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -47,7 +47,11 @@ enum kasan_arg_fault {
 	KASAN_ARG_FAULT_PANIC_ON_WRITE,
 };
 
+#ifdef CONFIG_KASAN_OPERATION_MITIGATION
+static enum kasan_arg_fault kasan_arg_fault __ro_after_init = KASAN_ARG_FAULT_PANIC;
+#else
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init = KASAN_ARG_FAULT_DEFAULT;
+#endif
 
 /* kasan.fault=report/panic */
 static int __init early_kasan_fault(char *arg)
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index c111d98961ed..2414cddeaaf3 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -78,6 +78,11 @@ early_param("kasan.stack_ring_size", early_kasan_flag_stack_ring_size);
 
 void __init kasan_init_tags(void)
 {
+	if (IS_ENABLED(CONFIG_KASAN_OPERATION_MITIGATION)) {
+		static_branch_disable(&kasan_flag_stacktrace);
+		return;
+	}
+
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default is specified by kasan_flag_stacktrace definition. */
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/450a1fe078b0e07bf2e4f3098c9110c9959c6524.1738686764.git.maciej.wieczor-retman%40intel.com.
