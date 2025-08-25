Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZUPWPCQMGQESZQIP6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 321D6B34BF0
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:30:32 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-b49d2f01266sf332387a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:30:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153830; cv=pass;
        d=google.com; s=arc-20240605;
        b=T0geIDAsXN/o8EJHaejwVXKPY7W6bfvTjesrXAv1FlyD2GG7EjYwtZDryqdl6oGnqj
         TtnJH9ggrwkH85UasI6NW+lISPj+gEV6Gw1SXi0E/hLusi3KHCDNwt3B0cIF6B/7eR5B
         Hoq8OyneR6c6rewKDnQGI/6THlQI5hivvLp7kIciQLI3gTBAMxYwKJFFwUU4T5vKf5kf
         rk7yZl+Iat85CPPd4AbFK3mSbs/915mIg37lw06JPDAoTdbXufW7ppYr3wvwK1RBI5qe
         HieMYLYe8gJtbUxq5uqL452lutgLfq/XIH5NSfT5tD0oOZnZW9j2ZntdOXLivISIDCPD
         WWPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=f75uvkawGzgJtJvmCUAJEAR+1yZWtnJ3mKnOErgSRHg=;
        fh=FKpEzD8MoyubgBaR//JwhBg7dNk93M3jNMLXSPWNS5E=;
        b=clfZGjZ7kFX17vhHk7E0stjTEu+8Cm8Jjc/9DHSUfVDCvB74RB2L1U1awm5Z4wtFec
         S3JUqLy/Rb7L40ooYAAv+8y53oH9b2J7qd8XdYfQbVrnlGI3e6Cg1e/QcnMffQuPYV26
         CzwpWO5aFQS2TUK9jD4yqHqfeoGU/1d+bM8NtxmId4wAQcm/hUa1+F9Rhjeo8uy9s/vz
         7gsaqZMqj+O5mQFx9XwZeS51jJ0YFI/NPkgHOSdmKMpbH0pXH423DtC09wkTLaqw0qlP
         lphPb63QXRCaFRfv6Qywwbzd6RSBYftAxi1xG8nIOrb6akIYIcmGG90HuPSG/9OsaXZi
         4mmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kNdFWBb7;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153830; x=1756758630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f75uvkawGzgJtJvmCUAJEAR+1yZWtnJ3mKnOErgSRHg=;
        b=mBKpSPbgEl+2HSK+FDIwrCZnDwMSVUu94QKiQaNUcohTMtDnVuW/p+6lBjsge1f6Yw
         S+T4EJAVDvNM70URAw9Z1lEk+seHzMiwr8hkiFHWhAHl3py1gK/VGJEtzr/G7O1Ju0e5
         atBJpXwasQdJyIh8zgB51g8AgvN+nyqmbCoBkWE++uHPIt5WpRNAB+gYzjeWxLWLXoj6
         v83WCe0rQy+fH0I2ZMAsmISxiwJO6iUZYgedgCs5gjCGdbHeOyGsbObs7vYB+ZgZBCcz
         mljz0KKcB1FyMqXlesdeFNdyx2TrEjZ+1ciubptZRwNyvI3P/clJN56n6oP4AByk+edl
         AH3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153830; x=1756758630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f75uvkawGzgJtJvmCUAJEAR+1yZWtnJ3mKnOErgSRHg=;
        b=w/0JfhhHFHLmC67+PN0C0e/OLcbCvI5VKQ/R6cs8Ta18r4q2smS4tZfk2OJ3U1XgKU
         8mGd8FfujOZEBye1mg0j1OUTt/6LjMMBQrsu/duQXMdV3mZEel9Ur76CiQOq64kYx20J
         HnPKkMBB85NqcYHEj0QpSEZEYiQAbuzvhe+UAGHDDv035J7zwNA7LO5+8G+bt1RAr3Pd
         QuNTLXYJj2QDakwMoX5X2DU8xxEzngsqxw+sOIYGRuXiD3quyHjq0SEgKIAytcNRtYVA
         omjGSsBnfxUZ79bS5KyVI+x2bNHoXUr9F18X/AtkmFIBtQgBIHigY0KOOJ48MDR/dAdT
         zfyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGefdTpFE8hrxvheIKATkoLzBMCEasMb9WC7VyHKtUC0ARyup2VAeMhcMbvGiT7Gp21aLifQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw8Mba8eMQrPAKngZOtHdLSNjK4CgF2j7xnnVQ3/uPm4MMvHY++
	CpxSty14Q/W/PZvNLaJ0OuswV+9JHTqS7T69O/ubzkS1HsSgdRhi19rE
X-Google-Smtp-Source: AGHT+IFjsDYQCeIi0dorm2w9OLBsU5rui9BzI6JKPJDXbLvEG9HdUtN2EsCi+A38EvTHPjqJrzXmXQ==
X-Received: by 2002:aa7:8882:0:b0:76b:d93a:69e3 with SMTP id d2e1a72fcca58-7702f72947cmr8669108b3a.0.1756153830566;
        Mon, 25 Aug 2025 13:30:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZch4qQwhF51p2dLA8lVvqSnDXrtd1bn3c/pSS9kLE+8nA==
Received: by 2002:a05:6a00:3e17:b0:725:e3f6:b149 with SMTP id
 d2e1a72fcca58-76ea03a11dals5422113b3a.1.-pod-prod-02-us; Mon, 25 Aug 2025
 13:30:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQCYkS/Y7LQbHgYdweqcKfcn3Pnc0oHmvLZTpiZwVQbxAynJylSdM4rWhiQ8LZn44aaMLrcDARRsU=@googlegroups.com
X-Received: by 2002:a05:6a20:7d9c:b0:243:78a:8269 with SMTP id adf61e73a8af0-24340dc974dmr16155169637.47.1756153829141;
        Mon, 25 Aug 2025 13:30:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153829; cv=none;
        d=google.com; s=arc-20240605;
        b=FTSQpQRQIr0YhrOFunI6EyscnvR0iDCxU7AqMV9mDLVn3VqFkCmKqBTQ3tQ2042/Pi
         KhI2LN3llHPCA0zzqpVO0/kRMHQbJG2kukuzoa0ZjiK+EKs8YUCE4ZqxgbRkByDhXWO/
         kakWI+2APCaWhMhgf3uocmf3z45sZq6dWOSLXN/d+zt2qpz1hOuD+xi9bo1V5iRJIfvr
         84Km19grqFZUJVBPwWn09n6GSKiTyHC5duuif0bFsQD01t1TOy3VvK2vSZ4hIcIe1EHK
         Cq3CygVXJVfMG8qda2raN4tbPy3eUHRZaGKZI279aKDJrqgtWjjc5LRVTHgwtC8mINQ7
         vqpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tb40DjADZPAVu1YBMPC2bsaVVCqkmgwDwfx+9HETv9w=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=bKHViA77ie9S+yHfNWWrsSar2O2gjaxjuslo6teiBYGvAgfVGCeuWtfSgrM9nTtST/
         kyhQmJyqHqaPr4C+JJz4Hx4hKa+ngkyRIQXPnrxjBWxVtNxJ5a/eOrDBgFojnHJ74hu7
         aKeFho0Ir+A8LPVSsFBTUilsYupIi6z0tFkPUqpyYnUN7qkLe3GLbHKqOIJh45srsYpy
         yHYhyptfVCoeK36v79UfiL2ZVTLnEwasYS3lwdHRVOHAcXVXbOKRLBJ0f3+dFGry+cGB
         yaFz0sqVQ7JxPPoGFmhi0WKcis6cIF26HQRiuknbg9BLYqXmk2OCUbl6qZjghXrKyFV4
         /EkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kNdFWBb7;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3254af497besi323790a91.2.2025.08.25.13.30.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:30:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: +RZUu+QiTMCjpGbN6Rv3bA==
X-CSE-MsgGUID: 1iejwZ8wSvSU4yy7WsFk+A==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970961"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970961"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:30:27 -0700
X-CSE-ConnectionGUID: nLGGLHJ9QoyoMNF1I/U6NQ==
X-CSE-MsgGUID: HzKVIVamQzSIU+bcFYV6OA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780844"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:30:07 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: sohil.mehta@intel.com,
	baohua@kernel.org,
	david@redhat.com,
	kbingham@kernel.org,
	weixugc@google.com,
	Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com,
	kas@kernel.org,
	mark.rutland@arm.com,
	trintaeoitogc@gmail.com,
	axelrasmussen@google.com,
	yuanchu@google.com,
	joey.gouly@arm.com,
	samitolvanen@google.com,
	joel.granados@kernel.org,
	graf@amazon.com,
	vincenzo.frascino@arm.com,
	kees@kernel.org,
	ardb@kernel.org,
	thiago.bauermann@linaro.org,
	glider@google.com,
	thuth@redhat.com,
	kuan-ying.lee@canonical.com,
	pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com,
	vbabka@suse.cz,
	kaleshsingh@google.com,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com,
	dave.hansen@linux.intel.com,
	corbet@lwn.net,
	xin@zytor.com,
	dvyukov@google.com,
	tglx@linutronix.de,
	scott@os.amperecomputing.com,
	jason.andryuk@amd.com,
	morbo@google.com,
	nathan@kernel.org,
	lorenzo.stoakes@oracle.com,
	mingo@redhat.com,
	brgerst@gmail.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	luto@kernel.org,
	jgross@suse.com,
	jpoimboe@kernel.org,
	urezki@gmail.com,
	mhocko@suse.com,
	ada.coupriediaz@arm.com,
	hpa@zytor.com,
	maciej.wieczor-retman@intel.com,
	leitao@debian.org,
	peterz@infradead.org,
	wangkefeng.wang@huawei.com,
	surenb@google.com,
	ziy@nvidia.com,
	smostafa@google.com,
	ryabinin.a.a@gmail.com,
	ubizjak@gmail.com,
	jbohac@suse.cz,
	broonie@kernel.org,
	akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com,
	rppt@kernel.org,
	pcc@google.com,
	jan.kiszka@siemens.com,
	nicolas.schier@linux.dev,
	will@kernel.org,
	andreyknvl@gmail.com,
	jhubbard@nvidia.com,
	bp@alien8.de
Cc: x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v5 14/19] arm64: Unify software tag-based KASAN inline recovery path
Date: Mon, 25 Aug 2025 22:24:39 +0200
Message-ID: <eb073b008b547cf87722390cc94fe6e9d21c514e.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=kNdFWBb7;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

To avoid having a copy of a long comment explaining the intricacies of
the inline KASAN recovery system and issues for every architecture that
uses the software tag-based mode, a unified kasan_inline_recover()
function was added.

Use kasan_inline_recover() in the kasan brk handler to cleanup the long
comment, that's kept in the non-arch KASAN code.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v5:
- Split arm64 portion of patch 13/18 into this one. (Peter Zijlstra)

 arch/arm64/kernel/traps.c | 17 +----------------
 1 file changed, 1 insertion(+), 16 deletions(-)

diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index f528b6041f6a..fe3c0104fe31 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1068,22 +1068,7 @@ int kasan_brk_handler(struct pt_regs *regs, unsigned long esr)
 
 	kasan_report(addr, size, write, pc);
 
-	/*
-	 * The instrumentation allows to control whether we can proceed after
-	 * a crash was detected. This is done by passing the -recover flag to
-	 * the compiler. Disabling recovery allows to generate more compact
-	 * code.
-	 *
-	 * Unfortunately disabling recovery doesn't work for the kernel right
-	 * now. KASAN reporting is disabled in some contexts (for example when
-	 * the allocator accesses slab object metadata; this is controlled by
-	 * current->kasan_depth). All these accesses are detected by the tool,
-	 * even though the reports for them are not printed.
-	 *
-	 * This is something that might be fixed at some point in the future.
-	 */
-	if (!recover)
-		die("Oops - KASAN", regs, esr);
+	kasan_inline_recover(recover, "Oops - KASAN", regs, esr, die);
 
 	/* If thread survives, skip over the brk instruction and continue: */
 	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/eb073b008b547cf87722390cc94fe6e9d21c514e.1756151769.git.maciej.wieczor-retman%40intel.com.
