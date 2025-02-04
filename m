Return-Path: <kasan-dev+bncBCMMDDFSWYCBBNVARG6QMGQEZUL6IFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DEF6A2789E
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:36:55 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3ce7a0ec1easf43223975ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:36:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690614; cv=pass;
        d=google.com; s=arc-20240605;
        b=PvKCxhAqEajyXlMFD3h8CH0obvoPpJRsbPHH8zYK5xH7pgGCnDrEnSlUhDf5BtWVnl
         Lz9grbb2I9Y3hPHbgdcRJONupKDUpNFawguA6tg5cgo/Eh73od1pQ/g7e/a/g1PkmS5K
         fEv18PQ8Ggon4qekHdhc8ksu3NaCs1mBUdGh73/ka3/X5YBzJDdeolzKn40RngdYeEZN
         IpDeyIIG9qKqsY2l5tawPnNu5MsBi7bcEWlBJn4c4n5eo2A9NgmQwjsSgdKksJx0Xqak
         6FG2pr56LnPk8tB3RJpfGxJh5Nn0cDLVCUUI/ZRs47qXqlMU2RXJ94QuyiV1ya6w+kJR
         j8kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5X45tEqdQFQjXqAZPs+leJQmraFpEIpUZQRkd7zmxYU=;
        fh=JjWgez6g+tqX25I3R1g+/DDdLyvWEAR0kCOAyUb9nTo=;
        b=QqG2vnzu7dNrNw07DhZ2UTHdU6zA7jmybQq1lU47cCzG0hGTYzpa6lxXKftNF6ayvo
         T+X7N46bMm8SmOOxZpdSz8ksnhw3HXHXMKCQNyKS/OLbCv90g5P6hQCm0SYLhQhH5Vgs
         WvCWtHAQKMOsBWJB9JdGvg3+b4gEbr4sH4DkikRa/aovQU47lYRgZvIL8tqSDxtSB8VO
         UI0cCnH+6QIRVos+miRhmH6zisEgGK4WAIK6TgjopRf7lubUYYhQMwq2etkQc1CUcZIj
         QyUR9ZF/8ffRo7lkvH0iwTEWhXjjor6uEnTbjYTM9m47kmGRVnebmQbiBzygFchtbika
         O8Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="jN/G8y/b";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690614; x=1739295414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5X45tEqdQFQjXqAZPs+leJQmraFpEIpUZQRkd7zmxYU=;
        b=U+J+OKUx3IwIhpYEA2/HjiQAH1VhBNsxNpb2ff+oB9+QNamkZHQAPCpVGRLqQZZ78O
         aZEwqUUN1gKW6awcpJu7YUhJNI4lHf8oeps1IkZD3hssHpTSSj4DPaYpM0w4e32QjzzN
         k3aZIPLmJkUGuepPiSagFndLOmYGeK8Q9EVXrxqptrMhwkYy/uh7waKK5YDYPCHPqYI+
         rB5eeWYryBY18hJzYfJ1Or1+fyCgHZpJE3GgyPGVLTOOIZCAqf5zi/uR3dDyeanCB230
         ZXE7RxTgtaJqM0EnMz+wdP1Y3OqCxk2ajaQy+Pva2SFrE7/a9BCItVrx3qAALn7L+pvO
         xBXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690614; x=1739295414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5X45tEqdQFQjXqAZPs+leJQmraFpEIpUZQRkd7zmxYU=;
        b=RJpM5qoYGkLfX28tSPNU7ft6IYEdk+pmc7rLUedE62OKrQ4xvGUIhz7Oc8brCgzu6Q
         Vr8uWO6C03p83U7R3jdJnzWxoYkqAeSNWXR35hTi/a6WlgO5GMRH33K0ENlOTZ024gUd
         Br+4G06MUeQ5nsyCrVKSPXxYrWVnbZTUiCQrQTCjTxA4go4rjXoCB6tVirtPZhBaYScf
         xLrdLoD7ZTT3O4higsK4G5le+NYqyKR+L0SU7CXvHbDGfZzdy0MJZ/Y/OPKfNHoS2se4
         WZKuNQ201h83f+uzfWqDynSTNhw4QAFFIzCldbFr1TDHXP6oLyojhnI0KtZZOHU1Bm16
         K9hQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6js9v5tDKMn5V49KDDhoMQln4bsbsc5vebPFcyyWKWt5zQmdqsl19AC29A4AUehiW/441wg==@lfdr.de
X-Gm-Message-State: AOJu0YzXT8yjO+mKUDRgQSMPiOS7iSsIZqJE48nxKSU+nwVyMgWuWVEd
	jVQayQ6yvEW+YZS6YLjdEx1vzLuu00DgzjZhdm29fRxgW653YAGZ
X-Google-Smtp-Source: AGHT+IHDV2x0dRPDm573nx7/10MOHh/d5LOYsg+OMYD/x8vPWqAKj9rIAc5Qm3EG2LB372QPB7cOPw==
X-Received: by 2002:a92:c269:0:b0:3d0:137a:8c9d with SMTP id e9e14a558f8ab-3d0137a8ddcmr184743165ab.8.1738690614323;
        Tue, 04 Feb 2025 09:36:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6403:0:b0:3d0:45cd:cd1a with SMTP id e9e14a558f8ab-3d045cde6ddls1973685ab.2.-pod-prod-06-us;
 Tue, 04 Feb 2025 09:36:53 -0800 (PST)
X-Received: by 2002:a05:6e02:18cf:b0:3cf:c7d3:e4b with SMTP id e9e14a558f8ab-3cffe6b7e26mr276527785ab.21.1738690613385;
        Tue, 04 Feb 2025 09:36:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690613; cv=none;
        d=google.com; s=arc-20240605;
        b=b+przthxcBEfvtdAy7SbLi2O+6pEERx7jWIYORrtnkgyiz1K7Zt3sN2H0i1+DLzAIc
         lSyqmyccUdKrF4brtnItHFFdI97HGNyP4pkWuyXQjVFhLREW4GJq221mZlYOmn4gms9m
         tIPcUDUfYnLn8kplaS9+xK/1VcDidho1VpeMJt2YR2SGSFtvJrZUk1pC7IAR0yWATvI7
         i8aHrCtGkMLFpQ8lBzcHKXm0CmykbXHKZmDMhQLtrQJSqgiSHHiqQZEE3UCTDbjdTER+
         DLW5gQg8Ca0sYkbCB4/JxMrdCtuzO3sVlhKVY8xomnebDu2jx0eoIM5/VOZQoEVTAHzU
         rUOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wcThim39EYPHxXLHIVD/RA5qpLaRNquzUdH4zXdFJ+w=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=IOMGfTo3nvXypX6GCTo9uIXRR9gvsmNqb11QP/rfBhpc0bK+EGZd6UFa2Co3YLSCg1
         +mRHR2K/GqB/omHDe8MhH+UA60HdoysgxWy2bBtf3K74ojChUwjV+iuWx9XIOBMLtCck
         BIA9Sl47yUOWPG0tZAokRC8XgvpG6SUP9rSBsfYPjrn5U7cFwQSZBEGInwTPEUxSc5S3
         2hGr6Q/nm6TGV/dlagL9Okcz5DS7Il0gDOY9XM2lo99ETkz9wHTe/Xy8EurZONVsoXxB
         xmsjzBUZjXAkSeOsM4thCunKYFXtDY5U0Lz9UUc8cAH+XQld0fQBmNMDjj0jITI4F1KS
         OeuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="jN/G8y/b";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ec7457c0easi440279173.1.2025.02.04.09.36.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:36:52 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: ZI1/EcwbSKe6agp07zQwYQ==
X-CSE-MsgGUID: r8XrB1X2RW2UH4wPUqD3bA==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930970"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930970"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:51 -0800
X-CSE-ConnectionGUID: P6du7V6VScafjuMIXvnbWA==
X-CSE-MsgGUID: W7s9nIAMS+GBPujRL+zY2g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866889"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:39 -0800
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
Subject: [PATCH 11/15] x86: LAM initialization
Date: Tue,  4 Feb 2025 18:33:52 +0100
Message-ID: <01104816cdd0d430ac843847a8056d07b8770be0.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="jN/G8y/b";       spf=pass
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
index 16752b8dfa89..7cdafcedbc70 100644
--- a/arch/x86/kernel/head_64.S
+++ b/arch/x86/kernel/head_64.S
@@ -199,6 +199,9 @@ SYM_INNER_LABEL(common_startup_64, SYM_L_LOCAL)
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
index eb503f53c319..4dc3679fedd1 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -756,6 +756,9 @@ void __init init_mem_mapping(void)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/01104816cdd0d430ac843847a8056d07b8770be0.1738686764.git.maciej.wieczor-retman%40intel.com.
