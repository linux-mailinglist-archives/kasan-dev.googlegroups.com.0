Return-Path: <kasan-dev+bncBCMMDDFSWYCBBOMF2G6QMGQECFS6EKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A372A394FD
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:20:11 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2fc0bc05c00sf16451238a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:20:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866809; cv=pass;
        d=google.com; s=arc-20240605;
        b=T4egv0WnPLtCby7GyIYTzjXU1tlJigSdyg1TIjZfVqgXgs3kkqL9i2TtXGHboDDb15
         0GUwr2wV9oY+ntTLlPnWqp+QR+5jv7AFLlJfjYKMp+ZWLyoDIGSrAmdnDYkPASrqHo+q
         tjY/NJE5lY+GLvXZXpd17EIbh7cWFusB3kvv3r79CAvCqcoQkDkqALnHOVI6rnh76X/H
         +oAlGgXolu48QqPRPeT22cMp+64cKkoZE1IjejJYHn/+igWJp0FdqaarAOLBis7AXn3S
         884X3OfitTWPg8QVN70Y3y82rR1wSFNH3EMyxdyKdsFGerH/W30fG7B0eeAGj38obX1V
         g9sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jvlSZH0fOgSq7Cmo7pBmXfLxvVnYDyl4Dlm2ANkslVg=;
        fh=9/CqWk8S4bAGPKLMHUMyI5BET8CFkeAXmvWtGPF6cQM=;
        b=SVxXh9Zbh6eOVsJ9GdvEN3BrwE6CUjeulOIX8HfcpGIJZ0uHlp3ACBvGoUsd5K0XGp
         5ggYnLtNnuv4jqrOtWMF7DTwDaslWZk/V2D09tPafz7Rmv8k9sDy8u+5sQXBzyeVRX78
         DbaGZfuGHnCIYhmqEuU4v4iWQrRuT3eCk8A8JAwz9rsKJxTPeJnHPDekJ5NSWAQGT3Y3
         /ALzww+4wpNmwvVGaLoSHWjfYp9IHUf6fbJXRqK+VT9ucPaV9BQ8RUJpvSb4MPzTb3HT
         RiifnwzmPvV9d2hnfnJM/w3mG3EyUadEcU1qqs90JpaUc7WtTQuQr+NgUtow0qP4+/5Z
         /ZYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=V4Y9J1N6;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866809; x=1740471609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jvlSZH0fOgSq7Cmo7pBmXfLxvVnYDyl4Dlm2ANkslVg=;
        b=dw0/w1fMRhTdC0IfARdtp9Qufthr4tXSHd64avsUOd9MkbVVodxuRon3sSE+5dCi2h
         DRAysjtGLZrAJQTluCD25qpxG3985ycP6j+3bCdmYHbml1Ozql2Hz7OkLE6v7N1rtl7I
         tAPfb0Eoy3VNe/aXCR3CUgdYC5b7g7gSAVODo0HPnzC4D1ekBMbZNALpKmGUbrGwau4U
         kinW9pZeN0/lh64c76aXI32EJkh/zjoMw6H71PKOKaFCk5R8LMXPekIU2/nWCeyESJVD
         J6mQkHYNs8YOEzFRoT369eaeoEsXIW5xd7OZm7OH2+p/K5ULQz5Kofd60xiKRfsdP3fS
         dVfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866809; x=1740471609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jvlSZH0fOgSq7Cmo7pBmXfLxvVnYDyl4Dlm2ANkslVg=;
        b=SSu3gASgH9r/2gFahyW5bVL4eSEueXKpOxRfmnDqFDg5xHzZvDq/i7INYD7MAu4Y3+
         Ir05JpbTnDFqAT0TZGCah2kyrFVCTJXwvkgUD83J0o4iAKqb51aPq5c6A2iNMdBD1MJ0
         pSE6dabIyAETxr7oXrtsEZrl8sKxC4sjFoCOI5v9ej3eqUAyYacZ1rfBBhuuPL9GuEzs
         PLyxtMgD5qyK5SKKFYt4s/XLcCIPhKO6XQbyGqyx1xpi0j6uMghd7nsPlPtx0BfLAlHq
         QXr375Py6qnrKWGvN0Av/RQ+54x1QzmgtnUjfo3QCyA2J4Or8JG1nua2uMtxfq/3rQ89
         dbew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeoiV7pYGrNM6+NnYAiWbonrYiCIp+YoN8PgZHaF3daL2o60rzYNLjRr4miJu3os04cIxGNA==@lfdr.de
X-Gm-Message-State: AOJu0Yxk+TqndOsJqLaDqBFHE2eTaSMj4JVzqOVus/LsIInDC4gl4bty
	ky8HgVVyy22VUjDQr0nyE/3cXVO5rpWLrFh4sUIkQFvGhd9RvNO/
X-Google-Smtp-Source: AGHT+IHcfS37XcnvXWbpBNySOtB1F6s8ZRC53zJiOG7ro83Ggi4ElXEbvsK6YHMWwYIqmTBLf5xr+Q==
X-Received: by 2002:a17:90b:1c0c:b0:2ee:3cc1:793e with SMTP id 98e67ed59e1d1-2fc4115098emr16978409a91.32.1739866809430;
        Tue, 18 Feb 2025 00:20:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF0gxnffF261yurk4rKfUTuZ0Ypc3//L3bgWZAyWfR6qg==
Received: by 2002:a17:90b:4d91:b0:2ee:edae:763 with SMTP id
 98e67ed59e1d1-2fc0d5742d4ls1060232a91.0.-pod-prod-06-us; Tue, 18 Feb 2025
 00:20:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/ys8mpq8PjOB8WDBo7KluH4xuasK5cXQ676Z0pA2voyGQ0n3yGa6QaMf1kwxkz3j8AKaano+/PZM=@googlegroups.com
X-Received: by 2002:a17:90b:4f46:b0:2f8:49ad:4079 with SMTP id 98e67ed59e1d1-2fc40d12688mr19167070a91.6.1739866808264;
        Tue, 18 Feb 2025 00:20:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866808; cv=none;
        d=google.com; s=arc-20240605;
        b=ALPrzT4+nY5eVJisFeG8zT0uXZddiRGgDYrY1PIUjTotcln1ZC0PPEGfPDn6Wtf9vX
         WXjlAZDUY6pVw6dsybo/lnsqH3GBxk/tlqPA/JqpM4jhVqnmnvpmkleSsy77O1Zuqhpc
         lkeOCctEfX/FZ5IwmNzeoPMHkZ5iOOS7pv+a1I614BgLeG6W+2oxeNhkwbwNDcBiVJfU
         ds9LxXaEGvO/KdbhQJCpNeLWZyBJm9trG3OoLxcnl/w3nxlLrLMKhHK0916CSZYhAe9s
         BFiFGi45V3CkZ7RbXzGd93UHpd6PHBn7tRCEWE9lS6iOazcdqdJ5Kro9Z8UiH3u1o+go
         WWXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=COic6/VOoJ0eGVo5zHidc2M6LNkQyli/tN3USV00O/c=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=HmZ9+cA4vLDgaHrSrF6H3yxdHRXP+kLh+en82Iiu1YnK1AM9ae7H2bkZ0uEJ0ttc5T
         IrgJb9pkouf5e12ERHU1+tBX5B6pTVO7/wW4mdhSbWzCGzr0+EzGDQp2Dh+BlIKHPpKc
         3SzNJhaq6ptmwuD8MLx8yMqbGHhmw4CphshdBfU6ZusZqQLDu9vKk2FoHanlj56vgKwS
         ZXoKwQouLvidnum4M6UNmNsmqnuTFIJEBowGGm9XsmYge+Fx2wiLx0etUr8bo2O8637W
         iANb88amAI1bjQPBJPPbmD56yEsedZd8mIFQJqMVihBR+/7vL5wJiMF6NqJ/WjSL79PL
         4nrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=V4Y9J1N6;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4aebb95si1492627a91.0.2025.02.18.00.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:20:08 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 8Vj4+LaeRCC3ThrzM/sa3Q==
X-CSE-MsgGUID: pR1BUsoTRL+6dF8HJ/yPbQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150525"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150525"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:20:07 -0800
X-CSE-ConnectionGUID: gMq3mPUvTV65euptYpCgkA==
X-CSE-MsgGUID: 4QJymTnUTKCW0GQU3obH6A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247992"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:19:49 -0800
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
Subject: [PATCH v2 12/14] x86: Minimal SLAB alignment
Date: Tue, 18 Feb 2025 09:15:28 +0100
Message-ID: <7492f65cd21a898e2f2608fb51642b7b0c05ef21.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=V4Y9J1N6;       spf=pass
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

Adjust x86 minimal SLAB alignment to match KASAN granularity size. In
tag-based mode the size changes to 16 bytes so the value needs to be 4.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/include/asm/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 8829337a75fa..a75f0748a4b6 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -36,6 +36,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
+#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
+
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7492f65cd21a898e2f2608fb51642b7b0c05ef21.1739866028.git.maciej.wieczor-retman%40intel.com.
