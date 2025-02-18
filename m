Return-Path: <kasan-dev+bncBCMMDDFSWYCBBB4E2G6QMGQEYNJHBRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 596BBA394E1
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:17:13 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-471fdc6bd41sf18999251cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:17:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866632; cv=pass;
        d=google.com; s=arc-20240605;
        b=LIxylczoo3P/wrI8VWnJru0BwR85iNGHzYmxvTNbwl4waidaQAGAyE4rOakkdibQmb
         8VIz1oN3dWYdfVyNw+hg+gNB9z84We328m6hT3AbT3MNhm6ToXKsMkBf6B0kDiPSnRGH
         2BnnYXLY1FENB670/n1Ymx/U5EpSfeUvgESSooHzIfprJDus1lmWLObtjfYVGMNk8wKT
         B1DzcMXd7i+s5U3wqnD1jSuqtHuKIRBq4MAyt6LEwtIMVNmOtj+9ExtfWiemOdLKF9AE
         ZtLQ9q2/Jk57W3jbvYKKLN1OE2qmhFNimg2vFwklotP2/jdw962BKESEUaXmCGy67mcd
         ggbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IjpdiP7GY6RmJp5u8Ms/qyfnBN2HVlqFgvANDRD+tZE=;
        fh=p8cv3UnISNtIuL59oBm09tltKKMCySF2rJJdu/sUDOs=;
        b=kmOQUAB22/HRmPkxyPVSEIeBPAYath6YrtGhN+YMw0e9jQWC33d3eYpVgNbk8eznVU
         a4M8qAkcP+q3XCWjGeH/MIX6LzAdJywlbVEi+9ht08nGdpM1SGBi1eVzZeJtrtFJIiPi
         S/NfegQvvw9nyrJrV4h2NzeOZsP6I7C3AoY7nxSWAxWamzO2PcbXnsUgMzBEQ2YXPlsk
         Mh9ihtmy9BNW1WYLtTxb6gGp0ne3dpsYxL877nb0WRIN3e3A4W4JGFpMl25rkOZLc9CK
         iJctmMaGTvfKWUtQRsfCTgfQBdmbKHp+y4KnLTbBd4yqPm+rjLAgqkZecQRxOzWWh14x
         PrEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jxwnY7hL;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866632; x=1740471432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IjpdiP7GY6RmJp5u8Ms/qyfnBN2HVlqFgvANDRD+tZE=;
        b=rQY0yZ/oWjv+Wm8KVL6Kz+F/g3Geio1tsJTWydVVx5+YHh3ajhxJTjA9EtKwRV8yp9
         or2xs1ghsXLVPb6cL4Qh+PzO2Dx40aSj2Fj0iCCSC/P57zVbwOGLoZB8ib8YavtaTzYZ
         BJ/s6g2RCYjyZ7bs8wfv5Kwr3pd/rEpewEjQANMFjOHjpWVDp2H4YXsQl1QjYmsf9/9f
         0qrXpu9rPi5xkPVK7dFit5WPmnij0KfoHtc5mbusf1YnFyWccCdhUF80VCk7A2dzO/cV
         lmcZvGR6e0kXa2PIUYtJ3aqRc7FYNXvooQIwPajg2hHsIqC7w638A5PVP4WaEXcxbyU6
         Gm0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866632; x=1740471432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IjpdiP7GY6RmJp5u8Ms/qyfnBN2HVlqFgvANDRD+tZE=;
        b=Vba+DS5l1ASwjgHnAzxUKaz6HH1oopnyESCfaFPqgPw6jiydm1mTYep8fHayH5bHjJ
         5qqUsOQ8p5mIFOnGYD7zG5IXJjd7KxRTdwjRreUOIR5kXgAtMGv3OY3+9vKCju2RPacX
         qUkGfDQU5lT0nS36gUiEE5ByJ5KxI0edTT3Iz3S8b6zUZBGYogrBRaJfRT1sCnRccANz
         crdsn65KtYRhDlZ1fOmdea6zAhFQmU1k6XFeFFSP4sGBNVr/w1OkUpb+2/CtZeycoKsc
         rrO8Mrhoz0O/rc62K04y9xqpi8vPCBCsKhPsh00H2+emA5XqVK2piq4TWeDAIgYPFkkd
         Zggg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVqJZ3CfPoze7DEMOBwIo2HSQTN7mQ/zNTVy/UoZemw5sWOIjgzPhJOV/ydKrA12c0PUlFhlg==@lfdr.de
X-Gm-Message-State: AOJu0YxaoDEPo/XEDigr5fVmE4oNYn3qusWl/9+RJoM2xfU+g3+hCGGi
	iii9ODFHy4ecmujQ4YmOZw4bFU+09dfrbeeES92TSonO9jSh470Y
X-Google-Smtp-Source: AGHT+IEEoHdm138kOzzFAv6sKrlzFIfhCQbceX4sDPSd2g3aUTb4FPTDHGYiwmqGnSfE4WNXpTgl1A==
X-Received: by 2002:a05:622a:1814:b0:467:8783:e48b with SMTP id d75a77b69052e-471dbe6de9cmr172441941cf.35.1739866631968;
        Tue, 18 Feb 2025 00:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVET+rrG8KmPKRn3kb3hIK/mSxdMO/knouYTRd3PWeRssg==
Received: by 2002:ac8:605a:0:b0:471:eb39:2924 with SMTP id d75a77b69052e-471eb3929abls28698461cf.0.-pod-prod-05-us;
 Tue, 18 Feb 2025 00:17:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUa7r/JCDe7iqpaQXiwN2bkjWv+B+UUemJeca6Qgghmp2Fvll0ndYDuzo2f6p/eoupTExnLw+/UUJA=@googlegroups.com
X-Received: by 2002:a05:620a:1986:b0:7c0:791a:6faf with SMTP id af79cd13be357-7c08aa74353mr1942835585a.53.1739866631219;
        Tue, 18 Feb 2025 00:17:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866631; cv=none;
        d=google.com; s=arc-20240605;
        b=HW5T78YKOl3C4D6tDggG2vhowH2Fqt+Gnr4TOGtPhO75GkpZ3DekMvcyKk1ZfBVqVO
         dEDarta6hNqSSUe5+kC36qu78liD1CE76Q4yL3AJ4zcBLDd4AcUf8OZs6pn6DlsPl02X
         yq2pKkH/tRCHh7GTRrkK7zErbVs7ITZsphft6bJX6/6nMwIv3QDPQ/eGuC9LyxePqxa+
         wTfla3C+WtP2v/wjZIQ8A9AbRs1xPPsISPcDwRmAqy0GUvFf4YdbzrMv1a+jKyDshjrn
         /Gv/WrwUWJnAgASx9Y/MWqswMqx2u6u1XOOK4d05+C6vLBhsWJDMimJimhJFlM2bE4mQ
         QJ6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iCSpbFIW52Uw1IMNiH8VOklKBmF7UNSkwh0phBRHF78=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=KeajmATwO/RmtR6GHsnuo+mjNBzPb1qRhPv8buHRQc7Ni6caUeTAC5nK5EhBh7PcAs
         k+tCS84xsK8WnedLZsvfgVRaqlYG8CKRx0Bxyz9kK2TU+wOVN5WqiniRa8ehf2SslEaB
         R3kgaYlDYUaBrWPH+8TDooimvjMTBPUqacwvmsbcvoviyLrcPN6gbz9UhpExejLbPr7g
         o3JEd2+ZAZ2M0P7WKIRZ59SKv7u76mM15vL4uhiHM2+O/UyYmjxijkOsLpSqWvwCAJpb
         ZyQnpC6awW+kZbiBJULPztWgIJAiQE9S8AKG8YoTVx5fEjpwV4dDj7ML59QmfrFYhRKs
         bBLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jxwnY7hL;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c0ae7323d3si3439285a.7.2025.02.18.00.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:17:11 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 2iGMSGhiQKOyXKXV4M+bAw==
X-CSE-MsgGUID: 71BasF2MSDee9kNB67i2RQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150100"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150100"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:17:09 -0800
X-CSE-ConnectionGUID: +HOO78zjQVWglPzSMQGDaA==
X-CSE-MsgGUID: iC+fl3UpTo2a4V5pAf6vOA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247460"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:16:49 -0800
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
Subject: [PATCH v2 03/14] kasan: sw_tags: Support outline stack tag generation
Date: Tue, 18 Feb 2025 09:15:19 +0100
Message-ID: <20f64170c0b59cb5185cfe02c4bc833073a2ebe6.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jxwnY7hL;       spf=pass
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

From: Samuel Holland <samuel.holland@sifive.com>

This allows stack tagging to be disabled at runtime by tagging all
stack objects with the match-all tag. This is necessary on RISC-V,
where a kernel with KASAN_SW_TAGS enabled is expected to boot on
hardware without pointer masking support.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 mm/kasan/kasan.h   | 2 ++
 mm/kasan/sw_tags.c | 9 +++++++++
 2 files changed, 11 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..2fb26f74dff9 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -636,6 +636,8 @@ void *__asan_memset(void *addr, int c, ssize_t len);
 void *__asan_memmove(void *dest, const void *src, ssize_t len);
 void *__asan_memcpy(void *dest, const void *src, ssize_t len);
 
+u8 __hwasan_generate_tag(void);
+
 void __hwasan_load1_noabort(void *);
 void __hwasan_store1_noabort(void *);
 void __hwasan_load2_noabort(void *);
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b9382b5b6a37..94465a8a3640 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -71,6 +71,15 @@ u8 kasan_random_tag(void)
 	return (u8)(state % (KASAN_TAG_MAX + 1));
 }
 
+u8 __hwasan_generate_tag(void)
+{
+	if (!kasan_enabled())
+		return KASAN_TAG_KERNEL;
+
+	return kasan_random_tag();
+}
+EXPORT_SYMBOL(__hwasan_generate_tag);
+
 bool kasan_check_range(const void *addr, size_t size, bool write,
 			unsigned long ret_ip)
 {
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20f64170c0b59cb5185cfe02c4bc833073a2ebe6.1739866028.git.maciej.wieczor-retman%40intel.com.
