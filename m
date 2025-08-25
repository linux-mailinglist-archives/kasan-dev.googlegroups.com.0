Return-Path: <kasan-dev+bncBCMMDDFSWYCBBEEPWPCQMGQE6G7F56Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id A1C77B34BDB
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:29:05 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70d9eb2eb9bsf69066966d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:29:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153744; cv=pass;
        d=google.com; s=arc-20240605;
        b=R1Fc4fQ57x94ZCWeuFS82rsbXYjGmZg7HfnsAwRnAMlRSbPy+3jwQX+CwvjTBt8kl4
         lf9jqEfptvOhioRu7Pnoh0RjKg79tQPxCyJD91Gn6YRjGUMPG6k+CDQdjB7x/yDJcteL
         XLoUIEv0ECbxqMJDlcRqCYYxZt+6ftZoN4bL6KvFEpex1AMPIh79MEBHXIvzrsnvKtSr
         rziuOc5bvLI1c+xUe00kMvn3mwHj4CsLfVUXLS/G1AkdBVMwvmkX9qmHQ3TgzG+Y9dj8
         Y5w+KgINBZqaC+0tzrj+PBOrWjnqMqiDPqV8t+7Wn9yROMWdgyMbDaBUGZ91zhw8Vzv9
         B47A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BlcTuJWLn6nTkUZ2BJV4wvyBA7epxgrZJuX/p0TsYTM=;
        fh=zNohUR5m9vCkjuqV+4uJNWEMIsj8NNYWgugXNYzLmdw=;
        b=fJOB2TUCX0UAveI5OTT5SiKUdBKwENK/7AFHo7URZXrFtyxJ6KIFB20uNr4SG0CriT
         3MauMAZKzFlqRMLxMl+muP8n2pluZSrbB+cJ4uJziHJHqeRwk0OGV3aVx3V8NOtCR+0p
         oWMdGbDtWIgbJLmBznrlvKGPZREz++bRPSJBV/t3qIv0DWlMHR/MW9s++PGeQ4Hy/+kz
         PWvxQ+j1ucUBnKjwpNZ8NKXL6krkSOA2pC4VvfSQrZUt/OYUa02yAnLg7xhBDgqyh8D9
         6wAnmpOE5aUagNj6n760lzc9CHyhzgT28kAztd+Boa+C/TQgQ1G3iu2ZkQ4FD9Gzoy8F
         dzAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=R0+tyzln;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153744; x=1756758544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BlcTuJWLn6nTkUZ2BJV4wvyBA7epxgrZJuX/p0TsYTM=;
        b=TkQc8Bh5yA+/yZj66+zW8SuzqzrS9vxMHhIpKfWxAvl46EGP7UNmHltg/g8SKBWbWy
         WdJLNCAPHiYCw3ss0G6H3d6IF6oB5UvFtkpENdaLRGYTTsxnx+KUWNaVARjzNFt/cgNJ
         7QzW6P2WJpDqywgV605sqSpW9L/h0l5bO8y2T8K0E1TEra+boQf6jB728VBnGOK1jHhB
         WN0/kW89ZmPjA5ePnMPUSv6GuERVpCDYT6JAHdDfSBfGQbk+JpQHK2vOJ+D+8LURvS8a
         HuG9tmifDMBKw6RpEHsQv2osoDuQw8jriSLmMkQkv4VpUHi61MVGAU9Hboof+W9mE14j
         NJEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153744; x=1756758544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BlcTuJWLn6nTkUZ2BJV4wvyBA7epxgrZJuX/p0TsYTM=;
        b=Vfw/iBGIh4xpQx2WOiUEQlm7G5iQlgU2JIc2Ey5zaP48XiyvZ+ePr/ALA6PyoIX4X6
         RHGXVP/8m6+q8Pka5GhyTh4evpnYdjzjYSgwTJf6MyxwyhZNNjCNVC4PAJbMXEzJRg3a
         CWrXE8LaxB0SiuRG+RjEZrVxYsg6kPHRFqbYZzrAnhol9bTkOh8IDPLKk1VEPrrpwypZ
         0PGNYTVAoiEmiA55ZQFN6GzQL812xUq06svLND2lk7uIUb4T9U5mVbRdC5Hx1hFcYjYA
         nXtFc6PJV/+dU805JtDJpiI4RVRd89kdl+ztoflRqRaXvZB9De0QDszgMUnBDzAaq6ig
         k6eA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWchatztdetiFIDOG2HJRjxusX2FvDx9PEaIS5ZtRmmAyhHnK0BghDuwMQzfT7igfVHa34E/A==@lfdr.de
X-Gm-Message-State: AOJu0YwXoP9NaG4yLhJe8JoEKBqsrV/34N0vqXeRAQPUIP16hD1OgMki
	gq8Y63ki/SAO2Bo3FJwukbPfn2QdVoePOf6/8ptKMzIC5mXr+5TeYBgM
X-Google-Smtp-Source: AGHT+IH9p2XQzF2vCg7fB7odGKvRhdOABwSFZsuHftnlaPeoR1iTBFmKCjmDIwmxpkS8H/eS1R7AfQ==
X-Received: by 2002:ad4:574a:0:b0:709:e3ae:d598 with SMTP id 6a1803df08f44-70d970c41ffmr165016056d6.14.1756153744263;
        Mon, 25 Aug 2025 13:29:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIUFmoC6vpy0ry/qryjLr5BwCI9WNuSkSMXoNfijtg3Q==
Received: by 2002:a05:6214:5e11:b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-70db7e61167ls22978186d6.2.-pod-prod-01-us; Mon, 25 Aug 2025
 13:29:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2Kv89yQM7DjBf7QFAwc7zT81ESLXHrIZ+vuNi33b9r47WzuVpEM/0Cb/wbZnQ/EimifTH84jtCM8=@googlegroups.com
X-Received: by 2002:a05:620a:2a15:b0:7ea:78d:79bc with SMTP id af79cd13be357-7ea110e2a50mr1434967885a.83.1756153743331;
        Mon, 25 Aug 2025 13:29:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153743; cv=none;
        d=google.com; s=arc-20240605;
        b=PkWYtZHgQP8z9ieEanQF1j/A53iuqf6SiDf2d4w8GwqGS6jd3Cicp52nryNDV0uJN+
         hK1eTE9SsxKSJ7viR6V6aDeo1wcXHQ/YaQoShO8fz7SgZbEt7cKHNlQHGcrnf1KwVWbc
         jv3oY+JgtQP5qnXh6Z1obo8xA9g0ADgF/MTsclAqbbXybcDPhAcH4gZB2+LQoo3FM/a6
         UPlpMoj+QwK8YOe8mUVqKYrW4KFE81TH2KaUvwhEdBSQ/dRPWEY5osjChuL8Jw0iHrd3
         VjCQQrHBr0F5W0/M3R5EjU9ShctIK+p64gkGfI6zxUSEb6sa+0yJdAecjp+8/4fRQB9z
         r5wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3VrKnxx0tLdbKl27xV7R8JaVVS1HXCMAhrp4rAkEYCM=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=AM6jphY+tUWljpEnaKCo03n2snw/6hie3rnblF74+LJGeUOec0pZNTy8ve7rG9d4dn
         H1Nb5ja/W6K0VknczToYQjdAJfF3lrXS6fKUHy95ZiSw3rwDQ7ZxWzjy3uTw+nox8mV2
         Aq2ZsBiHsiFQ3Bvpa8e3HkBNCrbV74F4QcXaw30lq9voSEqDDIZYg5wTqqU2O4Biku8H
         wOOODxsMhNAQ3ThmkJJJQB/les9WTTNkKvjUakaTKFkNDTFGKvPi/EBCN063/Ezcq5AG
         8ONMQxQUdNFoHnZ/A2CuZiLzUa9wk6b5XyrTeU07FLBhOxFfY3dZzFvF890NXeuAnH/o
         qz8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=R0+tyzln;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebec276de6si34151885a.1.2025.08.25.13.29.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:29:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: 3/FoL5dpRlOcABrnaERueQ==
X-CSE-MsgGUID: U8Aj8IQnSiGdGuvhB2vSeA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970688"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970688"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:29:02 -0700
X-CSE-ConnectionGUID: w+rKNHaARBe+f4eoM8vVOQ==
X-CSE-MsgGUID: /Hw/gZN7R822ANQdWoGk6A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780519"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:28:39 -0700
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
Subject: [PATCH v5 10/19] x86: LAM compatible non-canonical definition
Date: Mon, 25 Aug 2025 22:24:35 +0200
Message-ID: <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=R0+tyzln;       spf=pass
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

For an address to be canonical it has to have its top bits equal to each
other. The number of bits depends on the paging level and whether
they're supposed to be ones or zeroes depends on whether the address
points to kernel or user space.

With Linear Address Masking (LAM) enabled, the definition of linear
address canonicality is modified. Not all of the previously required
bits need to be equal, only the first and last from the previously equal
bitmask. So for example a 5-level paging kernel address needs to have
bits [63] and [56] set.

Add separate __canonical_address() implementation for
CONFIG_KASAN_SW_TAGS since it's the only thing right now that enables
LAM for kernel addresses (LAM_SUP bit in CR4).

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add patch to the series.

 arch/x86/include/asm/page.h | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index bcf5cad3da36..a83f23a71f35 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -82,10 +82,20 @@ static __always_inline void *pfn_to_kaddr(unsigned long pfn)
 	return __va(pfn << PAGE_SHIFT);
 }
 
+/*
+ * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality checks.
+ */
+#ifdef CONFIG_KASAN_SW_TAGS
+static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
+{
+	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
+}
+#else
 static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
 {
 	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
 }
+#endif
 
 static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
 {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman%40intel.com.
