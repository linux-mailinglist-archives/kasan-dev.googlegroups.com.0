Return-Path: <kasan-dev+bncBCMMDDFSWYCBBUFXX67QMGQEQLK7N5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C6254A7BD7A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:17:05 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d443811ed2sf33329875ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:17:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772624; cv=pass;
        d=google.com; s=arc-20240605;
        b=BbfZ0FzeeQBAf1p4UM/np/lvqRarOcb/dRU3OefjWQjF6nXEsya6MOD4JR94SFxrEu
         nsMZCm9zLHcxxLbi/JNA2NPAFF5UQJcbYXzUyDem0Rqw2SLOZ9TgClfgIulgDGzOgOSZ
         fXAC9z2DIPMo3pAsFG1KLlnCVGqEMtNTnqvEuJf2pheFMRNSwQkKd933lpSqemAK/49H
         1IG1IRQlr5EU0nP973nOdj1Yx8KyLk5aZG8voTS7jNiQKJNblp7ZBGMTJAnHVjORbvgx
         fsuxLwJTaTdZ+aOJkMI64Q6pkBkbaiQ4NiL7mtx3F8O6QjY2lecXqmBMB6wLEVVwgL6K
         nN1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Kt25HDYdrA6fd1sHcr4RYJiVj2BqShQNQzDC8gM4QH4=;
        fh=ASnk1Y4wTFkeTOU+E/cLf3Oe2EQk2IRJ6mifsMlgcvI=;
        b=QW0vNoZyv38VDEFkTPmuu3cGtHiZY5xOtzCIdQngZEp6m/NkIqWaG2OmSXxTK4yGsw
         ia5YfbLLVQZkpg2V59qInq/eTfHORTyhmvtER/bcu4dMgZzacyWF/MBdVF0T+M55U5x7
         ccwPqCeyszAe+ASVOaggOJTAyuiIX5e0+Qq3dKTBGawnKYBq/fVv5IEs1qtpoiSXnw/d
         byaP3MtVi+b12mAKtMIw4qF3hEZkoTCUr0mwCPg6dZVCy11lJfKO2N61aK0XTCeUk354
         aY6CyIxxlJh+/r9nE8zCa/0orME11TU1d8T3NbWl3onVDc3BLzxIxTFTfKD8rMGTnxHQ
         MS+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=D4aiAFjt;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772624; x=1744377424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Kt25HDYdrA6fd1sHcr4RYJiVj2BqShQNQzDC8gM4QH4=;
        b=voof3y84N0o2580m9orezt2+bt53auEuHPrGVvjJXro20jQkApFjoJMpAJnx+K4bv5
         qmRJqUNWihefiL5TbSSRhP94EpOdGPB3+nRSr4wkJ+bOK6RIYQ3IIQ3ih0B8bxZ+PZVQ
         RfcJrO5v3eEW3/Ix1DTf/9yXwQfHw8FMHE8h1iD/Qocg1CtdL0hBNeE1wZGEY29Paen2
         nuYt/fDQM/SX6VQbKK34Y/uKUT6/QcdYnAdgZesY6HF1kZBs4iHwia0TGestdNgXRoCd
         Lnp8bsn0gG+8E7+OonxwPJusjD7QIJ6vFPSTqMQumzz6/UB39EBkpIkrpnyfpaOWlFi4
         8bug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772624; x=1744377424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Kt25HDYdrA6fd1sHcr4RYJiVj2BqShQNQzDC8gM4QH4=;
        b=rx0TikKsUHDbf+Vuy3tobsCqwnjrsXf6WQeinNCuMMw6m60pHiHlKXrzzNqheBOqRI
         AR2p9E95u4GnYcnCCF9RafdIstHUejiD4gUuA6s/0LVA5Eiekk1pYx2aQHo5kmXgj76v
         7Tp1yjVtkaWRTofB9dJabwanh3WKV14ON1lmiu4luykFR0ZqHs8pmNArQruUxUXbmuYm
         27UzDw6q8y8Szeq6UrgoRc8QnHYB51FmVIba7t9P2ZJ+mqXkOmFFHmwwwzI3pqoX73Vr
         q4tWXkI2erRkJ7Yxmz/YKBJdGaxExhSieGOygCTT6eCO6EM2cbKGXM1HlXKOhJ48J8zk
         uxFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdPu8ByPTRBS+PpgYuJ+q+jcSGqVAuAAye7azze9qoUDNc97LYxrIivTDuyrKmNohfnyXnug==@lfdr.de
X-Gm-Message-State: AOJu0YwDDxQZX9U8ynhQvIP58njkVJL6OQTdVp0FSWamtEZerL9uJBDH
	dL1abATOMJOwPDL2SsAurUoSgvqXvdBGgp6E5S3h2vdTE1Zozch1
X-Google-Smtp-Source: AGHT+IFdevBgfeZ6qSiGq1ttRZBQ+nrhj4DGInyNfQhFLzJQs7qejegZ6cxLtA4m8UF/ZXrck/65IA==
X-Received: by 2002:a05:6e02:19cb:b0:3d3:f6ee:cc4c with SMTP id e9e14a558f8ab-3d6e3e680e5mr29647695ab.0.1743772624520;
        Fri, 04 Apr 2025 06:17:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIKU12HAd57PguZC+jkNAmc3EKvWu/vi3E86j462EOsxg==
Received: by 2002:a92:c60f:0:b0:3d3:d548:983c with SMTP id e9e14a558f8ab-3d6dc9bbb8als9377715ab.1.-pod-prod-02-us;
 Fri, 04 Apr 2025 06:17:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1kEuiZCgwt0FfAyDuJ9D1y+s6CH22aF0hC4kr8vWcKBS6Bmlms7u+DQJIhEJhxVqrJD+bbJrtVIw=@googlegroups.com
X-Received: by 2002:a05:6602:4c82:b0:85c:c7f9:9a1c with SMTP id ca18e2360f4ac-8611b52145fmr349000939f.13.1743772623849;
        Fri, 04 Apr 2025 06:17:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772623; cv=none;
        d=google.com; s=arc-20240605;
        b=QuxBRj7jnSTg2jOEL2q/2x3ykriYRLwK0ScYXSf8ARghbKiIHda/AnZgKKjwocWakY
         HNou0dKJ4xkHYtBlNv2YhANgoDpafvNz6dmhiGxDgR1zQonHq9uDPCBiaYRvda0cftCP
         NQvFlfSPT33T+09N3hAVsKHus1jlY0I0HkG9m/hqBK+ykVvrUwOgMK6mdGgMekdd0iRq
         mrp3lvrfiPoBRL8ekpqfn3aXkvSaECsmplU0ETGATDT7DXRFXplr+bPxBZOH6Tk1D7db
         OhXK4eHD2sL9+dwbHysEKYBIjqCMFeuwNVJw8KyMTlawCwzYDB0H6KE5y7wgrcyrfakK
         5XWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lnf6pC/5n4SCy1ffOsH42Rbn/6DISiknxHlO/AP+4As=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=jH1nbb/E7SPxqbcOyUOZxZvhn7lFkBO1pT7I493/wSEkkmZ8kZifufR9DcJTmqk9om
         PiNysk1seB2qvR0x1clfCNO1Yx1GiQ6wkbhLoTe4GB1c5chzpiC3Twhu3QVWCTsPz42e
         p3qtmQxX+rlzNHUh/1ZSGwOk93xj2f8SlkrX0b8jtv3qLqLLHrxOPyW9Smwm98RkZKZy
         UiygxNwAhUoCgp7v/NyAGVrcOuAJjSvwhLv8S3TsX4WEV4uoUNobNtrSOxp9xQJ3UtLI
         aEGL7eDikxxEoiLIgn1XRwbsNUNj4zyIBdkXFJ1C8mp/FUYejlUWrjIorRduJCHficqT
         2LrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=D4aiAFjt;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f4b5af9dd6si165435173.0.2025.04.04.06.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:17:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: WeW4qKh+QFG0opNP9WQszA==
X-CSE-MsgGUID: SgjPCpE4RMua+Hn/dXv26w==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401892"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401892"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:03 -0700
X-CSE-ConnectionGUID: 3+mynkr+SXqFVcdE3tJihA==
X-CSE-MsgGUID: ZzPu2O3cTHCCuwduFbu/7A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157271"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:47 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: hpa@zytor.com,
	hch@infradead.org,
	nick.desaulniers+lkml@gmail.com,
	kuan-ying.lee@canonical.com,
	masahiroy@kernel.org,
	samuel.holland@sifive.com,
	mingo@redhat.com,
	corbet@lwn.net,
	ryabinin.a.a@gmail.com,
	guoweikang.kernel@gmail.com,
	jpoimboe@kernel.org,
	ardb@kernel.org,
	vincenzo.frascino@arm.com,
	glider@google.com,
	kirill.shutemov@linux.intel.com,
	apopple@nvidia.com,
	samitolvanen@google.com,
	maciej.wieczor-retman@intel.com,
	kaleshsingh@google.com,
	jgross@suse.com,
	andreyknvl@gmail.com,
	scott@os.amperecomputing.com,
	tony.luck@intel.com,
	dvyukov@google.com,
	pasha.tatashin@soleen.com,
	ziy@nvidia.com,
	broonie@kernel.org,
	gatlin.newhouse@gmail.com,
	jackmanb@google.com,
	wangkefeng.wang@huawei.com,
	thiago.bauermann@linaro.org,
	tglx@linutronix.de,
	kees@kernel.org,
	akpm@linux-foundation.org,
	jason.andryuk@amd.com,
	snovitoll@gmail.com,
	xin@zytor.com,
	jan.kiszka@siemens.com,
	bp@alien8.de,
	rppt@kernel.org,
	peterz@infradead.org,
	pankaj.gupta@amd.com,
	thuth@redhat.com,
	andriy.shevchenko@linux.intel.com,
	joel.granados@kernel.org,
	kbingham@kernel.org,
	nicolas@fjasle.eu,
	mark.rutland@arm.com,
	surenb@google.com,
	catalin.marinas@arm.com,
	morbo@google.com,
	justinstitt@google.com,
	ubizjak@gmail.com,
	jhubbard@nvidia.com,
	urezki@gmail.com,
	dave.hansen@linux.intel.com,
	bhe@redhat.com,
	luto@kernel.org,
	baohua@kernel.org,
	nathan@kernel.org,
	will@kernel.org,
	brgerst@gmail.com
Cc: llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	x86@kernel.org
Subject: [PATCH v3 09/14] x86: Minimal SLAB alignment
Date: Fri,  4 Apr 2025 15:14:13 +0200
Message-ID: <173d99afea37321e76e9380b49bd5966be8db849.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=D4aiAFjt;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
tag-based mode the size changes to 16 bytes so the value needs to be 16.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Fix typo in patch message 4 -> 16.
- Change define location to arch/x86/include/asm/cache.c.

 arch/x86/include/asm/cache.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
index 69404eae9983..3232583b5487 100644
--- a/arch/x86/include/asm/cache.h
+++ b/arch/x86/include/asm/cache.h
@@ -21,4 +21,8 @@
 #endif
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#endif
+
 #endif /* _ASM_X86_CACHE_H */
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/173d99afea37321e76e9380b49bd5966be8db849.1743772053.git.maciej.wieczor-retman%40intel.com.
