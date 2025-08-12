Return-Path: <kasan-dev+bncBCMMDDFSWYCBBIUC5XCAMGQEOUCZB7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 74684B22859
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:27:00 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e54d60a4c6sf16913475ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:27:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005219; cv=pass;
        d=google.com; s=arc-20240605;
        b=f+dASge0R1m6xlAM16iRIaGX6po9DyhyxYO+ADxf3Q7BfVjUjL1QhaAyzd3+wT5FyL
         XrLG3uAyur6Mdeplx8m8AdPzAyrRoQNJgHTMTJzPmvVsRGp9/eamxYyYCdq0giyifnYl
         TE8fwmd7M/k6QNTjIPNDXCQS9W4bB5dFLZoR1+wbHJx1nNssyDVhsoHlI2ox2EWt3gvz
         hNqCK+RfyWJ6uB4tTqmyksNe3AngPpLwfr2jSIKlkoCeQaBJDyzJC4J6Ge8atWxxIn/I
         GtGW9iQ2PIAsmu7JvMZUD0a1UdVaTO/ftUqP6r9koOGqu0HEV3qXEU6jDY/VCDKv34vZ
         TLLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7JU94JCbCJGLcXPOmCSV/qSCanfqZtUairxEmC8TzkA=;
        fh=5eF9iQy5zXyF+5GwcbUJmGgkmui1Xija1GKiUJzPiFM=;
        b=LY//LpUVjgX5jBLptk0FT5q2XJWubteVdXh2Xehq9k5NBz9uiQWA92JQAndi84FX1A
         hzTvGPqGDDEp++55Ewwd4eVfcj2Qek+hli9aPJ2Pspb7xyX/eb7t/CT82qUnE1w1Lnan
         8bwuhPHr33qvxllL34m+2xOBzqsr7Q+yxxxPmUJ5bCU0dGV3XLeh5tFxTLbxG9jymxRz
         XOOM5CPZhaKZMs9y5qPVDPdw9Gfdu2eA807+P3xCqtZxb3hr6k0g+Nnn0kOtOQq+zEPg
         QU2WCoW5gEdpQ1fSYcQAYCrxFJ//zqUFMkaLfjwx0Yi9TSQUVgxZ2tGzTcXzKWnIXcpW
         fkZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mkqDmPbE;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005219; x=1755610019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7JU94JCbCJGLcXPOmCSV/qSCanfqZtUairxEmC8TzkA=;
        b=LA9tGDjWhDXtmObEAnhdRdvWYQKIZVtya+7U/5vpj3MaOddXNr5HHJHwrtKgwXZYBt
         ybV7x0a5CYZWLnhllc3KXz8GJSziv2yWVnPgCuE2D8HRKLbQl3kQHei1rBzYc3Nk3LT4
         7JzIb5QQwJhbZf2CyPJRRlYcVKWLhY4XdlUMZ3Gqxl26TvvY3YDp64V7TGmlgP1hc5tf
         4uGF2y+52R1Y3J6TPwmzZ1Rr5RzydwB1nWZcpIc0rRf/1bVZgCNFEAhE2zU8tSLSRPgj
         FtkjM92f/OtFdTzrus+yPNGmlyGF8X4HYVmMl1aCRiTtDwxF2IBZeHPIM1OPJaBKamfc
         gpow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005219; x=1755610019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7JU94JCbCJGLcXPOmCSV/qSCanfqZtUairxEmC8TzkA=;
        b=FIPbMmTQixRJoQ2CmSilxh+4hPPboMFJBRGv9lrretztMlkOwSWqrwm6g7rlY7OtIk
         jZPuRTXepxknppe3qT6mYG66frrPFQGwOUa3AflUt+vXc0PbLTEPaS6wFZTlSGvECc3h
         9bBLgLQCq0juYMpbqoJ9dDLAm2heRzbKa/i6ZhbcwYB+nVWnGaXZo95/4/OwnHO7sY30
         48XimI7+l0uGniHlQo/xOKQNIz15n3/s+v8i162wZA2qZcorbtUt5b46N8aeaZ3qUhP6
         C2GrSFnVNj2f3eWfCTe9h1ecCt65yqvCShxcXOov5796v9/T/gBwyoiLmjpTEPPUJRWN
         ieVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSuYgj4w2riRC+zCog5QmPccQL+s7IOQFvY41kcnSzk+6QMXpx5bObFxjPgza1g3af7B1pyQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw+/AXHGZPcbuHqTrB0uOvdGwgK8GFRY3N1fN+egDAdj+IbzgW5
	QfCj7vITz2FmVfxJjJqc8CLK4RXR+6hTsbsPbMxc7YmAccunN4NoGLRm
X-Google-Smtp-Source: AGHT+IHAzYBw1z0y32Za1mxUTh6NjGlEXjXZty9X1K9bJcG3gQBaKn3M49DMivK44fxGEnvvY5sdEw==
X-Received: by 2002:a92:cdac:0:b0:3e5:5466:1aa1 with SMTP id e9e14a558f8ab-3e55afdb1d0mr59061195ab.22.1755005219026;
        Tue, 12 Aug 2025 06:26:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeDwxcespx9tf9eeGlCqvdBB5droqqW2Mq1yPmffC3xnQ==
Received: by 2002:a05:6e02:491c:b0:3e5:4c39:3dfa with SMTP id
 e9e14a558f8ab-3e55ba53862ls6765205ab.0.-pod-prod-03-us; Tue, 12 Aug 2025
 06:26:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYM3JQZcrpA2wM/eHWg9v2rvHiPOmP6h5DnL9fFieh4EW9mWUvna54OT7AYmXC7HLJzZ7HIdKo+gM=@googlegroups.com
X-Received: by 2002:a5d:8c97:0:b0:876:a7cc:6eb7 with SMTP id ca18e2360f4ac-8841beefdf0mr569314539f.9.1755005217776;
        Tue, 12 Aug 2025 06:26:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005217; cv=none;
        d=google.com; s=arc-20240605;
        b=ggsmsr1enzHe+3el7zqL7AvH86gtF6dRFTMQJeszeMLF8gAmG+a9DyrgW9g6qN9t2C
         +ROGCf6ZlEIdALEfbPAHUnYcmHtjTOT1ySbfKwaEFVwFiD9kagcRRlaTNE+tHw/LNgTP
         qklTTvpIVnxe4Z3lri9rs6Y5DtpUVQf9SzlknaUwny1DgtCLamq+0XwNw4wIbI0qv3vI
         iKbOsVrMg/r8pDjw5UMsBA+iZbi/7YKKtx0ENnzdRMWHrKe8DRKQZedHElMk4XVCgq+J
         bQW8uSsrh2P0IFe+rE04vA6+4dTmIvS2p6GUx1VXxEMwWo50Y6xtYSHWZ0ECrtcMvB2b
         +X4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YBDY9caHiLZSBdqQj+HzWMgmCJ6zu6xj7R4xJfDcWQE=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=k8RRDmN6NyvRaIUxqx6SkL2n+vgPppp+Ge19khcuudNejT15Rp5wY+ximTzmRswFXy
         l4V8oBB7ol/LArB6BCXzFIAz7H+0oHnA+sEZIN3kSkFyo0coiyCb9i1j1H9xYgiV6rmu
         wD4TMKJbccM91lLb9BLfTl9tXVu8mX0ipLYZJAHnouLBTvco3O5rNQmxjCNer0EmFsSt
         7ZQaF6a2sTsCLJWTwAur+v4BONb4lP0amU73/q7kRtVWEwv/UIFRqPIjC0eCLE3gC4xr
         UnukAB3U9kieFhJQ7KKqr/uHAWw20BU2c8P7iXX5/8muIBo9ALf8VF/nXnYjS8hEVn/J
         VVlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mkqDmPbE;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f18eccc3si49156639f.1.2025.08.12.06.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:26:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: 5myjG4ppTJ61JOSNJNFSkw==
X-CSE-MsgGUID: wXhiiDPjQFOJa3Y6uV2WRw==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903283"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903283"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:26:10 -0700
X-CSE-ConnectionGUID: fEBGC8HBRSeUSf2GiP4qhQ==
X-CSE-MsgGUID: dKdrPa1TQk6ZCZHGur3yuw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831361"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:25:43 -0700
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
Subject: [PATCH v4 03/18] kasan: Fix inline mode for x86 tag-based mode
Date: Tue, 12 Aug 2025 15:23:39 +0200
Message-ID: <0ee6ca89ff7617fe7a4eda63ef5cf376d609ccdd.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mkqDmPbE;       spf=pass
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

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be pasted into each relevant
location along with KASAN related constants during compilation. If set
to one all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this, enabling inline mode in software tag-based KASAN
doesn't work on x86 as the kernel script doesn't zero out the parameter
and always sets up the outline mode.

Explicitly zero out hwasan-instrument-with-calls when enabling inline
mode in tag-based KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Add this patch to the series.

 scripts/Makefile.kasan | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 693dbbebebba..2c7be96727ac 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -76,8 +76,11 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
 		   -Zsanitizer-recover=kernel-hwaddress
 
+# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it to 0
+# when inline mode is enabled.
 ifdef CONFIG_KASAN_INLINE
 	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+	kasan_params += hwasan-instrument-with-calls=0
 else
 	kasan_params += hwasan-instrument-with-calls=1
 endif
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0ee6ca89ff7617fe7a4eda63ef5cf376d609ccdd.1755004923.git.maciej.wieczor-retman%40intel.com.
