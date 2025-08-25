Return-Path: <kasan-dev+bncBCMMDDFSWYCBB7MNWPCQMGQEBYQA56Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CB12B34BBA
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:26:39 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-246eb38205fsf12415525ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:26:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153597; cv=pass;
        d=google.com; s=arc-20240605;
        b=KG6elnvalgv+OOVtsUnTaUrPjimEToP9xar9CjaTTgdF9FRovk48Iq2cbYz9TnHBDE
         ts20Z58icUapbvI2H/vtEz/8XE/DsxMUBSPFrezwkdk3qnj6i+g0pHJ69UAWMA2S+scT
         O4SYPtygBv2SVFz9hDRcAc2DrvDI/nIKdeTBqWivGDv4ZR9gTOzvEMEkLQTf8NNvmyCx
         4bCrY7NY+6CvP2u+ejbcNceFQBkHgpGy75E/OwztJq+e1q9XmBMKONHIqqJmZRL6g7ig
         qTP+P4iNXp9Jip4dzWj304WIHkjTzNx7/yKjZyaZE0XIhzw36LRqa3o8ymmftP4GbA8O
         WfXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JJS5iUOEMK+XwpntZtWAB0sTdLwTtAD0WKxgpo+Yimw=;
        fh=YY/1LRu+3fi9QCcyeiVMympdEPg8YYfd5ZJuhrKtsQQ=;
        b=kcKX2lCNcK9wt5L0xYBW9aIL7j2BKoAzx2k2pDjXzsH+IhY9WZ/zlWAWsNzaJ1Xu1b
         AnV5UCruFGRAkDdoMksF5dv4MUyQtY+xSgx74ECIYmHDFLC0IEcEEN04Mzs62XghgG/5
         qboWqvJl03O6v4a3qULip/eNlgal64U/C0VruZtV9KJw+CZz8UnLmTqnFa/hXoHndPTi
         l+K4zH2xItVLd67oHXCfY92F8aY4dIsdqL4i/gEU27tudpb2IeEvsAnmBNx/8LNg47hu
         sVJyMQuDtTxTnfFAbn6nhELuK2So3PhvrSGIdaHvRcs8rRhIkmrUTwbIVlJYzzsbqz+J
         ejSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="XcD7z2+/";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153597; x=1756758397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JJS5iUOEMK+XwpntZtWAB0sTdLwTtAD0WKxgpo+Yimw=;
        b=k2QEpcXWTmcjFAebfywtihXruXD0RcVIYN7hoxD5WD97HUZBiJK2JCvyrXWmvgWydR
         M4bdbgB58VlYwukJY8fXeqS0sNQ0zYTFp9QtWgAHHcf0DFMmHPl8m/iZ32BdWp2Wry7F
         PItsMb5H9AdWgX2a+dakrIHtguwMQAJjahwht5BuIcRVVSpSaZhWcErYPNEaDiyklvJP
         7TILwGyX5qylsAxuQp8xhRHPAJhqk7WkyFKmVSbfCEmmut1V4Pyzs9cElVgTIqV93+IY
         TEEOWVHvEf2wnnWmqSzAV7SlSealR13a4QPGZg4rOgDUYzpVbw6S73y9ofXEWNQL+ZM4
         EIfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153597; x=1756758397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JJS5iUOEMK+XwpntZtWAB0sTdLwTtAD0WKxgpo+Yimw=;
        b=WNsl0S2g8ddyjHg7I90jE9YR1RIfvnYS+WrZ6eV51SPaPkFWy0CQTTUc41xrUEQ9Ns
         9ayPcCVdJuJweAc7A6xhGEBODzxodtLnBj6tqs21QqX1x2C8i/rdClM+X88iwsaW6RMs
         v8n9GYLyNglTD5S1o8SoB+IaPDkKsLYIjvA3cPzLHqsf/M80x1NUPJ4G6WjhveZJaobo
         NDgcOt37CEeYDH5ztFU37TdkNPAx1ns3Os0RBE1wXdlt7EF8oZVLnwgsUwzJhf74AxCH
         9Z9bA0GAJYkMulUUwjdjHplNW9Sy7GyXCxEIZzWENsLaCpmFJNnnuM3tBBx0kthYMEDY
         v9WA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvCxyoAa3ZUPRCOzeM2v0DXYM+V8KyKo6G24Gjk6SuJAAfTlgjRHFRbwz8iHAF/Le5hMQEPQ==@lfdr.de
X-Gm-Message-State: AOJu0YwWd4F6ledmUWoJxUP6YBCekOc3rutOl9HRbsR2SgjS0xFSHZSd
	pGVs99242YvcuSdkxRtAG3nLzRzXJ3xYVYrAHXhpm63IpzCCItvFTPbA
X-Google-Smtp-Source: AGHT+IGIZFivRQ/FNI4ICKI5WBmmrqsltyxzLFbnewvQAC7zsycmMfMesiBdEXo7FlwbwqIgc91i8Q==
X-Received: by 2002:a17:903:1988:b0:234:f4da:7eeb with SMTP id d9443c01a7336-2462edd7d61mr180080185ad.7.1756153597469;
        Mon, 25 Aug 2025 13:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc8ATBij8iMmMuEJiffepxNWdzEUBOd+bWp5oLaNKMwqg==
Received: by 2002:a17:90a:5182:b0:324:e853:c58 with SMTP id
 98e67ed59e1d1-324eb832232ls3808373a91.2.-pod-prod-09-us; Mon, 25 Aug 2025
 13:26:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZbIlPCXPRujet2QsctoeLBLVBfmWNjxeqL+SmNxES5+mfCi4vWsewEUENpCnYp9YvHxLIZdhPTr0=@googlegroups.com
X-Received: by 2002:a05:6a20:6a23:b0:243:78a:827b with SMTP id adf61e73a8af0-24340d7c956mr18716689637.51.1756153596260;
        Mon, 25 Aug 2025 13:26:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153596; cv=none;
        d=google.com; s=arc-20240605;
        b=a0O2DnwWSBLtFEpAKQ5SwTfK6iVvOO7mLIiHfmGZRSGyDU7TJQwmlXMNrCA3yLsyXh
         QsyRFUBfUqmjbbQBVdEHFPo9gZWd2/VLqpYypiG5BhVFVAPn8IqYa3OXlGNIw264wcTP
         dBDqxWjamvycam6ezp8h190Pf6b0dtxlTkntsovLO1IKWpcMcuwnrm3204Qoi1WVQNF6
         FhEpLCh7WywUyTKzbOS291NTSHATPJx6E4gFeJttA2ky2GtGuPesyhAKY2Q98Of7fbI8
         u/tZMXev1Px94oFC2gXKdLmLUYDHce0Hw+UGMcg+CUUGHxj0qDopwUpNEKv7skrrU4R0
         L38Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YBDY9caHiLZSBdqQj+HzWMgmCJ6zu6xj7R4xJfDcWQE=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=DGcDMp7uwhPhU8I0FFGEf+gSasv/dNBKKcaNqjGjiw+qiHOwrInjVGdHlRgR+aNNTV
         kSAxpJolCCp3Grj4YyjSkYFNYI5cUIaK20Utm+yY8ZGUaXWN5q3MmQtQiLOEveif8fEW
         AA1iEb/btUIdgctKemNEUG+quzwLkk+THMbYgploZdoqH3AJkZn6HV11Nw6N+SBmtZcL
         C1HDJ/4w+4GWrRc/8ZJMgsIKVjLW7nWFdKDqIWD2UYta6Cm3OHDn2xkSr13uAFXU/Y2m
         lZ3gjVIa1Ez+4OJnncZyjXyrZsq/Lj3p5DjSrezZ4oM7pnSqiSKwYCfF7WHIcONA1+Yw
         WO9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="XcD7z2+/";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b49ddd31e93si237349a12.1.2025.08.25.13.26.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: 1KdeWy8lQ+Kcjv2eG2QD2A==
X-CSE-MsgGUID: hPsZaTHMQqWa3ZRwOGdYkg==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970339"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970339"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:26:34 -0700
X-CSE-ConnectionGUID: iIqUDEsESZCpnMn6v7RjVA==
X-CSE-MsgGUID: 2PEh8pueQKehSA2GUwmUug==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169779925"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:26:15 -0700
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
Subject: [PATCH v5 03/19] kasan: Fix inline mode for x86 tag-based mode
Date: Mon, 25 Aug 2025 22:24:28 +0200
Message-ID: <98d2c875da80331a51a5c61e8a67ca43fc57cbd3.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="XcD7z2+/";       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/98d2c875da80331a51a5c61e8a67ca43fc57cbd3.1756151769.git.maciej.wieczor-retman%40intel.com.
