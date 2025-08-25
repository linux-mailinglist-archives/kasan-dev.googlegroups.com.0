Return-Path: <kasan-dev+bncBCMMDDFSWYCBB64PWPCQMGQEXGUK7SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 31A43B34BF5
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:31:08 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-246cf6af2f4sf28065595ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:31:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153852; cv=pass;
        d=google.com; s=arc-20240605;
        b=lHCJFLFWeiFvreAdec0/xaxWpe1v1EajgyO8wCedSCKE8bbPTHi/wOoiwr3ZtE1KAC
         xYET32nNwRp6gwd4WsOFewArov4iNJC2HdCu45hsrHfKyxZPmusEq8czJD9/4ZobOTU8
         jcObHxI/kdw6qQjfNdF2/0xIrUVEhdBXsnqezuTC4d3V48KwX+Ci3pglEZ6mfQF2kDws
         zD/EEyDPGi6WAqUbko5hciYS1Oau7PmddrDFqUuRRsy1Hoh3ZZh7FxmLpR9AOCQOu+/o
         0lzvu07Vqzq1PqWgslhBxLQWGwEpMrGG4m2ppuJbQ2Bv+1bDUa7CBbA05fO1+g1BjaZN
         noqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SMOHXqx23KdL13qeE4IuswEoz7Brzjy3ScbC8K1K380=;
        fh=Cxtp4QwLfIklrESDISVY8rNdpPzMcltkqzSHEZ8xzuM=;
        b=UgDUWWILXEtd50mkfU4bN55sN7hq7SQfNR35TDkItgJOqneQKIN9sYsFk3/zkXEzJf
         1DRe2clGp9e1OwdNya338Kz0GiA8xAa1Z6YYyffN6bpTSJccdCmANC+Q0zy2oG31BajK
         hhwuTFEwQEU8b2fYf9OXARjBnGY9xRKE6MGyN2DbWKHawLm1lwr+cOP4Db0e3j88Hxiz
         1c0TWkFvjAmrbMd7y8GezoqjN1ti78NX3NcmgfQM1gWyjAYpMPXQIj9UsSEL4rIW5R2J
         +fKoabYbWYfqhnrsN2Sc4KG4FO9ewYUtmomiOi0/wyK92mmJ8/JPa2a6B5t4c/NIRzli
         a+cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mex5CDkD;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153852; x=1756758652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SMOHXqx23KdL13qeE4IuswEoz7Brzjy3ScbC8K1K380=;
        b=GvnvmT/O/L/eXcj1KkZ+BfP7el03Fawk5SEOE8MXww6aP4VSxmkmPcmZlVvzdJFTxh
         BL4JlLUKD9BVWSnJtOlhvxwsCbQT9umzl46E+ZCs+A5O+muotfD2zG0rz5tKC4FFtN5O
         6GzqpkJ50EpKFqHn4DytDCv6om50jpZCbOmqhfJOuvky0RmYkfHuVCbSBJsRiab/TkaP
         M+GGmzyw80RWFw9hEn17yCUcI4t018EkJ9KemxeC2ayibFrf7aiFdQiU8kIkp/4CMVJt
         blfDy87koHQ1vO9nY0+d41f7NNrroeUBl79GTEF7Jx7DxoFyZ7DnAKJNIVyJP9v/r+DN
         Vp5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153852; x=1756758652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SMOHXqx23KdL13qeE4IuswEoz7Brzjy3ScbC8K1K380=;
        b=ArjE4RhZRXuoXZsoQSsSMFysjKhoceah17c+/08wABX0FKAdsqu74Z3qUaU5Ztedk4
         xm225gNLNGnJxAxXhyeb6lrQVQCQTgjHX1JFwvhKurUkvNSN6jqvhafJ8lj6hYigEPmL
         JgkxARchkOKG1d+umHZXtxFTlRefktFH8xA/Q8p2WIRPWNXkqdkNRjOvmN4mOpjuHnr6
         LjuU6Fcb1eBPp9ntG6/l326lXto1gIVz3yhJEAg/An4tbVnBaJKLUxs4GDAjFTQT6/Et
         D07blsQVV4os890hKADETkHQGN64T2grKz+pLyAox7GjJwKv1dj79xUQbAZ8IzCNYR7e
         7yNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrJdDKABrMlCoTXd9X3bWlYhrL2SZD/JtYOO9gRTi+PeQlxemiZ1mhT9bmmpPqeXQ901fm9w==@lfdr.de
X-Gm-Message-State: AOJu0YyPRCXeejX7psV0gNc1GHaQnUua8MipJZKTIdjQcolZq1ffhjZu
	em23or2x4arXdW92wsePyIu0tvOu5/SVf44yDBcYPXph7QPq9QXY8sld
X-Google-Smtp-Source: AGHT+IFO0FzP5yUSXK8nBAj/gWEqsJeGHyOxLa3L6eFMNMsZCd8NPLtvpjYr88xhsHeX9Fpor8blBw==
X-Received: by 2002:a17:902:e891:b0:245:f1ea:2a23 with SMTP id d9443c01a7336-2462edac953mr185968835ad.10.1756153852125;
        Mon, 25 Aug 2025 13:30:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+jp2fnPknyMyE2MS8I9dlRKbWuCCTnj9wVvjzVZoK+g==
Received: by 2002:a17:903:340c:b0:246:64d2:f765 with SMTP id
 d9443c01a7336-24664d2fc77ls21649135ad.1.-pod-prod-06-us; Mon, 25 Aug 2025
 13:30:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqIUplm5VPaVXvCfm6gVCjyeJJ+oFMUpysmWWDi6KZkTXXhoFrIUA9snXgbLCe4B+pUpvfpF0jObo=@googlegroups.com
X-Received: by 2002:a17:903:41cc:b0:246:b58b:8b86 with SMTP id d9443c01a7336-246b58b8f44mr60044795ad.32.1756153850837;
        Mon, 25 Aug 2025 13:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153850; cv=none;
        d=google.com; s=arc-20240605;
        b=e43/3mMJJEG7jTGTgRTom3mikJHLUU99ULGVmxSGDWeqpp23+2iAD/Ovd3FvLHFvIJ
         p58sv0EB/GFUDx87RAuoCJ0JWX1REo6aAEn0aSedSKtRwrmO74LWnQLBIy7aOEFSOX+b
         XOKgKY2sZuW5n0JKRt5Vbmz1rtCEI1W7jvOfOSCzJ//BnqdU30PWUz0otFuOhUtQWWlS
         Kt4PQVJd576jNBinLY9vTAWZ9dYclrthOnvlMGzFwMBNT+PlGN4kB2pE5faDVrM3jaSM
         bUJ4kqaH1Fg1G4H/v8mm49qGKCHXsdk2YPI7UHt1O8HT8ERDJ8TeJfVpLY/HP5IZGGWW
         U7Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XP32GgD+gomeVeYmlRqjPEh/ESuam3YgqvUl7LwQmAI=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=SQUJk61cgb+EbzpKwGx8kaR4HxsFDukdMezHYNrGeLB/suFcCU6+yj4dDXu697TYga
         95OrUBsX93Mbg/DC6Y+hNiwZil8bTvwj1X5ix0lXhYJ1+KI9gk6kqOFYLqGn7rAB8+5s
         hpfbw6mcb8nrLKFb1swaV+MXTJMIx7b5QwH2NwvarH3HdAxykJ65clLZ0IvBgDJ5rLC6
         fe2VYTSIjAeghTwtNL30KUtq4B726UT9ilJtHU7K1hk39Dn1FZ7Th0xoIs6uzBbfajjO
         5Qr6iZwEONBmj6kJx0kTzP7OeNG1+/92+FciWru6+2cr8TCcMzeW/xqyCJ1jwKopC81x
         OLDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mex5CDkD;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3254ad966a8si319275a91.0.2025.08.25.13.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: KNFyhRp5TgOrLkXAM4NKtg==
X-CSE-MsgGUID: sWQTnyccS9ezc2+hoIbuJA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68971017"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68971017"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:30:48 -0700
X-CSE-ConnectionGUID: K2BRmtlySGeelzThEKb4eQ==
X-CSE-MsgGUID: X0GDFQZSSQO4ZbqrrO+rdg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780899"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:30:27 -0700
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
Subject: [PATCH v5 15/19] kasan: x86: Apply multishot to the inline report handler
Date: Mon, 25 Aug 2025 22:24:40 +0200
Message-ID: <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mex5CDkD;       spf=pass
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

KASAN by default reports only one tag mismatch and based on other
command line parameters either keeps going or panics. The multishot
mechanism - enabled either through a command line parameter or by inline
enable/disable function calls - lifts that restriction and allows an
infinite number of tag mismatch reports to be shown.

Inline KASAN uses the INT3 instruction to pass metadata to the report
handling function. Currently the "recover" field in that metadata is
broken in the compiler layer and causes every inline tag mismatch to
panic the kernel.

Check the multishot state in the KASAN hook called inside the INT3
handling function.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add this patch to the series.

 arch/x86/mm/kasan_inline.c | 3 +++
 include/linux/kasan.h      | 3 +++
 mm/kasan/report.c          | 8 +++++++-
 3 files changed, 13 insertions(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_inline.c b/arch/x86/mm/kasan_inline.c
index 9f85dfd1c38b..f837caf32e6c 100644
--- a/arch/x86/mm/kasan_inline.c
+++ b/arch/x86/mm/kasan_inline.c
@@ -17,6 +17,9 @@ bool kasan_inline_handler(struct pt_regs *regs)
 	if (!kasan_report((void *)addr, size, write, pc))
 		return false;
 
+	if (kasan_multi_shot_enabled())
+		return true;
+
 	kasan_inline_recover(recover, "Oops - KASAN", regs, metadata, die);
 
 	return true;
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 8691ad870f3b..7a2527794549 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -663,7 +663,10 @@ void kasan_non_canonical_hook(unsigned long addr);
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+bool kasan_multi_shot_enabled(void);
+
 #ifdef CONFIG_KASAN_SW_TAGS
+
 /*
  * The instrumentation allows to control whether we can proceed after
  * a crash was detected. This is done by passing the -recover flag to
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 50d487a0687a..9e830639e1b2 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -121,6 +121,12 @@ static void report_suppress_stop(void)
 #endif
 }
 
+bool kasan_multi_shot_enabled(void)
+{
+	return test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
+}
+EXPORT_SYMBOL(kasan_multi_shot_enabled);
+
 /*
  * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
  * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
@@ -128,7 +134,7 @@ static void report_suppress_stop(void)
  */
 static bool report_enabled(void)
 {
-	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+	if (kasan_multi_shot_enabled())
 		return true;
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman%40intel.com.
