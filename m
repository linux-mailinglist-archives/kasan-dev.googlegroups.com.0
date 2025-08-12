Return-Path: <kasan-dev+bncBCMMDDFSWYCBB4MD5XCAMGQECRWQKSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C81AB22877
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:30:27 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-70738c24c4fsf50189496d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:30:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005426; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tb6HsAfEkXovtnQGptSMmBAxEgHgoXZXIiUN9Ap3b31KgIgRT2lH1r7nZ2XDjaGT8M
         fDUO8kLdZYH9nfjlsZwGZ0CNSqRnvwfHJpfYg+rcBv4Res8/zxb98PcIac1pSNkl/oIq
         a0t372YcaUUSe+67CaejF1RYm11wze8+V4cwVD6UL49fbFX0hvoxkuYWMawo6f1w0HqU
         RlDtZ8hJTaP2UPWJUXfun/8NHBYFZ5itpfaF3vm6go5Gq+c8ew7QFL6LlGwpcfNu5h0d
         U6HvQv+/U5lbgSZdEFMjh/kXIP8w4tMsd5S47ooEG/Ze/tWZpy+kne8p1KkGwroGPAHx
         fqfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EReYDCWEnX2J4aokqH8iDJlUeBoz6HLr171ezZN3rDk=;
        fh=A/jH5NJiskgg5jYWO1OUhIDveNsvG7UK9sdYuCXycnE=;
        b=ZV0us+53cmpZdQQSI9cVXuHRBmBUJNBKF9whMuxjiyV7l9aLBJU4u24JFs5ViDz0BZ
         kD8QJ+sTcmaE9uAPZTIH+bzJbYkRiM9SNdmHdhBlw7HLJjDb3wEOPsAlS7UOdkXOsAxE
         ZH2AgqvUonyee1HQYvqCmcYS9w4t8R1jgfm5nux04KJNEeJOcUNfaRP9GXu4vJBwqcad
         688udTNYE7m7zz26cZC3XZopmw3xVIPVwFdJ+9vts/5Xsrc4J3mFbjPZXvCLhjQGatVg
         wrj9qQGumoleFz4Ccds68cnt5nQV24TD0kIzoc34vjSIlc+98JqUZm4comIgA3ld1DXX
         MEsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HpqEEwRe;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005426; x=1755610226; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EReYDCWEnX2J4aokqH8iDJlUeBoz6HLr171ezZN3rDk=;
        b=f4yfmO2T33jGfYRBBxoG/UCXgHPl56d2oTOl0N6VQJ47MqTJVmaXmhTf4nq0KgC2f2
         ZT0GnQaqzAjxQlqWN+yzEuS7mvkAyy4w/tf0Foe+AVyuOMLm4y9JTQCDh4h4aMJeY8zW
         sCDFyrcoxlIWhI8UXLhK2F5Eub48ol97wOPUW3FRQDXEKOH5ymKwGAYyvtM4HK4K1AED
         YymouunAFCex56qHJL6Ng9Z6pm/PRL8kA5EsTqANEWqqzGaSpOpUSIMQnFGu4bqZ+dZW
         pbuJDKtOmBEwgb7ShOSEQDgQPqVOO7s77eCLmd3ekK61gaR8Be3M8UtImhXlcOXYBZ8y
         4B3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005426; x=1755610226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EReYDCWEnX2J4aokqH8iDJlUeBoz6HLr171ezZN3rDk=;
        b=DQy4mjURCJ7xMp4p9vD1cbZo3iaNmhQGJSYLPiY7oS/uQiQkcvLuDubJMlr6/WSwGR
         B129CE2aVaWdo9kSjmPPoQA/e1GuOVoEK+2P+jg/PnUdhIPO/yycN1YdXOcTrsJjOmMV
         34LgGqjZcuOgS1SiZAdps9LcBwW+egzhjk5HfAf6BFx9lB/OReJPiJNw6eWgFNsqw313
         CVBrzVlTrxsLzuODKQVw48zlSLe45d3bXI6xUmknAT5NPJTaROJNqsVrFFCATZY42XV3
         yt1dgE4Y4v4iyPdDS1/Spub/hcOW7K7R1VjKnoELMk96F97a0kiwZxkfQ0EBtGVTKTD2
         OQzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRPrnADJdKG8/YKH0vwC4U89hnoUorFrmo9bpapwSwaoaiLz91JWosYQ9l62Cqx4sJrpfM2Q==@lfdr.de
X-Gm-Message-State: AOJu0YwrlLlCRaA7qYTW5g37vOSczKgaja/Ei706cJQ2ODV/hN2wx/yv
	e7Fddbx61L/NmlJ5Mle9oddOOey0H/uskUNmwZUK5Q6Wg3/VJi7J06L3
X-Google-Smtp-Source: AGHT+IHeQ3wlC55oKoxt+uCGo7RIVrjkFPvEWte11ipqGwN3TlHJErYALj2VrEZIDS1fCMNPhX3mGA==
X-Received: by 2002:a05:6214:5c8e:b0:709:e1ac:d412 with SMTP id 6a1803df08f44-709e1acf241mr16857976d6.19.1755005425811;
        Tue, 12 Aug 2025 06:30:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfgW++Cy0crUJOZzqfhKVX+s/Ru1AkVWXHLEEehczgsmQ==
Received: by 2002:a05:6214:410f:b0:707:71f2:6be6 with SMTP id
 6a1803df08f44-7098809e3aels76493506d6.0.-pod-prod-08-us; Tue, 12 Aug 2025
 06:30:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUUs6REZ45+FMZVphRuvD39GTS4/hLn8esb6ziGtJTzUYFD1v1ZY4Ti3GIZbM7EynVWck+frDVxA0=@googlegroups.com
X-Received: by 2002:ad4:5fc5:0:b0:707:5369:bd54 with SMTP id 6a1803df08f44-7099a3e5782mr212270896d6.29.1755005424483;
        Tue, 12 Aug 2025 06:30:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005424; cv=none;
        d=google.com; s=arc-20240605;
        b=CQ2AgvVYzMPwSRY5c2kmiuH2u+/rMB7XjCHI790V7/Y4GlCd3dfcBsYjg8hFEr7lCF
         szqKoO2eXLD2LIylC/iUktk3+eizniRR3IrJbuoNIXVicP3dUYZXvF3Iebbob0da7ruu
         GdvqiaHdfMMRZde5edekPfEaqJB6wm8tudmJ87HFvLwzmKVcM9WRlh2h/10fb5f80pn0
         7NdYslCKCgIyJVP6LL6luuJp4Q1WLl6RprTiIQ1hPDu/pVfUOK0h272kH5v69mAVs/F5
         qCed/rWuwnSgSCfdVf223yB+A+cUVe+kgC2DtsuQqPV+WYtX8h/2DjC8J523sRGcth2V
         6cQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+FRb88WAfTjJryGAWrsyeX434cCBjyUKjIIkgHfjXhc=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=Faem9TMdZZWyS7Ob+ajP3oxaNdZ/1vOB4/XDdjw7GCOVdnXU2xGf4Assdhqh2CqvzS
         di+r22Q5NgGSIzEpsK75Vh880Be86G/kluIVKcEsC6FdvSg0uqi98d6qLQHFAQ/I9Z4q
         hwStYe3tgwpIIEnrFSYtwbxfZLbdJ/CvZtfR5ZZFA7ERR+wqzmbEj8tmuaPXgkzYDXMh
         guoJ5Zp4EGbCFPdgWbSBDIx+VXhxsQin9S6dv57bWhOtqW0XZTHRM8hZe2yUQgSDP4EP
         x+bBfnNAyIStiz9Cillgwv3OTnDQZ7gF//HuQRdPajvz7QJx54tqh1bOayIsYTow5VK+
         y5IA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HpqEEwRe;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077e0bd4b9si924956d6.5.2025.08.12.06.30.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:30:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: UFrKSuLhT6ymCxnl5Cnzyg==
X-CSE-MsgGUID: nHF/0RoSQPSe4D+DKjZpWw==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903925"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903925"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:30:24 -0700
X-CSE-ConnectionGUID: O4o3sBLXTKmQMTR9muYdMA==
X-CSE-MsgGUID: lT/GoXCxT2av3FFB71gMVw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831775"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:29:58 -0700
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
Subject: [PATCH v4 14/18] kasan: x86: Apply multishot to the inline report handler
Date: Tue, 12 Aug 2025 15:23:50 +0200
Message-ID: <8ace14464d88b51f309b289874760b5d6265e438.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HpqEEwRe;       spf=pass
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
index 93c6cadb0765..cfa2da0e2985 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8ace14464d88b51f309b289874760b5d6265e438.1755004923.git.maciej.wieczor-retman%40intel.com.
