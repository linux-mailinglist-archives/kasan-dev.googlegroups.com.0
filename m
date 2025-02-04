Return-Path: <kasan-dev+bncBCMMDDFSWYCBBHNARG6QMGQEGEAASYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EB21A27899
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:36:32 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3eba5d45854sf4696391b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:36:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690591; cv=pass;
        d=google.com; s=arc-20240605;
        b=aTZF/kNH7C60s/+o3639s0RoNGtUhqCOXR8WeO0XirhN/rLik9uxh5fPZs2zogr7ME
         AVjd46sWRw2X7RRlW6DadAgjyIGL8ajYEJACCF6sMFL3o1EeGiBoXCyHzqtGLEtks5Gg
         TnykSOtFLJHnkIaiUbyIA877PhSQ9usIQDu3reKfUtjmxgTDk5RNoGrBxotvO0/pZDUM
         E3iZaxXuAUnItYJJG/lhDG5j2NBvUTTWLbzCEH6jjoeKPvofFeUbp1Q+baoEDH1lvKfZ
         QzudcEmoVvoMv48YJQ/VfcFSsBrrA86cLaPWyuyu63HcBreUOUiwcZ0h4mUaXYiD1Jdm
         wYMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/fPbGFmLYx0yFfuyP3kYJ5POrYgZkJNJXdSqro8gjuc=;
        fh=wOp53ww3s0fkkd/mADtUGy3+84CTC5uBseM6fHvsqzk=;
        b=hdCZ2FjHPC7cvDkmOlAlm/ZmubmD7GqqkMp2NNUMJzgXTH8AnmCHt+GuzGAxSZpBuA
         caYZu7+GjSy2T6//bo+gmAtETYcfguJOoViv/mfghzgG4UNFRyeg0l3tIvJQL/zeaBBM
         0qz0vHIZzip+LfLyI2rlAjdAds8WbCogJYnbkcEsnOVLyAO9iShfRTeNc2cyWNbm8QWj
         X93Q9e3zGZ0rxLSCdmSl9w5M0DtfkrXQ6H0zdHdPgsWSRvXiUNJBEn/dvO83FVeWjY7N
         axzSO8JJlO48B8SeRiThhrLdwju/jCAqFxv6u4PFAws9MZn4ayIt68CZuf45SMSPg3aK
         YhYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QJJdt2Pa;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690591; x=1739295391; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/fPbGFmLYx0yFfuyP3kYJ5POrYgZkJNJXdSqro8gjuc=;
        b=Sgt6rjGaS6k78TnhYs4vjJ/7Y81Kgj0UCDdDkzix1/NzXPjBsBvf6w+71VJwDiSk/S
         nzje+1ueER+jBJgG+MaUX1h6eLB42LIxz7i+TqB3zt4Eqod7dCsAtScrZcLqKLDLX4ZG
         IJpSX1ysZmBe+YxbYfZ32dficuS+/dSoC1yCYGufwWhjcEpZYenozeJjKOeB0SfhfAkq
         wQ/JSgR8O9Dwj/AhkW4BLEpUI6KcTrmW5eNeEEaMp5KJi2JtTPPldeSi0mlisMtANnIS
         UmKrOkNrCTaS/X+9qmDsS7YWzNt1a1PKwtdHCxX8ekVqIjYoQvTig/aSzPTH2quqXq2l
         //4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690591; x=1739295391;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/fPbGFmLYx0yFfuyP3kYJ5POrYgZkJNJXdSqro8gjuc=;
        b=UrXMgGInJ3neIvRsVVwQeQz3obx4FLbo12NBD0AMt/DHdft/SJm/8xZ8/JlaP/xwGj
         MmSVuUXPq2U3hp0403yJ1l1kXxrnTGpsrDbe2VbvgKZqn9QElQKG1GDmxd1KtF43sTJq
         R//QQEAWL8fHw1DO2U0E/0/W/bQ8xbsZddSHhjhjz3t4zeHSE8c+wzV02Dbx+UOSeXUG
         yUmVuxGx71RqszdfRGBJKQ8Whe0ZNYozfCjYcljo4H66iEGEEkY9v0zU/l+CM/S1Ue3O
         jsBqLGFevxFi2NWSCEnwr+S0N+ixVzECA3yWX8KJT/WvCkhOwBWrgPtfeo0UnMzK8Moc
         IgcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVT0hdCufXcw2XME0fUbUgjZZY/wXyBYcT8MW6rM/6FppKA4lMr/t+Jhqvy2paMuTFId4ntmA==@lfdr.de
X-Gm-Message-State: AOJu0YxTCDXUaE84c7umUl4l8f4hJr1NMp9lFZgIc/QrUCsuTP69B3Vp
	UhnC37WvCRWMHoXcIxgzZVjnYdDahU4h/RkbPogM3AZsi0B8qXN8
X-Google-Smtp-Source: AGHT+IEjO1ZuT3WqXvw7xzDkickd4QAYDjiVR6RRuB2ameJd0vi/yoKdmZXhEXk10yKaqZl5XHiFRg==
X-Received: by 2002:a05:6808:3319:b0:3ea:6708:51c4 with SMTP id 5614622812f47-3f323a4702dmr18430117b6e.15.1738690589390;
        Tue, 04 Feb 2025 09:36:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ea90:0:b0:5fa:687c:8ac with SMTP id 006d021491bc7-5fc0dc3b1b5ls1915960eaf.0.-pod-prod-09-us;
 Tue, 04 Feb 2025 09:36:28 -0800 (PST)
X-Received: by 2002:a05:6808:228a:b0:3ec:e000:774f with SMTP id 5614622812f47-3f3239ecfcemr18178081b6e.8.1738690588588;
        Tue, 04 Feb 2025 09:36:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690588; cv=none;
        d=google.com; s=arc-20240605;
        b=CX7EPocpM5mbYwLgFrHp3W6VnU12YTHbiUar5QeQf1NXFeJ2P6k9/qHaU9Qm9BR9br
         yn/hfM+4di9RiyBi9nwJPKYFPSDi1N2oGwpY7GZOX3qOJIff7gn40yOjsu9+HO/fwMat
         nkechFEAodWEkI3FWj2+yvCeFqlxTqzfs+/Jz7aDMshFkSIyP0GdHq1tiGdRaYCAyDMM
         MZ58PnKB3cXXNtVbgIczkFfM2OyxhzAbJ8aoANDHgM5G7b+DmcYKlv7AXVxhnnIrkkYU
         HPyqglSn+MVgOeL2Q88KZTdnB+fdcTBSXJWGQb/8KpSxeUyYZb7CQMvadjZpOto6SKpF
         wtqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OjOreTL+Ot1aK4xRTqvixmr6X+5Hdo5QfDrtzsBAFBk=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=Iur83xnStCVTXGSH2PhKyS3uGWN27Aeaqh0aWX9kwRzI4aapV4rKjsMicGHHY0qrpJ
         j5B6tpTWHg+BDcm8A/FouijObeXxh7lGHQA0rQAgwl+BSNmqWEgELlvZ1BwEoq1M0Vn6
         EhI6cMELe8M3Tw5bCWjMUqCs+AO0R12lTSStBENbQ5FajP0kZCofxpQvS1n6/5cK0e4A
         1ZqGsyUuH0O+KMqtIffQ0dKFF3gSpBIKE4Pb8fKRfEI+jYzcDV4C3jMO0S1t/tE7R0x5
         MS3dATAkScPIo+vEha7794JgjtvhUzfR/8+f46+fgdn6NbFa3GphV1du9d9D4nMe7Jw5
         Ew5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QJJdt2Pa;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f333638c7csi671639b6e.4.2025.02.04.09.36.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:36:28 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: ZS6fWmN6SRWTnEun5MY/9A==
X-CSE-MsgGUID: 3WrZmT2XSZ6AMo4edr1ZYA==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930834"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930834"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:26 -0800
X-CSE-ConnectionGUID: jXIRAGRVSi6AV3rBRiAebw==
X-CSE-MsgGUID: yAFfDOxmTeCrIA01iFfVXA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866806"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:14 -0800
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
Subject: [PATCH 09/15] x86: Physical address comparison in current_mm pgd check
Date: Tue,  4 Feb 2025 18:33:50 +0100
Message-ID: <fde443d0e67f76a51e7ab4e96647705840f53ddb.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QJJdt2Pa;       spf=pass
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

With KASAN software tag-based mode enabled PGD pointer stored in
current_mm structure is tagged while the same pointer computed through
__va(read_cr3_pa()) ends up with the tag space filled with ones.

Use current_mm->pgd' physical address and drop the __va() so the
VM_WARN_ON_ONCE can work properly and not report false positives while
KASAN is enabled.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/mm/tlb.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/tlb.c b/arch/x86/mm/tlb.c
index 86593d1b787d..95e3dc1fb766 100644
--- a/arch/x86/mm/tlb.c
+++ b/arch/x86/mm/tlb.c
@@ -1295,7 +1295,7 @@ bool nmi_uaccess_okay(void)
 	if (loaded_mm != current_mm)
 		return false;
 
-	VM_WARN_ON_ONCE(current_mm->pgd != __va(read_cr3_pa()));
+	VM_WARN_ON_ONCE(__pa(current_mm->pgd) != read_cr3_pa());
 
 	return true;
 }
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fde443d0e67f76a51e7ab4e96647705840f53ddb.1738686764.git.maciej.wieczor-retman%40intel.com.
