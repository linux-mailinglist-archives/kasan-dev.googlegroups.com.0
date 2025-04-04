Return-Path: <kasan-dev+bncBCMMDDFSWYCBBAFYX67QMGQEAMVYWUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 30103A7BD85
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:17:54 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d43d1df18bsf23280905ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:17:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772673; cv=pass;
        d=google.com; s=arc-20240605;
        b=MQB9wMxuU8Ux0D+OpMp/wdln9/gnDjW6141nVKf0oMn4C7KxMJoIqqthhulImQ+6f2
         Q2V7xaZKZV5kfr0BI9BzBoBIcL5djgQMjy1zBwrmcmd3L3rW8J3RRiJcBMNM6GRCullM
         AnSVCrNtP5c0+oCBItLSCDxh2WDvr5Yxqd3hQgE5QL1qezLcdhlhBlrC6CsLbzrMtVCt
         oeX/ymwQLh37obWh7LPkRdF398lHUR2jvmG8EFCmu2DXu4rzZfxS07HDm12v6qpkE79Z
         FoI0oXGPcR6lQgZ56Fq8Pbsug8soR9T+aMqwoC+MyEjx/6e/1Ijlaheg8d/2QCmqEgC/
         nCLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xY8c1rhnI6aN6LUCEx7MEULldyCGAChtMfPmdyZonwk=;
        fh=FW7vmVOYCc4aGHwhRVYzqwn5+GKNs75kuMsrpmXKE6c=;
        b=F8cW4ioAODhgwY5jC9uk2RImQqwRH5/4y8q+4tvyZrkXFinLKdBCKWtMpAOmAdXUMz
         E0o9vnzwTw5rAgTxm/yZUD9KaHS5A8c7kEhenXWhzwU0F/HWpawfRTUbjMKrgBv3mFl4
         Uie6qMxZmJp2PyldU18ARK7JGRtD2og6mpdseyAVXXeQcK6jhHT6p7V9KRuqWIqoEFmm
         8SwPlILZTY5MgZfLGxMOyboHWn7YzzOaE4b089c2xG5mpts9RveJWLUPIPdFoFyvq5ye
         9iEItDA1EOYVGPy6Lh8isCzbfD3OUF//nNXPqQUVYVNbtIYu3RbxC3cXGdcHFthhZoFP
         MVLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=g7MFaeJ6;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772673; x=1744377473; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xY8c1rhnI6aN6LUCEx7MEULldyCGAChtMfPmdyZonwk=;
        b=IiOnb2RVV7dPBsSuEJRQ6aKHdaKTQnqOWxefHFC5ukOMSeKzrGaBdOEbDRD5TygT67
         CkUH2DlMelumojlmJeaVTNoHPpjMqxNsGLj2inb3J3/pl3+dehKiT6wHrD6CNl0zkOfg
         g7cC86ccH4zUrhaCVpJgZT/844Q3hsPmgEYr3SLZdl6MNhAWWayxD2oSBosGGf0uMgZb
         26QMZ3YBzErheKgDvmMRTZGNoQIV4Y3ZuglA4juFnavCaBX6gq064ZQcQYJWjocmoaGS
         1tw9Ohez+VxPeoJKT38uIKpkr3vqTM7wvVmwiKTzZXmSYt5P/nJxl5rKYC2/9iWVQ+B7
         pf9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772673; x=1744377473;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xY8c1rhnI6aN6LUCEx7MEULldyCGAChtMfPmdyZonwk=;
        b=t39swBCK7dl5oNFjSh76KMZMBx8OkJl5OG3lhD99PjYsANjNRH/+yeGeCsNfnbhg4o
         mPabliVWfegIutTLnUoHcnGVLNc8O0gwPfSUyvmabr+A7Xl3fFPFdiMJ6aH+N5nBheZz
         ixj13cFNysYqM0gpfIQQ9lmn7euoqgsCoYh0D00fRc0401ndBvv+VBfgcvMaquJSHSWz
         Z121u0OSqL1tbmM8Ktbvdmvcveawjm+ZScRW5mIKEWuVYxTYL2hhy7GYaKKF69drFhD6
         NNs3psYJbV+vCLS5r9EMbOKFBlmniKIAJ3vUFnvuGJ/usELxfK6cC4nDF3VzDbbbXm5j
         r4QA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXq2olOQAo+Nj1OQVXNNtc0VWUbsdhxn/9vf3fidcL3kGXAskYN9lO4l2LGWwHrSPb5AgBZ1g==@lfdr.de
X-Gm-Message-State: AOJu0YxGuDIam0Lp8deLv7nruSEh04JadRFXkeDsrAGWo0dA/2DlBMCw
	bJXYyXVnDAvH9ykFn1VbghM4QRYSIdB//JkSkg0wxai4DvPSlmm9
X-Google-Smtp-Source: AGHT+IGVRc9Do0MoMeHW96FH0t5iviB4rMU7mNoinFPcREzDYTt2MzdJ+CHaZSBXtg+rEjQK2scWHw==
X-Received: by 2002:a05:6e02:3e04:b0:3d4:3ab3:5574 with SMTP id e9e14a558f8ab-3d6e52f629bmr27600285ab.3.1743772672892;
        Fri, 04 Apr 2025 06:17:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL56kgV6/SfDBXZI15gFNo+onPRVqhQ0WAA33fNtyTq+Q==
Received: by 2002:a05:6e02:3e8c:b0:3d4:4545:9ce2 with SMTP id
 e9e14a558f8ab-3d6dc9e891dls15283515ab.2.-pod-prod-09-us; Fri, 04 Apr 2025
 06:17:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMQbzZhESi+pRc5BzHMvSzpuxX6y+5T9JkH1lzn6D0J6gVr23Y1s2lGRiVvjUTys1zmW8B/Wv1YUU=@googlegroups.com
X-Received: by 2002:a05:6e02:250e:b0:3d3:e284:afbb with SMTP id e9e14a558f8ab-3d6e53483f0mr22901115ab.11.1743772669554;
        Fri, 04 Apr 2025 06:17:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772669; cv=none;
        d=google.com; s=arc-20240605;
        b=BnFIYEpFZroavOmwAIh/fyM783u/607zbFis1ldkMJP8BHYJhBaEevylmoycXR5tH2
         7p02SbFIgfCeh8DWAxSwV1BejxLPh70Ia1DZMyzkdL6kT6eICYwCPJqEO2kueHiePUz1
         5W12ov9xSjXqOSYPAC1GSVE407+TJkoqV+BvM3HIGXH/mTnW/0bFDxNhD964UVGAkuD1
         q/ZRuSLQjD36rAEQ2R2errh2OnOHs2crz2U7obruIf8s49gXC715phEQKLqH7yJQ4o9j
         g9tXTps85levEsFPG7RJ8D2D0KMwWK6mKWikDC6TozdhvO9KnhcQ64SS9T0dicrG7MMp
         IJjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VZk6z45/TieMCWLPI8iFY06hsd50xsb22xpBUNnECFQ=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=Tk+SVvxCClossgoHNWIu9QcbuiIDZekii5lt5d63C0Wwkw5x29R7XIa8je1sflv3UR
         JKR3S6m5WcLL5t2WIuIdqLTdmtLYBGtlw7R9mNO48wvDMYNICIMyEvUFiNkPBv0jEJG1
         xC1kXlIzVWVaSAtSq4zFXJOb42hGMqLGqv7MXx84xtiAKn//TOOP30CHTbvG7nRERyLR
         a/XyoCUlBkHgB/NLPylnM8eFnyJvRGoqxfAC67kf6G7+Z5n9z0X710tpMVWAD3q9G5Oy
         APDepRo9QF/kud55NivUM4CMJK7V2dtC+AiFDGWip9OylZuylgvITXeOupYHUU+ENSD3
         FARg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=g7MFaeJ6;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f4b5d33778si192286173.7.2025.04.04.06.17.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:17:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: nRQXRLCPQBq+3WM1i9iPgA==
X-CSE-MsgGUID: Rr/rUYqxSpOh/iCUKW2zew==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55402030"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55402030"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:48 -0700
X-CSE-ConnectionGUID: /KZBOILGRPaVrrMli4Itpg==
X-CSE-MsgGUID: T+1IKqSwRheE1ok0gd7jhQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157374"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:33 -0700
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
Subject: [PATCH v3 12/14] kasan: Fix inline mode for x86 tag-based mode
Date: Fri,  4 Apr 2025 15:14:16 +0200
Message-ID: <9a8862c380805ac6c2fc137e8edb1d2e70ee2812.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=g7MFaeJ6;       spf=pass
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

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be copied into each relevant
location along with appropriate constants during compilation. If set to
one, all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this enabling inline mode in software tag-based KASAN doesn't
work on x86 as the kernel script doesn't zero out the parameter.

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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9a8862c380805ac6c2fc137e8edb1d2e70ee2812.1743772053.git.maciej.wieczor-retman%40intel.com.
