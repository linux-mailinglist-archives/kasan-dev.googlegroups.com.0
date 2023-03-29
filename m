Return-Path: <kasan-dev+bncBAABBCMLSKQQMGQELLC66NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A88676CF23D
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 20:38:01 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id o37-20020a05600c512500b003edd119ec9esf8277508wms.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 11:38:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680115081; cv=pass;
        d=google.com; s=arc-20160816;
        b=flLAdAFaktkIH8VHG7fVghnVRSlKN5KVduJWnHkpJMgXRIO3ZdFLzJMWGMG9aXj7xb
         vmRD7bkUI9dO8Awlzoolk7qZHJ8IJOrxT49fIB/cBm/coEpMtAZFoigAAV8N3KR2fJvv
         39tbEtg24yUP/PQurs3HUBq22pS1voP+JOXKt0lJSQdo42+Hf6m1fCk852JDRKnse3l0
         kjQ0RuzPqAOGYxJd49/jW4/wyO7pE/Vp1RjiIzJOesVBVSg4x6WZ1TapOntce/Bt5ruq
         MMA35w8jguMPX0Oxy0awjVlVgtTUlpb7l2+DQNJZ5AjBeuWiiRQLKII6zkS12z8QHCDr
         fx3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E8Dl8V2hYWcIqJhh8u5FVspV1gtHYXrZc/5Ep9c1AR8=;
        b=ocx+eTXJeHAONvSdYtFirSRGEyOa5wFlBa3tMAWUk6Rda0XVEHoqzosKiFaVOVZhKk
         fOBQWguMBRWl6g1ny3jDJyWgPz7+cq6HPlxl7IdWtFp7la2Ug5Ck1wouipz7VyT+MCCJ
         3I3pwkIUAL1C497nSEra71GhoRjvyhOMFJAmTDLWEroMDxy6JQSzKW9fjU1R5nSqgk+q
         O+D3sb2QWdB6KkOCIJGzqbxLZTj8pAuoeLchFIrc2XKiWA1vw9NHhclYuPPttLE5RzEg
         Sy90gKjGSuy2lFHh0o1dj0lZoxxq6XXLvlGY0jFeTOAbuEaG2+Y0Me8UCc6VMo8WmcP7
         vR4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QgAd4ttX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680115081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E8Dl8V2hYWcIqJhh8u5FVspV1gtHYXrZc/5Ep9c1AR8=;
        b=mrRy7vO114dak/ji10M0w9gSCv+TxqbQsIvnhUM8k3tx+acTe91tAK0ElLy/Ham0zm
         BN299QCFUouk4X/1GOksVVb6CQtKiOcVnTkZ+Z+v/jtXL5iua95x8i7JhLtF44QppS5+
         jzwsMHLeVo3yH+lT3P8/gd5DpqVUi+Ogzddg2GWsKrPDNPiNv9Ge5Rwk3Hdk59J/VB+o
         XDbfeCKTcSeIMuI6vJLAzCK3weIfxTX0nrief4RviroHPLGBspmNavyz1To2QhUDk5/n
         hfQxTl2qOUipBca7H9mlKLanIU4jR/1ys0SjTHbsrGUH2r7vYIH6EiJFBTyA9YLov8mK
         QZXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680115081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E8Dl8V2hYWcIqJhh8u5FVspV1gtHYXrZc/5Ep9c1AR8=;
        b=aiFGIJko9wQZ+MYTkYoUPzkmRNPC8U+7fZPIqefKvW7uJemb4fVuS1uDlBjqxVBBSL
         GYhndGP27n+efLzZ75lQ6GtXpeicb+z4C75OCCDygzAiozvRfhqdMKcJYkSW5T+Eumq6
         OlXSNJ1Bp3nBvAA3taf3pYHa8AfK4NavIX/2JG6mcjOH2juIF7GGPltP61thckYkORSQ
         mrdYjPBjuUCJkLRG0N/LRduEMzdLIwfE8+TrqEREDB67PGJrhYBQmd7O5KBGUV7hd1pY
         +xCZalWXpKqlUJw9s5qJD8AGaYv8dkklrGlyH+uUVugPfE0BUl3CEiNFj5CoHtd33hUh
         rkug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fG4aH92pnBHSMZW5nUMxbydlLJ6wl0It3MMyjpQWEgiPQfkbzx
	21zKey4dgk8R+fPaorUtuv8=
X-Google-Smtp-Source: AKy350YQdhTMfDFpFRHFJDc3lgiTuqi/8AbTQAafRI9GgZCnUfqtk+7HFn5Pf0XuW/1JSS7+ca7/5Q==
X-Received: by 2002:a5d:6b0a:0:b0:2d2:4920:8019 with SMTP id v10-20020a5d6b0a000000b002d249208019mr3607599wrw.0.1680115081278;
        Wed, 29 Mar 2023 11:38:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1cc:0:b0:2c5:5262:2e24 with SMTP id b12-20020adfd1cc000000b002c552622e24ls24997434wrd.2.-pod-prod-gmail;
 Wed, 29 Mar 2023 11:38:00 -0700 (PDT)
X-Received: by 2002:adf:f544:0:b0:2cf:f2f9:5aab with SMTP id j4-20020adff544000000b002cff2f95aabmr16868368wrp.20.1680115080265;
        Wed, 29 Mar 2023 11:38:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680115080; cv=none;
        d=google.com; s=arc-20160816;
        b=PHmIeiE0mWdKY+MJpqLdGTCuVRGPpFozn9thOHatVuaTllySIDbPvrpohq8sf4ScvZ
         ijWS4tnCmMsu5gvodDhy2+Jk2cOnctR/PcGmuo7IIQtJKXwEa8eVofMbEfRBeSooMJe6
         fAVc1hPsFbbbsVZJSELiqU+C+Yaa7fIgKmCggl7wY/Q7G/R3YI2Xdn1NTzc2dEG0zaZh
         4LXwleRFt6/m/0ggi/uaOw/781k3UZzulb5R+I3eLGBUW0QQdhvKVNj32Nfzu+E2WXhC
         yz+3GDxdLhxSvyuTbXvVWAexlT24QpkNrqH+mQcR6rEpevJcKu61Vbqawq2EFSKGoKqc
         e+gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4IBB0t30IQWFgjzMoDMwNtgr4khYAd9V6YJirYANKJw=;
        b=AN4muMpQ2HAIkAyB9udhKqU1f/BYNDworBuE7hZuj3L54+G9FtvxSiXbjo+V+FjdqA
         asN2hNuvJIKX8ioMmPy4Vf44lDlElsLWNrOD6+ZdxdGg6I11BAx/0zawBKbn9h5IMruA
         JYUsOobYt8AFIRsPrVVK1YOFeRcetAldIkeOixjhq4WqII1Ts9OCW26QTeRnZLzU4Kqt
         P5v8UuGe2a1HrRgjEHvOXNwAGAJR9O4aYdsIoE9gD/KaVGkUhESezmzKfwxgvi1O5gLP
         L1pLR6sbeLzUhmFVjr/3rl5Htkh38oSGgRbuh+jiwa+u+y96P55zBcUePA5SP9ffuHwt
         tLlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QgAd4ttX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-1.mta1.migadu.com (out-1.mta1.migadu.com. [2001:41d0:203:375::1])
        by gmr-mx.google.com with ESMTPS id p30-20020a05600c1d9e00b003ede00b425fsi337883wms.1.2023.03.29.11.38.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Mar 2023 11:38:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::1 as permitted sender) client-ip=2001:41d0:203:375::1;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 4/5] kasan, arm64: add arch_suppress_tag_checks_start/stop
Date: Wed, 29 Mar 2023 20:37:47 +0200
Message-Id: <7ad5e5a9db79e3aba08d8f43aca24350b04080f6.1680114854.git.andreyknvl@google.com>
In-Reply-To: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
References: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=QgAd4ttX;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add two new tagging-related routines arch_suppress_tag_checks_start/stop
that suppress MTE tag checking via the TCO register.

These rouines are used in the next patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h | 2 ++
 mm/kasan/kasan.h                | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index faf42bff9a60..05e42bd3555f 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -264,6 +264,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
 #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
 #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
+#define arch_suppress_tag_checks_start()	mte_enable_tco()
+#define arch_suppress_tag_checks_stop()		mte_disable_tco()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a1613f5d7608..f5e4f5f2ba20 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -398,6 +398,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_enable_tag_checks_sync()		arch_enable_tag_checks_sync()
 #define hw_enable_tag_checks_async()		arch_enable_tag_checks_async()
 #define hw_enable_tag_checks_asymm()		arch_enable_tag_checks_asymm()
+#define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
+#define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7ad5e5a9db79e3aba08d8f43aca24350b04080f6.1680114854.git.andreyknvl%40google.com.
