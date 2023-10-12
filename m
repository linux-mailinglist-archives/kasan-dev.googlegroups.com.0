Return-Path: <kasan-dev+bncBC5ZR244WYFRBOEJT6UQMGQESIRQS2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 59FB87C6A64
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Oct 2023 12:04:41 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-323334992fbsf500240f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Oct 2023 03:04:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697105081; cv=pass;
        d=google.com; s=arc-20160816;
        b=bEUt4k2X7OpgkHdxRCpf/2jDgwEsK0r51IHMzzLFshDNuEKmgEVFqotyVDM0QomLU8
         NrA90gjyX39jrhL6g41FP9+G3MTaUUDgwjGlTndOUzAjwKtIYgJtOaQaBNIXOhpEuGLg
         fIz3fAlJfLUh3SMq1nYRXMRUqMMIqKRteDLH8TljFz/HplwPs1gNRsZCZlSXd14PkaBC
         /gi/wBUefNuDspzgiVhIP4mFpKIX1yOky1Ujdk+YGgM0SNe3bmsuoPHmz835bB6LrawR
         wvmc8clFmYu1XfyCt7x/9f9pyFNbQGD73EBqyyXWe8s9PjV+43Nd4WEesBCrHlP3tfLG
         fgWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=q8mdIfY0d6/wDFxo6Yqb88CdDVWPNseX/aSbJ1nluKw=;
        fh=TZ1FtIqeUfZfQ3GkbpRP0NuCIS8eHq7hqM2LIHeinyY=;
        b=e7gtXchGGlSXYe9CloKYQOQ9p6LsyYrkdSDW4MdWQr7XgC5MA3JU7S3q2MtnWx6K6/
         MzvghXdEJ+3X33BMMHgyU6dXUoSuWL9kioWmMKBpGW9i5bwk/ObhyCEmUQUXjtXJuzmj
         OJp3vSMyIXZRGlUo1yhCdp1NRJSX50xpntAqfhekRgbfniR86PliSTK5ZLvwhxyiWnA7
         dJwhAYvOJ3WxHb2Iav2XOkSTGvQdZREYblvEOruCq7txX4BKli+t10qh4ethtxOzbgUu
         uH4zJZUwilSes1Xd13AtgwQ0NdCFy8tcIDonjiFb+D+FPvlaw5yVOk9v7pK3kQN2TXSq
         bpdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=FuPmOkNY;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697105081; x=1697709881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q8mdIfY0d6/wDFxo6Yqb88CdDVWPNseX/aSbJ1nluKw=;
        b=sj43Q0TBpZi77/T8A29a9xFTjyPOcwNEaALx34icWEOGLLCrHDojq2UDG5j9hzJ0s8
         TEHrpLNqybJuAgphWYHTNiLODq5flDiLgCGtqsTctyDZnC2fmyOZ6k+apZ4rKIqfEaah
         TLs8CMBWJvn6d9lA2QJVDJwrw+VrBwn3pF4S/0+cavpn2SHPT777fK3qWQtoGbBXPQIG
         iqrIICttIcndm4eDhwMk1DWWwvXQNhhuCtx+4bUGeDSx56vgfxAOEsLJhNeKqP+oYl26
         VJ/5+ZosJL+/8+GWWGIapTbBHcr/kE3i85HdylXcaCZED6vNUKQhh+TpwXtLnU65lj4a
         H4OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697105081; x=1697709881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q8mdIfY0d6/wDFxo6Yqb88CdDVWPNseX/aSbJ1nluKw=;
        b=YfY7npV+Ve6+P8oVRF0bizVVC9HfYxl+/J9AI9Dp4AXMw9lj5ovqqDzTPvyuMLYdUZ
         88Yw4gY9k7HHsVHDZEvDuN0oSqh6k5S91C1dr84vjbg4zVoYCdp2muyffqXjXHYjLOWA
         kC0x3cAp9WG1P58MXjrovMQANjl9nGCrJCeJAYSEZMdKmngi91uQQ1QzLPXl3h67octl
         cN69m6iMYkMSKdTH7v1E+tNaVYG4mciYOLZlRbqAoPs+oG0UrYsowiQ1nREkAE5G9wpX
         bp7hQ/U4QkQlNRKpNGtS1qBG5+bel//DHs8ATDqdWM2+PyWzhGXrd2amMufXXCLVhEGO
         2JTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyFN4FAx/jpTn3i4xFJWP1DQ2p2s4kjqPvfSy5Zka98q3GjYnmE
	uprr/YMm2XboxgiV8SftsGM=
X-Google-Smtp-Source: AGHT+IHEhFf+STE70VlczpjH9+tikUKlFNS7AeZiEpm/1twk6ZAl5hs8pPNITnM2XLz8ZbKK8agMnw==
X-Received: by 2002:a05:6000:cce:b0:32d:2489:911f with SMTP id dq14-20020a0560000cce00b0032d2489911fmr5566743wrb.15.1697105080403;
        Thu, 12 Oct 2023 03:04:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1d94:b0:32d:9395:c16a with SMTP id
 bk20-20020a0560001d9400b0032d9395c16als118722wrb.0.-pod-prod-06-eu; Thu, 12
 Oct 2023 03:04:38 -0700 (PDT)
X-Received: by 2002:a5d:4bd0:0:b0:32c:f8cb:f908 with SMTP id l16-20020a5d4bd0000000b0032cf8cbf908mr6023544wrt.59.1697105078769;
        Thu, 12 Oct 2023 03:04:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697105078; cv=none;
        d=google.com; s=arc-20160816;
        b=RNAGRcQmzrZGf8zr17J1ldeG1Y/lhQd4XIGCh0LYTr2s7gh5KNfVm3Sy7XK7HTDMxb
         b+OhJUbaRULZGsiamBBfTRaTIN8md8GvAJy2pQnWYZ4a6sdd89BSg2tBmfQI6sTyezhW
         pZHrtyh11AxOvGHFSpU2zfF+9VWHpgPoSLZvMavOuxr/4hTT3ZKYG8gSzQSaGpLuSKDq
         LKjuJWjVfZqcHsubQwnZjPhFU7LZfLyIuV/a/xY5seanAajnW2HN6KLRVKgAGsP7CMjC
         luKszoayfIGJi4Rf7HixkUOBeUe6rVshB7cnXhZMFK5Zeug8USUm7N3+yvnQd8b72ynk
         fo3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=FvnW4GC/EA+hIluOOBcOWvhFVq1V+VziXSvUcjywg6c=;
        fh=TZ1FtIqeUfZfQ3GkbpRP0NuCIS8eHq7hqM2LIHeinyY=;
        b=Txg2dFD9PpW0B9bMrMqj2Nrd0tViKmqJngkEKNPbhx0P3Lg7y9Ti7n7ntXn7o8N6V8
         WC/RXO5NgfHqhamn04LSq2L2UP3YJjQz7hLorEa6eF2Yf8uMH9QrBllR4zkg9ZwB0RJp
         CabSoe6pZMOovAktiC3KJgL2TR8h5p10GvVUg4RJgzUaSdIYDy6h7jSzyOWfYmRjlCgA
         z70mqVZVQqKTTxzG0LWu/Tcnd34rpYrX0A5zzlbnTsPRgloqgZyrOP3AXpjEMv3KGw/M
         WJXoN5ot20a/bqXEiIdsLvIJJlBjzLxg0b4CZKnWDOF2CxYG7tgaMR97v5RjXWzye8zM
         b3qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=FuPmOkNY;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id j32-20020a05600c1c2000b003fc39e1582fsi139939wms.1.2023.10.12.03.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Oct 2023 03:04:38 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10860"; a="388744140"
X-IronPort-AV: E=Sophos;i="6.03,218,1694761200"; 
   d="scan'208";a="388744140"
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Oct 2023 03:04:35 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10860"; a="789338995"
X-IronPort-AV: E=Sophos;i="6.03,218,1694761200"; 
   d="scan'208";a="789338995"
Received: from nmalinin-mobl.ger.corp.intel.com (HELO box.shutemov.name) ([10.252.58.130])
  by orsmga001-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Oct 2023 03:04:31 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id 3466E10A1B1; Thu, 12 Oct 2023 13:04:28 +0300 (+03)
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Peter Zijlstra <peterz@infradead.org>
Cc: x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Fei Yang <fei.yang@intel.com>,
	stable@vger.kernel.org
Subject: [PATCHv3] x86/alternatives: Disable KASAN in apply_alternatives()
Date: Thu, 12 Oct 2023 13:04:24 +0300
Message-ID: <20231012100424.1456-1-kirill.shutemov@linux.intel.com>
X-Mailer: git-send-email 2.41.0
MIME-Version: 1.0
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=FuPmOkNY;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Fei has reported that KASAN triggers during apply_alternatives() on
5-level paging machine:

	BUG: KASAN: out-of-bounds in rcu_is_watching
	Read of size 4 at addr ff110003ee6419a0 by task swapper/0/0
	...
	__asan_load4
	rcu_is_watching
	trace_hardirqs_on
	text_poke_early
	apply_alternatives
	...

On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
__VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().

KASAN gets confused when apply_alternatives() patches the
KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.

Disable KASAN while kernel patches alternatives.

Signed-off-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Reported-by: Fei Yang <fei.yang@intel.com>
Fixes: 6657fca06e3f ("x86/mm: Allow to boot without LA57 if CONFIG_X86_5LEVEL=y")
Cc: stable@vger.kernel.org
---
 v3:
  - Summarize KASAN splat;
  - Update comment in apply_alternatives();

 v2:
  - Move kasan_disable/_enable_current() to cover whole loop, not only
    text_poke_early();
  - Adjust commit message.
---
 arch/x86/kernel/alternative.c | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 517ee01503be..73be3931e4f0 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -403,6 +403,17 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
 	u8 insn_buff[MAX_PATCH_LEN];
 
 	DPRINTK(ALT, "alt table %px, -> %px", start, end);
+
+	/*
+	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
+	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
+	 * During the process, KASAN becomes confused seeing partial LA57
+	 * conversion and triggers a false-positive out-of-bound report.
+	 *
+	 * Disable KASAN until the patching is complete.
+	 */
+	kasan_disable_current();
+
 	/*
 	 * The scan order should be from start to end. A later scanned
 	 * alternative code can overwrite previously scanned alternative code.
@@ -452,6 +463,8 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
 
 		text_poke_early(instr, insn_buff, insn_buff_sz);
 	}
+
+	kasan_enable_current();
 }
 
 static inline bool is_jcc32(struct insn *insn)
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231012100424.1456-1-kirill.shutemov%40linux.intel.com.
