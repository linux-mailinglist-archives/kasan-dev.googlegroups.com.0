Return-Path: <kasan-dev+bncBCCJX7VWUANBBCMN437QKGQEIDHRF5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id CEBD22EFEF7
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 11:33:46 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id t23sf9814215ioh.0
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 02:33:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610188425; cv=pass;
        d=google.com; s=arc-20160816;
        b=eTC4ftWoVOJHD/Dchd1Lk59X8ZeF85D/hjzxuNtshhDq/o+gCkmva6uZOsw0y8AdpN
         gMsVO90cvzUdkG0McslhX0ODV/kj6AAlLoXcveIFTgpMd1ayCo8bhE0RBdVQMph0ljq7
         UvqRLaEcm8W2/mkIE57wG5lmOUd/leWqLfo4EGyKAVWPjOtewYMOc0iXiFbxHFCNVIil
         DyYjv65LnvEdkWL+/BZjt0uz+BsHZVxd7kmfAZOat9+NT7udHSpD4mGyh9srdqfXlto7
         g6gm5L8cQxo+HLeLgLZ3tY29+7LFr9Q4+4CdjdEyHsWBuW9a0d0Ivh8be6G580kyosAu
         q4vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=4fmn5huFzUMzM98McKZAH0EAavU5hicQBVK+VmtB4Yw=;
        b=DMuPFDeRuRdUhGE8wRSdRGqXxaQNWrK6AkWgLVyJGyS6sf7tT/wTEhY8oWXBI/qnPe
         ypXKJalKO3euvxhlWqRFNrMbRrLYF7rCpVfDX4zlL8ZR31ezL6XvbzTZ5XNstZf3Iybs
         9F3ROLpNOrAfWnCRELxGdXxEGi/o9yFoyrnHg4iNzsHF5GncLLMq7bix6wfMKqZfL71O
         2Izh3Cn+gj5DxBjDaFmdn9NmCrPfuCKM+zs3wWMsoTn4P51nBCwQLIBNErWjqgphlxtZ
         Sf4PJb2NkLnxTNHC/N67cg6VRECuHEi+92r90FUf47bmz+t6KQMoX6Eag1fYeMQPdTzg
         840w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BPZllgi5;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4fmn5huFzUMzM98McKZAH0EAavU5hicQBVK+VmtB4Yw=;
        b=nBjKPN8Tec2dwFUSulHkpmHeBgG2IlYZx7PTXemF6d1b7NOx3paS/k1bfVFH80fLKN
         Zzik5epZ9PtsHsIXTw90lW2wTg5TBmtWE2s7QAIvymObNpyt3G9JRIdIb2rMA6jruoem
         J9H4yBJPbaP0tZ3OpxHa9OZ7Qy4lgkUtoOo+TGwo4dNkqkL6QuWpG3P3dXS1mzFXJVOZ
         B6g0GwjdZNlEN2QDgLhQYTMJz4rYpbTYMuCQ4V87WkPNlzQ+8EsV6E0QSuv867/AUHJC
         qq4TLFuT2FK4olPLz6vfmYHK+I52ev4spqmzZLJYR3k7Bu4vtAv9xa95sCE6HpO62r7R
         DVSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4fmn5huFzUMzM98McKZAH0EAavU5hicQBVK+VmtB4Yw=;
        b=DFpco+bOFWKvH2qCvCrOdA5gasf+1aLd6dus7yudnJnMORP3YBv/LTLw/IKr1hGwNy
         MgYEEhQRLTVb5mrcbl63HB0S7tACyHerikFKq70MxhVgHXbdIgbDoJcg4o5nQCMO33fE
         Usulmkjhu9olrMeKh4+Okft9pv6hsBINbDSlQ705JLj6oyU+twEG+Q6/TdxOGF7aZ7ho
         JCTPsVYyzCvzJt7q0E8B9Efu+n0MmDu0rgX7wIjPI5Rcb2573sBVSDyCoOZaJAyGz8rc
         wH0ikzHvS8yYkEKh7RDtkVIHpWjtQtkLXcud0cbZJmUWMO4Inw3iGQTgLk0DdHEgu2GA
         XsGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4fmn5huFzUMzM98McKZAH0EAavU5hicQBVK+VmtB4Yw=;
        b=RXIBIyi813Ry/TqywuvfTKXy/8suvcEn0WO1Dmmz/8JSMf1mEeZw4NV5pIPJAa3Yh1
         XP0JCQWIvfUT1xJko/smMDl4gyNuyXjgCaEK0oYRarKS29EeSb+XYXv8KOY0dBqt7gAv
         VPw2S5USYO/JbQL3OongBQSEURkycqKy4zKDK2yQcFPC63dNriQM8ayQxYWgMXxaTwtB
         f1/fCB1yu+PwONYgzkEBDNEjUTzymLm8korrG+SfYSmIcA+UuyGNpG1do9ELto/y1AK0
         DDZbPDEb+uWmL7ivQvKh4fRZNhNWL8yplhm6U19YQfj3ILdxZ2bfd1s9UHXUQElAJ3gB
         U2pQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lKSj0Em8enY10lCti0W1GkZtbHinelB6sb3zmwkNIFCEWdWny
	1cJmlcnHUbv3ZmgnVx3a/0w=
X-Google-Smtp-Source: ABdhPJyb4cytz11mduNsKoFt4LKZUHJ1cGK0qZ/G+u9iLTXmFp3SF7umSlBJwJcVBamYErT7je0ezA==
X-Received: by 2002:a5d:9713:: with SMTP id h19mr8626982iol.14.1610188425829;
        Sat, 09 Jan 2021 02:33:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c0d:: with SMTP id l13ls2669864ilh.7.gmail; Sat,
 09 Jan 2021 02:33:45 -0800 (PST)
X-Received: by 2002:a92:9ada:: with SMTP id c87mr8114435ill.5.1610188425513;
        Sat, 09 Jan 2021 02:33:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610188425; cv=none;
        d=google.com; s=arc-20160816;
        b=czwcvWi2WyJ3hew31s7eJnjYW3j1NkcGB7jpucATrch3T1NQ/uxWb4DIYJxSkApwe2
         GQwG3PrgS81CzAi5BJg6o9f0hdIOUO/QGPen2uNhnQcCnmtdlt4oBS2ZZ17+DcGjMRSE
         xSLwzVRl2zttWF6wv/eMY93M8trTk5avL14R2HO406195ZqAprgIY1M7JxwV3lFrEei6
         faJE4jjp1D1MJJHBX+mF5GeTaPVdHbEkPqa5CNNpOm9uj7r+6KPRsP0J8yUVtmrX5F6w
         +X/e97Le2L8+BoqocPcCae+mLSDRE+bl/P9JaUTlTGOzKspogkkkzNIyws3mZclJlMrh
         tRiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xjESqlUb86RQ6iRPUx+QrIUmLWqLivYfrQTN5THOZlI=;
        b=kBdOe+wDjFOXaSOyFF895GXBDv+Um5bjlgSbPLuwwkzwv6UgVKHqe/rdjcNvWUOGFX
         PLtgLOqJ1vRRuRw3yxybhtwX1xUJgy1NSY3StG6cMGovtpAKjLuq1TmmHArnwdeHWZ7P
         NVGDL/KaAdl0m1QFD1I99qDBUrYu5vHGXhFzhfSisrdU07oAJA3cEr2cKJCTB9sojr3e
         GIgKxF2rmtWpogmYtgTLhBijI+zYRorNRG5LmrgoJ4iDruvk3THKBKMQ670j9nRtKi6R
         SFG52+Hc4qnp4R0wheQoksQPBoJEHGlfp+YAQnhay78RemYLvftbwGLlc5cMPzLtNbo8
         iH7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=BPZllgi5;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id k131si933511iof.1.2021.01.09.02.33.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Jan 2021 02:33:45 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id w2so23188pfc.13
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 02:33:45 -0800 (PST)
X-Received: by 2002:a62:25c1:0:b029:1a9:ee40:3fd3 with SMTP id l184-20020a6225c10000b02901a9ee403fd3mr7620101pfl.58.1610188424692;
        Sat, 09 Jan 2021 02:33:44 -0800 (PST)
Received: from localhost.localdomain (61-230-13-78.dynamic-ip.hinet.net. [61.230.13.78])
        by smtp.gmail.com with ESMTPSA id w200sm11691572pfc.14.2021.01.09.02.33.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Jan 2021 02:33:44 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	ardb@kernel.org,
	andreyknvl@google.com,
	broonie@kernel.org,
	linux@roeck-us.net,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	robin.murphy@arm.com,
	vincenzo.frascino@arm.com,
	gustavoars@kernel.org,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v2 4/4] arm64: kaslr: support randomized module area with KASAN_VMALLOC
Date: Sat,  9 Jan 2021 18:32:52 +0800
Message-Id: <20210109103252.812517-5-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
References: <20210109103252.812517-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=BPZllgi5;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

After KASAN_VMALLOC works in arm64, we can randomize module region
into vmalloc area now.

Test:
	VMALLOC area ffffffc010000000 fffffffdf0000000

	before the patch:
		module_alloc_base/end ffffffc008b80000 ffffffc010000000
	after the patch:
		module_alloc_base/end ffffffdcf4bed000 ffffffc010000000

	And the function that insmod some modules is fine.

Suggested-by: Ard Biesheuvel <ardb@kernel.org>
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
 arch/arm64/kernel/module.c | 16 +++++++++-------
 2 files changed, 19 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
index 1c74c45b9494..a2858058e724 100644
--- a/arch/arm64/kernel/kaslr.c
+++ b/arch/arm64/kernel/kaslr.c
@@ -161,15 +161,17 @@ u64 __init kaslr_early_init(u64 dt_phys)
 	/* use the top 16 bits to randomize the linear region */
 	memstart_offset_seed = seed >> 48;
 
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
-	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) &&
+	    (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	     IS_ENABLED(CONFIG_KASAN_SW_TAGS)))
 		/*
-		 * KASAN does not expect the module region to intersect the
-		 * vmalloc region, since shadow memory is allocated for each
-		 * module at load time, whereas the vmalloc region is shadowed
-		 * by KASAN zero pages. So keep modules out of the vmalloc
-		 * region if KASAN is enabled, and put the kernel well within
-		 * 4 GB of the module region.
+		 * KASAN without KASAN_VMALLOC does not expect the module region
+		 * to intersect the vmalloc region, since shadow memory is
+		 * allocated for each module at load time, whereas the vmalloc
+		 * region is shadowed by KASAN zero pages. So keep modules
+		 * out of the vmalloc region if KASAN is enabled without
+		 * KASAN_VMALLOC, and put the kernel well within 4 GB of the
+		 * module region.
 		 */
 		return offset % SZ_2G;
 
diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index fe21e0f06492..b5ec010c481f 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -40,14 +40,16 @@ void *module_alloc(unsigned long size)
 				NUMA_NO_NODE, __builtin_return_address(0));
 
 	if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
-	    !IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    !IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	    (IS_ENABLED(CONFIG_KASAN_VMALLOC) ||
+	     (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+	      !IS_ENABLED(CONFIG_KASAN_SW_TAGS))))
 		/*
-		 * KASAN can only deal with module allocations being served
-		 * from the reserved module region, since the remainder of
-		 * the vmalloc region is already backed by zero shadow pages,
-		 * and punching holes into it is non-trivial. Since the module
-		 * region is not randomized when KASAN is enabled, it is even
+		 * KASAN without KASAN_VMALLOC can only deal with module
+		 * allocations being served from the reserved module region,
+		 * since the remainder of the vmalloc region is already
+		 * backed by zero shadow pages, and punching holes into it
+		 * is non-trivial. Since the module region is not randomized
+		 * when KASAN is enabled without KASAN_VMALLOC, it is even
 		 * less likely that the module region gets exhausted, so we
 		 * can simply omit this fallback in that case.
 		 */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109103252.812517-5-lecopzer%40gmail.com.
