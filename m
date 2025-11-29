Return-Path: <kasan-dev+bncBAABBUEGVPEQMGQEEMQBM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 62F6DC93BC1
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 10:56:34 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4edb35b1147sf44350881cf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 01:56:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764410193; cv=pass;
        d=google.com; s=arc-20240605;
        b=gv1ex1Aq0elGxst7mLaDPr5HpW9KKduyXkUUA8jbhhLFxO4LOY0pbRbzSU0SJes6e1
         HRYz5bIV/yqLDX7CS3/wnKzhRQNrGgcEWgYS3VJjj0Yl/D4G/uh6FUWvnraTeZUHf4v+
         QGuy8KtACrpmjs60mxXr+OeVjps7lam41ECU1bau/r7t75JFV8rAUUvGlIQiKD+oIVYJ
         3ZlaQFUxiuM/+KlG+DEtj4NdbZyHyD4+ipDf0+p07MWyKYzUAl3G1Bkg4wV+EL5ARBVm
         ZXviHiNjTX8py3qAN3Eo+0DFefpchH4N6AypNWIH7T8WcyODwREFSneIe+DLICfxES//
         Kzwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=X4rcswVj3Q5lvYVfGOQnH364ESXs7mnHAOkDZkAR9FI=;
        fh=lN9ci+fxN+8lJR4SE/C/Im4LZE+J4emMTTbmke/fcM8=;
        b=VE2ZRUWY2JMExbZ/ShkEoSQ1vbr/+6rcKXS/XD4iqQtkZu4BD/1afWJy1MOY98xxnU
         sjQH3jVrOZF31jC1Sn/OvAbUkDGfexaB/i+vZmAqZ4sp1jaaieFLANPN/EiOjkKnf4r6
         LgNyyCKD1G0y0xChzwCHLVimxAGxdLwXgkslGGmf0XVUB8jwpzwbn/fZOMypdTzL9jXJ
         /mJI7vpmgEOLqTrgoTnUK0s89KJXsxsmEFi6xV5mxeW2LfDfvUM9W+hrYuNsSfzMKzZq
         +P3sw/IUODOE11tAlTdMn3TlC6XX2mpHKZ1ZQ4C86p1wlMrvmwy2tKUPVvql8vxXjzNv
         gMyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LP38N3ei;
       spf=pass (google.com: domain of chleroy@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=chleroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764410193; x=1765014993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X4rcswVj3Q5lvYVfGOQnH364ESXs7mnHAOkDZkAR9FI=;
        b=wicXAYW4jse04aV5RD/hho7PIU8KlPCuWspnWB//HjBRZqFgU2hb2dWNYxsaB98A3Q
         7Jsn4qCPbcSxjozCEnWqD87MLX2TT1jKXAjC8rbtRZ/pUY13KsCQ/GhmzqQwZaZhVImu
         lMznzUkg+bGzJLwiiSgJDRv+t1kl6OBdFPKfrU1np/Rnp5hb6f3ZzbExFgAf5PBn2cKb
         YMaip1hTEAMH9ApkSKXTA1Z+RTwt9wua3DJbNLzoG8dNalzFDVh8OmWrP8MXG/ALyVR2
         osoEl3GqDbsy1k05EptkSVUN/jmwvBszwhKED3voin0sZ7Al64HptWjTjCzIU5k2mOrY
         VHCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764410193; x=1765014993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X4rcswVj3Q5lvYVfGOQnH364ESXs7mnHAOkDZkAR9FI=;
        b=DKC63OIiyHVAWGBmsI/49LPvqUog4uX3buXSjZQ3woSV0TN2r+6UPeC++CgcFCWBdC
         dxR8h5a1AyYo0LObcYnTUpqBA8RyBjI5ZwecfVwvhaCK0UiVgoNyPsnxAmmDzCr0dClF
         Q76AnISjXwiWsfpe1rndYeIN+JZFo9i/wyFQEfDJJHv+zjW7rc3uYOuuvgYOLct1ojUZ
         wVPqNXshi06X7gbrZ4JU5Wvo9LAe+XymQHHeH6hx0dn0lFGGhL/50DbUTfXT5JsIAnkM
         U8KEwU5fl050mQ/gyxBlW/t1Ln3PyG4gbaR8AbryOSyLIrKgL3Yx9nx9Jf6cYnID3DGV
         2G7Q==
X-Forwarded-Encrypted: i=2; AJvYcCUivwo3g6FPcSSbtEDIbdD8nNsXO6wVxSf8hSih/GVXyprT3eH/NmK6TY9CfhyKQIpo4nU8sg==@lfdr.de
X-Gm-Message-State: AOJu0Yxxt6vDY/CPBwybcuB6H5GEH0vqoShyLBks+087XhpclyqNJJRy
	pFQHjJXB31BH4203W6oelIHj4d9y2Bk5bVKn+3XK4Oz7qvOXsU5WsVW6
X-Google-Smtp-Source: AGHT+IHeIMhtpwsvAU4vDp3mtB7W3XwyQpBtkBHVA56mtln1wTdCk1K2708XPLKhExzi5tlIBCNjNw==
X-Received: by 2002:ac8:59c5:0:b0:4ee:24e8:c9a1 with SMTP id d75a77b69052e-4ee588908eamr427377631cf.44.1764410192919;
        Sat, 29 Nov 2025 01:56:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bAQNpMKqIN4hVhYm+v/voo/R4kwWETrDnwRX0nXooppw=="
Received: by 2002:ad4:4d04:0:b0:882:3ab0:1d93 with SMTP id 6a1803df08f44-8864f798fe5ls34057386d6.0.-pod-prod-02-us;
 Sat, 29 Nov 2025 01:56:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfF4RtQX3xi9Htj7W7WyXTxddaBS3lVIDjYlH6RJvJhhfWarwlcgdoOTFfBX0qDxTqnFXVxzcFCbk=@googlegroups.com
X-Received: by 2002:a05:6102:2b83:b0:5db:d60a:6b13 with SMTP id ada2fe7eead31-5e1de273c49mr11550020137.21.1764410192294;
        Sat, 29 Nov 2025 01:56:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764410192; cv=none;
        d=google.com; s=arc-20240605;
        b=HSY5YewxKadOF2LpuFG3olutdxzHhftYUYMht9r+U2CfZR4EVWoHBHSQs8+YnDJ4vc
         ObeKRx9MuKZbbNuJ31GadbLFwwUw7S781BGYlO34eRtpN4cBf/nscySXJjwpkIsxbKbl
         n8mAY8afHjaaicWkM1NSrclgdPITgJhkAdgLuH6vh8rCR0owV5bM3UD3VA7tb9BUQXmr
         n3oArz8FLVMcoMYg5f3XdrCOLX8f2D+y0zXsl5GKSubxL1WHb3xxlXxO+UWfSz8XDVJ4
         Xeb2E5eq12/1tSpgCXs/M37Sr/vuhLyx87c8kA60Wh1KlylPNItuOHITXReIWIbhvsMo
         RpMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5bGQMHmHt61Y2L4ZBW8mkFAUL1LgjmOuklaN1EBIrcI=;
        fh=i882jP/ZWmlnecy2qjZZ4b3LYkznUdjwpX6CAuT5wxM=;
        b=Ra6i+/DKIDvmBmHmybGrTCBCX5rxE7SPDWxr3/W7RPgco7zMnwicTsfy/5daXZMaY2
         DoVwglp31mBt8C1+81AaqW83Hl7wAleUPgxtNZn6ROIH7SLYAw6mhLymiP20CgE6z9ae
         YbOCGocFB4XRNer0wfUUv4Z0h56IwT1hI+B7HCbG7AENWz9WdxevgB56sKJf8oHodFZq
         pboAvvgbVz9eG4RzgiJ0o+LUm49Wcr3EzR4ulhpkFDn1JKnnvmxoTzP7O/5+/rQHkMTT
         W7ex2vEjwYnAQDjviEyPMroireFTn/wJ5k0Hn+QOOTmHd6MKuWM3YltIgIJwDwN+StNo
         DLJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LP38N3ei;
       spf=pass (google.com: domain of chleroy@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=chleroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-93cd72c8b29si126276241.1.2025.11.29.01.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 Nov 2025 01:56:32 -0800 (PST)
Received-SPF: pass (google.com: domain of chleroy@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 53D8E4012D;
	Sat, 29 Nov 2025 09:56:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C6411C4CEF7;
	Sat, 29 Nov 2025 09:56:26 +0000 (UTC)
From: "'Christophe Leroy (CS GROUP)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Cc: "Christophe Leroy (CS GROUP)" <chleroy@kernel.org>,
	linux-um@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel test robot <lkp@intel.com>
Subject: [PATCH] um: Disable KASAN_INLINE when STATIC_LINK is selected
Date: Sat, 29 Nov 2025 10:56:02 +0100
Message-ID: <2620ab0bbba640b6237c50b9c0dca1c7d1142f5d.1764410067.git.chleroy@kernel.org>
X-Mailer: git-send-email 2.49.0
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1454; i=chleroy@kernel.org; h=from:subject:message-id; bh=D332WuuSN2u8Im5Q2thvdLGIXxokqDby1Zp25sCFMuI=; b=owGbwMvMwCV2d0KB2p7V54MZT6slMWRqHTY2T45b7xlWMXfp+VdnYhaKHBex8K7gib0oznZJ6 q1ER5V/RykLgxgXg6yYIsvx/9y7ZnR9Sc2fuksfZg4rE8gQBi5OAZjIPRWG/xEphwTWuEXyi//y SW54e4fF99G/U++2P6hnllltebytU4WRYVPItAv8uc6nL9fIRseFnlE5mj47j/lIUq7Kqk/dVwy 7GAA=
X-Developer-Key: i=chleroy@kernel.org; a=openpgp; fpr=10FFE6F8B390DE17ACC2632368A92FEB01B8DD78
X-Original-Sender: chleroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LP38N3ei;       spf=pass
 (google.com: domain of chleroy@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=chleroy@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Christophe Leroy (CS GROUP)" <chleroy@kernel.org>
Reply-To: "Christophe Leroy (CS GROUP)" <chleroy@kernel.org>
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

um doesn't support KASAN_INLINE together with STATIC_LINK.

Instead of failing the build, disable KASAN_INLINE when
STATIC_LINK is selected.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202511290451.x9GZVJ1l-lkp@intel.com/
Fixes: 1e338f4d99e6 ("kasan: introduce ARCH_DEFER_KASAN and unify static key across modes")
Signed-off-by: Christophe Leroy (CS GROUP) <chleroy@kernel.org>
---
 arch/um/Kconfig             | 1 +
 arch/um/include/asm/kasan.h | 4 ----
 2 files changed, 1 insertion(+), 4 deletions(-)

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 49781bee7905..93ed850d508e 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -5,6 +5,7 @@ menu "UML-specific options"
 config UML
 	bool
 	default y
+	select ARCH_DISABLE_KASAN_INLINE if STATIC_LINK
 	select ARCH_NEEDS_DEFER_KASAN if STATIC_LINK
 	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
 	select ARCH_HAS_CACHE_LINE_SIZE
diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
index b54a4e937fd1..81bcdc0f962e 100644
--- a/arch/um/include/asm/kasan.h
+++ b/arch/um/include/asm/kasan.h
@@ -24,10 +24,6 @@
 
 #ifdef CONFIG_KASAN
 void kasan_init(void);
-
-#if defined(CONFIG_STATIC_LINK) && defined(CONFIG_KASAN_INLINE)
-#error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled!
-#endif
 #else
 static inline void kasan_init(void) { }
 #endif /* CONFIG_KASAN */
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2620ab0bbba640b6237c50b9c0dca1c7d1142f5d.1764410067.git.chleroy%40kernel.org.
