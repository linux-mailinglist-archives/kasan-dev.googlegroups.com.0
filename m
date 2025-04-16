Return-Path: <kasan-dev+bncBCVLV266TMPBBZ7C767QMGQEW5ND5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id ACA09A90ACE
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 20:05:29 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-39c1b1c0969sf4756840f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 11:05:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744826729; cv=pass;
        d=google.com; s=arc-20240605;
        b=JFe7hc4t1MO5NBO789x3F8s83Y7H4tHM/g9OQG4WZpih1yMdx6xsV7a8ZPp05SIaQf
         EPNOE4DAdXIC/hLDI7v2CT+m600rrhtWwfkNYK7Lef8IMaO5aMcdbRzl6oj5nG6qoM4v
         py5qC1yBIuPp1bp2nBGDnskJ+UiMOp2FHJ+KzvFR4Mb7013hCP5974qoxod/JIE40lfF
         p2oW6xckLHIJNqMSbeaDz4NInoXUTtmoHdm8JJ+SGvV7qeg46PVhOu9cEC7ypGSB/7tQ
         /FSdY2kJLS7esgSrzjC6oMBQLYlY3sE6DVFHM3PDpMnHxwt0UlSOKTI54yqKlRYu8xAI
         SvmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yVoBT6bd17OOwhQl5aDkqb1T4bN7ANMQglOUPXAWMV4=;
        fh=SSKPzjwBbkFERoq9ERuvcCAggF9VOx2x4gS7hyR7bUU=;
        b=BecmiFDbwlmF8V6CpMTnuPM3m8Yl7demDFLc30y44CRYgnjEEiyuJ2MnzyQ2hpv4Sp
         rVjuuxD79Xxh/HqSHXdgXp6o/3dGVpj4RdOmG9VZsw24m6MwJpKHeLwIhJsIIhi8z7mr
         PveT+UyGEHsnXSbiS7G7strPCcjeBelnXK04FNWlhr2xwBd4dpoqEp2NMnJiDh/L2+WL
         PDK3Hdt9sDohDIG5qZl+9MmRvUoMPgbiyioroXlArzN+I3Gat4+Bfc8YKfM849YocN+D
         YTOZgaWS+6S+vfAFcXJIeeCr/NfiTX+UpXnBvgomtfx0cnIMfJNDwOFNbujgWur8nBMw
         L6cQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RNsyyPhs;
       spf=pass (google.com: domain of 3x_h_zwgkcyg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3X_H_ZwgKCYg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744826729; x=1745431529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yVoBT6bd17OOwhQl5aDkqb1T4bN7ANMQglOUPXAWMV4=;
        b=i4w/WGLlQXUPqdJrRMq/y3OuaNphwTElFIj9z+NSHT/N6aVjPlljouERgDiHsefq7p
         A3drBnpvhqnOmHIaKDKN4nI+8F5buo5uG0LFhWFESw3X67lLobLsnM3w1DSEUUTtX9E+
         KMiAAB4Uz3+YUx0lX6vqdS6bdSDBkothWPK/SnhdKF+TOH3vTe2lbUfXvGV/1Vk9YLo2
         Fy8HdRVq9QXSwJvcou+4cEw672U02u0w/1cII7kkJnqC+HrS3YQjTiR/T5dvo63YYUd2
         d21YvU9THDbqYjRuLIk04r6wCDbk9ztVQY/qre6GhzqwN4fkkuFbTIQZemF6YQIIpSuD
         mZOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744826729; x=1745431529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yVoBT6bd17OOwhQl5aDkqb1T4bN7ANMQglOUPXAWMV4=;
        b=SyuHlhuJ32rCLhrpG/5LGW5xaKnjFTJVRpXzTzjCrkY5wSysq4cMWwmn/LU9Rok4uK
         lWEXNQ/5eLTInlHmejsPbjnEcdsMsakxZPCCWDGINtS+MqHOjGG6SRH/TuTM58lm1gs8
         ppJtZtscBrFGkrUxiaHOm8fXM9D4kba3WPKu8mrX8/kB49QjpAbKesnfKoGERV41pniu
         radTF+2CqnE9ppj6kzIldgUGid2/npw7UDcWlaAEMkIYnbAkkaNclv3TOF7BXU7839IE
         a3HXN9U/QQCjdf0CfOsd3HYAFHVgX7yUZcWatfTardwiXXhc1yE6duN+GDbYWbVD9WUI
         wF5w==
X-Forwarded-Encrypted: i=2; AJvYcCWlFC2IPby1tp7byumjhpdtaHVDFvMziKlhqDW4+OxFMB/yrnLKwJ8pTk/S2ajGlleJ6/KU5Q==@lfdr.de
X-Gm-Message-State: AOJu0YyZU9zdS6Km3aiSLdHHWIc663LlnSG0qYrU0hCFE+XtVB/jNlQE
	hjs4NKP8Gc87VSsVMFeq9SvJCmeYpqyLxsJil7ss4VPWtvmX+1G4
X-Google-Smtp-Source: AGHT+IEpbZkVzbwUVkscJRHAIVX+iMRlnJ1O2qQmzapexz9EU1LvAGEzQbclKSg9L59lF1Mr/ksI5g==
X-Received: by 2002:a5d:47ac:0:b0:39d:8d54:5eac with SMTP id ffacd0b85a97d-39ee5b13493mr2942657f8f.11.1744826728103;
        Wed, 16 Apr 2025 11:05:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALfl/OkOfbrL6lj4cmnB/AFdPoah7jDoN6/R0vor1PG0Q==
Received: by 2002:a05:6000:2509:b0:390:dfa1:344b with SMTP id
 ffacd0b85a97d-39ee8f98eedls69917f8f.1.-pod-prod-05-eu; Wed, 16 Apr 2025
 11:05:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVYzXFxZtolbGdFBJoZ1XgEerdCBfP1h9ntojG/m6sflAnmREQ8r0xnnReSXu6L4luQk3cNKTDFuA=@googlegroups.com
X-Received: by 2002:a05:6000:250f:b0:39b:fa24:950a with SMTP id ffacd0b85a97d-39ee5b98d66mr2648002f8f.36.1744826720039;
        Wed, 16 Apr 2025 11:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744826720; cv=none;
        d=google.com; s=arc-20240605;
        b=hzrRcaLSmPqwbDguuOYBAQJrdRySGpMzRmcKvlkOL/9Ot7LF0b2JpH4V9ViziH5jw7
         gulJWdqQVzT2LdFXVN98YTJLztqwIAy9d/hDbNySZQ/UuoehYuqixLeMb4a3vb9BGwJD
         sz/qHCrokbthVN/kp55fq4DlPnf2VH6D9tSp2QorlSMa9tdiQhos3K3sy1HjJYenPPO0
         3EJpG3xJHKW3DUtWlk+iZLckXr6ZW/8XzFhbMsf+zr2Ip1qOY2DI9OfQM9Wl3r2FOSTk
         IZfm1dx77MAPXe6YJ7Pi/Y+m2/5SWJJmT6cFQZ9o7B9dHCjVHUougGpjkwU+VNWQOHvX
         ZzhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=cig4j4B59mGrHXUscIMbyQJ5aIiV+Rf6+4/as61+W8M=;
        fh=1X2iBBSpkVJ7p1Ctvzj8PIGJWj69M6XwVePCVxf+YI0=;
        b=Z4fSagn/U8Ip5ZD5241OisX5BwSkHIbmRmeKuH7ZPt60ldutxatd/BJaM8Vmgk0tlZ
         sWpCmZghCKERUwlMktWryupaNxT+axnQ7D+5LGfZBbifmrj36UdIhIkF3u+T5DHVrmlS
         Hh0tEpDp7PYluGGKUMEu65HmaRSSAMu/azqF1r0qfsZ6pOcqrPt766xP4ykA3jkg3Vr3
         elRKBB1rgT7fVBT7RxyNdnksaB++G18HxxBIjBtcwmLgt6E7UrJNKEaNmBqUCDq5CEDq
         qHhADT5IoX2XxEPITTEx/W0Pb/r1mjkiBq3WR437yb909T+iZJsIMuZW7jnbyu2AnbnQ
         bNDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RNsyyPhs;
       spf=pass (google.com: domain of 3x_h_zwgkcyg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3X_H_ZwgKCYg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4405b4c13f3si446005e9.1.2025.04.16.11.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 11:05:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x_h_zwgkcyg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-43d5ca7c86aso42327375e9.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 11:05:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOo7quCUlRNKxLimxWnXfi+HV10eW41KxS++AsOytVor16YFzDIgnttW5ikIeRoUhgDKs/orP71Rc=@googlegroups.com
X-Received: from wmhu10.prod.google.com ([2002:a05:600c:a36a:b0:43d:44cf:11f8])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:1c07:b0:43c:f616:f08 with SMTP id 5b1f17b1804b1-4405d61cdccmr26873015e9.8.1744826719680;
 Wed, 16 Apr 2025 11:05:19 -0700 (PDT)
Date: Wed, 16 Apr 2025 18:04:31 +0000
In-Reply-To: <20250416180440.231949-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250416180440.231949-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.777.g153de2bbd5-goog
Message-ID: <20250416180440.231949-2-smostafa@google.com>
Subject: [PATCH 1/4] arm64: Introduce esr_is_ubsan_brk()
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Cc: will@kernel.org, maz@kernel.org, oliver.upton@linux.dev, 
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, 
	hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, 
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, 
	nathan@kernel.org, nicolas.schier@linux.dev, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RNsyyPhs;       spf=pass
 (google.com: domain of 3x_h_zwgkcyg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3X_H_ZwgKCYg4y045mrms00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

Soon, KVM is going to use this logic for hypervisor panics,
so add it in a wrapper that can be used by the hypervisor exit
handler to decode hyp panics.

Signed-off-by: Mostafa Saleh <smostafa@google.com>
---
 arch/arm64/include/asm/esr.h | 5 +++++
 arch/arm64/kernel/traps.c    | 2 +-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
index e4f77757937e..350f02bf437d 100644
--- a/arch/arm64/include/asm/esr.h
+++ b/arch/arm64/include/asm/esr.h
@@ -440,6 +440,11 @@ static inline bool esr_is_cfi_brk(unsigned long esr)
 	       (esr_brk_comment(esr) & ~CFI_BRK_IMM_MASK) == CFI_BRK_IMM_BASE;
 }
 
+static inline bool esr_is_ubsan_brk(unsigned long esr)
+{
+	return (esr_brk_comment(esr) & ~UBSAN_BRK_MASK) == UBSAN_BRK_IMM;
+}
+
 static inline bool esr_fsc_is_translation_fault(unsigned long esr)
 {
 	esr = esr & ESR_ELx_FSC;
diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index 529cff825531..224f927ac8af 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1145,7 +1145,7 @@ int __init early_brk64(unsigned long addr, unsigned long esr,
 		return kasan_handler(regs, esr) != DBG_HOOK_HANDLED;
 #endif
 #ifdef CONFIG_UBSAN_TRAP
-	if ((esr_brk_comment(esr) & ~UBSAN_BRK_MASK) == UBSAN_BRK_IMM)
+	if (esr_is_ubsan_brk(esr))
 		return ubsan_handler(regs, esr) != DBG_HOOK_HANDLED;
 #endif
 	return bug_handler(regs, esr) != DBG_HOOK_HANDLED;
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416180440.231949-2-smostafa%40google.com.
