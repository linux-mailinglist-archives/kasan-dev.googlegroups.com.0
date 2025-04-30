Return-Path: <kasan-dev+bncBCVLV266TMPBB546ZHAAMGQEVUO5Q7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 35A3CAA51A3
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:27:36 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-39c184b20a2sf2859686f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746030456; cv=pass;
        d=google.com; s=arc-20240605;
        b=UkydJX+/FSyBCp56apmO13YduwmJBZg719sTYRYdgjafnwa03tEuRfEm0fHwCoZ27a
         hVLrQAmMgP3XzDAHaiQ9jioioD6s8jvJNwR4APut9i3dErdpi86SfRRXWq+gbQwI2LOy
         eHwkwDx+DNCV9MlA5aKc2BzFvf11CpXUC4AR1sUscdD+LtEoD9fVTuf3BUrAnAGuN3gB
         s1DOptPCrQ/au/EwSKHREyBFr9mkHNrOnB6mA9q0ErZHpbDzkEH63of4enG3y3rU5Jhj
         AuhnyrSkOXDsNw1isdcNmPdbrx2ZoqJ/GgT26LbtVsK/wG2kxjRfovaMjYhkMvGl6yLQ
         eNyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=oHDF1etxlU3OWxD/47pm1tMVY08OOFiDmqrDncSXa7I=;
        fh=QyhGLX2e8wN9iKAd1tDtxvXz68lePILXzZ5gVWDA1v8=;
        b=egiUdNTCDmkC6YBnnvQmMbA8/4A4jaFi7HytSa+KIbx96rKYlYOYyeiBdMU2wbuxRG
         VAuD6NwtM3NYBizPhagj8RSH66fk31hoc/sSGchjahLEcTts6Knq7kvSNqUP2PrNwyAo
         bNpFTvYUjSE06vpkVIC0Q6QgJR0d25RitxPvhSxVg3LyomS1PvhLYBj2FQ54x+7T88gC
         QwSDNWc0N65Grvbgcri0iGf/2y/w79YPIQw/5jR7Wb28nTQLE/sEpJPQlYUjKp3Pe7Ev
         O8la+6HF7es/NtjHB2a3EnAQZQJakKTWN5b6IMqqtLpr05I0SjLpMstHIEE/VW1ZM5tu
         uG0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bs1SYkRM;
       spf=pass (google.com: domain of 3de8saagkcamvprvwdidjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3dE8SaAgKCaMVPRVWDIDJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746030456; x=1746635256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oHDF1etxlU3OWxD/47pm1tMVY08OOFiDmqrDncSXa7I=;
        b=QB8Sb3245jFWPBLbvq67375ixcSJYSqTLQSNAVuaJnBKv6fis6Z5yWalEwFGWAeTqF
         IdMK9WCh38MdWRqMHp6Q7R5iaoCOv5rYWsLcrCe/A4/sQv/8egzRq7eMNIi/GYL5rVYa
         7mnwfxLsaHTRX1Z6YnI3kYyGvwtcWhOh9DVglf+ASO5vXKQ62EP5EjpFkiSY0JtcP9vY
         OphkjaSpdfxYUXX7gRqSE98lDRyZ0ch0KknTqIQI7Es9+zJIehHEOTnUEJx/Lx61gqn9
         npx0p1DV8j7sIVgYIv6ZCtBNbH5VYHgRE/pP0YKwrAhxPyev1u7wI3JwB0/OIXd1AHIS
         dK9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746030456; x=1746635256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oHDF1etxlU3OWxD/47pm1tMVY08OOFiDmqrDncSXa7I=;
        b=wVKDKePkIWiGUlEjKRhkdDAWCRtHrcEYFxU013xziinK3Koy+NyQk0RaE3J42cpv9e
         NTrUAoYMlyQnlrFph432QARL40lvnLY0OGBWL40VO3jNZQTJECaUpdeY6oaXpKCY4SwP
         j1T87g3CKWXj18NRz9CUCMXGApmna/UZcu+2FNDuV59lhuKo/QLeAGB4Uk3ddxZwM0Pq
         dTkHGX8WuJLftkT0QhnumFdRg3Z2spkTiQPs09TY7ZRXK29Ub63zVyv7NFDnxt+qmeIE
         90hIO1Xtb1me/uHXbyTFV4dXZwi13XW9K3UirR2eLOmq0eq+4BaDdCS8Et9f+b5OEISO
         tZMQ==
X-Forwarded-Encrypted: i=2; AJvYcCX1QFpE4OnTgDOBav4dvJdcTALB8G1ejYVFLP5kvfyoLjfkuXvN0dXOZN6nHNgTfa3/D3Lv4A==@lfdr.de
X-Gm-Message-State: AOJu0YzmApZeXMyghItS4n58WAqaNL4n8kO0U3E1C18znh0UdnQ7sIJ3
	A1BInY3uyh7s/H0zpKdEEoOWFDKpOuDZjI/ktREwpsEQPZO3h0JC
X-Google-Smtp-Source: AGHT+IGGJJvXg2yeqLd7HCdgK00SffCB2WYfYx+0FGGLm8v3pSbpend3VC2M5s9S+KT8qn6vG81yUQ==
X-Received: by 2002:a05:6000:1886:b0:399:71d4:a2 with SMTP id ffacd0b85a97d-3a08ff380f8mr2990006f8f.14.1746030455613;
        Wed, 30 Apr 2025 09:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHUxbQ6wMoVLmeOXjSM6vGOj3zyLmrcudRkLBrojI13Aw==
Received: by 2002:a5d:5f43:0:b0:3a0:7a60:3514 with SMTP id ffacd0b85a97d-3a092c4b077ls21531f8f.0.-pod-prod-06-eu;
 Wed, 30 Apr 2025 09:27:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoGm/wQq+d7sBffEgi+TTM9eAqf9z3ttIHPcWg8u/ktIWV+pp4v5mXPMJVdCumYw/rsMYIKxkHemE=@googlegroups.com
X-Received: by 2002:a05:6000:2507:b0:39c:2678:302b with SMTP id ffacd0b85a97d-3a08ff50b41mr2762255f8f.45.1746030452878;
        Wed, 30 Apr 2025 09:27:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746030452; cv=none;
        d=google.com; s=arc-20240605;
        b=YWyK8Ysskgc5Mh3B87MHLrU7v6TLSWCzh21QcEh8v3J+LtdZnKYq+9G0Y7MvvSRN4S
         O1GxPUPu/7Vc8WismV7gumpYWNL/QMmwfrzfApe/VtAN3QrgQ6IO+qZ3W79H3x/TfBmY
         cPkD04X5YX6WNbmf+tX7C/o4d93TzwQYq39NpajvpbW/4rB2t2tFlbwXnPgx8dkVh1cR
         EYX4OBRypyC/s25eY+ap6AZGzbPtlNYP2+VA/WmJkyg0cNC/1csbmy810KNypft4SAU6
         rYDMHimSU5aV8YtvSIbDdhDJbOl/15Glz2XcvHukHYQIcPVQxEOWQ421K7DQqAyHhn5A
         zH/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZqTf0w984hWi5llfvtlyawmZ56xQei2ohDzGa9Ujg2A=;
        fh=lIcnf59h84CrX/AxVJltvzUrJI3F6ZpaTpeuZ1+l9BQ=;
        b=a318O64vA2eo3CtIPJym4XhdgEC0M/bAQaJPjSQLC9/4KyhdbnzlxBtK9IRvR1crnF
         ZiWm7lBHqp6vuelgoowDS8cwr18k6zOBp3UTf/OGGlhGMv4kFx/4KqXd4LS6x9sCTLJ3
         otxWSx3/EWflNVjney3GfEBRdVKOApNIKRQvhoUuSCR9v/XAAjpT8Axy8urh+yh4W/bD
         p9rHW7sFUyA3KJhjmbrrSWZDf+QL4Kt4lFR1ZFKgUTN4iR80U3kqV14NGwquRQEABVJS
         E9xc4Skt+rvEDTuwrDPueROvBxooIaW9NzL+sj2ck2wpEQ26jX7KGB0edmH2w00Tg2R/
         n5zQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bs1SYkRM;
       spf=pass (google.com: domain of 3de8saagkcamvprvwdidjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3dE8SaAgKCaMVPRVWDIDJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a073c8db9dsi183445f8f.2.2025.04.30.09.27.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:27:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3de8saagkcamvprvwdidjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-39131851046so1970237f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:27:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX9QEgW0/yIAFUWLjhWha3u9pU2Qh26M8VuqKZxquUbyS7t02ZMIvnKH4PS+51nO2vRnPRVm4DieDg=@googlegroups.com
X-Received: from wrp29.prod.google.com ([2002:a05:6000:41fd:b0:399:71d8:5e84])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a5d:5f4e:0:b0:3a0:8712:5983 with SMTP id ffacd0b85a97d-3a08f7d1a1bmr3354676f8f.51.1746030452526;
 Wed, 30 Apr 2025 09:27:32 -0700 (PDT)
Date: Wed, 30 Apr 2025 16:27:11 +0000
In-Reply-To: <20250430162713.1997569-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250430162713.1997569-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250430162713.1997569-5-smostafa@google.com>
Subject: [PATCH v2 4/4] KVM: arm64: Handle UBSAN faults
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
 header.i=@google.com header.s=20230601 header.b=bs1SYkRM;       spf=pass
 (google.com: domain of 3de8saagkcamvprvwdidjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3dE8SaAgKCaMVPRVWDIDJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--smostafa.bounces.google.com;
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

As now UBSAN can be enabled, handle brk64 exits from UBSAN.
Re-use the decoding code from the kernel, and panic with
UBSAN message.

Signed-off-by: Mostafa Saleh <smostafa@google.com>
---
 arch/arm64/kvm/handle_exit.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/arm64/kvm/handle_exit.c b/arch/arm64/kvm/handle_exit.c
index b73dc26bc44b..5c49540883e3 100644
--- a/arch/arm64/kvm/handle_exit.c
+++ b/arch/arm64/kvm/handle_exit.c
@@ -10,6 +10,7 @@
 
 #include <linux/kvm.h>
 #include <linux/kvm_host.h>
+#include <linux/ubsan.h>
 
 #include <asm/esr.h>
 #include <asm/exception.h>
@@ -474,6 +475,11 @@ void __noreturn __cold nvhe_hyp_panic_handler(u64 esr, u64 spsr,
 			print_nvhe_hyp_panic("BUG", panic_addr);
 	} else if (IS_ENABLED(CONFIG_CFI_CLANG) && esr_is_cfi_brk(esr)) {
 		kvm_nvhe_report_cfi_failure(panic_addr);
+	} else if (IS_ENABLED(CONFIG_UBSAN_KVM_EL2) &&
+		   ESR_ELx_EC(esr) == ESR_ELx_EC_BRK64 &&
+		   esr_is_ubsan_brk(esr)) {
+		print_nvhe_hyp_panic(report_ubsan_failure(esr & UBSAN_BRK_MASK),
+				     panic_addr);
 	} else {
 		print_nvhe_hyp_panic("panic", panic_addr);
 	}
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250430162713.1997569-5-smostafa%40google.com.
