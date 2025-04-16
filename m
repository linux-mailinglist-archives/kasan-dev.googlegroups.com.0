Return-Path: <kasan-dev+bncBCCMH5WKTMGRB77A7W7QMGQEDAADMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B5856A8B47A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:28 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-54b0e3136ddsf220077e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793728; cv=pass;
        d=google.com; s=arc-20240605;
        b=FImsbpQkak7WA1GPeWHhJbga01+rEIB7pvzrtFVasg2/l7peyqXe4LGFgq9p3/lM/+
         ywUCPV88zirSLBc9XXFyjEBOI1rqHMIjqst9Dbh+N6aO11ZDCS+0/VHTLaErM8fujA2J
         j347ON0MQl14Ajp0kuxENE0DiyxgVlZjAdAFBL1jYictJhePphDeMMjBsLqHoZ5nyOd7
         GY+RdNULZSdYzHJyLqzrMUvaj8xWay0w5fFF/VFdp8OoSF83LdxiwBgh/o76r8iK2auz
         SgGAq2ms+IgvSpN71GRnXompqgJbka0JulL4z60461RAwl4mycQxz9At6cN/S1USfqeg
         fouA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mu1bxIb6oqTw3qfH+V1DN8jSdksaEyncZAMbeEKtu5c=;
        fh=1bkueh+J5D0edEiwt8mivr7ZnU9VbLMtpO8G7YkGuv0=;
        b=BsjwHvT4g1kPpkRKzE9eP2TzVKaMOngTEXA1LRM+wucO2QJNVO6D3GWiYxvIaDJYZk
         zh9slM5zWM5T5Ly9ReAi8CDf2ZnxeoPe/U+2FoqLkQGkH0UEuD7MDagPJJlQ8SfPMa8K
         uguY3YFA7uMUOwVxEnkcmzaVP6GcOiv4nj9K1Tcvg8AbPAkbPgtzgkq6Y8EaIvNdF1mW
         uqPgNaB8dxRpDK28F8hy3hAJxeYdKwpT4fGzzmvATdczFZPsLI5huIS/gDxMp3pt8drA
         RebLYBhJsSK/WcdRdZYF1XueKeLr1xUPqlx9QGc6fF6YMizXEn7kUVyVseyQ723jTYDV
         V5HQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CtxBMVU0;
       spf=pass (google.com: domain of 3cxd_zwykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cXD_ZwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793728; x=1745398528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mu1bxIb6oqTw3qfH+V1DN8jSdksaEyncZAMbeEKtu5c=;
        b=mulZf0EfJoNFIdr18XrTRUiuUugDbgLkz5gEYhzH1voqlI1LmY6byGwFNaoakMeF+y
         HsNxe6UGLNA+ALm/LKYxCRYpW+SeDCsctAYmmAIjqF7+YeZJD7REICkg6VGK10gR7dkD
         D/jHNsYIp8/zJHqTzjyhsVDZ5+2wFwGM9Om70fA8xgbFqu2eTN1bqucu56uX9O1qe08d
         yvk+DozoEmb6U0zws9A6MIVkJvi4o3APbE+KajMwDdplibiHT/b53yZSFtsTT1evQjkD
         F4hvVOFCbMAU1JhtIAmuQfzoirpuQKLEjkBs1f6OWMEC9+PYqFEsKAsFxYAMxzVbaGqW
         K8vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793728; x=1745398528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mu1bxIb6oqTw3qfH+V1DN8jSdksaEyncZAMbeEKtu5c=;
        b=lYaR/VZQ3f4XlkVd7yN0rVjrZ78JM3RTnZnLYPqd2RhMu3XeYa8qaHJAEj7chBX1OE
         8YBeCLHTYo+UIeyVosnde7dLKZjt0Y+B2Dx7RBWK7gydKRuWSntj0VGTHbROmXDpNqlw
         mgrF6NKsz+KVup7Cp/r3fsM7pZ78wi8TSWO7/lZGkDwgGwTb8HXupKnoP6sQfyq6wxCX
         uWlf20mFhonm4lvA6TkZ1HSb/5YwC6d4s2iDgsUEEOfFEQ4cCAR6tVK7dvUyodyy3yGv
         H4foZy/jYtt22tfNIpg6znQNkf+WgPFHVlzF0S4W/ggjSttobAmDPTmfdof3HJpODTo+
         xTHw==
X-Forwarded-Encrypted: i=2; AJvYcCU8nROURBUf5ldkH7tGEQBLn22m9N9cMjeWZyvlseinE7THaonXFmSEsazx2HFwaG25YY/T3A==@lfdr.de
X-Gm-Message-State: AOJu0YyYcz4GiaQU5qQwNFf8Q8zMm5prJz0kGWYkWp3IjJ566moFxLCh
	6RRBscVw83P0qsTaU8cT8we+NeimleBLxAYLXh8j7MtGRuVkypRl
X-Google-Smtp-Source: AGHT+IFEsTGZDLNGDRDcfUr+g/3QFc63q0GzSiXibRBr4IDnqxR51w4VO6KL+lS2SV3rSwuAadnZGw==
X-Received: by 2002:a05:6512:3b95:b0:549:965f:5960 with SMTP id 2adb3069b0e04-54d64bd323dmr313036e87.16.1744793727809;
        Wed, 16 Apr 2025 01:55:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKk1PjP7pYmKippReo4/MepgIWaX0OOWbi95UasBfkjXg==
Received: by 2002:a05:6512:3b92:b0:549:94ac:e7b2 with SMTP id
 2adb3069b0e04-54c4d094205ls155965e87.0.-pod-prod-00-eu; Wed, 16 Apr 2025
 01:55:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNx93iPhLU45Bfnowa5ZlzujBFjRVhj0otmbfYdXATbTpoxzZrE6VW9gVTWbmoP9dLRWb6BR6+joQ=@googlegroups.com
X-Received: by 2002:ac2:4f09:0:b0:549:6ae7:e679 with SMTP id 2adb3069b0e04-54d64b87fafmr298547e87.3.1744793724924;
        Wed, 16 Apr 2025 01:55:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793724; cv=none;
        d=google.com; s=arc-20240605;
        b=IVXJ5+Hy11KVtV/LNqoKXT44zjzot1DKbl4Uc+/SjVMu6YZDIm9JNUI5dAc2rcBCMF
         qg3Oktv3oFaGJ6HZRNw/oWAg93JoIxDHjvJrWnHhciPPWO26arzryjZwZ9JZMrs4XKuZ
         sMBxohQxR9y/5pzJ/+8z04SI2bvM4pE+hjRxrXWL13cBh6HLSG8M+if4JBXXTyyMe+4f
         HZF2yKQ0l0ACgrDaMM6rHhms02KWmbVKfrImBClrhiDrL+qfFPMoB27+q3P45dWx2UpB
         aB0viM/OlDLBz96CMAV0ihZbL/jEHl/AW2S5vRBZa8WcFz4zBsqZIOQSaoNEwWaw6Pmr
         MfBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=JTFzqr/xcSaN2yUJr69OYVSpzwgxx9PIurYAIv+eQpU=;
        fh=Umc7HuvJ0ff7YN3wGDCGZJveEBx4u5PHWMv3xUXT4O4=;
        b=g7afq3tvi4Y0frXcYu31uRkgfC8DjRRn5sj/lvesbXYvC4JJf0r5bvzOMKexYsgECC
         yUKt95aq2Qg26z6kxWR+DyGQcDcDPnpyd2PDhikVWnAM+wV8ShfRphHg5aI+/hq8Vpz/
         xYis5+DQ+bLJcezOlPv5G8fxrJLFjkMTg5Ty/Kt9IbsaLmWC1zD8cKxHYx4bZ62TOZap
         EbhTARsi8t/BaDxgqDNjKbMopbcpVMhmEC8qi6LNudMkCWE0fS+Ue6i9xNVzzcYeK4Sn
         DQzM+ivbyKej1wlqBN5WNrUwBlhQXgp16nEdMkOyeQc7mGwsKhBn9s9LiWvqw8ZO2oVI
         nWVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CtxBMVU0;
       spf=pass (google.com: domain of 3cxd_zwykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cXD_ZwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54d3d508a4bsi408833e87.6.2025.04.16.01.55.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:55:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cxd_zwykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ac6a0443bafso678294866b.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:55:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5nOMcOx+LSaxkFS15bBjpIHjpESgrbQliyl4jCcHPf4q0nCE2bg5CKWmrZICdXVsn04eo5nrtXpE=@googlegroups.com
X-Received: from edjb8.prod.google.com ([2002:a50:ccc8:0:b0:5e0:677b:d382])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:1e91:b0:5ec:9352:7b20
 with SMTP id 4fb4d7f45d1cf-5f4b6dfb88dmr841880a12.0.1744793713231; Wed, 16
 Apr 2025 01:55:13 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:44 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-7-glider@google.com>
Subject: [PATCH 6/7] x86: objtool: add support for R_X86_64_REX_GOTPCRELX
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CtxBMVU0;       spf=pass
 (google.com: domain of 3cxd_zwykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cXD_ZwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

When compiling modules with -fsanitize-coverage=trace-pc-guard, Clang
will emit R_X86_64_REX_GOTPCRELX relocations for the
__start___sancov_guards and __stop___sancov_guards symbols. Although
these relocations can be resolved within the same binary, they are left
over by the linker because of the --emit-relocs flag.

This patch makes it possible to resolve the R_X86_64_REX_GOTPCRELX
relocations at runtime, as doing so does not require a .got section.
In addition, add a missing overflow check to R_X86_64_PC32/R_X86_64_PLT32.

Cc: x86@kernel.org
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/include/asm/elf.h      | 1 +
 arch/x86/kernel/module.c        | 8 ++++++++
 arch/x86/um/asm/elf.h           | 1 +
 tools/objtool/arch/x86/decode.c | 1 +
 4 files changed, 11 insertions(+)

diff --git a/arch/x86/include/asm/elf.h b/arch/x86/include/asm/elf.h
index 1fb83d47711f9..15d0438467e94 100644
--- a/arch/x86/include/asm/elf.h
+++ b/arch/x86/include/asm/elf.h
@@ -63,6 +63,7 @@ typedef struct user_i387_struct elf_fpregset_t;
 #define R_X86_64_8		14	/* Direct 8 bit sign extended  */
 #define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
 #define R_X86_64_PC64		24	/* Place relative 64-bit signed */
+#define R_X86_64_REX_GOTPCRELX	42	/* R_X86_64_GOTPCREL with optimizations */
 
 /*
  * These are used to set parameters in the core dumps.
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 8984abd91c001..6c8b524bfbe3b 100644
--- a/arch/x86/kernel/module.c
+++ b/arch/x86/kernel/module.c
@@ -133,6 +133,14 @@ static int __write_relocate_add(Elf64_Shdr *sechdrs,
 		case R_X86_64_PC32:
 		case R_X86_64_PLT32:
 			val -= (u64)loc;
+			if ((s64)val != *(s32 *)&val)
+				goto overflow;
+			size = 4;
+			break;
+		case R_X86_64_REX_GOTPCRELX:
+			val -= (u64)loc;
+			if ((s64)val != *(s32 *)&val)
+				goto overflow;
 			size = 4;
 			break;
 		case R_X86_64_PC64:
diff --git a/arch/x86/um/asm/elf.h b/arch/x86/um/asm/elf.h
index 62ed5d68a9788..f314478ce9bc3 100644
--- a/arch/x86/um/asm/elf.h
+++ b/arch/x86/um/asm/elf.h
@@ -119,6 +119,7 @@ do {								\
 #define R_X86_64_8		14	/* Direct 8 bit sign extended  */
 #define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
 #define R_X86_64_PC64		24	/* Place relative 64-bit signed */
+#define R_X86_64_REX_GOTPCRELX	42	/* R_X86_64_GOTPCREL with optimizations */
 
 /*
  * This is used to ensure we don't load something for the wrong architecture.
diff --git a/tools/objtool/arch/x86/decode.c b/tools/objtool/arch/x86/decode.c
index fe1362c345647..8736524d60344 100644
--- a/tools/objtool/arch/x86/decode.c
+++ b/tools/objtool/arch/x86/decode.c
@@ -93,6 +93,7 @@ bool arch_pc_relative_reloc(struct reloc *reloc)
 	case R_X86_64_PLT32:
 	case R_X86_64_GOTPC32:
 	case R_X86_64_GOTPCREL:
+	case R_X86_64_REX_GOTPCRELX:
 		return true;
 
 	default:
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-7-glider%40google.com.
