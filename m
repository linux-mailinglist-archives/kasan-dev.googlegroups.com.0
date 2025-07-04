Return-Path: <kasan-dev+bncBDTMJ55N44FBBW42T7BQMGQELNCHVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B755AF9308
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 14:47:25 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553bb73e055sf1001276e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 05:47:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751633245; cv=pass;
        d=google.com; s=arc-20240605;
        b=aCtQEHLRnFe1qCxB96xitqFo2fWfjuh4IzCipsFkACIiiEKO8nucuFtJYAzlZgG2OL
         aEdkJnHaaUdEBhCN8ZwTDhz+6ZXxuUACI55thdUSP6++80ueB2guB1D+GEP1saxDlHID
         Uzu8z9kCXpiWku//LcnvUJTA8c+TxkKdbvHK3DK/j0ntyKKfldr5CMjX+LNtDre7CQs0
         OkfznTad018SlqVLYgB/4KejVOBho9UPdTE2oXqjxcGF1I0BZbGBQ1yfChOGEcFGAe1U
         shz0L4+t1LfwtEWE5RcmdU27YsHUEijEFCFFFuwI8GAvtlwldlX9kly14g6XmmBnPHHv
         b73g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=Qv+wCHpUKqZDm4+dvRTVp2SZqRh7I1V5V3hP+X6i4Ac=;
        fh=beSN/AjKAVuaKawLFT59r2EHCo6AI44SSmONDo7P5T0=;
        b=g0JlLA0MXwru5TkkUKMItgRS9A2P8e/zAcFVBbuOTuSZRoKrcpfhpzYgFfnmm1H98S
         P8zl8d5qhi30Ao/sRnPQy8VXHbLKzaLn/TJbIszRFVWwiwtVTfv9s8j539aWVZPMUanY
         1xt1d1582oX7jiDa57ap62OTzHngVLVD9jMP7Rwt5OzV3O/vlxWoHPRTF6FVvNZOeeAQ
         MYiCGoMPWzP+VrcIrO9bqfTx34DVQCEIZFRD0RXW2KgWh5J23xXHkNz5QQYelnB5jON1
         JqVkm6HQdWesa1w1XOdzzFvf9cEAylr6KEk1r8qQCRIyKGUpAc7KmNlbivaMroRvXnxv
         oqMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751633244; x=1752238044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Qv+wCHpUKqZDm4+dvRTVp2SZqRh7I1V5V3hP+X6i4Ac=;
        b=VW6j+RSn1C/+2KG1dcf3A96w2AsI1jqmh6Bp1OglzRtC1ytBPE2Z+4Xfps3kptC0e+
         L/anCeODxzwMWpo6y295seuKaTMKuzbQMJL8hOrqNHDtGS2/uBVFcI5LYbpSul6nYbP3
         pfEUQNM5gk/pIP8mS+scnU+vV4TU+CFlgVISlJCAus8cO21wmXacdvFXY75Uc++6cChd
         aaEzrnwEUmrCZPYeWQiLMb9o9Esnyf3tVlF55F+JNgTOAuFIxExqcPRjD4WfkIeP9Bo7
         /x0zu7bTgRmddxIe2VByz06R+ErOBU5AaOgHr2i7m7NHGqiP+DgtaF+01H9DKbg3XOL+
         Bt1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751633244; x=1752238044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qv+wCHpUKqZDm4+dvRTVp2SZqRh7I1V5V3hP+X6i4Ac=;
        b=QgV7RQNZMQ2Bx5KO9XNt/wtZv0oDFRq/tKH60XrDKimkbzZ3OQSsfID8Xql5mHWwl3
         KgC92s0YkkS+VoDulB6HdVSdkU2+HT97eGwQbyIMqW6rB/Ri0z8ibbajONV7rSTO7tUz
         voHUX3O78QN7I195I5MfRpgKTMvkC/0SAvegL9F8iqjDqRNrjflzvPDxQHlck3SiVPhA
         57ozuOFxzGFsb4dlXX3fNLjI4eet40b5vsBiK+mAhDVuDRjPq53ItzoJA4VMsy0+WKE4
         TdEbddbvHUGThxJz6lneQe1TqPhEghXOqked0hX3GGm8ChztvYYxfbXgrugizXvUSJsz
         4K6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnRbhfxm2puBiI5lAsKEL3K8KUArplaYVgo0AbK0yo/LIPVGLKV9Bc0gyVN62Woh1V+ettUg==@lfdr.de
X-Gm-Message-State: AOJu0YwnYB/BR6IupnlAAPKjpt/w646HaQftZipBM5mncOnKxSDH859X
	BDACgjrohzX89yDzZKAp0CBRiWmSeTvJwY2iuAWnm+CchAVmlu05FYWD
X-Google-Smtp-Source: AGHT+IGqujstf1d8+O7kRThXxzgvshHVwicUNp4ZXq3lRED+LxmXCLwOA4XLoJ8OjsFMQ3VRr04PFQ==
X-Received: by 2002:a05:6512:3f2a:b0:553:34d6:d67d with SMTP id 2adb3069b0e04-556f2357056mr693942e87.46.1751633244117;
        Fri, 04 Jul 2025 05:47:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZes9wSRRVtxsQ5eqKELK5uC7lsTJX1YuSe9UD9/iPobsg==
Received: by 2002:a19:e058:0:b0:551:a1d0:515a with SMTP id 2adb3069b0e04-557e36345c5ls34812e87.0.-pod-prod-05-eu;
 Fri, 04 Jul 2025 05:47:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSvGTxwV+bItsNJNrHgBHi7mlC9yQ0sRQN+rT+RjLpAxvjuljGpIYq6EoLH8GKym8TrWn6lg4zgtg=@googlegroups.com
X-Received: by 2002:a05:6512:1053:b0:553:3945:82a3 with SMTP id 2adb3069b0e04-556e65692f2mr789301e87.9.1751633240263;
        Fri, 04 Jul 2025 05:47:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751633240; cv=none;
        d=google.com; s=arc-20240605;
        b=IflnDPNIL/FJzyAQRxNdaAG830vLtalcPDVNvnZqnZ6SBHfhs6bCePBRF42gRBxzQi
         6EsBoJsSU89O+UDbkTEpASvlNZLEuXm0L9FjSOQzUKBuHPfofmmmuDwvtmnpDCse+5cP
         fhvXJt01ZYLpljv4fPwe+giS91zpd8f8Z61oulRky7MonD/S2vcFaQJjuA/gUwApuIim
         YAtJdOVKrzxwy+9sZbMkPrFPR6rtajfmzvc/yq+ACF7ZJMizyKqmd6aVjqAnMnIYh8Hc
         u7wEd1KyKnE9rac57WdZpEFKqR2xC2YNWBHIU2T8iVkqcq3zIASnLVKre/8an6a43XHL
         rdNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from;
        bh=TmBJIHqOp4ler4vBmcjf5ac2fSEeELNLUvkG6S/lhig=;
        fh=VwkNpSwlyvg1vAY5u2UkOLiaQFDgyQHYvZVNx8KWjFU=;
        b=Nv9tsgLjKALsrXvHvko5fjfnE4ZVysVOf8XjwottsZmMa0CMqHlH4jN5K5PwTnqUqN
         +TWtdty2Aa54X3fjWUCP9SDbcb/pHkPfbqimXEZNE/ByxgGVeA2dSo/Qabmi47lpDxSw
         U+cYIEYh/4XlWa7mB90pu3wvM1l6M1QoIo5kXuQ4RC9/POfRvZR0nwS/m+TrH8bPvYkT
         boAX46RwkTAa8nyvrCPDGJ5vilu9qLIFOvYuw6rCsXbNBYtqhdDCuulIJkI2B43dZFi2
         p+B3TPklQLzklbEXOWiNkZmZRxWDwLj5eKLQRPp7GJDRqGjh2wsg19rs21Q7O8ySw57S
         e1Wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ed1-f53.google.com (mail-ed1-f53.google.com. [209.85.208.53])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-556383a9bcfsi74914e87.4.2025.07.04.05.47.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jul 2025 05:47:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.53 as permitted sender) client-ip=209.85.208.53;
Received: by mail-ed1-f53.google.com with SMTP id 4fb4d7f45d1cf-607434e1821so1255679a12.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Jul 2025 05:47:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXHx0VeXEuuZGlW6wN6JhSlRuVoPsPC58uWbUZKbr2uQgt6gq46mlVA1BXQD4mH5Mt9Z2w4s3iziAs=@googlegroups.com
X-Gm-Gg: ASbGncs1jByPEdSQ86reSwJoxFIQy3KWlg+QSXb7lqTgF6Pbq7/dYgUm2gbqnWqCAPL
	nmG5a0qxAsWUoaMGRvRymTJlRqNH7BPw0RlFWkKaqVowNAWTQrmRAcuRR4mWxy/2OUsJB+eD+Y+
	d7vF/flfc2c76tMw0VGERqEP0scML8x5DUjabGYZ3mH0nrSaIULP//VsySyF2XH9A1sMSzOeGlm
	XMla78sy8d63/+FeP0jwL2j6Q0p2ubDFsgvja5z4/wvVIMaNNBWtPxa2ABqFAyLpX+MsDncL2x9
	XnVyoJ+ZSP419hxbt01qYFFwNN+LtYm6eX0YE5ExNj6D6IP6hNos0A==
X-Received: by 2002:a05:6402:354a:b0:60c:421f:1357 with SMTP id 4fb4d7f45d1cf-60fd30d0fb5mr2017145a12.13.1751633239231;
        Fri, 04 Jul 2025 05:47:19 -0700 (PDT)
Received: from localhost ([2a03:2880:30ff:73::])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-60fca695d66sm1295796a12.17.2025.07.04.05.47.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Jul 2025 05:47:18 -0700 (PDT)
From: Breno Leitao <leitao@debian.org>
Date: Fri, 04 Jul 2025 05:47:07 -0700
Subject: [PATCH v2] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250704-arm_kasan-v2-1-32ebb4fd7607@debian.org>
X-B4-Tracking: v=1; b=H4sIAErNZ2gC/03MSwrDIBAA0KvIrLXopD9c9R4lFI2TZCjVoEVag
 ncvDRS6fYu3QqHMVMCKFTJVLpwiWIFSwDC7OJHiAFYAajzoI3bK5cft7oqLqvMmGNQ0oB5BClg
 yjfzarmsvBcxcnim/t7qar/6W/d9SjTIKDZ01Od+Fk74E8uziLuUJ+tbaB8eBScmjAAAA
X-Change-ID: 20250623-arm_kasan-3b1d120ec20f
To: Catalin Marinas <catalin.marinas@arm.com>, 
 Will Deacon <will@kernel.org>
Cc: usamaarif642@gmail.com, Ard Biesheuvel <ardb@kernel.org>, 
 rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
 linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
 linux-kernel@vger.kernel.org, leo.yan@arm.com, kernel-team@meta.com, 
 mark.rutland@arm.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-dd21f
X-Developer-Signature: v=1; a=openpgp-sha256; l=2078; i=leitao@debian.org;
 h=from:subject:message-id; bh=nHYuH6tChVt5qIWjfOe/wW/MwpJhNrg5zTlmP7KwkUg=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBoZ81VFvHF7PJ6tVUQPcHhUtDROIBPyQcmYm6JZ
 GUZHPerTDKJAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaGfNVQAKCRA1o5Of/Hh3
 bYrbD/98qZZ8aLRXNLcokbh0chd6hghgMJY2Hz9GIVuk8KR71cJ09i9ySDkQqp2H1C61uWz+Eq2
 bD8FgXQTheK9Q29T5Xk6sMWGeE//NWZbj7vIjNyMWRdZODE5U4we0rvzLte8OD+4jLhICAozmIk
 OYkDIvz5tk6E99tkHyNwJ8od3UBRXBgsjuKvLhuuQZNlhtw7qvAjMHo5mKkPMUpuLZ1KBbWbIFx
 b7/bp0LBn05ZwX+ditk6pADUXYhWii2nxsoYqrQV8+q8vCcUgtvPBLBjSAaOcO3TVS6n7KOO2w8
 YKQG1BoHsdugXN6mPUhnCzcb2mVZD5ropVSH0s7p1kHVOiKGCiCQ0+hgJ4S8j5Cs0S1HvXn8bSk
 03j2TgoZUyPUFw9LNqOp0KLsk+Xxu4tCzYqa0EX00Fk7CvLhEVY4ulc+RClJ+c9drHUaJjXTWfn
 3itAPTWWQjVyo47oYEC+gPqWVk2f4xIqMNEdT8JWvCXrzzscqFAwylFhkH5kSEsDWIZ+1jsbg/a
 OlgL99AjUboOO1kCS9TJ6jOh4DWANwUmk7xjxDL0j1EIMlWhd4ecEbz3Q0QV2c80eVpDkcPqFUb
 uV23K5ppxBdzKmtBkcCjHyOzFYDGFjcDHnj9nSYODDAJelUnnDLSFK5RxoGzOhEdY/IxWrfysdJ
 fDr37mZQNUeJAUg==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.53 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

KASAN reports invalid accesses during arch_stack_walk() for EFI runtime
services due to vmalloc tagging[1]. The EFI runtime stack must be allocated
with KASAN tags reset to avoid false positives.

This patch uses arch_alloc_vmap_stack() instead of __vmalloc_node() for
EFI stack allocation, which internally calls kasan_reset_tag()

The changes ensure EFI runtime stacks are properly sanitized for KASAN
while maintaining functional consistency.

Link: https://lore.kernel.org/all/aFVVEgD0236LdrL6@gmail.com/ [1]
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Breno Leitao <leitao@debian.org>
---
Changes in v2:
- Clear the EFI_RUNTIME_SERVICES in efi.flags before returning (Mark/Catalin)
- Link to v1: https://lore.kernel.org/r/20250624-arm_kasan-v1-1-21e80eab3d70@debian.org
---
 arch/arm64/kernel/efi.c | 11 ++++++++---
 1 file changed, 8 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
index 3857fd7ee8d46..62230d6dd919c 100644
--- a/arch/arm64/kernel/efi.c
+++ b/arch/arm64/kernel/efi.c
@@ -15,6 +15,7 @@
 
 #include <asm/efi.h>
 #include <asm/stacktrace.h>
+#include <asm/vmap_stack.h>
 
 static bool region_is_misaligned(const efi_memory_desc_t *md)
 {
@@ -214,9 +215,13 @@ static int __init arm64_efi_rt_init(void)
 	if (!efi_enabled(EFI_RUNTIME_SERVICES))
 		return 0;
 
-	p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
-			   NUMA_NO_NODE, &&l);
-l:	if (!p) {
+	if (!IS_ENABLED(CONFIG_VMAP_STACK)) {
+		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
+		return -ENOMEM;
+	}
+
+	p = arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);
+	if (!p) {
 		pr_warn("Failed to allocate EFI runtime stack\n");
 		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
 		return -ENOMEM;

---
base-commit: 6b9fd8857b9fc4dd62e7cd300327f0e48dd76642
change-id: 20250623-arm_kasan-3b1d120ec20f

Best regards,
--  
Breno Leitao <leitao@debian.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250704-arm_kasan-v2-1-32ebb4fd7607%40debian.org.
