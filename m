Return-Path: <kasan-dev+bncBCVLV266TMPBB2XC767QMGQEII4LQKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C50F7A90AD0
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 20:05:32 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43947a0919asf47021585e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 11:05:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744826732; cv=pass;
        d=google.com; s=arc-20240605;
        b=eQVhyIggFKjCZyrjJpNChQA3dxXe1aFjNL8eY265/oKHKioIcMhOJHvNgkL7nrcOMd
         BA8BX6yRdQ5xSB/r6HwKwikIU2ASCuMvuZaxLsRmX1uXX51wlCXHviW+al2vddmyBWh9
         sNPxSEzLQRGpm1HGdG8H/fzB6LWPoxEophgCoonS6fXd2u6e3UbWEP/tzxAq/zTMviWX
         E7kjzrEiNbZtMQybgMhCBDYSmtRSYeK2mXvhd6TrChpb3u87iert3rdx8N4dSdbioyUL
         ZAkg+/eY6ts02vKXCrzIrW71uU3SYcbWRWx0vfVZXXtAEerzttcZ2luDgSiEaIwjgRuy
         1sNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PKoskcWTHMkWd/0tQNm8vegW9u9WRGd30FeD3W7vYIg=;
        fh=tW29m++r688q4hz3/YQWaxThVEx0B85bVW1ecUwa0bY=;
        b=QiESu8aZ+U5k/cdhen1f2g/LnkwIq/1VQe87U+lrvWB4mvPilXyuoQFSf/knJ704ls
         BiR+/QDzbvh8j0fMaQnKjjPD/jpeqer4pqKs5v2GwbQc3b1+N7xL+YZjr7Ax4jqnSj3o
         TuPYR/U0gw5fKr+yIYz69uv3QjVlUwXDRWXe/vTJyCNjWQdX9cZBYMdP/IZDQr0YWlOw
         ovhNEEPECP1aXwH43exEmaE7D1v7aYnVk/4dlX/3+cVM99Z0QUyrkv/w4/QCFF2q1L9N
         iP2qI0KQbLXMaU2TWNk5O29jRHI2xkwD1eRaqU9deMYSdxpN4zsTdaa8FfAO1RulR8Aw
         hrVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uvqBqiwj;
       spf=pass (google.com: domain of 3zvh_zwgkcy8b57bctytz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ZvH_ZwgKCY8B57BCtytz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744826732; x=1745431532; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PKoskcWTHMkWd/0tQNm8vegW9u9WRGd30FeD3W7vYIg=;
        b=Ez73axTsypzXevF5QfubHd+toJOohmFUy/RNv11lLFMD/NHDOOWp0C8F93HVUJe4au
         2yMqH6/15k2rYEZh8fW3k3opvFkan+OKLRL6JLIsAg56z+AOSZXUn3IYNH/v2RqrxA1t
         bBYtZ8WvA5ARSfNnyi4rLGTwsagMP6BiT/MfFnU8fJ5PKUMDOVKyEYReasFghCr72o9d
         LwH5Cqn5OAnvcxOGtuOEn/ZjbH0cbKYtAJw6uiGMCvTRU+f5Jbl+EuGqIiFnxtIIjl4A
         +Mcxn1id1BwC6OSiikQOcXBUOzvh/ruPpVBT3Y/6jkmaygwcufYQHyNybAwvchzzhUCP
         su7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744826732; x=1745431532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PKoskcWTHMkWd/0tQNm8vegW9u9WRGd30FeD3W7vYIg=;
        b=bnDtplIbqWVMvnJKYoSFbxDhudECyJDttNf8pxQ095om+CqqBpcQa15xDhVc/hfgfc
         aXAANgUYamjeR12fTuG1cRDdiestl8hAuvmV4xIgaEwfjwGMNnDXerpg/TlhXdwVp8e7
         3+y61FLJSBJ3glhh2Y598DQcve64Ti49HlehrvqOCBxjncq9s2n8UHnD5+QV30Kd2vZd
         wZR+Oca6SrUotc9/oc2wvmzb+3Ja5PEt0WFLvHDL3MqyN2YPb4C3Xp7c3Ap9VktWi11S
         idk241+aVvyCPJhS3/DAGHvmqUU9Ri+CQ/zOtciZSydCPJMknxVGy0Wgn3BbPR/KCZHg
         SPpg==
X-Forwarded-Encrypted: i=2; AJvYcCUD0Vr9z0z1nu0pZKy4gFpLK7o5BpRFKKnp6lT4YC/Rr0+FTopn4P3x+DgOhqzlwSg7aR/dVw==@lfdr.de
X-Gm-Message-State: AOJu0YwQZkjObzdSjgdydmeZu+NHnuTHBajKcPtbzs0ySiVJ9RimWTR7
	8zzbBkcfmujqkPU5vtCy/j6sauog65PfC37EdjH8AgjteV9yVgcd
X-Google-Smtp-Source: AGHT+IF7UWn/krnr70pt15FO+ZV7dMNhXLDTvUeFnZbARAYBXnF6OUn8ZjJqJPnf5+3LiBBN6ePA+w==
X-Received: by 2002:a05:600c:8716:b0:43c:efed:732d with SMTP id 5b1f17b1804b1-4405d62a534mr35939975e9.16.1744826731455;
        Wed, 16 Apr 2025 11:05:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALjoL7tARo9PdPG/EC/w+oThf4sp1ZKx7CxuiNdknRTHQ==
Received: by 2002:a05:600c:c09:b0:43d:17c2:e7f1 with SMTP id
 5b1f17b1804b1-4406233d77fls652865e9.2.-pod-prod-05-eu; Wed, 16 Apr 2025
 11:05:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnl03Qnu2sUMHqrkqh76Sz4CohWvaVkZZWFGL+zcd72wTlFNIgVZPGxnSv+tdQOrwRzWlGmS+K9fg=@googlegroups.com
X-Received: by 2002:a05:600c:34c6:b0:43c:fc00:f94f with SMTP id 5b1f17b1804b1-4405d69b68fmr28944985e9.23.1744826726619;
        Wed, 16 Apr 2025 11:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744826726; cv=none;
        d=google.com; s=arc-20240605;
        b=bZmqSLN+lgjiZtVvlVPAeugJBsCAmJg7NNUSdqkHxvDZOUYT4JfF2ukD05tpLQAnE/
         YFKaUOPXPRBuFe3UWjzuM1d2f6FmdvcwSD+wZBpN9YcvtJFj5CYvTDjoy7ebQQbhriBa
         sQY9QSBGQjUq9f/LpkHBrAKhlPnD0ABB2KOnC3MtTGFtlatj9YI9XElNvioYkzYYkzGm
         VDLwBJagTxG4qwqBKO6DelnGK1d1mS6d1GW5N2kXibOQsER8YDUepgmd+pT+WWC9W6gx
         rk5StmiqNmVhmH70uchUrHDf3OjvY9LGyn5adQUdoEOHdyZfCBEW1yTN4nEY5bnDj7yf
         LzKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xO8p3wWnMTFzkHmEwWDOeYMg/xjqFsfP9HNTtGIh/qY=;
        fh=ksu8so7CzJl1D6NEqoq1c+HO79RU3JjZaamwoQ0sifM=;
        b=cnTPQPawPI7RmJe9byY8925kpZcL7GDf0ZWiTANLIOJVm/Srk8RUPR66gS/XtJk6LR
         ZXGIs9UfK4UXdLdJF+yx87nJFKliKup3so7EPV/2cD3h8rqZnF40WCuaX1hUZD8eUl9F
         8B/RDVqUtSjcIsU3l0KPu5tfJW7jJ40FBRa9Ruh5g7piJL3RgH1ZkenMk6b3ddz/fR04
         6zP2FvQxSSEA7Ubjj2hYSo+mBrxXh+GPhG9aq51hWeC9eCGPgsWTLmTJBmgll4bKJxfl
         ZKe4bKFSwGf/CInyQRnGd/Q9Xv1fCKcaNbJyV22RYvPsvI/1PZOAUmBya6873MWXUxTn
         SWrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uvqBqiwj;
       spf=pass (google.com: domain of 3zvh_zwgkcy8b57bctytz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ZvH_ZwgKCY8B57BCtytz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-39eaf420e78si209471f8f.3.2025.04.16.11.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 11:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zvh_zwgkcy8b57bctytz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43d3b211d0eso5746555e9.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 11:05:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWf8/wyHn5062ETZhreJRX35getqJ4i46f1ziKORFOjJHRBd5Y8qvBoVUYF6ZMRIiHZLGHLwYomHa4=@googlegroups.com
X-Received: from wmbh25.prod.google.com ([2002:a05:600c:a119:b0:43d:586a:9bcb])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:a4b:b0:43b:4829:8067 with SMTP id 5b1f17b1804b1-44062421bd7mr3209925e9.6.1744826726256;
 Wed, 16 Apr 2025 11:05:26 -0700 (PDT)
Date: Wed, 16 Apr 2025 18:04:34 +0000
In-Reply-To: <20250416180440.231949-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250416180440.231949-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.777.g153de2bbd5-goog
Message-ID: <20250416180440.231949-5-smostafa@google.com>
Subject: [PATCH 4/4] KVM: arm64: Handle UBSAN faults
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
 header.i=@google.com header.s=20230601 header.b=uvqBqiwj;       spf=pass
 (google.com: domain of 3zvh_zwgkcy8b57bctytz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ZvH_ZwgKCY8B57BCtytz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--smostafa.bounces.google.com;
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
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416180440.231949-5-smostafa%40google.com.
