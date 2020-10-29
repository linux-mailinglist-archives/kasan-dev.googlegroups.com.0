Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGNP5T6AKGQE5TGNTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A88D29F50A
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:23 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id l188sf2916139pfl.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999642; cv=pass;
        d=google.com; s=arc-20160816;
        b=SHAFwsVGqOdQbVxfHyQjGoPijS1W12mXCsPQ/N39NJ/6ec3QxggnH4KKypmraErtq+
         AY7DBSpmyKEcizoLcCQtaf54MMmLMdO0Um5kh8ZtYaAs+0usu44uEq3dUv3dLnkmfLAV
         STGYQUl6yLFqnyzhlBD/7gLnfZUhvIr0wntHdIG0zzwROnvXHckbmuakOcyo8scZYmoK
         jtvFAS87qzKe6e3BAYy2Fv90tJYAJNqDrXVyAcHkilew7BUrvMTpPBHPPKOpsWCm+bCz
         /jMd7+uBrYe+2yYAl9Amw20zVZbD48KAksmUM/iGioK+x0D9gDoGiIBGiCJ3sC4SVH3o
         UJqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+o6klxjhls31ICdO8ESwuVQ/zxrXJD8angctaSpvvs4=;
        b=bjVvTdPs4GzeaWGKcXi65LRoDiD6g0OhAxVEe0TlIq2NchI/JbfASGdfQaCky7g2E+
         I6wUADO94L5Yj6kmDbqBMQiN88xpfc7gXNsKnCRIG043eFMZ/cfyYc89AJvKOtMqUTev
         bkAGh91m4WYpQWdTtNDiV7ur2OtGPrzKE52Vwfqcn0tPkOzYKV0bsbibAK4WaSaFVl6I
         XfveVVyj2zLJBmJA6QOFwwBjhH+rYLfMZsxMHqa8rb7ZgmIFimloI9QbrEYGXoA4/wo3
         d/1Q0EBoZZyep2PFeN1qEaz4sujTTSyyds5IvzOJPJ/oQ883wNr2m20xi9vvBEEOXNy+
         pXpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kyhG/LpR";
       spf=pass (google.com: domain of 3mbebxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3mBebXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+o6klxjhls31ICdO8ESwuVQ/zxrXJD8angctaSpvvs4=;
        b=igZXRcLqurvP056MyMxPUwxN7PIg9sMTg3fJzAwYOq+zFRzD7kzeZminMd4hv8hJ0f
         I3T3i7Y5CCvCOfqxXpUjjAREiN/LWYC+hqGpps2UAMz3TfLGGI6wcEq5F2JVvVQm9MAq
         JQa++kUooH3emwiLDFaoLi8tS06yxk9tQIVrX4lHHp2eDmpU2lqRZ+ylfI8hXV9059+S
         MF8lmBH5AYxsc7XW7wxyX+7t0hYLZ4O/7m7GUCJt0KGhE5kHbPiZ1QUfezjx0Z3zDl5L
         zqVQ3zY5I1y1dlilsFi7bz6ukjXnEzVdsbWmlWz4oz7plWDDatb/JQNhYYsL+IwDcwBH
         bwVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+o6klxjhls31ICdO8ESwuVQ/zxrXJD8angctaSpvvs4=;
        b=fQ41TA90DQVZfpC4cM7L88tnXMb76WT5H7wl4rk7dcOuZBskQxL6iR23RE3sJixl1M
         ZqC+aewVHhgGcclQYCHvQr4ncVS2m+xk+0/EofXxUZUGpDVicNDSQO2LeDSse2VST7LR
         yDjd1e0a/oJKcW2HX9LTR00FsOcJihDBsrf73glAWgEpLhumy2sK20hSqZesB+vSFDD1
         gFpcfq8LtkQvD53FHLSUTBDEyFjuKC/DIEM1AOohmpgurnNBDfqXswxmi22mwwcuObsY
         O8rvKuYNj/YASSrHRmIlL6RD1Zc/sMXL7B0ujeO5nMVA1zSd/gc7KKFIukZLp13J/12C
         mX3g==
X-Gm-Message-State: AOAM532+kz/x4cDn3Ia9cavHBnbVAjpLFq+ynuvuzReiOqdBh12bIRVj
	upq2D7w3Y1u7ZqhnJDu99P4=
X-Google-Smtp-Source: ABdhPJz7k9OaK78LuB9cB3Kn8p+tDAHtthG6ez/u0WlcKDMo2lKlIXR/wUTZDIlFqBfPIUoHgd3BvQ==
X-Received: by 2002:a62:d44b:0:b029:162:67f0:3c56 with SMTP id u11-20020a62d44b0000b029016267f03c56mr5578578pfl.55.1603999641892;
        Thu, 29 Oct 2020 12:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls533421pld.8.gmail; Thu, 29
 Oct 2020 12:27:21 -0700 (PDT)
X-Received: by 2002:a17:90a:488c:: with SMTP id b12mr1357203pjh.211.1603999641369;
        Thu, 29 Oct 2020 12:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999641; cv=none;
        d=google.com; s=arc-20160816;
        b=DYDPdvu0gZ3y7YtRa9uBm5t3/JAN1a+C1mT9yJLir9MskvZKcwT0SfA6v2bzcJCB17
         jePRnJCMZwOIXsGealokrmYIrzM+KX/O/qXEEQ6NuiqeUevcQx/yfwCPdFLmZMD79skF
         ezvQYcgZEZ+G8zu+I8ejy8tA0JmEKRpjBSrnJJtgqQxrHqJE6NHi/v8IcCoHj1OAo2Q6
         y3Zv5yVi/6oetyXjC6yWxZPcv5Y4M8klVcLW0CsehTeFgQaQjK3zFH1E6XxPAsembAue
         +LMcLKDkIDOAtLhOFq55yivIbPqKqwYwAXlpyswqO/4sebBXFNl1TwSFMDLsZsxTBsiz
         p1pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hmgLBwrpZmM2Ob1pVeE+PUpkn+sXRrzyuWPTws3FeSQ=;
        b=awoESVLTVyO4/mIfgmD6Ue/q5UEWLPifeloLu03LgYSe6YhDrWKI3NqlosAld7efsa
         KaKteN4QNKY+DWw9/t05MCqVaab3yaFpG78DY7cv1vvEptnNMliyCjSxB5r29nxAW0yg
         pxgU57DUfqGkCHNjmvPMgFuyAEVFZh/9sUVT7j7CLjgFsWqxzE4JDMIwvEE1aY2qqKXa
         dY61TtlE8KHTeoUBGK/dfm+whM3OUG/aQwWnLohz2aOw4E9X9zxtexwt33TPcLMBVbeL
         FWuzGfpk4t++QnYYHXTuT0su5JA4t+PI2zdf+t8IIjVW7vUpSlHSwvP7XFzNglyVyKl3
         5xSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kyhG/LpR";
       spf=pass (google.com: domain of 3mbebxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3mBebXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 100si34625pjo.3.2020.10.29.12.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mbebxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id i2so2468990qkk.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:21 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:2ed:: with SMTP id
 h13mr5419776qvu.26.1603999640531; Thu, 29 Oct 2020 12:27:20 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:51 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <8730eee8f88eafbb3148458ea8d2f55c89a94fbf.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 30/40] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="kyhG/LpR";       spf=pass
 (google.com: domain of 3mbebxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3mBebXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 9f13ab297b7a..9e5049ffa160 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -134,7 +134,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8730eee8f88eafbb3148458ea8d2f55c89a94fbf.1603999489.git.andreyknvl%40google.com.
