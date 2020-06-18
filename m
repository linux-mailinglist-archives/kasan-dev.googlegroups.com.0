Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7JVT3QKGQE4EYYNOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9FBE1FEEB2
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 11:32:04 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id m10sf2438455oog.13
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 02:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592472723; cv=pass;
        d=google.com; s=arc-20160816;
        b=x0RsmGZC6xEc1Z4WJYCIXE5jj74FEldBATW7xg51dtz2knUnY9PzCySROZuGYsprWG
         hw8jlFliWK2JKKRnxZulp8PSHw4TlmlqDLZj8zRBHGHKn0ZskhALG5f6gcmpqjJ0CydN
         zI5ufVdxzkscmFVlrjbPb+C0py4PSks+3wY0+Gb4ARhaxEmsqTn+RCNJErZC53agHPyd
         ZWAk4HGEsg85pQ3nkt4eQZy3GVSn1KBsROLrseo6cXz3DuXzJ2UJaeG/H0DjgGg/F7iA
         D0savh4AF3KtgRd8JiaGrAF6GLK4He9JM7hNSP/dN7P8R2y2PnuTGfQwa1xtUebZnwG8
         wUGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+nnjk4C7NRNFfZY2/cCtkzFuS5oSrm0Jc2ve5Iv8Trs=;
        b=sc9j8SNS5x8yphtPDu84nq3TArw14jC02rMX3a1t54+wl3K3Taqaj2k4rJozHwERCQ
         a0MChoumfZoIg22Lw56cNpAnYZ4EzUuljBzbZGpHCROjbfriR9yzc70Em/fHwZqar32o
         ZL6R6R991zZssBemrg0E0QHsFKV4tzhZ6EOpHIjJDmw+PiG4X7oYqUoRPAXmfCoXpL/O
         gAnRC4LYcqKNrI8g5voJLovGSLe4oMz/ML3vJsvUSVxGSjh94eAPzdgeIL5YKG+6x6i5
         6Hpb9QlyAznzUU9CyL0VpCC2rON3ckp3zr5Ot+3FH0j9j0IXDK96/oxv//HZKBmPHNt8
         gs7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fAXDSFhj;
       spf=pass (google.com: domain of 3kjtrxgukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3kjTrXgUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+nnjk4C7NRNFfZY2/cCtkzFuS5oSrm0Jc2ve5Iv8Trs=;
        b=jgCoCWUA3tngXMRKO5+qdZuGf/KBuZONtHXJC+Ocndiz+bbGUsIAFe3QKAEx9yvSVN
         //eLi1qrRKJlG8jOUbBclbpu268DNRd5ZB4UPTNjiQLo699saABDNiWdPc/HTZavGEmr
         7BCa4dStWM9DbCuL0pZs5LYrYxbKHnOCKrG88kaSe328wFymHUgXQA4R++3dpChJhknv
         sQcNi6DhpPvcwsGIo5q6GwDMsoUMhbwu+tTfhCZ2tobM6hq578nMu6+CJ3yuqUDmefBk
         ZHbo4LaYXQauZJIIH0XFJHwi4VEZIDFbI/VH1DgEw5HSfio26sFSdZ6jgokQ1tJQmeAq
         rk2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+nnjk4C7NRNFfZY2/cCtkzFuS5oSrm0Jc2ve5Iv8Trs=;
        b=Rl6ehB2W4pVMstv31RKT/K/H1x8hAZ11jp4Cfc1DtvtQ3PTIB/fpl91bkgQlBD80bi
         yV/F+8bmOeW/z4gXH3zOQl4ojzpF/IBf+yMlO5hx/Wc4f2vZVTf8iZWPQy4/hFOyadKO
         3kk0I5bGH4Y9pZvYLViy6jgFU9jfCa+1cVQagmKPPDxk5l7X/vlwlO01l/KMvYx0bLOK
         3zUm9OPS5sdOX3do9sFredS2NnSdcR8blui58Lh/nnndBxYMXkPq9jWdmIaLyd4X+JA7
         vXrKIbfsc44eZwkD6aRyBB1V1ikjsfibb2IPOVO8M1Y5envnf9eQ0R3IMglVGCzkM+lX
         3/IQ==
X-Gm-Message-State: AOAM533m77Pa7+dybSJoTTUEIX6ziZa88Fh/l9FwN8VBnhJ9l7LWtxux
	nCwuQ9hQ0D//OBkP/yh4VL8=
X-Google-Smtp-Source: ABdhPJx6MjrqSrtgcX5tJKN5oDcY3HmJR+EyPR3Rwb//X2Yj8D4GTq1qfK76Hzcqlf4M01fcFtwJYw==
X-Received: by 2002:aca:4d4f:: with SMTP id a76mr2246547oib.36.1592472723491;
        Thu, 18 Jun 2020 02:32:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c46:: with SMTP id f64ls1165012otb.2.gmail; Thu, 18 Jun
 2020 02:32:03 -0700 (PDT)
X-Received: by 2002:a9d:6349:: with SMTP id y9mr2800050otk.260.1592472723142;
        Thu, 18 Jun 2020 02:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592472723; cv=none;
        d=google.com; s=arc-20160816;
        b=fyio+bjRL+Lo7yciqP6A6vwwl4ojBwoim2iJ9/1AxN87YY+fKD30Yy7RZVrgdDIxUT
         TDciYxteSUJAgQmgKyv5GXqRSMgmy8AciMYjExebhjYPGNYbem5hNGd/wC1cJfSqzxqo
         y8QF2rpdF6epZ7mE3WWfKb1Z3iPpkceHOGXdPD+0Xu2W0VBIqAyRFKqdmI3UetlpZ8bO
         n1Y374sIvK2qWAXtDkGB7gCVmgpAYI4/0x6zGdHJN8LNfna7rXJwa9mx/YZmHaWbAsju
         ll7TNfcJCYPXX2JOk7oJylxLINWcBm8tcZxAuxyqp/XxVr2rDSlW0vm9ekewnR0ABuaE
         cOpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=086vfv3gPPfJZ5VO4SEM366I1+MoqC/R0oD42Imdbh8=;
        b=pHi9au2CdOcls+6hkcm+BZpBwbNGDHwS/WYVmpsvkn0xSYescdo84pZf/RG/T7+ezX
         4tp2PXr0sugGT1lfb2HoO67cLQT0chw5yku3aQRoCb7mlYQuu4Q4jvFDEQtDZW3F6BTf
         lVamvJ+BCutiSMNgfoAnieRYCSIGQHbKeh9m3EkkQ4zGoMqjXbX5D6blvHYRPTM7omaA
         RvUSCvqg9RUcZKxN471SBEsLkNTs9xgSDkRc/M7+cbijTvpe9JaY6LmcCvTDxjODj4kH
         P8jzEzCc71gSw0LfQwMDlgmWvVg5+/6o5D4iKVFTs7cpnvPvFginDM5AQuE3JuTuTyRy
         dLkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fAXDSFhj;
       spf=pass (google.com: domain of 3kjtrxgukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3kjTrXgUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id l18si139040oil.2.2020.06.18.02.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jun 2020 02:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kjtrxgukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id p138so3998757qke.7
        for <kasan-dev@googlegroups.com>; Thu, 18 Jun 2020 02:32:03 -0700 (PDT)
X-Received: by 2002:ad4:50c4:: with SMTP id e4mr2848394qvq.45.1592472722603;
 Thu, 18 Jun 2020 02:32:02 -0700 (PDT)
Date: Thu, 18 Jun 2020 11:31:17 +0200
In-Reply-To: <20200618093118.247375-1-elver@google.com>
Message-Id: <20200618093118.247375-3-elver@google.com>
Mime-Version: 1.0
References: <20200618093118.247375-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 2/3] kcsan: Simplify compiler flags
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, dvyukov@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fAXDSFhj;       spf=pass
 (google.com: domain of 3kjtrxgukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3kjTrXgUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Simplify the set of compiler flags for the runtime by removing cc-option
from -fno-stack-protector, because all supported compilers support it.
This saves us one compiler invocation during build.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 092ce58d2e56..fea064afc4f7 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -7,8 +7,8 @@ CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 
-CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
-	$(call cc-option,-fno-stack-protector,)
+CFLAGS_core.o := $(call cc-option,-fno-conserve-stack) \
+	-fno-stack-protector
 
 obj-y := core.o debugfs.o report.o
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200618093118.247375-3-elver%40google.com.
