Return-Path: <kasan-dev+bncBDCPL7WX3MKBBEHYX7AQMGQE2V3J3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C57A9AC1B1B
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:56 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6f8e1d900e5sf77381446d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975195; cv=pass;
        d=google.com; s=arc-20240605;
        b=dWzH+Uj1QKhpDm5mgz9lR3rWYY/xqpO+aeh6EE1y0uL0GMH3crY5Zr8/Cv7UWqJyAT
         /4fSsAmrLVg5ehT9F+IPzRVh7UnyCq2a/uURQfazQpnNYOEG0W29i2s5V4gCy7opHHql
         ncgIbzH6OkkWLBOG+cCNbMKk4hfzLpNO3ME9AVNXUozfm83qSf0szd4rH4Ulg7InOWjO
         WqgYv9TcfoZ4qzKMP9g1GU2AJuPeD46iLoEXVClw/DBwOa3JcqdgoQx3AlvpV1s2f1gL
         GbQfF/IW5m1TsBx2BhJY8gWaG7qo5X/0X29Uw9Nu00JMvyDIgP0FL+/YLMcHioxpPNb/
         sXWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=SosMzE3C3O6R/ro6sFYWLLlwDiYzS3BsDieSCXhVA1s=;
        fh=vki/ukXgdHIj0jlnDoFaJMHcht3en3969Wfi4/Qf3T8=;
        b=f1dZbEq/D5E6pyf7yKcYWk/PyZ/XMkhMCYnPKg1Uq4IbAQ0acZkZutriqQCVBp3qPM
         SYy96rMxoNj9Ynqvr8fbAq5Q8AkSrjVvp9lyCmoHiuy0flD/5g+zhhaQlUjjtHMOngFC
         7ipWCFbi8wwIX0Yx5z+mYSakDcRWgV8R0Wcv9WC6UoojOLVicV/khmtSlqQCz6QpT44q
         kjJvGjyxjDYLD6CgOCDUZXqYtnckIQMrlBBMvxx+Jc49xABuKwVVi8ce3k6SB419gCD4
         +vBT74fcf+hDyZ5WYsJeN/Py1k/eDLqNNcV9ze2bJ8imZ6n1396wZ4ad1A6LMCSQJvHT
         aopA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fbUGodwJ;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975195; x=1748579995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SosMzE3C3O6R/ro6sFYWLLlwDiYzS3BsDieSCXhVA1s=;
        b=WY5FC9LDmfGwbpUnHIFb/fJLXxiX1xMbUiCcrnDm1RL69A7O/loa/wnKKX8XwdmW/5
         NbXGSwd/VeXyrzEnA/onRWEh8cInX3ar7WQ42PGkspYWDSHi3d2YjcYV+q36B13rSAa/
         NYwN4fQztVxp9vCUvH/7SJGBUtVAKyEI/v+rZ3W+Xr0+cV5ZRxfWTOPb4u6DlkzKXvzm
         XToxjtc1SisrF/QEFD/CjMpcIAWUM/6WXb5L0EOLBBDACSvBbGTQQOBPFrXB0e8Y6N2w
         ofuPnQaWdGHgV5hqjRQQmiKwurmsm9fZhTynkHJVv348jQS9hLG1Mh/OLRWVkYWwFMe8
         KFSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975195; x=1748579995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SosMzE3C3O6R/ro6sFYWLLlwDiYzS3BsDieSCXhVA1s=;
        b=BPBy4Jl7NPlL/CXLHmbvpUkGrh4lg5u592PqzetX/XpofdyB2II0hBQVZfD4kKzUQj
         CxDVcBbfiOdZznhvzvDp75bVBY+SURm3rYTGlejl8Q0utCoVgtz+ma3IP4er6GL+rVxB
         Yv8JlD+nFR3cX6BMv4nA3YH/EHaOJORdqkZyfYbwSd6G2qaTx6V3hmnQw7nzpb7mvmOY
         lWX7IxzQDpGxzkqtnSU9dk/45Mrq2pOlG92/9FqJFkW1ZVFN5N3U7xjaIDo3g3fGu+JK
         qY95sFr7XxfdLPx/d0I/ALxfOLkHVDlyxkvEt6U6zl6v2HcBWEmNV/H71TKSBacL1sHu
         wYsQ==
X-Forwarded-Encrypted: i=2; AJvYcCV3uM2JmufZRZNopO5nq7r5G99Dz5wdIsfO2WikWQpp08iie0O5Wl3ji1ioKz/MZ1rtP6KMGQ==@lfdr.de
X-Gm-Message-State: AOJu0YxSQh2TFal/wbVaCjYa6AD5N1bBVwwxvTXDApmoN1kawLt2uFhu
	1ByjyWwnAJzgrDBajGJMFTYN3ODGqmjO4agI2F6z7pRVTlh2KY/Fnd/0
X-Google-Smtp-Source: AGHT+IEN3NZ/lVt6TnNiFJbb+wZLKINoiqF/2mSjix5Pb5hMU0QaUwuzy6H7MqldIlQsBZ/ycNfeFw==
X-Received: by 2002:a05:6870:9603:b0:29e:2bbd:51ba with SMTP id 586e51a60fabf-2e844c4df7emr883853fac.9.1747975184671;
        Thu, 22 May 2025 21:39:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEPvFpbkfWss+nTs2rkIfopcigONNyLMwT+JV3z8cJlzA==
Received: by 2002:a05:6870:71cb:b0:2ab:4267:cb7c with SMTP id
 586e51a60fabf-2e39cc9d09bls1100561fac.1.-pod-prod-07-us; Thu, 22 May 2025
 21:39:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoLuGDZ2+SelBZ4jTJQ7e1GywmLFMfYs70hlDbAkOWg778WMnMfVd8f3TuvozfB2jb2/0jkm8Eo1Q=@googlegroups.com
X-Received: by 2002:a05:6808:3a05:b0:401:e933:5dd3 with SMTP id 5614622812f47-4063da0911emr1289686b6e.17.1747975183762;
        Thu, 22 May 2025 21:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975183; cv=none;
        d=google.com; s=arc-20240605;
        b=PFV5ZALF+cQt6nI1IZ6QMqEVPI7kFfnsgHe2HHCEMFv60JbEcAeguNt9cTyLebSa+v
         rklXgywf4tWHJannmIzzsvLLZfLkDR7qvGYCNClQBCwRY8mGd3juAAsE9tl8AQfBOPsE
         H1Vs3X2kGwrY9UPB4E7Fp035kSAACjNmteQD8ylCQXjSCiDVhLBv/Hk7lkljm2ad3yeb
         x+XnLMbKOrUA70BSdmP+YVm6y0dfYBquelTJKg6QuopIWg3QaZYKShDNwJjuIwxPlfqu
         D6ZerPf5bMtAPRs36Cqz1EBSz7g347lvayltBGeYK1pkCEmF1dxJ+VU3HH/IlwYzYe/J
         mYgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JaXnETxdWqbmIbvIT6H5WRFYzJ05uVw7n70J2uUzaFQ=;
        fh=E0y4v5tyVvTKcj6/CrXHB5Z6/5j5ivJUS9F4aWSLazw=;
        b=lv3i8KFom8O9d4A1UYXK7gilgLSboC6jm5UM6w3EW82DpI3kGDTl1PqWA7BA2kULjM
         UzjrCfocOR75taWCQ8sj4N5Rz4gOPD15dJjTYs/XiUZD60b2Iih3YYLsZbctmATF3lHD
         OsfwwUMfib0WSX+u8Lc0WobYZz1+jQdy2vhHkTCIYcY2u7K5AQb/25BY+kBBDcl3wf2C
         ojhFr6GVLyW/GqCEpkvAGvlK1U+/psUNb566/hkvvUahBlxWEN8urHu0a/8lYCrunJn8
         H5L4mG2QIByOuHyUELSZg69dOcJQgq4VmVauxCed3Xi3lzGcf0HSK8X+7sTCldKRe7tZ
         pjKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fbUGodwJ;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-404d96dbf7dsi121494b6e.0.2025.05.22.21.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 59A3562A60;
	Fri, 23 May 2025 04:39:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 220CFC4CEEF;
	Fri, 23 May 2025 04:39:43 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-hardening@vger.kernel.org,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 14/14] configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON
Date: Thu, 22 May 2025 21:39:24 -0700
Message-Id: <20250523043935.2009972-14-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=961; i=kees@kernel.org; h=from:subject; bh=qfrc6vYarbMRQKv1a7xZvSfoxfkNIKlLJL8wJGuWS5I=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v/+stliQLFcnI3MhNuGpqrXlscsrPuZ2Pphw9PPty JK/tZMZOkpZGMS4GGTFFFmC7NzjXDzetoe7z1WEmcPKBDKEgYtTACZy9jUjwz9r0T3FG5uDw0+4 eXQIht/dYufivG1V+fbJC4R/a1xouMvIsO2lyatle/N4Tq8Kn/e280RHCuP9s5s4OE3DpW5fOpL 9jgkA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fbUGodwJ;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

To reduce stale data lifetimes, enable CONFIG_INIT_ON_FREE_DEFAULT_ON as
well. This matches the addition of CONFIG_STACKLEAK=y, which is doing
similar for stack memory.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 kernel/configs/hardening.config | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index d24c2772d04d..64caaf997fc0 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -60,6 +60,9 @@ CONFIG_LIST_HARDENED=y
 # Initialize all heap variables to zero on allocation.
 CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
 
+# Initialize all heap variables to zero on free to reduce stale data lifetime.
+CONFIG_INIT_ON_FREE_DEFAULT_ON=y
+
 # Initialize all stack variables to zero on function entry.
 CONFIG_INIT_STACK_ALL_ZERO=y
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-14-kees%40kernel.org.
