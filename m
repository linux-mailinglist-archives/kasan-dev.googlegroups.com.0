Return-Path: <kasan-dev+bncBDCPL7WX3MKBBY4M43BQMGQENGGVKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id BE19BB0974B
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-403317cd1ffsf652591b6e.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794724; cv=pass;
        d=google.com; s=arc-20240605;
        b=akvZAgNa5OBP0ioAEzgeaDjINvzrqEj7NeT7dbtp5jyT94K1J0KRNATX4IuNl/sahT
         UtJtI0BDv+w1sWGcgyIp08t0p4cwkj0yY8h0CjA/FVtGTlFqYwQc+DxDcJkHTRisJCVf
         fp5/tI4JwH5BNKhxKMefOJzjyszi5tbeWnU54FtrS0AJo964VcCEU73nSg62gkwg+fBc
         guGqMLBE09myYbtusKX4nrs4V1Vbtgooy9dJTTsmUp4lLTwi/Or7UOjosZBCNblUo1I8
         3OASQmUdXll9mpy3MExQnitEt2EhmS3/i/W8tHLqJjxyZ3671qrQGhPxqGaQIAvq79n7
         W5yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BlIfoUJOAOKr4h/ajmi9Qx/xHjJVl7TuZ3ZqJGqhhjI=;
        fh=hIR/gwrypp0egin0fiF8Ufd3N6OEFTl1wI5DUwhrrKA=;
        b=evJRo1aYIIgZXCELx/MCbp47MO8kDsxHVG7F6ljr7jmlP4yZjNbVeRdXVDMnBIlYS5
         csuQkfyfshWUXOBhpMNJMpHqulVl1dIKsTePhDVAohkv7VDvRegn65ooBUHpze4rUJoE
         LWt37FL+GMM9Y1PJmkmcyZUADcvEC+0/aFpXqRQiv+HML7J5JIxPhNlKjz/eB3ibcWeU
         4Gk4kyQ6SX8ggKAv//ti05pasrSXIaJrkBoWZ0YBt18ZP2xQnrhOOEgzGB/QIP4EPGRc
         KNlC5L4JwaCItJwnZ8zWSCbpVKjFTKLctx+0PH04TyysGk9ve2p6smKxeqgFhVj9SXh+
         iGUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FsqjdsQS;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794724; x=1753399524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BlIfoUJOAOKr4h/ajmi9Qx/xHjJVl7TuZ3ZqJGqhhjI=;
        b=StCzfTvenyyHX/lbJPoIBSECemjzIyHfm/nAURQh9ZYdpoEv7GCdpTYQbCR9BRifJe
         JEr0C8ytVgX7IUwd4LtiQ9AtQ70Kvf8qFP08m1mvKAGh6z5tmDTLe7aUDZYI5hJKDmmd
         5jCFPqCT4/OIz+iziE0qOVRzvk0AZ5Au8SKUQBRxap9ahHz/Lxz7w4sLGUepyrAv+jCW
         PlmMFy6RnZCEuqPpuE0wHEahz/k45mNc2gnOPp3N7bBo3z3Iyg1D7nZP7vZjWWNJtzGK
         99pPVscDdOACKWacj7+GlQ3lkOHNpAtC7G8h0g/WTa59rEMQ9tMxrVDay3oia/SAGxpF
         AI8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794724; x=1753399524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BlIfoUJOAOKr4h/ajmi9Qx/xHjJVl7TuZ3ZqJGqhhjI=;
        b=IT+WxDVwJ2ZDMINeGJYMVaq7gq1Q/691a3vxceMZZSyN2iS9qeWRj3ERVUzmYUZy36
         7vTTyxjAxHjfJfn1RdX/WuwIZfp93C5zyXYNqWN8qiw9jlh04ChLuQGqx6lopdf9UbXj
         3SgIXng7qi1ClvaUkHJGi4PDMMS74bC2OyGKKV9v7YlViq+rDwDGvL2AFNAlKQt59pe/
         Fg3fA9Mkjoc0ILvaX9oi8WRBXazgxvlZrQNyua1Rj/ygTfRCz2tStSRqUSscF76/8Bpz
         aabvwdi0hfKHxAhYNpITgfUtH38qoo67YsMf5poWWmauxDmk/toUArz2q/Mzkhbgw97B
         ZRSw==
X-Forwarded-Encrypted: i=2; AJvYcCVe7jzAtB5TsOIBK+GDR/fiqQYkeZyNOM6AQJtaPKIP72J06EnNjcAI6S7JJlxoqLslDP3vdg==@lfdr.de
X-Gm-Message-State: AOJu0YzUwv7KOlNzeQT8cB1DCvvN+5Ffh2SrMtxPovcoyoWimIVmolhe
	r9otY2oGigwc8Bcn02trMsYB91FpTYTGChN77VgNs4MTTHrthHbNyrDX
X-Google-Smtp-Source: AGHT+IHXbjDJVMOK6dF26qNZ4IVT9K4rEXEJAQeGJ1hB0YeklJKL973FjPBHpL6alYsMKvg8agfwRA==
X-Received: by 2002:a05:6870:7023:b0:2ea:73bc:1304 with SMTP id 586e51a60fabf-2ffaf54dc4amr7140788fac.30.1752794723655;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfPo0zAZ4glxkYSDXPWnV71hXzcxI6wrucO43OMdCI+Ow==
Received: by 2002:a05:6870:6c02:b0:2ef:51df:c05d with SMTP id
 586e51a60fabf-2ffca3be243ls871039fac.0.-pod-prod-02-us; Thu, 17 Jul 2025
 16:25:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUz+yhdibFle3GGZi7gMu7rNp8Q+l9h0UsFK2ezmP8lrIywRUmnqyXLkhNrCsxr6VmyiyJzQd98dc=@googlegroups.com
X-Received: by 2002:a05:6871:e711:b0:2ef:e34c:e4bc with SMTP id 586e51a60fabf-2ffaf4dd6cfmr6624150fac.25.1752794722941;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=PO+9LA/+rZcDKDC88dKhBSXsa8qvCgz7R7K0jUFBmbALSBLnHSP+5JetEfHzpInM1H
         3nKqbYXMwTEM1aZs8QdQ2pE6iJmJ2qR7hI8xcyk3fP2cgYoAoi4HzwKY1a3qo6Ex6+Nj
         uJhnyopy/w5xKDm4wf3l9IV4bXMh/V9RvkG5Sp1VbRvxfJZ5suhCXLizkJsbkYJk2CkP
         2aqGejxF2vSbNj1JO15ikUpNPZrANEiQeCh3TZY+TDAw/Bw+r//ECL3kwhNoX9hscO6o
         3ec7NuQ3kmj+X9fjggpMMhptZSZGRF7jVLflXHiAX9gI8Ujwj0sHETIABOb9rEcH0/TR
         s+tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1XSpvLlvtj4VtScpjrFy6wBiDmzEp6kgT61xywF6hNg=;
        fh=2KRsr1RfR9429D69ZCh/hINX3/tl2fq5IwJsvWO12qI=;
        b=GIWhwfbcwsF3XGCVAe/d48H4+PRlhd8ctL8PcBbR9xWnfJvPBQS9JVn+Cmut6itIdM
         ZeBpWuhG00XsO7fjNxLArYy/D0T6q271A0as2FmpjbD3fY4zR5Fj/g+kO2HehBBSjlYC
         3u3A0TW4uNAxEbfYCvBEgYc6ngq0VJm8DwxSMWTZO0b1ocabVcakTYdJk+cssS2tQgFl
         KBm3h7XlAn85t22h2bbkgLuvTg5NMvh1Kslv/eZg6Z+q7LfRuTpK+8IDdEMkE2YjAzQU
         MIMTk9Ms1jtU4md76joxM/5ylbRbX9er23UOkGR9M6W9RaCOEaLFuUPqnDoM7+UpS72x
         L69g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FsqjdsQS;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73e83bacc25si18411a34.5.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6842845B14;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B589AC4DDE4;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-hardening@vger.kernel.org,
	Ingo Molnar <mingo@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
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
Subject: [PATCH v3 12/13] configs/hardening: Enable CONFIG_KSTACK_ERASE
Date: Thu, 17 Jul 2025 16:25:17 -0700
Message-Id: <20250717232519.2984886-12-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1038; i=kees@kernel.org; h=from:subject; bh=hftQ+JwDBzI0zRNacsurrBG64kHnxlfHAL+GJc3UtlU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbbFBctklSlm/hUWtYmesmm/+4Mz/o2oveebseJx+3 f2N065JHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABPZrM/wT/+s9b/zj2UjKz2d 0opOWQdaqM192v1qrb5mpnFiz/LKFYwMM5YFnp723f9/aP7hJMnrxuH6yRfrcxYbWx+zavrULTm NDwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FsqjdsQS;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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

Since we can wipe the stack with both Clang and GCC plugins, enable this
for the "hardening.config" for wider testing.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 kernel/configs/hardening.config | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index dd7c32fb5ac1..d24c2772d04d 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -63,6 +63,9 @@ CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
 # Initialize all stack variables to zero on function entry.
 CONFIG_INIT_STACK_ALL_ZERO=y
 
+# Wipe kernel stack after syscall completion to reduce stale data lifetime.
+CONFIG_KSTACK_ERASE=y
+
 # Wipe RAM at reboot via EFI. For more details, see:
 # https://trustedcomputinggroup.org/resource/pc-client-work-group-platform-reset-attack-mitigation-specification/
 # https://bugzilla.redhat.com/show_bug.cgi?id=1532058
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-12-kees%40kernel.org.
