Return-Path: <kasan-dev+bncBD4NDKWHQYDRBV4L66WAMGQEOWMO7YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C8EC2828F85
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:16:56 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-595cbe58e2dsf2403175eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:16:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704838615; cv=pass;
        d=google.com; s=arc-20160816;
        b=oPEcz5t4i9htP4Jj/w0f9xBYCHznODW+urVcWbZUxio0xDb9LokNKZKEh7KXaw6GQC
         djGiJSPY2LkyFo1z5NTp2T6zToQjgdn9plfh6RnsOhUctPD9Aj9Wiv2htZlaghmJ1I8e
         VImRdhICZ/yX4qvfqI9GUALbt5bem3Y34lBa0uBtS/RPCGdK6QVUdX+qfYrQpPxzkpAA
         jUxCOOF7QqZK2ZZQUce4cTSXhpU6g0k33lp4c9hhO2IEQXthNE1jGh+mly3FcxNdsHZY
         Gv6gdBnfkW7i1BhDeBWoP5LXnCaVmSzX9/V7eMOjTrX9Chu1gkqPYSdtUCaC47NWZQ10
         s/bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=NomDBRp+LvPiZrLnYJilAkJp5E/AVkXUo0CFpWXaEc8=;
        fh=U610rwpBWzjqqwzWB+qVKy6HwACT/aT32/o8U6KTT3E=;
        b=f3xk/OnWCpU3/UTYp4FNLeP7R6e5czVMO/rPGeo124zKme9dor7H/Bk6hKyTMq5XuO
         Mb0Nu8xyPv8X9ew4pSP5u5mzL6fpbezK6OirGdjET9jl+b78L13XAOLM9JUTztFnmmM9
         SBPb7U9w4tP8NDtaSX4nePsJO2y1+Rir4ypisN/LXYI9+86J9/amXGQZEtQV+fMJQT1h
         USaFTiX/l2Yk4m8e7zIXnSKmA2j4xGPaiGcSovO3WxV/4VE0WLAyPODlmMT8BEHHLGk+
         b3HoI1InMSkvM3NByfA7O+ugjyDk1RsBrL6ANq/Yze01kuYim9NA9MYNccRP5R5P08eC
         Qt7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DcHElP87;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704838615; x=1705443415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NomDBRp+LvPiZrLnYJilAkJp5E/AVkXUo0CFpWXaEc8=;
        b=rXDae6hEpNCQc43rgSdzdS92vO9u6iK6DB8/zZLWCaOL8yYeCHLH6aKvGI2MJVEjEV
         xSaS+zWiD4+1a6wFvtzndSZ1iJoAuP6mK1szBJhzi7NAVxV0otQVhKrvRHI3XfZmJXOP
         3GZlDOvPn+Ltpmgrpb3s+ZEtT5bRCmi7cZHtxctdulx0afsA9kGHg8WjR3eqgcqtzY9a
         2baOE7YuNdE+ly9w8D7AED14qbTzEzTodxVV7EXEwHZaUQ73QF0x4LZXv67tHZ+6umU5
         0GynvBOwjomnOXcZPN33hUCMdyDdDGR8Nzwh6/nygneswGYiCTeDk2SVI/Y6LnvqjIh2
         c7dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704838615; x=1705443415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NomDBRp+LvPiZrLnYJilAkJp5E/AVkXUo0CFpWXaEc8=;
        b=X/y6L1LCd/EW2HKUstf6HA6kQ7dIcxhVtzIiGEYezWeTg/M/qdT4smh2YYIMRzYItD
         oZayhFCGz04a9OEFJGT+Q/vOna025ugUVuzgXJEFodP4D/J1pP6D2C/RFrNrgF7ZLm9X
         NmYkmQsudGwH1MJlbtlSm4ROxmS7G34dLLf28FSrrBWTCpT4E45I0LhohP+Ye207Z3ay
         dCgqisz66ftyTqDH+fpuM7rhj3j/dB9BFBHbJG0pkAZFEgqoG723IW2GQbJr38lNTkjm
         nx9HaY8EjaK87EMONZdpj5egh5l7GI6sj51IpdGWQURAsu2MUj/XItwp99ntzWuPQrE5
         djUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzLGbIbvSlU6AFG++A9TZJl/Ng5Gju85v8puwHVKF9aLHxmBNWA
	Ul5e0uR4bmMXg1kFnMyJEO4=
X-Google-Smtp-Source: AGHT+IFXS02cBgfAoYUojDR/aB4W93qNOWLCLIA2EIXzQIJbU1oV4aBKU5ik7hT3k6H0c+ATS8lINQ==
X-Received: by 2002:a05:6820:2382:b0:596:1aaf:ef17 with SMTP id co2-20020a056820238200b005961aafef17mr105482oob.17.1704838615487;
        Tue, 09 Jan 2024 14:16:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2214:b0:598:3899:43dc with SMTP id
 cj20-20020a056820221400b00598389943dcls1920005oob.1.-pod-prod-06-us; Tue, 09
 Jan 2024 14:16:54 -0800 (PST)
X-Received: by 2002:a05:6830:718e:b0:6dc:776:2eb2 with SMTP id el14-20020a056830718e00b006dc07762eb2mr35510otb.62.1704838614159;
        Tue, 09 Jan 2024 14:16:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704838614; cv=none;
        d=google.com; s=arc-20160816;
        b=v5BYKrhSiYW7kOEGxBWxdFUHXGdIX8vE//wtJrl1kad/DIULO4Uxq2DYWbKOt/xuLl
         +VDwFQzi9263bAhUm45C96R3AjOt/K0riXD4eQgMSB9Fof4jC14tEun8NzYTqRo1GJW+
         HBlVy/H4yI+Dt1z+X3L2bEcc0PjWh09m+ujhvzFv5IRZtOgeTvPwDLD+uXCC8HhzNsBy
         Vh+znKX/Dj7KJCeUkNIkcGxuV4PCdwuy3BPk93O90YpLfArwVCm2GRrGRe8lvltkrr9J
         fpe3PxUUdds/J98ZmTdhS/Pb/DDC/NgIsycWPkVoSoOBlgK0NBHl4SMZm8hqCrBFgt+W
         1ssg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=VtZ/OaS/oLDZxnbof29aK3bK4DqiEKpmYUBNnfxrZHg=;
        fh=U610rwpBWzjqqwzWB+qVKy6HwACT/aT32/o8U6KTT3E=;
        b=Y8oQ4gWrbKqCTd+KNwdJqig5Yq4RDfbNw47GZfbFAHLOQYt+bYrr4aMY7oeX657b07
         UiGDI20lzPI0TAh8RqV+hkrzG3wfHeTX3kGQWhmKOVCsf323b3ylcHauO+7E/R2HTlFL
         8BhA1muGPRtVbqhJwx9kjtI+PhkhWcObrOJG5rTz0MMfkU8kSaFX5niKp3WBgVfZ0EYX
         Hr9x4m2Vtf0Pwwp4RtrecHgbrWITXmMk8vRoUPOB0AzMTEp/tD1/0G9ZS5D5BAnPzrpB
         tWx6j4QE7UV60FLi8aWHRFjoeGwkXUdvy1p6fKtWQsmPdUMINlrbYeDOjR2JAy4PDa7G
         wm0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DcHElP87;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id di12-20020a0568303a0c00b006dbfec84c32si260030otb.5.2024.01.09.14.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 14:16:54 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DDA6C6153B;
	Tue,  9 Jan 2024 22:16:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 123A1C3277D;
	Tue,  9 Jan 2024 22:16:52 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
Date: Tue, 09 Jan 2024 15:16:30 -0700
Subject: [PATCH 2/3] arch and include: Update LLVM Phabricator links
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240109-update-llvm-links-v1-2-eb09b59db071@kernel.org>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
In-Reply-To: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
To: akpm@linux-foundation.org
Cc: llvm@lists.linux.dev, patches@lists.linux.dev, 
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linuxppc-dev@lists.ozlabs.org, kvm@vger.kernel.org, 
 linux-riscv@lists.infradead.org, linux-trace-kernel@vger.kernel.org, 
 linux-s390@vger.kernel.org, linux-pm@vger.kernel.org, 
 linux-crypto@vger.kernel.org, linux-efi@vger.kernel.org, 
 amd-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
 linux-media@vger.kernel.org, linux-arch@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, bridge@lists.linux.dev, 
 netdev@vger.kernel.org, linux-security-module@vger.kernel.org, 
 linux-kselftest@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>
X-Mailer: b4 0.13-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=3768; i=nathan@kernel.org;
 h=from:subject:message-id; bh=FqUV9XbJobSbmU63Vc9OUMUQcPG9O3IVnKnVxKihgqg=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDKlzj14wLXz9bOkxsYsrTGYdLPdQyNrnvz59Sf7hWSzS5
 avzyrO5O0pZGMS4GGTFFFmqH6seNzScc5bxxqlJMHNYmUCGMHBxCsBEuHQYGY67OxucPlmQ4Skk
 bzsxKZ793GXTxU+kr3sE7umaHJ1xyIeR4V+622l/ZUP3AsYOg2ahGcz/dlh+redryHGc4DIv7X4
 mHwA=
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DcHElP87;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

reviews.llvm.org was LLVM's Phabricator instances for code review. It
has been abandoned in favor of GitHub pull requests. While the majority
of links in the kernel sources still work because of the work Fangrui
has done turning the dynamic Phabricator instance into a static archive,
there are some issues with that work, so preemptively convert all the
links in the kernel sources to point to the commit on GitHub.

Most of the commits have the corresponding differential review link in
the commit message itself so there should not be any loss of fidelity in
the relevant information.

Link: https://discourse.llvm.org/t/update-on-github-pull-requests/71540/172
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
 arch/arm64/Kconfig              | 4 ++--
 arch/riscv/Kconfig              | 2 +-
 arch/riscv/include/asm/ftrace.h | 2 +-
 include/linux/compiler-clang.h  | 2 +-
 4 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 7b071a00425d..3304ba7c6c2a 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -380,7 +380,7 @@ config BROKEN_GAS_INST
 config BUILTIN_RETURN_ADDRESS_STRIPS_PAC
 	bool
 	# Clang's __builtin_return_adddress() strips the PAC since 12.0.0
-	# https://reviews.llvm.org/D75044
+	# https://github.com/llvm/llvm-project/commit/2a96f47c5ffca84cd774ad402cacd137f4bf45e2
 	default y if CC_IS_CLANG && (CLANG_VERSION >= 120000)
 	# GCC's __builtin_return_address() strips the PAC since 11.1.0,
 	# and this was backported to 10.2.0, 9.4.0, 8.5.0, but not earlier
@@ -2202,7 +2202,7 @@ config STACKPROTECTOR_PER_TASK
 
 config UNWIND_PATCH_PAC_INTO_SCS
 	bool "Enable shadow call stack dynamically using code patching"
-	# needs Clang with https://reviews.llvm.org/D111780 incorporated
+	# needs Clang with https://github.com/llvm/llvm-project/commit/de07cde67b5d205d58690be012106022aea6d2b3 incorporated
 	depends on CC_IS_CLANG && CLANG_VERSION >= 150000
 	depends on ARM64_PTR_AUTH_KERNEL && CC_HAS_BRANCH_PROT_PAC_RET
 	depends on SHADOW_CALL_STACK
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index cd4c9a204d08..f7453eba0b62 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -291,7 +291,7 @@ config AS_HAS_INSN
 	def_bool $(as-instr,.insn r 51$(comma) 0$(comma) 0$(comma) t0$(comma) t0$(comma) zero)
 
 config AS_HAS_OPTION_ARCH
-	# https://reviews.llvm.org/D123515
+	# https://github.com/llvm/llvm-project/commit/9e8ed3403c191ab9c4903e8eeb8f732ff8a43cb4
 	def_bool y
 	depends on $(as-instr, .option arch$(comma) +m)
 	depends on !$(as-instr, .option arch$(comma) -i)
diff --git a/arch/riscv/include/asm/ftrace.h b/arch/riscv/include/asm/ftrace.h
index 2b2f5df7ef2c..3f526404a718 100644
--- a/arch/riscv/include/asm/ftrace.h
+++ b/arch/riscv/include/asm/ftrace.h
@@ -15,7 +15,7 @@
 
 /*
  * Clang prior to 13 had "mcount" instead of "_mcount":
- * https://reviews.llvm.org/D98881
+ * https://github.com/llvm/llvm-project/commit/ef58ae86ba778ed7d01cd3f6bd6d08f943abab44
  */
 #if defined(CONFIG_CC_IS_GCC) || CONFIG_CLANG_VERSION >= 130000
 #define MCOUNT_NAME _mcount
diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index ddab1ef22bee..f0a47afef125 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -9,7 +9,7 @@
  * Clang prior to 17 is being silly and considers many __cleanup() variables
  * as unused (because they are, their sole purpose is to go out of scope).
  *
- * https://reviews.llvm.org/D152180
+ * https://github.com/llvm/llvm-project/commit/877210faa447f4cc7db87812f8ed80e398fedd61
  */
 #undef __cleanup
 #define __cleanup(func) __maybe_unused __attribute__((__cleanup__(func)))

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240109-update-llvm-links-v1-2-eb09b59db071%40kernel.org.
