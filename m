Return-Path: <kasan-dev+bncBC5JXFXXVEGRBUUR4S4AMGQESCEQLCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1288D9ACC69
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 16:31:48 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5ebbb808318sf3047403eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 07:31:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729693906; cv=pass;
        d=google.com; s=arc-20240605;
        b=EfebjlmNoyOQoC/u7aTP9edofSLJvFwQg427cqGLYHKi1HV42tIkqCHDe/SpvcZRwC
         Hg8Y+O65m6QdLEOdps88K8qsKcPzPT9rHKWcBkWm81GqJAzXRET6EU/azgzf+7blxw9v
         XxxFw/vn0T4LPmLdLBL/1jVOaKFzwTbSfKhJSg9+VWoVAHYpjfRl4LsreKPz06JGYisK
         HMIzQVmNA23PbaZYwgDK4iNOUpj2psyGpwwNO2pT/OC762p7pGB+Cb4HY+z/1FitzJLK
         PA+82BbPcRi6gC1Lhj4Ci0TN4TwutWpeNo8yuTtRDKJjk7J6rnazSl5tC7UkijjQOKgM
         Aa0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kDazEEj0l7Bs8tfnnmSAAcuUAzBRb/EwKJTAdpcu4f4=;
        fh=eHoW5WsLFQKEn4YtHNE13mgRIfWpx+gXRrNsJdrBirg=;
        b=XLzkgfyDe9qpG5DXvIJhvUT4cDFSK/OwI1impRkLoxSuzD05x23dCZOeBUpuJ4yMXn
         ZC4PjGw8qOuxhisfEZjym/sheOen86hrbW01lGAdTAAv53fHcXmDsqlZi1MB7yzl2n7J
         5V9W6P3NHLDEP5EG76xMM+0Ak7BAtqusHW/V44b28URwYHNQivLHAtoRRfmZpfMU2rFc
         ye8FCLwX8ctbb3trmIBpE4TxV5YfCCCAcj2UbYO/zga5WvI6bNv2LfOz+vcg9+viEeeb
         1RTkU8acF2z6J1LVv5+rNeuNqwCKXwpmYqMgpt/7z7tLq8OMCK9rt+N3Df80LaEZhtos
         ihvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nMOjG9LG;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729693906; x=1730298706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kDazEEj0l7Bs8tfnnmSAAcuUAzBRb/EwKJTAdpcu4f4=;
        b=ojeGnkQIs/LJDnXSxGd7bvMVsU0tEhjxDewtzgGfcxbJVVe+kapIhD8kyabuF1ZRaL
         bQcuGK4vqkm+ZUCMTKm3jmN+82FIPGpgvUmzqOawSPIwhy/QXl0MfkEjfus9k2UbPEGv
         POH74lO4CF6BPi57+VPUrVu0O+ENLNuLXymZxTbQotlzav4EcSZUksUkO6bqxFSZgmDX
         jAt6qXhNIQ9cztq5t8uLoC8CZldJjtgSKj4BJNlrPt55Aj8N07llDZ5ICjUnpjlG4aJ8
         hhZabtfwYuj3AUkZIvnk20PIyxWiu4UX9XcGbIh/yePT1Rxq1/7HJYIvLPy4vPhmAk7q
         wp1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729693906; x=1730298706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kDazEEj0l7Bs8tfnnmSAAcuUAzBRb/EwKJTAdpcu4f4=;
        b=tFUzs7+EfF3o9XGzS/wC+m6jmp6Ec6yAe+ij0C4aoKEvvn0bRKEAB7t21fifGpSyCy
         lHWbktlUh0KeFdCumduRIGECP3XJbEN56f9AcAsilrn/91TQVfIIzXRuhGCAF+yo64ni
         BsNrfMddJSMDSC14Tl30XrF7A39g42k/yE/mbiafVZRwsJ9fNaC1rhI7tMCjCNFOAx7U
         VIiVl8/b+Cvg71muVQt8xmnj/xSQGXSCIRqoOQQS538W5LU5pIwRqtDSYhsd43EHT8W8
         bQiD366DiGom7pIgxWjetGIWURo2D0j3N/irk2Xrfp3A8zWowlemuFwuJWzU134E40/Z
         o8Pg==
X-Forwarded-Encrypted: i=2; AJvYcCXNECpxGwhrbCxG5WjDIDsflgyHns0KfX8t2CbR5bogGg0O3p5ZikVdQnSvfCnXY4eBGYWcbQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw18fqDyyVCxrrzxBzGMjmK+1KeuxK4eDg8j93NiYJX0q0y/3hK
	mbqlkKypzmn13UvEkgdoHpVTVCEcDn73apdZjfRwkiEcYfmNX1TN
X-Google-Smtp-Source: AGHT+IF7o7n/JBgvlG+ySt03A1pGPdsMUUPO8tJT7GyCrG4hdy/RYMnJ8TN3SZ8k1ShfZ/9Ti4ARaQ==
X-Received: by 2002:a05:6820:812:b0:5e8:4dd:46cb with SMTP id 006d021491bc7-5ebee8e832fmr1997597eaf.8.1729693906503;
        Wed, 23 Oct 2024 07:31:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:40a:b0:5eb:64ea:8ec0 with SMTP id
 006d021491bc7-5eb6bb84570ls3974443eaf.1.-pod-prod-09-us; Wed, 23 Oct 2024
 07:31:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJWHNBJmcLd9HgC1zbmM0wTzJG5fXoFkagQve6MqDYosL/IVWXuu530tHJiKn84/9mTU55SAxPnoE=@googlegroups.com
X-Received: by 2002:a05:6820:220e:b0:5eb:7e7c:5303 with SMTP id 006d021491bc7-5ebee4e83d5mr2314822eaf.2.1729693905740;
        Wed, 23 Oct 2024 07:31:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729693905; cv=none;
        d=google.com; s=arc-20240605;
        b=luuLKAVHvdpLX76eNPj+mcuDhoG7FnEcQDV2jDmA7fdch6BKSAxvMJpf7C5fDDnTl9
         WL7jDqYg3izz5T2qdN+dzRpq7LcfA3ZWE6dCScAoB4l1TPoUGPtyrVK0wRfwcfQf3Z+R
         LaoF/UTLEFAxTDS5weKHOgHE6kz7qIJGWvNCCKiKo5bZS4qB3Kpyn3qDAAQDrcdy9Rwj
         bdyvHXcdh3xNeesZ8X2Eias7VWTCKDipTP3EZxK2q77gZTVsVDr6spqVMoQppJmQfkct
         HY1q7Gug8vPQUe6SwM5ZxhSLJPz5oPQ2C0sNhmmA5uB7OIb2Bj+4lS982RvuYzLYs6Mi
         AKdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6AummUMb7YO94vECU3SUs644F7NF9giHIE3Z3ETC/9Q=;
        fh=2zoRfZ3GqwaOB86OT+ogluMCAewlKKw5Tb+NnXhkKI8=;
        b=K7roUScPjeJAzn8LP+abf1D4ywdMvGzDKC4u134WTGDEOJVFRb25fid/f+f9CAmN9n
         fQrxfxyU7j4RktuBFVvzbg3szFxH/6Nbs5E7ZPBUnTJB9QNUUkWTdbak7SbWX+Vc3WZv
         mZKIRJtJLvpkhEK/wyTebB0FNLufHNvsXLufkLMQuI58YYmBf7CKP/m8kV4p2NLN/ohq
         7opl2Ibe+XcquHBUSrq9qvRjdOnN9vJtuNjl+bgHpS4nLT6A96xQ+/eczie243Y3fq1A
         3xUrnOOzBYDSM7KfYn8bE57NpnvX/awlZ6LwGOJLFBKI516/GoJmy9Uw/9VaY00sPLlK
         SO5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nMOjG9LG;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5ebb7a176e6si295266eaf.1.2024.10.23.07.31.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Oct 2024 07:31:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D0CDDA44EF3;
	Wed, 23 Oct 2024 14:31:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5904BC4CEC6;
	Wed, 23 Oct 2024 14:31:43 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	Sasha Levin <sashal@kernel.org>,
	ryabinin.a.a@gmail.com,
	nathan@kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH AUTOSEL 6.6 17/23] kasan: Disable Software Tag-Based KASAN with GCC
Date: Wed, 23 Oct 2024 10:31:01 -0400
Message-ID: <20241023143116.2981369-17-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20241023143116.2981369-1-sashal@kernel.org>
References: <20241023143116.2981369-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.6.58
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nMOjG9LG;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Sasha Levin <sashal@kernel.org>
Reply-To: Sasha Levin <sashal@kernel.org>
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

From: Will Deacon <will@kernel.org>

[ Upstream commit 7aed6a2c51ffc97a126e0ea0c270fab7af97ae18 ]

Syzbot reports a KASAN failure early during boot on arm64 when building
with GCC 12.2.0 and using the Software Tag-Based KASAN mode:

  | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
  | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
  | Write of size 4 at addr 03ff800086867e00 by task swapper/0
  | Pointer tag: [03], memory tag: [fe]

Initial triage indicates that the report is a false positive and a
thorough investigation of the crash by Mark Rutland revealed the root
cause to be a bug in GCC:

  > When GCC is passed `-fsanitize=hwaddress` or
  > `-fsanitize=kernel-hwaddress` it ignores
  > `__attribute__((no_sanitize_address))`, and instruments functions
  > we require are not instrumented.
  >
  > [...]
  >
  > All versions [of GCC] I tried were broken, from 11.3.0 to 14.2.0
  > inclusive.
  >
  > I think we have to disable KASAN_SW_TAGS with GCC until this is
  > fixed

Disable Software Tag-Based KASAN when building with GCC by making
CC_HAS_KASAN_SW_TAGS depend on !CC_IS_GCC.

Cc: Andrey Konovalov <andreyknvl@gmail.com>
Suggested-by: Mark Rutland <mark.rutland@arm.com>
Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Link: https://lore.kernel.org/r/20241014161100.18034-1-will@kernel.org
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/Kconfig.kasan | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c057452..275e6295fcd78 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -22,8 +22,11 @@ config ARCH_DISABLE_KASAN_INLINE
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
+# GCC appears to ignore no_sanitize_address when -fsanitize=kernel-hwaddress
+# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=218854 (and
+# the linked LKML thread) for more details.
 config CC_HAS_KASAN_SW_TAGS
-	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
+	def_bool !CC_IS_GCC && $(cc-option, -fsanitize=kernel-hwaddress)
 
 # This option is only required for software KASAN modes.
 # Old GCC versions do not have proper support for no_sanitize_address.
@@ -100,7 +103,7 @@ config KASAN_SW_TAGS
 	help
 	  Enables Software Tag-Based KASAN.
 
-	  Requires GCC 11+ or Clang.
+	  Requires Clang.
 
 	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241023143116.2981369-17-sashal%40kernel.org.
