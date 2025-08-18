Return-Path: <kasan-dev+bncBD4NDKWHQYDRBTPPRXCQMGQE6OVBAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 14BB3B2B0F8
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 20:58:23 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30cce9bb2bbsf9241540fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 11:58:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755543501; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z3ziwyh3VLBK9c4qWgb6mgPOUDvDugitKJJI1/xazNb6CDxr2PzEijFEiQ9Ig5BO/6
         YnKCcCZGPMmaltr1Zo0ex41q8tl9k1RX1KUgkVU3zmgzLzrUOm7navVASq5Z0vcQHkK8
         7dQRlmi/IaWagnRfH0ypGNJk8YYaM7MzV6IpNEreE+maWFPeKkNhvNxq1kB0kDWyv5X2
         UwkXzr+12FfcRsNxjoomiY1C8KZDHt0ywgtuAR1n4+RM2Jb18TvLFdxhScAlItLcNQvs
         kKo75Uiu4tUzr5aWYFDxza6srqdenBEntA74I8W/n5CCYkQfLb3IcT/DiJD9WI8GVxAv
         Yl0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=+57oOrUtE7r13X8aZFJUB5VDdrkYq1DSl24MTBFOx0o=;
        fh=GYacngUQK4Rp7ay/o8DhRIOFF+niPsMkjulM1LdFqu4=;
        b=lzf4H7k27UOLVuYQkdJ3wbippn4n7x3YEYTCl9zMOEb36kxGN4KOgJALOQDN4fMlft
         r0vo3dQqO7ckPxiTZPLE0+ug+YIQPb3P+ihxFoYJtDpvGyue5ieTeou/d0hnqGIwy0fv
         lRRJvswgrV+ruBcZxa5qcGlAP3iGOMjwDHcT9u+sGUA0rrc/UyMW3RHH7RN/XGJt87t7
         dvzEu3vMs0BP7WQlymJ9rwxLU7alUjEBwYC4dWsbL52X1zjpXkGtM1YhcoPrNQsfX5Ay
         FJKyAeq1nOWEEOLzOOVoSYCK5wqyOKGuD+XEKSRsmQLUm9qUKOkACYu4OIyDNy6vQH/q
         ZLxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IPBOhsZI;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755543501; x=1756148301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+57oOrUtE7r13X8aZFJUB5VDdrkYq1DSl24MTBFOx0o=;
        b=OI9QxOUteupNACdvPHWa1pprZf4SiTmiWZ0zFCncSLW5vcFR67b78nPCO0gK1ZW1LF
         BI2qzI0+mWKdZSaot8AgUMrIZtR1/jXSPS6HvD/iDu+g7qyvJF8IMgLF8c14vClsJPW7
         4iMaRAWROFhJ8TqT3eY3klM4zOa16SvyXsitCj20a0wWNadFbe1ha+lZwKpMtFQlJk9N
         K4qiSzYxQ3FtiepTgO/9BEFVnAiQHVnEkH3YBPwSwHCJeExhg3Jn5qRzFTNGysh/QxSO
         B9I7YcOj4LhCUqgmJX799dnfRGKyWaN1+RDSO8nTDKduLsqLTi+AjZp3carmGcBbO4Ni
         N9Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755543501; x=1756148301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+57oOrUtE7r13X8aZFJUB5VDdrkYq1DSl24MTBFOx0o=;
        b=Ba1BiNblp9qEsXc+RD1P+sLKo74Ksk1tyo7p/lFJnU1Po4AayduvQ/DBXZ1xlXUkSz
         t8Gmncb3XPzrGYruaZfRAKw88KmP4X5R6JF8+W9yXPh2QXkKD0kFXXWT09jI1x5oYWu/
         G+USFYfU40QuA274PQXoxRtQaRdePGEQNrvp/MB3HE+JNMSNWPx/bp5pchySa50DRAa3
         UU1rNLGAZEqi2kr6ZcFK45qCk/ntDmMTaNYH4I/9GYb0Qh2qBbVvpI8OCqzRS5oE5trt
         ClI6jMETCcaRIEn+acxtIpGc/P+51y0KB3hUU/PVdIo3FjSEFbYBb59d8MyusRLMkTFJ
         gkvg==
X-Forwarded-Encrypted: i=2; AJvYcCUVIwwrcKbKyz9g5Q6VYiMZJ8lebjatbQ3i3oVmSTPPYo4rGzwCF6w7xkKJOyIGhue+P3k33Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw6SUIoI/1rP/54/KMxJT2atapQIvdAJttx45E0pAFW6gJkbJsd
	uTilVtuhTFhVn2+mYwFE5jSgTeV+N32OziiGSXx5oP9RejHFHjZGQ+6m
X-Google-Smtp-Source: AGHT+IE6ROdb0PA/LfitkbLCB/8RUNwFziqxaU9d+ZoQmGjoCPl+IdXhbVFTMkJdjcws11QYaybYzQ==
X-Received: by 2002:a05:6870:ab1b:b0:2d4:d9d6:c8d2 with SMTP id 586e51a60fabf-3110aab4ba3mr133600fac.35.1755543501597;
        Mon, 18 Aug 2025 11:58:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeMhTi9Sc8B74HvGA63LtFfGx5GanFKU+7Eezl+ZQ4ehA==
Received: by 2002:a05:6871:a198:b0:310:fb62:8fdb with SMTP id
 586e51a60fabf-310fb6295a5ls262340fac.0.-pod-prod-08-us; Mon, 18 Aug 2025
 11:58:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmbIaHz+sfiZn6yTiq+pUsLlUAH4vHlTRqpHZvpJaSobTjc0bxhmcP6SA8jEZE3104lhPwCfdSOT0=@googlegroups.com
X-Received: by 2002:a05:6870:9626:b0:2bc:7d6f:fa85 with SMTP id 586e51a60fabf-3110a8adf12mr158406fac.16.1755543500485;
        Mon, 18 Aug 2025 11:58:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755543500; cv=none;
        d=google.com; s=arc-20240605;
        b=BM4qXOi9mpwv6npANVzFtqdoi6Gez1nZrZPhSd0R78+2a/Cg9QBh5WVNmRbo6+E5Oc
         zSL/1qfRcS7EF6NuOVuXkyI69rQXBDdzARvQihl3MIzG51SaTzqcfuwnjRExFo1EZHYT
         ro1O+lcBqmo6cKBRi1H8j7jANrs/MsAQExn/y7+2WSxx3xxYb97AbwcrfhQJ1/YUZuGo
         sYda3evkO4AuvMs/Layoerey4fXUjI8VFBzuJnpm15eSUliP3qccf2TlENrTMZVjfTaa
         b0nc76xCUmEWrq1D5b6bEaKAtaMicHF3GGG3yyTJRdshrC9LS+jKWA+ktnL1M0UQIaB4
         nfbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=vJgR3SBx7yFoxLglWDp4ib/7qfKrPDbNRRfICDOtUHA=;
        fh=T7PBil+zmFVPfuh/pfH7WFJmLBVnB1x1/W0cMBVbaxc=;
        b=fzPx98l4I4OQ2wpP+O+LWbW7zVykQWzwX0R7sXYHY2lFEPYKshGpbvDgdvpfXIQXIN
         XRz3qQSaaEtQvq8fP/qT6QmAfkI1wczHG1aC4oXN+kFupJ6ocx491vlBU9MnLsJS1h4U
         3TqvRrVb41D0YXchIcTygBKW/Xt5thr2EBUGlFYhgl7oqSv8KVje2X6cr+4VhIX0mNPk
         BDVrvVwcPAjTjHfua04D2tRJvfdmg6/8SevuUP57O5VdQjD/us448V8cJHRMBIw617Av
         cbUMyvZLFhneMBSw+vNU7U5uL3oFw1/kAreUj+lKhc2AbCuk8Co1gSMpASgj4wZ2cuBY
         7EWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IPBOhsZI;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7439204a0afsi349920a34.5.2025.08.18.11.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 11:58:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 997DB613AE;
	Mon, 18 Aug 2025 18:58:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1B9EFC4AF0B;
	Mon, 18 Aug 2025 18:58:13 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Aug 2025 11:57:26 -0700
Subject: [PATCH 10/10] KMSAN: Remove tautological checks
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250818-bump-min-llvm-ver-15-v1-10-c8b1d0f955e0@kernel.org>
References: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
In-Reply-To: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev, patches@lists.linux.dev, 
 Nathan Chancellor <nathan@kernel.org>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=1867; i=nathan@kernel.org;
 h=from:subject:message-id; bh=n9wtTbZr78bneGp9rs2dl5VTHuhlIejKNjhnDVexSd8=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBmLyxdpTPo4d83atdxffqwtOpPw7XPF2TUVEdHmG074h
 hbqHmLi6ShlYRDjYpAVU2Spfqx63NBwzlnGG6cmwcxhZQIZwsDFKQAT2SXEyPBt7+I07/dC02f3
 1W7u7ub1zku1F9x56toJ3pezC8uPCXIx/DPj3n4ueemmn++8d9k0lCu7SzxWyTmcGb9F8tSHN/p
 BC9kA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IPBOhsZI;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Now that the minimum supported version of LLVM for building the kernel
has been bumped to 15.0.0, two KMSAN checks can be cleaned up.

CONFIG_HAVE_KMSAN_COMPILER will always be true when using clang so
remove the cc-option test and use a simple check for CONFIG_CC_IS_CLANG.

CONFIG_HAVE_KMSAN_PARAM_RETVAL will always be true so it can be removed
outright.

Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
---
 lib/Kconfig.kmsan | 11 +----------
 1 file changed, 1 insertion(+), 10 deletions(-)

diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index 0541d7b079cc..7251b6b59e69 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -3,10 +3,7 @@ config HAVE_ARCH_KMSAN
 	bool
 
 config HAVE_KMSAN_COMPILER
-	# Clang versions <14.0.0 also support -fsanitize=kernel-memory, but not
-	# all the features necessary to build the kernel with KMSAN.
-	depends on CC_IS_CLANG && CLANG_VERSION >= 140000
-	def_bool $(cc-option,-fsanitize=kernel-memory -mllvm -msan-disable-checks=1)
+	def_bool CC_IS_CLANG
 
 config KMSAN
 	bool "KMSAN: detector of uninitialized values use"
@@ -28,15 +25,9 @@ config KMSAN
 
 if KMSAN
 
-config HAVE_KMSAN_PARAM_RETVAL
-	# -fsanitize-memory-param-retval is supported only by Clang >= 14.
-	depends on HAVE_KMSAN_COMPILER
-	def_bool $(cc-option,-fsanitize=kernel-memory -fsanitize-memory-param-retval)
-
 config KMSAN_CHECK_PARAM_RETVAL
 	bool "Check for uninitialized values passed to and returned from functions"
 	default y
-	depends on HAVE_KMSAN_PARAM_RETVAL
 	help
 	  If the compiler supports -fsanitize-memory-param-retval, KMSAN will
 	  eagerly check every function parameter passed by value and every

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818-bump-min-llvm-ver-15-v1-10-c8b1d0f955e0%40kernel.org.
