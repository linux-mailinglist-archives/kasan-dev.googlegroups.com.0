Return-Path: <kasan-dev+bncBD4NDKWHQYDRBFPX5HDQMGQEQGL5G7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 18126C031F3
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 21:01:44 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-4442ef8731dsf1863521b6e.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 12:01:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761246102; cv=pass;
        d=google.com; s=arc-20240605;
        b=D8VS/4tCy6tYdofdgq7FjMLeUO4ki+hWWzI243TzxxorORN/laoiMXpl1cc+jbtA8c
         vth0eLlP3z8S1tQ1TgmfqVJf292aaWtUg6A29PP0/KTTtCY9zK9j8/UniuBkAcV9/Pig
         k66Tfl7E3eVT969BlX1alja8HCD7nAml1/yUU9B/VskTflx7nEcl/AXEAe+0KzAK3mPo
         0o2EVg85LU+KuFbSH9mawPpSfJk1k2ozTyn/EMC+e5zJJVNzkDBr7JzYePo2YGHQ/J3K
         vz9BVB943kivrvaHOGEm6AYvAjdYyTpyGwAVqDQMX9YndtoGtGJkCMQJhwwmOLz0JyKj
         DtjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=RwjBAvUHxQeRx4JNKwBNSa195hX3tfzV7Wa15JU3rEo=;
        fh=nIw0BWMQoHug6FsOegb+o6duHck2cXtju5AY4UDLMqY=;
        b=Dg30IT30zKLw+qgGeYCWJkXgmZTpR9PyvJ8gle4wG6SMr8rhG07SfPbfxRtJVQtudP
         R95CwdwYb0SM2dam/30kNbJsZi5SEs1NysfHym0yIr+x4j9GTvYu84mc9s+2k6lUI3Pw
         eQcm7Dr7GVi4tfP+8eLoJ5XhCNXTGCfxXTkBxlJc6KugM9UBHdrJWopiMq94hgAuunzb
         vVcyR3EESh+9CZsAYwaKofDIdVYMw5izVFfN/AZbcUNU64oihIYFZWEIt1S5JDXhKXUS
         vPav13qig7uodbDfxvomQubJ8dFKqlWr0PCxy9/4UBsWXlYz3vtnz+EVEwVH6uevcaPU
         iwNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KdmDjyF4;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761246102; x=1761850902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RwjBAvUHxQeRx4JNKwBNSa195hX3tfzV7Wa15JU3rEo=;
        b=LPenBTagJfx3ekU22vOo+TgyLcS6hJEJHCKeWbMGN5XW0leaPqftYawhQiWW9AgQpX
         z4IB+KlZoZSdW2VygGJd3Yt0kZ9ioGmrjPCBwO/oixee24Uur/J18O4T5Fan97VBS4nK
         slmKEIqTlrfDbrSjQhT2ey/n45YdUz8h6/Y2PR6P9ovgdQgBAmRabf9VJ7rxUGd011BM
         /JvZ+S9npZDMeUjBIJlpsJZY9vn20tl9V8oSl6oBeOgEmaiX+HSKnaPZ5OLnrdPQMWJO
         XKdv7C25nbWABD0iHcgUs9tt8Ew5wryMFmHCxqOy+7bC9FjsmC7xO/nsJsL7g1cP1byX
         ZGBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761246102; x=1761850902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=RwjBAvUHxQeRx4JNKwBNSa195hX3tfzV7Wa15JU3rEo=;
        b=pwnL77Hmi4K72XA8eJB6aO+vAzrMWHAA5RDFkM4R1Bj6OftqnRI2vNo0o4TXOJIwgI
         5HQzwCdyU0vqPPP06YSRfWLDYkw5xFNRTzjgJq10L1sCHUqL/xROxX5qUT6swnEnlRKG
         bgGfpWhYBMWQnELcfzMaZqWi8JGIetBd7HJyOWoYb9+qtBmxzrlQBWKEdHWDRRhuncBN
         Q9AdgBcTEtyw5DIH7dnS5INbgUOHwgVGiNkzhmBClJ5OvPvZuhtT1wtyxYHyH487ZXnv
         GmWEBapWadu/5JA63Xmw7AVI/iNW7c+O2ysOpsZanIsP7YFRvsPAnjaixe1y95CJjECl
         2Fig==
X-Forwarded-Encrypted: i=2; AJvYcCUMu0h2gM3RcqZmAC7tfqGgsgnYxsQnmlhq2Sj1ZYdjIYBtERng5ZifO5iXX1zRR46EYtqvmg==@lfdr.de
X-Gm-Message-State: AOJu0YyZjb4n6+K+pRzE/K+0UfHFlgRaZQH8RaGoEmv0k+mtCk/W3ibV
	gV2UDVwP7wYC4Me/mfxH99YzrgYT2jkjQ44BKCnmkkcZhpn/6Uhciq/Q
X-Google-Smtp-Source: AGHT+IF3vA1eBz5j29OEvjxLPgRbExK9Fbm0doKpjHDLxtt5riB6TH7m3LrrwjZFDsAipp8ys6arow==
X-Received: by 2002:a05:6808:1819:b0:43d:2197:c1e5 with SMTP id 5614622812f47-443a2bdc5a2mr12260578b6e.0.1761246101996;
        Thu, 23 Oct 2025 12:01:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7juAayJquqwtaKAk1HVW8eiEbP6xjIbZveESz6K7GYfw=="
Received: by 2002:a05:6820:26c7:b0:653:6378:f6ee with SMTP id
 006d021491bc7-654d7d7a40bls267030eaf.2.-pod-prod-07-us; Thu, 23 Oct 2025
 12:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRfiqYnt3SEbOUg1asyuX1zwdxVy/F8vfjUyrj5kfLBS49EpbR9npS4b4wfzQPpGCxd4lHWK4fRRE=@googlegroups.com
X-Received: by 2002:a05:6808:1b0d:b0:438:241b:e8c7 with SMTP id 5614622812f47-443a30ec3f7mr13558287b6e.45.1761246100816;
        Thu, 23 Oct 2025 12:01:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761246100; cv=none;
        d=google.com; s=arc-20240605;
        b=W5kj1/m8qmHTLXmqoI3HudrLuEBFGxprHWcDgiEJ1xTbd1KFTgORHmFj+T8eBZX6Ni
         AKN5r6SX44xCm5aoUzg0GbsmsPW674sZ+ql7scTk8Avo+kdAb1nP7WOMmdDWpcyWyHxb
         PpAkX8YExMWcjkAx7JCbppT9KdlvEPS1g+IRdcUzQDp/bt4/UYgOXFEkK0H5g+7AqY5L
         X9GDKXCPqUkknHu3jkuqQ8OcAUOAMrTFc7Bdf4aHHbt4EHvzWMlcRMkKDgHNESltUnT/
         KiTI9KoN1QUl38WO3fVGKnxmKvLKg7KlZN4dLEyUAupQj/xOOtBzy1kIijJlv+wGS3dB
         mPTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=tf98YQ8MFQdrRM8nlh29olGhBS7f0ky/C7GlArcRRHo=;
        fh=Fei1v2Ldx6TSnDW0uAuGJujsNJAgV9k4O3RTQia+p4E=;
        b=SRsSQcdI25UMykGZMNBEYzcf6YQJTmQag+HdCgsa2gAK1CkvGiL8M7qMhU2XS2fqYy
         bIT2eDGretoJRYQDioHvdQ4gY4kLVG2n5iYakvuZcZpbPQBu6OVLcmnJ6dY9wtKZk92k
         GaAgNpoRv5R4ey8mOLjVfmXuvtufs8mRtsy0vKrZtWenDMqcKwptjC5EkkSP2GTgtzsQ
         pjwBthStL5jsLFvbQHDT/6eYlUbnmRDHOdtEZS1tD40yMWccbiSrOPYumi2A5DOTFHK6
         sZtz1cBuUWgbyS4sFnMqPRxiNpC8+9qzNE+P5pHVQCZu/NsB+5AGoJivtLXLmNytGAn6
         4VwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KdmDjyF4;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-654d7fb99c6si135200eaf.2.2025.10.23.12.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 12:01:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 18C1C64053;
	Thu, 23 Oct 2025 19:01:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D9F97C4CEE7;
	Thu, 23 Oct 2025 19:01:37 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Oct 2025 21:01:29 +0200
Subject: [PATCH] KMSAN: Restore dynamic check for
 '-fsanitize=kernel-memory'
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc@kernel.org>
X-B4-Tracking: v=1; b=H4sIAIh7+mgC/x3MTQqDQAxA4atI1gbmBynTqxQXGjM1TDvKBKQg3
 r3B5YOPd4JyE1Z4dic0PkRlqxa+74DWqb4ZZbGG4MLgXYiY5Yflq1NFWpkKakwO6WMUfXJLfMw
 z5RzBBntj0/f8NV7XH/7mBb1sAAAA
X-Change-ID: 20251023-fix-kmsan-check-s390-clang-190d37bbcff3
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
Cc: Nicolas Schier <nsc@kernel.org>, Kees Cook <kees@kernel.org>, 
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
 llvm@lists.linux.dev, kernel test robot <lkp@intel.com>, 
 Nathan Chancellor <nathan@kernel.org>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=1869; i=nathan@kernel.org;
 h=from:subject:message-id; bh=Rl/OP3FUtJNNdUtSALnXRPKL3CMR9JuwjVxR8uU0OvA=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBm/qiced1v7d/lK5Smz3a4c4Np8yvxnmv2BiNWeplO29
 S3fdbaov6OUhUGMi0FWTJGl+rHqcUPDOWcZb5yaBDOHlQlkCAMXpwBM5PxpRoaT+72Ltly+qla7
 +8WsD+m/dlx7eObXHXWJN7PuOvL89xUpZfifuvvo8lWik+0Kf687Kbsi4Gthn6lF+u3d5+ZWyW7
 5fMuHHQA=
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KdmDjyF4;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
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

Commit 5ff8c11775c7 ("KMSAN: Remove tautological checks") changed
CONFIG_HAVE_KMSAN_COMPILER from a dynamic check for
'-fsanitize=kernel-memory' to just being true for CONFIG_CC_IS_CLANG.
This missed the fact that not all architectures supported
'-fsanitize=kernel-memory' at the same time. For example, SystemZ / s390
gained support for KMSAN in clang-18 [1], so builds with clang-15
through clang-17 can select KMSAN but they error with:

  clang-16: error: unsupported option '-fsanitize=kernel-memory' for target 's390x-unknown-linux-gnu'

Restore the cc-option check for '-fsanitize=kernel-memory' to make sure
the compiler target properly supports '-fsanitize=kernel-memory'. The
check for '-msan-disable-checks=1' does not need to be restored because
all supported clang versions for building the kernel support it.

Fixes: 5ff8c11775c7 ("KMSAN: Remove tautological checks")
Link: https://github.com/llvm/llvm-project/commit/a3e56a8792ffaf3a3d3538736e1042b8db45ab89 [1]
Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/r/202510220236.AVuXXCYy-lkp@intel.com/
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
I plan to take this via kbuild-fixes for 6.18-rc3 or -rc4.
---
 lib/Kconfig.kmsan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index 7251b6b59e69..cae1ddcc18e1 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -3,7 +3,7 @@ config HAVE_ARCH_KMSAN
 	bool
 
 config HAVE_KMSAN_COMPILER
-	def_bool CC_IS_CLANG
+	def_bool $(cc-option,-fsanitize=kernel-memory)
 
 config KMSAN
 	bool "KMSAN: detector of uninitialized values use"

---
base-commit: 211ddde0823f1442e4ad052a2f30f050145ccada
change-id: 20251023-fix-kmsan-check-s390-clang-190d37bbcff3

Best regards,
--  
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc%40kernel.org.
