Return-Path: <kasan-dev+bncBCD353VB3ABBBWUMZO6AMGQE3MGQYMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 735BAA1ACCA
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 23:44:45 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2163dc0f689sf41748315ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2025 14:44:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737672283; cv=pass;
        d=google.com; s=arc-20240605;
        b=BqnU/mxxGCR8MxZFYYpMetwROTICnofCI4KCTl4qkyuqy8Ce619qUCtlaHnbYH/Lk/
         JpAaxkVt8xKAfewbE+h4ZVit3j4udd6sZpq0Kmq7xYtZKqmXvwGzVPSObGEaJ3WD6xWN
         R+u0cOO0HqRbBEexo7VYblNJSz1NQSmy4l7LdBbjXvDfBsDzUBujKDYJOUmWG9mdfMxu
         Shlzh9zHMk2RYtdWG5nsKKYAQAIvRuWdRNWxp1oS4ieont5Bd+YsWjiv0RHV2lqKYyRz
         ITsSGm3h9ProzUgUHMpg511BFjmOhODF2VUx6bvr2uHhXliMKzO4Nb/zYrzT8zAmBPi2
         x25g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=dOfwZYMwCs73xib9zCvkqaGMSTlZTwCybg6tzudOdpA=;
        fh=CVmOaQKRNXEdrx4mpSPymat0/uvDwEyRiEEgBtV4CEE=;
        b=Tff2E/yIvK7wMVBNMHKK7GrHw6twEc0MGJ94G7p0BqbZbDreUh8rSAG11jqKI6Qp35
         x6sHCWpt5zemHq2RRA8JtVSIiIoFvpMLdcD6DnAs+2crdKoQHOkfcwEsl3l25cnXpURq
         MC4RO/QnRWGstjEQ/gFr4x9UWHF3ox6db2h6qntWrRyNUhIO/Oc/XfaFpN5gmiooZO2l
         NlOAUPu5P1CNbcO0/Xw7itBKlFDEV8OfrgI4eIAbqlz6MpFFR7EGmn+fyD9O3Sm2ly/w
         5gLfgPNGvoySBhVKc+5bkFu0YIPtCjRv4lhhfZ6mx1Db8Tk+P67jPSL0/gclmF9nxcQD
         1R0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JVysbSma;
       spf=pass (google.com: domain of devnull+cl.gentwo.org@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=devnull+cl.gentwo.org@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737672283; x=1738277083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:message-id:mime-version:subject
         :date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dOfwZYMwCs73xib9zCvkqaGMSTlZTwCybg6tzudOdpA=;
        b=Qb1hjMqbS8S20loxLvKHfYVvlzCICwEtfMRQuo+1pLzEZ1B/daDFsuyLHbAIqpXZzn
         UMj86XCq8G28mYpC33lht9lJvy1pcatQywH1B2hX+GYzVCUw6O5iZtRQtf2U0Of9kQiy
         k1FmIMp1YcP5yrulXoRUo6qVJFlukPM0tbf5s0hytBmytU19387GMMfjkC9+M7HX5/U4
         4s1AxSmaGNNGuQg+PufHQPKub9WY+SUz4+59UsYdzJz7WE4Iz9AkfrfMCRasiVLRR/2v
         zueb84gga6EDFKM28Z11coI/6P/7onEdeHZFvJDd5Q8NtvjLYXOdEmESFqUJERbokl/U
         FeZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737672283; x=1738277083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dOfwZYMwCs73xib9zCvkqaGMSTlZTwCybg6tzudOdpA=;
        b=pZfUMcH6FqPy1WTAnegKVNc3xwkCOIcKfJuJGz359MPYETOjjt3o26OEBKAdfAgAbO
         m/2zcLjDsC/6+/Gp3QxTlVLVewNJ23MmEx5iYH+OmJEUMqkVl7dbi3Zysy8drjGEHg5W
         0fGNM7Ox3e+ucKz5OMB/YehA/6MsVkHCU+jeSMIeFQrM4i8oGFeZwhrsxju57sz/yBN9
         PTf6ZHLbsGbCeXl2Ko0VRI69dqm0Pk0VHOQuDpzwuMnGgq7S6YOMdhJ244HXapKd9AIV
         7CV8qN4gnzaoxps27IlWLZmjDqiutiQc1ZovlZT0vt3oOAhsIMofdlN+lHpr3uCOg1cR
         LpXw==
X-Forwarded-Encrypted: i=2; AJvYcCWeqd8YrlJKPFwlF/qQ65gkhaCtqq6IjVabivSJo5A4IcpLkT+hQdyGTFLgbbt/2Q6yUK6z0g==@lfdr.de
X-Gm-Message-State: AOJu0YzioyopeDxgp1tkf032bGLibFrn/PzoG1PoIugowkdSQoBhGUYk
	C9aQRKC8Lg7RGeA6rUy+6/LD/Kc3OwxxfqhMY1KiEhJIT0TE0c1o
X-Google-Smtp-Source: AGHT+IGNnPiuj/AUQA7PdDgUgh65XCrcqYfG+iS2jI9LbMhc1l03fhld8HSdpZ32hkwH6kPfKWhAGQ==
X-Received: by 2002:a05:6a00:2184:b0:725:ef4b:de33 with SMTP id d2e1a72fcca58-72daf88b1b9mr42858609b3a.0.1737672282953;
        Thu, 23 Jan 2025 14:44:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:7416:b0:725:efed:3617 with SMTP id
 d2e1a72fcca58-72f7d355fadls850684b3a.1.-pod-prod-06-us; Thu, 23 Jan 2025
 14:44:41 -0800 (PST)
X-Received: by 2002:a05:6a00:18a7:b0:725:f376:f4ff with SMTP id d2e1a72fcca58-72dafa46e92mr35800335b3a.13.1737672281537;
        Thu, 23 Jan 2025 14:44:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737672281; cv=none;
        d=google.com; s=arc-20240605;
        b=NvzxpJvVLptwGo4xE1K69xvSHIKN8mTeBx0+a8tY8pa8rtEXv9oLWU89nSE7UZ+NmE
         PPaH7CCGl6RSawfQGiUAneZw2a+mPgoRGuDJ/1VdsQxP7dqYsipK7fnjf8h72de8bi2A
         vRg3gyD1GA2dTbNoEdsZfWUUJZUHSM9tVvvadWKtYjsdy/0AFtu1GqEe6BiBqWEiI7aM
         aLXo9gK5VSSkHnbuZMGwHBjb0dTCnvcXIKYqUk/77WQV/TJXoLKDNvcXdtDkq8xRRyCi
         VD5tpJJ2VnVVAGzOuSdNm+s8x4H8so/gJYxwKkxITcnoiagR812MfcoqjLNh10Rl6Er7
         nRZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:message-id:content-transfer-encoding:mime-version
         :subject:date:from:dkim-signature;
        bh=DN2qIVtn45lSDeISRH7pzRdYiEAGo9xDvYndyjR48Wo=;
        fh=Adlj12xObAsViEXbvBHH6+1al8perxru2GhFcgjKLRQ=;
        b=NsAnMI4go7mFXhRuzc+/wQu+F3DNv2e9MKOzYSp9XYZzcaI/NwSm9o9apYRZO/1TXp
         fIEHetrXyn/tMVSCwBFVTXzD2jDQQJHMMAkpcTeuOwn6ZdNYpMd+V0hIVhprNfoFbicY
         TJc/szSqA/Gx0x333Awc5kiemX0gJhD+rLE+NKIbRIuOsQWRGvWxEH+/qMuWBEPOZIRJ
         Hl25qH+I02vJUY4EYI4yyyCrN8WtI1Kek1rRF6k6iUq7PZNdYNL6G8UdKraEYI9o3iTr
         rRLCsf2fMd/Ptz9RdXw5DSscWKO20yewFl6uwS/DQd26ycDlfgB+DhjM/Ru/ilL70K2L
         Fzvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JVysbSma;
       spf=pass (google.com: domain of devnull+cl.gentwo.org@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=devnull+cl.gentwo.org@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-ac48f2dac72si33640a12.2.2025.01.23.14.44.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Jan 2025 14:44:41 -0800 (PST)
Received-SPF: pass (google.com: domain of devnull+cl.gentwo.org@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 4B99AA410E1;
	Thu, 23 Jan 2025 22:42:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4BE82C4CED3;
	Thu, 23 Jan 2025 22:44:40 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id 33F87C02182;
	Thu, 23 Jan 2025 22:44:40 +0000 (UTC)
From: "'Christoph Lameter via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Jan 2025 14:44:22 -0800
Subject: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
X-B4-Tracking: v=1; b=H4sIAEXGkmcC/x3MQQqAIBBA0avIrBNKs6irREjqVEOgoRVBdPek5
 Vv8/0DCSJigZw9EvChR8BlVwcCuk1+Qk8sGUQpVVkLybUZvUbtg9bm76UDeSVOrtrFCGQO52yP
 OdP/PYXzfD8JKsIVjAAAA
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
 Andrew Morton <akpm@linux-foundation.org>, Yang Shi <shy828301@gmail.com>, 
 Huang Shijie <shijie@os.amperecomputing.com>
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
 Christoph Lameter <cl@linux.com>
X-Mailer: b4 0.15-dev-37811
X-Developer-Signature: v=1; a=ed25519-sha256; t=1737672279; l=3054;
 i=cl@gentwo.org; s=20240811; h=from:subject:message-id;
 bh=eIxS3YCsT4+4g6upmIgCuuU4kgmE4EN1FGtWLpy+DEk=;
 b=byG2v1ccXcVddMP4S2pWoNTqusVg0lM7PldpPyYmxe+NZFCRj2oqkKiZZAv6hjBhftZDnio93
 yi+D93q9QRVB0LvrZiXBylDWb052rPSMv87mqekQxhCVEDNQicsg/VF
X-Developer-Key: i=cl@gentwo.org; a=ed25519;
 pk=I7gqGwDi9drzCReFIuf2k9de1FI1BGibsshXI0DIvq8=
X-Endpoint-Received: by B4 Relay for cl@gentwo.org/20240811 with
 auth_id=194
X-Original-From: Christoph Lameter <cl@gentwo.org>
Reply-To: cl@gentwo.org
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JVysbSma;       spf=pass
 (google.com: domain of devnull+cl.gentwo.org@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=devnull+cl.gentwo.org@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Christoph Lameter via B4 Relay <devnull+cl.gentwo.org@kernel.org>
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

From: Christoph Lameter <cl@linux.com>

KFENCE manages its own pools and redirects regular memory allocations
to those pools in a sporadic way. The usual memory allocator features
like NUMA, memory policies and pfmemalloc are not supported.
This means that one gets surprising object placement with KFENCE that
may impact performance on some NUMA systems.

Update the description and make KFENCE depend on VM debugging
having been enabled.

Signed-off-by: Christoph Lameter <cl@linux.com>
---
 Documentation/dev-tools/kfence.rst |  4 +++-
 lib/Kconfig.kfence                 | 10 ++++++----
 2 files changed, 9 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 541899353865..27150780d6f5 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -8,7 +8,9 @@ Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
 error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
 invalid-free errors.
 
-KFENCE is designed to be enabled in production kernels, and has near zero
+KFENCE is designed to be low overhead but does not implememnt the typical
+memory allocation features for its samples like memory policies, NUMA and
+management of emergency memory pools. It has near zero
 performance overhead. Compared to KASAN, KFENCE trades performance for
 precision. The main motivation behind KFENCE's design, is that with enough
 total uptime KFENCE will detect bugs in code paths not typically exercised by
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 6fbbebec683a..48d2a6a1be08 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -5,14 +5,14 @@ config HAVE_ARCH_KFENCE
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE
+	depends on HAVE_ARCH_KFENCE && DEBUG_VM
 	select STACKTRACE
 	select IRQ_WORK
 	help
 	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
 	  access, use-after-free, and invalid-free errors. KFENCE is designed
-	  to have negligible cost to permit enabling it in production
-	  environments.
+	  to have negligible cost. KFENCE does not support NUMA features
+	  and other memory allocator features for it sample allocations.
 
 	  See <file:Documentation/dev-tools/kfence.rst> for more details.
 
@@ -21,7 +21,9 @@ menuconfig KFENCE
 	  detect, albeit at very different performance profiles. If you can
 	  afford to use KASAN, continue using KASAN, for example in test
 	  environments. If your kernel targets production use, and cannot
-	  enable KASAN due to its cost, consider using KFENCE.
+	  enable KASAN due to its cost and you are not using NUMA and have
+	  no use of the memory reserve logic of the memory allocators,
+	  consider using KFENCE.
 
 if KFENCE
 

---
base-commit: d0d106a2bd21499901299160744e5fe9f4c83ddb
change-id: 20250123-kfence_doc_update-93b4576c25bb

Best regards,
-- 
Christoph Lameter <cl@gentwo.org>


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250123-kfence_doc_update-v1-1-9aa8e94b3d0b%40gentwo.org.
