Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBKURWLCAMGQE3SNSFQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E230B17F3F
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 11:28:34 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e3d462b81csf13308325ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 02:28:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754040491; cv=pass;
        d=google.com; s=arc-20240605;
        b=QO4SH4sZVbk1v+PtVFpHMsk5d+woiipEQtSr7TVla2Dntn9FxAFJ4CEaKXwt/kyu7u
         SbPziJ/dF8sgiN9ehxH2dgdmuSmB/BaCutEdHcvclFBajEzi0VqxwpDFnHkgUBF3va/S
         CKPWUyKqOND6ITk3G7e+YGb3rvfVlxa1IjjdROHog/EQHsg/62F+RMXKa3JznLxZzfks
         Lj54rIdJFWm0v0ndTMW8LhIxzzNpeHDXmyOrf+Pw8ZNGBfOL3S6pXJyfsNKgDT54WDD+
         0NRtymR/ILY8ddX8PX4UKx2IK6lF6oB48PcrNfNTZEhMOkM53QzjZm1AsoAIVSBJktpg
         yvgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7PnWNJRYwUC9kRSEnu8q7Mp3ChZ/ZKU4HAeC13z81qw=;
        fh=7/bjjl98yFmbOuWuoncGCH/G0UZlcFMkIf7Uwjwi2vw=;
        b=hfsn01VcmcKepGY/7E7N5JbFp/NUrYoZO4bpCqFpVIZqXlPsWlrG7zK4WWLK4TISpA
         wJt2R/dEd29j+9p4LpNodEId+Tb3a1vA9u6Tcy2uvMJgp+fd9zjJYqBG7bTDPDB0rwkJ
         sQjGMuecEmbNHXT0lF5iGdFp0OuR2a6xfyQZvi3aCfDpxlbW8LTdA8rrWJ8XLiDIOyXi
         Bl2cpdmUaI4NArS/tHhi5BpnRRqtDwB3JmzfaGpyLd7kcDbHdsb5wK8L/SMAYghAkFWc
         ziTgn0swqIas8hh95joKQbPrIxn00bST/VHoZ5PIERUMLhEZ+q+MSU3FM6rZsrGvH5sG
         74/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754040491; x=1754645291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7PnWNJRYwUC9kRSEnu8q7Mp3ChZ/ZKU4HAeC13z81qw=;
        b=oiW+fyLhVHNLRFGLdxKpF4cqF/O4jY6Nyrdn2YRb7O2Y/Kqpoe9DkTn+VOwI0jjD5A
         OZiVxioLOCXAOv7n4qgP8YdqsRqsVI5wDC6PWO3xvIHbYoxHsxjM8G/2PxjyPJD2mezL
         SgETrGPkh5Mhz3q4G93PjiyRLlaGtiHq/EZe1saD+SE27eAo/iveE9qO4zvgkznLjNhw
         neSTTzoRyz6VXW1miAX8GMN7tu5VC2lj+5h4M/SXRku8/LVNt20JJGQTCAyqVdFN7wU+
         AwspdwBFiehyON7x6tg/eFqWqUbZ38gxs0MI8r/hNIVQZ3aTdDn2MRVmnuiAcIrM40cm
         sCsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754040491; x=1754645291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7PnWNJRYwUC9kRSEnu8q7Mp3ChZ/ZKU4HAeC13z81qw=;
        b=v+q7sxGVmcg/3sJ00PTexo6jiMpDUTkiqUBnojk/Exihw5eyeFZwJ4x4R9/l71dV2B
         clEa0hWgX1uzE8zBxsvLDIVKH+Z9ROP5JDMKwQ1JuRS4xNdn3G+gxkdQAlROUUmn/VzN
         zVqUHXrxVN1vsWW4pgl2CvBlnby8I3rzgFTS+kqKac293oqxx2PJ6x/CNDe8H8OFNk/m
         NGLCdH6YLhVVKHJJlBEoiQRNqIqHqKR7US43jnNbeYHskqnfyQCB9MLyLBde2e278Pot
         3eOvXzzv4Nnm6MtDAQOTLNFA89Ngm9V+YLPbxWgB6iMVCxp0m5wreEGPrXucy9j1sjvL
         TV7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPvZCC2vfCEv1F48NJ8NW3WMARbvSqKQVkgDvNdcLTYEJBLNW4jUctbJ11wxFPoA++SjVN8w==@lfdr.de
X-Gm-Message-State: AOJu0Yx28vZZh5GvRVJT/aSqEV14YAuwA2NcYsD9Vky2WrYP5tjF8e+0
	hYJpdpdQQwOloNwpglLUhFCQc8GPEhYEaVBrm/k3EpBSP5gRPwRbSesp
X-Google-Smtp-Source: AGHT+IFRqgVS1QxaYKMFzdEM70HT1zPJBUicMA+HFQaVnlWOoHagCoT3hosOCLiQN9WUsj4S7sidYw==
X-Received: by 2002:a05:6e02:cc6:b0:3df:3bc5:bac1 with SMTP id e9e14a558f8ab-3e3f60d2107mr148041085ab.5.1754040490974;
        Fri, 01 Aug 2025 02:28:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeXv4L/gFP5hUjesxspGYl8keBJr81sokkOoIgioC+i3Q==
Received: by 2002:a05:6e02:1527:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-3e401b21509ls14676595ab.2.-pod-prod-04-us; Fri, 01 Aug 2025
 02:28:10 -0700 (PDT)
X-Received: by 2002:a05:6e02:cc6:b0:3df:3bc5:bac1 with SMTP id e9e14a558f8ab-3e3f60d2107mr148040645ab.5.1754040490120;
        Fri, 01 Aug 2025 02:28:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754040490; cv=none;
        d=google.com; s=arc-20240605;
        b=R44cMVe2LSYyLxxPUiL43rcVJZq0Ut8t7Fjj/vRZ1G3jiYGrEMNEFWRsYtqWRnbZ4z
         6MY8Aq4CHcNbomN5qyk6xh/qAJWlpsfwCtPo8UAHwT3g8I4HMNv9o1J1axT3QGcjjiFy
         tLNaJVG1UJ4OYTjIPAeRIpDTsuLbfUo0rsV07hWM4G91wKMjehM7Z5f3eWnjTWpANzeo
         Sp8N4GJ+sIXV34m4Td2CQqDLzH46oizcgR1tvEMzKxyqM+V4Rk1JoRQLXE+glohY8ilQ
         JRzUA9hNz0+ePQ73itrBCr1S+h9c5HJsIJpZj97+VcATbrRkdydi41WSbArnS8JdWzy/
         t3gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=X3OyRbnd9tzDjFgTDuxacn2jSWdNOiudDnCqVY7X/Ro=;
        fh=3LwrvSBe3PJwQU1VQ/HIl6WQZkyfdcGJHLCyC1aCtrk=;
        b=BGAjKxM80Vevv/ic+MRZ3Bayr1IGzzeQdXDgD+w2ARM8DdgomruW0mjZvbP+oFAlGH
         BJHJroW60AP0YSqg1fWCXlUPGUMkNwIu+FhvlFjUmy/HPDNdsAR9p9Lr+voz1hbzbOAE
         d6MwO76AY9XsJNlDO5oNrTceneby4GQt8NXDFPwzpjuaFvRKdgHWt9aMkPjTu4PjQCrU
         4zxOTP8xjSSM0UaTO9PfBkLWkthNOfQkT/P1ki2fzVMnRiJuTLYAms2GVmQf+lh1Svf8
         qTNvy/WM866fsqx4HcMCIgQxdmnm8DGYnKifEhb9U0U+nYJLr1pfFoY75+nhaUwlWvpi
         xazA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-3e402a13342si1138995ab.2.2025.08.01.02.28.10
        for <kasan-dev@googlegroups.com>;
        Fri, 01 Aug 2025 02:28:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6CA46169C;
	Fri,  1 Aug 2025 02:28:01 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id BEE833F66E;
	Fri,  1 Aug 2025 02:28:07 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: thomas.weissschuh@linutronix.de,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v2] kasan: disable kasan_strings() kunit test when CONFIG_FORTIFY_SOURCE enabled
Date: Fri,  1 Aug 2025 10:28:05 +0100
Message-Id: <20250801092805.2602490-1-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
triggers __fortify_panic() which kills running task.

This makes failured of kasan_strings() kunit testcase since the
kunit-try-cacth kthread running kasan_string() dies before checking the
fault.

To address this, add define for __NO_FORTIFY for kasan kunit test.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 mm/kasan/Makefile | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index dd93ae8a6beb..b70d76c167ca 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -44,6 +44,10 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
 CFLAGS_KASAN_TEST += -fno-builtin
 endif

+ifdef CONFIG_FORTIFY_SOURCE
+CFLAGS_KASAN_TEST += -D__NO_FORTIFY
+endif
+
 CFLAGS_REMOVE_kasan_test_c.o += $(call cc-option, -Wvla-larger-than=1)
 CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
 RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250801092805.2602490-1-yeoreum.yun%40arm.com.
