Return-Path: <kasan-dev+bncBAABBGH5XKAAMGQESXKWS2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8884230251E
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 13:50:35 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id z19sf7091237qtv.20
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 04:50:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611579034; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrgHXon0/i2SIihTKqt6/QqMfmFgezodWVaH8IepCDO1nurDBkBVZfT4Cy1Pd8dYPv
         CeIiiP4c3UwWUOWVtNIzsaidoMyO8h7phi1/EZb/vSbDtTzFY/jdY/LStUmO5ODvJDiI
         Ws3g+16efkcm3722J3y2XgO9p7g6pSYiMtAOpzf5ltATR+IkyuzYL4ghepQObS4Z57gT
         +2TTL78eGjp3sBi9Wlld/bGpcr/yffQw2IEMxciq39AP618X1C+uWnnC4g7Ux4tOlKY1
         IiiUuLACI4VvGwK+thH/4ujeacu+6kn3blk1ePbFlKdUXgBS7VPwTCRPXvFcHhcBnHUN
         kwng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cj9wzUaOf4ll3i5SL3OkdBGwCm7R0Unnwscp4B1fFgU=;
        b=sQLtEehCh2lwcc2lxIzmLTZ1wSQTE+BfS43Y6SXLP5R+e8pvWHwtrpkL6MC5PAW5J2
         e9ONxd1Sb8qv4Yqs4gO2gXTLcHXSsC2DKr+srOa7u82BGZQoVajSFxvi13M4yS+CNHBz
         ts/FOUbT+26O7MWmfyrDb7iB3b4qiSFY5Qnbmzv9niJ8yV/qi6t12ffl18mXa2t7/pWl
         0N5WjCtvo/C2PxapimtEzEqQ6fO2RmMNyuldwg4XkpRw9r4GEQwHHdtQvjkrfSHB1dI7
         jjVNxaRNLgIYtIc5SxEyQNjvqSMKZ2uJ7cO6zv91g13JYWIPF5/N2wVvp91QaRcvxn4P
         mkrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H8ciKPee;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cj9wzUaOf4ll3i5SL3OkdBGwCm7R0Unnwscp4B1fFgU=;
        b=ghY5T5NuO1jjTQ/QQQ9BE7bwJiWxQCl0Df0/T8y1YAt3T8aqKc95+wny2ApA+5JToD
         Fjo8UxP/QJ3lKAv1DwC2kg00RdIDUpvCbBC5z0RP5lQlpOFATU6ezfzjzHbWuA6t9fwc
         ut23RgMzllFzxnajGpjyq/x3Pb+En6PCwRtR04+8vlJxeu0w79NwDo3fbKDDrkno2VV2
         guVDHCgT6SQwNIHe7yQQMNJtWSW637H7Od/Je3C9gzgqibKm+bAZmRR8afgXYIsQJOQs
         KuHBW2/t0Jocft1tCxFFhmncB/98J1v2TkxgN0OoxNj76RADShLTJemJzLIlH+zepwS6
         IitQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cj9wzUaOf4ll3i5SL3OkdBGwCm7R0Unnwscp4B1fFgU=;
        b=R5TF5+UGFR1drsjkCrl8cBoOiLm9kS6W2L766T8B0X2mQDp8HAyX+xUsxvyQlkZ1vD
         YJjDGWvnK3OsdXcC/69Xr77z870zsxuzFlK4UW0DFkoPQx4/3oWyLwwT2Q9yVqqxAO+t
         r1KWkYGOyyXuIYCYMGWoQwVzzbtgS2RqfVA/Qrrt3awuGsXZmq6nZYrYQSYCIgmFPdDb
         tNpN/j//5cPatQuDKxc7PpU1we2GClG/YRjXIfCQyPklu6BhL4mQYz3BRKGJssgRfMSN
         IqNO4RRrLHtK4rEH2Gm22ifbfGpgMUMRSRSBaMwL3163e/kl8wEDSb4TDwJ9XA66SQiA
         G55g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314PiTu14SsSyFLMOcoRSxBG0N/bbwhmbsiBHitr7F5jBTeJLpz
	RloxU9ulzVQnr2LyqnApJs4=
X-Google-Smtp-Source: ABdhPJwT9n87gRZfjTZkAv65ycetQR0s0W6dn6t3CWcICeEPBNBClBirTcxbA1Op1/XiX4efm4raPA==
X-Received: by 2002:a37:8b81:: with SMTP id n123mr514223qkd.242.1611579032278;
        Mon, 25 Jan 2021 04:50:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1c91:: with SMTP id f17ls5011599qtl.9.gmail; Mon, 25 Jan
 2021 04:50:31 -0800 (PST)
X-Received: by 2002:ac8:6f06:: with SMTP id g6mr263814qtv.80.1611579031879;
        Mon, 25 Jan 2021 04:50:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611579031; cv=none;
        d=google.com; s=arc-20160816;
        b=rE1+n6z3Op48COVxT02NlBrDwAjKCfbcfofj0ot0Sm+AnuUEmqMWOaA2tP7Tf4LIyA
         Up/aDgELts5GiRU8QRxr+M5fArgwn6CClis1jug62hU/Evb6GwZ9Ol01K2oin9gs1GIm
         80Wx02LddOzZHaWOM9a7MUyc0PuGOSeHKIJXL+TJvqpBIBOsIx1jtoUwEsDuaFo8LHkw
         AezGkcpuPuNadAWS/3PAOctuZZRqd9iMMdEPtTypWKbkeJkLaAHNbgMl6//7XN2xQedx
         mT/HD9GeevDwpNh1pTrunoR4tuRseFOdWmGwh7KgSFW2PBJ9lu7Q/Iz7InYPweWSBsjb
         yVmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ziEdnq9UfPBRVHwVcHFjPk3RxDk+M28vrocBq/u2R6Q=;
        b=RoPK5QBu6W4eQ349RhqXkW/rqdfvU3o8E/fJOgehND0eGIJmh0KdpMyzH+YnqEdxYz
         eqz+w1qYXClT1LOvifgAvNzm5y+SNpC4ajXUSGsaonl/hK2IlGiee9fMkX4tlIdiM6Q6
         RcMnUbXm0BzfuYmtk8458+sJ9JMFjV/3f4MDaRss1EyMfJqRnS6CE4jeM2D23TSytgMy
         u8THHzsNhmVuodBYn9X2TTFuZqUmGtTfta4PAnq0GDkOIQIifKSxggoCQBltNIem14FX
         BajAIIIjTkmLvkvSdxDAyVYaH6OFHjmbalFb4hR1WbV61059BSct5afM8Y70cOG5VgdO
         S5QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H8ciKPee;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i2si1046296qkg.4.2021.01.25.04.50.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 04:50:31 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D288122242;
	Mon, 25 Jan 2021 12:50:27 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Mike Rapoport <rppt@kernel.org>,
	David Hildenbrand <david@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jann Horn <jannh@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] arm64: kfence: fix header inclusion
Date: Mon, 25 Jan 2021 13:50:20 +0100
Message-Id: <20210125125025.102381-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H8ciKPee;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

Randconfig builds started warning about a missing function declaration
after set_memory_valid() is moved to a new file:

In file included from mm/kfence/core.c:26:
arch/arm64/include/asm/kfence.h:17:2: error: implicit declaration of function 'set_memory_valid' [-Werror,-Wimplicit-function-declaration]

Include the correct header again.

Fixes: 9e18ec3cfabd ("set_memory: allow querying whether set_direct_map_*() is actually enabled")
Fixes: 204555ff8bd6 ("arm64, kfence: enable KFENCE for ARM64")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 arch/arm64/include/asm/kfence.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index d061176d57ea..aa855c6a0ae6 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -8,7 +8,7 @@
 #ifndef __ASM_KFENCE_H
 #define __ASM_KFENCE_H
 
-#include <asm/cacheflush.h>
+#include <asm/set_memory.h>
 
 static inline bool arch_kfence_init_pool(void) { return true; }
 
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125125025.102381-1-arnd%40kernel.org.
