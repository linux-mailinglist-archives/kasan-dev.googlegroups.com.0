Return-Path: <kasan-dev+bncBAABBL7NSH6QKGQEIY4B5PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id BCFDE2A897C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 23:03:28 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id c4sf2354321ioi.16
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 14:03:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604613807; cv=pass;
        d=google.com; s=arc-20160816;
        b=sW7VmJk6i6i/Zjwj1EPiPjwb+7UM7Q2GLPHkqMTEe6AQxYWW3EoAznXny2O03iwTMq
         C3gnY16+Orqdq67YVCiGrOib/lDiLR1cXlhGde4WTVTXK7HikJFTlJU+lGu0Vbjh78En
         uBDX/h9OQ3M/oqM7IwQcPVHLEEOIrtrggO2MlPzeB1CNjN5OUOnvLu+nwKYEaQSU+YcJ
         KqpBYvzwAHIGLfESHyAKSn6qCT3rgceAnoNxzK3/RzDMcSX2Rq5kMVUqJv9UHst+YQ70
         Kd+92Yp/bTHCrU4Ht33mFJilQbbG5LvE5kbrUVLCOlu+3KHVsM0vQkhayRXZEvMWqJGI
         FFCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=sxhJh7ZPyRtbm8sHxI7IDmIJ/OTjA4rQAaYei7e4Ymc=;
        b=shBDej3jlG2g/OKU2wsARuclHUcc2FJqj5Nrijbgofag+RS1Rpuf4tG7Zx1O3OgxJJ
         FplrA8CXU2hWkGsoXMSxI5ehgIVdF/mza2aD6MTqTPfoIuNJJFhLpSweUNu1ntzw/30e
         1I2prOPeV4E516knBOJEPXri7pHVqDq2Ra6cDzRajOJe+fMK8BiftFGxE9EsHoXE1/xC
         d9rn25BGdVhu7L0Fo7NKxCSt0Q6kmnjW59ufbsMUfceeom6GeR3QgWQIjuPCfeUjfdJ9
         EV6HayatGx3iDN79DZ/T2fSLfT7VNfyA8/dtNdD/Xa/8baJS0/LJHtrfDSlFl3mbkgj2
         eu9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vcVqjhH5;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sxhJh7ZPyRtbm8sHxI7IDmIJ/OTjA4rQAaYei7e4Ymc=;
        b=f2ey4ZFK0eOjSq55JTcAeiLLTunkuGKREDMBa98A4nIh/9mkg0X9zXP8JQ970uIKcv
         kotyokrahpqe9Io/xTBrO+JPLGT8Nk96/dFm0ERGS5pNEhLsz1KJbSBXJbwm2F1ZQQWV
         Y1r3v6MmYrx6/BQERVIF045bFBqG1HBvKPkTy1ip9GSzZsWGoDHpX4s8sCiQdtGdLeC0
         4IXGoaYnORAWmAviGIqwOcvU2Lew024AKkkxwx5qY7BaFxwd+keF8/XjbTI4dx/CZKa1
         VSnpbyonD8pBLOj+TMezzGmWLEEyrbzXwl61qb3KTcNA9GDCBJn9506xKXSYb1P5pUkz
         otBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sxhJh7ZPyRtbm8sHxI7IDmIJ/OTjA4rQAaYei7e4Ymc=;
        b=H8gRgEuLB9pAyzApA53LICMbQ9d7yPHDJ4HeOAOgxkXsmQRL4aUEpoRLCuGrTnCATA
         TLCbviKEvzJzku7bxgyz5ncmKbFcO6aVeLuLppXEtTxxG18cTQsdovHx23WXMSbelc3Q
         eCPHAGKvKoQ38xCeS4kD1vnK7RLcbwSKk07PlW5oWTsdd/1jeU38+RsYMhQWiuv5lOpW
         A34ofViF7JPSWjznGmZjSgnAGEkWv4aEgn2KAoaFAQavDTpHIQ8wH4+L3BRouudrzQsZ
         Wx4ccOwlEOi87mcLi0Iv9HQbRE3SGh+5ArqMuBW4ZpgZJBr1GwK0DClUQ4EQh1xcume8
         p7lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530yDt8BPObgJyOIrr8BN3EQF7p/VDU8XltBnYHyO00TpueicYey
	+nsPHPQE5C7mKxRWoBeTYSE=
X-Google-Smtp-Source: ABdhPJySSdAPed/TtDq5CAOks4ZM5JB9j6jIxzfNoOL46xE2Z0GWp/hwOmCzjf52gMIquXMaDOl/uA==
X-Received: by 2002:a02:cbde:: with SMTP id u30mr4033709jaq.69.1604613807424;
        Thu, 05 Nov 2020 14:03:27 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:50c:: with SMTP id d12ls621531ils.10.gmail; Thu, 05
 Nov 2020 14:03:27 -0800 (PST)
X-Received: by 2002:a92:9a04:: with SMTP id t4mr3778790ili.192.1604613807171;
        Thu, 05 Nov 2020 14:03:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604613807; cv=none;
        d=google.com; s=arc-20160816;
        b=y2cTqOPZ8soNxt+gPIwKGf/m3NXuiCJXif7knLM7Ih64PUCV9x5ZeHDPpIBvo0QUdG
         14zlarGQycYhSF+KRAZzLwzLWw4SIK31Q3QNQj/0kHzwSTeUcie75/Q42iA5ONH9gMwY
         83jEy8MsPVWXVRXDfgchkSzjxijkNiwRXbMQpSiPsqWTY61qDU7m7JVMyVC8ZG78KpPv
         hW99vgPC+AJxgSBg77hHIQDPLfFKE9UsNPBGfxhtUsUdv17n8/6Dxlpvv8cexlmu+hHq
         2R/NTY9yfbuM51bYqsqLXFO4T8JbmRbCN31YnIFjLXtQ2iBVM95c6WdLdIQjuiAd16gz
         7c6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=+fdC3YxmF8QklniKJ7PP+WhpGmqTVv1gNX71PvwLGTc=;
        b=JLHrLEnjsON1Cm6sBbsJ7bpAKLO7BbryLgkK+jAGJydP1IXh8k/3Bd0jEo0vLEFdaq
         3CLtLD+QaRn+voSaidZ1Yh38lZVsyyTtnTjLNXOIoiKdybshZrp6z2FTwwbk0jRwy5AZ
         qblVqvO+JQEhj02l30Q/ePKflC45uOSDm6lds0C80EXM9yq2FVY/xbU3PX7LjZkwL+XO
         oThE8oynzrMS1OcOjUSughowPeeeH7QpJ9H9pNImipumqS0MVMGGKxQZ5vj4s9i7YiLX
         H0PaVQOJVtHVEnfx6JDQwtS5cQm5jq4pQsr1S9J9PTnh9H+/YpnzmQ7PJIXMsq7x4B6b
         wR6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vcVqjhH5;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s11si194925iot.1.2020.11.05.14.03.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 14:03:27 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 02F4D21D46;
	Thu,  5 Nov 2020 22:03:25 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 3/3] kcsan: Fix encoding masks and regain address bit
Date: Thu,  5 Nov 2020 14:03:24 -0800
Message-Id: <20201105220324.15808-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20201105220302.GA15733@paulmck-ThinkPad-P72>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=vcVqjhH5;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

The watchpoint encoding masks for size and address were off-by-one bit
each, with the size mask using 1 unnecessary bit and the address mask
missing 1 bit. However, due to the way the size is shifted into the
encoded watchpoint, we were effectively wasting and never using the
extra bit.

For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
bit, 14 bits for the size bits, and then 49 bits left for the address.
Prior to this fix we would end up with this usage:

	[ write<1> | size<14> | wasted<1> | address<48> ]

Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
size and address respectively. The added static_assert()s verify that
the masks are as expected. With the fixed version, we get the expected
usage:

	[ write<1> | size<14> |             address<49> ]

Functionally no change is expected, since that extra address bit is
insignificant for enabled architectures.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/encoding.h | 14 ++++++--------
 1 file changed, 6 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 4f73db6..b50bda9 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -37,14 +37,12 @@
  */
 #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
 
-/*
- * Masks to set/retrieve the encoded data.
- */
-#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
-#define WATCHPOINT_SIZE_MASK                                                   \
-	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
-#define WATCHPOINT_ADDR_MASK                                                   \
-	GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
+/* Bitmasks for the encoded watchpoint access information. */
+#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
+#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
+#define WATCHPOINT_ADDR_MASK	GENMASK(BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS, 0)
+static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
+static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105220324.15808-3-paulmck%40kernel.org.
