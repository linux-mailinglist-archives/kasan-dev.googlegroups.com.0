Return-Path: <kasan-dev+bncBDTZTRGMXIFBBOORRL7QKGQETIBXINQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ACF62E11CA
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Dec 2020 03:17:31 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id x9sf3536878pgq.4
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Dec 2020 18:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608689849; cv=pass;
        d=google.com; s=arc-20160816;
        b=MmmPZcrK5x7xY09Wv+A1ittxDPqN6KUrjGyEJwggCCHJuKvNr0CGtfelMHzOay9a7u
         oqGDCPG297Ec1+d1rE/8gTrfT+ZdRYPyqmQdsTh14SWkZSwjYWqFLxJ7XF0uQ3yUnBMF
         Vj87dcPaE6np7HAofi+0pLXDTnFKxCyt4bLzx0IgiAVlRWLHp/Zf8XUzIwILctnLG+74
         qXV7mdP2Kq9WF3JeI84Z2drbMvj/ynHGyb55EFKHY2VI3+Wby9QZbSkjmCzEj3BFmuQy
         kgqjVlJZhfNLv8T9EGXMI+oWy5sf1LmEiNs8i033iID9iEr2lFxgGdcQQQb8e3IhV0ar
         3hkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oXoAQa+BFg+eDn1fh6GLWFclffQtUxepMH9PfzJysQ4=;
        b=qkSAJ8YqeOf0iE+om0nbVSsxgvjvVLBY4ckTgHpKE6iFL7hDK+qKPZ9TzqhBB4SVQZ
         jgtO08F2fD93T8Zf1xyLKVWTkkMILDpfZuYbr8Ncn77ucI0yRx0gnyWyuyyfb2lmKelF
         JBFBWSkERQluIOviOM2ze+l3C/2HuIfIeSHVVcBJkj+HCFkdrk4aJe0r1ULNVto4Lfb1
         QgslpVVxO/aVMC65GJ2DG5ny2t6LfnfqRITs23DJ1JwqG8B6B2l419i5OwXfYJnP93BQ
         VG0SZc4I4c6viFERAHYQ7NpcgCJ6eJljJKrZ7cqKf3dcRE0We2kj7Rn7x5XnAjAc9d+C
         ZUMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NRLtPrF9;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oXoAQa+BFg+eDn1fh6GLWFclffQtUxepMH9PfzJysQ4=;
        b=PjJUeQMfXel5m8YrqDTh+i8B9JL1QCqNw2el9CxbFfFTdcCizS9v0zBlWRNHfBWI/e
         QMpMSMFrrm29GarxqMLPZHMg4zsorEsYkv/PbiTcgM7V0LQmV2PsZ9rZZS7Ks/xIeh9g
         gNtRySp6hdIiusruKYgAYd8ggQrzWeGJAOLjxvmJESunEDjR1lNGCwrAqWWWzBrCafsH
         g0fWtAB6/rmFUmSFFYk7YP4DYOGPxTinq64W3Io/cGNimx85xvVTUDr2+L+1FUDdPNj1
         1vq/VrAMRx6dObnZE6ImO68IqULBqwcGgD3/PbPwkZVvgdVVNBf/fUB4hzNL6Jx7lI41
         CYYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oXoAQa+BFg+eDn1fh6GLWFclffQtUxepMH9PfzJysQ4=;
        b=OuiKDDzIxNDDB3JF9bLA3e2j76PX9Fn9swIMAzHZkhFu/7ObxSJNNhDX73vj19qtZe
         SfAKn0Au1XHdMp8SAjZvMBTrNX1vcQl1p5w9SBrc8WMpT/l74Z+yHcA7J1bOM51kOiXx
         34XZu1nRHJUaWLciRDl7TGOBrUCzvM4BbNlt71HQmC5MNifa7I4Jk+IDV+44c0bBfLSE
         EwL/YEYl7+lXr8hE5NKp0pPk5oom2OQgsbKWfNG6S6JbZuClSFCSe7FbHTX8o8lPJyEb
         K2lGwxh9H7rQaicwqXuYyc9bIOy9NS96PbgJkJiQS7ARAOzKJjtIv9FP4hChPjJZ7AVC
         brIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nSQABllj45wXbGcxYFWWnKbxTejh9EZm9nEHnbHMYFDK5Hqht
	O6oDBe5KRvmJJwkV72tZDW0=
X-Google-Smtp-Source: ABdhPJyNncvIMzWCE10BGoy/INQM+SUpVTPKV5D/S9pi845JpuJ7gVpLWeWgFKp2oI31lZoQclTMaA==
X-Received: by 2002:a17:90a:a45:: with SMTP id o63mr24803353pjo.146.1608689849500;
        Tue, 22 Dec 2020 18:17:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a609:: with SMTP id u9ls9643711plq.7.gmail; Tue, 22
 Dec 2020 18:17:29 -0800 (PST)
X-Received: by 2002:a17:902:76c2:b029:dc:1aa4:28f1 with SMTP id j2-20020a17090276c2b02900dc1aa428f1mr23471972plt.79.1608689848967;
        Tue, 22 Dec 2020 18:17:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608689848; cv=none;
        d=google.com; s=arc-20160816;
        b=X8eKvjzUNmMmVCLacIsIJJD0sdt0F75FZLK5ACKZS59mxMRqeRmFphlVVmNcIrO8j9
         /hGfmFAhZ8/ODWQNdE4iMVw8vecZk12js9eY/T+PIqobNSUTKdM57i8VYMcPcdfqUtCj
         HSbCB1InJm/id3N3PoNsb/KXHc2Ai0rxxkEVzPxEbiKXI+WYXIQUG4l+HJTCHV1noyB7
         EFJI4HK4Cz8+ePyhgyFpzwL0bdev9NNdTFpTEYAWlqjnGO/CZEO78/TmIa/M2/zkLjLb
         xWq/b/ZeKi8BgLJK5N0HhTVrjfKOIhouWZW1Qzunpuim4CQ+vg4v44cTzi7J2K2n1XkZ
         SYDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mLKX3RfffljeRfp1nQXt/Q/GhumADW9ppA/oUuGYHqs=;
        b=MAoU+/l1WVryWU3J8JqXI6PXFERk7D6gg59zQ1/zeeI9OWfYqU5zWWUDAgE+VMfv1Y
         6axXEAuzyLHCguUv6cAYTGgUU0iQub45lVstalbWfSnS6VW09qVjgPfjL1lD1TT3PKFt
         e86eAZATSEvpur0hfLcuecOivPtQ6ISaAU2OfcRyVvxsI0T18p5cFmh0YtDZygDDt+SC
         SeeUFnuRMsI9JwPocDqTFA0LyuDuPf05l9LmR4RqJHLyP43Od3XcAJOLeSUH57sveGKm
         Dp7dl4MQrIM6jEsyEtDvI9YJiBMGlFoeUz6ODBOy2K+XQzL1B+evrkR+MdRpCBYEgh4q
         QEBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NRLtPrF9;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q15si1594178pfs.1.2020.12.22.18.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Dec 2020 18:17:28 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EAB61235FC;
	Wed, 23 Dec 2020 02:17:27 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.10 048/217] kcsan: Fix encoding masks and regain address bit
Date: Tue, 22 Dec 2020 21:13:37 -0500
Message-Id: <20201223021626.2790791-48-sashal@kernel.org>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20201223021626.2790791-1-sashal@kernel.org>
References: <20201223021626.2790791-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NRLtPrF9;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
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

[ Upstream commit 1d094cefc37e5ed4dec44a41841c8628f6b548a2 ]

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

Acked-by: Boqun Feng <boqun.feng@gmail.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/kcsan/encoding.h | 14 ++++++--------
 1 file changed, 6 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 1a6db2f797ac4..1a9393f789568 100644
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
+#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)
+#define WATCHPOINT_ADDR_MASK	GENMASK(WATCHPOINT_ADDR_BITS-1, 0)
+static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
+static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201223021626.2790791-48-sashal%40kernel.org.
