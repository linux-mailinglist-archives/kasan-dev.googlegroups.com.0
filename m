Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQ5A5KAAMGQESC7M34A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3853C30D95C
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:00:05 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id p6sf530486pgj.11
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:00:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612353604; cv=pass;
        d=google.com; s=arc-20160816;
        b=FDRsgC4me5Vmhw3qr/Ac6TQ1+Y3tDUEJ2JWCFGpH6B1dkoKJpd8PW/Cq69SDEL2X/p
         4lztO5PKpx8aR+UVym8Ap8cBH/FqRsuLkGpRwqcP8LDp2dtLpV0jBdy7LBC/8aK2xbHN
         /cMhqZ5kuPjIy81QiAm/BWCm9UD68I2ED+pqgGbT2Bt/DRcjWhYR3TjtyiZa4bkdZbfX
         kqPHZp8pu9tgZ1VO2vggJ23E9qEO/jwHmdorY+vUDGZDt2BppCnKM4ZZJHX5LqPTaOU3
         pbywWjAEMU5OfHDbDEpD9y06aeTpeGgDmqFrW/KlwrwL+wpdEtfU9pTFaei6K0jC/R32
         M/WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bzMJGnjGS1cyCROs39vwuUyHxhNMxlpZLnzvnOLPIfw=;
        b=m9seqJMqAYSdR6wr221lkLo7msMIxMU6avhYxMW1PDrLuZBgcmaW4IZxaGhDPzGAE/
         Tad0tzQcyXCSxiEFA6Qz72SBM2650Z3FI1t7RjhwpbhW0quAWUAxvCzmUOkQbcF/2Kdm
         BT3EzZHwmy4jlNtQrzaslJgfpyDbvdu4rHgTGy2mWAYsv+yS8ydyeeepIMpDs7qe/TPk
         I7jIYwuCknIIu+FGVnuwtfMndxO7P7cnvDjmZwAOuTQ2LK3UCz+rVXSK01dZQo0mv4i+
         sqQFWqjqpyoT10Keqqz1+5K7DizIOfaFMZWqdz+S9882Ixzk1TeJeT+rAdwBWqWYv11B
         Ec+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HdaU2Ykx;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bzMJGnjGS1cyCROs39vwuUyHxhNMxlpZLnzvnOLPIfw=;
        b=MTVB7YdoHmOXNyj2cuSggUcA5Gs8wIPUTaTFcg/r3ubRNldK1cmhEs0xwfd/d1WsI/
         GRDWfEYXLpFROSVXrPi/BZ4qrLuEQ0F0kr3+IppxQKExqjx557zWq72cYaIPv47zIxaW
         ZAhiNbZ1BlIA49+h1wiIuzkIipF65Istl3bsd9W+NHCx2W+DdLrugJiaZ75drvkqO5za
         TPKiKFdqgL75337EK+NKvlt+VgqZRiY5oRQiu366WVFp/iBHHpi/M9ItWli3vqMjTnEe
         LocbHo9El6MTXJmH2hpsuBGJgfuh1yzjIOihk+4d65jVitBT5uOJ0OZtE/+47Jur93Yx
         vfPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bzMJGnjGS1cyCROs39vwuUyHxhNMxlpZLnzvnOLPIfw=;
        b=UdUv0VD6dFtApgfmPzQv5eXgdeOCySvp76CZGBoV8mkzsNT5Eyx1O9B55q8OKH5Ame
         kn4WpHmT56dvk9zB3aS8ogYTMuy36bMp2Up/IhlytKpXl88MP1LCScaEEtmxEvLjsxSX
         ASpjAbTBhzD7D9Oh+5+jvnMt3E8x5cPXqPQ/CSLLUaJ63jh2wfmrRkSJfMICs1Jc/Yr/
         CQ8PojfD9NpN7Qlu4ULlwRq72bZAl45j01trVxym1ArqIv1zzoomqCZVT2OAo8oAZjtg
         qn4h92XuLY+G8quIBEGdRUv1HlOpPpIstxY4J4zr4J8Cx0z0FB6MA4q/DOdQ6Tpj0asE
         iSDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Y/dn4wm69sBlSEqCmP+q1ZgTobGW0m2gErli02HtSdK3DV7Mu
	3iVO4VwxVTyu7EGvud69h9k=
X-Google-Smtp-Source: ABdhPJzbWxTh/cQCNAgDOQaHIjuJ1KMKz8B4Z5xUvUCNVHuGlqUj+Mg5o1ymSEAzV6A9LPZFEDGl+A==
X-Received: by 2002:a05:6a00:1a08:b029:1cd:404e:a70c with SMTP id g8-20020a056a001a08b02901cd404ea70cmr2890249pfv.33.1612353603930;
        Wed, 03 Feb 2021 04:00:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8d53:: with SMTP id s19ls845553pfe.7.gmail; Wed, 03 Feb
 2021 04:00:03 -0800 (PST)
X-Received: by 2002:a63:1f10:: with SMTP id f16mr3187358pgf.111.1612353603242;
        Wed, 03 Feb 2021 04:00:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612353603; cv=none;
        d=google.com; s=arc-20160816;
        b=X/ki/PpsKZWK4DmmbOJnGKVos6tq9Pqb1ucy1vRo2H+T58qV94z+xGCmq0+qydvwUw
         7Ymo5wAtP/kiHRdUnpc2OnpLuPAZxajGxO02QyLscQg27gKfoDhMm9goYEwlfkbMx+SL
         d93/QKWiUtRfEuXlIpZZDQknUCPd2nQkuP313d5MGfC/JguzlYDBPIEEdYS07KA0u2+t
         M8nwb1qxKOmB60b96Gbm5ffpkjZd+om1K66qreuK882IHTJKakRLiotKjEDmvpsdiSjz
         1j3aSSgx/yeHPAlUvCjLL4/Zb21yenOe87arnzbFhCYuKe3BMyJ2VX3qys1j/7mx8C5S
         JRhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zyIIbH1s6hkgFOvACSv5XJQgDv/VgHDX59KWA+Xvn8M=;
        b=tWRsA6sF6nx87dQY2vizEClNteGcCUws9edyj36BDoF4HNLaT6xZHlWysvXGQtf05Q
         qL400DM6JUlifKdph6r/HI/UgNVAC+Nvb7OAG8q+IplvD0I/c/wKm/Fq2B7AIpOWVf9H
         8i3oaGWmyFaQcAV+K5cDbclWe3gLzBNsvUnm0MM/8lMNVLtMF64L9E/zpkZW615RdXIE
         CwDExlVkE0EIdq5+cYZeWk3HCK3IZbGlx8GGjjbPgCnPDXhy1Oix2L1a7sxAi7N940ka
         5ieSIO+h3LT3J0wLueRg/JBgbhadORst5CPnLJS2GqT0aM7VhsTivFtlG7muGoXImC6i
         N5xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HdaU2Ykx;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id p10si84292plq.0.2021.02.03.04.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:00:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id cl8so2965146pjb.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 04:00:03 -0800 (PST)
X-Received: by 2002:a17:90b:198d:: with SMTP id mv13mr2893257pjb.68.1612353602855;
        Wed, 03 Feb 2021 04:00:02 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id b65sm2750037pga.54.2021.02.03.04.00.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 04:00:02 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [PATCH v10 2/6] kasan: allow architectures to provide an outline readiness check
Date: Wed,  3 Feb 2021 22:59:42 +1100
Message-Id: <20210203115946.663273-3-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210203115946.663273-1-dja@axtens.net>
References: <20210203115946.663273-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HdaU2Ykx;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1035 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Allow architectures to define a kasan_arch_is_ready() hook that bails
out of any function that's about to touch the shadow unless the arch
says that it is ready for the memory to be accessed. This is fairly
uninvasive and should have a negligible performance penalty.

This will only work in outline mode, so an arch must specify
ARCH_DISABLE_KASAN_INLINE if it requires this.

Cc: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

I discuss the justfication for this later in the series. Also,
both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
---
 include/linux/kasan.h | 4 ++++
 mm/kasan/common.c     | 4 ++++
 mm/kasan/generic.c    | 3 +++
 mm/kasan/shadow.c     | 4 ++++
 4 files changed, 15 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb862d1f0e15..d314c0fa5804 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -23,6 +23,10 @@ struct kunit_kasan_expectation {
 
 #endif
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#endif
+
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a390fae9d64b..871ceefd723d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -348,6 +348,10 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
+	/* We can't read the shadow byte if the arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return false;
+
 	if (!kasan_byte_accessible(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 2e55e0f82f39..718c171584e3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index de6b3f074742..0aafc2d5138f 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -85,6 +85,10 @@ void kasan_poison(const void *address, size_t size, u8 value)
 	address = kasan_reset_tag(address);
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
 		return;
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203115946.663273-3-dja%40axtens.net.
