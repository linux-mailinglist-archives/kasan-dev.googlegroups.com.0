Return-Path: <kasan-dev+bncBCCMH5WKTMGRBH63UGUAMGQERFXXWPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F01C7A4C60
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 17:32:48 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-402cd372b8bsf36439225e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 08:32:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695051168; cv=pass;
        d=google.com; s=arc-20160816;
        b=ROoOsqG7WnYYsmrGaL+7eEXI/KvqGpJqo5h9zYAlTuCDEsgkyrseavcIj8DZeKiqyU
         AvFdcmhIb+o8cSu+xCRkPaD0d/6eEAqgjsHjpix54OGF2H2aCll3vs8FNcK21h9vdzR5
         jCcXQ08UXnGm4FB0TsPYTrtIMpamYdAnkMXYFsYkxxu5d/9FFMnyLApE3QhN7/aJ6NZI
         yjRvsmVEnGGux8UPiybFAX/dZEqKmgRBAtFcHs5M2FFAYyWoeWxvNBlQu0YRPDvOTa1s
         Jiw5BWIO2St2akngvdwmc6JyuWwPeAxInf78KPuN0a4Jj+5Y/1ehNf3W+KkoTHfJuQQc
         stcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=58jwusAPcDQNHbSg3MOuNUCuWBOWPfmHAXFLcRE/aoU=;
        fh=vyR805lIGMlJ9t/xQlmYYFFqFR6KUl8CN56S682SHGU=;
        b=CD0Fit2uC6+rmoM44a6oVJauEu9z783vldis/kk215cwMDM3EVwkmZbO2hi0GKf4if
         6mKwDydMny/RMWlL1Mc3m7G/ymPhTkWLytUUnjbIr78bcSRltiIVzecgzVdcsgv+47Ug
         J9EbzqOJvqa1jUy4sZO2jPBgkZOMrUEJ79jrSMvxgTVxJT6FhcFvlixgbDaJrWvFtI8Z
         t+xBSMl5oe1REWPTUYdujfAGPZRURIZq1Th/nz+1Vtwni9CPkLne0C3OamiwVVEvaBQz
         y5Hhjg/ixZZetvxgvW2RkVHIwxUGuAfSOed0TrmpiIogtsWgtW5H5auUz7oxxxGwHB8b
         zqEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=38BEnX4R;
       spf=pass (google.com: domain of 3nw0izqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nW0IZQYKCcguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695051168; x=1695655968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=58jwusAPcDQNHbSg3MOuNUCuWBOWPfmHAXFLcRE/aoU=;
        b=sxnhQ02oNVac1avA7tdMhoT64OASeIv2IqOoFM5X44CV7y/VT5mo5r+kSBZxz+DexD
         WjZ4gIMmZ2Yu/fgQ/uKnA1JTJQ/H61NS0l0uxIsRBfU+A3WEVDwhEYgdr5Amsljzb/mT
         cfkdrD2Fkpp+H29tTBfwEommJodwN10wzvmQqS/NxAKtwPEkbzmXp+z+bS27FHdAnIFg
         KVK+auwVaeV/uNLCRiYcF+mEmvpvSr2qi/VnCh6c20DAzL7AfB+GK47COhuvG/rRFzl0
         KzUsXI4SfAlfLyapr5x2fgIGxdEdVdxc/PqMNYz0GxhM21TKaRMmUiO1ttoo6gIG0nof
         ca4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695051168; x=1695655968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=58jwusAPcDQNHbSg3MOuNUCuWBOWPfmHAXFLcRE/aoU=;
        b=iIct9iWSSWHmwo2fDbogTbNaOx67DtafAy3exIO+AGZzh9tSbGN7mrAMTtyja7FnDu
         ++OuFL3l0/h6klGYEvay99K4AdIH6SEVj65iWkxGN/21p6dt4A1cDvJavvblhPE17fve
         wLVOf2OITHvuHWAXMGQWUVSD5120gP7bmrESbp7YqbGYJjvfAE6aouoZSoDTGYspg2AT
         otDno8LiPsocVv888b8JvCX9hIPMI9fR29Rg/BzaL0PrCtKK/rGoEnWBnFE/Cva2HXey
         JnqaIAMGz4o7uE3TkYChiYm6psIAuLef8+sS9QANsEzEDZuXBLH1X2jmceyLeCchNoPG
         0zSA==
X-Gm-Message-State: AOJu0Yx2BWog9mdgQWgJw8KfJvbeRfQYZeL8iJ9gNbL7y1rTn1RlH15Y
	ihzsHJoxkHiF+TPM5L0UIPWFtQ==
X-Google-Smtp-Source: AGHT+IEFcKYF9oXl2Fq19qNulc5lTGhX1hs0hKcWONMUz17w9HCNJyFwsnCQ1gsyEwL2pvm3fuBkJQ==
X-Received: by 2002:a1c:ed08:0:b0:401:23fc:1f92 with SMTP id l8-20020a1ced08000000b0040123fc1f92mr8295259wmh.25.1695051167397;
        Mon, 18 Sep 2023 08:32:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c09:b0:405:90d:47da with SMTP id
 fm9-20020a05600c0c0900b00405090d47dals745763wmb.0.-pod-prod-02-eu; Mon, 18
 Sep 2023 08:32:45 -0700 (PDT)
X-Received: by 2002:a7b:cbcf:0:b0:401:cf0d:25cd with SMTP id n15-20020a7bcbcf000000b00401cf0d25cdmr7845106wmi.22.1695051165813;
        Mon, 18 Sep 2023 08:32:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695051165; cv=none;
        d=google.com; s=arc-20160816;
        b=lfmpDC6opWDROPjJgrYWHDjFsU69d3a8YVkCChVYx492bmNqfm3eUeGtkvfa8WdQnh
         4e33x+Qbt5M3oG0X6DXHq46wC2KR1JIeHiju6cYkvxDD6tvjPpKECbOPdE6edQgtrMaC
         +jg6Ve7Ct4FKl+jsEE7cbTwb3fF4TSu4sjm2Dw4mbBT+xx56wZ30TKl0XOAH/qfyd9Qm
         T77FX00cNi09HemfaZ7xNQ4eeq6MNKmmQKTYPVgsZwy+ylhCa6xZcxnvyByAHW8jA7qB
         hwIu+a0FIycyn+y8i8AL0KhPPpqDGvoxNFF6tWK1OaqzGEG1JeSzvtF4tidQhjEGNW3w
         nQLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=jIAk2l8FHhw3IMNFzU025ohtjmLkXGN9K/jxVvhfHgc=;
        fh=vyR805lIGMlJ9t/xQlmYYFFqFR6KUl8CN56S682SHGU=;
        b=M/vt+o9Y0/nXgL+vCum2N5X+5FuWAFAsnoyUUsBfaICuC+Werz1tI6mZP3bel7NseU
         lWXnUdp96Sg7Dp8hsQZSI3aBS77jXVPLYCtdPVSl3pi8uvyAgtL+bnQubCubcMzXXe13
         xKdJE2m4bsxo68BwGFmetkivrrl8n7/V6iom/V27PTR4KcgLtrxvBiKWpT0qnmBHfzgK
         U3G7PZiNSPEMMJLwszkfVHcerDCFETgiPlFPxnq8dUXUNvDXePs7SZSsQ6br/Q44ZMLS
         Izui1daRcqGi7WJCRnzdrd0wINh+pfVuIbDSJuG/fzX/1X/y2wnEOOYHcWxUrI9ORRbn
         ddDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=38BEnX4R;
       spf=pass (google.com: domain of 3nw0izqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nW0IZQYKCcguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id o33-20020a05600c512100b00401df7502b6si883911wms.1.2023.09.18.08.32.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Sep 2023 08:32:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nw0izqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3200597bfc5so1165171f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Sep 2023 08:32:45 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:dffe:ac34:a8e2:f442])
 (user=glider job=sendgmr) by 2002:a5d:4b4f:0:b0:317:f046:25e6 with SMTP id
 w15-20020a5d4b4f000000b00317f04625e6mr101610wrs.2.1695051165285; Mon, 18 Sep
 2023 08:32:45 -0700 (PDT)
Date: Mon, 18 Sep 2023 17:32:41 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.42.0.459.ge4e396fd5e-goog
Message-ID: <20230918153241.2942764-1-glider@google.com>
Subject: [PATCH v1] mm: make __GFP_BITS_SHIFT independent of CONFIG_LOCKDEP
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, mingo@kernel.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=38BEnX4R;       spf=pass
 (google.com: domain of 3nw0izqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nW0IZQYKCcguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

The list of GFP flags is sparse already (see 0x200u and flags defined
based on CONFIG_KASAN_HW_TAGS), so it makes little sense to save one
bit at the end of it if CONFIG_LOCKDEP is undefined.

The dependence of __GFP_BITS_SHIFT on CONFIG_LOCKDEP also does not let us
add new flags after ___GFP_NOLOCKDEP.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

An alternative to this patch would be putting all ___GFP_ flags into
enum, so that we they occupy as few bits as possible.
My understanding is that this is doable, because tools/perf/builtin-kmem.c
does not depend on the flag values, but maybe I am missing something?
---
 include/linux/gfp_types.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 6583a58670c57..bb8d3b31e3b6d 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -249,7 +249,7 @@ typedef unsigned int __bitwise gfp_t;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (27)
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
-- 
2.42.0.459.ge4e396fd5e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230918153241.2942764-1-glider%40google.com.
