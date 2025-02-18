Return-Path: <kasan-dev+bncBCKLNNXAXYFBB2E62G6QMGQEYKQE6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA2C4A396A9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 10:14:18 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-3092a2c179asf12436251fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 01:14:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739870057; cv=pass;
        d=google.com; s=arc-20240605;
        b=djpUGCukm2JG0ACxMAUlgYqVxoXimQ1RDY3c/8p4CNrAQcsQAyd0MleKHOfKgih5ma
         evZr9Dng8Y2z64nWGuK3t8zsbt61X19QVlPdLEsBjpXMWuygyCSsCKcClGeG7zIJV9H6
         9S4c2CFdinrLUD4rVAUtnr/VW1uVyIrRV5nRWQg0WDcslTlEtHUVcNoV1/Lf3HgV6tCx
         rKKqItFKUJ4xakQtrbp1W1gYd3WgHCeHKnOnx/zQK/5TEhksVYdKiQxxqhV6JqT48iQ/
         IFwGqK3LBqLt46MOYwSb7SPyx2sAGTnqZrlk3HAY7tZJeCi5AwLKybQuBNr5g7LO6Q6q
         75JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=n7bHTH/crpHxNBudW7ZpxfqOeO3a2Dt750KfHpwJows=;
        fh=/beDg6zVYBRY8vYghsefx7u3VqQD0zFn0oQXDZq33sk=;
        b=BWUAHRkFjO7vrF1DxpE0se0ukVGTYnjR/OAQ57gh7uvK7cwGaEo/15zhZViuNmHeLh
         G0zZxvRYMMWTFoVVMHD1hKKIDsxyDjG5F7zsRyL5YYHlO/7dWgt0KQ0R4b+cj8NUnk8k
         LzPJiQ5ThSCidACD1fN6EKiCaJOm/8JjN8nds0NqFMGFpg0lwCwTWpdkD7iXlaYvSmSG
         p7U6aN3/C/2rOTmuIfIfrhtjHQucUJSW+YyTwbZtlOvW5odcGdf2n+4CGwfgpJnaBOXY
         5mDySSrUAphZI1HCKDwN/dXlVHOkxNS4S6Jmc9CR2StUJQ+mJybA1dSWURdb4x3IhhNK
         /3vQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=df2vx1Jk;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739870057; x=1740474857; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=n7bHTH/crpHxNBudW7ZpxfqOeO3a2Dt750KfHpwJows=;
        b=deN8ssCRs1/0JxfMPGGfk+9dDvtiIMyKMmsDMtfoPUIPRqMiNcOn9IbMYl3G22BjN8
         XwjV0cvjIXqm0oTt0yZ8ZWjW2BELCbbl6QQpItBB59ZtOmMoHj+ie97sN+TXZleuuRfa
         S+Nl1cOUbyJksxlWkZlXx13MfAEG4T2s9ZmBsDhdhWfb9wKP6/+fYJNOoX8zl3/Gy9l3
         uVlCvMPesZDnXHx3CJ5hOPhSK7dHiJcEO/kL9dsRvldxykbRmFhJjF0+xHfx6TOOQmKE
         HNXgq9XVQ9GheuXPLc0l+jVnQLv4DJRSU56BFvM+58MpY+IEGE9eBAxPDLKtvKIb3J2n
         LyOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739870057; x=1740474857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=n7bHTH/crpHxNBudW7ZpxfqOeO3a2Dt750KfHpwJows=;
        b=C5NtHo9XfxJummKYGRcVJjTnxwvQKEsQ77/nFY1t6rzaWHTZPtB3Y6UyTMQDXvjIEf
         Wm2iGoBHeYREdlh/HH5ueIcnjSM1lmb+LHbAm8KRaFjaJU0W9CxB8rmM5G/S+yeH/Ydm
         EjHvIA88NYjwcUX+0z9VflXd4yCnvku7csdwDxyAu0ggXY2qapvY8AUdaoYvOHSBGjgu
         9RzMy+n/QOPLRpQOi0HkFgi1GJEOAIpAEuEwBq8tr7uVtHz2N+XjIyvuKOArgSJvZjwy
         KfLJNhqJoB2kKK1vhBLtaEfgrrzk1V5nQSUVyZ3pCWWAhkhOL3hp6Kxi2TPEgsfJso+M
         YVZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIEWZTmkU0nl87IaUJliA7gadp7DMhONpxfPMp10MEGtiny1OFy8VM66Gg+fYiLM6YTkvedw==@lfdr.de
X-Gm-Message-State: AOJu0YzW3O+HiZIeC3JtPXDtE08A9Ljn23qIJTi8YFBlDbUoCOAY82gu
	drldztkYOdjJn1WB0xPubyYzI4pXsbspG/OEUtMpS1W4hIjtzeSb
X-Google-Smtp-Source: AGHT+IFQRE3LxJF4R+9mEWSbYAN8dZfoxNJVEon9q1C0eD5FHIODDw+jVH5wNZXqJi4PrYRNbjvBjw==
X-Received: by 2002:a2e:7412:0:b0:309:24c1:73e1 with SMTP id 38308e7fff4ca-30927a483f9mr30918961fa.12.1739870057040;
        Tue, 18 Feb 2025 01:14:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE2rqqQZiQ4fn7ydyfw8ycl+hKz5jS9ndqC30v+hiSL4Q==
Received: by 2002:a05:651c:19a8:b0:30a:3024:5be6 with SMTP id
 38308e7fff4ca-30a30245f94ls750631fa.0.-pod-prod-07-eu; Tue, 18 Feb 2025
 01:14:14 -0800 (PST)
X-Received: by 2002:a2e:805a:0:b0:308:f5f0:c436 with SMTP id 38308e7fff4ca-30927a2dedfmr39056131fa.4.1739870054099;
        Tue, 18 Feb 2025 01:14:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739870054; cv=none;
        d=google.com; s=arc-20240605;
        b=DTf3iEyaknQ/cWJFFaTtAIW+xl1KRKPBX8dFoYhNfjvGHCEbRaz9YSMgIVSz8VZ3bz
         UPDkXt5UzaQdBZzdTR4lBA4SvK7w6pjWdQqeBgc+993Hyu7+z8tUO9B221NpyEnCcEaG
         5/B80+39SZcEGV5Q1Pe3wLmnzCuzjBOFsszeEjmXxGLH8SbH8odKpPXGhwTLhXfSkCUA
         N/0SFMTNS3suzxM6nOB59ser+63RV07pJw/7xDk7t24TVy/kSXJ9+3vB6llI2iLA/lwl
         oab6Xt1Ww0/DlkCZplha6PzweoGBTmUA9eS1cuoWKJ2fDrUPCjB1S8Pcs+8mv/bvqPBA
         xvTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=YejFzVVvTbx480WIGNfaPb/xj9++hESGctXXz431OO8=;
        fh=a98NTn6ZnNX6R2oUdppyc13vJQepKYq01zLXyAZXMHw=;
        b=dVxiHs+TxdFwWHB4pjhDxX3Gq6HYAqNVcRxX8pohqrPDfp4kx3+HvyfOafIpnBcPzF
         wduzA1GP/5ko0cTjUlpOx/unqTRhU5Suq+qwGMH7LQf1/BaBVHpat+epUnizSEp2o95H
         xl+EnE5zCYcBQY583QsUhkUjcCTWeIhi7R8335BSuCSTRECJ/rt5yLd3SsyXilLc+Wym
         d5ShoHfRpX83yWB/Pz2fxOIQDDPdsHBi1qyMzCcIQL+tHjx6S98DZYLtzTg77g9ephR4
         91dmvg0d5T17p/Hw4fV9xr6bwJrlRUmQqJO24IptB6CvEniu57mV4hjxAF69i41GaePE
         v43w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=df2vx1Jk;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30924cb0b76si1736061fa.7.2025.02.18.01.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Feb 2025 01:14:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Tue, 18 Feb 2025 10:14:11 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kernel test robot <lkp@intel.com>,
	Peter Zijlstra <peterz@infradead.org>, llvm@lists.linux.dev,
	oe-kbuild-all@lists.linux.dev, linux-kernel@vger.kernel.org,
	Thomas Gleixner <tglx@linutronix.de>
Subject: [PATCH] dma: kmsan: Export kmsan_handle_dma() for modules.
Message-ID: <20250218091411.MMS3wBN9@linutronix.de>
References: <202502150634.qjxwSeJR-lkp@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202502150634.qjxwSeJR-lkp@intel.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=df2vx1Jk;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

kmsan_handle_dma() is used by virtio_ring() which can be built as a
module. kmsan_handle_dma() needs to be exported otherwise building the
virtio_ring fails.

Export kmsan_handle_dma for modules.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202502150634.qjxwSeJR-lkp@intel.com/
Fixes: 7ade4f10779cb ("dma: kmsan: unpoison DMA mappings")
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 mm/kmsan/hooks.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 3ea50f09311fd..3df45c25c1f62 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -357,6 +357,7 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
 		size -= to_go;
 	}
 }
+EXPORT_SYMBOL_GPL(kmsan_handle_dma);
 
 void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 			 enum dma_data_direction dir)
-- 
2.47.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250218091411.MMS3wBN9%40linutronix.de.
