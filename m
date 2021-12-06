Return-Path: <kasan-dev+bncBAABB34IXKGQMGQETLNPCTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6749946AAB7
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:20 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id n18-20020a0565120ad200b004036c43a0ddsf4375638lfu.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827120; cv=pass;
        d=google.com; s=arc-20160816;
        b=zP3/ZR7waJwk28rj+Wgys9KIRTYFcPNHrUsmrAElm0bdUH+mw+YE/nFyv/UNZGnpSq
         c4ZtaVoB6rDfUNn3nIJ1lkSxRBEDGvs3vxypDONYf80BCGbdjH14I90TOfTqbJQdQkej
         RFTJehZgISv3lJC/bXExA1i3kE0Mj0XWilvbGLTgCWcaYlQyzgcg32NxMuA8KB+UhPQS
         +XR8tOhIqNb6s6+V3ME4Ohym7r9BTKMXDgnqBHQuKW1zeE3/mRh4uUxiazNC5LO4Q9tP
         W6S4IM/uh+bOFa/H87+sAWfWbhZvClg490GQq+ZmnzlXfiydSLgQVmp57xUwwfQNm16F
         VDhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SOLSm+91IXVcfWFngO/h/f8sh+0SeZBSgxiQQy04GoU=;
        b=h94NON66l3v9HcmP2zDp+tdi7/ttHFeLHKcDLmOXFY+dwtWM8M56Vg8ly4es5IE6Ut
         bmEsCkf4qtDA6o6DuhbVmuKqdq0puos0NN7JR6n2n7Q93ho6zNQ7cEMgAzvlh9+ybPRi
         9uS10PNaTbIGX1E6paYkz54CzttddsPw3zmQWv5rNVunn71ZZ/7qHMq3YUSQPrikbFG1
         LPCQ2TRcSn9mfyWXYYoO5x5/fEXKFBKjTNdYaJ3LR7AHKCXFRtc2p3Ut5yjW5MJ12Ekv
         MimK/VShxq0lx+g7N23Id/lK8LdAIRBJoLhUZs/aknkiTu+Kxfb1Rs12krOTHAZqM8Mx
         MCpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ks6MOpDr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SOLSm+91IXVcfWFngO/h/f8sh+0SeZBSgxiQQy04GoU=;
        b=W2vife/h/1csaDKDQC7mO0L6pSR8P1dJ5CC15vhSkllgnv/YXkAEz1C3A9HSrriFUx
         3hKF3bn88ZRKzdhsV3npZMiUzaBOqIC8IunvkaXEcK/Vkgin9+cMZmAts+PmFJDPxcl0
         +ARFof0vSGXnixjpYOM77cm9S1WmU0ZcohcA03SM/5+vhmzh/XFC3coPZmRQxLoR40gW
         11m2X3H367VtuYuOCnCN/1vISf/vu/gMmAm6CRe9YKFv2tIkpPdyU8DpW5y2JFnldoKZ
         nl77wqhFN0WvmAvJrfRVhyPQk/D16pvsiLxjYgMTV9ByIs9GYNJ0i7PPCzkzEp/DSbMT
         QEsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SOLSm+91IXVcfWFngO/h/f8sh+0SeZBSgxiQQy04GoU=;
        b=KCPkrkuCxcVpa4QIsr07w6nVprm96qtGPirxR2XdkQoZO0cZcO5HWbtMzamksaTUmw
         U5jXSLXRMQkvQ+dN9JWRvimkcCPGlSzwHSk8KlTyPEPQ7fiXLcGAWGG+235sgaa26MmY
         HfKN4xYms/Hx9EAUt0Fm+MFeT4h076vjchIi916WBQ1l13us8JytqsTLb7Rw+azJi5ch
         2bggtMYuAzHAh+Gzi5jAS96kS5C7xTVWmkhFHdDHsbGBB2GnTITlRwoVjgjetGGCv6zo
         gaVazmv3ZOlTuEH58Nfpux/FaxSGPjaRtZUwWyOxyEGIBh77i/iBtekTFHCDVcR0NlzR
         TQcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qA8zk1xsKcWwehpR3WB7bYAJQK8lVK+KK+5IuvOU6WWX5FrIA
	4yjKT8+YCF+MnlvEd5kkpIE=
X-Google-Smtp-Source: ABdhPJyR6beTF8RBDp3Gnb//CyajuwtNjkwb6HrpWZSC4u1E750mpJy1wsP2qecsJNKNQnBHo6MPlQ==
X-Received: by 2002:a2e:86cb:: with SMTP id n11mr38956157ljj.425.1638827119958;
        Mon, 06 Dec 2021 13:45:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1925604lfv.1.gmail; Mon,
 06 Dec 2021 13:45:19 -0800 (PST)
X-Received: by 2002:ac2:5c48:: with SMTP id s8mr37494880lfp.292.1638827119291;
        Mon, 06 Dec 2021 13:45:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827119; cv=none;
        d=google.com; s=arc-20160816;
        b=utQPySmF9gUhJxXO2ZmSbI0ti/xCeyIoLJg4Qm1LuFTvRTh6GfgYRogbwUmQAny3Q8
         37yTE1/A7f38KIb5a8HYvN+WbU928NSMqViQt0UeocuIJiiXrtee89YLy7t+1qLzYwuH
         tx1y6xaOJD/S0w8YLmlUNQJZUbgRkE2HiaesGvlMvqKAnNFCXJXW6epUhR03vy1aD5Cm
         6AMxrX3CatDO7qPGGkIOplnQKCCxXGFM6v9x2diMPIYrtKrlDISftRs+vsKDAXp766NT
         bHSjGc3Qipab2M3IKsLRtVaFwOHf0gTHpxSjv4t0RSVapTcvhEnyx0tVf8ti5u/02qZP
         5jlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sq3jTC1ItQcEg8U0H5RA1L+mQBZGObrT47vWcbRK6Ok=;
        b=JEyJ2KEwVAQkfuD5umINijFAH58M/l1ANrYuF1eJ6oylAJA2WAxSwlPxxxeXrOA9BV
         yYmmOBiClbr32B3RsCKmHB53RXoj9a2WsLO5sG/6nnLspHNrpManRxQB5ADyxVRcouGW
         jiPa4T9Nja71PjFjErqzCQHendsuDEj/6vnDAbjgv/FR/Q4vmzgnmHAcrfSKoHqfALFh
         ZN1rSbI9JeuA49JfV735U23xtsZY70KVUvaPy7rU3lC1HV61ioxrNK25wKulBp0LMKy4
         yVr9aIhVqJuwTCI82wlO3Gi9eXLmZ9NB5Er0Ijp8MQVva9GszTob28vjQ4TaO2I8csWn
         oSxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ks6MOpDr;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id v8si814815ljh.8.2021.12.06.13.45.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 13/34] kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
Date: Mon,  6 Dec 2021 22:43:50 +0100
Message-Id: <42626baf4ce66be7fb1538c074b6508d9d867312.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ks6MOpDr;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Pull the kernel_init_free_pages() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patch.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 12 ++++++++----
 1 file changed, 8 insertions(+), 4 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index cbbaf76db6d9..5c346375cff9 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2420,14 +2420,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (!init_tags)
+		if (!init_tags) {
 			kasan_unpoison_pages(page, order, init);
+
+			/* Note that memory is already initialized by KASAN. */
+			init = false;
+		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
 	}
+	/* If memory is still not initialized, do it now. */
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
 	    (gfp_flags & __GFP_SKIP_KASAN_POISON))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42626baf4ce66be7fb1538c074b6508d9d867312.1638825394.git.andreyknvl%40google.com.
