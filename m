Return-Path: <kasan-dev+bncBAABBOMC36GQMGQEYEH6XPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E6E714736F8
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:05 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id d2-20020a0565123d0200b0040370d0d2fbsf8047056lfv.23
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432505; cv=pass;
        d=google.com; s=arc-20160816;
        b=RSO20YMlOm4Rg+CZwJc0HO59dx3t34u4hxsaR6vxWGRTywRssXzyw7mpbyw6sqNaB9
         wRKbbKQ95Kpz2SIZtMtlPeS3otTMqTGlhKEOMFjHM9WY+GflZQEALeP6AuUwAyKt5Aka
         PzHUGXnrmRg2lWKgz+q1kzgUMlU16mtfw+mN6PWLjJR7WlCYg3D0t8Kqb8nJzNMnqo5c
         MD7bRVHc3Fgv4D26UsQ4k7AHbVQzQwTmtsnSvT9/a84hscUpTpoDrXMEYniD4UDZ4wB1
         BERpbw555Uh5JRGtvmxcLN+QNQbGs3TQPUuF6Dp33Yxlaa3/6c0WuxF4vEcUrW2qkcyX
         LTZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vZgN7s+BTroduX18rjMUw6x7rfpOLNHsswNXuqKrlWw=;
        b=V5ekFyj6le+uwDyA8+rbZsGEBTSKQ4WIKNFBNbvaw5AjcnMntN6xXZwxjJGLhjSiek
         uw9WZJI1KCmY/w3KzRl8+djNFsOsdzvZvsUDcgckXwm6lgmLmJMtC56VKE2Shm2/j+tL
         e06QGctzGTRSOacUC3gK8MQxY8AnT4XmSfuFKbILHz/9RUaGyCeBt09DtR7L4XMXSlQ1
         Fk7Vq4meyOr7FiFQvxI27YeZIzY4DzuD8xsNLHj69aZ2avE2H1z1B69HEUF94G37vpoX
         nnGomNDgyLznDSbmlwitcgHYegub5eijmpGYx9RS3qL6r2bVcAvU5Vj05aVQHOpCsSvR
         Dm3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JnDImSkL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vZgN7s+BTroduX18rjMUw6x7rfpOLNHsswNXuqKrlWw=;
        b=QgnJzoe6SUhOqQpgxMzmyGl07QFZdAlBjKBeZzhs86StGROLUAqRMw5lIeTDIqokvV
         5cCSKV5LBLjDVaF76NsApGSacggksUc+pSTXgDXAhPg53KlvubSbKZmzqsluEfl6vgVJ
         cgYpoIOmMVaYTLCBDibRA2w4TqhhZp8KC3vUtR7jVyXiY8HjWqUrnd3KA428pS33VHJY
         rMzbEe8/OTRbrESdVpE/dKB7cHdTiN/j/YFsSfbAEOZL237QUNVAIjl+RPvib6Vdqi5j
         Tj7+0/4YhCNc7wgRBmJq0evBuyYslk838EJ2ajN2TArQJ8SsKxJd/+nX4f1Va+gaPkh3
         F8yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vZgN7s+BTroduX18rjMUw6x7rfpOLNHsswNXuqKrlWw=;
        b=zUg3nAQdN5PL1IsoAzOmMUX74j8UWg0NikWCa4tBf+dCMz8/yJUm7pMB6DqMayN4/7
         zNqKKaVNZ/eRKeHVaECmIcCQ+nLfSL4wGZX9RO1rVDyC5q2f3WqjIZXI6U97FWWe+pLv
         /6PhLJLh+3w/IP4wC1oxpvh57S+P1xIf37znD9kmOT/uleGo/ox8ab7iK1+pq1PAn283
         UW/DgZWd2zI92Ju/iL4MP65W/zwI8w8qVUo6gjP/7/8FQ18OsFrKHIabQYedN5NlK79y
         hxpECFHTkSzIZEcsWgG2BxjhrVASYFifh4P55bqNDaUaEfXiJHEZOO2PjgArLof5ZFos
         EchA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328kPSQ8gyEPMjTZFWARIc8fmOs0cJ/uMts5nigFta7oPQUhga3
	Bds34GUauTBDo+tCjRpnL8o=
X-Google-Smtp-Source: ABdhPJwat/h33dbXc+Fotr4rW8kwD9psY8s1NCnYH27n107Wdzxow//wUGmn2LO3KuFxvYHH1d7WHA==
X-Received: by 2002:ac2:4e61:: with SMTP id y1mr944154lfs.459.1639432505526;
        Mon, 13 Dec 2021 13:55:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc09:: with SMTP id b9ls2716543ljf.2.gmail; Mon, 13 Dec
 2021 13:55:04 -0800 (PST)
X-Received: by 2002:a05:651c:a0f:: with SMTP id k15mr1212090ljq.298.1639432504712;
        Mon, 13 Dec 2021 13:55:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432504; cv=none;
        d=google.com; s=arc-20160816;
        b=WXQK2IPoDQvMYHOCLH/Uo3lbrZ90sDi/rSUDNvNKas0aYnHk+qMGC02281EkgRdKMF
         tkRDmKt9OzK5GfD+oLy86Pz73Y3/DDqMmsBH3/lOyOCFSWZeDN/6YKV7UWsD0Ps8hY7A
         hCNe4Y6XjBXKJoN29AtekZzFCje6e6liOktCuDmoj3FRG3zfxN43hxwKbyGM/weyfjjU
         dh9GoSPpkPBm5SXSGmi/Rs/exirYfCVWUoC030kXUkG2pts/gEXT//jXkj2Da0oAoVLm
         v8Bvf/qYOUXO3hbR8lfdX0KWMHvaCz00mNVjXHlSRGxLyT4JJwV/Q1INHLYzCsFmUaH6
         x4lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vluHY+VQM1dpG6ccvF7RpbMooJaXSsDFIpBMIGK6fR8=;
        b=LvluaD1R+W/tNOtPkG5QUWDuxrXcsKOh8CR5jhCw0N/CrT7hjCWeXeSsq2PXk5PIHf
         B7KBhKeSAPr16tBieDFghjCV0dbTsGLFo7KcLj8kXz0RUlTGJMJjq/PFulz9u+yjUUyZ
         OOhOwcHWzFUufyraxbSemTZwHvBrF0dFW83ihDv7+8/6J2cBvPJCzguojIsleD3GFkGw
         Pwd8S0kkexi8m4kGu69cKD/1B8CwwNUayH/3KUvrOD4i0nhA5XSuMFniPHSulHX1sOx9
         rB04whOwYvr/aKDIjQ/fmHWixOGSosy4soqNvbM0JB3Ru0YOE/ohQeo//LhahdlkL7iq
         /6Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JnDImSkL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id b29si778999ljf.6.2021.12.13.13.55.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 32/38] kasan: mark kasan_arg_stacktrace as __initdata
Date: Mon, 13 Dec 2021 22:54:28 +0100
Message-Id: <7825a5fecec3626441ed3fe734090e9e3ab9a0f9.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JnDImSkL;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As kasan_arg_stacktrace is only used in __init functions, mark it as
__initdata instead of __ro_after_init to allow it be freed after boot.

The other enums for KASAN args are used in kasan_init_hw_tags_cpu(),
which is not marked as __init as a CPU can be hot-plugged after boot.
Clarify this in a comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index bbcf6f914490..fb08fe1a3cf7 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -40,7 +40,7 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
-static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -116,7 +116,10 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
-/* kasan_init_hw_tags_cpu() is called for each CPU. */
+/*
+ * kasan_init_hw_tags_cpu() is called for each CPU.
+ * Not marked as __init as a CPU can be hot-plugged after boot.
+ */
 void kasan_init_hw_tags_cpu(void)
 {
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7825a5fecec3626441ed3fe734090e9e3ab9a0f9.1639432170.git.andreyknvl%40google.com.
