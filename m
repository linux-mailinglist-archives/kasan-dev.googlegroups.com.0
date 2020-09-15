Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX66QT5QKGQENHTI55Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D62F626AF62
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:19 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id s8sf1694427wrb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204639; cv=pass;
        d=google.com; s=arc-20160816;
        b=RnQBodmlWpzFVp3jvutKqRm2FsPtSfWdqvT/8AO47eYC/A0jS2ah65J4a0RkZVNqbw
         t+AeKpgzlPxMFQKj0iSVRIEVdnFzXfeMeXpO8hmDN+LPQl1YF2pDj/APHC/9U+rp5VA2
         MgNnBqNh3RnBSMRxBFhKMamKiiqz+tpTfS716Q4q2fpPNJs0e4wpQRvgAXarZU7jdQoW
         RrDtreWaMKgUdShhYYIhtV/4smE0PHmlfgd53gh6W+37bSzvj2O3ECcPPYZxaJmsNnMk
         xN9txRBXvvaP0GkxcKtnptPvlwgOCxf8vk8939WvLyf9NK+cr2ikDU526bxEcn5/WOdf
         3Gcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0IC2thGOvjf7h/iGB9v2wypvx4+QNNqd2F86osoPPOU=;
        b=u3h+/7OKpX9IxpKML54T0Ui9H1p0WemzU34RRqzyhODmWcicTQhCi3og5Dg51qeDYU
         GxzRWV2izXLg7MGdMQaSQSMuycFrUzSgE7Pv0e5ccH+MOtZ8uVfUTmlmmwVLchJK2ibw
         PBtDhCLyhdiRoHUmpaDrHuzZy8G9krd3SUSW+tWsCXH1jSpoz6uUMYScEYX6GXkz0Ur7
         yQRcy36Cq3/P0Zgz/h3okuLSS+2VwKspVFAZvwcw/nMxx9Lp53ZxdzmtPQIz8d9N/Mh9
         OW+Ki/Q4sAIT9qI2t/M5/iJQor96NwkLg22m3blhScOijI+b1/ZGWbs7VvwxznvioOzd
         xNqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BMgCiDxI;
       spf=pass (google.com: domain of 3xi9hxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Xi9hXwoKCUMfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0IC2thGOvjf7h/iGB9v2wypvx4+QNNqd2F86osoPPOU=;
        b=f69yobOOSh7yJx386zxR5+W3wxb9b1WR0Jm/V7gdpmmK8XpRUJlW7JhDLMmW8hGYui
         YnxnVA2cSUomRuvQpV0OVGkPpX64oCMNh4/jTGmQi4SXDMhtvQTVf/Hz+ZiP0EuuKjj1
         szyjyJ7UDVZylVZ29ESYJhjzHkJMaV4Uo3GSmM6e2Lig1poocWffcWbg5r1BBbUg+ABY
         fN88rr4sDVdhxslNXxX4nD57khoyqZP/m2MS7B8nknz3xoe263m/Z0Y5o0tBpaP3rMyf
         eJIwLqxsa+nKSKuogeTPX1kxHZQcGvjJkamwuG37WVX2aaSjcRgQRIimD91qg73NaEIY
         kLCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0IC2thGOvjf7h/iGB9v2wypvx4+QNNqd2F86osoPPOU=;
        b=QXRyqP7EawAYglBf1ILhv0+NxnRoBdOw2KOaTb9CSpJftrQZ2nbp9dJ9rdtHXZlaz2
         WtPhd7aMCOjT3WHp9OWbKW9wGRPqWntl7FTjvRdJs6WhMp3Ofp31mapZl4ED4+Ab6S61
         kDq+jtbVwgUrE7fRHx/TD9ME4pi9BWHfxtfCVFaLEU8W4pCTBju8AP2iINYX4MQnChih
         25RQF17xMJn/Kue6969zXrdgW/cpx3VBXMnGtf6TlcO8jHIyGz/RgBiTKIzlocLHgk2S
         W5MwBPdEwugUQUP4sogGaHrEwXqs7YfvtZVPdfJzEsPdFjRZ39BrYv2ts6IYj1avf8Fa
         qR8Q==
X-Gm-Message-State: AOAM532qJxuwOLHvU2v4W/qRlZAZ0inxIo2CB3a6LuDnJ9GK8mH762Qc
	Vl3brGgmcqLtdynBFh+3lBs=
X-Google-Smtp-Source: ABdhPJzMkzqJc+eNk7fro2L5O/weO5KESAX7W19Vptb4sixPuFbZjwB42LKhGl421OEG92702+qlCQ==
X-Received: by 2002:a05:600c:210c:: with SMTP id u12mr1296056wml.185.1600204639599;
        Tue, 15 Sep 2020 14:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls357305wrq.0.gmail; Tue, 15 Sep
 2020 14:17:18 -0700 (PDT)
X-Received: by 2002:adf:df81:: with SMTP id z1mr24486402wrl.9.1600204638907;
        Tue, 15 Sep 2020 14:17:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204638; cv=none;
        d=google.com; s=arc-20160816;
        b=fhHQHxk3mMVbh5cY6AP+P+tZU5eZ72uhe0u3hdrcfGWB6mMdOsJ8Y9kFcdb0q2gxbE
         ayIv5SyHvKqpLI47URL3PAoN2DXe5qIM9ZmiV/EAQfSTuYJaELXC73g2iKLMJapIP+Ah
         92VVxauZshIOWvhCAQzz7+vGa+x3yky+p0DRuj/ScarYuqp6xWe5ZuJEedPXp7Zox63s
         CVp+iQPQ9SCaf7J5Wmugy3zQOg/Ubp8PNCm6s6p61vFGQJ3FS44WqKYhpadR7Vp6xgft
         lvJeJg1/Wz8Qp1pLbj8LumcC5LKZa2tZPnXK9lhzeIMvav9yST15TAi8j3caS+yqIWkD
         NhCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=uQBUcw70N5/pZNHz2QWMX765YU53M7496uPmAAbH/iU=;
        b=POqoi7dMw1n0LMebMQ1CyzK0/VsOSmFbveVFPQNKeAF+Sf8kqpgg1XXclPVIBW5lMk
         jKFmZMZNFdb+ruZYbdMZMkAgkEGYhUrGPzgZYv6BQerZGalC90WqwPgaxFFvdSgzFxG/
         r2ymnbibzvP6mZkabzazqNIe681I7Hu7Y4DZHUSuTwsFGPpJfx30ZV4yKYrnPA+cH4GY
         4VPRw3ziu90SNsxQP588A6q+G6Wd0coUvTBsgtaQrgmQD8nfFJ4mWDHqXdfcbeh+J2is
         9jhm5OOOmJtyN4HcmaDKd3yESIx0SYE4Xha16B9e/LJxH+KCiecandqHLfZdiW2aaKG0
         Ypiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BMgCiDxI;
       spf=pass (google.com: domain of 3xi9hxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Xi9hXwoKCUMfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id g5si49816wmi.3.2020.09.15.14.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xi9hxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id li24so1839280ejb.6
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:18 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:18d:: with SMTP id
 r13mr23596971edv.267.1600204638418; Tue, 15 Sep 2020 14:17:18 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:05 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 23/37] arm64: kasan: Add arch layer for memory tagging helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BMgCiDxI;       spf=pass
 (google.com: domain of 3xi9hxwokcumfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Xi9hXwoKCUMfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  8 ++++++++
 mm/kasan/kasan.h                | 19 +++++++++++++++++++
 2 files changed, 27 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index e424fc3a68cb..268a3b6cebd2 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,6 +231,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1d3c7c6ce771..8b43fc163ed1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -240,6 +240,25 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define init_tags(max_tag)			arch_init_tags(max_tag)
+#define get_random_tag()			arch_get_random_tag()
+#define get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define set_mem_tag_range(addr, size, tag)	\
+				arch_set_mem_tag_range((addr), (size), (tag))
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl%40google.com.
