Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCOGWT5QKGQEKLLVBEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 91DCB277BE6
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:54 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id w64sf684744qkc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987913; cv=pass;
        d=google.com; s=arc-20160816;
        b=fpXu++or8z1wsArYycIZWWTMTYxtoTSmObBidnK/+mVD43n/rNvWCCJaEerQgmVV3q
         CLjFB7XQvMdHRP5UyV8HdjuNWSW+NTTtw5ARUjrqPtNWbFFwVV66LvhLB+wfBNVP/pIh
         oF7cFPiGv+hbfVkxDD5s6oddxFAALM+eB9KX4GTvpH3vjhaHNVx/CzgCfyMHCaGixeuJ
         rlsWoP6kvZJ/+d/ZZvI48LBESx+IoIozhKd35yVsYbfSSYcnfOpyxNUD/AWX7U1F5xbX
         mAaTCOJO2Crbpo1SEBWYCUDbG1yiMU537JlxUs2fZEw3dEy5seJ8YSz1h0U4J0kFdOri
         hWow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=v1v0BvIHLG78xEQdYYYgPIBkx99+HrTbEg+RMaFN7sw=;
        b=OLnpy9yP+1edkiLOEnqglDWV2yYA9I/HWU8dPccMs8rtmkuad9+3m2mgjibheW2Kqk
         Tvx1N77XGaPDRZxql7c1jqgFCtf465EzttVjbJISUir/PeTobyQRxvBmvCJTFpfIrfUH
         JQ95ZISuj2ibRB0/EbBf2uxIbQ8j5Tr1AW+c1Vn0CP0D74Qm3aXImqOEYg25pDgfEHGF
         /TWXucLH3HDqOtVsujh37vcorvbOIxxB3+SdtFz20bdgq9ILPvUKPFYlCD+ksRmMs1GL
         rxfQwQiMaYmYmH6m/Qa9QEJH/32YQAtKIxjhStitFDs66UO5Bxw9Q3wjgR/K9tTEMeYm
         EBAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TATkXEfB;
       spf=pass (google.com: domain of 3ccntxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3CCNtXwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=v1v0BvIHLG78xEQdYYYgPIBkx99+HrTbEg+RMaFN7sw=;
        b=Q6nf7HO5Sum80vKCXneDJw66IwJQePtXYfiU7Z2spl5q7QC2JXIRSo/7IKVvKf3tdB
         lRc7xP3+1UCaL3V6kI+sj284twfFR3g6vRzjUNlXaz2AhvCmyUy7lq507m8fWFRNPFYM
         qWsBYvLGXuFefv+sr0BvPl7tPn+NX5bSGfeMXUG+g6W1lq8iv89iZiFe8esX3bKSAF3+
         zG/D2r+GmQqXNz2hLOUJ8tTGj6EXxqwWVdoTK4bGF7ul+VU7zqIyNhzI2dR17Wmyrjdc
         /UHkqKarmWBF+uZBzIH4DBgfeUZT1RMZDiCajR0Pjzmbu1ATqlu8Qx5C1ZSBg1so5Yhd
         PiaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1v0BvIHLG78xEQdYYYgPIBkx99+HrTbEg+RMaFN7sw=;
        b=t4BQi12N+l2AzXqPfBk5Lkww3s0o+0iOeKSAN5ovEgMfqTAYgTI5HvgSTj+LZp0/gf
         sV5fjzn4/fTXjQg8wIXkR5EBfk1RzK0miB7Qtp4SPPXOBaEIqi23DNPP5CQfN4d4reRE
         dRHvDBaXRxIMFWbI0cUlL2zFuA/W3d3gmVwuMAv0PQseUuIOWbkbImWCscHoyNu08akT
         MdSa5HX2cFpsI9zZewqO8vk3RkTNXUI1hvuFD7b1yl9T4/1bciMzmQ9luHx7I6p5tB5s
         /r/yw9KPZv0wyYP4gtHVB63/Oe0QOGBRGqLeBIS5b8QwvuwJSs7UVZog5s5kesFBWYAx
         x62Q==
X-Gm-Message-State: AOAM533eNvcLQZT/P8JkKqDFRSv4Ch7v+3Whm2tBTRjXxgcQo0urzd0d
	JrBSYTGAQOIEsdyi3Z6s01k=
X-Google-Smtp-Source: ABdhPJzrrHR6OwQnnGEsCYVgN14J2YuM0TI0+l4FwjVqySzdP3cRr2B19HUpzrlIuvee0R1Ioy9iqg==
X-Received: by 2002:ac8:7773:: with SMTP id h19mr1506845qtu.337.1600987913326;
        Thu, 24 Sep 2020 15:51:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4d4:: with SMTP id ck20ls229812qvb.7.gmail; Thu, 24
 Sep 2020 15:51:52 -0700 (PDT)
X-Received: by 2002:a0c:9d04:: with SMTP id m4mr1527380qvf.50.1600987912831;
        Thu, 24 Sep 2020 15:51:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987912; cv=none;
        d=google.com; s=arc-20160816;
        b=aLEeX836OGVWoLNJwnzfk88D3k6X8oHrYgiMFwHjXMSTdGK48V4lqKpWFvyqakMoZq
         /m7Jj6XuMIEqVy0V6rS1eFPz3lFk0AeWHgUWsTmf/0fCkkZ62Re54eqg3hHsjLVNQZKs
         mL6leW+TWmkeC+9NCmZrXnqPKZmkNUCkmVjDo7DF8k1Lr+c8XIQTj3y32uU/0IxYKUll
         wXaLymmeKDqgkOWG2xyKEtiHSXqWy4lXK3RJYtERnhwlvAuJcV/vYPISHc/XP9TYKMo2
         BDkWE+CRjQ9dvAylrm9IuC7j8ByfHwQ0jkvPnRcH2tP6ZlpQfaQP8TNnjtAIngGjSQVm
         r9aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0jztYvLtNDJTI+Li9nzFVZCFMRi2vX4Swz42H1b3+CE=;
        b=vkBYElZuOqvn3oHKiYYE6VZm+NKAbTvgXq0W1Y53402fw3O3oYYTOqT8eWsPcZ4t+U
         6KT/fEndnPxvv67KzWnN8jn4KfaKpEuvXtNfMoimfvygYRpRo5mPXsKEok0Z49jDeyoo
         PFhvXZhvNkqXnRSSuLDX+4UdseQwNVNcEQpZe+jxJXuQHB3QvAwWNQ0hjcfRKQimZQE3
         57iDs1ibZGuItGGvqYWpysseAjlDhXgr4nXjXKZgWpwY0/E8N9pF0ViKApYrzvJKBUzZ
         d3fbXEsB3AsY9rStje2LD078BiqXl3bC8KszR7EpxWir6CfMAa0FG2owrKRlXgHyUa4D
         3h3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TATkXEfB;
       spf=pass (google.com: domain of 3ccntxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3CCNtXwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id v189si52869qka.7.2020.09.24.15.51.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ccntxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id t7so493170qvz.5
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:52 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e5cf:: with SMTP id
 u15mr1552253qvm.14.1600987912449; Thu, 24 Sep 2020 15:51:52 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:32 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <176c7b60cb2711559450839242a0f6fade769c3f.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 25/39] arm64: kasan: Add arch layer for memory tagging helpers
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
 header.i=@google.com header.s=20161025 header.b=TATkXEfB;       spf=pass
 (google.com: domain of 3ccntxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3CCNtXwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  8 ++++++++
 mm/kasan/kasan.h                | 18 ++++++++++++++++++
 2 files changed, 26 insertions(+)

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
index 50b59c8f8be2..9c73f324e3ce 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -241,6 +241,24 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
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
+#define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/176c7b60cb2711559450839242a0f6fade769c3f.1600987622.git.andreyknvl%40google.com.
