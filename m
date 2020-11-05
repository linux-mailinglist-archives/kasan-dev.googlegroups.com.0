Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL4CRX6QKGQEAQ2RFXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BFB92A7377
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:56 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id j13sf100939wrn.4
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534575; cv=pass;
        d=google.com; s=arc-20160816;
        b=KJdqT9V2k2Om7Ozb5n+rp370aJAu4mXf24cFYyslBBWYkQV1id5aQ0pjrUNYmNirKl
         Y5bdJLKypJ3nluhyqME51n8LhFxLzZbQAgHeD1RDq9XfLJiGRiGtzyB6++YdCIxW2Azc
         Bt3Y7EX/EHGYjwdNrpQiO68SiVwd3i+Zo9LQrRVqeNa9oYGfaPaXkD9UG3AtxX99tLFS
         Vls22NpD5dlI+dY+J413/wVVeh39pyI7elANHOtNnG0ajiKNpQ7wXs7IgF9R7e0zH45C
         7HXNOAUgIOJE2zNwzmxdhJ131MX6SLZILn8pJqd01GELV6YJ9gvQ/9tuwXDMaMceLHin
         tbhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZXDAO3+YAmE+vJXiAyE9WpY6UdsgDv003j36dAOTAOA=;
        b=AznAOdV8BCwH11ItXIujhDOVbO0cFolx7XeMQMa3coFGlr9b8DNyWHkPlAUFK5y0ZO
         s/kXHd1ICtPcvJiwvSCmmQMdOooILcf4a1mopp8Swek2DbKSgYuSGpZYxHMjtrhvwO7X
         quWVOVtvC01NnUDaLPu1d4Qbi4Gf7sbHWE+vD8JKQ+9+mQe+BmTgHP5IpXmcQl4D+/Nj
         5dVL8KOAqhmcMI7idNU4G/9qvLxkBF3RMWlQiyS7i4zPhGkG1/HmASZCoQ1S6u0JQaQC
         ixGljf9xXXcWPlzbi4flEZ4nJqbiglw7aG+tCsluIhEpXkCEfmlJqZgdB9LjRMsfknwG
         kOGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cMYeDNAI;
       spf=pass (google.com: domain of 3lkgjxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LkGjXwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZXDAO3+YAmE+vJXiAyE9WpY6UdsgDv003j36dAOTAOA=;
        b=B2kfOZEHrZrBt+ULycHL9MhxSPOQNoNkgUkGpLvkwJ9rBho4kEdThKH6Rqy3/TRhqe
         Bc8Ejvtxu6emXzK924hxd7FAG6+LFYD16yqbNgXq4+GeeRWdkJ6ubYFxMal5y7GoyrH1
         Z4Pwr79wZkoEG87bSTSFw/Uj8t7fImQ+jUb9XGSUo5vUJgenp3/ap1ppNV1XMItXgaoX
         hmP6xF/yz/5PjJM8wpKB6LueploZZaVc+CO6j8M21ln+0t4n7wy6kN/eg6RgZa/cEdNA
         zXf2rxDdHcqOBkWd0FY0P9Hz+9xTDG5ZUCy/6MV2UHTKpOESMVtNWbmJXY7bAvft8Nk2
         ik0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZXDAO3+YAmE+vJXiAyE9WpY6UdsgDv003j36dAOTAOA=;
        b=BXri76d/mSzdQ80dFOb2R2gxz78F+RDfJZagFr7d4F3TpLHu+DioQaTQBFCRNiFY72
         M53YGeZIiLSAjmovBCjbBcV8vFANPu90d3CvH+xU/bAMZVAhBeQ2+dgE7CMaGYpAngOL
         5r26IeEwpcqLwMBl+H5JlJRQRHzFPNsfPb6HA8slqr7K6axWa6rAVXrZbJyytGGh165p
         pet1Gj3zsxDg1yEg0O3ypFaovwMcTtdtf5RTOmT4cEUqy2/MFcM+iUq7t8MdTt/dJnxb
         F0Jovgkwj6P6eqfiE7zsoOFk9XDf2BpI43PFwX4ZYx6Sz7B2KmkL4b5f3qwYYoDL6JA5
         uTvA==
X-Gm-Message-State: AOAM5336EEPTR9lzaRU9/VQ4Dl/2ioBjlB7V9HejmDMJtQ9x+nXuOb2C
	K6+rTA3GgrOnF7BwwpeazvQ=
X-Google-Smtp-Source: ABdhPJzdPhgRw9f9pUoRjNA9xMq8kjshVlsrOVOl8U2dPUfP7stale6FFOUE9YAq8Pwx06h5xO3k3w==
X-Received: by 2002:a1c:6456:: with SMTP id y83mr420wmb.59.1604534575750;
        Wed, 04 Nov 2020 16:02:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2348:: with SMTP id j69ls8469wmj.0.gmail; Wed, 04 Nov
 2020 16:02:54 -0800 (PST)
X-Received: by 2002:a05:600c:219a:: with SMTP id e26mr14971wme.168.1604534574931;
        Wed, 04 Nov 2020 16:02:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534574; cv=none;
        d=google.com; s=arc-20160816;
        b=hMsNdf5PCzN+Hda0Na4X5N9/rr37HAyzBlOGzzbe6eR7ZCWUwUNfs+kaOUbtPPxXPD
         n25w0m67PXjf/Wr7HGcJde4zhckkmiPJOLVmLmfHvOK61IaGYbU3KLeD8x4fY8+uxzu/
         iNGrgExLnqdkostp3i19US3LDazgLU2Xc6t+QidJEZQ55ekhrbQxUbMwARieSgCUwM2e
         rHUXQUJzf/yjAb9tpV/SkaGF2W1OSnL/51hNPXtNxulLtAd/Gk73GFNAW0o3bOR10Ah8
         jyLTQAZYCsIYt4Jfbj8CrODRjbxIq/zkmFtskJtlauSCmFMpewTxr7wqVZXURP75WbW0
         qvFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mRk4x8ffqejU12g7nFdHunjF+UNrFXF8Jgp9G1eFhMI=;
        b=0PTPZCtXiXhIfTFkHFNep1nAl0vGVOKZE3Yi8fFfwg82+WTnwYqLMfpRPTTgchS5eu
         xGD+hT5PRjqQ7rY7IS/mS7DwmnLPFW0WhPP292Wuv+xOQVA7CLX6I/eFIM8yFefWWeNG
         5xWupGtiZcvbJAIOBHa7qQUH51tnfoNsP0ib4KGseZ5fy2YRbHOTgKIJ9WwcTWvy2Jgt
         xYTnS6e5LeZg4GFJIBdK30ruXW8nRAuGxPHQYc0j2CZDhF7QE9mwlwESUdcn+nZC7T2i
         s8Yy72K3MdyFXGc/8QzknYP9kpNIKP8X3dIxTdO6VM73TQFPs2lY7yEqV3nA+fdpQYGz
         kbgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cMYeDNAI;
       spf=pass (google.com: domain of 3lkgjxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LkGjXwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id j199si622wmj.0.2020.11.04.16.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lkgjxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id o19so7401wme.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:36f:: with SMTP id
 f15mr532689wrf.78.1604534574449; Wed, 04 Nov 2020 16:02:54 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:18 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <f51b7247367b92e9ae78e12696c63dc58dbda83d.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 08/20] kasan: inline random_tag for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cMYeDNAI;       spf=pass
 (google.com: domain of 3lkgjxwokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LkGjXwoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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

Using random_tag() currently results in a function call. Move its
definition to mm/kasan/kasan.h and turn it into a static inline function
for hardware tag-based mode to avoid uneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
---
 mm/kasan/hw_tags.c |  5 -----
 mm/kasan/kasan.h   | 34 +++++++++++++++++-----------------
 2 files changed, 17 insertions(+), 22 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index fe8e6c8e6319..d5824530fd15 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -38,11 +38,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-u8 random_tag(void)
-{
-	return hw_get_random_tag();
-}
-
 bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e9c7d061fbe5..d7a03eab5814 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+void print_tags(u8 addr_tag, const void *addr);
+#else
+static inline void print_tags(u8 addr_tag, const void *addr) { }
+#endif
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
-
-void print_tags(u8 addr_tag, const void *addr);
-
-u8 random_tag(void);
-
-#else
-
-static inline void print_tags(u8 addr_tag, const void *addr) { }
-
-static inline u8 random_tag(void)
-{
-	return 0;
-}
-
-#endif
-
 #ifndef arch_kasan_set_tag
 static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 {
@@ -275,6 +264,17 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+u8 random_tag(void);
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define random_tag() hw_get_random_tag()
+#else
+static inline u8 random_tag(void)
+{
+	return 0;
+}
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f51b7247367b92e9ae78e12696c63dc58dbda83d.1604534322.git.andreyknvl%40google.com.
