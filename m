Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUNQ6D6QKGQEAB7ZV3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 43D112C1571
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:14 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id f8sf14918404ilj.18
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162513; cv=pass;
        d=google.com; s=arc-20160816;
        b=GM4AE0t9pOPoBB4qVTJyfZb3YQ9S57hUTHVT0HF2ad0GOQb7jRVcG59roqeSPCb9Sv
         o5wWBQ6CBz7W5tib0314bEgjVvm4/JXAWEpoyv3HD2VAiix8hCDqPUMc+UP0I2CGzlfD
         iRVjXbcwAs3P2oNfykeeNx76YoaNSYfij1ce+nVPBOQOPRAvfzmmt9ICVlwnEZNNOQs+
         DoRS1eFXOdTZrWh1hvazQjLAvsU5pA5Hh4xzApd7w2KBVEoC4oLgYiXNl6DzBuvh3lmV
         X6wZmWIiLHfQjS64S5HtpJgOoKb5YV5cW+0fQGrlF84+G1eQ/H8Y63zGA5EkCX2ZRGHs
         19Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=9G+wn9uKm+kYJma3x7v5wEkPSvNOheFDijXlCV1eRVg=;
        b=djE0jgSeXtcYx1LQM9B25hgQkMIymWPtgHkghmocRqnXuIX6tihGZaur/sL5fAL/eK
         af2Gtj/NH0sNjxdQVwjaVpjgzZg+hYHyPEIgy1pMX/4c+lwlX824wpLzA0zEk+ce8D0t
         GJT1hh6faES/jt+QMT81IOPiwupbTATCgS/zLMpyrV8lRL0gpRaoGT/Cc45Qr7waFhsU
         HYPQPJGTRuN3ahi0HVVkjjmHf2NYZ8xHz3n62Y8VsFVWJuj6dfJfV/Y+a5wXw0dAFveO
         FYAfAwuhUznDnf/yeVVdlXXWkF6jVYHWJ0ewGCGqkTeNwR2ZXD5fobrvQxZpjNEqSaUD
         ILyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nMsy4P1z;
       spf=pass (google.com: domain of 3ubi8xwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3UBi8XwoKCXUTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9G+wn9uKm+kYJma3x7v5wEkPSvNOheFDijXlCV1eRVg=;
        b=p2JVH3nePUapYPsveinnc2LRCM0hGFJbD9dzxDrnaRWdEFhhosO082iPKPdGWiPWyV
         oFh//JlEBmBuoWeUBtU9PYtTjGyei66bjNo+yedVUXUBurxdSQC2rVXWDi18rAIcqdBn
         njOEzKJKkBNzJxOz6VThSwg0xWITyAPT7GqMtGAHDHfCfJw9r2w9gdXE8VIwYPKTlaI6
         tAoAlAsNv51LvQC2jUn0g+5K8uc5zX2MW0YoHag9Xn/WL9pYqlQbY/5SYBaMyJjVjHeU
         8XB6HYxaajo2DOnZPPdMuRbu5e7084raYFmFsfEdP9TuuFYqWktPISzu1zj20ZcOTP92
         KV6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9G+wn9uKm+kYJma3x7v5wEkPSvNOheFDijXlCV1eRVg=;
        b=sY3Sq4t+mFlIOWjE8Iz3l4cBJ9/fVvq9dx9EnchT0wpbMqOHvuQxei/7Ny0zz0SXsN
         bMnAKD4BdhzyZ4f00ToVldnoKdgL9Z3y5gHLbe+dn9f2mBDoIm9KNOeiDhU5HztQOhBa
         5sEMbFW6Zrm8HU0ofeOHRcTFKledx92R3hYxpu27+jad9LlGMDYJp5vLPr+rx1vRuqOD
         ZcAHRfOmQ3GN/9cNeQ5ePQ+mdzTHCX1qL2JmP+AzfHiySVv8Xmo2nZ4jwUcK0uDv8IKv
         DD16drTPYK4HExmwua9wTv6VVQH2Klmp6LKGo3Zt7SCCBkpdN36gbcHUqKL38RnLKCcp
         bUrw==
X-Gm-Message-State: AOAM530h5q7s3pb184KgPZeIYtVg2Jy619d12+HpgRX9fr6yrJq3pC6J
	Uy3DpPAzAaWYNSB1bSm0MAw=
X-Google-Smtp-Source: ABdhPJxY8sFhvTbjmxOrgDft25WZhS1HLuYKl/b54Nsne6/EJJjwkl1cVXk++N9iUN937WYwwu1MMw==
X-Received: by 2002:a6b:610a:: with SMTP id v10mr1233048iob.206.1606162513322;
        Mon, 23 Nov 2020 12:15:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:914f:: with SMTP id y15ls1671244ioq.5.gmail; Mon, 23 Nov
 2020 12:15:13 -0800 (PST)
X-Received: by 2002:a5d:8617:: with SMTP id f23mr1250512iol.174.1606162512956;
        Mon, 23 Nov 2020 12:15:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162512; cv=none;
        d=google.com; s=arc-20160816;
        b=b/iXmjyKe2aGEehIXffINKi55+ddH31s9NMvGzJIUpZk0l+WbdnlYQLIodp5YZ66OQ
         yZ7mEBjV6CGPmb4ouHwwVhv9iH3I+POTtEL4wJBZkyNOz6DcOpoqIwE29PtpgzYGYCl8
         UHDdenWE/h99e6588p6eECwVFo/S2gsjg4EgeElUMT+OWUjIs8eW4xJYeYGf2ExU0ZRy
         K9oanoauE1/hG9MKTkgg4/2iVYoPR8w0sFveyBOwOGduUKWX8ktnBFui16C+loUn7iYL
         +aKSnJc6iFPhYyPBlTuoXtJw2Up2bJqJa0jg6jTPpvF9J6fYi9kxovYkopMc6fJUpBtR
         BEqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+ebVro8WhZiLU99JJsnZ41QIjsbf3l1QeUgTEZT5fwM=;
        b=ePNmHa/Mdhy3YfYmjK1uw4wrRaUiJ3DGEzmKtteYV92uRSyo133ZtarsduM2sP2/tf
         ls0jfJsz4ZlkkC1mlg/4k1WeoeCk0yR7xllyTX03lcNtlk6yS3GXeLUQjU3vWmm7KQKd
         y+Riip8ylnBbScvXernv9BmON7XXIqN4UDoKkZABqw49GYernkXq6vkmLQq8Q5dH+9ij
         vnBQjRoULStKJqWGmJSMtoUFG7ImHthZDrvIkUZhPQx8F0W82RX3ZXuBdquCOZNru0xv
         m08GseieX1V9R/hPRKJojY5LeZHM9zh07beSoPWgfc2IN8cyFGzhlRitak2q0mq2scEp
         zC1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nMsy4P1z;
       spf=pass (google.com: domain of 3ubi8xwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3UBi8XwoKCXUTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id m8si576091ilf.2.2020.11.23.12.15.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ubi8xwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id e13so2555214qvl.19
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:12 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:aab:: with SMTP id
 ew11mr1176833qvb.4.1606162512301; Mon, 23 Nov 2020 12:15:12 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:38 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <be438471690e351e1d792e6bb432e8c03ccb15d3.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 08/19] kasan: inline random_tag for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nMsy4P1z;       spf=pass
 (google.com: domain of 3ubi8xwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3UBi8XwoKCXUTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
---
 mm/kasan/hw_tags.c |  5 -----
 mm/kasan/kasan.h   | 31 ++++++++++++++-----------------
 2 files changed, 14 insertions(+), 22 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index a34476764f1d..3cdd87d189f6 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -51,11 +51,6 @@ void unpoison_range(const void *address, size_t size)
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
index 5e8cd2080369..7876a2547b7d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -190,6 +190,12 @@ static inline bool addr_has_metadata(const void *addr)
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+void print_tags(u8 addr_tag, const void *addr);
+#else
+static inline void print_tags(u8 addr_tag, const void *addr) { }
+#endif
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -225,23 +231,6 @@ static inline void quarantine_reduce(void) { }
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
@@ -281,6 +270,14 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+u8 random_tag(void);
+#elif defined(CONFIG_KASAN_HW_TAGS)
+static inline u8 random_tag(void) { return hw_get_random_tag(); }
+#else
+static inline u8 random_tag(void) { return 0; }
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be438471690e351e1d792e6bb432e8c03ccb15d3.1606162397.git.andreyknvl%40google.com.
