Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKVA2LUAKGQED7SFNMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 57A2C57F83
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:45:15 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id b1sf878847otk.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:45:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561628714; cv=pass;
        d=google.com; s=arc-20160816;
        b=R0IcaLqpoVq/srR4aLU/j9XMxgAnaQBkPdcQ1lOZKGKOxx4Ed8nX9keVIdwmkgLM6/
         u3BoeqCpcxHht8BN4MNSFNXFGgFm+HXEhTayGiiupBmyXPWzeRYTVj7dbYKVvTtGVTo2
         Xbt8gDG7VemUXGYwikUj7leNQb13h5WOAWYazWKofwHxZyZbSPwL+5aTtc+6dg6S1CYG
         GMlX2/F0zxiQ+pg+C7/eMsJNrMJxr9WCbrAWMYQBl5B4WvvPh3ace9wsRZLl8hydm0Qx
         Gr5ftV9qGPUeggBGdQXqteDPTWYvHFGwUZiGxWOtYOrJbYqhP2Ep9QLiP0i3wvlQuK9i
         gBnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=maF0LgSmjqzx1QM1IyRs04MycqilNXRhCRG/jZMRrbI=;
        b=NPOgnOvLQ0FIfPxGJV6Xz2p80IA74RySAjDBJ+Dw5uPH7VuB4sPyovXtL0nhyyRJod
         IXdqFNQ7w5oTuKp2wYQqyhWAQbxxfrr5xKuXLK/kat51cSxCygB+2YuHuc+PKRiyu4Sz
         s7wLAqm7tlYNTXIL7/oawzS8CM9nyYeT87mU8dbyDyleTiPU48srZq8Xc7XqEu9AsCoN
         OIgVOh5IajajluF/80eGHmau/WRq7wkYvUyKC4v0wtEssh1gjQLEfnAq5CPYgnqQQh+V
         /w2Ka++C+oWyFRJ6w+YqAmG/Tqb6bE/HSOUMmrigk+iHghHCxxtjSKalFVTCxw0p6KBH
         KE1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J0Ci+Hl2;
       spf=pass (google.com: domain of 3kzauxqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3KZAUXQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=maF0LgSmjqzx1QM1IyRs04MycqilNXRhCRG/jZMRrbI=;
        b=fiBAbJ0hedKhSurfOPxeYO8fo9hDiJs/EhJ+330KJHwUYPc5cXDbGzm18s56JgMZ2p
         iDivwR1wZjoZ4FYyu1hca1rXU4RMkjH6+5kOiJUR2jN4Ui0Auegl/U48q/1+v2sf4400
         nRTF+YQcSCjN++dvu7n3587Qs3Z/N0E5k9WthikMG4Ba9E2mbyDgm7xPnfERuMRryT5c
         XM17m9js2rjzwnyKkxTZCULvr0Uvq0n+mdep3rLdvQhVgNrkaOYTb1Nf7TeO8CJ7uQw/
         yJY+B0+COaT2N+SRuHZ9OcU5D3rKBwZH/KS58s1Ze9op9czDLhAf0bAHv098Rk+MoDZu
         zH8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=maF0LgSmjqzx1QM1IyRs04MycqilNXRhCRG/jZMRrbI=;
        b=guE9mqi6Jz2FEPyY+HJjmVJZ5Ku9ZSk4S0skd55LZYeolJAnC2zIDufbKziE4iLkUa
         lf/gDbeqDJ8+gu536U9c8hhbJIEV4K6nYoetNhVCArEsujRi3TdbTW6hsZIzF4BCzw/c
         oQRBBBE2vAwQLhDq2GNz2o7p1ELgqoiTdtIgVNkdAXJUC1jF1KTEdD+bdSFjcgo2tQex
         Fekxs5Z+vq2iflcDzWKAPn+EMlH/rJPiQ5Ytf0QT+1/B39X6nx/83thrb20oPQGVbB3F
         4bqPmG4/yu1BlalC+Ze8QnWLQqMi65urFdDKo3gqz8JMXDg7XqWsmbSr4PNZ5Gls1ND6
         +Xaw==
X-Gm-Message-State: APjAAAWAR9E1QuPJt7ZyL/FVASCSLHlkdWlw1FRImoVmeurT6vMXbP2H
	QWKD7f1LX332KYGMRqzlD8M=
X-Google-Smtp-Source: APXvYqzJPI/9tKTATvtzxN2sGTQmGHXEC0ocFtLFh4iQ9ysRczre7ZaRTtG3zte4yIkwtbW2cmcZNQ==
X-Received: by 2002:aca:c795:: with SMTP id x143mr1645518oif.50.1561628714053;
        Thu, 27 Jun 2019 02:45:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:afd2:: with SMTP id y201ls305124oie.7.gmail; Thu, 27 Jun
 2019 02:45:13 -0700 (PDT)
X-Received: by 2002:aca:4306:: with SMTP id q6mr1704847oia.39.1561628713734;
        Thu, 27 Jun 2019 02:45:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561628713; cv=none;
        d=google.com; s=arc-20160816;
        b=Dq07pGsVm/Qlzjgxl0iYXpSeWDDEcHTGPI4TWtiRcIRePkRgatQ6h0F1pgivnHurlU
         eTNFaMxvXm9ttaw4FIvrI4eqr2wgQbSK7hW1lOfqZOORj1HQ+W4H1jDVnsxUgzKum+re
         EKAdnY1u6HNVaFEQfGmZk/gTsWC+Vnstv4YzXmJu5JNV8VVL7fQ1gAtIcFwpcCE+Xfz9
         5ooWRzKaP/fp6M8X5QlB2Q7t3uwXOudERXPJ0V/blPbLqNQ4S/5BsisM+LGEJWz4kJIN
         HAarh7C33x77YTdbqjldT0LNs5fCrF6i1EnHbPBAGE1f+ozxqGASs/wE2p7h9n9lGPzX
         3whg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/Bjb3ErsQTLw+YrlSLkjBcr6K+fvu3f9fORDBwR/vbU=;
        b=OZR+q14u9dDxuUjgAM2kxiqJ/h7MIAHmwtzV4xcYIFOOpORS0Xs2jb0s6a394RKGdk
         1buvOjjzSGOsIRWtIn3CQ2I4zDVIQ/xxMCv+CBye5r7tFskBADvdarYcmTL8CSTkQTzA
         oBIm9jH1ymWKetEXmSliiRLn3Jpdh2zTCJHLegKjCHvr9eGyAMaSY0Q6G2FgnvKlTwS/
         W6SfrCyldBX4Rv7SbP5/BskXInyOoGY9JPBVgLEwEvqcCvlL4nvm+Jd6kjSGxrKrnF/K
         Q1HSD1RkbPX5IbOTAofJzGP4vrgWwq2yxQ5wCx+Q/+CCHcC8M01wjpW6cmR+qbTenfxH
         vL2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J0Ci+Hl2;
       spf=pass (google.com: domain of 3kzauxqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3KZAUXQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n67si111950oih.1.2019.06.27.02.45.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:45:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kzauxqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id c12so3238744ybj.16
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:45:13 -0700 (PDT)
X-Received: by 2002:a25:9a44:: with SMTP id r4mr1814342ybo.393.1561628713265;
 Thu, 27 Jun 2019 02:45:13 -0700 (PDT)
Date: Thu, 27 Jun 2019 11:44:43 +0200
In-Reply-To: <20190627094445.216365-1-elver@google.com>
Message-Id: <20190627094445.216365-4-elver@google.com>
Mime-Version: 1.0
References: <20190627094445.216365-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v4 3/5] lib/test_kasan: Add test for double-kzfree detection
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J0Ci+Hl2;       spf=pass
 (google.com: domain of 3kzauxqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3KZAUXQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Adds a simple test that checks if double-kzfree is being detected
correctly.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 lib/test_kasan.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3c593c38eff..dda5da9f5bd4 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -619,6 +619,22 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kmalloc_double_kzfree(void)
+{
+	char *ptr;
+	size_t size = 16;
+
+	pr_info("double-free (kzfree)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	kzfree(ptr);
+	kzfree(ptr);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -660,6 +676,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kmalloc_double_kzfree();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190627094445.216365-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
