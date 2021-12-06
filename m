Return-Path: <kasan-dev+bncBAABBHEJXKGQMGQE7PPRXRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F94B46AAC2
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:05 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id h40-20020a0565123ca800b00402514d959fsf4403493lfv.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827164; cv=pass;
        d=google.com; s=arc-20160816;
        b=NgPD3Z3/WF7O3PYuOC2iMrsrJvaDenViMXl8pL2QiB+zRfaQqi6xf2ox9zLEi4BHUy
         GQzKW34XAi+XxeIwtBhUe6wqxfXl8n4zeUxzPRNNpXikHa+VHYBbElJ0zGCtOIjQN2T/
         WTzvJXFFYzEC7tSBEVFT1xKVOegjaYxTu44fImY1mzzr8Y+SH9cS/plXmXu7zSmzjJtp
         dX4i4U4Tc70anpANy2ZaCPFtNc9qZ9dX97oNIkdsZXLBXkVFu1+kThbvyOvDPl9BSahs
         G1gH1uQgxPDH0UikmEiUQLY9cHVtpIURD4Xfh1WY53GPgo4juB/kjhKg89455BcaOO/h
         +oFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wnt8x3Rg/Y4cSCPm1NkADo4x77qAbd6qzPz4J3S/Nb0=;
        b=Y11M7JuBeO5PmBeNBeN+noNtQeojpn4fcBhsOEjRsWJfp4f60Ch9+4H1OhEw5paCoR
         bOyTBccehPuKoH/O5I7hBFnC4CxfhbyVxoc6gqf1KcgprsBpqcObduWC6YWSsQH4914C
         iWufgBpyfqvjDUb89XhjRoAx0xlIcdlqA+gAtRYtRi3jM30RNZsFPijOnRz/KZTnC0CL
         Q0mWfG4eNlrXX8CqXTICX0U48k0dpnfSc/jctT57mkKrlXYvbWdz4YFkjSSS5qwDQswV
         G3B2aIQf3KRYxCJYp7pgS4kGyU9bJXOK+Xy/khRPdJjYPjl49yfjOlNhw+DN+SwJYDe/
         wVfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BAU7QhMX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wnt8x3Rg/Y4cSCPm1NkADo4x77qAbd6qzPz4J3S/Nb0=;
        b=PGyQi4S/VHtE1mt/aluiJvgTMuhm1l7qzu64H52I2Tigo+76CthTPFYYY+eUNGpK/j
         /d5zM342GCdtxpaQCzWR0NWbz1ovYtRlA90K70WH6REv1AEmKMTGUspuX/MtUdN6R/Ka
         LY6/a9opQ5ByFfnARcEfHXn2IMKH9Zi+z8o1RG3QSXJYsL85udZ9qOqfubBBWa+/fqsE
         4cW1vdPP0UTAhRA8wns/1Fpw01tsRw2h5w1xyOPDxifnUA8BZKQbsuYXrjdnrSataFVz
         93kNuzMqYUL77FtpFxfYE6ZcJi6G10rIbd0CYIlka//IwRN5aGbI97dz0vdqYhx5Wbj2
         evbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wnt8x3Rg/Y4cSCPm1NkADo4x77qAbd6qzPz4J3S/Nb0=;
        b=ZN0Cr5A+wvHaK5M9/GwzOrMM4qPELtzKUzi2VX6j4juohHlph8nr/BcW+cu1KPUDg6
         yEWJ/3gxMNRpYtaCpnGQgUx+NKr7m2vz/LwVUf4S3flXBzNx5XMMbNRcSxuEWSKYK7hy
         YNRwQKuVqNlCztUQiEd60Q7sNVKc9c1UjUMyCTLr5RqN/V3YWmvZXjs5GY+b6cwHmoCB
         L7KBVaUZfjxQm+6Aau1QOqxke5w5aIqM7L7B2gWqAGEq5YfraQuF9qrMkEALSimYdnHQ
         f4Hz0AsQzvZJeJ5+iLb0jn++cOyLJE6k+sK4CnWdH1O6+U0vfZ0wBwp6qvxdPZ1Prwz7
         aJaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338xOU1r2owAG9mfzRAziLw/OHwiicDrdxP2VeGCWZERLkpdKFt
	rLoVSUBZ2MIm5Of2jxiNqbY=
X-Google-Smtp-Source: ABdhPJwCM2wbQosx8w41xvVRD882LTTIQPvfPym6iOb8YLLx0c48h6Z9GxGIezFQB6aR775CV2SpeA==
X-Received: by 2002:a2e:9a41:: with SMTP id k1mr38657724ljj.147.1638827164766;
        Mon, 06 Dec 2021 13:46:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc09:: with SMTP id b9ls2823902ljf.2.gmail; Mon, 06 Dec
 2021 13:46:04 -0800 (PST)
X-Received: by 2002:a05:651c:205:: with SMTP id y5mr38135887ljn.386.1638827163942;
        Mon, 06 Dec 2021 13:46:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827163; cv=none;
        d=google.com; s=arc-20160816;
        b=nZW4Dx6q+BKYtBstMw15FBdPkbXGzk1KTCvuz3kYgudlwWThXWiH/0r6iIWfyIZHlU
         8IhdWOzWZaUWC5f0t6/UHkeh0yGWoR9DP6E+RZMXl0Khe9bd1b+5tzmS9tE1TfcErY2Z
         384v29Q6WjJwAFzzWpxHevasqBQr234o2V5xJ3ji14kmGVV7mmNR+0IOLSZVMazwEKl4
         DIz7V/FZyGyuoRdVuYyDEXF55IgbY80qZPeUTIyobrBnDKqAy5WA3qSiEbv2EVLQDyof
         QKi9r62H4bxHaTGhLbZPutRcps/2qYbj/SThCw9F0hc0Ja6t/sKK65NFvi8IR+yy3RJx
         W4Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=n4gFh8zlpMsEgMrbMj+8ISQjGusuzX7sFY8iv+MHRNk=;
        b=Rn2SvP9KUcbUs47w/a4f9/kCjIdn9Gj6FnmsOo/Nx9LcD+Ssxe2LbC/kC1CIc8Ewv1
         J+LUIJtFCycgCJtmj8HrR7RTrU/RigliOFrEmDQPxeDu49rJUNjiXpSHPDFSAbyhW7UQ
         tq5KA97hTCBu6vedDGOmAccsqcf9vTLjn/WzPBeDYAjgWrx61Q4iNALmcWhEkLMyBiD1
         UidQOC/97ijvMVHQ5fgEZ7u19JojARx6yjzgJWu7UgLUoBoRQmB0xXQzPztH4eug+nKO
         SNh9wYUCeUlZQA7Q+F3sPewxgYEySN5Ci6dXxaYf9cQwHNZqYAGLZVu1hplmerv+yY0Y
         KGWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BAU7QhMX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id d8si802402lfv.13.2021.12.06.13.46.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH v2 20/34] kasan: add wrappers for vmalloc hooks
Date: Mon,  6 Dec 2021 22:43:57 +0100
Message-Id: <8944b0d772ed776b3d79eb26ed1bcf6888b0f378.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BAU7QhMX;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add wrappers around functions that [un]poison memory for vmalloc
allocations. These functions will be used by HW_TAGS KASAN and
therefore need to be disabled when kasan=off command line argument
is provided.

This patch does no functional changes for software KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 +++++++++++++++--
 mm/kasan/shadow.c     |  5 ++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index af2dd67d2c0e..ad4798e77f60 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -423,8 +423,21 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_unpoison_vmalloc(const void *start,
+						   unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmalloc(start, size);
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_poison_vmalloc(const void *start,
+						 unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_poison_vmalloc(start, size);
+}
 
 #else /* CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 49a3660e111a..fa0c8a750d09 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
@@ -488,7 +487,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8944b0d772ed776b3d79eb26ed1bcf6888b0f378.1638825394.git.andreyknvl%40google.com.
