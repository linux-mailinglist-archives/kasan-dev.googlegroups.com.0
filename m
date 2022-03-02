Return-Path: <kasan-dev+bncBAABBYV372IAMGQEMYQWCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F9F94CAA95
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:40:03 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id n31-20020a05600c3b9f00b003812242973asf1016624wms.4
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:40:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239203; cv=pass;
        d=google.com; s=arc-20160816;
        b=lyzwmL13lZd1qR+P5jrsqMniU9GeGQI3BW2ml6Se4mmZ+BSOCCV/ERbpCz68UrJ5Sp
         CYWKrp8fsGkYCG5mJWBUQetF+wjxuFGY5mnRCk3QXjgVRFmCNuiu3r+cgiJQ20yGsdAr
         watPBocuSTd1+mthYZ+uk0bep6PyTsClm2zw24ini3ly3AFbI6dAUi+Qu9eb8tO90DuR
         NlcJwV4mlsVntZ0mL+SVUYmfJZYchGT1vGvm+FjNFbSJcm58pf0EnaaZJFZ4ugaHYCQN
         yCyov7K0ybitRvz4L8A22iJL3VIoQw0HjRdWLvyybOKBG0kbGrR+OE514ftuDj1iqAmo
         GD0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OIgo8Jj9qhj2CxFLjXCCEyaf4BrZz8mant4gPLfWZM0=;
        b=m+FWPK0newdCtYMUvz6mWP178gkkakCTeC7UJX0Ghobj/z4fgPaUtnGR5411mDyAIh
         EGqsx3Z8dJsYi+c4v6Y6jxRCRaQ8lTA6bHJ0qnfjkvXceiVfOHBdxAW329rgsouYGGEt
         TGZmv09JpOmlBaBVkiJIjL6vQ8qKSi7hN/NxmPvzAw44PeiwwWWs+wYSUP4s8MIXsevK
         LQwhSafRFHcZ++vgItJzX98g6vbgXprCcPLgCWauip7frI+NTpCY+CVZQo/07nQa3riN
         mXO7eEK6pY5S6oKgv32rh0j4+n75ikRlOdBT9+fC2Es/9M1WNV8wQFDEqvL+qaXLmsY2
         7GWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d1ASAWaC;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OIgo8Jj9qhj2CxFLjXCCEyaf4BrZz8mant4gPLfWZM0=;
        b=VVUsCUXnFVyw0HZTGcTqpcKWgkr6+vc3kdlvH3V5YT004jIOs3bg5M/uC/8NNu9rnX
         TJbvkVfuX9FCssmhls3axW6CTtqi3VHo9napRn5mkkBvZ2c6sfiWNldVMdmKQVpkSPD5
         oAvnUXtx1vHDdrwb2OV+jY1r+JbFrgXdKd2lrDR1Htq0OryprijBcbbqdobZWCJx87N9
         bmHlSQAftkclgX4dH/jGuYM+kgb5VAz4lMwOCMdtJvlyJDbHvRvY2wR4Q55uNpMB222b
         T17bCmNlCUVC4WyeukvK07QNCVN2UWiAAl+mNLmLzCt17suBJXSC0rsD3q6TpdHvsZXK
         WJuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OIgo8Jj9qhj2CxFLjXCCEyaf4BrZz8mant4gPLfWZM0=;
        b=NoONaf9ru3T1ZckvYkpUL63ZxVpkA1x53/ORLVvLgxypc/h5ZR6O5JgAMtuT6GGOMS
         Y2vOyNkHfzOkds1gM/m2T1L2YUS18UV6l8x5baX8lrE2pcSw6ekH5Gb4x1i7iPiG8brx
         EKJWKXobd6DxlhfyIAckO9W0tuZ1Nt62Tq5H0+/MXl2CdLQKvy6rtMR0diwEJliMAFJ7
         jG5HjwDGkxorI+QuWsEiWOI+K0ghuggpvnWMpNTsJ8+6TOr4YZmFmLVhIxv+YeWYsF6P
         xzZZFsqCRocc3oZEqzFkYMYJEkR8fChmhysHz1BIZHU2kHdi6LUaNLJSx3EZhlukRfM/
         4Plg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XH2bsWJvWe6tLYFPuq3/clGdg8AqUq7PQUEwRtL9sRDrSPaW5
	27opgxolAf8ysjRRHTcTOZ0=
X-Google-Smtp-Source: ABdhPJwyl2OpX96PRbybSoTOhD/4UpiQJ5rDft5sInNFSxdTJ/QQoMusoBRA6ZxexdeMPBrgaWRayw==
X-Received: by 2002:a5d:62cd:0:b0:1f0:23d2:b38c with SMTP id o13-20020a5d62cd000000b001f023d2b38cmr4601176wrv.82.1646239202816;
        Wed, 02 Mar 2022 08:40:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6489:0:b0:1ef:d725:8751 with SMTP id o9-20020a5d6489000000b001efd7258751ls706377wri.3.gmail;
 Wed, 02 Mar 2022 08:40:02 -0800 (PST)
X-Received: by 2002:a5d:534d:0:b0:1ef:956e:320a with SMTP id t13-20020a5d534d000000b001ef956e320amr14205842wrv.613.1646239202250;
        Wed, 02 Mar 2022 08:40:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239202; cv=none;
        d=google.com; s=arc-20160816;
        b=eYHZG7a82jCpfmfxvI2PcUP39NUIUNOalLeaUQzUx7SZjjVGQ1K9mINgTILizHekGI
         VFiniuzH2K+b5ffudoDOz+0PGGaiv7u30ND6oQtb1ix3D0LpCZDXUtgKgZ4Ir2c85PFI
         KF6WkgiyiQlz38fpyYRqoKlURVrtKoghg5HlIF/TpcXvuHPpeL08/dpyx99OyHouzkhI
         AZU4jDzW9frP/Nj9jvgc6mNkDzfIupYuzXqeFhLRltVXS9TyiMyXz8ESjJlYc6cidnn1
         7HzrE8Xhnjpxz3mTjGtUC/gGt/ka+P9EQrcp4y8MxpsT27gSvjJ5jckZ/Fmm1OlB9+Xb
         /klw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=87o7sANrY5Obyuk6ZGRgPFc8t4HBbQ7LJJT+IQadP5M=;
        b=t74Civ3uUgFEgSiMTMlzocK4xOuM7RW5IUMq4VnMu5+kGblH4bjrfLw+zSrieUn+8Z
         ov3J9KTd40drHRUASLRHn7tPeuxgMsqfBZqKmBVYL/TiZkeYlQpykq0PZ4/DRaCIj969
         u6fZs6l0nMQh3aB+lWRgmS9n0Hem3D4GwDeQ7er7/NoRDjahIh+H5n9f9yLMg1q3Novm
         BtXKmsAheAI3KIcBB+2+/XulnW0aTqdAAyogD3j/6CG8mDPPjateACO+TnTC3ESCZ70n
         wT0wR3vxJq5RLeUcLjnR2stE2yWqsVWLwtbZCUaw4jzDwrY/aK0U4wqVXQBBJe2WvZm9
         5mIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=d1ASAWaC;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id u1-20020a056000038100b001eff9a5b12bsi405637wrf.0.2022.03.02.08.40.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:40:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 19/22] kasan: respect KASAN_BIT_REPORTED in all reporting routines
Date: Wed,  2 Mar 2022 17:36:39 +0100
Message-Id: <715e346b10b398e29ba1b425299dcd79e29d58ce.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=d1ASAWaC;       spf=pass
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

Currently, only kasan_report() checks the KASAN_BIT_REPORTED and
KASAN_BIT_MULTI_SHOT flags.

Make other reporting routines check these flags as well.

Also add explanatory comments.

Note that the current->kasan_depth check is split out into
report_suppressed() and only called for kasan_report().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 35 ++++++++++++++++++++++++++++++++---
 1 file changed, 32 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 08631d873204..ef649f5cee29 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -381,12 +381,26 @@ static void print_memory_metadata(const void *addr)
 	}
 }
 
-static bool report_enabled(void)
+/*
+ * Used to suppress reports within kasan_disable/enable_current() critical
+ * sections, which are used for marking accesses to slab metadata.
+ */
+static bool report_suppressed(void)
 {
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	if (current->kasan_depth)
-		return false;
+		return true;
 #endif
+	return false;
+}
+
+/*
+ * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
+ * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
+ * for their duration.
+ */
+static bool report_enabled(void)
+{
 	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		return true;
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
@@ -416,6 +430,14 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
 	unsigned long flags;
 	struct kasan_report_info info;
 
+	/*
+	 * Do not check report_suppressed(), as an invalid-free cannot be
+	 * caused by accessing slab metadata and thus should not be
+	 * suppressed by kasan_disable/enable_current() critical sections.
+	 */
+	if (unlikely(!report_enabled()))
+		return;
+
 	start_report(&flags, true);
 
 	info.type = KASAN_REPORT_INVALID_FREE;
@@ -444,7 +466,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	unsigned long irq_flags;
 	struct kasan_report_info info;
 
-	if (unlikely(!report_enabled())) {
+	if (unlikely(report_suppressed()) || unlikely(!report_enabled())) {
 		ret = false;
 		goto out;
 	}
@@ -473,6 +495,13 @@ void kasan_report_async(void)
 {
 	unsigned long flags;
 
+	/*
+	 * Do not check report_suppressed(), as kasan_disable/enable_current()
+	 * critical sections do not affect Hardware Tag-Based KASAN.
+	 */
+	if (unlikely(!report_enabled()))
+		return;
+
 	start_report(&flags, false);
 	pr_err("BUG: KASAN: invalid-access\n");
 	pr_err("Asynchronous fault: no details available\n");
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/715e346b10b398e29ba1b425299dcd79e29d58ce.1646237226.git.andreyknvl%40google.com.
