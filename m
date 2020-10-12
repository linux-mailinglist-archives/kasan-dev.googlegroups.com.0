Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4EASP6AKGQECDD2PTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 12ADC28C2FC
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:38 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id b2sf12581809plx.7
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535536; cv=pass;
        d=google.com; s=arc-20160816;
        b=SNZePm3TK5AzhkKAepyXSylSzfLz0Ivi3vdUVZiWeLjWhJuystiT67zzWjbMrw+NUU
         vXsqBhu0qiZ+3qQQd921A2cX+f1vTftSJWBsMcuWukBvklLRpY241a5X4ami648oCxV7
         vae1dnYgqau6ag80r8fwMppv4zQf9DzOHPoklUAx4dzGt0w63JgdRVTlln4KvHBoS4dI
         lvtlVh+bpl0uXCxakNI4rQFF74uAyj2qNikPfQvb6Cw0P7jIPUypEPHW0TMgP7WYDd7Y
         x3Zg0gzkCw24gdL9ilpxojWcNklh/HGCTcUkTPJc2TQnjFRkZejsF1TwPIR5ZM6n5ZH2
         jv4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=01ANpjR0yZPAA/vE6Jo1kS9XCmu4IjOhsRr9GU7q4OQ=;
        b=s/uU64DZ+qMjna0RdgLSabZxL3sMSMFosa2WXR6ll9+Mfy9X++RuWo+hEvglQkr232
         QW6juyCj8RoAFpLw4VgW9xAMOFPV5SyiZZ1qBtOT306Tj6d2FDuR7QrrJH+brETMVj9U
         sGCiWvGPfgRo4uJb+Y+Q3B9dGSDQ88PfiCahgL8pL01bdeyc/Z7xmHr/iZu/wC+zod0J
         8w98LKOpoH8iS0T6muDDXr4SbUwcV8yNLpCPIFgAcdOCgR1zDr0XATMdudfFqM7W0PoM
         Qos54ftunnJICxFfNc35IRqIlnj+pMQuUmr9JvQheFyA/ibDAX1aIDSKYZyL8OVbPCBd
         qOZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f0hD+Xsj;
       spf=pass (google.com: domain of 3b8cexwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3b8CEXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=01ANpjR0yZPAA/vE6Jo1kS9XCmu4IjOhsRr9GU7q4OQ=;
        b=alhS/gSk0WbhckfzdJyhMcCokBtsuTxhrYlVCf6+bVdyB+Q0Hhx20BFu3vqvkwL2ej
         LJLgUL/W8Yh1mLe2LH0+hwyYWa+ShRmoYmCaxheNzFU/lNLiy8fqWWAH9ciUqANDdCdL
         TFuuv3dHvsaRotWi1u8nWPve30FNPz1vP9aRuTK8WesKSfuXjTnCul5MCiSPDTi3QoTN
         741dfZIH1pe4MQi8hM7UOCIhQVVLaDNu2QVZHE32nzHe8n0DC9XXh3v/k0Yq+rjM5Zw/
         yaRhIQiKmDM+hfHL+4xgsGNlgjRNggFWiTlG8JW7F7mnB16cz1MN860zK6/fmcvnbJLs
         tjQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=01ANpjR0yZPAA/vE6Jo1kS9XCmu4IjOhsRr9GU7q4OQ=;
        b=Xl+bGpE/KEcfu94rhK77uqYEvFiIdkz7NOLtk8swGglmogdQdhDgy/Tildx9l5Cskl
         G0p4h31PCeoHlXtXi1lm0uA4e+wnAdvKHYeTljpzSqateb6pVyM6U1rlu1rr90aad+oL
         UwBuMqpd0ljsHKtPwcNKY06GZJHn72YOgR40oWK41m/tKjZSDGClvMv11ohqvuAwuk5F
         wwbZBLWRiTpdy6TvvnNRA6EJoxhR0mx1TG+LgDDcixvbGn/uEx5kHFb0+juqD/wng1p9
         Qmc8LvEWPHCo+4q4OBUIUuvkMURQifru1dn0mXHM6KfBOUfn83OnI6oqe/QmCR8UNywS
         aAew==
X-Gm-Message-State: AOAM532qhsWNNWoziLObysCxERikZH6dK3DQMTO02+iTYIZjM1qByJqx
	rFj0xa+9cmu76WVO8xdLmSE=
X-Google-Smtp-Source: ABdhPJw1uE49vJZCWUhEOtYo7CeO1wc+xwHI/rf8qc8o7stqdvZeDt0OpyTh9GXJdoSarm8GVaSUTA==
X-Received: by 2002:a17:90a:804a:: with SMTP id e10mr21405407pjw.218.1602535536754;
        Mon, 12 Oct 2020 13:45:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4706:: with SMTP id u6ls6038898pga.8.gmail; Mon, 12 Oct
 2020 13:45:36 -0700 (PDT)
X-Received: by 2002:a05:6a00:44:b029:152:8967:1b2a with SMTP id i4-20020a056a000044b029015289671b2amr24524116pfk.48.1602535536140;
        Mon, 12 Oct 2020 13:45:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535536; cv=none;
        d=google.com; s=arc-20160816;
        b=ByS21mrN45WiSkG6SkoZAr4sDJiCxaMyR1/IcPFe26qUzDBBYt6LWnRqenTsrSb6Cm
         DhVx0EoMDu0OImRIBaNyjCFifrUF8+fygiyHYn+44ipv6vMbvjvurAH08Nw+k6AzQbAL
         XTyxsV/0DnROOLNXYvXVB7OjiR6dirwyFLRCL/NK5S6VptYWgh7mnQrCWCO4jawLrDSF
         EwBw+uZmGDjoTTXViRrE3/8sywVr0B61zj+kZn+HWW00kBBK2AnYAPgzLVKBeSQ8voYb
         zFv8apFkP8QbVNn17UAgTPA7EicX0AqGU0Ao4MoiXoPtkOJwl+6kr3zG85jUltxKiKzR
         P/jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=n1AqZxv60BB574ri7/jtGUbbjonXXdfbOUxY3FiS/Tw=;
        b=EEMrRhccthepvHn7EzScLKWn9NEHaJypRRcH6Jm2z/kgwsqNntwcxP+0iQDuimhmew
         mOfnkBM7IrXmCHh1zIHwQIvawuf+V4QAWVii0zb5HUwuswwE+0hfU1Fq4KiGAutSS4Uk
         oCkWtiy0zJzBA9Wy1bZs5hDkXRXYUB1/EWW3lL+wuvLtmILEyPibnR16gIdP2YJwzU+9
         L9+J2fJnRYN964OiR43N/M5hI7HQjb+A2EgsZMQAVDrhSfGCx1XPljAR6sGIUmWzq6Mw
         HBBnriX5EcntVLtVktgUpJFSCm3qcJrI1i0TgjNCSU28Jnk6ymb8SguPjRxXT2x2AOdt
         gbSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f0hD+Xsj;
       spf=pass (google.com: domain of 3b8cexwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3b8CEXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u192si1261851pfc.6.2020.10.12.13.45.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b8cexwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id es11so4066286qvb.10
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:36 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:ab4:: with SMTP id
 ew20mr3294782qvb.19.1602535535714; Mon, 12 Oct 2020 13:45:35 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:24 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <f0b5b693e5bdee39c2633cd1d5e30b71bb7c4f8a.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 18/40] kasan: define KASAN_GRANULE_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f0hD+Xsj;       spf=pass
 (google.com: domain of 3b8cexwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3b8CEXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
to simplify it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
---
 mm/kasan/init.c   | 10 ++++------
 mm/kasan/kasan.h  |  1 +
 mm/kasan/shadow.c | 16 +++++++---------
 3 files changed, 12 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 1a71eaa8c5f9..26b2663b3a42 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e5c28d58ed6a..a2e71818d464 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,6 +7,7 @@
 
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
+#define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index ca0cc4c31454..1fadd4930d54 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -161,7 +161,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_end = shadow_start + shadow_size;
 
 	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		WARN_ON(start_kaddr % KASAN_GRANULE_PAGE))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -432,22 +432,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_start = ALIGN(start, KASAN_GRANULE_PAGE);
+	region_end = ALIGN_DOWN(end, KASAN_GRANULE_PAGE);
 
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_start = ALIGN(free_region_start, KASAN_GRANULE_PAGE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_start -= KASAN_GRANULE_PAGE;
 
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_end = ALIGN_DOWN(free_region_end, KASAN_GRANULE_PAGE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_end += KASAN_GRANULE_PAGE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f0b5b693e5bdee39c2633cd1d5e30b71bb7c4f8a.1602535397.git.andreyknvl%40google.com.
