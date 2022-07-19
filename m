Return-Path: <kasan-dev+bncBAABB4XO26LAMGQENJZWNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C3E61578F00
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:14:42 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id h37-20020a0565123ca500b004889ff5f804sf4778540lfv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:14:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189682; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6QmQUfcW66932mZPCCUvBvAq6UXiWBXF2Di6P9hYFOPBpYQ2/eXmJ9pntkN6EE2Lx
         p/LBsDXyK8zQTd0NlI0ghwdk3e1T0oLhD1ErL1mjOMHIjlM1nKOV846BEMNOA49PMJgk
         kzipZo729Q23II3ajn1O/Dp/BcEQikiSiYeIIvwyij/MTyaRBxXk2s3Ev/w8UIM04iSP
         SfYpqwhDTSUypX9iMvMxOb2ls/CyfoeuUBXvkLeZg7QforZ4kQNdKTzwiGmI7SrAuGH9
         7962/9OacKxb7b+hjpei7ThDviYtlTxrPSUOnwQFqo2yX9ZIANd7c73vOqyZSswejCgJ
         Iczw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yRqn1+XzpfcqaDjZiVV6j3MN5Jovuza8WXgcTQi3a5Q=;
        b=AlL4wOu50l5dxXp1CYIL5o6UU4snJ6fLICaSWlGWInzDpuhS7HphWT9rZbTjYnNBSX
         vpRi4G0bxsGv0OrLsR0zJx3iwEFz4ab9qoRD9kTMo8OaADfjzry58FUjnmigfsWzC3Tp
         GV7b9cilm5W5/95iFtYeJPuamRiZ65FHiFoMtXkitDX/llpKN2j9BUgHZB8b5zqHLvGM
         VVyBZVsD3GGw93iVTC6GrkqbUXg1NuahM4J86urGbppk+Z8w9AKzekX8jKfbHfjD3I8s
         HteVZq+BOpix4GY2BQpggm6xzm6g5fQdHmSyYbPkgxF/5vtz7c8MLECx/yKoHTUBTBsr
         EA/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YAVfPvux;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yRqn1+XzpfcqaDjZiVV6j3MN5Jovuza8WXgcTQi3a5Q=;
        b=aiIo+QsP93Q302yY6mJYcFGJgm3hQNakE8WqIqKtA2xTbi17YfADfShRaoPzC34q9R
         gPN2tMJZuXrpjTlCvXhlAl7keHqqAdwawTC3sCrZWc4qBNaVAs+c/FPWtU8sSdKteuKq
         UdiTE8KQe7RB1DJYw4pjG6B52YCNAEUo8VQJgI+I5ULGkzxMFwRzg/QQVR3sJpuAR1Fu
         6ww8owRz+maw9T6ZEoMz2OeJC7Uast19iHK5fdPPE2k7IOvIYlWEHtxVrmjLPTkr1Zft
         KVCn1TGbzvZ2ltiWS88opmb8eH6iHTy6qlvvk3fQrHrM0NRcnY+efydfnXbWyquzZV18
         PhSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yRqn1+XzpfcqaDjZiVV6j3MN5Jovuza8WXgcTQi3a5Q=;
        b=TRbtFwBhJzeXQwu6aAla9II8AkPC3bWyWo6gRVmY/ssIoHM0Lb43yw+OGCwnn4TepO
         7lKqAZHJ3zDKoqsL3h6XhoNnVEObSPSFvBU3xF003wzgZtULminwF7H853Zqr5Uc5YPp
         Pf1EHHggsTHw8giLtrvfQbED23JNsKIkELr9d+uRh/PSoWe57T5jARn7IyIpUthN/Umr
         Bg8Ms5dyuhRwO9+nz/iMy6SoUAg9iZtnjxBPpc7Mij5JagGkhxx4G9JNdoGuvUHdbx6M
         56f70c0UX4csr/6g4UayX+TEAvIEWHd4FFb79Zw/eSdlAHUx+fTnwl+rwze1xVENEzMo
         0Gaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9UdDDYOtrEdZdxpFUvy+ow97E+ugfw16uWDsgAnwSf9xUcWwQq
	ce+e+wbT5xGpmmvKEJBPBk0=
X-Google-Smtp-Source: AGRyM1u4EvobDvy5k6Cnt9RfGcb407XhOKaR4zOdDOE6D467il/sFkYTPjgmMwoyl39wuUgRVKGqiw==
X-Received: by 2002:a05:651c:a0c:b0:25d:7468:f9b6 with SMTP id k12-20020a05651c0a0c00b0025d7468f9b6mr13232405ljq.306.1658189682286;
        Mon, 18 Jul 2022 17:14:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e34d:0:b0:489:dd8c:5436 with SMTP id c13-20020a19e34d000000b00489dd8c5436ls1663919lfk.1.gmail;
 Mon, 18 Jul 2022 17:14:41 -0700 (PDT)
X-Received: by 2002:a05:6512:ac6:b0:48a:29e0:2006 with SMTP id n6-20020a0565120ac600b0048a29e02006mr9146981lfu.110.1658189681482;
        Mon, 18 Jul 2022 17:14:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189681; cv=none;
        d=google.com; s=arc-20160816;
        b=OsfHAdg/3SmhUarxrrPsPniFJvNv+NgYRdqk2XPmeft2MPw65aVCNeAPzJa8ssfcXP
         PqYy66xW8SyfEfYm6jvcDFa3RFtw0Qpc1EFXCpBZODrYCk9cbz4jRfYifcSe0cxS/j4T
         HdtTgsBZfPfUoWeF94hOfBum5aZcOwFw58DNTqWL+GnZhRwdPzyr3+DldukeQWEdd1FM
         WiAGe4KfyfABEDSmT6n8ioCwfVdNoBFBX30e9BHiMZP4EFQ/HxrWwtUr45lWD+8nAh0c
         5+r3f6Fz7lsZEaCNNuwtLXgAhtVcMzwWAx1OVp2A7wYSpBwJSaTwP3hh/Jb37BVfi1RI
         vHdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zHx81bpzjWOxKC5pKO2LKT22RGKsdl7WhMonqA7gxhs=;
        b=HuUb5Emwgd0uOrZvh5ZS3NUFbOOEci5qMgtdOEXuNKHg2qox/dYWX52M9kMWbq/J9/
         75misVZPcsFCTo+k9cE9qpwEixhsWuZj2m+yXFvdPGDy7//lbdhqpWyjmYkT1ki8dWAx
         hOImcdL5DMwCKaETqxVCLc3dFVPti7qeARcnHx5HLsjpiRvr0x7ENgGe4filMPchWo5Y
         BhzJlq7QZo6GeF8iw9jpcgRiQskfEMtOTPv2bX2mmbV9AS8NseRZe3tzGB5CIANGHXIJ
         VYQd0m5uCFS9XjBqIHp7Ztcoa5aSyl+80lSCLNdEn9YcrxDgNS/Oz4klzTTHzv2Av3Hh
         V8VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=YAVfPvux;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id s10-20020a056512202a00b00489d1a6dca6si401502lfs.8.2022.07.18.17.14.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:14:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 26/33] kasan: introduce complete_report_info
Date: Tue, 19 Jul 2022 02:10:06 +0200
Message-Id: <5ed013df1b173806eb7aecccd2254aa46d3abe56.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=YAVfPvux;       spf=pass
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

Introduce a complete_report_info() function that fills in the
first_bad_addr field of kasan_report_info instead of doing it in
kasan_report_*().

This function will be extended in the next patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  5 ++++-
 mm/kasan/report.c | 17 +++++++++++++++--
 2 files changed, 19 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4fddfdb08abf..7e07115873d3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,12 +153,15 @@ enum kasan_report_type {
 };
 
 struct kasan_report_info {
+	/* Filled in by kasan_report_*(). */
 	enum kasan_report_type type;
 	void *access_addr;
-	void *first_bad_addr;
 	size_t access_size;
 	bool is_write;
 	unsigned long ip;
+
+	/* Filled in by the common reporting code. */
+	void *first_bad_addr;
 };
 
 /* Do not change the struct layout: compiler ABI. */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index dc38ada86f85..0c2e7a58095d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -413,6 +413,17 @@ static void print_report(struct kasan_report_info *info)
 	}
 }
 
+static void complete_report_info(struct kasan_report_info *info)
+{
+	void *addr = kasan_reset_tag(info->access_addr);
+
+	if (info->type == KASAN_REPORT_ACCESS)
+		info->first_bad_addr = kasan_find_first_bad_addr(
+					info->access_addr, info->access_size);
+	else
+		info->first_bad_addr = addr;
+}
+
 void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
 {
 	unsigned long flags;
@@ -430,11 +441,12 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 
 	info.type = type;
 	info.access_addr = ptr;
-	info.first_bad_addr = kasan_reset_tag(ptr);
 	info.access_size = 0;
 	info.is_write = false;
 	info.ip = ip;
 
+	complete_report_info(&info);
+
 	print_report(&info);
 
 	end_report(&flags, ptr);
@@ -463,11 +475,12 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	info.type = KASAN_REPORT_ACCESS;
 	info.access_addr = ptr;
-	info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
 
+	complete_report_info(&info);
+
 	print_report(&info);
 
 	end_report(&irq_flags, ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5ed013df1b173806eb7aecccd2254aa46d3abe56.1658189199.git.andreyknvl%40google.com.
