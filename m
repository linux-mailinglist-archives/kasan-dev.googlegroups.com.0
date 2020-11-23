Return-Path: <kasan-dev+bncBDX4HWEMTEBRBY5N6D6QKGQEQW437JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DE4D2C154B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:08 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id c2sf6529893lfr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162147; cv=pass;
        d=google.com; s=arc-20160816;
        b=mc6ZTH/95/+M6UHOdPCmLW/+a0hYBzFLtrTxclaSvd8BMuyDu56QXMPoN/DvQ4X/kk
         edzqtZn4ZduVNimVMq0UmBRK69//9C4lMtYDQnfIT7+S5uREQHURekUXgJBwSG4/NcV8
         ksa4xo6RKiZzM5aGIgxHg8yFCP86KBFG3XNNFUHtuBascpBVM22Q3Ag3IXMLZ7Dpn1ia
         mVV7YE5i4O9oRZxZPfU1bh8H7tBa7nYFW9bfcyQ6WKfnVx2pGg2yPuVsFDcAD14fxV2g
         NALrbEVCvHmxUAHT/PdAlqaWSviBITJWfvva5+i8PvsrsgCK/Dlm/KYHip8iBmuiTzcE
         Syxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=/WJnzVPa5eOGoyEVbsRXG9aEvTi8fZIG84hIGqqQKfI=;
        b=DGclRxM1g1+cRGGqdE9vzg0s8AB6fl8iMRIPeJ8hKLKTW2Z3/JUoQLgLzLZdpBDuu7
         IrfsmZ9v18qez/58jhpuKQU/gk+ptnRCOHhUbODQx50RkNT+xWRFrRUJPEJNZRuKTgZT
         ENbJncwZZ+yo0HbwQg5ktUSukQGvmBWsvPoiT6D1VjhjUipac8kbPpsbLyysNP36hNuQ
         gEZf0IKCFkAPudpdASAbDPRXLtYQiTk72nYGhxsHxpZITK/o9BHWuYj+exYRIor9ZOZt
         HT3rX9KjeUJjiJwppQbsIs3rWOZtDFbPhiN6iHLVzqBeQtKqV5umhNzwLkoCgvXdvoO8
         cqWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HCFwctjL;
       spf=pass (google.com: domain of 34ra8xwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Ra8XwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/WJnzVPa5eOGoyEVbsRXG9aEvTi8fZIG84hIGqqQKfI=;
        b=XLfvq+C/RAORVLrPAz7c6JleaQA6sKbHhglBlBAUj6I+8xsZ7goCIT4bPcDFVp7mZi
         hxWoGxgI5mAyw33mOliZZQ0W5f5UrQhJVEpW7RvUjupP+KDnpGNXVPqrY0VxDh9tutr3
         /9Xtc78ft0sKrhJqr1gab6R3GqOJ4gndQP7DkCp0sXzL5UDK8ZpvycZvUGoguEQVfF/H
         8nDwbHCiFQQswmGg6jtz86r00e99iVHE73p5AdMhjybQyNXAS26nY3UxLpjSxh/BNGBO
         zzhU2hdOmqXCN212xrn4WlFIAsQpXZI2uavratsr6K8Jw5uY2zriB4g3UG4gCwuLQ3+U
         vGZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/WJnzVPa5eOGoyEVbsRXG9aEvTi8fZIG84hIGqqQKfI=;
        b=nnOGcchjp3IvpmR5aNLoezb29bhtObiIOcf5uIxhdWKUQDYVtatfWxJGikL56XCRql
         05h2WwYm0T93xbkFAr4qUrC23fG1sSQcnjCUModfsTyyBdLyXBfabj/PmSnjUR4bb6Kq
         EBC5yZETfsGbKZitT/9t90HbZRAQHsW2IvUuBGXfTChi37T1QPfvpkiPj3SxhpvaqsKY
         9t0hC7y/B5Gnur8DgJdtz8zvySNmSa959yy7+iDBC0BzhW2TPePI3A7qq6UpTp1KuUig
         wNqauxbLLVjQ7O2wdRJycpvrH+YfF7HrBReBXhz3TRju/9Uw0njuTtiDlQK5dVd29yRB
         9MmQ==
X-Gm-Message-State: AOAM530CdzuDvLZjkIiA0D0gH8j52KhGiCc5GNIPNzVhuOOMNobmeA1j
	jjevl2w+KyM1WitUtB0Yocc=
X-Google-Smtp-Source: ABdhPJzUXqDJat5Qz1EFLsFAcn6wnpwC4Xd5uL13b5xRR/B9xYIF/MqtS1L48PVE3lX/7eK4a/1Vtw==
X-Received: by 2002:a19:e215:: with SMTP id z21mr359288lfg.414.1606162147552;
        Mon, 23 Nov 2020 12:09:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9059:: with SMTP id n25ls609503ljg.3.gmail; Mon, 23 Nov
 2020 12:09:06 -0800 (PST)
X-Received: by 2002:a2e:b164:: with SMTP id a4mr396774ljm.115.1606162146525;
        Mon, 23 Nov 2020 12:09:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162146; cv=none;
        d=google.com; s=arc-20160816;
        b=RbfQCX8kqE3K0Ey8GZiHSuaBQRwB+K9vMEBUAyJRY/C9dHcUc9xhqguV+4a1RJzrnJ
         NLGWac8l6mC6tb42Zinm5KiY87WalYg5y+areC4VVKLhlMvNHeKo5PRn8T2iTnGGOciI
         eNd5LyI6p6Old0ke4quLVKWvQACMt9PCZw5TvPjf5LEKuwpBsOVrKDlUKarjGjYGPvAU
         ciNgdFadAUP9K6xnS0USnkUncrCGGEj5oUb/4HRgZXgDjkxFu3WJvwh21cIGaSnZmpm3
         +BH7xP22S/JkdZuoz5cUsnbhh6EwsYm+PYZ7+jOwjE+h69xvR1I0dNKmgRIQnxV0H20w
         j6hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=a0i3AqOqSlN3mSBa2/h8s/3PQOlnMPwV+np3TVLmk30=;
        b=i/EQsSTCYMymASSCumgU/lopkSEzn2DcjZfRedA56S8w3BnW/1Ql1o/5SOqVbegH1X
         V/Q8VZ7Fz+AV5fEjGhzz0teCTDSt1i5n5FM2UEdl9yeg0z+7TMXoGE9GEGtgRRk25b3h
         UjePYb86vQNwOuC5Jz6sf4few0aeEixafOvIt0SXcxRUC0lY0W1Jy6ASoE80LU8ucq5R
         fdKenbKtauAY9Fa7kPAJ10+f+9ESVGA0ILnJADzs6nhgjJE4Sac3IvYCzPbArRJXKQZg
         TQyFBGZ/Hod96YVxob8IFYClusKUbo8Bvj+6JGDcPbcBY4lFYjGwZ31wPGhGuMnXAi/F
         5bvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HCFwctjL;
       spf=pass (google.com: domain of 34ra8xwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Ra8XwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id b26si71152lfc.12.2020.11.23.12.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 34ra8xwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y26so98165wmj.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:06 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c1cc:: with SMTP id
 a12mr202256wmj.0.1606162145370; Mon, 23 Nov 2020 12:09:05 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:43 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <dd955c5aadaee16aef451a6189d19172166a23f5.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 19/42] kasan: rename print_shadow_for_address to print_memory_metadata
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
 header.i=@google.com header.s=20161025 header.b=HCFwctjL;       spf=pass
 (google.com: domain of 34ra8xwokcqqerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Ra8XwoKCQQerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 2990ca34abaf..5d5733831ad7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -252,7 +252,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
 }
 
-static void print_shadow_for_address(const void *addr)
+static void print_memory_metadata(const void *addr)
 {
 	int i;
 	const void *shadow = kasan_mem_to_shadow(addr);
@@ -338,7 +338,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	pr_err("\n");
-	print_shadow_for_address(object);
+	print_memory_metadata(object);
 	end_report(&flags);
 }
 
@@ -379,7 +379,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
-		print_shadow_for_address(info.first_bad_addr);
+		print_memory_metadata(info.first_bad_addr);
 	} else {
 		dump_stack();
 	}
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd955c5aadaee16aef451a6189d19172166a23f5.1606161801.git.andreyknvl%40google.com.
