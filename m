Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG7ORT6QKGQEPSML6OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B1BE2A712C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:57 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id n5sf93005oov.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531995; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vc7WJNGDuEmhY602tciIpPqB9yaCsQXQgFpk1BYUzV+DvBpH8Pz3f2SceKLvHKksBQ
         F60ODBxaCW/xF2rppnxa+Y0G+QCbqCSfI4IMBAuEswGnSf4Knnb7MVFpXlPcE5koGym1
         WgmkV+L/w0+CgoHoOMGE0ZmdeAychDnS6i5nHEQnXixTzxm8PTH4bol60acGDSzj6wcP
         2jdqJgivjdwJU275CiWrQPAwVtxeAzXB43n6YB0sdPyCxCjY3c0U/N/5s/F3lU1k8b+y
         7QNj7/o6iXEozANz0BQWo0A6T+ySCVlC4oDmTcZ+vXEDdplusd+ugsKsN5Wntx+14LG4
         nq0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8ExbGhyAd/VK+yCPZjtX9n55Q7MajRKcPRZSN+VMC/Q=;
        b=rJrJp9h84MxmaRbb7ri6X0YKWP8AGlFj56NklHxa8lQWXRE7ynUyGI5CtyfeGQ4uIm
         EXHadp7fzNATNxK6ppxt54vlIo0xctNeHdiJ93tgG7sqVpSNv1bkdt4Y8DBsJTXKceMm
         mG8GFKUR/bD1dItIhBloG/XX6/4T4XOl/WxtMBrJxYGl22NvDNaC5X79V2VAjns6i5AN
         N7AdM9JVCZd/JNZTyR7biUkZavf4rVahxB6HPH4on+2j/pVtOFKqZAqdewLjfX/B9G4Z
         K1HbLGywePRhExCzxNxNYxI89czOKqUXh3Kv3IsAZysD3ZsXCV+KuBJ8YHM/ZV2NexTJ
         w/FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MHsAFWSN;
       spf=pass (google.com: domain of 3gjejxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GjejXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8ExbGhyAd/VK+yCPZjtX9n55Q7MajRKcPRZSN+VMC/Q=;
        b=BceiJiTxzYqsHY8YubMC2sMsl8ofr95ftLn71MFOOYj61ysNNUFnulxYqK+jg7oCas
         OzlxnGVq5AFtcGTe6VPTiqimeAe9GQKfjMq0LGl7XJ9JoOz89F0EE9Hj8NCF06+o8bF3
         0dE8oEv0lpaGTvybGL3GDJSVoLHOsE/2dN7yF2F/hPGawAnmKXZZGJnmTE8hJc8oM7PY
         j7pCZGzUHQI/yRi75jHAnk1ebD3oIvUUnleOUVc4S7jcCgu1FSxY0Y6s4TYfFLnaw7oU
         DaAcFQg/Id5FKKzB0nkKu8Bn3GqPl75l8rCc14Mx5WjM2Os6gY75KyCYy0KzDhjF/wsl
         pTxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8ExbGhyAd/VK+yCPZjtX9n55Q7MajRKcPRZSN+VMC/Q=;
        b=UHNRAAkkIZtCnffUwbgVZgXC1OaBMvnx4+2Cmh/2q8G+VWh7xKrqyUcRHaIabFGq+2
         e0M3j9/B9Sowlj5ppGyzbVcA17diiLdlcZbxIrHpBKtUQ4mV40avZ+twow6a/X3WNam/
         YKPjzCQ4y7lYYJuS9bmIKVUyY8kkCx23soDiQa8JjtuutlKfiyIMLnR08l4BWL5vhABn
         oFoOaroWFJRUzI5/+BPcU4T86hlbEgFWPe+qeFW5tJIf3FQ7XL6XIgwM72f2GZ9OB/ir
         +RI3RdTUbAtshx7LYoKlYehqXX7ds1PaGB3nRi6n4PoMHSxhtmQLA7iaDy2DdgP3DHOg
         7KXA==
X-Gm-Message-State: AOAM532kogkunxD7XVPOVJw5mIk6ZoVjuOtKI0Tgoyf7ugrfuM0jfuPn
	wOju8QuT+n775j4haiQGIEw=
X-Google-Smtp-Source: ABdhPJyluNZf01eHqL+q550zS/cJvn6J3pULdlm2WiaH1inHOHVT0kik09Bfo8Tp2JE9uFYfmiXlxA==
X-Received: by 2002:a9d:7850:: with SMTP id c16mr60668otm.342.1604531995745;
        Wed, 04 Nov 2020 15:19:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:416:: with SMTP id 22ls1003646oie.7.gmail; Wed, 04 Nov
 2020 15:19:55 -0800 (PST)
X-Received: by 2002:aca:ddc2:: with SMTP id u185mr96874oig.81.1604531995432;
        Wed, 04 Nov 2020 15:19:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531995; cv=none;
        d=google.com; s=arc-20160816;
        b=XkOjBwzfrMfMd+4as10WHkLAm0+H8tjwsi/CzXI8MGh5YgYDNZEVYJWtfyT/tsAQC6
         A6bObfYqQznk7SQuWe5+PK3IqNUTYEfMb8pz4XolOexM2mndhQMaf3SCWtzjPnuWBGF+
         L1YXF1HD4RyCGln6p1Ayu3VlBnG059Hxra0dMYdT1e5cdQTvH6qkyivLV4sX9ISdwlhy
         +OVn2D2d3P+cCr7ViqqNKnEk9B7QbIDtS2LAU32c5mczSm+jJYQHPvZFEat2yqZ0rfxw
         lS8nu4hc2Kx+CTYFcJNs6u8aqIVGQpf1yPPdyqXGvE+xJFtqOuh4xYXhIiTj23RRe7Z8
         HslA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=96T+1f9i/jCV3zB6gHtRoH9MAYIWASsGc4o7euuXITQ=;
        b=eCgp9WjhvzU8G5n6DZRHjZv8S76Zj4zeIF8aLWhupmKDw8PBSVdHvxGuXB+pTiQ/bH
         xqnwSlSGMJlk+ydfZeLBc/acrNY7C/QwJeulwjWopxUf2g7FILbkAOk+ZgD8SLkOEQOQ
         /pCwY/jRScAN+qX/0lqlbwX5IIBYNuGPERabv52eWPsjtYskUq+Lj4reA11Ya6N70dlY
         RlV8J8AfTBDa3xoNwYBiL05YI0gX0lerCb7wCJQvNRiKgdZevY/furda8oK59Y4Hw/Lt
         uKXiCUgdObWT2PHbyKNYDSlQzxPCHxo5iYPOvHG2lm1O+e9KirG3kvg+nE0l9wgeuq0S
         6f5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MHsAFWSN;
       spf=pass (google.com: domain of 3gjejxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GjejXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id m127si341826oig.2.2020.11.04.15.19.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gjejxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 22so65966qtp.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a2a6:: with SMTP id
 g35mr293187qva.4.1604531994786; Wed, 04 Nov 2020 15:19:54 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:35 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <ed664e371a31c5e0dad63cf8b67c61efa0d08409.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 20/43] kasan: rename print_shadow_for_address to print_memory_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MHsAFWSN;       spf=pass
 (google.com: domain of 3gjejxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GjejXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ed664e371a31c5e0dad63cf8b67c61efa0d08409.1604531793.git.andreyknvl%40google.com.
