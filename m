Return-Path: <kasan-dev+bncBDV37XP3XYDRB5UQ7OQQMGQEDT4NPKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E5E36E69C4
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 18:42:31 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4ec81339fbdsf904647e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 09:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681836151; cv=pass;
        d=google.com; s=arc-20160816;
        b=a6B6Gr1sLOxNWnvB/QRiRR7W7k7GrBKJBML6MDiMzb1hxz13QeLWwUIoohjM+eRw7m
         uhddnESTBPuNl1Ew6ZS+yQw+7gW0J3gSSP6ADWpfSI14y8twNlko0rCxkZwWnZhhniqN
         uV72OViiqETOa5gJOVlH6F9UzUXJ4ZowbSJY3jofgl1E+pcX9HdmPBjjLinngme9mJxN
         Y9lJU0E4Pl7z3bo4O6/p+X2DJFMOflsRw2KXMe7KfjaoSadOL3irmEx6tHn3URdgfIoG
         cAwmrnMc+1/I/44KCQzM5XitvGrFcMDrOZ3etbh7yktWWjHJg/8inv4qOPpAyW/WvK4w
         tpVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NEKbev9L+yiYtrcQ96FR4y+AV3MSexmaf/oKkxbP/V4=;
        b=Jw7acbXmdlOSqozWPIiQXO2R6S2FbjzpyXEdUwuYrEctdkCV7kIPdoyhcUC10RVZl0
         yWHFfxm21Z9ds5elBwBNI0sIObapbfcuGu8SBmd9iDHm0eLlCDm/skJjH3rKN9PfGPqu
         UbclLJUAL7CyCroMw0FLLvyzG1lolNHm8VxGZVVBgsrGmED4/0OE7OVz8CVggn5fb4qX
         favs3S/X0F0mPu3YCiydmAdhFhzF+BB13RaXXGtk/k1VS/UVQVkzNs1D/TJKzRJyn404
         LkyWyGiwMydaaRpMYwAEp9whTM8ukkLcPSRQEU7YpoaarQIAvATIs0ZYekXt4VWyB1Lk
         YUnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681836151; x=1684428151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NEKbev9L+yiYtrcQ96FR4y+AV3MSexmaf/oKkxbP/V4=;
        b=XFbo+r3YD/uDbxdyyeAJVttLgi8KyiRLtol00Igk2KYAzPhMSimAD99lOEfE5+q5Z5
         1cBz4yf8MsaSqA2h/Sm86urfm7uDNiNh3wSnXOQgGhY6yyiYhSyAj2HXxUZG+orKZLqU
         9WlYi2NVlpFh9aHATlzlz9mF9hZEK5dJvOgGckrkA9E0WPVLcHn10KVQlA/ZKXOk18Yh
         /KSjqWdRKGnBEwMHj5hKfp0NCMFVc2k7w37uKkQjjOSbtR5biVO7vt1YhquEH7hjli5Y
         I7RJhJbq/gLN0CgXUeeahQnNRLCOLzT/lJl1Z5dHgzoY+OUekvpqKUMavqCv3GxCxQug
         IjXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681836151; x=1684428151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NEKbev9L+yiYtrcQ96FR4y+AV3MSexmaf/oKkxbP/V4=;
        b=f+fy3KktfLTAWryZNmJjAC0Q7FlrKGKgT6t0p8FumWE/UmUr3rkdrTHVPU9AvzlU3o
         V5ezIl5FzrUiq9+U/PKz2ZHacsaTEAoke4bJbb1+biSokKfu/6z35RqB0LoXwn35l6xu
         2CRcrzt+hDenUJ0JyfGHIHP2KJMcARYiG+wdlRiFhGfIpxcmWadl4JG2V8pf7tDCashP
         WNaoYmSrkomY8VTDHuC1wUrpys8nZCmLZeHwEll6mk2XMuGnn6tbhlowOtj2N0EoZX+s
         YE6m0UspEJGB/PoHwcaHVcsfuNPWXy43I6znneDQMi05vRdht9KAGXxX3R5KvDXyH72i
         J0dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eb9CgESS1JXEKL6NNGBhEVlG2SI3TRnHVbTPhBfCMc3QRspU3t
	SQ30AYdm+XgT/7pcSFxXPHc=
X-Google-Smtp-Source: AKy350ZKMnyIYH2PYVyAzwp3NG7RfXAhQtJBU/iHTG+dkTo3CVWwIrp6mBoRmsLokHW1d40uTr2nhg==
X-Received: by 2002:ac2:46c6:0:b0:4ed:300d:79ab with SMTP id p6-20020ac246c6000000b004ed300d79abmr3454098lfo.7.1681836150475;
        Tue, 18 Apr 2023 09:42:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d22:b0:4ed:bafc:b947 with SMTP id
 d34-20020a0565123d2200b004edbafcb947ls1678156lfv.2.-pod-prod-gmail; Tue, 18
 Apr 2023 09:42:27 -0700 (PDT)
X-Received: by 2002:ac2:55b4:0:b0:4d5:978e:8bcf with SMTP id y20-20020ac255b4000000b004d5978e8bcfmr2507293lfg.33.1681836147035;
        Tue, 18 Apr 2023 09:42:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681836147; cv=none;
        d=google.com; s=arc-20160816;
        b=hhNqo/CElOHD6aLy3gN2lboTzY7Q3U7Jysmjf43e1S4a/aF4sntmIM86FwGmiWl6E7
         8na7/RxDBCAcQpuySm4MlpjNuxgrFEoei5VC78c9uoV+2i/yZhUtJEc/EX8eGgac83jM
         mCJTNsvhGKeXGI7VSj04kisjqQzwpRie/YYVmnLk6Tv2O0zTVAvi5++FvaLvDwgORW7x
         P8QQm2hK/In+Jrw03TkwotdUdIMNw1h+g6TrFQn4ByuM5AMNWUMoqkvIqT53qiSTGq4m
         +5soWf79SY8aKvsdKCdiSpGyh1F5fVmvC+xNqIpk+n3+DIHeO9HFCiirBToE6djS+cop
         nv4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=G6Z/2ZgKXp8PPKCDjOV9eB8S1vzbb6PdfxIcqEgeVWg=;
        b=RKfQX//8Y4hO2h5KSEXCu1o4jYyfvsQfwnBHHmdiTqHalG7U+52s3WZuyw6HXXD/e5
         0WRt2v/jiNT/docjg3nHGdfrNKwpSX19aVQu/QTzPCv7/xwaj4Z16HVGP5lAhAPR2h+w
         mKDjKezOSo2p0f5baE0yMiGkDXyxU21RX8AAM0+Hiwb3cQM7jux2VoQVr/CsGFZRCvBJ
         Q0jZoX0qHXGrnpNJ+jhwr2yelXY6/yG0V6ch2I/rk+l8qfyrFlqLIIaNyOKbqV1pJZmq
         o+SKT3RG/ZEyI61cn1l+Ivo+dwTQ3vnqftFG7pUvH5IccCbcq/0TXcWljECLQ+O5DARP
         PJig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o7-20020ac24c47000000b004dcbff74a12si799988lfk.8.2023.04.18.09.42.26
        for <kasan-dev@googlegroups.com>;
        Tue, 18 Apr 2023 09:42:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8D72911FB;
	Tue, 18 Apr 2023 09:43:09 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 80F633F5A1;
	Tue, 18 Apr 2023 09:42:24 -0700 (PDT)
From: Mark Rutland <mark.rutland@arm.com>
To: linux-kernel@vger.kernel.org
Cc: akpm@linux-foundation.org,
	andreyknvl@google.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	mark.rutland@arm.com,
	ryabinin.a.a@gmail.com
Subject: [PATCH] kasan: hw_tags: avoid invalid virt_to_page()
Date: Tue, 18 Apr 2023 17:42:12 +0100
Message-Id: <20230418164212.1775741-1-mark.rutland@arm.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

When booting with 'kasan.vmalloc=off', a kernel configured with support
for KASAN_HW_TAGS will explode at boot time due to bogus use of
virt_to_page() on a vmalloc adddress. With CONFIG_DEBUG_VIRTUAL selected
this will be reported explicitly, and with or without
CONFIG_DEBUG_VIRTUAL the kernel will dereference a bogus address:

| ------------[ cut here ]------------
| virt_to_phys used for non-linear address: (____ptrval____) (0xffff800008000000)
| WARNING: CPU: 0 PID: 0 at arch/arm64/mm/physaddr.c:15 __virt_to_phys+0x78/0x80
| Modules linked in:
| CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.3.0-rc3-00073-g83865133300d-dirty #4
| Hardware name: linux,dummy-virt (DT)
| pstate: 600000c5 (nZCv daIF -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
| pc : __virt_to_phys+0x78/0x80
| lr : __virt_to_phys+0x78/0x80
| sp : ffffcd076afd3c80
| x29: ffffcd076afd3c80 x28: 0068000000000f07 x27: ffff800008000000
| x26: fffffbfff0000000 x25: fffffbffff000000 x24: ff00000000000000
| x23: ffffcd076ad3c000 x22: fffffc0000000000 x21: ffff800008000000
| x20: ffff800008004000 x19: ffff800008000000 x18: ffff800008004000
| x17: 666678302820295f x16: ffffffffffffffff x15: 0000000000000004
| x14: ffffcd076b009e88 x13: 0000000000000fff x12: 0000000000000003
| x11: 00000000ffffefff x10: c0000000ffffefff x9 : 0000000000000000
| x8 : 0000000000000000 x7 : 205d303030303030 x6 : 302e30202020205b
| x5 : ffffcd076b41d63f x4 : ffffcd076afd3827 x3 : 0000000000000000
| x2 : 0000000000000000 x1 : ffffcd076afd3a30 x0 : 000000000000004f
| Call trace:
|  __virt_to_phys+0x78/0x80
|  __kasan_unpoison_vmalloc+0xd4/0x478
|  __vmalloc_node_range+0x77c/0x7b8
|  __vmalloc_node+0x54/0x64
|  init_IRQ+0x94/0xc8
|  start_kernel+0x194/0x420
|  __primary_switched+0xbc/0xc4
| ---[ end trace 0000000000000000 ]---
| Unable to handle kernel paging request at virtual address 03fffacbe27b8000
| Mem abort info:
|   ESR = 0x0000000096000004
|   EC = 0x25: DABT (current EL), IL = 32 bits
|   SET = 0, FnV = 0
|   EA = 0, S1PTW = 0
|   FSC = 0x04: level 0 translation fault
| Data abort info:
|   ISV = 0, ISS = 0x00000004
|   CM = 0, WnR = 0
| swapper pgtable: 4k pages, 48-bit VAs, pgdp=0000000041bc5000
| [03fffacbe27b8000] pgd=0000000000000000, p4d=0000000000000000
| Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP
| Modules linked in:
| CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W          6.3.0-rc3-00073-g83865133300d-dirty #4
| Hardware name: linux,dummy-virt (DT)
| pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
| pc : __kasan_unpoison_vmalloc+0xe4/0x478
| lr : __kasan_unpoison_vmalloc+0xd4/0x478
| sp : ffffcd076afd3ca0
| x29: ffffcd076afd3ca0 x28: 0068000000000f07 x27: ffff800008000000
| x26: 0000000000000000 x25: 03fffacbe27b8000 x24: ff00000000000000
| x23: ffffcd076ad3c000 x22: fffffc0000000000 x21: ffff800008000000
| x20: ffff800008004000 x19: ffff800008000000 x18: ffff800008004000
| x17: 666678302820295f x16: ffffffffffffffff x15: 0000000000000004
| x14: ffffcd076b009e88 x13: 0000000000000fff x12: 0000000000000001
| x11: 0000800008000000 x10: ffff800008000000 x9 : ffffb2f8dee00000
| x8 : 000ffffb2f8dee00 x7 : 205d303030303030 x6 : 302e30202020205b
| x5 : ffffcd076b41d63f x4 : ffffcd076afd3827 x3 : 0000000000000000
| x2 : 0000000000000000 x1 : ffffcd076afd3a30 x0 : ffffb2f8dee00000
| Call trace:
|  __kasan_unpoison_vmalloc+0xe4/0x478
|  __vmalloc_node_range+0x77c/0x7b8
|  __vmalloc_node+0x54/0x64
|  init_IRQ+0x94/0xc8
|  start_kernel+0x194/0x420
|  __primary_switched+0xbc/0xc4
| Code: d34cfc08 aa1f03fa 8b081b39 d503201f (f9400328)
| ---[ end trace 0000000000000000 ]---
| Kernel panic - not syncing: Attempted to kill the idle task!

This is because init_vmalloc_pages() erroneously calls virt_to_page() on
a vmalloc address, while virt_to_page() is only valid for addresses in
the linear/direct map. Since init_vmalloc_pages() expects virtual
addresses in the vmalloc range, it must use vmalloc_to_page() rather
than virt_to_page().

We call init_vmalloc_pages() from __kasan_unpoison_vmalloc(), where we
check !is_vmalloc_or_module_addr(), suggesting that we might encounter a
non-vmalloc address. Luckily, this never happens. By design, we only
call __kasan_unpoison_vmalloc() on pointers in the vmalloc area, and I
have verified that we don't violate that expectation. Given that,
is_vmalloc_or_module_addr() must always be true for any legitimate
argument to __kasan_unpoison_vmalloc().

Correct init_vmalloc_pages() to use vmalloc_to_page(), and remove the
redundant and misleading use of is_vmalloc_or_module_addr() in
__kasan_unpoison_vmalloc().

Fixes: 6c2f761dad7851d8 ("kasan: fix zeroing vmalloc memory with HW_TAGS")
Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 mm/kasan/hw_tags.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index d1bcb0205327a..2f7ec2e1718ad 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -285,7 +285,7 @@ static void init_vmalloc_pages(const void *start, unsigned long size)
 	const void *addr;
 
 	for (addr = start; addr < start + size; addr += PAGE_SIZE) {
-		struct page *page = virt_to_page(addr);
+		struct page *page = vmalloc_to_page(addr);
 
 		clear_highpage_kasan_tagged(page);
 	}
@@ -297,7 +297,7 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
 
-	if (!kasan_vmalloc_enabled() || !is_vmalloc_or_module_addr(start)) {
+	if (!kasan_vmalloc_enabled()) {
 		if (flags & KASAN_VMALLOC_INIT)
 			init_vmalloc_pages(start, size);
 		return (void *)start;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230418164212.1775741-1-mark.rutland%40arm.com.
