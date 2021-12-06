Return-Path: <kasan-dev+bncBAABBIMJXKGQMGQEFOVXUTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E8AE046AAC5
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:09 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id q26-20020ac2515a000000b0040adfeb8132sf4385089lfd.9
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827169; cv=pass;
        d=google.com; s=arc-20160816;
        b=bCE3ngCgxblQnm+dbwoq1SUqqEVZqsc+G0a61uTPMTibeBWetC+ghVUxbm8Y9RQBzJ
         GAI/IxGifueiPIuoqHr/rWNv3sMk5N2+TtAdY4DnAkRnEQiL7eCELsdwrWYgazyqfH/2
         zJGpbiS3bdFz35FphsYaRRFBZ72M3loLgw46X+kDicpBnrM5u1vIcjWCY4INY+yZ9f9f
         TeNmgz00OArJqFeLgaS6sk+aUVRsWiSmzPSkINUf18pYO4pbs6jGZ+SBNZVc+ca3/5tL
         Xdt4s4IGLHO/RyLDQoDhQS0POLVxIT3btV+6BnxXbsXQkTpPxCSrIMa958mDwIigDz27
         bhIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=l1kaNxxhjZ0h2NWMPw4LozRUhfSmPywVH0OZ3ZkCDV0=;
        b=eNlqlBur0X6weEli90JZ33/xDuG+eEjISZy9V/T3zdii+q9qKs2DEmYdXgzm405prk
         y6mPLgow/G1ZKaDAGeMf/IRiJkFJV9iMW6Ur4yVlm6mvtzoPelSB+zo6fhUXz8rIh+ah
         Gs36PygD4Pcl98xqjUUPyVSMwMbT1Y0/Iphv/oRzgcE9O3NOH8/VKSok+Is+288jXX16
         zVtvzl9SML8AxEtrlRVCSWnzxaYyazw2PBil6+8cukyuZR0f4+1eO3Nm3hz8u1rPl4WB
         LdK6hdAvAhxCYrDa/mPkFdWuxYu+Xp7ymYMmFUgv/PH3uSz3JCYjKt3IexAQfVHZTfxc
         UT9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vxro8/A3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l1kaNxxhjZ0h2NWMPw4LozRUhfSmPywVH0OZ3ZkCDV0=;
        b=eYNBU2jgjnKwbVVpfELz61EjWhLngaYuVY57OYx8A2AYX7UwS+c04fhq01F2F17wGq
         m7pVWAVnq8gUJ9DDyc3Qo52VJWoacoO6yX+6P+AWAqbNuRqzYa3FdHby1Ma1DAb9Ftkv
         Mdowfzv6E4i0ED0GlXTwRwdYFZRxcVbic9keewNODS6rribzYWDAG4Svvsz4gTWQHs+9
         TW7euZtM+lFiTT5ecS67jjoQ78qzWyedw7GeDA7cnOMBK9VdIw9IZTUdANN7viyUfc5j
         +q7gKEfryCzhW0VQ5LIMc9eHNiviDWJM2CLXp64iUOQbYSpuW5fd3FhoW0QRyNM0mwfz
         lnoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l1kaNxxhjZ0h2NWMPw4LozRUhfSmPywVH0OZ3ZkCDV0=;
        b=vhrzLFhVvKyiMOj3zLHDcitbrcnZeD497N4X1WN55qabIeMHN0hsrosG0xn4qRM79V
         9x593h27IKgcS6cqqwyAL/KQnTfjUTG71ios9OVdPfM/wY8qNp2OlNXEVuIQMg17phXC
         VkJh6BkBwinSXJUeUiJzp9J372DcOwroJmwd893xO+h0mdoGZR0W1udM90Fue+tZxmEm
         8ctAJRL534YXVFFlr33pO4Kbc7cg+wz/P0Vzadyn2dEXM2QU8D4UlW5xkXEutZqrQdPn
         clsk0YmUKiQcNix9yZ0CmpxytzZZQRo72Va4txw8F/KpNd96QEy0xm1DHZgj5A6jFBA7
         mqfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533eHHohYON99afKTFedvZ3HZ7CB+ILFY5/OFx60KAjT954Qyv/d
	Hc3+I6FdtHgSAPFGXW+M3O4=
X-Google-Smtp-Source: ABdhPJySM2lZJ6QJ75kMcs26dgtiSLXckzacaeQZlCRP5vEVIEXdaF6PYjktUbdEE+uPj5PHxTkTeQ==
X-Received: by 2002:a2e:530d:: with SMTP id h13mr37500003ljb.95.1638827169503;
        Mon, 06 Dec 2021 13:46:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c2:: with SMTP id p2ls2825606ljm.4.gmail; Mon, 06 Dec
 2021 13:46:08 -0800 (PST)
X-Received: by 2002:a05:651c:238:: with SMTP id z24mr40686463ljn.84.1638827168822;
        Mon, 06 Dec 2021 13:46:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827168; cv=none;
        d=google.com; s=arc-20160816;
        b=Ty2StGG2rcmBLutKBCg26RLZANtRFvkJvdpjAzouknqsXb/+/HHsIAZc4Mq4Tk86fi
         3qAQJF4Z8fvGILmiQmeJV4oVm2xd6Vy6wOtC+9djQBKpHYr1rXxv/3bDXjXgOFJHoX2M
         vAeb9VopIU3uMV5r7vBPU9hY6a8v8EYGRsDOE2Exy4tx6JDduobnYr5x+GOoZfymYAEx
         J4qtfMrlMA74hDImIHf+h58UNI8pn+AR+3PWvPtjp4Udht/lbeGk/GKRHSId4OQl5F4y
         jWaJtpFnwL6jjyO2nm0+tazgLp1HWt9JjcMEDWmw+ihyEwgixPMbduqTS7dAOsxWf/uU
         MJEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DG1z80n+FdxKIjaCouQa8EFEG7uKXNAbYhiqtcBDOzg=;
        b=tJq1RTwQLkqdylAwCJw+uydxpsT4COXlEkTEKjaRPAu3chSCgoELXDJhkx6uLV8J5e
         clZtkBI8QOcaJJ3uqch4/Q2hnfQJr5noymORt3Eul+QLwZl4DSrTrOyAMBNU67VDp3im
         bYJSUxrjMkei+4+eQ8S7zVApUQBJUaJ3rdhJdGj6Jn4NmEuGTvRq4darnYfVJwtKGo1y
         LtjVT7TNnXbdLzJFlOf3rUZ4LcGktM0xJJirxnDWGgP5uMXZwx274Jr3tKUIU+n4RB9x
         A9Bt/FsgRbaXfLy3YFcbwDdcrkH8cenBM/YRB2vFfSWx8mpEj6rJ33HEvHVBKQ/yNVGK
         SbLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vxro8/A3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id b11si863615lfv.12.2021.12.06.13.46.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:08 -0800 (PST)
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
Subject: [PATCH v2 21/34] kasan, vmalloc: reset tags in vmalloc functions
Date: Mon,  6 Dec 2021 22:43:58 +0100
Message-Id: <a957938b0c0b3a07597594481473c32866becbc0.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="vxro8/A3";       spf=pass
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

In preparation for adding vmalloc support to SW/HW_TAGS KASAN,
reset pointer tags in functions that use pointer values in
range checks.

vread() is a special case here. Despite the untagging of the addr
pointer in its prologue, the accesses performed by vread() are checked.

Instead of accessing the virtual mappings though addr directly, vread()
recovers the physical address via page_address(vmalloc_to_page()) and
acceses that. And as page_address() recovers the pointer tag, the
accesses get checked.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Clarified the description of untagging in vread().
---
 mm/vmalloc.c | 12 +++++++++---
 1 file changed, 9 insertions(+), 3 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index c5235e3e5857..a059b3100c0a 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -72,7 +72,7 @@ static const bool vmap_allow_huge = false;
 
 bool is_vmalloc_addr(const void *x)
 {
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 
 	return addr >= VMALLOC_START && addr < VMALLOC_END;
 }
@@ -630,7 +630,7 @@ int is_vmalloc_or_module_addr(const void *x)
 	 * just put it in the vmalloc space.
 	 */
 #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 	if (addr >= MODULES_VADDR && addr < MODULES_END)
 		return 1;
 #endif
@@ -804,6 +804,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
 	struct vmap_area *va = NULL;
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *tmp;
 
@@ -825,6 +827,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
 {
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *va;
 
@@ -2143,7 +2147,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
 void vm_unmap_ram(const void *mem, unsigned int count)
 {
 	unsigned long size = (unsigned long)count << PAGE_SHIFT;
-	unsigned long addr = (unsigned long)mem;
+	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
 	struct vmap_area *va;
 
 	might_sleep();
@@ -3361,6 +3365,8 @@ long vread(char *buf, char *addr, unsigned long count)
 	unsigned long buflen = count;
 	unsigned long n;
 
+	addr = kasan_reset_tag(addr);
+
 	/* Don't allow overflow */
 	if ((unsigned long) addr + count < count)
 		count = -(unsigned long) addr;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a957938b0c0b3a07597594481473c32866becbc0.1638825394.git.andreyknvl%40google.com.
