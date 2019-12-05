Return-Path: <kasan-dev+bncBDQ27FVWWUFRBY44UTXQKGQEPW3RAJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AD9B114236
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 15:04:21 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id u10sf2454393ybm.4
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 06:04:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575554660; cv=pass;
        d=google.com; s=arc-20160816;
        b=OFM4tkLNWVmnZ2LR8aBxelyv+fwFcUwgLRBmlzHBUZDp6zMvyGFLc3s6waJeHq9ggl
         jdyc2n8kRuZ7JSsO6gX4kJsUsFD5mEiDlK0HVjqznA+QvHc0fypowgTJEc7k05xC8Gds
         WS7ufHM+3xVlJBKxcD3v0w3FVibEwInqswKVfM3ujkIoZ3u/+ag3T5EcO2b90BpFnrGo
         ISh9JqtllSjoQFKbnIyfJYNKOBVJRYl8S5BZZSCngYNjoMOvmfDm2JKK3U9dTyDAeBSe
         H4F5zbJ7zOU/FW5UPrNc2zFMCIbuveEemFoUqYQYSjF6ddjbZPWCeCOK77A+MiaOwVGy
         XUTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zUcOFjDyYZBwmSJrOal5SbpzvQkUmOyo/XHSWclF42U=;
        b=LDhI0FGyhwKvlsnmA/hIPgaGvRQY4pgF7qwU2XDDOtt2N+PzsJEPgX6ZI4MX8WofjF
         78KsemCJdXkSyDmU0LtPrpuQ17e38Y6wZM6fBxZdhD9RbniBykzW9vlAcivGtOy3B12f
         AE0AdFnFkeFgjk1tjpBLFunlWXMDkn8v5KgGampxkfn3ftds2VkSh51ObE1KQYJxc/GL
         AJuQlN8+0B003L7Sx4J1j1LoZ97h8k03wqnSS7r+63UBSvUkJrNQrpxnDohRQ8VMGVM3
         FkqqljfIun7SsDsYh0U1b6z7xIz0mKgxsOHpyxsAk/KZHKBsC6/mdLQla9tHL4UZGuPQ
         Ymtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="HyowXUY/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zUcOFjDyYZBwmSJrOal5SbpzvQkUmOyo/XHSWclF42U=;
        b=UZig/J91+OUIivjzWxaFel03knvuLypbBnKPXq0pFEAFGVVlAP1HhsIiNr1OsyWmxX
         TiwTVQVLJfIKAeAAmFLK/UHTs/7BT1D6/H2WPdXK6/ydyHqW743x73LFMeOUS6Zr1so+
         psRCrpxHZqTUMi3MQSB1S2yZOQeERp7N4VAi/SH9ckWIhokmMaU9l0omlwNieOMGtU4z
         9Lqq6we+BDmJnk/0Gjd0wfi87EEV83u+k0XYdxvdROGXzaLQkjmMRbfk04prQ/Z4/6Eu
         npVYVH5kSEKbrWCSBzxlj4EshOvh99J95/7CWwJ4Cx6DmWs2VuQlFwSwCU3vq+zJf8Ff
         5K2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zUcOFjDyYZBwmSJrOal5SbpzvQkUmOyo/XHSWclF42U=;
        b=tbga8VvY8x1zbsyPN0tmRl21NlRUqKDKUhf0Lag3cH9fUkmN+jpzrkn5+ARSWhj/KN
         WTTrNoLxCrWmFsUKVpvCOH9OOkZhT7Q3+elc7A8QitpVCVdXb2GfXOQgoXBtW8snj7XJ
         rhpd/j2ECu3liiDYBWXBMlngTrNx+aQ9RSiKyvroG0KzoJTsN4LKONSJdbeYXzWQbGT4
         4C44qHjkrlK0JvEo55cX/NIg5F/6JONxm2QwlWdhk9dbeyvkgymeBXB4kbw0VF8wCEEc
         OcMdJfqpYG/fbmCgu1PfBrgDhcJ5P0qnrqhnJ/SjS9WeZA+LxQVlQYxD62XHMyaY361k
         rOFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcC4hahMdE6P0wHFjRJyFPIiUj4LogbcPaPwPTtL0vD7frkLIO
	MGfweIjpdmIcp/xY24Uwzm0=
X-Google-Smtp-Source: APXvYqzGfzeemhRs996nA+mC6LdxExY5crhWn0dCAZYDav9nH8rryX4ZV1J1aY+gopU/PuU6QT38lA==
X-Received: by 2002:a25:ad13:: with SMTP id y19mr5617470ybi.366.1575554659997;
        Thu, 05 Dec 2019 06:04:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8488:: with SMTP id v8ls449226ybk.14.gmail; Thu, 05 Dec
 2019 06:04:19 -0800 (PST)
X-Received: by 2002:a25:844f:: with SMTP id r15mr6572612ybm.370.1575554659507;
        Thu, 05 Dec 2019 06:04:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575554659; cv=none;
        d=google.com; s=arc-20160816;
        b=uz+m3bicypjtcakH3OmRpyhqQ65/UBpEiMVWaMvX382ZuKTXZVDXvpEbHeztzKFpYo
         bn0nFO+1ojLfXAfHREghxGnxhliqRI1c7u+g46Gymd6kVhBPgCnRcP/SJghxYQdH9CoM
         sXRym9u1M/5kYP+U5tRaKysn2WojatgQCUANps4JLNBxhheiTZ2WjXSzQYajMAhP4ijX
         ZrdZxeSRL/dCK0CZowQ8hdrUSicLfpo97D0JB7RzqEjnMHEpojNmjc2AZmja4H3X7M4Z
         YABLIOeh5zptn6XD0YWNDcPOndk7Hv1sieBUIOH9yreyhXDee2pNPS9S9scGdzFk2hj/
         TU9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rrl6fsIQIcheAl6pCi+n0PQV4bZosMoozWNraf35XNA=;
        b=rUoomub499tEL1FYVhlje6VNUOEFZWzazhym4PQG2r9WksdUJB6BXpfCUmpsgFOgG3
         B6vf6zjZLmWPFf7HADRvh5hXzzlD04OExPu45/gt4xhMqaM/Xb3Ka1jasAl9POgD+8jD
         04LPnTLt8Bhk/vzA1njXS3Sx3AwoQV57Yor0mzKw//ztH0Rz1NtfYMTBE/SEQo1/cs84
         I6Spk1BXtxyRn/EVgbbnQRPFN93HnrthcerIkKskZdCzsmGwalfv4jHCvUNaSomaS7c2
         bUiKCZa0aVUIqLEDHyLkq5ATsXZ+0e5bDYIko+UVN7BDcim6vmk4S6BVwSJF0haAWunh
         R68w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="HyowXUY/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id j7si706597ybo.5.2019.12.05.06.04.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 06:04:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id w7so1286378plz.12
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 06:04:19 -0800 (PST)
X-Received: by 2002:a17:90a:a881:: with SMTP id h1mr9398250pjq.50.1575554657418;
        Thu, 05 Dec 2019 06:04:17 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-61b9-031c-bed1-3502.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:61b9:31c:bed1:3502])
        by smtp.gmail.com with ESMTPSA id c9sm12165045pfn.65.2019.12.05.06.04.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2019 06:04:16 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	linux-kernel@vger.kernel.org,
	dvyukov@google.com
Cc: daniel@iogearbox.net,
	cai@lca.pw,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 2/3] kasan: use apply_to_existing_pages for releasing vmalloc shadow
Date: Fri,  6 Dec 2019 01:04:06 +1100
Message-Id: <20191205140407.1874-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191205140407.1874-1-dja@axtens.net>
References: <20191205140407.1874-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="HyowXUY/";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

kasan_release_vmalloc uses apply_to_page_range to release vmalloc
shadow. Unfortunately, apply_to_page_range can allocate memory to
fill in page table entries, which is not what we want.

Also, kasan_release_vmalloc is called under free_vmap_area_lock,
so if apply_to_page_range does allocate memory, we get a sleep in
atomic bug:

	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:

	Call Trace:
	 __dump_stack lib/dump_stack.c:77 [inline]
	 dump_stack+0x199/0x216 lib/dump_stack.c:118
	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
	 alloc_pages include/linux/gfp.h:532 [inline]
	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
	 apply_to_pte_range mm/memory.c:2031 [inline]
	 apply_to_pmd_range mm/memory.c:2068 [inline]
	 apply_to_pud_range mm/memory.c:2088 [inline]
	 apply_to_p4d_range mm/memory.c:2108 [inline]
	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
	 __vmalloc_node mm/vmalloc.c:2607 [inline]
	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
	 __do_sys_setsockopt net/socket.c:2133 [inline]
	 __se_sys_setsockopt net/socket.c:2130 [inline]
	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
	 entry_SYSCALL_64_after_hwframe+0x49/0xbe

Switch to using the apply_to_existing_pages helper instead, which
won't allocate memory.

Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Andrew, if you want to take this, it replaces
"kasan: Don't allocate page tables in kasan_release_vmalloc()"
---
 mm/kasan/common.c | 8 +++++---
 1 file changed, 5 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e04e73603dfc..26fd0c13dd28 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -957,6 +957,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 {
 	void *shadow_start, *shadow_end;
 	unsigned long region_start, region_end;
+	unsigned long size;
 
 	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
 	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
@@ -979,9 +980,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
 
 	if (shadow_end > shadow_start) {
-		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
-				    (unsigned long)(shadow_end - shadow_start),
-				    kasan_depopulate_vmalloc_pte, NULL);
+		size = shadow_end - shadow_start;
+		apply_to_existing_pages(&init_mm, (unsigned long)shadow_start,
+					size, kasan_depopulate_vmalloc_pte,
+					NULL);
 		flush_tlb_kernel_range((unsigned long)shadow_start,
 				       (unsigned long)shadow_end);
 	}
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205140407.1874-2-dja%40axtens.net.
