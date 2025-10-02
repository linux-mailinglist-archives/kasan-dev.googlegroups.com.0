Return-Path: <kasan-dev+bncBDIIZHFC4EKRBYES7DDAMGQEODQ6TNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id ACCC9BB280F
	for <lists+kasan-dev@lfdr.de>; Thu, 02 Oct 2025 07:10:58 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-27eca7298d9sf12155825ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Oct 2025 22:10:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759381857; cv=pass;
        d=google.com; s=arc-20240605;
        b=D990QNP1M6/pLUc8uaF5VZqMU9pBVr4qkZ2LxBLb9cmhnU3G+GOsgphfZpPQALh1vF
         f8RTip4eRcJdnCp5Lq6XgHjvMYdckBbLNCNjLx2f28dXNY3fZbjpReZCRcW1O38Xrmi6
         oNyuGQDxH3SdOhvpH24T7KWlRLzpcjm9N05Kxwpv4VE8DcIbNc0HT3DVtfes6kYha2mT
         68iafIYXoXw37oaRhLuagVH4s20xOiLeU6N23s+KSzt0WzeuEC9Bbc+JCq9vgA5EorPI
         XQkuqxBBDHCAnEoL+McdlrGThOPBn1+RLnG9UET13oq+FdlGkiOzf74kmnsJd6kAsjA+
         sftg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=RaxoZIy5H2zqby5kffEpT1Lxej9CbGDV2qowcyrDKSI=;
        fh=bq2OmBqc2cKpvFZyOFnOcIKD11lpQmPVezh7N9wFaxw=;
        b=D+rilkoMIOs1ZbFixhAW0HDvl4evhmKQGWfOxG7BiG/5tMU2p3TnAIrI0EoWZ5xE9f
         gcPDmX6o/QByH4f3m0r5x/AgWj01CzojV1z9Q9xUsQyFgh4YJfMzfcYYe++bd8zukdP5
         s/PNKfSrvPWm0yFjbqoyRgiBQ/5+5yfazLYcHffRkHHBBJNg4QvbK8zJMWCFsbXZ2mf1
         zKIHH0h5OsaXN/K9+yUHwJl1RAssV+3fksqvYhXklhgoH9f6lPRd0mRY/4iCIkJInhVs
         gEESTfEIoRVmTxdPL5BTY4pn4LMwr6xaH3cu3XVQoh3+L0oVzACyriNf7I9z7d/CmLVo
         urHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UQd73q1D;
       spf=pass (google.com: domain of syoshida@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=syoshida@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759381857; x=1759986657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RaxoZIy5H2zqby5kffEpT1Lxej9CbGDV2qowcyrDKSI=;
        b=hiXUe6rlth4Re+2Fsv7ypVqM1jMXeZFFaJDIRMrrdlT9AXIkcP04/X+beNsvmPw4SI
         YZoQj6FVjFZ4uTT1OVw0vvMobGeVRI3OctsWqWUCdeczoWGepRttNfw7lSFeTdyI6qZA
         OBK+/Dq8E6woVbBUjo3GEGd9oB3S1V1AQaUfGLVizwe4ctzrsfdjY74cpmsvcSVpptzI
         XFSYF78S4yeBfBRfFHwUIUJCUdZe8koqKTHVyQniwD2s5TNtbDUboDSDSP3Ua/opRC0B
         OUS0XMHhLwFz4rv0PXkjDYS/1WEMtNa/rjkM1pvs5gH8C0FXOTZSODOzKHxJ4kPuCW/M
         CoRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759381857; x=1759986657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RaxoZIy5H2zqby5kffEpT1Lxej9CbGDV2qowcyrDKSI=;
        b=vOra10hNHHEreFsigFSKo5Xl9uLuYNV8TXm+a9Wx+RWXh65GWF4SzgRt9UsvnIlICk
         WJ//hq6L1IoWVWIHsProTgpwq6TkP+1Tg3XSSG/jugLYYbcrIxZkHOC5qJJ8RcE0b6Vm
         X27b7obEnfz4PTcgo3/kxyFEYRfJ9a5orDGRwQ/ZF5KbxqtQb/I6eh39ForDfRwrOosL
         AVP4Zpf2kc/nZ15gweuZ7Wcz8lWArLT2mQ7pWtc+J84w+PKQCRzIk7GLTL3bnhyOkFXI
         9Liqzf0l3YQOA321aevtO8i5autV03I7YBCSiFiYUxazFwkBQ4aUIHNj4ctBkjDgqVwZ
         n4vA==
X-Forwarded-Encrypted: i=2; AJvYcCW1HW7qIGaVPgjj6YPYyCf8RSMbtNS1HmhO8IUPck1vhwNrBf9/gXlYFsYyAFZp9oX5Xt08UQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz/Wg425ZtoVAnnd6K8y5qQdK/thAb/ZOcehEjtc1hwpwXlYdMB
	frVs19eqhLaXhLFahm4qBL7+4iKEOyLEoi8tNMqi6EKkm5DojkqzbgJf
X-Google-Smtp-Source: AGHT+IE8LMeW4v49SLOkJQg7MGMEnD8mopF85+7Gz3OAwZorqIzXIRmtisWaOJQH3FeF03ZQ5BO8Ow==
X-Received: by 2002:a17:903:350d:b0:26b:3aab:f6b8 with SMTP id d9443c01a7336-28e7f4444d1mr76688545ad.58.1759381856649;
        Wed, 01 Oct 2025 22:10:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5elHoxve17vm+sOQvTCBKPwpx6B8sCNJgE1wzp+895Ag=="
Received: by 2002:a17:902:cf07:b0:263:df8b:ff32 with SMTP id
 d9443c01a7336-28e8d204b84ls7349385ad.0.-pod-prod-03-us; Wed, 01 Oct 2025
 22:10:55 -0700 (PDT)
X-Received: by 2002:a17:903:4b47:b0:264:8a8d:92e8 with SMTP id d9443c01a7336-28e7f446c33mr71126465ad.59.1759381855261;
        Wed, 01 Oct 2025 22:10:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759381855; cv=none;
        d=google.com; s=arc-20240605;
        b=G0HcpiuKyEPT3YZOt2OMc+YnHdhgbE6qp4iqANI0tAVCX3L8ZtoOVxYVzeT1d/nJSS
         DRFvzk2GmLiB5oQ+B+e+a/g886ov0X8rgEVNmA+vSbSAJbR34fig63H3VaD2u2f4m9J/
         QJwl4S1qjyf73I3IX6VJpL3c/rVnQwlPcaUeL7PsrikjEflbQR0kPhErEWbKTjAXPfis
         bLI+FiIWZxddtP5xEMPVBvX9gSwbvFvgQFkifLwyhYpqkdPwqS7O/YZ1oldMIP0rRAwT
         d2kjqshyHzql9X990amr9mw2FLxQQHGVx90T3J5fx3kfG23AXueW/q57KSgX90wqiWQs
         4eoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=4JQvSrEFCsoxe5xRRs2Oi0PpRnlMQT2kkhwm1m9/XgY=;
        fh=xgpgzEuUbPU7O68SgaIDBLngfimYlmnQYiYtRWPeMLA=;
        b=RQmzmbNcdRGS2y80KQ1aVYpeOxefkXbx73e008RCMtgxYFUIBmHzc6UA0RihybGHqc
         CiCwglWEDVLuP/x+CiTKiQ1l+ze9ZGT2e089C9jXdmWqoit5/7z8Dxn+8Dlald8ro4fb
         rzyHpr9JBtrq2l0r1dCVh3sIWb4pfoW7geIuPoyaD5/UlZzgc3qBUQyukBpAufjrlmeQ
         h9VxP7TMZSRoCxomVd4qC9vA+Dna0e7Hw9wnjFlJYL40xNquRLqOINxwLZnrzeUf1h2p
         m2i+DAEVBaC/23Dh0kQgkA6pkABcTcMtkWwjyWtkFGYXSE3dUS18R488Uu02JHGPq24k
         QaNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UQd73q1D;
       spf=pass (google.com: domain of syoshida@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=syoshida@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-28e8d03034asi663615ad.0.2025.10.01.22.10.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Oct 2025 22:10:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of syoshida@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-pl1-f197.google.com (mail-pl1-f197.google.com
 [209.85.214.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-80-6WHdbZF5NKGhCVsgF5yIuQ-1; Thu, 02 Oct 2025 01:10:52 -0400
X-MC-Unique: 6WHdbZF5NKGhCVsgF5yIuQ-1
X-Mimecast-MFC-AGG-ID: 6WHdbZF5NKGhCVsgF5yIuQ_1759381852
Received: by mail-pl1-f197.google.com with SMTP id d9443c01a7336-28c58e009d1so9937905ad.3
        for <kasan-dev@googlegroups.com>; Wed, 01 Oct 2025 22:10:52 -0700 (PDT)
X-Gm-Gg: ASbGncvR4ETGvSRYHQattGmqGTJs6RuFxhDXfodz8iZ1eyl+n/c0JxU71+5vzHSZuaL
	mZYRPyAOaP5JTsyiv7GZXWJhwp8Hp/AITgjsTSt8btyN0697N/PqjrI/DE2KRQYW9v9lfjP+46E
	RTj6dhYvuIUyUx6tOBAY9O4XlDyNTlAKMpRERguRW/bLpO2xQ9CypKCcnMi7LL3aGWYMU4qAWTi
	3EKV0W6Odsnr/gXhw9ZPnGvESAyNJIjANLcgtargom02laxAzP+CST2hOTSDsyiuxjUh753ML/w
	KRd5T+AqNVK9fIjH3pYfTA80Q/faIBImnA3PVGZgeKd3ew4=
X-Received: by 2002:a17:902:ea0f:b0:27e:f005:7d0f with SMTP id d9443c01a7336-28e7f32fa44mr76227895ad.44.1759381851854;
        Wed, 01 Oct 2025 22:10:51 -0700 (PDT)
X-Received: by 2002:a17:902:ea0f:b0:27e:f005:7d0f with SMTP id d9443c01a7336-28e7f32fa44mr76227545ad.44.1759381851283;
        Wed, 01 Oct 2025 22:10:51 -0700 (PDT)
Received: from kernel-devel ([240d:1a:c0d:9f00:be24:11ff:fe35:71b3])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-28e8d1e9de2sm12545715ad.121.2025.10.01.22.10.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Oct 2025 22:10:50 -0700 (PDT)
From: "'Shigeru Yoshida' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jgg@ziepe.ca,
	leon@kernel.org,
	m.szyprowski@samsung.com
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Shigeru Yoshida <syoshida@redhat.com>
Subject: [PATCH] kmsan: fix kmsan_handle_dma() to avoid false positives
Date: Thu,  2 Oct 2025 14:10:24 +0900
Message-ID: <20251002051024.3096061-1-syoshida@redhat.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: GJpcZHm6uxXDrdmyP76f5j-Z_QGMzt33b3N0ywi8iXg_1759381852
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: syoshida@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UQd73q1D;
       spf=pass (google.com: domain of syoshida@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=syoshida@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Shigeru Yoshida <syoshida@redhat.com>
Reply-To: Shigeru Yoshida <syoshida@redhat.com>
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

KMSAN reports an uninitialized value issue in dma_map_phys()[1].  This
is a false positive caused by the way the virtual address is handled
in kmsan_handle_dma().  Fix it by translating the physical address to
a virtual address using phys_to_virt().

[1]
BUG: KMSAN: uninit-value in dma_map_phys+0xdc5/0x1060
 dma_map_phys+0xdc5/0x1060
 dma_map_page_attrs+0xcf/0x130
 e1000_xmit_frame+0x3c51/0x78f0
 dev_hard_start_xmit+0x22f/0xa30
 sch_direct_xmit+0x3b2/0xcf0
 __dev_queue_xmit+0x3588/0x5e60
 neigh_resolve_output+0x9c5/0xaf0
 ip6_finish_output2+0x24e0/0x2d30
 ip6_finish_output+0x903/0x10d0
 ip6_output+0x331/0x600
 mld_sendpack+0xb4a/0x1770
 mld_ifc_work+0x1328/0x19b0
 process_scheduled_works+0xb91/0x1d80
 worker_thread+0xedf/0x1590
 kthread+0xd5c/0xf00
 ret_from_fork+0x1f5/0x4c0
 ret_from_fork_asm+0x1a/0x30

Uninit was created at:
 __kmalloc_cache_noprof+0x8f5/0x16b0
 syslog_print+0x9a/0xef0
 do_syslog+0x849/0xfe0
 __x64_sys_syslog+0x97/0x100
 x64_sys_call+0x3cf8/0x3e30
 do_syscall_64+0xd9/0xfa0
 entry_SYSCALL_64_after_hwframe+0x77/0x7f

Bytes 0-89 of 90 are uninitialized
Memory access of size 90 starts at ffff8880367ed000

CPU: 1 UID: 0 PID: 1552 Comm: kworker/1:2 Not tainted 6.17.0-next-20250929 #26 PREEMPT(none)
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.17.0-5.fc42 04/01/2014
Workqueue: mld mld_ifc_work

Fixes: 6eb1e769b2c1 ("kmsan: convert kmsan_handle_dma to use physical addresses")
Signed-off-by: Shigeru Yoshida <syoshida@redhat.com>
---
The hash in the "Fixes" tag comes from the linux-next tree
(next-20250929), as it has not yet been included in the mainline tree.
---
 mm/kmsan/hooks.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 90bee565b9bc..2cee59d89c80 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -339,13 +339,12 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir)
 {
-	struct page *page = phys_to_page(phys);
 	u64 page_offset, to_go;
 	void *addr;
 
 	if (PhysHighMem(phys))
 		return;
-	addr = page_to_virt(page);
+	addr = phys_to_virt(phys);
 	/*
 	 * The kernel may occasionally give us adjacent DMA pages not belonging
 	 * to the same allocation. Process them separately to avoid triggering
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251002051024.3096061-1-syoshida%40redhat.com.
