Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBCEYTHFQMGQEVKILEEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 05A02D1922E
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 14:43:39 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-34c2b8720fasf2521104a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 05:43:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768311817; cv=pass;
        d=google.com; s=arc-20240605;
        b=CLHSEvdEO+bTO8h+jRxT97yKKLHfNAUcEiMZa8+3ABxQQZ8Mkq99JhBjRElMJFdFxM
         Fx6uDSfNsbCYAeIcW1q8EGBikGWHzIeCFBrzBbG8xkx4zSyqwc3SK4c9V+6y50UTxt1a
         AkA4a5UEzni5ojd8F63r43nA6VqeTVVvT8Sylgn7hscXx0X3pVc8uYfWsoSna3rwrhIQ
         2cUAZqmG8ufsH+zrpmaEBPFvLq/w0SzfHZqXk+N/Pn/POKog3K81O7eqxZpQABLnnjnh
         ICEP90HYiPxJmtkPnlCnGeFJRi2PdKa56251bJORiC7mQRyyLazkoRieucyHp8Lydnyt
         9iWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=UFkrhzQ+H+eD9Q6RyzPu2+tihmJAszVuMruWaUBLj4k=;
        fh=xdbWTNLST0r2ON8oaWUBzeB+ZuGTpKCSLhtrkn9IJYQ=;
        b=jJc/hLTTikJCNrCSoItYlphdjenpjoUIkampe29pUdvTyp8v5CU8zkRr8H62YqfO3Q
         8CCP0nXxRljh+371GwadtG6J+CMQuMUKsa/OhmaoEE2C2JGfmRsobZNUqrcktZA18I0b
         emlnZURzu1MwIhNgyFJm6bzUxQvYq5QMsRJKSPFRqL7+f+kXs//WNoPmjTFGnuyZRNC3
         qkky6E0LHmUYlcZfunMJMsXc2uwIJclyNDjDMWb8TTQ6OYQCwC8TuCtvhkM9vL+RvRxu
         fSSPUDQFrhnjZlHi1LaL2Pykv+b5y7BLP05RAK+z0D+8m15PWMSKCH1VRPZ/Umpub0zn
         iLpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q7awYaCE;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768311817; x=1768916617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UFkrhzQ+H+eD9Q6RyzPu2+tihmJAszVuMruWaUBLj4k=;
        b=xl406nNVasdskEWLLP+ONN09khDIDPAoUAd427jU412olzNXywqlOtnO5r6ZktKlmN
         88nH3p89+RoCrxTVN5eUNPZdc7PGDbUiel4qW2Y6hVJAEPVhcU+SFUl4xK9UN/Rl+ed4
         31o6nkLhU3wTxfhMPn0R2+UDTMOgJH1oa9YMaQg2wXGVHI1El088D+90K/Du+iDXmbGO
         Zsm2sm5umX3XLwT0BfS71fbaTBHM+YqATNvpH46O5zTxgpKDOYaCjvpNeURQwuw+s4Jw
         BMvkVPzNTkfT4Txg8qQHZ1qIyJ4H5850F+PCSDOyrmYtcIrLeLpt3AfvKMK3iqv0VFDf
         YZuQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768311817; x=1768916617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UFkrhzQ+H+eD9Q6RyzPu2+tihmJAszVuMruWaUBLj4k=;
        b=T1gSag/4dPlFpcKSL5qWmduTq+j+VmOm5U4MXDSc+g1yaWjiolCw7MBMlDswypmVnk
         kVy3vQpQyVxEg2GvEGWpcPIWWv2oRaXM7Kx1dXSV6nGpyz6cc8chuI8LJHQ/oyuVJ1BF
         zkng3xVImVm2MZ3FNSdclh3XMT//kuJFZL7wkLa/u+VtuVB5lPeukt5QAtgLmNMI+GY8
         2mSX4ZnIY0V6wuiI0xnZsqy6mN/8wnEVWpekre3dm08gAwopJHwMkqWXq7usf6I+eYPW
         yR7KGofMoCZTryYnqL320Lpg14wfG2T6oZQAiRv5x0Q5ArI9Umiq9bL330+FDizO9Vr0
         z86w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768311817; x=1768916617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UFkrhzQ+H+eD9Q6RyzPu2+tihmJAszVuMruWaUBLj4k=;
        b=AfFNMHAmAQZ2p/Gtm1wdKGHNt08yigNhwVr8UHzWdLEBh3HgdI5dxwMQlOvOlv8JEV
         xhbm8vPlplqULUtQB4r0cP6Iwm8vGz/XBWERhbelgROWu9+ro4ZsN7tZcKGwjR1iIc/0
         iosQ9yyWlT0Q/hH2QxrkQ9Gao4qvliHEpLgrFliV+p2d5A2GodBE8lWtV3Oqgqdy+CMQ
         ATj6eyHewT8QW5FzBwHiXbZ3+QfGKte8gLo5CXDAIvoASIZ1moHXTHmF9f64bBBgbWIV
         tfC9969rJfRloSRGW2h4Fl8gTgwjFOQ7GGL4cPN51Eb3VzO4oCDzPSfknxggknDwbJtj
         VrXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUI8zXMQFG77ooXYbBWx/L0InvozQXmPZXhpKpF7aQshuNX2t9ixynHC1zZI4AFnIYQCbiidg==@lfdr.de
X-Gm-Message-State: AOJu0YxUsw4yomdFvET0rz2BPipS2XzfeqWBO4oeyobWcai9zMPWDBTG
	5afSQFYaS+XM3Y99JMwt3GGFGVnkOrmJyTJ1Fg91SNXA0hh8VEYQCFei
X-Google-Smtp-Source: AGHT+IEj9duYoFhNUV9Riyh5sMYuzUUjxrSkc7Kjy4oGQ9+YqQOhEZRp+Q2/BQUHZ0N+Oh+OSUyB6w==
X-Received: by 2002:a17:90b:57c4:b0:340:bca2:cf82 with SMTP id 98e67ed59e1d1-34f68ca85f3mr12780223a91.4.1768311817005;
        Tue, 13 Jan 2026 05:43:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G9gHmKtVebRI9DK4lTN5l13GSVo7IWob31I/s4xuCu+A=="
Received: by 2002:a17:90a:ce11:b0:340:be45:629a with SMTP id
 98e67ed59e1d1-34f5ea7434dls5649923a91.2.-pod-prod-09-us; Tue, 13 Jan 2026
 05:43:35 -0800 (PST)
X-Received: by 2002:a05:6a20:7286:b0:35d:53dc:cb52 with SMTP id adf61e73a8af0-3898f8f555dmr18426445637.11.1768311815179;
        Tue, 13 Jan 2026 05:43:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768311815; cv=none;
        d=google.com; s=arc-20240605;
        b=IILDQhyQLFI1d2fL615IXStggeyqBg20Glr7aanOz88C/ojaix0H0SiGDnkfufiVkA
         qWA2mZX+RXg+T2zp6SPC1vZErwC901tza/Bkt4s6Xg2SNf8Wehvug7E73dkZ+n+iS3N6
         fdY61QrlvQWcPOPuW9afO+xB98c1oE0Qi75i79pR8GbyWwbXShMWvdNT4BrippfxV4LD
         fLH4BWHnMR9hABraqj1IXR2u61D7/ylDQ9rOEfHYPe2hcH+kroAs+65OanW+Vs7DwfuH
         hQ0c1aC2FdrrVmRHgcODTahjywBDhrQ7v7IXXxI9weWHaZ3lA85MkEzTTvcrEKV2oxiT
         sSFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2b/x68gTscAwmJtQgXa+XL8/0ARsLeGlB68VJPW+4SU=;
        fh=pL8ytJNtHfkFIqb6trRJmqTouv042fi+/fucj0/gfko=;
        b=KE69bGXDq3uapZB3p0ecEKMrCjyYjqFmpIE25oup1pqtAMUPUueXvamLcq4OjaZ3SP
         UnhNsAFoynoHmJ+1yRJGrfX2N+kwhSOqi5uYsB5JWN6Bco0M+uOWq5opasA16SgAA+pd
         SITjmW6Nlt8R0EvT7thouCQhA+M6bVgs2YbbA9psBpr9vU4yMWgr+ECpIN2+0BG3mCPP
         KflJXPKv5X4AegWfXaPlHbWr/DCnHCHPadE6jfTVEnm4AQBB1IbaBTdLQlLZKymtP+vB
         NlTZajduSVrk7ajEe0MNiN7nR1rKgyQLQOmuE/r1PQ7LdyfP7m+DRI55KHpQJg8sVjT3
         dJtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q7awYaCE;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c4d8ce6c0dfsi603141a12.1.2026.01.13.05.43.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 05:43:35 -0800 (PST)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-81db1530173so1951085b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 05:43:35 -0800 (PST)
X-Gm-Gg: AY/fxX4JlcMU7CqiRSPDwRqFAv/M2hN1w6w/OhNwzZJPGMDc0fDuf+og2JJCbM5p0zO
	fAIAX8FHJKqQB6eA4Acw3xEg0AlVXd++v8BVle8ZKu86ua0Awwm9k+TQpR5r1S5np1DsWac/ZCq
	XY8nM+Xbl+5ZfNoyzD2VTP1O909vRwR84sBXMowzNKvr0+YKxb0r5mFxsLnb6pIG3ceiD8HjiRg
	mBLEJke3qiINNQkMK34G4kQFuDZFzXsR4RYqg5QpmT/DVDHgFhFwbwHB3ytIj8JIMGo33w/3Qg0
	Q0yWCsJd1tV0qusyYEQndnoXETVk0OrzKR/nH/XqHjj2rYHV6WVAz8iFVkOBPGtQEZtrUfb8T9T
	warpAgnN2RMZ8gdw7KhWHpArL8sS9rnLHme23fVPFWLY7oTxNdpCNkKVqGV7yIcEpXMg3k33GEq
	iEeiTkpcJhP0Xscz6ScMz8969gyS4spE8=
X-Received: by 2002:a05:6a00:3003:b0:7f7:58cf:404a with SMTP id d2e1a72fcca58-81b7d86027bmr17114436b3a.13.1768311814067;
        Tue, 13 Jan 2026 05:43:34 -0800 (PST)
Received: from dw-tp.localdomain ([49.205.216.49])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-81df41f5180sm12366037b3a.35.2026.01.13.05.43.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 05:43:33 -0800 (PST)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC] mm/kasan: Fix double free for kasan pXds
Date: Tue, 13 Jan 2026 19:13:25 +0530
Message-ID: <b8976a5d5fcbe8bf919dfa5d8ffbf22be8167eba.1767797480.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.52.0
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q7awYaCE;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

kasan_free_pxd() assumes the page table is always struct page aligned.
But that's not always the case for all architectures. E.g. In case of
powerpc with 64K pagesize, PUD table (of size 4096) comes from slab
cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let's
just directly pass the start of the pxd table which is anyway present in these
functions as it's 1st argument.

This fixes the below double free kasan issue which is sometimes seen with PMEM:

radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB pages
==================================================================
BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20
Free of addr c0000003c38e0000 by task ndctl/2164

CPU: 34 UID: 0 PID: 2164 Comm: ndctl Not tainted 6.19.0-rc1-00048-gea1013c15392 #157 VOLUNTARY
Hardware name: IBM,9080-HEX POWER10 (architected) 0x800200 0xf000006 of:IBM,FW1060.00 (NH1060_012) hv:phyp pSeries
Call Trace:
 dump_stack_lvl+0x88/0xc4 (unreliable)
 print_report+0x214/0x63c
 kasan_report_invalid_free+0xe4/0x110
 check_slab_allocation+0x100/0x150
 kmem_cache_free+0x128/0x6e0
 kasan_remove_zero_shadow+0x9c4/0xa20
 memunmap_pages+0x2b8/0x5c0
 devm_action_release+0x54/0x70
 release_nodes+0xc8/0x1a0
 devres_release_all+0xe0/0x140
 device_unbind_cleanup+0x30/0x120
 device_release_driver_internal+0x3e4/0x450
 unbind_store+0xfc/0x110
 drv_attr_store+0x78/0xb0
 sysfs_kf_write+0x114/0x140
 kernfs_fop_write_iter+0x264/0x3f0
 vfs_write+0x3bc/0x7d0
 ksys_write+0xa4/0x190
 system_call_exception+0x190/0x480
 system_call_vectored_common+0x15c/0x2ec
---- interrupt: 3000 at 0x7fff93b3d3f4
NIP:  00007fff93b3d3f4 LR: 00007fff93b3d3f4 CTR: 0000000000000000
REGS: c0000003f1b07e80 TRAP: 3000   Not tainted  (6.19.0-rc1-00048-gea1013c15392)
MSR:  800000000280f033 <SF,VEC,VSX,EE,PR,FP,ME,IR,DR,RI,LE>  CR: 48888208  XER: 00000000
<...>
NIP [00007fff93b3d3f4] 0x7fff93b3d3f4
LR [00007fff93b3d3f4] 0x7fff93b3d3f4
---- interrupt: 3000

 The buggy address belongs to the object at c0000003c38e0000
  which belongs to the cache pgtable-2^9 of size 4096
 The buggy address is located 0 bytes inside of
  4096-byte region [c0000003c38e0000, c0000003c38e1000)

 The buggy address belongs to the physical page:
 page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x3c38c
 head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
 memcg:c0000003bfd63e01
 flags: 0x63ffff800000040(head|node=6|zone=0|lastcpupid=0x7ffff)
 page_type: f5(slab)
 raw: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
 raw: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
 head: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
 head: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
 head: 063ffff800000002 c00c000000f0e301 00000000ffffffff 00000000ffffffff
 head: ffffffffffffffff 0000000000000000 00000000ffffffff 0000000000000004
 page dumped because: kasan: bad access detected

[  138.953636] [   T2164] Memory state around the buggy address:
[  138.953643] [   T2164]  c0000003c38dff00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953652] [   T2164]  c0000003c38dff80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953661] [   T2164] >c0000003c38e0000: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953669] [   T2164]                    ^
[  138.953675] [   T2164]  c0000003c38e0080: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953684] [   T2164]  c0000003c38e0100: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953692] [   T2164] ==================================================================
[  138.953701] [   T2164] Disabling lock debugging due to kernel taint

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---

It will be very helpful if one can review this path more thoroughly as I am not
much aware of this code paths of page table freeing in kasan. But it logically
looked ok to me to free all PXDs in the same fashion.

 mm/kasan/init.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index f084e7a5df1e..9c880f607c6a 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -292,7 +292,7 @@ static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
 			return;
 	}

-	pte_free_kernel(&init_mm, (pte_t *)page_to_virt(pmd_page(*pmd)));
+	pte_free_kernel(&init_mm, pte_start);
 	pmd_clear(pmd);
 }

@@ -307,7 +307,7 @@ static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
 			return;
 	}

-	pmd_free(&init_mm, (pmd_t *)page_to_virt(pud_page(*pud)));
+	pmd_free(&init_mm, pmd_start);
 	pud_clear(pud);
 }

@@ -322,7 +322,7 @@ static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
 			return;
 	}

-	pud_free(&init_mm, (pud_t *)page_to_virt(p4d_page(*p4d)));
+	pud_free(&init_mm, pud_start);
 	p4d_clear(p4d);
 }

@@ -337,7 +337,7 @@ static void kasan_free_p4d(p4d_t *p4d_start, pgd_t *pgd)
 			return;
 	}

-	p4d_free(&init_mm, (p4d_t *)page_to_virt(pgd_page(*pgd)));
+	p4d_free(&init_mm, p4d_start);
 	pgd_clear(pgd);
 }

--
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b8976a5d5fcbe8bf919dfa5d8ffbf22be8167eba.1767797480.git.ritesh.list%40gmail.com.
