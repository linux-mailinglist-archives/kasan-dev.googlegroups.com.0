Return-Path: <kasan-dev+bncBCAJFDXE4QGBBH5J2C3QMGQELXESJHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BDEF985EFE
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 15:48:16 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6cb27fb4c98sf5725726d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 06:48:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727272095; cv=pass;
        d=google.com; s=arc-20240605;
        b=MFWSwdd/Flbdr1AI+O3i8+y6Mhw0VopkB3ajrUCDhT+dy6Pu6gGZaROkbxVd1xnNTs
         RbL0f6vLo4n9o/coJxiieiHT2psKAK5Zb+w8IMk4wyj5da4uqaMi+rpF6lCjr8JxFVVd
         vghVhczgvquxRuCmamNcwCOqglS/nKRFFm+qGOPWRKIgz31bs0Gi3ovYRzD6IhKs5m4N
         mhCaJxkzr3Zv03ImHx8Nrkxuw2xULkI0wANyXNQwdL1SnwcECSdMnMEqFZ9CyibjnC+D
         NJQ+I+b0xFeq5c978hK3i/0iSqck8x53vqWj71A6nLOvKKzb7mJDIFv7bj7Al8Vj+B9O
         41zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=Tmh+s9TVB5zTn4zCZeXKD/FlgQWCEnP6vwHx5vEES8s=;
        fh=c8SPbfkUFzzH4Sn+cTqW7nvH27jJ8Wd4iN/VbXeLvN8=;
        b=EJ8VxfCRT51kMgpdWA9JYymL0R5DejHEgfNvHtQxgSPhYyYDmujOgQApNysjUUY2WW
         RrdV2zNI2xHq6b83BsEPkYluLR80Uqjy9gsBZY5UEYWefsRyChwBMRoPqOUhklGFc/0h
         /Oa4btEOaRD3dXAaB3mQ0LOOc96N+AXUaIvaxV+BRQLkGIyGhqHzv7rEnNRMZHEwE5Hg
         HwRahWYuS8Yc5Lu6hNpCLOE+WfeTOo35M30bzVjtY/UQY4+RCvifGOFSlWdDM7Zy9bIo
         8BDjGTJjXZzueMQgyv808nYDo91H52GjljtKBN/LcLPHpbEn4tw56oXsfZlXgHV+dHf7
         Dwhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WCQzURMs;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727272095; x=1727876895; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tmh+s9TVB5zTn4zCZeXKD/FlgQWCEnP6vwHx5vEES8s=;
        b=m+L/d8Uob+x2eHHt2Bdql0mP9YRARshJgowHe5gngmKRz5hnX8htTEgWVpz1TGyTEn
         hN/Ww1gKlDs9ywsnk3kWCSqfsMy6cJOSBhHwOPEQu2vYpoyRNPYLmIZlW2bVgn805SNG
         xVF8Kgsp/bSNswzpdbJDuMhE7p7AqY7RNK6qQRXuEOxXvSPdpgjTOrh6ECH9XzYwvkOY
         PRMGm9FuFvDmK3YLmdyrQu2+jHwazt9O8wdoJPH28yJsL/GmmPj7iiBh4ftzEqXCSKF/
         4J82gB6RRy9VZeqCl6YzwKheFajabaYP2pHoxpWdmokS6L46Ji3koomuAUCavJAVZId3
         S2Bw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727272095; x=1727876895; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Tmh+s9TVB5zTn4zCZeXKD/FlgQWCEnP6vwHx5vEES8s=;
        b=XNOAKsE5e1DXVf39UYTCxa2gNseq7QP5J7UADOptHD3FPm4M8fH/bezd3nCKhesSsE
         ORLE9vrpj5p2ciENK/cyZ/okwgOecUl74ju5qOZr6sAohbVWH3WNPNIiH8QYpy9Z3D2q
         3eLTYyYCeAFSWCFhKcRyP5x5OMQxu/stpvLLZq64OsoZAv5fmA1DJgzHewDaGEhC5upD
         KsmS/25pmHUSTbO4VCdf/f5Yg7Lig84k29Zxkd3E/BaeIqEsEVoaMtaMMByjQ1eUcUoy
         xsDNveicYVOkLAN2cCq9eVePo+Pte33B8jXsPyR8KqY2tqVetgnwyZNHTxjgSk5Xx43N
         3yOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727272095; x=1727876895;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tmh+s9TVB5zTn4zCZeXKD/FlgQWCEnP6vwHx5vEES8s=;
        b=qoiSOVvGG4IxE29L3eb9YD3FM9XSGn3ZUWZpRiaEpvNtHdGC1sS5OK9nV6kj3n/OzC
         UAII+skVKK6B8qNR80mCizcdl/SDdTE/2bSPWfWAqEfthbZoW2stkIsBZ3Exlspu6u2D
         zpvYS1ANLLvc2maO3clG1TVbvR0EKFmdzsdSqVZg50XLsSxhJfc3zDf9uRiUK1Cnfmg0
         D0wBWYsXzWqqsAhtKH1vPU4YM916NiaKSjtbPluPVn8Bk/1GpbXOs9/CmEuCfFPujuDi
         lxV/mz91GieKZ7TpJkZuKPo0ywJloV5C/ebhCwEbp/4FDB63dlvO/Vxls5gKFzEzs7An
         SPEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsa7gvdB8+o+lQtwSZWLa1yin2ofjHSafwr54XLAa3vyXZY3GEjTvlR/giW2rzycGtsKVjbg==@lfdr.de
X-Gm-Message-State: AOJu0YzBe5dCaxeMEY31hNGLQIr1gkr7Ut98lfmAY7j3iVbURZhKfB7o
	tdx6B4Kwx8arrI5GWcgQCp29hCbp+J0nsaCf2C0oxKTe9fyuJkj4
X-Google-Smtp-Source: AGHT+IFXQFABhJNRJaKBfw0nTYrRRVnPERD1VOI8kVWVcvytF87ks+Xo7mx1kLWCC5xRaYQ2yyWVmw==
X-Received: by 2002:a05:6214:3d99:b0:6c5:2fc7:a623 with SMTP id 6a1803df08f44-6cb1dd17561mr48644546d6.11.1727272095388;
        Wed, 25 Sep 2024 06:48:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:21c4:b0:6b0:8881:bc19 with SMTP id
 6a1803df08f44-6c6a7f9b1d2ls117538706d6.1.-pod-prod-08-us; Wed, 25 Sep 2024
 06:48:14 -0700 (PDT)
X-Received: by 2002:a05:620a:170b:b0:7a3:785a:dc1c with SMTP id af79cd13be357-7ace744d99amr371914085a.50.1727272094684;
        Wed, 25 Sep 2024 06:48:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727272094; cv=none;
        d=google.com; s=arc-20240605;
        b=cLOztUH3KbLNKnYldxvUzRfA2zQ2Fa5K08epwKMSIZJ2gfsMAthFw2FcwJv08EMXuN
         92xwMuyXby0BwuUdPFUd5VjIplrf0bGmPdP5CDXxbzJ1PfC5i1dqELUa43xzJMsEPnyR
         /Tp26gZmkZuLR2BNu515/ML5GKRpK8Z3tUfREdY71iyNUQSbYeofG5tQgNGGZKewrwJW
         9/VpaKiq+M8ulECNeYOn0RnM5zIK+46PkAz8nMlQC8nNHFgMjIeREpU716+ealY/s7bT
         YhG4aeWzMcoPYkZGLmJRBeE8Fh5oj3MlTlhuWZQRgBWXb1t4qU+qPFp9xCQ6wEzHeaIQ
         773A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5Ssh+pRrf5L+2e4qG8n4IwFFdzUvMFGa+rHl+gGVC1w=;
        fh=3d4rYj7y2TlmClP/cIrdUmUATLndWk9RpmrEI0CRy8s=;
        b=OdtBAQRsz0qc/nzB0lR2CZGnJIb4oEl1HaIlPQ/h0nLkNLrEvYXqXfI29yoAWwYiF7
         I/rnoHCDDjsgSOF6z6VYycHqZzBZXbG8ZWPKVLRXU+Ka2vufWyivhxTIuLhOyUmSzifU
         nYFQh7kIz0Ts9vOLASUFUUJlxO5E7XVZvV9ICD5hRlOuajp06yF+RB4T3EG1g44YcQzv
         oXzdAHJjhkxjjhth78lN/21zmPYWVrampkNFPFzTR/eYhWLM8Lem52ps5UE1mRh47/VI
         rO+ZyJxh+T50VZuZAr+X81nMhYYzjDFtnEh2wj5rFsdSM13EfHfFV6vSxeGuD9UORAg3
         dQKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WCQzURMs;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7acde5cbcdfsi16496585a.3.2024.09.25.06.48.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 06:48:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-20b0b2528d8so5393715ad.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 06:48:14 -0700 (PDT)
X-Received: by 2002:a17:903:234f:b0:209:dc6d:7697 with SMTP id d9443c01a7336-20afc44865bmr34325865ad.24.1727272093509;
        Wed, 25 Sep 2024 06:48:13 -0700 (PDT)
Received: from AHUANG12-3ZHH9X.lenovo.com (220-143-197-103.dynamic-ip.hinet.net. [220.143.197.103])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-20af16e7f40sm24958805ad.8.2024.09.25.06.48.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Sep 2024 06:48:13 -0700 (PDT)
From: Adrian Huang <adrianhuang0701@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Adrian Huang <ahuang12@lenovo.com>
Subject: [PATCH 1/1] kasan, vmalloc: avoid lock contention when depopulating vmalloc
Date: Wed, 25 Sep 2024 21:47:32 +0800
Message-Id: <20240925134732.24431-1-ahuang12@lenovo.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WCQzURMs;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Adrian Huang <ahuang12@lenovo.com>

When running the test_vmalloc stress on a 448-core server, the following
soft/hard lockups were observed and the OS was panicked eventually.

1) Kernel config
   CONFIG_KASAN=y
   CONFIG_KASAN_VMALLOC=y

2) Reproduced command
   # modprobe test_vmalloc nr_threads=448 run_test_mask=0x1 nr_pages=8

3) OS Log: Detail is in [1].
   watchdog: BUG: soft lockup - CPU#258 stuck for 26s!
   RIP: 0010:native_queued_spin_lock_slowpath+0x504/0x940
   Call Trace:
    do_raw_spin_lock+0x1e7/0x270
    _raw_spin_lock+0x63/0x80
    kasan_depopulate_vmalloc_pte+0x3c/0x70
    apply_to_pte_range+0x127/0x4e0
    apply_to_pmd_range+0x19e/0x5c0
    apply_to_pud_range+0x167/0x510
    __apply_to_page_range+0x2b4/0x7c0
    kasan_release_vmalloc+0xc8/0xd0
    purge_vmap_node+0x190/0x980
    __purge_vmap_area_lazy+0x640/0xa60
    drain_vmap_area_work+0x23/0x30
    process_one_work+0x84a/0x1760
    worker_thread+0x54d/0xc60
    kthread+0x2a8/0x380
    ret_from_fork+0x2d/0x70
    ret_from_fork_asm+0x1a/0x30
   ...
   watchdog: Watchdog detected hard LOCKUP on cpu 8
   watchdog: Watchdog detected hard LOCKUP on cpu 42
   watchdog: Watchdog detected hard LOCKUP on cpu 10
   ...
   Shutting down cpus with NMI
   Kernel Offset: disabled
   pstore: backend (erst) writing error (-28)
   ---[ end Kernel panic - not syncing: Hard LOCKUP ]---

BTW, the issue can be also reproduced on a 192-core server and a 256-core
server.

[Root Cause]
The tight loop in kasan_release_vmalloc_node() iteratively calls
kasan_release_vmalloc() to clear the corresponding PTE, which
acquires/releases "init_mm.page_table_lock" in
kasan_depopulate_vmalloc_pte().

The lock_stat shows that the "init_mm.page_table_lock" is the first entry
of top list of the contentions. This lock_stat info is based on the
following command (in order not to get OS panicked), where the max
wait time is 600ms:

  # modprobe test_vmalloc nr_threads=150 run_test_mask=0x1 nr_pages=8

<snip>
------------------------------------------------------------------
class name con-bounces contentions waittime-min   waittime-max ...
------------------------------------------------------------------
init_mm.page_table_lock:  87859653 93020601  0.27 600304.90 ...
  -----------------------
  init_mm.page_table_lock  54332301  [<000000008ce229be>] kasan_populate_vmalloc_pte.part.0.isra.0+0x99/0x120
  init_mm.page_table_lock   6680902  [<000000009c0800ad>] __pte_alloc_kernel+0x9b/0x370
  init_mm.page_table_lock  31991077  [<00000000180bc35d>] kasan_depopulate_vmalloc_pte+0x3c/0x70
  init_mm.page_table_lock     16321  [<000000003ef0e79b>] __pmd_alloc+0x1d5/0x720
  -----------------------
  init_mm.page_table_lock  50278552  [<000000008ce229be>] kasan_populate_vmalloc_pte.part.0.isra.0+0x99/0x120
  init_mm.page_table_lock   5725380  [<000000009c0800ad>] __pte_alloc_kernel+0x9b/0x370
  init_mm.page_table_lock  36992410  [<00000000180bc35d>] kasan_depopulate_vmalloc_pte+0x3c/0x70
  init_mm.page_table_lock     24259  [<000000003ef0e79b>] __pmd_alloc+0x1d5/0x720
  ...
<snip>

[Solution]
After re-visiting code path about setting the kasan ptep (pte pointer),
it's unlikely that a kasan ptep is set and cleared simultaneously by
different CPUs. So, use ptep_get_and_clear() to get rid of the spinlock
operation.

The result shows the max wait time is 13ms with the following command
(448 cores are fully stressed):

  # modprobe test_vmalloc nr_threads=448 run_test_mask=0x1 nr_pages=8

<snip>
------------------------------------------------------------------
class name con-bounces contentions waittime-min   waittime-max ...
------------------------------------------------------------------
init_mm.page_table_lock:  109999304  110008477  0.27  13534.76
  -----------------------
  init_mm.page_table_lock 109369156  [<000000001a135943>] kasan_populate_vmalloc_pte.part.0.isra.0+0x99/0x120
  init_mm.page_table_lock    637661  [<0000000051481d84>] __pte_alloc_kernel+0x9b/0x370
  init_mm.page_table_lock      1660  [<00000000a492cdc5>] __pmd_alloc+0x1d5/0x720
  -----------------------
  init_mm.page_table_lock 109410237  [<000000001a135943>] kasan_populate_vmalloc_pte.part.0.isra.0+0x99/0x120
  init_mm.page_table_lock    595016  [<0000000051481d84>] __pte_alloc_kernel+0x9b/0x370
  init_mm.page_table_lock      3224  [<00000000a492cdc5>] __pmd_alloc+0x1d5/0x720

[More verifications on a 448-core server: Passed]
1) test_vmalloc module
   * Each test is run sequentially.

2) stress-ng
   * fork() and exit()
       # stress-ng --fork 448 --timeout 180
   * pthread
       # stress-ng --pthread 448 --timeout 180
   * fork()/exit() and pthread
       # stress-ng --pthread 448 --fork 448 --timeout 180

The above verifications were run repeatedly for more than 24 hours.

[1] https://gist.github.com/AdrianHuang/99d12986a465cc33a38c7a7ceeb6f507

Signed-off-by: Adrian Huang <ahuang12@lenovo.com>
---
 mm/kasan/shadow.c | 10 +++-------
 1 file changed, 3 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..985356811aee 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -397,17 +397,13 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
+	pte_t orig_pte = ptep_get_and_clear(&init_mm, addr, ptep);
 	unsigned long page;
 
-	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
-
-	spin_lock(&init_mm.page_table_lock);
-
-	if (likely(!pte_none(ptep_get(ptep)))) {
-		pte_clear(&init_mm, addr, ptep);
+	if (likely(!pte_none(orig_pte))) {
+		page = (unsigned long)__va(pte_pfn(orig_pte) << PAGE_SHIFT);
 		free_page(page);
 	}
-	spin_unlock(&init_mm.page_table_lock);
 
 	return 0;
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240925134732.24431-1-ahuang12%40lenovo.com.
