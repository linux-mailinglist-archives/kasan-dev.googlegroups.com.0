Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUMP56LQMGQELUDCEZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B8D7596063
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 18:37:38 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id s21-20020a056402521500b00440e91f30easf6920562edd.7
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 09:37:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660667858; cv=pass;
        d=google.com; s=arc-20160816;
        b=FRzo+M7Jsi6cgk+VlynhDzbvzjs5AnnfaoAcchB1fK9z36OEWJ5AME/0VqFzIe1tD8
         6Y06mo5SSoUdiam1eJWAVndANlRi8aJzJ2t6OX0XtF739BX8XYhdQYbNPMUdIgou+K95
         Lkyl08xmwyTFLeqI/++4XmH2r/a/CZ5b0/viAv/1FQbJbIYbuPypJ24B+WQQ8VAL4Iis
         GKj3ltolryCiHKvNKxWOMqFltWJjJS4DYy5rDVzisq7MHJn2i6k89tks/XYA1U9YKdbk
         gqEoS8ilAfbvlZOPgLX1eLXO/Fs6kBJw4zF2C4Y+RUlAkGseIW0+xfTlq0bR/5cpeHVh
         om3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=HzIv61OZSFAVqSYRL2Afaw8m2y8BKlNIN+VKE+rFbag=;
        b=poKZQhcMejxMw+edAwraAJDD4I6IHI6UEcZevoKraw1m2ZtuwFkEnhRiWMvZNiArWg
         UUxgraWOiqT3lfkeymdcGMK1pCfkDMF/HI+0/cRBAhqHGQDv/R37uBa4ukFPzmThK/8Q
         VMRfm/R7H1M3WMkz4O2BXuK8jUuR68bIozEzU8c7Q8CKcvb5kIn7OsEx9jK0Vl5haS5i
         0ouxXiAVtsS6iYvYR1O9qlHV5UoyQomU7oFedAQKVB7USBMM5Z2DvyPqEAqcIr9tRaX8
         NAvz8afUlXJ2OeUC/BQ3bGThwS3fP4VfIucD10hIxX7cpy07bigwLYTG5lEu6GVsebcc
         bTuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qLBFcuLA;
       spf=pass (google.com: domain of 30mf7ygukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30Mf7YgUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc;
        bh=HzIv61OZSFAVqSYRL2Afaw8m2y8BKlNIN+VKE+rFbag=;
        b=d4oeaqPBTkykqoKZtcpDgoL3I3eXdcCs/eW/Qb2XyfdwnQtMDy8SK7yStWwylbXf1G
         Xn+/pTt1OC0hk3soS6CnjkAc8jz9vafY8Ffg8XrT/AT2rt+EZjmlZ0FpwFicvhpUKgtq
         uw0wC/sU+L3G+kLx/88O7uY69vAFTN1IC7bkfTG/WZbYoDPWVcqQ3PZtqTSGqYjzpmed
         s0zz2eoiW91s2SSlMEOr0j5a/9IA3HLj4hvhybCWX3QdOhRRb+DzovJRT6xw4soB02JQ
         5Q8W4chI8iguFY4Yd5AMz6eHw8oO052GemNRY/+6KVpLovYaHjpdt+TlaNxC59xqowlO
         FS0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc;
        bh=HzIv61OZSFAVqSYRL2Afaw8m2y8BKlNIN+VKE+rFbag=;
        b=ACnM8aB9wspQqPI7ROcCTGb9u1WVq884EUJ3Am3JSJ66iO/USJzTgKoxiy6G4N51rg
         cmAB61UNeBR1a1Hvr8EcKJBgxnTzEg6LuoGsDfu6RygyT1xni1ldLqxhA6k4an1jqzW6
         6Hnj1kLmoCnPq8A8G294n0IkAftYnc2+hs/KPr9HYNZzyM8Fc0y/SNIQikXJ4LDWTvfc
         X+nIMCmHuWJ5OkJ2lZk9KBg0nio150BYSij/mNyodk5SY8+zp8LHvXn5DbLJ79U+escm
         CQNnJcQ7tcKqp1+zRVmS6GVqw80yax2ZMLfvfP/+ggMFZkNBNi61+3uooi9HYioMRvFD
         mvSw==
X-Gm-Message-State: ACgBeo3Tnm2JNZCKDNP3m7/En1WNJrsc6cgHXPCQShKgbwMhEtAL3nIi
	6bMcPvVUHIetdZi/CBDvrf8=
X-Google-Smtp-Source: AA6agR7/99uqjI3Hs2lPoLZue7I89DXWtEj/XkmdYkczS/VngYlEuKDipabjgx8DLATI81JPH2ek6Q==
X-Received: by 2002:a17:907:a046:b0:730:9c7a:eab3 with SMTP id gz6-20020a170907a04600b007309c7aeab3mr14577948ejc.285.1660667857941;
        Tue, 16 Aug 2022 09:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:209c:b0:731:366b:d9a8 with SMTP id
 pv28-20020a170907209c00b00731366bd9a8ls2226817ejb.3.-pod-prod-gmail; Tue, 16
 Aug 2022 09:37:36 -0700 (PDT)
X-Received: by 2002:a17:907:72d0:b0:734:b451:c8d9 with SMTP id du16-20020a17090772d000b00734b451c8d9mr13753982ejc.272.1660667856625;
        Tue, 16 Aug 2022 09:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660667856; cv=none;
        d=google.com; s=arc-20160816;
        b=G+rZP4nrs42VEoGeB3YmbhKfMQ/WpUHQD5XjKPNG37/NM1DBbFtD+ZKzRbB/a60OU0
         olkzdGkpxCBC4LyrpUo0Pv7MkXf1SeRRx3GGo+L8+TRaEabtsawrN3DhFtt87Jj5yVd8
         42pJyvZBJNh01bztavCcmo1FJbYWIDWq2wsxswmOj4cBfilNeTTf8PUj/YoXRYZ9UmmZ
         PvpMuN3GNDx6EWhppIFdjmVKPnWJbR5gddictGf9FxfRCNltTqu0Mud5HIXsgIpDPXHX
         INi4xNMka2qq+WgmcEOMDuJkgdln3wldFl7RPZRFvtecrExb4tfuhFFCpcUSH5ERwEoN
         /xHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Bt86ycU5TqIe5DWAivAOKuWY2/WSOfZm/1Ale3yOGtg=;
        b=IPaRW7u7EoBtfggBWCjEYsKWQOMKwotc7Ak7UG6e01+cgiY5VC7MRRRwnmJNH6P47Y
         6x4lpONO5mygyaCtQPdXlL2KNdPR+OFvMqMkjRpJB87Y+GyNTITJZz2EyD1+PY8mO6pA
         LfcJ6Bdf/jMUusJBd4lFBorI09/exMvHzJaV4f7Jgchb6N2RVVfwEjVR32pGdNHPTaRz
         VuxSrIoTJWkxw82sBSH03Q5pLc80wN/7v23kBq4fUqXt98XVpjU/MJJMmmN6NReQOPvl
         QtwVnoxDsKzrWP0K/eNLImpgFiUL2izpzinHyjgV0HhFxfwpCBnbS4ErDm3JR+tFAnin
         wO8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qLBFcuLA;
       spf=pass (google.com: domain of 30mf7ygukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30Mf7YgUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id er21-20020a170907739500b00730b5fd89d2si17320ejc.1.2022.08.16.09.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 09:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30mf7ygukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id oz39-20020a1709077da700b007313bf43f0dso2000125ejc.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 09:37:36 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:b8f6:52b8:6a74:6073])
 (user=elver job=sendgmr) by 2002:a05:6402:4282:b0:43e:612c:fcf7 with SMTP id
 g2-20020a056402428200b0043e612cfcf7mr18989740edc.242.1660667856291; Tue, 16
 Aug 2022 09:37:36 -0700 (PDT)
Date: Tue, 16 Aug 2022 18:36:41 +0200
Message-Id: <20220816163641.2359996-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.1.595.g718a3a8f04-goog
Subject: [PATCH 5.19.y] Revert "mm: kfence: apply kmemleak_ignore_phys on
 early allocated pool"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, stable@vger.kernel.org, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Yee Lee <yee.lee@mediatek.com>, 
	Max Schulze <max.schulze@online.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qLBFcuLA;       spf=pass
 (google.com: domain of 30mf7ygukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30Mf7YgUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This reverts commit 07313a2b29ed1079eaa7722624544b97b3ead84b.

Commit 0c24e061196c21d5 ("mm: kmemleak: add rbtree and store physical
address for objects allocated with PA") is not yet in 5.19 (but appears
in 6.0). Without 0c24e061196c21d5, kmemleak still stores phys objects
and non-phys objects in the same tree, and ignoring (instead of freeing)
will cause insertions into the kmemleak object tree by the slab
post-alloc hook to conflict with the pool object (see comment).

Reports such as the following would appear on boot, and effectively
disable kmemleak:

 | kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
 | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
 | Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
 | Call trace:
 |  dump_backtrace.part.0+0x1dc/0x1ec
 |  show_stack+0x24/0x80
 |  dump_stack_lvl+0x8c/0xb8
 |  dump_stack+0x1c/0x38
 |  create_object.isra.0+0x490/0x4b0
 |  kmemleak_alloc+0x3c/0x50
 |  kmem_cache_alloc+0x2f8/0x450
 |  __proc_create+0x18c/0x400
 |  proc_create_reg+0x54/0xd0
 |  proc_create_seq_private+0x94/0x120
 |  init_mm_internals+0x1d8/0x248
 |  kernel_init_freeable+0x188/0x388
 |  kernel_init+0x30/0x150
 |  ret_from_fork+0x10/0x20
 | kmemleak: Kernel memory leak detector disabled
 | kmemleak: Object 0xffffff806e24d000 (size 2097152):
 | kmemleak:   comm "swapper", pid 0, jiffies 4294892296
 | kmemleak:   min_count = -1
 | kmemleak:   count = 0
 | kmemleak:   flags = 0x5
 | kmemleak:   checksum = 0
 | kmemleak:   backtrace:
 |      kmemleak_alloc_phys+0x94/0xb0
 |      memblock_alloc_range_nid+0x1c0/0x20c
 |      memblock_alloc_internal+0x88/0x100
 |      memblock_alloc_try_nid+0x148/0x1ac
 |      kfence_alloc_pool+0x44/0x6c
 |      mm_init+0x28/0x98
 |      start_kernel+0x178/0x3e8
 |      __primary_switched+0xc4/0xcc

Reported-by: Max Schulze <max.schulze@online.de>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 6aff49f6b79e..4b5e5a3d3a63 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -603,6 +603,14 @@ static unsigned long kfence_init_pool(void)
 		addr += 2 * PAGE_SIZE;
 	}
 
+	/*
+	 * The pool is live and will never be deallocated from this point on.
+	 * Remove the pool object from the kmemleak object tree, as it would
+	 * otherwise overlap with allocations returned by kfence_alloc(), which
+	 * are registered with kmemleak through the slab post-alloc hook.
+	 */
+	kmemleak_free(__kfence_pool);
+
 	return 0;
 }
 
@@ -615,16 +623,8 @@ static bool __init kfence_init_pool_early(void)
 
 	addr = kfence_init_pool();
 
-	if (!addr) {
-		/*
-		 * The pool is live and will never be deallocated from this point on.
-		 * Ignore the pool object from the kmemleak phys object tree, as it would
-		 * otherwise overlap with allocations returned by kfence_alloc(), which
-		 * are registered with kmemleak through the slab post-alloc hook.
-		 */
-		kmemleak_ignore_phys(__pa(__kfence_pool));
+	if (!addr)
 		return true;
-	}
 
 	/*
 	 * Only release unprotected pages, and do not try to go back and change
-- 
2.37.1.595.g718a3a8f04-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220816163641.2359996-1-elver%40google.com.
