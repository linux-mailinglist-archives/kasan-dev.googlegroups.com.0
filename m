Return-Path: <kasan-dev+bncBDN7L7O25EIBBP54T6MQMGQE4UALS5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id ACDE65BC1A7
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 05:13:04 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y1-20020a056402358100b00451b144e23esf15508798edc.18
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Sep 2022 20:13:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663557184; cv=pass;
        d=google.com; s=arc-20160816;
        b=qp7D7XgRah1Jmg3hH7i9r6XgyG2Rzb8LAlETLgm4O2thUU1nVV4xb8bHaLBsWDG2eF
         sl6BoM7cVX9HOJR2P/2aZlhusqtyGxymdeRLYM5opRs5w/AWgwjX6IpBzn0+1iHTU03y
         oDgMIgjHR457UI9yqXHSEouaqbehXtU2OWFPsreWnrj8eG3CmMCBX49ALEe2ohmq9azG
         v1CdvoTCiwFOZDTNEHLfUpFFiTsE0DEtXmEGYC7wX5WmLNr/tVU5FmD3+nIU4YxWHrEi
         4aodwKY/RPi6wBmOcqkNUl+9lQliglGbhuE60lItQyXo/a4l6Ymde34D53wFbCKqMUrw
         8pZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BMIw6AdevMzEJB+Rs022jy3WZf1Gdvm+vKNOFqH0Qfg=;
        b=vXjDXKNHyx7kcyCIbt4uqjAj1vvyNw2fYy8ygDpIPA2jtdCl71QbLZXIwT6CDWQK+y
         XlOXLGUynQg2fpQ8NYtN7e72PFq1ALqRU22lhCiM8W1tZrE+FOanYF9xxXwgahi8hoEe
         QHAtRPOl3RLJR4crHNorxqweVNe8vUmF44QTHKaRS+YPyZG2+Sm4+gvnb8Pg79yodOkZ
         3OfUSaQsGfYDEKzjVCVN39ivSg2nFV1fXSlMY7zhULC7kyEVwG3ETFueEpxKitAGX+PD
         PMkOAAlmrMF91J5/Kg9s0hn+wwUb3AJQiL0IEtaKBSUDZIb16sApgZh/5oH7+Xqlx1m+
         6VpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SCqBrasU;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=BMIw6AdevMzEJB+Rs022jy3WZf1Gdvm+vKNOFqH0Qfg=;
        b=IFAxDtikOceDYSuUl0NLvJCt75/299T+6LFJ7FWi0NyYS5DRDMRvUyPq9I2fBFK8nr
         AsdG07O2dIErKTMDb3K4yHSPFP3R5a1YJu3gsigpMLStomCJ9xtTW3ATEbqzbBJtr5F6
         GgwT8zLJyk7yf2VrtpUCx4mUsEkeUVv1uctC5byDhb+zvBPGSZph8EOMji9qLgBqI6em
         AuWgKj8wf0LOQz9OLmyNEgf6EqXYvKyzSn4k8mfcmN1B2T2bV9atW5G50tiZcfGaCiaz
         ZypZfIajPJpT+HSpFbY8qS3saiPklrmS76lOORrUUZK33KJasNrh321eOaw0lfbf6VUh
         f+qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=BMIw6AdevMzEJB+Rs022jy3WZf1Gdvm+vKNOFqH0Qfg=;
        b=TP8wiaEo0uaGltgZO9T8CoXw5XrpOmOapnMPyLpT1bUJxkcrK9BTeXi8mXeNZ1+jMk
         81VsNoYvnGcatLzSuPz2Lf8nFoaUAIqM4JLwWbPQX+B4azZlLIEbBIumr74n/NDgU6wQ
         uETKttEPvP6iev7zjkBg5ezxIPpcZa0AEGyb7ui5/Y7xmCBaIsZiYC6AoT/t+PZOlsLB
         JQj0GlKPMyZaW1JeqCt+eznlRVyu5gFf1V3dxz8AVF3I4LJ/BHSEL/cfH6uDY129Kwy9
         j5KCTgAGrkXLGwj/rFW6A9sYTfYzF6AnVXNQYxYKeE8IF5d+CrmQgX0flY6mQ5AUlH1D
         +YaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0by1xnwwXcGPOA/rg65oMWg3SZhfZc57Zxj8xKz2SUsDAQMFtd
	2ccSsno60b86zYC8MSa6MMA=
X-Google-Smtp-Source: AMsMyM6JKtrwj2FkA4nP34UNz1x/SwipSVQofPl+CuZuExdgHJO4Vhe1izeReLCw35JP580kdcbUag==
X-Received: by 2002:a17:907:3d8e:b0:77b:fd55:affe with SMTP id he14-20020a1709073d8e00b0077bfd55affemr11122544ejc.498.1663557183763;
        Sun, 18 Sep 2022 20:13:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c5:b0:447:ec6e:2ee with SMTP id
 z5-20020a05640235c500b00447ec6e02eels3577440edc.0.-pod-prod-gmail; Sun, 18
 Sep 2022 20:13:02 -0700 (PDT)
X-Received: by 2002:a05:6402:26d6:b0:451:24da:f8cf with SMTP id x22-20020a05640226d600b0045124daf8cfmr14134561edd.385.1663557182768;
        Sun, 18 Sep 2022 20:13:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663557182; cv=none;
        d=google.com; s=arc-20160816;
        b=BHt25sFig3eqmbn4Jifx7ihqe9ahLVTwPjjjJ21CdxFZDmEoNSbalXnHSHu8g7cU+w
         nPUahD08Qt5p4D511NN9ZGNSz+F0mLDYeRZdT1BEnJflVEgbo50KGWfbUdCUMckB3Wvi
         3zF8THqrf7FkRSnO97heJhD0tMtuCnENt3BTKCod7QRh83g5It3FpSt8ft5N/JbbRr1M
         ezFiR2+5xQPILtqO3aLPDXqPFr1zXHR2OBcPEZP9PRHh0hgDu5Jk3VgxzMl2dW8biHB0
         hX/hs3nG/Famp9EAAnhaAv6qqkXiamXA0y03ddJq9QJceLmeGG7yYXXQUaWbWux4mk0V
         1B6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=FZjlYl7FscekgfCjfYFDbh04Q1yveWpCRvs3I06iz68=;
        b=jR2Bz7n6COxkiZDBq+rC1iGHBvHSx7k4hAMqYrERJb0Uc/1ASDmKNYyXRRFrhlBneG
         MxVTJaMrjcNb1iqCyKpvnExqJxwz7wxzaXAZtlh0PcW5G+u7pvb2zEUz9zJQlLZ+YSsm
         HQ5Ti4M2tmCHoViASjh5rI3o4/wlHof4XCs++ZLzqYbR74uh2FS/QwQF8P/chk5CY/HE
         keAT48BdtS3DMCZahkZ5g0mOpQXgySJtTuvHnVu3+yZAyRdGMTl3zZSItzLgaRR6RO/R
         0PafoU2jtr+j2jw8NeC2lWiupqYlI8VMFedEwR1TiTve7pIh2d7ve1IvulqzUNqoE3N4
         F9Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SCqBrasU;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id w21-20020a170907271500b0073d9d812170si893183ejk.1.2022.09.18.20.13.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 18 Sep 2022 20:13:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10474"; a="286338246"
X-IronPort-AV: E=Sophos;i="5.93,325,1654585200"; 
   d="scan'208";a="286338246"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Sep 2022 20:13:00 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,325,1654585200"; 
   d="scan'208";a="569477795"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by orsmga003.jf.intel.com with ESMTP; 18 Sep 2022 20:12:57 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Waiman Long <longman@redhat.com>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH] mm/slab_common: fix possiable double free of kmem_cache
Date: Mon, 19 Sep 2022 11:12:41 +0800
Message-Id: <20220919031241.1358001-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SCqBrasU;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

When doing slub_debug test, kfence's 'test_memcache_typesafe_by_rcu'
kunit test case cause a use-after-free error:

  BUG: KASAN: use-after-free in kobject_del+0x14/0x30
  Read of size 8 at addr ffff888007679090 by task kunit_try_catch/261

  CPU: 1 PID: 261 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc5-next-20220916 #17
  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
  Call Trace:
   <TASK>
   dump_stack_lvl+0x34/0x48
   print_address_description.constprop.0+0x87/0x2a5
   print_report+0x103/0x1ed
   kasan_report+0xb7/0x140
   kobject_del+0x14/0x30
   kmem_cache_destroy+0x130/0x170
   test_exit+0x1a/0x30
   kunit_try_run_case+0xad/0xc0
   kunit_generic_run_threadfn_adapter+0x26/0x50
   kthread+0x17b/0x1b0
   </TASK>

The cause is inside kmem_cache_destroy():

kmem_cache_destroy
    acquire lock/mutex
    shutdown_cache
        schedule_work(kmem_cache_release) (if RCU flag set)
    release lock/mutex
    kmem_cache_release (if RCU flag set)

in some certain timing, the scheduled work could be run before
the next RCU flag checking which will get a wrong state.

Fix it by caching the RCU flag inside protected area, just like 'refcnt'

Signed-off-by: Feng Tang <feng.tang@intel.com>
---

note:

The error only happens on linux-next tree, and not in Linus' tree,
which already has Waiman's commit:
0495e337b703 ("mm/slab_common: Deleting kobject in kmem_cache_destroy()
without holding slab_mutex/cpu_hotplug_lock")

 mm/slab_common.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index 07b948288f84..ccc02573588f 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -475,6 +475,7 @@ void slab_kmem_cache_release(struct kmem_cache *s)
 void kmem_cache_destroy(struct kmem_cache *s)
 {
 	int refcnt;
+	bool rcu_set;
 
 	if (unlikely(!s) || !kasan_check_byte(s))
 		return;
@@ -482,6 +483,8 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	cpus_read_lock();
 	mutex_lock(&slab_mutex);
 
+	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
+
 	refcnt = --s->refcount;
 	if (refcnt)
 		goto out_unlock;
@@ -492,7 +495,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
 out_unlock:
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();
-	if (!refcnt && !(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!refcnt && !rcu_set)
 		kmem_cache_release(s);
 }
 EXPORT_SYMBOL(kmem_cache_destroy);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919031241.1358001-1-feng.tang%40intel.com.
