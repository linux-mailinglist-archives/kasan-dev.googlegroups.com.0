Return-Path: <kasan-dev+bncBDDO7SMFVEFBBX6DZWGAMGQENBHW2YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 39C0F452C19
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 08:46:40 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id b15-20020aa7c6cf000000b003e7cf0f73dasf4043043eds.22
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 23:46:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637048800; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tf+aa0E6IM8M1PG/Y3Cpc3d4JwzNGPUjmQdwiQTMOkXNJqFT5akyi+WUREIvBVZpsy
         GC0DeyI/oxk0bh0+8xs5lrbKEeTp94WkQ6i0MgTxKvj0MXgduci4KExt2T0X4P2dpBxf
         05qivAAof79xVXW4wBaIcSfPYuQrRrLouVi8TrRrD0w8+ZdBijHWprDegeX6W3dPNVRt
         qc/Yt37MX+6Ne5T2sc+2YupHZlq9aaBttBEAowpbalR4vreKFEsQF8aPbYc+1FSHLdul
         L44wWI7DDeOwiXl4WBHW5EMuB24+odNOeMN0kIyPKcR9gMmGvgrByZrR4yD1xPXjDYIC
         FH+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=AqQ3AlfWL+QlFNGqxaz5axOURAg7YaE9OuLtdThNY7o=;
        b=l6afgpZPmsrCGsxwT3VxcrOULuB7/9z0bQUfBfdhCv4GJiFaDP7RzyIPekpAx62xBZ
         u8+oUTFT2vf/tejnGoDIg+l6urSyzGP4GjMzj+42bev+NZ84i5aTWaPktvlSDQh/SflT
         PiTldQgRZqGXSjg3AajH2b1jwP5Tob43XWH7ZJltDpClJNsTXM+5DspoHlFvzuOvQ5wa
         8YcdXcDfNpbRcPojMTQnEXqyBy+qZSax+r94U2CXpK0BPKOPR+yFhclE6a35RxPS9LAc
         eBpNh7uCPojcPdgHaGVj622hJ2OJnBZn7IyboA4600KFnBNlOIvfCpfhawCSEy34Kyz6
         VAeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jun.miao@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=jun.miao@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AqQ3AlfWL+QlFNGqxaz5axOURAg7YaE9OuLtdThNY7o=;
        b=FUEdOf7Fg1KAkZprSE1bwLRjC3jgMVr3S0X51pju495gegBz5hSY52SNbjHMo+hl7/
         1vcw6psa0z1WLFh1uHb+GmVeRFu80OGurtKrL7EoVx3W7FDTRS4OthodaDZaG4OPbbpq
         2LNdSskxZ3aahiXTWS7q5nWyWllUMbSOHOh7LPiyXnky7Qd2nI+80DyxvBDq7EAx5qU3
         3/wUQfXk37Ss96fjJ9P4WUTbrTdaQya+wQQLU52f6HbnspQzOXO2vK1QMi50UvMcIhdc
         UI16WgUTOuLH5cUTvqXatTLib0eDWAQskYLGdlEnAIqqoBsvZ95zxzFrdDQYYnVGfiK1
         vwFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AqQ3AlfWL+QlFNGqxaz5axOURAg7YaE9OuLtdThNY7o=;
        b=PHJdyH04pkmX1mCww51E5scflO/B0brynyHVp4cMiopcHpqwFqrvNVRdbklQZXyhfF
         MF972ab5p5agPvmlzYD0Xysr/JofEjK3YgHmTqtPyP5T0qzAw35V5vXOZhDz7oYVns02
         3AJT8o9w3v3rZzEivwCHYo/CpbCIv8W/lXOt13tO21Y5lRfq/P4wECM+eQpPtUcuBbR3
         dnOoKCzu2A7SPNwneARzm8pX9hcnlFtVAgCAkBRTj6gBytO8JJfrJZvputeCq4Pd34TI
         X4KDWID+azfBGqUKt6+36ue9xmpRJe/7nJFwzFLsmeX74+zJhdyJkO+C5CCTWeIUvxqM
         EvOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gw2O8boquJG+3h4nv0fpvNoOGBigqf6GEs3LuYn7RMz8Vo6G+
	UPTlMYWUSc+/ddQ+Xocv9f8=
X-Google-Smtp-Source: ABdhPJzv0J2K6PDbpdh7s2nKq4iCD2UXYQARaw6XbbdsiPx5MqlJuPapdDYF1F5zootjCk/LJHK8Zg==
X-Received: by 2002:aa7:c902:: with SMTP id b2mr7273955edt.320.1637048799980;
        Mon, 15 Nov 2021 23:46:39 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8e41:: with SMTP id 1ls1750574edx.0.gmail; Mon, 15 Nov
 2021 23:46:39 -0800 (PST)
X-Received: by 2002:a05:6402:34d4:: with SMTP id w20mr7459491edc.63.1637048799064;
        Mon, 15 Nov 2021 23:46:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637048799; cv=none;
        d=google.com; s=arc-20160816;
        b=KbyPEs/JNkspg3YzcB7reHMYyFRrxSq+wtgFikX3r7JmiKKqBwZ6u+uZQyFdosa934
         Ndsp1LY8D77m3yGAOtmtIcHSpjWBVALsxtayRDYazS/Zuzsj0s7V8CixbHQaA/6H4tM0
         9TuKauH2c9AdAOIQWsHdbSE4dYx8AT58qqJLgEUCOmLLA8hHPMa05dcgwSajEWYwJgGp
         lhRkh37h8akfZggtcYp9GXL1Vc32VrAhs7I1tVUqm2A1rZxCVfbE8dsKUucObGM8o3sB
         ruI2uAr1SraBKJrb1dLHyZ6oICUrow2gXxuTzUHp6UfBwbrT4J3Oojnz1pM5sUp/jr92
         M9IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=W4DhsAqA+0vfI/+SKEZOsLNQv9K2UwZ1yUbvLw0uFlE=;
        b=fcO0hYG0jxB2uHM+GYGZw1B2B0fLzMsxQy6eCjgimpbcTsxqFTv1YsQuD+jWo8OT15
         7O/RmtP2+9xsEqKqlIxBPO4PF5ZUcF5Gur9SOMR/XggLTshTY2meMFWWxzPC/XB0FXof
         aWJuHawyFwLnaUK/3F4eGyrMjh15/XmDkHE46v+ZTM4PW/5GoHmJ4BrQI5HoS7vDVcYt
         Yet3rzQTH0kb1zCrYu+htg3dQ8eqqo7oiiQIdn61TXpBE9MAPa2z22MP6U4iRU7GVcRL
         3mhZu+/xk/hzzq4TwLhVahh7XX8GcLLCYdmZ6mSuBaG+SBVSvOlGv4xh0gw3wPuCJHXo
         k/PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jun.miao@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=jun.miao@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id w5si1153902ede.3.2021.11.15.23.46.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Nov 2021 23:46:39 -0800 (PST)
Received-SPF: pass (google.com: domain of jun.miao@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6200,9189,10169"; a="319854778"
X-IronPort-AV: E=Sophos;i="5.87,238,1631602800"; 
   d="scan'208";a="319854778"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Nov 2021 23:46:33 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.87,238,1631602800"; 
   d="scan'208";a="506321806"
Received: from sdp.bj.intel.com ([10.240.193.77])
  by orsmga008.jf.intel.com with ESMTP; 15 Nov 2021 23:46:29 -0800
From: Jun Miao <jun.miao@intel.com>
To: paulmck@kernel.org,
	urezki@gmail.com,
	elver@google.com,
	josh@joshtriplett.org,
	rostedt@goodmis.org,
	mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com,
	joel@joelfernandes.org,
	qiang.zhang1211@gmail.com
Cc: rcu@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	jianwei.hu@windriver.com,
	Jun Miao <jun.miao@intel.com>
Subject: [V2][PATCH] rcu: avoid alloc_pages() when recording stack
Date: Tue, 16 Nov 2021 07:23:02 +0800
Message-Id: <1637018582-10788-1-git-send-email-jun.miao@intel.com>
X-Mailer: git-send-email 2.7.4
X-Original-Sender: jun.miao@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jun.miao@intel.com designates 192.55.52.43 as
 permitted sender) smtp.mailfrom=jun.miao@intel.com;       dmarc=pass (p=NONE
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

The default kasan_record_aux_stack() calls stack_depot_save() with GFP_NOWAIT,
which in turn can then call alloc_pages(GFP_NOWAIT, ...).  In general, however,
it is not even possible to use either GFP_ATOMIC nor GFP_NOWAIT in certain
non-preemptive contexts/RT kernel including raw_spin_locks (see gfp.h and ab00db216c9c7).
Fix it by instructing stackdepot to not expand stack storage via alloc_pages()
in case it runs out by using kasan_record_aux_stack_noalloc().

Jianwei Hu reported:
BUG: sleeping function called from invalid context at kernel/locking/rtmutex.c:969
in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 15319, name: python3
INFO: lockdep is turned off.
irq event stamp: 0
  hardirqs last  enabled at (0): [<0000000000000000>] 0x0
  hardirqs last disabled at (0): [<ffffffff856c8b13>] copy_process+0xaf3/0x2590
  softirqs last  enabled at (0): [<ffffffff856c8b13>] copy_process+0xaf3/0x2590
  softirqs last disabled at (0): [<0000000000000000>] 0x0
  CPU: 6 PID: 15319 Comm: python3 Tainted: G        W  O 5.15-rc7-preempt-rt #1
  Hardware name: Supermicro SYS-E300-9A-8C/A2SDi-8C-HLN4F, BIOS 1.1b 12/17/2018
  Call Trace:
    show_stack+0x52/0x58
    dump_stack+0xa1/0xd6
    ___might_sleep.cold+0x11c/0x12d
    rt_spin_lock+0x3f/0xc0
    rmqueue+0x100/0x1460
    rmqueue+0x100/0x1460
    mark_usage+0x1a0/0x1a0
    ftrace_graph_ret_addr+0x2a/0xb0
    rmqueue_pcplist.constprop.0+0x6a0/0x6a0
     __kasan_check_read+0x11/0x20
     __zone_watermark_ok+0x114/0x270
     get_page_from_freelist+0x148/0x630
     is_module_text_address+0x32/0xa0
     __alloc_pages_nodemask+0x2f6/0x790
     __alloc_pages_slowpath.constprop.0+0x12d0/0x12d0
     create_prof_cpu_mask+0x30/0x30
     alloc_pages_current+0xb1/0x150
     stack_depot_save+0x39f/0x490
     kasan_save_stack+0x42/0x50
     kasan_save_stack+0x23/0x50
     kasan_record_aux_stack+0xa9/0xc0
     __call_rcu+0xff/0x9c0
     call_rcu+0xe/0x10
     put_object+0x53/0x70
     __delete_object+0x7b/0x90
     kmemleak_free+0x46/0x70
     slab_free_freelist_hook+0xb4/0x160
     kfree+0xe5/0x420
     kfree_const+0x17/0x30
     kobject_cleanup+0xaa/0x230
     kobject_put+0x76/0x90
     netdev_queue_update_kobjects+0x17d/0x1f0
     ... ...
     ksys_write+0xd9/0x180
     __x64_sys_write+0x42/0x50
     do_syscall_64+0x38/0x50
     entry_SYSCALL_64_after_hwframe+0x44/0xa9

Links: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/include/linux/kasan.h?id=7cb3007ce2da27ec02a1a3211941e7fe6875b642
Fixes: 84109ab58590 ("rcu: Record kvfree_call_rcu() call stack for KASAN")
Fixes: 26e760c9a7c8 ("rcu: kasan: record and print call_rcu() call stack")
Reported-by: Jianwei Hu <jianwei.hu@windriver.com>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
Signed-off-by: Jun Miao <jun.miao@intel.com>
---
 kernel/rcu/tree.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index ef8d36f580fc..906b6887622d 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -2982,7 +2982,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
 	head->func = func;
 	head->next = NULL;
 	local_irq_save(flags);
-	kasan_record_aux_stack(head);
+	kasan_record_aux_stack_noalloc(head);
 	rdp = this_cpu_ptr(&rcu_data);
 
 	/* Add the callback to our list. */
@@ -3547,7 +3547,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
 		return;
 	}
 
-	kasan_record_aux_stack(ptr);
+	kasan_record_aux_stack_noalloc(ptr);
 	success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
 	if (!success) {
 		run_page_cache_worker(krcp);
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1637018582-10788-1-git-send-email-jun.miao%40intel.com.
