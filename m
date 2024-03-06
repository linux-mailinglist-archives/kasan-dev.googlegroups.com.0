Return-Path: <kasan-dev+bncBC7OD3FKWUERBLXKUKXQMGQENB7I3JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DBAE5873E9F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:51 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3657fabb6dasf930015ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749550; cv=pass;
        d=google.com; s=arc-20160816;
        b=NteL6AudkEMRONMTZ1hpYL31Ve0C76CF5oMzl8tplQllbI7ZszRq5ylQ4L+L6m55JM
         +ji6WBtnyYe9t98LocFUtQObJsxFkdoNnucEyLPlqVOGKmd097qD54/m22XWX0QURGfs
         Rez7ocELRzS4uYA72brhcHf81FKfzxZP+Jrb1+AQXayjKWFhGPxLOi/x1ZWD28nQxlbC
         fouqyufv6xCyTId+Sprpq1tkAC4S/Iv7nre7uAQz7gdfy5YODZkVaVrFloIYWLvJrom+
         egIPPkowef+RjapV4oyQTX/usuEDpyCOqRNLlgd0ghq3W7qGV8D+JLHPVHUB9qE+6Pib
         IBpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=msfGipk9mQxZZJzhAKL2BFQxpss7RnTKWtw2bkqdxNQ=;
        fh=4Zo4tYpfUrLHDkPzUUl2+ol6RYGkK2qXuTco9hARsok=;
        b=q9msm7wKlEO7I7qqqcbe0JPAJqKd5cN4uEqkjG9pKwefP6pbwViQJcidZYt5ipdkP4
         gc2lQ4nTPjMiA1e5s/GSRY3mWk8dTPuV1Vu5YGMlKkpVS+FYrvASklow5TJvmllXDEq7
         jKo0XugRm+d2ctVJIu6KSmRhr6q7gMAJJfT0nhkxkQGP80HI738+zc3mtaqNPJcEJ32e
         kVfCmrcXqKmvxNlshrh8zq+KuYvBiTFipab8YQNj9PXedSVOLFfAMZoEy4kvEuOxY05R
         vh5FZuhTKjyy4NibS6QDTBYzmOACAG6yuQh02IXFVmO1HslVbDEmxH5mmJ0MXW9qMoxC
         pE4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eEOJEdwP;
       spf=pass (google.com: domain of 3k7xozqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3K7XoZQYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749550; x=1710354350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=msfGipk9mQxZZJzhAKL2BFQxpss7RnTKWtw2bkqdxNQ=;
        b=wQ21IDc3GQJL40GJwG6r6SH/X678U0zNrQmT7DFQBUVTEtAtz3e5zlY16PJv3hnMU2
         Wmjse6Z/dJtR7N4zwfWJgDfZhVai0yYdaN8jcjFI9NOAMBQ4y/ocFzTKiq2B2LshAopf
         jSdOCUC90/WtygB6b3okKDUBfmFa14ViuMnXUmc+OALuJtG9NBBweAsNeJflGSN2ZrFf
         LTYEW4qi5cmLGoKW8pRuUiUykRwbh4qte5GH1v2dA5hARZ9c+R66JxJ2pQdLzcHRCVqR
         EvtsBtkg5gYtC+AYEZ7xozZtzma5o4Ja8Pzq50GdaJYaru7eESumZSA6QAcBfe6/P/5F
         nzuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749550; x=1710354350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=msfGipk9mQxZZJzhAKL2BFQxpss7RnTKWtw2bkqdxNQ=;
        b=CtRe9jnKjk9CQTs4BPaB2VGWSMCwLVDWCuh/lieOZlh3Fr/XvjFMXdS+VhpnAccVQ5
         nfdngoDdGYUWFG3ERsbcpahwf5KQUZquMoAXJxh6fVZP5IxYKT2gpQiNp3sgtRNA4Z6g
         NmVpm6lHIBpEN05hWQ4SKAjtTC2UznITHlyzgyIbDjwejxiRBYCRK88F6P/dx2h9WrkB
         7XpzZLL5wlUEwyPpsyRrMIpPAt01yqsFHchIDkUxRMJzGfJfQkJKk1kxswwWLQpvLrpO
         BP2ceyEHLZaCrij1TbAFIrkTC42VqVvA7BvEGHyYviENae53O+fuTzEgnE4F63R/73Zu
         UTDA==
X-Forwarded-Encrypted: i=2; AJvYcCUsYAazepMrDKJ1+NyxDRKT+3IalBlMXPZL7nLZXTyzErQ5vJSZqhnrjM+XZvUdHolAvVpAXBD7S04gs86Np0MpSkkHQHpA+g==
X-Gm-Message-State: AOJu0YzjKCcwV62UVmWgku1FY08GRHduR+ck7JgQnfEdr3SXhehtnrYj
	2rS/u0UMmEXABenGeV9E5cHXhLWASM1mIwKo26que9yP/aqo55Ik
X-Google-Smtp-Source: AGHT+IGLMTWwhUJ/51XurKVCnxd86rsYsF6cnfJZlZ1ROeJ/7lrRWBYtDoilUV2Q9hQk23GnODF6+A==
X-Received: by 2002:a92:8752:0:b0:365:2644:c846 with SMTP id d18-20020a928752000000b003652644c846mr636856ilm.0.1709749550651;
        Wed, 06 Mar 2024 10:25:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ed:b0:366:70d:8658 with SMTP id
 l13-20020a056e0212ed00b00366070d8658ls62992iln.1.-pod-prod-00-us; Wed, 06 Mar
 2024 10:25:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUUrfWTQV70z0sG384Y4tUcvemj0eu3aMdKkllantLz3zFG+MXh+wN8BIrfos2QAmMWwAfZA0OpH/PxyZygAEL6TVFHyIVjdeETwA==
X-Received: by 2002:a05:6e02:1c22:b0:363:86dd:b35 with SMTP id m2-20020a056e021c2200b0036386dd0b35mr5769172ilh.10.1709749548334;
        Wed, 06 Mar 2024 10:25:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749548; cv=none;
        d=google.com; s=arc-20160816;
        b=ZoIuqn/XNdMkVlM+wVGbUKuU/9wlOp7gb6t2qYTbJKWnuoblcKzXENoJg7ddq8/3Fw
         YA97191B3jb+3e/aoFZ9ieiEovkzQqRMA5MVz/3Bjdqq04ZiSNVmwRkRWL/sPghwqi6y
         3RXVs9Zyphfw3XryDmQE9J0u0iNkQqhAfr77PQt7nH/bxuV7fWxcrk4CV56ucFd6cKOS
         QeK7YQ20FR+Jtvc27+Xx1QRC4WQvURIge/QKq+ciS/XN2bD4YWfgKmsp6XYETv2TbkyG
         ELLyzmriQ6/KGvsUZzpfNa1y09KHztrcW7/s8DV66s3NWo7zg88BCSBCnLEAhJZXfOhc
         1qvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DxoUvKCzEXXEdeRbYveeEvTG3TXaR8hRTTgS3Q5TXls=;
        fh=aJgmB6/XXr76ad1ofW1Tbh6jsQNe9cRQCTmiG6e7mvg=;
        b=aAnGeXiU1Q1569B7qkHqdCZ1ogwgWuCzUJBz9odUm/+EKOXpwXCD61uU7pTnJKNpfw
         jiSCcvGU9c/kbiB/XkUqXXkKtxhcePor6oEJi7Ly0mX8PiZBiENUvi5iyYU3zFZi4Tzy
         sW3VkmA4Fe6i4XdasM5OxWilA5ywhvNGSwJ1jqRp5icxiF5K5stzv6G8+f2n3hl9P+GL
         9kdXZY44bNIUboNeszikL9Ov8rxdsRkfC+dsfYc0Rl6C5JLJgbni5W6ty5SmSGEDjTlW
         L/0kBRk5K/dZrdy3rm/vexC5qWJunw5Rfz+e8TrE2oeGdFndvGHrwY+r14cHjubgtDlk
         s07A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eEOJEdwP;
       spf=pass (google.com: domain of 3k7xozqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3K7XoZQYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id gn7-20020a0566382c0700b00474f9eb1c28si436272jab.6.2024.03.06.10.25.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3k7xozqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dcc05887ee9so10099841276.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX/kqWbXZ04yVeOAeMi0m16lPYNIkQ1gX5p/uSEFxGzGlZeYkRn8Uky72rezgprcaofJUGt77k/qMNdl26xwcNuYT/9FkWv/IfwIw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:10c1:b0:dcd:59a5:7545 with SMTP id
 w1-20020a05690210c100b00dcd59a57545mr531845ybu.10.1709749547368; Wed, 06 Mar
 2024 10:25:47 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:27 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-30-surenb@google.com>
Subject: [PATCH v5 29/37] mm: percpu: enable per-cpu allocation tagging
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eEOJEdwP;       spf=pass
 (google.com: domain of 3k7xozqykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3K7XoZQYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

Redefine __alloc_percpu, __alloc_percpu_gfp and __alloc_reserved_percpu
to record allocations and deallocations done by these functions.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/percpu.h | 23 ++++++++++-----
 mm/percpu.c            | 64 +++++-------------------------------------
 2 files changed, 23 insertions(+), 64 deletions(-)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 62b5eb45bd89..e54921c79c9a 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -2,6 +2,7 @@
 #ifndef __LINUX_PERCPU_H
 #define __LINUX_PERCPU_H
 
+#include <linux/alloc_tag.h>
 #include <linux/mmdebug.h>
 #include <linux/preempt.h>
 #include <linux/smp.h>
@@ -9,6 +10,7 @@
 #include <linux/pfn.h>
 #include <linux/init.h>
 #include <linux/cleanup.h>
+#include <linux/sched.h>
 
 #include <asm/percpu.h>
 
@@ -125,7 +127,6 @@ extern int __init pcpu_page_first_chunk(size_t reserved_size,
 				pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn);
 #endif
 
-extern void __percpu *__alloc_reserved_percpu(size_t size, size_t align) __alloc_size(1);
 extern bool __is_kernel_percpu_address(unsigned long addr, unsigned long *can_addr);
 extern bool is_kernel_percpu_address(unsigned long addr);
 
@@ -133,14 +134,16 @@ extern bool is_kernel_percpu_address(unsigned long addr);
 extern void __init setup_per_cpu_areas(void);
 #endif
 
-extern void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp) __alloc_size(1);
-extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);
-extern void free_percpu(void __percpu *__pdata);
+extern void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
+				   gfp_t gfp) __alloc_size(1);
 extern size_t pcpu_alloc_size(void __percpu *__pdata);
 
-DEFINE_FREE(free_percpu, void __percpu *, free_percpu(_T))
-
-extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+#define __alloc_percpu_gfp(_size, _align, _gfp)				\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, false, _gfp))
+#define __alloc_percpu(_size, _align)					\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, false, GFP_KERNEL))
+#define __alloc_reserved_percpu(_size, _align)				\
+	alloc_hooks(pcpu_alloc_noprof(_size, _align, true, GFP_KERNEL))
 
 #define alloc_percpu_gfp(type, gfp)					\
 	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
@@ -149,6 +152,12 @@ extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
 	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
 						__alignof__(type))
 
+extern void free_percpu(void __percpu *__pdata);
+
+DEFINE_FREE(free_percpu, void __percpu *, free_percpu(_T))
+
+extern phys_addr_t per_cpu_ptr_to_phys(void *addr);
+
 extern unsigned long pcpu_nr_pages(void);
 
 #endif /* __LINUX_PERCPU_H */
diff --git a/mm/percpu.c b/mm/percpu.c
index 90e9e4004ac9..dd7eeb370134 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1726,7 +1726,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
 #endif
 
 /**
- * pcpu_alloc - the percpu allocator
+ * pcpu_alloc_noprof - the percpu allocator
  * @size: size of area to allocate in bytes
  * @align: alignment of area (max PAGE_SIZE)
  * @reserved: allocate from the reserved chunk if available
@@ -1740,7 +1740,7 @@ static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t s
  * RETURNS:
  * Percpu pointer to the allocated area on success, NULL on failure.
  */
-static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
+void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved,
 				 gfp_t gfp)
 {
 	gfp_t pcpu_gfp;
@@ -1907,6 +1907,8 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	pcpu_memcg_post_alloc_hook(objcg, chunk, off, size);
 
+	pcpu_alloc_tag_alloc_hook(chunk, off, size);
+
 	return ptr;
 
 fail_unlock:
@@ -1935,61 +1937,7 @@ static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
 
 	return NULL;
 }
-
-/**
- * __alloc_percpu_gfp - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- * @gfp: allocation flags
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align.  If
- * @gfp doesn't contain %GFP_KERNEL, the allocation doesn't block and can
- * be called from any context but is a lot more likely to fail. If @gfp
- * has __GFP_NOWARN then no warning will be triggered on invalid or failed
- * allocation requests.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
-{
-	return pcpu_alloc(size, align, false, gfp);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu_gfp);
-
-/**
- * __alloc_percpu - allocate dynamic percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
- */
-void __percpu *__alloc_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, false, GFP_KERNEL);
-}
-EXPORT_SYMBOL_GPL(__alloc_percpu);
-
-/**
- * __alloc_reserved_percpu - allocate reserved percpu area
- * @size: size of area to allocate in bytes
- * @align: alignment of area (max PAGE_SIZE)
- *
- * Allocate zero-filled percpu area of @size bytes aligned at @align
- * from reserved percpu area if arch has set it up; otherwise,
- * allocation is served from the same dynamic area.  Might sleep.
- * Might trigger writeouts.
- *
- * CONTEXT:
- * Does GFP_KERNEL allocation.
- *
- * RETURNS:
- * Percpu pointer to the allocated area on success, NULL on failure.
- */
-void __percpu *__alloc_reserved_percpu(size_t size, size_t align)
-{
-	return pcpu_alloc(size, align, true, GFP_KERNEL);
-}
+EXPORT_SYMBOL_GPL(pcpu_alloc_noprof);
 
 /**
  * pcpu_balance_free - manage the amount of free chunks
@@ -2328,6 +2276,8 @@ void free_percpu(void __percpu *ptr)
 	spin_lock_irqsave(&pcpu_lock, flags);
 	size = pcpu_free_area(chunk, off);
 
+	pcpu_alloc_tag_free_hook(chunk, off, size);
+
 	pcpu_memcg_free_hook(chunk, off, size);
 
 	/*
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-30-surenb%40google.com.
