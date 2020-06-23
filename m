Return-Path: <kasan-dev+bncBAABBOFAYX3QKGQE7TCNIVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id D52F62045FB
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:37 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id t22sf13507987qkg.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873017; cv=pass;
        d=google.com; s=arc-20160816;
        b=DIE70v4piE9tIlSIx9ndD/egOdjqw21K3+SVYo8PBldr9aq3F4mSviUnPpmg/eUkwf
         vq5+Svskr6s0lfCxjyBruO/tutPzskULlLSQzA4MbwAJSJgSFNKIdF8B6Lo0H3P18TAs
         XPQuu2mrD/QZQ/Isw06iQF1xR4UqaQDMw9TQxsGTSTlUSczsN7pm3I7o0nXZFcyvdw+A
         w0mPtbsG04sG6RFtwFXnqNk5QlZRjmBOgrBrlKRcKNGyID5Is5q2RXq1jUbFHdg7FMtG
         T++FpIsUF0TtnoDIs/JteDuZFL5EZ034ntivSeFUBVx2jzwk86YaKxBAFFyF3Yf1FWDt
         97UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=t9tQWdyhhyjkR3XiFGmS0CWSuFMtI/2Jnb+A5nQ2Hdg=;
        b=OXiPHyj/BQEc2ZonAS6fHgYO/i/uhD8kqkXNSKyfZQBDyRaHEdhkYZpLWZIhHorMYK
         sGB21cDpDMuAR6MdZoOgzdPmlxYdI21Jw2qkrGInQjZJrW5bBqHcbZDyd+pEWmu2GKQf
         KxoLpaecsYVOzynnpxsuSr9RNRegNN9fa5EjyCtYzNCMEHD19ZLDWU4bbCXdg/hhnSZ/
         FcqrmVmswDssJNnz/DfyN1TTxIZoTrkoe2iKqF9y4mRFSRgjLjxJX+P7zKaTbkCZP9S5
         t0A0f0UgpmuxoTjsJ0IuXCouZQ+0Cq5TVbsDUmOlXqTemEMOlq47xZb3e1FzKdKThJIw
         VxzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=r3mLacsz;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t9tQWdyhhyjkR3XiFGmS0CWSuFMtI/2Jnb+A5nQ2Hdg=;
        b=S8hu+hF90KBQVCMcAaqF1EzWrGqFOGisKm2dqpkaAn++G5FVIZoXmhiVuERYDULbYi
         09T+vsS1whSRGVLMEYxvi2HnNTXeTkl6vNOOcbdoHy0B+yNDh1F4Y4zaRvxe8yFXPYt/
         OrysmEAnLkSghmoQJOAYTJwrB10g/T578G5DoqW/fUeKbqW2ddYtfxFejg8k4p4w7HNj
         q3ldETRGNE4OzeJJq1beKZexuCRp8ZvjM5Sn5B6aFMXrjEi5yt3Hak5mRzJuVxZk3r6k
         bLzpIaIokvoK6b789vlt7+ciiznvW49yYryQzZHYHChyv2OZ3pACRxPIGqVhYhQ96EQm
         OTJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t9tQWdyhhyjkR3XiFGmS0CWSuFMtI/2Jnb+A5nQ2Hdg=;
        b=fETtIjMDldxMPrnFAQ2woOW5dq3Z4Q2TYF3f0mqqP/axBuDSdNZTT7JoYh1fEkzgQ8
         QPqdxxB3z2o66X1FB6yLdJ3QqiczZnFWoFQxZM0KgrLoXFSWFlUZZxgxCK+megFp3nuR
         jgusLxuL+QYAg7iImTkKpWhXJVmHhk86Q1nANru+tJ26hBr3d2y7jMpnlcp0v4TebtNr
         dOIQ/S5PwpinuwhzPZj4SQMTlXjgNGfs018+XQ54m2cyROBtzbsOF7DMse/WeaFrjjuS
         i5U6j0zaFSOKBsUZOCs9rUVo1qUOQpdGACoQD0oXOszup12y5jFp/WOxiT40IBLrItVG
         idQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QqCL2AkR9Bk/AdLUZMzpqCRKDUma5D/Ons4sSyr8oxFojScDm
	RWSg4hWjeSZNZYu0uvMroLc=
X-Google-Smtp-Source: ABdhPJyZwzrcP2+JmgE8I+CFl6fv6zpFXRCsUTi8+Qgc6MYPzihcq/7H6dSdXpf7SBPPwjlcEs6YDQ==
X-Received: by 2002:aed:3201:: with SMTP id y1mr531667qtd.156.1592873016710;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:cd07:: with SMTP id b7ls4364516qvm.10.gmail; Mon, 22 Jun
 2020 17:43:36 -0700 (PDT)
X-Received: by 2002:a05:6214:852:: with SMTP id dg18mr23270645qvb.97.1592873016461;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873016; cv=none;
        d=google.com; s=arc-20160816;
        b=GtvFVRg/Q3hzQe/7OMLL1+aUP1KfYbm2KgGmsOXRNTnIIZwXPXfDPh1iNoupzjEdrK
         9sooSRf7MVg3oA7yffwL1wAY8BUibYcTVvbdsVWy7UgZUU/OUswnm/MOoftoXmhIOwKu
         KStlNEuWXIOxWevsmFzQSS2aKG3+oX0zT0cPxFShdA7g9KObT++NiK0n9MochP0hOfnT
         0ND8K/NZ6GjACr3YyNMFtJOnH/6Jj9o4vVHkozh8C5is+TGPZrkYWJcFYcqUczF56Rqp
         Bmf9ck7VNyIGGLK+V8bOv6MTibsFxj+AeoZc1pIk3HEyhg5mYZ9b12o+eTFzyg6jaWST
         80Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=oZ/nVkFJA50fOEBZroLhYWJvzM3f4CYy0U0lJu1lBpY=;
        b=kL5PYZSkslOLNIHx69w/JdpisZI3a9HB/4q1HJIJZdNi02x4XImWwYulAUCsa7YPbf
         R1DGQgJ85S0aNrjyyAZNbxOQ1C4AtmMftIjUHTf4/MeRnCF0nLMgAdjLaZN588/UayJS
         RQ4J6m/IfhDsfVKmzBELtyqIfAGbsZREqRq76gYtTRCiFb/WyraeI4T8gHiGagd2Jeyc
         83DVp3+8pyv0Sh304+XfYEsqpuiaGIvih4cTh/fiB4nYqajtTYZPDCDaNKSv9tlZmIvz
         xI4JyuP4Y/WUaXQ6RddQDd31itKCfgyiL7on1HgvK7FhE+4uJJOtYfP/mFrHOOS1FNWB
         NL7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=r3mLacsz;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z202si529507qka.6.2020.06.22.17.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 614CF20706;
	Tue, 23 Jun 2020 00:43:35 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 01/10] fork: Annotate a data race in vm_area_dup()
Date: Mon, 22 Jun 2020 17:43:24 -0700
Message-Id: <20200623004333.27227-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=r3mLacsz;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Qian Cai <cai@lca.pw>

struct vm_area_struct could be accessed concurrently as noticed by
KCSAN,

 write to 0xffff9cf8bba08ad8 of 8 bytes by task 14263 on cpu 35:
  vma_interval_tree_insert+0x101/0x150:
  rb_insert_augmented_cached at include/linux/rbtree_augmented.h:58
  (inlined by) vma_interval_tree_insert at mm/interval_tree.c:23
  __vma_link_file+0x6e/0xe0
  __vma_link_file at mm/mmap.c:629
  vma_link+0xa2/0x120
  mmap_region+0x753/0xb90
  do_mmap+0x45c/0x710
  vm_mmap_pgoff+0xc0/0x130
  ksys_mmap_pgoff+0x1d1/0x300
  __x64_sys_mmap+0x33/0x40
  do_syscall_64+0x91/0xc44
  entry_SYSCALL_64_after_hwframe+0x49/0xbe

 read to 0xffff9cf8bba08a80 of 200 bytes by task 14262 on cpu 122:
  vm_area_dup+0x6a/0xe0
  vm_area_dup at kernel/fork.c:362
  __split_vma+0x72/0x2a0
  __split_vma at mm/mmap.c:2661
  split_vma+0x5a/0x80
  mprotect_fixup+0x368/0x3f0
  do_mprotect_pkey+0x263/0x420
  __x64_sys_mprotect+0x51/0x70
  do_syscall_64+0x91/0xc44
  entry_SYSCALL_64_after_hwframe+0x49/0xbe

vm_area_dup() blindly copies all fields of original VMA to the new one.
This includes coping vm_area_struct::shared.rb which is normally
protected by i_mmap_lock. But this is fine because the read value will
be overwritten on the following __vma_link_file() under proper
protection. Thus, mark it as an intentional data race and insert a few
assertions for the fields that should not be modified concurrently.

Signed-off-by: Qian Cai <cai@lca.pw>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/fork.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/kernel/fork.c b/kernel/fork.c
index 142b236..bba10fb 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -359,7 +359,13 @@ struct vm_area_struct *vm_area_dup(struct vm_area_struct *orig)
 	struct vm_area_struct *new = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
 
 	if (new) {
-		*new = *orig;
+		ASSERT_EXCLUSIVE_WRITER(orig->vm_flags);
+		ASSERT_EXCLUSIVE_WRITER(orig->vm_file);
+		/*
+		 * orig->shared.rb may be modified concurrently, but the clone
+		 * will be reinitialized.
+		 */
+		*new = data_race(*orig);
 		INIT_LIST_HEAD(&new->anon_vma_chain);
 		new->vm_next = new->vm_prev = NULL;
 	}
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-1-paulmck%40kernel.org.
