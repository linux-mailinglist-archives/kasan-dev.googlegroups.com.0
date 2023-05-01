Return-Path: <kasan-dev+bncBC7OD3FKWUERBL66X6RAMGQE6P4RAZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5750B6F33EE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:16 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-32f23e2018fsf169337775ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960175; cv=pass;
        d=google.com; s=arc-20160816;
        b=aHrD/RLr/wUDF7XXmLKxl4e0EEzGiEgkra+4h+P5yJN2L8vA8OHcTndaTrTOPyFkQ1
         +0GS1VxY4SinlAigQzFd0GZBRp6EyjQgby0SQV6pwbk7tSeDyuhgRBVbWbvoGiEHqVkK
         XPOYqGuV17+TpvL3/7G5AMzTXWDS9MzfZIFIOWH1Loyj743ZAzf++njswuhXCi674mYN
         P90fRs0SS9Bzrl4b7vFxVUhXFIoD3JfiCc0G3w6xDY4rnYzOXDi1k9l0pGfGkYRP6U/R
         7ImDKNG6O0mOSbKPtWXNP1CPK/zN/LU8gnjXsVYu2G3snFPnbbxir+yCvMs1gVh5SOmi
         C9Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=t0KzpCgjctdVb4isVumGKoIU57eHqW8lzHCUKjse6FY=;
        b=M3ZWDFP8gnQZX4llcYQKgHMYRZtOsal8PmKfaIn+gCHzw13L6KBuwQjjoNn3O7L0VP
         9w48Xfeaz02ckB+3jSJozLNuxjHwRtUM9PDP66Aq+5lYx3wa1mUd+1Ob1v/XbEwr/Y90
         PAL1fYa7L5Jgxt9vKbJEtgG7+ofs+3rpgM2Aox8QrVZPpzowZGfYqr9ORb7c83fOS1Cf
         WWlISObsYAzVrgDgq9WjMndvC0K7mx6YuzFA5ZPhqYHtKPwwoPWcv/93ubRfVerQMkFh
         SVi/Bqa3revbRrXlURhUzsitWF0dVH1mN7p2+/BCy0r6k0IIargion5lvCONLAaVzYs3
         +5DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=DmSOIqXp;
       spf=pass (google.com: domain of 3lu9pzaykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Lu9PZAYKCXUlnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960175; x=1685552175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=t0KzpCgjctdVb4isVumGKoIU57eHqW8lzHCUKjse6FY=;
        b=iSGhIXDj9wF6+BEJKOCwdzFDVdihni80iQVOcXYCIIi8+8wIniczsPAeHCg03v1t3z
         pfKzjDtbRcDGGvL8WGBL5NWAXfCHQND71wi4ZSpRnSDc25OP1jj4HbF7mLWsk70DAan4
         +MhIoBp03PamQ1LM27SUxHh+rPDu758xX0E4c1iOCRTvTNVRHs83rHNpu/MKoaH8/xtS
         fePoxF8VQxKxTvJa79f6EQQvjoz02fCgOPcI7fVojC3ZAkTniQmcGtIM62MqqXOp6kIy
         S1M/46zzQn0ie8JPGqL1+sckpX4fd7ld9Cj8WqCnVghdTb3E5rnUntrhT4WQ/6+k8XuZ
         R36A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960175; x=1685552175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t0KzpCgjctdVb4isVumGKoIU57eHqW8lzHCUKjse6FY=;
        b=OSyXGL5XdOIpXmHoXA0gDN5Z6oRgnl2aAkGjZzXVQAWFB5H/a14yM1tJ7i69h9WShl
         UOIPJ4aIBuXHxQrGokkWpW1rTZm4ycdIDKSFQ/jB6pErkQxtfdTzC4wTxQKnP0G9pS9f
         DTbeKvkxZzK8soijMi8DoZpkrvRT37564Hry1XzuD89/OzB1uH/1/yvK4FuMg78HMVoK
         ryCthHFKTLx7Sw9Kge604bzcBolv4ud30c/N61f6wxnoSgiO9FTgS6FrlGOVYfK49OTa
         yjPbEv4QPJPRu2hhv70c9R87ee8D//YeDEn2+XkyY07Rdmlzo01CpzffZ5O0GP0qZjVY
         eHHQ==
X-Gm-Message-State: AC+VfDxsn/6seVqdDGVf1jGXyItlbdmZvWFSRu8t9GlfEDdzXWDUc1Ia
	vU0873rs3WUmBeMetjKWnDo=
X-Google-Smtp-Source: ACHHUZ4gK/9r6+wRKZhA1OqMOACgvbGqVO4woBX0HvTajanfk3nG3moR0/KVCm4QrEk2/FhMx/On2g==
X-Received: by 2002:a05:6602:701:b0:760:ee03:7e95 with SMTP id f1-20020a056602070100b00760ee037e95mr11362280iox.1.1682960175240;
        Mon, 01 May 2023 09:56:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:c995:0:b0:763:5829:9243 with SMTP id z143-20020a6bc995000000b0076358299243ls2146725iof.7.-pod-prod-gmail;
 Mon, 01 May 2023 09:56:14 -0700 (PDT)
X-Received: by 2002:a6b:ee17:0:b0:763:8ad8:e2b0 with SMTP id i23-20020a6bee17000000b007638ad8e2b0mr8891259ioh.7.1682960174747;
        Mon, 01 May 2023 09:56:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960174; cv=none;
        d=google.com; s=arc-20160816;
        b=jV9+iIIbkP9jW6JtTyIEYq+i/0HgyGN/maXtZGvmSTtJF1cjr4XluYtOxTNMpRcuLb
         nvd5FLf4p21SumxMqD8suhwzyIfH98zgDCWu9HkUhqa1xVqKYZnlqrKvn3W3DENvxgvF
         T/K6854to7WEPWs/LdhZ8CssEmYGlKaVMHSFzcqpu0gi0p2kJs0NfB/5AW6fgrvqDhoQ
         nsX56JITW3aT8H/q1c8wu8td5ne1L5kMoe/TC4EoPgnpw+WbyMbVLtIwE/4q6DgkSY3o
         UK6mLQEIvfNJvQ1X3WApqZVKTpZrcU59Pl9VFfRdzBzS5/zOhihD4hYXVOPBM6AaLsEj
         kZyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=k4gyiXZ+rLWKPzhf5TCPslUr+ioI4/2asgnCyiPdOEo=;
        b=dY0xltOo+O+uzJPcPxv2gf1/jgUa5cp9YUkKxiq2r94t9y3T0qrnPQ+e2ehAhcWPNs
         U+C/EdMggN4ERp1x+qUMBkI5q1yVK08uDJrwTrH1piAJFbWYT3Hn8deF18dO9MaAG9LM
         nMj1OtKexu+7r9k4oxGvrcgIyx4GZKktd0sJZhpckY1orbsDYTAu6ELTjvE5F0R9lMgj
         PcPWLSR+P9wFxpw2vYQvUJqX0IW6ztkc1T9kt48PiUCKugyl56lLmzVlrdpRuK6aZjQy
         bARoIPmcMknwpO7VsO///Ef0UThfd5bPZG/STkAkT10v5jo09qbsWrbsUzxQVUbvv4bI
         2DfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=DmSOIqXp;
       spf=pass (google.com: domain of 3lu9pzaykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Lu9PZAYKCXUlnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id t21-20020a056602141500b00763b993e80esi1343989iov.4.2023.05.01.09.56.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lu9pzaykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b8f6bef3d4aso5547290276.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:14 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a05:6902:1081:b0:b9d:d5dc:5971 with SMTP id
 v1-20020a056902108100b00b9dd5dc5971mr3225339ybu.2.1682960174070; Mon, 01 May
 2023 09:56:14 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:39 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-30-surenb@google.com>
Subject: [PATCH 29/40] mm: percpu: Introduce pcpuobj_ext
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=DmSOIqXp;       spf=pass
 (google.com: domain of 3lu9pzaykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Lu9PZAYKCXUlnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Upcoming alloc tagging patches require a place to stash per-allocation
metadata.

We already do this when memcg is enabled, so this patch generalizes the
obj_cgroup * vector in struct pcpu_chunk by creating a pcpu_obj_ext
type, which we will be adding to in an upcoming patch - similarly to the
previous slabobj_ext patch.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Dennis Zhou <dennis@kernel.org>
Cc: Tejun Heo <tj@kernel.org>
Cc: Christoph Lameter <cl@linux.com>
Cc: linux-mm@kvack.org
---
 mm/percpu-internal.h | 19 +++++++++++++++++--
 mm/percpu.c          | 30 +++++++++++++++---------------
 2 files changed, 32 insertions(+), 17 deletions(-)

diff --git a/mm/percpu-internal.h b/mm/percpu-internal.h
index f9847c131998..2433e7b24172 100644
--- a/mm/percpu-internal.h
+++ b/mm/percpu-internal.h
@@ -32,6 +32,16 @@ struct pcpu_block_md {
 	int			nr_bits;	/* total bits responsible for */
 };
 
+struct pcpuobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
+	struct obj_cgroup	*cgroup;
+#endif
+};
+
+#ifdef CONFIG_MEMCG_KMEM
+#define NEED_PCPUOBJ_EXT
+#endif
+
 struct pcpu_chunk {
 #ifdef CONFIG_PERCPU_STATS
 	int			nr_alloc;	/* # of allocations */
@@ -57,8 +67,8 @@ struct pcpu_chunk {
 	int			end_offset;	/* additional area required to
 						   have the region end page
 						   aligned */
-#ifdef CONFIG_MEMCG_KMEM
-	struct obj_cgroup	**obj_cgroups;	/* vector of object cgroups */
+#ifdef NEED_PCPUOBJ_EXT
+	struct pcpuobj_ext	*obj_exts;	/* vector of object cgroups */
 #endif
 
 	int			nr_pages;	/* # of pages served by this chunk */
@@ -67,6 +77,11 @@ struct pcpu_chunk {
 	unsigned long		populated[];	/* populated bitmap */
 };
 
+static inline bool need_pcpuobj_ext(void)
+{
+	return !mem_cgroup_kmem_disabled();
+}
+
 extern spinlock_t pcpu_lock;
 
 extern struct list_head *pcpu_chunk_lists;
diff --git a/mm/percpu.c b/mm/percpu.c
index 28e07ede46f6..95b26a6b718d 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1392,9 +1392,9 @@ static struct pcpu_chunk * __init pcpu_alloc_first_chunk(unsigned long tmp_addr,
 		panic("%s: Failed to allocate %zu bytes\n", __func__,
 		      alloc_size);
 
-#ifdef CONFIG_MEMCG_KMEM
+#ifdef NEED_PCPUOBJ_EXT
 	/* first chunk is free to use */
-	chunk->obj_cgroups = NULL;
+	chunk->obj_exts = NULL;
 #endif
 	pcpu_init_md_blocks(chunk);
 
@@ -1463,12 +1463,12 @@ static struct pcpu_chunk *pcpu_alloc_chunk(gfp_t gfp)
 	if (!chunk->md_blocks)
 		goto md_blocks_fail;
 
-#ifdef CONFIG_MEMCG_KMEM
-	if (!mem_cgroup_kmem_disabled()) {
-		chunk->obj_cgroups =
+#ifdef NEED_PCPUOBJ_EXT
+	if (need_pcpuobj_ext()) {
+		chunk->obj_exts =
 			pcpu_mem_zalloc(pcpu_chunk_map_bits(chunk) *
-					sizeof(struct obj_cgroup *), gfp);
-		if (!chunk->obj_cgroups)
+					sizeof(struct pcpuobj_ext), gfp);
+		if (!chunk->obj_exts)
 			goto objcg_fail;
 	}
 #endif
@@ -1480,7 +1480,7 @@ static struct pcpu_chunk *pcpu_alloc_chunk(gfp_t gfp)
 
 	return chunk;
 
-#ifdef CONFIG_MEMCG_KMEM
+#ifdef NEED_PCPUOBJ_EXT
 objcg_fail:
 	pcpu_mem_free(chunk->md_blocks);
 #endif
@@ -1498,8 +1498,8 @@ static void pcpu_free_chunk(struct pcpu_chunk *chunk)
 {
 	if (!chunk)
 		return;
-#ifdef CONFIG_MEMCG_KMEM
-	pcpu_mem_free(chunk->obj_cgroups);
+#ifdef NEED_PCPUOBJ_EXT
+	pcpu_mem_free(chunk->obj_exts);
 #endif
 	pcpu_mem_free(chunk->md_blocks);
 	pcpu_mem_free(chunk->bound_map);
@@ -1648,8 +1648,8 @@ static void pcpu_memcg_post_alloc_hook(struct obj_cgroup *objcg,
 	if (!objcg)
 		return;
 
-	if (likely(chunk && chunk->obj_cgroups)) {
-		chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT] = objcg;
+	if (likely(chunk && chunk->obj_exts)) {
+		chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup = objcg;
 
 		rcu_read_lock();
 		mod_memcg_state(obj_cgroup_memcg(objcg), MEMCG_PERCPU_B,
@@ -1665,13 +1665,13 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
 {
 	struct obj_cgroup *objcg;
 
-	if (unlikely(!chunk->obj_cgroups))
+	if (unlikely(!chunk->obj_exts))
 		return;
 
-	objcg = chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT];
+	objcg = chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup;
 	if (!objcg)
 		return;
-	chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT] = NULL;
+	chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup = NULL;
 
 	obj_cgroup_uncharge(objcg, pcpu_obj_full_size(size));
 
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-30-surenb%40google.com.
