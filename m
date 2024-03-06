Return-Path: <kasan-dev+bncBC7OD3FKWUERBKHKUKXQMGQEHTAPY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 81270873E9B
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:45 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5a1202521easf4177672eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749544; cv=pass;
        d=google.com; s=arc-20160816;
        b=0s45eaVXNTO6kjn+ZzhPme/N7HBa+WrqiNQzBL/tCGREXQrrPFMc1+DgS98uOEikVG
         XniJBYisuX2KsxvjVJD9Ie3tuttYg5TTou75ZmkUUFmXvvuqM+QHaENrIVF3LnQQDtyp
         LKYoVTM3QHTZsnWUOJwSmWCV/3B4zWZXNiO+T+r5+2HceiV0Qnm5YQvAqI3rgcuwKsCO
         6rr9TmPTpzh8Xrv1E4UQjA9JFRcbrwFsrqqdCqZDrIB5oLo0dvJrQVagqrzp9LsVLoBD
         BsNzvzK9VK9LPOr5VP3lJCPxYEWLOWkh2NvtpGwE1rGTsiQWVUlJ0RIG37BxdwsNTez8
         mjnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=CBA2SXnvyWRMyI0aQbgk4LdgN2yGZJQIVYvmj0D23ms=;
        fh=VNAbR/HUQnY9UAeudxtqkv7suv1O3OyWAm6/ZDcFJIY=;
        b=aG6fMnwPpBSMr8qwVO8tVIzQGoHmB/WFd/EJca6VYsA5SKqWNQ7dIWcVZFBV8nbWgQ
         hipGgvvESUhLWuxXr7EfhBmkUqMyUjch5U4QVmy/QJVx2ofN3T5fkFMHuWC/Db++evoV
         8XjYgTMcSHea2U+6rjja7A8IRZSrfiJOuU5kSO+A0hZ9ggAUN1hXSse8gYScnKPH6BET
         pA4T5JnyGGYsuSTGVemj4hr7v1ISTD0UGIW80nczl8Xw+L2/SgnpiUk5pnYRf3cSvNoy
         lJA+iLHEgKQXqES30/Au8iIwQSjcXra+hjmMxvNVK83I9jqwLt76mKU8L1KhVezVMrCQ
         teMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4qqVHzba;
       spf=pass (google.com: domain of 3j7xozqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3J7XoZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749544; x=1710354344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CBA2SXnvyWRMyI0aQbgk4LdgN2yGZJQIVYvmj0D23ms=;
        b=VYIoal+42RzY21OGUzwCsj397/6iI0CG0nl0Z12/7NMT2cYulA7rMO3DKasrGDLAfz
         nEoblMQ6JRfYHyI4BmUStiqASv21CwjTXweHj1Q5kAGc5R4E+2Us/KbcSFezuKOGjwlS
         qMsTZPs/yT4SVc2sS7JBx6EtwdjIijC54uyu1JsQrQaA6qM+ydCSNTol4Mu9MmkOA8FX
         hO+WxXNlD3k011ibhCqK2dNZPuKWBioww4FD30AaCaKLqoEMtsGuLiryD6K43Rarfc8M
         HqK3zPQWtft0tf3wxgxeHpNWT2BMQWZddI4hTPXGwY8RqkVvqZgoByO1hZUUK5g9p/RP
         mNiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749544; x=1710354344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CBA2SXnvyWRMyI0aQbgk4LdgN2yGZJQIVYvmj0D23ms=;
        b=m5Kjh3PoBohmEWjtzQUZw6fQhYOmnHMrmCr2kf/Dn1UFW8apqd61oejH5VFIfVdc43
         T6z+Y+9NBAG7q2kQ1xcKvdIKGQEyMrrSZroqiH/4sTN9wyi/r4X9R37Y23d/w6j3U5OU
         HKcsG1MDaNEhA6r2iQyS7XjM1OZcXv/ZhaWSTAaYSz+UP1IfWkHRGtVX9ScHiqi3mEQK
         K8GoysdL3WfGAbfTjkifI9VQ6+ni41cBtwmAl/NluYZ8WSbvz/SoL3nLjFawvZDFUQQP
         8a2w5MT9bV2lVZqQHrUmaunbVapPizM9nqqk6yA1j3HwqzmvhRtUt+Of9UEPUnhkywEk
         SGoA==
X-Forwarded-Encrypted: i=2; AJvYcCVw53Gtxch/nDji5URTSMcJciCIFd432wtQBLOkWjjP3LqKBYyhxVGPi1v+/Xg4dSa0kNvSWpKTh5agnwKQes4oeQId5TWlmw==
X-Gm-Message-State: AOJu0Yz3E7QUbYj020ZEH5mEMtay0Jg0Ze/uqvO1nKKEem7VaTHjS4BR
	YDkYrbm9e0+jRiLjHDAiroAlKbk79gy3erq+Gkt9w7yjKTuHzmb3
X-Google-Smtp-Source: AGHT+IEUG43YIOBsom7F6Gj/xaZy+XITLOUYkNPij7w+9rUie5m553TEKknOcvnpWXyjzraMddDVmw==
X-Received: by 2002:a4a:6553:0:b0:5a1:20aa:d201 with SMTP id z19-20020a4a6553000000b005a120aad201mr5018049oog.7.1709749544417;
        Wed, 06 Mar 2024 10:25:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1055:b0:5a0:58ca:3fc with SMTP id
 x21-20020a056820105500b005a058ca03fcls86955oot.0.-pod-prod-03-us; Wed, 06 Mar
 2024 10:25:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVybvWRf19pX0dZbFebpbo7+dcwtJtTm9DvfTxdSEYBzaxApWPc18YMfhmJch2RGppFOTwm+LgSL1P1s44q3khlOe9C2pK0fW+0Jw==
X-Received: by 2002:a05:6808:8cf:b0:3c1:eac4:7395 with SMTP id k15-20020a05680808cf00b003c1eac47395mr5504155oij.51.1709749543652;
        Wed, 06 Mar 2024 10:25:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749543; cv=none;
        d=google.com; s=arc-20160816;
        b=gA7LhosQv3HInsEfTZghTX13sLAvzs1fiKgFJITN5SN3TJVOPzqzlvV/DizvCEnyAA
         z3QRe4XkSkPRxASezybRppHPX06J14eiSHy4rY6ibAoVS1oe0Hy5CjWPFGkENWnQQsig
         zbrOqZCtlGYg2tYpRinvLooVMhykoh/AV8Et2i5WCq+Fl89+muUMOeNddCv5gaC0Fpyg
         i7cOY0GZyzLYE9aa7M4Vz8WhMgSy4unziXcugJliHvC6h/Za0WrEt+pAvzuIE8thBooH
         pcTzCfC0VXTUnGbgiypqS3NqhIZcLfwGrdoV1tpdGUOWy4wu5Zz+nchht+i2kx80Kt+U
         JbsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=vneHWg8klAgpjQ629hDbHaGhEsZ8DTv1BUkMhsSVPcA=;
        fh=dJMp0Fq5bwgTPO/Dp9n7LjBP7zjEOg3ETK2MXFdP88k=;
        b=nxfO0fgVLUfEiLOK8b4uks4ZnE9q56Vlecby7FEeeCcOKel2W1yxxPbzVPGGEkOf+Y
         kaQ8qCjnU//qDTC0YHkhnH2Qob2+QgfC26T0Leo3VUvJOO2WF1vx70UkwoTBeCmiL9ax
         tQtvZC01SE/l3dGGSeQd+cQLKhKT5gwCrPbBjXXWxBZmdAhytMYTF4Z+8o8ncKENPnBr
         ZdbLEOcN8+zYES1VLgoD0+3gg7UZ4/5YlXZtkcOF2HtPCKKkhhiuqcyKpUkqFQ76Ccp9
         k8+BO98GbAaJ24y7cc0cuLbaCOxRG7FheWLHi58GAS4ZibX8sYWfx7Ftb6BHky2bCwSr
         FTwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4qqVHzba;
       spf=pass (google.com: domain of 3j7xozqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3J7XoZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t18-20020a056808159200b003c1ec43807bsi515291oiw.0.2024.03.06.10.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3j7xozqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b26845cdso10940450276.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUF9k5BXrPnBRn7IV0W82R5EuGq+XotpBl599Oxc70cwfhUxnqx8W8t0JrfOvIEb8XT0l8lc/XE8FPY69AKwW7iyOUMGKZJ86x+kg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:b1c:b0:dcc:e1a6:aca9 with SMTP id
 ch28-20020a0569020b1c00b00dcce1a6aca9mr3819417ybb.9.1709749543321; Wed, 06
 Mar 2024 10:25:43 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:25 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-28-surenb@google.com>
Subject: [PATCH v5 27/37] mm: percpu: Introduce pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b=4qqVHzba;       spf=pass
 (google.com: domain of 3j7xozqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3J7XoZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
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
index cdd0aa597a81..e62d582f4bf3 100644
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
@@ -64,8 +74,8 @@ struct pcpu_chunk {
 	int			end_offset;	/* additional area required to
 						   have the region end page
 						   aligned */
-#ifdef CONFIG_MEMCG_KMEM
-	struct obj_cgroup	**obj_cgroups;	/* vector of object cgroups */
+#ifdef NEED_PCPUOBJ_EXT
+	struct pcpuobj_ext	*obj_exts;	/* vector of object cgroups */
 #endif
 
 	int			nr_pages;	/* # of pages served by this chunk */
@@ -74,6 +84,11 @@ struct pcpu_chunk {
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
index 4e11fc1e6def..2e5edaad9cc3 100644
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
@@ -1646,9 +1646,9 @@ static void pcpu_memcg_post_alloc_hook(struct obj_cgroup *objcg,
 	if (!objcg)
 		return;
 
-	if (likely(chunk && chunk->obj_cgroups)) {
+	if (likely(chunk && chunk->obj_exts)) {
 		obj_cgroup_get(objcg);
-		chunk->obj_cgroups[off >> PCPU_MIN_ALLOC_SHIFT] = objcg;
+		chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].cgroup = objcg;
 
 		rcu_read_lock();
 		mod_memcg_state(obj_cgroup_memcg(objcg), MEMCG_PERCPU_B,
@@ -1663,13 +1663,13 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-28-surenb%40google.com.
