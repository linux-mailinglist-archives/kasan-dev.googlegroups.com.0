Return-Path: <kasan-dev+bncBC7OD3FKWUERB7GE6GXQMGQEL4QZQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 92879885DCD
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:21 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-430c3b3b4dfsf604061cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039100; cv=pass;
        d=google.com; s=arc-20160816;
        b=TeRfdqpiQkYarFfXHfYDWEtNuFEs4l9Qk0KMS1Rt0WQOCSPf7nB62EqOnOOkoA0Eh8
         BmLrH0Cd5QpjZ7MTiLtt3cLNiGgVhMOmGiInFOnySjZLqSvf/Q/RXn5xvN4j8/oTo7ZI
         vOb+fl/2IW6kAvSC4XH7RMty8kM7c3ZNkiwiXoAZRTlmmn6UsuM7PmpUFX5/FLpe/Iz3
         kYUgD2zvbFbmFXQqdNEb7uA8lXhE/pOHIweTiSOcLWK7zy6+MklXK0U/cvc4Ea9q7TSP
         9NC1Sc/24eDFLuCLuT+Iu3JkFz//Opm6/lS02RaDw2Mj78q2wUvYEw+jmiwtVO25rUca
         CxIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=84SO2fB/8UGlcHEDdElwcdE1YRYz5KAqmYSE4uWeTnM=;
        fh=cJ4owkUp8SDJ9XOH6HElnSxttuIDik8RQdppwTZSLvM=;
        b=WzOgqMprDfaPzFkyxhff2e5H6ZijcPrxMaT2SRAkD+pGh5Ildr/jRUcm5JgjUkK0Nx
         zznRy3hEGHk0/gShI1o5eij8kjZRRvcLi91gEmboEFypX/RyZ2xYmhvk5VZAHN4Q9wR6
         5isEs7vz0iSZWDhe/3LYMkPLz6yrHMaAf/r5GgpTC9+g7dLnOR9pOlWMtce1vj8xdc+b
         +HuC4x1fvTgbSClcFKrCSGqvZNneptgfnQotpPP0fWECJMMgcUh2gmRU+T4cXruivuNZ
         d5ic60ksUIX3YGbfhjzJmrbRelDZ81jYSoXPXoD71fdFJCtzJuNyLtuYP96wfGoAwQY3
         tTow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xCrGqKIS;
       spf=pass (google.com: domain of 3e2l8zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3e2L8ZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039100; x=1711643900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=84SO2fB/8UGlcHEDdElwcdE1YRYz5KAqmYSE4uWeTnM=;
        b=AaMAhNHW19XIP8JZ7Sq4u/UCPqwvgTX5/6fKwMytYD9G0N/YfXOcEsYE5wQcidAwJp
         iInF1LUvm0pKouz+kPLoSk0XZ7DMy8KmsRdx7R4Zel9I3SB+VqNhCyF58Hks0KzhqBY6
         eDF6PBQPZZku51pHjD5vs6kgkgoJG0zMvFmWeDiqlXDq4UHKynuJ+aQYvngwYtlTxRWk
         ONBw25nNsp0qL9po/xu/6Zfl+BC+kpx4alU51Djo9EFh5VXmJF2xm+SVIBselszRUY+z
         vHk8N+uT5LDs/ax8gJv9mEim/vYZpjBBpkqp4fF+UKhJGK7kAvwjnqxcktzs3VbPDXwJ
         ckuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039100; x=1711643900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=84SO2fB/8UGlcHEDdElwcdE1YRYz5KAqmYSE4uWeTnM=;
        b=irssELPpeUUvuB8lO4RfUzfJP4/33jUM87TUdenMRcKWkgK0jnfBy+tcnmIJqEXQl/
         e+jvjSBHvsEsvSQHvppqq1E63jdYANFEP0eM4l2UHzam+wGM3gaNHFGZfSaRGyhWMBCF
         U38LrkPTvAB6SuRa7WGc32NSlW1pKe7/UiQGe1hqK9XY1bObyDOXUqr9v699Pc/MMUwd
         UOdrV3AOPhHbu4v1H3Ud1jiFJViV/AgMpSGSrFkqjXMVYuyipgVbGf8HpR/UZ4/DKyiE
         6P1LOoZgedgM3HZ9Kr1ib7+YEpGrMKeC3AnjhXuXB1cZ61NQEYUAv5IzofZkJBOcjHfU
         VbyQ==
X-Forwarded-Encrypted: i=2; AJvYcCWx2sJ1m+2Z9YJP86tMGOVMtxYNDj190RDW45HYowzP67byByys8qnPrEhgXOxgj5Yj9mJNa77QwzpBTLzpf+yJ2Zb2bR0kKA==
X-Gm-Message-State: AOJu0YxZW9Tzs8YyBpwda9xGtduwfroiUr4Z+cKFlqA0HxlGV/UEzdJ2
	XHLXPpZHlpBzWpbD8SasBtDnnJjllG3WnpiC6p12RvX5VvCt7c36
X-Google-Smtp-Source: AGHT+IFeasjDzTQsfAlRF1TaPKbx9brmCkUz19DJc9MdoWhcHuolwgnM5/53LYLWY/6EfWzoELJr1g==
X-Received: by 2002:ac8:5714:0:b0:431:2a40:27e2 with SMTP id 20-20020ac85714000000b004312a4027e2mr89781qtw.7.1711039100593;
        Thu, 21 Mar 2024 09:38:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1011:b0:430:edac:58f4 with SMTP id
 d17-20020a05622a101100b00430edac58f4ls1646481qte.0.-pod-prod-01-us; Thu, 21
 Mar 2024 09:38:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkQd5Uk1xgNPYMRc4LcdbwHFSVF6RDf26hcfPE3uHCF4T90AMXaEApBv0vudwNofotQz3J+NeAe8hoGjL5Xckz+zuYuXI06yWWeA==
X-Received: by 2002:ae9:ea04:0:b0:788:3101:b1f0 with SMTP id f4-20020ae9ea04000000b007883101b1f0mr21543477qkg.64.1711039099777;
        Thu, 21 Mar 2024 09:38:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039099; cv=none;
        d=google.com; s=arc-20160816;
        b=TvBMgI4c3ZqnBWD2r47GXTtVrzhx8dCMGwI3kRv7ZXcvvuqD5dPDncwdIwFeXh3fDi
         /N/ivUxw8tAQzrJaO4pMTj4Qxmnk9CZxfPXY3nsoWKRgHdNeFxHCfemWxJt90eDWzgKX
         fZKXdyPAeqfJPucmjSxRBS2hKCQBAliu31OZyJ6aAvyiGf19z1kJpqaoQISkbOWba1IT
         0PhxF/Z6k1jhSqGGLj6JIWYndMYdpR3WiiVjLvlPCcM/VFOQ88fA9ly/UmC9c46jmXzV
         OHERY8NzgdKfU4mkSmlIBBAKubPY1et+jOBvS+ceFmcZBlenYhjzgtjK8yx/3N0b4o+/
         xjnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iYMC0aOkTaJuIlgenfbozu9BZf0q2gbSOAGaj6P53nM=;
        fh=+QaQ7GwNw+Q41KajVoT1pSSL5LsN7suVAjNEGESYSf8=;
        b=lwawqQuWHTlYj1XzQpbdYVQL9+7lJvipXm+EogNLhBigpO9+rbx8MAgBF8P8JDIFsm
         sEm0q/BXaRFe2yV2U7NNAXvUB0RdFHpOF43lVVHAPZwxnlhv0LKEbeZsziAvmj9sUrJC
         8G1C+OtqoYwVz8gbtkBUGWedRy7qGFkrh+g2Fvlx+tIxcP4d1MHwPEyjaqC2bMGn+z4Z
         EgFXthIYXckp02TJ/rIwuJN1m9KVPfL5cGl5ULr811/vw27L4C7dX4+1Z8zdyY7/vV7k
         CW/+SBWhOL/uJ+sxMR4h7xALTU4P8/S2SdovvN6dc6+VXAlEWMuBh0+gjoN64qDa6FR8
         85OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xCrGqKIS;
       spf=pass (google.com: domain of 3e2l8zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3e2L8ZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id br37-20020a05620a462500b0078a2918f02bsi7213qkb.0.2024.03.21.09.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e2l8zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b269686aso1811184276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFOTziUgnbMSplZa/elpjQ54nWCC8rXhelEx6AZmThU6/g53eJKVbKvsFuTFzfpvEy+F/GDdUYUGjxkbk99dqSTAMA4smrPA5rXQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:2009:b0:dcd:c091:e86 with SMTP id
 dh9-20020a056902200900b00dcdc0910e86mr979486ybb.13.1711039099264; Thu, 21 Mar
 2024 09:38:19 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:54 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-33-surenb@google.com>
Subject: [PATCH v6 32/37] lib: add memory allocations report in show_mem()
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=xCrGqKIS;       spf=pass
 (google.com: domain of 3e2l8zqykcwgyaxkthmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3e2L8ZQYKCWgYaXKTHMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--surenb.bounces.google.com;
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

Include allocations in show_mem reports.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/alloc_tag.h |  7 +++++++
 include/linux/codetag.h   |  1 +
 lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
 lib/codetag.c             |  5 +++++
 mm/show_mem.c             | 26 ++++++++++++++++++++++++++
 5 files changed, 77 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index cf69e037f645..aefe3c81a1e3 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -30,6 +30,13 @@ struct alloc_tag {
 
 #ifdef CONFIG_MEM_ALLOC_PROFILING
 
+struct codetag_bytes {
+	struct codetag *ct;
+	s64 bytes;
+};
+
+size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep);
+
 static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
 {
 	return container_of(ct, struct alloc_tag, ct);
diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index bfd0ba5c4185..c2a579ccd455 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -61,6 +61,7 @@ struct codetag_iterator {
 }
 
 void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
+bool codetag_trylock_module_list(struct codetag_type *cttype);
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
 struct codetag *codetag_next_ct(struct codetag_iterator *iter);
 
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 617c2fbb6673..e24830c44783 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -86,6 +86,44 @@ static const struct seq_operations allocinfo_seq_op = {
 	.show	= allocinfo_show,
 };
 
+size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep)
+{
+	struct codetag_iterator iter;
+	struct codetag *ct;
+	struct codetag_bytes n;
+	unsigned int i, nr = 0;
+
+	if (can_sleep)
+		codetag_lock_module_list(alloc_tag_cttype, true);
+	else if (!codetag_trylock_module_list(alloc_tag_cttype))
+		return 0;
+
+	iter = codetag_get_ct_iter(alloc_tag_cttype);
+	while ((ct = codetag_next_ct(&iter))) {
+		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
+
+		n.ct	= ct;
+		n.bytes = counter.bytes;
+
+		for (i = 0; i < nr; i++)
+			if (n.bytes > tags[i].bytes)
+				break;
+
+		if (i < count) {
+			nr -= nr == count;
+			memmove(&tags[i + 1],
+				&tags[i],
+				sizeof(tags[0]) * (nr - i));
+			nr++;
+			tags[i] = n;
+		}
+	}
+
+	codetag_lock_module_list(alloc_tag_cttype, false);
+
+	return nr;
+}
+
 static void __init procfs_init(void)
 {
 	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
diff --git a/lib/codetag.c b/lib/codetag.c
index 408062f722ce..5ace625f2328 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -36,6 +36,11 @@ void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
 		up_read(&cttype->mod_lock);
 }
 
+bool codetag_trylock_module_list(struct codetag_type *cttype)
+{
+	return down_read_trylock(&cttype->mod_lock) != 0;
+}
+
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
 {
 	struct codetag_iterator iter = {
diff --git a/mm/show_mem.c b/mm/show_mem.c
index 8dcfafbd283c..bdb439551eef 100644
--- a/mm/show_mem.c
+++ b/mm/show_mem.c
@@ -423,4 +423,30 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
 #ifdef CONFIG_MEMORY_FAILURE
 	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	{
+		struct codetag_bytes tags[10];
+		size_t i, nr;
+
+		nr = alloc_tag_top_users(tags, ARRAY_SIZE(tags), false);
+		if (nr) {
+			pr_notice("Memory allocations:\n");
+			for (i = 0; i < nr; i++) {
+				struct codetag *ct = tags[i].ct;
+				struct alloc_tag *tag = ct_to_alloc_tag(ct);
+				struct alloc_tag_counters counter = alloc_tag_read(tag);
+
+				/* Same as alloc_tag_to_text() but w/o intermediate buffer */
+				if (ct->modname)
+					pr_notice("%12lli %8llu %s:%u [%s] func:%s\n",
+						  counter.bytes, counter.calls, ct->filename,
+						  ct->lineno, ct->modname, ct->function);
+				else
+					pr_notice("%12lli %8llu %s:%u func:%s\n",
+						  counter.bytes, counter.calls, ct->filename,
+						  ct->lineno, ct->function);
+			}
+		}
+	}
+#endif
 }
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-33-surenb%40google.com.
