Return-Path: <kasan-dev+bncBC7OD3FKWUERB44V36UQMGQE4JC6HJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id B034F7D5257
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:32 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-da040c021aesf659774276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155251; cv=pass;
        d=google.com; s=arc-20160816;
        b=jV2LLczN3B86/SZUxxOXoiS1dr3zPHrhUNVMOs8bYNK3yk4jBLRB4x1IIFVvJWl+Df
         XxCOTnpQNZy4gsK58+0df1aU6gqQ3s5AnTs1Y8Tu/MHbzrKYKgbwQTEFRJNtOqbfV+m1
         vHu5Ks7BRzvO3JREnMG7xwV7XozcUpES9x28IGDZcOTRa3VpQ8oxrWIiZI1GlUVSEyLO
         mCHRenss1u4kkNg+PeX9kSG7GlD9aq1JRcV4BwuAi9ZXvt3rotkyK7IfDVbbta9pt3Ln
         iJFF+wK/5+qrWTHv6CHn7KxwEj7oKYIkNc+kXYsoDxkPWE7Sdn9ZqmwDpjBL0MSlmkhb
         eDhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=hwH+a3ynmEvpwX9H1noqPkkiA5o5kk7oIjOyLCrAyBg=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=XxE3l3Qt9oBfpAfdb3aeWqG9k3VpZqZMbdJDRs7eNfI1gcYUASYBCgwoPKXc2BRgPE
         b1scqSJs+BImSzFlgnyPiRpYZLqQgEBoqF4QxFEZ1iGZQ2epD0G6ofR7xSXB2/jbeatI
         xiVK/gHzlFz3oq/mA3MuLhJFxNAQX/g04I4MStfXaLvXzqrdGmDIICfGwhcvKB7WyhzO
         hq+syAaGqEwKE4WrjeKG5SAIAux1frtqnY0Fu4Z4n80NoTDmPqeBiZt+ByNypnmr3Bvf
         ojzkp1Xdvz7uEFeZwK8WvbEC6trIxAlIVHpMmAjv9b9yQjSTKEEAtDp2muVktXTJl2oY
         giHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wf5vuUNS;
       spf=pass (google.com: domain of 38so3zqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38so3ZQYKCZcJLI5E27FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155251; x=1698760051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hwH+a3ynmEvpwX9H1noqPkkiA5o5kk7oIjOyLCrAyBg=;
        b=O+ZPy8jDfU1fBnHQ9uHfbZtdIhycYUC5ojC9Kk0+/CcBfQc1onZG+Mv21B6UTXRVem
         Pd5nIr7xWK03X6b5H7Ks7taFDNvd+his9vpeorpGwn7d9B8se3eD5EDKqJH/NDTmjpPD
         eMOhbrVaLmSHWiVX9nmo1Lhv9EJThRygZQV2WpnjRn39wjUQ5HCWR5E6w0sPtjrStFKa
         gX9xSh6IF4URfMXP/YAZa+NHsf7j+aS317ugPEMKw6J7GNccVxUL8npsgYmgkGXCS493
         s9gTua68P2p3X/y9s3uR152ZANl2USKwZkN7Q1wu1CJt8qw+Af1HD+DAEI9Nmy3wpuPI
         hU4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155251; x=1698760051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hwH+a3ynmEvpwX9H1noqPkkiA5o5kk7oIjOyLCrAyBg=;
        b=tvEknB03khOrwNeWWHaqdxgITh63YLLWPXhw7zXotB8y2cZ1KGJTzGDcKJDe5CLH4Y
         pRTiCAB7OOF8OVVHOqjIN9vioBTc7OQNpdkNnOeP+w2hXZb3oYfhtIr4tzcz0imfqlqp
         J5s5q2oecQblqbUbbtAyKM1NP1FOmQcuWTuLQDY3v+WQlOvZzNs989VjgaSIiQyrCAS2
         x6I76p8FEqZ+FD+nCg6F3mDXAubZ/vw8ww+nf14cwIS1X7Gn5AbSDvZ6MAstEDvdJGi5
         ew0RhmU9eEVh475K+gruIqJTQ/DUeHGBElK7I0ructSCMB0POhfQs3sESpKhDHqQ3bcL
         fxDA==
X-Gm-Message-State: AOJu0YypXs/PKOGCX6+VKLz9r+2baJd7q4vEhLJegbWZwKWoZSM38HM9
	VirIkDmDJc3kWTz1Fh46ZaI=
X-Google-Smtp-Source: AGHT+IFxxvwYtbdOA9ncCv1CAgLsAOvElLl6NjSfgiDQnk+6QLeNIuA/uJOiprQA6CRLUvwlr3byKw==
X-Received: by 2002:a25:b187:0:b0:d9a:51d7:2d1c with SMTP id h7-20020a25b187000000b00d9a51d72d1cmr11718074ybj.45.1698155251670;
        Tue, 24 Oct 2023 06:47:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d045:0:b0:d9b:df64:a21d with SMTP id h66-20020a25d045000000b00d9bdf64a21dls3942328ybg.0.-pod-prod-06-us;
 Tue, 24 Oct 2023 06:47:31 -0700 (PDT)
X-Received: by 2002:a25:aea4:0:b0:da0:4550:2517 with SMTP id b36-20020a25aea4000000b00da045502517mr1601208ybj.32.1698155250991;
        Tue, 24 Oct 2023 06:47:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155250; cv=none;
        d=google.com; s=arc-20160816;
        b=SUaOetLZ+gR6GA6NIlH69S6ayzIDTr8Wrg8txWPXJ/osM1Qk4+ucc+Zancv4hTq2Z5
         KkdjAOW3TVhTwiMdliqvfRGGYZWeOs3y4cP90vR2TbTtuM6MiJF2QQm7yVsdo5u/jxON
         zW+Q+c9ERFjh7EHPcPU9CLMdfHqqhMSLSCa/EdMf1LQsjTPn8y4eqxNxndBu7IXFfumt
         eYTig2LRpXRs5CNB4+Lsq5SY2HIfbg0KY1n7ikgB9gmZ3izHNz0+ZPKUvOYcYIzvfEye
         Zwa16gvPS9nH71f6gE83XnRwve/GPDKAfrimlFBJ2IYaAn0a2b8K2t2i4q61bG2LUpDR
         IwGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=dyxdpQkY+52gRKectHQ0ToMTqRIUgvQpNStJHRxgij8=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=HPbindG0QrllXYzD8TVU3dU1UaN5Lx/bitA91JG5j5nn0lqjHn6N8ktecw1ncHJ0Se
         T7aq0sWZNn6Nvli/9JYSe1DYQ6gX4mxffkBjIFSMHRZ2rQ0+jP263T4tAcDwrf9PHoJu
         OziUn0tHw0TcdZ9Ro5NCAZIVW6HtLRFjMwOY5EsdHmwuApcfrsQI48SrBE+VPqQThjuU
         cKlGQlSUfOjcV6J2w4BVAlDOMCY0LyRVfcw5NXiRf7CGWPmX7VoCISwQjXAnYFWzegTI
         o2czyFgC6mD3cj+MKYGr/Ejsbx3KiOntcSkKn3Quo4PAWSXWlJHisEIW+Io77ES7F3it
         OUXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wf5vuUNS;
       spf=pass (google.com: domain of 38so3zqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38so3ZQYKCZcJLI5E27FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id s131-20020a257789000000b00d9caa2a9dcasi1176760ybc.3.2023.10.24.06.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38so3zqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5a7ac9c1522so62106147b3.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:30 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a0d:d84a:0:b0:5a8:5653:3323 with SMTP id
 a71-20020a0dd84a000000b005a856533323mr243310ywe.2.1698155250598; Tue, 24 Oct
 2023 06:47:30 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:19 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-23-surenb@google.com>
Subject: [PATCH v2 22/39] lib: add codetag reference into slabobj_ext
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
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Wf5vuUNS;       spf=pass
 (google.com: domain of 38so3zqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=38so3ZQYKCZcJLI5E27FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--surenb.bounces.google.com;
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

To store code tag for every slab object, a codetag reference is embedded
into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/memcontrol.h | 5 +++++
 lib/Kconfig.debug          | 1 +
 mm/slab.h                  | 4 ++++
 3 files changed, 10 insertions(+)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index f3ede28b6fa6..853a24b5f713 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -1613,7 +1613,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
  * if MEMCG_DATA_OBJEXTS is set.
  */
 struct slabobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup *objcg;
+#endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref ref;
+#endif
 } __aligned(8);
 
 static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index e1eda1450d68..482a6aae7664 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -973,6 +973,7 @@ config MEM_ALLOC_PROFILING
 	depends on !DEBUG_FORCE_WEAK_PER_CPU
 	select CODE_TAGGING
 	select PAGE_EXTENSION
+	select SLAB_OBJ_EXT
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
diff --git a/mm/slab.h b/mm/slab.h
index 60417fd262ea..293210ed10a9 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -457,6 +457,10 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 
 static inline bool need_slab_obj_ext(void)
 {
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	if (mem_alloc_profiling_enabled())
+		return true;
+#endif
 	/*
 	 * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditionally
 	 * inside memcg_slab_post_alloc_hook. No other users for now.
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-23-surenb%40google.com.
