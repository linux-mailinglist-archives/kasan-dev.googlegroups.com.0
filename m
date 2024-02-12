Return-Path: <kasan-dev+bncBC7OD3FKWUERBL5AVKXAMGQELX4W2KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 80EE3851FD0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:01 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-219114b797dsf4637060fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774000; cv=pass;
        d=google.com; s=arc-20160816;
        b=XOC9xzv7wxZpFvGbVrcR22aLc7bmFzqZvhGAlsI1kCOSNgm3GqKP6UqoBD3Xo0ymwU
         PMNbCd0k9AYyZmfuBLRAMqJR3cIqIyYOulCLsX0CthZflXwPU87HxA/ISwM6B6d+GEsU
         K2WaWuXF6SloQV8YY5GYRIjbkP6bDz7LCkh17SmLtL9Ah355/IZWmWUTuMnZGOVnjm5Y
         ++k1chMIQ/XTWkJnVDoBujwuxlZ2+6LLAe4mt60N3WrX+5DcJ6XWsDyI8UX1bazA4kVj
         wGq11zHYXOGw67+z7WVNLzb0T9FuirJOfzlGASBpgq7lj5KzTKxmXwIhXnTcLdp9vvvg
         qeig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2W03ZZUbB/xJzatyqVghuAfSKfvG8bMVlwl2rz9sqU8=;
        fh=aMap5cYQu/M3KFebykHS/HtVhAES7uV7JA6gFzbzXcI=;
        b=U1kGZIldKzuj9XiMVBhUH1KsIGUZtRaThXYql8ElGfPnCR2q1HYP+xYtvOUyzU+jo8
         oaL/vMeCBAgwFGUfiLFJjlaGgHmPMffBrIfJiG+4ZG0/5rsPsrckDSMEVQ95+GrO7QaE
         nmusWHzzCGwwC1FfvkC0OVU6rMDQBE0tcZHljOhMCOasQJ6dmrTrWV4jVQMmzXiDu2Sj
         OEwMMTxlXJJnyPe2fVxxmft92jhWk0Z6qlCP+Vk8z3bqMkUvZYeVUMMzUBZXVwl8yrqg
         hF/mzOOQLNwLFjzpH2N1fUy67axNoO71PNWvSTHThwBEwuLF8lw8Kd4MXC4VigtOIAVv
         HJmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tEPBvqcF;
       spf=pass (google.com: domain of 3lpdkzqykca0fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3LpDKZQYKCa0fheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774000; x=1708378800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2W03ZZUbB/xJzatyqVghuAfSKfvG8bMVlwl2rz9sqU8=;
        b=faPYQK161WD30cA4tdaLBn1LfOSKDFeOfUqD9XrVGCFy1UGaWggcWT6ytF5iNP8Y7i
         pv6p2In4I9PAtHUC/pVrKYGcqILMb+PzJSGNZ8m1ld5HmweCysjY7UC4zKoD36lCtCG2
         HjmD4k4JRyrwOUP6dyeMKKoUwJdpefrVFRn9z2oHB0Cuju6GSQKLf+lUSuD047ftdKQ8
         G4tnby6TuUpFmVU0pvrSuBgMq/Dv+Xlj/6jKeE1sb491lZdd0UqBqAG4F+rmCnnrUEVN
         +kXw2O7JrdmLuACCPaKF2q9sIrQo7sBnHSu2SPLHgjq4XD4MbFrnZiiA538w92706fpc
         jfsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774000; x=1708378800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2W03ZZUbB/xJzatyqVghuAfSKfvG8bMVlwl2rz9sqU8=;
        b=nONa+Gc7Ni1YNyeKMGTHXJMBZuZmkNfxxxAkuHRmsGD/FbMD26wAX6PdV05AJwBjrN
         D2LDNRDtrbLWjAddmN39ZIXvkAgWc/sfr77sP8KwGF+yjAbtcBK8OQIQ63BsBOum/SOG
         vPIW7b4SN5FYg3j8MvGb4mHFVgOQLxu/oJOcuV9hn0JNSSRKHdzvTBIhBmDpvgiEaLNK
         qpPJ0LF9p2M2tVPDcBubGZkc77tAij/FnRLvkGjltQKZbvZ+kfY/O1wolwPf9m09FDAG
         5I0WZK4hyd7cs+/UMM5g/WyhpxlmdCUdtf6l9S15/dhcN5XJUglOt6minxDJhzHfUw5Z
         LsZA==
X-Gm-Message-State: AOJu0YxVsS3hJQss09tnIeJBM/CzClc++6mFK2SovaXneDhC3RrCxrad
	A88rfjtcgauFqz8TJ6S+yke/o7z0P46U8N+XKNVKtoI0uckdM/7W
X-Google-Smtp-Source: AGHT+IG1a5zRl7+dbw7ASa/9dqizT0rzNtNhmkIjPOSx7ft3NdXkclrVfjrL6xp9IUWdvubFtWKLsQ==
X-Received: by 2002:a05:6870:3c87:b0:214:c5c3:76ae with SMTP id gl7-20020a0568703c8700b00214c5c376aemr11767195oab.45.1707774000027;
        Mon, 12 Feb 2024 13:40:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4997:b0:219:7dd0:d09f with SMTP id
 ho23-20020a056870499700b002197dd0d09fls4657955oab.1.-pod-prod-09-us; Mon, 12
 Feb 2024 13:39:59 -0800 (PST)
X-Received: by 2002:a05:6870:b509:b0:215:d030:ad35 with SMTP id v9-20020a056870b50900b00215d030ad35mr10916452oap.35.1707773999365;
        Mon, 12 Feb 2024 13:39:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773999; cv=none;
        d=google.com; s=arc-20160816;
        b=fzW+dySJ+H07cOc3w62mttziqAfslEmIzNBZJvOrPpVPgse9M6DsYtfVCFH1yiMfA1
         X4CQejBsnk4zXK+umr31/NIB88gcUkE7Z5dG06sRbGltH3OuGe5maweUgE/ihY5/4411
         fC/Wr+C5p2vKkqhUEWrQbIB7X6/5JSsZYSC/sC3IVb4dWLlbj/f1ZvVDXCVDB9ZgGVSk
         MRaYE+w2xGFale1KHm8rsmJfwTtI9pNGm6IqLom5VFYUZqeNeZdkw7tigGvS3fr28b57
         DRV77xr0fOh6RGw5N3H95PkMVPVaUGx3eNpaGlRsZCYVSEApj/H0bcJLLh0OZKVWrqts
         lr5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=9alS6gtOXFejwBrY9h+FRijZZu8X6fVY6jwbxDwAezo=;
        fh=aMap5cYQu/M3KFebykHS/HtVhAES7uV7JA6gFzbzXcI=;
        b=gmNh8yNFWRaAut4CNWL3+PQqXmYaO4M5cvUiFkRkcUi8YpCut/2ud1ut2P3zow0XFs
         USZB3DknlL4eSF0XcPV4uxY1Y96KHhsRXiOU0ALAdwrU8Xu9FqkW/jniLE7fR5bHiGqM
         dXVKE8P4n5gtN9T3ECxDhcWp7Eq/5qpB0CiMooXdludOynZtZLsHSnr+FMWzqQ0jJSnH
         L5CTJ7uri2sfvS6vrZIxFxrj4Psm/tvIdbEP58k2PfqFXswymg7VNYIAZ6xG2BlJ5Frr
         mscbxbbJ0/k2HIwzhyBsLRbOpybhmfkw/A6EYWCpCUxsVVA2NTOPG8kqIOJTkfq5ntJY
         YgSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tEPBvqcF;
       spf=pass (google.com: domain of 3lpdkzqykca0fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3LpDKZQYKCa0fheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUVqZlfAgpiHqqv3jI2UP7QKP/1JjZYCwU9QjfC7hFSNiroDBAcCCZpw03v+FZorU64KuUadns2RdHw6gEiDI7q/X/hhBlumzwHHA==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id cr11-20020a056870ebcb00b0021a0c4bd2edsi657963oab.4.2024.02.12.13.39.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lpdkzqykca0fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5efe82b835fso84262847b3.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:59 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a0d:e844:0:b0:604:a67c:7f8d with SMTP id
 r65-20020a0de844000000b00604a67c7f8dmr2200694ywe.5.1707773998774; Mon, 12 Feb
 2024 13:39:58 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:58 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-13-surenb@google.com>
Subject: [PATCH v3 12/35] lib: prevent module unloading if memory is not freed
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=tEPBvqcF;       spf=pass
 (google.com: domain of 3lpdkzqykca0fheraotbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3LpDKZQYKCa0fheRaOTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--surenb.bounces.google.com;
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

Skip freeing module's data section if there are non-zero allocation tags
because otherwise, once these allocations are freed, the access to their
code tag would cause UAF.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/codetag.h |  6 +++---
 kernel/module/main.c    | 23 +++++++++++++++--------
 lib/codetag.c           | 11 ++++++++---
 3 files changed, 26 insertions(+), 14 deletions(-)

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index 386733e89b31..d98e4c8e86f0 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -44,7 +44,7 @@ struct codetag_type_desc {
 	size_t tag_size;
 	void (*module_load)(struct codetag_type *cttype,
 			    struct codetag_module *cmod);
-	void (*module_unload)(struct codetag_type *cttype,
+	bool (*module_unload)(struct codetag_type *cttype,
 			      struct codetag_module *cmod);
 };
 
@@ -74,10 +74,10 @@ codetag_register_type(const struct codetag_type_desc *desc);
 
 #ifdef CONFIG_CODE_TAGGING
 void codetag_load_module(struct module *mod);
-void codetag_unload_module(struct module *mod);
+bool codetag_unload_module(struct module *mod);
 #else
 static inline void codetag_load_module(struct module *mod) {}
-static inline void codetag_unload_module(struct module *mod) {}
+static inline bool codetag_unload_module(struct module *mod) { return true; }
 #endif
 
 #endif /* _LINUX_CODETAG_H */
diff --git a/kernel/module/main.c b/kernel/module/main.c
index f400ba076cc7..658b631e76ad 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -1211,15 +1211,19 @@ static void *module_memory_alloc(unsigned int size, enum mod_mem_type type)
 	return module_alloc(size);
 }
 
-static void module_memory_free(void *ptr, enum mod_mem_type type)
+static void module_memory_free(void *ptr, enum mod_mem_type type,
+			       bool unload_codetags)
 {
+	if (!unload_codetags && mod_mem_type_is_core_data(type))
+		return;
+
 	if (mod_mem_use_vmalloc(type))
 		vfree(ptr);
 	else
 		module_memfree(ptr);
 }
 
-static void free_mod_mem(struct module *mod)
+static void free_mod_mem(struct module *mod, bool unload_codetags)
 {
 	for_each_mod_mem_type(type) {
 		struct module_memory *mod_mem = &mod->mem[type];
@@ -1230,20 +1234,23 @@ static void free_mod_mem(struct module *mod)
 		/* Free lock-classes; relies on the preceding sync_rcu(). */
 		lockdep_free_key_range(mod_mem->base, mod_mem->size);
 		if (mod_mem->size)
-			module_memory_free(mod_mem->base, type);
+			module_memory_free(mod_mem->base, type,
+					   unload_codetags);
 	}
 
 	/* MOD_DATA hosts mod, so free it at last */
 	lockdep_free_key_range(mod->mem[MOD_DATA].base, mod->mem[MOD_DATA].size);
-	module_memory_free(mod->mem[MOD_DATA].base, MOD_DATA);
+	module_memory_free(mod->mem[MOD_DATA].base, MOD_DATA, unload_codetags);
 }
 
 /* Free a module, remove from lists, etc. */
 static void free_module(struct module *mod)
 {
+	bool unload_codetags;
+
 	trace_module_free(mod);
 
-	codetag_unload_module(mod);
+	unload_codetags = codetag_unload_module(mod);
 	mod_sysfs_teardown(mod);
 
 	/*
@@ -1285,7 +1292,7 @@ static void free_module(struct module *mod)
 	kfree(mod->args);
 	percpu_modfree(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, unload_codetags);
 }
 
 void *__symbol_get(const char *symbol)
@@ -2298,7 +2305,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_enomem:
 	for (t--; t >= 0; t--)
-		module_memory_free(mod->mem[t].base, t);
+		module_memory_free(mod->mem[t].base, t, true);
 	return ret;
 }
 
@@ -2428,7 +2435,7 @@ static void module_deallocate(struct module *mod, struct load_info *info)
 	percpu_modfree(mod);
 	module_arch_freeing_init(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, true);
 }
 
 int __weak module_finalize(const Elf_Ehdr *hdr,
diff --git a/lib/codetag.c b/lib/codetag.c
index 4ea57fb37346..0ad4ea66c769 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -5,6 +5,7 @@
 #include <linux/module.h>
 #include <linux/seq_buf.h>
 #include <linux/slab.h>
+#include <linux/vmalloc.h>
 
 struct codetag_type {
 	struct list_head link;
@@ -219,12 +220,13 @@ void codetag_load_module(struct module *mod)
 	mutex_unlock(&codetag_lock);
 }
 
-void codetag_unload_module(struct module *mod)
+bool codetag_unload_module(struct module *mod)
 {
 	struct codetag_type *cttype;
+	bool unload_ok = true;
 
 	if (!mod)
-		return;
+		return true;
 
 	mutex_lock(&codetag_lock);
 	list_for_each_entry(cttype, &codetag_types, link) {
@@ -241,7 +243,8 @@ void codetag_unload_module(struct module *mod)
 		}
 		if (found) {
 			if (cttype->desc.module_unload)
-				cttype->desc.module_unload(cttype, cmod);
+				if (!cttype->desc.module_unload(cttype, cmod))
+					unload_ok = false;
 
 			cttype->count -= range_size(cttype, &cmod->range);
 			idr_remove(&cttype->mod_idr, mod_id);
@@ -250,4 +253,6 @@ void codetag_unload_module(struct module *mod)
 		up_write(&cttype->mod_lock);
 	}
 	mutex_unlock(&codetag_lock);
+
+	return unload_ok;
 }
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-13-surenb%40google.com.
