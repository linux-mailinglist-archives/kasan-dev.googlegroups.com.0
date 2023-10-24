Return-Path: <kasan-dev+bncBC7OD3FKWUERBYUV36UQMGQE3ZLJW5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 802D97D5243
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:16 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-27d2245b836sf3337528a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155235; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHXnC3yu3LLB2OP2Kjy75nwjpzOM3U8HJx6UZNyrBRQF6DUDgNApUFpFynPyXmy/qq
         Zu6x6njgeVTBfL2A3NaP7vCSDqZtY42FfEJXH+jcGnX72Wr5oUQTRUiN3utekcBb76UO
         K+xpdRKKsBp0FDwXKrYIfNH8Hamw53EgnMa6V87qUrydX9elmoifYTI7XJGCr5uNm06B
         ZnfjZlwDJQLq3ajDejFa6dGCYoG3mrAOVZ5aUqX1fV0TLsJbViN3p3a6EdESCcdzLtB7
         9vUgkM/BPxBNFHBaBiYh8+0PXsNka5XJWPwP4XnYRZobFjZc1LqhPIQp/sYiH2MR7cGP
         ELew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=xe/1FBQcgNQNW+Z5h57yPS7mYEHoiorBd6F3MolcTpQ=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=NtNQz1ZAU64hZM/MLEVWAKmoKsyk3/dXIE1DgdBStWNs8GWJJmc38OKBJm099fNWGk
         j9kdS9fjsl80ppThOCOIXzpxsi7P1ULo2uOW8/NJ2X5fVIoed0xKoXuBoiUtEyGgRf2L
         mXgdr7/7tpa/yGFrahk6alrQr58+wxTNqp0sUFkkp0VblDJ8tjJE+cbR1FagM+ClznK5
         OD+wBPD2qefunZTb0icd2clStbxisVoGgZ2DKwWJTpvp+VPweDwa8aIvC+rTy7E8Zzum
         7OXZOyAdLSHftKmC2gJCYIvLR6EuiE9seqy22aJwCJ97onMJqQJ5t7n58sOqGq3T4I/k
         SmOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fQ6qXdTZ;
       spf=pass (google.com: domain of 34mo3zqykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=34Mo3ZQYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155235; x=1698760035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xe/1FBQcgNQNW+Z5h57yPS7mYEHoiorBd6F3MolcTpQ=;
        b=E0f85UxXToxcXL65rrXyGN2neJLpjq8J0a5U8cFwUHRrVd0A8GWrx+Fj/kWe2LKhlD
         tlhzyIourDHw2FsRz92hBezxNSGUOPm6WM33uR9lCKM6MiE0e7pn0xX4dIMTAASo1Zkc
         Dhb3468FaA2tnxnNnFmS3lIDial5PKDybSMYj4AQrKxdcid02D+2Yzz8zV3wZGnLRjQV
         99gzxqHFKjd10sjJCxT14Bcd2V+jqFTg6YMsdD8AVCtT50KAoC8gT/rpd2zQp+pg0d5C
         JOr4koXAuGODvgYAsWgOf/pY+QkeX+iLTq1BlUb8UjEAk5h8S5/o54MA2uMrnqv09S6r
         Tnjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155235; x=1698760035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xe/1FBQcgNQNW+Z5h57yPS7mYEHoiorBd6F3MolcTpQ=;
        b=D85F4wovWtGzOkNl9JLh9AvZc2JD7A3zKGyG1P4wNSdJShWfKAh5QaD29qEIfha75S
         CEcdxpL6vaFhJalK2TyrAvdbJSS0QkU7NYtIjU56AvcQ+V8QxdPB3oMippp4HIm/41yh
         ZkYDDaTtnpz8cemM4LX9lGFeqqisjpruTfZznqhWxVOxz9eGETt/eyHRaRwwnnu1n+OO
         B+ckTxbgMuzPM/rnsdbuhYJhYvlgiGYzAANtcaEYyvQcYoCc075aP4uQ6ZYlXyVHt4PH
         IoIw58Cgzxa+bOv4C8BIyzWoftoKiWPUR+9734MPZUv21uW+DaIEEj7m6UAGn5JqGtnm
         XoQA==
X-Gm-Message-State: AOJu0YzgWe1E02Yy8//Dh19krjjpm8ErQc4P2gdVRJ32On11XfcOD2T7
	N/D91FUDM06Oamp/viRxwko=
X-Google-Smtp-Source: AGHT+IF8YAhk/nPCgb8AZINW9Xm434Qd43qDwfQUpEbxUwZGXtpb9QlGi1JwI9B8BHJXmLhw2zjKuw==
X-Received: by 2002:a17:90b:2512:b0:27d:4935:8d9a with SMTP id ns18-20020a17090b251200b0027d49358d9amr20823782pjb.4.1698155234643;
        Tue, 24 Oct 2023 06:47:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1bc4:b0:26b:708f:aa9d with SMTP id
 oa4-20020a17090b1bc400b0026b708faa9dls2642694pjb.1.-pod-prod-00-us; Tue, 24
 Oct 2023 06:47:13 -0700 (PDT)
X-Received: by 2002:a17:90a:a206:b0:277:4be4:7a84 with SMTP id u6-20020a17090aa20600b002774be47a84mr20537396pjp.19.1698155233638;
        Tue, 24 Oct 2023 06:47:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155233; cv=none;
        d=google.com; s=arc-20160816;
        b=ft3p5NHN/arq4CMbXNSexGLjXLGi7RjBixRO5KQtSmvWUqDB2Rql4UaaptlXsX+OAd
         u5LBOH/A/VQgL1MUkEy+wAQCRhjaVu5AGnrjYIobXaisDcHt0zKj+xj1ggsINmw7tFy/
         O6Zr5JEPp9icsD+gpkRhzcDmPyrGzqN/CmIiUzz7kDTb4BXaqcOMl9cu47oiNPROzCKU
         rk25uQVK2cukUbCcIXQ0wmr91EtvTwrYiFUjyoY30uddQztUr01SV3AJFGmxj8rGfKwk
         eJbCUrK3qNHh4IuowW6i1jtIK91VoEErxHBzD4A8VDIm/8nS4iDMiromkRIkWy52rqZv
         fGzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+qMxws3YMU5LIbVoF9EJC7SgnlaxtiNdFL01V96iMG0=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Xtsh0Ns64ID0bgVWuU80N5P5ZybSbcZLhAckPjdfGigEv5V25lCufij9zqTiZHGPVV
         UJWQtB4BhseJT3pQWZR1gorxc8N7onP0r2Cx3t35i3uS4GlwghybXWhS3E3q6GOBxNXc
         dWAQXdNVZXk3L93l4zlbnWN2S2ZscVarFzjnxiI7bnZzY6SbxlHAS+SZnkHp6hTV5ZB9
         EcwudSr6eX/N3xkfd3oJGtAb7Kqhi/LITx3zdNqI7xdts3B33OoDYiGZykA+MkgUpKQB
         Xi7mKSpEHvZWEIfBF6of2BcuR/DNx4cBrF8Snr9aJnzRC9nzjNPQRXWZyR14P+DMn1tJ
         F7Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fQ6qXdTZ;
       spf=pass (google.com: domain of 34mo3zqykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=34Mo3ZQYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id c9-20020a170902c1c900b001c093744cbcsi508607plc.9.2023.10.24.06.47.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34mo3zqykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9c4ae201e0so4420306276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:13 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:b28d:0:b0:d9b:59c3:6eef with SMTP id
 k13-20020a25b28d000000b00d9b59c36eefmr419344ybj.0.1698155232720; Tue, 24 Oct
 2023 06:47:12 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:11 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-15-surenb@google.com>
Subject: [PATCH v2 14/39] lib: prevent module unloading if memory is not freed
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
 header.i=@google.com header.s=20230601 header.b=fQ6qXdTZ;       spf=pass
 (google.com: domain of 34mo3zqykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=34Mo3ZQYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
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
index c0d3f562c7ab..079f40792ce8 100644
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
@@ -2295,7 +2302,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_enomem:
 	for (t--; t >= 0; t--)
-		module_memory_free(mod->mem[t].base, t);
+		module_memory_free(mod->mem[t].base, t, true);
 	return ret;
 }
 
@@ -2425,7 +2432,7 @@ static void module_deallocate(struct module *mod, struct load_info *info)
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-15-surenb%40google.com.
