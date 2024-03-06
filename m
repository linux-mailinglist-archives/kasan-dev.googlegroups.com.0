Return-Path: <kasan-dev+bncBC7OD3FKWUERBB7KUKXQMGQE5NZVQDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E8FBE873E7E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:12 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-42ec1f0d99csf71138111cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749512; cv=pass;
        d=google.com; s=arc-20160816;
        b=EX+Y4ZO/I5osqiD5yjWO2hs1LTTjdeLhZwLy1PaY9d3G+uWfh5EkVoDRjeYvr/n1aQ
         QAE9dXXNENXrPOOXvGOkt8WMJcAHnBc22XNt1bnK/j1II6TTDxaMrJ/8TiBh6T2CXggf
         LTYhBN8eeXr9K2wOtxKgysNz2hpMA6o0rNTg8mcWchP7YZsSoA0CWqCI+SSUOStMlpV4
         NGIrAdMM9s0kZVX5tz51GKfGc0vKOR9kmJverug3EHaUt3gcH4Ghntt0F986uIWPX6K2
         RI9xS0ds6ofi9vVZ5uC28XYxbVY9s8K0MoZ83Z2zIsureOjcdc34rUgQrc9PpdowMaAq
         7vKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vVG2med+YFAjz0qyeXrivagrCRL7rfZUjsoIRJOxy3o=;
        fh=xgPQbWyIZfBgK/ihGq7Qb+xriLQ7Uc2S9xqMQznl84E=;
        b=TUqhcKvieWjZTUMed6sIZ6QV98Vn/z+1PQxsOaUBYltn9xuARLR8AkWMzL6fuAfMpn
         Ji9OIECNDS/gAsXMDM8b2oE52qCTu//mVXDHlbSXi9uZxPyqHYX5ZVrwZCZtUW0ZQiDP
         QlO5Gsb3zD147YsZpgsL9NmO9z8EpKukbTWGfuWcZsZsBN5GNmHshKeqOojFxiMzQOrA
         iYevsKorLfS2enGFQmV4uAG2TvAL/acC+fwE5y6grYlAfBYpQUMscUs4CduwSqcDLzdQ
         LoiKZtqEs//qDrWz/Cl1/8DH2CtNEvM1q+MJtvceGmog8mfaxI37HCT35MeuNckvrMkl
         Kp5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dQUklO7r;
       spf=pass (google.com: domain of 3brxozqykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3BrXoZQYKCUk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749512; x=1710354312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vVG2med+YFAjz0qyeXrivagrCRL7rfZUjsoIRJOxy3o=;
        b=vb0qSI9KL3BuDS87QFqV3Kz/E0vVQXVRlVZi1ybOI6tz91Yts5JA1XfB26JK3q7tfl
         GJ+mt1c/DAmYB0FVo26Q8HboEZvnXRm5b/LFlw2DgHLefPrsNHJqSYaCL/ZQdtbV64fM
         IFoYHvOkYcHMil3ckBqCUEMMKFNyeWYHL4iE01gZgFfn8gIpEwGQHrPL1cxHVHGGWEb0
         Rgpsj5PaJSVgh+V+CO/jQHO6yh+MZPpZ6pg5YzKWUZiKkzXD3O76QVtVhssiw4FZDHXB
         Dt1La9I10SWMk8YsDA+X2rTdKE1WZamqok6cP+rT3Oi+i2cIlIhN5CBJUUd5pdFN21r/
         5v+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749512; x=1710354312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vVG2med+YFAjz0qyeXrivagrCRL7rfZUjsoIRJOxy3o=;
        b=xG18gjrCZiM3cD8010wdu+oAwt0xQPaqCOLJDBG5hWexWpDBnT2VpWuxtPUpUBDwls
         orFFUVtyDOjp+MoFA2odszT6atfy2o/5MPnPo5YX+cbRtAIE3ggzitECB96uc61TKjgp
         JKxb+Dg/+1ZAd/cjjX0oUf42iuVuPZn4c80a8QJJd03ADoCftY0SR46oWBdWlPTAE07b
         EjS1TAtoQNAf4QP3JWoimlRtUb69cMGx/E7EmS46Y5Yx1s1UNpOlbiO69ajIZ6mhfRZ1
         kBIyms/4WunrAedeXjrpfrK3vL9NEVFhpjof25gWYtq4rcCvbfeE0XAcK2d69cC49Q56
         emjA==
X-Forwarded-Encrypted: i=2; AJvYcCWGs2FbAuPApWoYXfvX7GVa2Vw3GqlAGXROnvgdIf171aunmnquEf43bMdQ4qiRe1dYv9s4ZKtME1xfHinpXW4+FRytzIueOw==
X-Gm-Message-State: AOJu0YwCTLauAjEMEcUr/Ikse60GOHrB0CDyTeoTL/tsAUhetV5BbTT9
	agxj2Na2aoDAKfbV5hRaGPeM/fZa4nbibv81T3MyMIj0tr9/xiVn
X-Google-Smtp-Source: AGHT+IGovHWsgmfI7KW0Oqsgfolv0VIyc776Iu4JEcuZtfKm5A9hobJia2y0aASsL64DWNrqhxZgKw==
X-Received: by 2002:a05:622a:1d0:b0:42e:ab25:9526 with SMTP id t16-20020a05622a01d000b0042eab259526mr6443194qtw.67.1709749511892;
        Wed, 06 Mar 2024 10:25:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5907:0:b0:42e:8783:a4ea with SMTP id 7-20020ac85907000000b0042e8783a4eals77707qty.1.-pod-prod-03-us;
 Wed, 06 Mar 2024 10:25:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDsSL18FrLaY2msuavqeOLjJdms/hSWUkvb/qDlzzGrKvkv6uvKAjgFp5uJBHpBkXTU4rW/znrpX/461bU5077Z1OAjgDpW5y+HA==
X-Received: by 2002:a05:622a:1043:b0:42e:eb34:5ba5 with SMTP id f3-20020a05622a104300b0042eeb345ba5mr6388530qte.28.1709749511151;
        Wed, 06 Mar 2024 10:25:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749511; cv=none;
        d=google.com; s=arc-20160816;
        b=mMFYN9VugXlFIVreVN1ijDZRQupgvgy3gvE70D1+LaFz8c8RxJWHuy4Z166M+Luind
         JrgKkDFeSOLwH4SbgFDaGKGI/cqJeNgqA+8K8foWtqqqUWOqfaqz/VLRNF9bzxYDF01I
         0ckBqAURc/eQC2h9iPqlqeIRZpXnmzOhDxXy2bfGe7XyUUV/sus58c+ZUgh6l7UkUYpM
         bcqY2QlecVKsywBazzWQXehxuDDHBKz643mU4aHNA39QuV6k4XEY8MCEGpdO7egvivwb
         +lo6w3z86XASuT56qLsT0tczgSRE5T44ZM9axovNPVQVpBlfP/W7SvaNFN1BiYttCV3+
         kHaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UUM81FzZaYB1+q8hTjh77vdQeiiRG/JwjOPLDZjum/8=;
        fh=afALoSDg8ugemxkK7Nx3jP1oxNmYiSscLAXISWrW70c=;
        b=n/maCucsE2jvnrRXlf8THyQtU4Qq1wsQp5qAb2HLnA3yKmXCAVRlbs8Bw0VQrGRWAD
         bz0SUX2muyybSmtqu7EGxq3zM5q3eCMWRgxho9W8fgc32k4awIm5TIfgESB8phxH6ybT
         diHo1xJQWObCxAIN3UycmGV5uy5LSlRpR+52RXa4xeNQDGh7PHZTsYpj+JvPtU5s6ROs
         5nB0afZxagV6n3Wd6UGpkaWCU/nWCUzp8ZK2i0ZB8J3sw6FVJTbYrtstUr0JgB7qarAO
         CXiLg1YmZzINFoL12LskPLVt8ZnClp9W8tiJQOcvYMFLVM/oAdD3lyq3WMHnYQ9zmRUH
         TreA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dQUklO7r;
       spf=pass (google.com: domain of 3brxozqykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3BrXoZQYKCUk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id w9-20020ac87e89000000b0042efcd72c03si344708qtj.3.2024.03.06.10.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3brxozqykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc3645a6790so4022882276.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUR0cgXnvo3kgASbbg3PQVk4Tjb4R8v2d+upkB2EyDzk7+oYZjgMG+2ocijcqawRIltv+7UE4Av6IqpqGMZL9RFWSYjJuJKQtB3mA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:2492:b0:dcb:b9d7:2760 with SMTP id
 ds18-20020a056902249200b00dcbb9d72760mr4211044ybb.13.1709749510558; Wed, 06
 Mar 2024 10:25:10 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:10 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-13-surenb@google.com>
Subject: [PATCH v5 12/37] lib: prevent module unloading if memory is not freed
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
 header.i=@google.com header.s=20230601 header.b=dQUklO7r;       spf=pass
 (google.com: domain of 3brxozqykcuk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3BrXoZQYKCUk352pymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--surenb.bounces.google.com;
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
 kernel/module/main.c    | 27 +++++++++++++++++++--------
 lib/codetag.c           | 11 ++++++++---
 3 files changed, 30 insertions(+), 14 deletions(-)

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index c44f5b83f24d..bfd0ba5c4185 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -35,7 +35,7 @@ struct codetag_type_desc {
 	size_t tag_size;
 	void (*module_load)(struct codetag_type *cttype,
 			    struct codetag_module *cmod);
-	void (*module_unload)(struct codetag_type *cttype,
+	bool (*module_unload)(struct codetag_type *cttype,
 			      struct codetag_module *cmod);
 };
 
@@ -71,10 +71,10 @@ codetag_register_type(const struct codetag_type_desc *desc);
 
 #if defined(CONFIG_CODE_TAGGING) && defined(CONFIG_MODULES)
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
index bf5a4afbe4c5..41c37ad3d16e 100644
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
@@ -1230,20 +1234,27 @@ static void free_mod_mem(struct module *mod)
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
+	if (!unload_codetags)
+		pr_warn("%s: memory allocation(s) from the module still alive, cannot unload cleanly\n",
+			mod->name);
+
 	mod_sysfs_teardown(mod);
 
 	/*
@@ -1285,7 +1296,7 @@ static void free_module(struct module *mod)
 	kfree(mod->args);
 	percpu_modfree(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, unload_codetags);
 }
 
 void *__symbol_get(const char *symbol)
@@ -2298,7 +2309,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_enomem:
 	for (t--; t >= 0; t--)
-		module_memory_free(mod->mem[t].base, t);
+		module_memory_free(mod->mem[t].base, t, true);
 	return ret;
 }
 
@@ -2428,7 +2439,7 @@ static void module_deallocate(struct module *mod, struct load_info *info)
 	percpu_modfree(mod);
 	module_arch_freeing_init(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, true);
 }
 
 int __weak module_finalize(const Elf_Ehdr *hdr,
diff --git a/lib/codetag.c b/lib/codetag.c
index 54d2828eba25..408062f722ce 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -5,6 +5,7 @@
 #include <linux/module.h>
 #include <linux/seq_buf.h>
 #include <linux/slab.h>
+#include <linux/vmalloc.h>
 
 struct codetag_type {
 	struct list_head link;
@@ -206,12 +207,13 @@ void codetag_load_module(struct module *mod)
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
@@ -228,7 +230,8 @@ void codetag_unload_module(struct module *mod)
 		}
 		if (found) {
 			if (cttype->desc.module_unload)
-				cttype->desc.module_unload(cttype, cmod);
+				if (!cttype->desc.module_unload(cttype, cmod))
+					unload_ok = false;
 
 			cttype->count -= range_size(cttype, &cmod->range);
 			idr_remove(&cttype->mod_idr, mod_id);
@@ -237,6 +240,8 @@ void codetag_unload_module(struct module *mod)
 		up_write(&cttype->mod_lock);
 	}
 	mutex_unlock(&codetag_lock);
+
+	return unload_ok;
 }
 
 #else /* CONFIG_MODULES */
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-13-surenb%40google.com.
