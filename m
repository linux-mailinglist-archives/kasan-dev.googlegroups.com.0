Return-Path: <kasan-dev+bncBC7OD3FKWUERBUWE6GXQMGQEX6GQ5SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id CC4E0885DAB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:39 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1e01a5e3415sf2145185ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039058; cv=pass;
        d=google.com; s=arc-20160816;
        b=1DCG9Qvnz7RUTVF7799ZMG6ZK7Of7Zz3e9PXVZwk7KvBZ2GNOVZ5g7bmQfu/04U0nS
         KRzNIJSGU2OhDr15RKTLJV9yZaiWaM2bafYJIMUrktKAkPCVRCgoMIxrRLlR2T9WvASu
         UM8VGw8kfjtAd/ZyVKYo//LXvEQ/I+6d5sXyr4BWNSdI4Yls4fZ+UBcpuJJ+vlZtG5R/
         bINMkkFXFwRTqvNE/zsCCzXU1ifj3yH0c7x6+4ye9gCD6kJuUv+u1TwliihrtFm0hFxf
         q3k2baeqIgE/P8QOo6dObJFmCI2sFfqCQnhjF8JP5DBVDcFlQk1qeoXPdrbAgooaoR9D
         HA/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XeXgq3LGcxWIZzaOxI8hxjHf1zPWIrShUoMlbrwSiws=;
        fh=SfpL/bOAjkHmvPMZToyZiW330WodZFje/SOr6oSdEPM=;
        b=UaWMMNpsmDO3h1T/JEGvnrIh18aNBtLfpIf0N8cGl7eexOO2/QNcPRf2WXtfW6Rv4j
         HX4/cJ55kQf2WeDBI7PoC4EuRc+94gKvK7BWiNw3i745/WACZdrX/MTDZk7d9gParSnN
         Lv7rH/6pFqcaVmdH+3n9+eOrrZDe6TwHF0KBasA7CPTk9IqXME4BpriD0aZ6NRQVrMjJ
         TBNLGKY67QPEY4ZAYEkL1nWrSJpF+WQvGbKGMmb2w1gGRYunY+klTBjSoi43dClGhZ5G
         CvNbKXHp2w2hhw8Twr8jA4udroWzK4uVIliKbw/BQ2CJTs7+4PIbNriZk3hLQafW83PN
         WeLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SeJpGbtO;
       spf=pass (google.com: domain of 3t2l8zqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3T2L8ZQYKCTwqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039058; x=1711643858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XeXgq3LGcxWIZzaOxI8hxjHf1zPWIrShUoMlbrwSiws=;
        b=mXYkZ86+oDCRyxXkfMU95uLYm4Tv/i2zTrbnHSF5f4kClkBRVogu2WGgjCOfNPRjlC
         4mCiX6BBoQAlR6n9kd/OJMG2PyKfLU9YUf8DjROtv0hjWSXnaKkYLRGR0usln77IDrrW
         AGYeRjcbVlKmJRWtgT16hadmHmAAFJJcRQY8iMIXjYNpaz+J3sttzmVvVshYOHg95635
         tYPkRC9HSF1LAFwMBYAQqvCBk+hdu6eDr1AycRdFZ2ZpMCbRLMzTJeRyX/8G1Yo59LK8
         3d5XUeRNptTVvkAXWoI7IYTAQUPvDfGOZxVipEPEVP8OF+0niX79Gjzrvdpt+MNeIBGu
         4u7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039058; x=1711643858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XeXgq3LGcxWIZzaOxI8hxjHf1zPWIrShUoMlbrwSiws=;
        b=SgM6l4c4YnWI5crCP0XGI6+aQapNC51AILtJxELtGTV32xbIly6Am98Xcn6qoARQXi
         C5IHSrLWudQ3Hz2WcQ2puCY1mtIdcXZpdxXhvXcTY8ZiMX/ZPF6hB+aIM9bW9JwyOgUF
         fzAz+jPQKROmgwPBSOc5UxxS+raxmoh2X82ceDTBeah25+CBr2VT4OrUxDBcHvlIN9l4
         0qFtX0Wqmu4q6G+W6gXO7AW6RarEgl4jA8J/7zgSFPtGiW8TuynLdPIKAhnN0ekbNtVV
         +ITBjkocKKM5kCRajKjQFpaqiiKqg3A8E+f2wG0o4RonldYGWKPgHKoDjeq7F6Be2vH9
         zbIQ==
X-Forwarded-Encrypted: i=2; AJvYcCUzWgvMn3tah4hRbI3gac//YhRLXQEoHLV+x3NJo/GAOtnzCGTwlkyjCrZnuRndcKGirvjJB1PAN+2KpqvP9GZSEeJSNPHnyQ==
X-Gm-Message-State: AOJu0YwcXZTL/9TzhY6A2VPQbxIHklbgHHTq/06B/6YHacDJkg8lYTDo
	9ajInR3GyoGPXCMt2rl/ftwj5HclnsjhGCm8HxE6+Ss135vrSDC3
X-Google-Smtp-Source: AGHT+IFD5BkenOCOlE+5Cg5CLgooMKPUXCmlTcbnyzzRrJQypiGKUo30xCcxtFQ029QvUyHGbeJfeQ==
X-Received: by 2002:a17:902:ec8b:b0:1de:fdbd:930d with SMTP id x11-20020a170902ec8b00b001defdbd930dmr292835plg.16.1711039058227;
        Thu, 21 Mar 2024 09:37:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2449:b0:1dd:ae61:6793 with SMTP id
 l9-20020a170903244900b001ddae616793ls856503pls.1.-pod-prod-04-us; Thu, 21 Mar
 2024 09:37:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9H2/61ZRqN1cW8fBD0JEcJ9r38djrbIahKXI2yKllN0ToWJZ+8/TgukIfCrmKYTa5DRQdtz2lPDymB5uHl3jD14hvVBc+weXeQg==
X-Received: by 2002:a05:6a21:9994:b0:1a3:3064:9931 with SMTP id ve20-20020a056a21999400b001a330649931mr53837pzb.3.1711039056948;
        Thu, 21 Mar 2024 09:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039056; cv=none;
        d=google.com; s=arc-20160816;
        b=Bp3Q1EvQsBVgf/N8QU/oUKP/DMtOKTFPv+V6uJG1ablSwJV8tu04liDhqbX8XzIL7r
         fWfHOsDUE87DISA8b670ljwZhg4VnxBxuO9OBudEEBNrGVLvzPY+FAjH269Utm3cKQfx
         iJaRZ/IlBKLm/50LNHYeQvO/NPBl2Jdt8ceD6eH8FRRYYnQs2DB2Fo3Mi9uF3ARfT99F
         yJkRcSiFhzSO+F8uOszQMsfYCQdDYmtc2/qyD2Y4PYm9gMzqMLkKulQQsCfhvAtYXr6u
         eS9KRL1IACYOvERlwdjUeSimKSpDlr86VrGtcgcB0FGdakfP13OdtP1uEKqw+u5wD6aS
         NL7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=LQ90PfNulEINqNY+MaQbbDhVRZQhbHdS/nw/zX5Mh3o=;
        fh=co26FYxDjNa/K2ZVwOBJHRlh8yI4TFyLYsQrwuKmxoI=;
        b=RyjteeOBzTQkWuV5cQIkNGvGBspdfsk6PQvcgpbwzk/Q3pcFXaq6CDH2mGyhES5YNS
         grSfZAA+T4qJjiBhApv82DDcS5BjBZawEvqi67yPM2AcjTMCVPhEkoL6wN9jMpPSJkOX
         eVXynYmTrPmQj3JoDWHXLuUFOSDVcMCSEXKObY7ecELifCU8JhPboVIUJ8OACcKezMr9
         6yd86bVCIDnE6sLrYYSOV2XR8y/Lk1T9eMhnhLBhI13TUI0FHUEi/FgIdIqddsGuOKzM
         DohKnCYlUgxgYoYmNIxAqGk1hht/xxhVUNdI0OnbBfBSoL5qBxuJGz0GxgQ9TS84CJzs
         M4EA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SeJpGbtO;
       spf=pass (google.com: domain of 3t2l8zqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3T2L8ZQYKCTwqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id s6-20020a17090aad8600b0029fe3bdb545si212876pjq.0.2024.03.21.09.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t2l8zqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6ceade361so2069796276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWbIO2t+vBaZey1kTq4L6d+R5mL8ex58L4z+RlCRaOS0ZE2CZpsRHP77aVhlUkVbDs52rnMEvDZgvNgi5W0oxcu21J7FPjt7Z+57A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1144:b0:dcb:abcc:62be with SMTP id
 p4-20020a056902114400b00dcbabcc62bemr5818428ybu.6.1711039055775; Thu, 21 Mar
 2024 09:37:35 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:34 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-13-surenb@google.com>
Subject: [PATCH v6 12/37] lib: prevent module unloading if memory is not freed
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
 header.i=@google.com header.s=20230601 header.b=SeJpGbtO;       spf=pass
 (google.com: domain of 3t2l8zqykctwqspclzemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3T2L8ZQYKCTwqspclZemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com;
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
index ffa6b3e9cb43..2d25eebc549d 100644
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-13-surenb%40google.com.
