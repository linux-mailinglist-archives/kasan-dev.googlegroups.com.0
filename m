Return-Path: <kasan-dev+bncBC7OD3FKWUERBD66X6RAMGQEYM57F2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E8E576F33D7
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:44 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6a5f602a905sf1812966a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960144; cv=pass;
        d=google.com; s=arc-20160816;
        b=zlB9e+2WfSwsd5wMAoixTtTs2b9Eduj2DJHq/BepzuKRSwn+tKzWEZMDcfFt/O0WpG
         mLyBi8QYeugGz9BYqPwxlznwufHGmJD6hiGrLrLstdZAgxasPsnMFMAOPOoxlzpXelxE
         FfZsINJw8N//t1fIourXowCcqi84doloZkrNPsGULk4vQcLISls2hHHokuOpWCWEE5tr
         oCpnmhiCmGOAfcJY7/bhhqZnCrCp4jbNoHT1dHRpLE6wzjWGQPFmiwCkLyHMscT3A8Ca
         W4QC4PzAdWB0XnLxHAfGTJySLGZU46pQDzHa46ofSaZqUQzokIbGZ7fVQbDFswla8HZP
         hTdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=S8sfoEAVVIw0dfUqt0/+w8XwHPyS7IUXSg/LB12KrRY=;
        b=sYNn7w9ZgMTNLpdJXLD/EWfNLVv8Wa4c/g8bKonpQoZT4V7Chpuvqt23mRdP+98dzf
         xo9H4976glthH2utPq/og4QishSQBdziLybId99LDzfKNGD55sRMPVmyYHsoyOjulkSI
         CCAIYah+LNmvgN1hBW8nPM5ucRJQ/jwxbgj4F6Y/+mCi+qI2PoSyK/tUFrK1VEm1iMKV
         VBW1OcelwKqKKFTH7avINJuw7/LXkdJe7jPdiqXyJliK6EzOm4HAsvI+CYtE52T4uUPx
         1JxFFOtNdMiAYucEBeUkTJZEQIUj0JmKEm3+YaPj3Ry4o+mrBoGsZ8LpdFG0c2MdfTKp
         l2vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QWt5E67j;
       spf=pass (google.com: domain of 3du9pzaykcvufhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Du9PZAYKCVUFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960144; x=1685552144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=S8sfoEAVVIw0dfUqt0/+w8XwHPyS7IUXSg/LB12KrRY=;
        b=Uf+yJcrzPH9Ei2Jo5hL1cmcEEeorz1xU2x+IUldArdU8e4xSEhjoq9rLQrd0a5uom9
         Rqyko5Kfe162OGkLRicg92J47yRfX0A9p+0ZQLvM35upsWoefZxP1YyZEWOkB0hIQtkz
         iueBTweZRJVYszzxsEzH6TzQ9Ym3m7f1IpD4pUvn64Mh3BqKCavdIVJ41g0QSf7cLqVE
         SMFNUj43VNERta2vrAS1uu0XCOaX4BonOg8IrXhkzUAmGw7Occ7qCIVVmoMWbFME/+5A
         +Hyi96MKJOiVlHLHXAKpBm8EpEAorX+qmdzP7bagROk7VhigyONGJlHQLzHE78SVNzhZ
         J7vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960144; x=1685552144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S8sfoEAVVIw0dfUqt0/+w8XwHPyS7IUXSg/LB12KrRY=;
        b=EOGHwFdvcZfPmqzm3mXlIN9GOQO3at3g6nJBgeX7MqQq1I9QvdThy3uHsxvtdm+nHk
         QWMb47QTMAmcn9zRPXH4LyIXUOvt+bArDcaeegF3YQFi/XgeTRJsRalzCbg51QDqgX3d
         0iPeRbh09GwOzGAxE+0HmQlODmaNg1DplZ7McPHcQsT8ZOyJnEKr90oUYL348QW9x4qe
         EXueF4/wqO2By+U7fQw1qEMrjRqKXoeuGN2HbpivAO5wcjdLHS+3wYJ+UpdL4FH6uZ9D
         jqkflEill5p7+eE3nAwQUcdq4bp1BQVbVh67CPtM3hTioYoYZC4M8R6DasuKs5CcbIQF
         atnw==
X-Gm-Message-State: AC+VfDw5JdsyLikPI72VDP2ihswS3KJr3droFil7AeR/a1pLWYBolcp/
	+Yj7K6U3Yz86PTF9mGBGpUc=
X-Google-Smtp-Source: ACHHUZ6gtowcTpsL8bb6mmzNRSr6USB2pctV6f8LJlXu54k9NhakI45dIOasx5G0P/TngdOMoCmLgQ==
X-Received: by 2002:a9d:4b03:0:b0:69f:8e17:ea19 with SMTP id q3-20020a9d4b03000000b0069f8e17ea19mr3635829otf.1.1682960143828;
        Mon, 01 May 2023 09:55:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4410:b0:18e:160d:c077 with SMTP id
 nd16-20020a056871441000b0018e160dc077ls3330762oab.4.-pod-prod-gmail; Mon, 01
 May 2023 09:55:43 -0700 (PDT)
X-Received: by 2002:a05:6870:c7a8:b0:18b:1ce6:bbb8 with SMTP id dy40-20020a056870c7a800b0018b1ce6bbb8mr7466184oab.22.1682960143373;
        Mon, 01 May 2023 09:55:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960143; cv=none;
        d=google.com; s=arc-20160816;
        b=vgt/isCo4L/QaEmes4VEWA/W3/jkixvtVh2Qc5lfdXGqXDkFYjgv/DQmxsgKrw1LAv
         5Etl4jxUVm3Bb1u2n7B2FSw0ezWnZafl5qIa2BO42Ble6j/CI3drO6Rnw+cXhhs0W7XK
         ylg2OiVpVoGwKMV/V0GJwGeK1m2+JkRqQXt4ixzfBWA1YOokmFiChNiU1ooKc7gkplET
         FYe41ETnHuCtZE+8tsxofs6lIHYWhnj2XT2zPo4H4DXyOTE8CyRnvx6mexJxSx4YFMEo
         8Z1XuPZ/DSzeGUW/msgl6b37hAjhE4oOlcHtBNBoShyQLhg6oQZSxnzIQBNR2khdrJTR
         sxrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KlR34XlXux9ljlJXPX99aK4k/cmOetFB9Q46atx2T7Y=;
        b=WKJCvfuQG1yk66gYMlFpIzE+yLIAsXKNg7+YcPQeUlk21lRL6kHhy7l+6ZA15e2/xy
         +CYGUMbgMo5QAhl9GzJzRUO20p0ekKGUVbeiMFsXqfb7ndWrDT99bbBLrBV7ThLlWHWW
         Zpv2VnyWNVXyZ8twE5EU05CCPpVxpbGh+oGKUGnzCnNrSOCy7XQkMX9AKqi0Xn2Pi5oH
         SQFxqOwGpQjA5iZPn5A46MAl2M5yIKZuIwrbP1v+oq8GHOVxnSsyVI3yKrk2E1/CfSZu
         xOjutmxNB/G867kUXvqeWcFCM+xNAtsikL/KAolr4oRPCVKt4WlOWIUiR4CRCzzRC1L6
         esqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QWt5E67j;
       spf=pass (google.com: domain of 3du9pzaykcvufhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Du9PZAYKCVUFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id pv16-20020a0568709d9000b00180bebe4961si2389104oab.3.2023.05.01.09.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3du9pzaykcvufhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-552f2f940edso53193627b3.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:43 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:b3c8:0:b0:559:e792:4e87 with SMTP id
 r191-20020a81b3c8000000b00559e7924e87mr4661945ywh.7.1682960142770; Mon, 01
 May 2023 09:55:42 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:25 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-16-surenb@google.com>
Subject: [PATCH 15/40] lib: prevent module unloading if memory is not freed
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
 header.i=@google.com header.s=20221208 header.b=QWt5E67j;       spf=pass
 (google.com: domain of 3du9pzaykcvufhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Du9PZAYKCVUFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
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
index 4232e7bff549..9ff56f2bb09d 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -1218,15 +1218,19 @@ static void *module_memory_alloc(unsigned int size, enum mod_mem_type type)
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
@@ -1237,20 +1241,23 @@ static void free_mod_mem(struct module *mod)
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
@@ -1292,7 +1299,7 @@ static void free_module(struct module *mod)
 	kfree(mod->args);
 	percpu_modfree(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, unload_codetags);
 }
 
 void *__symbol_get(const char *symbol)
@@ -2294,7 +2301,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_enomem:
 	for (t--; t >= 0; t--)
-		module_memory_free(mod->mem[t].base, t);
+		module_memory_free(mod->mem[t].base, t, true);
 	return ret;
 }
 
@@ -2424,7 +2431,7 @@ static void module_deallocate(struct module *mod, struct load_info *info)
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
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-16-surenb%40google.com.
