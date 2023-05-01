Return-Path: <kasan-dev+bncBC7OD3FKWUERBDO6X6RAMGQEQNYMJLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D1DA06F33D6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:42 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id 71dfb90a1353d-4438185eb52sf469166e0c.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960142; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1ee3RQT/ghNn3NJaeLnH/fwjHrgIrj7qWQvp0xA8l3q9Efb6w+fPlAh9ESNNhZWhR
         6d9+fEKe0SyOm6LMKauGodlK9+9/970klz+OZISGQ4vhpNUN3v3IMYdacrL5zzzk8KUR
         HG/YvvjPRLIPuFXiHt3z9DEaYQWBzB7LwNzMZxT7kieeeooronQVt+98z2kLrgzjTJyd
         OdmPxoE7aKxzY7nuOLMwdlqbHGVw5I5XWP2krI20zI34K1NLuyAe9IDr+E5ZO5eG8kRl
         lr0AIaZFmmEZ/npNwQMvV3xzsr4a+PLYSjm1h/zV3FMlO6MzhA7BhqFrIrCz4TIyr2g9
         Tgtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6+6dg9XE6AGNvzbj3bKfBZ+0Xq0DN91r3g1rv0p6AIE=;
        b=KorNaIvnwHyAM7CyN2TyYfbGdVmoamrbQTYN73zoI2KVyF2oTmD+TUjIAdukLc1KGA
         +RzhL0rlZvnlPqu18dpeIiIAs4nnjk/KSpszQTcOsukgOFfYt4MgLPorVyVuuivAsMlm
         ZDHLCy98ywLxOK5o+93Lxxe3ueENJVORZhvAIFzry4UKwt0apDoUB1/HiZ+hmohxDhld
         +fxcxJpjuofe2gYTXoXuKBhFfy/wxmw15djgyk4bxv6l0AQtfq+C8+/TF2elLZb6GJ/x
         Prl/WK+CP528Gd6kOLeWLvmYwBNyEEwl3/Z9al5CJQ70B5RcTs3I8dTuI+O+oDl6WRQs
         dMtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=XugZDvU8;
       spf=pass (google.com: domain of 3do9pzaykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3DO9PZAYKCVMDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960142; x=1685552142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6+6dg9XE6AGNvzbj3bKfBZ+0Xq0DN91r3g1rv0p6AIE=;
        b=sf4n0NSGh7BnrmCqv1CfwUeLw6v1nMc/dDMKTD9nstS+J90djpQJe923oit+CLoZTl
         jZiS0JOHtLTOn6StGeGK+cXuGtRLMkc2q0NpQkLZ/3DluJ2QvwpwUoo2V/YXsKjosR2W
         xzCwutQlH8yAflDOG25GvmrJ3apAsh2bUDTz0oIlpowuIBZrAQRk/Y4dqPhdK/SeRTKk
         UxTMCqsBEFZLrkYzAr9FiPcxURlOkY1mngxp2l7+Lzu30SjAD022TCQiEVqoo5Cm/h39
         xgWMj17yM1ndKiMWAGofGG5kHlbCm2oBTFR6fVq9gAtPq69u2OUES29yAEPobc1S9uBj
         D8hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960142; x=1685552142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6+6dg9XE6AGNvzbj3bKfBZ+0Xq0DN91r3g1rv0p6AIE=;
        b=YuYu1zYKQFW4r4XauCcTfHI5Iv/as9UAQ/LWQoLdz3GFkHkYVbWsrZ8k+NOWMi00O1
         7hkraNoMiAxfJ2ocrScVT5CyUwLme/xb8NdKH7y8teqzXXcSBhI5yBndWXgww8IM60hZ
         QwJ8u7oIH+WjC4neBGo5MAu/4c3PWFOzbLmSQL2nNV2MBVRMhcd7wiPaD83vkElg1BIm
         BoYJRAwL1qYK7BjiVGgSN+3f6V7tw2vMpzaDmByz1nehz5Br+JXjkeQKab2UGuF/KH72
         nGRaSuvyMBQDktEnZT35VHY7OQfUScLh9rKUz4pEwCwYohPz+u9taU8wXc8hw63GoGa5
         hcOQ==
X-Gm-Message-State: AC+VfDxPbg9MX73SApK6wURIu7fka41gBNqD2y2pKfHdJEJ0klyTC/ES
	MUaJHbZaNE1TlKm81vytaZQ=
X-Google-Smtp-Source: ACHHUZ4CH/olTj6aWlfXrAhv06hfjAmCvjo1bTB1EVfJ57PQckg4S7Zndwtv2NZeUTl7uK+SHptXzA==
X-Received: by 2002:a1f:a00c:0:b0:446:d60a:c150 with SMTP id j12-20020a1fa00c000000b00446d60ac150mr6411640vke.0.1682960141735;
        Mon, 01 May 2023 09:55:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:1685:b0:443:bd55:5e0c with SMTP id
 5-20020a056122168500b00443bd555e0cls1223676vkl.0.-pod-prod-gmail; Mon, 01 May
 2023 09:55:41 -0700 (PDT)
X-Received: by 2002:a1f:6419:0:b0:443:b924:da82 with SMTP id y25-20020a1f6419000000b00443b924da82mr6474347vkb.2.1682960141093;
        Mon, 01 May 2023 09:55:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960141; cv=none;
        d=google.com; s=arc-20160816;
        b=z0i6szFKnLTaZ4s1cSWNwpXk5meRuzMp0LM5ACXKmPWjG/KRSS1Nom6IUT4Eq5RZ5M
         AZBeYwifsc07cmr0mfzWKmWUBUFnxY0UT0gIAEmyk9ifLlw/UYCQUGTYg2ETFcdGS0es
         H9cs6B21GzQuqFsiPIZfSBY8oBTdnZx4iwIGCBNQy5vz0GF/tzSjyJTgFb727g7lHOEw
         g5ElA3coK1m0tk6D1kW2xUt+AKllB40zcMrkMkE4iGCupkaJwEvJvlq/C2EKsrtfLL5S
         0c3wDWtTkTUuw2artAzCfVb7Pta3MA2grfW9wy+tch2kzco8r/UQmZhe7VECBZPW5hhj
         doZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Fsyg89/vfc29JJa9GS5YhCGnLnEPc8LoOfUR2xEk3nU=;
        b=mSWtztTBR4ujFyLaas1rW5bup4Z+8YyWn5effIelR6rvgYNK5mZn8faOHYgy3f05XK
         dEvUeqJOxkXsX5dQmQSnzz+SOmJE8x1dO+vvJfhBnIrB8lvGVcri7YE5ihMJEBfkHfwS
         OLYXly1QYEb5cRe8Zb9t6SKmqKUifRE260Xh48cNp6qLZFWWjYw1WmWy504ADeY/WP9l
         U5pxXSC6AhA61VqOg+7WlXXgWVA2vlBEDkCDBU7TujveAdTxyL5hAVMR0HlzU0x3TSHE
         d27009Fl5MqDugJwniPB1RlPlJg1392XmnOz/DBw59B8AOLNsgF85VcAaldJnauTlHUV
         JqgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=XugZDvU8;
       spf=pass (google.com: domain of 3do9pzaykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3DO9PZAYKCVMDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id bc35-20020a0561220da300b004409ac628a3si23668vkb.5.2023.05.01.09.55.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3do9pzaykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a6eeea78cso27814351276.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:41 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:8087:0:b0:b8b:f5fb:598d with SMTP id
 n7-20020a258087000000b00b8bf5fb598dmr8714623ybk.6.1682960140703; Mon, 01 May
 2023 09:55:40 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:24 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-15-surenb@google.com>
Subject: [PATCH 14/40] lib: code tagging module support
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
 header.i=@google.com header.s=20221208 header.b=XugZDvU8;       spf=pass
 (google.com: domain of 3do9pzaykcvmdfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3DO9PZAYKCVMDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
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

Add support for code tagging from dynamically loaded modules.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/codetag.h | 12 +++++++++
 kernel/module/main.c    |  4 +++
 lib/codetag.c           | 58 +++++++++++++++++++++++++++++++++++++++--
 3 files changed, 72 insertions(+), 2 deletions(-)

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index a9d7adecc2a5..386733e89b31 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -42,6 +42,10 @@ struct codetag_module {
 struct codetag_type_desc {
 	const char *section;
 	size_t tag_size;
+	void (*module_load)(struct codetag_type *cttype,
+			    struct codetag_module *cmod);
+	void (*module_unload)(struct codetag_type *cttype,
+			      struct codetag_module *cmod);
 };
 
 struct codetag_iterator {
@@ -68,4 +72,12 @@ void codetag_to_text(struct seq_buf *out, struct codetag *ct);
 struct codetag_type *
 codetag_register_type(const struct codetag_type_desc *desc);
 
+#ifdef CONFIG_CODE_TAGGING
+void codetag_load_module(struct module *mod);
+void codetag_unload_module(struct module *mod);
+#else
+static inline void codetag_load_module(struct module *mod) {}
+static inline void codetag_unload_module(struct module *mod) {}
+#endif
+
 #endif /* _LINUX_CODETAG_H */
diff --git a/kernel/module/main.c b/kernel/module/main.c
index 044aa2c9e3cb..4232e7bff549 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -56,6 +56,7 @@
 #include <linux/dynamic_debug.h>
 #include <linux/audit.h>
 #include <linux/cfi.h>
+#include <linux/codetag.h>
 #include <linux/debugfs.h>
 #include <uapi/linux/module.h>
 #include "internal.h"
@@ -1249,6 +1250,7 @@ static void free_module(struct module *mod)
 {
 	trace_module_free(mod);
 
+	codetag_unload_module(mod);
 	mod_sysfs_teardown(mod);
 
 	/*
@@ -2974,6 +2976,8 @@ static int load_module(struct load_info *info, const char __user *uargs,
 	/* Get rid of temporary copy. */
 	free_copy(info, flags);
 
+	codetag_load_module(mod);
+
 	/* Done! */
 	trace_module_load(mod);
 
diff --git a/lib/codetag.c b/lib/codetag.c
index 7708f8388e55..4ea57fb37346 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -108,15 +108,20 @@ static inline size_t range_size(const struct codetag_type *cttype,
 static void *get_symbol(struct module *mod, const char *prefix, const char *name)
 {
 	char buf[64];
+	void *ret;
 	int res;
 
 	res = snprintf(buf, sizeof(buf), "%s%s", prefix, name);
 	if (WARN_ON(res < 1 || res > sizeof(buf)))
 		return NULL;
 
-	return mod ?
+	preempt_disable();
+	ret = mod ?
 		(void *)find_kallsyms_symbol_value(mod, buf) :
 		(void *)kallsyms_lookup_name(buf);
+	preempt_enable();
+
+	return ret;
 }
 
 static struct codetag_range get_section_range(struct module *mod,
@@ -157,8 +162,11 @@ static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
 
 	down_write(&cttype->mod_lock);
 	err = idr_alloc(&cttype->mod_idr, cmod, 0, 0, GFP_KERNEL);
-	if (err >= 0)
+	if (err >= 0) {
 		cttype->count += range_size(cttype, &range);
+		if (cttype->desc.module_load)
+			cttype->desc.module_load(cttype, cmod);
+	}
 	up_write(&cttype->mod_lock);
 
 	if (err < 0) {
@@ -197,3 +205,49 @@ codetag_register_type(const struct codetag_type_desc *desc)
 
 	return cttype;
 }
+
+void codetag_load_module(struct module *mod)
+{
+	struct codetag_type *cttype;
+
+	if (!mod)
+		return;
+
+	mutex_lock(&codetag_lock);
+	list_for_each_entry(cttype, &codetag_types, link)
+		codetag_module_init(cttype, mod);
+	mutex_unlock(&codetag_lock);
+}
+
+void codetag_unload_module(struct module *mod)
+{
+	struct codetag_type *cttype;
+
+	if (!mod)
+		return;
+
+	mutex_lock(&codetag_lock);
+	list_for_each_entry(cttype, &codetag_types, link) {
+		struct codetag_module *found = NULL;
+		struct codetag_module *cmod;
+		unsigned long mod_id, tmp;
+
+		down_write(&cttype->mod_lock);
+		idr_for_each_entry_ul(&cttype->mod_idr, cmod, tmp, mod_id) {
+			if (cmod->mod && cmod->mod == mod) {
+				found = cmod;
+				break;
+			}
+		}
+		if (found) {
+			if (cttype->desc.module_unload)
+				cttype->desc.module_unload(cttype, cmod);
+
+			cttype->count -= range_size(cttype, &cmod->range);
+			idr_remove(&cttype->mod_idr, mod_id);
+			kfree(cmod);
+		}
+		up_write(&cttype->mod_lock);
+	}
+	mutex_unlock(&codetag_lock);
+}
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-15-surenb%40google.com.
