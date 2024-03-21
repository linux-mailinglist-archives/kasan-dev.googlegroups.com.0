Return-Path: <kasan-dev+bncBC7OD3FKWUERBT6E6GXQMGQE3NZSTDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B033B885DA9
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:36 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-7cbf2ff0e33sf115917439f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039055; cv=pass;
        d=google.com; s=arc-20160816;
        b=oEwtYvfB2qtjw0xBTtziW3s1M0f6eRpoj7LpupF/fBzPEdrSlC376iXo0ra881CpLo
         5CeldO4pLv58BKZHPXKvsLjCyz97sHf3BI2nMud8ADltEfIdB8ha1dMDbYJDB8NmBUK3
         Pjgbx+xXx4pjH8sK/0q4uoqSpDpfT+0EKdwYI32c7AOqTUWoHv7Wa1O/qnvGboorQnqZ
         Hqy8oluqfrHym2lHsFl1YDJhCVJcI5Er/ZH2wl5hmFbtxvH/dQhH2jyod9Yg+IcPhgZY
         wnQWGTwGgEE3MO6yUJ/xt3ACR7xD9bz5w9/mHVGJ/pYn5IFJOt7j6W9iMKlAZQ1BO1T1
         nOeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Vq4xDfAo4A2n7CBpnLi2+6hBSKZw94R6HlDbTZPoWkU=;
        fh=j+nj8y52wFB+n75murwYnzgJzYBFH8cdnc926y8oQ6o=;
        b=W0KjSuOakBcC2+PMUApxyQtqIXZK1uf3DKIOCrj53T07PmJpiT3p5rMZa8F3jFQkPF
         Xtxs+ahz3pm4b4Rs1J9xseuUdIwoGuaCYU0CtnvLbNfMtdr0/u4cdC0hfM39B/orioWb
         eCEztPFwVg6T7DN1a/wRxzDlpVDP14MzBBRTdkwqu1py5g4CGSL4tpO4v+CrclVhp5/z
         lBXu/jGuK5VjqlpY5aA/L5QIRN4imeO0CH+QS4vOVQBtWSNEtNDgd+d6J/9myT9WVOW8
         X9IYuaBKQUpd2dITnbZ39u1nHj+FDfPxWmYIbQhkabEnh359Kxf/aGzvlKyQqrlezxr+
         U02g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=e6oS4AbO;
       spf=pass (google.com: domain of 3twl8zqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3TWL8ZQYKCTooqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039055; x=1711643855; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Vq4xDfAo4A2n7CBpnLi2+6hBSKZw94R6HlDbTZPoWkU=;
        b=TqF4TxIsfofa7X8x7e7yxvOQ2VEOBRi4/SRKbUDvSj/7S+HMttklXtV+J5+02J3qbo
         A6LoT8juD8XifpcHmcrdxVfjbH6JUPgIFHa6OvSF4SXQgz/VuzLBr5QCplPllltKVtCB
         er57W6jdlEzmeuXl68dhQcrfNCTRaL7f4Bs/kRXKI5ZuIZignYcxp/RBo8DAVj5I9Jtq
         x3tycWRy34XdWrOpP2PvmYI6NdYhScAk9VML05U96jGrB2/N3vP6t5Yujn3YNUV90GgY
         xjXOr8FI6V8NiZATr47mvyQgEs7DinXolguSXHLvRphLaOm/urzhMTsRhOP6+ZIqqu6N
         nH8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039055; x=1711643855;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Vq4xDfAo4A2n7CBpnLi2+6hBSKZw94R6HlDbTZPoWkU=;
        b=CSqgREzBwFovt+yOlOt6/Xl38sgmazfI+omfUSaIGaqGwV4JHlvYLtqsAtzVtSa5s2
         8KSQVYPz/xRrHjKvf5VYi3g4lIimcxjDumTPHW37YsQh/zG3D5VV3xY/j4ntze9nHoB/
         bJNR4eLgILEiIqiPbkT4EJAbAzdv/6dNnhRrUvEpfyHx7dhOQ0+bmOgrfzvWw6UwCs6S
         G7Vyycikm1NDnl3gdpiSB8GBDVfwg8HWHPR3TdnVYgyp5Y5VxtRviSXf4vkQhysvLGbq
         n84v9aabvnJ99iU6A1Uf4qbYRSlvUgw8ciPexVXa1AOI8TIMlGwMoVU6s9ZfGPx81pGD
         rSxw==
X-Forwarded-Encrypted: i=2; AJvYcCUdk8W6wNnf77/gWSCFdoDy9RTZOrCSu17ja0Mmb2Pby5CsvqwitHjKd+8sSPwpn23Fc1t7oUUEi3FS1ieraXYRboKvIhUZjQ==
X-Gm-Message-State: AOJu0YyMyCVQjOC7Z8M7KIqgN2RPFXzXszCyLnlg5HDyg42qPZE35vHW
	m9ymXj+Un7r8N0wICqbIsdofz/tJNaIcij6KPitwwdE4XogUFL71
X-Google-Smtp-Source: AGHT+IEYkRQ9pb90EFly9vsgQWEuA9u/BZqKBVxF0imdCUdai8th2LlhzEnQvajQPjekTYsBikvSmg==
X-Received: by 2002:a92:dc8f:0:b0:365:c6ae:c40e with SMTP id c15-20020a92dc8f000000b00365c6aec40emr100283iln.0.1711039055563;
        Thu, 21 Mar 2024 09:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a0a:b0:368:589a:3ea0 with SMTP id
 s10-20020a056e021a0a00b00368589a3ea0ls574253ild.1.-pod-prod-04-us; Thu, 21
 Mar 2024 09:37:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNZUdgc7aVg5Zv5QQrKZTRNNtYW3I+GFQNV1xDbY4pZRArknLrxKyN+vKJnMkqUxqdgr7B2vDks5Eez7G3gZ6IXatDsx0h2FVmLA==
X-Received: by 2002:a05:6e02:792:b0:368:5ecf:30bb with SMTP id q18-20020a056e02079200b003685ecf30bbmr37896ils.17.1711039054346;
        Thu, 21 Mar 2024 09:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039054; cv=none;
        d=google.com; s=arc-20160816;
        b=qocyr/myyMUErDUOA0rkuWqLc97MGqWlgrdpgJt3GklrLZJbC8hfolJ/v2FdWjrKOQ
         w6ClUhCncdYrLBcFyF/UE2OaCkgS3Ukz71USRkGTX/9z3kWObVddgAEqNHzlJ88C3RhW
         wX/0NzTYDRreEglcjnRLn7XcbL0hKBg6SF5xUHPWUMPlWPnDVQC5wsREm+wFkI9GWlAf
         i7vYUww0DHoJxTVCzxKJXlBgvzIKWnM0nk1ggMxxnKMzlYKrp2nBlPN68PSaFWj/jJp0
         fx9WtMM0sgVwytBmbWnqj3oXVAhUyXAUW4YZUfHwlmT3tJTTb9oDma5sjdt82kpfXuS8
         jcsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BO7qlg8CrJrpGAZLx2tB5/z68XAeLcOjL+jbqSm1NrE=;
        fh=DXF0DkOoJ76JBB5XBU+3wqzgMA2aVzScq3uPBFZyg2E=;
        b=0Tss3ucXRMMm7JG4geTuQid4j5ua9XUMGROpYh+KAa4iStlLgSY6niZ4TXmVmKYvc3
         kf9WLeiIwflzgVzOFxbzyBYajyw/Ie0Z4+goubIGKBxUh5yizjs6OWcz7xn59gR1WvvP
         I+DZ8Q6HetYhca9qKV+XIdbzRWWxo1EjmcOtfhxa/BbuP3WEfnMx6HCKUv3bmYZjntgg
         RIf0MgBTmzluLD7/UskkXK4Koyju4afZIVy7D+2fWg3/czFGSWOP8wYH0G1FwQiE/UbS
         k6SSsliohplEIZowmZv6iTKnf7t2B2F34iHekg+2b4lpHV4QR/xWU8N+C0F/4mGq91OG
         0VRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=e6oS4AbO;
       spf=pass (google.com: domain of 3twl8zqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3TWL8ZQYKCTooqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id x6-20020a056e020f0600b00365e9e3139fsi8672ilj.2.2024.03.21.09.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3twl8zqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-608ad239f8fso18736557b3.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXo67mmapWzVK/FqIjXFjtDlJnflsieFDuXotU7jZqmIoSmZIcxyBypiP7/2dZ7VIYNu4BZJQa96cdsht/tAIR87080+v9a0A/eCQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:2681:b0:dcb:bc80:8333 with SMTP id
 dx1-20020a056902268100b00dcbbc808333mr5470245ybb.13.1711039053606; Thu, 21
 Mar 2024 09:37:33 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:33 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-12-surenb@google.com>
Subject: [PATCH v6 11/37] lib: code tagging module support
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
 header.i=@google.com header.s=20230601 header.b=e6oS4AbO;       spf=pass
 (google.com: domain of 3twl8zqykctooqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3TWL8ZQYKCTooqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
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
index 7734269cdb63..c44f5b83f24d 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -33,6 +33,10 @@ union codetag_ref {
 struct codetag_type_desc {
 	const char *section;
 	size_t tag_size;
+	void (*module_load)(struct codetag_type *cttype,
+			    struct codetag_module *cmod);
+	void (*module_unload)(struct codetag_type *cttype,
+			      struct codetag_module *cmod);
 };
 
 struct codetag_iterator {
@@ -65,4 +69,12 @@ void codetag_to_text(struct seq_buf *out, struct codetag *ct);
 struct codetag_type *
 codetag_register_type(const struct codetag_type_desc *desc);
 
+#if defined(CONFIG_CODE_TAGGING) && defined(CONFIG_MODULES)
+void codetag_load_module(struct module *mod);
+void codetag_unload_module(struct module *mod);
+#else
+static inline void codetag_load_module(struct module *mod) {}
+static inline void codetag_unload_module(struct module *mod) {}
+#endif
+
 #endif /* _LINUX_CODETAG_H */
diff --git a/kernel/module/main.c b/kernel/module/main.c
index e1e8a7a9d6c1..ffa6b3e9cb43 100644
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
@@ -1242,6 +1243,7 @@ static void free_module(struct module *mod)
 {
 	trace_module_free(mod);
 
+	codetag_unload_module(mod);
 	mod_sysfs_teardown(mod);
 
 	/*
@@ -2995,6 +2997,8 @@ static int load_module(struct load_info *info, const char __user *uargs,
 	/* Get rid of temporary copy. */
 	free_copy(info, flags);
 
+	codetag_load_module(mod);
+
 	/* Done! */
 	trace_module_load(mod);
 
diff --git a/lib/codetag.c b/lib/codetag.c
index 8b5b89ad508d..54d2828eba25 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -124,15 +124,20 @@ static void *get_symbol(struct module *mod, const char *prefix, const char *name
 {
 	DECLARE_SEQ_BUF(sb, KSYM_NAME_LEN);
 	const char *buf;
+	void *ret;
 
 	seq_buf_printf(&sb, "%s%s", prefix, name);
 	if (seq_buf_has_overflowed(&sb))
 		return NULL;
 
 	buf = seq_buf_str(&sb);
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
@@ -173,8 +178,11 @@ static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
 
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
@@ -185,6 +193,52 @@ static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
 	return 0;
 }
 
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
+
 #else /* CONFIG_MODULES */
 static int codetag_module_init(struct codetag_type *cttype, struct module *mod) { return 0; }
 #endif /* CONFIG_MODULES */
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-12-surenb%40google.com.
