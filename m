Return-Path: <kasan-dev+bncBC7OD3FKWUERBLNAVKXAMGQEHT2CX7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E44F6851FCF
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:58 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dc74ac7d015sf5030939276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773998; cv=pass;
        d=google.com; s=arc-20160816;
        b=XbaHPs3EBMxnBS+oVOep3Nuh8b9EtXAzp0ntCggycI/+ILguJH+KQhBTEgs8FaBtWz
         dJHpBK+9+m3RgSn6VIbkL5t027jqT69Abf2KSCESGxJ+LMq+DVOaF1C3Z1bWihizUzU4
         iq4N8dC7X0o39LtMija5Y2KTQtpaQPPyj0tqfdNIEJ8+NDY5cmrR4eL09WOMO5aTkXx/
         PxDZAbMlyREAxLx+31/K8hHfD4zIN9doDpbeB1YAESR6+LNFwuYLbzZzKIKKW75gGwDb
         kHHqnshkedPEQCwaVj8otZG22Mbth2lHMN1y6KpL2uW3cdJ3uVBSMBjdFhDtGeqVyXb4
         MYQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ol91hhlZH16kCXNVHLNIOTViHP5v5B1tGyP6kXiWEK0=;
        fh=KsWj7BPlvGeB/PUNXQLj2EQrnqN7/8ByKSNwN4Bu68Y=;
        b=lwu10OXHpSzU+qzQjff9KIYpZqnp8xb9i8O1Iq1MXLg6+Tsdjwv3zXytOg2tSsgn95
         Xcgzh6TwgRnuy5biFSaI6gE9hk8lWBjQjLij9Gw8ovoKJtA2HXDnVVqOYnt22tCAv9nH
         jFfqF8DIVyw3p91viRVVAIVlS3R8+M8NU+RPLeWFcz9HwIJnHMpeL8ddy+TyqNpJr8uB
         MGV7AZdjm0b1nxYW+V4VV100fnDgBTDQA9/YjuZFz3BgrigIGaJ3f9owiw8sqJmRaACC
         qIGesRHiUW4haN6zXGYv/XnSKO18Is5qzh4cWZUPHKMjw9zJS4/okCnn/KJrGAEjNTVj
         XPyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DxNJtkvo;
       spf=pass (google.com: domain of 3ljdkzqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3LJDKZQYKCasdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773998; x=1708378798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ol91hhlZH16kCXNVHLNIOTViHP5v5B1tGyP6kXiWEK0=;
        b=o0U40cS7ma4LhzVtiz6VoxrTp169AXu+B7Fj7lBrWV+Deq8wMcJuLfuCX5zhnx1jNJ
         UUuPHhWiaiI0vaYplfEVKRBSGNREh83OZ+LgJnK+sm9UWu6HfKzU4rSAqnctW2MbeuRW
         RzvN4mvcY28Ei6IPQSFnHluyxwXanbT9bVC6NWUb37CuPxF59je72XtUYGhJK83yEEbI
         3ZvquE3xDP3/z5YmCqGiVfGRwcu8tZqMg6mgmmvz6Y83mVu4afmtHxPvYlBEduyRPg3y
         yjvmGKrsTwZbgHqK4f3bYF7DeWKQLKa6iHEapcP6PYaDqlCA0HX+aldh/Jc9Byp2s09v
         qTMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773998; x=1708378798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ol91hhlZH16kCXNVHLNIOTViHP5v5B1tGyP6kXiWEK0=;
        b=rQFTFphhQ+trLxDcaItoqE+rRUDrHwD5DXq9Y6GOl1lqspr59SJcwqjFwk5y077F/l
         sF9laMiT5XyLaLqgZNg8CF0FLuKHsKQvkQGHRDBxN2uwEDPGKHVo1kf3Js54puzndnlf
         QjtO0aUS80cm4ZpYahhnHRez1HBbYb0LxLTgLts/dPxBb7ReO5IapBvDNxO8hYieAN2m
         cIiqdn4tNNz9miNMrfJM/x9kyucMBLnvwTTKn9CtE3A/grEHruSz9TzBFYthtfY+c79a
         qU72mNRjgmNJNDTf0YHURA6qqIktcvWfUYCPkDLYxAB9kBSDLUR0wBpbI4Y6Sj7myoeI
         CuGA==
X-Gm-Message-State: AOJu0YwYA1v22U8xCwXgoCudn0VFQLgnHKVDIka4rY2iFzvcgDNl/izB
	QSTNASIGZBYiMi2JyPgOwEWUO/+aO7HyZKIc5VyK6NtaxZkb89kr
X-Google-Smtp-Source: AGHT+IFFi1DlBW8AuGDrOTy/oHqIp9yr3cMVfGP5I4YZW+lA7FmefEbm6F5y0A6J1bIsux/e5d/NoA==
X-Received: by 2002:a25:aa84:0:b0:dcc:4cdc:e98f with SMTP id t4-20020a25aa84000000b00dcc4cdce98fmr417285ybi.34.1707773997693;
        Mon, 12 Feb 2024 13:39:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7496:0:b0:dcc:2da3:c41e with SMTP id p144-20020a257496000000b00dcc2da3c41els117519ybc.0.-pod-prod-01-us;
 Mon, 12 Feb 2024 13:39:57 -0800 (PST)
X-Received: by 2002:a05:6902:2483:b0:dc7:423c:b8aa with SMTP id ds3-20020a056902248300b00dc7423cb8aamr7719416ybb.12.1707773996990;
        Mon, 12 Feb 2024 13:39:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773996; cv=none;
        d=google.com; s=arc-20160816;
        b=yO46WzOzprTdD26FFCLBeHsEfxm/0V7BuAL735aInC39GvQlNZbQ66w0T4hDI6uRQK
         IGzc0z6V1g0WQXbUwiPOkYYXfnIfc5069NP1lPcQcFFHbh22rW5EpAMUmMBDhCOw/22T
         aA8C6tdirt2GdWkkBwP0eX2YgtzYJaXrVjYO1mMKffNWm3LbT1cuY5I9vOprXgIFUanK
         hZndS6gQztpJSMnXMhQgbvP/im3EB4xrT/JuksIlSWUzuF2L022ce2QSxbtNEgKkhzht
         LUoHzp1he3b18z3nkOxoTkcsgfM4NhhB/yOJ2uFxfRpRpXHQuubJMsnM/ZPqBzI4A41R
         MKJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZVR5x2YILJK+zhPcdicEuOWU7vdbf7DJDXDz97hru8E=;
        fh=KsWj7BPlvGeB/PUNXQLj2EQrnqN7/8ByKSNwN4Bu68Y=;
        b=FCIzqYml/nJV7uzEHKSPlZQJmApk75eS7oB1zuBybINVsjbyCQscrnP8tBTMog5tn+
         QdOZG8DPB2mJz9QI1AdrlScL5vVP+7er8zF7gBPyzMS7Wse9WpDo8j6BBM9PJyPc27ei
         39MhH9T3DHJS8DDEl6Qww8mp+sIu+OXtz6YAMhRNPgbjHXGzpcZhAMChrj+7+OW/begE
         ONR809GTAZ7WUayAB+AXcpZ/n/x26PURiZG6bUCeTvvFUybYwcJ2guTIw/rjGYwcLvCj
         zKiwgwquN1K/RubL/Gi2ufKLkKiexp95eNeiCBVMtDs1k5NBU/wW7R1ZQkHCt0skVMkm
         DTiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DxNJtkvo;
       spf=pass (google.com: domain of 3ljdkzqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3LJDKZQYKCasdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUknM9OfY2llTFQL1plgC5GDFO/b5jn0aj8t2Yrnrc3dXrgA8LijGHCeyM3riJUBhnjKsAcYPZODDtNaAr6E8judD2hnxJCS9Pc/A==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p77-20020a25d850000000b00dc657e7de95si87520ybg.0.2024.02.12.13.39.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ljdkzqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc3645a6790so6760894276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:56 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:100b:b0:dc6:fa35:b42 with SMTP id
 w11-20020a056902100b00b00dc6fa350b42mr2046974ybt.2.1707773996437; Mon, 12 Feb
 2024 13:39:56 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:57 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-12-surenb@google.com>
Subject: [PATCH v3 11/35] lib: code tagging module support
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
 header.i=@google.com header.s=20230601 header.b=DxNJtkvo;       spf=pass
 (google.com: domain of 3ljdkzqykcasdfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3LJDKZQYKCasdfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
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
index 36681911c05a..f400ba076cc7 100644
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
@@ -2978,6 +2980,8 @@ static int load_module(struct load_info *info, const char __user *uargs,
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-12-surenb%40google.com.
