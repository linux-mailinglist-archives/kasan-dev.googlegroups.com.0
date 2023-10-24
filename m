Return-Path: <kasan-dev+bncBC7OD3FKWUERBX4V36UQMGQECXCCLSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E52D57D523E
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:12 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-581df11b5b4sf6521561eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155232; cv=pass;
        d=google.com; s=arc-20160816;
        b=ig/esBC1XQEICyMuF7c7Bg9GV2i8L7sUF8jcbzvp5eMRL+X5SO89qTBBddHjwvOMJo
         oDdLrh4Z44V2EJrEIdntvbGfpGKjarFn7PjFvrZg9naYMtJ/mcG/iQ8MP9TrtjKVGzrf
         q/Es9M6zYSb7Koqer4bgvMwCpMadm5mXch8cHAEYtTKIJ/XzZqRf0DFYlADSh0fg3Aa0
         fHfsS8Al2ZcgJRg9IjM9hfs9hj3tiEgECLOnA0QJQOExu+thW9PgLTyuOehy6nOEfDqo
         jKG4fNcVP67iVxv4CVDVyPOtiX6ZXW3zCESqTWJdOoKP+NvE4xk46qhQR7JAWporE0tT
         U30g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/QkGgl6Kae1DpQCdf8yPUpjeO9Ea7LDxyntoPVneIq4=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=p89pTAVDdPZyEekUFPYPWY1DRgWKfmStucVj77PpudQE7uT3lUd+vVAyr+8JzDoOwJ
         HSLgJ9Ijn2aEcKseZuGM4t1XlRMAY7dMb4P7lcI0NsZV2byGZQt8NLNNOlqeE3fBCuSA
         T9JKy/VuizqOlQJfLDjUPh8nMdxbJL9o4cz8c94J3+zmjq7vELm72eiUE9Ht4z3bbMGb
         8Dy/F6O8FweBYWmR2noZOhcmgTIRARWmuUJ5VLPhg5j2kQxsjFgSNs3jUWZW+sobmSer
         2CqqE4PDI/q9vpKK+V+WLGRB7lr4+mRVOcRPVcgV6zBOZozu6rFLgo67VMvhn0+Hj25N
         tbLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1xRNMFyx;
       spf=pass (google.com: domain of 33so3zqykcymz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=33so3ZQYKCYMz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155232; x=1698760032; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/QkGgl6Kae1DpQCdf8yPUpjeO9Ea7LDxyntoPVneIq4=;
        b=s3kuGxvoqbdxt3aeJi3yLYzefSMgA3ymsqePAauzG/h+9R0HC8yQ/hFyPd7H1dLoq7
         b7S7WanuB1Z6YMxWYs46uF1Qn/wEHnyaR1VmHbnU+cVUt6QEqXAY5gNptNUEAo5DLh3u
         BC0hmUxg8GWnKruJ+qxdnFrUx7Lxjabn2bVu9W+ccFNJY5m4sFxn6iT6nIHD5d6PjZGv
         pFJ9sXeQD4ih/usinghwfcs4qieH/88JiPidRFKkSCtjHFK/bYuzWZTuEiz9NpeUzVsJ
         S/PrO2jWNYZphuJiQx89Apc63BftT86CjUkveUkIfI43EiKHdi2LaYaWKcjF7P0qBboD
         ufVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155232; x=1698760032;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/QkGgl6Kae1DpQCdf8yPUpjeO9Ea7LDxyntoPVneIq4=;
        b=t0oZLIUpNJoRHTw1De+lCHc23blS3ZaKbgXbhBHjdbyAFB68prNSM6keRROxV9Jmzy
         EgNS3T+ou5oaiFACIG59hKDmQX6885u7+Rz8fxSm15BZsMa3oVyiaxkmkSq/83c0kTEM
         vN+MV48ZHI6sJixDM5WNgdpr009RCrqmIIxiV1Vd7ZkXpMoVrJbKzUIbVEDq+VKjBnty
         NH06pnNF8w4x1Med5jQxu2QYWUhHr4FmyP7MnogcB8Pp7sTHaXKpCl0tsOGEH5kCBxoN
         2ohqpcCv17fWF3ynaDobsZy21Ao0jv2xR5UJeClpn2m0bawLsUoRDDa8eRG+YxZsLz2h
         Nwmg==
X-Gm-Message-State: AOJu0YxQgAMefTbLEAdjkCJdHCxCgp6ZLL0mMNi+UD5Qub9Dk8f0tM/l
	xWM1b2JUU4xmytcgUeH//ig=
X-Google-Smtp-Source: AGHT+IHO0yyoarXI6wy+77vRNjRWf/HvQFkBLQT+dXwm02qp7jGmDQGw1/4tD7sGGvIa7UUf0CTLfA==
X-Received: by 2002:a4a:d84b:0:b0:57d:e5e7:6d00 with SMTP id g11-20020a4ad84b000000b0057de5e76d00mr12241396oov.6.1698155231742;
        Tue, 24 Oct 2023 06:47:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4f83:0:b0:581:d755:f05f with SMTP id c125-20020a4a4f83000000b00581d755f05fls1622123oob.2.-pod-prod-05-us;
 Tue, 24 Oct 2023 06:47:11 -0700 (PDT)
X-Received: by 2002:a05:6830:20d:b0:6b9:8357:6150 with SMTP id em13-20020a056830020d00b006b983576150mr12642165otb.35.1698155230884;
        Tue, 24 Oct 2023 06:47:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155230; cv=none;
        d=google.com; s=arc-20160816;
        b=MmpnhzIbglS8Wwbabqw7ICLk+SgQKOFyUqbfdGrisaj6xjFS2km7Q7hb956aJjiPfZ
         Vjr2B5vtFNhtw70CzZbyJafYqiW1rGYX55RrHjmQv/Jv8pbw9inBwFv553dMj+1PdmuF
         DI8WZc9yH9waVIlMnNqFZEj4YTwnd5DYI1QxSMKguO++Nleqk60nSft++depXW365/bY
         AK0eIVMg6Uc9a+7Rlv2Sj3NEA0g/HYTkkqydmvium8Nz+iN36YZBZXzI/48XSu9LBOsU
         t1jvcUPhyCAAeNf4+JOWFQGY7iPJttHR7CUC6aLUUXcT9Y+U15VVnh92C1PUPFlgx/nA
         /8ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YavwLOEBRwC8H4iLOoVDT3e7zkyr1je9EHR8XAi9ck4=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=YTKhrNNlqEvQYtJXI+B+MnZrTfXjGuVApLIepbvyAXoAh7WBkPi/G/Hi+J2mQVIwSj
         KLd/0rPUX8dIdIPZ1r8/kJ0LpQHjcroVz140EcXLau/Iwd7XfSMHuz6GnKlNcfhTiXUJ
         ICvCyCEHJCbxIF75yjaM5ecDA77WpGpOUDBxk0rAnsxfpXhsRYPEVCBYI2itNI+inTHr
         Yl9Hfp9XbfQmL1CtPUDhuUqgtAcIJ1Orc4t0w866TsDu14IUlTseiDGcKYtTKCCt6sJh
         bI5Q+iJpLhy4vMAHgemFaCSIW37xldn/BsJMu4MpX210GaJV78Ks/2v80JwSol6xk61w
         2bOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1xRNMFyx;
       spf=pass (google.com: domain of 33so3zqykcymz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=33so3ZQYKCYMz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id n24-20020a9d4d18000000b006c64ecd75f8si869711otf.5.2023.10.24.06.47.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33so3zqykcymz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5a7d1816bccso59393277b3.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:10 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a81:4e0e:0:b0:5a2:3de0:24a9 with SMTP id
 c14-20020a814e0e000000b005a23de024a9mr271520ywb.1.1698155230510; Tue, 24 Oct
 2023 06:47:10 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:10 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-14-surenb@google.com>
Subject: [PATCH v2 13/39] lib: code tagging module support
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
 header.i=@google.com header.s=20230601 header.b=1xRNMFyx;       spf=pass
 (google.com: domain of 33so3zqykcymz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=33so3ZQYKCYMz1yluinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--surenb.bounces.google.com;
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
index 98fedfdb8db5..c0d3f562c7ab 100644
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
@@ -2975,6 +2977,8 @@ static int load_module(struct load_info *info, const char __user *uargs,
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-14-surenb%40google.com.
