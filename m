Return-Path: <kasan-dev+bncBC7OD3FKWUERB5ELXKMAMGQE2SFPZ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B7545A6F82
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:41 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id f202-20020a1f38d3000000b003802dd3dc36sf2099455vka.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896180; cv=pass;
        d=google.com; s=arc-20160816;
        b=ta8qniVb6ARIjNIBVYqZNLcVjNHOGNd4oDvIo0pHuLnIqFVgCb9x3B37t3+UbrlIkx
         cymUr1+D+CKZOO08E0xxgzJvEcHhasaLbb1AjHiOM1DmE0rLbaUpfSPEK30gynXgtmWI
         JQXHyVRkaHeMPKmzBJS5wIIRlKLhscKzrg78Wuoy4T1WA+x99XVlq5EEpwxokXh9xuBH
         9tmFH4ZSdQpFrOXFdKZyiThGXCwiFH0BTifYqHwya2IcDFdvb1ZOXzTUv2gAU9A/GZwC
         EHaVjqLiZIsHS6jVfF2FEPFM+xYsVoUeXbX0KY87Rd5dFch3KiD+iI7C5AGTTuUOGgcF
         ne/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Wezcy7QA7h11zXZm+1Fr94kK4afhAfRGEC7b8GkaEmM=;
        b=pmxtNCU6FH1A0gfhq2HVR+Az1tzIYRWUXI3A8vbpnDHO+lucrR3+DDNSuIbz+NN5s5
         ZI3L5/nlylYGuwZ+3MEdQOWkgZ/dpF6avRcMDFttw/AqTExM6l4Sn1TJpPASmNGMNJJW
         tXPOxLEmMDsRcEF2aQ398NSy9aScXuMGKWb0n3C53WXUIOuGYI4Ia8YlsDUU6hMKgjj4
         ljlaOn5qYBZIWI4w4ycIRDgnx0AZMhYp+KBTMDL7X3vxoZ6LjIvVjKMkfzOyctdxl+Qu
         moG+zxXSVVkWtVBmvQlQRFvD13jzoHLBry+XZl2A6lz/65GJwFmS+gez90DwD5EXYcef
         LG6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ppQwolWM;
       spf=pass (google.com: domain of 384uoywykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=384UOYwYKCVgIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Wezcy7QA7h11zXZm+1Fr94kK4afhAfRGEC7b8GkaEmM=;
        b=ohgxzonvRpdwjFHUJ843Ro3Q+tg8KJv1HuJ29v4umJKoHQ9MDPFpb9lAC7Zvj2U7/n
         wWu2LfrTKgnGbTOOJTnI6ZosuufL/GjhyWcxa6ex5qhrj2LdWwogE/8BQL267/fAD7UC
         IjL+6lTcLgDKx3jb81kQASgJDFIiz3gunDDQe0TaFGGirsgCi1EOZVk8xpZjezrp+RRY
         R7/oGej+fgbB13T0YGBv7UyB/Hl75wfIPJu+1hf7mBEujb1BqRJZU4G5UP016/QSkbb/
         ktEgva9iIQmuYbcDqvD2uXpPL0xiylWUCeO56G/Hi3xs4Ngv7XCUqhQDHY64r4VbEnU2
         CFKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Wezcy7QA7h11zXZm+1Fr94kK4afhAfRGEC7b8GkaEmM=;
        b=n4c68UCvCzd5GY/Ou2Bbp8RBjwSw7DWo3fXXCnMuHoDOGNhWQ4GSynXY8jDtG6uq/p
         8qMHg/IRFl1xr5sZ9Uqe02/cy4/VACKQsXGf1vLC7SQxIXRBwVEl7KZKy/X+bBxA5fLT
         rdjeyP50Of1uB/vsaGmlHNvPeraD2fuordbK8UhCGN4ZdxhB677/f7eiKoY2VsGFRN/V
         wPBN8oLODg0DvMI5ChIoEH6U4UeoX7328Anq++7fshuuG4cgqwZj2OUpsY4PTcJDsXqT
         nI3AzP1qDtBkUvlKzJ4+Gc4bN+sL6P23DV386I28Hg4f4jm7MnD8zzxCUo+XZ111eyQS
         GR6w==
X-Gm-Message-State: ACgBeo3tqbSOi1BTSyzyizPsNXS15dWTfkoL1kJe4QjgAM6LvK8aF+GI
	2apraVOlsbM671S7kSRpmzA=
X-Google-Smtp-Source: AA6agR5ORqp3hFSYCRsDBFBEuoLT1HoFYgFCioJ8sd4Si0vgnF9tq4U4JwVABtcc8VZDAKRINoLqGQ==
X-Received: by 2002:ab0:5b01:0:b0:39f:50e3:ea0a with SMTP id u1-20020ab05b01000000b0039f50e3ea0amr6246181uae.48.1661896180325;
        Tue, 30 Aug 2022 14:49:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:df8f:0:b0:390:ac7a:e6e5 with SMTP id x15-20020a67df8f000000b00390ac7ae6e5ls1746741vsk.3.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:49:39 -0700 (PDT)
X-Received: by 2002:a05:6102:115:b0:392:97c0:838c with SMTP id z21-20020a056102011500b0039297c0838cmr1203277vsq.60.1661896179711;
        Tue, 30 Aug 2022 14:49:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896179; cv=none;
        d=google.com; s=arc-20160816;
        b=w7pUYfrH6pFjBVd0CC3kEDJGqhdXkz5jOQjgF4i7DZCQJ0jYgZmpItjBMawrDdHhuY
         /rJVVWnRMHBddL7cPuZ7sh7iZdcZ3LFVX5XQc/q9XdZvOnhHS+YuXHHRb2u9pEErT6HK
         vMnn9Cs2j9Y8ZIZ2btp1bBwmcA387WMecXQCA637YlkTxawS+L5wCDmavKsFRaVpNO6i
         3NOfCOW0vcTyavlTf/UoC02aZYtY9YpcIJzfCiry7hxWOhwb6uA7tfQbdFHM1STTxp5f
         I2WmBjZwxtboVA2TKJuyriaDPRqFzqNfsmIU22O+RkwvszK+AbDn54N53HnbtKVUHFPl
         3H2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=98WyT1z35HcvSKL2J7VN7g/2jl2Mia82SjRaCpg7p/8=;
        b=QoPvudMzkc525c2gwayA3InxxMqedFCjMymv1arGZX7EWXiaOZkGeEr4I5PO+vsXjF
         ocEwXT2t1dXYf58OjCOb2x9e3L4BFDnJ0AHP+v9EQih9prnDRywtWFwU/Y9fd45MeqqN
         wxGKZwAb3xH5fliPbOZrHC36iMmX72dHJ4AQGeT8LkWy/RC5ac843Izp0432HOVj5vkY
         HHR+4FjLuwMY8w1tQVG9i6ivLEnNEXSwmH4UKNnTYb9U38Y9mQtAS9AjP6y9g+DzSYFf
         2AFPCg5q6zDIpIGa8CdCH7SzdIovy6tgt9iOI4+iSUD09hawbb8+k+W4GjoOMddwx6ZX
         xJQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ppQwolWM;
       spf=pass (google.com: domain of 384uoywykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=384UOYwYKCVgIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id w134-20020a1f308c000000b0037692a8beb7si438616vkw.3.2022.08.30.14.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 384uoywykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-340ae84fb7dso156826227b3.17
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:39 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a05:6902:2cb:b0:684:aebe:49ab with SMTP id
 w11-20020a05690202cb00b00684aebe49abmr13690932ybh.242.1661896179352; Tue, 30
 Aug 2022 14:49:39 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:55 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-7-surenb@google.com>
Subject: [RFC PATCH 06/30] lib: code tagging module support
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ppQwolWM;       spf=pass
 (google.com: domain of 384uoywykcvgikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=384UOYwYKCVgIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
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
 include/linux/codetag.h | 12 ++++++++++
 kernel/module/main.c    |  4 ++++
 lib/codetag.c           | 51 ++++++++++++++++++++++++++++++++++++++++-
 3 files changed, 66 insertions(+), 1 deletion(-)

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
index a4e4d84b6f4e..d253277492fd 100644
--- a/kernel/module/main.c
+++ b/kernel/module/main.c
@@ -53,6 +53,7 @@
 #include <linux/bsearch.h>
 #include <linux/dynamic_debug.h>
 #include <linux/audit.h>
+#include <linux/codetag.h>
 #include <uapi/linux/module.h>
 #include "internal.h"
 
@@ -1151,6 +1152,7 @@ static void free_module(struct module *mod)
 {
 	trace_module_free(mod);
 
+	codetag_unload_module(mod);
 	mod_sysfs_teardown(mod);
 
 	/*
@@ -2849,6 +2851,8 @@ static int load_module(struct load_info *info, const char __user *uargs,
 	/* Get rid of temporary copy. */
 	free_copy(info, flags);
 
+	codetag_load_module(mod);
+
 	/* Done! */
 	trace_module_load(mod);
 
diff --git a/lib/codetag.c b/lib/codetag.c
index 7708f8388e55..f0a3174f9b71 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -157,8 +157,11 @@ static int codetag_module_init(struct codetag_type *cttype, struct module *mod)
 
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
@@ -197,3 +200,49 @@ codetag_register_type(const struct codetag_type_desc *desc)
 
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-7-surenb%40google.com.
