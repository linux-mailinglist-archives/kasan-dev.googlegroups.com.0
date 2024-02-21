Return-Path: <kasan-dev+bncBC7OD3FKWUERBY5D3GXAMGQEMGHANUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4690085E77A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:25 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-42dfe528ddesf48987661cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544484; cv=pass;
        d=google.com; s=arc-20160816;
        b=ljxdeT8thht7W3dp6tDEedAsIPz4oMM2+VcSo3ptOLLrUMq2/tglh3GOOzKSSFeK3H
         5ic+CuA6UO1aSv8S4UN+rlf9ASbiMPCIpjHalAcd9AURoR1dzQQQqoBr4NJ/uWtuHhZ4
         AZXUFE3JGKcgP0sl0XAHWU4khFViKDd/OMz1FRmcZzoymt4xYwITla6IXK6aBIp2Er67
         U5/z0qpi+mcfLlbh+DB7SQ4W51z7XgvhNe2ZM2FO9+81mYWFj0NQi23Uzi09dYC2B1Tl
         BHo6DqsqlIRvovfjOxnEJ3RwB89EAUs7KOUCTpHCiozFadOtmJTSnCd4r6SMu/BlRrOL
         VjCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7zkOx0lG+NSmX2Lxlwf4r0FoCby6+TSE4bp7XxlQ3nQ=;
        fh=STqe0BjpZfKbpHD+WD4C0zVk1oTUxUyV8C8bPfZ46tc=;
        b=PMdiHlK3Vit1UNYckQw1xHkMsZtQhv6NRvGlC7bBYdYeruszdyKuynHALFQgGXp+8m
         iVEqpI08JhH8RzfoXKpj4+7oBTmyChJHxhwnUuQnxZ3LPnzPxKmz857R0f7oh1bO7ccP
         Hw7Ej0YRFie30DpFfBvScaamD4sjQThzQQ8umITjQcv/UOxIjSQY3I9oNHBkbOGHOE22
         rDNNNEyiegwWRd+QvHWdzstc/LGv25fSUf+zbC8l0xqXV1P8jtgu2Lu+mrjGdwPeP5Eg
         eG7EP6097RyvG7cQ0SsFBf16hcfupx19RA0yG+rZstuI4Csj0r6VN3VVV2PgIgLPxyPa
         zwAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="n1/tTiYt";
       spf=pass (google.com: domain of 34lhwzqykcrudfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=34lHWZQYKCRUDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544484; x=1709149284; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7zkOx0lG+NSmX2Lxlwf4r0FoCby6+TSE4bp7XxlQ3nQ=;
        b=uuvT15vjL0mlArvcmQ6AYA95g6rE8E6ZYo2/4fKDtb2YdOWh5T7kqGLBQvQ8xGVEIl
         D6TJwubIrjZuM0EZ3MrzfHgRn8j9hWS88KC/UIkHPGHiByQ0bm3WUVOEygpOTQSw4faT
         3s4Z7EiugI+/y6rh2JJk3tRwnnFET9hHsH4zcvSLdWqimUgbiWFAmjD8a6w8WMTNPAQp
         rHlm6ssB1hNwKBGujDI5Ve8xTPEJbjAmKLZ7USuZc+YoFziksF4vjiCb8kKi2GmM5zYI
         bkGWcZ4o5LH7Zv1jQ6VS5AsybN5cBPwC+Bz8LkQv+MMHCbFjXkwc3sL8mbC+mSodkd9d
         83ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544484; x=1709149284;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7zkOx0lG+NSmX2Lxlwf4r0FoCby6+TSE4bp7XxlQ3nQ=;
        b=ak0Bq8IXLqUU0Kzuh81vq3qBzXacAC4faLtWZ7E6noIumXaMVIVaj+v8637DnouoH5
         bh3ncR48cU5yjyeBQlpaeUteSPMdlwZdemCauf3nZcGW+EyWytPV1qOwPdYd3KzSQjAt
         RJ2yyI6l5p6RDNRpv3UIEH4iT3AsuwW69jeiDoORfzVJiqQGcsPMgjEzjEaj/q77jkAm
         Jn50ym7woYcpguJE+hubyT9gZYAtJvIw/arz6LwbHXk2NICQKPLqKvT6DaJXAYPW/RYk
         hIWsB2VqJVqGsIeijJmmJhsQDb+XglZQjlRVd5iRXphn8Ld4ngZbNbwAIVNOGPBDS4KI
         WKcg==
X-Forwarded-Encrypted: i=2; AJvYcCWrpa2p8gs8tPQS2nyv2iplGSaBs+V70AhMK3GcaonYgHg8Tm+WAhrQLk1H0R9E5saEudS6w9cjqTzlomQsi4W8EP3WIQxeTw==
X-Gm-Message-State: AOJu0YwElgpDivnHm5JF/WFvyQHWgkiTIlK92ymfao81uDyvrNCN16IE
	SJO/+u4oHiHrOhKsj2jNf52t34nZc3jkz5Hyz7P4vjHleINyQiMR
X-Google-Smtp-Source: AGHT+IERBE+7lCDTNdbdc6y1qFr8j2oyFIPZpHuPP7lgBm8VsYk7opLA8Osdh9LNaxtGOVSwBUxw6w==
X-Received: by 2002:a05:622a:5c7:b0:42d:b3b4:982a with SMTP id d7-20020a05622a05c700b0042db3b4982amr22986724qtb.66.1708544483852;
        Wed, 21 Feb 2024 11:41:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:d3:b0:42e:4321:e6fa with SMTP id
 p19-20020a05622a00d300b0042e4321e6fals654106qtw.1.-pod-prod-01-us; Wed, 21
 Feb 2024 11:41:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV8hxprivT8l287zmx3FKpLPiOKosFy1fbi8LLrDQqVQvntRokNUIuWQ+bnldmwCWpyOgM65n58tSGfTMbjy05GdO7uMUmDmr1YwA==
X-Received: by 2002:ac8:58c2:0:b0:42d:e772:843 with SMTP id u2-20020ac858c2000000b0042de7720843mr19427217qta.58.1708544482923;
        Wed, 21 Feb 2024 11:41:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544482; cv=none;
        d=google.com; s=arc-20160816;
        b=vQItD47zwON6/TrP/mgP9dNjubBzuUfJFxXfYQYcio3d32rg7EaIxUSOjBYpUFGCAf
         3LCsfJoUL/N02SUWwLNlUMqCSamRfpJJTX6Ve9vvFhfVlcgHc4JzkdeeSaCPHjqtN4vy
         TSMBzXcfPDeZv0k13p/LoLminG4NPKXx2xZOPpagxNDMnOnOjpEj0qk+sx3RLRJHCaGC
         Ir7FMhiBXxPctxOnrX36lyEa3IaNdA1LOOPdjUKA77vlGkLudyExLQYkK4m0H6n7sfk0
         MgfbmgrOj8SUk/cPTpNHQcy5m48D3hamSzx8pTSut4ecck8/1u4mrjrqlPQaDM7WfiT2
         tIIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=XR/SP3Bk5ahA1k2JZ7LXmVl+aTAtC05e65Lb1fPVJe4=;
        fh=o4dHe+f4yLxLa3cp8atU87lzsQvLiw36xY64C/Da5HU=;
        b=F1mk3RI8sYxAU5iy4jtG9XSquO0rdWpBmJ/uSWf07ODGEaZJsQv+ODPjDuw4EBdC8C
         On7q5xaCg7oifYX7aJzTH1EWH2dsG2rq0gB9dHWeYizrcUyA55xh73ispDEm19UTlE3H
         T0yFMjgVucO7l9ZPXNTkql0q4nr6UoZLyrY9oA/foZVO4tduzH67heHtk0JOXMzmSJTU
         mvdobKzOQ1tupDjeUatz9hMrK34nwBKbc5lXjhdI2eDoJ+lKEO6Q10+7RUM5Wg32rMke
         i9ElJRIkhD1hJNwByRc9lusNth5VMWKYtPuckUCCkTNE+53MwotqX1mVg+/bU0/okTMO
         OxSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="n1/tTiYt";
       spf=pass (google.com: domain of 34lhwzqykcrudfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=34lHWZQYKCRUDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id g1-20020ac85d41000000b0042e082ee1f5si564938qtx.0.2024.02.21.11.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 34lhwzqykcrudfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b26783b4so6791298276.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWk7HilczYgMkZoJlIkMwf8O03jNw3T8Pvy1rw8ezNN6UZ2SebNsSfpIV46PhCq2h5sCQzxvg1jmpmxGT73uPiOyxEQ5QksEWwcKw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a25:910:0:b0:dcc:53c6:1133 with SMTP id
 16-20020a250910000000b00dcc53c61133mr14837ybj.13.1708544482428; Wed, 21 Feb
 2024 11:41:22 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:25 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-13-surenb@google.com>
Subject: [PATCH v4 12/36] lib: code tagging module support
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
 header.i=@google.com header.s=20230601 header.b="n1/tTiYt";       spf=pass
 (google.com: domain of 34lhwzqykcrudfcz8w19916z.x975vdv8-yzg19916z1c9fad.x97@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=34lHWZQYKCRUDFCz8w19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--surenb.bounces.google.com;
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
index 8b5b89ad508d..9af22648dbfa 100644
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
@@ -217,3 +225,49 @@ codetag_register_type(const struct codetag_type_desc *desc)
 
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-13-surenb%40google.com.
