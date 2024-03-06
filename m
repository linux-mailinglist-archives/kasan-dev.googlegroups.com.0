Return-Path: <kasan-dev+bncBC7OD3FKWUERBBPKUKXQMGQEWKJL7FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 56236873E7C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:11 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-3c1d24ed227sf252596b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749510; cv=pass;
        d=google.com; s=arc-20160816;
        b=WegyWo2b60ur5rQf/2ijcpjfYifH+XAL4TZBSkTB3o6QxGOSbV2ZpDFyw/qMLXvLW3
         UFTaqmVs5QYGFIfs2M8/m02IQRIR1JSr506DxMEwbLxwrRJhFD3+YC9+uqYnCbMH3HIg
         TF6AScbfA8hVGirFJQ1y5YX+vU6qUWNIZ1w1IUw/yzM3aTpRyIlhOsiS8/SAyTUbpvQ5
         oRCT6Kb0YuB7yg9U/IXfv68cQWnIDJRk9YOKFmuWiBu9z6m335yfAtjHi0ig+lmiLKHb
         9I1tPecMbaKOyw5nwTWvlCob4nuHZMsa2jt//cLwlRbXK3g9qe5X4hXPPRgBj7TwiXvj
         jiew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=70xBc6ZOSieA5weB6Dk5xzADZi5d+zN45F1G3I5tJxA=;
        fh=Uv5G4orYIgdJIN3p0NAeb3EfjbHOpZJSP0de4K3nX2o=;
        b=uR6AROd3nw3GzMLe6sRyaW5ZepzAE5UPv2jVQwtojFkxjEC13vNSHskP/XkhqlC7tw
         184DnVlzKpq+eWQ6ZR0DN0oeqFr09NLbzkPsnZeTq61Xfw3T8YZuH8uwegI6qAwz2SDB
         rHdzrXXk4RiUiD2C4r7r7pd4t7bbE1HBZ4z6QJg31YUtBafetCoJPnDRA+v1N6O7JaC9
         M9GXo0LB5K8Ivp9947L8+YadHayUcEyT9selfGnxkfV8fC/7zybVPzZa90m/O07KtWYT
         eJtSgm0vQx3YPc9aUAeoEy+v7WUz5Yz71dCRFql1j6giwvzIAKiCVJ6evDScp5oFVIne
         wb4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="v/oNba/j";
       spf=pass (google.com: domain of 3blxozqykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3BLXoZQYKCUc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749510; x=1710354310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=70xBc6ZOSieA5weB6Dk5xzADZi5d+zN45F1G3I5tJxA=;
        b=EfGIXgv768UICBurmpzC1jmkDfJ+eYKz0rPyOmOlQhmVx56Ih/LVD+BP3E1vwG8qpN
         fHRmm33KCrZdxEBmiDrqoBSyJuMkLiTYH/q7NTWV0vRP3r8P9hEyHTmYIWjrXXmsAxtV
         Tkk42h2gUnvCPDQH/7u0NeC4qLfL5BXr5JGJvc5cmikCStey/3IP8vbNs1E80gH9+Rp+
         /xptOTRfJdrstaAFo37KgTbTC51S+0edOoKKG13/nl2WARALixpzRJxSUZ2nzB6BHE8O
         xqXxOF8Ew7bf1qoUj3xBrIF9wa4EN6AjGgAQE6xPTBW3cOBQywmQVIW90XhM38gHqbqW
         qrJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749510; x=1710354310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=70xBc6ZOSieA5weB6Dk5xzADZi5d+zN45F1G3I5tJxA=;
        b=c98VWNQBneD3Drzou/2gf2is7RABO4s3zFTbLjWMQjOS6gmtXK2WHhwxA8xXYmlZlk
         RChm+nEaY+bn77qqik+9iIKuYc36rRldfubZkXIlb/40cHItIvV/NIuhbZnpmThAB34G
         YcqhMqhECAOvCs+3g+Yj4veuKKFu4vMHTaTtVi+CZvDrgPi9WSBYEMaM6merjBwFTYeA
         +scZclFFCJ5qEO0NOg3yVBx+gUUbCapD4rlPbWtH7rlUnQrFk1bh9GBVkH1UPSu1anYI
         bN8l1Ip+8d6ZcyzFKsBjuVKiHKRGWCTw4npVcBlbqW6+rrbMTN1ZkypXFtdSckiDlokQ
         zyjg==
X-Forwarded-Encrypted: i=2; AJvYcCWfMIJi8xBv9cvvd2RsLciqiVOLEfKMTh6oWEFoMFxixjuU2N/nB/okmv1fkRMvdI6eioMQXhMFzbhzAY21gNl1D83ZWipZBQ==
X-Gm-Message-State: AOJu0YwOF/Wb8JyTa5IryrayPJCuSmWXX5QxG7RdffQE8FysjVGo7z/g
	BiSK/V4bkitt7PchajVYuK2c9sMMhP/gONyMHR4jAepyU5WVl4mZ
X-Google-Smtp-Source: AGHT+IHLqM+Z8HVr5CeFJ2+ArxKQEt5mWnbELtzNYSjvIGZGt/NSIAzsI+Q7qt9J3Pa+4RdKzsASFA==
X-Received: by 2002:aca:1208:0:b0:3c1:ea81:64e9 with SMTP id 8-20020aca1208000000b003c1ea8164e9mr5220701ois.44.1709749509965;
        Wed, 06 Mar 2024 10:25:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:59cc:0:b0:42e:fd89:8ea5 with SMTP id f12-20020ac859cc000000b0042efd898ea5ls89831qtf.1.-pod-prod-07-us;
 Wed, 06 Mar 2024 10:25:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVV0/94bns2/w7pV1fRKID3grbvl3EDxREPBx19Kz1vdoYrG9DoPmXIHuXThc4BPqjjgHw0uS+iAXEilNvaYgIPq0jrvvgyPN2fhQ==
X-Received: by 2002:a05:622a:181b:b0:42e:e554:d10c with SMTP id t27-20020a05622a181b00b0042ee554d10cmr3256784qtc.52.1709749509027;
        Wed, 06 Mar 2024 10:25:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749509; cv=none;
        d=google.com; s=arc-20160816;
        b=MkphiqUCX1oFfZvMoNGZR/x1QknKW8GyrxYW16kxce7CihSNq1+JYSG8m5R84UO48L
         /Fbf82TzCVrlML0NGVkpxBHEZRk//anzhl3r6zq6d7gPf+CuJkOR779tPw1Olszi5koC
         jdO2NVMCVknMNOJQy+pUJH9zgNNz2M8dx/MSHSGtvC52GmaKkEZoaoAleQMqK0sDzcjq
         g+3MpQbEntC9TvZJEDIquLiZcRn7X4noW5QigRrnMgq4pbCtsiyr4HU+Qn+/pLeK/uAz
         jmXYSsFqCJ2so60DT2FfiSLOfpYTdPgJ9bVkGqEL5z3DdKMZhqaBpgIqFv771mxyAJA0
         3SdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tPAQlIYBmu/nqjnWAR+Y3waoaH5kDJ/L5+WSbugHpuw=;
        fh=z8Jv1FcvBr1OhTd+C9Bfz11apdX4fzKimQE3B+NajdY=;
        b=EzyDGA/q/oF8uxr9LDepPhNqJnr60JVS2AqWE0gz5eJrsWjA0TiVzHljud02LokB2Y
         fdh5pxwX3LIqi6aNxLjBKybqdyNafOjDpx76CTG06Ka0Inz02lSYXK8Bm6ntIXb98E/u
         rtgApyJmEtBNhnVW7V37PqrY8T1wDt2DIjwvmZmKnlmuNOxicIBvTSeDk7nzOyef8cSW
         5YSS/p59KC/8e5HKtvV2Twa6xo2d8WQkFIG9bLCUUc5iLzREsP+fcozEbwfu+fgCP43L
         xgnRwGfBKR5y25VBL38jgUizeqB59XOxjC0BB8eGD36k7pRlMCGeuirldst/o9tu51Yl
         ExIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="v/oNba/j";
       spf=pass (google.com: domain of 3blxozqykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3BLXoZQYKCUc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id bq16-20020a05622a1c1000b0042c35cd8321si1504731qtb.1.2024.03.06.10.25.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3blxozqykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60998466af4so108337b3.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUZHB5SFmmnw0KGwWijJKhkm3DeOUB1ZLmR2/44lAFwB8uDyt7sUBC+pcl2vHkQRlurWzuU9McXFSPmg+8heAVMJZFcaMVP3Wyc/Q==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:ec5:b0:609:247a:fd3c with SMTP id
 cs5-20020a05690c0ec500b00609247afd3cmr4821873ywb.2.1709749508522; Wed, 06 Mar
 2024 10:25:08 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:09 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-12-surenb@google.com>
Subject: [PATCH v5 11/37] lib: code tagging module support
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
 header.i=@google.com header.s=20230601 header.b="v/oNba/j";       spf=pass
 (google.com: domain of 3blxozqykcuc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3BLXoZQYKCUc130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
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
index b0b99348e1a8..bf5a4afbe4c5 100644
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
@@ -2983,6 +2985,8 @@ static int load_module(struct load_info *info, const char __user *uargs,
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-12-surenb%40google.com.
