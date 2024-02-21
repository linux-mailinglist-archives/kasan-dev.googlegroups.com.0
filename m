Return-Path: <kasan-dev+bncBC7OD3FKWUERBZVD3GXAMGQEVCXGNTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6694285E77C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:27 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-21e6d841929sf4857440fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544486; cv=pass;
        d=google.com; s=arc-20160816;
        b=JkqGk+c9iJRjkYbZffcQ3Tgj9ugwu/zZDZNguMUKDjbrnvhjsLxCbIYcBmp6d82dH3
         YOQM7BZXLoKrOgIDtFepOxu8ue6seg+/NV/fvb1PS/DsdPLUfVrU/dRoHjuQ4Sr6NxrQ
         3jUZGC7+msQ4+Qn4yHx6Ybi7CCHOe21Syap5/jLh3a6qGSyoC4VARx3PBw/CFHPLKLId
         +dRtZKP+uP6H1caCEZdrvBFKoHdqGyW8SVHs/D2DPaWjOej6kncW8HL/XhhtbHg6pPw9
         /04+P9sfkMiTki8gHeDlJEjgh5QHxoSpV5cyGqHMbZcGHyK5Bc3u4NEMzPEBXEsdCQrp
         OqTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kCvt7I9ZdvoS/ps1vWzefSWnSBHBjxesPwyaM8f1fMk=;
        fh=7jKtdynYSif6iIdEe5Sdv+hIpt318Fl3ROaSXffQuFI=;
        b=lxYEE7cuF6i4DU2FFGEUTZw3lizPOBKcKS3AlMfW4iaw1/akpMXctz/PVlM2HkRxu8
         d4WCqVQYwuEkCujFH6HFSClq2gVJWO4kKnY3M3ggzqQptP6QR20Nnc66+vp0qbWBr1W9
         dNjTQ5WxddOI+ex6kvkyTKuB5SIETIcJM0RGkSmWbhrnxJI6nZ/QXk+ktuBY3W9PhjlC
         BhWyyk2jq5YEzHa8rQpBAbf7JOVR+wuKPIXQPP7PsaZWB8udxvJww8hjaCmhEiEEP6NA
         itEiRHuMi07vhP/lFhniA8NXe6FqG/cT0e7mX7+nZFDZVPDXetDL6DmDCOTrYd6TQ1DP
         btZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tyy3S4z9;
       spf=pass (google.com: domain of 35fhwzqykcrcfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=35FHWZQYKCRcFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544486; x=1709149286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kCvt7I9ZdvoS/ps1vWzefSWnSBHBjxesPwyaM8f1fMk=;
        b=JQUyR/oO74q8mzlTTymaaGsGBFxwRDJvSuw/wNakcnSqFk39zasoKKyOyTd7DQM9tK
         Fg34n+F2VjzBpsPq+VWq52KHDSunEeYG1h0oOaG8CFyA2u9XHeWFdM3vsC2FhnncjgUE
         1L3U7UZbL9ovEfbRBtFQ3ZnFGnjtDRzWKUjJf4MmgyZrt0TeH+AotS1cJfImYE605r/z
         aOnHC/L2J2CzB4d2Tj5lWHOxfG0KEIQIwZdn9Xup4oPlgC7WXlc88tRbH8q9VBA4WK9B
         +7XlTtk60AV6J1FP1HPTrhrMCW2ZiQJccSruKZhB0bzVwwMgrE+keER6t06LJqLW6FrZ
         ZOkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544486; x=1709149286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kCvt7I9ZdvoS/ps1vWzefSWnSBHBjxesPwyaM8f1fMk=;
        b=gw5Rbm3SIsAkjgfvaxTF6+JOK3CW65zOzek7TostYMtDwKEQbsdQV/Hpfsliv8zWjZ
         1OhIwCOIiCxUunkhZ2VI1PrZkh8jdj1Ya4inM9BHgLtxq3cgcvWwbD+fV1FltS3ppaSO
         tabADRGuiXMaehd60/pJTLCn5Xd14/yUZIJ8gxZDLlrIjrwo/W4ps4bA+Q427N65oOse
         R3zdMsfST9ifztRrokkJQg7O/7FqchHJ1qb4EMr14LvIG3Idxo7Va1os6sUXIbdxQT5g
         fN7Ja6PE7HmMm5PVGUe0T8wdmNKBwmEka1pDk0L5H5MST9ZX6WXJebLDnb7tTbRN3LH0
         YNkQ==
X-Forwarded-Encrypted: i=2; AJvYcCXzPIhs2zXUgXxNuouNLFLg8aUBYRAvOTT5cYQCD4iLMSTjtktSPXKLTN5tuUrSt7H7xSI8sUQSUnhBjE1RxuEU6xAAcemZJQ==
X-Gm-Message-State: AOJu0Yw1gcKjXAJi+nQ++STR7cRaL1WIwGECktzpMetDY7DcXE2OyTDr
	2LZphMc9VqKAsCQUqB6yJfYYrLMkJ6f7uU+3Ooyi4E8qLwzhC+hX
X-Google-Smtp-Source: AGHT+IEkAaQrmCJ6OsrSqu2aBq+VCGN8jO7dJOF8YuMLAGsu6Qm+gY81aS9i91wqZsvu1BBCKsDxwg==
X-Received: by 2002:a05:6871:546:b0:21e:d92b:ef39 with SMTP id t6-20020a056871054600b0021ed92bef39mr10326167oal.27.1708544486123;
        Wed, 21 Feb 2024 11:41:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b494:b0:21e:40f6:4f8e with SMTP id
 y20-20020a056870b49400b0021e40f64f8els1998997oap.1.-pod-prod-02-us; Wed, 21
 Feb 2024 11:41:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXqTmp+oiS7Ubd0sgvHP0fZciyKdL2gNhB0aCNNlLFguOixo9azJf7cvvvGMHESbffSWR5FfTth/F0oNLmvpq/7QrVG4BBTnVXkrA==
X-Received: by 2002:a05:6871:e80b:b0:21f:cda:d027 with SMTP id qd11-20020a056871e80b00b0021f0cdad027mr8100570oac.54.1708544485450;
        Wed, 21 Feb 2024 11:41:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544485; cv=none;
        d=google.com; s=arc-20160816;
        b=ICrbBv6yJNMKYTxQ29z8Gn0qm5oR/5dQSROytzUNnxGfNXyoKwkat+PrfSbXOgimo+
         Jx5pPMsUAeobEUMapThRwBpvhm3gMi8AZl3ZLmkYpblHegFBIefJ146V0EV88eGU8R8P
         +SaRwsp5eIs28JLQPJcaaEYRN7wTvhKOkxIhUC3A0QFRhEOXxTuSPaxP0DlkgsXLuGE6
         LXGtqYE0G2nx+alCScFUanN890FSubcUydiLZ+Londy7VGOR6u2/D+SBk3DlqJ0QfkLu
         6FVpGED37Vnqa1ilICyH98fbYzYi1sxShN/vnO3oNmZU3daVZu/5pNgcgRBaSKsBdIP9
         OKRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BvZ08b/3oavcBvAkiQZyOMSmbVmpa+4ihUtpMl+Uc6w=;
        fh=gl5iGXOh3gCvS/KTgR/6TtuGZRustvC1yNSZPlWHOwQ=;
        b=HLVUKZXURZ26icoVj1pY0pjQ8jS75j3RMLgxdgLwsNvBdqjOXLuIZNaGufUc8DEaUu
         /VvAuhsXImahyhk2lrNZtzKUQTJ8mxA9+x99zDUIlCDZht412SbBV3Dvqp58tGuofwrt
         HHwot9rtjCkIIhByJe4wVh05NthWoppzbbC9duhZzeom8TMHpxYKxKc+ApfmGkJkfFPn
         oSl0JxGApmeEpfY1B69YRdIcdMtU5DWoCGzTSRTjd3bMN0+NBMYcQhGSLVSF7PNrmAeK
         12NZFzLshu6U0KWIiPF8yxzl8T5cGmoobqKk+Wrm/QvUk/PntLLB/WGOgkexQ5rjv0cj
         T9qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tyy3S4z9;
       spf=pass (google.com: domain of 35fhwzqykcrcfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=35FHWZQYKCRcFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id hb25-20020a056870781900b0021e5223aee5si919890oab.4.2024.02.21.11.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 35fhwzqykcrcfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5efe82b835fso156746327b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVYqtv6CN8DbzAiEqlFegjWNjn6HoCJdp59JokfKXTsG0YLGYIiTao7ahHZCsFiNkoj8dvK01ns4K39NkrNu5O32l2h6++F13JMKw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:7956:0:b0:607:c633:2997 with SMTP id
 u83-20020a817956000000b00607c6332997mr4958335ywc.5.1708544484752; Wed, 21 Feb
 2024 11:41:24 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:26 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-14-surenb@google.com>
Subject: [PATCH v4 13/36] lib: prevent module unloading if memory is not freed
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
 header.i=@google.com header.s=20230601 header.b=tyy3S4z9;       spf=pass
 (google.com: domain of 35fhwzqykcrcfhe1ay3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=35FHWZQYKCRcFHE1Ay3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--surenb.bounces.google.com;
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
index f400ba076cc7..658b631e76ad 100644
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
@@ -1230,20 +1234,23 @@ static void free_mod_mem(struct module *mod)
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
@@ -1285,7 +1292,7 @@ static void free_module(struct module *mod)
 	kfree(mod->args);
 	percpu_modfree(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, unload_codetags);
 }
 
 void *__symbol_get(const char *symbol)
@@ -2298,7 +2305,7 @@ static int move_module(struct module *mod, struct load_info *info)
 	return 0;
 out_enomem:
 	for (t--; t >= 0; t--)
-		module_memory_free(mod->mem[t].base, t);
+		module_memory_free(mod->mem[t].base, t, true);
 	return ret;
 }
 
@@ -2428,7 +2435,7 @@ static void module_deallocate(struct module *mod, struct load_info *info)
 	percpu_modfree(mod);
 	module_arch_freeing_init(mod);
 
-	free_mod_mem(mod);
+	free_mod_mem(mod, true);
 }
 
 int __weak module_finalize(const Elf_Ehdr *hdr,
diff --git a/lib/codetag.c b/lib/codetag.c
index 9af22648dbfa..b13412ca57cc 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -5,6 +5,7 @@
 #include <linux/module.h>
 #include <linux/seq_buf.h>
 #include <linux/slab.h>
+#include <linux/vmalloc.h>
 
 struct codetag_type {
 	struct list_head link;
@@ -239,12 +240,13 @@ void codetag_load_module(struct module *mod)
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
@@ -261,7 +263,8 @@ void codetag_unload_module(struct module *mod)
 		}
 		if (found) {
 			if (cttype->desc.module_unload)
-				cttype->desc.module_unload(cttype, cmod);
+				if (!cttype->desc.module_unload(cttype, cmod))
+					unload_ok = false;
 
 			cttype->count -= range_size(cttype, &cmod->range);
 			idr_remove(&cttype->mod_idr, mod_id);
@@ -270,4 +273,6 @@ void codetag_unload_module(struct module *mod)
 		up_write(&cttype->mod_lock);
 	}
 	mutex_unlock(&codetag_lock);
+
+	return unload_ok;
 }
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-14-surenb%40google.com.
