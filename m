Return-Path: <kasan-dev+bncBC7OD3FKWUERBCMW36UQMGQEWQ4P26Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 14C5B7D5277
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:55 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-357bbf7bd57sf47550775ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155274; cv=pass;
        d=google.com; s=arc-20160816;
        b=If/b8NkImXxPgWDo2xF3+DgTHj83dvs89oL7DfO0UD9x8MYORlOsLIpPh+vEFYvEub
         QwGzUvtgTZS+u27K/f3wC2riS6EqZyKDBG9oGoIuyffo/lqHsK2fgCeIw4g1Q0Ao3LMX
         sDREsfb8skRwegIuCAVYw7xdRQNsqviFkU0QoEH5roIHJ6Nv4wNPB3zZ+BU32sZ9muG+
         pPT/Y+72x3RyXCbWfm28U02YfDifZlZ5njL/CsW0oiC8RY64OIh+S5QkP2V2FsDTlSm4
         L8pdRRcyvqDXPk+hLJrDNMqJwahFvDFPQ2JC+HJ9xfbFO0CLAXQv/2nMWNq5JtW9DsER
         tKRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YWNS/T7XsJsysNuMqPO+VQ/SrSHnThiuIB6bSizwwjs=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=criLw/UzPPDXwafAsZQGUpXs+rMPrkQLvtnRoB/+lN1Rsw24D2vITSb/oUG2ZA0rhT
         5oDLalhwItFstDq9NRPWeIDzTIxGVQikIjo6FPp11NJcjOncUznoGYvK1uCYycPS/VQ3
         zhYIxbTvGdFa0irPH7YFbz0oG1QdttWZg8IBm9G8wnn8cKjvd1Ig2CGkYr8KeNPbE780
         0fqIH1qcLZ8301WKAQsFiZBCL+LMDEB3YnvvoQcs2vSud0cVk0/15RDRkPBiaqTtOvSz
         kquh/UczuwEFGZWEV1WlbzlKa/66Ps+RtIaGwi0SeOwsvz0bx5gbSAalB+hd/rh0Vwzu
         cDog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xeRpeoqI;
       spf=pass (google.com: domain of 3ccs3zqykca4gifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ccs3ZQYKCa4gifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155274; x=1698760074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YWNS/T7XsJsysNuMqPO+VQ/SrSHnThiuIB6bSizwwjs=;
        b=KdHAhdYcHEC2ESiAOGxiFLjO4jhlRw5WaUFR6pxcd9S+ZguGYxtVEddc4qlJwKKuZy
         Ce/KAbXnAjj+VNsj5auGUDfNxw9lGWTXHCTneamTHgyhWb5B7D45bJBRl8bKgelxcE2r
         RFbIC+gu8trMUwgnSGH5bgoHuEXumvg0msKFrS3m/O6Gw0Ndhzdm0HYvasNVM9PZeFYf
         Ni/S/cUTaVO740qwD2/X+tV3n+jdBvcTqkv5dAcuzEkjHq8cFVbgTBepgpSK9ca/57DO
         rXw++lUVj9Vh/bInz7zJHrKOjP+m3ypZ9WdBJYQ49OXQG8nZIvReSsp1E5b/lt5elIKS
         75Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155274; x=1698760074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YWNS/T7XsJsysNuMqPO+VQ/SrSHnThiuIB6bSizwwjs=;
        b=klXxXZ+4CcFvtzQ+eZ0DLy61jpirUzzCjRAvMRvK2VL+KRJvCAm/EFHBtpiEnPnXgc
         6OYGojAvE2POXFmPfR3MYftT9NB/E4nUHvUZ6ZDCZlapHiMFN18QSGdJj2SS9apCPYcx
         uGmWZ9g7DEMPPEl2C5/kCu7OtjAemWctIobzBkaw75czM9eHteg5iHUppu0Gwd+BOdQW
         lS6s6n7iD+1NKZflpQwEdfJpFCkOPnSVzYm8Qmd8j2ZIePsbW/lvj8wPSrohYQpNvenM
         ONvUEUs52CNA6vMKmhGjXPBs5STBQnLs07xHhoztreNU9BWGeiZPuKFD9R48yk8wMWp7
         2qtg==
X-Gm-Message-State: AOJu0YwzWjhhksWG2VdQdak9Ikp93ajvKWMinnWIPH/3HJc2muJiUKSu
	rdJiFHFqpJOt5vpzcMMZDSw=
X-Google-Smtp-Source: AGHT+IFzrUjcNsbLqPRiYKEaCIh8qO/scxX4srr/Uj1Op+PjyFIt+cepHtFUV5jmhs0lHd8swAUGeQ==
X-Received: by 2002:a05:6e02:156a:b0:357:e783:eb8c with SMTP id k10-20020a056e02156a00b00357e783eb8cmr3764397ilu.3.1698155273957;
        Tue, 24 Oct 2023 06:47:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1be9:b0:349:aa0:9696 with SMTP id
 y9-20020a056e021be900b003490aa09696ls2543954ilv.1.-pod-prod-04-us; Tue, 24
 Oct 2023 06:47:53 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a27:b0:34c:f2cb:b2c with SMTP id g7-20020a056e021a2700b0034cf2cb0b2cmr15319382ile.19.1698155273397;
        Tue, 24 Oct 2023 06:47:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155273; cv=none;
        d=google.com; s=arc-20160816;
        b=ifuN9IeNh4vnxrYB3/K5DCuh4jHw12SbMQmwm7K2lzxIEuQmClTzEfeb/Y0qjpbAob
         hkcsA5WiNwWIXeE5dG4rKxRtOFz9JlCbRdSl3LoCCnxJJ4rsuyv5cpOCRBiZqZGTRVy8
         Yx/2/tb4wBkZ5GdSCpHK4tMdRtjjdPsj718yrRf/wuqXDwLWbjGZ2hPQqpHBHoSjE31/
         WYSq4igXTSVmwd3xW2F/tyhoHArY5XFM4nMigCBnBYSKKHzXY/mK+16uC35i5Oof1Yni
         KzzKdal4OlgP3xw56FHkp1ddml0c0oRsxf0683hcBURiAMlDSx10PO+/tu9lfVCVuFNS
         hxHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=XaYZQGGekpRYWKofo5TkfncjTV9EZU0daTUjtZ9a4ek=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=FcgPDeJAIXsG+di+CN9GLuyxtSSOr5Qv5wQAZr7ZwLspm8zZ/kife6QeHqVYwxP6qH
         c8DZbJ6Oc0kA1Gpccfxce47ScpskQyMuF1ZnhQqArct/eQzbZ0inp+M/dS1fV0hleyzw
         Az5J9xDNnZUT5FuNZrfFnft+6dR0WyxqeNsc/PWoHnQOWqo05rF7uTylSLatH4Eq+KOG
         2GIf3+o9j6HSHhnRlAZoaPgb1ryeuvXng6tG4V9o4nnHuASM0QkA5eKpw3Iig/LP9wQq
         Vmt1YvCYK+7axdJn70TLqD29+/EBG5H5cQguzNuJUmIH2YDprKCjtJUm75tvKFemXpzR
         yysw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xeRpeoqI;
       spf=pass (google.com: domain of 3ccs3zqykca4gifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ccs3ZQYKCa4gifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id o5-20020a92d385000000b00350fd9a47f9si84525ilo.5.2023.10.24.06.47.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ccs3zqykca4gifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9cad450d5fso5175419276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:53 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:168c:b0:d9a:e6ae:ddb7 with SMTP id
 bx12-20020a056902168c00b00d9ae6aeddb7mr221434ybb.7.1698155273022; Tue, 24 Oct
 2023 06:47:53 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:29 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-33-surenb@google.com>
Subject: [PATCH v2 32/39] arm64: Fix circular header dependency
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
 header.i=@google.com header.s=20230601 header.b=xeRpeoqI;       spf=pass
 (google.com: domain of 3ccs3zqykca4gifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Ccs3ZQYKCa4gifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Replace linux/percpu.h include with asm/percpu.h to avoid circular
dependency.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/arm64/include/asm/spectre.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/spectre.h b/arch/arm64/include/asm/spectre.h
index 9cc501450486..75e837753772 100644
--- a/arch/arm64/include/asm/spectre.h
+++ b/arch/arm64/include/asm/spectre.h
@@ -13,8 +13,8 @@
 #define __BP_HARDEN_HYP_VECS_SZ	((BP_HARDEN_EL2_SLOTS - 1) * SZ_2K)
 
 #ifndef __ASSEMBLY__
-
-#include <linux/percpu.h>
+#include <linux/smp.h>
+#include <asm/percpu.h>
 
 #include <asm/cpufeature.h>
 #include <asm/virt.h>
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-33-surenb%40google.com.
