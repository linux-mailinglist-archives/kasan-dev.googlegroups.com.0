Return-Path: <kasan-dev+bncBC7OD3FKWUERBUFAVKXAMGQES3BB3YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3378C851FEA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:34 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-6e09015f862sf335683b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774033; cv=pass;
        d=google.com; s=arc-20160816;
        b=xEPTUwr39Dte5QP/deO3rOggo1LvhP5H/dQ7+qc8UQyr+xRBcWFYoSdwpkaQegsMFP
         hhysoKsByuKPz8pCFbtgyDbMA3fQnm81fUO7OB1lnBFnROQoqWkwYgPNa5iuQnhw1783
         4Axo63emu0AjcDBvdd+RZVvyDvM1HKUs/3NRxHTAgpW4BNYFOHtyV/ZbYeIDuEZKYC6b
         IyLWBYVeoWhb9/00GnpzraY+CtCAunSEuD+lha1ljfTbWNGoKEn6RXlCnOTuKWbVmkGT
         1Fx8QBg89rWU+VW8dqODp1VZWw9pfT915upe80LbpAogGmceFoWEPcMOyvQGkbZ38qmT
         xtng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zn2mSaENcAxY1r97CTDN/XkLmkYC40gnJWXGKQ7Lvwc=;
        fh=Ff2ZUG68xxh5365bi6WUojAa72aWng/UFmSYax6/PwE=;
        b=nLfVXhpDI7VsfVV/GfsgD+OYz4gVVzSttJq3qWmqT8QNrQgOJTDW5aZ+sBzYoEgHS6
         9MIoJlWa6fLt+cWqv03vLa+m21IXMEEMuOg4lKkGY/Pv+ubI28ZPOwFxGaNdk2pmm0Pw
         RhOJe04AUpRwPRKT+F/jJVRE5nClq3bl5yvPxM1y8PV4MNdXY8evkpidvr5anQ+rma/P
         RUE8jIJsRmYGn/PIwt9S4qO10aQqJFrUfOSAlgSvvFe+61oTO8VIKE0bcxUnVG9jqDSY
         KbyT2HNo2ybG9+JEEJ46iSxil1+iYTGoaYtoHwadtFbQAe3EWIFFcWqkXlk9uxhexthh
         8kpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T+UPKFzh;
       spf=pass (google.com: domain of 3tpdkzqykcc0bdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3TpDKZQYKCc0BDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774033; x=1708378833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zn2mSaENcAxY1r97CTDN/XkLmkYC40gnJWXGKQ7Lvwc=;
        b=AEREkjNo/gm/M8vtOgtKkK56cdgCbNQeaWfzlsC3zLvApEuUClhdkWrj4lWoplIRgL
         G56mqPrDXn1VcJPFab2Jg+sqsEv8OqbHcl1hhbXPsrykJWw03EOn+M5ggRs1Wo709L2C
         eBE2crzkOezq/ii2nr1pyJfO14f4MvVWLKhKTrfL/Pz19GVvtDzr85QXWn+rdo6fABvH
         XGQW46nW2wrN6AElsv65VCg5bE+CpKvd5o2ihqp9z/MbkYGPy1STcx+tMJU77vXYnZmz
         b5+iBG3aM4PKs2PD6wJHo1asJCGeuTH+tiy5wG5rj9qEBIM4ppXzhJ/9yzMjc8GQFg5l
         wtEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774033; x=1708378833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zn2mSaENcAxY1r97CTDN/XkLmkYC40gnJWXGKQ7Lvwc=;
        b=YdSBq1YCKG8YA1YKsHxIsaNHh/RiF+QNDT9Tte3cxI5JEsUJ5yVICteEUjxMc0TdTA
         /Byvl5aN9B2f+EcfCup797Pct7l3MkCZ/jvOVTEAfkmfQYnjAmBnwcGGZrKuGfyr8LBi
         30VHTTILrt2cZdGWLfOZE0zLvTmVBgYu6BRpbp6rElbsWfPcyexv8E46xvHaFsBkq9i8
         /eTiIb0FFmqpw2MiKSys85hlnyUIsSqhy9i0x8+Hg4cC18jSk3EFguHEEAt239ozUGxO
         oTOJSs2l0gWey6KG44Yc/pW8Befnm0W+nYKOFy0DDE4BfPOdUJu1wVSCjGtFWuV8uCNF
         jh7g==
X-Forwarded-Encrypted: i=2; AJvYcCW4cYJhS7H/OTO6/SYMN5jhQOA/hu3BqJd1G0vGPySamh+jFdlaF6zNW686JFrBuL8tSmbgEnZlD3FhqT+z2cWWCVtP8nqqWA==
X-Gm-Message-State: AOJu0YyVX9gdJPogU9AedhesX4Z4btmyqTd/xaXLdQ/GHecuktbQikNA
	dFU3wJ9peW+opQ+HQ1c/wWvIrN3uAniz7S5H0UkowVT7rIJPzYuV
X-Google-Smtp-Source: AGHT+IEasps2NH0v2mSCVANG73SFAglpiIgf/RcxG7rl9SV0uoba4Hwpn7ivMr5KflXoCN0KNQg2/Q==
X-Received: by 2002:a05:6a20:d04a:b0:19c:7b2b:6cbf with SMTP id hv10-20020a056a20d04a00b0019c7b2b6cbfmr8023199pzb.47.1707774032824;
        Mon, 12 Feb 2024 13:40:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4c9a:b0:6e0:8a5e:af46 with SMTP id
 eb26-20020a056a004c9a00b006e08a5eaf46ls1947208pfb.0.-pod-prod-02-us; Mon, 12
 Feb 2024 13:40:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXa6ozBGe43TfVIlXJ1Yk9275ZRuU/aH1YC2DEyWlEGzWF9lE2IkQMFOyXNNZOeUlDKXmddlcTgf5apdfSvPBrL0by6WS6JjnsgSw==
X-Received: by 2002:a05:6a20:93a6:b0:1a0:5c37:9201 with SMTP id x38-20020a056a2093a600b001a05c379201mr2027822pzh.52.1707774031762;
        Mon, 12 Feb 2024 13:40:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774031; cv=none;
        d=google.com; s=arc-20160816;
        b=ZGCZZ+GcPvB1Ns3A7voYbii7F1K/R6r0xlR5dNAN3dG65Jmsz4FbbchCrwhpcXkDP4
         LIndEHgR1bfqCn1rJgngOPraIyKajiQadqwIX5syd3GnitzfA6Br8MyOd61FLjJuN5te
         AOMLW/zUdb9HbP3ahcju6raqMM43USSfByfC1ESAcHF64+UMdXBi9jQavj+z+fZJFCqN
         h3ESArie4hpyBtiM7DKjp/kGIYBLD3z2z9t7xtjwvEdatwRixpC+BSc/pkcCOKCHhdWD
         EAoy4viIGF+62GblnOXRIknp+lPAEcSRLkWm2vpRC68PRbIvSuaaF12F/+u0rLVDPXnD
         tPmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=X07z1RjJe29sLMh5N/vKSXU8uipRKYcH64glAbq+0r0=;
        fh=Tw3TXF62GzkqeoxOSj5qlz1oTYzhFEjBLTFOGioUlRM=;
        b=nzc8oClqNzTmSPgcnwPlL1xj9dn5rrtCmerRSKgFPS76sxVT/GKwEDJmP4N+l5w3JQ
         9A/pdBsfD2Pe5sQlZg7HB2YOyeHoNlqTL6NS80K+YClrXRflTgEsnBdSkGYjThoqpev4
         14r2YgkcX9iIQxNV58m0iN6fpp2kE+Yhs0jvIgoopU3rDzJu8gV09AneKV3KqmjrQsCE
         heXFyHuZ3dPxEU2bwg8QCHKVeSweaI7iHJ/qtu7TaYkIbsnUDrsVpLyhuhqBXwQEz/zl
         blebA4gXIUhsQE8Lv3hBiIYimJFdmvZxUL1QTo/7qnqcoREH5QgSfmdLys53v0A1H9ZO
         T/rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T+UPKFzh;
       spf=pass (google.com: domain of 3tpdkzqykcc0bdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3TpDKZQYKCc0BDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCU1FJKoBKby/QPHcRkgfiJwZLgH5nqpX3zJkZgUTsOB8t0BtYKERYqBhXh/vGETQvUmOV+OsMbMo2/Nia68Nj55iFQQUTGMLN1RaA==
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p6-20020a625b06000000b006e06c8a8c7esi1189769pfb.1.2024.02.12.13.40.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tpdkzqykcc0bdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dbf618042daso364724276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWLqfZrfSHs1dICERp3iM8hoFznIkCyi1G0BZXW2j2Oy3WIlT4KbL2cU9Qa6CR0D1+V/bfDfPebgH0NPAgOia0Le42kXgk8YIQnCQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a05:6902:709:b0:dc7:59d9:7b46 with SMTP id
 k9-20020a056902070900b00dc759d97b46mr291099ybt.3.1707774030642; Mon, 12 Feb
 2024 13:40:30 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:13 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-28-surenb@google.com>
Subject: [PATCH v3 27/35] mm: percpu: Add codetag reference into pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b=T+UPKFzh;       spf=pass
 (google.com: domain of 3tpdkzqykcc0bdax6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3TpDKZQYKCc0BDAx6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--surenb.bounces.google.com;
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

To store codetag for every per-cpu allocation, a codetag reference is
embedded into pcpuobj_ext when CONFIG_MEM_ALLOC_PROFILING=y. Hooks to
use the newly introduced codetag are added.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/percpu-internal.h | 11 +++++++++--
 mm/percpu.c          | 26 ++++++++++++++++++++++++++
 2 files changed, 35 insertions(+), 2 deletions(-)

diff --git a/mm/percpu-internal.h b/mm/percpu-internal.h
index e62d582f4bf3..7e42f0ca3b7b 100644
--- a/mm/percpu-internal.h
+++ b/mm/percpu-internal.h
@@ -36,9 +36,12 @@ struct pcpuobj_ext {
 #ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup	*cgroup;
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref	tag;
+#endif
 };
 
-#ifdef CONFIG_MEMCG_KMEM
+#if defined(CONFIG_MEMCG_KMEM) || defined(CONFIG_MEM_ALLOC_PROFILING)
 #define NEED_PCPUOBJ_EXT
 #endif
 
@@ -86,7 +89,11 @@ struct pcpu_chunk {
 
 static inline bool need_pcpuobj_ext(void)
 {
-	return !mem_cgroup_kmem_disabled();
+	if (IS_ENABLED(CONFIG_MEM_ALLOC_PROFILING))
+		return true;
+	if (!mem_cgroup_kmem_disabled())
+		return true;
+	return false;
 }
 
 extern spinlock_t pcpu_lock;
diff --git a/mm/percpu.c b/mm/percpu.c
index 2e5edaad9cc3..578531ea1f43 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1699,6 +1699,32 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+static void pcpu_alloc_tag_alloc_hook(struct pcpu_chunk *chunk, int off,
+				      size_t size)
+{
+	if (mem_alloc_profiling_enabled() && likely(chunk->obj_exts)) {
+		alloc_tag_add(&chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].tag,
+			      current->alloc_tag, size);
+	}
+}
+
+static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
+{
+	if (mem_alloc_profiling_enabled() && likely(chunk->obj_exts))
+		alloc_tag_sub_noalloc(&chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].tag, size);
+}
+#else
+static void pcpu_alloc_tag_alloc_hook(struct pcpu_chunk *chunk, int off,
+				      size_t size)
+{
+}
+
+static void pcpu_alloc_tag_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
+{
+}
+#endif
+
 /**
  * pcpu_alloc - the percpu allocator
  * @size: size of area to allocate in bytes
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-28-surenb%40google.com.
