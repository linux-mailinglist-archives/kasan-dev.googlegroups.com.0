Return-Path: <kasan-dev+bncBC7OD3FKWUERBBNE3GXAMGQE2ATR7FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 537A185E794
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:59 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-5c5c8ef7d0dsf6267096a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544518; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/9c9i73cQVf2GfTNaHDpJSZcPDJmSBvc7xQ29hfxSDs477tVc6Hb0jv5gDx9HBqoo
         tmDL31LmFIfIhxTOgO7gbDVFhJz3R2Y2Xn6oA/18aH+BmRletm/do3xiphkQNGbK388v
         kALUeKJhuJd6qLJmbxpo7a+9yg5JfjF4PL8l7RerLucJBQXlQ9f2C+JzKHvOPhv04k8f
         vjMKqrSoBdkH8cAECqg0qu6yM1fCbCwBA3bSj6BQSXkxjja9K8k4r7mV+sHQ9sFs9pR/
         IK+EPa1pHQ7nLrTUTyFbi+4k7Q+DY8K27E2qVhnYtwEM3RSSNXnY4SP65BpIyiAonIcX
         W/Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9Rau1MgtKixOIaFpROatrzSm/lwasEmBhETuvJ5eCD8=;
        fh=YDFwpwynKhQCTkLThkKirEK2x6+eeeyz1GnDp98EY9Y=;
        b=rOEnLCX7CfP5ftcTU0i4ejYCUimbg+qdH6ZPsDLo7R30Kf0Ji7399d/c8GR+ZmEZlD
         sZXlXS83sAbvku+Adxh6NW9waRlOPa27lE4mGacvdkaPXfcpECP9kQrlBYTIPnFj3Ssd
         vnoyasHyO6kGh/xnZ6Na/Xz5sShpHV3/m8RHWqlclW4bm+dRs7MeDHveV+epIMIr8dGN
         4E3yKBle071MCe++0yKa1UJsT0+BIRH4NwZesoKGPOcQ4n+LFkLt1ISO0L2PIWgTzWfC
         yp2m3+5GJJpZ9KCd7z7UhRuwqTkPoyuHTVQTUm7OQTnB0A6Wlc4jbR2e9/LcLozhSSL7
         zmjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="wm+s/2FB";
       spf=pass (google.com: domain of 3a1lwzqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3A1LWZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544518; x=1709149318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9Rau1MgtKixOIaFpROatrzSm/lwasEmBhETuvJ5eCD8=;
        b=Ae3LTT/vIbwZwaCWlvmKCfSIapck0mijWD2uTRvGpW/hYCg3pUDm2hPFP8WSGciR2H
         b3bnYlqB9+cFYzXmP6XU0AQpp2yfxtX8JMJVs2cKl0oaRqYJGdTm9ezoNY+hEEgXpYzM
         wqvUT2VtsS9VZMF270BWi0J6BqOLihnWyR0IKDvHMPKXrW6Rde/B4qCHaByXMTVzEzuc
         Z0XBSOLX46EMtn18iinoGS2iru9UYG40jPbssHNYYk8LCJeZRziRVeOTpfRqF8PsWp6X
         +TP0votOZmugbEUMA6IBnOc2ZYt30Hrqiq9kU1u8oFGcvezKIFBSku2i9VX2kcbp+IO4
         DucQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544518; x=1709149318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9Rau1MgtKixOIaFpROatrzSm/lwasEmBhETuvJ5eCD8=;
        b=k6KhTF60ETp7HDJ4JnryC0AXTZdovneVnve2dl+VC4qb4eXjLfF4adtm8YITAcPuj9
         j+PxHzHjXBKYttvX1CXoJISuAbvKoDfo97uezUdrrlMF/P6nGI05RzIvGVx269qJm5dQ
         tI9XDgMIeg2uRmBKStbAQHXbkUQI4/mqaiB1cLv6xe7fTbb955EdKpfhqNCvotq7207c
         MD5f1uuplByLoyDFhFJ/0FXbruNxZtK6fIcy3x6NG34F3I81/jer+q9BY+dtyRGbTQPF
         gbql7ifMut2t4REyoB7BWNeeTySxNsvqityp1Sf5ntO1kVodmxYBFvyWa8tK3Vvajfug
         zLdg==
X-Forwarded-Encrypted: i=2; AJvYcCU8NZJfeEfgfuiOWeNefYUo+sKAIjOyCq6IVtBeuGZOyWf1MUeFOnr6HgNoXzJ1IkjxGJ0Lu0qgUPEF5qaBKif0mL3rg+xA6w==
X-Gm-Message-State: AOJu0YzrOxn14QvFZZGBtaaCIYj6pFbnmxNmWGk9g8jnVfIThRbfCpQA
	o62GN6tYs8/TvL2qafxYsPhppm4BKCFbjWHoQeEuRIzQUkR1jjCR
X-Google-Smtp-Source: AGHT+IFPt5DWH1/wuMStkeZoWqURuHF79P8oc+MLPJqeviCbSa0rDpI9IS70/0fGSWvsFAZIu0i6eQ==
X-Received: by 2002:a17:90a:6343:b0:299:4ac2:150b with SMTP id v3-20020a17090a634300b002994ac2150bmr9832992pjs.4.1708544517955;
        Wed, 21 Feb 2024 11:41:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:5111:b0:299:7c4f:efe8 with SMTP id
 sc17-20020a17090b511100b002997c4fefe8ls2237145pjb.2.-pod-prod-01-us; Wed, 21
 Feb 2024 11:41:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXI4i04RS/zIOaYKxj/e7RXEzwL6yWCUHmqf0zA2tMaSa16VuavipYreJK9juE7/yV70H9sjcrqwgWeY27MqxDZhcdakMsvZOqaZw==
X-Received: by 2002:a17:90a:304f:b0:299:17dc:ba26 with SMTP id q15-20020a17090a304f00b0029917dcba26mr14384589pjl.32.1708544516842;
        Wed, 21 Feb 2024 11:41:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544516; cv=none;
        d=google.com; s=arc-20160816;
        b=dmjdbsdKxyrDTGVy2oWAd653juPmPaDZU+MlzkrYE+y7irWCb0Cxpw2eUiMeFWBKlA
         fcNMgiXq7kXLzSYR1vye+sU/vlo3maCHlxkRGiJz2aLw1TPDi9o8vYSc3FPKs73KRPS1
         w/JCMP8HxJGxD85DHZC9ryiY7rLg9lHiV6Mn+xyOdRNIhhgdRTLpM+MXvJ4HSD6Wpg8c
         0kZg13CAVi5i2Ib3ClFqCXa5yPcX1q7FxbywESCmohes+a20yxDm+3cEOPR3rGOlb8Ez
         ALhViaDJq3bZfr04aYXmLdnr/s4NcJWtH40Yxy34m71seExdqiyE7ezHJJ5O61Ll21D3
         8tmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uHb4H3aBf7zVkxjSohmSP0JQMXLGrYpxjhF/b1cUoKA=;
        fh=F4tWCFhIVwFdScVD03YtliI3OP+oEV2nzvzH1k1CzHk=;
        b=jzOimEDFXqnAHRu70aoUxVrnD95tfRRUz6pi1dOteMkFsjMK0z62THeOxx9w+Vq9RX
         eP61Uhl38TlbvfdqTvtJLrsizc9JW6DcpkfFj5WjyVM5jS3J8QEghdtCLCRQXc8JL8g1
         bpW0o5WYfy3DV8NmZ7I7MAV5/m7RKDJXAxI0D08n76hZLIWa4YpX1eZzHznH38t9TZnS
         yXlKF+Gf7AqlIUNVD0i6PR5oUTyERrP0c9WZU6rZvct2x1YfgNGdKCy5npt0rV/zcH8I
         EHHZWa1hdlwRKiT34e3usF7XPxz3etn1UhX6ULLVM7bMmNv4oD0M081grPqN0U60PJxj
         5mtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="wm+s/2FB";
       spf=pass (google.com: domain of 3a1lwzqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3A1LWZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id e3-20020a17090a9a8300b00298d35696d6si188213pjp.0.2024.02.21.11.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a1lwzqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6088fa18619so9946987b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXvN4OSsKIxw9/110lXMSoAc6HYgF5TsEW5uZsLM7843Ixav9Gbyvs2JAnAoDGGY6bFSLi9lGrlGbNm4vVYlK3OaeSpPYyjjXH1kg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a0d:d5d7:0:b0:607:9bfd:d0bc with SMTP id
 x206-20020a0dd5d7000000b006079bfdd0bcmr3270706ywd.7.1708544515839; Wed, 21
 Feb 2024 11:41:55 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:40 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-28-surenb@google.com>
Subject: [PATCH v4 27/36] mm: percpu: Add codetag reference into pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b="wm+s/2FB";       spf=pass
 (google.com: domain of 3a1lwzqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3A1LWZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-28-surenb%40google.com.
