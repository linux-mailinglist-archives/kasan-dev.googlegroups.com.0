Return-Path: <kasan-dev+bncBC7OD3FKWUERBBMW36UQMGQESKSTXJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id F3D2D7D5270
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:50 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-66cfda4c191sf66317966d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155270; cv=pass;
        d=google.com; s=arc-20160816;
        b=GVC/BHRXZtUx+Jx3gh98xwALMVfodUX6vrkIK7NzCZSU4l/W6jNpcZerf4f1x2rTPo
         OIVEPDAurpRXZbtL4Ou972qLAreCRqVaq0P1XVJv+xjyH0RfLjnCqIHE3ZKjvV7wN/cB
         hLnA+m7oHgiKU/DDIRkuC3w1NPCnNe0vORTK+sbhNtG/5e+d9FCFBLAlU5fNTO9ajt4I
         xu6AdqNIN6V0R/dpg0jQC9YWyVQc8HIZlgfLu2xK1T+sAV+vfANbkaPJDnvy7MYtaJ6+
         GpsZdg4qRZSt1yEydLLdyehjbo2mB/7E0SPKUbtk8/L7SHsCdwq7Yf1/QnUWhT1zGMJ1
         XyxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zmvuXW/cBK9zYr0xIGw724ZOZZTaBr/1NDj9WI8xdcA=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Y/oZue12IY0OKLl6j5skVEubHSXadqI1yX1SPR2KP93EMTjDbiRmNHjGJgFdkS3bS0
         qnR3sV6jjt3phwyDqWv8ntGbmeGiq1jmzVOX7LIm8Gt6Avuyln18G2fw4ZkkYadGHQ7d
         LYoVC+gV9kZxYMfwEFhO4x/UFXgaxmoYH4hd1elqWqVqFHv8a8jiWQxWEcmioNeMNtRA
         yllltamDNK6tOJI59Z1orI8htIGhJxlH9jBoVaGwH4F71P32b3FJDMDYe16tx/FLuHI5
         IVkunvaoe6rsxkxsZipOGRUxDIQQkX46UDqko3LjYSN0sNVOnnZ1X9F+PqTQ8nYJxaCP
         D4UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ttobo9bt;
       spf=pass (google.com: domain of 3bms3zqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3BMs3ZQYKCakbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155270; x=1698760070; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zmvuXW/cBK9zYr0xIGw724ZOZZTaBr/1NDj9WI8xdcA=;
        b=ddxi6Bq87i4t5aJtmvmxKprHCVtfkkSfLvqWwAwLfpnX0pv2b2mNwgk6c7Zifi5VR3
         rQlY3uEhRfEIAi1i2S6thIkNHSbBuqFMZ7UzsO1OgRtSzWf0tjPaRhH3oYvNnAUBpsxk
         Yz5sKkL3WsAubIfH0KjgxltmZGFfT1reaTU6zzP6+ldMHCQvELyDdgMBU+Eqv62hFPe8
         B5xalc1BV7KKzbitgpGseVA4oaZR0bAQp+LHXCYEno38MBbb2TfoX0U6JIgeCN4Hxxxd
         WTMo1JyGPrR+0lPiH8vpckRJSL0JqpfbDpISQTxi15azkkZdxwD6r9DL0hBGt3hLSP9E
         d2Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155270; x=1698760070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zmvuXW/cBK9zYr0xIGw724ZOZZTaBr/1NDj9WI8xdcA=;
        b=EPruDqpQxyuZPTy9nm9QLnJCc3c19pb8bQ1tE92i5Bf24H7kejU+YZKdBthMHyQ5R/
         hYZTZ0kT2tP5cp1joNZO6CsFZOyNv3E9UrCv3/tCz0XB1Xi2v7ct4/KqFlfLHMrXH8g0
         oDcCv1giLE073Qal1gNC3DA229o261Vw/wT0SaD4HUWyG0PaxMdnzJvcTweIpshPCwXd
         q3RL+bsdf4rLGrYwSxmZQFfI002GXuKBdLi/0kMAVpY3x/yuVOKgc9csvdzh2PKdKI9G
         Wg7AOmUxVxYHpwzBIRsbXOCiHqI/GcrHl3xSXMiU9rC2s4UrJtzjAJbbUfjeUiTWxm0b
         WlVQ==
X-Gm-Message-State: AOJu0Yxem1YlQaPnuDlR0WecZYhzXrWiK1gXDN8JQxo6Xrtfs9KsBU5+
	cKUeh+f893imjGpLyvxrTM4=
X-Google-Smtp-Source: AGHT+IEnqdx4dLjk4K4OU12VHroKeTs8eobGtloxgqeVMtBMJcmSbWzcJlnhiMS7jPymb1OONfqo0Q==
X-Received: by 2002:a05:6214:c8d:b0:66d:1100:7b82 with SMTP id r13-20020a0562140c8d00b0066d11007b82mr12903755qvr.18.1698155269823;
        Tue, 24 Oct 2023 06:47:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:55e4:0:b0:65b:1c2b:3bb0 with SMTP id bu4-20020ad455e4000000b0065b1c2b3bb0ls3978217qvb.2.-pod-prod-06-us;
 Tue, 24 Oct 2023 06:47:49 -0700 (PDT)
X-Received: by 2002:a1f:a8c9:0:b0:49e:2145:1651 with SMTP id r192-20020a1fa8c9000000b0049e21451651mr9219370vke.6.1698155268923;
        Tue, 24 Oct 2023 06:47:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155268; cv=none;
        d=google.com; s=arc-20160816;
        b=B4LVl/OSFz7Et9SK/4SwrxnPxNo1ypZtK4NBw3I7KBj8CTcpbP8VcnvT6hGjePi1Mc
         fwtshYA+mUWJNYaeOKo8vEfFBWVyAtVmHv5ZcnF3Y7KfI59SOfFPTNaUqwCoiA592jlZ
         I1sM2nsLYMMz6U1gKd96FCYO43O86fNxrpSqTOnfqMtQyn1pSr71YOfrBc364Ydp7dYa
         U3wvcPCODkHSlZNOr6zJr1np2mOvsBx1GbQaoZElgJBmtlY89IMHnQ2QCxsdvfSIMQP2
         sXw30ahMd5dlQwBsv8+uK95U3KPpXgwMKtw9fBD6IaW3inYgR9Cxug0IZXu6hZoYw7Zc
         9CWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=HuI3Xrhprruhc52//OZX/xia3QtNu4igKL3qfHIbn+g=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=iJbxdz9rEmunAFtsgV/bphbihbaQOWWk6vGoRaeqRsktlyKZ6aTnjKhfhggIAhsxhW
         1twBzQhzA5vLNFdfIIIh9w7rRtmtY2LVbMYTb/L6gXGcpLeMgWfSZwJ88qG9qKVrGvHE
         soyzGun075TnFHwd0RaE2wmHBs2EEvINTx/petMao+Uyj9q4hzKIyAJ25CXHvfPPNl4p
         gVcxDfT/mLuP3offotm7dc4/i7/LMhhybLCazaDY/Tz+T92++FO1kh+CurVvfS9TU6xj
         jM7NujrOlXKqusBoiCXGibgLk2qVkCTXbD+sBb7q8EerTuaQ99wAd0CyzFI3qPYDUIYU
         XRQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ttobo9bt;
       spf=pass (google.com: domain of 3bms3zqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3BMs3ZQYKCakbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id 14-20020a0561220b4e00b0049d20faf956si337397vko.3.2023.10.24.06.47.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bms3zqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-da03c5ae220so671093276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:48 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:ad41:0:b0:da0:6216:7990 with SMTP id
 l1-20020a25ad41000000b00da062167990mr3869ybe.3.1698155268465; Tue, 24 Oct
 2023 06:47:48 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:27 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-31-surenb@google.com>
Subject: [PATCH v2 30/39] mm: percpu: Add codetag reference into pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b=Ttobo9bt;       spf=pass
 (google.com: domain of 3bms3zqykcakbdanwkpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3BMs3ZQYKCakbdaNWKPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--surenb.bounces.google.com;
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
index 5a6202acffa3..002ee5d38fd5 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -1701,6 +1701,32 @@ static void pcpu_memcg_free_hook(struct pcpu_chunk *chunk, int off, size_t size)
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-31-surenb%40google.com.
