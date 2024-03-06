Return-Path: <kasan-dev+bncBC7OD3FKWUERBKXKUKXQMGQEH6KBUFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 91049873E9D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:47 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-dced704f17csf12187180276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749546; cv=pass;
        d=google.com; s=arc-20160816;
        b=yHsfjJxGk3XHbhI6CPebwhxhIsk9niMkceu898dbnFzdJEAtEAoLILqv8JmaXCluMs
         8ybcl1nPxAe2WcMiLIYE/FCMX6/D6YN4RASFl+5AUSamfXZtkc0OGOMnxXJKdYIJuc7e
         U7UYQZUauc3SoU59Vjo74pklznj8hrZTnOdmWqqcaq7GZDOoMtK/KxHwPh6OrsKtUto5
         oaSBpA6u3ALqJUSRIx2oantAi0c2Uwz6KsfbxQ/QdiHPO2QL57obDb61qypGhmXWRP4e
         DpPOAgXgoRALFhpPIDQQxMOx8h/nVC9QzFMS8jklvOpwFDYWQlAtgnyHordXfOlvU5jL
         6nyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AdR5Y91pbAgqViWeimGVQRiY0pEQDusFDkim5yoYK54=;
        fh=R6D2u63eQjpc9SojQW+VL/DkDDzhClGLMujkpYMyQ/k=;
        b=zZ9qHq8taoGwYVX1wtb2jaHjsfzUPOQ1q7DMr8kh9B6gz5vMSLqYmVmV9lPu9n0cc8
         cSFXrbVh0C8HF6IXSAxhl76wZJ1y61keMMMHVacrzaT9adKcoJ2+WPpgS5S6dmbPskft
         p2NGv2FgKNSppbYy+K9NT0dAKMW8letoYWaQbLk0AnRL5Hw6PFGlcx5OeiMeRDG8Arjy
         +bZu4BYBGQyAwyzq2VG75U2hnGy5pzCzpzqseSCydcgLqXoFi5c4yL44f2Fu2+1kHk8n
         IeUg/TgFIVA/n7Q06aHjDR2VOPO+Z7iv8fUGS/lr0hnnH3MkiX8wv1DuDgYYqtYzE19H
         o+Rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gZvAt4RW;
       spf=pass (google.com: domain of 3kbxozqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KbXoZQYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749546; x=1710354346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AdR5Y91pbAgqViWeimGVQRiY0pEQDusFDkim5yoYK54=;
        b=LoWvj3CO0mBZe6O3ntEPhtpkPOPUZ7sX0GrfzwIoFi9beiHUYxMSzp6MJKt/s6kzBF
         jiwM9XivEFq/AuOTStbQMtapcabP3ZJlQ3jqqkAT8GdQNkpMOKLiPKJhI+uDl/ZvfryL
         4/6enKiT4ZN7xuDjQHSC/r6OMI+Q5j3GyQFQwIUJFXYX92YMq0Ig14KwTWUJqjd8LMid
         Qm78fgcTmBWvGXVfvVMRv3vSjUJ1AbJE6IVewjv/QGtY859oJzDD/Qo5EUBszMVMck/O
         vj9VU+t1ODEbUIGlm5X6ZoCC+U3HcotAKttZDYpc+cglNUc2G2JDZYi0jq6Gg2b8MWy7
         sAYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749546; x=1710354346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AdR5Y91pbAgqViWeimGVQRiY0pEQDusFDkim5yoYK54=;
        b=GUq0wX3Fqpl0es41Px7ZthcNYPhl0rn6jGMJzsquhj40viH/5WlDI4J+dGJYU6xWME
         pF9PVhmYHBvmBDIovRnZ6p+Vs0vVpv9FKdV5ielmPHI+iQ7Rkt7y2kcUsjtaNIHIQmLt
         GjjP/3jhgvPd/TfIbp9XfWo0UEFULzsiVJNBNqTTEqVowAro28Br0yS+91/5vHBDI0sM
         J3u8FRg6vnL53fUQjSzTlUPsfNpu/I0UlXHv6Z7C2ZidMacBFgNaRFu3tSKxloR56l85
         MXu6rSRNqBmNTXDViRPg3cvlyhvB99GP1qR3aCHUElEiZUHEPwNhaxI2qW4nQrxLimAG
         3LDQ==
X-Forwarded-Encrypted: i=2; AJvYcCV+rTX4yhjZrVPOeLjXZtxqBzpP3Z55KvmORpxrNUawPWY1/okg8mD8Wj56t46ITvaR9pQDqnP+CVsJiuauGFevtUEV0Ig7PQ==
X-Gm-Message-State: AOJu0YwrWXXQR6wVV7J1sVqUocHKwU7ep3m1j/RmOJALewwmSielEgNV
	PIitza5YvTwLDZQjjARkRbJ8Lb1LD1R3H4PDhGjYAID16RyJ1GD4
X-Google-Smtp-Source: AGHT+IEvf8Wue+kf2ftKPeYt1l+MH9Q+HQTddhn75aGUcZQ7NPB92KookA1CslNu69bItv5BD1O5FA==
X-Received: by 2002:a25:e20a:0:b0:dc7:443d:d9da with SMTP id h10-20020a25e20a000000b00dc7443dd9damr14180983ybe.4.1709749546309;
        Wed, 06 Mar 2024 10:25:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ae8d:0:b0:dcb:b370:7d0c with SMTP id b13-20020a25ae8d000000b00dcbb3707d0cls83655ybj.1.-pod-prod-02-us;
 Wed, 06 Mar 2024 10:25:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWmrexz5RSVoAUo720WN9TJkIkrDUtYzI7i4pHTD8RoJ5S7XeK8wUjJH/YEsJUL8QFhUC8D99Hv1+IPRNkxAXhe22zUHQo5EeOxKQ==
X-Received: by 2002:a0d:e904:0:b0:609:8649:f4e7 with SMTP id s4-20020a0de904000000b006098649f4e7mr16193766ywe.3.1709749545654;
        Wed, 06 Mar 2024 10:25:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749545; cv=none;
        d=google.com; s=arc-20160816;
        b=CgVXC9G5I5dHt2UvCZ6ZWS7N62WB30XRKERwB7tgefK6FKgPULvFgn3LCH5cvuj++O
         6BtwNyL9buUH5swVV9htu+EsPuMM3WL8Z3O1mVbITE1OnJyzDzn4XnIEM7fOVO27E1E8
         pdkaTNbMvqLxSAy0/+OENK+9B14U5z8It9Gs37buCVyhjio1hyA5o440JT8QRB9jSKfP
         uI1yUFnooKB+wCyrzuqkSFG/fG6GFYkzEndUa/SiIieXGxBDn0lgr2CbDiDVQc3PQGf0
         k1NBsV6t0BHl0Igz7vBI7QH55gGyXYT/AtsxCjOcW7a+vgywUwalVb+4ymlEIz2ra4LK
         gfYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uTM4daMpjhNnHNsVheTGd2gBho3MSeHG2jrz4iVybwI=;
        fh=5O8085vjNb4owySdDKrD3eWXR3E8htOvGF9j8hbiS5w=;
        b=f3oiu8pkkHdkw8VTNsuEHuukaIYS7pjp3V+pdQRrIMlqz4Wi2A1I9u5+OZH4ltmy6O
         FmxBustoz6qLfC/PPFr0nr84/eFB2gOWfduID0a6ktMmISa/2eFYQa3pZe5e8zXfLWc2
         WGXvcr4IwRcbyPgh/CMgiyjYSlT6H577fC2XCJjtujMG1V2XU64HeuXt/dThZ3hj64t2
         5LynH5RzNdjaC+Garo40CXJQqyoe/+s2Dsa0d9+14uHZh92X7pUXbLseqJUq/Fv0Tw+6
         6bhrYtVbm+Q74vTVk6raS/I+Zlb32qrf9rgtKSyKiU7OmksD+mjBqJQSRHFvLVuUpFjl
         8Fng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gZvAt4RW;
       spf=pass (google.com: domain of 3kbxozqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KbXoZQYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id y200-20020a0dd6d1000000b00609da8cc7ebsi176121ywd.3.2024.03.06.10.25.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kbxozqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-609db871b90so321197b3.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVsgQUoltxrepSYpj0Uq6qtVQ6cQDgz+3MJq9qXyCMjlpf+apygK2DQ6JRbMAA8IeFydihifx3bO9uwwa24IqsmWpMoGn9ZHKwUaw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:e18:b0:609:247a:bdc5 with SMTP id
 cp24-20020a05690c0e1800b00609247abdc5mr4410842ywb.4.1709749545152; Wed, 06
 Mar 2024 10:25:45 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:26 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-29-surenb@google.com>
Subject: [PATCH v5 28/37] mm: percpu: Add codetag reference into pcpuobj_ext
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
 header.i=@google.com header.s=20230601 header.b=gZvAt4RW;       spf=pass
 (google.com: domain of 3kbxozqykcwwceboxlqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KbXoZQYKCWwcebOXLQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--surenb.bounces.google.com;
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
index 2e5edaad9cc3..90e9e4004ac9 100644
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
+		alloc_tag_sub(&chunk->obj_exts[off >> PCPU_MIN_ALLOC_SHIFT].tag, size);
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-29-surenb%40google.com.
