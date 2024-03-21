Return-Path: <kasan-dev+bncBC7OD3FKWUERB5GE6GXQMGQEVZBJWKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E371885DC7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:13 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5a4b8bad9aesf1009308eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039092; cv=pass;
        d=google.com; s=arc-20160816;
        b=S4BhHVbr4nSfMvAc/kRpi6b8CWQWjk5ykhr0BHrHlhSB++NcA78p34PqG/bB0P+9q6
         k9RAQAH+S92JHFosb27dv72tVXlUwp0hs4xu7r7zYIvisZ3Z1GEta5+bFznzpq9UJJP7
         FoebJH1GlndLfwXFI2+vtkGPDj2CRlUMuMwvUigszBFcbVT2ic1s0sLDLKF5xjUsHzaT
         04LQMSvQt05bUZTn8rVqbxeqyA0BoAt2W2kepHX9y4eVptbtlxIHnk9a5SvjXHZFQvba
         6ADBWthZnj/bchwkvL3DFXFBjMbSIQHx1kyXUvaPQ6WQvq2ja2yCT827u95jmreCqkUZ
         xkpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7Dw9QyZbGykYLu17nOVrZ7+yB6+SbPxDZCFasxQR92o=;
        fh=txRagAORLPq+Nh9MoZlG/MBjzsgrQO/lADYsDmhIGHg=;
        b=X2QZk6q2iRBkfMguoy70a9b51m2hpuGHVZCadGyKrGN0s/YNRX8nGP6mCUJEauBOos
         xroWKoiPsWQMrH7IlkauPeBzKd+CQ2ENhqAl+K+0CCmEV7rdlL9m2L3+aD3U/mAJEIfR
         IYUO/iB30lVUphedyCs/Sne4LkoSeCQjkDYd03wth220DVI9zETUsEVyisMvoHFCRr3E
         RwYXPXBY4U9l7TIAvp8nvPnJ1c1WksSUOylijC5GGurbAHYBmMjOJE6/VmOdO/AAM8n8
         FlROx9XT/d+ACqKA+wpFkp2k5v9fGtPbFUXL297bsHvE6Vy/+8byZx4ELqzmPuVcBpmQ
         HaMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=twG9Qzp4;
       spf=pass (google.com: domain of 3cml8zqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3cmL8ZQYKCV8PROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039092; x=1711643892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7Dw9QyZbGykYLu17nOVrZ7+yB6+SbPxDZCFasxQR92o=;
        b=v3YhSjobhJNBojkygtXcLLFygGATeQMVIb76gwLCPoYNT+W6wSM5RJ8Z9twk4XB9Af
         tYxJO6F6M+ByDPuJ0v8Cpvd3Vjal1iwEf6afFT3Ih4S9dOHuZ+bSlyf1pPSSP7r6S6dY
         ResK0JgceDFhZN6lKIAilwTDe14sP6/xo97bb4vp2YWkYzf6SYG+Jd64R7gwqtDdMbuE
         /Kzx4s2I/p61cUayJmzMFVCGt36WeJvQUrxHN1yUKlQ+k1u11uZzJkNeSvHkBaRV0gCi
         hgsRZkv25nZ6KOM8pnQOUV8Cn3lvHcvq05L2KjL7RglLs1BnmOb64XXFy5G2yE18IGTq
         GKkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039092; x=1711643892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Dw9QyZbGykYLu17nOVrZ7+yB6+SbPxDZCFasxQR92o=;
        b=khZ70YOBFR2I4uGEJEX7Ae8R6nZSZnbs4lTOPjby7muFQ24qUhU8vphlZN6VTREObD
         aCMDpPlDfJmsEbXranwpdh9dX6wC1dJrD4OYyWuXQycXSKWgyk3Fi4ptp4U94Mr/qWF+
         x03Ph4yImOEMYDSdRyFckcgUZ5bd2jcyr0LL+HEspl0VnEFSQ4P93IU7fCQDoYYdy1Mw
         IAHReYZDAa4cudj55IOkis5jq5nD+HmuaKHfc3e2IY1vztJVrQeT2tWWRKLO8J5uCV0S
         8t3xiMJY2++lTCChKtopNI5i9dssqDVcuyXWu6dk2jufyI/H90nquQMGiYWY0OaMmCK6
         UIZA==
X-Forwarded-Encrypted: i=2; AJvYcCV0dd6r+mjPCrue5XMbUyt8bQwa9mfrwJ38narLVAg0xmTl4otM55wbeoeu1F/6IQpqF4B3DHJpF7+7ze3IM32TNuJuPpPzwQ==
X-Gm-Message-State: AOJu0Ywxqeeo+9TcLcuH9oh0EzFKNh7j19ju5L2vDpoJo0amRgP/Ixb6
	dfBwcyHy8yc1vr9jkWd9nWjFd0Q5kE1kH4kusXsXHKhSOVDJE2H6
X-Google-Smtp-Source: AGHT+IEIxsoJUGm8Sx5fdwSce0E67czYkjfuhO7zLX5Nn0Ad5Or8MbGoo1n0Tqsc3zCeoTDvVvwgPQ==
X-Received: by 2002:a05:6820:308a:b0:5a4:f5b6:4eca with SMTP id eu10-20020a056820308a00b005a4f5b64ecamr12645oob.7.1711039092147;
        Thu, 21 Mar 2024 09:38:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b44b:0:b0:5a4:905d:743f with SMTP id h11-20020a4ab44b000000b005a4905d743fls1127765ooo.1.-pod-prod-05-us;
 Thu, 21 Mar 2024 09:38:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWElnG5I4faE3zKSfpt1fn+3yPKfwqlt8s61OIX7jwXMbNU+cUlCoqxp+Gop8XXGJNKqBp7UF90jPrL1sKYvADyZJBrjz5PIL2YUw==
X-Received: by 2002:a9d:6e92:0:b0:6e5:78c:45d2 with SMTP id a18-20020a9d6e92000000b006e5078c45d2mr2851693otr.8.1711039091144;
        Thu, 21 Mar 2024 09:38:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039091; cv=none;
        d=google.com; s=arc-20160816;
        b=noLAwyTyBsecquXMX1Hm0znNdgLuRiDatHjUzcL4guLoAakAtvK7qKeSaPOWXPbqRl
         JFxO5TXz08dMV0SMIFkVZeVqUqFbtKR4g4humEwHDp0T1/NYIklL7AY/ldwjarV0+vQu
         zl6tLNadhYk+YJ3CVMwcwSXN35iJzBe7mOAbAxGq7MqZQnhuJ8FwRNv8e57vwMBbGbaH
         HM+SDTh5qDDglbQHA3rSGKjrv7t58VdppmOw7kDVVef1xTQkMlOwL6vJDkgXrdOrvbmB
         STNZtJnNP3nhEbImmVtUhB2auCQowx8obkSgp05L3G1AchTfhP+fCuHO9tTbJKk5tegH
         Av9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=krRMCxbEdPvR0gpNvdmt+1GzNi+HHBvoijzlHbN4rmY=;
        fh=gKqfhuvVGbBkwvhT7thM4zUratIGAubJryma7bLspUY=;
        b=RRc0MGn+esahGu16ZrCHNF6JRWZl0Zdm6Hbkgl8zw9usLAmkH/YoBa32Y6dDHGDiIB
         i8AaltHOTc7rAXIro1TPTLvLv2c3Ie7VEtIKemK3Xoml9+On+95FtOrMFq6IeahcrflP
         nOcF7pEwPC6i0JTzJbQFbeJwU9AUUY2FTMy7uH6ERr5b/t0QX739tK58oGu97Hhj8IOz
         +JfBJ2s9L6RtLQgG9EgZb40rOyZ+rXK8jDvQxmkUmNj1Mngqw/rAZx+BO96qZg9q3lor
         rBU02RZPiCehaVdi0UT6UayyVhRtCyrC1T+66mhsj/U4NDWdJVj02ORVsXiCH+2Bt5Tj
         E4ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=twG9Qzp4;
       spf=pass (google.com: domain of 3cml8zqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3cmL8ZQYKCV8PROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id ee14-20020a0568306f0e00b006e6839fcce8si29152otb.0.2024.03.21.09.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cml8zqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60a0a5bf550so21851007b3.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0fz46XZ17HcJ2CXs3Wdb30Zo5/IpNJWXWNxMXgWAvV5oy6RP2SdStOm2nfGNlYWeqKGiNL+BHpMCDw/E59Lg4ZqWxo6pCg3JB5g==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:2506:b0:dd1:390a:51e8 with SMTP id
 dt6-20020a056902250600b00dd1390a51e8mr2395872ybb.10.1711039090742; Thu, 21
 Mar 2024 09:38:10 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:50 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-29-surenb@google.com>
Subject: [PATCH v6 28/37] mm: percpu: Add codetag reference into pcpuobj_ext
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=twG9Qzp4;       spf=pass
 (google.com: domain of 3cml8zqykcv8probk8dlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3cmL8ZQYKCV8PROBK8DLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--surenb.bounces.google.com;
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-29-surenb%40google.com.
