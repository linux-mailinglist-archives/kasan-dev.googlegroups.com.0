Return-Path: <kasan-dev+bncBC7OD3FKWUERBZ6E6GXQMGQECVRJZ3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A2BE885DBD
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:00 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-22984cd61fdsf854972fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039079; cv=pass;
        d=google.com; s=arc-20160816;
        b=biw0VsPTkScLcao0KUwGrxOtLS5ZTyD1NFq9jJdhT24rudGftdyvftDg/YpskW28wO
         6jKMMzpvPDChVFvdV+aIxGVIxiLMKlhheX7rraItlLJieRAjI4ALinJpHkYj8tQUyQk4
         fy1LiQIWo4cINqs9l/wgg7USIiIxybx+hlqMLL0bYusDcHrD46lUSQTiYZbveUN0aIoP
         gJzIPae7NZOxym4bwp+Kh5BuvLahLnlJF9br3wDCEMHvXwLBmJaJpg91QKtH4FOH4Std
         jCz41lXp2rkzqYf593Ty4HYw1g9I/EX72UuoYAtOwlHrkK8DW1QE0F0pyQA7M6gzAsqk
         T+5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LsCxegjIpenIfEnKnS5xckknGXoADd1l7/t6ECLOLNs=;
        fh=yteXa6+FwSVoSP4aZjLQZeiTyXfjjienWDUgNikOh94=;
        b=Auk53R3Wz7Qg9Qk5eYq4SvVoMaLJW1WzPHu2worOjRj9CMjxeaKUNTUneC8ZY106Kc
         ajcrlG0tHMoazGQhqddK+WTKHb7tJ37v1Hb3g66xm8NS+HK8jt5RWAEKJkDLG0vNaCah
         hUkakh1s60wexaSSvm8tqcD1AaCRyOiLnPsdlxjVNLr2iLmKj/fYp8VfKSeD7eX+KhTA
         P0j22O5alkhaCeqOayXXI1wdGgaNzcgjSdSRn4buU7eKdFT1wACVDMIeUyd5qQE3n1cc
         ScAGG/e3g6ym/ypkeYkg/X6x9HmLm4TJABXu78B9BY1DNn1fubkuzPajuA15fxuGAb3a
         jDwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fy7wbNei;
       spf=pass (google.com: domain of 3zwl8zqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZWL8ZQYKCVICEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039079; x=1711643879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LsCxegjIpenIfEnKnS5xckknGXoADd1l7/t6ECLOLNs=;
        b=POEcjrUfaoMVr7LTbl4OwlwA5EVdCOgiAThehX2fXdTHMp4j/OZCLqdW93WYVV6VRO
         xIMV+ti8je14SjqH71+Tf8c7j4TvcJE2QR077NwylPrT/VKJ082c5RtHXZbGCTI3FJwf
         dF6xhusp1bpzokOqSzdG7TOgXNDckM5vSbCNlwvze9gcxdywJPle+O0iP/5tn34bmS+p
         R161gtXXCZmRF+uXrcFI8SrKjiGO9bJsRLRTa9O8hFuR76LsRnah8/Euqe0tR9ZEpG8W
         INBovPckKxtZhXT7rAk9zNNWYKVKHT3JDaP5RaqyKZWtRTECK3m8Jj4tc75w5+vgCF/Z
         diCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039079; x=1711643879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LsCxegjIpenIfEnKnS5xckknGXoADd1l7/t6ECLOLNs=;
        b=DgwpkVZVb/wYOIhRSMt5aO+njKRZyw5zeXHeXBR1AmAkJg4n8VYMs6Yw7K3wXMbqvk
         jbVRcz9QzWWenvYdZL3beGGMWcGPA5B3flDgy/9EIIQelchnwDgAhBX7DgLaJK1WK3A2
         gBjdtKJo1QUT2DwgN45FvRipx0BHQwPVTnqqPmsDCw/XnXhb/dtqeAJccDMX34njEazb
         I0asveinh+g310Hc+cTZz+otg69SDp8aYXtnE+TOZKgtPcxjNkD2zWDHhUg5OwnAz+th
         2eITTBdH5KegBypvBoquY42xjocZTMzjablNNge/HtHkzxLiFQXHMJ7lBwphcoceRrl5
         H3+g==
X-Forwarded-Encrypted: i=2; AJvYcCXSt9x3EKEplmvrQCa8Uo/hgbAYf0FnSMjzqGMjUnowpzoL8hLQ4IjhnqJDOerA8u8nkdj/toQs0eWuWYJWpH3vm2h8hBvpCg==
X-Gm-Message-State: AOJu0YyDytwskQq2acE29QSWrYygGPna8kEq/2ptBajZyeqQgC5+REVh
	BwPhoUuQksrX0zJgs9zYx1+Ufnqpmx3eLBSVwBz2vDNhx5PWjbQ3
X-Google-Smtp-Source: AGHT+IHlzNqw4d7El9mjz+JReyJzoSghxsgJgnmQIilQF+rrYIulCOtPGq0BQOVZwlXSv6ZjX2qp0Q==
X-Received: by 2002:a05:6870:f80e:b0:222:8961:43fa with SMTP id fr14-20020a056870f80e00b00222896143famr18014oab.15.1711039079483;
        Thu, 21 Mar 2024 09:37:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e78d:b0:222:5ca1:6a93 with SMTP id
 qb13-20020a056871e78d00b002225ca16a93ls475364oac.0.-pod-prod-00-us; Thu, 21
 Mar 2024 09:37:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSdmJnKLZ3LBihfCJ0Lg9tp/KLxaag6xjKFJ5KK3g1xyqkP099A8Rps6lieGa8UbzUJwiGZVbsc6dhbWcdwru7/BRvbS4b7nDp0A==
X-Received: by 2002:a05:6870:3755:b0:229:bc65:7332 with SMTP id a21-20020a056870375500b00229bc657332mr25428oak.5.1711039078208;
        Thu, 21 Mar 2024 09:37:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039078; cv=none;
        d=google.com; s=arc-20160816;
        b=fBfrJUhVgFqXTCtS2IITYxaOjlAtrdzKLSpmGusQf83c7bswnKEyrqChYPAKabP625
         UOuNajGewci5FYIjKXvEe9eg0NbKIpJFvGvUDKQPMm8SGczzlTC0A8Xzs2ZfRRwM9/gB
         OxeTNdYYa1ca1GueLpdd5qdBVADG5ZWYSuqfztSjvHHVkjcNP7Gx6KbO/9yewGdOnevM
         jbv5d93iW5TgaujS1fePwbJA0nTz8UIJo0EMSGxp3XFT71q1V60BU19snaGZRHloHcHl
         QpnPis63/EeHRUwmRN9bVSPU/m1ncWnsUEmc1uGv4szNpwDjcMnWcPMO2/KG4GwKGJrT
         +BVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=pOwNrbZCC43nJVxac3Uw9hAvg9K+bdh2+QxQ9H95ZLk=;
        fh=+Ix0RWQ5KpsLQMCgh6YhWYdZmd3yZBGgyZslw2lWnKk=;
        b=yxRUUAPX3zhi7KZwRqCv2FnVHBmh1tZxCfp6AHvORULHvlSrvsPajDyqOYVh5LdC6I
         CqUZnhrwtUVlwfzamsx1Q8AETiqhYUksHVyPH6sgHAXLDi1KMeeo7oAR4pl7DEhYsQpE
         eZJtkf5l/b5wx1Z75OJZAtlNLnbB4F0ofk+mM4DiYawI2gXxtrn0IVNP9qBuhzExd5kE
         bDeaRc9swD8TTnhr5KjlBR7kv7JOQChM5NprnnTLQhqfL2swDIpZ15duU1EDXECmXGYp
         Wa0nCKeA+NpVa5Lk0NuAsq6hMsy8VH1uHVqSSIwg0C6Rk/gk+jIYHi/rqh0s8zmhD0M1
         gdZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fy7wbNei;
       spf=pass (google.com: domain of 3zwl8zqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZWL8ZQYKCVICEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id oo6-20020a0568715a8600b00221d92ba892si27269oac.4.2024.03.21.09.37.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zwl8zqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dbf216080f5so1808631276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPd0ct3s/pO0mu8J8UGaNDDMhyTOFA4eB3wO7irh7e3MiMuEGjt4yPbPMfQqzd0YAqHWDZCedplvFf1OTze+vKSvjdRJfdqbebVg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1004:b0:dc7:5aad:8965 with SMTP id
 w4-20020a056902100400b00dc75aad8965mr5894352ybt.0.1711039077542; Thu, 21 Mar
 2024 09:37:57 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:44 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-23-surenb@google.com>
Subject: [PATCH v6 22/37] lib: add codetag reference into slabobj_ext
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
 header.i=@google.com header.s=20230601 header.b=fy7wbNei;       spf=pass
 (google.com: domain of 3zwl8zqykcviceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZWL8ZQYKCVICEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
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

To store code tag for every slab object, a codetag reference is embedded
into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=y.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/memcontrol.h | 5 +++++
 lib/Kconfig.debug          | 1 +
 2 files changed, 6 insertions(+)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 12afc2647cf0..24a6df30be49 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -1653,7 +1653,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_data_t *pgdat, int order,
  * if MEMCG_DATA_OBJEXTS is set.
  */
 struct slabobj_ext {
+#ifdef CONFIG_MEMCG_KMEM
 	struct obj_cgroup *objcg;
+#endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	union codetag_ref ref;
+#endif
 } __aligned(8);
 
 static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_item idx)
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index ca2c466056d5..dd44118e7337 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -979,6 +979,7 @@ config MEM_ALLOC_PROFILING
 	depends on !DEBUG_FORCE_WEAK_PER_CPU
 	select CODE_TAGGING
 	select PAGE_EXTENSION
+	select SLAB_OBJ_EXT
 	help
 	  Track allocation source code and record total allocation size
 	  initiated at that code location. The mechanism can be used to track
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-23-surenb%40google.com.
