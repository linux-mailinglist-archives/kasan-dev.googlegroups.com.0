Return-Path: <kasan-dev+bncBC7OD3FKWUERBAPKUKXQMGQEZJ7DF3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id D7AF9873E7A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:06 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-dc746178515sf2058544276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749506; cv=pass;
        d=google.com; s=arc-20160816;
        b=kr+z22KGqE+r4klgeRn8sunrTgvPYdBpj8rspbMwWN7WK4DnChW8bunsEpijOpGQPW
         sxkQZbUG51lZpWSTsR9A//vx2gnPyZUxRSGuLgjXm/z7FoXj3ggV4OjGBlAWMtRUuWGW
         w3eiG+wUvKDgF2n+Y+gc9iTzRci3l4QAG+yxIo/PkxH+UCoTTcAxtvU4JWnH3vFuPemW
         PN74E3hIEnIcTvDUmuoacOslNTgvg0cS7lN38BvvVwtHpZjsMtJpBx4lAiswN8VpY0bW
         ggg7IpHPtcVV7/tTYao1v1lsxyg+G8j7iKO+6/bHzdDbijTD+3XpcLY3Yy7C05WcvGDi
         u5Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yQ7fNbg/BZxXHLDCgoO3bHlmWfZqSw0yc75a7RNy5LA=;
        fh=rO2koLtieokwD+Fo1gXUfS+wTidAyPI9tOXNhxYOXB4=;
        b=pUXn7HEXy+5YUmLLaLCisyS9brzvTMoVUKCwX+7pwaTab2hwxo20PryoltEQFIOyUm
         MJDkDXmlW065WenwIEv8a6XKqUVHqrCuE5y3jhChJxzg6QN11Ni8XLmvmpTcNPLPe/B0
         tl/xqRg+uQ47aKo2Mx38okzUsRVxVWJB8bUSJzmC4wS4vJSHO7qxT2l/2mFUtS9/5svc
         Rlmn/R7PdPPN00wnwMHNuOdPL9m+Y9o143cmWZ3DHSUX7Q14KAnZTSSe6zB/FPe2zBkG
         s7svqDhMtSB3XJtykn5nSTqdUOF4A6KpYvaIYYmlGMLExjqq4sQf3x337L8MF5NPUxPc
         lh2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0PImvBy5;
       spf=pass (google.com: domain of 3alxozqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ALXoZQYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749506; x=1710354306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yQ7fNbg/BZxXHLDCgoO3bHlmWfZqSw0yc75a7RNy5LA=;
        b=uOSy3mIs1g5aWo/7eiQLPdHjotWlcrTu2sfuWOoMyP8ycDiIfisN4YgprpULS836f/
         beKUYOFizlBtE9m+aFZocunHmJ99wC7qk3VVHgC3Zu5a0MqXn4Xq546pOUBQUsxWmdy+
         JFoCcO94aJi3iYNFZPG55bVgVJFLN4V/JUGKExmHZ51X3sFIZpsz5P/COnULR3j5j23V
         M3/5i/SzMnIB9XeGNDRsfA55v1+TnhMrUKSYYPxmXULNElV96EV3ML1HpgAfBFF6CiKW
         o0ZLyYGnk6Sz49DHz/WsqIY+pihZIuh/CEBVe4r1HgLfxORz2ZEp8XjzrSj32TIB3HYj
         neaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749506; x=1710354306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yQ7fNbg/BZxXHLDCgoO3bHlmWfZqSw0yc75a7RNy5LA=;
        b=QVlCs1i5Ou+NwprP72nfW4X+EU0gOX5l8rRxtUuW6H7/RYlo0pR4QwLuuunG+HBFqh
         dq2lrHZSHi/zpnKfP+TFHAvz7n+FO2y74dkynOfxlJ8XLkPh2otgVvicQyGleQEG1Kes
         W6erh4GQrkWk+LN5MybNjDF9OgNzZ8NJEXvumXnQv4atCuIqcmIs3Fv8QYwiQ77MtTCI
         FL4wMRgTCQiVe5NqaW1IjmrswnKNXIUGeNBtWdWiTaq28tlo/EvlaOC0YZAUMbMyueC8
         aSI9JgFdcD/osTHRHcuQfIHRnFpaGlLkD3cxQ/6yFxLwCMzhUilxul+Fi6pWGYpL97MT
         rcnQ==
X-Forwarded-Encrypted: i=2; AJvYcCUDYJ+MfBv4k6JgwhUvHShRKO/+pjGBZX7jEuPwHX3EVt1j81K4u/wR2vNYwoPndvPS8H+C0yBeWzX2+nZVO1xqC7B4+qyjGg==
X-Gm-Message-State: AOJu0YyPVw15Uj0HqBS+dX2nVDLt4kEbyicbun2mbeVYva9fcMNVV3H3
	WQExNHfiOIxDwxVGGgLcw7yoCjHAvgFJQoA2fFWLBP84mq9S9Mrj
X-Google-Smtp-Source: AGHT+IGO/g5tNPh1VKHcJnd6ZGMfj3O93yIwhCiPywLken3IAi3t7h2LALo/kTp6FdeilC4HpUZE9Q==
X-Received: by 2002:a25:f30f:0:b0:dcc:744d:b485 with SMTP id c15-20020a25f30f000000b00dcc744db485mr12307381ybs.33.1709749505727;
        Wed, 06 Mar 2024 10:25:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab65:0:b0:dcc:4b24:c0dd with SMTP id u92-20020a25ab65000000b00dcc4b24c0ddls111370ybi.0.-pod-prod-08-us;
 Wed, 06 Mar 2024 10:25:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlhmgaofSzTWL3wh0WpXP7YI2tG7kZiGsn8ga3RNkjeoMqMfP/rz7QoqXpLGiAnX/txvxbqrcONz5Nu4Hr8/6NfqbTzwADZYJFPw==
X-Received: by 2002:a05:6902:2306:b0:dc7:496e:42e1 with SMTP id do6-20020a056902230600b00dc7496e42e1mr14428937ybb.51.1709749504744;
        Wed, 06 Mar 2024 10:25:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749504; cv=none;
        d=google.com; s=arc-20160816;
        b=xB452m0SJliwO5a7Mz0QlpU4teew16uB2vBPeSu9pTT6CZNBkSMP4bj6FyEO9Mjkvo
         B7ZC74JL0/dSC+TEFiNsk+OKAxCgmp5hLCepLUt11EVGq3cEeG5BLLz77aIFWOi8gQfi
         BSJSoCU6vX/AhX20o/fO87kkFMJPdaim3TwZ8FBT2RXcgJp6d43ThUBqlWj6MMntaH/K
         QGm+DoF93Q9xhrWKXpD0FOBL1BRS5WpNSsWQkZS7RvX32bHw+PrsHFKM3E6TzDjAjPPe
         Ag38MnBVVjEKKWqIG+JxPZqQnvlM7bHR94VIkKycSJhfOyjDpeR379Z7PPM//+HKaMrN
         p2ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WRHB/CGZyDTcWTfW8LE9qYpRlSe4g56CTtmfKB0L28A=;
        fh=xaUIfSIlTWYISLG7zFpLM8fOYIBdd/4XJ16iGV3Kes0=;
        b=LiYcsrRqCsDUOVz+w3mG3vPu19CzNvL8AIWtQgAoH38dIpAbAGee5xvjUqL2kfWAsV
         qkbJ5v0uOoZi33YoGNZedkOBpRD6+6Q2tUZ6PYSZ54CcaIJXWrCtRU6STYZzVnsJ1zkI
         urHE64CLW2N0vijGME4I9PEl2vDPuwMTOiRKYXdJ+wu3TUTgyYgnCNst4O+lgSu7yUWZ
         +GHefzUOKxP5uXtX3mDd28HqRlWgLx+eWiEapGTHSOb8iarhd3qf2YjVWecI1m/pfa3o
         coYhOM+PsZRCyNVutnCLsxmqo9bKoKfH2HHf2KPXCRLoIVbtOCaoWaF4HZES0rMf5P8H
         KPlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0PImvBy5;
       spf=pass (google.com: domain of 3alxozqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ALXoZQYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w2-20020a25df02000000b00dc619c1f82fsi1223433ybg.4.2024.03.06.10.25.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3alxozqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60810219282so548397b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXaXrSb9Q7el3BYG7MxdzPO1ZNl88yRO/VHY5QskpG4Ira3uSky6zQJrvRlOVKnuHt7XJ1yEIu1TUNNel+yESRg9clKM0/4N961aA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:ed3:b0:609:3c46:1885 with SMTP id
 cs19-20020a05690c0ed300b006093c461885mr3528012ywb.10.1709749504202; Wed, 06
 Mar 2024 10:25:04 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:07 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-10-surenb@google.com>
Subject: [PATCH v5 09/37] slab: objext: introduce objext_flags as extension to page_memcg_data_flags
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
 header.i=@google.com header.s=20230601 header.b=0PImvBy5;       spf=pass
 (google.com: domain of 3alxozqykcumxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ALXoZQYKCUMxzwjsglttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--surenb.bounces.google.com;
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

Introduce objext_flags to store additional objext flags unrelated to memcg.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/memcontrol.h | 29 ++++++++++++++++++++++-------
 mm/slab.h                  |  5 +----
 2 files changed, 23 insertions(+), 11 deletions(-)

diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
index 9a731523000d..7709fc3f8f5f 100644
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -357,7 +357,22 @@ enum page_memcg_data_flags {
 	__NR_MEMCG_DATA_FLAGS  = (1UL << 2),
 };
 
-#define MEMCG_DATA_FLAGS_MASK (__NR_MEMCG_DATA_FLAGS - 1)
+#define __FIRST_OBJEXT_FLAG	__NR_MEMCG_DATA_FLAGS
+
+#else /* CONFIG_MEMCG */
+
+#define __FIRST_OBJEXT_FLAG	(1UL << 0)
+
+#endif /* CONFIG_MEMCG */
+
+enum objext_flags {
+	/* the next bit after the last actual flag */
+	__NR_OBJEXTS_FLAGS  = __FIRST_OBJEXT_FLAG,
+};
+
+#define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
+
+#ifdef CONFIG_MEMCG
 
 static inline bool folio_memcg_kmem(struct folio *folio);
 
@@ -391,7 +406,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -412,7 +427,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
 	VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
 	VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
 
-	return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct obj_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -469,11 +484,11 @@ static inline struct mem_cgroup *folio_memcg_rcu(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 /*
@@ -512,11 +527,11 @@ static inline struct mem_cgroup *folio_memcg_check(struct folio *folio)
 	if (memcg_data & MEMCG_DATA_KMEM) {
 		struct obj_cgroup *objcg;
 
-		objcg = (void *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+		objcg = (void *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 		return obj_cgroup_memcg(objcg);
 	}
 
-	return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
+	return (struct mem_cgroup *)(memcg_data & ~OBJEXTS_FLAGS_MASK);
 }
 
 static inline struct mem_cgroup *page_memcg_check(struct page *page)
diff --git a/mm/slab.h b/mm/slab.h
index 0e61a5834c5f..c8504574f8fb 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -559,11 +559,8 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
 	VM_BUG_ON_PAGE(obj_exts && !(obj_exts & MEMCG_DATA_OBJEXTS),
 							slab_page(slab));
 	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
-
-	return (struct slabobj_ext *)(obj_exts & ~MEMCG_DATA_FLAGS_MASK);
-#else
-	return (struct slabobj_ext *)obj_exts;
 #endif
+	return (struct slabobj_ext *)(obj_exts & ~OBJEXTS_FLAGS_MASK);
 }
 
 #else /* CONFIG_SLAB_OBJ_EXT */
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-10-surenb%40google.com.
