Return-Path: <kasan-dev+bncBC7OD3FKWUERBYWE6GXQMGQE5UM5W4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 08F0A885DB9
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:56 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-430e4afb01asf12872661cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039075; cv=pass;
        d=google.com; s=arc-20160816;
        b=eBjacxDOzJ8RtTMhA/xU4U/61la76CdfQO/aA2A8XmPC9S2ZdkIKhNVkDwfNHwb/ZS
         Ab7Yjfy1f2AJKPOLZLP+3/KBBVUVkxQt2nNY7YjdYcnssaowswQYEheGCj7LkJOJmsSp
         9I9SDeIETtn/WuoP4E4enzm9YXiOELJvQAt6NEU4pUy+DaQC1NGO4AIdPW37te4qINK9
         abjG3eFz76YcPDzBOPG5eHP9PSpGcJKzO40qpexOzhH+WKZjNDfPOH4JVb+rZNMhGDCT
         RJ40DG5ixL+SM0fYGjb52KAl5bkyRcB87+dC7ZJylZ9fP0dGtyok/Aq/FK0kNNNfT+8o
         SI4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NIniu9CR8r+Qs0zyKP+ZFo5vehdhAeMpGxazovDoJy4=;
        fh=oYxLSh9OZvOqjGRIxYMfPIMXouhXd/jMNvDXRp2qLTE=;
        b=WorxatHD4OW9APhGVN37oy1DJN8Pp5gNn9KIG4cJwhtLZQa3NhNAHldN/0kjU2kZF5
         NUFGyfq8EE6I43frDTD535tJWfj2qFYmOHakm/xIaKREeZcomKQXmnwwpjCOW9MnwQT1
         SmTVP0LzEVj/FXq3dnZcTuI3w/OehFhOIXhvTfIymApwgnpTC7u7BMnjEI/M/b0agm+6
         9RjzC2SWeQjKyCjjdzEdl5PQUVWJaq3Jvk8MlLEYJY4SmwlyUm1OR9ptcjiNXwLSc+qn
         PiOQ2RJXm6Ge6vzFnUUhDRCWKNAgOgFf5ZYrVypmr/kPngKbUyebJLDRkARTl5VuNEe8
         2a0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mcot+1oc;
       spf=pass (google.com: domain of 3ywl8zqykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3YWL8ZQYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039075; x=1711643875; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NIniu9CR8r+Qs0zyKP+ZFo5vehdhAeMpGxazovDoJy4=;
        b=VDjXOvJiA/MT9awPwcN1qJsQnQh5Eaf/XP0RdIqLPPDLXm0+9AGnLtJrYd6xVwr5I9
         sN8ep57RfuEOnY4MBlhOHV67Rsi7SyBZ+bq7lrYwJZT6dEBJbatOUKBadcv1AlaAWGjK
         rsJZ9UYRuwIXczeyLF+IQkO/bETVAhNKIqTox7LEhTXtG0Bh+iZKkdUxG2bdHvZRnMH9
         znee7tDx10YRp/+8lyxcHPOw7fOvQ4lLLXTgnU01oxCB6f9+ds6EJw7Z4RA3PzC8DtW4
         Zl3GMEea0wEZKkJ1b370on3LKHgII1ZCxBM21N9SrHEjotIJoJ6OzX05ieTY2Rz4J+VB
         ubcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039075; x=1711643875;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NIniu9CR8r+Qs0zyKP+ZFo5vehdhAeMpGxazovDoJy4=;
        b=PIk3GGjZeIKsj2J7Kirs5vSN6Wr/ZH+cMzDe0b/rcpfTjAbM4nUgsJ7YkXP2MJmIcz
         KM4L8eAM4dCziRdoY1UipCKP7/+Qvu9WZPX4lTu6pomDEHXwp74ixyULlC6Nx3Gkl0PW
         mns7Nkmty2H4hsNdfRMgQUefSdexckkBsWVmQ+YLieUfI+v1o6odbBpMenQUHzdJ0qhf
         myowAajItjMRv7btYWzgwWXULhb7PH7D2hoxreC1BbxPdU/RwpUOtLrfe2oi0HBhqgOy
         Hcwd+WQsdTrCId2xmWrAGeZWCwTGZaBaytlyQsnATNK5Lf6v2EVpxHmoxRZBhFfDXw6n
         P59w==
X-Forwarded-Encrypted: i=2; AJvYcCWHUgV9ztmIaWsTO7Ay4k3DgLuEazfOtFDgzLHPzA/tt67SZyfN3aLCuec93kGuSchWTWS3DNnX3vNsovdHNAtx0dETlarisw==
X-Gm-Message-State: AOJu0Yx94bv97TBL1rVvabA5vYOSiy6VLsbowJXDt1mox81Eh6BOgkYx
	9b4nh51nZn8mg/8OIAleN+PLMsXXWL36aQ35/MXS5ENwNYBc2ztn
X-Google-Smtp-Source: AGHT+IH4kmpc+DavSqoEhfGsWq75NXcHuYZpeOppti51HTjatUeq8dYoSpkW1C6WmZlaVGE9ec54FQ==
X-Received: by 2002:a05:622a:1991:b0:431:57b:ed45 with SMTP id u17-20020a05622a199100b00431057bed45mr2452776qtc.34.1711039075038;
        Thu, 21 Mar 2024 09:37:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:570a:0:b0:430:c273:680e with SMTP id 10-20020ac8570a000000b00430c273680els1592353qtw.1.-pod-prod-04-us;
 Thu, 21 Mar 2024 09:37:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDkjbS1Jwm0yBS/BXHPmHFw8UpEYa6u77hkECOtY/ehwIwwAtVq8WK1KFWWjmYyGXK3R1/7OodfceLo3twYJjAs+HkaZr45va4KQ==
X-Received: by 2002:ae9:e119:0:b0:78a:26d6:72c0 with SMTP id g25-20020ae9e119000000b0078a26d672c0mr2595199qkm.18.1711039074123;
        Thu, 21 Mar 2024 09:37:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039074; cv=none;
        d=google.com; s=arc-20160816;
        b=EPYkJNSsmKzuW/FICrkCcdoc8hMQgBEdP/bq5BcOT0kuNLngE2nh+FtLnewD2yQzaR
         jYk3TPB55RurqVxIsfZPEHKa4LGhupZEfcHDntdWWcdgKySVTaYrn1B4zekBJ4HJJWbw
         /8SUwLJisdHr9n/HY0PlYwrPmOij0Lzdimwyuf7LUXKjqWz9Cf9n/k2pJ1QA2AUcD345
         StXf7Vy5iEhOMP9J2Da6Ex79kLR5FwDBOBOUOb44iKc5sQxySU03Hm/rHhv/iNCbuEcj
         bJKjr5ZiWLmpoIiNM9F2YPtS9jVdY8tqVal+4zqnp66wTXnYVP3RF49j5X94SEQwA5ah
         d25w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=/zyX0GCVbwAVqAn+thP4TQZbJ1DZ8xPrkSKdxK+srAs=;
        fh=THMAOcihLJeTs/hkQo+BxhvqVIIiJwMjMKqB5fXRkyw=;
        b=Wk3L1mBwJhQbhPu71zzL0LJp76AYIi+W3WLqgMSHALcOqGGGQkGe7PLed/YApcc78x
         EHkgwqEWgf+XfLOcRfbroRUKbmNs7cVXweqgOdgqkKwxc7RoIfFgFt7qQbrFrNwuHvaX
         A9L0+OO3xGrpxN3h1hEsyQyoYk2xpCbNJccSiN3nQ3GILBNveu2gN2WIVjt5BKQsXWhV
         3tqdU2/k0ksP82zEWf2nYFsc/GIkYcNsfjY6uskz1g0SpYSKzDCPVGvzD9bGwhJ7Yc9T
         hIRaOnutY9DOA3ejc+TH0FqWzwBwGT20VoQLbhFb/8LwXX3/RN+woOf2Fg9/CyOVio3V
         HeNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mcot+1oc;
       spf=pass (google.com: domain of 3ywl8zqykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3YWL8ZQYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id br37-20020a05620a462500b0078a2918f02bsi7213qkb.0.2024.03.21.09.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ywl8zqykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b269686aso1810616276.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXm5aUqNcqcUvw0goPqUT75QrZl2A+eNj3jo2SsU7saZ64NqrNCOLpHNxYqFTB167xqw8dWwfkkknbjT/xbt9hxbXKyMqzD85HPjQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:218c:b0:dcc:4785:b51e with SMTP id
 dl12-20020a056902218c00b00dcc4785b51emr980431ybb.12.1711039073381; Thu, 21
 Mar 2024 09:37:53 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:42 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-21-surenb@google.com>
Subject: [PATCH v6 20/37] mm: fix non-compound multi-order memory accounting
 in __free_pages
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
 header.i=@google.com header.s=20230601 header.b=mcot+1oc;       spf=pass
 (google.com: domain of 3ywl8zqykcu48a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3YWL8ZQYKCU48A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
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

When a non-compound multi-order page is freed, it is possible that a
speculative reference keeps the page pinned. In this case we free all
pages except for the first page, which will be freed later by the last
put_page(). However the page passed to put_page() is indistinguishable
from an order-0 page, so it cannot do the accounting, just as it cannot
free the subsequent pages.  Do the accounting here, where we free the
pages.

Reported-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/pgalloc_tag.h | 24 ++++++++++++++++++++++++
 mm/page_alloc.c             |  5 ++++-
 2 files changed, 28 insertions(+), 1 deletion(-)

diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
index 093edf98c3d7..50d212330bbb 100644
--- a/include/linux/pgalloc_tag.h
+++ b/include/linux/pgalloc_tag.h
@@ -96,12 +96,36 @@ static inline void pgalloc_tag_split(struct page *page, unsigned int nr)
 	page_ext_put(page_ext);
 }
 
+static inline struct alloc_tag *pgalloc_tag_get(struct page *page)
+{
+	struct alloc_tag *tag = NULL;
+
+	if (mem_alloc_profiling_enabled()) {
+		union codetag_ref *ref = get_page_tag_ref(page);
+
+		alloc_tag_sub_check(ref);
+		if (ref && ref->ct)
+			tag = ct_to_alloc_tag(ref->ct);
+		put_page_tag_ref(ref);
+	}
+
+	return tag;
+}
+
+static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr)
+{
+	if (mem_alloc_profiling_enabled() && tag)
+		this_cpu_sub(tag->counters->bytes, PAGE_SIZE * nr);
+}
+
 #else /* CONFIG_MEM_ALLOC_PROFILING */
 
 static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
 				   unsigned int nr) {}
 static inline void pgalloc_tag_sub(struct page *page, unsigned int nr) {}
 static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
+static inline struct alloc_tag *pgalloc_tag_get(struct page *page) { return NULL; }
+static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr) {}
 
 #endif /* CONFIG_MEM_ALLOC_PROFILING */
 
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index fd1cc5b80a56..00e0ae4cbf2d 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -4700,12 +4700,15 @@ void __free_pages(struct page *page, unsigned int order)
 {
 	/* get PageHead before we drop reference */
 	int head = PageHead(page);
+	struct alloc_tag *tag = pgalloc_tag_get(page);
 
 	if (put_page_testzero(page))
 		free_the_page(page, order);
-	else if (!head)
+	else if (!head) {
+		pgalloc_tag_sub_pages(tag, (1 << order) - 1);
 		while (order-- > 0)
 			free_the_page(page + (1 << order), order);
+	}
 }
 EXPORT_SYMBOL(__free_pages);
 
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-21-surenb%40google.com.
