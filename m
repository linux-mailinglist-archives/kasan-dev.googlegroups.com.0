Return-Path: <kasan-dev+bncBC7OD3FKWUERBNHKUKXQMGQEMOKLX6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E192873EA2
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:57 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1dcabe5b779sf280905ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749556; cv=pass;
        d=google.com; s=arc-20160816;
        b=g7eXcCbnHnrcvMHlwYSKCTrpmKY9f/XLH0ScIc6K72rIjPIdmIvhpEkEHLpR5ITMHu
         4Alqc4aO6rL3gDHhA2klM2MOdqgNNXw98HiHDL87pyIdWldJZzSydN0Sv1At5Ig5Bi23
         lgssZnndrfAd4y5pFbqTHn3ekYgb/qpxkrMWy6tkN/deAJnFSMY4ipH6WoxpPs5WoqPB
         eziIahSfCRPVdhpJqqjWa0pdIl1RT1BDvAjOir2NEtCjwUxohNcMD0jG+TmNUQum3TmU
         +A0fqnUY7/qFDBkSNoVk7tjeDhq7QWbBe12NXK5QESsA9dMic5kSKsLHzeE6XmYOtVyB
         qCcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6PBp+7gBB7HJz2FKAZdlW/TyDUBQVS3h4iw4pNkJd2Q=;
        fh=COq3o1N/I8xkSU7iTJZAGrYc6cEiENj6M2IESWxvPps=;
        b=H9Samc+ZmelfVUzf41EjQ3I9vmmvztf+ueafRJKEUfqrYAaIudNq8Fj596M79Dq78H
         8IcsbpmN7ja7Z/ScA36t2qk27gN4uhDt5K/LdTVrO6DYjkIL19KUhacjiSE7V53zrB+5
         8Opvhqd6HSV7J2646kWgvnqZ8I1/fMY8MEbhbr8CRQz1F0TxbTIS4g6o32X78KT9IPat
         dfMJ5fCF+aJbLpiBdjeba/7xVEFod6QBxhIJK6LkzJ1SdbNNrtey+KAsGYF6lA7Ys2Rt
         o4xbD3jb7FXeAnuX7gMgNPsnCwCGLqVquRYVEcCLZq7hm3m6o6JTZ8GtTm3o1+xA/kCt
         DgPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TFAbkyQx;
       spf=pass (google.com: domain of 3mbxozqykcxqkmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3MbXoZQYKCXQkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749556; x=1710354356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6PBp+7gBB7HJz2FKAZdlW/TyDUBQVS3h4iw4pNkJd2Q=;
        b=IUzcmxadX8qFbiicXtgUKAkxPiI5bkciEIhOJphkjL6koQQW+qZMxZozrDqY17B8ij
         nHJN6VneugkbZn/cDqgLMZ1Jsrhf3vKwjnOo5xXeD3TwC/pgHTt2Jf3+TatESogHwr+5
         wlwPy6fAqi/GwcDymZxdsVLGGGgBdMv+jXHmqsQCi/SNcLN9wKpg7ELEDqO0j00qnpKx
         rQXmda5rM49/B/3+lXQtS0bI3HDyVoPV+fV0h1ET23kkVuykS0Yww1rRQUbRzrAhTv+L
         Dgr3UJS6qzKRCcnVac2g3GMKHVImtIoxNirrNotFRv0iZY5yKrzCEhrSu52izBOpRSuj
         /TJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749556; x=1710354356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6PBp+7gBB7HJz2FKAZdlW/TyDUBQVS3h4iw4pNkJd2Q=;
        b=hmn4S25Kbcmwn/XQQMN1bpyX8zPvVIG4FE2Q+gHzct0D3DuajZx8qY8Pv+MmexredU
         f6t/hp1/5NuXRwCXD0rjBDdQTGSi/FNKu0de2ciUm8wZjfAkA4oYH67/YwwJC8YO4N6y
         X9rQx7PWIkQzURnEFrEVir+HcXk3Iq35c2iBqW3AhLg1wHwVZsmWW4QCVO4IuFsFJO34
         z7Gs0sqObOCOGqR7CImXo6v1J4gFffm5Wgi74WNPnf+0MOjWD4CvWL87RQ4KvbYXTU37
         YOY6vj6b9MR0lj3vgleM+nVyGDM9xiZdCnPPyRSH37wOYcvwKzeolyWbf2KWgpG5E7G7
         +2iw==
X-Forwarded-Encrypted: i=2; AJvYcCXX/JUE+4zx/EoCYmN1LCfWNP+vAWa50Wbzlp/47CLzRSoy0ZJCQL+pSJwaHepIuC0fuhCwnuAoEBBStRn2OM0VWCfWBV2Dvg==
X-Gm-Message-State: AOJu0Ywd+sYEhooqzEoBiM/VpbiLsQAq8QyAs4dM4pKPFs2+atJmKdIM
	sO/wKhCaQDhhdK490bNthm8whl04SFGmg4/LWpDelOYsO38GLOdD
X-Google-Smtp-Source: AGHT+IGAWg1ePRsza9VUbRnqBHMlCnIZKb174K+7FXj82EvRk/MbfSvDzI8ZP3oPwT5vjHcg4Wo0kQ==
X-Received: by 2002:a17:902:e74d:b0:1dc:26a1:d1da with SMTP id p13-20020a170902e74d00b001dc26a1d1damr7838807plf.13.1709749556152;
        Wed, 06 Mar 2024 10:25:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2c9:b0:1dc:fadb:4b0d with SMTP id
 n9-20020a170902d2c900b001dcfadb4b0dls85569plc.2.-pod-prod-06-us; Wed, 06 Mar
 2024 10:25:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUS4rZSBRnjdNU4iVPEVzr+y1mGxXLBX0qKSEI+bO6x24g5EdyOda5YHx1cKyMRwo9nfCwKWRZVpW/QxSncM5yifpEpZxXdag4L+A==
X-Received: by 2002:a17:902:eccc:b0:1dc:b3bc:b7e1 with SMTP id a12-20020a170902eccc00b001dcb3bcb7e1mr7484634plh.1.1709749554778;
        Wed, 06 Mar 2024 10:25:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749554; cv=none;
        d=google.com; s=arc-20160816;
        b=lLdlfe+p1hDEr3QcNy/ZxKp+/SMtL1xEPibUGsWCPvrMw99EvffR2YKZ7vInxIr/y1
         sTks4PnSojQUZfPQR8s9WQqe3C6S4p9+Xj+3wJuykhZKxlEsn0xgWxiqPgLZ3pkTuCg3
         sXTmf8QHw3bIqaqXKO5g6Aj9OgptHA9KDacDmNIoH3T+g1VEmM8uN+fz/+ePUNu05MVo
         5yDgc+jYH2rvRmHWbD5DOhpUn8YpeXmDiweqE8PfBhZirvPFnl5pBmSl1UrHxw5sdYxH
         PU4GqejiH+z5CTGcXKUmuDr+MPUYKVgcSAnQAyumwz1m9y2nRLCRuXhZo6sOv+QcicjJ
         8e3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+wmfS4WzHQ3O9sWr06d7OoGjn7qYNg0oNg7s1VmP4AA=;
        fh=HFOpgcJXkDW0ok/2LjIJvpJOlVhAuzzdihOh2nUH76g=;
        b=Wk0e6yviP3U0WE18bbk3DpdNYf+m7VKtDk/RdMBmDSVvFR5OF/8Axgp4XzhVsRUTgf
         T9TJ+ffZscR9XEpc0l+dllT4Y8UVNsCm/+9gYPRcKkMdE8QUUH4zi9TkATYttNmJN+4R
         Y89//gIZQpbuqtaEDI821bhAyXXk9HcUKfE2Jqee3XAkWDnmHA13iJBDFbpJLxHO0U9a
         IPL4wHmOGlplBzJ04VVrOv/sxJbTPvIP3N7SWcSdMLD8fd5zIBzPf6SJZE3Jdo1buyKw
         IgWjvrHmXWc1OOL+wtWM7SboNIjqW4nLbrfxyUSfFR9I1nxJT8zFY+82zyyjRdL09TA1
         ud+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TFAbkyQx;
       spf=pass (google.com: domain of 3mbxozqykcxqkmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3MbXoZQYKCXQkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id mi15-20020a170902fccf00b001dd46cf7751si34246plb.10.2024.03.06.10.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mbxozqykcxqkmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc64f63d768so3713987276.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUe701iCcVnwiJ8yOGMN6O2AkGfL/7sQtCmbNi9pNkIV+rDi+LTH2Ai+EXbCtE2AdnQsdScsdgjItVj8z9oK1unOOMrLx7AScQsAw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:150d:b0:dc6:fa35:b42 with SMTP id
 q13-20020a056902150d00b00dc6fa350b42mr4231906ybu.2.1709749553765; Wed, 06 Mar
 2024 10:25:53 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:30 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-33-surenb@google.com>
Subject: [PATCH v5 32/37] lib: add memory allocations report in show_mem()
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
 header.i=@google.com header.s=20230601 header.b=TFAbkyQx;       spf=pass
 (google.com: domain of 3mbxozqykcxqkmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3MbXoZQYKCXQkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
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

Include allocations in show_mem reports.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/alloc_tag.h |  7 +++++++
 include/linux/codetag.h   |  1 +
 lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
 lib/codetag.c             |  5 +++++
 mm/show_mem.c             | 26 ++++++++++++++++++++++++++
 5 files changed, 77 insertions(+)

diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
index cf69e037f645..aefe3c81a1e3 100644
--- a/include/linux/alloc_tag.h
+++ b/include/linux/alloc_tag.h
@@ -30,6 +30,13 @@ struct alloc_tag {
 
 #ifdef CONFIG_MEM_ALLOC_PROFILING
 
+struct codetag_bytes {
+	struct codetag *ct;
+	s64 bytes;
+};
+
+size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep);
+
 static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
 {
 	return container_of(ct, struct alloc_tag, ct);
diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index bfd0ba5c4185..c2a579ccd455 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -61,6 +61,7 @@ struct codetag_iterator {
 }
 
 void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
+bool codetag_trylock_module_list(struct codetag_type *cttype);
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype);
 struct codetag *codetag_next_ct(struct codetag_iterator *iter);
 
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
index 617c2fbb6673..e24830c44783 100644
--- a/lib/alloc_tag.c
+++ b/lib/alloc_tag.c
@@ -86,6 +86,44 @@ static const struct seq_operations allocinfo_seq_op = {
 	.show	= allocinfo_show,
 };
 
+size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, bool can_sleep)
+{
+	struct codetag_iterator iter;
+	struct codetag *ct;
+	struct codetag_bytes n;
+	unsigned int i, nr = 0;
+
+	if (can_sleep)
+		codetag_lock_module_list(alloc_tag_cttype, true);
+	else if (!codetag_trylock_module_list(alloc_tag_cttype))
+		return 0;
+
+	iter = codetag_get_ct_iter(alloc_tag_cttype);
+	while ((ct = codetag_next_ct(&iter))) {
+		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
+
+		n.ct	= ct;
+		n.bytes = counter.bytes;
+
+		for (i = 0; i < nr; i++)
+			if (n.bytes > tags[i].bytes)
+				break;
+
+		if (i < count) {
+			nr -= nr == count;
+			memmove(&tags[i + 1],
+				&tags[i],
+				sizeof(tags[0]) * (nr - i));
+			nr++;
+			tags[i] = n;
+		}
+	}
+
+	codetag_lock_module_list(alloc_tag_cttype, false);
+
+	return nr;
+}
+
 static void __init procfs_init(void)
 {
 	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
diff --git a/lib/codetag.c b/lib/codetag.c
index 408062f722ce..5ace625f2328 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -36,6 +36,11 @@ void codetag_lock_module_list(struct codetag_type *cttype, bool lock)
 		up_read(&cttype->mod_lock);
 }
 
+bool codetag_trylock_module_list(struct codetag_type *cttype)
+{
+	return down_read_trylock(&cttype->mod_lock) != 0;
+}
+
 struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttype)
 {
 	struct codetag_iterator iter = {
diff --git a/mm/show_mem.c b/mm/show_mem.c
index 8dcfafbd283c..bdb439551eef 100644
--- a/mm/show_mem.c
+++ b/mm/show_mem.c
@@ -423,4 +423,30 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
 #ifdef CONFIG_MEMORY_FAILURE
 	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
 #endif
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	{
+		struct codetag_bytes tags[10];
+		size_t i, nr;
+
+		nr = alloc_tag_top_users(tags, ARRAY_SIZE(tags), false);
+		if (nr) {
+			pr_notice("Memory allocations:\n");
+			for (i = 0; i < nr; i++) {
+				struct codetag *ct = tags[i].ct;
+				struct alloc_tag *tag = ct_to_alloc_tag(ct);
+				struct alloc_tag_counters counter = alloc_tag_read(tag);
+
+				/* Same as alloc_tag_to_text() but w/o intermediate buffer */
+				if (ct->modname)
+					pr_notice("%12lli %8llu %s:%u [%s] func:%s\n",
+						  counter.bytes, counter.calls, ct->filename,
+						  ct->lineno, ct->modname, ct->function);
+				else
+					pr_notice("%12lli %8llu %s:%u func:%s\n",
+						  counter.bytes, counter.calls, ct->filename,
+						  ct->lineno, ct->function);
+			}
+		}
+	}
+#endif
 }
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-33-surenb%40google.com.
