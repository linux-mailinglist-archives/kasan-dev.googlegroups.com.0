Return-Path: <kasan-dev+bncBC7OD3FKWUERB35D3GXAMGQEWPFM6XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 4085785E783
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:37 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-6e41d856114sf74154b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544496; cv=pass;
        d=google.com; s=arc-20160816;
        b=SnenIMMYc16BagGio0QdQG7fgb6c6TbsyNu2prRaMdNkb0JMrUgFxZPsnqaM1jTt2c
         lc19V/7LgAhHSsxHmsSdC3G4Hv+UBD0eT2MD6mKN57zoJ4W4oWDKoLWzpMPHSa+xLTRM
         WWevimg1UryLCEjofNQYlvrGPs5HWtAX2W4uHFbQxD9rkEhKCxohbqQaBsKg79PlzmaL
         tPx9C7l60ZfrxSdGEIkSrUmfYGNxrtzOyqbGONbSB1kE20bgFNahO42bA22e2tMiMmgH
         WOi6xn7eDbWV9mHZLWl6JGKIsAwOKE21WpOykbeALX9jCfcHmAE5fadB4K2F5N/a/sl+
         Y7ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8h3j/xDdlJaihpCQRaed23je+RO8sYVD2JUdPd0/OQc=;
        fh=gaO7AAS6948xVAuF69dVqqDkHRFgOYiI6iitWH78Rs8=;
        b=cFBbsQo70KEUvhDwJcPSqCfBAK6kfza96otLBDnEp2+xa4w+EaAF9j6M8i8o6AdtY0
         bHjXrsm7ad6pDkPxcwBdzJxHq9MmwAK3duIabsYcKMySOKtF42pV0fJfJHB8x9HSO5PO
         Y3udPQozNY7ioKjDa8hCoeU0ryYeinfaw/BTgE3dz0H4nyxs2jNRnt5mfrceP1NI0lfE
         bIS9qmDawlLyHShc2ptbZQG9b9QyKnmmhgjmJ54VLkayBvLgVK0PZ/+nYx2TAhFhrhdT
         HiHYRQ6PvYARX9WddEgcMMQf7OYzeWjRcy2GpayrhhgnxXNsFU8SyCZV2rw2gr1ho2KF
         VGeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FzljRwrG;
       spf=pass (google.com: domain of 361hwzqykcr4mol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=361HWZQYKCR4MOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544496; x=1709149296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8h3j/xDdlJaihpCQRaed23je+RO8sYVD2JUdPd0/OQc=;
        b=EPWp0OYjIaTfsyMHuy9pwAJsVMxxXEojobji42smcAQGv05Emcbv0eoo9JdeCpIung
         zXJN9nv5AKZsOAyij39GqSasP+JLJtYqbv9bT/Ywx2lXVLB+HIE8L5hKmAMd8R5jfUdX
         azNQHVldGvVQk9i1FRT6lp7nRfQ0orpqkbeRdM/u8SM39ivq1EccSxp5EilkwDSsDDMQ
         6rx8WfEY6zMGbpEaqV5fzvjhOkFqL2mHwnSxjPBoBYY5/0+O4fvj5i1kSHsC2r+Qmn+h
         QXxiNwz1ydroXqHDgU48GEAc9gt3+Zp2vsVDP18OSG52xmpJM2IMBo97wOFR611AY+VH
         sfnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544496; x=1709149296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8h3j/xDdlJaihpCQRaed23je+RO8sYVD2JUdPd0/OQc=;
        b=Hvmkxnz2XKk0+JJ1J6RiI8zeLQ2toQdcVxmuC2TBo8FZWsG3XWtGRlAUUgU67dwiOh
         05Z1VuFkb+5Rlo2kBhKwckLbozxcz95m04d2WyaZeyRCJPMWmyq0FsE3Y5n1Rfm3mLVb
         Wh4gTJKfgP7doeOqrVzsPTVR8La/wZARk6ufuZgrGFGzitLWjvXFLxxHDupEQbDK/vsY
         d0cJK/bAS4sRR6aUWRWv3n8nQ4q/AIG15Nl2cJmCUD0+nwyf1tMkIPGanDv2K747upRU
         ODIO4Wj/1ushgdPQNKx8Ajfu4AKDiVUscGKu3VxtbggWyMqHuH1NAfIubvTrDF5jh92a
         uB9g==
X-Forwarded-Encrypted: i=2; AJvYcCXvE3AVutQAj/MAdAdXMvqCneN4HgYj0kZlY8jdVrTOPDxsSALq//0/3YzKF2YzhxodwWPY1yMNEUgS3Qnl5FiUYMN5TKKzug==
X-Gm-Message-State: AOJu0YxpBCAW3ITwC7ZHyhtogvLU4mMf5M/v5MYuPKI/q49aBs/HU/rq
	6f4oDykVUyNW0l8xlzNB6weuo7Jx+8NBvZBuF9l6A1ynIg0F/VWL
X-Google-Smtp-Source: AGHT+IGp4oOXPTpw/9C9yV0KDRUPidqTiKXAJthbM4dRLPiuKPZPVcXLms97O8RG7kBuF8JP+iimVQ==
X-Received: by 2002:a05:6a00:4f89:b0:6e4:8d20:66ed with SMTP id ld9-20020a056a004f8900b006e48d2066edmr680623pfb.3.1708544495544;
        Wed, 21 Feb 2024 11:41:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:300b:b0:6e4:6d02:a25a with SMTP id
 ay11-20020a056a00300b00b006e46d02a25als2493290pfb.2.-pod-prod-00-us; Wed, 21
 Feb 2024 11:41:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXgEPQdljXBTBq+nw/rhzxnrAbi4sxqHXHta4dpA3J+6ftuEPTP81xbm9JczBXXV1dQgSNlryr+GuSogXrNygenJluT2vJyRGRiCw==
X-Received: by 2002:a05:6a00:228b:b0:6e4:7af4:d741 with SMTP id f11-20020a056a00228b00b006e47af4d741mr554962pfe.17.1708544492078;
        Wed, 21 Feb 2024 11:41:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544492; cv=none;
        d=google.com; s=arc-20160816;
        b=DoBIeTFgnqiurta1UNVSbajRmA1TnMWNjlBZumoIdKHeX9g6MUL/gL6V/G/XLS+3uA
         0jptLKXK3Vc3K3goTctLUkq1R0jfDqcus6jkC+pDyqdyzE3Xugg8gQ3axoyKofhrEZlP
         m23mIgBmdDA6+Aw+kWsuVcTb8DuA0pbpl4IQ4jo6Llm6gcqxL0vwGbD4BptRt6vJLZuz
         e5Lfoz8fVFQwYhDdArvcfnRg3X3+070Fdw328D6iToonw5D6lnCZREFkPrVFrnKDlKaM
         tPHW6Vqj0U75I8mnpw6uHowe8pBhyKgozgwPh07M8vLvtyIPXJxFWjoGownutSFT3CLn
         1wPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GoE6bGSaoBD7i3pA8lR/Run1pysn6CP5hI9CoxzKmn4=;
        fh=OcHhLc5YnbrHzhDUTRdCQtvZUpZMP2gGN27HspQ/g/c=;
        b=madQZAECfox49dR/aEN9zAe5Ad4rBk31nvVVfbYvBAt8tcJ82/jUC7Hf05GEjxNEys
         EDRX0J2P4eS7osWnECypLpBJW8eOnsu/PWAcs5rreYclFE3tdwMdPrEI9CLdFzk/T+dL
         yCrQ4S1ssHAv3uEwoqm/6JCqIxygH+/BkfGRgAZ6hfWfRcPY+FS56lohAXouWXs+da/C
         lIukWM22FyyRWjonJCdnV3nSl5pA75dN/uX2PKPTgYKrvi28X9J/MXCC9I/DugRMNwM6
         xgvmKXrH9+nXJEiBJ81d66/2j4ZtHtQ/3QORmOKqk8FDDBGnNzTur7y9JQt4Rgh4TaF7
         0nfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FzljRwrG;
       spf=pass (google.com: domain of 361hwzqykcr4mol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=361HWZQYKCR4MOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id jc34-20020a056a006ca200b006e4781493ffsi402568pfb.1.2024.02.21.11.41.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 361hwzqykcr4mol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60802b0afd2so1238137b3.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUSoxElOgcAMzOI1An1gEFjzyZsl2/CVk8aBW32wj1udGeGyGfp6k+S0NvzENytyN14wTdHrfBfW9pcghNBnvW2ErCK9wWifRRXtQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:690c:fce:b0:608:7c19:c009 with SMTP id
 dg14-20020a05690c0fce00b006087c19c009mr105006ywb.0.1708544491160; Wed, 21 Feb
 2024 11:41:31 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:29 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-17-surenb@google.com>
Subject: [PATCH v4 16/36] mm: percpu: increase PERCPU_MODULE_RESERVE to
 accommodate allocation tags
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
 header.i=@google.com header.s=20230601 header.b=FzljRwrG;       spf=pass
 (google.com: domain of 361hwzqykcr4mol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=361HWZQYKCR4MOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
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

As each allocation tag generates a per-cpu variable, more space is required
to store them. Increase PERCPU_MODULE_RESERVE to provide enough area. A
better long-term solution would be to allocate this memory dynamically.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Tejun Heo <tj@kernel.org>
---
 include/linux/percpu.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 8c677f185901..62b5eb45bd89 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -14,7 +14,11 @@
 
 /* enough to cover all DEFINE_PER_CPUs in modules */
 #ifdef CONFIG_MODULES
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+#define PERCPU_MODULE_RESERVE		(8 << 12)
+#else
 #define PERCPU_MODULE_RESERVE		(8 << 10)
+#endif
 #else
 #define PERCPU_MODULE_RESERVE		0
 #endif
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-17-surenb%40google.com.
