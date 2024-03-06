Return-Path: <kasan-dev+bncBC7OD3FKWUERBG7KUKXQMGQESTKSOXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 830DD873E90
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:25:32 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-365b40e24e2sf77029395ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:25:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749531; cv=pass;
        d=google.com; s=arc-20160816;
        b=zfLbqr6siYhK+zv3ydTf7xTr8I1+Farld2qxVM9NGyrp1lQcrIjt0RpYJ5QrJUNtGi
         LTseXcTQPj3NoglHhdWIJz9iRTA+gmVrkkhXmd8soxy5bYlpG/WyRRP8kKzoTl8bLvp/
         XmkQSZyd+mNxXciyrDJzxJC1uMcOmNTd5yMIb2QNF4D2GQ5jMv5SGgBSJ5zdIZyjDNFu
         C6uPN5MK9zQ3cv3D0N4ft5B3Wid/GukaDLekGC1+UqDQ0iN8BN1P6ndBvmIrWvia2rGl
         9qpl4TOstwrS7Bdz3WfnZ7C9e0DGVqDmaYpBw57yZ5Cqrx3RQhdj6isVJHyFpl+7nZ9i
         uT9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gdcimcTvcLFg4IlomJGqBiBG3z+cTceFBCoznKhYrBA=;
        fh=b2vrEqmMCIPytsT3hG1AYFJboxoWBPU3qBGtR0jZUfY=;
        b=zW+Cgd5HU7NmVdwLIoUdv3j/VLDlw5LS8kpgnV35itF8D22HhDRBXhp57zDkOFE9At
         GDgutJsM3/yBhKvRgqJXtxGB01aAE1OtccShz1/n9ML/aXMrawVBhOuNJqMRWe3mvTwb
         V/hODxMtS7HRFXpzl58jEYhCxu/Q074gvMeTG5I/4paQ7rnMl5SmXBAYNN4H4FFFhrAj
         c4RFqWBC1tt++yLYzRROT/A6TGTL5ykeDZo0NEvheuKd4/C9SMPuxHkrY1yhwZhWwb48
         Wb0b4GK2Yl9TkYB9BQJ9lQfVCcl3pYYHr1ol4o/1hIlGTIrs9Idnb096lE4Wad3Tjbwy
         tn3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f+SW79ub;
       spf=pass (google.com: domain of 3gbxozqykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GbXoZQYKCVwMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749531; x=1710354331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gdcimcTvcLFg4IlomJGqBiBG3z+cTceFBCoznKhYrBA=;
        b=XVOtM0VJp1reM0Id33za4QDTtUyMrGS4vqhv9oa0PC9RPz36/b7GU1PiL3uERnms7L
         KnIv3GR5KTW+x7VsEk22P5ZVhxEMQWknAuAehPnrH/DndaQZasruyEJMKZIRv7ZnnaMY
         d0qKjN9CcqLA3P2QHejdWeoUrVvzbn6hLBBB9BmyrIRzAKH5MhpRf800res/ETpxc8Gv
         9ifbvtZo+B+xuWcPesCxkf+ThNymCZzkp89otB+nlJT2/98CDiZOrYStYfZ7eqJG+kCo
         n8xnOoMsqRVRkQuCQZd5MvImJMuSFPXdPEVOP1wUu4I64QLFOr0tuuaeBpmjOzvyhmDE
         tp9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749531; x=1710354331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gdcimcTvcLFg4IlomJGqBiBG3z+cTceFBCoznKhYrBA=;
        b=HNsggKft38w5PFFTEdprfrV5A7olywicv2+UD/iiyRauK+OfgZ2WY6cVKlIzjF+B2l
         NOtn9za6jNevoNDQJdj+kTfBpi1A2xkU4lvGfasdIFZKBR527cdK+qwJtn9OKO/Etgll
         9fBkuJBnyaicw9z3qEJqPcfGBsbidRCbnmZr5IkUNJWO6Ytyh8H3UWHCN4+giI0VOtUX
         9UkXkl/ysvmECeD3RTf0Ap3Fc5C/WzWcaFhy7wqlKyADm8uuANhfJhU33rkrKocQvM59
         ciHuEbHKVlhgkwPfP7hAbDQ7rq1NhKOgWdmr9W58B8czQz2ieqWvjm73RUXft2shPhwa
         5+6w==
X-Forwarded-Encrypted: i=2; AJvYcCUEP7JBd8OHkWH8Ee//iFhdwTSccFsJV6R1ZGagMOUBQkJQdjwvaeunvi2mHAQET7w82L58E65maPQPIq8XyJQ30p2buR7u+g==
X-Gm-Message-State: AOJu0YyDQbzUjOH6bKOKL5/cnIJux7/7QUgQE0+R0lxCX2YJEIkB7s9K
	UK+tU8gOgBidmNM2ISGJChrVVE3aIwxGfS5E1UTOPIZsBuTmf8wj
X-Google-Smtp-Source: AGHT+IGFlf9yFy6wOy633noYvI38xh9ybx6vV2aBhnAr25b61P4Il2cCoqmxX5gKj7WFYrTca7YkJw==
X-Received: by 2002:a05:6e02:1e07:b0:365:139b:f4 with SMTP id g7-20020a056e021e0700b00365139b00f4mr22398456ila.2.1709749531416;
        Wed, 06 Mar 2024 10:25:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1785:b0:363:8ef4:5a93 with SMTP id
 y5-20020a056e02178500b003638ef45a93ls100145ilu.2.-pod-prod-05-us; Wed, 06 Mar
 2024 10:25:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXaF2azxPlOVkKJikRm7ZjBW0W/cy7UUd4stuts7T/P8/OV/VRQ0zbOpfcbIjOyGCOrKg2wcYl0Zvy952Rb60c+DarmoM2FIuPiQA==
X-Received: by 2002:a05:6e02:1d89:b0:363:d96f:6850 with SMTP id h9-20020a056e021d8900b00363d96f6850mr19596357ila.12.1709749530525;
        Wed, 06 Mar 2024 10:25:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749530; cv=none;
        d=google.com; s=arc-20160816;
        b=mIRc+qWUasHYPzaIEaIFj2zXCKxkvsqcc3Cqr+2sUm/VKwOpeDvvnWRdIkHXYSbSNB
         0Lhxqo43P0+Nep7cQ+IljU5zesprhH+vRCqCdRCZKhpdJ44SuoSwwtg+/dXr40yU8R07
         mgAVqeIUSMSSBgjWV+laxOdSbBlKM+OzwlMxBsEhFyPvd3ZUc7tBx8GuToIYb8Pi/4Hd
         JrYIkgVVfZXvAGnCpOX7unFH/j1I/LqoVsICEtvcWjOFlDuk6T53IUuiF4WvQ1L45Hk+
         k5vPvp/CFV2j2iFWEtQeQEbXPBjJDpDEC/+tohOJ4KiZ25cK7QVnBEwjJS+XoO04zBZ4
         sSfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=r962bvR5LCwoMgFXL0pngYYUaEUVgmlMd//tXW54EfM=;
        fh=UPkqK98eQhDxR/2pM0GnijiX6CwZp53JGfTifeMROJM=;
        b=cHXSPn9FUzTFIlq7wFLNWod0Dl7uecZx7Tf2sGPjtTRz866eR6RVWWoQSiBzA3RDT7
         Xg+xX06Ils0wkADY+NgfmnsshnChSdrfY2b668HAXTIoIwVfT/QX3yOv3y8ENOUNkixm
         0OdECP5G9CHdRe5CGBINbAIOltQouaE45CqPWf6FspxP0BFK8PZFfGJ6QQxVev9t3LVU
         NmfbJGFJEhMbYpybk6/REUwj0Kq6/RfVlxYlOxQ+WaMIORvbdDtu7aIsj8+/zRf8wMde
         Ep2dTtN5etqZl+/ABrmo0VNue9CLehp1orBN+470dLiVMZzar//CH+u9TjSTqF6X/d0w
         qLkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f+SW79ub;
       spf=pass (google.com: domain of 3gbxozqykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GbXoZQYKCVwMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id x9-20020a92b009000000b00365c9b0d2aasi1145327ilh.3.2024.03.06.10.25.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:25:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gbxozqykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60996cdc37cso163157b3.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:25:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpnn1DVYYnF9nAQYNlTFPh2zKPN4tERSIiix4c+qkJfbOdAa6dIOQoypZKS1iyOH5BN1ov/0F8OpJPjG0O7tF0s3WSbvcyjZumjQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:690c:82:b0:5e6:1e40:e2e3 with SMTP id
 be2-20020a05690c008200b005e61e40e2e3mr3383691ywb.5.1709749529862; Wed, 06 Mar
 2024 10:25:29 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:19 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-22-surenb@google.com>
Subject: [PATCH v5 21/37] mm/page_ext: enable early_page_ext when CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
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
 header.i=@google.com header.s=20230601 header.b=f+SW79ub;       spf=pass
 (google.com: domain of 3gbxozqykcvwmol8h5aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GbXoZQYKCVwMOL8H5AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--surenb.bounces.google.com;
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

For all page allocations to be tagged, page_ext has to be initialized
before the first page allocation. Early tasks allocate their stacks
using page allocator before alloc_node_page_ext() initializes page_ext
area, unless early_page_ext is enabled. Therefore these allocations will
generate a warning when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
Enable early_page_ext whenever CONFIG_MEM_ALLOC_PROFILING_DEBUG=y to
ensure page_ext initialization prior to any page allocation. This will
have all the negative effects associated with early_page_ext, such as
possible longer boot time, therefore we enable it only when debugging
with CONFIG_MEM_ALLOC_PROFILING_DEBUG enabled and not universally for
CONFIG_MEM_ALLOC_PROFILING.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/page_ext.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/mm/page_ext.c b/mm/page_ext.c
index 3c58fe8a24df..e7d8f1a5589e 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -95,7 +95,16 @@ unsigned long page_ext_size;
 
 static unsigned long total_usage;
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+/*
+ * To ensure correct allocation tagging for pages, page_ext should be available
+ * before the first page allocation. Otherwise early task stacks will be
+ * allocated before page_ext initialization and missing tags will be flagged.
+ */
+bool early_page_ext __meminitdata = true;
+#else
 bool early_page_ext __meminitdata;
+#endif
 static int __init setup_early_page_ext(char *str)
 {
 	early_page_ext = true;
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-22-surenb%40google.com.
