Return-Path: <kasan-dev+bncBC7OD3FKWUERB5ND3GXAMGQELVMBD4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8576985E78A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:42 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-42c6fb437b9sf71841cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544501; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gx1dzIv/aI1zAYv7pXcrF+DGFh5Kc5mRrzdvTk+m2ACdAGpAwdySj7ONDtbzq9NGBB
         fhi8BCVDrb7jfcRJrP3bgDN+GCov8o66NPQ7jGi4BjpY9m+/+bxmVvvKNanRFHSN7IOx
         ljFPug9eFOdqjeHLViCU6/dkGMmF8NwbbmGuj3kF/wQW/UVtOUtVtmsb9PS4oTUFJ1Ke
         PNJAHbb9NypZao+VYxOy4i4dQEQgRMYrc4c9ucuu54HEDvQE6uasDdc4+2+XtnrcAZ/o
         4lk+3rVhwul3DJyKRWT3l1BHOQgZKMl938L41EBHd8aUhmktGjcpfaDYVEii89tlghXw
         0Y2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rtxdsoUvAvIzGWjwMFVDtNP/d1Y3LWQ586ed6m3R9X4=;
        fh=9MWKyyj1E+ua7+YduNmuCph1oaQ15sPZarIEq4SLUrk=;
        b=cPx91DAxPFKe6g7bEcPHskWhT/lItQpTdKdTdioO8vv2EhLUF28Q7RrUxtV0jNw/u1
         AIgOudZU61NZFjqg8rTTCDnhvo5JXVbbnvntxqsNwu6p8QBnOOCHHiITkAcfa7o237vj
         4NG++5+JOZfY0Nx6hQ2A7m2mDz1uPuWjvleTZ7R19wkZlAShKKNesnqVpO/U75rC95vH
         //MZ0dNxW/dWvKt1/iub1p2q1nt9Yer+62ZL+uXVN8K4vyR5W9mIzsonuDnoMoE7JDp0
         lGTMdsZM6AMTAGAZOhx6DjNKZDWR8fnR2qKB62G2VbQdnPw26iakdhhHfl1MdKE2NQRX
         W49w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nufuj/zP";
       spf=pass (google.com: domain of 39fhwzqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39FHWZQYKCScVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544501; x=1709149301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rtxdsoUvAvIzGWjwMFVDtNP/d1Y3LWQ586ed6m3R9X4=;
        b=ee2Q33eXdebmxP6AWsx27FmU8hNfjJVY2S7TpGmNrWxaBwYgW2U5U0TTFfa4mjbzc0
         0knx52qR5VW+af+17qD6JrkEHYQ2bKsnpRpixws5mohn25dLXqq1mSM9t3RJCa4584Q8
         JzY22LVLPnLJMA0CYx6X8eE3e2XCZPLSsiH9cm04/Yl1uoN7XjhOTJcABDrVItDSfQDj
         W68csqMAp5o5vkx3Wnk31H0jP+GZCfxW3YLB3i5w6BIbvwnNKWwl2QjZZR79qePTctA4
         dn1vG2pP+ugvcoY+gzvbFHveRjKgGl+o7PtqYZPq9S7ty+9Uk90fxpi+OKJn/KP5CsPK
         A+Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544501; x=1709149301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rtxdsoUvAvIzGWjwMFVDtNP/d1Y3LWQ586ed6m3R9X4=;
        b=kRh0ugkGJUCLpTPF6g9gVe/RzBfVkABuoeArAXG/buHOEqTCmO+dhRvo8C+1WT3Ugw
         O5eXLNVcgy/044Q31KydTYeX3Z+krUc2GKVRWa7HCfUUtShWrF15vkxJt2gGyoffTQPK
         FaU2oImQShG5QmSa6uEwdzOnvSPa67X7ZMTjNca3FRN5tJCXxcinD1EuzNqWg0Y1i0By
         bc6GChTSJJ5AqLOJNNUzATWWnl5iMPq41qMff3SgaLzgUJc+f4GeCsCyKpk1o1Z29h31
         KxQxJhxaDCLZeJcvchK8cuUCeW3HONDRfYASU8Kl3xeGenX0msZH+2y1sNyc1c+NQ40W
         Y4PA==
X-Forwarded-Encrypted: i=2; AJvYcCVXADA3cerF5WSFE2yTLGvD62VFkw+4VLqaGTBM9tMzhRCE8jjktGs152dZSP0jMPgvleoVbNkl2DAmdEwX8S1xmaVlSaaqEg==
X-Gm-Message-State: AOJu0YzA/S+e//fxyb8LMNIkUMszBNUDJy8Z8qLips4KddtIrCJb7K1x
	7uWdv6Ni1Hj0K3Uy2DYiZp4KsqB+RU5sCIX7wxsOnPvEPvIe2q+D
X-Google-Smtp-Source: AGHT+IGTfXlbiGIrMZPIAW/vK3iM/nF1bdYTTl+9mQKgy3eIPJZblNHP4vecpDQyrrf2+5VIlxN9bA==
X-Received: by 2002:ac8:4f14:0:b0:42e:3d6b:2762 with SMTP id b20-20020ac84f14000000b0042e3d6b2762mr196967qte.3.1708544501461;
        Wed, 21 Feb 2024 11:41:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:242b:b0:68e:eb32:903b with SMTP id
 gy11-20020a056214242b00b0068eeb32903bls1003264qvb.1.-pod-prod-02-us; Wed, 21
 Feb 2024 11:41:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVB3hrafWcywKOr3NQZ7j5OsAGjHrGtQ3rLQ9H3+OY7C/Fsave0k3vt0yK9YC1X/kw8UpGVm1vz0pcwLoOtGpmQ8A6c2dgjyAZZOQ==
X-Received: by 2002:a1f:d447:0:b0:4c8:90e5:6792 with SMTP id l68-20020a1fd447000000b004c890e56792mr10632740vkg.7.1708544500867;
        Wed, 21 Feb 2024 11:41:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544500; cv=none;
        d=google.com; s=arc-20160816;
        b=u04hxBgaaz4ma8Tr53oMOENVuabBA+lb9bstK0rEaNieTLibEeXRPAuDA7fQF7nPqG
         oeuCwM/yPMp3kBELzQljEKLsUHfxvld6zv4r3VFLmzhTahsLW5lfMVQZZ2k1m+wlDe0x
         dndpt+7iyY1YC/UBID+VZ0QX9W2EDboUyFRVBf8otr0BO1NwPA3S+H5/RDp/RaMC7zwN
         r6c65XEsRNr2fMK/i3DPakqRGqTE70Qd7/SQqv4rG6Y/emFIBqkWUVe7SNBl+8cX84ib
         5SZyqAD7HPV201P1xiqOqyn0SFbXPXW4S957v9akOPUvj+2YEp8urv1VUJpyvBEAUStI
         D1gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tPPJBer4xtwbKjpAS2Ohhk9ejLfkpDLeASf186TPNEc=;
        fh=hQV29N7ahE/foImMWkMWcXFti/8ye1CjpeYH5sdyjNk=;
        b=Pdt8KsSKpPLmCjjGsY7Z7EmHkHRto8tUlpOQ4PfHfgu1gyPm9IEP8umRJZa3JanRZ5
         DS4paVBPWImJETMKIjIbwfpVqbDIksc0el1/wClQyjCHAZATRZ0du2oMojO8VmeBM4TM
         JOlMSa98X3FKn49ULkJE2nVfqxvdHX9bf+4oymbyIZIiwI71+AXWQDZ5fusxBa9MYK80
         +d7NtUqTn3mVQLbVyxJmYQ/4nuDxGqZkej6B90umYI4VlrTyQYeENYdOdaTuGflxXnCN
         e2imqrC3Mju4Oy0HqPhf7nbkI8cABwPoNM/g4FUdQHSd/7fJWhl5+6BjojKAv+6P3Jqn
         ge7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nufuj/zP";
       spf=pass (google.com: domain of 39fhwzqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39FHWZQYKCScVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n123-20020a1fd681000000b004c02d939b37si1216857vkg.0.2024.02.21.11.41.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 39fhwzqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dcc05887ee9so8540199276.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV+dnMvwb+KTBAPo21NstLZ0Q9zyIaEkU+INV1gp4LknLUDUcLpKEe9hnV8o5/axklhURTPlQA/bfml40w9k405SI8eYe/o1NpltQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:1008:b0:dbe:387d:a8ef with SMTP id
 w8-20020a056902100800b00dbe387da8efmr14985ybt.1.1708544500266; Wed, 21 Feb
 2024 11:41:40 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:33 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-21-surenb@google.com>
Subject: [PATCH v4 20/36] mm/page_ext: enable early_page_ext when CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
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
 header.i=@google.com header.s=20230601 header.b="nufuj/zP";       spf=pass
 (google.com: domain of 39fhwzqykcscvxuhqejrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39FHWZQYKCScVXUHQEJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--surenb.bounces.google.com;
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-21-surenb%40google.com.
