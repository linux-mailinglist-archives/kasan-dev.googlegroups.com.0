Return-Path: <kasan-dev+bncBC7OD3FKWUERB4MV36UQMGQEA54OLDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id CB9087D5255
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:30 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-581fb70456csf5665359eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155249; cv=pass;
        d=google.com; s=arc-20160816;
        b=F+UCTMjqFTNPIm2XIDjNuJKMO4y0pV2kw+z9ZH/BF+E1q3zhFJO5WWHvYls367GK5U
         9Pzd5a/treNuNTJ7P+SX73WvRhc+4O5g3n8XRiZGcTT7bDRhcTIsAG1rzFE6xhkpkHQo
         XkAXZueVHrQHsS9m5ZQYKlSovfA+FSoM4PLuBesXCLjk6UCNF5+G3aUJfgIP+NBS/kff
         HdLeIH3pBpq1Pg+kwz8K2Y+ipxj6NlY8h5kZVQe98Lt7Bd2lll14u3h3xIjIt9NSKUoM
         MQV5Ky8DNEJgloK6kakMTHoo7UCtyK3AFeTkBxmpV6I1IhHT8gsm0kv6HPPH6q68g3ac
         cU0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EdHtxy7bR26gZnsLTRYpgaWNBBKfIXd0HWyE2n1mWf8=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Id/aX5rUry7e4WtF/X2EpuvDR73lWWQGki+51CcLedtNneKe1jdu0N0NyNxSdbxfUP
         cKTPQgsj0q9nGV0lAULnkiEQLiYh0HrC7z4xIjj5EiPQ3V2oAZnIeaCjyGOVkvelbur4
         kgnFpHRMEI81L7pf3EQSwWWeLqKAGtrJcsE3qt+B5I668WqBxjpgqBeRFdzDsqWzswWQ
         9STLFW5SetslmHaWOqUcmwC2Ki3Lp4oK4T3LeCFb2Mngh/UJjWHHRJrwJ82UqVs2MXmj
         QNJ+MWxqFD3EYBYQdomI+Xv1Q/bvBypxcUD1KqQevYOffG3sdsBf2PHaUQG53M0NcdjW
         o7PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2i6iAmMO;
       spf=pass (google.com: domain of 38mo3zqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38Mo3ZQYKCZUHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155249; x=1698760049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EdHtxy7bR26gZnsLTRYpgaWNBBKfIXd0HWyE2n1mWf8=;
        b=Bg7DXXOIYfefl2lDZklkDhKqU9ZroJIYsIj5MMrxscXokb1ThA/vreiRXLvoUDE9WZ
         tlcrwmsgIsreoT8/XTB9nrmu7Ot0aHPHr/922gXZO3k55Tcak3qn29AdNzQnoPVSfE4d
         pkcdlcDqSqpPPrS7Ls7tFfdN87yMf5ik/0Kq316efzmndgvqzlpPMXS+kAtoosqkPccO
         us2Y6BQZ/77RuJSpfBr8J56MQ1CcHY7TEcwJ72Ueb6k0jevtDpE9bc/HK71vCGHwewHG
         KDm0Be5LWmFpmCDddCJibLK24vCJz+VclozrZ9gjbw9ce2bzd3AEuS2hpRT6uxBEvhOd
         pqgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155249; x=1698760049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EdHtxy7bR26gZnsLTRYpgaWNBBKfIXd0HWyE2n1mWf8=;
        b=W58fYcjiNBqfJIjqLrHd/s0D4cZApMH3ClZAvWp9PtW5evfywLqKBGQwNo5TNNEeBH
         hr6JlzJZh0ypvjZfRZEdHP/iLrbzBnCOxCxtj3OxXiOEJg0GWHC1Prsokh1XVv/51olr
         01D3xFVPlNEDmeH32o1XFEIxtmn8vPTWISQyq1S+EDVA/En14XJvXTusVx69PjLMDSsB
         MzNzFg/8T90QIngyNTOU/cK3jbmWPpGnhFhpvT77Zsy5vjsFyrMD5Uolwzvl3H4XvrU8
         lLT1uM0c+Q9O0MF40aBoQVH36c4XjU5zd6zZJCW4Zsuzotczecz3ssdbZwbYiFgd4EOd
         xRPA==
X-Gm-Message-State: AOJu0Ywzad81F+SXYfL0wDMUJY1Qr/ZT5EgNVLWHleDlte8qlOg3TU75
	0DumwDV+CdZN3hugzlSAhZs=
X-Google-Smtp-Source: AGHT+IEQwnS0ZLMXSFwu74ZOTiTCqenYyvhSdNgssN6iYjh8jq8Vxrrx+Dhlsyqxz80hhNl0CHIlFA==
X-Received: by 2002:a05:6871:741e:b0:1d5:b1c7:3617 with SMTP id nw30-20020a056871741e00b001d5b1c73617mr11549604oac.13.1698155249576;
        Tue, 24 Oct 2023 06:47:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4512:b0:1e9:d835:c43d with SMTP id
 e18-20020a056870451200b001e9d835c43dls731089oao.0.-pod-prod-06-us; Tue, 24
 Oct 2023 06:47:28 -0700 (PDT)
X-Received: by 2002:aca:2b09:0:b0:3a4:6b13:b721 with SMTP id i9-20020aca2b09000000b003a46b13b721mr11179837oik.46.1698155248752;
        Tue, 24 Oct 2023 06:47:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155248; cv=none;
        d=google.com; s=arc-20160816;
        b=odn4bxMaHK9vj2TrZ7xCeJKzqOXSuJaqvvMddpPG7JBFI8chhYTySHNSK/qGST33Gb
         GNllRewQt34sgnsopwXYtbm7EuDBvSdMCoYzycFuMyrF6RSkC/3zqIpPVsx+D812ylr2
         4suWZ4UPQsiTZWiy65TAErz3XzVnMzZ2tnGQER1hadl+cucu0Fg77LBp4LOnVC8iKLKw
         En9RJg8M6IJa7ruDrydNXIEtCU1Q3KewSTZiJJlTv2TRuqvY0eANDJ8QWacfblpD5tJ9
         rq/R2vGpyvCwHaLQAQHIrt5dZ3l/eceD2aY5K1kcSfDhX9zR6vtxtt8ckG916U4agQ6V
         a8ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=zC2/AjWbzXkwFGJu5UOviuzr4L4X1GYNGPTyCuvFw8o=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=LHTfafRJiwg5T8rjG/CNEKDc7JlBEKiC8MKM2L4sDgDUjiR2sIG8dRarZFQzvAeone
         ydLzAz5Nsn8lvdk2phtXaCL32K0OVzPRHo8XeADZCPZq6lJ/6F+CgB3FF9oBBrJLc4sU
         1b+tUZdZNcEAY14D/z7uoFZXZdPy3qteDVpi/qX6O17JiiYAdCEfbCSwP2I09gAE0XOB
         7+B8VudfsY1CIZ6mJgXSYHSeQ8IvB1pSiFziw70jaCiu0Lru56qo9jSxvoCvfjyEnx30
         xFoJCF5b9jbHaxDp7CFTEZktesoSXZCfzxYXx4gp98sGiYllCKCLT7GjNUYDqEYHnwlI
         N7tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2i6iAmMO;
       spf=pass (google.com: domain of 38mo3zqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38Mo3ZQYKCZUHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id w142-20020a25df94000000b00da04074e233si166788ybg.0.2023.10.24.06.47.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38mo3zqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9ab7badadeso5067913276.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:28 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:40c7:0:b0:da0:289e:c056 with SMTP id
 n190-20020a2540c7000000b00da0289ec056mr61156yba.8.1698155248287; Tue, 24 Oct
 2023 06:47:28 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:18 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-22-surenb@google.com>
Subject: [PATCH v2 21/39] mm/page_ext: enable early_page_ext when CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
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
 header.i=@google.com header.s=20230601 header.b=2i6iAmMO;       spf=pass
 (google.com: domain of 38mo3zqykczuhjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=38Mo3ZQYKCZUHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-22-surenb%40google.com.
