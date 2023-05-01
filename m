Return-Path: <kasan-dev+bncBC7OD3FKWUERBKG6X6RAMGQENFOVT4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C3A16F33E4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:09 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7664be0e9c4sf155152839f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960168; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMW9wCKJrt47Lg3InSFqt1ir9lcDgKglhxA5E3CyOEHSzALQrDLPJIk/T1l3Kf5Mwk
         IIck3h7+CE84Xaql9prVKCak2zwADhlls+TMPu8EtVeBKQL7ghWUizoF1i5lAeExx8YJ
         kI+GtvPTFrOwlTBZiFdrMs31MPICS5deKfVjAVXHdoKob5ZTEKHX6KXwv6F0VGLtaZ/N
         5lt2iP6gcBTyhtRz0qarBDqgt1sb07TeQiI9CMShfzcKVvXW8QPh4F/Tlvjmkp3IDWtS
         uE2OMPUujMije9w5IobRXFA60PEY0mlmGufEaZK7m0EbWXJlegetADc3Y8mLmg6p2MJR
         dXYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zGfbEI8mQduWOQeENi/wYTu0F6w7cARTyfSFPmXs3UY=;
        b=tIFCBHO9/pqwZmmS2GShISLkIO31+tKYI5ohoTkZWM/mCM9RxfB6tLmuGsoNDk3qcs
         3Al32hiy+ra79oVa2ZCDgs2AlNyxrByZg2BNuyTfmuSkg4PoqLcg3OIVQu17Ax7iFC2v
         usRYpystF20IyN4OgbIPLA791WnHE9FntNFKZkJ0/dW82LO5vQ4QBoNoXOWQueCsSaI5
         5a2ObUserUbJB/jpGnMLDkKPmFN5NEtZadtjku48syZOXaD5yRKjEoxGSLfS89JDap1o
         wzi1mtPamXg6cprjQ7O/+EBh9ZxESsBVhIAUTmsgt/EzT1+Aj8nZaSRB/6wxobv2FB3q
         vKIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Db2dTvDW;
       spf=pass (google.com: domain of 3j-9pzaykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3J-9PZAYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960168; x=1685552168;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zGfbEI8mQduWOQeENi/wYTu0F6w7cARTyfSFPmXs3UY=;
        b=HQ+2PAvaizU303/T7P+9AsjSJKO3K1UT31nEK3YIOcrnuzsTf+LkWTEw7iH6dzGPJW
         qdgU5yPwtAUrqfmw2hECJVISeb+rYoUCzh8oqrc7H+kuR3co2Hz6VCTGfqZHbMOOaYd8
         q9lKW9GORL0CgqzL4x063B1vG12inT/sAC6r5tAC6tkkdXYdFjYZks7WJQMqsKibf3Pw
         2zifeCMSYHNI8GG72amrk7y1Rptdaj8imoqWAZBEMv5fSniNGuDE56u1GEr7QjlvBErn
         6sf2ly9dzq8fFHar5ga9lvOmpmZIpPolr0yBDw7JPHvYSi4hT6VaT8KutRZ7UAGMy3xA
         QB7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960168; x=1685552168;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zGfbEI8mQduWOQeENi/wYTu0F6w7cARTyfSFPmXs3UY=;
        b=hzDHwJRjZUB5oRH655c9XmbHUh3G0JbYRYWhJfXKbadePB5HA7U/Q3PJbMocYxpiuo
         LbcvEMY7mWRrizsd4NlXkx5cmoRNyrXYMTiMqtYoeDMAsAdPtbWm+NrbODlX9jEGG0MX
         RZVk9b2bT+TSk1Bxt9xHW7u74prvyRXqg7oQEWREn9CywIfeYWg02EF1qU/ctg/1h6WB
         0mEQLdayyo21IyMjJA7wdU4JwXLm6Nz1KBGZA1AIAl/nSGMqQjniYdJpMsGd8cS1ymLU
         HS74NdJm5+0Vqm4cvRxJ+jJiDJN3+FqQAhDxFZvZMO/v+i9WrmJGzzsx8bW4f27yxhvs
         quGA==
X-Gm-Message-State: AC+VfDy7f2KHiAOwUAaU7GojribqtUaR4YEv8wRXYZ04oSDE8O7HdTqu
	RXaLu9vVnRjSO4Vz9HaDv6I=
X-Google-Smtp-Source: ACHHUZ7pYXnIqhJFzAJiU8FdBxXifLTJbPmCytSc3HRinlj3a2n9KLkID8AeAHT2MKdwB/EqcaKHXA==
X-Received: by 2002:a05:6602:258f:b0:763:c346:be07 with SMTP id p15-20020a056602258f00b00763c346be07mr6273320ioo.1.1682960168534;
        Mon, 01 May 2023 09:56:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b86:b0:317:979d:93b3 with SMTP id
 h6-20020a056e021b8600b00317979d93b3ls3404207ili.9.-pod-prod-gmail; Mon, 01
 May 2023 09:56:08 -0700 (PDT)
X-Received: by 2002:a92:dc81:0:b0:328:8770:b9c2 with SMTP id c1-20020a92dc81000000b003288770b9c2mr11025846iln.14.1682960168052;
        Mon, 01 May 2023 09:56:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960168; cv=none;
        d=google.com; s=arc-20160816;
        b=edi5Yr6FGhJaSgpx/vA6EqLDRVJKDRJ8Ms4lnbtl7t1b+cY0poEWEOHibIUOL9WbYc
         vwT24qCJzBOoREfV7OqTyJXNjmn3QOEi3+SN2/b8RI6wfxNW61FQdczbh9RZJOYR+5I6
         3launCU5qSqm7s/L8rwU69n0tpl2xnIn8wRuhEsB+1Q84R/WIwStQiGxjvuj0VQmVbys
         29+lbRPKpLVJhLV6IKxfli9+rw/Yk4f0XaiS+S6IuERWwDbzPqQTQMIgN9+WQpOjpnVM
         2h+fAm2KkO8k7cTsiwoGU1xaSjy5mzYGi6SxwqvttlFejvwsJtMYt9wRfJaJBwCVzfzz
         avbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YfoToyHVT1LJlGJVQ6MuRV3hbhaLXh5d5qfc4HkIPik=;
        b=Br1Kgn+qNuauUb7o+AL9Bd3TdQ2KCOiCc7JYVN2GyIglihD+yFdVIYM5/z9y1q0EuT
         xPt5p6PapH0AybmNNSwvQ9IgYDf0Eu2H9Pvv8szHgMTxFi1PkGdTC+qhEEocli4qnbdj
         8iTtrDtki4pqwY4mLZw9maLCv+PEqiKRTlCWM5rLi3PwYZt9chvcwKD+xmrPWJcb51hN
         jKwdOz8nIVzt/uVTz0KHN+LZrpAAGWl8VnmzYWBKp0qSvrisGahe3CxGqHhIZ8aQsBCx
         Z1EiWR15Aeh9BbZy15jTGA4ImEdfEKpxl7CA2RyQ5e0TqsMlaEcTpUsWPRuYTmk1mwMF
         0U9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Db2dTvDW;
       spf=pass (google.com: domain of 3j-9pzaykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3J-9PZAYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id bi13-20020a05663819cd00b00409125e3b19si2155788jab.2.2023.05.01.09.56.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j-9pzaykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a7c45b8e1so4808884276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:08 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:c0ca:0:b0:b9a:7cd6:ba7a with SMTP id
 c193-20020a25c0ca000000b00b9a7cd6ba7amr5449586ybf.12.1682960167516; Mon, 01
 May 2023 09:56:07 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:36 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-27-surenb@google.com>
Subject: [PATCH 26/40] mm/slub: Mark slab_free_freelist_hook() __always_inline
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
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Db2dTvDW;       spf=pass
 (google.com: domain of 3j-9pzaykcw4egdqznsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3J-9PZAYKCW4egdQZNSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--surenb.bounces.google.com;
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

It seems we need to be more forceful with the compiler on this one.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 mm/slub.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 8f57fd086f69..9dd57b3384a1 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1781,7 +1781,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 	return kasan_slab_free(s, x, init);
 }
 
-static inline bool slab_free_freelist_hook(struct kmem_cache *s,
+static __always_inline bool slab_free_freelist_hook(struct kmem_cache *s,
 					   void **head, void **tail,
 					   int *cnt)
 {
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-27-surenb%40google.com.
