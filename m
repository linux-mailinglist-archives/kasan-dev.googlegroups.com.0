Return-Path: <kasan-dev+bncBC7OD3FKWUERBZGE6GXQMGQE4BLQKDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 27E0C885DBB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:58 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5a4e252a350sf951363eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039077; cv=pass;
        d=google.com; s=arc-20160816;
        b=yU9wPdWazUiD7vJ5kZLfSxWJb7kw/RC8mAvfE2pWkUT4+nWLahP75lOLegIW6GC5NF
         DXMf/9uZ53rfNPAPajbhDlmd0sREvCqxb680mzCHucG+/WpFBUNV6Vt7wNFnEq8wt130
         p3aGbTfKvKxaIKtnuh5as2kZtNi8+/0zxNrq8qmsE4tG6/GtKWTrG/E26Owkwax5STIa
         Ub0rc/On88WBpJIgL9Bh5S0sNUxacBYrgTHEcN9pBmVobI1ux4AjQrywjkKcbu4dLEey
         HVhOIzF/0Txuh0Zw/5lM6bRn5da9eAielvPAoGz1cU14X6LES9QJJCaQf7tgRcMW+akC
         q6CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=icMA+WAMOxEx84lPClCdRMGvJI5e9Ru8HaQS/XHxGv0=;
        fh=DSAhVHnRRvmKfyIG6wnBuFfkeO7ZB/X15VRo+G/QYTA=;
        b=UxTfoXIGCrUAFEEGCHhHp3p/RkbNDMj6I/0oIdmvxK4mgmHW6w8hUDQBZJD2sZmWSp
         Xhr6CS1Ssxk4SK2son2mRJr7rHhJiymQJ2qFlAJkiNNNMKXB8QoxV82HKAnKjdw9vo1a
         6Vo5dLP7+BYxO8AAhmAQSPbtYtDt9hkLpWqXApOtT03pQ6LAQ0IQyFhfBkA5sPVDsqLY
         5/d2zHAVne1zt/PBFlpH+HhHPDvqizUa5bbMBP3jZEqckAB+NfnZ662Qam/FNGsAICV1
         hpzvAixLUwMuEgmqNkpflVQDV3sxYv740ImURJKBw4OilhgevWW2PJV6cr4rnqsdSRQf
         QEFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=W76ok3GV;
       spf=pass (google.com: domain of 3y2l8zqykcvaac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Y2L8ZQYKCVAAC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039077; x=1711643877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=icMA+WAMOxEx84lPClCdRMGvJI5e9Ru8HaQS/XHxGv0=;
        b=TC7niVLpv+xsYnenT5G6og+ckw5owbLMcs7vTXJwGEYsVKGrOmTpzU/lVdbKGNpL+V
         IrLjWApMQmFCRxAlo30XhSIj3K6lZpjQgjZhuGm/g0JwKer9ursRgAtFdHvw+e2GPDj0
         oao+Q3VaIu8GnXS6oPE3A589n+HYtluDIiQOhDjsBkUT88A6Ly68XtNtsu73upWZArs6
         6HvGUN/hAeyJ4Ib4sCb+xlgZTB/diCe9Wz5ccUXUZCu0WdaSgVdg7SH8RueP8Dfy5ixk
         FRaZI6ZH1isg+8mZ90na+Cr1yA4x0mQzbG8cOPPAuLtoq3d79czTAboatU3teR5VmnjR
         vc0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039077; x=1711643877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=icMA+WAMOxEx84lPClCdRMGvJI5e9Ru8HaQS/XHxGv0=;
        b=Y1ZgkO0J/0c+kp89s95rgZbVLmzta/baHOUz/btvyMu578lJS5bgUC95+IA0mZmH08
         AnjQgIzaxiq29pO1Optkbi8hZQ5k2t5Ce0HacVBYg8vcZ7UwBqDoK0fW0cxbOWa3bPmy
         0IsNDx7++pD81Lt8gTacFLUIXEnuZCPAauFZKqsLVG+I0iCA61BUlhGhuxa6IVc6eBDS
         z5CDN2K4vVbpoyVJ4wO3tm+Y9lDFKnm8ZkN4kxveOBLCbIoLz1CbtStHr8TUCHLka2BH
         BzG7mSF2UTvPV/PhIo9qASJWDK++peM2J+KGey9MERwN7aL+AFGTkGI85kGfdDPaohFh
         llNw==
X-Forwarded-Encrypted: i=2; AJvYcCUiAKsISDfWpt9Qnbtih7g+8MH7nlqz0jDYFyGMrNQt7Tben1ufrNiEkeL43r+8UcmDdLkXLkRXrukh5cnZOw5bzheGebwy/g==
X-Gm-Message-State: AOJu0YxqIhQxwQjmCWlEfVUXDUiAqQXVoY3zIIy5exjSSIhaJwUwt9k8
	tq9OVjd5gqHF3bGQOqhDIF6ikUN9sJHYYSnWWaGsn1Rx8ETYBGni
X-Google-Smtp-Source: AGHT+IEIfH4ZNI3AH72ueFupkqyAhTcq5WZpqwLcxXGnx44oBxsgaOOKKVx6PQ87QIDXmz/NkjDrnw==
X-Received: by 2002:a05:6870:3926:b0:220:9f8c:b97b with SMTP id b38-20020a056870392600b002209f8cb97bmr25474755oap.4.1711039076914;
        Thu, 21 Mar 2024 09:37:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ac0c:b0:21f:a0f8:8272 with SMTP id
 kw12-20020a056870ac0c00b0021fa0f88272ls1272696oab.2.-pod-prod-02-us; Thu, 21
 Mar 2024 09:37:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/IqwcUiFmhUuHkpNBi0wkxyFjWzK1vlS5plWR6taygnyAp4Pkvdh7W+Hm/KeLyFgWOJD73aVFJ1FIHSnQb2y+y2pN9W/d87t7gQ==
X-Received: by 2002:a05:6870:17a7:b0:220:c604:8df with SMTP id r39-20020a05687017a700b00220c60408dfmr24219854oae.37.1711039076151;
        Thu, 21 Mar 2024 09:37:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039076; cv=none;
        d=google.com; s=arc-20160816;
        b=nY/c4ApW/OOcef0qTA20d0CQi1spsnPgivUcVVL99CxuX+k5HhSYxs/5F9NiLinFEW
         v+m2TBhU6g7h35HJymJezvGjsIkix81aSIMH+bFsMlUL3n+phrkkMLVZChcyumhZlxo4
         Y22+Zy226lTDkKNZa7no9T7k+Tnbuvh2m5YagJSjnOZzAOkFNlSMoMFamocGxX+nMFvW
         eJD396MPrhsT5klFXnRC4FCyVsRPuCp5CTVoz3AxOOPF+UY2Y4sBpBHcaQ1ltq8n5/HM
         pj0Sp2IQs6gVmXn8pfH0IEIBjrSchu6SOIXJ5ibzDxeynioyGm7V8DiykYDEihTk68cE
         iejQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=l0NoLpdPXZUI9jv+GBaFWeUdE0u/LS8GwKny2YwhxYE=;
        fh=YpsfmbiMFBFR1068C0MLUTYk4Qx4T8IvZIyZxuvZdHE=;
        b=yzSUqIJ9xuky/XHGXytfuo95KR0tY5bWDhZ5j1ijt/S8JUqndt5Uq6t89QTFrpeaKu
         L7UuYejERle7Wq8J6IlGH+esbV8oaoPVQLPvJMaiIfXNaTvSyCb4O7guwVYXuHvHRDF6
         yHa0WCN/4ah9C/pyCaJAigpbvZ3VivEfSjV3tMn2qfQLqDmUz+rI+YfQLqNDyIB7suPO
         qU8LwdF84GYuy9JHQ93718/TnKsdWupaJSQQmkZ9r7r7odvGUf9RuiSUXCUVsl0V10Ur
         Jf5Var9wdSi3rIBKyb5Cgub+sAcLTkJJw9DfmfV8DnpAqZhhXMU6km1gGoyhhgzx47c/
         wUwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=W76ok3GV;
       spf=pass (google.com: domain of 3y2l8zqykcvaac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Y2L8ZQYKCVAAC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id lh22-20020a0568700b1600b00229c91af0easi28032oab.5.2024.03.21.09.37.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y2l8zqykcvaac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dd933a044baso2906013276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXabDVkyr1xL1eCHPdSmEIR0xof6qOv/x6RhsfmLUyfpzF2v6zc0iBqQYx7VGwC576tq0aqrEoiGVrtVRGGfFpV8joH2urDNcmzQA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a25:ce51:0:b0:dc7:4ca0:cbf0 with SMTP id
 x78-20020a25ce51000000b00dc74ca0cbf0mr607569ybe.3.1711039075564; Thu, 21 Mar
 2024 09:37:55 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:43 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-22-surenb@google.com>
Subject: [PATCH v6 21/37] mm/page_ext: enable early_page_ext when CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
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
 header.i=@google.com header.s=20230601 header.b=W76ok3GV;       spf=pass
 (google.com: domain of 3y2l8zqykcvaac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Y2L8ZQYKCVAAC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-22-surenb%40google.com.
