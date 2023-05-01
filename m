Return-Path: <kasan-dev+bncBC7OD3FKWUERBHG6X6RAMGQEFMQRITA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D06A6F33DE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:58 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-74dfe945c74sf134211685a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960157; cv=pass;
        d=google.com; s=arc-20160816;
        b=u2GiwWeTlEFcuXTQXhFhFGu0Qo6pijEqhie6FLVMmPWlRrmh3ZsPT5MEPWgvywbOfZ
         XTxSbRhnBVavLs29iMoVdY9qESqtcInUIcOxOehJ/6x64C4wQ47jKrb0rbFUa6wStOJp
         ClZUtoybSahbhwmthUmVMA0XgsbMKowleRo3I1en/YriiMS8qZf2vPBDvEaGwV68Nx2P
         SpoZzZYbnyJiyq2nveh2XM7EmZebdkqBZJD73JEz0z7Ks5mcVBsd2Ifs5Mt5D+l5+3fi
         Vkjrk7S9txhqcr/RXbaBcYwVUnYMmyQu8cppUo/rjkModcGtMjDuaP70LtJBrAU9ssTg
         dOtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rd7sSOaOPD01xe5Y/65wAZ8b4jPOy0XtxwjHhDKCrVs=;
        b=QaxsDea7kQI1w34j6SKd9k8DAD9jIy8RQMw7+A/nPxIS2q26RBuiGuYMy602DTz/lT
         P0kNT+lE/wqC3eZlbT5J1kIJ/lf4bP4VdKiDQVppwo2+cw4PHW9vTslrP6jIC+po7CMB
         ebohmmm5yFXNR0SZaU1jjNr58SRlcSgci1R3G9+Rjnd0/WClWSR9L20iElY3VMwpftrp
         HFliWhpEG8MEiotN+nO+bw5Gx9huFbjCtC/f9K9xduIBKXL2GV6JQVFRljvTz03c4Kuq
         1On2V0v1asGDp7MiSz9Q+VyeMsGY3j83eND4qVSKTdjCgGU0o/3INuA9kMFA0hhCj8D9
         XWZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5JJhV76m;
       spf=pass (google.com: domain of 3ho9pzaykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3HO9PZAYKCWMTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960157; x=1685552157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rd7sSOaOPD01xe5Y/65wAZ8b4jPOy0XtxwjHhDKCrVs=;
        b=Uc9MAw9oryOOciSbqWGM0wud6tUsZ/uZZSWMwWMf2LcCFRGuiDW1LA6W9lSnCqP2ol
         bJrBsT7qZ2CqbTRxGZC3onhpDzA0Ly3dOOVQvbtV/r/3BpVbq+3kgrQBGiN4BkZfoHSv
         i39GfpjfNwRleSmHO0x6vxkmzLySzhiFuzMLCDH8wd3p3g6oua7nh9HumEyOv7qmvq59
         AcJPvtlKRDne5iGc65Vk5bGwj8HcQyM+Nhi/h1wXNQ3R3Ge7a85TkC3JeYICGYrC/aBR
         bgGJHzANxxdMGQUwzbQ84RDS/XP9Otam43vAnj+82B2FUxkSJyQRAfdPbVu7xouZmvWG
         hR3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960157; x=1685552157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rd7sSOaOPD01xe5Y/65wAZ8b4jPOy0XtxwjHhDKCrVs=;
        b=d+XW2E7/X1NpWcnwPTGMttLVZ44xismY6EWUW+1yzkaZ7tFd91z+keL2WN45/0Ej6d
         RAorBiTQRiTRTPbjqNovGvYlXTid5aDNSHGWZTkKoUBmWroNjDWKTt/2cbuy939KBNMv
         F2Ld5cT7HgzNG0eEnbiax8iVHhIubrNqTmBPlQ17wqOPnL0TIjF6tHqwZgf8yZp0NS0g
         W7mLK7hXJNDaAgsImWSrAZOEv8b0ns7yUmR+7xj+tyrY2uJXRKlKrhIhPKUYY/bgDdqx
         1YqPe/n7lGeeSZSO3vcyE3f46n4fEcGxUWX/jdBNx5YWO+7M61zZgjTVeGhNVGtfLGsi
         kw8A==
X-Gm-Message-State: AC+VfDxyjVCIeUsOx5hy52Mdvz6Vjs9YK28o17qc58uTIzF/V8Siqx5f
	FXVmuF5Ji2O2FUIOn+kC7z8=
X-Google-Smtp-Source: ACHHUZ4Qyf9sNCJu5Ps87nBcyBlxiHlKEpAT36T2gmqtT/bywchd/zM013smc/TA2Ygy8njHgyGV4Q==
X-Received: by 2002:a05:622a:1991:b0:3f0:a1d2:7969 with SMTP id u17-20020a05622a199100b003f0a1d27969mr4711438qtc.3.1682960157048;
        Mon, 01 May 2023 09:55:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:459e:b0:61b:5dbe:d03a with SMTP id
 op30-20020a056214459e00b0061b5dbed03als822992qvb.7.-pod-prod-gmail; Mon, 01
 May 2023 09:55:56 -0700 (PDT)
X-Received: by 2002:a05:6214:202b:b0:5e0:3825:9ad9 with SMTP id 11-20020a056214202b00b005e038259ad9mr1246172qvf.2.1682960156566;
        Mon, 01 May 2023 09:55:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960156; cv=none;
        d=google.com; s=arc-20160816;
        b=sroaH0TIFMO6qVe+DCSo9cfk2lm1TO6p/A93aVJkOQEWMEB0iRW1BYrG7Ire9iKWoH
         61DizZ61a3TNxqDnUVbv3SvzLi/Shuu1VnKJ2Yurj/+x8+4uhLpUKbFShw3haePSf8Up
         l7fiN2DoPjtk5TSxksorsRtVWe3emx8rupQxp5lKBfqgSgE6uySlDRFOsc3y2yzd3Xf2
         EpzYuenH/KUbGrz2V1rHUKADN0WCpss5V74RDgfIry/Iee9fEhF0gdv6fHNh6siCkY+O
         0KaRji709TrhM879OVF5W4awNI9CIOQ8M0AM1cByq/LB/OikiZwfWz75aGRV+MvZXeWW
         vBPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ia0f0ycGZD+jM5YS+jW1bQxvUpAwQcUQoxrBuJXYMcE=;
        b=AQ46houHyVtfPF/S2qDN/zc84U6Hx+ZOCxI9tNBXYrpxdO8QcomKVzxwR55vANgTCi
         nJyIO9K8RfRUTgwtIoAl1NcBCIjOq8DC/HZTbrlGuaSNrqH5sYedFal2sGwZCwFmOLbg
         CK3TM6ekrPdcyU/bene240xpTrFQdjJkaFP9kocLHO1chEbOJEeWsBXogEuVArzl5vRG
         0VR9WaLWYP2a2iMQ6GiLIDjMzKuHSe/Mq3tw8zrFAQOiPb1hOMFIljSp5gXTpqz7nBKe
         PwOltsmvc0lWe2hrzZaAHI+VvflTzhbaHQs/SB5D2D8jw9qL1+xUApurKsUg/wLbm4Qi
         3dmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5JJhV76m;
       spf=pass (google.com: domain of 3ho9pzaykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3HO9PZAYKCWMTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id op25-20020a056214459900b005ef42464657si1584259qvb.3.2023.05.01.09.55.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ho9pzaykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a8075bd7cso4836943276.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:56 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:5d1:0:b0:b9d:52cf:4a6b with SMTP id
 200-20020a2505d1000000b00b9d52cf4a6bmr4308920ybf.1.1682960156135; Mon, 01 May
 2023 09:55:56 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:31 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-22-surenb@google.com>
Subject: [PATCH 21/40] mm/page_ext: enable early_page_ext when CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
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
 header.i=@google.com header.s=20221208 header.b=5JJhV76m;       spf=pass
 (google.com: domain of 3ho9pzaykcwmtvsfochpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3HO9PZAYKCWMTVSFOCHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--surenb.bounces.google.com;
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
index eaf054ec276c..55ba797f8881 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -96,7 +96,16 @@ unsigned long page_ext_size;
 static unsigned long total_usage;
 struct page_ext *lookup_page_ext(const struct page *page);
 
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
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-22-surenb%40google.com.
