Return-Path: <kasan-dev+bncBC7OD3FKWUERB5PJUKXQMGQEOQOYIIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id DFD9C873E70
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:24:54 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-365920e7cfdsf13505ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:24:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749493; cv=pass;
        d=google.com; s=arc-20160816;
        b=XcKn6YlZdyTLoyabMi7lYtY1174dF8xhh68oEIcMFH8xBUz4vXlIPhQaZs2BeALYIc
         WZKekovt6ibBH/jLXrMkE9/tTvDf8izu9BQp6IOfnN3hjQ+m7w5LYzYgej/hxsZsNsi/
         pLrwenbYmldn7LJYnUJShr0qpc5uKPPpuHDpYw9EKdmRSWLD9l0uj7B8LDiBQiPGdmGf
         TlmlhnPzjbUNerVDZuRb8afenRi2yTaBumdAyq/CZVXytYXXsgKhxXMk4gW4SqDxkvRz
         MTe74laUzG5FxFJ+rntkcAiWZHLHXDPMJZQFBf+qs9vLt1mEo/DO5PUEA7UXHUEoLC3/
         m5hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=N0z6ta5A7l88HyBtBhLycYCiYleSuZpc4+ZdF6XsvFI=;
        fh=EsH7KaCT5n76ZSMCQpL4WTf9t+zglPRs4ZGbj/Qcw4g=;
        b=mAYZvsnkKfqHMT+IR/nHT6jyg/9imsWaS6HyU51R1Nw9S6yhxGdZqNNAZ9V5Y+degY
         m2o7GrNGpTkVvJLDNIDsbyIQbwH9w9KsLyNAc8Y+kLblJFpz4Gnpm0Gey+IjH7tKIHaY
         wQUz0jXHmzVuVt6ck25NlH+yR8xGQ13ZlcmL1FQypFQO1aqF5P2HSOMosQy/hIQSS1cy
         vJWwz3aMuqRj4C2I5fLyA8BsGYBHjuOPZLXJGjeQ+WxoZB1M2N12+LiOAqNqr6SdEieB
         NbQFcRFRKJ3OCvEd9FvxkKbK1eVjp1jdLTSYR2HXxbC9XLO8GmMUC17w3EovrtQfdU15
         VfQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="NiB1Y/8f";
       spf=pass (google.com: domain of 387tozqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=387ToZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749493; x=1710354293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=N0z6ta5A7l88HyBtBhLycYCiYleSuZpc4+ZdF6XsvFI=;
        b=HaGOOd39SIKwQU3PIPzIuU+kFYaQSsSXHV+ZO00A/iwRAkXM8wYtUOR6k4HscEqi88
         ZTRyjfGVqqFbEDpSOsJTBV/fuEaFRvu6GIiiprbeU7RVo6VHdZXbnJjHYqfK06xlSNOX
         vRDWRJvPfaED3klyQd/5hXejV3nWcR9mq+n18t/X3aFG8eaWUbfyjHAAa7QwVhOEDE/l
         JowelK4Rdfe/43t56YCECD1bOtaFxWvyMN03yraqsJeIhICPB6QIPri0ID4IQnTUF93N
         8K3hbFf+bME1WdOLAG2UDAa3Edvi9X8NbGR8TwYxJkVnHTYGLYnDd6LwJxKgm4m4wdB9
         kvXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749493; x=1710354293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N0z6ta5A7l88HyBtBhLycYCiYleSuZpc4+ZdF6XsvFI=;
        b=idBlKsAtOVvhaBx0pKy+XtP4cKSrza3kzGjW95dCw4kukWdvn7SWF+D3OcW7ATe/LC
         UR+urhtAL759uOepuvXXVE+KmKGfrH97i7FKhmyVGZtAx97F4Y0tuITp0zC6u2dkAVZY
         fyfHWdURPGFH0bEpMjgTD+VO9ENcsqLjojrpjzTvpaUCMn3NIkNQ+jXPkhjuZ6nU1exD
         EocGf4ddcBwTHB2TkKwimS9XmH3oLKTOgrYoH4eHI/cEgt8bxqLxvw/51y5ti+AVDtSN
         w6/2dV9fAScGyl+YICrHunVl93Gx0LmopEH952OCo7Um/TYCgKkRsh9bQuagL3dho41G
         kMJg==
X-Forwarded-Encrypted: i=2; AJvYcCUnPnzFsfOob96iQ2mD3Ff3u81TvMfBPZBl6oiX4t38RujVNiPT0bzOl5aVNX5Vb96RttiUFaP/5DVBEMDNhScPFr8eXehJUg==
X-Gm-Message-State: AOJu0Yzua66WeINn2VIARvhL0KQ8/HAkLyOtFU565UYhK31OZJmAUmgG
	5V7362CrA7lnrGyBPJantf9UEwPZdqmrD9KuXjiMmlT3SNX6iZgt
X-Google-Smtp-Source: AGHT+IHxkpGMCDmzn1eTiwS8cZIFAjOtOay7a0wOV0DTDfjHyX7o012ilgDszaK1Z4z/vFKEoEOtCw==
X-Received: by 2002:a05:6e02:1e02:b0:363:b65f:7d7f with SMTP id g2-20020a056e021e0200b00363b65f7d7fmr45631ila.21.1709749493298;
        Wed, 06 Mar 2024 10:24:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:cb87:b0:221:2003:4bbb with SMTP id
 ov7-20020a056870cb8700b0022120034bbbls69339oab.1.-pod-prod-07-us; Wed, 06 Mar
 2024 10:24:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUXOaPw+eTItONO3UP7gwA0z9u7mgpeM4Vjj5ivshTey16eoXqxB/0y35JbWcplYIf8eXWcsR04XB7xfZ1X3DMKJ8FloNxI8ytxEA==
X-Received: by 2002:a05:6870:888c:b0:220:8cca:b632 with SMTP id m12-20020a056870888c00b002208ccab632mr6152226oam.17.1709749491778;
        Wed, 06 Mar 2024 10:24:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749491; cv=none;
        d=google.com; s=arc-20160816;
        b=aQWnCfvWqerwZ+Z26cMpl1TPwS5BYYzdOtNTWmeH4D3Gn0I0AtnC/cZRA2xs4ON9NW
         l/XTwUI7o3KaAVG4manWONtVj/n61PzFssneZzvtsOhTGJ/zZErye4yV6g1BSvI22byX
         NYI9hT1alB5Qbe4/H2iO4jNfYswQqs7gSBblrGJ7MoaXDg3TdZKrgrPcoE+CX5lIPbRV
         ZOTLhMkU1JghY7sH2pXfqaWVlY3v+ikX2LePZ2AcVbd8cYeiTI96sjbUKQ1TIiy5T81F
         FuAaDRsAbarNxXnUDIaxekfRhnCJXnqCladw5fi6iZhKSKRhF+VwcukcY1FfQsrT3zms
         hf/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NeN+jv49ztz1DkBAYeWMzQyB4IxgpHbFtvet8rPjepw=;
        fh=9AI7M45ipOQVHz/f5LVS9aFktPbSm/ogt/ijd1QMfH8=;
        b=T6kRGTpZqFlOSZmHgW79GUtNsbgGD9FDxKi+jsQVC5LYhZqXYrKIJtMWZQucYdgsX2
         lk/tInpVtxWPQXLCFXlmmP9pTUBeAkQBrTAcLuBA3hkfCEvCtrNmsu0olKDc1+QyolpM
         1RbzIkBIl0CDCyIHG/CL6sWEDzg4iTts50Rtkra/F226Ck1Sff0w1gRccmW9fzH7CHJE
         H7parVHt1PgNv8LX5eA+7SuIqUujjYlSugMuAPmKfKI+WPodpevXyrJDdi1oEQ1Ky2VB
         ZViWXrhHhc6vyNjqIkJ17bBms/ctILpe7VyEdybyOsoQUXUjWgXgCllYTdjTsx9A3iTB
         /Enw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="NiB1Y/8f";
       spf=pass (google.com: domain of 387tozqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=387ToZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id pa42-20020a05620a832a00b0078729cc7a65si1194910qkn.7.2024.03.06.10.24.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:24:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 387tozqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dcbee93a3e1so12144392276.3
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:24:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUb9mXsWqI4m3o+DGSMfzIdpfG9eVDzSra8qwLM88R3MYdoZWR8FaifbgWrJ1kBXXt2J/W7eh5eidL4E8w2IhDAiwN5MTLPcnaREw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:f0d:b0:dcd:4286:4498 with SMTP id
 et13-20020a0569020f0d00b00dcd42864498mr559510ybb.6.1709749491385; Wed, 06 Mar
 2024 10:24:51 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:01 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-4-surenb@google.com>
Subject: [PATCH v5 03/37] mm/slub: Mark slab_free_freelist_hook() __always_inline
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
 header.i=@google.com header.s=20230601 header.b="NiB1Y/8f";       spf=pass
 (google.com: domain of 387tozqykctykmjwftyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=387ToZQYKCTYkmjWfTYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--surenb.bounces.google.com;
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
This is done for performance reasons only.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
---
 mm/slub.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 2ef88bbf56a3..0f3369f6188b 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2121,9 +2121,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
 	return !kasan_slab_free(s, x, init);
 }
 
-static inline bool slab_free_freelist_hook(struct kmem_cache *s,
-					   void **head, void **tail,
-					   int *cnt)
+static __fastpath_inline
+bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
+			     int *cnt)
 {
 
 	void *object;
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-4-surenb%40google.com.
