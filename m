Return-Path: <kasan-dev+bncBC7OD3FKWUERBVMV36UQMGQE2M6QM2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 403477D522F
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:03 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-56f75e70190sf2576804a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155221; cv=pass;
        d=google.com; s=arc-20160816;
        b=ckT1UE8dEtvIF9lSGxCS+r5Rv8NlvzPNDxyGFA014dBKB++Vjae6/5IFMOqgCHfZYm
         T2KfJlAU8F8AT2LfRV0EoyrnW79R5uVtg23pbbiSgK7e/cBr80JS52JrkQfDEPLAy1q4
         sNltx7g222LRPQiGTKq68rSaWXUZr6+wr6f90vEgGNsRVIT5rWFyHcAj4xxIpU5bA3B+
         7KMm/hBwgy4QW1qn/UbL1UewqpHQrw3SN3zx6Z5pAye8GhxOMpZl8gFjTtrjHrRafLsM
         2+/mBD/xc/ICd1rR9paLHpysg7ReEAKr39hgdvbPlnwoEqK5t7EOqi/zrngD5M5bVPdu
         IEhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=99p5qDjzEXJ0OLX3leWHOANlBmp6HYrkXTjPkTPVvJY=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=AZSFcds3KXTI2BtYE9S0wvFjxpUtdb+YShcL25649ttj0+e31bbNCBeQj/qt5I70DI
         UPYegH0ckxcCMqF4N5fEZnNBpKYWpKxakeEiVaN+DQeLa8WlK6cqVJEkfBhiTTUf6PAR
         2gomGtZ5oauX05gM4QMcW6vSRdmhl6dQzMSe1HZCoGPQE8MpZaNrF+nVlJO7O9LZ6D/V
         8j+6f2CbvKY1Pgz657B7KfPV7SdezfWMeYshfCLl0IUieLzTPj6zRSFHBeIw2G8IJddR
         qQvsCclhrfT7zuVbvPKtscrtYH0YUH1xBXCeIIrnfRF0fZheYMYG6vwykCVaRRNX00s/
         uHiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tD8BbjgH;
       spf=pass (google.com: domain of 308o3zqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=308o3ZQYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155221; x=1698760021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=99p5qDjzEXJ0OLX3leWHOANlBmp6HYrkXTjPkTPVvJY=;
        b=LNY/q6rgyPe0KdfOOEIsyKM+HxoPNZ347LvVEhZy+PcLKy737O8I72xR4csGKWkrrC
         0ClmvBqIioSD/4geB1HyrYJrNP5Re5SNSiUwvZjeFCr1iwBCIY0Nj+g/jfjCM8WFuEBm
         SHod4BnnJNuY80Cv1nf02uEbVZj5kpt6PnzjhgUxbUeyEwoxYLc96XboaQdaMEUDjGb8
         huXYdHoS5kqZkxW7cqx3/N/Ts72z49etxeCANQhp9x2c95gr68T/l9maO9jj1hMH8Dwl
         qAaV5l7jnGKVpHcEpwVHOuHqdJeb2Xp0YYb2t6OEIOLpwl49TYVG24quXhBe254rrL8i
         3ZYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155221; x=1698760021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=99p5qDjzEXJ0OLX3leWHOANlBmp6HYrkXTjPkTPVvJY=;
        b=uxsJGe06s6j4BrDDu9tIxIQmEfxpNg+JONERCenbNsO5DpPTzWQeahDxP6RUIIrzIu
         xb22+iJXimqsNAxU2OH+vFJIaDsTrT5mZbiaDf8MF8cVfniqYHCzyeFk+MI8U8Clcn4s
         bU5JsRsSpawC+l9PZjgsqe2WJr/fU4pan7CeRFg2pqPknu6C8gbqAP4WSVwwg6KLhmsR
         Chse3C5tUiUiK0feNWhjUTzizHFb0lN6KvxlmV1jUN9mAb9O1cf+OnzsWHZ0lPE2jrX+
         cSaVZGyPJJhQk0ZH31pcseLUYpEqZv7LZL3LmCZbTiewjffs1C+dVj7u188Sqw4V4pBo
         671A==
X-Gm-Message-State: AOJu0YwOHR0SsE87MnMBTkLFgSArf5GVEUeQsEUXNjPXrc/gnJ9KsWNk
	aM+29dU9hMoelQPfaNuEKzI=
X-Google-Smtp-Source: AGHT+IG8tjRiJsf8FVb1hf2YXIwXP7bQA//CRYOv4D2vLX9r6qago7ZggUKhCQQUUgo34UX2zPEumw==
X-Received: by 2002:a05:6300:8003:b0:166:82cf:424a with SMTP id an3-20020a056300800300b0016682cf424amr2171098pzc.33.1698155221181;
        Tue, 24 Oct 2023 06:47:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3287:b0:68a:47ec:f3fb with SMTP id
 ck7-20020a056a00328700b0068a47ecf3fbls2203569pfb.2.-pod-prod-04-us; Tue, 24
 Oct 2023 06:47:00 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a4f:b0:690:3b59:cc7b with SMTP id h15-20020a056a001a4f00b006903b59cc7bmr10539924pfv.32.1698155220256;
        Tue, 24 Oct 2023 06:47:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155220; cv=none;
        d=google.com; s=arc-20160816;
        b=0cAuwo0z+BgLGvj5HAw2e/PyTeW1zyA3z5tg93QnAQJOBLy6p0lGv1EM4awnABpvr+
         b271lXyj/RivQsN7lx9l2/N9DfyC48OmcvZEPwLh4LCb4pK8OyYZyN6g68cyTCd0nbXc
         Q5KedsRhZmtJBomjrk3O6EPz0JukKmGA//gL0g1MsnmtyXKWYv4nlGGgBX5Bqz3WsAjJ
         pegBk0z9o7UwiDP15+xMJxEqvX9IUSmvDYgB5kwTDVDohM3jARxW9SyL95aiB6fxt+EX
         Y5ytA6i9SWBoqsoh3ztMvmvghry9Wmn4D6t44vjGox4vgQNvuxsqFWBSyQwuFqi4qgQm
         zHlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=re9qyJoQbXM1lB3hu8WMyX+cG50piCMxG0UfNqXuCfM=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Bbe8JUIvVTXzxNDbBik6QMPYVtCixtjOqdGvwFqHGSr6RiV03E2ErZYX9QNnnDXldO
         Q3iFUJENyuM2msxOfeiw+F7byDcaJMtZKZdAYkOfdOJpRxcdMRjIFVbIGXo543ckGv6e
         MXaZkX6DIr5/Oi1jT1X4ukrKF0Ks7tR3EGeen1pHQpIStaBkixC/g4torCmRgOiDZP1e
         H+Ll7NDguc/TnNzc9fONBgVBju6UDrjGafEsuAo/mpqZdj29rpl3766Govfk1L2cxiye
         kOVEnHsNAvU1/ZKSvud8SCgRhOnmYIpKIkgg0j2A3kUaWY4cu6kf76cDsZAUse3Ek8wU
         /IYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tD8BbjgH;
       spf=pass (google.com: domain of 308o3zqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=308o3ZQYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q22-20020a631f56000000b005b7e6ff6c09si793536pgm.3.2023.10.24.06.47.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 308o3zqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d9ce4e0e2bdso2342227276.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:00 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:1083:b0:d9a:c946:c18c with SMTP id
 v3-20020a056902108300b00d9ac946c18cmr311395ybu.6.1698155219188; Tue, 24 Oct
 2023 06:46:59 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:05 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-9-surenb@google.com>
Subject: [PATCH v2 08/39] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
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
 header.i=@google.com header.s=20230601 header.b=tD8BbjgH;       spf=pass
 (google.com: domain of 308o3zqykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=308o3ZQYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
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

Introduce __GFP_NO_OBJ_EXT flag in order to prevent recursive allocations
when allocating slabobj_ext on a slab.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/gfp_types.h | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 3fbe624763d9..1c6573d69347 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -52,6 +52,9 @@ enum {
 #endif
 #ifdef CONFIG_LOCKDEP
 	___GFP_NOLOCKDEP_BIT,
+#endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+	___GFP_NO_OBJ_EXT_BIT,
 #endif
 	___GFP_LAST_BIT
 };
@@ -93,6 +96,11 @@ enum {
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
+#ifdef CONFIG_SLAB_OBJ_EXT
+#define ___GFP_NO_OBJ_EXT       BIT(___GFP_NO_OBJ_EXT_BIT)
+#else
+#define ___GFP_NO_OBJ_EXT       0
+#endif
 
 /*
  * Physical address zone modifiers (see linux/mmzone.h - low four bits)
@@ -133,12 +141,15 @@ enum {
  * node with no fallbacks or placement policy enforcements.
  *
  * %__GFP_ACCOUNT causes the allocation to be accounted to kmemcg.
+ *
+ * %__GFP_NO_OBJ_EXT causes slab allocation to have no object extension.
  */
 #define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
 #define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
 #define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
 #define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
 #define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)
+#define __GFP_NO_OBJ_EXT   ((__force gfp_t)___GFP_NO_OBJ_EXT)
 
 /**
  * DOC: Watermark modifiers
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-9-surenb%40google.com.
