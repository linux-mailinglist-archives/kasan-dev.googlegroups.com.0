Return-Path: <kasan-dev+bncBC7OD3FKWUERBR6E6GXQMGQEDSFX2UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E66885DA2
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:29 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1dedc89d478sf2048335ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039048; cv=pass;
        d=google.com; s=arc-20160816;
        b=VGMfJXFKZPdpF2fjGCtSFkvhx2vRLOqqhUCUG2xJq0bS0oQWXaLp2PcIG1bbFU+O0q
         XPBX0Cq4fpJjdV07WIHXc8EaSKAd6Uyk+RrlYsPMkNhluCTNZRfs3psfrfW+zXOqo/Hp
         kB7v2vFVY17APKjGBI9wIPrlpFZv9ruOr0PithRCXc04It4GW7U+WaQrPKyxy5QjiT0W
         lsEsgfIuflZ9I+JvZ2sJDwIw0ZckRA9LwJPD1Ex4iZ9usiMsS4FnWJBl6rxeHEfB8Sur
         qsbF5spN4uXNcjC+OS0+OSGilvh98IXHD8EqXFnz6UjyMSPxJm3NpBAWtD/9wN9OKowi
         5L+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nGphlXA6lwqH+DccaPwMiUIyxymAeVauzemVh52lF4U=;
        fh=3onLv0JYrDSCH21mFYJGWal5fij0n6ayDw1JO6nQxPw=;
        b=muC2oOeLPtsVAx3LseeC0OKC3/QqZabsMc1yEeKQGNPEw4Mi7F7nLITyNL8v78lIeg
         WCp/pTphGTTOguJn2OzfoMM0GaoAC1GiqnvXhSww0dWx/UPOYMSmI3OlXDf9jSK/ZdtW
         c50P1jbi46hT6tFnDCPCh+TntR+oP4k6QJO5kZr9vEV6bZD0U0qwzL53DlXtq0Qx6IPF
         WgkOKAfSeBZHdhRUTepqszN+FtyRPVeQffXxeaUoxIHDBBZhNhWu1yhgj0yr9t24N2y0
         h/PX1NBV3Ukua4nxHFy0ep0U6nv4aWeKqsnpSpw5lBo9fAHev0vclob3N6awfNTA4gmo
         +qlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nFbYtO0N;
       spf=pass (google.com: domain of 3rwl8zqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RWL8ZQYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039048; x=1711643848; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nGphlXA6lwqH+DccaPwMiUIyxymAeVauzemVh52lF4U=;
        b=K8m4vnrcELMdKmoTWUOPC5Y2yHP6s8cBsXGhkDJPCA27naxmOiixRRhuUJT53S/fkt
         tkOQf+bMXPkocsnca0ujq5YN4vw7KiFEcKdQJQNlEFACIp1Og3+9wBPP7zEPi2YExTpe
         WRKfeOLLrEzlNLJKbHawcjO8FbwITuwe/1skCH5U7fON+/rm0q0i/cSpo2eDN7xS4zZQ
         IqTMVMkMDbrUYVqCodhduWGjAZ3+rdomiWQSo98++qt6iLhAaRX/1Qu/Mqn/tQLu8vXD
         P9sztm2DK/sYFkmY5KCKVsU5iQjR+2DLwFkWmu0i3b2MdByNY8/AiLXKE1ympUMKbfYp
         wTlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039048; x=1711643848;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nGphlXA6lwqH+DccaPwMiUIyxymAeVauzemVh52lF4U=;
        b=pvlXxsYd5PLsT1ngK/CmLsiAUynrcLzZi9+GHLhwgIbA1uOFsKW0cunSyWPdZa4sWi
         1x4ytz0n4FugAvhjjjtDl3+F4ApyIDWyvk5ZtpuU9eZf3fvD7rCQbwrXkf0kAqGoYT6t
         yCvw1sj4AYihRFpExCKRwbDPk5urODc+L5UTYO7RaqfNvGWH92acJm34FMLzATEBd2JB
         csacRCFXOtKHrQpV+NCKL/A250MWh7FZ8DWrIDWpvGuNpiTNx7SzcJUop3CiRJARxT72
         QV4bonbU9QwjPiZUc9XlIn3P6C8pmc1tCSTTTWVXaGLva6XyFIgroMjrxVIMYsPr87/H
         d0Zg==
X-Forwarded-Encrypted: i=2; AJvYcCWu0WIfRu6FIcCl4UXk82v0o6gwCeKsAPAvat13eodW85qRVkq7aF5RqTaglC8v3qS7Rbi7VZpIZYtsCX2trUwW2p1vbBFDoQ==
X-Gm-Message-State: AOJu0YwqyaLLfigH2vGtPmr3ExXggUd4BosUyG/SYSeLdkntPEM6uaRa
	FYOPtRAPNCqECBomATJKfdw0FL5ypOMhtFZyK2V7Ge37JeUXoWRd
X-Google-Smtp-Source: AGHT+IEP9EIN8f3QYMnCvbN2f7jU/DpM03P6qVwlyCfFBelmY7E4zCscU/PBu+CAtqV3y8j2kTsYwQ==
X-Received: by 2002:a17:903:186:b0:1e0:e16:dcc0 with SMTP id z6-20020a170903018600b001e00e16dcc0mr228491plg.13.1711039047582;
        Thu, 21 Mar 2024 09:37:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2e10:b0:29c:77f6:bd96 with SMTP id
 q16-20020a17090a2e1000b0029c77f6bd96ls665049pjd.1.-pod-prod-05-us; Thu, 21
 Mar 2024 09:37:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlRxN1uMwBIwxFmW3kdQwutl8iOi8sZMIA5IyPSQeQ/M/jffrczNbOlJw9BxeFBamno4JaCtQTIjUoop0dfiMt5kZRjbcFmOJ19g==
X-Received: by 2002:a17:90b:d87:b0:29f:ff6f:b52e with SMTP id bg7-20020a17090b0d8700b0029fff6fb52emr2521265pjb.17.1711039046381;
        Thu, 21 Mar 2024 09:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039046; cv=none;
        d=google.com; s=arc-20160816;
        b=wDMv+9WRTeo09mh3ydixpqZSxTN+01pBMq3EoOIpt5m7ejEaFdBE7yIxnQhnqm4SR2
         GHd7nmI5m5I/2u0RJftknEMVmbf/ARbXXt5I2MVIrNgw0YX2SJ7TEFLYDXdme1tAjGDU
         UC/8RDGy8jCj3Jc9Z/yqKLYPZFl0MIVAKOUZhCBhyI4JXHH/6MZbl/AfwGfmXgzzOFKv
         e5iYKCglA/MQbTWsF5puZ+lT1WVeeMIUgDHunzi4T8Ah3dAThPB5Oooo1WrJj5urIDjt
         A059Lghfm2OtYWQTEIiBw6McNQV01e1fqo1kyypy04rpuWFje+oot9ElzjuMj+a/ura2
         xd3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WOYiJPoOo6EZ1v2aVMfBUZhNa7dlHF73f/fDRlekI3w=;
        fh=BQRFBNhr+rR/RgcoFbBU954j0Usr3ljgAAt1dS4NVjc=;
        b=zzWxPJ9+//KB9g316OjlB+EEjN5vmO48jtoka1KL2u3VPpbP15iIKjTVYa4lmDmcP7
         p2YUR+ujNUBBse97fAezUAizBIHBlOKq4IrQiFslk8W5HM/I0LODtg+15DZTbK1Vt86v
         61Tl03OAuNXIsulbqwc0/ivodYhLo3O0k5EOss39PyI18bIxe+0dTFeSWMO6CGS4wdPo
         G2zrHPQfAdfVMvQKtsmsm89z0VtbIh5hBZ7nrV2+OibivAdBnDNDoanHvkYDnehIpMhp
         q2A3itsiczbmr8Z+q5B2EI6qKOagmVGREytrQEzJF5szKkb2zseFKq0hNz4hx9+clbL+
         1mJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nFbYtO0N;
       spf=pass (google.com: domain of 3rwl8zqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RWL8ZQYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id s6-20020a17090aad8600b0029fe3bdb545si212862pjq.0.2024.03.21.09.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rwl8zqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc64b659a9cso1795977276.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4YXyU3NU2BDVVP++bDWtLb0EYi/Cl6ppH1NplZya8X1g0lhKVQiHKZRqwumqIkfbo2/Egfm9KoCKnGUPdU1KrilmVKInOj/Y0nw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:72f:b0:dc6:eea0:1578 with SMTP id
 l15-20020a056902072f00b00dc6eea01578mr2412289ybt.13.1711039045315; Thu, 21
 Mar 2024 09:37:25 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:29 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-8-surenb@google.com>
Subject: [PATCH v6 07/37] mm: introduce __GFP_NO_OBJ_EXT flag to selectively
 prevent slabobj_ext creation
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
 header.i=@google.com header.s=20230601 header.b=nFbYtO0N;       spf=pass
 (google.com: domain of 3rwl8zqykctigifsbpuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3RWL8ZQYKCTIgifSbPUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/gfp_types.h | 11 +++++++++++
 mm/slub.c                 |  2 ++
 2 files changed, 13 insertions(+)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 868c8fb1bbc1..e36e168d8cfd 100644
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
diff --git a/mm/slub.c b/mm/slub.c
index 5c896c76812d..2cb53642a091 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1889,6 +1889,8 @@ static int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
 	void *vec;
 
 	gfp &= ~OBJCGS_CLEAR_MASK;
+	/* Prevent recursive extension vector allocation */
+	gfp |= __GFP_NO_OBJ_EXT;
 	vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
 			   slab_nid(slab));
 	if (!vec)
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-8-surenb%40google.com.
