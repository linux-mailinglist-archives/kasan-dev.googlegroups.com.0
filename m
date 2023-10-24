Return-Path: <kasan-dev+bncBC7OD3FKWUERB2UV36UQMGQECIYH4UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id CAD767D524E
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:23 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-41cd445180bsf1458091cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155243; cv=pass;
        d=google.com; s=arc-20160816;
        b=WIK2/CL99EVOBL/69Ec0QLOCFhkyO5aCjAf+UeVG1a1/19bIsbqf6j9ciKxqraipy2
         LcG469oSDsEQyJbvsQR4rADgeY7/xdIwS6kqZcabuCrQRUicFZ1iH+9JwvFcjhqnB9Ir
         TUu8DpFbejsgAkbM1l3cjZsz90gFf5bp/aY4n5ztE2Eu+E/CfxUY0uIqohKZlrDSvydQ
         Ir2Rgsqo+XMkZEs3+3Ag0E4jYWLvjq7gGuqnYH6CAVJGG3q+9wdAlmnw9CREXCVOv205
         90K+bpGZdzXEh2NOGF87lq+uOlfUy7dOLdpI08p6YIjNrdHEOhHl24X53XS3/UcBUveU
         3Rfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q6TUgU0ryJiPlBf0zoaMRPqFqvvBHMbjYBUd+pLC03I=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=i/VY8zZRcswyiz7ukYX9auUP+XkDBDgana6WsbqQcXFcqjGdt/fpw9fw3oGD3FRC/g
         6VmbrHhC6+4x5v7XCb9nMm6O1LVXzK1gIor3dsnQXcKDBQP0zBChzrV3WGFlQIHG1dNu
         TAXJVD0VqjCcF46Uz7ItvYkXN9sdRTZjgJsujLe/0xLD6q3DlwQTyOdiWTYEQlQ0mrph
         2xDsU0JluCY8kk30UWr8drKq+tdbZo8xpfcyunScXyGgWeq8jTDkXy+Mgx0lJ4nANmC2
         TpC60+BDYv+rGv4NcLuuFr61k6Q6JXV1f+NBkSLrNeyvIceVnrq76QthQwBgos5qdLmr
         Rixg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WGnTEMwQ;
       spf=pass (google.com: domain of 36co3zqykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36co3ZQYKCY4AC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155243; x=1698760043; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=q6TUgU0ryJiPlBf0zoaMRPqFqvvBHMbjYBUd+pLC03I=;
        b=fptMZLqTHIgt4Zon48gmgGiCBqXPkbtk1Qcm+dpRZfklBL+mdVtC/RZMNLfjC+20jJ
         XMbhKajr3YL969KwJ41S2b/fLgbmBWgQrEl6fTZmw0qb1o0pJFfGuxnnYfHpw79sAy+J
         zAzJSdVW403LdvmmaxyZLg2+hlNqjqOZioIb/Lm/sh1KjZPcBTYbof3PnwdentMSfWG3
         fLS0r2UhIEFp7/nwNBK0rzIzCGEAtC+/sypBj0pYh+ctH/ELR2hYTRAdpJDbh5NeyxQY
         fSpgCZfPgssg31GqHTUu3CrbdcNC0UkfFbGkb8XsyciTJ+qRxei3Y3JYAtyxstN4PXXe
         K+pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155243; x=1698760043;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q6TUgU0ryJiPlBf0zoaMRPqFqvvBHMbjYBUd+pLC03I=;
        b=vDL1RGnFSUva5CB7skrtf/Q3AxKwglJiuleN5rY23ccZJSH5jdRiyWxQH1/zsaPXim
         yg+IZY1r3xX1Oo3wNZyikwnjNvn7xDQ88NAB2j7UVDs7vneLKhv5q7i2qIVITcghBv9z
         jM2M3l5QgawypsI4+Cv4+v9UYtHM0a4Eja3FUAIi5N3Blto2FJa7VoctutBaXRBzLZYu
         Ig2vpLsGnrMedXHpkX5Cy8nUGLCqZ9loyNLMcg1R4/CraddUGiyIO93n+S1y6l8kMDq0
         RGEraiaLMYddDMJYWwFVpmv3RC6e3ZhqN4AKOtjD7uS+5ZJLy/fZvn/nvU1vwwDzFiXe
         Sbdw==
X-Gm-Message-State: AOJu0YzAAKOMJhWgyx1GIMpDDX55VWIBMdVP4fEPE14zea6U6fv5ZsyF
	FxvPHEoZkTPmN2t6I1r3Uww=
X-Google-Smtp-Source: AGHT+IG51gUL6kxWYEQA3S7aQ8AbnTAy+JGPzZ5ZHYB5jkmejH2p9E6cB92aVWme0cdKS8d554tpHA==
X-Received: by 2002:ac8:7cae:0:b0:41e:1cfe:8966 with SMTP id z14-20020ac87cae000000b0041e1cfe8966mr286974qtv.18.1698155242767;
        Tue, 24 Oct 2023 06:47:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7755:0:b0:d80:8d0f:1129 with SMTP id s82-20020a257755000000b00d808d0f1129ls1224392ybc.2.-pod-prod-09-us;
 Tue, 24 Oct 2023 06:47:22 -0700 (PDT)
X-Received: by 2002:a0d:e2c9:0:b0:5a8:286d:339e with SMTP id l192-20020a0de2c9000000b005a8286d339emr13621439ywe.4.1698155241889;
        Tue, 24 Oct 2023 06:47:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155241; cv=none;
        d=google.com; s=arc-20160816;
        b=uuUYbDMksO2LbKR2PNk0ELSdHOEmUczrB1lCN5pf5uEBrhqYN5GMV5qJHybDugjiUq
         QnJBXe5yRY5ZDFpKwvNjHENv9HcQq+iNiynl8CkZ+MvgSgLI0Sov494dP/aWajDzpj+8
         2L/aO00PqFFqIcMpZnIpyYIA8nyRAd507dcT8A5YJ9r77XnSGln1Ig0RKpefG4ygtS2Q
         tZf9S9R6zfBE3zaUfxBX3TggHIURIgLtQcdkj5fRauvbNur20VLfl4zsfhaXlsPVHBa8
         QbYd4qXm2TTxY+k3XBdEQPfMyN0NF6nHuw20ld27zqyGAWN8VFVzTBNyLeug6/UUFl2i
         +xmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=zb+0nW/ZZ6NW74eJtanLAYQ/ebma3WHtobF3vZ6u4HE=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=OIyCS0//nz/imUkGlh/grNUj2E65UZsQE25RdMMyo5Kexkvu9z0zv5MWLP8aj3mgJ5
         RJTl7IaiqYFTpEF7fIq3S7z47eyZMVMccYPGukvsMm2wYdYD74Cz08HfCZwwAuO7DTqv
         WBJ3lsApT8u6mxn2n3Y5xmtOvrzxvUUZJfPy3CZ9VnokEvMGZCayj7ykCUrdorz0DbPG
         35riwMKlA3OqM1kN1Ve0XgcZfpRsS+sNbmBvicmK8wJ29Px+6zxsiT1u0dfI7SjA4QIa
         1cnbCjcZdcmL+nEbmjh0KmN8L0S0/oIPfrhfs6oLUY7I8z8kclkj+TckRY1tQefuKPjd
         S1IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WGnTEMwQ;
       spf=pass (google.com: domain of 36co3zqykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36co3ZQYKCY4AC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id cs11-20020a05690c0ecb00b005acdb94d61dsi69665ywb.0.2023.10.24.06.47.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36co3zqykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-da0631f977bso19266276.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:21 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:544:b0:d13:856b:c10a with SMTP id
 z4-20020a056902054400b00d13856bc10amr261040ybs.3.1698155241467; Tue, 24 Oct
 2023 06:47:21 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:15 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-19-surenb@google.com>
Subject: [PATCH v2 18/39] change alloc_pages name in ivpu_bo_ops to avoid conflicts
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
 header.i=@google.com header.s=20230601 header.b=WGnTEMwQ;       spf=pass
 (google.com: domain of 36co3zqykcy4ac9w5ty66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36co3ZQYKCY4AC9w5ty66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--surenb.bounces.google.com;
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

After redefining alloc_pages, all uses of that name are being replaced.
Change the conflicting names to prevent preprocessor from replacing them
when it's not intended.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 drivers/accel/ivpu/ivpu_gem.c | 8 ++++----
 drivers/accel/ivpu/ivpu_gem.h | 2 +-
 2 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/drivers/accel/ivpu/ivpu_gem.c b/drivers/accel/ivpu/ivpu_gem.c
index d09f13b35902..d324eaf5bbe3 100644
--- a/drivers/accel/ivpu/ivpu_gem.c
+++ b/drivers/accel/ivpu/ivpu_gem.c
@@ -61,7 +61,7 @@ static void prime_unmap_pages_locked(struct ivpu_bo *bo)
 static const struct ivpu_bo_ops prime_ops = {
 	.type = IVPU_BO_TYPE_PRIME,
 	.name = "prime",
-	.alloc_pages = prime_alloc_pages_locked,
+	.alloc_pages_op = prime_alloc_pages_locked,
 	.free_pages = prime_free_pages_locked,
 	.map_pages = prime_map_pages_locked,
 	.unmap_pages = prime_unmap_pages_locked,
@@ -134,7 +134,7 @@ static void ivpu_bo_unmap_pages_locked(struct ivpu_bo *bo)
 static const struct ivpu_bo_ops shmem_ops = {
 	.type = IVPU_BO_TYPE_SHMEM,
 	.name = "shmem",
-	.alloc_pages = shmem_alloc_pages_locked,
+	.alloc_pages_op = shmem_alloc_pages_locked,
 	.free_pages = shmem_free_pages_locked,
 	.map_pages = ivpu_bo_map_pages_locked,
 	.unmap_pages = ivpu_bo_unmap_pages_locked,
@@ -186,7 +186,7 @@ static void internal_free_pages_locked(struct ivpu_bo *bo)
 static const struct ivpu_bo_ops internal_ops = {
 	.type = IVPU_BO_TYPE_INTERNAL,
 	.name = "internal",
-	.alloc_pages = internal_alloc_pages_locked,
+	.alloc_pages_op = internal_alloc_pages_locked,
 	.free_pages = internal_free_pages_locked,
 	.map_pages = ivpu_bo_map_pages_locked,
 	.unmap_pages = ivpu_bo_unmap_pages_locked,
@@ -200,7 +200,7 @@ static int __must_check ivpu_bo_alloc_and_map_pages_locked(struct ivpu_bo *bo)
 	lockdep_assert_held(&bo->lock);
 	drm_WARN_ON(&vdev->drm, bo->sgt);
 
-	ret = bo->ops->alloc_pages(bo);
+	ret = bo->ops->alloc_pages_op(bo);
 	if (ret) {
 		ivpu_err(vdev, "Failed to allocate pages for BO: %d", ret);
 		return ret;
diff --git a/drivers/accel/ivpu/ivpu_gem.h b/drivers/accel/ivpu/ivpu_gem.h
index 6b0ceda5f253..b81cf2af0b2d 100644
--- a/drivers/accel/ivpu/ivpu_gem.h
+++ b/drivers/accel/ivpu/ivpu_gem.h
@@ -42,7 +42,7 @@ enum ivpu_bo_type {
 struct ivpu_bo_ops {
 	enum ivpu_bo_type type;
 	const char *name;
-	int (*alloc_pages)(struct ivpu_bo *bo);
+	int (*alloc_pages_op)(struct ivpu_bo *bo);
 	void (*free_pages)(struct ivpu_bo *bo);
 	int (*map_pages)(struct ivpu_bo *bo);
 	void (*unmap_pages)(struct ivpu_bo *bo);
-- 
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-19-surenb%40google.com.
