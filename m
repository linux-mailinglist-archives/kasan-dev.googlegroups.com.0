Return-Path: <kasan-dev+bncBAABBCUVYWUQMGQEAZ5HA4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 06B637CFDC9
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 17:26:04 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-41b827579ebsf822241cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 08:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697729163; cv=pass;
        d=google.com; s=arc-20160816;
        b=TquI8e6GHkWd5OIWTg2IGv2Y7D3Xpns2gA4prSG80sK4YROZ4+OZ/l/M68V9P6Ftro
         axgqkv+MHJuEulaLWZyWp1YY5P6n49BykiaAXyuBJX3rWDCXpj3hBNY++xMzrjIPC2uT
         T54pCzNrBO9nFYlY4WhnpbkICXNaojZLBzvdWaOxQl4H2SvMQzNwlGxDXdn00eTeM1A0
         rMetpLVf3eZXhQDJR68ahJnuLdy9vcH3bcKWnQrpcy7SwzUhqAwJg2sGntNOIJcBfOh2
         dZ31cMqWo5vMuJWWHr8rkMgtM2f7bDHhxoCxKGoN9Eo4ITwJjikWgt6TF62eslviFvVb
         xwfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:cc:from:subject:sender:dkim-signature;
        bh=Q/bs82o78/fVC+k2HlYvLtLjs31Zwml8ToZTm7XW4TU=;
        fh=yLG1ju99JpkEbMqeaHbuQdiFQdKg/5UsEQpIfLydC2c=;
        b=y20cZauiTRWON3PFoAMim/KGdtNPCSQff6T+w8U+HVwC73fs+/agqtA6aY7RoedH+T
         81ZnsQ4tFHWkxLr/l+l9vjVHv+iJen+lWm8QO5Nwb8lZMLfaYWUoyMZQIWO3vRsylqzU
         f1Kvl0oVxGgpRI3XL3M/lscPva7FJok3hyHEEckUyBP/gMkXNOUfQwQryjFHcnIPBYQz
         IOYJclBV8hdE9Y5YwIyobRS9TacAmORsPokOWf3QBp7Kc/dsh1MA/aw329NNL62e7XeL
         bZ3gONlGvSx6DgvT8rpmQ0YJkgHsoQg6YARTv+/X0oabKn+sIcwt3IKj9m2J0BJLlMvJ
         ytVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ocXti95o;
       spf=pass (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697729163; x=1698333963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:cc:from:subject:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q/bs82o78/fVC+k2HlYvLtLjs31Zwml8ToZTm7XW4TU=;
        b=EcssXxQGWpCiDfB7ygqA79adks2qBYkllqHfLFCUkZ1IzXZHR2pVGqQC96/WEHvAGo
         YzYR9Pt7gtv0aWEt91Qh2Oq89JXfEHIY84O6agdCP+GluGZmvlBClPkENQhMDi6CBF88
         sCpHBkL7AHgTfUcUriw8NFRKe2rNFS+MNzY88HQzpC5SVGiJBuKLbbPktP/afusdO8G4
         iVxya8E5vr1/NYahPbfG7miBpxhlArEmc0wKB66VmI21s2IpfJ7wA2eGFqpc/TqoENuX
         YjQXbPByuUBnwL4sDcN+ptEVZ2VdZqbEVnh9t9EzHx/fhxCoY9suiyBGTwZgKEibUZWC
         ib1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697729163; x=1698333963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:cc:from:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q/bs82o78/fVC+k2HlYvLtLjs31Zwml8ToZTm7XW4TU=;
        b=hi9On/NNSNQXGqmhIj14j3eRz19STIfbB1Nmfug8rjhIt7Nyzr6B1VmnNXq8jL/djf
         kuK8BQZuP1AxQwoPPYNpRUwP2511zwGAvzDXapLF7ZTeZnXiC5uT0eOjcbVG8Zs0q3Mm
         0L+kx7mM2jTWn2XH5A6KW4eEN+m8PhOOuGb5U2owiuYQd1Uh1J6kykjMalcmsoZycF5g
         4ITMi97M4VhNi3EZZ/fmQQk95MDQBPkwtVbQzZ43m8i7Jo7KkOwF4UPQpDpafec0vlQn
         znpZNvrnWjyc4M7W7yxV4iQ7Tz98ML/rE8wJgzK+g8x2GYG0v1O3Wl1Fcch7ayGFy+Z5
         +02Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhVvWBMVFG4hzJJ9leGcVtrBvJoBy8c2W5z/7gQbYmSL6BzAc9
	jm2vKy+jbdXqxE/o4RKo3+Y=
X-Google-Smtp-Source: AGHT+IGHZ3Mx5ksNZh0xu26gmQHUjnp0QlJKjl+b67Bai5zSySc2wPrDIdyLxI33nuxU9TJ4p1T6dQ==
X-Received: by 2002:a05:622a:a049:b0:412:9cd:473b with SMTP id ju9-20020a05622aa04900b0041209cd473bmr342044qtb.4.1697729162853;
        Thu, 19 Oct 2023 08:26:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2b85:b0:65b:e4f:d22f with SMTP id
 kr5-20020a0562142b8500b0065b0e4fd22fls1548058qvb.2.-pod-prod-05-us; Thu, 19
 Oct 2023 08:26:02 -0700 (PDT)
X-Received: by 2002:a05:6214:20aa:b0:658:2bec:eae2 with SMTP id 10-20020a05621420aa00b006582beceae2mr2729857qvd.10.1697729162142;
        Thu, 19 Oct 2023 08:26:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697729162; cv=none;
        d=google.com; s=arc-20160816;
        b=qpkkk9nlxbiaNZ4oI+O7oH8uXjHvMto59Hg9Eg3e9UZjyZXaKxZbHBaYdoCa39ebm4
         k///0iIpIJdDmVhZoGcYiiltPNHEtFuGu808zRe5H+NglkRqI3wqRFdbs86ck4pgSNdl
         yTErVo9ac6qHr7KeJImJE6Cwrj8CGAaWc8Rx+brtMpZ99cNbrWDm8dTZJDhHXOKrbfUD
         /oALd58jvwaIQcVhC1gvYT8jDrC2RvHm+ustJ+iYlKZCfRh6H77DwdK8PyWQy5al0TxB
         pRJ5EOURwmN9WRu2CSsDKIEl/AjoilvjbbxebURQyNTaFD1E09/v+M6jCUAO3f49a8oP
         Zk6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:cc:from:subject:dkim-signature;
        bh=xDR7dn0oKDWDBNbcVNI65T4LvKi1Dhba+HObmm5aiNA=;
        fh=yLG1ju99JpkEbMqeaHbuQdiFQdKg/5UsEQpIfLydC2c=;
        b=Eea2X9oxAvzKdpm0czNR+BZ8YVYy+ShMSGn4HzWOKxhmSqu4UQ5YQoFoz3EctUea/R
         5jlp32VTgPwbwXKX7g46RyvMfxuhH60eUnV7EazODnE09d08MgJSc2ogPyJUJROEH0CS
         FBJTrUkw4rGrYsON6yalhKY4EQ1Y81wFkdcD+DA6o/AD7lB+QBHLTSXvx+OTlmkdCRDO
         +Pb+lY3f4r6jRp77hU0ASPMOIWHJq81SFI/2Q9ha2Tw6Q+1G4Tj6XESilh75e2tkFMQ4
         T4UC1ghx7reLO6ftMZ8Ea9tqfy34njjbrkJimp0z9tJMM8L+1Cm1hi4rACKcSCG/cPax
         /ilQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ocXti95o;
       spf=pass (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id du10-20020a05621409aa00b006589d264fcesi336463qvb.0.2023.10.19.08.26.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Oct 2023 08:26:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id DE096B828A4;
	Thu, 19 Oct 2023 15:26:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BF50DC433C9;
	Thu, 19 Oct 2023 15:25:59 +0000 (UTC)
Subject: [PATCH RFC 4/9] mm: kmsan: Add support for DMA mapping bio_vec arrays
From: Chuck Lever <cel@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, iommu@lists.linux.dev, linux-rdma@vger.kernel.org,
 Chuck Lever <chuck.lever@oracle.com>
Date: Thu, 19 Oct 2023 11:25:58 -0400
Message-ID: <169772915869.5232.9306605321315591579.stgit@klimt.1015granger.net>
In-Reply-To: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
User-Agent: StGit/1.5
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cel@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ocXti95o;       spf=pass
 (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=cel@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Chuck Lever <chuck.lever@oracle.com>

Cc: Alexander Potapenko <glider@google.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Cc: iommu@lists.linux.dev
Cc: linux-rdma@vger.kernel.org
Signed-off-by: Chuck Lever <chuck.lever@oracle.com>
---
 include/linux/kmsan.h |   20 ++++++++++++++++++++
 mm/kmsan/hooks.c      |   13 +++++++++++++
 2 files changed, 33 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e0c23a32cdf0..36c581a18b30 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -18,6 +18,7 @@ struct page;
 struct kmem_cache;
 struct task_struct;
 struct scatterlist;
+struct bio_vec;
 struct urb;
 
 #ifdef CONFIG_KMSAN
@@ -209,6 +210,20 @@ void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
 void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 			 enum dma_data_direction dir);
 
+/**
+ * kmsan_handle_dma_bvecs() - Handle a DMA transfer using bio_vec array.
+ * @bvecs: bio_vec array holding DMA buffers.
+ * @nents: number of scatterlist entries.
+ * @dir:   one of possible dma_data_direction values.
+ *
+ * Depending on @direction, KMSAN:
+ * * checks the buffers in the bio_vec array, if they are copied to device;
+ * * initializes the buffers, if they are copied from device;
+ * * does both, if this is a DMA_BIDIRECTIONAL transfer.
+ */
+void kmsan_handle_dma_bvecs(struct bio_vec *bv, int nents,
+			    enum dma_data_direction dir);
+
 /**
  * kmsan_handle_urb() - Handle a USB data transfer.
  * @urb:    struct urb pointer.
@@ -321,6 +336,11 @@ static inline void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 {
 }
 
+static inline void kmsan_handle_dma_bvecs(struct bio_vec *bv, int nents,
+					  enum dma_data_direction dir)
+{
+}
+
 static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
 }
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692..87846011c9bd 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -358,6 +358,19 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 				 dir);
 }
 
+void kmsan_handle_dma_bvecs(struct bio_vec *bvecs, int nents,
+			    enum dma_data_direction dir)
+{
+	struct bio_vec *item;
+	int i;
+
+	for (i = 0; i < nents; i++) {
+		item = &bvecs[i];
+		kmsan_handle_dma(bv_page(item), item->bv_offset, item->bv_len,
+				 dir);
+	}
+}
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/169772915869.5232.9306605321315591579.stgit%40klimt.1015granger.net.
