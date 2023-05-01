Return-Path: <kasan-dev+bncBC7OD3FKWUERBNO6X6RAMGQEAOMNMMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 037C56F33F5
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:23 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-32f240747cdsf169185785ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960182; cv=pass;
        d=google.com; s=arc-20160816;
        b=O49alObOgk1dQX3nJZeeGdPG7TQOh5aNKXtTCyiDeUs4gB4sK79KU0vPklWfkrsSMy
         zVEN3bWQRGk9Hn1csrV9LwwOaBodn5DYrrPhtHo09qRuXWy2XR2eRhzFdiWBVpMvQl5M
         Tj6bWzfMIxDEmid1b7p5I5uLaJIVRKyw+mIM4OKr5zCxXnmUHFJyNGFF7iynhdQTON8V
         fTiJvD1VFDsjlFnl6EvImzTeZhyHvX9o5UfTUBfZF9viTOQ2OB6d9rkEStrDEe/WK0ni
         V4LwblxBmcGvCc1fBYcpVw0zLkx8O8nFxVuinmTyl/gOYB6OGAyekXglOakWxDSDUw1H
         b/Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QeGaapIb+YI/HiI+NxZ88G9ykwYZZMzcymJ2OOvpTeA=;
        b=T5HaIbqjI1bvyjECc8Go30DSu4PjnfKan+0OyRIDYW6gyh9pT4Dq2ZHz1XG7Kfni1n
         kaUlUlhZIW3kqCOOEaHogqnaospVkNfq/bnsws6a1wG7dsBR7Vx9AAVCLjKoURDPqK3t
         Zr6F1eiAhzRU61yhGEnnVQhOJ2lOCrU+k6R7Eg0vPHqyU1YopoIDvaML8iTISjgKzORd
         7P8o7NzKeTDwyGrSsXOv13+gImtdjbX57KZz+zpb0ZqVsrOqxe+QFd/546tdMHEa17RQ
         V/7IF6whYIFOAWBHrfeN6aKXEV9egwmydRhGIH4asyL89ic7z1nL6aCaoR/egS5e0oS2
         QnDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Aq78soAa;
       spf=pass (google.com: domain of 3no9pzaykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3NO9PZAYKCXsrtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960182; x=1685552182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QeGaapIb+YI/HiI+NxZ88G9ykwYZZMzcymJ2OOvpTeA=;
        b=B9+KtR1E9R6vDtOt+1vXVWD1G9SNsTj8v6i+PfkpJ0Sy2kSmAAy+0qGk3pnxFKReiD
         udBCCi/mm30AXEo1/5FEc35lqkiRRI32q3QFVVp7bgQ6DvujQaUL9XUXHh+Gc5J6Snu3
         s3DPB+cPx8zFTBF4nb8l7hcByfT1djkNfONy3MGzrdov+KZpUsNSWl46fxoIYVK8xtnm
         HOte5duJcnDy22K69VAefqpfOtAJL4neKNTDNLp521pcdx+zjssjWJA9yUls7Oa/ri+Q
         tnyPnlCRoVzjnByku4EXVqDTBPp1ux2UOz3AwBaKypdw6TfcwRkZNcYjsRfZbKCwxxch
         4rtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960182; x=1685552182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QeGaapIb+YI/HiI+NxZ88G9ykwYZZMzcymJ2OOvpTeA=;
        b=j063fzGNeo7RfYR0lSNhiRLr648yJZ2elKnNNqa1RCWUBNxo40xv2Kpz6/dHT1k5qP
         JG1Txte4i76O6mnOBvAISrRJuf53KL4GCa/WJy26FwReXGvqQT+UKrawZ3VPFBQo3hG8
         Jka7s6UahmBQTMrPUD3clnGgThJXjfubvbgkP5Ji3Aops36IzPjivxp71L8DJyoeAsg1
         U3XoiVIwANxUHCyJWAs+j5dfohdm6gjqfLHiNNFaz8K+jMxPy2rO2Eqzihcf92SSW10j
         6o/hAijvOSq3HC2zECuFdi2Qhn7o75zYiVtTeCg3EDWl5WuwEQNtCbw+rhdQQ9XuXWMN
         JHOA==
X-Gm-Message-State: AC+VfDyLxBk5uzAfkBmb75Ctwv0S3Qhb2NtuucMokBxI1/F9gWx3Wz1F
	dKH+hKIcec3PwqBUwDKdMQU=
X-Google-Smtp-Source: ACHHUZ47ohW/77zPZPlwmPcg+TjpcsdoUVD83J538oo54F/7UDsmqR/EAM4AnIpa/Xw7GhEWmgScfA==
X-Received: by 2002:a05:6638:36df:b0:40f:8f07:e28e with SMTP id t31-20020a05663836df00b0040f8f07e28emr12542314jau.1.1682960181883;
        Mon, 01 May 2023 09:56:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:c995:0:b0:763:5829:9243 with SMTP id z143-20020a6bc995000000b0076358299243ls2146782iof.7.-pod-prod-gmail;
 Mon, 01 May 2023 09:56:21 -0700 (PDT)
X-Received: by 2002:a5e:c017:0:b0:762:f8d4:6f4 with SMTP id u23-20020a5ec017000000b00762f8d406f4mr8882389iol.8.1682960181360;
        Mon, 01 May 2023 09:56:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960181; cv=none;
        d=google.com; s=arc-20160816;
        b=r8pk58vcnjyCmVwO+LIchyJQW8r//bNlVYl09v06372bP0ab8P1sZNlrr9yFZ/qnH4
         jFw8/PN2TKjembMOMaHXaER9I+n9gXSTe1/3f2GvJ/62Hr9/Ay2AVGY/kcJsu8iokjCG
         nbUKe73PLKvpSmiHB9rbXL/23zKyfAdZJCxUXWwgWccGoypZvxSaD2ZLmPyz6zr5z2Z1
         gWXlVAEl6DRaCj8Q5AnyJa6vH2yDCCwZeIlyJFw55sQSfiBU4SBOasrZDAdGwGN+KbPH
         CCmblD3aHL9T5EQlstd/okF69afIwf6SpS/QmePPixOLgXqsRzRRJyl82/sgGpkQLCA4
         Akkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jY4Why07vSNVPpYg+gbjry+wnVwWuxvaUCerSTimV/s=;
        b=UU8egJRD3bvaGfF2SHvAI50gLprhv/2DelJUYO6z/qqCyDp0Ur1jc1CcmXGxJ6NuHz
         H75guaXRsQC4ezegJmM9Si9WeAx9XgLVDXmDPlHyvET6OfUwOkX+L3EkC1sqb5S+z3ih
         /EcY8UZpQBwOmqj9mAmLP8P+4GDuXuVejMAmrwUAwQ7M2CjNp4e/vwXYZxJn/92sziN6
         iRbzeZFXplj/LwKBIiErnRMUTN3SFdKk40Izk4zPqpFFIen4TEvJxTkmRUBQXBCxNFkf
         iaCt9tm0Yl9jabnDW1vwOne9QPb75YLvf9qtUl9pPI5RKQ2kqoR9+SmguVMZAVi+hAoO
         zBIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Aq78soAa;
       spf=pass (google.com: domain of 3no9pzaykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3NO9PZAYKCXsrtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id c7-20020a0566022d0700b00760fac3ba91si1525318iow.2.2023.05.01.09.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3no9pzaykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-b9e50081556so491582276.3
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:21 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:24c4:0:b0:997:c919:4484 with SMTP id
 k187-20020a2524c4000000b00997c9194484mr5789976ybk.6.1682960180824; Mon, 01
 May 2023 09:56:20 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:42 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-33-surenb@google.com>
Subject: [PATCH 32/40] arm64: Fix circular header dependency
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
 header.i=@google.com header.s=20221208 header.b=Aq78soAa;       spf=pass
 (google.com: domain of 3no9pzaykcxsrtqdmafnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3NO9PZAYKCXsrtqdmafnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--surenb.bounces.google.com;
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

Replace linux/percpu.h include with asm/percpu.h to avoid circular
dependency.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/arm64/include/asm/spectre.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/spectre.h b/arch/arm64/include/asm/spectre.h
index db7b371b367c..31823d9715ab 100644
--- a/arch/arm64/include/asm/spectre.h
+++ b/arch/arm64/include/asm/spectre.h
@@ -13,8 +13,8 @@
 #define __BP_HARDEN_HYP_VECS_SZ	((BP_HARDEN_EL2_SLOTS - 1) * SZ_2K)
 
 #ifndef __ASSEMBLY__
-
-#include <linux/percpu.h>
+#include <linux/smp.h>
+#include <asm/percpu.h>
 
 #include <asm/cpufeature.h>
 #include <asm/virt.h>
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-33-surenb%40google.com.
