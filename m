Return-Path: <kasan-dev+bncBDKPDS4R5ECRBZHURKQQMGQEHXKWYYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B497C6CBB9E
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:59:01 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id h19-20020a056e021d9300b00318f6b50475sf7569951ila.21
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:59:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997540; cv=pass;
        d=google.com; s=arc-20160816;
        b=GlJqjbrqe6KXaK/E7y37+xfJ3ge7rnKuddPprk4GIRMbeU3xEZ+NWrWFE6us4PEUmS
         78iw9BGGmwzYM5wSsZE+oCcvnf1WqhXMgK3V7s0xjSgyWUF0rpCYyio6wJ/O43yiSGtY
         6GzsQLmVCTc/ZGlFPm2Uct0+coiWm2MeLk5L0IVNXvLI+O0AkL/MejZY4AB7MFA2CJnA
         0vZXKq0/J23P5RpnVKhNMCk9cV0CO8VHkicB4xfWa23S2ARkxjGQDv1zwzkkEkQyEWLF
         eV8TFOs7jpCWSq3WBKHnu9rhGYAqMNgONTXoQ4H42stM7w46TYIsnlvDeKkz8GBthE0Q
         WYVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=iqOQ+womc7vkV9GJGdXTS+vgwT7gxD3akRw3BvVFFKs=;
        b=esBp7g/XKs3fm2O1glvJoJqu8nSH5FVI+GVkneV8/WXo/dHR5LpcGTiXNd1bLoeX6f
         fZDsLEzGwm4ywyM5YWVaSSbv2TSZ2RFRob3qHfegjpSv1c7yEZZdX0i9En7JFtr7aIJ2
         TMBAGZjeDtoOKPDLXZ4yeeyYfS4SLfqggInEc7+2/IFcs/1bs79FnnWRbbB2/NawOTNj
         5O9ZH9mGwoFsOfDsu884KS+1x76YlxweMD99WYIJp1Y96cvSAYZ93VLH1VtC++R+nDmS
         xkLL0Vxcup4A0jiQkiPja+CAxkcqcRMdM0BfzLS04edSkzyReCXuMGXWbDRZ3sy8kfJF
         sZJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=VsNWH6wb;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iqOQ+womc7vkV9GJGdXTS+vgwT7gxD3akRw3BvVFFKs=;
        b=NfP3MzH+LMqUHyQRi6AklqP3TVA6hFw5duwBrhgFFcNMDu4lQkSEdofOkySJ3VTubV
         V6nPmCR2/iKJK02jxwIOIwJ8gupjopWFcvCd4nTabC+H523Z4Lpbu0crd2W56AGl4kRe
         zxzK8hVQ6n8GRrPPplf6zKbWgZ6+mKTZi0x4VjQ0N+pEfG9CUHioSZOAB4nd5wJRYgcA
         /3/uExPXXmFlpjio0IpkQFPvFVg4LP76mWAUQEDNPYlb/y4QHCC9VGzn7LhwdWfBZSi8
         kHK9tRkwowrWSJzs2SWQ02ssqAsSxH5xdbSTxcBGXF86t0U3Xz/f8a3lYPeDpMiIw8jh
         UlXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=iqOQ+womc7vkV9GJGdXTS+vgwT7gxD3akRw3BvVFFKs=;
        b=2GvVLS71YjWcBS1e8HHfLYya4VfIxaQLcXTX4vGLAMlFkLk6W/8Pf0Ydcz52ySBnpf
         WZoQ+UFXJhKJGkHzrln56mDgUZw6ajTNLDRDbqNxEWGgLUYMti7br69nQGdHHKBj4Her
         XEpb7RhcdU71JDFSzctxYPMKyZA9cCiCW2Pl+CB2tSLi/o2M9ed+fhPXSIbecWKmfsu9
         6GCr7jNXlQFOiUdqLBt2KTtvQuvjp7kRPTXAxTgUHAnuQTY6S03ICA/mCzpE6BotqgJ3
         aYveoqpxFIfZhz9lpSHKXJhMNvgG3iezU7q2g212MJWA46VkXnIE7ex+qMvOLjZd6PuB
         sjMA==
X-Gm-Message-State: AO0yUKXlyyCDRz6KA0T0rEu37wvVt+SbzFuFVSTeotr0FA5wgd6xlfec
	BLBrny8cPh4FHbPz/QMit/Y=
X-Google-Smtp-Source: AK7set/PW/nNmqWJrFQSHuaAUy4279PGFiTkBm/MG4HefF1MMixMNfgNObfbXcph8A6sT+r8d0+WlQ==
X-Received: by 2002:a02:aa09:0:b0:3eb:fd40:78be with SMTP id r9-20020a02aa09000000b003ebfd4078bemr6116955jam.3.1679997540581;
        Tue, 28 Mar 2023 02:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:34a1:b0:325:cefc:db5b with SMTP id
 bp33-20020a056e0234a100b00325cefcdb5bls3296212ilb.7.-pod-prod-gmail; Tue, 28
 Mar 2023 02:59:00 -0700 (PDT)
X-Received: by 2002:a92:dd03:0:b0:316:e6e4:570b with SMTP id n3-20020a92dd03000000b00316e6e4570bmr10837570ilm.11.1679997540085;
        Tue, 28 Mar 2023 02:59:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997540; cv=none;
        d=google.com; s=arc-20160816;
        b=ERXCnj8Kx5dGIikq3NW4XDDlkPLMQnstJqaM+2EN1KDFJWUUqFAKwIw481QWSy6i3n
         NigxvmZxDx8YmAX7q4EervgPj4xvAL4k3mHprtXJQDTbIgcf459KVdzU6xdEhCAZAcv5
         ZFtzvxr7IysKWAD1ACTAKtPu9JofnZ4sMOE3Nt0GmZIcp/w3ieIk98DYzTblwiE42J+k
         QHXKHpmOj565u64LZppCCLSlYs05pFVqUG5NEuhBjNus0Ch9aszebCz0OR8h6QQblUc9
         P4+9gCBN3ealzmbmFd5h0YoDUWuYEYQTOjN/f2saQ6ybFh6up5Si2o6f39yHFX/O9knL
         oTKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=a9z+2OKezgBl6Xq8s4/uft3FH4lHgs0F/FglMYKuxZE=;
        b=sud49tV6AEgaqIA59Xcy6X8m/ttTmBJF0WpwaMWKlw9NHzoC5p7Lt0WY6DDVX9npF6
         UDXQ4trYwOS1b0LIvU3YQNGIwkr2stw5Mljb22mkfR/uS5spA38vDpJP6Tqy3crHt9bN
         gKcAuoyfnKM3Y8GradAOrFCSgfHAvxysHBV3xuC+RmHnDF3gAzI0ntHeg0kibXNKxBRc
         +cntHcAMPOWdF3PAo496osCctDQnCPfDyVZXll08uR2ApfradRseBYJ9qe5a8EI/+6JX
         NtoEQ+nBRudVtSCHI1vZXZxl0M/GPYVJOFirGPcqctQN5KwQ3hE/tLqq4sg8dzadghLp
         ESzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=VsNWH6wb;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id s19-20020a056638259300b0040619abb9aasi2918765jat.4.2023.03.28.02.59.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id f6-20020a17090ac28600b0023b9bf9eb63so11928405pjt.5
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:59:00 -0700 (PDT)
X-Received: by 2002:a05:6a20:6aa0:b0:d9:2d4e:c08c with SMTP id bi32-20020a056a206aa000b000d92d4ec08cmr12797492pzb.61.1679997539764;
        Tue, 28 Mar 2023 02:58:59 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.55
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:59 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 6/6] mm: kfence: replace ALIGN_DOWN(x, PAGE_SIZE) with PAGE_ALIGN_DOWN(x)
Date: Tue, 28 Mar 2023 17:58:07 +0800
Message-Id: <20230328095807.7014-7-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
In-Reply-To: <20230328095807.7014-1-songmuchun@bytedance.com>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=VsNWH6wb;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"
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

Replace ALIGN_DOWN(x, PAGE_SIZE) with PAGE_ALIGN_DOWN(x) to simplify
the code a bit.

Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index f205b860f460..dbfb79a4d624 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -230,17 +230,17 @@ static bool alloc_covered_contains(u32 alloc_stack_hash)
 
 static inline void kfence_protect(unsigned long addr)
 {
-	kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true);
+	kfence_protect_page(PAGE_ALIGN_DOWN(addr), true);
 }
 
 static inline void kfence_unprotect(unsigned long addr)
 {
-	kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false);
+	kfence_protect_page(PAGE_ALIGN_DOWN(addr), false);
 }
 
 static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
 {
-	return ALIGN_DOWN(meta->addr, PAGE_SIZE);
+	return PAGE_ALIGN_DOWN(meta->addr);
 }
 
 /*
@@ -308,7 +308,7 @@ static inline bool check_canary_byte(u8 *addr)
 /* __always_inline this to ensure we won't do an indirect call to fn. */
 static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
 {
-	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
+	const unsigned long pageaddr = PAGE_ALIGN_DOWN(meta->addr);
 	unsigned long addr;
 
 	/*
@@ -455,7 +455,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	}
 
 	/* Detect racy use-after-free, or incorrect reallocation of this page by KFENCE. */
-	kcsan_begin_scoped_access((void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE), PAGE_SIZE,
+	kcsan_begin_scoped_access((void *)PAGE_ALIGN_DOWN((unsigned long)addr), PAGE_SIZE,
 				  KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT,
 				  &assert_page_exclusive);
 
@@ -464,7 +464,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 
 	/* Restore page protection if there was an OOB access. */
 	if (meta->unprotected_page) {
-		memzero_explicit((void *)ALIGN_DOWN(meta->unprotected_page, PAGE_SIZE), PAGE_SIZE);
+		memzero_explicit((void *)PAGE_ALIGN_DOWN(meta->unprotected_page), PAGE_SIZE);
 		kfence_protect(meta->unprotected_page);
 		meta->unprotected_page = 0;
 	}
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-7-songmuchun%40bytedance.com.
