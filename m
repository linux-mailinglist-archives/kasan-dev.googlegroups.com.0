Return-Path: <kasan-dev+bncBDAOJ6534YNBB64N57BAMGQEMZWHSSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19E4EAE7E0E
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:27 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3a579058758sf2710076f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845181; cv=pass;
        d=google.com; s=arc-20240605;
        b=LnFPKAzGWOoBfSW8FQEZ1NxMMliGk9l2hmeSeeLSY+YbzF9QoWMabHV9oA1po0jDxX
         /stcGlObH+xbctsECO3VuCgpIAopKFuAO3Nh0+Bgjn8g6JTP35XTdwtaqu0sZ/Wb7Kt4
         bv6h7M0J573gX0Y6eoFcb7YH8s92lab6gShT+Lo/qL965ASBQJr2g15TVu+OX+LzA1Kp
         e77PyKK6I+W6JZGFl/WgLpJJjckdvo1iu/hEjNAbMOwYn4Grm83N0TaNd6PNOhEeLYKk
         7XklqLbrT7HEE8bLUQ75Y2XkzxlGxBVfc8RInNMjHmsRYXmiSlgz3NGGha3Xs8y5V1gB
         V6Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RnZOddxm7o3ujjORuh9dRobXZzH5ZyT/NQumdyFANiA=;
        fh=opCveXUbQWnigrsh5VkIJVNL4iJ2NJ6yc05k2jgAxi0=;
        b=caITCoauPRb8Xe5GvGUrgyZIdqJpdA/g8i7xIwHIhHkKeIIQA0tm6ZbeR9WcPpHGs2
         2O99HsSk626GC4YPWNOIfvpzFBpfrc9cOz1MoCEPa/3de3GsPLchEG0hFKLscAeE+Jrj
         0xAjBicm/cvMOvJVnQQ6Lvn85DsWezPANECARwryZjsXfq5ZZht7aoSjrtP61hcl8Pgu
         1HvHPQ9XqpEpYaJ4I7kP4VKQd8r6pUnBjls7L1N0Ur1jRcLxx+72giTjm8ds/zzGye+R
         PbCv/qOq6vRIRZ4isAyU4JrerIgJRzq+yka32TcyrvlVtb3Rg4+r0gMOMpMiMfqm/uoc
         7Wmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Rf6SoonE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845181; x=1751449981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RnZOddxm7o3ujjORuh9dRobXZzH5ZyT/NQumdyFANiA=;
        b=wkpRyu5De/aaZJVbCg/93qOyvOZw5BtFR2p5ibT1oIPHPSfJJcSGDvmEWSkU43SCAz
         IIvkJE0WdN4kUiAV+OSwpABtV0JJsabYoYumYqNo5rfODdQAXaQSf+ciB3sLThnClV/p
         64DyH8PB3k5Gdp4SLkXFtZ0Fht5kWxt02yccsg39A9FU013H5TvmwfGE78uFj9vQLKwF
         uCabjnKGlPuFDc/lB8Y01youb1yyTFPc0tRmr3en5k4lz0SWzfQXg1/4W/dmJ7Wm8fC3
         99/VU01ZpLUJWKp+2PTpMP0PJO485uyvVpc6UBV5JCVp88XzDJ/xJ0jvHynvAGn09azW
         /pcQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845181; x=1751449981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RnZOddxm7o3ujjORuh9dRobXZzH5ZyT/NQumdyFANiA=;
        b=RoLHIprYEgaqokYWZJEqUpZNJXwnHuMhj3DM1csaXuShMuiqi35tTQLrjJBNTWucqq
         Sd0KHtGjxyJwUii1Abp7lZz2mdJMQitMGF2a8faYz2qmFe0LGDceS76Prf5UBeUiY9DF
         Pnn+3X8XKN0ec1ao5dycekskjsP4IOEfCQMVURGkjb/+h1SPZ3xCO9IwyqlfR46wu3yO
         yhecWNBaoYbYuQ4VwQvRN/tb3i90OofvhdVQasJw393A0mJ5VaVOUj6cCAAVZW/EIOo5
         GoMacGJe/eU0f0fAsmihqdPHbTi81N3Z+Xyg9WykvNZk1diaDMEBG9aio7fHB6/5ny+J
         L+kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845181; x=1751449981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RnZOddxm7o3ujjORuh9dRobXZzH5ZyT/NQumdyFANiA=;
        b=DonmvHUP+OR6VurzQAzUeMLnRVaqGWeiQxSvS3hk1d+UgTKWmy28y6V8UCL7rDynm3
         pbT98vStNelp/IPqgj/hMVBpt4mwM/EcmGSkahOluchqXSlYZmkHUCdXmA8SmlyuT/LB
         E1XnA1lGMM36LlsqZFbsuTA097z5GgtgQesgKEape3z4SmtdenyRw9MO015haNkvuD5/
         H84r5qF6Ts4Z3Nvz9p/1o1jAjaHUVStzhpOyQAPCZIra1Q4io5Vd9aIn0rEziY8BYtUA
         fU/1ZoFXUf1+7V3FT243ce2Dq4LPT77oTnk25EDti6vJW6pIN8zFpdP/Di+imQ2NXIKg
         zFcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXf8VPnwVr7CyP74J42PyJ4KSWJPCQdecy/cWY8vNAWIZugGIH1a4blxhmcFa9BbEc6cRskrQ==@lfdr.de
X-Gm-Message-State: AOJu0YwX3USXANBc1EU6pdnMkZwF+gToIt9XU5i1CAZ39DhuvoDtzDjq
	qpOnd+xkfWkexJkMOjLbwjxJEvCdGcdk6ZjlgpzVfx6bph5tesL2Sch8
X-Google-Smtp-Source: AGHT+IFBb0AtbEjNDZTnBgp9DHvdCcoojpgBpZdbZZ1PBH10l2cwdXpWoNTsDYjpoBU/ZYLyMc2AUA==
X-Received: by 2002:a05:6000:2287:b0:3a5:27ba:47a8 with SMTP id ffacd0b85a97d-3a6ed65d23amr1677854f8f.52.1750845180393;
        Wed, 25 Jun 2025 02:53:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEwS5gRZpQ2L+PGqEP1dyatYl6NGiR2XaKa/WhFSb/vQ==
Received: by 2002:a05:600c:1ca4:b0:43c:ed54:13bf with SMTP id
 5b1f17b1804b1-4535f27adfals33395545e9.2.-pod-prod-06-eu; Wed, 25 Jun 2025
 02:52:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXpHx0VgvCOlUh7cJgYGrrvWm/X4wCtRKeOgk00ZkkBbYZjuomTXu99g6IISp8p9lXMdtZneNlXL0=@googlegroups.com
X-Received: by 2002:a05:600c:3586:b0:440:54ef:dfdc with SMTP id 5b1f17b1804b1-45381ab7ec3mr21627015e9.8.1750845178188;
        Wed, 25 Jun 2025 02:52:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845178; cv=none;
        d=google.com; s=arc-20240605;
        b=HIP+NQRKby2Cr8BjXAb9e76xmZa5VrDZ3Fr0k/kzb565LoKd3CNdaQ0sa4tuAGp3Q9
         6kM00er55pvbbi3ySOQZcd/eYzvPSoDphPLH1gl+6+soqwPN6MNRA4olzKQ3DqaGz9r9
         3KnXHmS0qATSx5zYAddsfSyVP34RfK9orLQBQ+g/ez0BKQxDRBrpgs5o5Cg5faCDye1P
         e9m54z57IKlUcNw0kPjCV5ZCKsISPh0IcLZeQwQOwUm1QjsN9a0H0ibTVWHrt1ftTn6y
         2L1vGlvAtaPJrQBkwM80qPxTapX6Lj3Ynn6AAN2U8Gw4mvFGIouywZJBeCjc/08ka6JP
         jS4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=spnPWYrTCugBtv3C0I1/Y7oTbF6XlJIePRXoFmRkZ78=;
        fh=ifMAHHdWnfH2KnnoDm1ZBZ/H957ZH9px01MnLpzfGIg=;
        b=fsOWDeorD8esGAdVjHsJVu/QPsfY9xl/mKYy9Rc5oE4kZwpJ8LOxRp3IY9bQ8JXaCI
         Axr55SiRAbvR9JcJKDuYWx3AF64rcJ6PzVznQEL2bD2rwxZOecpfvP/KhtK0tyf0Tims
         //WgI5Atr2c08XOI1YrEMWjyYlTLsGFdlbKUf3QGWTSbpBJzhNqPv+sTi2hY0ituq7HX
         hqtC7/3pvRAUrDurxNN8rIc0N46DaCfafFGHDdmqOWszPY8t3wrRwOis8n2/EajmZdov
         CNujPgyA/lUfNGAH+kWClCZpGlj+1+3k/WLroGEGNxiXxrOag1yOWBRLY9ipA714Y6TW
         /XSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Rf6SoonE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453822d391csi282395e9.0.2025.06.25.02.52.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:52:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id 38308e7fff4ca-32add56e9ddso52457871fa.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:52:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1sSbD4OxonW1vDf5x22RHYis5BPsbYeZcaDt9npsjM5dMadO3acYmvJWZrX1Qc0tpwHgdQPa07+s=@googlegroups.com
X-Gm-Gg: ASbGncubv9uL3ZGiwys4A2WGTCghYvX/TNPPzVHabVW0VGl5Af+2Hw4mFpBmuXf+Hxj
	E+y/pY4m4SMu6lxPEr3g+u9I1iFW+XC7oa4Zzn0tjyxEffU28nhnCkzWhfhVYzN0E7OexClR4qD
	cPyOmbQfxNOsIlPfbYWLG4wbyoYS9afdM7QQbXYR41RKlo7U4nl2o606xB3axGSfiy/Ki6CqAXU
	kN+oSSOBHL8Dew0owy+0LBcrHP/cXHHbPUg/pffesNLEuiqk3r79ZhXB9LRpbf6kz2tYbKr7qlj
	qDk+HxxOw3mBqmMO8GJfqeCfbWWMk4mX9Qp201WvtRt5GBy2ugPLIUAaqudBgfD60YxiLej1GtB
	54iTJaNv+cJBfMlsjot40p+8V/pkCCw==
X-Received: by 2002:a2e:7806:0:b0:32c:a709:80ee with SMTP id 38308e7fff4ca-32cc6582a2emr4097091fa.39.1750845177105;
        Wed, 25 Jun 2025 02:52:57 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.52.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:52:56 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 2/9] kasan: replace kasan_arch_is_ready with kasan_enabled
Date: Wed, 25 Jun 2025 14:52:17 +0500
Message-Id: <20250625095224.118679-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Rf6SoonE;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22d
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Replace the existing kasan_arch_is_ready() calls with kasan_enabled().
Drop checks where the caller is already under kasan_enabled() condition.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/common.c  |  8 ++++----
 mm/kasan/generic.c |  6 +++---
 mm/kasan/kasan.h   |  6 ------
 mm/kasan/shadow.c  | 15 +++------------
 4 files changed, 10 insertions(+), 25 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 525194da25f..0f3648335a6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -257,7 +257,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (!kasan_enabled() || is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
@@ -265,7 +265,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 		       bool still_accessible)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (!kasan_enabled() || is_kfence_address(object))
 		return false;
 
 	poison_slab_object(cache, object, init, still_accessible);
@@ -289,7 +289,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return false;
 
 	if (ptr != page_address(virt_to_head_page(ptr))) {
@@ -518,7 +518,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		return true;
 	}
 
-	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+	if (is_kfence_address(ptr) || !kasan_enabled())
 		return true;
 
 	slab = folio_slab(folio);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index ab9ab30caf4..af2f2077a45 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -176,7 +176,7 @@ static __always_inline bool check_region_inline(const void *addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return true;
 
 	if (unlikely(size == 0))
@@ -204,7 +204,7 @@ bool kasan_byte_accessible(const void *addr)
 {
 	s8 shadow_byte;
 
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return true;
 
 	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
@@ -506,7 +506,7 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return;
 
 	/* Check if free meta is valid. */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e6..e0ffc16495d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -544,12 +544,6 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifndef kasan_arch_is_ready
-static inline bool kasan_arch_is_ready(void)	{ return true; }
-#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
-#error kasan_arch_is_ready only works in KASAN generic outline mode!
-#endif
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_kunit_test_suite_start(void);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb..9db8548ccb4 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -125,7 +125,7 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return;
 
 	/*
@@ -150,9 +150,6 @@ EXPORT_SYMBOL_GPL(kasan_poison);
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
@@ -390,7 +387,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return 0;
 
 	if (!is_vmalloc_or_module_addr((void *)addr))
@@ -560,7 +557,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return;
 
 	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
@@ -611,9 +608,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
 
-	if (!kasan_arch_is_ready())
-		return (void *)start;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
@@ -636,9 +630,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-3-snovitoll%40gmail.com.
