Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMXAU2DAMGQE6TERWMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id D5C843A94A4
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 10:02:59 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id i13-20020a5e9e0d0000b029042f7925649esf1351955ioq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 01:02:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623830579; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q021T00pHdwQk299dIfqf3yikvPXzmv4ymsL+99JD0Gcqjisd+1tfyYvKRWHEQgG6h
         UshxZumxL9uAVWdeZ67VFSwN/lQKZDmpZqvKaJCPw7veKYiOKnjodl/yEVCPR6sfTZwh
         NHjeqxLpk+hZy2KQZVQRHQsP/oZVrDBRcmSeQlf2l0hth1OXlxLrkb6E+vdgZoltQoOu
         2jCPTHbMovF1HBMRtTI6FbPJpuECCvoWNcW7ph4wfUV/xvvlcuEbTrkHN1+Rs/vZv0hr
         MTDBP6oQxSHTgmc+PhUXkszRxJsjzv513d+G0ZO+whtrCjJMx04mZ8gyHvimUxHDMcyg
         MyOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gw014+UrMH9p0Kq1bnlJo3EtXN06QI0B6sRk15LWig4=;
        b=l0+SSLqgLadgdLyy3B/7hlUv4VNEWQY9NHLqrlimYebF08uBGq1Ceknc9wd9CxIGLn
         4aOC5nTtd577KshM0rP9/noKAAGFUuGSrv3gufordG4192v0+zSIzk3WkZa8nPG+5bkE
         8fmqFKFxsvQDtLfWaRjhuh1vjcCer06ZBrgluEZi423s1MlfVHywmzQEVp4Yybi6b4cw
         2lE7+YrLeS1AJ5cThjQpMGMG528y/Y5UM/kZm6loit/4nHdtVB1egC3rBumyXt5BHDAo
         TBo179B6ehEzbkEO+9CiwJ2prIyaYWB0x+1T4sK5ZSx6z/pHobFavrQu7eiv5shrtKsI
         9yGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rWR8koka;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gw014+UrMH9p0Kq1bnlJo3EtXN06QI0B6sRk15LWig4=;
        b=f6gVATLrWqmnXRpirkQBKO1iueGdTVpv/q0QxrThiskOds+3E//88UNNI6ZBM0/+NJ
         9N4RFucdMR+0H4qYWVcDvbxrZtN3ZtyK+dgSx8KoK8ODRe7/LOAU2RugJpC18RULpqPG
         alwDIPk+gkEOsWk1rM6W5AwcSdQo5BF+3fuAkg9J+EUXnUme6PolcN1Zb8v0rRSPebcu
         r/C6s7FvqBFxRNDGjoDmTa9jRLS2VFQujP6c5zfGgNok9fP5nE3VKIGz9JFiebnkkcaJ
         fDj2y2U9BTBc/3BciXGrZWwrCa4xR7G4m2IJMoqbwsQXd/tjBBDZxlckpdisSiVLHzkU
         CPIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gw014+UrMH9p0Kq1bnlJo3EtXN06QI0B6sRk15LWig4=;
        b=LuN5A3MmKc/PiNuoYn50IS4DXKe9NLZfELowxS+L/EP1dlZgyYJDCQXa9jMog81lt5
         49KEo9f2REOdsAA6Cz3i09+CvKBsJdHqGmceGkvFII5YEgfOBg4KGv3IKnSiMuA3RgSZ
         tZSBdI1wokpn3NIQxu1daMFqMsJQnD2V8Zcltl3+tAH8R/4dYV2MJfn+jZGn1QrsfJOf
         to/tftLIGHOMXsV1ntlsfomaeBwJIeeaUBotLFPKBAfiUkVOAfN93VRsufYEiSMrDx/n
         upRTSQbacxVSYzSUjSXO5+q4loFku/kE3jSvU5hmcppfVxu7m6G/3EYtZbBXSQ5gX8ss
         KJeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JKTmvGqTw0cfukZoqd5eTIlcY00wIA65RESs1y5vpPo6i1FEf
	LFuFu9XjQQQs20IW3Shb/ss=
X-Google-Smtp-Source: ABdhPJxlkX1nobHFiM5SdKVSc+yFzX1ZHB5Osy1ZMBEPIGwFyj84w6NDi/3iRgQMlvBqdTDVuSjOog==
X-Received: by 2002:a05:6e02:1068:: with SMTP id q8mr2758965ilj.276.1623830578860;
        Wed, 16 Jun 2021 01:02:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8d02:: with SMTP id p2ls225302ioj.6.gmail; Wed, 16 Jun
 2021 01:02:58 -0700 (PDT)
X-Received: by 2002:a5d:8986:: with SMTP id m6mr2584853iol.87.1623830578541;
        Wed, 16 Jun 2021 01:02:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623830578; cv=none;
        d=google.com; s=arc-20160816;
        b=pIrFPJCBEY+R2tfT9Wrkct8wtt0feqnhRAFOWJ4t7EjqSmQKLEIe9CWoGIQT1DLMPI
         yalriDY9bv9sPgt0RIiBTB9V0TYKCDeXYRw1GtFTfHQw6DJhGx80aH5f/9rcD5xp7aN3
         GjdZmdwmX+rwPF0YM2/pCkdKsgZ6hASw18x2H/GqsYNVzscpZTtQEHM3xjP/sArKt6ef
         aQmQkM5/V/DyuLUiYGw8U4UF3orf1FmyA14qTaqfDYpwBP+52VDZdCGK1H1bhW1IxjNp
         e2BGBHSF//FgnOzubXcgdvHIssZU7g2Xmx3OE/BF2HixYAtmn1k8Yn+YobVdwUEwm1Np
         T3Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rH421sL9ZKJVhIfbMwMWVv41eEYVWpLNRPNIYH4GF8E=;
        b=OlUb2TC2O3xKjikES6rqZ6idXIHBXM5Jj8UQo4dYmEQESrO71+++CLZuDbuObLTkX1
         bLBEpT7e3vJgc9RKtgSEhvjdAaWpX3rq7xdP0iqjHhnPW9lonrKK7KeLU16YCwglSOZm
         1vJOeKpC/T9dF8/bAdUo6czj1ldiPubw+RPErB6Ktfp+LhB1Owin23kIrDlm+36l2x8t
         RXiJ7YVtnh93fK4Oj++9FxvIHzIIKYOYznIkXgNfe1YIHQNHvt9RqdK1TL+BhcGhwk/G
         QKoAdA12esPsctpBV+JuVb3kNDepjBvD7gp4eD9TCc2LzE74tyWDeIe0/bBfsn72F83m
         cWUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rWR8koka;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id v124si127606iof.2.2021.06.16.01.02.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 01:02:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id 13-20020a17090a08cdb029016eed209ca4so1293421pjn.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 01:02:58 -0700 (PDT)
X-Received: by 2002:a17:90a:29e2:: with SMTP id h89mr3700284pjd.93.1623830578010;
        Wed, 16 Jun 2021 01:02:58 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id z3sm1398579pgl.77.2021.06.16.01.02.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 01:02:57 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [PATCH v13 2/3] kasan: allow architectures to provide an outline readiness check
Date: Wed, 16 Jun 2021 18:02:43 +1000
Message-Id: <20210616080244.51236-3-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210616080244.51236-1-dja@axtens.net>
References: <20210616080244.51236-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=rWR8koka;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Allow architectures to define a kasan_arch_is_ready() hook that bails
out of any function that's about to touch the shadow unless the arch
says that it is ready for the memory to be accessed. This is fairly
uninvasive and should have a negligible performance penalty.

This will only work in outline mode, so an arch must specify
ARCH_DISABLE_KASAN_INLINE if it requires this.

Cc: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

I discuss the justfication for this later in the series. Also,
both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
---
 mm/kasan/common.c  | 4 ++++
 mm/kasan/generic.c | 3 +++
 mm/kasan/kasan.h   | 4 ++++
 mm/kasan/shadow.c  | 8 ++++++++
 4 files changed, 19 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 10177cc26d06..0ad615f3801d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	u8 tag;
 	void *tagged_object;
 
+	/* Bail if the arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return false;
+
 	tag = get_tag(object);
 	tagged_object = object;
 	object = kasan_reset_tag(object);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 53cbf28859b5..c3f5ba7a294a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..19323a3d5975 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -449,6 +449,10 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 082ee5b6d9a1..3c7f7efe6f68 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
@@ -99,6 +103,10 @@ EXPORT_SYMBOL(kasan_poison);
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-3-dja%40axtens.net.
