Return-Path: <kasan-dev+bncBDAOJ6534YNBBGNJZDCAMGQE45476TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 44CF8B1B659
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-3325794ba57sf15246351fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754403995; cv=pass;
        d=google.com; s=arc-20240605;
        b=g3G+KkUNOdtvdhbuxoFirOh0kcaJYth03+8OiF8ynUyK60fUgtc/UpF6aVEmZefzch
         XFSMwhWeo6O7xufOaUTC89ExNoZRjpSEHNsT5aFO+yZ8VpnP+IwuVRzWBrr5v5XFmS2c
         mm9sC0j1PbY9OoW1/vdOPVa08G/NeHMWxnluiFWTHzfXZBtaymmyy2kTavcU8j/44WHu
         fKeKw5PCMInLYwTiLo6sSu19jIBL8Jcjx8JI5CY7F31CgMhGkrUTgC4sdyyxSKiJbW0b
         yfT6WXaFmWNsXepnkeawGYhe3AMbg6VThmxKILrtrXdcu4n+mi/UPRkYzbtG5w/vhEOr
         By+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=saKPi22ldAnD7cL+9fBsrkG7e+/0oXMF8S79PqjLOWU=;
        fh=fbNVG0457SloMereRF5WbFTsh+XPSAeDJVIvVauc1RA=;
        b=PglwqZLA8gv+QQwcAkwsdSgLzbLGyOsfNXEH2DscaXumTORuYBe0vXjeKLJ5I7p9eR
         Rb6+Cfvm9g6aX6UFmmtqgeR3sTHEfqtIQ5ujzuM0/sDVs5JWTIqTCMOgELkFlc2ND37k
         U1oDd3JyAX9sQytzUwR8HG+g8ILX2KtYBbXE3ZFJ/XcKSVNqV2CsdGXqn0J81E2M3dNV
         smAZouY1apM9rMAj8ed52Wlh/PNNNiZwPasZoBjV2E4TM9JO32tVfS/zKUj2cwuPrzSo
         kNrO5hlVo6+dYwmWs07d6BOU5cYrsGtjDPX4YhO0SVgJY9xkxywyYeessW98sJsKh+EE
         coMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VJU99kQL;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754403995; x=1755008795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=saKPi22ldAnD7cL+9fBsrkG7e+/0oXMF8S79PqjLOWU=;
        b=caNNqLhBiwILr4ifonyJtqMPqJsLE8MghI7JSKeW/16iQFuA0/LbVOpvUPcQMwU/+2
         ccdESwbT3psHQxEEHAs2+NBme6WEto4tscc7/cGknYDWzZVEprI0pdgqlJlAazbiQ5MV
         ZJn/RH3UJG1l0jWR9jH2sS7IDyPw1eSxWCJL6L6s9HD8B96HynGj9JgvsSPJlgDn5giQ
         WrSbmbgIqWzxOnc9FimB5dJ7phGFSPQ03M0y9T1+HRYHDZJG2hDnRwuCO9zWMe2nv2ad
         vNtQ4UREPKx4s5fCHfEuenlEpc5Uttovhy6UnPQC7uvka/Yy+t1t4dJSnBjatrWQrcAR
         1c5w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754403995; x=1755008795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=saKPi22ldAnD7cL+9fBsrkG7e+/0oXMF8S79PqjLOWU=;
        b=cmFwUiBIyccJEWoeQhYzsDtMUwUc8kANu7xF2YU6TLdfEleMv1dB7ZA7jhsKnufJ07
         PvRDZniMhD4YKhPJC+Nz+GDJ//sYyEMSsWhbwDMegJ1zO81KKmQPtBguEhlbu4V8PzYZ
         FZ6lQAu5Ve1YExqkL8j8GtI7wj2yQddeggDRl6MxiwBfxAW8f+42f7nN9LzI+aRNm993
         pn0gKEhU8pKjbzVm3UxtbPrW+6lJrlpiHIrUux2EMyU1maOGpzXpenGe2KHVHJvp/nIl
         r8qM6Z/j0LEAYczAcnEStp2koB//8CLy55UsbuQJiPU5R+8rnM3N0CiHGXZIQg0+Pbgp
         7L8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754403995; x=1755008795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=saKPi22ldAnD7cL+9fBsrkG7e+/0oXMF8S79PqjLOWU=;
        b=Z22eSrKexC0oZhp1LvozSgwU4G3RaIVlG04Bxa2VVzguyxHwLWHPzNuJfwuRujTnJg
         yrW2fAaMm1dIKB8Ii0oLXgr+Wz8LOH6XpG3shEoBZxR3kAGuDvXiAf2u5zU2YDmZCMbm
         KVINczHc3HPcFdkcBH+rp4rikAtlmn1cOiSopoUXqBMF6C6MOrLwiUBBMicojFYwJ38Z
         qw5Jx/CA148XUMMrFuSXwZvJ1a5hqrZG2OLmtSTHPdUPt/iIG2GEPu0TqyynXt2KV4U0
         6FosT7L5hFXU+u8S7ddLgN7awhiFYz4ED1thU5DTm9tPfl1fAx+pRonJ5ssyMuA13RSY
         LZ4w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTINXxeXXsre+nGoU/sElaDCsZhXYFPJQN9HyLxBLqOL0vRHq/ptgb3kcAuvwVSUr5i3KRDg==@lfdr.de
X-Gm-Message-State: AOJu0YzUauMmOf1fW8rTBgO+kfL7iHvRzc/b55zImqzi7Ee9RAA48mym
	M6efdEnVhdmOhpCCXppKLkaIkH0oDzx7Qz3ud9FLZx+7zrrhxCyTjwCN
X-Google-Smtp-Source: AGHT+IFVHf0t1qnn5NuxfByPpSFNNflr9yXRwI05L1ku/Eum2Uo37xkIurASiItA25Ch5o5he8wN7Q==
X-Received: by 2002:a05:651c:2220:b0:331:e61a:21d0 with SMTP id 38308e7fff4ca-332566c9213mr44064311fa.8.1754403994575;
        Tue, 05 Aug 2025 07:26:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCq8/gZRTsOXYDhlEgp6UBW6SQd5UwSiNii+CSDjC0jg==
Received: by 2002:a05:651c:2115:b0:32a:8018:2a44 with SMTP id
 38308e7fff4ca-3323888a5d6ls17934751fa.1.-pod-prod-03-eu; Tue, 05 Aug 2025
 07:26:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwrvgT3p3eknGQGgcNa4kpdOMGzVFKE3CNcmZMhADTrSZaIrC7f8KXQ9vbRgpDx/6uasOPQVKN1RM=@googlegroups.com
X-Received: by 2002:a05:6512:3e16:b0:554:f74b:789e with SMTP id 2adb3069b0e04-55b97b93001mr4604054e87.43.1754403991594;
        Tue, 05 Aug 2025 07:26:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754403991; cv=none;
        d=google.com; s=arc-20240605;
        b=Jq00Tf+xgGQ6YDXj1qDyo+FAJwQ5Od2js1gU9Sm+mJRuhYYbyocp6MIEnwYZJTlARD
         hE5OOs6XlE7Gad3j0UzQQ3vJ54Bl38YImODO0OTvC6EJM0btCNa1Fbue8jQ6+H1aytOI
         KlXdKqbwnO9HF/4EcvkpQjfeq0iB62ytwbRHpa1dqCSLK1aO40RaSaiCZtaYf6mX7VJs
         w5OAXh7lqMOkj89pJU6xncilcxh7zPu9CvDMdA2EchNibC1G2tGJo615B4bXbi2auzNR
         njW75cYlfWe6ebkcXYLNbCL28iJvVCeVchUBlv1F8sOsOnbRtrZokCJv9LYGvu0oP2TG
         woqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=45SkqGXSprn3rZh3fzo6uRt8dTAwtmpvzDxxX6Brgt8=;
        fh=axpN3eatQvZVy2k4PkYnssQZyHRrz8CcRLAYwlNG5C8=;
        b=knuvXU3Rlq/eJHJZbAs3d+mkAkg+ZdYA8juPACkzlQbTxSYcrglF46l5AgcvpV/zh5
         sSjWVu34I3X5Eh13ZuDL++ZHqZ23tihYUxpmlxvVpZb5Lz/yTvF/yjTJEXn/S09LgARa
         JoJ3UDTGKcaU4nD6nJ0oosbGWRv5/tkY5SIjCZUHrus5mIpdtaV9C1VU1WNbXWaSsIjl
         4jyCFZXU9wX59QWcOT2OLW2IjePECfXSrt7dnRi2z4X3H/IR+3g4c0IaUcBVTCfDhrJX
         d2lN+4/bzJUFv7tkf33bqzZX3JhtlRr0VzzrtzjjLsWLACyDusCk362TYBOOKZ06VcJJ
         0BbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VJU99kQL;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8870e498si334788e87.0.2025.08.05.07.26.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-55b829c7f1aso6569000e87.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVuKdaSiYEthwir0zyETh0i7x4X4LU36DIXP0q0iRhdfNVjTPnwRg1abjlcUU43ZLv+aFMJBEd9qms=@googlegroups.com
X-Gm-Gg: ASbGncurmtctdXERkQslLwOiTuVDpivCKtyxgZ+VGVDCd18p2O+AYA2iRibb9YWRTmU
	irznQ/te9noWiLYO6jCS2TSBsJbT5fraYtH9IMJGl1NdwVY0IYjwn5e2GCZYk2u94xREwkAs3Pu
	Plmu6s1xh5fLwTHlRZetdg39/wh10l4DwJ2tOnYSQR2cbxPnyAZxmDOvQ9TLFXdZ4HK67fTZBNs
	94X6dTLBYxpehcOqQ1kHZv9vKht4zpUnKOya4z+xo+fWTuDZBCCLjuZCs5Y91k8+C7ILVfItF7O
	ch72XcZ03AYqtjSvrxOzApaOdH2W86hWPq2zsVGN4CBn6tTm9lrMfH1EujL1iFMhIUDl6InkJZv
	pHTbglKUbeA8f/xPqSfmSmoW9O14miczp4br2LCGRAh2bPl84Aoe3FJNWCME49pXusLj/Lw==
X-Received: by 2002:a05:6512:3053:b0:55b:858e:b602 with SMTP id 2adb3069b0e04-55b97b92fc6mr3295883e87.42.1754403990799;
        Tue, 05 Aug 2025 07:26:30 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:30 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 1/9] kasan: introduce ARCH_DEFER_KASAN and unify static key across modes
Date: Tue,  5 Aug 2025 19:26:14 +0500
Message-Id: <20250805142622.560992-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VJU99kQL;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
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

Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
to defer KASAN initialization until shadow memory is properly set up,
and unify the static key infrastructure across all KASAN modes.

Some architectures (like PowerPC with radix MMU) need to set up their
shadow memory mappings before KASAN can be safely enabled, while others
(like s390, x86, arm) can enable KASAN much earlier or even from the
beginning.

Historically, the runtime static key kasan_flag_enabled existed only for
CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
architecture-specific kasan_arch_is_ready() implementations or evaluated
KASAN checks unconditionally, leading to code duplication.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v4:
- Fixed HW_TAGS static key functionality (was broken in v3)
- Merged configuration and implementation for atomicity
---
 include/linux/kasan-enabled.h | 36 +++++++++++++++++++++++-------
 include/linux/kasan.h         | 42 +++++++++++++++++++++++++++--------
 lib/Kconfig.kasan             |  8 +++++++
 mm/kasan/common.c             | 18 ++++++++++-----
 mm/kasan/generic.c            | 23 +++++++++++--------
 mm/kasan/hw_tags.c            |  9 +-------
 mm/kasan/kasan.h              | 36 +++++++++++++++++++++---------
 mm/kasan/shadow.c             | 32 ++++++--------------------
 mm/kasan/sw_tags.c            |  4 +++-
 mm/kasan/tags.c               |  2 +-
 10 files changed, 133 insertions(+), 77 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0..52a3909f032 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,32 +4,52 @@
 
 #include <linux/static_key.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+/* Controls whether KASAN is enabled at all (compile-time check). */
+static __always_inline bool kasan_enabled(void)
+{
+	return IS_ENABLED(CONFIG_KASAN);
+}
 
+#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
+/*
+ * Global runtime flag for KASAN modes that need runtime control.
+ * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
+ */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
-static __always_inline bool kasan_enabled(void)
+/*
+ * Runtime control for shadow memory initialization or HW_TAGS mode.
+ * Uses static key for architectures that need deferred KASAN or HW_TAGS.
+ */
+static __always_inline bool kasan_shadow_initialized(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
+static inline void kasan_enable(void)
+{
+	static_branch_enable(&kasan_flag_enabled);
+}
+#else
+/* For architectures that can enable KASAN early, use compile-time check. */
+static __always_inline bool kasan_shadow_initialized(void)
 {
 	return kasan_enabled();
 }
 
-#else /* CONFIG_KASAN_HW_TAGS */
+static inline void kasan_enable(void) {}
+#endif /* CONFIG_ARCH_DEFER_KASAN || CONFIG_KASAN_HW_TAGS */
 
-static inline bool kasan_enabled(void)
+#ifdef CONFIG_KASAN_HW_TAGS
+static inline bool kasan_hw_tags_enabled(void)
 {
-	return IS_ENABLED(CONFIG_KASAN);
+	return kasan_shadow_initialized();
 }
-
+#else
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
 }
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* LINUX_KASAN_ENABLED_H */
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2..5bf05aed795 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -194,7 +194,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
 static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
 						void *object)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		return __kasan_slab_pre_free(s, object, _RET_IP_);
 	return false;
 }
@@ -229,7 +229,7 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s,
 						void *object, bool init,
 						bool still_accessible)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		return __kasan_slab_free(s, object, init, still_accessible);
 	return false;
 }
@@ -237,7 +237,7 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s,
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		__kasan_kfree_large(ptr, _RET_IP_);
 }
 
@@ -302,7 +302,7 @@ bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
 static __always_inline bool kasan_mempool_poison_pages(struct page *page,
 						       unsigned int order)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		return __kasan_mempool_poison_pages(page, order, _RET_IP_);
 	return true;
 }
@@ -356,7 +356,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  */
 static __always_inline bool kasan_mempool_poison_object(void *ptr)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		return __kasan_mempool_poison_object(ptr, _RET_IP_);
 	return true;
 }
@@ -543,6 +543,12 @@ void kasan_report_async(void);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_GENERIC
+void __init kasan_init_generic(void);
+#else
+static inline void kasan_init_generic(void) { }
+#endif
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
@@ -562,11 +568,29 @@ static inline void kasan_init_hw_tags(void) { }
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
+
+int __kasan_populate_vmalloc(unsigned long addr, unsigned long size);
+static inline int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
+{
+	if (!kasan_shadow_initialized())
+		return 0;
+	return __kasan_populate_vmalloc(addr, size);
+}
+
+void __kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end,
 			   unsigned long flags);
+static inline void kasan_release_vmalloc(unsigned long start,
+			   unsigned long end,
+			   unsigned long free_region_start,
+			   unsigned long free_region_end,
+			   unsigned long flags)
+{
+	if (kasan_shadow_initialized())
+		__kasan_release_vmalloc(start, end, free_region_start,
+			   free_region_end, flags);
+}
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
@@ -592,7 +616,7 @@ static __always_inline void *kasan_unpoison_vmalloc(const void *start,
 						unsigned long size,
 						kasan_vmalloc_flags_t flags)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		return __kasan_unpoison_vmalloc(start, size, flags);
 	return (void *)start;
 }
@@ -601,7 +625,7 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size);
 static __always_inline void kasan_poison_vmalloc(const void *start,
 						 unsigned long size)
 {
-	if (kasan_enabled())
+	if (kasan_shadow_initialized())
 		__kasan_poison_vmalloc(start, size);
 }
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830f..38456560c85 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -19,6 +19,14 @@ config ARCH_DISABLE_KASAN_INLINE
 	  Disables both inline and stack instrumentation. Selected by
 	  architectures that do not support these instrumentation types.
 
+config ARCH_DEFER_KASAN
+	bool
+	help
+	  Architectures should select this if they need to defer KASAN
+	  initialization until shadow memory is properly set up. This
+	  enables runtime control via static keys. Otherwise, KASAN uses
+	  compile-time constants for better performance.
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c7..dff5f7bfad1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,6 +32,15 @@
 #include "kasan.h"
 #include "../slab.h"
 
+#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
+/*
+ * Definition of the unified static key declared in kasan-enabled.h.
+ * This provides consistent runtime enable/disable across KASAN modes.
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+#endif
+
 struct slab *kasan_addr_to_slab(const void *addr)
 {
 	if (virt_addr_valid(addr))
@@ -250,7 +259,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
@@ -258,7 +267,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 		       bool still_accessible)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (is_kfence_address(object))
 		return false;
 
 	poison_slab_object(cache, object, init, still_accessible);
@@ -282,9 +291,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
-	if (!kasan_arch_is_ready())
-		return false;
-
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
@@ -511,7 +517,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		return true;
 	}
 
-	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+	if (is_kfence_address(ptr))
 		return true;
 
 	slab = folio_slab(folio);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e..1d20b925b9d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -36,6 +36,17 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/*
+ * Initialize Generic KASAN and enable runtime checks.
+ * This should be called from arch kasan_init() once shadow memory is ready.
+ */
+void __init kasan_init_generic(void)
+{
+	kasan_enable();
+
+	pr_info("KernelAddressSanitizer initialized (generic)\n");
+}
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
@@ -165,7 +176,7 @@ static __always_inline bool check_region_inline(const void *addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_shadow_initialized())
 		return true;
 
 	if (unlikely(size == 0))
@@ -189,13 +200,10 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 	return check_region_inline(addr, size, write, ret_ip);
 }
 
-bool kasan_byte_accessible(const void *addr)
+bool __kasan_byte_accessible(const void *addr)
 {
 	s8 shadow_byte;
 
-	if (!kasan_arch_is_ready())
-		return true;
-
 	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
 
 	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
@@ -495,9 +503,6 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	/* Check if free meta is valid. */
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
@@ -562,7 +567,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_save_track(&alloc_meta->alloc_track, flags);
 }
 
-void kasan_save_free_info(struct kmem_cache *cache, void *object)
+void __kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	struct kasan_free_meta *free_meta;
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b5..c8289a3feab 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tags().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
@@ -260,7 +253,7 @@ void __init kasan_init_hw_tags(void)
 	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
+	kasan_enable();
 
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e6..2d67a99898e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -398,7 +398,13 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
 void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack);
 void kasan_save_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
-void kasan_save_free_info(struct kmem_cache *cache, void *object);
+
+void __kasan_save_free_info(struct kmem_cache *cache, void *object);
+static inline void kasan_save_free_info(struct kmem_cache *cache, void *object)
+{
+	if (kasan_shadow_initialized())
+		__kasan_save_free_info(cache, object);
+}
 
 #ifdef CONFIG_KASAN_GENERIC
 bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
@@ -499,6 +505,7 @@ static inline bool kasan_byte_accessible(const void *addr)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
+void __kasan_poison(const void *addr, size_t size, u8 value, bool init);
 /**
  * kasan_poison - mark the memory range as inaccessible
  * @addr: range start address, must be aligned to KASAN_GRANULE_SIZE
@@ -506,7 +513,11 @@ static inline bool kasan_byte_accessible(const void *addr)
  * @value: value that's written to metadata for the range
  * @init: whether to initialize the memory range (only for hardware tag-based)
  */
-void kasan_poison(const void *addr, size_t size, u8 value, bool init);
+static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
+{
+	if (kasan_shadow_initialized())
+		__kasan_poison(addr, size, value, init);
+}
 
 /**
  * kasan_unpoison - mark the memory range as accessible
@@ -521,12 +532,19 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init);
  */
 void kasan_unpoison(const void *addr, size_t size, bool init);
 
-bool kasan_byte_accessible(const void *addr);
+bool __kasan_byte_accessible(const void *addr);
+static inline bool kasan_byte_accessible(const void *addr)
+{
+	if (!kasan_shadow_initialized())
+		return true;
+	return __kasan_byte_accessible(addr);
+}
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_GENERIC
 
+void __kasan_poison_last_granule(const void *address, size_t size);
 /**
  * kasan_poison_last_granule - mark the last granule of the memory range as
  * inaccessible
@@ -536,7 +554,11 @@ bool kasan_byte_accessible(const void *addr);
  * This function is only available for the generic mode, as it's the only mode
  * that has partially poisoned memory granules.
  */
-void kasan_poison_last_granule(const void *address, size_t size);
+static inline void kasan_poison_last_granule(const void *address, size_t size)
+{
+	if (kasan_shadow_initialized())
+		__kasan_poison_last_granule(address, size);
+}
 
 #else /* CONFIG_KASAN_GENERIC */
 
@@ -544,12 +566,6 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
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
index d2c70cd2afb..90c508cad63 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -121,13 +121,10 @@ void *__hwasan_memcpy(void *dest, const void *src, ssize_t len) __alias(__asan_m
 EXPORT_SYMBOL(__hwasan_memcpy);
 #endif
 
-void kasan_poison(const void *addr, size_t size, u8 value, bool init)
+void __kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_new_object) pass tagged
@@ -145,14 +142,11 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
-EXPORT_SYMBOL_GPL(kasan_poison);
+EXPORT_SYMBOL_GPL(__kasan_poison);
 
 #ifdef CONFIG_KASAN_GENERIC
-void kasan_poison_last_granule(const void *addr, size_t size)
+void __kasan_poison_last_granule(const void *addr, size_t size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
@@ -353,7 +347,7 @@ static int ___alloc_pages_bulk(struct page **pages, int nr_pages)
 	return 0;
 }
 
-static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+static int __kasan_populate_vmalloc_do(unsigned long start, unsigned long end)
 {
 	unsigned long nr_pages, nr_total = PFN_UP(end - start);
 	struct vmalloc_populate_data data;
@@ -385,14 +379,11 @@ static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
 	return ret;
 }
 
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
+int __kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
-	if (!kasan_arch_is_ready())
-		return 0;
-
 	if (!is_vmalloc_or_module_addr((void *)addr))
 		return 0;
 
@@ -414,7 +405,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
 	shadow_end = PAGE_ALIGN(shadow_end);
 
-	ret = __kasan_populate_vmalloc(shadow_start, shadow_end);
+	ret = __kasan_populate_vmalloc_do(shadow_start, shadow_end);
 	if (ret)
 		return ret;
 
@@ -551,7 +542,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
  * pages entirely covered by the free region, we will not run in to any
  * trouble - any simultaneous allocations will be for disjoint regions.
  */
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
+void __kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end,
 			   unsigned long flags)
@@ -560,9 +551,6 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
 	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
@@ -611,9 +599,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
 
-	if (!kasan_arch_is_ready())
-		return (void *)start;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
@@ -636,9 +621,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b9382b5b6a3..51a376940ea 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -45,6 +45,8 @@ void __init kasan_init_sw_tags(void)
 
 	kasan_init_tags();
 
+	kasan_enable();
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
 		str_on_off(kasan_stack_collection_enabled()));
 }
@@ -120,7 +122,7 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 	return true;
 }
 
-bool kasan_byte_accessible(const void *addr)
+bool __kasan_byte_accessible(const void *addr)
 {
 	u8 tag = get_tag(addr);
 	void *untagged_addr = kasan_reset_tag(addr);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index d65d48b85f9..b9f31293622 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -142,7 +142,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	save_stack_info(cache, object, flags, false);
 }
 
-void kasan_save_free_info(struct kmem_cache *cache, void *object)
+void __kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	save_stack_info(cache, object, 0, true);
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-2-snovitoll%40gmail.com.
