Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWEBRCQAMGQETCRLDJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C49B86A992E
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:14:48 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id m3-20020a2e9103000000b002959b43571dsf650151ljg.7
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:14:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677852888; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q77huTiVfhvZDo4fNZ93m46Fu8Jbtt3P6YcB6YqAMw+Arfu9dJHguO43aXHEkJaCH0
         DJNZhtSX3b6aVOHNvPj77t/EYz8XfsxcR6G74G7MyR3EmFoHMnfH0cuhHKEqfQHTA1WE
         64Z+vU8IGcg8ZOSacYaIbrtF46jVsVyFOcr/3yDCDCw8xaOzmtyGS4N2/dkgCxcDh3ST
         bbV8oPfJdgoXvw7tk+GFaPK0NwW3v0Dxdp4vWZ74Kwx7If5ciA94Xfei2m+DDBdXKssl
         EroTndj8duVelJT88AsROJ+l7/6dZEiR01Y74qZisdBMij6vDQlOo+tDgKeOGL9WWDrD
         OiUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GD+QbfPBOeTUOEav9EoL5NwT1a8wtwz9+fCeXoutPTw=;
        b=KgwBCR9KKZdV6yzJMC0hVAwqDEeCODFVIc63LfKGiURm9esolEeJH6kqV5OLSfFlbd
         tS00GSWK+yte9ElHJdBnGAHEcPoX9zqN9FdlbRXUW+uKcRB+wgEaQfJet1UwiWLwKJnG
         MEIaJ5dyD+aHfWr7fbX/HNyujACvE5QW0aoDch+l9XlqSL2oTuOiy8sokQqGF53aaPlA
         blAf2NXJEvR2mOIfu52hrkDH5YmomBlH13qknaTryoW7I+P2uZ78Yk+ySMu8wwaEmRBY
         GhrF9mREjVq8HRu06+cO9lR2tOQFt52v3P0iCmbquTfkWPJq2TOHQlX6YsLRZ/SUlBhM
         nG7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=edrPhHR+;
       spf=pass (google.com: domain of 31gaczaykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31gACZAYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677852888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GD+QbfPBOeTUOEav9EoL5NwT1a8wtwz9+fCeXoutPTw=;
        b=AJbJWTpZscBB3eDQ6sBml3BwZthxJaJVNJMO1rbYbEt1Dh9NPN+KgKUKeO3wV9x1uK
         aBRdjm15QvZuy0luyavUhQlQlwr7/4QIQB7GScjr/Fa/gspKkMlpgKcwPtDNNy43jk/T
         JJ4y8ho2WRJzpD4XkTuvGdsgjBASbKE5FaAamT7fy6PzHlxAM2Soxck6p0SxMZ7HH393
         pddDpJoc1t3uODH2Wr9zxrSGR4JIAoP+ZbSJYDi5KLgasMjXbtH2b1uUhsLyno2Rx83/
         7hJg0MyALtcoTWgEqzcGbcTxkVLth94hF/1ybZNBCLTZpjIsp7BVW3YjroKRekNRO/ma
         +TYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677852888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=GD+QbfPBOeTUOEav9EoL5NwT1a8wtwz9+fCeXoutPTw=;
        b=JY53uh7rrJsJO2kHDwLuJvHowPeZ1w9FZo2v0M/HiSfyDOSMJThTGjzswvOK3ldvay
         ISEa1BMppwrb+9Y4fEYnfGh5cO1tUnUaFEbLah3MHBkKVykSJYx6sDar+D6raL3aFptZ
         pcAMjzMFWYzPp041FiyeY165XwjLRCK/IRC37a0bp/ks9qnTj+fcpGNRj/w5O/AAYLbR
         u6q2rOX54ve7RR7shNAGsn3frIeyG9pdNdLYn6Z2ySv4k2eou/IU6rss22VQT0+55hbU
         7WqBjXRBdqMAwDcMCyIQIEM390IO+biE+NUWMRF8KxjhEWEUqwvtMpZGbxOstTLPGL56
         9zlg==
X-Gm-Message-State: AO0yUKU3PytF7P47ejSpVPqa7lmPFOHvR8PaqZamI4OFVN/cbRkt/hqd
	iCQb7I32fJo5fWfDsK7bM4o=
X-Google-Smtp-Source: AK7set/0OYif/sz/vhRaAw0VYiqxnRJ2ePnkSVj5zheEiYVin929ias+N8IzmEQIxI2qbNx8fQ3twQ==
X-Received: by 2002:ac2:5ece:0:b0:4dd:a74d:aca3 with SMTP id d14-20020ac25ece000000b004dda74daca3mr699010lfq.3.1677852888320;
        Fri, 03 Mar 2023 06:14:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a2:b0:4dd:8403:13fe with SMTP id
 bp34-20020a05651215a200b004dd840313fels2524963lfb.3.-pod-prod-gmail; Fri, 03
 Mar 2023 06:14:47 -0800 (PST)
X-Received: by 2002:ac2:489c:0:b0:4dc:8004:7677 with SMTP id x28-20020ac2489c000000b004dc80047677mr480027lfc.12.1677852887025;
        Fri, 03 Mar 2023 06:14:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677852887; cv=none;
        d=google.com; s=arc-20160816;
        b=taA63ApTVJg5ajOp+BI1G1CK3SxaVKyWfupPfw7ulMF0ISgvusdhPi5bSXpAOi/AQw
         ahVKGGfCCMbRFlJ+ifbeqOApVojPWupMllBzXN5jh8XNEYHRRBVVpM5f8yt2qZLZAtxD
         Q5AsWDt9QhYp5TVFVDggHELwjEC6mooKfKl3gP7lKzAUHqRLeKXhGBKS3ufSlQlI3/+T
         7cqh3TDY0iXUX9U84YG8nMam8WEZeuFerCoRjRHufWDPVc1Lr4NkWi0vZkegjfLoJ022
         c/envRxKwZ6Rg5SgeXhpswwgrolfecbvnXhKo7u2X/gZ6bMRTx3lNsFFdG9dojq+Ef9+
         Ahuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NAtSFGVTwhm/tX8WamH/Zd7xaJyhhcixand9gS9KqOo=;
        b=GDWJN13b06ZQWM1ItFr5NnILlktLyfB6VJap6sAWrsFlTr0m8QtSLGI24BCAULiCYg
         pj95O7A06UYOrvcfWvKrVwRO8u4iHwQlwNejnQK7OfJGxqxh7SmC6qHmRW+4eMWvmOeO
         TqAq64sWkchlaDOPidxrai2HjNBph0pl6pOcl3VCA8PZwRP+s9zzqYQEp6jazKgNlmR0
         7o4WYhVIN9bzosa2bOVSE8A4S7gTr+X58+84pYJJQJhzhJw2mdmUJ0pfqb4rVfn4f/2Q
         FHwyhehpruij606c5KLlPfyILCby+RJfYxNjBmS5uh/f1q9AXyvJ2AeCqWm+21sGvrX5
         U56A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=edrPhHR+;
       spf=pass (google.com: domain of 31gaczaykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31gACZAYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id u16-20020a056512041000b004dcbff74a12si129282lfk.8.2023.03.03.06.14.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:14:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 31gaczaykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r6-20020aa7c146000000b004acd97105ffso4137999edp.19
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:14:46 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:f11e:2fac:5069:a04d])
 (user=glider job=sendgmr) by 2002:a50:d581:0:b0:4bf:7914:98c5 with SMTP id
 v1-20020a50d581000000b004bf791498c5mr1171964edi.4.1677852886570; Fri, 03 Mar
 2023 06:14:46 -0800 (PST)
Date: Fri,  3 Mar 2023 15:14:32 +0100
In-Reply-To: <20230303141433.3422671-1-glider@google.com>
Mime-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.rc0.216.gc4246ad0f0-goog
Message-ID: <20230303141433.3422671-3-glider@google.com>
Subject: [PATCH 3/4] x86: kmsan: use C versions of memset16/memset32/memset64
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=edrPhHR+;       spf=pass
 (google.com: domain of 31gaczaykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31gACZAYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN must see as many memory accesses as possible to prevent false
positive reports. Fall back to versions of
memset16()/memset32()/memset64() implemented in lib/string.c instead of
those written in assembly.

Cc: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Daniel Vetter <daniel@ffwll.ch>
Cc: Helge Deller <deller@gmx.de>
Suggested-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/string_64.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 9be401d971a99..e9c736f4686f5 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -22,6 +22,11 @@ extern void *__memcpy(void *to, const void *from, size_t len);
 void *memset(void *s, int c, size_t n);
 void *__memset(void *s, int c, size_t n);
 
+/*
+ * KMSAN needs to instrument as much code as possible. Use C versions of
+ * memsetXX() from lib/string.c under KMSAN.
+ */
+#if !defined(CONFIG_KMSAN)
 #define __HAVE_ARCH_MEMSET16
 static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
 {
@@ -57,6 +62,7 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
 		     : "memory");
 	return s;
 }
+#endif
 
 #define __HAVE_ARCH_MEMMOVE
 void *memmove(void *dest, const void *src, size_t count);
-- 
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230303141433.3422671-3-glider%40google.com.
