Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAE34L3AKGQEOIUA7LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B6AC1EDCC9
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 07:58:26 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id o1sf3850349plk.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 22:58:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591250305; cv=pass;
        d=google.com; s=arc-20160816;
        b=qlJE9sK6cH6GuyCszg8VUEJALeWCkCLDnQxO5zp0UDep6YcCRZKMnmBzYU9LYZT4SW
         kGAIXsowRyY7VNl8Or5DQpxyXahGuGRKYSlvQIWytS7Zb8Me6DFzRxqXlv7/PiF58HHb
         lLaPullzazexh9Nq17oDOTK/Ye1nrGDYNIbU7tFXpZFJ4JC/atV0pDOKlcSzyw6fjHRq
         3nODR+Bcqjox7ikdrM0WX2CR1PhI4uAJVUClNxWq4QOiCF3VChkMI2ViFrUu8Q76UUyH
         ME+UO2ta3uYKCT0eNk7HTvKScml9qe/Bv8Fr+T8CoGU6LDk3WdnJlRA3fUHFcUnLOeyZ
         /EKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=1fjphq5uU1QSNtSNb3lte9I3c7AVre/ysNPQE9F8cLE=;
        b=ltOddprBR5klbc4j4VuW9VCpF06LLEvKuS+6r++mq+uiSlKuyOnJnGN5hm7rvIMqq6
         kaSVL7c7TJucZcvarzYMSK99H9p84Pz2Ssqv7dGefrPptyZLlFNkQA9QKvPOLxtuCHX1
         90DXiHscaDrgSBsN+ZAUTN2wuhBXuIYI1Pps3fl6S+mPHl3ewS8MBGpMBXW5/jjlB4O9
         y4HSFsqL2ahr/UDhraYLUCNMF4iQqMYuc/jZuzln+bMU0WwyT9LCzAXwLUzcPK6LLOtp
         YzvPNPCqfWL53+45Miq/HIg8Tq4VF7xskFZsSynH1oX0XxTT0ods96NJKSrGZgswb/fr
         Gzdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I4BZ4MPd;
       spf=pass (google.com: domain of 3f43yxgukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3f43YXgUKCfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1fjphq5uU1QSNtSNb3lte9I3c7AVre/ysNPQE9F8cLE=;
        b=saKiXUpQrvuCvCLYZoM0KW+VnPrYSZuQ5v2uS3E82FrBGLE1uP4U53myxTPz3NBTPN
         05cJt8akOnLtPsjXoYe8L+i9GsIBreBt4hgsomeAPMl16uzM9+23SnojMS8MATgK2KJy
         tH4qPJojMTDvRw2EHwJB8mgZ1IisASYcEu9WBIxaVXr3yJuf2chNEVstjlqkTGLYzW/s
         mbaQ6nk7zBz8eE04fug0SvyNSSCOEqlDcTEgiLawy7CYg78cvD5TKEn2Ng3XQnZAcsT9
         mbHPcL2THYypzqpIGdmK0Tq83SIzdythY9AiakMKh8VbqwomMdwwomsLAz8oErBaHLxe
         N4oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1fjphq5uU1QSNtSNb3lte9I3c7AVre/ysNPQE9F8cLE=;
        b=Scx4Lcqz/WPC3TdV1/lQ88VNtlxxheXdd97xsxBAryJboHTQJAVpJMrNscVGEpw4UQ
         bcBofFw5jL9LD9Jk9vgX17Pdf8L3n9bTSDnsyMjWNqI1H4Myn+ikoIr+4pxCcnHDuV2X
         2m9ei8Yd3jOUtRyDR9hSFdZQuQK9cQPq0nKWFWpzppKwT83+yV+hJMtGpeBSflf8q7kW
         KN9A3N7QYFuCokYaFoWfr1Hozh4PpaPLAYL/ItFtFVkxKTUB+HOuIuXG9+99eKL6DTd8
         v8Jb5RtgSnF2TqViqR/59DmyjruXK0KBz5a9rKVDXsLt/t2ci8LY2sDIRegS/aO7ofB9
         u+DQ==
X-Gm-Message-State: AOAM532GiWYY5nGdC96jd8izBVEjlhPZcRq9YLhUVH6aWNJOGLQUaGSc
	FNKZgiTpirWcGrW/iNToAJg=
X-Google-Smtp-Source: ABdhPJyCNFiTGXkPyvLdgVqZVAEC4SrR9MsMGkjo3h7SQLyQkEOm9VQArEZsUxek0BhJ6vOnbX1LPA==
X-Received: by 2002:a17:90a:1ac3:: with SMTP id p61mr4220969pjp.23.1591250304814;
        Wed, 03 Jun 2020 22:58:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:104a:: with SMTP id gq10ls2697825pjb.0.canary-gmail;
 Wed, 03 Jun 2020 22:58:24 -0700 (PDT)
X-Received: by 2002:a17:90a:ad87:: with SMTP id s7mr4209052pjq.225.1591250304352;
        Wed, 03 Jun 2020 22:58:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591250304; cv=none;
        d=google.com; s=arc-20160816;
        b=EHd+q4tHTA1do0clZhYV5lpKphjcIf0P9NHp9DvhTEBf8tvEjHw4YRo7Re10aXPIdI
         KUbPM4be8h3a/0Ig8/WzdDRx57ECgp5FvkPiVNhAtiZRmKosQ+nPzKdG1Rj1N1RIIwpq
         Q0B+dGB5Zu9tzXuZzv9uu0JjaJDVTD3WNsBw8D++UbWttgizoadJrYhYWwj7/HF4UMgs
         denbvNrDvpmLK8bbUktYrQNsTpCS/TCiKiT7pxuSJEFwviXZWv2bqED14P6lt7icOMPp
         1mCIlyvz2wDrxLPZ4dTeAywla0XGuXAGFe2ORw6bmdbatWrnTZP3M0U48t4px/65Sx0q
         prow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Y2WghFK4jI/68L/mvE2beXccHpF2A1uuR6W3fE75YUg=;
        b=JNLIuX3CU6XK6zK6xNvjrKjPZOdtSe6CD2DtCje+cEHOZJn1mvnrE/odGlcwndI4Aw
         JETHM0i/5lzrUGV1ggnILWPa9YKOBka/fsRenBeAsoYOQ46sPnK96buhg8JKGhWXMq3m
         WYxPEYe8U86/KG+tWlFGVIMttuUjdEA2tRY5QqPJCQyz60cTE1Qg2zkxApwz+U+i1WkN
         ke5PlfEsDogaXd2Us6WX6epqBDWCi4ROlM2PmB69+VWxkqlZgJuOhGGGa872NMgMZuZY
         TUsSE+ijAbM0JDc5zGhHMvvBqpEF8FsTmxbJogmfKyyZ1HTGMlnaAySb8nf0p30xbAlB
         k+2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I4BZ4MPd;
       spf=pass (google.com: domain of 3f43yxgukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3f43YXgUKCfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id ds21si397427pjb.3.2020.06.03.22.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 22:58:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f43yxgukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id p18so2624711qvy.11
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 22:58:24 -0700 (PDT)
X-Received: by 2002:a05:6214:1842:: with SMTP id d2mr3212300qvy.197.1591250303486;
 Wed, 03 Jun 2020 22:58:23 -0700 (PDT)
Date: Thu,  4 Jun 2020 07:58:10 +0200
Message-Id: <20200604055811.247298-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH -tip v2 1/2] kasan: Bump required compiler version
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, clang-built-linux@googlegroups.com, paulmck@kernel.org, 
	dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I4BZ4MPd;       spf=pass
 (google.com: domain of 3f43yxgukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3f43YXgUKCfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Adds config variable CC_HAS_WORKING_NOSANITIZE_ADDRESS, which will be
true if we have a compiler that does not fail builds due to
no_sanitize_address functions. This does not yet mean they work as
intended, but for automated build-tests, this is the minimum
requirement.

For example, we require that __always_inline functions used from
no_sanitize_address functions do not generate instrumentation. On GCC <=
7 this fails to build entirely, therefore we make the minimum version
GCC 8.

Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
Apply after:
https://lkml.kernel.org/r/20200602173103.931412766@infradead.org

v2:
* No longer restrict UBSAN (and KCSAN), since the attributes behave
  differently for different sanitizers. For UBSAN the above case with GCC
  <= 7 actually works fine (no compiler error). So it seems that only
  KASAN is affected by this -- let's limit our restriction to KASAN.
---
 lib/Kconfig.kasan | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..af0dd09f91e9 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -15,11 +15,15 @@ config CC_HAS_KASAN_GENERIC
 config CC_HAS_KASAN_SW_TAGS
 	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
 
+config CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	def_bool !CC_IS_GCC || GCC_VERSION >= 80000
+
 config KASAN
 	bool "KASAN: runtime memory debugger"
 	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
+	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604055811.247298-1-elver%40google.com.
