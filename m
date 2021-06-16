Return-Path: <kasan-dev+bncBDQ27FVWWUFRBLXAU2DAMGQES4TRK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BB9CD3A94A3
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 10:02:55 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id b4-20020a920b040000b02901dc81bf7e72sf1167420ilf.7
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 01:02:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623830574; cv=pass;
        d=google.com; s=arc-20160816;
        b=e8kEjGo3LUkClrwxD2EBfiY3Qwf4MXAuxUGRHB7is7+SR+EocaoXou8JF2OKTk4LW7
         r7Qa1WZNPppziDF2/HkUqeW9YcyaMHzTqlemLIWzBB6DpotzsEyyX4d39l7w4JGI/Inb
         TO0nGkDAt/yrngIPLoGoMFm3Pq8f4vkbg2+KufkvdJVrM6vB6tpl2PJeNnRskAEQoCZa
         224ItmfVpMXRIl5AgLC/NTg9YCmU0kaffGocIATfLVc8vw+KeQ7EwjdrDyenofBpDsTU
         mFMLpDRv8gZTOHvg+yI/UKQdoVozuPBbkUFdYsTdvmdg5TtLvcuEdrhD79cno9v80h93
         //TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iPDmLg/3Nx86GNLBcQhpyDKnooU7tFyVagO64F6nqEo=;
        b=aG4EVFRQizE0xGEn68bf5MS2ZPwwz1kV3un38OzkpLPuzm6yj04+XtuTQq2+SGMaUR
         2Cgja+ilI2GwTGcIRl7mBLsV7etloMwQL1LdQAWhIL/2dq6RIr63UiQ3LX8+wNk3DPVS
         kT+KSBluBbLSmn2/AOXfccYYS+Xx9HISHpXQ66GKuPG1iRLK74LZS/LR/ixPlOrJiS8b
         djZ01ucEXDBw2q22lZjdOqMnhZUnSL0Nbg5BrHv6Om+CVeTkRE2Xnf9LlY8x4FEZcA79
         FMJy8AuSUmLgA47rgaFLbDeNNmFMoBZ3UtNbjng7y5LV4disVjEBi6zHN+0scl8YMWjx
         ub9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hJE2AePh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPDmLg/3Nx86GNLBcQhpyDKnooU7tFyVagO64F6nqEo=;
        b=gWkLlKF4g1JaLnWd21HH/r6kohirThBgBVT1xxi8Mntk7KrrOlrWy77C488tdaWI9j
         L4kMgEqADcgLFLTwebvrJA42zntuwUcSIjKj156HEMXrvVxRkfaPlv53Qfwu7aC2OXaM
         5bAa6HINadrXouFS9z7dyYZZ8W9WtX7GI8kRfWsIrxe4Zjtak/89mo4hR7aQkd1pUieq
         bNBwlxZQ4VKVshOUYzCv1mZ4dlIwXajIEp52YNL5fvoX29/AjlNSMTpLIBQ1q+0BkV0G
         yCywTuKn2a9Q19YLuxFWMrFrNsnv4vLFKjNAqIm2hqho6G1baNI0EALtcmwHPxxUMuJT
         HNvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iPDmLg/3Nx86GNLBcQhpyDKnooU7tFyVagO64F6nqEo=;
        b=CZLirsg6oNOMhllbR3K40JrNn0oqEPFohvO1kgb3nJQHdce5BFDbd1+MIGwuR+/csT
         nYrmY0OTs/nHCtKbkrg7MRBpP3i0hJjNTs8Bs7gl2CwOZ1DSUnmZxxksnzVn0Di/BP3S
         X0IJcWVg4hDDeWHrjgBV5t3HDDBny1M0eP+QZwhv/Du31FvmZAPY9fMrsiB+flL4WfIl
         xTc0IX4yG/nzuYQYjP8iPOrWxVBSMT/R3iXzCuoTpLEWZjONYYttC40F873XdTTHXfXX
         Og1qVtTg2TV2F1caiO6DW/5KMW6Fnzj5M1o2abuCp+qN+VwI9drz5KI9i1lttOM+n3Yi
         4m+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324YwuNQiW0AO/XUDLStQXofyuMNYwqwyqluaAzsDBrMJOhzmrG
	11yCBPiEDySj4owN1AnfX6c=
X-Google-Smtp-Source: ABdhPJxChPQERos7J3w6h0h3B6uVyeEFvaSRMJaX7PVgTqEyGAQjRaSakKMvm/1lSmqwFrrsyDo2YQ==
X-Received: by 2002:a6b:f815:: with SMTP id o21mr2645929ioh.137.1623830574742;
        Wed, 16 Jun 2021 01:02:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:860d:: with SMTP id z13ls224669ioj.8.gmail; Wed, 16 Jun
 2021 01:02:54 -0700 (PDT)
X-Received: by 2002:a05:6602:702:: with SMTP id f2mr2556055iox.29.1623830574417;
        Wed, 16 Jun 2021 01:02:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623830574; cv=none;
        d=google.com; s=arc-20160816;
        b=F00DZv5a8TjDYt7vc/3ImdZI1lfTtBw2OHYn4m9SL3F3dCqbu8qkU4vIkn7Ky5HZTl
         ioW40enMLy+ACkXXRcxbK4oLONDkgLNl4DtlRhnaEiPL8YsoTyr2jV3JYwsdKnvD7fWO
         B326FK729hpPpSPvbQABZrmIu8u+l5Iynse6XB+97I+ImBOfv2stT49nhuycrZMLQVP7
         v2ku0qyUvtwmVKQD0ZuVRNmruOU9rJo6l6uGffIBuLksb36gwDhUJG6jasAcz5K1ofwO
         av9ypqAn9hk0u0HGmUkN91DUV0QXuq7IpXldGJCwk6ZR9pThDlq5sBJK6az7Xy9TizPr
         tKAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FhcxQma+NItwG5Mp37m/KF4tp14MA8dMkKZlGGIww7w=;
        b=q3rElBfi2+qOkvszB4kSx5Mut4vEMMuxxVdVUlgsrJUnuKs5mO1sz3YyDaJIMjPDSN
         lvcMZflQQ/z9Spf8n0q91V9kjayDRECHL5fOzoSXpT1AJetNiRw91nyVagi/wA91XtA4
         rF0VEYxcYDvqGjGCxO9EQJ5b8lEhJUdqTkbbEaejvU9dXJw+mc/HGWb6oGH+EN0jT/yz
         aDp6K0PRNfbllx+OOHAnARcmOyfmzKed4rHYztpsXteImO7mdiV0Vaauc1BCH+ohLfjF
         o/zNydEuoUteWNsviU9vf+bLqVM4g1y8yf/dyPU28DJgpPw+336/NXKzNOabaMztoECB
         0k4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hJE2AePh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id r16si134743ilg.3.2021.06.16.01.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 01:02:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id x10so720020plg.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 01:02:54 -0700 (PDT)
X-Received: by 2002:a17:90a:708a:: with SMTP id g10mr9621854pjk.108.1623830573897;
        Wed, 16 Jun 2021 01:02:53 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id v15sm1595449pgf.26.2021.06.16.01.02.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 01:02:53 -0700 (PDT)
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
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v13 1/3] kasan: allow an architecture to disable inline instrumentation
Date: Wed, 16 Jun 2021 18:02:42 +1000
Message-Id: <20210616080244.51236-2-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210616080244.51236-1-dja@axtens.net>
References: <20210616080244.51236-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=hJE2AePh;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62a as
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

For annoying architectural reasons, it's very difficult to support inline
instrumentation on powerpc64.*

Add a Kconfig flag to allow an arch to disable inline. (It's a bit
annoying to be 'backwards', but I'm not aware of any way to have
an arch force a symbol to be 'n', rather than 'y'.)

We also disable stack instrumentation in this case as it does things that
are functionally equivalent to inline instrumentation, namely adding
code that touches the shadow directly without going through a C helper.

* on ppc64 atm, the shadow lives in virtual memory and isn't accessible in
real mode. However, before we turn on virtual memory, we parse the device
tree to determine which platform and MMU we're running under. That calls
generic DT code, which is instrumented. Inline instrumentation in DT would
unconditionally attempt to touch the shadow region, which we won't have
set up yet, and would crash. We can make outline mode wait for the arch to
be ready, but we can't change what the compiler inserts for inline mode.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/Kconfig.kasan | 14 ++++++++++++++
 1 file changed, 14 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..cb5e02d09e11 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
 config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config ARCH_DISABLE_KASAN_INLINE
+	bool
+	help
+	  Sometimes an architecture might not be able to support inline
+	  instrumentation but might be able to support outline instrumentation.
+	  This option allows an architecture to prevent inline and stack
+	  instrumentation from being enabled.
+
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -130,6 +139,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
@@ -141,6 +151,7 @@ endchoice
 config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	default y if CC_IS_GCC
 	help
 	  The LLVM stack address sanitizer has a know problem that
@@ -154,6 +165,9 @@ config KASAN_STACK
 	  but clang users can still enable it for builds without
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
+	  If the architecture disables inline instrumentation, this is
+	  also disabled as it adds inline-style instrumentation that
+	  is run unconditionally.
 
 config KASAN_SW_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-2-dja%40axtens.net.
