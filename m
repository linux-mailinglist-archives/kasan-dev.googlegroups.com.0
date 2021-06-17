Return-Path: <kasan-dev+bncBDQ27FVWWUFRBSO4VODAMGQEZA7BQBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8C5E3AAC8F
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:40:10 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id r5-20020a2582850000b02905381b1b616esf7184563ybk.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:40:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623912009; cv=pass;
        d=google.com; s=arc-20160816;
        b=h7UiFan+Rw3eHT+LHtIlCS6DSOwi9zDk1/v+cABcWwFZdy+I5Y5gmdTglFXSHXh7+v
         s0Au4tvxUBqKYwjpTznP8NB24tBzQJ2iGS1CpOU9MGLLaZ3nAlC/oc+5VhosN+MNmrz+
         6B4MVAZcMF27NTTCLNR6zDdFgVYxR+93Vx8EPycK9V5BbMEaOVXV0GwxwAT1N8DrWEIT
         kn39U0u1e5yx0RQ6LRIYDPEC7kqMk0HpE7vLbkjUsZS3IMOQzWBJqLU4UX3SpleCAOE8
         H9nx55t+gsiNxk7HpIWgAQ/5Fmj/gwGV2Rn1hHbsYhbBzs6VfCN2qJQ7mmLO3E0lIqmW
         6yJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zFMA4TIaldJTY05ZGSyrhTu7HBDu6DUDxj0I1jSKmMc=;
        b=yeGgtbUkv1782BBB1hy1/ZWnUTCrb7ntuL7Fv7WFShP0e/R4j1gOFZBUs3TYzYklA1
         rMXM77kb1CZ6TidkE2uO+eo9oPNDNj/7Wu5RcGa+UHqz0rGhhDok5X+9OvV+n9c2TKI8
         XRb2DGiwCofSM9kCgO2RlBZwItgxGC4+8lR1SW1MCW6iVAx1qgpYBdAUHTqGw6I9Q203
         NQFnldEpoGlISwYgBylIbnAKmjOfK7m1p/Dkxn0Lxh4VZMdOXj+MgW79REuSdfdBTidb
         2HoWEJaZbVUAvbs5lVp6AUyna+AXwXfZkRsvKFTc7CVHDxvJ1Q0EUvsWapDAeCuSw5Ak
         6ZFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="NX/qvxr8";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zFMA4TIaldJTY05ZGSyrhTu7HBDu6DUDxj0I1jSKmMc=;
        b=lOwa5E9NnedD7QEiqzvzj25MajP5DJ8X7DJhtlJ936YM7WOb32zMxmqG1DrH9MAg08
         b5ZjN7y+k0vSAGmSiycvCGkm+TNAU0EoqblZ9xfmcsSihm2YIKqrFsXiadOnvW35AN/B
         He5oQWzJUjnfoBnBF7UNWFYuOPA9HD2uDBQ2EcyIXNvDDpz+nwomGS5bIBAm1s13kXgG
         5Yup+fgLGv2ySjSTZC+LQxXD+Cv4nAqLTDr0k9F1xBjQsubKvXpPgN9fiZs+lI2k6zcy
         opkI39forC7GATMReLwO8zuP5x2GmsF9Nk8bP7l33Q/pf4HxXhDPbqIDUyErH8jN0rhI
         qzEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zFMA4TIaldJTY05ZGSyrhTu7HBDu6DUDxj0I1jSKmMc=;
        b=J1jtIhUtVBU4WNvgfPn8/EEM6wU+abDFJCpyypiH0zCKv3cWzkyAUI7Y9pUAuecANq
         eFiaCiYAxQOfXDno7zJRZ4iDLnVpkoKjdGIS15p2uqXd9uXWWShhE7Cg2lrzllT5/Ro4
         ZqvMLiOuZRY7e9GEEsz6P5q93PJsfqSTGJDwrx0sOPgAslDMlstNpHHeC0w+TZKtfKrC
         hoDctrfKiKOWy3cQ9sJXhmXimKuJe284DQqupiE6o5kAZuofOROfMGVgd0TFYAhk6/bA
         3zlZwJV5asXGptvMD7qv7yaYdnrynyKYrkM/LvGKnShNsIzBtFim9NrbbuOiY1CcNNNp
         brpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533phAO7Fw1XUAZyvdyHqb0Jlu/Vs+1o8yhbpbKQq4rPHxh9KGMs
	1RCYk85mBxlIZZbCnq6C1nk=
X-Google-Smtp-Source: ABdhPJxmaMpS3TvruAvOwB8ir2ruCUUNfsctvO/pE32lnww/mIQuFNljPG7E/QadlPtPPZCEuJJJ6w==
X-Received: by 2002:a25:e78e:: with SMTP id e136mr4157548ybh.117.1623912009627;
        Wed, 16 Jun 2021 23:40:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:544:: with SMTP id z4ls2465305ybs.3.gmail; Wed, 16
 Jun 2021 23:40:09 -0700 (PDT)
X-Received: by 2002:a25:bec6:: with SMTP id k6mr4370012ybm.187.1623912009112;
        Wed, 16 Jun 2021 23:40:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623912009; cv=none;
        d=google.com; s=arc-20160816;
        b=h19iuX+4pDjRw+8p/i2kJ6tho60WKaIwPU7KJPXKKO6se2qoQnnjxiWCP2l0PLZPgF
         VVDYnQM3qT8URZsE1jud6415052kwM+uNIplQd1mbzyvyFYlxg6Zy+gI+yFksA1ytFX7
         9k3mRZSRNAfzBl+DA7+IUzUpSfHhv8mDZb2CZxU5XUINCD93fbsdb8zbHlhwfAFZRAO9
         RKY/tH5cW9KAJStUQyblEnez/VowVYrjFf15RhDM4UH9KhkpwhOyNDXa1owUc/mLA5T8
         +4aTPXSo1JoLSlqZ8bDQtrjbYk3W/Xkyk7ELpFNxL+AWaHEhnGxr2NOFSeIIBFubQm+i
         GBtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FhcxQma+NItwG5Mp37m/KF4tp14MA8dMkKZlGGIww7w=;
        b=WFe6X5ERzH3+rut++iMMNnvBXtQK3Pti1UC649MSV9wYmQ25V1qygac/psxskI5SrE
         R6gFFgSTzs+Lk0Yh6Q0+uQ3Xu3+UmeBj6TX6qpbaY6kivQy+quhj5SysT3yVxwEnyltP
         ltLzQd0wvHrzx2h4r9TjLp+vDCLYi8zvCA3w/qJcZntQFlOUqFBzS77xbQUueO+pV0ke
         p57Sv33uYXjDN7nxGRxQ+WOOg25Ihk//mne5G3pLLfYhfc++PAvjM3IgVrVMhm0Ko43S
         IBJVYcBA0v+GxxJKvxHh3AqtuHkvypEkH1IAjIy31nE3cxIYUQB456hxHNrB2tZ1XrLO
         DirQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="NX/qvxr8";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id r9si503477ybb.1.2021.06.16.23.40.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 23:40:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id f10so268525plg.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 23:40:08 -0700 (PDT)
X-Received: by 2002:a17:90b:38ca:: with SMTP id nn10mr4147573pjb.127.1623912008754;
        Wed, 16 Jun 2021 23:40:08 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id d12sm3987316pfo.113.2021.06.16.23.40.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:40:08 -0700 (PDT)
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
Subject: [PATCH v14 1/4] kasan: allow an architecture to disable inline instrumentation
Date: Thu, 17 Jun 2021 16:39:53 +1000
Message-Id: <20210617063956.94061-2-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617063956.94061-1-dja@axtens.net>
References: <20210617063956.94061-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="NX/qvxr8";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::631 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-2-dja%40axtens.net.
