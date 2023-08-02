Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMPCVGTAMGQEDN6YSUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E776576D108
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 17:07:30 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-d13e11bb9ecsf7365797276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 08:07:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690988849; cv=pass;
        d=google.com; s=arc-20160816;
        b=lCpuDVuLgaueRfcBbdW1u1hbUSSlGmfAxfByaKLKrq790YPh6mHkceOWJtScdjvwTX
         7pIprC25nf6gxnS6xecNNXr3MR6vaLDzLNlxNPAfuQ3Kc0KsJX7m3EAmHOU8f9DKONid
         hIrbU9QNEqfWJK4DldS4ki7G75lRbGifXZnbUbFd55obW2wMtRXs39qeLLlNu5vOWr+L
         TUjyUV2WjxO5SHBd+FRk0nWmon3mWixkHJE8dyNs+dlJmUjODp295h1/V2dH8Uraf8Zh
         YsIsRkjj3b/Hxjh6PunPNhDbROd7pufPCJMpOfqKCHYnFPK+E2Vyt3G5XsaKXfidTTs5
         /bBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=dRUFXcCXP9iNSwnh8y9GMZZsCqWKIl0+YVMnifKFE7w=;
        fh=uAQSQbJ2uPOh1U3Yr1sxvPhVEW4wvg6y/uAlAwy6j5c=;
        b=Ng7cJp+r8N4d8KMGRzRdiKvi1sciM5PEk2qLgYFuXjnCD5P0cHKHyi4kYdco+1ude0
         sW0FwegxOf/Goj2j4G4uXoz8AVFZNRhUCuh5FhRfzuuXBSVKTe4ncqORI9kcXgvoasa+
         V17ChkZIgBybwfmsRjTx33YjkBJckq7UOfbvnjXSwGBQDSMKt8cRSD88uksQ0URXL87E
         iR/t+aMVUaAtZQ7XlDHVjbo7gadis1P2R2q9ilc5m0i4s7k6EsYLKhzwr4tPho6vVVbK
         VxBJPA/E9GVJ+kfVHAIecAOKmtKLh1i9S/hmkAandHAu4N2mD/7FS+GW81pdLOvG+dPP
         SkGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=SlPCrS1x;
       spf=pass (google.com: domain of 3mhhkzaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3MHHKZAUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690988849; x=1691593649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dRUFXcCXP9iNSwnh8y9GMZZsCqWKIl0+YVMnifKFE7w=;
        b=s/arUvtIdfkx/IX/H3gkI/h1z8zqRNBFG7czSIp1NJ7hD2has9gDJJat+n+satUWpd
         AOZmPZCPZEoDU24IqysFceh6AQG6uctOTxOFRn5/5LSiZxLyF99W9zVUbM1C0C/FLKGg
         w3K3kJbrTve2tQxdS2RP4b7TcSBbBWZF+edPJtHalueEQIg9PpFoEr2i0seOWO4a2NvY
         PByz5FoOA5a3n+o4gGt4rXg5CHxuEZq7rR8HrcVehuqiVl9KJZYNSD94CFxB4vn9IqG+
         r3BC+NqJRDM76QvuL/0sHfz7jPeBABayAj+scBK2bgu8r6ADcy7dJW/BJIt8D0ko2XEY
         0D0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690988849; x=1691593649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dRUFXcCXP9iNSwnh8y9GMZZsCqWKIl0+YVMnifKFE7w=;
        b=WpdMWy4czM1wyhJ/SD3EuORCFG7A2ujcyPKc6gerxPhq0ngjkEV5oRh0PPFgg3Nzph
         Pr5JCGRsFrgHS4EmakoWBuUdjmhGxLstlyyVtEJ4LHctnBhLpdUjQ+xmHqoDxbu1z4Eu
         lPi/H2jvthYdIkhXXCqrsUtszGaRxai1pJYaJsliLkP7OLlnfhDucRgq21OFF575Urfd
         Kxg/jYxzKSRv4tsL++iVcWK7o7hyAES0R1goc2VSxj7DC0upLdSMkz7dgY43QfHlybK4
         X0aNoLRuKiRwI0hjW3R/b1goEpDDXp1qn6jYrBu0KSwwVjiwgTlXZoyyMP+logMuaC2Q
         lCKQ==
X-Gm-Message-State: ABy/qLb6MvFGGcsGPS/L1J5lqk3V2JcEgek/nr1bIxyvPENaYqZriGwS
	vhCt/qGcs6jU5aPt7o/4r/I=
X-Google-Smtp-Source: APBJJlGgrVlCgVnSmo9zTn6LKDSfgbd7/zyIsROrRT8qVqqHPlYWyuIWAxdo8FPr1zhGPMtPJzqGSA==
X-Received: by 2002:a25:ac42:0:b0:d11:205f:c55 with SMTP id r2-20020a25ac42000000b00d11205f0c55mr15972022ybd.4.1690988849578;
        Wed, 02 Aug 2023 08:07:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1547:b0:d29:1758:ec0e with SMTP id
 r7-20020a056902154700b00d291758ec0els3076803ybu.2.-pod-prod-05-us; Wed, 02
 Aug 2023 08:07:28 -0700 (PDT)
X-Received: by 2002:a25:918d:0:b0:c12:29ac:1d36 with SMTP id w13-20020a25918d000000b00c1229ac1d36mr14827184ybl.7.1690988848719;
        Wed, 02 Aug 2023 08:07:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690988848; cv=none;
        d=google.com; s=arc-20160816;
        b=flt/P+1HcBgye6qkMshwPSvsiyEqidCBfzZhhs+ZirbiwWpBajYM/7PfUSCjztsz6g
         wT0Ozd9EkPR0Zrk7ZefcisITvorQIOzQ+k2vEHQDnlnh9f/exkaaTu7eKt2EE2NBuK41
         3W5R02ERTHcgbd3tBEmGaz4Cgrb/RQc8KLKdif9tqEPIDjFvUeo6tVxOMKpCLTO9tWXI
         Qsh0wKa9JcauzQjIJYISHAimiNo5Rk4CcTGZy6apApoWqR93TmAUY0bqBWFNwFRUglDV
         z6L3IIaxRx4p3EmOiaK8CAjpmh4GMGFcwHX7sgWZ2uBMXHFY3eHSyUpX73FDvhaSKxrP
         JFLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=ODlQqQRL7j+ioqTq3MDMk7BwHCUeRlM+arLr48y6tNA=;
        fh=lNGG3jUJkf8aHp9vpCSrpIUZatSpkge/xU1iDADXpuE=;
        b=gWj53vAIFuC2THxu8vzZck5vX39Vi4+xhJfB0NJb5cLBS9Mkh0GGdGW4Umt/xO8F5V
         LpdA819JWkDh6fOeg7mB783/gxsyU9lz62nIdI3iSucNbFwVWTIyYXBhs1HaMKdtl5eS
         2wykY5j9lY1TZuykBMbtutZJJHeV9/CUn02Nce++30oVpwzSheUBbxQN1l1COMs6I8vj
         JzMe0mxoiAL5R67C47dy4pYEvh6ktSzaU+/qJ11AJwuKPa1mNO1gw6gBso3Wqgi73NfH
         ML1FEtWmZUKIkGabgH7HftEFsb7+fbNqyViO4ogAqRPooD68ojGNPZ5xk2xcl89DCS4L
         LPCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=SlPCrS1x;
       spf=pass (google.com: domain of 3mhhkzaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3MHHKZAUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id r84-20020a257657000000b00d36cc4f5201si795975ybc.3.2023.08.02.08.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Aug 2023 08:07:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mhhkzaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d3c37e7f998so1258419276.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 08:07:28 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:5f73:1fc0:c9fd:f203])
 (user=elver job=sendgmr) by 2002:a25:dfc3:0:b0:d15:53b5:509f with SMTP id
 w186-20020a25dfc3000000b00d1553b5509fmr197192ybg.2.1690988848424; Wed, 02 Aug
 2023 08:07:28 -0700 (PDT)
Date: Wed,  2 Aug 2023 17:06:37 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.41.0.585.gd2178a4bd4-goog
Message-ID: <20230802150712.3583252-1-elver@google.com>
Subject: [PATCH 1/3] Compiler attributes: Introduce the __preserve_most
 function attribute
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=SlPCrS1x;       spf=pass
 (google.com: domain of 3mhhkzaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3MHHKZAUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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

[1]: "On X86-64 and AArch64 targets, this attribute changes the calling
convention of a function. The preserve_most calling convention attempts
to make the code in the caller as unintrusive as possible. This
convention behaves identically to the C calling convention on how
arguments and return values are passed, but it uses a different set of
caller/callee-saved registers. This alleviates the burden of saving and
recovering a large register set before and after the call in the
caller."

[1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most

Use of this attribute results in better code generation for calls to
very rarely called functions, such as error-reporting functions, or
rarely executed slow paths.

Introduce the attribute to compiler_attributes.h.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler_attributes.h | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/include/linux/compiler_attributes.h b/include/linux/compiler_attributes.h
index 00efa35c350f..615a63ecfcf6 100644
--- a/include/linux/compiler_attributes.h
+++ b/include/linux/compiler_attributes.h
@@ -321,6 +321,17 @@
 # define __pass_object_size(type)
 #endif
 
+/*
+ * Optional: not supported by gcc.
+ *
+ * clang: https://clang.llvm.org/docs/AttributeReference.html#preserve-most
+ */
+#if __has_attribute(__preserve_most__)
+# define __preserve_most __attribute__((__preserve_most__))
+#else
+# define __preserve_most
+#endif
+
 /*
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-pure-function-attribute
  */
-- 
2.41.0.585.gd2178a4bd4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230802150712.3583252-1-elver%40google.com.
