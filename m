Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXNMYT7AKGQEHQB7KOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 34A882D48D9
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:24:30 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id m31sf78453otc.22
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:24:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607538269; cv=pass;
        d=google.com; s=arc-20160816;
        b=goEm5jcGibEklGAIJOFz6otsNSHqB2umPrAeEs4V/lblZzyrszsEmndqA6MDhZyuPr
         lf2a054r3fhMNm5HwTKc38tJdRjKNFasFpQCSbDaztIyrGAh8Pb+rFWVP28KTrbR1zFR
         5BjuKnB/7hIMvG6tfGajMzL1pzAlrRa9WY33T0fSE86fAXyBsj2nWqzUygeuDEzxa466
         bKpCfCsBzmVKwYhTTwgjkWb0aCCiEqvZcHOR0UN+EqKtklxIuWn1lcxV9NI8MW10HgIx
         1p3fuQ7ESLvy5R5vctKHKYv6Xbbx4w7RLhl3bNBLbADDUnd5jSfT2F8eHfku8t/oGEg7
         j52Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=++93Cgo3QvTVhK4RHrrNtvz2WdMPvwnbPtXe8hJDeJA=;
        b=C7bprThEdwgR70vDarwStbF+shDJSeFXq0tGXylViC89DeXwgMsnK2LTEGiGrGVa5o
         Zd1E2vXMPFXjAoyWEqrhmXnsL4IJt3q4bjt3CavGeXBqRmXgjKCjqgHx7DNEMYspdUm3
         /LcFw4n6Esh4uG4ZzHFfxhvUDpVqUYlymg6888lSt4EAnpXG02XJDLdFcIWfoOZfDHR1
         vf/FXHJrRgVBaQR4P/YWWmT+p4WDaN1QyKB5F2H271SiDl5FwL5RcnxSJixZXz76vAMN
         WcmFG7kFZlAN5+BQNMUyIC0g0CKLV/kAE8ZKKQ8m3svLT36M7jwSe70fL8C4M5dePqUW
         dZ7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jtZIxOGh;
       spf=pass (google.com: domain of 3xbbrxwokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3XBbRXwoKCdExA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=++93Cgo3QvTVhK4RHrrNtvz2WdMPvwnbPtXe8hJDeJA=;
        b=WZnl8vpQn070GthxxntSRklO262glPpPLw3t7w11py2ptr9LvWQp/jn+UgEaM/uUhy
         tj7QKk2jBs5vTUoOtj8BZdf9BW4Dwk2jL51i7Y8g/KT5lU8xMEER3fJVyT5gaE4bIZK4
         b/QX805SVMHWZi0R8Pkp2TdP+2FRezo7UnQ0cw/8fIlTGo4As+VBreY0yKoFoC7IXQHW
         pxeTY2x7cnTspOkO6jX8YLvyZzcvCFTkRnn1h67D9HZnNM+CrRbWkveIk0d7GrLpUFMH
         JJwBxq4V9HMjU3zP22Z6KkeJoyVn9KJhS1Upf5wzipdXRUEV4am8LMONkEXWt6m8L7Wx
         Wntw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=++93Cgo3QvTVhK4RHrrNtvz2WdMPvwnbPtXe8hJDeJA=;
        b=Wu7sdwNGx/ol3UTdP8EPr1m49SJubWe44m/nRIx0qLAo/TDLehRCOx4kT97QIzxvD5
         /w/t4aPRuzVsN+1Rdpq+QwBzPcOSmCGti74RhfpzMrFEppiBePo8J8OP4buYBj44OArs
         RjMe2SQQETKseodUfm1Pk/o+6/ILQWmiWq1ESVNergl+NAyiHrkzqD8HdHSdArDXdW62
         bKHSkFq/1osbjxR4f3qj4GWJfas9MEgUfgnpP5bO1hStbPkYne0Vg2fUqumjptwlLKkz
         y3+oYMADD+mZNLRcHARSif7CSfDk7XSJ44F6ldJDVmiM1Z7pvZsO6T5oB4fMmNBmFLxT
         7qLg==
X-Gm-Message-State: AOAM530BLCQnoorGNTf7ZNndy9FhvA88NSmLfuki7vM9YHFq5WaI/huv
	R+m7q/qan7NGY13kjvcU1nk=
X-Google-Smtp-Source: ABdhPJzj/vjk0kdiAqCIpGGxaBARP57G11fvNj5PQgJmwL6STyVBfklWkTCyAN2SdnijRZWpIGMhyA==
X-Received: by 2002:a9d:64da:: with SMTP id n26mr2872901otl.64.1607538269189;
        Wed, 09 Dec 2020 10:24:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1e87:: with SMTP id 129ls197528ooq.7.gmail; Wed, 09 Dec
 2020 10:24:28 -0800 (PST)
X-Received: by 2002:a4a:bc8d:: with SMTP id m13mr2979170oop.63.1607538268800;
        Wed, 09 Dec 2020 10:24:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607538268; cv=none;
        d=google.com; s=arc-20160816;
        b=Q3sarWfwNDPsH/iGNzsUYfXhi8VaOLwdxJjrY1IoRPVKJOJYQyv8NJSPP9BQmb71xn
         6gBhyJWkG/owtx67iQrly0SwP7jgI3MKvU9VOM/itr3o2turwMnBUFxlo6E2fDQ5AC2c
         wEndpMq9IRuSGepwcXcFPTfiCJ/cfOp0tXH/1yB7H2eT+LCdnitEYDaNtlca76Nk3IjX
         qjX86vJxDHeJw7vLPImmh/2F7KtTb5bDcvZDCauM6DdPrJr6Pkfpgh5vxY24KpwzwREY
         Y0N0WcYkXbXgLHsAFZojGwNRZo42UsNh1kgB68Vc1NXn6F9BLOxkcVVRRRDvJGG/ec3S
         ZPPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=u1bxfC07ZuZBOWsTyyUWqPiXaJQ6KPVo7f7CpicouQI=;
        b=hKf11Wvgwi14hQ52JwkXV9FqTh+7kSUWps4+4PrMF7uJXu/i0BMxPKNqrr7YR9+6i+
         OZ1HXvX+Vbd574p4vVvOa5amFAb9INTzLGHRqEHIPiDHBQm1L+BgxR5wLsad4D6xswcU
         0WaV47SO5i2jTZNe+lhclPxPe5GtBoYBu5DNiXDLVZbEOVUIXwjrZOA2ECS1QH+XUdq8
         Pw7EQHGqhZpuWNGjGD58zgz2ePfDjvXSF90gZllHuigGLTogCq00ZVhDs7I4izRRzwei
         Z8/6kCbonRTmGWjRTU/hKk0wilKk/Zl1DRun0WUPHa14GPrw7VChKsAC78cKV3Qz7k+9
         5HWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jtZIxOGh;
       spf=pass (google.com: domain of 3xbbrxwokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3XBbRXwoKCdExA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u2si206466otg.1.2020.12.09.10.24.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:24:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xbbrxwokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id b9so1791494qvj.6
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:24:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:47c4:: with SMTP id
 p4mr4509202qvw.23.1607538268306; Wed, 09 Dec 2020 10:24:28 -0800 (PST)
Date: Wed,  9 Dec 2020 19:24:16 +0100
In-Reply-To: <cover.1607537948.git.andreyknvl@google.com>
Message-Id: <a6287f2b9836ba88132341766d85810096e27b8e.1607537948.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1607537948.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.576.ga3fc446d84-goog
Subject: [PATCH mm 2/2] Revert "kasan, arm64: don't allow SW_TAGS with ARM64_MTE"
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jtZIxOGh;       spf=pass
 (google.com: domain of 3xbbrxwokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3XBbRXwoKCdExA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This reverts "kasan, arm64: don't allow SW_TAGS with ARM64_MTE".

In earlier versions on the hardware tag-based KASAN patchset in-kernel
MTE used to be always enabled when CONFIG_ARM64_MTE is on. This caused
conflicts with the software tag-based KASAN mode.

This is no logner the case: in-kernel MTE is never enabled unless the
CONFIG_KASAN_HW_TAGS is enabled, so there are no more conflicts with
CONFIG_KASAN_SW_TAGS.

Allow CONFIG_KASAN_SW_TAGS to be enabled even when CONFIG_ARM64_MTE is
enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 6fefab9041d8..62a7668976a2 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,7 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
-- 
2.29.2.576.ga3fc446d84-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6287f2b9836ba88132341766d85810096e27b8e.1607537948.git.andreyknvl%40google.com.
