Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRGE3H5QKGQE7QV2SNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 66B50280B1B
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:05 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id d190sf76350vsc.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593924; cv=pass;
        d=google.com; s=arc-20160816;
        b=fyLg37pnJIrhWqFyZuG9lj644XKQc0IiSALehlGYotZ8hCYq8vjbXp7JHeP5pUEyY3
         NGVYRdaNJ/afhzl7rNXFL5KK3LZdbzeMKvWJ6Uy7LaZg7WDCPWZINvFWqVm5rndmnsru
         TCbyqfY4hAxTsYPrJJwNKbOzz7+6mtpMHa8UXHlXKeu2Puq2hR57H+GPTwWv5U0y9G6N
         QWoN6VqqYu+0pVVPCc9B90QWQ7uWDWp7aM4N6hUYc63q70cJhr/25hcDLuJ1tw29xjTO
         whVKDk2hLGsZRETH2oc27a57DhCbPEIk1bOUG/axPN9Xl5eQ4xx+FMjPCLX5x4OwcCVp
         6SFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ilf9B+5l4eq+vvJq03tNpJSmn1dB60t/TAu19NIKbyY=;
        b=cg6kLpbc7h3fPaZoLfNfrsKwiJ33H0SPiuxmdWA+Kb9D79++oszLlOZTjczWy7v6kv
         1IOH3HalrbUV+F3p0lhgHyHEhVRkoydhz+PX3PXvWsiI0qlM71Xt6WnTzwakLYCoK56y
         dkEQ8iUgbjflEsY8B1G8FPpZOAoDj7yqHbodSia+nDLJ8izISxXo58vhoi7sVCLEibo4
         j4wNvcBFp0e91PrHhWVFrCy2C4v4qSt2m76G5mcUb6Zu5oQHVmGgSSwAjK+/oPgpxAhM
         6ZF6Wbr7DmAtx0DSPMhOiuHxv7cXbyu4/5pmddrEDGiCRQQzDlR+WNujEPBYf0jRFlj6
         G25g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNwdqefk;
       spf=pass (google.com: domain of 3q2j2xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Q2J2XwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ilf9B+5l4eq+vvJq03tNpJSmn1dB60t/TAu19NIKbyY=;
        b=oqQI90WNK39+sm3EuTIiRoIA7YvQEMPc/trxvtMVHbPzu91Jm7/kc7DyXV46hVXgFE
         Le1S0wWMhC2VDeDzqMpqeWmUxig46J5jqyIbb/wvH1m3gkVopWRvg/Uv+TLZjjhq0ssd
         XYzOSWlm9OtPxgzUdRURgp+buxNHlt7NyHK+pwLDaiuZFmrMjJzp2fa6qcMszx2KHpP9
         YcBsEpLGxrme9o3b9cELVsD/lK00TPPNXMPnMr6wsjKgrKZ1xhgp5aAHRBTCf+HpU9Qn
         aw0heZcUNguPtCRDT/xjLf9vHZ9CgyQfIzBJh3twRFrVY/5hXKeYg+jkM+Ue79S19hkF
         EIbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ilf9B+5l4eq+vvJq03tNpJSmn1dB60t/TAu19NIKbyY=;
        b=GFdW17lYZHv3JZ2YkLZKL2yt1Le+9SKvy5wh9tqUxGB539mY4RsWu9zCrdAOhZbH8m
         kbGHmZfmPX7oeQ3ym7Nh5EAhDE/jcSKfNZuTnfZIr1zC/hB4+/pWJXW9dl0POFA5uPhF
         5G2OkAN7/lAjdE4uQ4nPSvQ3ydSzRXKXqX82RlZhwFus3tgemhNpswbC8KmVSaYXVxCo
         9NCPiwZW86Pw42uFl7l0YwRG3dn8dL/pXP/CYc2CN6BRcNJ50vVGf6kbf/K8Vr1jZ3Y3
         47GIEjtSoGFvczRJ7IM9f8lk8c4QmjzA4nqMVyM3LxSBNnflhLrZzHJ5PvvaDFPU4YsK
         jb7g==
X-Gm-Message-State: AOAM532AIGUoafVdmHfxzxezqbrtvBRoiFWHSyJ6peHBi/31rZrV6iTL
	Hxq7eyZCr0Cin+KvlBbPaG8=
X-Google-Smtp-Source: ABdhPJx631Gu2FqkmYmAB519dj1rnn95WqRWyTcsyRhf87eGnSg313Ym1W2CHJWCAavt3TAbsqgAIw==
X-Received: by 2002:ab0:384a:: with SMTP id h10mr6882766uaw.77.1601593924444;
        Thu, 01 Oct 2020 16:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:874b:: with SMTP id j72ls935488vsd.9.gmail; Thu, 01 Oct
 2020 16:12:04 -0700 (PDT)
X-Received: by 2002:a67:fb90:: with SMTP id n16mr7794875vsr.22.1601593923971;
        Thu, 01 Oct 2020 16:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593923; cv=none;
        d=google.com; s=arc-20160816;
        b=n32022OIG8ASJsuNxnH7RjPJZcaxZHI81PgTwbH2WGjfdqEdX72O4RbYikDl6HGv4G
         JIPXUTGQ76k/0R33K2CFzPVLeUwPBAGcpXIbrR0zm+NZMA440omm9dClDTsbpukrGcSk
         X272WKcfcTM2FqD6jlZ8ks1CbGCgQaSB7OffEcAwusm6eZ84jxCVM29btK/oQQct+7pI
         cZpqzHW0RvR6nt924Jb4otNwAEFo4Z4VsF//0u8A4gBIFiTDdAWNgeJKgqA9I/GAyCP5
         ygq/7NF0qhLXuSZxfa0K4IeCSM1N6yUCnHE3ExRLc7owa0+hVsfLueK8YN/xzyZRhX+g
         lubQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=avhnvpcdCzsaNfGYEey/eQHTKDiaKIA9undXAy55Bw8=;
        b=mOTuyFtn+7mIKnGConSKLn8TcVAaKLEVa32J1A30Yngkf22yaMC1R+8g023gXorerr
         iz1VLi9p4GhhpAkie4ULGnq4121Z4YIzmBUgkYUxhS8HbSrDf6tnGLsjXAfzyu6YgOhb
         1Bfmovo1kDlwvtVAv6HQ8+hVIXOt5BiYbuGwjoZkpmHKf3kq7HcV9MTDkS2eCXTjclKY
         allli1O/fJfcvn1TEcL3rgiKvIwyxvm7EQNKG2zdnKBltqyCtj2TzKsZXaBQCCwXdRre
         es3Av7ZKdqX5frPPjaSfei3NOBHofiXRl76gtuZUH9mqs506FvR8oRZeklc3icf2OiO+
         I6Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNwdqefk;
       spf=pass (google.com: domain of 3q2j2xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Q2J2XwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id u19si518098vsl.0.2020.10.01.16.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q2j2xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id m23so45347qkh.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:12:03 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a899:: with SMTP id
 x25mr9459301qva.46.1601593923500; Thu, 01 Oct 2020 16:12:03 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:34 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <21a9da4e730050d421eed7fcefda2db508c730a4.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 33/39] kasan, x86, s390: update undef CONFIG_KASAN
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KNwdqefk;       spf=pass
 (google.com: domain of 3q2j2xwokceierhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Q2J2XwoKCeIERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index 726e264410ff..2ac973983a8e 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21a9da4e730050d421eed7fcefda2db508c730a4.1601593784.git.andreyknvl%40google.com.
