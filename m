Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHOGWT5QKGQESK5HXBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id E9736277BF4
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:13 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id md9sf276119ejb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987933; cv=pass;
        d=google.com; s=arc-20160816;
        b=HiEF7+7UaxJbgvPJ7EYknPMIBOUoLY5EFeATR1vsmXUD9njoX40n5Ro4a8ZgT9Vxdb
         kfc/ov5F7rMPphJY6LG1IoUfpbF41VeeI/RH9TgByhVcQUinDdmF1Z0wA7jSYTmy+0zA
         ZuKprMdNncZZ1Ej1yqi4fEZxqG549hREkyr/TgeNO355RcZcJO+UP2anNXgv4KW5exFB
         oMyq9tMbwkWpE5vUYE25XThDJz64Isbe7pKaPxrop6apapXzbD41zMLxnKIb6TlGLQlq
         EcGm+/RHASYotekxx/R4sbP22T2WEb6nRtTdx3fJDfimg+HdZl3d8ikoLg/9NgeMj780
         1mWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vdNHYj21mCJ9uE1LEyP/zpwfDWbnIgs82+QQApzleEY=;
        b=DW8bJ9tUHiQ1T0y6QuY04vFAog5UV8ih+ubkdTQ+UT7G39kp6Dz6LhGTICakkyuiHJ
         gsMeIGPX3tb1RJVtTUZUf1cOoRP5ILOJ/sL8LtGgq8BZiI8dat/h/rD3N5gaOyrUNQqz
         5o4SNGLsFBslFPHhdNtdfXVgVKVDMOZxWLO5wc3aTdj0Trb9vJxw+qLYCmna0TeC3ffe
         YFVG1tDJcYAouRWfkWxUcvEP2K1BglBAFCKjfO+Bqon1FFI2Cso64SpJGM9sMM7uGuAI
         K84RKYGBPKsxeuE8Rt8mbsfxEmI21GMhLWfy3fJZR7LqEvT5WKaD4KYHDZ+euQpSCTm8
         N4oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ma0reHmg;
       spf=pass (google.com: domain of 3hcntxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3HCNtXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vdNHYj21mCJ9uE1LEyP/zpwfDWbnIgs82+QQApzleEY=;
        b=VdxT4Yz0EClnv5szhqS6yAcl7JXP7lankINIY+ciW488Ow0g32tZPMKWTsYNrYINDO
         M7+xdT56KabmHRdReiwEbxX69s7ecvadBZWIWEykxoMOS8K+wGcd2ZCRpTCGXvyXmL8Z
         N+vAP/67g7HE36v4KT9s7IR+PTFZZ8XmVU9x7NJixYLyKn2hKeBRKJuG4kMEWvtxggUC
         QWYKAlqmmbrjVvFGTYBAWT4jS4/SFolqFTL+Xv0KXN8qhUnjyg9Ek8zHrdxtLNmFiLb7
         Ndc7cFCt331aUVHYznNKGOeXrHE2DaysdxVRXA5KG/TYowTp8hrX+Io4d8HtqvK0yI9u
         RgcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vdNHYj21mCJ9uE1LEyP/zpwfDWbnIgs82+QQApzleEY=;
        b=HAhfdpN9hzxSQ51+cu8JjBcDdu98LT8WRv3oFqyvS3XjAJtii6Q+Ar+qDa4+GmF8bI
         kC6thypSjKlXsEiZOZIAeCeWmo0iv+o2+1xjRn3wk5p8lDML5qAbAAIRed3mvFShnjEv
         JfnYaXJh6C2ejMKpsxQN2Vxj4MK31cn03t2chURoc7pHJW5u1HyNq3e0jA6RAbSioy1b
         yTgpj04B5m4/ViOqAa4jI/sLA0ElRvF16Qs7wLDNBi7yMnXVxs+K9oWahJQqrqwOQvgS
         L+gyflVNulnOeENQXsb2LABKWFwpykxB5R8CBqTqI9cFH1orfS6nvwU0mrNb8W3/yHas
         iqNw==
X-Gm-Message-State: AOAM531iZtVVHzVhpJJtKaDtvVkR/sULo9yq43B2tqenH+ZlJs9kdwyz
	ghaxGd2vD7AH3ccll085uTI=
X-Google-Smtp-Source: ABdhPJx9EArzpZsooBVvhayXBNtRgR29ZpiUTSxl0XDHsb5gAcZUMnxUoTIBQNKwPAWM+6bJkNYySw==
X-Received: by 2002:a17:906:6a54:: with SMTP id n20mr865283ejs.401.1600987933715;
        Thu, 24 Sep 2020 15:52:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:387:: with SMTP id ss7ls257350ejb.5.gmail; Thu, 24
 Sep 2020 15:52:12 -0700 (PDT)
X-Received: by 2002:a17:906:4cc2:: with SMTP id q2mr907600ejt.422.1600987932763;
        Thu, 24 Sep 2020 15:52:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987932; cv=none;
        d=google.com; s=arc-20160816;
        b=OnNFfvo1fcrLZ5kCFK5HBC08ojG3r4FxfzC6WNiX6S3xW5tCRsYIbFjrXOg0X0lEDZ
         76iShhdkGmBNFdwel98KBuKP+MW70kaADMDJxQmf4jSjxo+K677SeFnzvkQpzHGyWfEZ
         uu/gDbqOnD0dBRzbhPYGzw1T43qbWMK/D66Uj0JV12u+Lcq5NIRgv8883RQGahxOKigK
         rieexFCHXxWfYh288JtxSVWtdPXwGyPKBO3gpUGfmkZgoJ3CGa2EDGqXpx/Cs3YiBk8l
         7w81HB/cGrQQ1thfVCCP+SJBJTGNqtD33AYEAdRmGjV3FYxyui/nYCI3IeyPp3PSqvPr
         NIZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=9ix+4hPu1M5tbLN/A8rv1MdksQ02QT73msi6Zomooco=;
        b=oILpJnfg4R5Bw0318aJ0iAOiLO6WUFciT1iXHblKG60HjxsdpGeu5JlZ6BJjOGZ/iZ
         MNu32szkCxOzie1iLvUQkaxDJE00bf/OdeL2OcSK3bGNIHIxnApKbaMgOG4u8X2KlPS0
         VYm92p8as+xfzDGs8C8GNj6an2ia9Zc64CkXm5ptbYNJTl4c3vbnrWWcr32r4MSAWym6
         jMDHxoge/0CAdY1qaVzMyFRtg9p5HtQlb13Hwvl6FcQNdEpoyLVa5Rhkxb6P3ESGse7y
         cg730AIKCgWxFUY8xaLoOHmiH9MMSlCecuqo8cHhC3jeXelrDDAzE7BbSvGMUpDlAzb0
         mJaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ma0reHmg;
       spf=pass (google.com: domain of 3hcntxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3HCNtXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ca8si6042ejb.0.2020.09.24.15.52.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hcntxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id d13so274417wrr.23
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:12 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:f619:: with SMTP id
 w25mr852343wmc.62.1600987932419; Thu, 24 Sep 2020 15:52:12 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:40 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <78ebf3bed0458172fec9e1e32f2d29d7c8c37341.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 33/39] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=Ma0reHmg;       spf=pass
 (google.com: domain of 3hcntxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3HCNtXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78ebf3bed0458172fec9e1e32f2d29d7c8c37341.1600987622.git.andreyknvl%40google.com.
