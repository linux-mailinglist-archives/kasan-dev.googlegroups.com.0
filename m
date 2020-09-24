Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZWFWT5QKGQEJ5JHO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 57220277BCE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:19 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id y136sf321642ooa.14
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987878; cv=pass;
        d=google.com; s=arc-20160816;
        b=eiFV8k+a+wHH9JqXge/KUIntORNapymBFX4nt12tfULwRtmg/gepsNxXSKlMOyu5Ox
         h1XVMI1Ny/i+jy1ZSxlwKMQTROe5AzASWRDcGS0mZYqye2wFEkxbSfEIwTSkTAPzDwbi
         MGZ36SLnqx5cEXJylC/ZDFwnIam1QMO8jnxpSP6BEk/K1Gway5+kNFk97mp6K069mKBe
         fAPuu1cyEPYkNQGQlajKIvYsAUYGc5PKyYt4B9VDI1Glul9j8cxJdLjA/QTWFGxS9u7s
         sVHqbYtaOSYoTJNqMSpGPSFmuoYbzaPNUlR5XwwNFLXKvsCck+QD2vi7yaGyHwLZoesw
         Ub5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6fIKI9fNChqOUImGdiJoGzU0sMc0NMz/eYdVQ3GJsZs=;
        b=Ei6nolTAg+eQAF/sFRSeNHBjClyC8kZNBYyM00clBMwScT/2vWac2t8E9Niasp9dgV
         xiL3sTnIM9OVVGOYulDgmzTo4EKf7mKZzlHvVADozFXKQn9E2ndTBtuoE3ToVxtlkCcu
         x5AdhC2v3n+8fNHQUmP0eCVXmcqwWV+fMD0Fus9q0wDelzBUFQhPtOKF8j3UjEzKxNS+
         W4o7kv83s8aQcAnqyQZtE7DCkCrWRFImFS4YCJPpf47cwkRrUluMr9n8gqkjctiWN50P
         dIN7YSarH9BPEVYA7gdPE5pH01L068X6vB8WhRR/EzhPs8Isxjy8T2frmhxMqOzL44I1
         t7Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ALi2C5kO;
       spf=pass (google.com: domain of 35sjtxwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=35SJtXwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6fIKI9fNChqOUImGdiJoGzU0sMc0NMz/eYdVQ3GJsZs=;
        b=HhyhUqk7VaV1QyfvVcl9VP3X+frX1yat5p0fhCwcICyAe4X55iO8y5nJHjhjQxsM/7
         rYGiiNRU3TP9ewdRDJv/z5i3fhf+VGcBgtr1WYPXcHkFseK4UzKnQbk5hsbjuQbtepA5
         +eJ9y5gIW6X3xdt1fAWh+1vR9q6RvPn3ivIUQXrV71newfTFHD/TPM2xUMKpGgL4b3Ey
         1oB9E/VET9sPkkbmjle8gqidxCKywdLzqS23XYIf83cLvqiyV/Z3s462JGfn14G45RzN
         eNLuEvF2kWNfAhze5uvx5fA+ICdq07bwwnupVZjb8d8P4XzUy7Bx3YJYoI7sBZ4/Mgfk
         LF6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6fIKI9fNChqOUImGdiJoGzU0sMc0NMz/eYdVQ3GJsZs=;
        b=sXKS2mOWL3SfU/DobeKVxiFSiBProERXj6tTVr8fX+nmdpVNtFjTzKzLyUgt3+GqeT
         Gpj513k4f9GOHTcUuFSlB1ls28mB43IotdGj0igE/7qQh7BbX9J/s+qytJhy7dAxymb0
         MkIELH2TUMgG1tCZPEUJrtsCmeCttFlinJ4JNk/IKq+48tGAzqvV/N4ZO2kMtUzV5ZUT
         NDG50LXl7yzpWPX0IuX+Egr6ydq3VQDG20VIamOZVVkwfLk4V+KYVL341N4xScyWj86t
         3Qlb3Y0yU3sMuRkb2f7aobHIzBXUHhVgeVo82z7AJvvsP7YwMfZ/yAi76iqqPPPsERkl
         VSgw==
X-Gm-Message-State: AOAM530OjzzyS8x9uVKyYnnSsKEigtP9BG17ZESA/alPwD69BOxK21X3
	hLslAcZUdy8msdRbvzfZ23U=
X-Google-Smtp-Source: ABdhPJyhKWQ1+pmWCaF4KxFrZeED/EOtZD8kdaYXezHcvsQdpKAlVbF+QzfcsOoQLQwVqExHqTMO7w==
X-Received: by 2002:aca:4ec9:: with SMTP id c192mr662979oib.2.1600987878197;
        Thu, 24 Sep 2020 15:51:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f0b:: with SMTP id u11ls249084otg.3.gmail; Thu, 24
 Sep 2020 15:51:17 -0700 (PDT)
X-Received: by 2002:a05:6830:a:: with SMTP id c10mr985441otp.195.1600987877877;
        Thu, 24 Sep 2020 15:51:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987877; cv=none;
        d=google.com; s=arc-20160816;
        b=j3d0Pi4yTXoWCF4cxpICkWQwrF3us7DSqgyV2bxoe/g7MN38iBpVz5bKBCiK/MHyrb
         X/IlQZMzp2OXiZqNzKU67+oPsgtVljS4VQmAbJi7uO2s9swTvvVbe7rc3EFxvT2GqR7M
         Iub3CiXIX9kGNbrKdlCoKAlFTZl+7SOMJmqrpOt8SVOST5W/9wKEku4rR80UgiBuabem
         zonatSgbk8MWFypwJ7Oj5K41EVuhWqV+yZ2aj4Fj3nK6nT7DFx8nivVHxM0BOB0q4lpA
         0oGkMdl5yq9bz2QVvCesMIuVdQsyZFIxIa8Sy1xMDT+wNQ+SrUQ6hIk0EY2XXCqhnTDu
         TDoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=it1AK7tfxDHGBKnxx2DLY0hRUu4OKaOHj6i7en09YKs=;
        b=SlzuxnJu4w0gGWZp4mJ5CkNKo12kFRQ6QOFPrqjfrBn++vUcZxLhUjKU5DcgM3HPbD
         s38rsBN5ZQTRxY044MD+995kl2Ckkcg613qtSTSComdRErszAeoeti6UEim5D3IC5l/e
         zMr6WQVI/K77AXzCq0rHRe8vecMltYvQ07CSX8APvcu7tiWEGRqJhFkYb88NCpCjo8T7
         iH2Z29uzr5HFkSBZ0jjcjlXFJzjbBuNOsB0LINDdFD3WNm6qWdc8XNWxhIbAtNrz+dpP
         hb+nha+yeTC8x84naPRJbLMhMm28K0bGE/oaKx2X475vE+Y8MxEA0XmafLyx9yxAYIbj
         o83w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ALi2C5kO;
       spf=pass (google.com: domain of 35sjtxwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=35SJtXwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id o22si130927otk.2.2020.09.24.15.51.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35sjtxwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id g10so532314qto.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:17 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:43e5:: with SMTP id
 f5mr1567528qvu.12.1600987877306; Thu, 24 Sep 2020 15:51:17 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:18 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <728981bdedbca9dc1e4cca853699b6a6e8f244e0.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 11/39] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=ALi2C5kO;       spf=pass
 (google.com: domain of 35sjtxwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=35SJtXwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
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

Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
those to KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 11 +++--------
 1 file changed, 3 insertions(+), 8 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index e1d55331b618..b4cf6c519d71 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,9 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +49,6 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,6 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/728981bdedbca9dc1e4cca853699b6a6e8f244e0.1600987622.git.andreyknvl%40google.com.
