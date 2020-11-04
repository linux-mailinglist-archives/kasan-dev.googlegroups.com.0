Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB7ORT6QKGQERJOL6GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 607DA2A7121
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:37 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id j10sf366507ybl.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531976; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICAc8gP7RmGwDizvinXAD/96oF0lBs/6xVHDfHJ45OddrXcHku2LoxuzO8NiepkGiv
         +RXSo5sl8dj3sYS8bThyvgU+/snTvUIAsTw6NRWTJba/vc8dOnxPEkxZ/TqsMESTmH9R
         s9EBq0FDR5SsSRD3tAe/NaRVhDUCAkSenUZqYm9vwbzsdC3ODFDa5PKrb27dYhtRjadw
         yxwbQ+Ea2TPKLto0JUosDP4NbLipOVUphdT7KA6ONZ8YNy9aNNoR9f82ogsFlsAOEGpQ
         WLwXU3buye6WHAf+fRuAAuhQgUUdsrPGF5KSaAsAYER+zr25W3QNskG4Oa1joBHKjJGA
         dPww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OMWBxnijIi8WCdaTnoJxP/dmogDXuNt+wm+YqFtr8FE=;
        b=y7vdYVNuYQAUSREhcqQNlyjsXLT+umJB4FsR7v0Qm4m4jGs+xTbWmbyQtcVvciNmUy
         h0TkFcoVb7T0+qjihJUFOxfFYsqOjnbIZBRvlMlnMEd7058CDAx2pMosH1Q3b0P6m5+c
         Ded5KUCKaW0bhWoU5cTUwCyenRyoN9MlAtChc0J0hroZdSwvPiNTm3HFPpILYWJm4ftV
         SMSw19bk3NvkPv4BywVDG1KYeW9kUQC6Yi4yCwxAglba2ChlWQBLifN4eW0RCPNXOEY2
         ZY909z8piYBguFbltDpBKRRCX0pqrdKlb4lqCW9HI3YP2WS3Fimu52HyrAxrQP+1ewqe
         MZQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VzWDrHAu;
       spf=pass (google.com: domain of 3bzejxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3BzejXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OMWBxnijIi8WCdaTnoJxP/dmogDXuNt+wm+YqFtr8FE=;
        b=QZk+fpw+3jnSLM8esQGFRsja1nTtsI7yAmyYZoTpWprFT7FN/A72iikEkCo2FuTvLW
         0RoNDYXSFkVG0HZV+pRAZpzpb3qkejVwempJ95hzt7eGME6JpE3KCgpmYQb576+rf0yx
         5c7Wog4/J458cQJSN7UOHpKzf8crefncCms9yBTfLCexHP6LuAI56TprAbN9loX8Zp7r
         F/BUR9sJsm1kjUwr/oeXWHfF+N10Yqlj2581qN45x/6S1xw9VpwTdwC1v+HHM612Tkvs
         uTlD/XTwygvLA/5+HgGRvzM2o0TuesOINqDiDs9gToVaRqDm5Xs/9w1qLgy09Qlj4uxl
         4PKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OMWBxnijIi8WCdaTnoJxP/dmogDXuNt+wm+YqFtr8FE=;
        b=A4VLMzT2ZDClYW7CPP+Mb9fambo80wxTyAMbj1mS8vuFf/H+vcBBaO3qvj5nV5n2J+
         c2dvPnXxX5bZmadELSK7zs4BJ1CW/eWdlWhpj4U0jwFYtwlI/I/T1UNrQ1V+XTdyZc64
         yrWzkh57+XCFjrpqVz5Ch3YVKGll2y/JTmb7N7mOHbFCWM7Tv9svrKpEUbTOvHHFSqVs
         kPC9lv7gKMRHVLan/CoMQibDqa8CR3d83qUjhnSHlQ7It1yv1crM8nGUPcPTv3dVOGL8
         1Z0OKAPBmwXBkzpmzI0RIZnGURRuL+B/uWoBNalW545/BvEHrqZbwG7Tl9cZhh8XtDrz
         FPkQ==
X-Gm-Message-State: AOAM533xX3eUTwOTtyef1UfUGBfYDAU/8qRiQc256kw4HW/KQiSmqLUA
	86m5rs8l5ujWmddsy4SHJkI=
X-Google-Smtp-Source: ABdhPJwYWNK+pcAM4tANdMcKx/N8R4RZa15U1o+ZnXseXnFEZXDzgKMz6EsSJMMC0MlT/GGBIXQ5wA==
X-Received: by 2002:a25:73ce:: with SMTP id o197mr267436ybc.462.1604531976112;
        Wed, 04 Nov 2020 15:19:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:84c4:: with SMTP id x4ls1719556ybm.6.gmail; Wed, 04 Nov
 2020 15:19:35 -0800 (PST)
X-Received: by 2002:a25:2c0a:: with SMTP id s10mr260585ybs.217.1604531975598;
        Wed, 04 Nov 2020 15:19:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531975; cv=none;
        d=google.com; s=arc-20160816;
        b=VHz+NHdJ9cnyUNxpAMXlRLZo7Aeem/ht2MFWoQ0mOZ2T4j/ZPoZKLXq+cJIWYlb53P
         BTUy0L1JHvJYnM6nPc8qmWPKpCSCNAiFZKfmrqVDrjyNYJKYkdYKOeQNNQDVJ3pl1DCK
         MuTnqlCq2Q+4ZaMVgrzU9uApw898KrRSDiI3OBmkEsMHPWdQ2rwQIFXSpWGHEZCelp+h
         RHrj8tg6SgT3W6fLTIPGLK5c5LW9C5xiLL7Lf8Xd2xfz1FTcdjxKWegbgGkygGQ7as/u
         3KWN2AKoI3Z9lV9Xtm6fyGeN6m53nRdlmt9L/XimMO4mtXavFQ4Wx9XTbQG1WDP5Nyq9
         WNUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=n8TE6VLWWv4zp+ZnErvJoE/L5oOe+Pde/aeeJYIsZf4=;
        b=TUcQEF5KqNv6+/oYLyyXMRPjSUiVTbsQx/QxxpScX0e0lDU/rAdO/DBi+xv9niarFF
         C4onGQ2ldhj/WemSOUV6Y/fyQ1sjApZUztCPYJ5GqRaixqR2Ru00+gg2w8xqqROVXat6
         9Z1PfAxzgyErshte8pClWd3bl1Ir1z/AM6YFz3v5EjUY54/M0I24DG42wK54zwot4YHV
         ZEw9etWbjdVTUWjSal3mnP8FUDyTsB6uaug3buLg0EeZ8jOSNme0IVPMzWx88XwnGOj3
         GxbfKeoGixJxZ+bVm3o8LC3rfZ4l53nslL3p7VVrEGUYSxEMI/Cx0Q9H93hz4JnATENa
         5KAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VzWDrHAu;
       spf=pass (google.com: domain of 3bzejxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3BzejXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id i188si249092yba.4.2020.11.04.15.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bzejxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id dd7so2047qvb.6
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1586:: with SMTP id
 m6mr249436qvw.15.1604531975177; Wed, 04 Nov 2020 15:19:35 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:27 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <6320e83ab93e0ae574426e5ad36ee3e52dcadf35.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 12/43] kasan: don't duplicate config dependencies
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VzWDrHAu;       spf=pass
 (google.com: domain of 3bzejxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3BzejXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 8f0742a0f23e..ec59a0e26d09 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,8 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +48,7 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6320e83ab93e0ae574426e5ad36ee3e52dcadf35.1604531793.git.andreyknvl%40google.com.
