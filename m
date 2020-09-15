Return-Path: <kasan-dev+bncBDX4HWEMTEBRB466QT5QKGQEBYNVRPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id CF35326AF6A
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:39 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id i23sf1803650edr.14
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204659; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sx49uo+nYbOcUPFvpiR/EkbcxIDpZqYCf+yDVh79Dwl6eVb9tJj/h82MwX8RGe8nOi
         DDGKBPEWnKA53elYYgLcfuhPRFipvF4AcPwXxSusgDVGuj3u3lMHJUEyYlauRvbOEuhp
         Gwk1AjDiMubmeoLPUoSbN7VZS+rizFgkPSF0lPllRChSG4mmuQyBfDNOlpcM9EqdZHuj
         9yJqqpD28w1nvrTpiQrg0AD+Q1XFLf5O9YgT15OtiWvspmy9MBoHNuQVcy/RrAU4D3JF
         bf4fjMD2vc6lCj6JqNtTuUQ8NjVjgVaeJ/kOOAQ9/CI10SkrcuzJ+c8AcRD8HuvFZNNQ
         RRtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=9bjlQhH33lfjGGbVSCFlFlVLfAEOH6Vb8RGBgb0hQSI=;
        b=kFkIUypsBnPesfmM+X4rJTn4+R9rA0v6s425Oay5k5PARMi4Mr4/DJ37jqVbIx/sTD
         cuIul4d6M1TQAEUPOnRYrlY7nym0RPSnQ7gBnV88sg/24oq9nHFtdAwTz5BK7whSM4zC
         3pD93C0Ya7eFWuXh6eqcKWKrqctITpjkh0Q85cTI79U2PofSpIZB8xPu9xnUDt3AT2rC
         TPo81IA8JgKURfJM3p5KKucUnIDl8oLndzZeIJcg5oTWM9tI8csvScapMzqT0doCLPeN
         sS2aUt31kRZVdVHKowA7QRNFYEwMCU5NMfMxFRVRyI/XtR7Wtnd8AH9O/boUUCsRzhUP
         5ZIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gGShhG9R;
       spf=pass (google.com: domain of 3cs9hxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3cS9hXwoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9bjlQhH33lfjGGbVSCFlFlVLfAEOH6Vb8RGBgb0hQSI=;
        b=hBlFZeipzYjWm3My8aLS3IRTMndpKEkCj75CTnptWliT1CCnOZhTHl5IvAICRNqAc8
         V/gQ5KOQ9XetERw7bN0OuEHd/9orcmywhSMTVEzSrl1nJpYgDeHfBmD9LHtssvQ43lrj
         XFewwPuimbnLYpJLCjoaUEbzoZiRtjm0j81WJQOnjt9ARupEKDFbARsPu/n69QBoMo/3
         w7ay/PaNt6ZUqLYw9Dqma1nvITZMbMsMxOXm2W7d8XMrN/RAs3KSxwK0AVmQLEXrrfAn
         74q3dxmKm8GOGq6d5ebfJbjyoPxZ+p9W5Tn7iEcZ2U33rHKGDciO7XwWaEytlSW26IOm
         wuHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9bjlQhH33lfjGGbVSCFlFlVLfAEOH6Vb8RGBgb0hQSI=;
        b=qd5WRbJ26gBFF7XjqTjrOdsC78yoZY8dNpDPaCrlN40xixS1u9qPVKhTprFKU5EUxw
         AoMqTAZTXA5qidnELJaqNA1vu8QkPIT6QfmFl9dWF/9KXfheEOHAqS22N+uQci4i7OCh
         5aiRJzPRvdiGOdByvnqWhC7iV2xwBvTHaMp23XMVNrPI3cPUnFWw1/1JmXMkUNHOgTSv
         r9u05GRntGN7ObXv0Pl7clTKwBwxiBoCjKxNHD3t5f/18v1z2iMGDvNIKrE3J65Tz/+e
         Etw9i6IFYYjlMwpynEoOLUxw7MhC7A1LSf315ZEjyxWoLo40RhtW4mVAJrkc7cE+BSCJ
         cjsg==
X-Gm-Message-State: AOAM5337xO2qhb5LpF+I8sB1XSaGQpvC8tIRpApowybFtnpIQlneNFMx
	HQVRtqLVJrJlH+4TfTk2TeI=
X-Google-Smtp-Source: ABdhPJzgA14BHVtlwEzU2HKGhu+23V8UaR5sMyvwIZ2pkN2qI+2rwKkO9BJi7WIth1xr2NwGO6gv4w==
X-Received: by 2002:a50:8c66:: with SMTP id p93mr24781876edp.156.1600204659548;
        Tue, 15 Sep 2020 14:17:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:d0c8:: with SMTP id bq8ls65326ejb.3.gmail; Tue, 15
 Sep 2020 14:17:38 -0700 (PDT)
X-Received: by 2002:a17:906:275b:: with SMTP id a27mr23051234ejd.190.1600204658719;
        Tue, 15 Sep 2020 14:17:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204658; cv=none;
        d=google.com; s=arc-20160816;
        b=S8M0mJyVHhywNCufVXiZ+86QXvluEzkYfmn1bk2Nf7M0wi6KRNqED7UFtimZ1vjr/o
         +YtndzdgfCISEq6/Y5I6x46x8nlUSgfw01WGZueE+xFq3A4nLv6mFjv4hCjQqStuXvqO
         2aMkv78MetFzdymK3TFiewm3Q4oNSq63UhtKomrH+Bx3Ey5rsF02lc7FKxG2Eiv1QB8T
         hbbBCI+ftGrXXnAosjyP+QVZE/WUmCTWnqx5ny4ry8fjeONo62X9byB7Cgqa65hdRT/9
         CfmTYrxQ52y2nHIKkwoCZ2Oy9rK006F+q/D2mgVjvX0SxNUJP2WpboJApVtebbSsDC8R
         TgvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gJaj9HJzY/xay7XUoLkj6R2OGJl/aiV7rlwVCZ5wZTg=;
        b=EK8tFrx6HF/6Z84p63xc06CoTVK4ClRzVnoLJGTZmOE9XQlrG/xoIwUNT+9awH3UNT
         SIskNuQysj7tHy17yCPhobkn2+VT3lc0wYzxKlpNL3vW7G9Y2+8lZevJ5d7ntu9sqcqr
         I7S+3gr+3JiIZYa3rFOqK29ZgW1LZ1xRYXT7G4x5t7hngTdv9wWxWeRWM9u9UaDlcidm
         x3LRc7kbJtr9OAM6VZy+Kadch6QqyazL5bqbXwemhVMdvUhJV29flHZjoCMa7Bl9LTfw
         IFhSDFeldUFJBvd4DUbKX+ddLN6WBQH89mzi+oisjw1Zf1uo0+us64csgJKm/2BDE+zL
         9eEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gGShhG9R;
       spf=pass (google.com: domain of 3cs9hxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3cS9hXwoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a16si764518ejk.1.2020.09.15.14.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cs9hxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 33so1700170wrk.12
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:38 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c14f:: with SMTP id
 z15mr181253wmi.1.1600204657873; Tue, 15 Sep 2020 14:17:37 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:13 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <0a35b29d161bf2559d6e16fbd903e49351c7f6b8.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 31/37] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=gGShhG9R;       spf=pass
 (google.com: domain of 3cs9hxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3cS9hXwoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0a35b29d161bf2559d6e16fbd903e49351c7f6b8.1600204505.git.andreyknvl%40google.com.
