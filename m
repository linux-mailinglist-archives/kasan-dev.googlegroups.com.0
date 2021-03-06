Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2UOROBAMGQEYEJFZEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D35D32F712
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:06:03 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id o21sf53721lfg.21
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:06:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989162; cv=pass;
        d=google.com; s=arc-20160816;
        b=lwkRgL2aAidtCLdV/D7rZ30GzfoOea6D+ruUomNPe9h6bXK36w5CBr4Jd7f102qOPA
         PU1PUZz3G8Tmgvi23qdR2Tyl7tbYSG6w7aZZxjEijT309+A1/Ui3KESA4I2BKPOJUKiy
         brD4dZZ0TilhgKB+2i1Eipfepf7d0/ITDEUQ5AYyHR9c6c2YoWim6Yox46PkwJSthk59
         zmGnTudANva0v4166Yza/SUHggSaoqiPUdQJBUtgCvuuZMIxJC0ahofcFFwmYjvK0kHO
         +1XX6QIPMJal0RiMa4fEmAW2J4MEUP2hGs1fiQDPyVCCthOYc5yqoEG6P2NAaVEF/6HO
         62xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=r/NPUus3wMfXEI0NcAIWHaqZas1k5hNhT7UWYk/ooAM=;
        b=PnlWqgQbIR8BNFEUmgfRy91jVrV5xfqx4Uhlq47prVAnJ1lhou6ERQF2adHVItNfIg
         n57gtYf8j1ofIdvrp5CIzoH6IA8gQluNX+PMomNXrR8Gh3D4H53yrTLGyEe1eoVFkZzB
         d4si+nVS/8IYTVwicUIaESAt7AalICzChn9lEpW9Nom1kXIxhHCh3Ps1awTvRHzgb2pw
         kxqlC07fKkhC7ET94mOR82K+XfJYfnunNsHRhA3fOf6EnG92Qu5N/UUnSbU5pbf5UQnY
         cquX5I4tUANfHEbOgBuPHQURClX80xqCQmCduigk1exdXoMNkMfdbXkb9ialFYk6mLs0
         nPRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UM8dPWue;
       spf=pass (google.com: domain of 3acdcyaokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3acdCYAoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r/NPUus3wMfXEI0NcAIWHaqZas1k5hNhT7UWYk/ooAM=;
        b=HbYp36uYdW8TdYGVG71dDLYnwelbGw4U4SAYylooYZC50wAIO+5S7NJyBlv/3CpniX
         GlJRS1fkdK1l5IoXbWRV73QA+pGT3Q1qyrfB57RnrNoSFCE0vio7eRO2JKkDcSurRsP/
         V8sXSEfwKTOro3aC8jt4ECliIqSFNHm/gn1UpFMMYiu97Mr1urvq8U9dCnPrHkMZN7NF
         MabmnJUQa+TG3f3kWKQJTv59ZgUuKUt1kfaD41fxzC56rQgy8dvtX5ktEKPXPxv4PLMq
         CjZr9S1dAYvAVyt3fz65SmDzhy/8Zxwp78BS+FxWTAZjLIbnJpRUWmD7nxAiWRa6rEsN
         buaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r/NPUus3wMfXEI0NcAIWHaqZas1k5hNhT7UWYk/ooAM=;
        b=JSexeBGHaZWwvNzyJaZm0OavuLjLNfAOgc70ksRWEEvZPKV+gY0ZF20b8OPdZNA98u
         1Pn8k0qqN1tv6G70P+93gEEZwXxarza7D7S8/ftib379mR959a3/JYA2++Pk0szxzsoi
         DP3eV7vIqWSfunBM0f6A+T9lL6z6FIiVasnUNgnKw1wZmbK/+RBbGJeZAhULCX066Exs
         TB6mrpbFJpUioVPfmbbqf/tTEWFtjpafG1/0DwMGsEXuzy7yBswurAHnupZyyeYeuLZH
         EUj9otNHJ5ga22ZEaUoyxJ41fin5b9CWyMbFCxk+BTynrg8vbGWPxM1WLTWWdB2qdZw3
         CTOQ==
X-Gm-Message-State: AOAM532czlcl6CJo5LdjctWFhP9Eo9Aq69TcgtqFPCIJfkoLz2qTLHrN
	qXJ6HMGwtmqxFd8OKseX3LA=
X-Google-Smtp-Source: ABdhPJwPSz9psKEf/Xh2jlPl2Y3eV7hAP+hPgFBO3MfsmFjXo/BunGq3s+0GapeK4i6zuZeF9lkstg==
X-Received: by 2002:a2e:b815:: with SMTP id u21mr6821961ljo.308.1614989162706;
        Fri, 05 Mar 2021 16:06:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ac46:: with SMTP id r6ls1035070lfc.2.gmail; Fri, 05 Mar
 2021 16:06:01 -0800 (PST)
X-Received: by 2002:ac2:428c:: with SMTP id m12mr7508464lfh.430.1614989161685;
        Fri, 05 Mar 2021 16:06:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989161; cv=none;
        d=google.com; s=arc-20160816;
        b=CfX5QtGUkEi2snomg+6LEavUg6QkbZQDRcPcvaMb2eG+WjMHh60gCrKtJr/4q8eslz
         B93aPkjHsvCP+sCvJCv3ANyB0WpU67vjPSE0UEcn766wOc4P3Rg8a/4TUBCkz/uRrIYP
         fqm87iBeP5GYeVjtMoZ5eGdBbTHVlfdp+JH9eBhsT7Xv0kdQ93D7uEComRLwK4zwZosG
         u8I0Z7lSU5wQC9ZTkRQsoxZ25pFNi7ufbobN22idhOtOlU969aDl0b4PCik+DbzseEje
         4ZfmTbwQXFyzByZaBsVK8sxXreywNsXa23lH8fHDgkjwJi1sWK5dC+ylAurWEhOysdUJ
         G63g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=fj2q1zjTS7x5AWIG0dea58z8gWp6VMPPrsYTyOmyMJM=;
        b=w98VqGhfAj75gAS+EkSADQGosD9XCvZgBvei63KLDiZl2xbVhGtsjV1GsvU4fuPvf6
         Z9oRJNxJkAt7SAh+slf+TG2eu/JES+wOxlhHtn1PgXuW5QZ6ZP2y3vdU4q+i+21cXPR4
         41W/Zmg8fZhkbUTJYQXLp1D+zebHSHB9HhfkOnoZ0O4Fy2h/i3KNTHdZlkrxjwkDGTTb
         5PEFS6bbcHqEUT3Q/dJsPJh+oh2cbgwXZuKxlXjqfPt4wmJQj0I4RRIPM8gfZxRnNUBz
         nfjTEVKhi0QDCSD6Ixn/EiE7MxBM1kCG5fTZAGU0OpMQMNxeaQ95s32T26miGj8Zn5Cq
         GgCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UM8dPWue;
       spf=pass (google.com: domain of 3acdcyaokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3acdCYAoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x14a.google.com (mail-lf1-x14a.google.com. [2a00:1450:4864:20::14a])
        by gmr-mx.google.com with ESMTPS id z2si151950ljm.0.2021.03.05.16.06.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:06:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3acdcyaokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) client-ip=2a00:1450:4864:20::14a;
Received: by mail-lf1-x14a.google.com with SMTP id m71so1382596lfa.5
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:06:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a2e:8e86:: with SMTP id
 z6mr833578ljk.27.1614989161291; Fri, 05 Mar 2021 16:06:01 -0800 (PST)
Date: Sat,  6 Mar 2021 01:05:57 +0100
Message-Id: <b6cd96a70f8faf58a1013ae063357d84db8d38d6.1614989145.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 1/2] kasan: initialize shadow to TAG_INVALID for SW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UM8dPWue;       spf=pass
 (google.com: domain of 3acdcyaokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3acdCYAoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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

Currently, KASAN_SW_TAGS uses 0xFF as the default tag value for
unallocated memory. The underlying idea is that since that memory
hasn't been allocated yet, it's only supposed to be dereferenced
through a pointer with the native 0xFF tag.

While this is a good idea in terms on consistency, practically it
doesn't bring any benefit. Since the 0xFF pointer tag is a match-all
tag, it doesn't matter what tag the accessed memory has. No accesses
through 0xFF-tagged pointers are considered buggy by KASAN.

This patch changes the default tag value for unallocated memory to 0xFE,
which is the tag KASAN uses for inaccessible memory. This doesn't affect
accesses through 0xFF-tagged pointer to this memory, buut this allows
KASAN to detect wild and large out-of-bounds invalid memory accesses
through otherwise-tagged pointers.

This is a prepatory patch for the next one, which changes the tag-based
KASAN modes to not poison the boot memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b91732bd05d7..1d89b8175027 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -30,7 +30,8 @@ struct kunit_kasan_expectation {
 /* Software KASAN implementations use shadow memory. */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define KASAN_SHADOW_INIT 0xFF
+/* This matches KASAN_TAG_INVALID. */
+#define KASAN_SHADOW_INIT 0xFE
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b6cd96a70f8faf58a1013ae063357d84db8d38d6.1614989145.git.andreyknvl%40google.com.
