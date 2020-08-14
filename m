Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPUT3P4QKGQEAFUIWPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id BE2DF244DD8
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:31 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id g2sf4666625ooe.23
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426110; cv=pass;
        d=google.com; s=arc-20160816;
        b=jUTNenLe3E9q6ijoFzOtxvyQDXA61qe/ekwyasIpqntHk4+S64pN7jrjcaTa29NMHg
         NGG9FpmhCtLLgmAUG+0o1AVw5Fmqh5+g4OcFHkm6Bx8MzDfNjJHhdlTiCh76ZI94gWpB
         ejSl2BYkuiroWshAZofEGPN1fPkAJPQm9KWJJFeE9x48ziySv4j+HrCAthai4RBgXKch
         TYtSa5MlMgClFHJkUX3d/vLWAw2i6NhWlFt1JFSXQs7fDH6A/P0+1TCclbNWKeFo1fIV
         wo3WPkuiAOM3QKl8M4pUQVD0uuPa5SkijuT0wT00Ofvu8yyUM1Dwhy2VU09BVPPk34fs
         V2cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=pSGRFshQ0NCqJ/I7uDaUp3V5FFIgrQcBkPJNHvT7eE4=;
        b=nCpcFzeoqhsTBdSSb8SvhFQJbYmkhaiGmPODhWAdF/2uH5gGtmm1CMSIivycO0PeEg
         Y5Qg1Ssl4FnHjeJXvM1nw2swdv3t22WKhjlsHWvv5pcjX3s80Ajtxg9Ay2JjvfokZFEw
         IqIQL9gttdDeOnhJZxz/CpUGJb5DPUK53hxurvZ6I+FgUrBvYmq8xq51irdvmAtdDvWo
         7z2NEcuWj+fIfjCy3O4zoexJ9uXn9DmwaoanNm5f9bwAuZiqJQ4EW7iRKO1qe82FMrCc
         CIbXORVbSrkuA6Vaf4ga0rpBaAv+2B9sLLQuYya133I7NFDUa68d2/okrOxikTWhXnsA
         bONA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LuGw15Zk;
       spf=pass (google.com: domain of 3vck2xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3vck2XwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pSGRFshQ0NCqJ/I7uDaUp3V5FFIgrQcBkPJNHvT7eE4=;
        b=aMGf7n9qu54IDTAfv7Tn9cMo5wZAu4revT7M5fXZDKmIJLRw2GmShoLTI7foNHv/AI
         D0HuhitWMJBLF6CEVpY2aDik7l5BFOMXDWZqCQjAiio2t3prYm72HMp19H8PUeBmPuad
         5nyI38v6IOoKkOQ2+GOk/Km6Xwbrtr+dT/C6NSVVxg3kUgzRehh1AqEf0zvfNmlJpZ4X
         CgpWIMpXgleVmb2FraZPQSl0T/bUKoo+xPDbu/VUt/alYMg0c7EZmXUQG7ALRaoLcIYy
         TECgEnBsN7X6CphgKZUpLWsTwubXQ+cTkQtvRN1UbexfXCD3YPNKH6GoUNHraoD/TLHS
         W4/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pSGRFshQ0NCqJ/I7uDaUp3V5FFIgrQcBkPJNHvT7eE4=;
        b=pqKmc/C0sXnKJ8mY9aHOiXkg9tA0l9kZv1sygMm/wSyGYPAX0mEBTC9/7ZsGra73fy
         +iIPBwDQkfdR7Yavsq13JUm+kF0URtDCDax2ns3KVO6R19U6izkHl+DOi6uXkkgSuUtg
         qNkaiXOaaEx5Q7cXZ+iq/6sgDmkknPhZr5Tt78PvwJoAEJXp3CwExrgT6Vtmwxj8Z+kB
         0EnXIqBK/qqAjCU9uCh2p+C9HCjtZjW6rMLiK22R50PYm5OyILmQ03R+OJc0Q19ZzRnS
         96foVRHUBdqibQgeNc1yj0yZW/tS86fQLUEwemcws/noU9jh1mKn6xO/rYbH/kFOF9XI
         LZgw==
X-Gm-Message-State: AOAM533k0Q5/HjXi2GUYQNpTkDmDxvgygdo1PNFHy6gkPAsGK+JO+y9i
	kpncO2iKXSpLB/XUxhrbEPs=
X-Google-Smtp-Source: ABdhPJxhkcV1U2Bo9pb5gpEDDNBaJnA7Yf90zD7CEjufprpWQpNCcSODc9oIBO5CKwTWwQC39S39Wg==
X-Received: by 2002:a9d:4c12:: with SMTP id l18mr2804100otf.260.1597426110731;
        Fri, 14 Aug 2020 10:28:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fc57:: with SMTP id a84ls2028618oii.2.gmail; Fri, 14 Aug
 2020 10:28:30 -0700 (PDT)
X-Received: by 2002:aca:504c:: with SMTP id e73mr2257729oib.63.1597426110484;
        Fri, 14 Aug 2020 10:28:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426110; cv=none;
        d=google.com; s=arc-20160816;
        b=KuANNr1oFTOudVAXb3SiTeLUKmWXLS8AuYEh3aLDoTzDGNmEGraDWoBUtjnuWH4HEf
         d2WEH49A7qgH44JBNq6vAi0nhE6zHRmZE3riTOG8Zos3KuWvgF0wFJ/o1kRp7+ngU/8I
         VKjzA1oLbk7xVe8Ru968MTDvZP2dNE3Lj0Pyo/1Cb4+ltR5B55syZuxn+oYXZGYmDZP6
         0gN0Gc+SlaRKz9XtX+DNyDO3uaczAqvLa2vYHm/ia0FazAsQhCod9IkqPYowPSNx6iBI
         3ch3550M5vXUt56HkA/TGcPwT7Qc9LXYFDtAB3zAeYHgR8okqkvbHg6lKVhxzj5ZExA3
         NlWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Aq2upZC9S5Ys9XP2AH7I4ISIryYXBDc2x7o0GoeV4Tk=;
        b=DyCEiKKyTXZEPy1P5FRNf6kMmJ/Ns/Jd4IXPKFX3bVSNlMaPr2gCHXTg9mlE7SReLe
         UpwHL/Q0AnWEkO49nXrEMJwv8vBMH1rCflGrHZd9Z4KTabaHCuUbTMbDT/xcyDod5o5K
         FLL7Qv0vxSoAQRaF2mS8ynqQ2Cg3omeQHHtKM5FO2bAK6wZb8b36dEbdT6nR5FMwpwxf
         W/qTIWWNWckcN4u5/7/ePqR/iGApvhJnxSGP5Hs2mM0GJahstqwz5kCTe076HajF0lNI
         g9vwIi9+PT0RRhOOA4BE3mw5eeA17TUAMWm1jbuuhlmIsA+vyyZYfBRz6udwDqqwLr+s
         aopQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LuGw15Zk;
       spf=pass (google.com: domain of 3vck2xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3vck2XwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u18si221430oif.1.2020.08.14.10.28.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vck2xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id r12so6489967qvx.20
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:30 -0700 (PDT)
X-Received: by 2002:a0c:e883:: with SMTP id b3mr3537357qvo.133.1597426109995;
 Fri, 14 Aug 2020 10:28:29 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:10 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <07455abaab13824579c1b8e50cc038cf8a0f3369.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 28/35] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=LuGw15Zk;       spf=pass
 (google.com: domain of 3vck2xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3vck2XwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1d3c7c6ce771..4d8e229f8e01 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte.h>
+#define KASAN_GRANULE_SIZE	(MTE_GRANULE_SIZE)
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/07455abaab13824579c1b8e50cc038cf8a0f3369.1597425745.git.andreyknvl%40google.com.
