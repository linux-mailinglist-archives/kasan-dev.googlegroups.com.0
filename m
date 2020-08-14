Return-Path: <kasan-dev+bncBDX4HWEMTEBRBE4T3P4QKGQER6MSGFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B914244DBE
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:49 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id h36sf2681740pgl.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426067; cv=pass;
        d=google.com; s=arc-20160816;
        b=yAYYbyRmOG7HwbTEkBZsBGkNIspo64iM/abDotKBOwQCOytxJP5AuoWFHUIcWusqbY
         UCfTsk7TqqfHCz7NfpjwFAAgFpCnLpEKambNyDjE8fPEJ/Z3GBSQsX6HChk+vLns9IqP
         WhaOnoZ4TTktVhDZBiV9qslp3FQZx+ZnpumopeqwbO9tlSLmgPWTw9BnHTlLzMB3H9zx
         I6MuY30K9SRub/OEjFJjxHs43+3aqTW9b2HMCNYsfNNAllGPdLKMT9GqywW1wBgBKrbf
         uyZ3TSHuPRSmx1jmAmw44fQPK2VwOXMtdXVPuPAvVqHsKZxhTRALDj0gZ2mmff1A2HHP
         9oFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=r2Keiivw/dVROJVsii0LpVehZufeG/dzaZf0rnRQCqk=;
        b=w+SBMe0eoutZ31CEHPqmW0pVActK7B1EMqDVpXGK2NfMlUjKbxaV7CVWm2Nzp0Iq66
         L74G94OWGJ+oGLzffj0TVPFBg0UDZY9MMzfxpxd57053y0HhCish1+whi3DZ9Ib4GUmo
         M+TZXIyLziLvjga16OU2yZieS8DiNNvZmxbp8/qJbQF+VXm9Yu6Vu45grYIxaFMYA9cO
         GORjNFvYcXlJbMi864/eU2cmvye6R8+T4xWIDToPuBFzy3+z+kcgmKuU3jvv2+IHFgNX
         rR3S7YOcBZPM1YEiknHvofO1FUPufWTu3OMgODj+wE3fIOKfN5vwG1sWzF8b1y3MaifX
         OEmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZgHPshRZ;
       spf=pass (google.com: domain of 3ksk2xwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ksk2XwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r2Keiivw/dVROJVsii0LpVehZufeG/dzaZf0rnRQCqk=;
        b=O2zBmKZP7jlGEnUisSzBTkSCkmYxQhRWzA5Jc6P/HmVrS657EVBZEjEhtIoqSEjdQM
         SsBoOAN6BU1jtMdsHW6F0svs5T8FglTgvvYld7hHEINNoxShgCQz5tc5s+rHbQZEUXAb
         VTh9IWnsc5VPvF7us5Kqrf4oNk2sMnQ6GcwoCxib+Pi8crtocIFcGD13MVuZRQ3EsGnu
         XzQgKkELThYQaS4lnlroHZ5aODtKDUR+Ki6j3nSwNDEwYv3qMlc3Qy4/mEIyfmKOwQY5
         edsFbSF6Vgpvj22nb42JKJUx3HMheNzrtMphA2NJYJ7cWZN0TS6M4agSQeJPNiY/CeMY
         ougw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r2Keiivw/dVROJVsii0LpVehZufeG/dzaZf0rnRQCqk=;
        b=lTmSHsvKz4lq48sx68FqD9DF2KB7VCR7UrA6QhaQSwFIQTCJ5VNDfdqBrTAd5SsQQC
         BZP4Z8rTBLi9izwzzzftf8+McE2femHahz4+DT2eKZaQad38YiK8M1Mwg8emDVFCB24W
         vVERR/vwYMQS1MMeU3V2Ht0QP2CM8cNw5ISUPYA0dlGWz6SLtPFjdlTOHbFMdx0mC1yi
         dQBUako3b0HOzvmnfzJzjIEG98VmDZnqpcB8LF+DAU4Amwc+d87Yr9p2k+YijpQzOhus
         KMnOijs4/HkJmMXuHIjQdPMJndPtGgrcadn4a1DNUUeEMC3kS+AMrql/uGvoc528I9nq
         ZrPw==
X-Gm-Message-State: AOAM533SUE2Ba3DeUAqNeO3cVPjy0mrLUdjZO/Acy6eIc3WXw52XXAKr
	linp72ru/e+fpKiK9o4vfzI=
X-Google-Smtp-Source: ABdhPJzKhmOz8+asEbiC1RHDJIK3oT6tr1I1+dQYCnDuGOcD6bcwztzJJhpkCMj95nHk27r1v/LJHg==
X-Received: by 2002:a17:902:b701:: with SMTP id d1mr2709483pls.92.1597426067548;
        Fri, 14 Aug 2020 10:27:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a84:: with SMTP id v126ls3348855pfc.11.gmail; Fri, 14
 Aug 2020 10:27:47 -0700 (PDT)
X-Received: by 2002:a62:1714:: with SMTP id 20mr2610189pfx.133.1597426067152;
        Fri, 14 Aug 2020 10:27:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426067; cv=none;
        d=google.com; s=arc-20160816;
        b=mgN0csm+jkxa4/2Za5Iy7SDsTXr3A9MzW42XBd5pBqIXp/Gn+CMiyN2fWa20IIHxv8
         hv9N5ln6fcUsLU2b0l3Jn0G6+kStkVFf/fbUd6NK4yVH4SamxY1TlxUUnMEaFIHP21G3
         B+bRrr71IzwPoQotR2gfces6QxcsZQbpJ12G4/8gIFcTRXcmMBqQT3dccOeCub3A6QiK
         resM/SveACCZIhHE/xbr/jcNl7SKQHpP/wb5kA0evbkMjmNb4uyImU8HcI4mTUkeMW/C
         DeDPqTwHz0tcc612aUflOtQaIkUFC5uUZP16+cMJelPsD/aKbC+qHhQCildgmKV9F6Jt
         ILYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=e2KGLRW+d0jj4Tv+MmRAX362NCHhZR9ltOsxskRbVvg=;
        b=0YuVUQtee0BmnGl+Yh6Us4+2nmnfIZPqBy9yeZSei8DQTQ/OYnhHZ4mevZ5lZu3QjC
         DPC/tNGdyuqqO+ZuaFpeEnae29w5OFrVM/8CeZ7lh+2DKETm5kCe+QS36GHubzNyz1BY
         KBOzXpW1GttcdR0YoEoa3NdJ1H7+9uql7rD9MtflIt9Qx6G6Db5Dwy0v6QrOykGvL7us
         wg/PAGvdqzmTVTgzV8abyLedInIHXZg3m3DiKcVwwzGTqYQBE9i4z7CjOJSB3/q4FBNh
         CBuBTKh5AB2Rs1fzlD9Nv43ckCH05lNP9UUP7r1cpI5bRx4zJcjhbea2N6yKNu4jyRIM
         q+Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZgHPshRZ;
       spf=pass (google.com: domain of 3ksk2xwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ksk2XwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id kr1si731525pjb.2.2020.08.14.10.27.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ksk2xwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id n5so6514284qvx.2
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:47 -0700 (PDT)
X-Received: by 2002:a05:6214:1086:: with SMTP id o6mr3450750qvr.41.1597426066233;
 Fri, 14 Aug 2020 10:27:46 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:51 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <0197bbc0050e20ffdbf43eb8300af245c5c169db.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 09/35] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=ZgHPshRZ;       spf=pass
 (google.com: domain of 3ksk2xwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ksk2XwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0197bbc0050e20ffdbf43eb8300af245c5c169db.1597425745.git.andreyknvl%40google.com.
