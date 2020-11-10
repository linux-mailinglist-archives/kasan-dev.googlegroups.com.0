Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNNAVT6QKGQELJQUP3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E06872AE2CB
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:05 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id 2sf31469ejv.4
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046325; cv=pass;
        d=google.com; s=arc-20160816;
        b=EIBo+hvz2jf+EwfM+RKfBfMr0bYs5vZnMBerOeiMZGg6gNPyXXt3KAMyiwrPdL99nj
         RfcoBUPNEFXV3ulTF4BJDq52xQo1zvhRxAnGeyGNaXijhgOM5ieJOpeyLxFzCzGB+Hk0
         6ie8P4Zd5G/mddZqr1ySp8VjQ3fggG1mPEYfzAbXVEvh+cv6abVdshlNJ51sy84ulw83
         MfEeHbGf1rV1q5pq8Yiyhl5fq2h1w8iAdzRM0JMSSyUCpPWz0urR4IsMIZ1Ta6bcX6x5
         DxkKBKzSDkvf51BayDQnx+JkEQkH5AzAiXu3P+lCWmOxuppwl5tL38L0etjq73Qdbqb3
         n9LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MrxPDt9SU2pkTTbkVvyFuocwfJeNUSbr2PNf6iDRHYQ=;
        b=lTllxsDL5rtfXgz3cHWeVIhjIJL2ltmANOU4IJszm3gl7XKrY7bakEEt6TOFF0lIHO
         QUcBTFVpKnR2R5QLAdUs5E9exDj9kJ155GQTrIoEkPI686Ph22M9iaj0DWHr5DnVawC0
         nMLJ0NBPXFY5OdUi3FuHm4XPaeimPxBQ8LWiE658MsLX1nug/FhmZcs6IGkcjQhuYr6o
         o1368fwLFEYrm5tntr+Bd/eZovNjHsZ5EqCEYQGpUuBpAPtuP9R3WQlGYd9uNVDXbgdf
         lW8mTquN+k04Gx+79GxzDigUF222P3aT8fEFzBzAibuVXG4+pObCE1sYkTuHGf71c5Wh
         lFQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N+EE4tAa;
       spf=pass (google.com: domain of 3nbcrxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3NBCrXwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MrxPDt9SU2pkTTbkVvyFuocwfJeNUSbr2PNf6iDRHYQ=;
        b=oNVJot+Zt1mViYSB8fIudZYT78svbnoG2rL/0aGhLZTOJAQsKBtlaeDE8CSCuNz8C8
         v2qrK7V1vOnd8SVVySHbMeqaqr++laCgCAD9IDpa8gpW0P68W6raUm54CJlRj8qnNdgp
         oLKbTvRpfd+OU8/fwRNpTLpLWD1gQ5S5xNtGKG5u+ksiywjEfyMOzzbRQTQocuaqC8Hc
         7+GkHdL4e/xjXubVIqZayydf7atEKJGQMP9JLWVq7eAJioni9Of1Hlp1s+3c0WHWxpEL
         h7ovJdSZMVle2CzipDOsBtC91YkJnePK0g8amKY5ubwqaBotEXd3E15F3QJUQB8ayvwe
         RJfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MrxPDt9SU2pkTTbkVvyFuocwfJeNUSbr2PNf6iDRHYQ=;
        b=UF7skCmthX0SWfHrRDUxmFdqmx8z0PkvIP6aMywcKGsxBPxFye73K7x9gHFyOaDftq
         3D9ixctDrcZJI6IwATnVROsxA5/PcwS2k/AGALtUtGs+jlsmrJIkQnfzmPUwH1A0GADh
         rHKgJZIcg3AirvsuL2PjJqJs6U4UDJ5U54lflQZEjTD/utVcs4kMHcvJ1sUDKimMRl7l
         Yb+cb5pow4Foq1/lE0UlBkhPGd5xTfgGNyrzsebEBahUW892Xq1ZAxAC8bVybX4xL1v7
         lVDzj87EEP2Ozg5H2sh8I9dLYqzspgBjCSI5aYFGgfFSAqNhz3EACJbRM/oaQAvw2p1o
         Jt5A==
X-Gm-Message-State: AOAM5318dYnNPSj1ckoMB2PNriv4ZcfMaNuXjsb6CjbFcVa+n5uX11BT
	38hrlxEtzxAmdFy2KDnjiP0=
X-Google-Smtp-Source: ABdhPJzajtvpZbjxzH5NVGHCtHTD226aqk3qRcGJB91wB89F+SwCeQVd4txbr+Pdge668tcQlKR66w==
X-Received: by 2002:a17:906:1a14:: with SMTP id i20mr23277267ejf.422.1605046325599;
        Tue, 10 Nov 2020 14:12:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4c3:: with SMTP id t3ls14287545edr.0.gmail; Tue, 10 Nov
 2020 14:12:04 -0800 (PST)
X-Received: by 2002:a05:6402:1042:: with SMTP id e2mr23854140edu.320.1605046324773;
        Tue, 10 Nov 2020 14:12:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046324; cv=none;
        d=google.com; s=arc-20160816;
        b=h2pLfaWhrJPHzcVn97VzjFa+bLpltPPdYDcs2zh1rZwmU2nesyt+BNuFm1iUi11mAj
         Mk+PmEJO+SOTvHIrMnSf3yKitl1dwdWXq9ZECp78VBU3NAbdmDE8FQgTljI+NNQ6RL0+
         aOD7W52kCBwq9O9jF53GpjnRbMRqg/k0zegat8iB/PEwbaWuEBEI0wT0AoVX7XdlDbxn
         2wc/aiuhq7img2R+a75NQPuarHDVxliuD811DibIYQCJu5DidvUnv6ikjw6ZFHWlZD+F
         9B2LMPHkh0/qkIsVaAykyQ9/dXpe4g2c8J/pfZIMLowOwhF/63hqeIkikXfOLxQFbZ5Z
         payQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Pg6PJaVDUkAITFjkMU6ng0d8HxlghasMrqy2nxiQARg=;
        b=WctGvRjgRhbuBRPNp+ZjAtIRMhH35OxtKlHuZE6J/igkGINL7M7iH4/fKBUWkpRwyJ
         B0DuKdW8yU0ICWksvACoxnwl5X/8FbEDmazFX3HGwTAv5wvX9gjF9JoBgy49PR972lgh
         MMsOcOZgDcgI/nlkr1tHD/FAhj4FiKbau1UIc46sV5jAgiaTSyJMRKidhLw1RNszSnho
         j3+cRaTDkyVUSLYtePcdi6Wpr9Bn5DGJO5Fjjqx/ExzuQKwPz8l5EZZ9LCSlHE96OBc9
         PWddETfz0cYCEVRFG5rmoE9ZC5GuVrNYxC1cEJp/ZtTiOqK/6ijfsxfgPiKQMhNskz2I
         VQqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N+EE4tAa;
       spf=pass (google.com: domain of 3nbcrxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3NBCrXwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id a11si2792edq.1.2020.11.10.14.12.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nbcrxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id t4so4791671edv.7
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:1a33:: with SMTP id
 be19mr1661521edb.47.1605046324324; Tue, 10 Nov 2020 14:12:04 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:21 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <67c17dafa28036b628234c8f1d88368af374449c.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 24/44] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
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
 header.i=@google.com header.s=20161025 header.b=N+EE4tAa;       spf=pass
 (google.com: domain of 3nbcrxwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3NBCrXwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 1515f6f153a0..25ead11074bf 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -134,7 +134,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67c17dafa28036b628234c8f1d88368af374449c.1605046192.git.andreyknvl%40google.com.
