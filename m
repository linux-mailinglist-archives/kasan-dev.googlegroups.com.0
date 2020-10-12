Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDMBSP6AKGQEYVRE42A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5019C28C310
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:06 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id l17sf9721627wrw.11
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535566; cv=pass;
        d=google.com; s=arc-20160816;
        b=uG/Z3UJ6TlEV8UUe+K7r+kejkIBtMvzyxbfta4XiFN69FtHhTcXA3abZa1iOFf++Re
         SiX93NcccyobLykjfiG978Da37brvN2PDgOI6hWfulBUQ0yuQZNpzj02BA/E89xM/vvk
         2fxFb4JVCM3U8FFKpAYfUZpd9dCmiVNXyb3SqopQ7rS2T0B6MNcXMk/hygrZAfh6M1Jz
         AkUScXaUjtVYcODOnG5lS3PNICljJ60GExG2ot3CIKfDp8527Ek8ZTLsJM7k8DnapzQb
         R5M+OnU5H9TQaKx/HvhsH4r3EFemy9ss5XGg9Ya/gGRqWa2uyLj4FW/Lz3n7gkm0Affa
         +F+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nrk8pflz7p8p7cZem3iki/hyL8DMAtVEvSKOIfRuszs=;
        b=CVqPRY/Iq4kMHvfUX3PAB+8siwMi2BV7Nah1B4jjj/c2TjElqWDR2xJd2C+ALqW/A6
         /mtGBCagis2tK5VZerDbZjJVjps1DDEc2lEOMfLSZUXi9Yc4/Dafvp6llI0UVEM95Qs5
         LmmI/rC4XAT5WrEvLYB/r2jeXf/VPbNzPsg7yxXyFMgNJV7RSyC77u3T3lTEB68iKetf
         QaS5tkgng65s6apUYmNU8cmds+OwJyOK2soGpZa40IL9Eu5UkDNAtL2LLgwml0H5BobB
         s53EVZ+2Y2v5omzldth0mPR8LI+j03ZbGLL72V/2eaqyMLpLvvAiZRKNknz4ZUVKSElw
         /S4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bW93PBWy;
       spf=pass (google.com: domain of 3jccexwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jcCEXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nrk8pflz7p8p7cZem3iki/hyL8DMAtVEvSKOIfRuszs=;
        b=Xf/89HU6Sp3fR2bbTloZTpxCnjQoFyauwX0WO7Utah23OZrnMLIka1O5N/3HhCVVEw
         IyT4q9mAYJo1v4grD/M+Sp+NHmG/6B6msw3AIjpFD9ZNzN0OJv4cx6b5i1uTsfpcdXIR
         ibjH/igHafCqrMixJXiP730jaaYLBg5r5ErdggGOn4Jum3h0iCz+L+jOrSHfwfjTR+dI
         lX+9kAYsVLwKfO9LTarZqtIfl+h2DNlg2K+d81usWzku4juzH5gMIzN/NC//KBEfTdPV
         M81L6+X8RI7qu6R3GBNy5V/1rVABD0NpzI+pgmoMoPPXW6cucrF58SHucpkH4OkRzhhS
         8VeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nrk8pflz7p8p7cZem3iki/hyL8DMAtVEvSKOIfRuszs=;
        b=GiQ6HHHHJYKF8FjexD/DXfXnrYrtpY60dWPu42aUI5/ZF04dbbAELVlUPq8z7AINTK
         5eovGn4nM2ZG9c4PavTV2ky/fukKRRHThZZ5/mXQKt2gbmisNxXaohgdDQw6T3xaKi0a
         /efHXIvxT1GZcZr6a+6DxIvtyLAIaA1pXhzD9wN6MsPWN1EkMa/0q/0CSyCiFO5Ne06J
         U41oqlRaBJteZ6WakYBHuYrBNr1F1RNRcMndX9wfgQZcZbjmKADdnJhns4Lu/dqtTvjI
         g4wQcIkq39IHX2L81SS908jXEv2RnBgh3vPYahjWHIKybAhJyKP94HVFU1DD+ZuDF+vR
         Namw==
X-Gm-Message-State: AOAM5301mIJiYek/wB1FuXniPWVv+Gx5ArAq22A0oShVS3A/y0Z3Kh/8
	wamBcpuum6vCYjOkIQQKuH8=
X-Google-Smtp-Source: ABdhPJwA4/G4OlM4skvG2mExZ7qdV1i2TgeE3BrQMkF4xrtmY//byJELJzYLie7QUAkqQsBOg1CctQ==
X-Received: by 2002:a1c:63c3:: with SMTP id x186mr12965683wmb.66.1602535566086;
        Mon, 12 Oct 2020 13:46:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2506:: with SMTP id l6ls5488890wml.3.canary-gmail; Mon,
 12 Oct 2020 13:46:05 -0700 (PDT)
X-Received: by 2002:a7b:cc8b:: with SMTP id p11mr12753471wma.100.1602535565382;
        Mon, 12 Oct 2020 13:46:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535565; cv=none;
        d=google.com; s=arc-20160816;
        b=i8l7YW6TML8+sY0ikVgb042mZDpXC/wqdETWvbcx4k3nlWH1To5YZCrTUnuUuFbJcz
         Mam1PpwTvesUePVfh/CnMkGXxexuofbvx4Cosa3W04DoliKDlwqevS+0xmqP0wiwze1P
         JtNviDQxQeJhsz7bBEHKmYLqJJPw9xYaiN76N3ZBfPBfdZ9/lo3eWmDg4Mw1IuQENdIG
         mDCoEQMIUMFfSD3M+WbDF/jh0nS9AE5gL77GHPxRCHvk81ufiCkRPGqt58IlZ1aPneet
         CN7NlQ0Zgjtv+zU6zIBw5JhU+YAV1iZ3Kw4TZRFZGihA81gXe1nGWL5qTxfiam0r5QdD
         zMkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=traBQYsXDq59+qKm3sjLr2vdah15OLSAttojnE/4vlo=;
        b=pjeOepZle3s9CwuwKwCB5Vp1lxacvVTDDNw8QkgCA17HjQRoax858cHmY3Hnw2rQqb
         y0L6o6k6kh1zzrGUWIcliEkyoqw2xVc7Y1+GrUYaMw9+EXjRM1DIjE1p/y5AbxvbWB17
         YbwrIf3xOqTkLCu5EkUfD0jodas/FLJ9e7YGJ1fCJQiL5pDP7UQxKgfs72bLk+wEX27s
         kvWn3FaDSJMEhoHmCix2QjjCXoZqqfsHPAsjAovEQFIKB7yOZMHOojzo6v2hvMHVQ8B3
         d6LVjWnA6RlkXM+25Nm9nEXVG5xSk1h/ejTgiEpJaFWWSBnoB8bhT4R/4FCIvFva0EaY
         TrwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bW93PBWy;
       spf=pass (google.com: domain of 3jccexwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jcCEXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 72si478096wme.1.2020.10.12.13.46.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jccexwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u15so9844773wrn.4
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:05 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a3c2:: with SMTP id
 m185mr10326465wme.161.1602535565034; Mon, 12 Oct 2020 13:46:05 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:36 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <38ca7c139b94d2de5152d30496aedb0a193507a8.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 30/40] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bW93PBWy;       spf=pass
 (google.com: domain of 3jccexwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jcCEXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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
index f27297ac70bf..192544fcd1a5 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -131,7 +131,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38ca7c139b94d2de5152d30496aedb0a193507a8.1602535397.git.andreyknvl%40google.com.
