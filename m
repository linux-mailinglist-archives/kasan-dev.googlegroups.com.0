Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5MASP6AKGQE2FVL64I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 533CD28C2FF
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:42 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id s14sf6861134otr.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535541; cv=pass;
        d=google.com; s=arc-20160816;
        b=SwJNb7jj6aTogGJ5DigRCcHEwNNU4ioLGKWp4z5Kn4OFLrQIBqWRhmQZjlzVHQq6jd
         ttgds1NKfcp6SsbOKNL+cAo6+Bte+oEmp+Wj+JLXPXy/BZ6kyQWQA3M5hTL1JtXN/a1v
         +JoFha3THWwYLU0nljUnCMYfwpMt4NRxSDGkdZwbIb2xfXHysGGHoS0o+nOEiKBMplxk
         o5hr9cms+49zFteTrnYGGpS42/dICE8YLrjghdZX+id7b+gN9BgvsXp5wlSQloZ1EaNf
         Vj2nVLNKBrmzCpmc1yNN0PJpc84ZTHBqMORVs/irki+jcwTW+T/KZIDOsQ/08JpPpqMo
         IwiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=lDLVc2WGBcciueGZOzDsX6yqa/afHZMQy9CVNVVxFNo=;
        b=aUYIHQvE0SD8AYvQbUG9fhGEZYuaRhw6Ul2Gtt5LeVlIOzHDGYQmZmiIxwlhq2ILQN
         KJu/46gpjXAOxRanmdZmpulWos+0lL4ti/S9uVXsMY+WUZGoFu7ve8u8rLhhbJFOniyN
         Sf2S84fnJFWhAk/9GZJpsAq60M8hk8iJlmdizo+tzJ4BKu7yruFkWXtiZBQyG0O1EEIc
         AKOWNgmt2YNxpYm4T+nThQjyE8pYtNKNCe4lmm1ogjne05fDhPbq08I6EnZOC6kB2IUF
         Pw6CzEEHmz/XIXB07jdZoRmGkjjGtGU62BRpUQKblDMA+mQZa9o+I79vJhJWM4Dx/cYu
         HtHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dLvBzdDs;
       spf=pass (google.com: domain of 3dmcexwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3dMCEXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lDLVc2WGBcciueGZOzDsX6yqa/afHZMQy9CVNVVxFNo=;
        b=UsuvXUQrl4+NRm1R5lZaiY2YXy00AkmXocn8saNKmJBz+funqbI+EHZ+9bWCInoZYO
         u2Cmfxy/jQrRIUV/bXAUsaDBoRk+2/BmAulgAsEM8Gz773LsUl3fmH9lMNWnl97yjRIe
         iHXxgsOWnm3uGwpL/McAvK2WGwBca+0BKGLRWpMsWTvCEscZOAwHNjirFydyRi4gsLsz
         N5Sn2EhRxW6Rt3HtkCySRwqs8mAaPp7VLn4o2w811pbNXoGyV2zCdeD1hKdj8dDwky7b
         ceJkuDfSqn4wHn/Uwha7uALrLupgjMi/muh5A7zndOn6NWV6VYKkh+JCLyzeQ5PVvUfd
         6PGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lDLVc2WGBcciueGZOzDsX6yqa/afHZMQy9CVNVVxFNo=;
        b=TMqLvnjMrJNW9+BjUcCXvvfn5SReY/y6FNLcSzoyTIBx4LNC00M9JEs0Z6V/79xd5n
         QKZbtM9hVe1B8+njisfw3vvACIMGJ4WSTTi/KvpM5R3V4QW7b6XkWGE+K7LoPqy8s+09
         DS5Lna66Ge0nK3c2pbExhh1suTCgB1hzdbShvl03Ky010YH1IO2O5wduCKqa5uVyIDOQ
         SjraS2Syz5DL8avJf73OVuiyXIjBUDCTpAnzGuIf2YjF3NWa2qffZ/F2Um0C6rSVRGsB
         KCaRQtUVxolCGYa1/BUIiX2JrzCkScYf6yywsD5o0HKA+8tiDMqGv9hJY8jioQhaeZdg
         Pi2w==
X-Gm-Message-State: AOAM531IE3082v1FgD8o+9BRNY2AXny/vj8HQURy4Ju8uswUEqXZDu8c
	QIaArOfjpW+eyzt+3VF3r1s=
X-Google-Smtp-Source: ABdhPJwH+2lNXEU7fo1zSZ5P3WhzRYdz7LLFAPBw+Vw4kTum9IwxWFgZ7kaneXnMjFwCqMv9W/ZFvA==
X-Received: by 2002:a9d:6013:: with SMTP id h19mr19507508otj.262.1602535541313;
        Mon, 12 Oct 2020 13:45:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:119a:: with SMTP id u26ls4225861otq.6.gmail; Mon,
 12 Oct 2020 13:45:41 -0700 (PDT)
X-Received: by 2002:a9d:5910:: with SMTP id t16mr21112295oth.155.1602535540991;
        Mon, 12 Oct 2020 13:45:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535540; cv=none;
        d=google.com; s=arc-20160816;
        b=QvjGfRqa77nkro0oqvF5VBmrILfNSUit/xHHoJemSHMMxBMZQ+2FRLTa1MhmKHsFFW
         5UhUXoSgOifWKOLOg8cA5h+8io/Vy578CeatWuOWZ7ens5wvPinKfF/pW+4Qk6C15EAE
         WDflKpGZDCAK0wF5gcL9hS3qQYXlgYO+cJENPtGHWbqlhvZQ/MZOtWERwVEKFDsrY4n0
         Hh3yGTQfLLKe+Qw2iP1/4HYP/p3ugRal7XgZwkDJAcvoQBUug4IEJrFfED+5o5K7kOH+
         gZH0bWqY2u9TilRHuUcyqdcjW+/q3xC2Y25VCkXTKFYyA1YG8DEWH/m+7TartQzYvV8u
         MKGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=bjQ7HGNrl6lZ+I2pFRgMH/Dm6JOdeFQivr4o3Lh72GE=;
        b=unq/awzWIu4EIawuf1pNdisaqtNJfOgqucIQt6ioieIJhM0T0iRh5PdAKP8iDN50mr
         EO2MicBdAEKza4S547b/pEZ0idG2RgAEOLHmNdBfgbYqYZX7DZSPR7wBnRVIuCgYcxf6
         odRL8GnTdhBHpPedYxR5CUk9ovNzYalNTG0bFzvEiqllSu8+FIlaGuDpNNyCiZGafZm4
         xZoBaoIGnSOTveLGD/A9ELWQH8Bb/wu0E1dKiwm2+B9ooaylX3tbN9v0uqRcHvbSRCMc
         VnyC6mU8yi3miR+yndwoPYFKCE0qak5e2QZEcfRnwCYQ1i6t+opyuMNXVEQBUqDBHnyi
         wr9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dLvBzdDs;
       spf=pass (google.com: domain of 3dmcexwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3dMCEXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id q10si1144799oov.2.2020.10.12.13.45.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dmcexwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id z12so10034203qto.4
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:40 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ee86:: with SMTP id
 u6mr27307337qvr.56.1602535540392; Mon, 12 Oct 2020 13:45:40 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:26 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <46a553603c4c16e8ec2311bbec2294ac4938a0db.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 20/40] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=dLvBzdDs;       spf=pass
 (google.com: domain of 3dmcexwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3dMCEXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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
index e1d55331b618..f73d5979575a 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46a553603c4c16e8ec2311bbec2294ac4938a0db.1602535397.git.andreyknvl%40google.com.
