Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTXORT6QKGQETVE3W4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E814D2A7152
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:47 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id u4sf14989343pgg.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532046; cv=pass;
        d=google.com; s=arc-20160816;
        b=EU5bedLyQORFOgB2Xp1Yg7/gYO9JJeS8ZcTpyBKnTyCAlYQ5zLil17T4MprKL5hebk
         PJZGYNgJ4AzPVqWPMsB+/1DZoR+O5RWfWDcEAvqeRBe/QHOTKNW/r4Wq9g2xc99NyEO5
         a9uTvRP0ayPxhHZrEhxBPswZtV6JqmBONPiXoGV9W4GMfOQAcPiOETN00h/mZpStfPtH
         b4Ivm6Bgb6H4JLgRGkXBDUuBp115+WJ3asPYtEjK5oImpSe6Vja9NkBKxwADcSbFR4lE
         9wN6jYTvTT3SgJHYqxPHOxZyVYqG8gvqU0RtAy90ty4U8fbggRLsje+78J0cfxf/1Foy
         nVMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jM965j9lctgS3TGeUwMgcvGEZ5iijagix3p9aQGKOr8=;
        b=WBUo9T8k3VtFPl87xmK62m7f/YVggoDeGolTihpUdlsrWSCCp/HjIgA6YI3j0rBxEH
         VB/7bmCEZCKNw7bBs3ODkdqjzlW58q1wZ60rq6osg7vxTDm4JUy7xu6KoKMmpV6HMKjX
         h/Z20T61BTf2gWNJMWg0RiI9GXwejZY/Br8vxejHtTlU/9ely/ELyWolUkCgKRbT9X1P
         q9gMkN39mc5X1PMSInZTlvCILzB7YXSX8SWQ/SIOxT80iuTfmNeSwcGvEr6uWKWorxmB
         xY81GiRslcOHxM/9zQFBDTxEnazqfTiiUy+SvQOfYKTJ5NCKOnEYZ4aZ+vNLvu5s3srj
         d1lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DU5fct66;
       spf=pass (google.com: domain of 3ttejxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TTejXwoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jM965j9lctgS3TGeUwMgcvGEZ5iijagix3p9aQGKOr8=;
        b=NadP8H4Ei2ioOp+IK6Qvt/zPLyQ9W+oYJz8BRwXCMh8ZoLGO/+oywdGxLEiLU7drmY
         mkPsi1g/JIlC5s2pe5CoaNEz/8lYveZPYQWXXQUzXHsTr19MtKDbVoOwiKJimQA0P4m0
         DigSYx7aot/2Ne75tiLvB+EoQ7xGzEZ5Qk8lHeZzcTkwKNjIF7njXbHHKR0HAuOARcvv
         CymYroymgHA5LT5YWDlTJ3b3qJl14va774mBTADzmZYe6qMb8rio2Q5rCGVYpuNPbwDF
         q8Ss2bCTQgRuh1Sb6FzqvSITDxLTdKqnt6zfYQOfwWEYgJZ73dCCvH5BCoPeWv3p0i4R
         /OaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jM965j9lctgS3TGeUwMgcvGEZ5iijagix3p9aQGKOr8=;
        b=cYTHZqp0NvyU2W7ooHO+xKx/zCCcxLFDvHW+zU4tY+QffKPZKK9JWLdPFiH8Wv66Mj
         DyS7wOCAocgnYBeVgP1iVjrfQ9ehpUQePNG5tNIa1I3BkTUfbnUp3F2/1WzBn/mf2zzz
         HjgpHeL+9ZCQiOlJtfXji+XSQKxFgnMqyMieQEW2gOB8x9Us/QWUptt/lLf7C5T+yLdm
         18hd3vrPsXD7yztimZP30euAtHLsCQM+r8bAG4EhvlI0bqNOCmKwDP0sjznP2LFla8Oi
         OKmVuqr8TxGi7BzyEukclbps/q8HmEhwdfa4ypC2/f5I0IVd9Aum9RaFc7y3GcPK0uFK
         PhAQ==
X-Gm-Message-State: AOAM5331IlWz63iLmyGjw4KzxIoeVCoRBQrQWeJZQPjO5x2aJcUO5ayq
	L77kp5MnmGSiu7LRofziHrE=
X-Google-Smtp-Source: ABdhPJyDAa1lDexjS7LKfMFgoHxXijH6zzHcHLaVGoPIzsoHs/zrE40uTBvMa8CgcB62UDhs9leqMQ==
X-Received: by 2002:aa7:97af:0:b029:18a:b53d:97f8 with SMTP id d15-20020aa797af0000b029018ab53d97f8mr151216pfq.17.1604532046709;
        Wed, 04 Nov 2020 15:20:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8f0c:: with SMTP id n12ls1366644pfd.8.gmail; Wed, 04 Nov
 2020 15:20:46 -0800 (PST)
X-Received: by 2002:a63:2051:: with SMTP id r17mr281894pgm.191.1604532046146;
        Wed, 04 Nov 2020 15:20:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532046; cv=none;
        d=google.com; s=arc-20160816;
        b=YOF3CmlOn0MAZWgfFXTd+zeey3higMWluyqtQ/5aWn78J8xMyZj5C9lHlL5Rt2HIoL
         ZAQ/gLNvthRCdbdyRHZFDR9ZRtEfGZb4Q6g5zNZhrHbe1FYMZ6zkcYbaUwhLKhCIfCnT
         JXXRzI5s8kdRLRAW8tAjx1RPcWKhJ6jlF3f38mci3uUXsxM+TcWX8juoxH2l5/FCWPCx
         nwy6+BDa6BcHn0KB7wo/0etqRjwxO7iy3alaFO7AYyPOxgqMhWkfGluzmS06o9kovaZD
         Amnv582jN0+ExJiGWdU3ogFwVsNJspcPU4JRqj53/M24Gwidf/6lSWPI+a+jY7AhvRHG
         XnDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hKqfeGmJU17yqcBnh9EcbhWo2RSZMPrdWdsmZezW6Y0=;
        b=zXzxdFx/OFt563e30WIqE+He6RMk9o/27SbFmbP+S2J5cxbvhkC3zncDTM6Byjh59L
         iTbj0ay9xcL5lksychTiShjjhm+LvYuQmZksCaDIqHW237qg7mk673olA5zKn5hVg9co
         2PT/ntiSp7i1XA7d0Jrom1UVPyF3JDVgNPKBd9t3H8QG1sVPqTBo7vKWbeypdwx1+0bX
         FhUCPNtsBjRjT70zQT2ciN+c0+0csjbbFUnsoz0schSJ3Q4OSp3Nf3lTizChy/GHVPaM
         XIEx0J1WYJwQV3vioWcnOcc0TSavSfcfXYXE2PtNukn75iGWmciFtRWRQLByr+KyuopH
         rPfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DU5fct66;
       spf=pass (google.com: domain of 3ttejxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TTejXwoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id j63si220414pfd.1.2020.11.04.15.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ttejxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i39so78254qtb.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f3c2:: with SMTP id
 f2mr271968qvm.24.1604532045303; Wed, 04 Nov 2020 15:20:45 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:56 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <c21462b3ea128943b3e7af2788d562aa05a247ae.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 41/43] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=DU5fct66;       spf=pass
 (google.com: domain of 3ttejxwokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3TTejXwoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 43702780f28c..0996b5d75046 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c21462b3ea128943b3e7af2788d562aa05a247ae.1604531793.git.andreyknvl%40google.com.
