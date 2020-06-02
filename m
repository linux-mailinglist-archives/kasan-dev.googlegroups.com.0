Return-Path: <kasan-dev+bncBCV5TUXXRUIBBN433L3AKGQEM73ZDFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 69A1F1EC100
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:34:48 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id d64sf1639697vkh.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:34:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591119287; cv=pass;
        d=google.com; s=arc-20160816;
        b=DVAw3IKRq/meBZLuJHESUnLMTYc//m6Vb8fPLrd9lYeNNMsZahIz43OeTvU8Q3Y0Ms
         PHCiHe1fR9Ib90s3wdqXSQJySnSE4R52bb1giSAcurCOE+BWHfxrJDQV0zqFJJCnM7fG
         TLJH4UIMTXN5AuUv0MYFtlv3D1HONscuFrgiDi3x2kkTJH1Jhg1E97ea6ToeetBeAQC0
         8KmEJ2XwXXlHk9enbUoBlqzA0rndHSULgXVI1QfoSCIoTTsdP/KOwLJXlT22aWKHpQJJ
         UWr7LTO6D7c7sIlr4x7dU+o7R42LZz/Utc/7MagNbI3+pUmBU+sGzLfl0+UzYXz5NksD
         HOxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=zkU6QXgfRrDrVbVkimS+IDWcS7KsJs4PJb8MT5crSoI=;
        b=AB15vae3VvoremD0MzUB7rqrFtbAA3q2c2c406KtlxUjJD4Ex+NbqYitx+nm3/84Da
         2XIPPpzudOtae95aRLrI6EVoyJG2wMjFYn2EBxhN/T9FdL2044vfS3Atp0LOwGTKiZn+
         vWyQ4rLylFwFwK1c8oYv0OWs1cwmm3xg/0dg0wa4tIuhhm2u8zt5MJMlf+f6VQ5BSzCP
         bFvpf6Th0RFVUWwVyEYKQgNpwQ2+M8Egwd+5Mo4zHXYt4H2BvNNN5zvTa9lde2fbYekA
         kReNXrYkRqoeJXb5Ba6rjZoJ5AEAvWpswZdp+DSxAqkWV9IaOLSMBzBqo44++0wNRvRd
         y5YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=bFaio31l;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkU6QXgfRrDrVbVkimS+IDWcS7KsJs4PJb8MT5crSoI=;
        b=dHhXj0qLPMR8a/XtXPiuIxnu9Zjy7JJ3ZyPlYDAWwIyGeJwMm5yjNvl9ym8pjK2UgU
         LlQtKUsmPbTTWosZix6JnPd9GocxS/Ye2HMZxE9OcxuNpg9JKZVqp0225DpUR90lTv6I
         eLrbTEot3pE8BY4iuNC4PntQYlvQSKTmIcCX7MTzlejfh7Yab8UW+1K6pzIwtL77XLF1
         rfkPaXXR95Zmjz6t4MI5mSrGDrjJkFvAEm6oty4eD1YTe9x5z0SYjTOSuqH38+qzwI5M
         6aAE2mIYv54frTv1sWdOGzq3UQex2Uyk7mH/ldhvUC1ckTU+hiBlTWuOkkIlkwOAKmRr
         ME6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkU6QXgfRrDrVbVkimS+IDWcS7KsJs4PJb8MT5crSoI=;
        b=R2JSAdku1Wd20hvuhM3YhURJTzQJpKWUuDOimXeww2UW/P3UZ+I8r8Y4oEhxm13W6P
         nq2UpC+LlF4C75A5oqM7fy2RI4Kp3oF2N9yIQnuefgf7cm/5HKfAxWNXcTv6BIPVOxz2
         8y+66RNKkxIvDCP/Tl9Cu8+b0QIy5LebwCTMm/RVX4HWWCnIVZYup1a1HN187insz4VY
         QhRzr/e9hSpNaOHF0Hlw/OiFlw4m55f8MqRyny/ja6FlDFhaumIemJw0PxSvfeffQwV2
         bfVk9oxAwUFyeAD8KJh33zvBH709YICujC7AnXdtubVhuS3FEdS7xX5GuUyx0XkIP0Zf
         Zzgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ir6nax5hnqMCMLuvG62sCdAkNRXQs477VTj2Hx+P6Lf3igG7/
	WWqCFmlUPRGd0BNPLEUCXbI=
X-Google-Smtp-Source: ABdhPJxpsBiz6PpRmQvOcvibbjG5WO6W+QUvYYx2lBVJQnrcQxkXs/+umTcW0J3KEbxtWhLDwSmKyQ==
X-Received: by 2002:a1f:cd83:: with SMTP id d125mr19120057vkg.35.1591119287383;
        Tue, 02 Jun 2020 10:34:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c305:: with SMTP id r5ls1066788vsj.9.gmail; Tue, 02 Jun
 2020 10:34:47 -0700 (PDT)
X-Received: by 2002:a67:808d:: with SMTP id b135mr18426353vsd.68.1591119286937;
        Tue, 02 Jun 2020 10:34:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591119286; cv=none;
        d=google.com; s=arc-20160816;
        b=TiPxBWqhZYYbsJRCWwjn43kBuVvank1AhYthzF3PrEXGoGham6b0Dxf1lUMJxWUcps
         IXP+sJr+B74DSrNyvX1nCzhXLv8Z/mHLO1x/bKeFzC6eMyHeC4iN/OUqJ6rQTGzLoXc/
         zZv/ed/iVYWOwEhvdZDFCbIqd3wJFCkpYCOxOVdAvZJRhejpp7tdezoX2PfUoTR0Bn7r
         gyrg7PcsILyUyI013n0IL1Tza7rhLG78cV8cFnwOEbD/SsAfs/WTbzJM+KNR26IpM+Qv
         hKFfUKhrfjHWL6nq++9ZVnYkM10uAOMMguRFcn44bpEN/lMHDQVJ7q6pGV6NhARxw414
         lUFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=wZRor1BzB1/H6lezWifVNSHYwmu48K5Pc1GZOtnXb+s=;
        b=vLx0B0G5G+8MQg5ZJls2K/CuMWtJ7fOsFO94rvY7VmGa3c3j8mjD6/RK+cHhu8vHK2
         2xnCYg2exXrE13LpNKA9ClWQaHo5oG/XpleXHCSuAeLknecYTOrMu6+brdqi7wszq40/
         CkN+bZVA98tiz3HlzwPhrzri39sl54ERJyLTLat7gj1EqLeH+kIoDZuvTJLOcs09BTee
         fJEaybACYHiPcYcz2PQhLbyIs5iOt2qV7yyVQyCMBWsx8kLYOMut7V0+WYxDMrbUFmVZ
         FXaBF/gnMxRCworRAfkdzv2hXRxydQcQHT05iHBhJI9hmUZM8ywNFws4MGbLic4EXWIO
         MBYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=bFaio31l;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id o18si37230vke.0.2020.06.02.10.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 10:34:42 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgAoC-0007Ar-7V; Tue, 02 Jun 2020 17:34:40 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 331C03035D4;
	Tue,  2 Jun 2020 19:34:38 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 07D64201E996A; Tue,  2 Jun 2020 19:34:38 +0200 (CEST)
Message-ID: <20200602173348.401295331@infradead.org>
User-Agent: quilt/0.66
Date: Tue, 02 Jun 2020 19:31:05 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org
Subject: [PATCH 2/3] kcsan: Remove __no_kcsan_or_inline
References: <20200602173103.931412766@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=bFaio31l;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

There are no more user of this function attribute, also, with us now
actively supporting '__no_kcsan inline' it doesn't make sense to have
in any case.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 Documentation/dev-tools/kcsan.rst |    6 ------
 include/linux/compiler_types.h    |    5 +----
 2 files changed, 1 insertion(+), 10 deletions(-)

--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -114,12 +114,6 @@ functions, compilation units, or entire
   To dynamically limit for which functions to generate reports, see the
   `DebugFS interface`_ blacklist/whitelist feature.
 
-  For ``__always_inline`` functions, replace ``__always_inline`` with
-  ``__no_kcsan_or_inline`` (which implies ``__always_inline``)::
-
-    static __no_kcsan_or_inline void foo(void) {
-        ...
-
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
 
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -193,10 +193,7 @@ struct ftrace_likely_data {
 
 #define __no_kcsan __no_sanitize_thread
 #ifdef __SANITIZE_THREAD__
-# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
-# define __no_sanitize_or_inline __no_kcsan_or_inline
-#else
-# define __no_kcsan_or_inline __always_inline
+# define __no_sanitize_or_inline __no_kcsan notrace __maybe_unused
 #endif
 
 #ifndef __no_sanitize_or_inline


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602173348.401295331%40infradead.org.
