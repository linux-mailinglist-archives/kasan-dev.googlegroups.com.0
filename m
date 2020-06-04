Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCUY4P3AKGQEIANZBUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 10D951EE25F
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:15 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id s90sf7378850ybi.6
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266314; cv=pass;
        d=google.com; s=arc-20160816;
        b=gI7Ys84V/w1yz7f/d3iNPpzzfp9UWZvPnC8VdKw3tu/4lMk+V3f1VY8yAzqk5UJUkt
         KxEFGYv2+jptfLMjM3ALJXyXcSpILWeBq8Ha3D+kmjdFGSE1ih4hhg5pCTaeReIagYgS
         mS2ACtu7+jLciF5MCv8vMLcPXKulupZI1M34yc6rhAhiLlySit9khhSXwDxb1W44W38Z
         NqdVGvyJoXC73uzyPp8NiQjxydIW2XZwt45p2jsq+cSi/qqJQc22rux4nGPJdmfimj3y
         q0e9mY+eiPXQvfv37Dt4+7z6YAwhXQYEwLHiOMjDwjXo9UqZkCw/eIy+VoOyOb2zH5HC
         MBEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=nFzGLTUDLgLLalNMn9VtJxjN6LSMt1lUPIBz1Qr6TCs=;
        b=y4Mwbuaq1iMMyi1z9HNKXjP8YMDv+8SUBCdtf6iqVCMukaDaaLdfrMl0boLreAD6od
         uXem2t60aWydvC+rnHYMIxD5R2dcdg9jzqDQ7htst/QgOnszSUgyeGA6I9AHk5/281h0
         0624YE8vl2I5lKe+MscaWCdL+jCOKAzLIQ2cMa6lbDaT5Xq5zbP2WPdp+25q7NLeJBOc
         VJAC//nYKyRqChuSD8x+VXF85u8xbsCTH9aau4l/Vx2VsdwXTC4z7tLHyjVbwIjRuECQ
         Ir6oy4L7qUhbMwdqaJzn5p+gWS083YBll7rzhxRol/RyXRo96hQ4wCjC8z3/T2Pko6UJ
         6iJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=gRPfcB5K;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nFzGLTUDLgLLalNMn9VtJxjN6LSMt1lUPIBz1Qr6TCs=;
        b=ZptBqc06R19e2xzdn9Y1aqn/u3XHttMpdJNFtfHoqQZ1lI74jrDgi/kRznf4yLV84K
         KqDryHUf2hi3OAQi4Wwn/WngtDGT0raJFmhJ9ZWEClADyGFg61k/3ETiZjQYVkWv1a6e
         5hUHeQhqDRE9bOy+Xa3S8O+Csy9FILUCAIGs+rR2GIBKZWFPp+7z24BmerxhhQJRTHY9
         Xrjt+qf7mVhZcOmjOtfQS1hFAxkTlncVui8IOKa+CpoYgegHA4brnOjO4bIjm3PGsR0e
         s+dsb3Hi/kCC/4bzQc1kVoyjqUqGl8gcOBzuQ23h+qp4qR39SNNT3t14SV0ZZSA/DDQb
         1KQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nFzGLTUDLgLLalNMn9VtJxjN6LSMt1lUPIBz1Qr6TCs=;
        b=TuNi5RS/Zi1qfYP6os1UD9rtzwDdmfncNYBIRG9SCGUYhfTeMBsO5LMKCANYzTjU8u
         2G6Ecj2I8ciNqIM5OCJ8s/YX7IenqAb4P5KpsBkrX1f3y0SHo2hPXDSytYPnOvEB0xfa
         mltaKNZfj1+aKgxvebzGeBmZTCQR4/TNH+q6xZ9+AtZTQCXG2yIzbDiVGb1Stb4XPz+R
         kwVaStjUYzqE+IFaZhgPtrB/NiUSsT4D5c9gwtHWigSh1n7w/Ok05LCSiolc6E2QETDt
         tCMDqnSgWnEgX+Y5LBJWzTma4qgoA5GK/pDT+Zyl8+nD58LTTj230hJVUwhrUS14y1qh
         zzVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r0FzCXU1zKGJruQ+3U4E5BxGHyvznGdxWwf4Axy2lgST3iWTl
	smbfim13VKKi5pE8r5zIET0=
X-Google-Smtp-Source: ABdhPJygJ1HRY1MO3eLOw2vr+92NPmHTCOi5Go8rik/epa8F0DqcuOMmM0d5rCbWOv1DrOXBTpHvmw==
X-Received: by 2002:a25:bdcb:: with SMTP id g11mr6795522ybk.256.1591266314094;
        Thu, 04 Jun 2020 03:25:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2057:: with SMTP id g84ls2292923ybg.7.gmail; Thu, 04 Jun
 2020 03:25:13 -0700 (PDT)
X-Received: by 2002:a25:8b83:: with SMTP id j3mr6788919ybl.318.1591266313760;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266313; cv=none;
        d=google.com; s=arc-20160816;
        b=PA519zduBZMXz4QOMIusddukef5YeQZn7i/cc05e80zBLEtQX/lnZRE2ySgS6yoa+s
         VwYyrX8LQjMt+2FIBDXkppBs4q1GdkY82ZglnJU6hi9shVXvpoNLIZe6vDjzwCbUPznb
         Pp2tvjkEqM41g91Oaop1KDUXd9vIPYBMFtpsm6VNp1f7XbaJlp03GEsctGmgl2YulryE
         lNG8KfpXgU5CN3rpczy2d54b8Iu29d9ETquFW0RBzHaPGIn4gXiJFYsUi83avBIU8CYN
         Wvv33TEG2KB7ui0UvDSsSQvC1DYdTiK1sqbDosEQKrBqyeK3ikMUM5M+yduIOvSf75Aa
         d/lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=qEEnCRuSkGqY17m970ZD2QMrdQ942DugTV6zA6aC45U=;
        b=QNIjiAdkZ2SJkvK/ahCKvh81SlOxQxwl4Um3l5ZZEl8xw8pAFgHA/7YY06Ur+WyOQZ
         8+BGtS51Mzxwy8e8ld3cP3D+HNqIC75jrqzNUqG0hnYd8Qlrv8yNp2Y9L0k7r5RDiUIL
         3u7nGn++EE7iONDghodGCE2OWPBgwPHfEo9uvqE+qilmr/j9+LwbsAC2hRT46rT5OWQn
         hWipus8p2W5wBhe8nCv44k8LCBapwWI3afMOTkuYEVPB2EdkamfqbVqD/rLS7D4CjN2a
         bBG0L02uo4Tb6/jabiX7klotdgQlFxxfkVGXAMPqcbHQyfxjhm4osURRWZ9Pk2aAFY9T
         w0LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=gRPfcB5K;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id s63si329104yba.2.2020.06.04.03.25.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3e-0001r3-V7; Thu, 04 Jun 2020 10:25:11 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EE4F630581E;
	Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id DB15520C8F8FD; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.077944145@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:44 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 3/8] x86, kcsan: Add __no_kcsan to noinstr
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=gRPfcB5K;
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

The 'noinstr' function attribute means no-instrumentation, this should
very much include *SAN. Because lots of that is broken at present,
only include KCSAN for now, as that is limited to clang11, which has
sane function attribute behaviour.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/compiler_types.h |    8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -118,10 +118,6 @@ struct ftrace_likely_data {
 #define notrace			__attribute__((__no_instrument_function__))
 #endif
 
-/* Section for code which can't be instrumented at all */
-#define noinstr								\
-	noinline notrace __attribute((__section__(".noinstr.text")))
-
 /*
  * it doesn't make sense on ARM (currently the only user of __naked)
  * to trace naked functions because then mcount is called without
@@ -200,6 +196,10 @@ struct ftrace_likely_data {
 #define __no_sanitize_or_inline __always_inline
 #endif
 
+/* Section for code which can't be instrumented at all */
+#define noinstr								\
+	noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
+
 #endif /* __KERNEL__ */
 
 #endif /* __ASSEMBLY__ */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.077944145%40infradead.org.
