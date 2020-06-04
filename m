Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCMY4P3AKGQEAG57UFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E26EB1EE25B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:13 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id a4sf2234408wrp.5
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266313; cv=pass;
        d=google.com; s=arc-20160816;
        b=TGpwVQQXlsQP8/UrAhwKU/j6XeFMYZJaqMpPvrKDrWdSczClKKSwM5XmM23Mfe6JYw
         fVSzGePSx51cOpiCKLASTGGTCZnNwFqajuAY+vvyVawmaBpjZLc53RZdtCJRu8m3+ejH
         ljIk28UE2X0ZhvAcvGzZVYj2lp5z2kTzGn+ACdOw6OjrLe/6ExIJrLD+Yc2VFN4vdfgt
         p3A3VydsSGCKwDJl3CzX5J6disHMVgnKEYCyAFSKPdzxspgKwN+Id7lyc0GlqK2BVdZs
         uLF366ZFDrZW3Xm+TFKncNMJ6CPk4sdR30YhXT1oH1lmzP1BdLCEt6ox+SxQHKo72nVK
         vIKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=L2bT30I3loDw1SIgOH6FkH5oKdt44MO0KWa/Hbhdn2Y=;
        b=RnzhLkj2k1Riu2svkzkjp0JeKdGrzeMPtcJ76JCBMAfEQCgc06JiLw+lilnE0Epurd
         AbhlHJiw3Gv0n/dmyxQbl1j+UCHodXGm8OmKa5Yy1Kbps8iI/azLbuGuxHVL/cWVszPX
         rHtg8H58qVhQ/HLE8Z+hb09jWB1QF97U5XRHbqd5yQ4vFUMEmmn2OGIMA86OpEGiZBd8
         hdVrARdTVgUsVrsGiMDSNNXgtx1isTkyA3ImXkUngskIpMIcaEwMdpQUnCO7ZMqdfP/2
         GstCLxPGZn7JOnMxurMlFZg8DDwKCvVsQNxSai283T97JzG8W4nPp46SXHSWMrPRsYk2
         25Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=ztDTJhFd;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2bT30I3loDw1SIgOH6FkH5oKdt44MO0KWa/Hbhdn2Y=;
        b=Gb/seSrMUFnLHseaWDvuV6ykFAbQj8V5vNHAE2h9KPjAeJq9VgzODXTsyAb5hRDKz+
         xbqAjohZ/7GfccbajzqciDiQHnj4SIi9R58e6LZdF9X/KCzuehksOUUgeObKyXGpxdF6
         YVO9nRSAoYuel7zX56WQS1LVPs9m2NY1Stk4e9gp2OcjQadlvbncTJlqQc9u+IUjJnP7
         mBLe/JELxxjNmTVg4MCZexdz/FpY+DhQ4uUDna4DheKaBI0hSJe+x/umueo8KdTsoQGW
         qXA6+IYVsfyhOdinRM78vL1dMP3BiCw+vhuPgacwqW6tmOv+cyE8lSh/VsASU8DEW95b
         05sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2bT30I3loDw1SIgOH6FkH5oKdt44MO0KWa/Hbhdn2Y=;
        b=af3uaNCd/+joREMslHgPADYKGJXeMVJWft5VNZhuSfTLkcKHWmHHmMsrW0M/ZA6Qj9
         kkaV3Zzvu+TJSe9OXJGyXf8WnjpGjZv2292jT6ocCCY7n8fnNELmgOP1J3AM/tCV1NAK
         2iCq6jT1tPzjCRtulm1JACLji88vgTLzdC7ZKO3ERFyTnCZBwmCJ/c1nrFCrakDopT5/
         DjtrgfzCP0dO1ZYDeZQvaPzCQbovJfHp8uwwp/KHaV1DAJFBURZB+HhRO9Az8Q9Jyvz6
         wwa1gq0FgBYk1hLul78jH61vZmRMzP9SbcRMj31lcdxT2vEwZEGwnUmAFC/ET8ociIVQ
         Czzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332+MPlpn4oihNfMAyvbvv6N5wPNQ1R5ZcFW3dL/trYisOxQqsJ
	X83RUJT7bSI27HifqDJcyHQ=
X-Google-Smtp-Source: ABdhPJw4YMUwg2mnwhDtDJShZVFBljwkqtv4BgmBkxgoRC0uSFig+58syePvXLCKvnaKqJb8/auafQ==
X-Received: by 2002:adf:a157:: with SMTP id r23mr3964695wrr.92.1591266313646;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d84:: with SMTP id d126ls2568439wmd.1.gmail; Thu, 04
 Jun 2020 03:25:13 -0700 (PDT)
X-Received: by 2002:a1c:143:: with SMTP id 64mr3569671wmb.182.1591266313155;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266313; cv=none;
        d=google.com; s=arc-20160816;
        b=fQpmsaYUknMs3ljrkkUk/lxUabh+LTACnBmZqnT0TKkM6Evx6SD4T7llAH8CF1do2L
         q8KhZt9NsXcV+BOLDFJqm3Y+z2Vqd+wukLQpa0RUzhghpbSx/jGHUkajXBg7XfxiLnkK
         vsk+yaSHsbTc//isix4ZX4GnUSrrjQc5yO7aTgBfJPuI+H1zc1GOSkCM11jAFBmX5nH1
         a+FD1oYbkXgLvXon9WoUddBMMXr4EscLbu1FUGNKaNiak/AYYlnEdJYomHqoIzdjVK+W
         zxFTGrn+ixBlbGgim9b+HGswjlCocFTm2BC+yJPiE4OZ2XlUlA47sHDshs3lim0gUogA
         9z6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=wZRor1BzB1/H6lezWifVNSHYwmu48K5Pc1GZOtnXb+s=;
        b=hjWiNeBToSx0QXGj50FvXlIMzOBiwoIeoVwg5fTMrAGIRhIjpFj8T4kmzLmmyoseHR
         kmU5rXRyGdYmErtFtXsdEwFm7M3RiBqOLXiTPnphN9Sg2SKkOdQQEPI9ksytDCkiVNLL
         bAvMOXrwsO0x26R6vK6lWtqMO7nJFgb0SSPiAg10di3yn4aZFx1S2B4Ym6ZVGeDd4Qlz
         TVSm4DDzoAWeW43TEiq5+LZ7QR3XOk11GuQD2/3qF0d2CMZs/tQoAQi8jvV+GHKssl11
         lXX7E58WbfUVBsaLmBSNb9j6TkEInItv8eDtkxzKegan3dRZer/59fEGEQEEm2M0+pZU
         O0/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=ztDTJhFd;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id z18si284161wml.2.2020.06.04.03.25.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3d-0003tc-9P; Thu, 04 Jun 2020 10:25:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E9E5E301ABC;
	Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id D873220C6A1FA; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.020498631@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:43 +0200
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
Subject: [PATCH 2/8] kcsan: Remove __no_kcsan_or_inline
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=ztDTJhFd;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.020498631%40infradead.org.
