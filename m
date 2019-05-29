Return-Path: <kasan-dev+bncBCVLJ7OQWEPBBQVOXLTQKGQESG6YTEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id D1F7B2DFB7
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 16:29:23 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d19sf1685946pls.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 07:29:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559140162; cv=pass;
        d=google.com; s=arc-20160816;
        b=SFpmIIWd36aykEIz6G7Dgmvb1faEedr2482GsHJ5RJQ9yBWgBPLm+Ae7L8bVCJQefq
         DoOGAZAYn8Y7LQ3QTGh/bwYkQc2Z87x9Se/Tbk+Cqwob0awJQWIf0HZOy7nPdnRaOihN
         v/o0U3uPXbm1oKq2I77MYqoj6bDsJNsLAA8SobD275JPTqRGJAa6ZrSPUo7rzRQ171dI
         ltSUDX24NksnCxwAkc8NvkQboz+COAqC4X3/fhZnxbLvGbMSH/cusfME6hhcG3QRm4F8
         FnBAD6yPAScbdZL0an45dy7mkgehZCODb75OA8pzD/wRsc6BSA796uaiCdnNVFBE7MXD
         9U0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:from:cc:to:subject
         :mime-version:references:in-reply-to:user-agent:date:dkim-filter
         :sender:dkim-signature;
        bh=6PzWCa6YdwDs3uBNpX6kb3HLoBW26+hQVA3D6+XdNhI=;
        b=clE4d/vs6XEogLeEtozSZaMkrqj23+ZxM348kBTCDumTP6ggmxWlKdrPUxtOdA6FXX
         qv4+ni9ogON6nNQpxXfP4ra+P0GDVXFY1GEBiWlZtiSiOriY/1hCqQGivakFm+vO8O6z
         N1yiXE1cfnlqubOpqS8w39t7btXQLd5bdF8gcPX/0ywXmCTwBjCHT6tomrTcttxpFAw/
         UpKJhBaWPSBTqW3F/aTc37qL0/olh/2ecL7U2XUw1CjVw8opSxKUz7lNfrD1Tm5rI9TJ
         vFdhv1dVDGVvHjQKVoUeRBplogXs40EIXzporXhF4jUdE90xAfiCg983G4NdyR6Uh+nc
         L/xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@zytor.com header.s=2019051801 header.b=JzlSyO5e;
       spf=pass (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted sender) smtp.mailfrom=hpa@zytor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zytor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:date:user-agent:in-reply-to:references
         :mime-version:subject:to:cc:from:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6PzWCa6YdwDs3uBNpX6kb3HLoBW26+hQVA3D6+XdNhI=;
        b=jUP51b9I+AahSx7a3mN+fS9audWlCbnATxgSm62PNd/nAndCHO4IZTMOApIHONv156
         uH9u06IUhHWaRk3BisqXDk/3b58cMErAtRErKsgwcekIX2CuOg7Kzx5sKfp7Rp1Ihhq9
         ZXMbn07Ybtktr+g4BBUceuTOZ6KpvJmmLfuc33g8tea1FbWTey32uRjz7p+IPg8iS1Js
         rYbl1DU0n2Mq4EIQFFC5M19SW0beA4kPLCG6DRKACKY+yPvvgpm7OHHeyWVptwLUwi4L
         uwtflH6gEjQd7JDbbRQ6eYlWw6c0iBlR2dTSb+BcspFs93TVZH8tNj6omtH8RAMSM0hx
         5ZNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:date:user-agent:in-reply-to
         :references:mime-version:subject:to:cc:from:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6PzWCa6YdwDs3uBNpX6kb3HLoBW26+hQVA3D6+XdNhI=;
        b=Sz3AQsfTwDPuoP0VI1wx/QjjcrhIzB8yyASc3jRE7AAuSJvqi4rm4ib1LtlrD1pGAo
         S7t6JW2bMQzVSLE4++2DH2YTutK1/8zQyrIKNM+x0tm20fYQbTp+47LaEjoPeBo82XoY
         0piA2tga/9B/EZTUQgLIvKAVcJ7c98HqnF7SCdhREEkVMy9fw6JgCdmtRRDcgcCLSMaX
         JCKLlOUyR4rlwcoMdlZxlSDp/mSPETTieg0V2SbMH06XvhVMjCAG9QIRiIT6uh5ztGTA
         VTvAE9GR84t1YCmSLsZ/KXMQ+GGpsQGH25k23R/EWinHr787YU7XK5WGGS7Qk/UmL6C1
         ZcCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV7WFODgXfEAcEXxdQN4Jo2/TilStHGu4fGoQVBJBYkx0/w5yd9
	Kp1QWgYTgEaTM4yjfUn7Mv8=
X-Google-Smtp-Source: APXvYqy4mQWQBb4oIehLo6xuq9YQ2iNN3hu4Ei123TRPGkmhGrir4MgHLp05v9lsmH/lTRkn8OOsTQ==
X-Received: by 2002:a65:620a:: with SMTP id d10mr14543284pgv.42.1559140162577;
        Wed, 29 May 2019 07:29:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1b4d:: with SMTP id q71ls715160pjq.3.canary-gmail;
 Wed, 29 May 2019 07:29:22 -0700 (PDT)
X-Received: by 2002:a17:90a:e0f:: with SMTP id v15mr12493006pje.140.1559140162306;
        Wed, 29 May 2019 07:29:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559140162; cv=none;
        d=google.com; s=arc-20160816;
        b=TIj0t85UMDrAIxIwDbJRxWPjl1/XJyS+qXKTl1+1NFN79PtxcGP1UEaIUYGRHQTOau
         hgtfx4hRkQPMMiI7TZEhMCZ8kw+KYZTJnOPgM2pDw2seKsh/P6FAGTswP+waqGHo02TP
         aFb79PkcNGnUHT8NnxWfXn5pQDoOgZcOC0mNGQqLvUVdq1O2/OQf6ERBcZfX66w4aaaK
         B95oMIYhV1QiwHnFLAYvZTup3F0JDDw8FZi64dJUqfcS0udgLqpDcgtiEtH5VUYc8pSI
         jUCkD/Ct7wfwEdeKnyJQap9lAY7ZLNx4uQ+tTiO8+SO+Y2rCqMuxgeVgGKIkMkVxdrKQ
         jUEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:from:cc:to:subject:content-transfer-encoding
         :mime-version:references:in-reply-to:user-agent:date:dkim-signature
         :dkim-filter;
        bh=0QBCMhL0UtNfpa1/nHPwY54RLtb1R1cG9r3yArQfJtw=;
        b=Epf+3scViykDus/DRXyejmlhoBpr7SA0OU48rbtfH0ed2z/gLuerqQG9XOFok7VKab
         r11jkQ2nr5XVAs59hnziDIucfDHiI65cnIaQMxWHsHORXgZ7QgxTmZL5mu7MASebMUQx
         XHQpYRz2pOYEuAuD0FJbpmYasuUZyJN7Wv8TQWa2jjTZ9Nk4O6JTiex9GDQip3XNvvMb
         O1jEaBdoyKc4tfH95+R76cifxq9p4cYJ5a0OC+/yVd7Wqz6fZZ2FOlN1ASs9y2NDcY0W
         bhEjyE1OJ2e7R6CFt7ZCErTrf652kpTVuuzpkuBaPVGjClxI+ltCw7E3oz+6tTEEau0B
         MUlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@zytor.com header.s=2019051801 header.b=JzlSyO5e;
       spf=pass (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted sender) smtp.mailfrom=hpa@zytor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zytor.com
Received: from mail.zytor.com (terminus.zytor.com. [198.137.202.136])
        by gmr-mx.google.com with ESMTPS id s3si206551pjb.1.2019.05.29.07.29.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 May 2019 07:29:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted sender) client-ip=198.137.202.136;
Received: from [172.20.5.109] (207-225-69-115.dia.static.qwest.net [207.225.69.115] (may be forged))
	(authenticated bits=0)
	by mail.zytor.com (8.15.2/8.15.2) with ESMTPSA id x4TET5Ip2561081
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NO);
	Wed, 29 May 2019 07:29:05 -0700
DKIM-Filter: OpenDKIM Filter v2.11.0 mail.zytor.com x4TET5Ip2561081
Date: Wed, 29 May 2019 07:29:01 -0700
User-Agent: K-9 Mail for Android
In-Reply-To: <20190529141500.193390-3-elver@google.com>
References: <20190529141500.193390-1-elver@google.com> <20190529141500.193390-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Subject: Re: [PATCH 2/3] x86: Move CPU feature test out of uaccess region
To: Marco Elver <elver@google.com>, peterz@infradead.org,
        aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com,
        andreyknvl@google.com, mark.rutland@arm.com
CC: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
        x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
        linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
From: hpa@zytor.com
Message-ID: <EE911EC6-344B-4EB2-90A4-B11E8D96BEDC@zytor.com>
X-Original-Sender: hpa@zytor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@zytor.com header.s=2019051801 header.b=JzlSyO5e;       spf=pass
 (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted
 sender) smtp.mailfrom=hpa@zytor.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zytor.com
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

On May 29, 2019 7:15:00 AM PDT, Marco Elver <elver@google.com> wrote:
>This patch is a pre-requisite for enabling KASAN bitops
>instrumentation:
>moves boot_cpu_has feature test out of the uaccess region, as
>boot_cpu_has uses test_bit. With instrumentation, the KASAN check would
>otherwise be flagged by objtool.
>
>This approach is preferred over adding the explicit kasan_check_*
>functions to the uaccess whitelist of objtool, as the case here appears
>to be the only one.
>
>Signed-off-by: Marco Elver <elver@google.com>
>---
>v1:
>* This patch replaces patch: 'tools/objtool: add kasan_check_* to
>  uaccess whitelist'
>---
> arch/x86/ia32/ia32_signal.c | 9 ++++++++-
> 1 file changed, 8 insertions(+), 1 deletion(-)
>
>diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
>index 629d1ee05599..12264e3c9c43 100644
>--- a/arch/x86/ia32/ia32_signal.c
>+++ b/arch/x86/ia32/ia32_signal.c
>@@ -333,6 +333,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal
>*ksig,
> 	void __user *restorer;
> 	int err = 0;
> 	void __user *fpstate = NULL;
>+	bool has_xsave;
> 
> 	/* __copy_to_user optimizes that into a single 8 byte store */
> 	static const struct {
>@@ -352,13 +353,19 @@ int ia32_setup_rt_frame(int sig, struct ksignal
>*ksig,
> 	if (!access_ok(frame, sizeof(*frame)))
> 		return -EFAULT;
> 
>+	/*
>+	 * Move non-uaccess accesses out of uaccess region if not strictly
>+	 * required; this also helps avoid objtool flagging these accesses
>with
>+	 * instrumentation enabled.
>+	 */
>+	has_xsave = boot_cpu_has(X86_FEATURE_XSAVE);
> 	put_user_try {
> 		put_user_ex(sig, &frame->sig);
> 		put_user_ex(ptr_to_compat(&frame->info), &frame->pinfo);
> 		put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
> 
> 		/* Create the ucontext.  */
>-		if (boot_cpu_has(X86_FEATURE_XSAVE))
>+		if (has_xsave)
> 			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
> 		else
> 			put_user_ex(0, &frame->uc.uc_flags);

This was meant to use static_cpu_has(). Why did that get dropped?
-- 
Sent from my Android device with K-9 Mail. Please excuse my brevity.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/EE911EC6-344B-4EB2-90A4-B11E8D96BEDC%40zytor.com.
For more options, visit https://groups.google.com/d/optout.
