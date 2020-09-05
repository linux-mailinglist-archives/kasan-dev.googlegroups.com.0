Return-Path: <kasan-dev+bncBCIO53XE7YHBBYFY2D5AKGQE3FJQ2SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id AAF5625EBB4
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Sep 2020 01:16:49 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id q15sf6026095pfu.20
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Sep 2020 16:16:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599347808; cv=pass;
        d=google.com; s=arc-20160816;
        b=wD+DOhkZRUZNl48pDaseAbnlZxU9n7EsBSnWyv/HeimCcHk35ln73vxwnqLwMDpGIx
         mQgqtGhpXkK47cHHNqGSTtAdgvziHIJu3zxAAyDyZ+ijotm5/DiMb6iZihujSMQbU4AW
         RZTqNdEEl2Ll1Di7uBQRRHQjbYEsZZvaXhH/p5YVzGNhelfIS2I7FlcuzNT9VQbltPZr
         LmEk1JAezHwXRXiNMTKBpx73Vcl7J9EMP8RkjhsTIyRa/4sUIdttyQSCm6b3SsTVx9jb
         liL7KMgKI0txd5sAXnWRmSteqWlBitG9Zrb3ODzoxa4Y0H5KA/+TpiWAC7X9T87wnqJO
         Uvow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature;
        bh=L6iHfa73udMRTG8xBWeqeeda7QSB9YrHEhCBPuTBLM0=;
        b=IUeD6Dw7FUkss3IY17jbkm1QeNdkn2sOM5q5A0QrfyXxLLPcHdv8PsBhL4LeAwalab
         J2EfjkJQCO6nUur0Fs9xzbKX/vHKZWIIodq9jojRjPSFvhDkTUprGN+qs4mCnADUHzEP
         +aOV6+sKNPfWYFj7vQ2VsMqGSvFf7LRcmz32zZ10cxZthRzluqOyL4NRcrfTnjT9HXG8
         zjNmJOj+I6X7ECWbhuuYrLKUji37V+MvKOUHhMG1+5zzbShQSd845bx9bCckA5mE+QLs
         bH673KuquSf6V7uylxo6p1PsblfSSVUaqPE83lEACURfrgkaPNF4agYDyh/wewLPuugk
         762w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ijV3p0mC;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L6iHfa73udMRTG8xBWeqeeda7QSB9YrHEhCBPuTBLM0=;
        b=B2A7a2lVDdBPlWLr11uEdP26V80SFYXctpzBriDHrf31OHkz/yJoX6uNv+hag7X1fE
         aCcc4fJefYjrAu92SGxPwaQEg7v2bI/JllWAD1TCnM+7ETwpvxwmCcxiCGpDh2nIPY0V
         SKOLp37eqsTH3Qs3LZZV0NUpEEEZECIZO7WIARwfsnEL2bu8OrNx5S20BUiogySeUhr3
         aGq9T/lpplNlXSBq+Zr5VotU5hY295nlPGiC3kCxUgC3kI4twhPcc/jNwX5QJ3ztQhcQ
         Ki9vo+7NvXeRJzrFCWL9FiU0w4bfHFrobrO3iMV6f+fihHJfB90j8pvAdpQNhQUaRFFf
         CVvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L6iHfa73udMRTG8xBWeqeeda7QSB9YrHEhCBPuTBLM0=;
        b=ZXpzMjuPrYXLOIPApPpAPGdR7KYAr712B+FtzRf4MITJ0pLZ0TYS3g5S/+LKRbZVLz
         vPAuDbrkKMVaWngDaN5snfBPHJ7LVEK6BvEvqc8EeDuU2ucAkwXiXdh3BCkYTsGkNRna
         6DzCzD5J/c6K9Rqi9iVweTCvnRC1OyzHWVKnTu4VfS9SS6zh+USrMLQv+CrohsTrSgNk
         DPR1o/hvIsR5/B0AbxDubExcblx81wtx1RemGpzQv37grGWsL0oV+0dLVGM9tyDhlPXA
         3mZ90U9tNz1wZ1+WekoKSQQ3fSbTxV9HvdlH/CTgbaZaNpsU7rQmxYEYb6/UYE3K1pAI
         xUnA==
X-Gm-Message-State: AOAM533GzYnBdQXo9BSZoSOYbDc6pedjpJ4prw/tJB4RfhGUUfTm6V1m
	tnWVLnDXc1L4xbHsE1TjStA=
X-Google-Smtp-Source: ABdhPJxjalA4KE1W8PPyP8HfCg6MFbxzv/imMRLFC3Nww3A46LT0IOYcbTe2/quwbX/BLYXO2e3WxA==
X-Received: by 2002:a63:1341:: with SMTP id 1mr12130243pgt.144.1599347808295;
        Sat, 05 Sep 2020 16:16:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b4c:: with SMTP id g12ls6241900plt.7.gmail; Sat, 05
 Sep 2020 16:16:47 -0700 (PDT)
X-Received: by 2002:a17:90a:e207:: with SMTP id a7mr6747516pjz.117.1599347807834;
        Sat, 05 Sep 2020 16:16:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599347807; cv=none;
        d=google.com; s=arc-20160816;
        b=EJS11QPRqq1t9+uo+6sVW0VQoiBJpZW/QsZEPTckh/B+Cl8x1bgclfeZcFAvZDyk25
         bH7YLL/onV57qkCdbq+cUt53MFOe0pNGgIQwOCv54gBKtJrWb4g0jVMifdoZHkSCbr3N
         bDWlfHssYWs0+/FdsQH7e14y/Q8NJuzmUgmgR56El3wi0RJ6BpMFsbC3JsV61ybqNJ3D
         NzcW1o9xcYwKJTea8Z+SGZKwO3zUIICE/7D0NXa/ucSeR2FPMU1F/V1jwhnWLrttoWku
         8BxMipAp5EyT1UHEqXJMj9l6t78cg4rDD0cbgTC5t/qr1acKQnNn50JM14VDWQqFs9K7
         5s5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:sender:dkim-signature;
        bh=kI4V/ahU3BYgz++tM9NELKbYkCbYwuyU++xD5Hv5/94=;
        b=ZtUeB6wbHwTUhV4s20M4eqsFhfF1Ityyq5G3Vf+GtRLOQwHWSHDrB54HUGLdg1cPxI
         BCM18eH3CPDEg3I+Z5NhcTYvS1VhfLvWA7tIm4eay7EMOOiBV+CDuXa3uxX14vdXubcg
         P3zqblDhh8Dr18KHD+r5i82McrMq9JWmuuNKpWwoarrVLKlMfYH59cLHdDMQpoDx3MLv
         ZkT13lcyVC/NMNmqiOwP2351KzlyqNknQ6tcH9Wj/OuvmrLzA67xGCwhQukwqjN/4lgR
         vM5UR8D/bbA7V8GkBab0QMeFWVMb7L0WFZvNH9iFYAiBpMHxW4kQOQFqX62gws4v6v6B
         bO4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ijV3p0mC;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id a199si806203pfd.1.2020.09.05.16.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Sep 2020 16:16:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id o5so9777554qke.12
        for <kasan-dev@googlegroups.com>; Sat, 05 Sep 2020 16:16:47 -0700 (PDT)
X-Received: by 2002:a05:620a:4c3:: with SMTP id 3mr14499449qks.105.1599347806988;
        Sat, 05 Sep 2020 16:16:46 -0700 (PDT)
Received: from rani.riverdale.lan ([2001:470:1f07:5f3::b55f])
        by smtp.gmail.com with ESMTPSA id l5sm7742648qkk.134.2020.09.05.16.16.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Sep 2020 16:16:46 -0700 (PDT)
Sender: Arvind Sankar <niveditas98@gmail.com>
From: Arvind Sankar <nivedita@alum.mit.edu>
Date: Sat, 5 Sep 2020 19:16:44 -0400
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Arvind Sankar <nivedita@alum.mit.edu>, x86@kernel.org,
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 2/2] x86/cmdline: Use strscpy to initialize
 boot_command_line
Message-ID: <20200905231644.GA1506363@rani.riverdale.lan>
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
 <20200905222323.1408968-3-nivedita@alum.mit.edu>
 <f5a29e70-7d11-16ec-8d72-ed71da4124c1@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f5a29e70-7d11-16ec-8d72-ed71da4124c1@infradead.org>
X-Original-Sender: nivedita@alum.mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ijV3p0mC;       spf=pass
 (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
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

On Sat, Sep 05, 2020 at 03:59:04PM -0700, Randy Dunlap wrote:
> On 9/5/20 3:23 PM, Arvind Sankar wrote:
> > The x86 boot protocol requires the kernel command line to be a
> > NUL-terminated string of length at most COMMAND_LINE_SIZE (including the
> > terminating NUL). In case the bootloader messed up and the command line
> > is too long (hence not NUL-terminated), use strscpy to copy the command
> > line into boot_command_line. This ensures that boot_command_line is
> > NUL-terminated, and it also avoids accessing beyond the actual end of
> > the command line if it was properly NUL-terminated.
> > 
> > Note that setup_arch() will already force command_line to be
> > NUL-terminated by using strlcpy(), as well as boot_command_line if a
> > builtin command line is configured. If boot_command_line was not
> > initially NUL-terminated, the strlen() inside of strlcpy()/strlcat()
> > will run beyond boot_command_line, but this is almost certainly
> > harmless in practice.
> > 
> > Signed-off-by: Arvind Sankar <nivedita@alum.mit.edu>
> 
> Hi,
> Just for my enlightenment, what would be wrong with:
> 
> (which is done in arch/m68/kernel/setup_no.c)
> 
> > ---
> >  arch/x86/kernel/head64.c  |  2 +-
> >  arch/x86/kernel/head_32.S | 11 +++++------
> >  2 files changed, 6 insertions(+), 7 deletions(-)
> > 
> > diff --git a/arch/x86/kernel/head64.c b/arch/x86/kernel/head64.c
> > index cbb71c1b574f..740dd05b9462 100644
> > --- a/arch/x86/kernel/head64.c
> > +++ b/arch/x86/kernel/head64.c
> > @@ -410,7 +410,7 @@ static void __init copy_bootdata(char *real_mode_data)
> >  	cmd_line_ptr = get_cmd_line_ptr();
> >  	if (cmd_line_ptr) {
> >  		command_line = __va(cmd_line_ptr);
> > 		memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
> > +		boot_command_line[COMMAND_LINE_SIZE - 1] = 0;
> >  	}
> >  
> >  	/*
> 
> 
> thanks.
> -- 
> ~Randy
> 

That still accesses beyond the end of the bootloader's command line,
which could theoretically be a bad thing: eg the EFI stub only allocates
enough space for the actual length of the command line, rather than the
full COMMAND_LINE_SIZE. But yeah, that was my first version of this
patch.

> > NUL-terminated, and it also avoids accessing beyond the actual end of
> > the command line if it was properly NUL-terminated.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200905231644.GA1506363%40rani.riverdale.lan.
