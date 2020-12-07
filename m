Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPFOXD7AKGQET3OJHTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D0E6B2D0FB3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 12:51:24 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id e16sf2660663lfd.19
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 03:51:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607341884; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDyiMG3hQZfSciK9Ecg88QzGdpuvc4F94rNbZbnr7/WGwZTUlLgZFS5V1jxxPijAN8
         N2WLh+i1TsGVQcnu/fvcfJ656dXj/VvORZxlX7fPBfH22RmxeVjpJeDT1oZplqI0oMtr
         CDrxap7JMSLNVYcUK1O0DVDWqlyN/4Ol5phNKLoNFNHaaS0q/xFHUov1KTYLPd4Pg+uO
         j9+pcA90EgPU0fJuCttDIUh3VzJ3971PGn8SoX5PlieiCGD5Qqb6kDgvgrK/4x6YHmIu
         nYSPLRdsT0CvQUhIBFUzWFz16lda7jWKXDOdLGYusSqfEvbHJ0w9ovZCSwoMGVhG4pvJ
         vTzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gP4T/oq9/PBsISdSD1u/msf51i8Cu1JisdXFiOANHTY=;
        b=0IRHAajuu/6D3PbmO+5CPLU6w+oRf6dsYWnDqJjjHGoQKrw/961428f3FBRAczRdP2
         vnsUaQRI3UHnVcP0CxdLZZeBa/QSsMkMXJa//q7OclqE7a/6VgcJFHgZNqWNnCTYCumY
         UzybIA7U2iBIZGOSWBN7qlh1Bb/+RWcWPSmXpyQAzuY1sLO13NJ0PYX/c+o09Wlk8S6i
         niaS1zNW8zJaQj5eqMdYOkeHgiozm8gOUVujUtgPbDH79b0ALwbUQ5aOaaywKJTwMbKa
         zR632hQ5QpWmSHX6nVa0Ks3dwpRt/el03CK4NDhu8KgxvN0UPbetJRxwZBBG8iOp+tc/
         i88w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=u1zSahYW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gP4T/oq9/PBsISdSD1u/msf51i8Cu1JisdXFiOANHTY=;
        b=Xl2D6UDjTn70Fjp3evS0t1YE8aZTqssZ4gjP+hTqukE0h5MNA9nlD2f3Rc7SnImcl/
         XTDQAtIKwaVSQKrgbIFkgXflszmcvlumR0qOolpvgj1aRW8rvBiIH233FJaqdYMINBTB
         MuRIBA9PpMT/kzHabiCHwqIKxRljv1mca3XQWOHUcYCfLGLkGFwHhgFiUKbG4daGzRYZ
         bAmnQCaTy6b1LUkWOpmHS4my7fAm83CLpAbuFbSFib1o65RIneWZAU4cdYvx7ZTqpPy/
         2LaKN1ZyfGnbx38FmpDb+t/O1zZ/QuWzgv5bgFVAC2ldynICDjGoStIosB4QiL3+mx/f
         wO1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gP4T/oq9/PBsISdSD1u/msf51i8Cu1JisdXFiOANHTY=;
        b=MgIvf+HjPE6CYDUE/+8P7m0gZ83HVPgy4q2ZnI2cFbkmig7IrXmzc6KvfVfRwljaFH
         x7zJqwEeQPJS/TS3gYS4wfAwe7PsFrFd0OA5paBTVRvKCTixGsNMikuVOT6KSlP5Sdya
         JLIhdUVOMIgfUJsfI7fhC2+5ptihlUbxfnFwnnWB78ph91FN4kEnqPXzp72i46W6JxmA
         MDJ1MwZr+x1cYMkMX7l22TCaOxMN/GwrWI7wqYufs98i+3W7vAO33GxyLY6O0g6I9PST
         aiEXgest+Xi1bP0c7sQuQvt7fqU/HOHosFJ37CI7uG4ENn4cMR0RlNDWRVtUh//H5bnI
         h5Kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qqGcujGw8l/jdoZvDyzojZqrPjCoQ3QHi+oiGK5dZm9G/vgSe
	UZOw9s31Qq2wI1d+ou7qUPw=
X-Google-Smtp-Source: ABdhPJyuHZC8OL5DbFEPOn5LcyaBzq8toA93DDO6Sd3P7Sy96dgHxIVnDXrERTEPdVGYk6EVFA+a0g==
X-Received: by 2002:ac2:46d4:: with SMTP id p20mr1878279lfo.299.1607341884366;
        Mon, 07 Dec 2020 03:51:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3614:: with SMTP id d20ls641807lja.6.gmail; Mon, 07 Dec
 2020 03:51:23 -0800 (PST)
X-Received: by 2002:a2e:95d4:: with SMTP id y20mr7972824ljh.74.1607341883202;
        Mon, 07 Dec 2020 03:51:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607341883; cv=none;
        d=google.com; s=arc-20160816;
        b=kT45AGOmMZEqnmYNEJxaj2ta56z+qIEgnRbx8HcazDi7/JboP3dIP0TCj/AT1bT6p4
         cliwUl5O1ZxuXj+uJnSMr8soaizQ/S4yQJxhdVB/O/8PpDaeILPysfAzbH2wwQk6HiOJ
         FnK1czz9YnLGj9r8rBepY8qmHt0p5C+AxfZRtyRscvUIviJG1XiWvC6iTUWbLwhiAs/s
         aog8DaL1NPP1ufzjT2JTTJAurFJV9bPnZsEFID77ae62hk/P+qxA/y6X3H3Vn3uswRvg
         UwSntcIS5jFLKPUBOUo2BkF5h8YVPZOvzfkuq50aPxz79aSA9N+L9AdNCQYRjeSvqDPe
         Irxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Tg95pwKVfQPUA8PWvLFZbteHSebozu5OxDajnVjWT7Q=;
        b=CNIJH28CgFIhPa8MD6w3Gmru2pHSGEp/5b8gG8l+ogajmo39qZmJHn56ZYYbIPE0Ul
         09N7eATFrPDhq0Mk++P/B4sO4U2sORQEI1nfOjuG0wdxuVMed6GoPh6ypTFgxN4Hhzsw
         N00czYO+aB5Od218HbfuwiRihxXtxr6sK5+HjvQzCaicZ7db3cW4EgnGHOGfyv1Bsam5
         Z7rFdoAh5kqO4V8BAYc4TpJmXBtJcDVRnf4PLDFMmFigq0/RofJyrqQFb5CPbhep7jSj
         nSPy0dGFECsKHm7cLTa8bHloTSPuxhia3rPA2dffG4XrhLhste13GD312Re5CKctP08n
         biQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=u1zSahYW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i18si166501lfp.2.2020.12.07.03.51.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 03:51:23 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kmF2z-0000Ii-Rc; Mon, 07 Dec 2020 11:51:18 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0F7AB303DA0;
	Mon,  7 Dec 2020 12:51:16 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id E9D9E2081295B; Mon,  7 Dec 2020 12:51:15 +0100 (CET)
Date: Mon, 7 Dec 2020 12:51:15 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, linux-usb@vger.kernel.org,
	lkft-triage@lists.linaro.org, rcu@vger.kernel.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>, Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will@kernel.org>, Lee Jones <lee.jones@linaro.org>,
	Thierry Reding <treding@nvidia.com>, mathias.nyman@linux.intel.com,
	Qian Cai <cai@lca.pw>
Subject: Re: BUG: KCSAN: data-race in mutex_spin_on_owner+0xef/0x1b0
Message-ID: <20201207115115.GL3040@hirez.programming.kicks-ass.net>
References: <CA+G9fYuJF-L+qHJ3ufqD+M2w20LgeqMC0rhqv7oZagOA7iJMDg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+G9fYuJF-L+qHJ3ufqD+M2w20LgeqMC0rhqv7oZagOA7iJMDg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=u1zSahYW;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Dec 04, 2020 at 11:51:39PM +0530, Naresh Kamboju wrote:
> LKFT started testing KCSAN enabled kernel from the linux next tree.
> Here we have found BUG: KCSAN: data-race in mutex_spin_on_owner
> and several more KCSAN BUGs.
> 
> This report is from an x86_64 machine clang-11 linux next 20201201.
> Since we are running for the first time we do not call this regression.
> 
> [    4.745161] usbcore: registered new interface driver cdc_ether
> [    4.751281] ==================================================================
> [    4.756653] usbcore: registered new interface driver net1080
> [    4.752139] BUG: KCSAN: data-race in mutex_spin_on_owner+0xef/0x1b0

At the very least run your splat through ./scripts/decode_stacktrace.sh

It's impossible to know what the thing is complaining about. I suspect
this is one of those known KCSAN 'bugs' where it can't tell a load+cmp0
is perfectly fine.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207115115.GL3040%40hirez.programming.kicks-ass.net.
