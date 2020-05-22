Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJ7TT33AKGQEFSO5PSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F23441DE5AB
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 13:38:16 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id z2sf7969332pfz.13
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 04:38:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590147495; cv=pass;
        d=google.com; s=arc-20160816;
        b=bTNRprouSYXwpdWoaOKli1apKfnEzGy77HEOATnlx3YIUFj8m7+nmuH50e+PdRLB6z
         N03aLINoITpwPVYIbFNAN92IDTafhs7hNZ0Va6KRRQrynaTJ720QusQfGQdCPAOMZch0
         5YP9PQFGjW1zSCRPG7qy/NYpDF8NQqnE91VvYGfY+l4fOvK8bqimf0QjVx/fwjWp7wqC
         QvwFKVgK2U9oXz7BrwxzdDjOyeOQW/qK5s7VoGuX2aw2CasboVtnlGldSGNJzCljRT5g
         p78z03sOec+drzNUhjruYsZuyARiP5nG60NlwtckDEvbzbee+K0Xd8166q9bC7K4c7C4
         8V3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TebrMZ8btxSddytLKHdzrNwlcgpPXsDhI4q8/8UlblY=;
        b=piX0gTjr5hcKHkWiziK++XCO6ThAk2NyTKz0FhV1Zjv2ev/6OSkVMQbDR4cLOgobYl
         kUz3i3JSDGUgSbgysDj9fl3Q5BlUhhwHHRWApJu74DjEmNh+u2hxAcXlESc85whRy2Pa
         MFhdRJDjmArKP/HgDqA95wYXLams8OHj637eovoqvGVIehx0bren0HNPww6//69nlfs8
         g2UmQUVwaQfpawVo9b/kOenFW5Su/L//Uyv2GcD5Wr/S9NsaHEFP48lj1vPXt+bwejcD
         n1J84EpKIN680hPe0Qy76NwgZu7IgyKWdFVXcBkM1XabFoVXfbZyksSGu5Ecd3gyCwqM
         2syw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=d6QGp6Xm;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 205.233.59.134 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TebrMZ8btxSddytLKHdzrNwlcgpPXsDhI4q8/8UlblY=;
        b=Fo4ZOoaWyjivJDt8TRnhur8r/xHKG2/TNutdsDn7Q1SJT3ZhLaX6SbSdjC41VKRwsL
         ZoWBs1aiqNP/knC3TuErgd4gmyU87OZwIRozCBPDMZQiITuaAsCpQjpC8MTz/7Ghljhr
         eEw7opKeDQPcFwOZkOv5x1qGlYx0/56hWjhtRclSkFunxkcyBU91RB3sDhvUx1Gr4jwE
         yYQ3DfDDHfpPfxyuJQ4rbn8yDRSsuI/gV2ZCDJlJA8E9jO2IOL1/sbLgXI8My9+ECO0D
         5YnJVNbkZHfDieHMH56I/qcVACNqvjj8zuWEBMAOnYg3M34J8XpYVevsaciUkWXcJZBF
         w3Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TebrMZ8btxSddytLKHdzrNwlcgpPXsDhI4q8/8UlblY=;
        b=C74R+3A45IfdqJ2+mZvv8j2Y/wy23V3HSpvZDsVYDklSbYRzHBiW0/ZRlHzcNTjwRZ
         9illMVaAGEYscrg/6VPyVdKd7hf6el7PkIqKUSso1Idw5NFoXxgcrvNP3oT/nTbkwUWc
         lOE7CAv2lufroN8FWjtkBcAZdeBz8AlBDYchO3f6WpfzdakJwalfeU6BDue0TFYGRYJU
         miZXwb+oP2ZqmU1d8ifrZuTq6dutMPJJ+Za099pJ2wcHsPNcDVVXA5gG2ZLWVmmKSwv9
         Z+KWOv9P+DCIjiscJEOxhQUxCT8+GInX7w1Nwuse41yH1mInshdaoW+y+jx1IglRF1iR
         tE2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PEhKadhlsw5oZQsV0ZK2SBgedD8vaeR6Bsk4qsyhh6jyB5FkM
	RZQIImv6HRVmXhS0HDw+YFE=
X-Google-Smtp-Source: ABdhPJxKVKTtH/qWKjiUixWPMexBaKRftYig2s4FS5ZJ4gxKYqxShvKN/vMyE8ZU6UbwVU+HORLu+Q==
X-Received: by 2002:a17:90a:fe83:: with SMTP id co3mr3981058pjb.62.1590147495448;
        Fri, 22 May 2020 04:38:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d90e:: with SMTP id c14ls539219plz.0.gmail; Fri, 22
 May 2020 04:38:15 -0700 (PDT)
X-Received: by 2002:a17:902:694b:: with SMTP id k11mr14971391plt.59.1590147495068;
        Fri, 22 May 2020 04:38:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590147495; cv=none;
        d=google.com; s=arc-20160816;
        b=PYtXA4dqRTCzPoYJnom0bxzjXXroo4AOHZMz+Nl3TSR/vGMoIILAG7m1qdAtHURI5x
         0Q5ApaHvwaFFDZsvYiuFtaurCGQJsyQzh/XFIlet7ssJdKHfazR2qcgsQ4dBvytWUEKO
         OQaZLCNRrDWMW/j01MV+6gHA9LqLSeOsY4sXJ/QB6dLNC/6++lJcxEAnIc0mtFImUXaZ
         LtigY/anXmSor+r0xHayn0Zx0Qj/NwR5w5oA32tv4DByZMtXwZCpdhl+j/dcTdCiLxwY
         emW/xUfqZwRzhZRK9o+8iUlzdfj1JNv9+qbGQfpOq3tidNgPtqSomfWYAoPs3EkHKyX6
         sidg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XH1Yj5aOcR07TnTGoIfuiVoH/MNimUictOSMhtQ2KiY=;
        b=MhJiVJ000jnlJgGNIVY5d4/mvDXWGJ5xi54MzC/GT497ahOkK2yA1VfuRiQ4usV6jv
         Nb8p5WZ73Z5SO0nKdB5EkcAmPNR7+186ZohTS0fYljE3AJax7wMWMWoCmNwXxNxSOmZT
         3HCcMI8hbiioo2KCV/SkCWqzN9O+S3wqoTIel7l6sRy/8EkgmqfA5hrXeBLBiNntlCuy
         gjAidnbZvcm1jWBhIZ5D0TZDd+uTsagoWCzSMS0DtvjUvwzA40AayvnkOFd7OOXfyB7P
         MFCptB7kIQTDRuKjphWtq5/X+cnI4zH5FwHCC55mNV5A1Dk43iOCoZyGNgZsdis4djRJ
         RRmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=d6QGp6Xm;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 205.233.59.134 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [205.233.59.134])
        by gmr-mx.google.com with ESMTPS id c15si996994pjv.1.2020.05.22.04.38.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 May 2020 04:38:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 205.233.59.134 as permitted sender) client-ip=205.233.59.134;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jc5xy-0007dX-JN; Fri, 22 May 2020 11:35:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2D6EE300478;
	Fri, 22 May 2020 13:35:53 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id F2D12201479A0; Fri, 22 May 2020 13:35:47 +0200 (CEST)
Date: Fri, 22 May 2020 13:35:47 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org,
	will@kernel.org, clang-built-linux@googlegroups.com, bp@alien8.de
Subject: Re: [PATCH -tip v3 00/11] Fix KCSAN for new ONCE (require Clang 11)
Message-ID: <20200522113547.GL325280@hirez.programming.kicks-ass.net>
References: <20200521142047.169334-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200521142047.169334-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=d6QGp6Xm;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 205.233.59.134 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, May 21, 2020 at 04:20:36PM +0200, Marco Elver wrote:
> Arnd Bergmann (1):
>   ubsan, kcsan: don't combine sanitizer with kcov on clang
> 
> Marco Elver (10):
>   kcsan: Avoid inserting __tsan_func_entry/exit if possible
>   kcsan: Support distinguishing volatile accesses
>   kcsan: Pass option tsan-instrument-read-before-write to Clang
>   kcsan: Remove 'noinline' from __no_kcsan_or_inline
>   kcsan: Restrict supported compilers
>   kcsan: Update Documentation to change supported compilers
>   READ_ONCE, WRITE_ONCE: Remove data_race() and unnecessary checks
>   data_race: Avoid nested statement expression
>   compiler.h: Move function attributes to compiler_types.h
>   compiler_types.h, kasan: Use __SANITIZE_ADDRESS__ instead of
>     CONFIG_KASAN to decide inlining
> 
>  Documentation/dev-tools/kcsan.rst |  9 +-----
>  include/linux/compiler.h          | 54 ++++---------------------------
>  include/linux/compiler_types.h    | 32 ++++++++++++++++++
>  kernel/kcsan/core.c               | 43 ++++++++++++++++++++++++
>  lib/Kconfig.kcsan                 | 20 +++++++++++-
>  lib/Kconfig.ubsan                 | 11 +++++++
>  scripts/Makefile.kcsan            | 15 ++++++++-
>  7 files changed, 127 insertions(+), 57 deletions(-)

LTGM

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522113547.GL325280%40hirez.programming.kicks-ass.net.
