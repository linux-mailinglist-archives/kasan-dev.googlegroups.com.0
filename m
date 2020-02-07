Return-Path: <kasan-dev+bncBAABBJX263YQKGQE6JYXZEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2384E155EAC
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 20:40:24 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id k10sf223745ybp.4
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 11:40:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581104423; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGpbDZZ1Jo+EDtRcbPCTIqpE+EgXs9hjBdqUGyNpq4S7xHRuo+RntEawrPPZnZ5qhh
         Rz6XlrPci7HiNalhdMyamCWYiibFQZHNFuL0SuuP4sa/pO24sia1m4jdbNiw9pJUsMbK
         ECIjCAgFKsqCyRDo4Ix1XDRCZJJaxEWckXwsh2odTZMr58XD1BlX2MfDJ1fV8dXdaz1p
         w9oyn+Mw7Xm4urddOpJPzCVQ0OoMe2Ced+scpradyl6vsIDIcCw4d/KeYUx0+1m0jaXH
         CR1J/LRHgMFPVjdLtX/IMgPyLbaDxDEv7cbhmFCyIuB+2v/K0G1QjMlr3L2WsIKxRm/s
         wBWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=j4GDyOWd4I3NEKrab3NFGciVlJRdlyeX9RoANHB653U=;
        b=ZItGc7w0XFITCqypQYt71mxdxM7xE0jYtEDbzEexW+76U/yR18j8okJlooiPMDN6ED
         bMyzLQnbnzZ//F9clSVL0Y6ee9x4mr8lT9I4xZhYnGAYlhzhexqHlnSEd2pvI7Qx+L1a
         tD1crA53JpNm+5f96InDpou8JsFWuJhJOvpAOKp56auoc7SHF7k6EFBSNHEvW4HQKWNO
         Y3tzuHtNofyZKoJIx4//CyGo0R1qYiSO8n8QLQrowX7D0i5DbzdJqRQa5pn0ZMrobTlM
         AH7XH8PApl/KOd5wDdELHyWIFGibMYDRITMYlZwVx3pqTqmTZhTmgqmCv/T/hvXCrbAq
         vEBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vkh70UPw;
       spf=pass (google.com: domain of srs0=yqfb=33=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YQfb=33=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4GDyOWd4I3NEKrab3NFGciVlJRdlyeX9RoANHB653U=;
        b=sShCbjHGbGuUA358EfYthC7uJutW6TSca8DJkuWaoDhewbVwwakEnZyXwu+cKlCG9V
         GmyQhFREdvEsNg2FpEVJs0+mprM9O6uyjmR7czG8YTfBOF/QZqdOJ+z+Qy/ALt9L2/ot
         cLRAX8sjeBFqv9K1qPItp2RSPNnI+ZtRHT7ngqJ8jK2faNJW/uRncEbRy+5UnFuF6oaE
         yP0lSoWgyK/y31S9QmD52fJq7+xSK+8XgaZ8rXtuoobYI+vnf/YyQArcbfYDN0C2UKgx
         nA4yCtVBDXBucn9pOAK1eBztnC5JiUrIccqQYaBFiC0T/F0MvxhV6BHZ77isbXCKrc3H
         ol1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j4GDyOWd4I3NEKrab3NFGciVlJRdlyeX9RoANHB653U=;
        b=c2pjjQG+2sOCiokGgoCV2RPYk0PU/r80kcfw5Z4dO8lwvr4cYNey614Ry9AbMbRz+P
         cBSdMzCohpORmccs8njDvf6M3SZ9bzuCrzAauCh7tJRlC1/st5rFI6befKs/n71YLNlq
         Y/JN/FLndqEapW0UdlMN9OOIImgZNQ/GaCWFOSu/Z32ZniEURj48WEPGK8/dLv63Uu0s
         XSkTVdfOjFeV0tYaZXMhQpOHOL27jd7YfHwnmlvhFoNsUvFbcNV1JWQ4hn9gUiy4A58N
         JrMWB3PVXN4/PzBaJ2nmtbhfdcHlrGyG42XxjVP1zY0UIfSVfAkSn7jh0J6xlVAYwYz3
         Nt0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWYGt+6H023OmSbvOdVobVKSTbEnfb9+p5SQBXCpBmttIYJnilk
	gD/e/UULlPZ7bzhkw/luKL4=
X-Google-Smtp-Source: APXvYqya1yOnbbTWkL+1aSm3Zmp0cyg98/Iwcyz9VTleEed8Knc/uqH9C5n8sQHxeR8gJ2hi7ck3XA==
X-Received: by 2002:a81:3e17:: with SMTP id l23mr619779ywa.248.1581104422882;
        Fri, 07 Feb 2020 11:40:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:764a:: with SMTP id j10ls30628ywk.11.gmail; Fri, 07 Feb
 2020 11:40:22 -0800 (PST)
X-Received: by 2002:a81:138f:: with SMTP id 137mr662164ywt.364.1581104422594;
        Fri, 07 Feb 2020 11:40:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581104422; cv=none;
        d=google.com; s=arc-20160816;
        b=sgsPmjV6t9lMx87A7ypg/yN/MAI6GmNkhtB2D20pcDvREzeKJ2StTUvOHepuDNtBGC
         f4lZ/qEgKQpUmuQo4Gv9dlNQYav2gGOfxOGrpju0ICxGqTiu7Uy26WnKJ1nYvSoz+ik/
         b4QJqjbwIaVNQUdjarF6y0uImBhlWQBEjIkcNPao7TrRjosBYs2yOjaForOHBo1Zis2R
         6lRMu9EI8NkrwWtKYB0ciXc3MZXL3LzLm2n9K8QVw8N4+1MLwK1WqidTtijuE0v2tvYj
         rn8J8z7bOUiO5NkN3Xm2FkXUQ1Co2gezI+N4eU5tz9vHXGbhLqPQvoyMcgSH40l19b8b
         Kqyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=V91oaijQ8Rl49IpFIbW1Z7GeCZ2SCsVUSx52WBU4zlQ=;
        b=Y3BCGEBZpdb8XV+dBreuZ+LvjhBj2SdAXOGPGwgNIwR3/6PIadowyLjbE9OgG1ElL5
         9IuhVL041PHpP/Fv+pTtHvWVtCvt1Vqub3YL1nWz3BoiPpZsYj1pGLiCAODVQAX+nhEs
         TVF6MUHidlal1fikI0RWH60JDFyzRkrrbf1XSOaAL8BKohhythjkxY/WSW+Tb3zV4OB+
         yn/fNpPxRxptiNMe7PxAiQTAXjgHXD7lNNzFwy+9pz3peXUOeNnBDcPI8llZxNhKAbGd
         /rslcARUUUdplwvEgOUFfiHgUG6RqNmbliqAZEwQ7Cp7pNEhPw9C2ZMmO5gkWqaLpGnh
         wm9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=vkh70UPw;
       spf=pass (google.com: domain of srs0=yqfb=33=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YQfb=33=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p7si22880ybg.1.2020.02.07.11.40.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 11:40:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=yqfb=33=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9B5CD20726;
	Fri,  7 Feb 2020 19:40:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 641F535219BF; Fri,  7 Feb 2020 11:40:21 -0800 (PST)
Date: Fri, 7 Feb 2020 11:40:21 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>, mingo@kernel.org, will@kernel.org,
	torvalds@linux-foundation.org
Subject: Re: [PATCH] kcsan: Expose core configuration parameters as module
 params
Message-ID: <20200207194021.GO2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200207185910.162512-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200207185910.162512-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=vkh70UPw;       spf=pass
 (google.com: domain of srs0=yqfb=33=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YQfb=33=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Feb 07, 2020 at 07:59:10PM +0100, Marco Elver wrote:
> This adds early_boot, udelay_{task,interrupt}, and skip_watch as module
> params. The latter parameters are useful to modify at runtime to tune
> KCSAN's performance on new systems. This will also permit auto-tuning
> these parameters to maximize overall system performance and KCSAN's race
> detection ability.
> 
> None of the parameters are used in the fast-path and referring to them
> via static variables instead of CONFIG constants will not affect
> performance.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Qian Cai <cai@lca.pw>

Thank you both!

I have pulled this in, and have also rebased the KCSAN commits into a
separate branch named kcsan in -rcu.  This allows people to use current
KCSAN without exposing themselves to random RCU changes.

f60f0f543333 ("kcsan: Expose core configuration parameters as module params")

git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git

I just now kicked off a short sanity test with rcutorture, and will of
course do more testing over time.

							Thanx, Paul

> ---
>  kernel/kcsan/core.c | 24 +++++++++++++++++++-----
>  1 file changed, 19 insertions(+), 5 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 87ef01e40199d..498b1eb3c1cda 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -6,6 +6,7 @@
>  #include <linux/export.h>
>  #include <linux/init.h>
>  #include <linux/kernel.h>
> +#include <linux/moduleparam.h>
>  #include <linux/percpu.h>
>  #include <linux/preempt.h>
>  #include <linux/random.h>
> @@ -16,6 +17,20 @@
>  #include "encoding.h"
>  #include "kcsan.h"
>  
> +static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> +static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> +static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> +static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> +
> +#ifdef MODULE_PARAM_PREFIX
> +#undef MODULE_PARAM_PREFIX
> +#endif
> +#define MODULE_PARAM_PREFIX "kcsan."
> +module_param_named(early_enable, kcsan_early_enable, bool, 0);
> +module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
> +module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
> +module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
> +
>  bool kcsan_enabled;
>  
>  /* Per-CPU kcsan_ctx for interrupts */
> @@ -239,9 +254,9 @@ should_watch(const volatile void *ptr, size_t size, int type)
>  
>  static inline void reset_kcsan_skip(void)
>  {
> -	long skip_count = CONFIG_KCSAN_SKIP_WATCH -
> +	long skip_count = kcsan_skip_watch -
>  			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
> -				   prandom_u32_max(CONFIG_KCSAN_SKIP_WATCH) :
> +				   prandom_u32_max(kcsan_skip_watch) :
>  				   0);
>  	this_cpu_write(kcsan_skip, skip_count);
>  }
> @@ -253,8 +268,7 @@ static __always_inline bool kcsan_is_enabled(void)
>  
>  static inline unsigned int get_delay(void)
>  {
> -	unsigned int delay = in_task() ? CONFIG_KCSAN_UDELAY_TASK :
> -					 CONFIG_KCSAN_UDELAY_INTERRUPT;
> +	unsigned int delay = in_task() ? kcsan_udelay_task : kcsan_udelay_interrupt;
>  	return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
>  				prandom_u32_max(delay) :
>  				0);
> @@ -527,7 +541,7 @@ void __init kcsan_init(void)
>  	 * We are in the init task, and no other tasks should be running;
>  	 * WRITE_ONCE without memory barrier is sufficient.
>  	 */
> -	if (IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE))
> +	if (kcsan_early_enable)
>  		WRITE_ONCE(kcsan_enabled, true);
>  }
>  
> -- 
> 2.25.0.341.g760bfbb309-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207194021.GO2935%40paulmck-ThinkPad-P72.
