Return-Path: <kasan-dev+bncBCF5XGNWYQBRBAND3ONQMGQEMS45BNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id AADE062EA3C
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 01:27:48 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id y18-20020ab05b92000000b0041893919450sf1306057uae.4
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 16:27:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668731265; cv=pass;
        d=google.com; s=arc-20160816;
        b=fhVmbLw0rsFKBY5+PUF8g7a6dlaeMhx8FigjwqqJKGUSBW9spVO6kvKfPP2qREXkZ8
         L7+Io/wNu1ic47ny7mcJm2vxyqSWknVOoBh0BBd90ZMNgF+7htNKzjY3lHhe/zklwjsi
         LJVfuxkVj9oW2jJ5zNAkmU1Y9/WxzHlF7joHYz29394uEI1mTN5AwVngmy2ovL9zsJrW
         YPWMq9ODIJ6ki+5DyGc1eWEq53qsedn8nYZTYmH8b/YBYmmUMWY9sIuBASqjaepmrSkk
         CtPYXMv8UubcEhUw9vkW2lX1a+8f9ozgDyyXcCw0dIZn1/OlhvFTjxTbvWti0A27wGXb
         jPPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yC/N61s0Eyoq3GqMkp6HEqr/aBYp+p4yMgusWOSJMVs=;
        b=Q1N6soWyY2Uy4oKwy9A93AbahDTA/HryLAHkyIXOLbGUFA0Hn471y5nNb0tANetYQr
         t5V7GiQujE4Dk3bVwqMcYYQ367DiAfVkXpNTeZvH9/4aILs7R5PmMKyDDuQNx4BLBj5/
         F6xJLbLx1vdCQIe26MtItivbqrBGd4oYF1GrmgLQtofEFrVkX1uVgTBTiJMVpZrmyrd9
         d73WahG+6Ccid0IFSODa+r0Cl9cpnn2QlK2o9LUzAaEpH257FrS52Mb3XYx+c19+z26v
         JRhVBjghLCrLG+iSvFVtghEiF3vWOA/YIchgRc2YtTSaG4dahAF8qDb+TAsi2w9pM1sG
         ZwxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=b785W2M0;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yC/N61s0Eyoq3GqMkp6HEqr/aBYp+p4yMgusWOSJMVs=;
        b=aaCwgSpR/5UoeXzeU+fF+pEhXUNpWRmUbQ57nJKj8YbayMDU2V0XhuKxfUDcH7wzWz
         Ex9GnH6GNZzXeKwsNQpLnlFUifaI2jdMYzAnq3tpWBcwHxB1SkXIyuuuOMHOr/aXspvK
         JgmfKA82Hc+oGSW4CTVnlAmSgJBFkOyNR7m4r9PCTSvALziTRmrxrhYEay0qTEO8d1eR
         k0iMXglS/4wCCurDS3LeJ25WhNf7cXu0znpux99Bp7MxcBNH0SJPnKyZeOgGFsPfma7E
         CM40JcoE5EqGiaPj3E5DbjCoHWYs+hiERFDuqggbXxpSf57cItmaDACTFE4VMuFRaeNU
         MmIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yC/N61s0Eyoq3GqMkp6HEqr/aBYp+p4yMgusWOSJMVs=;
        b=kH4GHMfDuImSc5esusAuMw3OD/2CP/AmYF+9/LPkFvrAlcsrPCMRZEK3XxhftPnU82
         X81RKBYLSNHjE/134lDU7eSnkg4oCcNSHQNNmiu77dqxtO09+/rycbSUWgmrhTbb/D7G
         dJcqgu8GtPjtjrQmW/hyb1DcYr7NL74/bo814yVXCJs64yhVsTdeTOlSloSBE7t871Dn
         rUc208qQUuwR+ZXJHuzKAoRBkmt3spXEkjGKTk0OvxIxQYVthB8bKbR3StNNq1meU84k
         txJWrQxQLUTJCZQ5SJB41ZBZjg30lFxgFPe5Pc8jxPhc2SYlwMkLbh14xPjpYKkAjRzp
         S6jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkk+G1l1QhDamG+fmZtBFZUWaqsG9QikTwlsBNlvNawuZ5Kj3pG
	ze6AGqnRI5paSWpSPGQmQLQ=
X-Google-Smtp-Source: AA0mqf4yj3MXbs1w4QIMlCEVsmJw3sUm2JFrfr/1lAtwVbUl/F4j3tvL6LiJELmyubtWkcZWOZv2qg==
X-Received: by 2002:a05:6122:2167:b0:3b7:a73:44a with SMTP id j7-20020a056122216700b003b70a73044amr2899787vkr.32.1668731265323;
        Thu, 17 Nov 2022 16:27:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dc8e:0:b0:3af:54e7:dbd0 with SMTP id g14-20020a67dc8e000000b003af54e7dbd0ls848925vsk.0.-pod-prod-gmail;
 Thu, 17 Nov 2022 16:27:44 -0800 (PST)
X-Received: by 2002:a67:fd9a:0:b0:3af:f394:588b with SMTP id k26-20020a67fd9a000000b003aff394588bmr2872407vsq.61.1668731264720;
        Thu, 17 Nov 2022 16:27:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668731264; cv=none;
        d=google.com; s=arc-20160816;
        b=uDv6DcoKlZmzDw/NRo2iuglG3g0cuFzPBSll4PeYslHfJkSw3fGj0gC8WrLXT05/xM
         gXJ2WJWT69gUMVf0ukiJ1qZrOBfpp3Wa6Uyr+11DXc21EcnhG0bTtyBMPx5ILwEFLqLc
         022h6z8HL5uCa6KrzetgJ/l+ZxIHjC1DyXGY5FRGKhbVzUywcjnsbRk49wknlc2/lOOR
         pkmaZGQgEFrbB54ktdemeXaFKORJE3I16Yt+5Qpil9vD27Uv/iXwIVuFSBsnrMf5J7FL
         EOTCUHvS0vzlRBbpCPstdlPjh0tvwxvOj2qUneSVCLEP+xfHEScGYRrAPu1mkppiujeb
         kXvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Ztxf/N067AkE8cSn/2kvfcuUb/GtHbfVkaEhVKHtSlA=;
        b=vCcCd7QQCix8/T6W6goIVtiTXKhtH1zIQeivBPXqGdzu6pUqh37Fm0oFFy4sI3hGXn
         MEYGphrdiBR/6CZ5xBWj1xjhEfwtaLRD/mNBIWLq+XCPwvu1E0GmhVjDsdOiM4RVU8Nv
         PYnC5FjmLmKo95jBMsn6XNR/pumnL7jmVLIdGTsgdsEbid1tPe1N10rb4Wf4W0F0tD7g
         +xlm9JvFlZv+BNzHhuvFM4FfFXSJU7Jbozbo2V0kHIhUP/HcTjvMGLWtsbM6jVMOOnQf
         rahb3WJza/f5A0ALzzIbxd973C4II0DnfjMwLMI09U1ptDXXcG3sDNVp5vNv40LzQ5jY
         EBew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=b785W2M0;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id az3-20020a056130038300b00414ee53149csi381285uab.1.2022.11.17.16.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 16:27:44 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id k22so3384814pfd.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 16:27:44 -0800 (PST)
X-Received: by 2002:a63:fd08:0:b0:46f:ed91:6664 with SMTP id d8-20020a63fd08000000b0046fed916664mr4319364pgh.558.1668731263832;
        Thu, 17 Nov 2022 16:27:43 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u12-20020a170903124c00b00186fd3951f7sm2011902plh.211.2022.11.17.16.27.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 16:27:43 -0800 (PST)
Date: Thu, 17 Nov 2022 16:27:42 -0800
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>, Petr Mladek <pmladek@suse.com>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-doc@vger.kernel.org, Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH v3 5/6] panic: Introduce warn_limit
Message-ID: <202211171627.CFC188B@keescook>
References: <20221117233838.give.484-kees@kernel.org>
 <20221117234328.594699-5-keescook@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221117234328.594699-5-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=b785W2M0;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Nov 17, 2022 at 03:43:25PM -0800, Kees Cook wrote:
> Like oops_limit, add warn_limit for limiting the number of warnings when
> panic_on_warn is not set.
> 
> Cc: Jonathan Corbet <corbet@lwn.net>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Baolin Wang <baolin.wang@linux.alibaba.com>
> Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
> Cc: Eric Biggers <ebiggers@google.com>
> Cc: Huang Ying <ying.huang@intel.com>
> Cc: Petr Mladek <pmladek@suse.com>
> Cc: tangmeng <tangmeng@uniontech.com>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: linux-doc@vger.kernel.org
> Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  Documentation/admin-guide/sysctl/kernel.rst |  9 +++++++++
>  kernel/panic.c                              | 14 ++++++++++++++
>  2 files changed, 23 insertions(+)
> 
> diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
> index 09f3fb2f8585..c385d5319cdf 100644
> --- a/Documentation/admin-guide/sysctl/kernel.rst
> +++ b/Documentation/admin-guide/sysctl/kernel.rst
> @@ -1508,6 +1508,15 @@ entry will default to 2 instead of 0.
>  2 Unprivileged calls to ``bpf()`` are disabled
>  = =============================================================
>  
> +
> +warn_limit
> +==========
> +
> +Number of kernel warnings after which the kernel should panic when
> +``panic_on_warn`` is not set. Setting this to 0 or 1 has the same effect
> +as setting ``panic_on_warn=1``.
> +
> +
>  watchdog
>  ========
>  
> diff --git a/kernel/panic.c b/kernel/panic.c
> index cfa354322d5f..e5aab27496d7 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -58,6 +58,7 @@ bool crash_kexec_post_notifiers;
>  int panic_on_warn __read_mostly;
>  unsigned long panic_on_taint;
>  bool panic_on_taint_nousertaint = false;
> +static unsigned int warn_limit __read_mostly = 10000;
>  
>  int panic_timeout = CONFIG_PANIC_TIMEOUT;
>  EXPORT_SYMBOL_GPL(panic_timeout);
> @@ -88,6 +89,13 @@ static struct ctl_table kern_panic_table[] = {
>  		.extra2         = SYSCTL_ONE,
>  	},
>  #endif
> +	{
> +		.procname       = "warn_limit",
> +		.data           = &warn_limit,
> +		.maxlen         = sizeof(warn_limit),
> +		.mode           = 0644,
> +		.proc_handler   = proc_douintvec,
> +	},
>  	{ }
>  };
>  
> @@ -203,8 +211,14 @@ static void panic_print_sys_info(bool console_flush)
>  
>  void check_panic_on_warn(const char *origin)
>  {
> +	static atomic_t warn_count = ATOMIC_INIT(0);
> +
>  	if (panic_on_warn)
>  		panic("%s: panic_on_warn set ...\n", origin);
> +
> +	if (atomic_inc_return(&warn_count) >= READ_ONCE(warn_limit))
> +		panic("%s: system warned too often (kernel.warn_limit is %d)",
> +		      warn_limit);

Bah. This should be:  origin, warn_limit.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202211171627.CFC188B%40keescook.
