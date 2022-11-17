Return-Path: <kasan-dev+bncBCF5XGNWYQBRB7UG3ONQMGQELDDFLEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BE22B62E98D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:27:59 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id 4-20020a671704000000b003af7639515asf837873vsx.8
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:27:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668727678; cv=pass;
        d=google.com; s=arc-20160816;
        b=vOpmWqFlESjBEwAR+Dwr0g6N37X0XO8UgtLTbS65viiiei71fktSEJrtRUzpK5XH8S
         ClDikrxGHupexpSdtd7NS8rst+MVZec4E+OgLo+qykBFC05NlgF+JAZ5XMWzsq5sGvwn
         7bi9xjukKB0jlCLNuE02QvgDnSF5iB3jIp3Uu0ONLlzLPe0fDwKcJBWgHXBSBDA+hgSA
         FYMshhjqH/awMlrOjKos7kdcFRcNEoeAoUJPGDsGmHp1g0mmbBXCZPgGWLPTMCzX5in4
         JKTK+52R803+E4Slm9lY7VjlwwmOh0Tn44iy41/9giWO4vaLUKa3da5Gp0z5MYMgquCm
         eJDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oWTeCpq70aBk9qXXRca818TA6lnXNFlNSb5emC7g7uk=;
        b=qamQrZIC2KxjTbA0aiuayI9+pNyP8T5urlv8Ilop/nERow1ru6divmjyQasauQeuv9
         6VPuiX6ELgpEBNRK7wIUzaG5eHJwiJYKHmz20VhBX8I7795wh81Kh1Ipzk7hBqdR2KsL
         Af2wlI1vyeBhAqtYDGYlQdkYqLGWVD6NAoV8LQOnLXZGglh0bp0+QazGVlqGRVUJsjjS
         /iWigRToyudRERjagkLqmHCjAebKchB1MugtogHdTvYhemrXpA32XYC1drXfc7hV/PPf
         cSjoPy+wQUTGvpK0jJ6H+4V1d90MJvwvWZ6sHlJ1pJdprMGKOTFAiuj0x38P34dSfbux
         IO2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="lV/oOdWq";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oWTeCpq70aBk9qXXRca818TA6lnXNFlNSb5emC7g7uk=;
        b=fNaLWhn/55S0SUTuMa5iGUT0klUTT/QeNv8c9tAHv0L36+v+U1shNA+ZSoQfClAgEA
         wSkwE9cv8JjoW84lY9G/44lTrYoTToXHIMbnU2VyKO8gSPwDZi9NmSlZ+9V1q6bn0yPx
         SZzF6f16ia1dd8x2JFn4MRqI/gFVMBhBvi8BF7jrjLaIUWgmhXKxPFEbNswpjAief4KQ
         w7vx6U/5Vb3+If712lhz1pBn87vWI6OCBrbvNdSyhqVHx8F6kupZ0pYrLYn/YaBoZQ7X
         QoDeII+OvRPxWvPhGvlvKvVIu4wRrfL/VWSBEWnEBBzYf7jCg++beQ/j7gReszdmjTWh
         e9OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oWTeCpq70aBk9qXXRca818TA6lnXNFlNSb5emC7g7uk=;
        b=J8/RfH2gVafU3PnbFCav0MQFzt0DXUirfvC5RRX9SvFcAYMTrGPCqLFCY/3mAkTqWD
         DmSTf7+Cwjar9vC+sVbrSZftVfT5v3WKndTf3KTPjIL7WY6gVAF0P80fGOR9QxMz9exj
         i4ddmeonQ/Fgc0CdwRLuXz3R6ErUfpOyNTET4NtHja1QWnQX4SSN37r+NWJO6QDYJnZe
         QyWCiA0VzKcJAzls5CEgHgVxoLOMETGNdTYomwmmXRHabn8T/mJ7uMyxF1REHS0kZX9S
         SsPQ+nZdnBP7SvfGk5INidLTgpkpJa02F3B54VW8VojWvakJ56da8wV+2HcjylELuFWv
         x+Vw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnGkwuxcKPtlD+a+rgYyFwwma9o2DMWEItDG1aEDv9ExwSJMay6
	3QfUsS9AVwQhWmjfxjHx+/g=
X-Google-Smtp-Source: AA0mqf7oUUtNdnvTXJEuGfplLmUkNLk6Xxj8Ndj1TSf1c0UcLw1SF9M+86aUmd7xzfjSGkHg4V27hg==
X-Received: by 2002:a1f:9e08:0:b0:3b7:82e4:f3a1 with SMTP id h8-20020a1f9e08000000b003b782e4f3a1mr2755996vke.17.1668727678409;
        Thu, 17 Nov 2022 15:27:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e0dc:0:b0:3a9:e441:5ef with SMTP id m28-20020a67e0dc000000b003a9e44105efls812083vsl.3.-pod-prod-gmail;
 Thu, 17 Nov 2022 15:27:57 -0800 (PST)
X-Received: by 2002:a67:e013:0:b0:3ab:8a0a:a4ae with SMTP id c19-20020a67e013000000b003ab8a0aa4aemr3444463vsl.21.1668727677841;
        Thu, 17 Nov 2022 15:27:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668727677; cv=none;
        d=google.com; s=arc-20160816;
        b=T/i3hVDrJBeKi1L10HHqDGbsl1d+UIpoXbzL965hfA/2WiC5uYyQu2VqmB0j3b8ZRR
         aP4NWMmlIpjQFLSUQg0DmaPgollAg+KGsBLm8lIAZ/oRUAIY8M6v3w4ZYaRLZ2xAJdKV
         Y73UyN626UDBxYK19k7+kjkllB3CSFdUG19yUcOVV6ouFwGOsUzYiPnAw7kVuZ/ye2UY
         lmOX77N7cGo+NjxmPM1b5cyxaz34gCHlnybPw7Cc0GQ+EVqdBjkOZ06FnSvmH05RTt00
         IYqdE/O0/5gKTwkoSDgbAk5LPBGSOBMN3voPG67B5x7ot+bUBZvbMnPP/gNh0AMjlSsO
         2E4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+zOnZ+iVEe8Qzy0xCfuCuxCEDTF24JR1bRlLbEe2Zd0=;
        b=DKf6cHhBRsQeNXOnJEqMjHJFF5wAVe1OX7wheQ/kiXMYVUT6xi4cBEyyAhHtHJmGW7
         hobbEP2AzntfIXFq7giAUA0sCOcNFQVA5v7W11g4hxo+3wOWwG6nFiRwKrRPx5OKOQrE
         tTZp5eeSekLt/LN2Sr+3UDCF8IRorPv47/Nt7iNsFEf11moQhzSyrpg8LKyBcKMrkrSo
         AqkjZ3Z9p6vPkJTULGJM/wjh3DoBNIqpZcfusYgCgcPMuuAuAFYu0l5P9NlVb3AqCF77
         720zcMVYbj+ZHAvuMgDpHq5NQiLiurG358Hbu0QNy0EqcegZv5t/XPLdVmUTVG72Ug3b
         Dw7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="lV/oOdWq";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id u7-20020ab03c47000000b004181ba78c01si320886uaw.0.2022.11.17.15.27.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:27:57 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id d13-20020a17090a3b0d00b00213519dfe4aso3466723pjc.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:27:57 -0800 (PST)
X-Received: by 2002:a17:90a:c901:b0:212:fe9a:5784 with SMTP id v1-20020a17090ac90100b00212fe9a5784mr4887578pjt.91.1668727677220;
        Thu, 17 Nov 2022 15:27:57 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id o1-20020a170902d4c100b00186b1bfbe79sm2070434plg.66.2022.11.17.15.27.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:27:56 -0800 (PST)
Date: Thu, 17 Nov 2022 15:27:55 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>, Petr Mladek <pmladek@suse.com>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-doc@vger.kernel.org, Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 5/6] panic: Introduce warn_limit
Message-ID: <202211171526.5F09B6D3D@keescook>
References: <20221109194404.gonna.558-kees@kernel.org>
 <20221109200050.3400857-5-keescook@chromium.org>
 <CANpmjNO_ujNwaFxpsAWWXhBajhV8LJMXQjCHiSLHKG2Dc+od4A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO_ujNwaFxpsAWWXhBajhV8LJMXQjCHiSLHKG2Dc+od4A@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="lV/oOdWq";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1033
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

On Mon, Nov 14, 2022 at 10:48:38AM +0100, Marco Elver wrote:
> On Wed, 9 Nov 2022 at 21:00, Kees Cook <keescook@chromium.org> wrote:
> >
> > Like oops_limit, add warn_limit for limiting the number of warnings when
> > panic_on_warn is not set.
> >
> > Cc: Jonathan Corbet <corbet@lwn.net>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Baolin Wang <baolin.wang@linux.alibaba.com>
> > Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
> > Cc: Eric Biggers <ebiggers@google.com>
> > Cc: Huang Ying <ying.huang@intel.com>
> > Cc: Petr Mladek <pmladek@suse.com>
> > Cc: tangmeng <tangmeng@uniontech.com>
> > Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> > Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> > Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> > Cc: linux-doc@vger.kernel.org
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> >  Documentation/admin-guide/sysctl/kernel.rst |  9 +++++++++
> >  kernel/panic.c                              | 13 +++++++++++++
> >  2 files changed, 22 insertions(+)
> >
> > diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
> > index 09f3fb2f8585..c385d5319cdf 100644
> > --- a/Documentation/admin-guide/sysctl/kernel.rst
> > +++ b/Documentation/admin-guide/sysctl/kernel.rst
> > @@ -1508,6 +1508,15 @@ entry will default to 2 instead of 0.
> >  2 Unprivileged calls to ``bpf()`` are disabled
> >  = =============================================================
> >
> > +
> > +warn_limit
> > +==========
> > +
> > +Number of kernel warnings after which the kernel should panic when
> > +``panic_on_warn`` is not set. Setting this to 0 or 1 has the same effect
> > +as setting ``panic_on_warn=1``.
> > +
> > +
> >  watchdog
> >  ========
> >
> > diff --git a/kernel/panic.c b/kernel/panic.c
> > index 3afd234767bc..b235fa4a6fc8 100644
> > --- a/kernel/panic.c
> > +++ b/kernel/panic.c
> > @@ -58,6 +58,7 @@ bool crash_kexec_post_notifiers;
> >  int panic_on_warn __read_mostly;
> >  unsigned long panic_on_taint;
> >  bool panic_on_taint_nousertaint = false;
> > +static unsigned int warn_limit __read_mostly = 10000;
> >
> >  int panic_timeout = CONFIG_PANIC_TIMEOUT;
> >  EXPORT_SYMBOL_GPL(panic_timeout);
> > @@ -88,6 +89,13 @@ static struct ctl_table kern_panic_table[] = {
> >                 .extra2         = SYSCTL_ONE,
> >         },
> >  #endif
> > +       {
> > +               .procname       = "warn_limit",
> > +               .data           = &warn_limit,
> > +               .maxlen         = sizeof(warn_limit),
> > +               .mode           = 0644,
> > +               .proc_handler   = proc_douintvec,
> > +       },
> >         { }
> >  };
> >
> > @@ -203,8 +211,13 @@ static void panic_print_sys_info(bool console_flush)
> >
> >  void check_panic_on_warn(const char *reason)
> >  {
> > +       static atomic_t warn_count = ATOMIC_INIT(0);
> > +
> >         if (panic_on_warn)
> >                 panic("%s: panic_on_warn set ...\n", reason);
> > +
> > +       if (atomic_inc_return(&warn_count) >= READ_ONCE(warn_limit))
> > +               panic("Warned too often (warn_limit is %d)", warn_limit);
> 
> Shouldn't this also include the "reason", like above? (Presumably a
> warning had just been generated to console so the reason is easy
> enough to infer from the log, although in that case "reason" also
> seems redundant above.)

Yeah, that makes sense. I had been thinking that since it was an action
due to repeated prior actions, the current "reason" didn't matter here.
But thinking about it more, I see what you mean. :)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202211171526.5F09B6D3D%40keescook.
