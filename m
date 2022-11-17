Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLUH3ONQMGQEUS5WEII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0498962E994
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:28:48 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id q89-20020a17090a1b6200b0021870ae78c7sf1851975pjq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:28:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668727726; cv=pass;
        d=google.com; s=arc-20160816;
        b=YepOPiYbaSoWdf2HKHZvpIWTOTR5dGP6B6olaQWrTUFkzdZ7DEh9dSZGtre5HX46pU
         z4zWf35FX1F3UARjGpXoPZo9WroqxBlEN7e8cHSO0J0jwzlZ2KLN9FQc6NksF/gIqbZB
         3IBmFdjx3Xq4LvJoZuzr7iQ1fdu9i2Xct5sMCJk/nh1bNK1HG8T70V9xwyPKMdbVaYsL
         XZ9I6DYX2nu3mjH4jAns6RaKTCQUkkGb5JpIxIWPOlu9HBCBxh+nq0m8UypTd+dr8xEe
         SkeJWsav5r7zhIfjiknZZECaFd/QNgFXZMtM14dEgkUpTg8kMc/+Ua1MypS9Ugdib4L9
         aFQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=aRiJ0fbwGVq/V8IFBNsE3dYG4CJw4FLqviUD7ySuz6Y=;
        b=UDIO+fB9nIirYk7xlBknQKQPGYnX9P4mQr49dlRJWXKINysZd0vGgiTixIQEiBfpzO
         y6tyShwE/M6jNWimDjhS9+XhchC5rOl5YHslnyrHms00e1IOBiwIZU4VHwv92Yiq1Vws
         jhu/FdMFNNc1nROw6jI3D9QEOSCqRPDJ48n/cA153H5c8vVs5RCLmSxYKDShcCYYRJ4Q
         xblloocc0z5+Y8uyFZhqXtd4JN/vbY5AM0PNhSpUwSDSG8JuEbp9uh8NfgqEELcP6EmH
         /XXDtmOQpcIG5VmuROnldxOCZAroRJyG0tCjaisu8MK36WX5U0phUG5xsK9q+7w3Up1Z
         fhvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lj3JmYhm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aRiJ0fbwGVq/V8IFBNsE3dYG4CJw4FLqviUD7ySuz6Y=;
        b=N7v3WJi+ran0OV0ub6fwPR7BCELc/PB5Fik7xDIEsfiMsDdRJfoH5B/Rbh9KIaz75T
         VVGlhT5whMMkhF6kjxE2b8QQx5DKSH1IkRTSlDOg1SHt5ih6+RTJF0ifoyi5Cuq+8p67
         uiKwry/0HVTELFJVl3gFfc0rQls+Fg33VuGU0SN3j7695snLwXNchvBeDtly/JT/X4CZ
         vJ9NCwBmVJ4oqhuyHlyCFvahZ6Zz49diat4XAnQW407DOI1mdHvqMcnX2Jg+MrGRLyhi
         pwZEn0kojuL1uAcCmIHU+mJcOwHVthfY660fUW3GTGJD7v8Z8/3xTJz2iB9P9Ppx/WsH
         CQJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aRiJ0fbwGVq/V8IFBNsE3dYG4CJw4FLqviUD7ySuz6Y=;
        b=VkAkEU+8IXGgs+BFB9VXVSsYWmh7jSk/rY6ZFGM0Unt71ra4YPuu3NOr8ytnj334O8
         gcYXbCucH8/UAMOIji8ASyxEHe5rupB2UWm+Sks40TnUOtGXY2sJH0KToy2NXRl3x7bH
         LBc0sKouazFbcvfcyUpAykqcpvFU8v+lhM+PbaZa3BzNV7z2QcfTE9asRF+AMWsSeeBf
         nUOSrSmpA7naWla9IB7GYsPgKocuvIp2N/zYtUOD0D4Ipgt52COLqPpcj3qxKixnI6t1
         YPyaPvn6uii+VrflqoVOlTr59lzrD9IL/8wrR9Sc77w44hCS+8Ysi93BZBxuA3H/EaO7
         EdeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk/wMh+r5vh+8Dnq6B5GMvjTIgC6MMeiAKmGOhDDKnckfHy8CVC
	rZXfOiFiRjkcKYMIrttRfeM=
X-Google-Smtp-Source: AA0mqf5g0Gv+juk4uHU0CE49GteOiCSS9hlEtBHXX9SHNF0/8e4f7zov2p69QMQVQTaEVNQMSey50w==
X-Received: by 2002:a05:6a00:27ab:b0:56c:71a4:efe with SMTP id bd43-20020a056a0027ab00b0056c71a40efemr5062168pfb.84.1668727726352;
        Thu, 17 Nov 2022 15:28:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:300e:b0:56b:696a:9a6a with SMTP id
 ay14-20020a056a00300e00b0056b696a9a6als1675056pfb.6.-pod-prod-gmail; Thu, 17
 Nov 2022 15:28:45 -0800 (PST)
X-Received: by 2002:a05:6a00:1892:b0:572:b324:bbe9 with SMTP id x18-20020a056a00189200b00572b324bbe9mr5143679pfh.57.1668727725606;
        Thu, 17 Nov 2022 15:28:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668727725; cv=none;
        d=google.com; s=arc-20160816;
        b=oxju1iWDPf/kEtQ7RPxq+r2ctqzixXwYZ+RlLHfxMIFqt7Yie0X1LK5n/G3SKnXVmz
         uy7pLFIXFsD2n3StkZFfudMNRNLMFemR8x4q0jNSlC43kJBKMzaAhgkD5F2Ic1ieoDe2
         O7P5fAVyBaXC3QeIq7I3ujtaYWpVHdEIG3W+R57D9kh6+O+SbtgM0gB5Vws5ee3VjLpR
         XZmMTHxAxOzag0NvQpiU3/KEePscA9wzMhwMM3pv4yICakXfQVE23LEM9afjaNoP6lW1
         QcgAuLg9onZs9yxfmrymz3h3cHPoZenFdkUmzGvgF803qxFLWGBCa/kfiIL87VWdJjjk
         tbBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FcOLKLI7Dm9mEvWr+m80g8x+dHIAf7454LwMBIEgBJs=;
        b=d6BdC5GWICzhFEOBmbJxJ4rZlvHb+a9wrCrg6JzCZa9xIaSdi3BYarPGPndg8s9MQy
         fxWr1Ee6lbePa+mAhbKaUr9q62vnXaUBHPWrAlPbkFHV8e73cb0ZLWdbLFxmp1t2O0q3
         O3jvDJ5F60KNT7DY8hYn4gtshDYcYmlvIzWmrlB+n4yqdi1yegOG8PSrM62T6CrmBumw
         WSqHa3tfm+0ABtyu7UYYwxbV+ZrBu8NgemDnv/rPVFWurphbIMjk6l8x81GR+zOTSOLw
         IsVKtAJgZ3LoKJoAklydOQSzrCmdmYlux9E8BOUDvbqgAPGdfhLy4dLlI7PsKjjyjyfT
         aiGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lj3JmYhm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id on16-20020a17090b1d1000b00213290fa218si109914pjb.2.2022.11.17.15.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:28:45 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id jn7so1196523plb.13
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:28:45 -0800 (PST)
X-Received: by 2002:a17:902:f651:b0:186:b5c8:4c8f with SMTP id m17-20020a170902f65100b00186b5c84c8fmr4827739plg.124.1668727725304;
        Thu, 17 Nov 2022 15:28:45 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id y15-20020a656c0f000000b0046f7e1ca434sm1643826pgu.0.2022.11.17.15.28.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:28:44 -0800 (PST)
Date: Thu, 17 Nov 2022 15:28:44 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Jann Horn <jannh@google.com>, Dmitry Vyukov <dvyukov@google.com>,
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
	Andrew Morton <akpm@linux-foundation.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	David Gow <davidgow@google.com>, tangmeng <tangmeng@uniontech.com>,
	Petr Mladek <pmladek@suse.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 4/6] panic: Consolidate open-coded panic_on_warn checks
Message-ID: <202211171528.DF818B1CB6@keescook>
References: <20221109194404.gonna.558-kees@kernel.org>
 <20221109200050.3400857-4-keescook@chromium.org>
 <CANpmjNNrYDNrRR8i+8xAFnmSjZ0Rdp-P14Sf9d+dadfsik18QA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNrYDNrRR8i+8xAFnmSjZ0Rdp-P14Sf9d+dadfsik18QA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lj3JmYhm;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
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

On Mon, Nov 14, 2022 at 10:57:15AM +0100, Marco Elver wrote:
> On Wed, 9 Nov 2022 at 21:00, Kees Cook <keescook@chromium.org> wrote:
> >
> > Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
> > their own warnings, and each check "panic_on_warn". Consolidate this
> > into a single function so that future instrumentation can be added in
> > a single location.
> >
> > Cc: Marco Elver <elver@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Peter Zijlstra <peterz@infradead.org>
> > Cc: Juri Lelli <juri.lelli@redhat.com>
> > Cc: Vincent Guittot <vincent.guittot@linaro.org>
> > Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
> > Cc: Steven Rostedt <rostedt@goodmis.org>
> > Cc: Ben Segall <bsegall@google.com>
> > Cc: Mel Gorman <mgorman@suse.de>
> > Cc: Daniel Bristot de Oliveira <bristot@redhat.com>
> > Cc: Valentin Schneider <vschneid@redhat.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Luis Chamberlain <mcgrof@kernel.org>
> > Cc: David Gow <davidgow@google.com>
> > Cc: tangmeng <tangmeng@uniontech.com>
> > Cc: Jann Horn <jannh@google.com>
> > Cc: Petr Mladek <pmladek@suse.com>
> > Cc: "Paul E. McKenney" <paulmck@kernel.org>
> > Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> > Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> > Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> > Cc: kasan-dev@googlegroups.com
> > Cc: linux-mm@kvack.org
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> >  include/linux/panic.h | 1 +
> >  kernel/kcsan/report.c | 3 +--
> >  kernel/panic.c        | 9 +++++++--
> >  kernel/sched/core.c   | 3 +--
> >  lib/ubsan.c           | 3 +--
> >  mm/kasan/report.c     | 4 ++--
> >  mm/kfence/report.c    | 3 +--
> >  7 files changed, 14 insertions(+), 12 deletions(-)
> >
> > diff --git a/include/linux/panic.h b/include/linux/panic.h
> > index c7759b3f2045..1702aeb74927 100644
> > --- a/include/linux/panic.h
> > +++ b/include/linux/panic.h
> > @@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
> >  __printf(1, 2)
> >  void panic(const char *fmt, ...) __noreturn __cold;
> >  void nmi_panic(struct pt_regs *regs, const char *msg);
> > +void check_panic_on_warn(const char *reason);
> >  extern void oops_enter(void);
> >  extern void oops_exit(void);
> >  extern bool oops_may_print(void);
> > diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> > index 67794404042a..e95ce7d7a76e 100644
> > --- a/kernel/kcsan/report.c
> > +++ b/kernel/kcsan/report.c
> > @@ -492,8 +492,7 @@ static void print_report(enum kcsan_value_change value_change,
> >         dump_stack_print_info(KERN_DEFAULT);
> >         pr_err("==================================================================\n");
> >
> > -       if (panic_on_warn)
> > -               panic("panic_on_warn set ...\n");
> > +       check_panic_on_warn("KCSAN");
> >  }
> >
> >  static void release_report(unsigned long *flags, struct other_info *other_info)
> > diff --git a/kernel/panic.c b/kernel/panic.c
> > index 129936511380..3afd234767bc 100644
> > --- a/kernel/panic.c
> > +++ b/kernel/panic.c
> > @@ -201,6 +201,12 @@ static void panic_print_sys_info(bool console_flush)
> >                 ftrace_dump(DUMP_ALL);
> >  }
> >
> > +void check_panic_on_warn(const char *reason)
> > +{
> > +       if (panic_on_warn)
> > +               panic("%s: panic_on_warn set ...\n", reason);
> > +}
> > +
> >  /**
> >   *     panic - halt the system
> >   *     @fmt: The text string to print
> > @@ -619,8 +625,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
> >         if (regs)
> >                 show_regs(regs);
> >
> > -       if (panic_on_warn)
> > -               panic("panic_on_warn set ...\n");
> > +       check_panic_on_warn("kernel");
> 
> What is the reason "kernel" in this context? The real reason is a WARN
> - so would the reason "WARNING" be more intuitive?

I'll rename "reason" to "origin" or something -- it's mainly to see
who was calling this when it's not core kernel logic.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202211171528.DF818B1CB6%40keescook.
