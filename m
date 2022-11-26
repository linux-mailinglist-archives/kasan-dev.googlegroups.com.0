Return-Path: <kasan-dev+bncBDW2JDUY5AORBVMQRGOAMGQEKLP7NPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id B26B9639761
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 18:09:43 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id mh8-20020a17090b4ac800b0021348e084a0sf7652359pjb.8
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 09:09:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669482582; cv=pass;
        d=google.com; s=arc-20160816;
        b=zPsrWjQtzZ3numh2rhTi75z4djGiuuQZPb1tXET4wMOLz6Q8gTX698cGg0QWYQ8LPC
         wRSLBa1Z1beFCVlVDOG2Lpcvk08iXKwhwZlnaG2ot8JlXqX7XS+ocUvWPLrP8Da7THew
         fgJ2BNUis0Dc4XjXf7lf9R0u2fQ5jHIZBBDuJguWzAztgmer4OsNmRs+SAEiRUqBEcFl
         rHt/VzW6fU21p/g+wshiW6WwTSJcESX3+71XeiG3wCuZgOhJgYsWteDarEM4kY7OAy9d
         gh5xeaR4k8EUpA49OLh22gQyO2eTntFG8Xk/B5m5K+UX08xYeSeUv/dhst7KtI+SYtpp
         AikQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=I5gpEKySJ5BCh/RY5hwbLjQz0/b3Zqmr0ILRhirbPmY=;
        b=iK5igOxGdE8/jEzUsQulNnU6mSj793u2w0hxYTZnpptbG6yqtXHnLuv1QcH8QvbIxy
         b8Uq33SbrDecS0Z1WkodGKphqvtRlmWybKegcOOd09MHoPIDxzLpLnqCzjtQVc1BGCG+
         OTbA1WSRDKilD4tz1OJg7SPbgtks9by0c+ZBDd4Yf7wY5UcH4wLLw8TZ8oKTSAZK1/3p
         pjC7Z5bLvqpsYk4ZqfiugbZIqf1jHfRgS4+qHQeCl0EnMsYuRWDk1VHZqq6YlEBIjcdu
         y78qOnBdH55teipEtOccrfiKkcCvhjMosm6L5Tpms72YRXj84/kgFJI9JSmVfm6RmhBa
         TZXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Qqdy2+7I;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I5gpEKySJ5BCh/RY5hwbLjQz0/b3Zqmr0ILRhirbPmY=;
        b=jH7QCzAgKUtXxA2QteA4/3ODyYIDqzTHkm7jzaUbf3HbEnQGe/6cFQmBp3H+bgGlEq
         urJeQRCyErw/oU7/QOKfmZGMyrnvWS2N7U3zhMBb6uKo0mtwbNTX7ixrqzoz9QQwAugf
         BFYkePs0PYZM34+H1AWG9/bnzL1LFTvAu4377iP4YGTnKVnm+vMuJc8q+IMhlA4jWVS5
         46LDHMjJd0jzlPCB4g1t9A6m1ixL8Kkkfj/7eYSEUzRl4aJwPAwfyzp5GucFbX9NqF5T
         8YJ8SQx/U+WDYOFzFnuYkcnrnjDm67jrDs+IInbF9mRUAXvhNPvbGNup9XFdXGUh3SUy
         GhrQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=I5gpEKySJ5BCh/RY5hwbLjQz0/b3Zqmr0ILRhirbPmY=;
        b=QOD1DvN4jxWGY8hC6S94TQIcnn/Z5NLcWHEN6DHUJhDG1fYIsx6LCupe8chY+qQV6A
         7Wt5in4lKEHR0PITQRuJPFEYN0w8Mh7Zg656HiocculrzDznlZaQcwWdC3Wx7URn6/Zb
         wlv6yWTAZhuq6DTP+xeSAlF9+1jNiAiywXTaQuvNsdCF9JJYig6i2R8O+1z2K0y2AMq+
         wWbGVPUIPnZmhl0zA5ZfGHsRvH0skX/QHd0d3Aa773HtJuZZYejRyRezXV2nesxlki2R
         aqJclqu/gEexAotmVToFXedcGoP6Ak75fUTGHnnXUq+aijzEfUGrrCQ9pyUC7ACEnw4J
         K1Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I5gpEKySJ5BCh/RY5hwbLjQz0/b3Zqmr0ILRhirbPmY=;
        b=qQ5TqSkqJa64Mjte6dk/6SNVrFVOStmtu56h0NflYqGtOofXyMN5+ctWu72zbzdJLu
         9BWtH8cX25xSoKyb2vVXl/6C0Wm46f5jcBhXVIKH/R5XuQxGmIhTmGrtoE8dQJHT8UWx
         dSiPL+auFZyncFMpihh3CAfZRKki6fN/sKHIIebI4Q4HPEDYSfBBhiYJ9obo3EemCKnw
         Y/Zq+N2harpTRTrUOHJer7u7jdP9JaFWT8DmPA3p0TvSzFvXr7kKxlmrYnsb3//WVbSC
         Z/WYnIMbtvFY5M77BYZfVhiqaKnwA4um1Xy2tmImk96zFdhHZF/OLcymoh8mV7L7gz6o
         aOrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnb6hfVKCwxYb8wwaQOGFF3wfqfIROOpUqH6HQ1Z/5povR5wcR1
	glNSblyBrSSUA7Ogk2xMrZQ=
X-Google-Smtp-Source: AA0mqf4wxOa15etY92C4vS6PyE6J/Wu8h8odxR6gsUX2fPH+mskcOVUSFIRsV3+Mqd3cKchflC+9tg==
X-Received: by 2002:a17:90b:2305:b0:218:7bf3:864c with SMTP id mt5-20020a17090b230500b002187bf3864cmr731994pjb.33.1669482581917;
        Sat, 26 Nov 2022 09:09:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a03:0:b0:477:6271:966b with SMTP id q3-20020a632a03000000b004776271966bls3573520pgq.10.-pod-prod-gmail;
 Sat, 26 Nov 2022 09:09:41 -0800 (PST)
X-Received: by 2002:a63:cd09:0:b0:476:d44d:355 with SMTP id i9-20020a63cd09000000b00476d44d0355mr20873040pgg.289.1669482581119;
        Sat, 26 Nov 2022 09:09:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669482581; cv=none;
        d=google.com; s=arc-20160816;
        b=bPfkmT9+y6DFa8hx+08yA5dnNaLPkQLCtsOffv1rA0C/Kt8SzgJKsFX7471ryO3qob
         +v/kdBdWen1zSBatMNmYUyGmFgYveSTFPjhyvlPRMIMcXW7WxjFKNUMDiX7gE9z0RsZE
         flzHa7Px8kQX5LpDGxOutUdu89tEWUQPkzyp/n4yd9BAZY2ClxeTVRgunI3+48/d7CKI
         MkPdOMQN7r5eZm/SbbUi8QtvcMGvOXdwStW92qqLF/nsmWu/ticFo3RmIs6To1v0Ao89
         CN1mwtjEhWq1ERAEdFZ45Sn+IrEZ4QHG4EkOvXs5FbFjXKFQSBpqpwHp7kesRsapfYUb
         3KUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sLFIKfte67bdoQLm56Ip88k11Q1iXzAXCyP4EbfifyQ=;
        b=SsfeS2n3aN6TpvTYkbINPNB/dc1UIL9+lxJgnukZM0MjL9UXcwdT+Ku9UZEC6TnEN5
         yVayOiJZJATR7DoW14UIwFo0jdJUbo6r5/1PxwngtvNzLXPMXQXJx3P9isYcpWsk3rAi
         h9sPYjAWyYoxzMFs7QjjRS/3pQ0C9kl9P4B7RLTdGgE0rTxsx+AtjRn9bbaauxEsKC9z
         BCfYruPL2HWujKwDpPDdpliXDe0PsK361QG2kWkLVrZ5J8PFUYca5kpJEV/XNJAwh7LD
         FolGSNmP1DvHQalRUeCAl4dov1cM9Ot0Y9//5zcYid+nfafJJFrUPghoZhsT0Om89GB8
         IW+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Qqdy2+7I;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id m17-20020a170902f65100b0018734e1a0dcsi419406plg.0.2022.11.26.09.09.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Nov 2022 09:09:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id o5-20020a17090a678500b00218cd5a21c9so6681376pjj.4
        for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 09:09:41 -0800 (PST)
X-Received: by 2002:a17:903:300c:b0:186:9ef5:4d59 with SMTP id
 o12-20020a170903300c00b001869ef54d59mr36934713pla.89.1669482580757; Sat, 26
 Nov 2022 09:09:40 -0800 (PST)
MIME-Version: 1.0
References: <20221117233838.give.484-kees@kernel.org> <20221117234328.594699-4-keescook@chromium.org>
In-Reply-To: <20221117234328.594699-4-keescook@chromium.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 26 Nov 2022 18:09:29 +0100
Message-ID: <CA+fCnZdMNs8Ut=_vwZNu-ksAW1T9+dxR3AcLpGb_3rYJjzOffg@mail.gmail.com>
Subject: Re: [PATCH v3 4/6] panic: Consolidate open-coded panic_on_warn checks
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Gow <davidgow@google.com>, tangmeng <tangmeng@uniontech.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Petr Mladek <pmladek@suse.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>, Tiezhu Yang <yangtiezhu@loongson.cn>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, Luis Chamberlain <mcgrof@kernel.org>, 
	Seth Jenkins <sethjenkins@google.com>, Greg KH <gregkh@linuxfoundation.org>, 
	Linus Torvalds <torvalds@linuxfoundation.org>, Andy Lutomirski <luto@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, Arnd Bergmann <arnd@arndb.de>, Jonathan Corbet <corbet@lwn.net>, 
	Baolin Wang <baolin.wang@linux.alibaba.com>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	Eric Biggers <ebiggers@google.com>, Huang Ying <ying.huang@intel.com>, 
	Anton Vorontsov <anton@enomsg.org>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Qqdy2+7I;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Nov 18, 2022 at 12:43 AM Kees Cook <keescook@chromium.org> wrote:
>
> Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
> their own warnings, and each check "panic_on_warn". Consolidate this
> into a single function so that future instrumentation can be added in
> a single location.
>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Juri Lelli <juri.lelli@redhat.com>
> Cc: Vincent Guittot <vincent.guittot@linaro.org>
> Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
> Cc: Steven Rostedt <rostedt@goodmis.org>
> Cc: Ben Segall <bsegall@google.com>
> Cc: Mel Gorman <mgorman@suse.de>
> Cc: Daniel Bristot de Oliveira <bristot@redhat.com>
> Cc: Valentin Schneider <vschneid@redhat.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Gow <davidgow@google.com>
> Cc: tangmeng <tangmeng@uniontech.com>
> Cc: Jann Horn <jannh@google.com>
> Cc: Shuah Khan <skhan@linuxfoundation.org>
> Cc: Petr Mladek <pmladek@suse.com>
> Cc: "Paul E. McKenney" <paulmck@kernel.org>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  include/linux/panic.h | 1 +
>  kernel/kcsan/report.c | 3 +--
>  kernel/panic.c        | 9 +++++++--
>  kernel/sched/core.c   | 3 +--
>  lib/ubsan.c           | 3 +--
>  mm/kasan/report.c     | 4 ++--
>  mm/kfence/report.c    | 3 +--
>  7 files changed, 14 insertions(+), 12 deletions(-)
>
> diff --git a/include/linux/panic.h b/include/linux/panic.h
> index c7759b3f2045..979b776e3bcb 100644
> --- a/include/linux/panic.h
> +++ b/include/linux/panic.h
> @@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
>  __printf(1, 2)
>  void panic(const char *fmt, ...) __noreturn __cold;
>  void nmi_panic(struct pt_regs *regs, const char *msg);
> +void check_panic_on_warn(const char *origin);
>  extern void oops_enter(void);
>  extern void oops_exit(void);
>  extern bool oops_may_print(void);
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 67794404042a..e95ce7d7a76e 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -492,8 +492,7 @@ static void print_report(enum kcsan_value_change value_change,
>         dump_stack_print_info(KERN_DEFAULT);
>         pr_err("==================================================================\n");
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("KCSAN");
>  }
>
>  static void release_report(unsigned long *flags, struct other_info *other_info)
> diff --git a/kernel/panic.c b/kernel/panic.c
> index d843d036651e..cfa354322d5f 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -201,6 +201,12 @@ static void panic_print_sys_info(bool console_flush)
>                 ftrace_dump(DUMP_ALL);
>  }
>
> +void check_panic_on_warn(const char *origin)
> +{
> +       if (panic_on_warn)
> +               panic("%s: panic_on_warn set ...\n", origin);
> +}
> +
>  /**
>   *     panic - halt the system
>   *     @fmt: The text string to print
> @@ -619,8 +625,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
>         if (regs)
>                 show_regs(regs);
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("kernel");
>
>         if (!regs)
>                 dump_stack();
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 5800b0623ff3..285ef8821b4f 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -5729,8 +5729,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
>                 pr_err("Preemption disabled at:");
>                 print_ip_sym(KERN_ERR, preempt_disable_ip);
>         }
> -       if (panic_on_warn)
> -               panic("scheduling while atomic\n");
> +       check_panic_on_warn("scheduling while atomic");
>
>         dump_stack();
>         add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index 36bd75e33426..60c7099857a0 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -154,8 +154,7 @@ static void ubsan_epilogue(void)
>
>         current->in_ubsan--;
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("UBSAN");
>  }
>
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index df3602062bfd..cc98dfdd3ed2 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -164,8 +164,8 @@ static void end_report(unsigned long *flags, void *addr)
>                                        (unsigned long)addr);
>         pr_err("==================================================================\n");
>         spin_unlock_irqrestore(&report_lock, *flags);
> -       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
> -               panic("panic_on_warn set ...\n");
> +       if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
> +               check_panic_on_warn("KASAN");
>         if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
>                 panic("kasan.fault=panic set ...\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 7e496856c2eb..110c27ca597d 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -268,8 +268,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
>
>         lockdep_on();
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("KFENCE");
>
>         /* We encountered a memory safety error, taint the kernel! */
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdMNs8Ut%3D_vwZNu-ksAW1T9%2BdxR3AcLpGb_3rYJjzOffg%40mail.gmail.com.
