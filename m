Return-Path: <kasan-dev+bncBCF5XGNWYQBRB776WCNQMGQECLWZYHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id ADA866237DD
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 01:02:10 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q6-20020a170902dac600b001873ef77938sf132250plx.18
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 16:02:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668038529; cv=pass;
        d=google.com; s=arc-20160816;
        b=PHXitytFN2n0JRhGL2xyfFfuJ3vrWhH0fOAvnj27+jBr92T+xEejdeQf+9LS7dfqHp
         fgsnDWbVmXBmfSFCyS0rjc0m4KQUb1uBNjnoZLO6nTtQ0RahRxBb3xadPmjR3tMwbw5h
         qizLY+Cq8pmZM+oR9Xppt9aEp5FMYy6ufnDa7KRKBzFEF5fA1mJIb7nZk1h75UNR5UYF
         DMYIRGR930uJ0h+C5NbPecGWgpV0eqjwcjicuxedGCrcjQJFU4JDod7UT67CSdvXavIM
         v9O71i2Z6e0pvo0d70UkNPMgqzDTAXFqXKb+NyBTAzDOMxjboYCG0PtzAJzlgDGIvOEt
         ijJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=a+NA7kKi5+eB1bKOOTgtCkp1VOkg6c9Tk4pSMWiX2ck=;
        b=OiWvaXK9Y83WEKSvWvnk/ycnTXrvpjUycymdS+v42JlDRjfhiil9zugqjSApwUpJqk
         /YroLjzBm0GnjPge4JOkT1X74vpVfLgrLhoTk+jwyJHGTHJjZndfRT9/uc7n7T92s72v
         cAdSthqmxGlYaNpBKWuAisIcA1e1uve/lV2oc2CJ4TkzXwSJSZT0VmolR496zMHctBkf
         Ysyg0gpu9+cRfCL+s2UTR8KMiJoXdCV22auj0M+ZSUuvkewCpOG/vv59jyy4qnFvvtNS
         cW1ye7bD5qr9Gx3ueR09KQO3QNWJgf6p6B+K2p9ih6h1r6wyE1NL+wljIE1mNZH6+s6p
         RJ/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=de0Un6NH;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a+NA7kKi5+eB1bKOOTgtCkp1VOkg6c9Tk4pSMWiX2ck=;
        b=S7qhx3ORK0B9tdQTydwjNdFtl8rjo2JGV4xV3VxD/EUr0qSGOrJY1dMMBZ23c1MtrK
         76hgLKhgQg8OrnUPJsBOS1s54dHnMI9WDmntLTo6W//YOzmK0A32XzypoggC4YDJGmeY
         7d8SDr0Iiak/rAHVfzH1RVRK0US1FxZ7KzF6pT3khkCgjS+bNF6j2CcDVwPKWOG4ttZG
         ANFGm2J5sHEgrxGs4E/ew3ToH40zuzEmPwlQvCOwOBGx9QKZtwYFu6pzdr7ePa3Qqchb
         CwVW+/gWxUl4gBmMmYF1EGY52Y79CVIDq9QIf4kaBL0Cn0h8PjOdplvc/oB1KpzbkQlC
         nJnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a+NA7kKi5+eB1bKOOTgtCkp1VOkg6c9Tk4pSMWiX2ck=;
        b=UWDBziz4P0zU5BUACU2Xt3MolTyMxKSbRWsSwEibLxHCN+z/S/P5Ud0lQ9nOtVn8oP
         7jmf3dh2USSp+mcYZwf1+Cm09NlqQP3Tu10dUbMqNNQSRLJuzkCOYpj5vv5R1DClPGj8
         u+664KLf71uNP6E/kiVMd6vkTQWM4yPKbsb/xNlR2RQVJJiCODkWZ6pZrgOzwRwnvDt7
         ZlOVDOyal+uP/C+qGSmaSyXgn2UIs8Psmdwxi1xVUzt8QW+KrbnDBEoLXpV1kB1EVkt5
         nQKxH2HGCrNXHzpg8QkdDKI2+osGJU2Y1/YOQ73P71DL5itjDG4jSIPnyzVt9hm6p+5n
         ULjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3A3ynkq/Ik35TBzf4AKDCZcIvYetpf0On5cXPc7Ub1YG3PdVzW
	VcUVz8oaWJYq7D+L8QkGpDg=
X-Google-Smtp-Source: AMsMyM4ZuNPjh8pip70ZZwWyOnjIgwRETEjdKQV23K6dK6xNew/00le5R00jvXYShjd3lWnCjEMlmQ==
X-Received: by 2002:a17:902:8a90:b0:186:b145:f5ec with SMTP id p16-20020a1709028a9000b00186b145f5ecmr64131449plo.103.1668038527999;
        Wed, 09 Nov 2022 16:02:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:959c:0:b0:561:e77b:c7c2 with SMTP id z28-20020aa7959c000000b00561e77bc7c2ls193678pfj.4.-pod-prod-gmail;
 Wed, 09 Nov 2022 16:02:07 -0800 (PST)
X-Received: by 2002:a05:6a02:10e:b0:43b:e57d:2bfa with SMTP id bg14-20020a056a02010e00b0043be57d2bfamr52536496pgb.263.1668038527319;
        Wed, 09 Nov 2022 16:02:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668038527; cv=none;
        d=google.com; s=arc-20160816;
        b=JwpjTE8tmgZHqwsV6L6l5W9d3zSkE6CUattXHNkya/uS2O6WaFjTIM9fDpVSvhEzPM
         PrU8Yni5/FhJnvijqVnJmVVqf/yhY9xoXhMOoHdcc0LnufG8fZQJ0pIJMaPgkKW1VMcm
         EHQ3qmE1AR4OByLVS7zMCYtlgzl9S3FXHnoDJTAja2I9vdpA3FFLHmWRaXWavGOsSrSn
         sOdtDsoGVvDoNFhhpc48Xh/MN4eFV0F6Gga/Q7+W4pfbcIQzQcj8vLt0+R5heKRptDbA
         GiOrd9AZTpwnRHK3frxPUbK2+lkwG11OJWCTdnGnMzhmi1/zS1s1c6DYmNGidHX0o/bC
         DaeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=p7Daps8F455XQYwxt4zsfNkYk/NEUbSHg8y4fLlQGlw=;
        b=wI7JerMBblhXHywdB+qakietwNolKsX/H3M35WTU9HQoMGO2L2h87//jOG5vPFQbF7
         Dmj0zcsz+lVjbqNp0L31iNPqxhTAztKeSosXkOE9uKFRVfOUVsEjObokyudlhoc4O/2Y
         h23OtTdwoIljcRJeOokgU/kSR8b8fXY0TIcbrlNkPpe/u2a8CR21/hhe47NlUEKpu93v
         pUFa0qi6jz/8E+neTE7+8Odhv1yv1FrxbF9WinLca3EiCvQy4ZNELe0JNnDlX6E0ZTpR
         SLG+b2NUGk7j8m8RlRlDieI0gIwWt4huniOZVhYRa0jBlTqjpxasjZybRoXpIRmMd98j
         wNSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=de0Un6NH;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id k17-20020a170902c41100b0017f7fffbb13si695720plk.13.2022.11.09.16.02.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 16:02:07 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id b21so157094plc.9
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 16:02:07 -0800 (PST)
X-Received: by 2002:a17:90a:f306:b0:213:b191:f3bf with SMTP id ca6-20020a17090af30600b00213b191f3bfmr62515127pjb.237.1668038526964;
        Wed, 09 Nov 2022 16:02:06 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id i4-20020a056a00004400b005668b26ade0sm8799343pfk.136.2022.11.09.16.02.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 16:02:06 -0800 (PST)
Date: Wed, 9 Nov 2022 16:02:05 -0800
From: Kees Cook <keescook@chromium.org>
To: Bill Wendling <morbo@google.com>
Cc: Jann Horn <jannh@google.com>, Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
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
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 1/6] panic: Separate sysctl logic from CONFIG_SMP
Message-ID: <202211091601.E07A8D57@keescook>
References: <20221109194404.gonna.558-kees@kernel.org>
 <20221109200050.3400857-1-keescook@chromium.org>
 <CAGG=3QXM3u_uz1fuW2LzvrZqqPhYL15m+LJgD39R=jkuyENmYg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAGG=3QXM3u_uz1fuW2LzvrZqqPhYL15m+LJgD39R=jkuyENmYg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=de0Un6NH;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c
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

On Wed, Nov 09, 2022 at 01:48:45PM -0800, Bill Wendling wrote:
> On Wed, Nov 9, 2022 at 12:01 PM Kees Cook <keescook@chromium.org> wrote:
> >
> > In preparation for adding more sysctls directly in kernel/panic.c, split
> > CONFIG_SMP from the logic that adds sysctls.
> >
> > Cc: Petr Mladek <pmladek@suse.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: tangmeng <tangmeng@uniontech.com>
> > Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> > Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> > Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> >  kernel/panic.c | 4 +++-
> >  1 file changed, 3 insertions(+), 1 deletion(-)
> >
> > diff --git a/kernel/panic.c b/kernel/panic.c
> > index da323209f583..129936511380 100644
> > --- a/kernel/panic.c
> > +++ b/kernel/panic.c
> > @@ -75,8 +75,9 @@ ATOMIC_NOTIFIER_HEAD(panic_notifier_list);
> >
> >  EXPORT_SYMBOL(panic_notifier_list);
> >
> > -#if defined(CONFIG_SMP) && defined(CONFIG_SYSCTL)
> > +#if CONFIG_SYSCTL
> 
> Should this be "#ifdef CONFIG_SYSCTL"?
> 
> >  static struct ctl_table kern_panic_table[] = {
> > +#if defined(CONFIG_SMP)
> 
> nit: This could be "#ifdef CONFIG_SMP"

Whoops, yes. Thanks. I'll fix these for v3.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202211091601.E07A8D57%40keescook.
