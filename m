Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZHCZGGAMGQEBATEEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0484745074A
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 15:40:38 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id y3-20020acae103000000b002a7a173f78fsf11466650oig.14
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 06:40:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636987236; cv=pass;
        d=google.com; s=arc-20160816;
        b=I20iNTQJfZJYCwHXC5j0/EQNXUhlE/vOllJ6NfpKVW7scTv13/UgqYZZTp9oAV4Xc+
         IrHfCQtbYh/yHHseFiQjZhcSu64B/JdGNOENFbLplVmdrt8XAlHw25M63cbItD0ajzAu
         IA3DbnBAkYMhkv3nyL0Dh6elFnZce3n8KIb1IPVIjMW74jyo38SB2iAracv6+a3oedKg
         jfZRC25rPjIPXz7x8UdDfac81di8iYoUGv8/N5O/IRdX5t5spIADIfAWz7wAon9PjqYr
         Eva2CsJUe1uGjBdo7kqTL0BGxzU0Nhr7Q9NWcv1Mb9WNROtvzZ9mFFn2g7qTtvA4CwE6
         d+XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iIV1gmFsy4p6sHKbBEv4gVA7E8cx9rynG4twiwAPGK4=;
        b=LQ893bl9VCwazwTCmKNgtPnAvXpy0CwejZ+gOR4aeRKjK//Gkpqm3oJO2h60cjePss
         o7StOWs8pnRw5ogYQ8u6Z6GzPGZdL5ApM1ExFEf/k/DzXGbRf9Xjw0A6b0+iSp5pOy/Z
         YbBP+GY7AYOy+mKfV7xNl734dsSwtskznUcKkAlqvWZNvBh5Slm5cj3TlngGnHqx2ua6
         9nyx4j8sHOxWQRHqezl6Gsp5XLqX3Bf0nO16c3/eLwKyKjpdvYgA8QD776COdnMcZu8K
         XrIdnXCnaomj8JdkVvs+oymgyjyQkgwDZKU7IavCK9hbGCZ+RE8GSkPM9mA3fZy5ZZl0
         eKkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P4Wkr+j1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iIV1gmFsy4p6sHKbBEv4gVA7E8cx9rynG4twiwAPGK4=;
        b=TxaUEjFxSzpFAV9nHCQYEFeGMZI80bhM3NNikdJlwAQg3jxZC4j83+Mbhcwkl+Ek/p
         5xw3Lr7sTvphsltpqGVqt1IYbeMp+YZwgvXdB/0qEIN2blYhWwp6M8kBVDNqhvdlpC3J
         cUAwc9CfE4TngONTIWQ9yZBYQp0u3zB9MSrQbTrlnGmJHbgihvv+qtWEdhUolVDFSEKV
         R8fAQcA6FnKCpmVdgXMO+She8GXi+BxOr8G9amDui549g7/sLnN/wTt0uOB9EuACeOlL
         uRRxCR7ND/JHE9cGctyDTRELUHrTXtD0NUtbKgfiBHUcJ6KtMYHrHFe6W2gdplvaWNOf
         mPNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iIV1gmFsy4p6sHKbBEv4gVA7E8cx9rynG4twiwAPGK4=;
        b=VKdN6+M1AN8KX6YZTwMNNFeFPermViT4AUCZVXeeCMdB2tpjrRZmJkAVLBmR+LDgED
         c6epph+rJkG1RQX++A0c7KFW1uOjWi91Ms2mJ0b/m9E4eOsAa2yndC4BvFMjNxY/NR3v
         QTTXe26g5k3UPoD+k8TzgW/4IPFYvvH5kTysmIAJlts6cfWR24VIvgOApuweaCZaFeOr
         5F/qAPeh3Z8jvO7z4ofHep1uy7Xhsmxh2O1lTastIgyHZJbWrYLAsqpfNAqUUoX0f/c+
         6mVAlMWAaa/pIUf94GNn2FbCTAfoODhb/peP4PZWENPtYMdd8piXgcRihreaZ8gByZ0j
         xdyQ==
X-Gm-Message-State: AOAM5306V9VO4f3P9Qllw+mqiytsxPgOlxlUsO7YScLw5ytozVLW0bmi
	qx040SgQP/Uf+0tsHpJz99o=
X-Google-Smtp-Source: ABdhPJyygXeJ5s0rYWU3iZGakk3XvyLKwYLa3dGD9n3qwnp3e7vE5v5hXSaJLFh7Lza5adSYGAYNQQ==
X-Received: by 2002:a05:6830:104f:: with SMTP id b15mr31578246otp.215.1636987236623;
        Mon, 15 Nov 2021 06:40:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4110:: with SMTP id w16ls4901768ott.6.gmail; Mon,
 15 Nov 2021 06:40:36 -0800 (PST)
X-Received: by 2002:a05:6830:1e13:: with SMTP id s19mr2296219otr.358.1636987236227;
        Mon, 15 Nov 2021 06:40:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636987236; cv=none;
        d=google.com; s=arc-20160816;
        b=YMGFialnjg8tWEtG8XgXO78adjoanIKlcQRTRZ2OwIwy4nQmbssV+ZirzFKvrEwxv1
         osRLG89HKGsFrV9hFh/Bus5npp7PaXstRRXFaT57Mh/F2qmN9IEpyav7LERa1cuoxfwa
         n64Z7RDws+0EyKxwKTEdSql17a1uhNEeLfj1cLQFNP73mC/K8jtVWC8n8/S8QcylLvxn
         QlM2ag8tOH1SJUtxXYrysaeU2hPgx95ZcWoxpCGU/P8EMyHM/VFCIXuwH+zwDNynhGM9
         OWskpLCFwTZelWtiKcpj/CURQiBfrXGRJtUEL3He4G7q/vGe4IUuFHplarWCNIlows0z
         tXKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+mG8lh6BBVoPcqkpcdF5hHU3Rz1pA4sg03dlH/N+8Cg=;
        b=DlRAaETHthCWyLyUbd7BlenuPM2HkffGTi/1xnXln6Pb4xFaVzz1ZbxMvnd9W3iRoj
         x8AEHP/9+rx/UUOkl1mFTK9Uliw0UkKXEQ2HLsoFxKKX1nHZCGMyYJu/M9k4iKaF8lsA
         XuFXqXyG22hVXKi8OlwYg+f9K+jxZSJcYA5W5NU8bmMa7RZE2TkGW21sVZ6FXwsucu/b
         A52G+TEXeyiM0AfIHv+J5Z2gZpI1VhDoo3kFnMtuDtFAwVbirHAkMVr/o3HC4P9UMHWY
         rmbaHp7KLYM9Z0Y0j/EQ0iOf/IrKFaVPjEvIbwlfEW6JmmTxzwCYYSb6pkVCLmTbA0LB
         cM7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P4Wkr+j1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id p6si1106970ots.0.2021.11.15.06.40.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 06:40:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id x43-20020a056830246b00b00570d09d34ebso14306183otr.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 06:40:36 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr31541498otl.329.1636987235754;
 Mon, 15 Nov 2021 06:40:35 -0800 (PST)
MIME-Version: 1.0
References: <20211115085630.1756817-1-elver@google.com> <YZJw69RdPES7gHBM@smile.fi.intel.com>
In-Reply-To: <YZJw69RdPES7gHBM@smile.fi.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Nov 2021 15:40:24 +0100
Message-ID: <CANpmjNMcxQ1YrvsbO-+=5vmW6rwhChjgB20FUMKvHQ9HXNwcAg@mail.gmail.com>
Subject: Re: [PATCH] panic: use error_report_end tracepoint on warnings
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Petr Mladek <pmladek@suse.com>, Luis Chamberlain <mcgrof@kernel.org>, Wei Liu <wei.liu@kernel.org>, 
	Mike Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, John Ogness <john.ogness@linutronix.de>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Alexander Popov <alex.popov@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=P4Wkr+j1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 15 Nov 2021 at 15:38, Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> On Mon, Nov 15, 2021 at 09:56:30AM +0100, Marco Elver wrote:
> > Introduce the error detector "warning" to the error_report event and use
> > the error_report_end tracepoint at the end of a warning report.
> >
> > This allows in-kernel tests but also userspace to more easily determine
> > if a warning occurred without polling kernel logs.
>
> ...
>
> >  enum error_detector {
> >       ERROR_DETECTOR_KFENCE,
> > -     ERROR_DETECTOR_KASAN
> > +     ERROR_DETECTOR_KASAN,
> > +     ERROR_DETECTOR_WARN
>
> ...which exactly shows my point (given many times somewhere else) why comma
> is good to have when we are not sure the item is a terminator one in the enum
> or array of elements.

So you want me to add a comma?

(I'm not participating in bikeshedding here, just tell me what to do.)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMcxQ1YrvsbO-%2B%3D5vmW6rwhChjgB20FUMKvHQ9HXNwcAg%40mail.gmail.com.
