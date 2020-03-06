Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJF2RDZQKGQETPEPOOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 66FDB17B994
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 10:51:34 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id x189sf1121594pfd.6
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 01:51:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583488293; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZKs7QyeK5EcbYE48if51Vt7RrsRhJViXIdQSnxOwVrxMm4M09Js7DbXxZAEbhywx9a
         31+WFEHr/cqYa8XvKeGv0c6qANxYHyd5KRLAxN8EejEi275OfokvllU8b0cHHZDt9stE
         vxnpbytPccbLhRGAN7/uLoC57lqW5MpMyTZsQasEAoZfCXbc7Texbhk/D1SpoqhHRE8H
         cFTkc7qukG0BcsGfYAnhCqVoJVn2totvQpvNjPKZI4mFdGmTo6F+mXQ1kdIHgbbJK5gY
         ZUQQwetV+ZAU+5X4hfLGjMIDqO/hlxHup5Xngw+huozEoBC8aKx4cNNWi/Kc8sdwzmgx
         4G4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=CywHy6bO/TZcE4sxF4gKQJVJUj2WVS7oiPOmTyRNTWM=;
        b=zAex8W+63tPdvsHwqhfzKqah7gBaNnY203KzQjjnt8Ae3ydCmxHgtb2t34CfxBQ1SQ
         v6IWp90XMfkJITmt8MR1x7wvArC5LFlPZ2fh8y6odGeNSHFq7l2oWxCrg0O/GlayMEUU
         HTZQrY5XfJ6le6IYigDRx3S3myojUCL3OGsGoXsLkamC0zVydgWB1Eo2apKvJIPhxlst
         YLXNP7lNxRQ7y+8pgTpEP6BlLwT1CrkllME5oT0w0hC+EExaQO8FmKnDeCJjZ0ExR8CR
         mnOuS9oEna272yW5X/Vp0V19kk7vs7DSL32IB3kb4fL/Y8z+Q9fcuDe5J9r83KbcBXRb
         JhQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="IP/n4Jl5";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CywHy6bO/TZcE4sxF4gKQJVJUj2WVS7oiPOmTyRNTWM=;
        b=QN/MkQqksaBVBnASPIoVD4i3gHr3imZ+0isz6/rrTX2m4sp8wvm4buaK0ohKQUnnUu
         VsS5d1aZuUKLtmgDwMwyZ+yqKGxbDDCP9eFO+0AFCb8LmQqmGkcEay0BNQ85RRSBK44N
         fO/S4DAH2vK6pkOrn+sAwayH8j5hoKkSltxIlZLqN68XrqzoQtogXe8q2EFgmwOOcglU
         EHjGbB8FJEwSGy5veqAO0VWbECUsznV3dMjc+/FeANIFPCOqJsXgtsW0D6Yh66fpq8cN
         Gsh3/2YNGgK2tU2+Crb5yAaW1Q22VDk8pr4vYFzmploCvq0y3eg27kbfS+ai1g5Td76s
         L9Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CywHy6bO/TZcE4sxF4gKQJVJUj2WVS7oiPOmTyRNTWM=;
        b=A5arE/jQPKPiha5u7PspE6IhusEqNlw85socjDJJOyJo2l8WrfpWilPWeJg7e2hB1h
         ILR65Ql4O0wT2aue8cDZYTKI8e81usNXnl824W3qDE7Emnvvaf86RRcjYRZjj9Kitrj7
         OBneqtJILQUmaMsc/G2ApkU1RTTHY9havLhDpkForNO+0y09t61IFtJdhGrmHsg5dRW/
         adW6wdLvi9T+re5xP31Kaa/zRWL6YRnIVYD6Iij75062ASYwxhL2Zzlnf4H0Nfwfieao
         FH1c3VOZKj3O2KNokmZS/bcp/0aoBD3vDTv4JfUTpSqa10ZW7JZn/NSu133wy2WLeTQV
         fOEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3KCJD59DZXw2o3jCuNLNoaEoqAJ/9x4FtbL1K7IoOKFqLDiLzQ
	sePRdtVO68euW7AjBTyr6U4=
X-Google-Smtp-Source: ADFU+vuHT4u0ryXuTUltmfN35Mbf8vlZZ+e1dNXwCSRqJx2KndoPz8o/Ne/krHfMToSRePKUJ6Ai5A==
X-Received: by 2002:a17:90a:210c:: with SMTP id a12mr2745243pje.16.1583488292953;
        Fri, 06 Mar 2020 01:51:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8744:: with SMTP id i65ls652818pfe.11.gmail; Fri, 06 Mar
 2020 01:51:32 -0800 (PST)
X-Received: by 2002:a63:2b4e:: with SMTP id r75mr2584287pgr.32.1583488292353;
        Fri, 06 Mar 2020 01:51:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583488292; cv=none;
        d=google.com; s=arc-20160816;
        b=lyNd360lsgAS1NOZIheQFuH+9tKbOdDoO9tcrZ6VFFDdBjEv/fsm3LzJN9JSHvVNPQ
         gMIBi0clU4bn63cUTSTPq7YFb8qYIjEcc9z3R8UOe1nC5KlCJVefhlqKl3y/l0TdGgJ5
         3Ak0QD5qQvDudx87RTyjTcqXyfTW1xTvoHif5JJt96lBuQwmO2k7YIhOphUSm6oGW0lI
         FSY0hGywOIe6C9z0K2HVLi+ESP+VVipEDAllK6iTPTdwZhlEVUQ2BEHpXFkbf97pPpM+
         2ojfrjY89zrfKfbkJ8Jf9I2cBgqFdH3kMeIWF2h9+uEY/4LpfkWYCYC+BXtiLZiFeTDL
         vgcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Rsm5zsIkQiYt9KoHXiRANfe4Ox8U1Ne4EJbYKgVO2mw=;
        b=z8sjs6oarF4+9731GdIQZ9v0Au+plUNnoVHxsjG2tc7Jo5bi5iavb8SqfO2nABs57j
         QNdsc+FXrkYPI7JMKD4ab+7LcMtsd6D4k5OLn4N5xiv7aaeUfP8rf7U9RSlnLT7GUs2l
         O0MDmwuXEez68KfqxjqR5FMa3wpENDEFTHbwicG5eQD7hbjfXMXMXj6VhAkbXdI8apl7
         OHFvaUbpnYmpNzB8A6VkUFis23GLns9Sp8mDupiC8klwAPsEXCjr19wZxyMvLGsRC9Vj
         n644FQr1bSGRax4BXn7uCT2DzeQ/SRfyMjl1vyg/3pkXPhuIeRsW10/q1O6tnLagZMun
         OYVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="IP/n4Jl5";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id i4si55518pgg.1.2020.03.06.01.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2020 01:51:32 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jA9di-0005jF-CB; Fri, 06 Mar 2020 09:51:30 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 98340980DE9; Fri,  6 Mar 2020 10:51:27 +0100 (CET)
Date: Fri, 6 Mar 2020 10:51:27 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [peterz-queue:core/rcu 31/33]
 arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to
 always_inline 'try_get_desc': function attribute mismatch
Message-ID: <20200306095127.GE3348@worktop.programming.kicks-ass.net>
References: <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
 <20200305155539.GA12561@hirez.programming.kicks-ass.net>
 <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
 <20200305184727.GA3348@worktop.programming.kicks-ass.net>
 <CACT4Y+axD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg@mail.gmail.com>
 <20200305202854.GD3348@worktop.programming.kicks-ass.net>
 <CACT4Y+Z=qy9MjhqOMNr2kYLwHy=gRXo0yqHBWBZpX2foRJBpMA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z=qy9MjhqOMNr2kYLwHy=gRXo0yqHBWBZpX2foRJBpMA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="IP/n4Jl5";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Mar 06, 2020 at 06:34:49AM +0100, Dmitry Vyukov wrote:

> Say, consider, poke_int3_handler
> gets inlines in LTO build, and compiler says: you know what, I am just
> going to silently ignore your no_sanitize attribute to give you fun of
> re-debugging the issue you think you fixed ;)

*groan*, can't LTO still mess things up when combining translation units
build with different sanitize flags?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200306095127.GE3348%40worktop.programming.kicks-ass.net.
