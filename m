Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOBWKCAMGQEMKCPJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3443F370466
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 02:28:47 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id m7-20020a6545c70000b029020f6af21c77sf2368963pgr.6
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 17:28:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619828926; cv=pass;
        d=google.com; s=arc-20160816;
        b=ILyLX/RPUabBG46ZuYc7nDMxmAoM6p/Zrl1t/FLBlNDoLKgCyFQyZfuGnX0apDnNXA
         vSSspqYOa7aXYWLzplZudyY1bkqBo/kaQ5sC0k5kNR6+V7R6mK/TJgxVxcmo3zBFdKUo
         5lGAoq5wCmDk88vADRazJPfxFuwUIdEZd+3N7ew/GZvTyoEi2Or/zDaRUKhGOrMjaZXg
         dZhMCOYB3TJVoTBeHBY3jx8zJ6kuOU+QP+yTf0/5Cd0FIXKUMeaVj20wxBHaD3T0DDfZ
         r42HbsbTubTOFq5OgJwPnc12maYBiTRNjO7PPfTPAcnJQi0vUK1+PNnlWyzlzA7P/ba3
         varg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E35dq+/BqyEcIOeW3Xp2h8TlJng98IfAmszAsbC5sr0=;
        b=osIhopLZ1lRKs5ogCwjA028KO5DP+AzfljIgmMhgA1IAVTWLZTYNGWxpIi2oN1mtUr
         i3MOnPPLObRZDQdxLJ82VGlVW1/FW2zYlPRxP0bI46Q/Js0xxZCNlqRN2bZ8jhgX4E3+
         w7VTgcmbuYz112RbIqKXnE1JX6HKwqnTC7d5tQzEoKIoJHoLRZrYC03Bq8jfuAyHIvKD
         hLAcDWcgmdLN60ULOCPUVOJZmxPe/djRQDea9yjLoiY4Cv4ufS9daOIDVCrT8avwGJdz
         hzjv+LTfyxBe7S6uuP2SJRKRMlHAnohLv00hjgwboNHH6LuyuvWcVcc/p6EC1V26YLVV
         VDrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cvM0ZoU4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E35dq+/BqyEcIOeW3Xp2h8TlJng98IfAmszAsbC5sr0=;
        b=FnLc+T+qFSdzPVBW41tDtR9Q3yDjG8itvFx13pv1G3Y/1H/W+v9fwnBhjA3Vl5m0dw
         nmIU9uzqxvWkDVhpBDi99xS1GFPUiCzGYzr7mzdoPXfKG6syaaNOxVhGQn+pH+06qJdR
         JeTMckMjzaFzbUVgp/I/yT2fM66eoAZx52KW2v39nk1JtfQbUZC0H8mQK9yepTtnQ88/
         2FAc0s7VQGWVhZaYXIrs8Ur6EcITzy3FHoAz2QIkOhUnF734zFaT6bzbeSk9jcBxCcKD
         4W1N7NurjB6tGkhnDTd8mAJymTVNJNVHqCb2BrAEGoE2IqFFLYCz1rr90DlGskd2Aqls
         3UdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E35dq+/BqyEcIOeW3Xp2h8TlJng98IfAmszAsbC5sr0=;
        b=pVUdagKO4rSTeH3dcnFIhw6HUlLyt7iHN8UhoTTW/W5gNDsYF6+RLn+FnGg2r6Jb8V
         NZ93B1f3pPme0QlulOXPZ/cOx6rKU9xzVHPu7YJka9xlOyEi3MfYXQE+llaDtjipMttu
         98c7pa17GUm45oWnic0E8yOiVkF62A/yIJsA4y54OZpLbsLJM9qIT5n+Qelp8zTyeh4m
         0oCOsJIe+kH5hR+STgIw7Zf0ixwlIDqesqxZLVnX/l33FL6ykiqsAl8lQ9lxsMID2R8r
         7uBE3VeERVqi8lqSjBWreS2bLqi+PHSeYhOZ0n7Qv5MIrVpDBt8EcsS8no6b/vV3UQ67
         hxEw==
X-Gm-Message-State: AOAM531vw1/kRz7+AAfSVBuUpBbkSdUPPoGXBlrbBg1HYkl6i9VieGL4
	oXh5bW66ghKV667W9enMDt4=
X-Google-Smtp-Source: ABdhPJyb4tW5h/vk8X3vAQR1jnFp9YLYoKPJ58cBfcXh6xNp9oguIFRq6I8ksI0zPvK4TqODaol2dA==
X-Received: by 2002:a63:d509:: with SMTP id c9mr6964979pgg.280.1619828925930;
        Fri, 30 Apr 2021 17:28:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7d89:: with SMTP id a9ls4197326plm.7.gmail; Fri, 30
 Apr 2021 17:28:45 -0700 (PDT)
X-Received: by 2002:a17:902:ed85:b029:ed:6ed2:d0da with SMTP id e5-20020a170902ed85b02900ed6ed2d0damr7925388plj.53.1619828925348;
        Fri, 30 Apr 2021 17:28:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619828925; cv=none;
        d=google.com; s=arc-20160816;
        b=Dd35NwvCapMFVeuQnlCrkVAxQef8AboKNtSjRKWcApZAbZoXsAVfBmz7qISIpcDKfg
         GUBGVC7UxjS2gXGo02W26clWwdd+TaHuBl3PCtZDHxWOr/K9H8x48g74XWw19g0nOHF9
         mvZaiipiL6MyXC7z7T6xGj6JTIevq/pg7phd/eDZaP+QHZM/7dvDQ8KpoJS7XXDcLW7U
         6RMR7/Gghe4HrObizGpkFZ+G8zuiWg2usKwBmEZYSt7JqdH4lGK1yvigdZgY7feBufdk
         UoGykSDUuJ7KBKndLg51E0zYWenf7AvIi5QiaGhSfKZlr9JuTr0kPQqHAxPbHQYtt/PW
         IXbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wrSDrh86BIUH92uxEEUIIzYXakmk5H1bASu7Ra8z2vg=;
        b=JIteL5D8Y2GmAxmIhnL4pbhLUTKL2IB3s6gShFT7utN4o59YnfZIP/9EJ6R+/Sxyez
         ZzZTKMW3i0bcDu7iy8kc5Ab37r9YAmAHo3BfXMbbkI7A3ooz+6nJKwOJ4eUsETRBIIP2
         F0DFf+VexPCG5YpRsdJg+5wargDyGY98iipIDP7I9HKfOcICRexo3ujqAfYK22bO67KV
         yPudlGB5EwiPTtfr/mkoOVEBNbfgOU+W6RFqnq0j9vHigvqyAXVJKQvMLpUIrTewqcFi
         iURcDdS2qGq41WW81r3/v6mK39BOKHFRaAcRxK0shyMWJg++8jO6WrMPrFuPRAJd9skG
         cA8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cvM0ZoU4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id s20si772184pfw.6.2021.04.30.17.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Apr 2021 17:28:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id d25so34222053oij.5
        for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 17:28:45 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr6068321oia.70.1619828924536;
 Fri, 30 Apr 2021 17:28:44 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1im43qrug.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1im43qrug.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 02:28:33 +0200
Message-ID: <CANpmjNOwUfcCrBfCjtq9ngjqkqjYzehrqS+=+2oA=703tNP=aA@mail.gmail.com>
Subject: Re: Is perf_sigtrap synchronous?
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cvM0ZoU4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
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

On Sat, 1 May 2021 at 01:23, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> I am looking at perf_sigtrap and I am confused by the code.
>
>
>         /*
>          * We'd expect this to only occur if the irq_work is delayed and either
>          * ctx->task or current has changed in the meantime. This can be the
>          * case on architectures that do not implement arch_irq_work_raise().
>          */
>         if (WARN_ON_ONCE(event->ctx->task != current))
>                 return;
>
>         /*
>          * perf_pending_event() can race with the task exiting.
>          */
>         if (current->flags & PF_EXITING)
>                 return;
>
>
> It performs tests that absolutely can never fail if we are talking about
> a synchronous exception.  The code force_sig family of functions only
> make sense to use with and are only safe to use with synchronous
> exceptions.
>
> Are the tests in perf_sigtrap necessary or is perf_sigtrap not reporting
> a synchronous event?

Yes it's synchronous, insofar that the user will receive the signal
right when the event happens (I've tested this extensively, also see
tools/testing/selftests/perf_events). Of course, there's some effort
involved from the point where the event triggered to actually safely
delivering the signal. In particular, for HW events, these arrive in
NMI, and we can't do much in NMI, and therefore will queue an
irq_work.

On architectures that properly implement irq_work, it will do a
self-IPI, so that once it is safe to do so, another interrupt is
delivered where we process the event and do the force_sig_info(). The
task where the event occurred never got a chance to run -- except for
bad architectures with broken irq_work, and the first WARN_ON() is
there so we don't crash the kernel if somebody botched their irq_work.

Since we're talking about various HW events, these can still trigger
while the task is exiting, before perf_event_exit_task() being called
during do_exit(). That's why we have the 2nd check.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOwUfcCrBfCjtq9ngjqkqjYzehrqS%2B%3D%2B2oA%3D703tNP%3DaA%40mail.gmail.com.
