Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAHTRL6QKGQESAAFJBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E8942A664D
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 15:24:02 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id t6sf15517800ilj.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 06:24:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604499841; cv=pass;
        d=google.com; s=arc-20160816;
        b=fIPRPqwp1vScplC5FqC58YNfyi01JrWeNsYhyk4AcEpRKwwLCsPEC1W8hXyUvgkce3
         1rIGeRML8di3IS221E955oTK0YqAZdUxqnw2YiN798w6boTWspu2bB6snCE1kpBSAnLO
         MvMcz8WVk9uYemVhJvUfaseA6/zMa039xc650NVIKUlfwKuO+m7DZT+m4VJNhhyWU6El
         rtKwTIERPqZ3I/goCEV4REfVOZ+GXgSQZuq7c8desgIemZurvRnUh+IdTxUuBoHRnBDO
         PbyOm8ssZ/XRZUWbBq/v/272RenGhpkCtoS+Fx1w38FRUixtKAYnfSnwt6Q032miVZUQ
         WPYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nolMSAhzlkwUqRXZZF/sAPMJA57T21hrRJDeTRSjFJU=;
        b=qw32NVN1rdJl64FQLdyqm+go5yrCCNT6ZSneeHj1YevBwOT0LBGk/j2ewKVNZGcICx
         7nhPLklN2suMC2YmeFf+Exur0MDbeHsA358MKM5xF6NApWxtXd/CyjSXiyU0zED4tnR8
         Q8xqwoITPBmjfbaCY/sIsgMxmVp3JbHi/l0iE6C5jbZ8eU8k6w8H76WMSr1phVrzMRao
         UnwBNVP2+rbppr8Rc8Vg+/212var0Mu2nSlioL8BDl8y0fsW8nMv7bb4kQyDwdsd516K
         NgT9nXcmNMFtqjc8BKiVy7MjeccRIjlWrXxVAJkjEonnhfoULmqVewUzwpLnq+KrVCSn
         qbOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vzJv83fM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nolMSAhzlkwUqRXZZF/sAPMJA57T21hrRJDeTRSjFJU=;
        b=dJXtaw26SZGgl3peo//9Pas4Cd5/KdFZ+Pnn8qNNuyVUFFJgVVuiaXx/JShAq94VDm
         PUJgIbX8z8fgDbps7Vh1RyMiKKxfVXg1QO4qqAL6o6ekcCACsQ843X0u3ookiCG/amaU
         PdQhIgM67Vn0TZt6JTPv8Oi+fC6XKPYnSeqDrKcwPr1SpqiF+rk1omqQ+ZTK4bgNlsNM
         Ak2aeWPy6kDzo4DX+EdlMKxBxwfNK+hUrUe32DEHANR1dVCgqYn4pxDZicWaYlICJixj
         A1mlaPgOmbij+gkUUUfpQPSsGc6j3tI6T755064isOl8343zYRqlOT3bGPNcJmo5Popt
         EBEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nolMSAhzlkwUqRXZZF/sAPMJA57T21hrRJDeTRSjFJU=;
        b=nIoyFAtlinn509hBRn2/WT+c9CdWV1eSuoQrXr/6aExI3AZ2kRnoLWYhS8IqbC0zX+
         XmTQ9yjU4z6Ul8+xA48+ZzFFgqgMWDYTjfvg4uLZsMVrS576aDnDYjvxz49D+UBUm6MO
         wfP9cT7j6lSWMgASwNftGohh4CN/zVtPBcdCeOTmA5tYY5Q9HMJgX+vFX1Njl1pT+IiO
         KL73fJJCBcaBSYzptq+9Q2QMhA7qUiYnaCrq5gDvm9F7Mm1ox6S7Y/8g4GH3zSxXuyMI
         wGY9qRz3xD4T3wC3z6xPd39gc/UL5IpB9zPjTfkNgiOVQBU7+gYzIGEh3iWy+xVCnhND
         B8MA==
X-Gm-Message-State: AOAM533FHT2S8tV4GBMZJNmD0u560qljmaEToBvKftPp9lR81dSo8sw5
	HAe14pDdAvziEMGdicwY1NQ=
X-Google-Smtp-Source: ABdhPJy2/rdC2ZVhZK5uM2w/DSVNcYIr7tOUiMIoWDipcJdMfNgLaljF6GDdSDkz9M+xqZneDnrOzw==
X-Received: by 2002:a05:6e02:2cc:: with SMTP id v12mr19305298ilr.115.1604499841016;
        Wed, 04 Nov 2020 06:24:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a981:: with SMTP id q1ls230019jam.4.gmail; Wed, 04 Nov
 2020 06:24:00 -0800 (PST)
X-Received: by 2002:a02:3b2c:: with SMTP id c44mr19854718jaa.134.1604499840505;
        Wed, 04 Nov 2020 06:24:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604499840; cv=none;
        d=google.com; s=arc-20160816;
        b=H8GMZeQQmZ67OPYQ/prnU5lH6ZIye38nLjii4LUPcXu9hCdnmdUOeZNTnt25p5WAbL
         dJ8Hz2cJAbkKqXe6YoRIHvsB7Eu8auMp4m3zfzBderNRaGlPLepVXTgNMd7NNymSa6uY
         3pijyw6BcCnU8bJVwhRvzSOubqU71MARfmkuEBHIL0Enbp62OOYwHkxT8eKulT4/C2tf
         y3oUjkT7U7eq+1bsztHmwirugfTx+HWUKEhCwnXRe2v4aYrk6wp+lQ36xqiASpxJMAUs
         9IJVYivE/kE39W00KQnl0AQcaxSjss4if0cLMoGlHxfrmPQ0lo5VZvt4jfGEYiXhJpLG
         jj1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QR9P889TV6Fm+64MkqBDR3Qv0vkmxXCe4guOWfntHO8=;
        b=Hdc5Nux0mSGyDDlmzwvRJ/wT9IbeXGgBWpKReQALSPEZ1lVAYDVBfxy2ayYQSFtH+H
         gdkmtTCEq59HvxpEsNwAmGDWWgHzgUbSojmPuB5oVHViBQGGXWpsjz6xmQeYX5/Vj4JT
         oG53xRodhoMJLPd6afdBKnI6zyZS/TVVmc9BBxvaG68pbhkqetVIVcWdu9GDfosIBbnM
         MyYtD3hgeoRJCjqyFhr+qYNCSYx7CeGSMHjchkHs5Hw/DfSqbe9vWBTmadHZCbwa9dZS
         JZQeqNDUgoDYdNEL1kCkz1UvfEA55mhdvmVBRMReUDeH7Dqq3oKa2c+6Hsq1FLglhqPy
         YEwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vzJv83fM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id d25si143170ioz.2.2020.11.04.06.24.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 06:24:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id j7so22270239oie.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 06:24:00 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr2710278oie.172.1604499839884;
 Wed, 04 Nov 2020 06:23:59 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103175841.3495947-4-elver@google.com>
 <20201104130111.GA7577@C02TD0UTHF1T.local>
In-Reply-To: <20201104130111.GA7577@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 15:23:48 +0100
Message-ID: <CANpmjNNyY+Myv12P-iou80LhQ0aG5UFudLbVWmRBcM3V=G540A@mail.gmail.com>
Subject: Re: [PATCH v7 3/9] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vzJv83fM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Wed, 4 Nov 2020 at 14:06, Mark Rutland <mark.rutland@arm.com> wrote:
> On Tue, Nov 03, 2020 at 06:58:35PM +0100, Marco Elver wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the arm64 architecture. In particular, this implements the
> > required interface in <asm/kfence.h>.
> >
> > KFENCE requires that attributes for pages from its memory pool can
> > individually be set. Therefore, force the entire linear map to be mapped
> > at page granularity. Doing so may result in extra memory allocated for
> > page tables in case rodata=full is not set; however, currently
> > CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
> > is therefore not affected by this change.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Thanks for dilligently handling all the review feedback. This looks good
> to me now, so FWIW:
>
> Reviewed-by: Mark Rutland <mark.rutland@arm.com>

Thank you!

> There is one thing that I thing we should improve as a subsequent
> cleanup, but I don't think that should block this as-is.
>
> > +#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
>
> IIUC, the core kfence code is using this to figure out where to trace
> from when there's a fault taken on an access to a protected page.

Correct.

> It would be better if the arch code passed the exception's pt_regs into
> the kfence fault handler, and the kfence began the trace began from
> there. That would also allow for dumping the exception registers which
> can help with debugging (e.g. figuring out how the address was derived
> when it's calculated from multiple source registers). That would also be
> a bit more robust to changes in an architectures' exception handling
> code.

Good idea, thanks. I guess there's no reason to not want to always
skip to instruction_pointer(regs)?
In which case I can prepare a patch to make this change. If this
should go into a v8, please let me know. But it'd be easier as a
subsequent patch as you say, given it'll be easier to review and these
patches are in -mm now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyY%2BMyv12P-iou80LhQ0aG5UFudLbVWmRBcM3V%3DG540A%40mail.gmail.com.
