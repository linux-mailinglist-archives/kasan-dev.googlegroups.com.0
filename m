Return-Path: <kasan-dev+bncBCMIZB7QWENRBO62XHTQKGQE2NAMMXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FF752DBDE
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 13:30:04 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id f18sf950319otf.22
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 04:30:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559129403; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZU+IK7End/rcrZd2qbhl3o2rMzaRkxqiYt3soRUsGIQg4G1keYQ+H/eyesIB/9wqg
         7YVbIyyJ3J/hik6v/SfEB287d4nqbHNGMEsPRide2VakL8/czvPQr4fHUgiI4GTX+0tA
         3tojmu+ZBM7vr09+03II8+gPFg4hjzb6GrVDqFHuR5gELUlHJbQTjjAmpGbAQwmMKYIX
         GmpXuzwTMfjWCst7//EZz5nCOu10LrB6kKzxeGvvcgIQTVLzmrWji+V0W43NywME9t7O
         er76YXvyf0llmd/AGa6St79fhujrwnF/lvAwkibuAZcopLiTriV94DBus3Gtj9wMgavw
         f/IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xZRC0wvE7p1c1OoGpMQG2c83thgOkecksNFK8Q2RsEs=;
        b=txkNYTZIe0tCLX9s+f7eFdW699p+v52dNi8jhmkTtrbI9YPOzLIB5elb50FUDKnhk2
         U38ybra49uUoldeSEMLvWBb/JkEt5iAuX5h1+HSL6mQROK2H74oI3W+RGAZ+BV9cp+Pu
         9HkoxAOn1pCy1PSM6yL5Urb846IouvFlrIHq54znLCL9Z32s9WH5RHudBySXjJxFz/D3
         SdJf/dQnoQ3SoUTV/X5FdYmqO/lCEdaa6Grh0sk6Bq9QfZZpp3FgXGw0ChmQJeEKr22g
         AK3lmJnYnfdm+GWoUiafddja3JprrV6Bz/ym42TQYXK8nQLzTQKePQyHb+ecvtU7Y15L
         DhdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YbJT7VLF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xZRC0wvE7p1c1OoGpMQG2c83thgOkecksNFK8Q2RsEs=;
        b=mgfCaoDE+aDTMPUN3uSADwjjShR24VE1zGoDtYbTE9bA6NcIJQu8tEjpx5Bz8ID1Sq
         xzli0lMkxKkaZt3pDdr8KIT5NHDwCEfh+7IpQhCD+zZCdH3UAOyB5hq8RGDoP4PkOaJU
         PTje3DyphcM5OhWCxKfbwWq8KCC6Z+fVjyIXrqBNt+MHwWuh0dDFtSqCvuqt3jFnhh3S
         mesiFLgePWD0a491ALISQOKkA3r0AMwYCbjaok0eARQEKsXgVoItgAcbEfnghE+a95c2
         moIzwuVoHyvfhl+HXXCVbjgusSonztIPF1IooBU9UrjEjUllAv4SAdX7/dVEvYTkRBKv
         THQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xZRC0wvE7p1c1OoGpMQG2c83thgOkecksNFK8Q2RsEs=;
        b=Tk62Qvu8LZrUkAoc6eHnL1kTLxYAxE35ZFi2E1jx962F2i9PEEhprCy5A2xuvX6NzO
         RsJhdCB8/MTkqoGt05pQaaZoQBXiCpQ174Emyt5ujUp5PVcq4/YDDI5RjqeL+tXnK+Fb
         UMKu5JbLzJoe6XLJ8v2/8qbW8nCF78fQtUHp0d6JztaRRhFhHlDvM9UdCrlAE+M1Mo11
         KhUrCft+uyEaYOJRDI+6HIO3lJyNIneFdQiSeR4JZo507vIekZ/eK2JQDqCSIqpg/kRB
         k75EkDcbnZYOYQtL+ARhs2ZtS1qlS96a3DP7BemZqvGRKFMDnXxEGqb+kNOIpfU93jrW
         mnJA==
X-Gm-Message-State: APjAAAW6hyOsPez/Frska5EMBMM27LnRb5Dn/iH/y8NQ+AfArGBUgR20
	keVHUpswSBNsyR+TjsD6A3E=
X-Google-Smtp-Source: APXvYqwuOHjByB0J/W3Vk/OAMMttn5mze667AqwVPry4VDR3wwjS8ZAPgpu6bSfSIcHeqkZ2foA6WA==
X-Received: by 2002:a9d:6c89:: with SMTP id c9mr29483467otr.52.1559129403414;
        Wed, 29 May 2019 04:30:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:ba2:: with SMTP id 31ls359787oth.2.gmail; Wed, 29 May
 2019 04:30:03 -0700 (PDT)
X-Received: by 2002:a05:6830:200d:: with SMTP id e13mr12418otp.304.1559129403138;
        Wed, 29 May 2019 04:30:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559129403; cv=none;
        d=google.com; s=arc-20160816;
        b=RCNbh2X/O0JraJvAZUPph6r0OaA/phnFQe+VkIYxtemutHES+8NIS0EVelR67Ft4Ha
         ipMaPRU5ob82b1sUh5Rog87JuTQZ751H2uCSScOWEJI3VZ/9I2dCIyRnf7Yi4sAPmfrp
         0rVbUsYrU8REkYE+v48f4mDlZy8WWIiBE1+pfZdyollYI3CmvFzt7RF7uZo73Gej7HH1
         QZStZNBKFboVMAJyx+gYyM1Yjh0UNhyeL7aQnZd7FfZoAANHjbISOOBgLxcGwrU9gxfD
         B9xz2zOMRwGvRPHk/aZtTKGMBZoxVDgmv9X8bQwKbHsnAceH0pUgJsEeqQQhWlpAeEAQ
         zpSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3AdnAOZFu4T3VBLgV3Cb7hGxak9UusYOHweQj/woqpE=;
        b=Y1VML/pJMur5aQUsScmeZwAKGC/Kh5FANFO1Hc7HhTGf/p2hYguMZ47iVNeJNphPl7
         AunfaPd8ku25vj+qtruMzfYhN8KM9lsbLfhNihOanQHESYUuZZvVFEYHgDTSVON2BvY0
         T0TkuRr0DLi6otndJzD48Houns6uhEhY//+1G7SBNTpiyrGqAQcIpKTqZGrcMBhX1Fju
         fM59XYEwgkMNoY+A0hIwh3Bxs7DILdMkq7kyirVOYsVBuyJFNZnZ5cQ+R5cDqkJMPdzC
         dsZPu8SxmMpAqf2rTHmHkTlwYobxq7cTEMZLa9doiiLzXtN5NFGKLpa0YERMWRYkoQQO
         qaZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YbJT7VLF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id 9si703171oti.2.2019.05.29.04.30.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 04:30:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id g16so1477032iom.9
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 04:30:03 -0700 (PDT)
X-Received: by 2002:a6b:e711:: with SMTP id b17mr12875963ioh.3.1559129402345;
 Wed, 29 May 2019 04:30:02 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com> <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net> <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net> <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
 <377465ba-3b31-31e7-0f9d-e0a5ab911ca4@virtuozzo.com>
In-Reply-To: <377465ba-3b31-31e7-0f9d-e0a5ab911ca4@virtuozzo.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 13:29:51 +0200
Message-ID: <CACT4Y+ZDmqqM6YW72Q-=kAurta5ctscLT5p=nQJ5y=82yVMq=w@mail.gmail.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YbJT7VLF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, May 29, 2019 at 1:23 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> On 5/29/19 1:57 PM, Dmitry Vyukov wrote:
> > On Wed, May 29, 2019 at 12:30 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >>
> >> On Wed, May 29, 2019 at 12:16:31PM +0200, Marco Elver wrote:
> >>> On Wed, 29 May 2019 at 12:01, Peter Zijlstra <peterz@infradead.org> wrote:
> >>>>
> >>>> On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
> >>>>> For the default, we decided to err on the conservative side for now,
> >>>>> since it seems that e.g. x86 operates only on the byte the bit is on.
> >>>>
> >>>> This is not correct, see for instance set_bit():
> >>>>
> >>>> static __always_inline void
> >>>> set_bit(long nr, volatile unsigned long *addr)
> >>>> {
> >>>>         if (IS_IMMEDIATE(nr)) {
> >>>>                 asm volatile(LOCK_PREFIX "orb %1,%0"
> >>>>                         : CONST_MASK_ADDR(nr, addr)
> >>>>                         : "iq" ((u8)CONST_MASK(nr))
> >>>>                         : "memory");
> >>>>         } else {
> >>>>                 asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
> >>>>                         : : RLONG_ADDR(addr), "Ir" (nr) : "memory");
> >>>>         }
> >>>> }
> >>>>
> >>>> That results in:
> >>>>
> >>>>         LOCK BTSQ nr, (addr)
> >>>>
> >>>> when @nr is not an immediate.
> >>>
> >>> Thanks for the clarification. Given that arm64 already instruments
> >>> bitops access to whole words, and x86 may also do so for some bitops,
> >>> it seems fine to instrument word-sized accesses by default. Is that
> >>> reasonable?
> >>
> >> Eminently -- the API is defined such; for bonus points KASAN should also
> >> do alignment checks on atomic ops. Future hardware will #AC on unaligned
> >> [*] LOCK prefix instructions.
> >>
> >> (*) not entirely accurate, it will only trap when crossing a line.
> >>     https://lkml.kernel.org/r/1556134382-58814-1-git-send-email-fenghua.yu@intel.com
> >
> > Interesting. Does an address passed to bitops also should be aligned,
> > or alignment is supposed to be handled by bitops themselves?
> >
>
> It should be aligned. This even documented in Documentation/core-api/atomic_ops.rst:
>
>         Native atomic bit operations are defined to operate on objects aligned
>         to the size of an "unsigned long" C data type, and are least of that
>         size.  The endianness of the bits within each "unsigned long" are the
>         native endianness of the cpu.
>
>
> > This probably should be done as a separate config as not related to
> > KASAN per se. But obviously via the same
> > {atomicops,bitops}-instrumented.h hooks which will make it
> > significantly easier.
> >
>
> Agreed.

Thanks. I've filed https://bugzilla.kernel.org/show_bug.cgi?id=203751
for checking alignment with all the points and references, so that
it's not lost.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZDmqqM6YW72Q-%3DkAurta5ctscLT5p%3DnQJ5y%3D82yVMq%3Dw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
