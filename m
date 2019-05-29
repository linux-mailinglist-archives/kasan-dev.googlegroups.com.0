Return-Path: <kasan-dev+bncBDV37XP3XYDRB34QXLTQKGQEN645A7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AD722DE15
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 15:26:08 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id q11sf590807wmq.6
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 06:26:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559136367; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lk3ZdS/Mlaj7oTye/xYk+Kaiplybu7tGryrVnmUAQsiJcC3HW01g028rfj8yQi0Dm3
         PoHOPk7dQR49DyIcauZkg7p2ARuiBLSvCOeOMeBkYIG7VYrKD+4G0fSA0LPJtbNlBzCS
         9QoYZtEhG4LdCwIrfgZd9x0R9n3kfJo3eSvHtK32QwGB28fl6A1EYVlCzqw16sETHgzl
         KBakWaghHZG21QOBsxpHII3zqMHe8VDMr2KLC3sIl8+dC3GLRfnAYe1oZiY8IEJ2rRVk
         ulstKghIQ6gdf3oA0smdySuNqKvPpgndIiSrLxLNMiJaIXTktsWDZiypW60vPoBoT31q
         3DGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OeWTE0h+rARvWP9vTKsbElJBT0IrVWWHDpOuT7ML4t8=;
        b=bckw2A3KrxH260zCjTkxWyyatdvNV+R8/u6y9dys7t9ZmK16omr4R6BbgakAL25BCR
         2soOorFSJNxc98rxmkcVnyNdNPBH8kiAyQILH2MMRkpMVGEO2zlIuL4WEd2yp+aP2T8P
         EamXJKtOG37LbI1yhdV/SS0A6key4vLHCn+Z4w3NTNWa8cMxUqKQ8eQDbSQ9Xoal3Amo
         Mjl7vM3GiULREuX/2fygT65nnfysmnqFws7nmFWvz1RIXKjAacLPSBHlfzTI+thWrkYi
         ovj1TKaWJpXt0DEFA67lImE4dWHcyO00EGHcL9zNipjhgUjDaVTI/dZyzmAyIL9dnYJF
         b8rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OeWTE0h+rARvWP9vTKsbElJBT0IrVWWHDpOuT7ML4t8=;
        b=HajybJR9LxiLtxMRxEssg/kQTADPQBbiH5myVZx7OSIH1CBW+ib1cuqXBXcOonrlQC
         h2CYrLkIU0/omePF3eaa/P63nVGhqxCU3Z1Xf0u6GchLmtPpLIFNVOrEc6vak/Athvl9
         q3Tx3dSvBF7ObkEJK5nx7SqPZSV2aZqkrqQ5DN4z+6OeNqmoXBKJft3D+htmKfcIa+yk
         0AQrqyptY5awkEq/gINakSn7qS88crkFwi4WtvN2CCNirQK+mp57a7sz859rx1wl+hse
         8TxldAvu9tQ0YZbTBdm5cLacwUU8/tmoJ+BSkbUDUx4GJr/LVh2dMSpl08MLkWvB7hom
         xm+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OeWTE0h+rARvWP9vTKsbElJBT0IrVWWHDpOuT7ML4t8=;
        b=bWCSsUUofqaZrSHb6O8OVT3iuqjpQ6WHh/vULlyaj2pbvysH9jdx251SSnO5BNIvJg
         J3qv7U+d856HaX470nTY7ggGbRFuUQsMMmvSs0DGd5I2emjybZXjglwm5TiGiPJdzjut
         GWiF2J4JcBZ9m0kuTHRTCoNiczosHA8Fl1KhFqFCMqV+A+hr5ygI9iPO2Ql35+PR5rH1
         vbIm1W8uSQSViwnRIrHpf27HxZBTILJ6ZMqLyTtjiSER0HP7Z6OtwIQUF2jFysmBVG7N
         Eb1ldYGzby4n5G13AD9qIzOZHhhWfpfb3r9Ti/SjaLNlghBNBVe1IclmYAj+9p9QF0SG
         0a5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVz3BAyNznszk1kGfVXsJwmDUgwa29yzsqmhjURVdFRw0P0BIIg
	h0GdcARYkdXq9sXHKz4WrdU=
X-Google-Smtp-Source: APXvYqzP82Bnw1Po+R4yYwXuZrv9hjKFVIvo6sg04VTpzKSVUvypM3bAeSeSzJLcnVCfcO2vT2z4tA==
X-Received: by 2002:a1c:ef05:: with SMTP id n5mr7120101wmh.149.1559136367765;
        Wed, 29 May 2019 06:26:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1204:: with SMTP id e4ls525646wrx.5.gmail; Wed, 29
 May 2019 06:26:07 -0700 (PDT)
X-Received: by 2002:a5d:4692:: with SMTP id u18mr409383wrq.285.1559136367121;
        Wed, 29 May 2019 06:26:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559136367; cv=none;
        d=google.com; s=arc-20160816;
        b=UBenHy7wMgG+/GIv0YmDCN8fchZPsl4yPl0YiZYJ1X+E9+WQFjS5eaEXR2XPgW4rde
         YvRmCa1LhB2VjlzmcJbCfNvYbJvL5LsCo3l6AwREhFuEwouAUAsoul3VI90UbuzLXvVX
         c13zIZ62rrDq7yoa1nfSUk6OuWAs1yz7IA0mp+SAwDlK+3UiHh4W7AzqRqT7Lk7vY6FQ
         LhbQnmBafrNYTI5ueN8Gxv1vMbNhO/ZmpwCb9zILnR8pyNgEVjqPL/cSfvR0sIs46Yxd
         fUd6vPJn+br9FQEE8VIVwHH4iePR78nPw2Sy76woTWogiaESIpUSiPaPr0OM1rmhu6tF
         U1RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=C6xm/1JZRTGiQcbYl/hGDnYi3+ndxEDlmLfrg15PAmQ=;
        b=je5XwlQwbT3FRbZEhV5F6DAfrk3rQFTGM5cLDfrHlrUdXMO5EkXlXxb4Bl8lziZJmy
         j8t/M/EeN36vwAhH6KE/NSdE2jcROEGjX9ghX7KBb2J8n4UathjE5x8ubpPPjJEUGRuE
         Maev46l8Y2tRH2+L0+9fvxWH8tuNEVSEJj2QPdiPUV4mr0+uzlaRADXpyGr4fNfgEE/G
         q0epL0ole8bYdXl0dijmTjvitmEt96qU9Hb0KaO/idPCxloH5a20gifxvUXWJhs61b4E
         12BcXlUbr02l5O0/tQTQ9eFbFE+m6J2gDV8e/Xiljr/ym+oebNkqQlF8fuIJTkz5ciYX
         U0yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id x3si103817wmh.4.2019.05.29.06.26.06
        for <kasan-dev@googlegroups.com>;
        Wed, 29 May 2019 06:26:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8CE4C80D;
	Wed, 29 May 2019 06:26:05 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8F6763F59C;
	Wed, 29 May 2019 06:26:02 -0700 (PDT)
Date: Wed, 29 May 2019 14:26:00 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190529132559.GF31777@lakrids.cambridge.arm.com>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net>
 <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net>
 <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of mark.rutland@arm.com designates
 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Wed, May 29, 2019 at 12:57:15PM +0200, Dmitry Vyukov wrote:
> On Wed, May 29, 2019 at 12:30 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, May 29, 2019 at 12:16:31PM +0200, Marco Elver wrote:
> > > On Wed, 29 May 2019 at 12:01, Peter Zijlstra <peterz@infradead.org> wrote:
> > > >
> > > > On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
> > > > > For the default, we decided to err on the conservative side for now,
> > > > > since it seems that e.g. x86 operates only on the byte the bit is on.
> > > >
> > > > This is not correct, see for instance set_bit():
> > > >
> > > > static __always_inline void
> > > > set_bit(long nr, volatile unsigned long *addr)
> > > > {
> > > >         if (IS_IMMEDIATE(nr)) {
> > > >                 asm volatile(LOCK_PREFIX "orb %1,%0"
> > > >                         : CONST_MASK_ADDR(nr, addr)
> > > >                         : "iq" ((u8)CONST_MASK(nr))
> > > >                         : "memory");
> > > >         } else {
> > > >                 asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
> > > >                         : : RLONG_ADDR(addr), "Ir" (nr) : "memory");
> > > >         }
> > > > }
> > > >
> > > > That results in:
> > > >
> > > >         LOCK BTSQ nr, (addr)
> > > >
> > > > when @nr is not an immediate.
> > >
> > > Thanks for the clarification. Given that arm64 already instruments
> > > bitops access to whole words, and x86 may also do so for some bitops,
> > > it seems fine to instrument word-sized accesses by default. Is that
> > > reasonable?
> >
> > Eminently -- the API is defined such; for bonus points KASAN should also
> > do alignment checks on atomic ops. Future hardware will #AC on unaligned
> > [*] LOCK prefix instructions.
> >
> > (*) not entirely accurate, it will only trap when crossing a line.
> >     https://lkml.kernel.org/r/1556134382-58814-1-git-send-email-fenghua.yu@intel.com
> 
> Interesting. Does an address passed to bitops also should be aligned,
> or alignment is supposed to be handled by bitops themselves?
> 
> This probably should be done as a separate config as not related to
> KASAN per se. But obviously via the same
> {atomicops,bitops}-instrumented.h hooks which will make it
> significantly easier.

Makes sense to me -- that should be easy to hack into gen_param_check()
in gen-atomic-instrumented.sh, something like:

----
diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
index e09812372b17..2f6b8f521e57 100755
--- a/scripts/atomic/gen-atomic-instrumented.sh
+++ b/scripts/atomic/gen-atomic-instrumented.sh
@@ -21,6 +21,13 @@ gen_param_check()
        [ ${type#c} != ${type} ] && rw="read"
 
        printf "\tkasan_check_${rw}(${name}, sizeof(*${name}));\n"
+
+       [ "${type#c}" = "v" ] || return
+
+cat <<EOF
+       if (IS_ENABLED(CONFIG_PETERZ))
+               WARN_ON(!IS_ALIGNED(${name}, sizeof(*${name})));
+EOF
 }
 
 #gen_param_check(arg...)
----

On arm64 our atomic instructions always perform an alignment check, so
we'd only miss if an atomic op bailed out after a plain READ_ONCE() of
an unaligned atomic variable.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529132559.GF31777%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
