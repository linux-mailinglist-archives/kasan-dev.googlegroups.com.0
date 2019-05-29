Return-Path: <kasan-dev+bncBC27HSOJ44LBBG6WXHTQKGQESZY5CNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A5B42DBA2
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 13:21:00 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id n23sf2961871edv.9
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 04:21:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559128860; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZR6ZXuiLjvpc32UQK20fZN51FasFJPjbByveG6KXILv4PgpX8M5JpJc0D2vO75gfx
         3Qp0pKHiGpMmuAkH18f7C15aL/BneYKXeTQ9JCJWlPxcXVVV9yjfFWRvvMvUgdr+Wqry
         I/g7b3kv43W6yhdkpXWebHejLctTu4huBr62fUtgxHR8XO4AAF00m/Y8mBksElzdVqNA
         Zth4oao7+ctOXCd2aFVO8pVNnJEZ0eaZi/qePvcPPakr4D6eyMK1eV3Xs+RSE2RAgYcN
         nIL7M2GIybEJKikpYMK5xw2YlOF002+jyyTv3Hs0ON4pfhJ2fPa7w6PLNU19C/xi8Ur8
         iiDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=9FU6hqx8/0hYGKKFLMjr7s/v2yuhOX6+BsOMScJz+mg=;
        b=W9pbl7vuEYQ//6sdFiUDwEHSRxvUdGidKY5Thr/ncz3nzs5N27JDFWNsmade9Tydee
         yGLuMoMGYIdser7qHS9/G7ups0VLXN4Z0gTJx3a7fhNWYoJ2WMRgGN1sofvP33YMF/Uv
         6gARIPsCCR4Qz1U8ciICcph//imR1/vjla/IjsRXGoAmcuD7bcgOoRqVEBjhMCBFz7/C
         8XG1u7X8N8LMmBXEXVV+OGqFj1jG9o4mckvNeoymQFzqEC4b6/LsZJ/vLzaNCITC7FCp
         zOGOm41TGybkGMIuRXv/DyWSymMm2Dty3EK4PqmwcjZgaYizTEfiu6eScML3+tN1sfPK
         be3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 146.101.78.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9FU6hqx8/0hYGKKFLMjr7s/v2yuhOX6+BsOMScJz+mg=;
        b=lJ2OJGu5V5GPwhj/6CDuL8OpokGXBcmRXbdBwauUVzDsxdGsxY5NpFiZ6FvrWlObJm
         4OnTWz6unkvmAzGZ1ZbyyBURUwdH/GuUtqurK0+cu1IwRAhpDX+bAAELUAkzdJtVWtta
         GvHG5G4p7enScUBJZYtgWtfJqirkPQymX0D575nyE/d2p1MLQWLT5VawhFyyftFd76x5
         mruXkJwVPHp6Y/8GnhWfzvD31CdtKfdzhsOWAuh3a7mM2K3YderW+rVp/tFaMe6SBo2t
         xzEIQAUx1fa+UcWJ7YoVMyr/f1gz96QILvHRJg2VkjaSN65zYt4CNoRybL6yw5L19M4I
         Utig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9FU6hqx8/0hYGKKFLMjr7s/v2yuhOX6+BsOMScJz+mg=;
        b=em6LaUlLa5MRFeXMpAMULdoNkIIRZwi6W855kvgQXXhxh0LJhSQocfmEi2dhd6lh/v
         bqv/t0E3OQvcKlZXCICToQy3kC6JGsg5Tf8iM+FsVYBb8qpozogvgMY8DcTUdnJGvM4K
         yYnC07SeCtEe2nJD4Bq8DvOPD0FPUDNtWlwFUtHE/oISrHn2DM9WqNqBtobW9ypUH+7g
         pC5rUl0zyj93dPGxekjGwBhN8tcH5KKh3ptaeLr/VNhHXc2YG6xcSn1p4lcG8LJwNzv7
         IqYhLNgrzSuDnxOkxNsbjIrcW2n/+pSm/vmpYSTdN2EzpK5T3lNHpzhAjL1qk+sWohvq
         JelA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUD7mSg05bhQRBVpfTiqnyoGmgaUU3qh8HLdtxFLk184XiRnopv
	9CFlAFpJRP0+F2aelLv30Sc=
X-Google-Smtp-Source: APXvYqwh76wQhEOTQ0ak4MZEbnl6dI1jfOitDyHcpDsczkPrSsktynYoJLqvzQtHgFL3M6G/7Knx6w==
X-Received: by 2002:a17:906:11d3:: with SMTP id o19mr89297994eja.278.1559128859895;
        Wed, 29 May 2019 04:20:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1849:: with SMTP id w9ls474961eje.2.gmail; Wed, 29
 May 2019 04:20:59 -0700 (PDT)
X-Received: by 2002:a17:906:68c4:: with SMTP id y4mr95125788ejr.198.1559128859243;
        Wed, 29 May 2019 04:20:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559128859; cv=none;
        d=google.com; s=arc-20160816;
        b=LvVjsS0mi2TPV9LGj41HDUoNupcUEmWA/35uDhPCV/PsOdFoAqgt94P1cYUemH6NH4
         a9O8w/NDKpMj6EbF8A3I/xqrIpagsgZL3YWFSXx0E5j66x7VlnVBP4GnTIFq4gbSQzyT
         q9r7rmZhHR2Mzl4u+h7ge4dlMvMbrhxXCkYQkEnqg2EBCz4nblqs8V72QxbMIhF6V68O
         eqdr3FNLp/HlOWuZSgvTxSw7oB8aa3WgcGVXrETGJ/GHwZEvPooSr3fl+q8FimHJmh+U
         jHmLRyV9ql754nvNmg+3LsokSWC33tLyK7topRovBJdedgLNNADfXK2pRowVqFPAOQVj
         gENA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=7Zz9BWuFB2sP/Z890+Wa9eCWT1qP+0rHL9QfBKY4v5M=;
        b=KFhTJm9O9tDPGD5ZXGh46hnKacq+XJomE/dYb3jEIe3NxM1wbr5fmSYBxcunN3/cjK
         GFsV8/Zn4ie8I1VJNAMwwUKgZFo6t/Y2dAdSuog4LHn9LQFkx2a/gOEbWb++uz1bUkE/
         I5JXtaXD7SSiLzs0QS5YtcGts24bR6xQN2HZzTlw4Ldc5iDN7wUIavNYehTe4dqE9e7G
         S3vOV/loxWGch2VgO2WuzzTPKZVtw5wfxYTn6Dj9CWdRarfmqNQnAP2QMquSg9UGpDso
         1g353idx9Jr8osp2RkDInXC0nuFFiQiyRMJEgn5K0mVgPta/S9IuLxE0OyqqfnUcAkpJ
         1ZeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 146.101.78.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [146.101.78.151])
        by gmr-mx.google.com with ESMTPS id f9si217289ede.4.2019.05.29.04.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 04:20:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 146.101.78.151 as permitted sender) client-ip=146.101.78.151;
Received: from AcuMS.aculab.com (156.67.243.126 [156.67.243.126]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-175-n6S3TAExMKGEa1CSkKSjew-1; Wed, 29 May 2019 12:20:57 +0100
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) with Microsoft SMTP
 Server (TLS) id 15.0.1347.2; Wed, 29 May 2019 12:20:56 +0100
Received: from AcuMS.Aculab.com ([fe80::43c:695e:880f:8750]) by
 AcuMS.aculab.com ([fe80::43c:695e:880f:8750%12]) with mapi id 15.00.1347.000;
 Wed, 29 May 2019 12:20:56 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Dmitry Vyukov' <dvyukov@google.com>, Peter Zijlstra
	<peterz@infradead.org>
CC: Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, "Jonathan
 Corbet" <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar
	<mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin"
	<hpa@zytor.com>, the arch/x86 maintainers <x86@kernel.org>, Arnd Bergmann
	<arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, "open
 list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML
	<linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: RE: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Thread-Topic: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Thread-Index: AQHVFg1T4KMnNqJYZ0KJ/Gnew5X/QaaB8uxw
Date: Wed, 29 May 2019 11:20:56 +0000
Message-ID: <a0157a8d778a48b7ba3935f3e6840d30@AcuMS.aculab.com>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net>
 <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net>
 <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
In-Reply-To: <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-MC-Unique: n6S3TAExMKGEa1CSkKSjew-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 146.101.78.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com
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

From: Dmitry Vyukov
> Sent: 29 May 2019 11:57
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

The bitops are defined on 'long []' and it is expected to be aligned.
Any code that casts the argument is likely to be broken on big-endian.
I did a quick grep a few weeks ago and found some very dubious code.
Not all the casts seemed to be on code that was LE only (although
I didn't try to find out what the casts were from).

The alignment trap on x86 could be avoided by only ever requesting 32bit
cycles - and assuming the buffer is always 32bit aligned (eg int []).
But on BE passing an 'int []' is just so wrong ....

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0157a8d778a48b7ba3935f3e6840d30%40AcuMS.aculab.com.
For more options, visit https://groups.google.com/d/optout.
