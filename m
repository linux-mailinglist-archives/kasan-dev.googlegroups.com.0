Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDH7W3XAKGQE2JDL6LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id CA9D2FCFEF
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 21:56:45 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id v71sf3166248vkd.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 12:56:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573765004; cv=pass;
        d=google.com; s=arc-20160816;
        b=0WpqciIc2kF23PSc4WJSbPdYZ8bL6s/Vh+JADt14PrQZKfrtwYwCF0D38p9humJ2RR
         04chBHbiVX89RioGwPLv8Xt98UirywRVw0AKVxMabAPvQFV/5cJ74oWNTUo/pIwpRanf
         RSbyRPsI4eyNU9Pn4gXZpkcu3j9JUTkGSMf7KgDNulXNrbd115xvvDJOHpiZW7HgF9EF
         0GouDNs/xNf2Q+0g4IRYHT5LjyFxod0rym5ZLkoLtTDExLStf7iBy/Vtouy/xRM5+hwh
         OLrvzFxnvMKhYhQgnCdDD7kKgbNVcaXeQMNKzl6PNvmFrfZdEc0FBkJwk153uqOKL3mA
         Y2iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c1zaNPiOSTbt8AiOIqHngiqAlilS8OGo7mk6/iT+3L4=;
        b=oUQILxUpf9SGrDEhp3HCuKTTc9Yu+ekaIl+dyRETgy35Drh9+wqvmQ7JoPkTrLYsFe
         U3BnA/7W8TM5xGuHrds+txLNK0u6p+a0emxuOaCv13Pwv414Rq1AxRalMmY5PpSlsza7
         RkBng4uR49S134SFarxZR2Um3NqE/VSA+ISTVHiFrAlJQKqutsmu2Prcnw5BG7XKhUqt
         AQF/TMzF/k0+JtcgD/wv/Bkuctw7hOWtAJu26jAXOypVssUCl1fiZVg2TaJ2at9XtAj0
         kSTnatu93TeJONsscEgpddiC3pQtCZnirXlKuUyg9OthNDzAr4PLDcnqN0GLxyXpxkGx
         c9hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qCp1f1YP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c1zaNPiOSTbt8AiOIqHngiqAlilS8OGo7mk6/iT+3L4=;
        b=JlEQr8OBrWsYh38q02LHxlPBmXB9h/EbqvDaCRECmckSSCF9xKurznHsoczQdP+zZ4
         T0WuwMksVKDc4X9+KCAHbnFYdayTkjFFmsdvMjE9R0sZxGnOc7RhpHOncIX7rvw6L6Nw
         PMdwPBXuZtvWa9cgr5Pmw8FjazhtLDYxTQyPaXV/y/esOH/oHG1a2kMe897Sn3q2Rz8I
         elvfmRwXTG4AYXbeHeqTTgx+moLeJxw4KH8WjT9XBZYIzmcIfDU9zDNmi1ySN55GFlZB
         lt7EKExuQRE7fSHQX4ZS1VYzea7xoffE8c++HakB0IPnHE9lqUvZYPwy3eHWsKknX7h5
         MIGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c1zaNPiOSTbt8AiOIqHngiqAlilS8OGo7mk6/iT+3L4=;
        b=ZHSCwE2YQoS5DIoAIXD5c8uNPi+JZ1Nl0O8cVTtp4M7JujII+1ZHNMtXVL/SVB5f/p
         jPWHTPyewXZ8dtqYqpc9bEPtzq6Vh6iLSmSgrPoXKikA3A7iQqFHOP+McPmQFEfnG4Cz
         hsr3ICGKU7CYX26L4r7UdBWnzac0PYiR3yvC1ee0nZWHu/C7EbphoXUuxF8YOumzOKnv
         XiyVxdg8QzKemVX0hxfCUOSwR5Atus9X2AIITxPLOwLA65P/kde3xC7bnMeZQYNYQqZR
         VaB2HwNjb+fkoJACYVdzX2HslTwOBAWv6EeTma3C5wfwwxnpFH8N3L+8KPPa6mFq21JD
         eXqg==
X-Gm-Message-State: APjAAAUbZYYEL0F/5eCk2nTuJp7KPX0CS7CnrqMD16Tc0OU1xRRmnELW
	QMJ20Fg3p72ZVBgh1hnPMhM=
X-Google-Smtp-Source: APXvYqzpgWiUmHYxMHSta//FvpdTyqr06J8/HgvK10o+kihu7tulM9JCxvmz5DQCdnCnEk6vHaNZlw==
X-Received: by 2002:ac5:ccdc:: with SMTP id j28mr312266vkn.69.1573765004718;
        Thu, 14 Nov 2019 12:56:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:421:: with SMTP id 30ls208656uav.9.gmail; Thu, 14 Nov
 2019 12:56:44 -0800 (PST)
X-Received: by 2002:ab0:784d:: with SMTP id y13mr6724348uaq.34.1573765004081;
        Thu, 14 Nov 2019 12:56:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573765004; cv=none;
        d=google.com; s=arc-20160816;
        b=ivO9IsaB79EZro5DJo5vmhvBOMUkKmgndrQVm7Ts859/ldUBd9be0UkPlCjtLLBXRX
         om1VbJmYE2XH6/Rg0lc4+sZLwCxiVd+QCHTiIUdPlSMd2SvM75qOo+7sCW2iKZ7Y+wRu
         kB06jFX3a6Y3KUTUJkKSWMf/C69L+2HqXnWPX8MsqKrRkrysDG2pS7TUmbgCtHvpgemh
         F5yEsSZCOQibv2bhcOmgjMrGFIWjq8/uYdqPWnyFo70zhu8Fl18x9f1nIUVVTuNZR3dm
         dDUoQVgr1Uor9jjqag//41mMTdKvyVf7npkRr4eKfce0PCRBB3rAT238BOVedAcbpGU/
         cIrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MGPaD+JCp5eJsiedxtiR+j0yWvlYxXBC3sLEfcuEPJI=;
        b=KWFV8q+xqPoVnLHoGEVWSkuOmQDA2/f+uI7afBiLrj0nEc6/ae+0WoGQTKP1ffeQtK
         mKvwZ4ACFySNQ8HKSTWphNRm9ZgtPeKllf+7rSRwHDedZ9aQcbQOsc8ZDghsZKnlIzjT
         WsrfQ1fiUnC03Q4nAsHjKeA7YOtrn7iw+Uizipf0z5Rv3AMRenMvVVyAioHjTL5NB6GP
         lOXDQEMaZvDTbUzVMcTu/UZPHQBfY+MqmLrDFVxhQ6HX6sDH/AIxVdBZPBl5X15o59MV
         q1HLhtZGFBWuonwGFQdMSjLyPja0f0/4as/JuivBSkSLYHcQTWSl0zCijVgUAqsBpOaU
         PyvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qCp1f1YP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id p195si484913vkp.1.2019.11.14.12.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 12:56:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id l14so6107150oti.10
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 12:56:44 -0800 (PST)
X-Received: by 2002:a9d:82e:: with SMTP id 43mr9268935oty.23.1573765002545;
 Thu, 14 Nov 2019 12:56:42 -0800 (PST)
MIME-Version: 1.0
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net>
 <878sp57z44.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <878sp57z44.fsf@dja-thinkpad.axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 21:56:31 +0100
Message-ID: <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with
 generic bitops
To: Daniel Axtens <dja@axtens.net>
Cc: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, 
	linux-arch <linux-arch@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qCp1f1YP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Mon, 28 Oct 2019 at 14:56, Daniel Axtens <dja@axtens.net> wrote:
>
> Hi all,
>
> Would it be possible to get an Ack from a KASAN maintainter? mpe is
> happy to take this through powerpc but would like an ack first.
>
> Regards,
> Daniel
>
> >> Currently bitops-instrumented.h assumes that the architecture provides
> >> atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
> >> This is true on x86 and s390, but is not always true: there is a
> >> generic bitops/non-atomic.h header that provides generic non-atomic
> >> operations, and also a generic bitops/lock.h for locking operations.
> >>
> >> powerpc uses the generic non-atomic version, so it does not have it's
> >> own e.g. __set_bit that could be renamed arch___set_bit.
> >>
> >> Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
> >> split. This allows arches to only include the headers where they
> >> have arch-specific versions to rename. Update x86 and s390.
> >
> > This patch should not cause any functional change on either arch.
> >
> > To verify, I have compiled kernels with and without these. With the
> > appropriate setting of environment variables and the general assorted
> > mucking around required for reproducible builds, I have tested:
> >
> >  - s390, without kasan - byte-for-byte identical vmlinux before and after
> >  - x86,  without kasan - byte-for-byte identical vmlinux before and after
> >
> >  - s390, inline kasan  - byte-for-byte identical vmlinux before and after
> >
> >  - x86,  inline kasan  - 3 functions in drivers/rtc/dev.o are reordered,
> >                          build-id and __ex_table differ, rest is unchanged
> >
> > The kernels were based on defconfigs. I disabled debug info (as that
> > obviously changes with code being rearranged) and initrd support (as the
> > cpio wrapper doesn't seem to take KBUILD_BUILD_TIMESTAMP but the current
> > time, and that screws things up).
> >
> > I wouldn't read too much in to the weird result on x86 with inline
> > kasan: the code I moved about is compiled even without KASAN enabled.
> >
> > Regards,
> > Daniel
> >
> >
> >>
> >> (The generic operations are automatically instrumented because they're
> >> written in C, not asm.)
> >>
> >> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> >> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
> >> Signed-off-by: Daniel Axtens <dja@axtens.net>
> >> ---
> >>  Documentation/core-api/kernel-api.rst         |  17 +-
> >>  arch/s390/include/asm/bitops.h                |   4 +-
> >>  arch/x86/include/asm/bitops.h                 |   4 +-
> >>  include/asm-generic/bitops-instrumented.h     | 263 ------------------
> >>  .../asm-generic/bitops/instrumented-atomic.h  | 100 +++++++
> >>  .../asm-generic/bitops/instrumented-lock.h    |  81 ++++++
> >>  .../bitops/instrumented-non-atomic.h          | 114 ++++++++
> >>  7 files changed, 317 insertions(+), 266 deletions(-)
> >>  delete mode 100644 include/asm-generic/bitops-instrumented.h
> >>  create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
> >>  create mode 100644 include/asm-generic/bitops/instrumented-lock.h
> >>  create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h
> >>
> >> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
> >> index 08af5caf036d..2e21248277e3 100644
> >> --- a/Documentation/core-api/kernel-api.rst
> >> +++ b/Documentation/core-api/kernel-api.rst
> >> @@ -54,7 +54,22 @@ The Linux kernel provides more basic utility functions.
> >>  Bit Operations
> >>  --------------
> >>
> >> -.. kernel-doc:: include/asm-generic/bitops-instrumented.h
> >> +Atomic Operations
> >> +~~~~~~~~~~~~~~~~~
> >> +
> >> +.. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
> >> +   :internal:
> >> +
> >> +Non-atomic Operations
> >> +~~~~~~~~~~~~~~~~~~~~~
> >> +
> >> +.. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
> >> +   :internal:
> >> +
> >> +Locking Operations
> >> +~~~~~~~~~~~~~~~~~~
> >> +
> >> +.. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
> >>     :internal:
> >>
> >>  Bitmap Operations
> >> diff --git a/arch/s390/include/asm/bitops.h b/arch/s390/include/asm/bitops.h
> >> index b8833ac983fa..0ceb12593a68 100644
> >> --- a/arch/s390/include/asm/bitops.h
> >> +++ b/arch/s390/include/asm/bitops.h
> >> @@ -241,7 +241,9 @@ static inline void arch___clear_bit_unlock(unsigned long nr,
> >>      arch___clear_bit(nr, ptr);
> >>  }
> >>
> >> -#include <asm-generic/bitops-instrumented.h>
> >> +#include <asm-generic/bitops/instrumented-atomic.h>
> >> +#include <asm-generic/bitops/instrumented-non-atomic.h>
> >> +#include <asm-generic/bitops/instrumented-lock.h>
> >>
> >>  /*
> >>   * Functions which use MSB0 bit numbering.
> >> diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
> >> index ba15d53c1ca7..4a2e2432238f 100644
> >> --- a/arch/x86/include/asm/bitops.h
> >> +++ b/arch/x86/include/asm/bitops.h
> >> @@ -389,7 +389,9 @@ static __always_inline int fls64(__u64 x)
> >>
> >>  #include <asm-generic/bitops/const_hweight.h>
> >>
> >> -#include <asm-generic/bitops-instrumented.h>
> >> +#include <asm-generic/bitops/instrumented-atomic.h>
> >> +#include <asm-generic/bitops/instrumented-non-atomic.h>
> >> +#include <asm-generic/bitops/instrumented-lock.h>
> >>
> >>  #include <asm-generic/bitops/le.h>
> >>
> >> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
> >> deleted file mode 100644
> >> index ddd1c6d9d8db..000000000000
> >> --- a/include/asm-generic/bitops-instrumented.h
> >> +++ /dev/null
> >> @@ -1,263 +0,0 @@
> >> -/* SPDX-License-Identifier: GPL-2.0 */
> >> -
> >> -/*
> >> - * This file provides wrappers with sanitizer instrumentation for bit
> >> - * operations.
> >> - *
> >> - * To use this functionality, an arch's bitops.h file needs to define each of
> >> - * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> >> - * arch___set_bit(), etc.).
> >> - */
> >> -#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> >> -#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> >> -
> >> -#include <linux/kasan-checks.h>
> >> -
> >> -/**
> >> - * set_bit - Atomically set a bit in memory
> >> - * @nr: the bit to set
> >> - * @addr: the address to start counting from
> >> - *
> >> - * This is a relaxed atomic operation (no implied memory barriers).
> >> - *
> >> - * Note that @nr may be almost arbitrarily large; this function is not
> >> - * restricted to acting on a single-word quantity.
> >> - */
> >> -static inline void set_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch_set_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __set_bit - Set a bit in memory
> >> - * @nr: the bit to set
> >> - * @addr: the address to start counting from
> >> - *
> >> - * Unlike set_bit(), this function is non-atomic. If it is called on the same
> >> - * region of memory concurrently, the effect may be that only one operation
> >> - * succeeds.
> >> - */
> >> -static inline void __set_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch___set_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * clear_bit - Clears a bit in memory
> >> - * @nr: Bit to clear
> >> - * @addr: Address to start counting from
> >> - *
> >> - * This is a relaxed atomic operation (no implied memory barriers).
> >> - */
> >> -static inline void clear_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch_clear_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __clear_bit - Clears a bit in memory
> >> - * @nr: the bit to clear
> >> - * @addr: the address to start counting from
> >> - *
> >> - * Unlike clear_bit(), this function is non-atomic. If it is called on the same
> >> - * region of memory concurrently, the effect may be that only one operation
> >> - * succeeds.
> >> - */
> >> -static inline void __clear_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch___clear_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * clear_bit_unlock - Clear a bit in memory, for unlock
> >> - * @nr: the bit to set
> >> - * @addr: the address to start counting from
> >> - *
> >> - * This operation is atomic and provides release barrier semantics.
> >> - */
> >> -static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch_clear_bit_unlock(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __clear_bit_unlock - Clears a bit in memory
> >> - * @nr: Bit to clear
> >> - * @addr: Address to start counting from
> >> - *
> >> - * This is a non-atomic operation but implies a release barrier before the
> >> - * memory operation. It can be used for an unlock if no other CPUs can
> >> - * concurrently modify other bits in the word.
> >> - */
> >> -static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch___clear_bit_unlock(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * change_bit - Toggle a bit in memory
> >> - * @nr: Bit to change
> >> - * @addr: Address to start counting from
> >> - *
> >> - * This is a relaxed atomic operation (no implied memory barriers).
> >> - *
> >> - * Note that @nr may be almost arbitrarily large; this function is not
> >> - * restricted to acting on a single-word quantity.
> >> - */
> >> -static inline void change_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch_change_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __change_bit - Toggle a bit in memory
> >> - * @nr: the bit to change
> >> - * @addr: the address to start counting from
> >> - *
> >> - * Unlike change_bit(), this function is non-atomic. If it is called on the same
> >> - * region of memory concurrently, the effect may be that only one operation
> >> - * succeeds.
> >> - */
> >> -static inline void __change_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    arch___change_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * test_and_set_bit - Set a bit and return its old value
> >> - * @nr: Bit to set
> >> - * @addr: Address to count from
> >> - *
> >> - * This is an atomic fully-ordered operation (implied full memory barrier).
> >> - */
> >> -static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch_test_and_set_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __test_and_set_bit - Set a bit and return its old value
> >> - * @nr: Bit to set
> >> - * @addr: Address to count from
> >> - *
> >> - * This operation is non-atomic. If two instances of this operation race, one
> >> - * can appear to succeed but actually fail.
> >> - */
> >> -static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch___test_and_set_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * test_and_set_bit_lock - Set a bit and return its old value, for lock
> >> - * @nr: Bit to set
> >> - * @addr: Address to count from
> >> - *
> >> - * This operation is atomic and provides acquire barrier semantics if
> >> - * the returned value is 0.
> >> - * It can be used to implement bit locks.
> >> - */
> >> -static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch_test_and_set_bit_lock(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * test_and_clear_bit - Clear a bit and return its old value
> >> - * @nr: Bit to clear
> >> - * @addr: Address to count from
> >> - *
> >> - * This is an atomic fully-ordered operation (implied full memory barrier).
> >> - */
> >> -static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch_test_and_clear_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __test_and_clear_bit - Clear a bit and return its old value
> >> - * @nr: Bit to clear
> >> - * @addr: Address to count from
> >> - *
> >> - * This operation is non-atomic. If two instances of this operation race, one
> >> - * can appear to succeed but actually fail.
> >> - */
> >> -static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch___test_and_clear_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * test_and_change_bit - Change a bit and return its old value
> >> - * @nr: Bit to change
> >> - * @addr: Address to count from
> >> - *
> >> - * This is an atomic fully-ordered operation (implied full memory barrier).
> >> - */
> >> -static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch_test_and_change_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * __test_and_change_bit - Change a bit and return its old value
> >> - * @nr: Bit to change
> >> - * @addr: Address to count from
> >> - *
> >> - * This operation is non-atomic. If two instances of this operation race, one
> >> - * can appear to succeed but actually fail.
> >> - */
> >> -static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch___test_and_change_bit(nr, addr);
> >> -}
> >> -
> >> -/**
> >> - * test_bit - Determine whether a bit is set
> >> - * @nr: bit number to test
> >> - * @addr: Address to start counting from
> >> - */
> >> -static inline bool test_bit(long nr, const volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch_test_bit(nr, addr);
> >> -}
> >> -
> >> -#if defined(arch_clear_bit_unlock_is_negative_byte)
> >> -/**
> >> - * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
> >> - *                                     byte is negative, for unlock.
> >> - * @nr: the bit to clear
> >> - * @addr: the address to start counting from
> >> - *
> >> - * This operation is atomic and provides release barrier semantics.
> >> - *
> >> - * This is a bit of a one-trick-pony for the filemap code, which clears
> >> - * PG_locked and tests PG_waiters,
> >> - */
> >> -static inline bool
> >> -clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
> >> -{
> >> -    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> -    return arch_clear_bit_unlock_is_negative_byte(nr, addr);
> >> -}
> >> -/* Let everybody know we have it. */
> >> -#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
> >> -#endif
> >> -
> >> -#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
> >> diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
> >> new file mode 100644
> >> index 000000000000..18ce3c9e8eec
> >> --- /dev/null
> >> +++ b/include/asm-generic/bitops/instrumented-atomic.h
> >> @@ -0,0 +1,100 @@
> >> +/* SPDX-License-Identifier: GPL-2.0 */
> >> +
> >> +/*
> >> + * This file provides wrappers with sanitizer instrumentation for atomic bit
> >> + * operations.
> >> + *
> >> + * To use this functionality, an arch's bitops.h file needs to define each of
> >> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> >> + * arch___set_bit(), etc.).
> >> + */
> >> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
> >> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
> >> +
> >> +#include <linux/kasan-checks.h>
> >> +
> >> +/**
> >> + * set_bit - Atomically set a bit in memory
> >> + * @nr: the bit to set
> >> + * @addr: the address to start counting from
> >> + *
> >> + * This is a relaxed atomic operation (no implied memory barriers).
> >> + *
> >> + * Note that @nr may be almost arbitrarily large; this function is not
> >> + * restricted to acting on a single-word quantity.
> >> + */
> >> +static inline void set_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch_set_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * clear_bit - Clears a bit in memory
> >> + * @nr: Bit to clear
> >> + * @addr: Address to start counting from
> >> + *
> >> + * This is a relaxed atomic operation (no implied memory barriers).
> >> + */
> >> +static inline void clear_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch_clear_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * change_bit - Toggle a bit in memory
> >> + * @nr: Bit to change
> >> + * @addr: Address to start counting from
> >> + *
> >> + * This is a relaxed atomic operation (no implied memory barriers).
> >> + *
> >> + * Note that @nr may be almost arbitrarily large; this function is not
> >> + * restricted to acting on a single-word quantity.
> >> + */
> >> +static inline void change_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch_change_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * test_and_set_bit - Set a bit and return its old value
> >> + * @nr: Bit to set
> >> + * @addr: Address to count from
> >> + *
> >> + * This is an atomic fully-ordered operation (implied full memory barrier).
> >> + */
> >> +static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch_test_and_set_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * test_and_clear_bit - Clear a bit and return its old value
> >> + * @nr: Bit to clear
> >> + * @addr: Address to count from
> >> + *
> >> + * This is an atomic fully-ordered operation (implied full memory barrier).
> >> + */
> >> +static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch_test_and_clear_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * test_and_change_bit - Change a bit and return its old value
> >> + * @nr: Bit to change
> >> + * @addr: Address to count from
> >> + *
> >> + * This is an atomic fully-ordered operation (implied full memory barrier).
> >> + */
> >> +static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch_test_and_change_bit(nr, addr);
> >> +}
> >> +
> >> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
> >> diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
> >> new file mode 100644
> >> index 000000000000..ec53fdeea9ec
> >> --- /dev/null
> >> +++ b/include/asm-generic/bitops/instrumented-lock.h
> >> @@ -0,0 +1,81 @@
> >> +/* SPDX-License-Identifier: GPL-2.0 */
> >> +
> >> +/*
> >> + * This file provides wrappers with sanitizer instrumentation for bit
> >> + * locking operations.
> >> + *
> >> + * To use this functionality, an arch's bitops.h file needs to define each of
> >> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> >> + * arch___set_bit(), etc.).
> >> + */
> >> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
> >> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
> >> +
> >> +#include <linux/kasan-checks.h>
> >> +
> >> +/**
> >> + * clear_bit_unlock - Clear a bit in memory, for unlock
> >> + * @nr: the bit to set
> >> + * @addr: the address to start counting from
> >> + *
> >> + * This operation is atomic and provides release barrier semantics.
> >> + */
> >> +static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch_clear_bit_unlock(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * __clear_bit_unlock - Clears a bit in memory
> >> + * @nr: Bit to clear
> >> + * @addr: Address to start counting from
> >> + *
> >> + * This is a non-atomic operation but implies a release barrier before the
> >> + * memory operation. It can be used for an unlock if no other CPUs can
> >> + * concurrently modify other bits in the word.
> >> + */
> >> +static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch___clear_bit_unlock(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * test_and_set_bit_lock - Set a bit and return its old value, for lock
> >> + * @nr: Bit to set
> >> + * @addr: Address to count from
> >> + *
> >> + * This operation is atomic and provides acquire barrier semantics if
> >> + * the returned value is 0.
> >> + * It can be used to implement bit locks.
> >> + */
> >> +static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch_test_and_set_bit_lock(nr, addr);
> >> +}
> >> +
> >> +#if defined(arch_clear_bit_unlock_is_negative_byte)
> >> +/**
> >> + * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
> >> + *                                     byte is negative, for unlock.
> >> + * @nr: the bit to clear
> >> + * @addr: the address to start counting from
> >> + *
> >> + * This operation is atomic and provides release barrier semantics.
> >> + *
> >> + * This is a bit of a one-trick-pony for the filemap code, which clears
> >> + * PG_locked and tests PG_waiters,
> >> + */
> >> +static inline bool
> >> +clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch_clear_bit_unlock_is_negative_byte(nr, addr);
> >> +}
> >> +/* Let everybody know we have it. */
> >> +#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
> >> +#endif
> >> +
> >> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H */
> >> diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
> >> new file mode 100644
> >> index 000000000000..95ff28d128a1
> >> --- /dev/null
> >> +++ b/include/asm-generic/bitops/instrumented-non-atomic.h
> >> @@ -0,0 +1,114 @@
> >> +/* SPDX-License-Identifier: GPL-2.0 */
> >> +
> >> +/*
> >> + * This file provides wrappers with sanitizer instrumentation for non-atomic
> >> + * bit operations.
> >> + *
> >> + * To use this functionality, an arch's bitops.h file needs to define each of
> >> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> >> + * arch___set_bit(), etc.).
> >> + */
> >> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
> >> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
> >> +
> >> +#include <linux/kasan-checks.h>
> >> +
> >> +/**
> >> + * __set_bit - Set a bit in memory
> >> + * @nr: the bit to set
> >> + * @addr: the address to start counting from
> >> + *
> >> + * Unlike set_bit(), this function is non-atomic. If it is called on the same
> >> + * region of memory concurrently, the effect may be that only one operation
> >> + * succeeds.
> >> + */
> >> +static inline void __set_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch___set_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * __clear_bit - Clears a bit in memory
> >> + * @nr: the bit to clear
> >> + * @addr: the address to start counting from
> >> + *
> >> + * Unlike clear_bit(), this function is non-atomic. If it is called on the same
> >> + * region of memory concurrently, the effect may be that only one operation
> >> + * succeeds.
> >> + */
> >> +static inline void __clear_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch___clear_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * __change_bit - Toggle a bit in memory
> >> + * @nr: the bit to change
> >> + * @addr: the address to start counting from
> >> + *
> >> + * Unlike change_bit(), this function is non-atomic. If it is called on the same
> >> + * region of memory concurrently, the effect may be that only one operation
> >> + * succeeds.
> >> + */
> >> +static inline void __change_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    arch___change_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * __test_and_set_bit - Set a bit and return its old value
> >> + * @nr: Bit to set
> >> + * @addr: Address to count from
> >> + *
> >> + * This operation is non-atomic. If two instances of this operation race, one
> >> + * can appear to succeed but actually fail.
> >> + */
> >> +static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch___test_and_set_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * __test_and_clear_bit - Clear a bit and return its old value
> >> + * @nr: Bit to clear
> >> + * @addr: Address to count from
> >> + *
> >> + * This operation is non-atomic. If two instances of this operation race, one
> >> + * can appear to succeed but actually fail.
> >> + */
> >> +static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch___test_and_clear_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * __test_and_change_bit - Change a bit and return its old value
> >> + * @nr: Bit to change
> >> + * @addr: Address to count from
> >> + *
> >> + * This operation is non-atomic. If two instances of this operation race, one
> >> + * can appear to succeed but actually fail.
> >> + */
> >> +static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch___test_and_change_bit(nr, addr);
> >> +}
> >> +
> >> +/**
> >> + * test_bit - Determine whether a bit is set
> >> + * @nr: bit number to test
> >> + * @addr: Address to start counting from
> >> + */
> >> +static inline bool test_bit(long nr, const volatile unsigned long *addr)
> >> +{
> >> +    kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
> >> +    return arch_test_bit(nr, addr);
> >> +}

This one slipped through the cracks, sorry I didn't notice earlier.

test_bit() is an atomic bitop. I assume it was meant to be in
instrumented-atomic.h?

Thanks,
-- Marco

> >> +
> >> +#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
> >> --
> >> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878sp57z44.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA%40mail.gmail.com.
