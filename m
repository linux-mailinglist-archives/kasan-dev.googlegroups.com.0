Return-Path: <kasan-dev+bncBDEKVJM7XAHRBJW47XYAKGQEKGXT2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C4C013CD82
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 20:55:19 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id f22sf3486249lfh.4
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 11:55:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579118118; cv=pass;
        d=google.com; s=arc-20160816;
        b=UnR+LBRHmFiiwvs4aorv7ULc7nKQDRD8LM4yae3QnM+MVF3xYGiFsxc3Qa1OI2Hp8J
         km/SmUBUlbZ3GiW8pWt4MaUxMZh3E7n2U4Tt7s6SyKBJLORz0XXdJgTK8apCjZt4x01k
         bXtnjnRteQvdocTycwSclMfaDH1b2SdZN5DAq0ud1Bq25W2efYMwnLILMzRzHLoZQHdL
         CHoIU0lBz3f2ltY2bNxW2i1IqxNWouZr+qazpvxyPJlWy01p2Lw04rKBSJhiEugTbCAG
         6OvOArOk8d9T8E3zHUSiPcY83ZhOuej9qU2xQ4EC+6nSxI7VTVn6C5JyS3jf26JifMFm
         E3Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=QDf905OqdbTd+2UgSCHQ4NWfXwMe/Q/rp+hvrxI1Bbg=;
        b=gBHAeloleDU6KQ/gUL27Cmpq4ImBOslKh6KUTM8qor0wO40BwM80DEhZXXIpYLtzZr
         IAqICQXu2Xph9mGmed/UtbN3sMELjFhu+m8k2LWHafWnLLr8facdFmxuiCZzW50ZbGlW
         ajR/WtVsHySmMnEq/4V10femOBhGGEFmtXiGWEf0uF6uiE9GBQvLvyoxxCC336yjpc0Y
         lP+Eb8+JGeF2ssojUX72fAK4/cCA3J91Rc6JBj5qNpUSf9l3eEaJUcZFYzeEcVyD5LoB
         piN+1N96bj/F8pTpFgWnXIK/ZcYsaoIG0FRN52eoEeLMICw/ootCSTKsIcCUy4Yp/4AW
         JodA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QDf905OqdbTd+2UgSCHQ4NWfXwMe/Q/rp+hvrxI1Bbg=;
        b=QYuA/PZT6EPTMyboXiWrL763tpxGoa1ETde7hCcgaDf8ChNSKlPZot4iFRm+9ekeOn
         FHCVFUwKQl8qf/ds9wo3L2LjAMRurUYQo8Q7uIdQWG8yGBuiZT/mkQZPaxZ7L7A9llIe
         fZ3wnGRzCfVV6r6EpRHtJ46dneTX+z4VzMXK/yQv+A1NC7X7chtYcSlSEWE+K6W3B496
         c0ba5NY3gbXQ3QclvqlNDUWOvBSvJU5LAWtYMMlfGKB3Quj1ECczEGSIDyQh0WYc2cMc
         gVqB1KKt7gOw3pc2nCHEUFgn6Tr9GJ8mOhbNSAVXc4hOx/3geZf3UIx4w/N80/Kj7zIx
         J6Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QDf905OqdbTd+2UgSCHQ4NWfXwMe/Q/rp+hvrxI1Bbg=;
        b=YOgL2PkBgCWMtKjl8uxF/yZSjqe59aWwBb0yPwXjEq4I96sBkDwW2SiW79pxxgjkj9
         kGPjn0a9VQ8aBJDdl9pmpbMrW4OaB92y2JG/d76Cdp6GUUzU6g0wfJiS4DpAliDx2Vi/
         2shmpkIorHhXAvyGUczvWgLsZwTGdVV/8IjticyKa+KiEBnwaw+rU2MIWDY1x1+pubCy
         /HEGofcuVdikv1GP1MWNZFYHxFj9s7muLCflUcZ7Bn8XCVMlY16XAUwlFBZvZ2+4fyAF
         Kx6uS4jFKf2Ux2pfUMIsaafNyJjxEKXSGmMG3GUTgeQuTsCQIMRpebcWxMRQNtWDwEdq
         hJJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW9WrGzjHLyM9kJWaJgI8KMTsuBCXWUdiP4hx2nwm28/a2Mahud
	Rp5sc6Jx1SVBzi0hP8GoJ7I=
X-Google-Smtp-Source: APXvYqwrK+xBKgyfQwd0e+BuHTuro/6FdUBbV+sge1aDZCazzHIB+2NkjB9NQGGfbuLcLMKxUAC6hQ==
X-Received: by 2002:a2e:88c4:: with SMTP id a4mr57864ljk.174.1579118118644;
        Wed, 15 Jan 2020 11:55:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c09:: with SMTP id j9ls2777807lja.2.gmail; Wed, 15 Jan
 2020 11:55:18 -0800 (PST)
X-Received: by 2002:a2e:7a13:: with SMTP id v19mr49092ljc.43.1579118118019;
        Wed, 15 Jan 2020 11:55:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579118118; cv=none;
        d=google.com; s=arc-20160816;
        b=I/B9QhaO8jvo6ELLLnTWThBsWSW6BYPFm03wBbKTGQuIW10i3w+6rG24Ar+plkvK4m
         iBezytjWIFuwlKCjVILFNIl6JXqnsKm/pon/Dxi0k4OrEIimW33/JrEPkRdyuS2NeEHN
         QLhjG+K2OF2vkSxAXe/XAc64PpB9pKWqQC7ZTiAoUSzuJwrf4cAXPtmgR0jyExhUmMhb
         xLuKFgXV640ix20Bc9cQsqXGdk9zgOM+y0fZRf0xVfgrPtzRMAwgWcwVCrL6SMxipTfK
         O/Ytx5yQtYg9RcGk9Dt6BnOVgMXODLOGN9tNfWJFtYgOCKBmodVn0Ba+i+e8Xq/8+QiZ
         ShaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=SZbFVa0jXuljBq6V1cn+BvebaW891PMlSyxejQc9s2w=;
        b=Vl6oLeHw08VKPe1zqIcoXGAvoHD4Dv4ZQfLBZZRneSuAgmSzRAgkRQZeL8+LKAdfPs
         Rk1x9WM3sBae9AARQUPLcCt5CLPfEiYXRpTw4+3sVLd/VLTPnAPWlHTOL1QYkOBPxisp
         EvfZ8b/IAPI+dMhrdBz3coJqaivXvRxna7OOfEmUKsFrENLSptm7v8gOgb2ExL+ep5CZ
         M0ekaEXS0qkEX5RU6tmVx+TLBEdnMhgWN4dnjeSkzNXKYlDnPOdMsY093FBs4Bg1PY4u
         h9CLcpchM6R8jIthhAldEqT+SGCX3HVzi05ujiDv035cdylzKJYJI5oavB0HFnvOWWcv
         O42A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.74])
        by gmr-mx.google.com with ESMTPS id e3si1110077ljg.2.2020.01.15.11.55.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 11:55:17 -0800 (PST)
Received-SPF: neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.74;
Received: from mail-qk1-f177.google.com ([209.85.222.177]) by
 mrelayeu.kundenserver.de (mreue108 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1M5fQq-1ikftP0RFC-007EE0 for <kasan-dev@googlegroups.com>; Wed, 15 Jan
 2020 20:55:17 +0100
Received: by mail-qk1-f177.google.com with SMTP id x129so16848597qke.8
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 11:55:16 -0800 (PST)
X-Received: by 2002:a37:2f02:: with SMTP id v2mr28707027qkh.3.1579118115977;
 Wed, 15 Jan 2020 11:55:15 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
In-Reply-To: <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 15 Jan 2020 20:54:59 +0100
X-Gmail-Original-Message-ID: <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
Message-ID: <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:rpU26yh71WKA6bU+XiJeeqi+kQpv3Nv8FvllcgslGkg6wPNXy/d
 TIP9jFhX/AtdLrmSKrDE7I7rmsrNFbnyGm1Gq/y/2dE5+dTc1BYlHYM1e+gX/Vaug/8CcIc
 HMcI1oteuNEXrv6bZWQ3sMhi/2fBR1E48gBe0N543tobU8Fg7PFTVFo8qcNKguHRp1RPLjB
 DbcVwH2PlcUiqJ9J3dVJw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:N4QdULzMatc=:CF84d4Gomn0qWGUnGVd5Ao
 81HQkY2J2XXvCo1qLgyfnWxVTzxlhoEDIA7sF+QSmnRYJEw2+XGt2yauu/2vEzIKtRq1VC/qm
 vkGPPJ0XpW6oGL2yx6IwUVkRqa3+Xj5atSOzq6Tg3Wl3f5iyyaEorC2SlWOV4uoVk3ptkEWS4
 ePTvwepB8xWk9kfyPC7grD6wd7gGEGvx4AcYt+qjETh1XkKq5vwZV0mJCVA7jvbcERdDrXguz
 FdlNp2rcKLXG3TLoayNAoKOS3wZ4rbYHPNllwIFtH8i0dymiRyxT4Hu2YQIn/G6iICS6jkYQb
 SveUmjXmd2QJ4mbdGJ5PzaqlbDVwU4xau0MXGaNnXj5E/QrAH5kALRxreB71/tduQe3rz3wb4
 lTx2W+b34Zb9PlZgfe3b9FZ0SiChRuPt3LyZvS7nMheQMnotMm9Inz1pTFcSc+g0yFSdvHG6B
 kdaBYpnTqxcGhY2ISffHjdZyycm/FKFE0TmbEt0bvyfUbjZUiK7jhAhZw9C/DduDVUOjWGhEp
 UhslLFwrW0iy4dNLdrM7uACpZPtxC5dX9HUjL4eyYFiO9ncB9YK3bP2XKWFWouFm821yDuLfo
 QynRFFYzsYwMUv98vj3lPKA8+stYNDzX/m9XSXsAbdBCRUwnDVoiIWyBJM2UNwdHck9+XEXrW
 j+UoZsr2FoZV3qK4xjeOJpMJEST1974FJ3ZPaiiq0axHJyvbxicDXpcPqb/PgVRo8dtHzxaEI
 bqG/WiWSAG0rKCWNbcGg9XoYdLRW1UXH0rKyR+2eFBVq0sG87hmFTEinecp98GegYwtpV5Ko3
 e/14i8oAez9xbzyb3seC4lrBPI53ki7yZpBVtumSccFBoRW2hGgNAgY7v0qvPwR+BBbIfS034
 Hb3ACpavVZNWMbT4NZmw==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.74 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, Jan 15, 2020 at 8:51 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 15 Jan 2020 at 20:27, Arnd Bergmann <arnd@arndb.de> wrote:
> >
> > On Wed, Jan 15, 2020 at 5:58 PM Marco Elver <elver@google.com> wrote:
> > >   * set_bit - Atomically set a bit in memory
> > > @@ -26,6 +27,7 @@
> > >  static inline void set_bit(long nr, volatile unsigned long *addr)
> > >  {
> > >         kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
> > > +       kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
> > >         arch_set_bit(nr, addr);
> > >  }
> >
> > It looks like you add a kcsan_check_atomic_write or kcsan_check_write directly
> > next to almost any instance of kasan_check_write().
> >
> > Are there any cases where we actually just need one of the two but not the
> > other? If not, maybe it's better to rename the macro and have it do both things
> > as needed?
>
> Do you mean adding an inline helper at the top of each bitops header
> here, similar to what we did for atomic-instrumented?  Happy to do
> that if it improves readability.

I was thinking of treewide wrappers, given that there are only a couple of files
calling kasan_check_write():

$ git grep -wl kasan_check_write
arch/arm64/include/asm/barrier.h
arch/arm64/include/asm/uaccess.h
arch/x86/include/asm/uaccess_64.h
include/asm-generic/atomic-instrumented.h
include/asm-generic/bitops/instrumented-atomic.h
include/asm-generic/bitops/instrumented-lock.h
include/asm-generic/bitops/instrumented-non-atomic.h
include/linux/kasan-checks.h
include/linux/uaccess.h
lib/iov_iter.c
lib/strncpy_from_user.c
lib/usercopy.c
scripts/atomic/gen-atomic-instrumented.sh

Are there any that really just want kasan_check_write() but not one
of the kcsan checks?

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN%2BPj6G8nt_zrL3sckdwQ%40mail.gmail.com.
