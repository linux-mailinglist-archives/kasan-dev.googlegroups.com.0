Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBMGC63YAKGQE6SD22QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB4713A7F4
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 12:08:33 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id f25sf7935269otq.15
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 03:08:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579000112; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZwCEdUgpkWeyVMYmWWq7P1lz+E7+aNuq0jcvES09Tzeqk7JaQL3FZIrXf7cnubQZ+N
         GyGGZE6SmiIoMFID3Hfjo3vT8nvgI2RkeLHU+oWIs8jnw8Jg0U+ai26gEllkqm7HSoqv
         Ef2KRcw84NLZxwx6uodJ2iRIvSbwRo7wm3zxvCDh1NzzJ0PKZE21amIwF9Gc1/XbZVx6
         IUySCo929kSFCjagK6i1te6rLGvhMZaxFs2cG3SLR3i59tnEovL97CXe5GebMN5ekVyK
         KBcH7SROiTaOGx9wg0yAjdhJkM7Jb1xMsQ+Dw/zWy0IPJPNs/1lijFOiswT/fLcOsAt3
         /skg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=17hz8THzmJFEDg1Z93hhxdPO9nfJjpQJmT5aQXWGjBA=;
        b=TEAKpwgHNzEiJK5EpNIC9tTO7Oo2yZAMgoFFWo3DhBMbgWKKbbgqArS1AyYYjoa9fE
         VoOCdjFNbTqMu0lK3Q9yDJWQz+8u+T7HwOoDoBS9n7SZU+tIYKn2XkgPf2lvTX4o1gmb
         wsXUkC0hsnV/MZSzJfYx0HBPoM6jxjNUyyCVCVGkrcKFWKFj0h/ahtZZuaY7m/H8TQ+y
         stys6YAo02sviJWFkqHB8E5o1f2ucIT/NGYZ65p3Ijbp4MekorlNDfZ1/7rmEYTXfJUp
         N2JsiexejUT5tuY8VERcs3pkZHFSey7gZZUZbq6gZj8FzKWqMSp7kXWhUMriYSkGAwR0
         lOgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=mDLkJsF3;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=17hz8THzmJFEDg1Z93hhxdPO9nfJjpQJmT5aQXWGjBA=;
        b=od4N7KuqL45W6s+eBiq1fZ9nXU8miLP0qxwsvBsQGq+tI2C8ggFcP5fV4Y4tyePTmN
         vJaLD3vwAziloiSv3h2Iv6nXBy+LODCQnSFuFVS+3Gxcz2jDa0FgSw9dN739KIk2dRKk
         1Sitgjfbfs/asHa4aVccFjkwUtD7N5M1z7gLZ7iUK9YMJzLgFFxo2HkJWqsxwIz9DlLL
         TnDO+1+wpzAfd0MEs3qlyaqw1gUmggqqqOu/1u210Sa3oKIpWco/IpqFxrijTkc8MvzZ
         wiRRusObXHLq72AMMjrFK2Apu1pusgJqghH6y66Pa5CYrKOBS25ohjdq2rA+7/Z2Pbo2
         f9LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=17hz8THzmJFEDg1Z93hhxdPO9nfJjpQJmT5aQXWGjBA=;
        b=A30jqH3Ql7bY44c2RVw65q9ljmzgTUwbadJZ68Gdd12//wXuRgJuM9dp38hBSrGHqB
         EzoZe+lqLmZFjhT3zmg+xKA8KYhOMjsjEb2ryYhwoPUmI3LNBajP4rgpzgx5qyn8T2NM
         JTFIOo1TJs7YowPtTbvZ4PpbFhEW82dIrEE5Qj3TRhNCWqRO8GdlkKtucJiT+2i7XmwF
         gqEfTVCXvYuF9ugsOz2WiczCobJdxGsbj0iOS4xxUxY3WhcOOm2XI4hKnWQqtYQmk9qX
         /7V++R9bbYQvnIJ3YXQFPOvV+jWe6M5DDPJ9tF+MBFbcaTfmmv0zxeySOS0BUEKn+he5
         CarA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQXd5WL9+BBd+ifaTcdCqr7C9BqmNs49tEuNml+R5ms3QGbm3h
	MV9YmQgJ87XeDzGKV8Ar2XU=
X-Google-Smtp-Source: APXvYqw47Eb7A5BlmbwELlizbgWpqeLGESSLO1/Mlg9HXV1//wdjpbYb9pls2fAaqhODZb6iefJG6w==
X-Received: by 2002:a9d:6b17:: with SMTP id g23mr15831609otp.265.1579000112329;
        Tue, 14 Jan 2020 03:08:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:469a:: with SMTP id z26ls2752310ote.8.gmail; Tue, 14 Jan
 2020 03:08:31 -0800 (PST)
X-Received: by 2002:a05:6830:18c6:: with SMTP id v6mr11622679ote.145.1579000111941;
        Tue, 14 Jan 2020 03:08:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579000111; cv=none;
        d=google.com; s=arc-20160816;
        b=if0EHX85sBejD8nAjhml5ncj1yKr4rpE3l5ywzlN8Ij3l4Y34h9hes4OCbH+nZSwBD
         DbHY6NHpHxHajtIcLqGO2epO++6GPU2f6ZX1aJck8xp8LzOVyifNniWVDDkbU5g4apEJ
         EyBN98GLjpLDwAhpRBcLW4moqZzHSyqJaP+F7585iV2MjkONNf1vQDDScarmNF6oO8ym
         Ii2q2c98cbvJX1n2tdi/a4WC3a3F+EBES5g8B35cu38GeGdGW3z1fzGQYsN4KuqXmkUm
         l6RELphRVIyEjleaaX++U+d0KSS6JZoAZFeORDhpWrXzfn9i6B0TeY0gzMIjPY4R4E7F
         5b9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=ukU/HTx3Lur+oN5f1R5Yulqfuax6so7AyFG3I+NXijE=;
        b=aFPZIKEc2CZN3jJDO1ELJlYYibxAntGWgBCUe9LBN+5ZGAvLH1HJDXipzr/oDGGwob
         hSxKguuiLtOMn3/3J/2NM8M4RhIefqaZN9tyVkhlkWLVASHAGYlhX/RZS7IVdExLXfCK
         fhI7sr6t6yq96XK76cWZqi97wtZZA7aXDg5mrGSEqEuLzSioGOy70Gywv/h++rw5JGHK
         H6y0O8iRdRaH8nie7QpFjfJWlRHGfPTZqSDzNPw1MGfHM2vnxXauj3hHuMPr1cKzOgLA
         /Ru5VC81V6RVoZHyFKNZw7//Ma1RQ7xgw00wWm1WqB0DX06gXfl0592P5KxcHz2d9tLH
         ufcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=mDLkJsF3;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id a12si708033otq.5.2020.01.14.03.08.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 03:08:31 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id r14so11638067qke.13
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 03:08:31 -0800 (PST)
X-Received: by 2002:a37:4b93:: with SMTP id y141mr21982856qka.205.1579000111263;
        Tue, 14 Jan 2020 03:08:31 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id i16sm6406845qkh.120.2020.01.14.03.08.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 03:08:30 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
Date: Tue, 14 Jan 2020 06:08:29 -0500
Message-Id: <53F6B915-AC53-41BB-BF32-33732515B3A0@lca.pw>
References: <CANpmjNOC2PYFsE_TK2SYmKcHxyG+2arWc8x_fmeWPOMi0+ot8g@mail.gmail.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
 Alan Stern <stern@rowland.harvard.edu>,
 Alexander Potapenko <glider@google.com>,
 Andrea Parri <parri.andrea@gmail.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>,
 Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>,
 Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
 Daniel Axtens <dja@axtens.net>, Daniel Lustig <dlustig@nvidia.com>,
 Dave Hansen <dave.hansen@linux.intel.com>,
 David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 Jade Alglave <j.alglave@ucl.ac.uk>,
 Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>,
 Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>,
 Mark Rutland <Mark.Rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
 Eric Dumazet <edumazet@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 linux-arch <linux-arch@vger.kernel.org>,
 "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
 linux-efi@vger.kernel.org,
 Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 the arch/x86 maintainers <x86@kernel.org>
In-Reply-To: <CANpmjNOC2PYFsE_TK2SYmKcHxyG+2arWc8x_fmeWPOMi0+ot8g@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=mDLkJsF3;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jan 6, 2020, at 7:47 AM, Marco Elver <elver@google.com> wrote:
>=20
> Thanks, I'll look into KCSAN + lockdep compatibility. It's probably
> missing some KCSAN_SANITIZE :=3D n in some Makefile.

Can I have a update on fixing this? It looks like more of a problem that kc=
san_setup_watchpoint() will disable IRQs and then dive into the page alloca=
tor where it would complain because it might sleep.

BTW, I saw Paul sent a pull request for 5.6 but it is ugly to have everybod=
y could trigger a deadlock (sleep function called in atomic context) like t=
his during boot once this hits the mainline not to mention about only recen=
tly it is possible to test this feature (thanks to warning ratelimit) with =
the existing debugging options because it was unable to boot due to the bro=
kenness with debug_pagealloc as mentioned in this thread, so this does soun=
ds like it needs more soak time for the mainline to me.

0000000000000400
[   13.416814][    T1] Call Trace:
[   13.416814][    T1]  lock_is_held_type+0x66/0x160
[   13.416814][    T1]  ___might_sleep+0xc1/0x1d0
[   13.416814][    T1]  __might_sleep+0x5b/0xa0
[   13.416814][    T1]  slab_pre_alloc_hook+0x7b/0xa0
[   13.416814][    T1]  __kmalloc_node+0x60/0x300
[   13.416814   T1]  ? alloc_cpumask_var_node+0x44/0x70
[   13.416814][    T1]  ? topology_phys_to_logical_die+0x7e/0x180
[   13.416814][    T1]  alloc_cpumask_var_node+0x44/0x70
[   13.416814][    T1]  zalloc_cpumask_var+0x2a/0x40
[   13.416814][    T1]  native_smp_prepare_cpus+0x246/0x425
[   13.416814][    T1]  kernel_init_freeable+0x1b8/0x496
[   13.416814][    T1]  ? rest_init+0x381/0x381
[   13.416814][    T1]  kernel_init+0x18/0x17f
[   13.416814][    T1]  ? rest_init+0x381/0x381
[   13.416814][    T1]  ret_from_fork+0x3a/0x50
[   13.416814][    T1] irq event stamp: 910
[   13.416814][    T1] hardirqs last  enabled at (909): [<ffffffff8d1240f3>=
] _raw_write_unlock_irqrestore+0x53/0x57
[   13.416814][    T1] hardirqs last disabled at (910): [<ffffffff8c8bba76>=
] kcsan_setup_watchpoint+0x96/0x460
[   13.416814][    T1] softirqs last  enabled at (0): [<ffffffff8c6b697a>] =
copy_process+0x11fa/0x34f0
[   13.416814][    T1] softirqs last disabled at (0): [<0000000000000000>] =
0x0
[   13.416814][    T1] ---[ end trace 7d1df66da055aa92 ]---
[   13.416814][    T1] possible reason: unannotated irqs-on.
[   13.416814][ent stamp: 910
[   13.416814][    T1] hardirqs last  enabled at (909): [<ffffffff8d1240f3>=
] _raw_write_unlock_irqrestore+0x53/0x57
[   13.416814][    T1] hardirqs last disabled at (910): [<ffffffff8c8bba76>=
] kcsan_setup_watchpoint+0x96/0x460
[   13.416814][    T1] softirqs last  enabled at (0): [<ffffffff8c6b697a>] =
copy_process+0x11fa/0x34f0
[   13.416814][    T1] softirqs last disabled at (0): [<0000000000000000>] =
0x0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/53F6B915-AC53-41BB-BF32-33732515B3A0%40lca.pw.
