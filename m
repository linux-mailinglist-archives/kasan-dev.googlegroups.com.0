Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBAGK7DYAKGQEB2WBDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 130D913B3A0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 21:30:58 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id q1sf9046478pge.12
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 12:30:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579033856; cv=pass;
        d=google.com; s=arc-20160816;
        b=AZqRyPfIsgBSAT4tn9SRtmXues2PBsdPfyA5wNAv/B2thFCV+9gYaObf0uA9Da4IWm
         F+Fd4rtQjGw38um0I54gzvvxwBtNL3QbGv1AuXs+mqKZyNIiVhGplYukdaMYTkqyOlP2
         BtQZoBRGaOSYaouGRxQwsTeLIaJYed2pTsgt+8dNH7WfPdNYnP6SSqUt4w5/NqwTMMqp
         R6Mb7req1Rg+B7soRPzNtJd/m25yBwA2juXzBQHtMFI/LDGDqVgHXirrGUN63lD+kBcp
         sDgiF6XQ72kRmWcNFWxbZhQN+XdBOJy3Zbp0jeLd5rIH/GV+4GSrzosRrDjN6x0I8wGA
         CuEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=DZEdzUzydnwpCeAS5zdx0BO/cgZYGL0dfNHQRD48H+w=;
        b=UIqRSVGiTPXMNye7C2ma3DAO3x4SV+O3XJ51P93qgYvvgds6Cz3JorokOh5iHvNLou
         z25wOAGIn6hFUV/tS56+T9mIWJQAQrVwLbD2/eKp+cErkKpm+Ww6GItknTh2j37lyD2V
         GRA0gSkr/ra0/traP+dRVodv63KphMzO/5whiYsNADmqpG1ABemt0+/fLfAKR627Tdf0
         ygW0EmhEcE9OurbDLK1Qhk7eI3/HmjIf1uOs8iwwmK2W6JSAcTy8ntP6cLx6UgHJhf0F
         gvtA7ea8hK1GuV6qfzTcncIiYumY81T6DBChh+jE3n4tkbMsGRPnQxKxQYzZiz5FDDhp
         YByg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=qfNdLg3k;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DZEdzUzydnwpCeAS5zdx0BO/cgZYGL0dfNHQRD48H+w=;
        b=YF9N7FdnpL0qaqyXwGa7orY0r1DGk1nb46oSZnbjXrPBIWFtvFmwCxanErb2ivwlCl
         pt8VnD6PgWZxbTMLArewDx2E62oamGxOFUB5f9IISELkBPgED0oHxr5YHEhtrsNi0eKL
         CgYzg93urNnEgyJIWWfAZAXBugwix9ihNVG1J0OgzXRdfv9Xf2uso+IhuWcdpEzXWsQe
         rzozPvc7dLH7R1yb4zWGtEbn1jXWBpWUzB4LwV4PO+NJtp0gzkX2U/wkUEUPrM+LDoHV
         nS8Ml3emDL2V9hXTi7T5kdOWkZdpdOs1Ry88V3qbsIRpVzGVVKBoniPASaXcq5ggIo3E
         Fftg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DZEdzUzydnwpCeAS5zdx0BO/cgZYGL0dfNHQRD48H+w=;
        b=Q8FbpRwVfnt2gEa1eEKMapJpo/SJDUT/cGogjAy6UGMv48WHllJaCzL0svX/Nv23GS
         xE3upI9zEX2LzYxVn88P8IhzwvtvZwf60ntv3aTD1/mNLdWHJ1T9vPByyTqd1Aq60P7O
         oT8pYY05tcY49TgFrM1nPs6/6lztwmZSOJRpFMvw4f/8Whf1A5krAmS225mkeQU5Q4WE
         8euHK0mBP5LXv/GG93NF9Tr7QUmMVCG1uKE42DOTfwq2TjqmLJQD+5uU7gJtyVN4kGcI
         acfneuDgz80221zH2y0FNYQEjlcF2yFiWrYy4PhUmu4HxhIvrWJ+crt14bC/p6kFjhNq
         /tdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWkt8Ujyx31jto1CcfahJIYRz6VhbL/lorFEzI/FRiDOAC0Fqk0
	XxUKoQUIhUt62uyDlTbUpBk=
X-Google-Smtp-Source: APXvYqzbdROnTPMu3cNYhLsoAC6c32vpm/R1r33O2RfdDCo3IE03sMRjQBUph5+XuCjVIevs7xTk0A==
X-Received: by 2002:a65:4206:: with SMTP id c6mr29163879pgq.46.1579033856390;
        Tue, 14 Jan 2020 12:30:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b10f:: with SMTP id q15ls4064900plr.6.gmail; Tue, 14
 Jan 2020 12:30:56 -0800 (PST)
X-Received: by 2002:a17:902:462:: with SMTP id 89mr21985669ple.270.1579033855937;
        Tue, 14 Jan 2020 12:30:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579033855; cv=none;
        d=google.com; s=arc-20160816;
        b=ctCfGIXdcbmRHC1n6zpfD4cfdrE0qNxT4OSDWkj1eVY7PdyZ/E5VVs2Xx+e6HVb0lF
         jpSN6wcFtihQ0LmGLIePDFCIMUjyxJZu1pjC24lwBSiWM/PBWuWe9kP1dML3wUILwxcz
         YO4ZfCHNME+gsC7Z5jFiRUoRndj8WX/X9x27h5XwXFfcxSc9sSYpnzdp7a3owTHCyOLI
         QCgyCC2pW0q97fpFaHmngwqYqp9wx3LMk6dD2A3NmijAR7DRrcCLD49wUn0QvVKxoHF2
         +u6wiZ7tvAOy9Vs6uzB0xFnBkJ4yO+Iy/P4/UT4tg3ilTn3ZG9s6HAeSdQ7CjFC8x1UQ
         XVOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=GM2cmKJLGIw00BnTkj1dcmxxtlMk1WYpnp+HW9nEczc=;
        b=YM3pDDSbw21WSqM70SFvHo7QcEsZ09nMMhSbjqJDozmAqL3YbJlqz6cMVLvzaRbmPM
         odIAWx93SSNfnNJPSf7ERJuKYdtWWKfvxwzC9asbxs0vhiRSiH9cRw3YKW5bUuGoaNU9
         To6MfvRgIjnIysZ0I2yznllWtQhrAKsXH9AxmwPYw5/DmgoTpHm5nvlZ7TgSYmGvX22V
         TtXB2e/dk3HpuHMKI1ZbF3bcLFCkFCai/YGz6VjouvU5Y+s4WE5fwZ/wwtPsm/og7Tky
         nF9DSJP3KpGC8Vkk9AENeDnR7E5bofWdKbacs+RlHC5rRH3BUZW7yG5aSG75rifRljqj
         7QfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=qfNdLg3k;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id y13si202338plp.0.2020.01.14.12.30.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 12:30:55 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id z14so13467005qkg.9
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 12:30:55 -0800 (PST)
X-Received: by 2002:ae9:c104:: with SMTP id z4mr18665764qki.418.1579033855079;
        Tue, 14 Jan 2020 12:30:55 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 68sm7357546qkj.102.2020.01.14.12.30.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 12:30:54 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
Date: Tue, 14 Jan 2020 15:30:53 -0500
Message-Id: <F185919B-2D86-43B6-9BEC-D14D72871A58@lca.pw>
References: <20200114192220.GS2935@paulmck-ThinkPad-P72>
Cc: Marco Elver <elver@google.com>,
 LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
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
In-Reply-To: <20200114192220.GS2935@paulmck-ThinkPad-P72>
To: paulmck@kernel.org
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=qfNdLg3k;       spf=pass
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



> On Jan 14, 2020, at 2:22 PM, Paul E. McKenney <paulmck@kernel.org> wrote:
>=20
> Just so I understand...  Does this problem happen even in CONFIG_KCSAN=3D=
n
> kernels?

No.

>=20
> I have been running extensive CONFIG_KSCAN=3Dy rcutorture tests for quite
> awhile now, so even if this only happens for CONFIG_KSCAN=3Dy, it is not
> like it affects everyone.
>=20
> Yes, it should be fixed, and Marco does have a patch on the way.

The concern is really about setting KSCAN=3Dy in a distro debug kernel wher=
e it has other debug options. I=E2=80=99ll try to dig into more of those is=
sues in the next few days.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/F185919B-2D86-43B6-9BEC-D14D72871A58%40lca.pw.
