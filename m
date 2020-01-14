Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBKPO7DYAKGQEWVLXH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 044D513B49E
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 22:48:27 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id n6sf11721229ile.6
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 13:48:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579038506; cv=pass;
        d=google.com; s=arc-20160816;
        b=sCXw5CLdw0CevIPdlGxlzs/esm25bb65Xvcj7lvQMHLQLznLAoO4JOgK9HI6zTkZ9Y
         SrxA84z/pKxa8irKz0tOnjaneIUb3z3nVWa3vqu7wuVvstXiivuRExODGu59I0Z5XaTk
         pvcE3WDSUkjgQFSWXqRwhB5OOpTtUVK4+3G+Mo43swGO3Gj4stMJDs2Oxbql7Bfisj7U
         rvuqGoyRIS0C2iO0vXH62zib+d1549Ujvkd/TPoAD/DKnx0o2RCoYoHnvnvukEppdVtW
         wuihaRo35hX1SgovZv3libIaTbtGvk8I2zVxJ8CzVJnNGJ0RgtuJ+jeZkizikz0E9yrR
         4JRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=o6T7CNEXNo/UOZ9+mpL3CelDgMk7RmYtu16YFniRAXw=;
        b=gogNqixqCnjhsyWSRmgZRHsQ3rCDCSFO7+6l/zQJBA399lcbLtln4PKX4Lr1D7JW6Y
         8m3WUd2zxcdp6shpVpnkXJSE3L5SEUUIxj2gr3IEodPn5irprtcplcPAAn9DwBwXz0bV
         7gvFE33E1J9FhEkJ8OkoVAGqK3X3Y0rXEXH7lzDK20jNc3lvw0uJhcBuzEMNovVqEVUb
         mNTDfM+bJ7CZuPbXs1Y70XlrzEJNzLWvX1EWu0vcbH4wXJooq/a2XgZi4PWI4ilF8oSR
         KoAoHJdbSfo+mbCNTL10hZPehGF5eZGJmW4iM0wpv0WmMi/Ze9U9/P5YjgwdcOTXmbAa
         xVoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="kTA/4UdO";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o6T7CNEXNo/UOZ9+mpL3CelDgMk7RmYtu16YFniRAXw=;
        b=qkAdB0JrKqozAfnu7K43Z/fzwuiMVTrpyP3RzwHlaQ6/PAk2SxOWFXVgacKE4UyeTA
         JcX5iw+q2eu8mPsqyGFk5glzW/EcsbFi0/liJVI4Jdy8ET4q/QVkvMpQzxpSfLEAOAS6
         AuIzLod92l/o3UK/RfTERPp7HnlcAH+6Ww/K5kXhKmI/Ds366ad0IbU/eXydYrDAPAJH
         UG09j44EIn1HO4tCqm7ZS17aHrsxltFqW0nn/x08ZcFeZwaoQksGP+FiXIwJMIrvO3T7
         c+DHeII89/1nSLu5v/0queWP3XXk1xQQLfiEFWwdmWprlZxvYpQxUjURvTecyyg3nNZB
         1pdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o6T7CNEXNo/UOZ9+mpL3CelDgMk7RmYtu16YFniRAXw=;
        b=UT00Nw0UO8aRzf69Jt/W1NeAUj6NiTdAj/Fk2y5XzeNrqo6HDs64pg7Pqqs71Q1yPj
         4Xo1EzGtW6v7LZCdhGJpq/b0uJFGQ6stnfpvcb7FDyE7ZqixdL5dy0u30YXHSA6a5FGj
         Ti8iPTNQRQuOC+ARbZE9K6NoABNS/jQ/l/SSQxpXtLHC3voJE+8UCL+R7vnSofV/Do/Y
         GhHWjQ80QI626o5/JBTw0uUIPMsYqP0SCZhIcDXC++/NqGHqNGssz4MK+yvuuAfBteoC
         4t3OepF7s7pRPATzH5My24Z8+Gnr1Bk9zXBbKGbBi3nhwupHohOuaWatQONYEnqdVB5p
         F/RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWqcINF+JWYnAz8UdXcWUg8OABIGrxbeslT2CNQWut2fdhS7g0o
	46yma3PhWe9XZmP+vMd7XZY=
X-Google-Smtp-Source: APXvYqyhEOr53ztpLSZHIahq1D7jj8Q7R5bfnQb2DQ/QIiPrMhQyA6WqFjP9u56DQKRwmpYsSOGIxw==
X-Received: by 2002:a02:c011:: with SMTP id y17mr19729576jai.41.1579038505936;
        Tue, 14 Jan 2020 13:48:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:1444:: with SMTP id 65ls1384743jag.7.gmail; Tue, 14 Jan
 2020 13:48:25 -0800 (PST)
X-Received: by 2002:a02:c9d2:: with SMTP id c18mr20988506jap.66.1579038505563;
        Tue, 14 Jan 2020 13:48:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579038505; cv=none;
        d=google.com; s=arc-20160816;
        b=pkYIHokUWNoFFGht3IrxRADRM4dGJIKq6zJUXVuz9TFjEM/UrRSbVj79xC3U0GdA8e
         WBtIXvcXSHCy4M2p9Bc5qvuo6G6Gds2TweNJUc/JANQaSVrqZaw87GGpId40XyeQ1AEj
         zpWPGgJeAwU3FYzvLhhZkIz6W+x5mv81FEksd7Aa9vUtafsGYpKIquKODVyrmVBvQnuN
         DhTSvU5EnRIVIG5db4yRIt6F/7ihld1ycMYxQtdMP7lrj/rK2GDRNQEwf7NH4/cXcQWF
         FPUtDgGDS/59v5gAskmz3tq6D9uMkZp5t9JYl0VkXTfftxOth3jOhs2QR02rAPuvtAoD
         cQrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=+DWS+MFZkVa3i7JL1v23vFX8ZF9bOD40hjVh+TnhgTw=;
        b=pkv21BFTwfWBmjSNWLqw+gimVVxrsXX1b3je46xPzhMauQ0Sxb3hI67NPXBfiuwdNX
         Fqem6N4br5ZBbNVZoRUjr3iNermZPcXsX+X6YobMs7eUGd073eBESNpg22yyuQffiOyX
         uC8SnmbIz0PocjXnqrJuDyROE694GLpHLNSMqLb7mXohOqAcXICPHE4BrAtILhV6tFaS
         2qrKuG5fgHo5OVWi0QDPrXRSh2eLEebVPQ0exy9SSkhVJJgDW3Xy/N2ft6Qss3z6JakF
         eZc76IKlMHw0qfLMIQDc/jeLyOQJ/5riXZN6D5bgIINx8iOmw+wHUHEK7rfGhujo3ikP
         jqIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="kTA/4UdO";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id z6si645035iof.2.2020.01.14.13.48.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 13:48:25 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id r14so13678366qke.13
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 13:48:25 -0800 (PST)
X-Received: by 2002:a05:620a:1592:: with SMTP id d18mr24178234qkk.80.1579038505028;
        Tue, 14 Jan 2020 13:48:25 -0800 (PST)
Received: from ?IPv6:2600:1000:b029:6649:f4b1:4b94:dfb9:77cf? ([2600:1000:b029:6649:f4b1:4b94:dfb9:77cf])
        by smtp.gmail.com with ESMTPSA id 24sm7408173qka.32.2020.01.14.13.48.23
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 13:48:24 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
Date: Tue, 14 Jan 2020 16:48:22 -0500
Message-Id: <9970E373-DF70-4FE4-A839-AAE641612EC5@lca.pw>
References: <20200114213405.GX2935@paulmck-ThinkPad-P72>
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
In-Reply-To: <20200114213405.GX2935@paulmck-ThinkPad-P72>
To: paulmck@kernel.org
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="kTA/4UdO";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
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



> On Jan 14, 2020, at 4:34 PM, Paul E. McKenney <paulmck@kernel.org> wrote:
>=20
> As an alternative, once the patches needed for your tests to pass
> reach mainline, you could announce that KCSAN was ready to be enabled
> in distros.
>=20
> Though I confess that I don't know how that works.  Is there a separate
> testing kernel binary provided by the distros in question?

I don=E2=80=99t think I have powers to announce that. Once the feature hit =
the mainline, distro people could start to use in the debug kernel variant,=
 and it is a shame to only find out it is broken. Anyway, I=E2=80=99ll try =
to edge out those corner cases. Stay tuned.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9970E373-DF70-4FE4-A839-AAE641612EC5%40lca.pw.
