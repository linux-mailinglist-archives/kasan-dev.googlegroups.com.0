Return-Path: <kasan-dev+bncBDEKVJM7XAHRB6VLULCAMGQEXNXQ4RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 858D4B14B58
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 11:35:56 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3e3d7e44ac5sf55198545ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 02:35:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753781755; cv=pass;
        d=google.com; s=arc-20240605;
        b=AZNOTw6AogVEc+uNoyQqPoHrvljO7+QXIAE+ANL55RcOMntjVKyQ6OT20NDmEjrY0u
         c5wLKaS6k4uWR8jBUzN7WgTOv0cu5JYWPn9C8dLQx+HS5XleYzXqvu3nlJ6tFFrIaJfB
         NKSoLbSDZBS8jKiBjvTIfrOtUnYIGJeUMCHCqkpEUHm+TPGov6bZtm3+OBNI+VUzuToI
         CDsdaQQeyvOMjBXwligfatph2rqrtM/Ok4rjFYE3n6PvB2eAexpu0onUHiorZ3eGzurf
         sp7GmU/mqpEiuqdaXm87tZhb3x2DVHKyszhbW1MLDitWl3FPjLv2KhrdylwAMvB9RZOU
         wqzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:references:in-reply-to
         :message-id:cc:to:from:date:mime-version:feedback-id:sender
         :dkim-signature;
        bh=DXrAbEwA1e2iheQN2Iv9SSk4hngUKP6Bv+5trQEedD8=;
        fh=TM29HvV3PCKu2M55f5LWZ/kcXKaNjI2omV3SO7S+HrU=;
        b=WYxoTjA77A8OdmIBif94iAMYkgRiN52xsqhJhUxiokq7xKBbmaOm0IROk8e8V9DzB0
         1ujx2CIx75a3jqDPujzvC7tYqlOAfyYjj8HzDoMxnDzQHykqH5keQGEVPJKomV8lHMG1
         T28wW7zIbhfsGtt/tPnrdJJ7ufRQ/o30ymqgzSMbWl80SJ1QX5VlkcQEgNQsZpHEO7E0
         1eIm0rwbOKixM3lNK3N2eg5dTs/7JBsHRWpYUORc+Sgvr26qj26dGUcifItaDmKb1AZH
         z58J3io6urNoGxslO9Ok/ZwMnCW+qzEtUA3VHnRuMqcpYPPxssVZqYuzjCe18KSmhfqd
         wNHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=SefSK9JI;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=dcWL30Zc;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.140 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753781755; x=1754386555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:references:in-reply-to:message-id:cc:to
         :from:date:mime-version:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DXrAbEwA1e2iheQN2Iv9SSk4hngUKP6Bv+5trQEedD8=;
        b=PBaCvyUwW4Wdz4RAPV7VxVvjHcZQmgddfRzK2p3QzvdVbOOtQRptLNZyS/K99Xh7bi
         VTk+T7MI3pEancIfh6CnZaVtnCHVGZgO2B4FmFNFyVMw6mK8i+ugSMuQ1e6FfBYq7O+P
         YWjxluda9oLOh+aIHGjXOGGTZBMmKfyrxbbNuwcnyAEETKRGcxS+6bzoix9evuZnAZcl
         hcpBZ3d+yyP2B0+YqANedM/46BwMHVjHemBz7u0PkPM1htaq+p8jUQR1EtY5Vd//WtFk
         /WHfPgGTvJI0kcMGeLelQILdBWW1V+B36hHXeMRF0rOYzZOTzPyNBFehps7Kz/QBUly/
         n/uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753781755; x=1754386555;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DXrAbEwA1e2iheQN2Iv9SSk4hngUKP6Bv+5trQEedD8=;
        b=AUbCxfJXuRDxkNtTQ+LQVhns5VVJ2fV6l3VbaCWzy9UT7qUkdeTuy+pVDYtb35Ej/X
         glwqztQYKSy2m+y9bugeATNWTdhdEngGNTSbxCV/kQtCM4J3IQdHig6+9xTRftJINr/p
         OwDIxOx4jvVl1rVvE2efdUDAlJRbwci2gGO+vEVhi0VXV3eZEvL6AVpiU19ZC6b/DGbx
         knP1ifzikvofSzeapQQ3hDRui9cQhgsLejh1cNQK1amuwIt6y97KEFprTKSMBOM7p1A7
         GCaV38N7JHcPnCRPWcyzRQhN+5SEQPWEcQbONd6LpDBxdoQR4EImcUDhwsd6mnAtd+9e
         h9FQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvrCZMraCPrXvH0YtoRy6AuoIpvqsG84bgnfnPu+LbEw8HZv0kF6H7MtzOKLoxxUA/0roftQ==@lfdr.de
X-Gm-Message-State: AOJu0YzuSjSEH+19P/pPQZClB6vheejvweVt8+Rzm9GPrELU4CAelXnP
	YKzROpFda5LeRUYP4+hvjiV0Sf3vKyR93SwliIG0TrHDomagK5NFlJeY
X-Google-Smtp-Source: AGHT+IFf3XQQvTUs9NrxCwdiC5y4uV2ovOAGdWuZOVCIlQKaDOVkSRnqw0zqka+EcqDC2cA00o85BA==
X-Received: by 2002:a05:6e02:194a:b0:3e3:ee9c:725e with SMTP id e9e14a558f8ab-3e3ee9c77e1mr9819185ab.0.1753781754832;
        Tue, 29 Jul 2025 02:35:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc4UiM+6/8Ga5H1C3IdQArQTjOYJuyfmSVA/xHE0ds66w==
Received: by 2002:a05:6e02:4618:b0:3e0:5c71:88f9 with SMTP id
 e9e14a558f8ab-3e3b51957abls55739085ab.1.-pod-prod-02-us; Tue, 29 Jul 2025
 02:35:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUypkaPzsV1x2vEgx1Rgo/N1+MnDvW43ROiWZQ6Cs+H/Rm3wNfYHuR0z5o77QZq6b1JatJLnayemJE=@googlegroups.com
X-Received: by 2002:a05:6e02:4508:20b0:3e3:cf0e:c2dd with SMTP id e9e14a558f8ab-3e3cf0ec54bmr120251285ab.11.1753781753428;
        Tue, 29 Jul 2025 02:35:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753781753; cv=none;
        d=google.com; s=arc-20240605;
        b=IwvHHhjgH1aVuRoVED40uWo9wDtw2FhFfIfyWud/WtnwzkEMCaILH183gRHpOQZY3j
         rYtVDbog1XeAI6aWCqk3yyKkV9oqZhGyw00OtEGppKmwMFBdygEhAb05yOWZLEIYIUbl
         1234j5e0EaD4sbhgXEd38DMqc3jAwb/NSnfQIgYSpOabWwW/45qT11pCSc6AeqgxXzwO
         zfftl0XySPzgiYAAKc4bC+6nclnEFNkcX2GfwckWEPMnrGArXRDhW2DW3/Wt5mTfWqAo
         HQBrhiHHWpsiCJRLxdomTUbAc97iCxUUBkwoUz2tVf/Ekc+B48JoFZiiVNXcLkIeHoD7
         kYXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=//ORI/NIeaAxh1YrBcckAswwPCVYsSmGgDQbyUkZAq8=;
        fh=IgZXsUC05qQiC8XeuYc003uxjiYGDIXPtWmLui7lWo4=;
        b=SPpjNoZ9zGP/zXPqYJMMnuuTx84MeWbRLHSRzF/zzJ20KYYa9/XqYep/EeYli1nhCb
         ZSbLr/xAvnMBrXlEYxEVKSuL68pjBESvgxYzmnpx6BG+vqKxB8knYcoblPxz0ppUunaM
         3D1a0pXdseUxB92MLdzyfVlcJkwuwXjjyKrozvNXz7dok2ii9uPf4WkdYVBqtvX1U8rg
         fwA3qzZVXaZR/WXallAa+e1SU/yr3rdCbGlnW4ybM9hEqlPpDgV8oHttkUF7ENoa0JJH
         sZQ8MfbEJ5pWvQxI/nlsL/AcrluTVdBs9E7iQnVPGz9r47rvh3NQIEKeWwQ87dXhHUn6
         4vgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=SefSK9JI;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=dcWL30Zc;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.140 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from flow-b5-smtp.messagingengine.com (flow-b5-smtp.messagingengine.com. [202.12.124.140])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-508c92ed610si399503173.3.2025.07.29.02.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 02:35:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 202.12.124.140 as permitted sender) client-ip=202.12.124.140;
Received: from phl-compute-05.internal (phl-compute-05.phl.internal [10.202.2.45])
	by mailflow.stl.internal (Postfix) with ESMTP id 282E51302005;
	Tue, 29 Jul 2025 05:35:51 -0400 (EDT)
Received: from phl-imap-02 ([10.202.2.81])
  by phl-compute-05.internal (MEProxy); Tue, 29 Jul 2025 05:35:52 -0400
X-ME-Sender: <xms:85WIaMSdGeQUGSWiZhLdfx2lJ2mSTS7IehTipzI8wt2v51LJCX16QQ>
    <xme:85WIaJxgTNOs5oElfHTSY2AEYjlrQwVHJZaKe-7EAi0lzxzNaEeVgBrJT6vSi8wjW
    LT2PNORziXGfT5G4H8>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdefgdelgeejudcutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpuffrtefokffrpgfnqfghnecuuegr
    ihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenucfjug
    hrpefoggffhffvvefkjghfufgtgfesthejredtredttdenucfhrhhomhepfdetrhhnugcu
    uegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrghtthgvrh
    hnpefhtdfhvddtfeehudekteeggffghfejgeegteefgffgvedugeduveelvdekhfdvieen
    ucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegrrhhnug
    esrghrnhgusgdruggvpdhnsggprhgtphhtthhopeehtddpmhhouggvpehsmhhtphhouhht
    pdhrtghpthhtohepsghpsegrlhhivghnkedruggvpdhrtghpthhtohepugifmhifsegrmh
    griihonhdrtghordhukhdprhgtphhtthhopehgrhgrfhesrghmrgiiohhnrdgtohhmpdhr
    tghpthhtohephhhouhifvghnlhhonhhgrdhhfihlsegrnhhtghhrohhuphdrtghomhdprh
    gtphhtthhopegrnhhshhhumhgrnhdrkhhhrghnughurghlsegrrhhmrdgtohhmpdhrtghp
    thhtoheptggrthgrlhhinhdrmhgrrhhinhgrshesrghrmhdrtghomhdprhgtphhtthhope
    hjrghmvghsrdhmohhrshgvsegrrhhmrdgtohhmpdhrtghpthhtoheprhhmkhdokhgvrhhn
    vghlsegrrhhmlhhinhhugidrohhrghdruhhkpdhrtghpthhtohepuhhsrghmrgdrrghrih
    hfsegshihtvggurghntggvrdgtohhm
X-ME-Proxy: <xmx:85WIaBg7DA5uE80TwTiALrCzrej-0WgEHArKmquSwrXZjnU_QkHjTA>
    <xmx:85WIaDuZyOtGTHzz9bt_zPfC2qi8OrDyaJph1YM8cz3Q2pyWkFKbIA>
    <xmx:85WIaJInB3n0SkqGw796UfROaiDbKXXRWu3O7x2Xa33TjPnJPwVAIw>
    <xmx:85WIaOrnoUdsZpkoMcDfVOZN4XnTcRVptWOuf5XhqRCWibFXNKnQJQ>
    <xmx:9pWIaGmo_XxnnYEJX4gT9GDpjIrX6lXqryh7rr9LZTo_B0167GYZAeVZ>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 9F298700065; Tue, 29 Jul 2025 05:35:47 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: Tf1c1d2456aa020de
Date: Tue, 29 Jul 2025 11:34:57 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Kees Cook" <kees@kernel.org>
Cc: "Thomas Gleixner" <tglx@linutronix.de>, "Ingo Molnar" <mingo@redhat.com>,
 "Borislav Petkov" <bp@alien8.de>,
 "Dave Hansen" <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, "Paolo Bonzini" <pbonzini@redhat.com>,
 "Mike Rapoport" <rppt@kernel.org>, "Ard Biesheuvel" <ardb@kernel.org>,
 "Vitaly Kuznetsov" <vkuznets@redhat.com>,
 "Henrique de Moraes Holschuh" <hmh@hmh.eng.br>,
 "Hans de Goede" <hdegoede@redhat.com>,
 =?UTF-8?Q?Ilpo_J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>,
 "Rafael J . Wysocki" <rafael@kernel.org>, "Len Brown" <lenb@kernel.org>,
 "Masami Hiramatsu" <mhiramat@kernel.org>,
 "Michal Wilczynski" <michal.wilczynski@intel.com>,
 "Juergen Gross" <jgross@suse.com>,
 "Andy Shevchenko" <andriy.shevchenko@linux.intel.com>,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 "Roger Pau Monne" <roger.pau@citrix.com>,
 "David Woodhouse" <dwmw@amazon.co.uk>,
 "Usama Arif" <usama.arif@bytedance.com>,
 "Guilherme G. Piccoli" <gpiccoli@igalia.com>,
 "Thomas Huth" <thuth@redhat.com>, "Brian Gerst" <brgerst@gmail.com>,
 kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
 platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
 linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
 linux-mm@kvack.org, "Will Deacon" <will@kernel.org>,
 "Catalin Marinas" <catalin.marinas@arm.com>,
 "Jonathan Cameron" <Jonathan.Cameron@huawei.com>,
 "Gavin Shan" <gshan@redhat.com>,
 "Russell King" <rmk+kernel@armlinux.org.uk>,
 "James Morse" <james.morse@arm.com>,
 "Oza Pawandeep" <quic_poza@quicinc.com>,
 "Anshuman Khandual" <anshuman.khandual@arm.com>,
 "Hans de Goede" <hansg@kernel.org>,
 "Kirill A. Shutemov" <kas@kernel.org>, "Marco Elver" <elver@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Hou Wenlong" <houwenlong.hwl@antgroup.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Masahiro Yamada" <masahiroy@kernel.org>,
 "Peter Zijlstra" <peterz@infradead.org>,
 "Luis Chamberlain" <mcgrof@kernel.org>,
 "Sami Tolvanen" <samitolvanen@google.com>,
 "Christophe Leroy" <christophe.leroy@csgroup.eu>,
 "Nathan Chancellor" <nathan@kernel.org>,
 "Nicolas Schier" <nicolas.schier@linux.dev>,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 "Andy Lutomirski" <luto@kernel.org>, "Baoquan He" <bhe@redhat.com>,
 "Alexander Graf" <graf@amazon.com>,
 "Changyuan Lyu" <changyuanl@google.com>,
 "Paul Moore" <paul@paul-moore.com>, "James Morris" <jmorris@namei.org>,
 "Serge E. Hallyn" <serge@hallyn.com>,
 "Nick Desaulniers" <nick.desaulniers+lkml@gmail.com>,
 "Bill Wendling" <morbo@google.com>,
 "Justin Stitt" <justinstitt@google.com>,
 "Jan Beulich" <jbeulich@suse.com>, "Boqun Feng" <boqun.feng@gmail.com>,
 "Viresh Kumar" <viresh.kumar@linaro.org>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 "Bibo Mao" <maobibo@loongson.cn>, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
 linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
 kexec@lists.infradead.org, linux-security-module@vger.kernel.org,
 llvm@lists.linux.dev
Message-Id: <f8bcf5ce-8b8b-4555-a210-14e1974eac92@app.fastmail.com>
In-Reply-To: <20250724055029.3623499-2-kees@kernel.org>
References: <20250724054419.it.405-kees@kernel.org>
 <20250724055029.3623499-2-kees@kernel.org>
Subject: Re: [PATCH v4 2/4] x86: Handle KCOV __init vs inline mismatches
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm2 header.b=SefSK9JI;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=dcWL30Zc;       spf=pass
 (google.com: domain of arnd@arndb.de designates 202.12.124.140 as permitted
 sender) smtp.mailfrom=arnd@arndb.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=arndb.de
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

On Thu, Jul 24, 2025, at 07:50, Kees Cook wrote:
> GCC appears to have kind of fragile inlining heuristics, in the
> sense that it can change whether or not it inlines something based on
> optimizations. It looks like the kcov instrumentation being added (or in
> this case, removed) from a function changes the optimization results,
> and some functions marked "inline" are _not_ inlined. In that case,
> we end up with __init code calling a function not marked __init, and we
> get the build warnings I'm trying to eliminate in the coming patch that
> adds __no_sanitize_coverage to __init functions:
>
> WARNING: modpost: vmlinux: section mismatch in reference: xbc_exit+0x8 
> (section: .text.unlikely) -> _xbc_exit (section: .init.text)
> WARNING: modpost: vmlinux: section mismatch in reference: 
> real_mode_size_needed+0x15 (section: .text.unlikely) -> 
> real_mode_blob_end (section: .init.data)
> WARNING: modpost: vmlinux: section mismatch in reference: 
> __set_percpu_decrypted+0x16 (section: .text.unlikely) -> 
> early_set_memory_decrypted (section: .init.text)
> WARNING: modpost: vmlinux: section mismatch in reference: 
> memblock_alloc_from+0x26 (section: .text.unlikely) -> 
> memblock_alloc_try_nid (section: .init.text)
> WARNING: modpost: vmlinux: section mismatch in reference: 
> acpi_arch_set_root_pointer+0xc (section: .text.unlikely) -> x86_init 
> (section: .init.data)
> WARNING: modpost: vmlinux: section mismatch in reference: 
> acpi_arch_get_root_pointer+0x8 (section: .text.unlikely) -> x86_init 
> (section: .init.data)
> WARNING: modpost: vmlinux: section mismatch in reference: 
> efi_config_table_is_usable+0x16 (section: .text.unlikely) -> 
> xen_efi_config_table_is_usable (section: .init.text)
>
> This problem is somewhat fragile (though using either __always_inline
> or __init will deterministically solve it), but we've tripped over
> this before with GCC and the solution has usually been to just use
> __always_inline and move on.
>
> For x86 this means forcing several functions to be inline with
> __always_inline.
>
> Signed-off-by: Kees Cook <kees@kernel.org>

Acked-by: Arnd Bergmann <arnd@arndb.de>

In my randconfig tests, I got these ones as well:

WARNING: modpost: vmlinux: section mismatch in reference: early_page_ext_enabled+0x14 (section: .text.unlikely) -> early_
page_ext (section: .init.data)
x86_64-linux-ld: lm75.c:(.text+0xd25): undefined reference to `i3c_device_do_priv_xfers'

And one more with a private patch of mine.

These are the fixups that make it build for arm/arm64/x86
randconfigs for me, so you could fold them as well in
as well. I have already sent the i3c patch for upstream
but not the page_ext.h patch.

--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -57,7 +57,7 @@ extern bool early_page_ext;
 extern unsigned long page_ext_size;
 extern void pgdat_page_ext_init(struct pglist_data *pgdat);
 
-static inline bool early_page_ext_enabled(void)
+static __always_inline bool early_page_ext_enabled(void)
 {
        return early_page_ext;
 }
@@ -189,7 +189,7 @@ static inline struct page_ext *page_ext_iter_get(const struct page_ext_iter *ite
 #else /* !CONFIG_PAGE_EXTENSION */
 struct page_ext;
 
-static inline bool early_page_ext_enabled(void)
+static __always_inline bool early_page_ext_enabled(void)
 {
        return false;
 }
--- a/include/linux/i3c/device.h
+++ b/include/linux/i3c/device.h
@@ -245,7 +245,7 @@ void i3c_driver_unregister(struct i3c_driver *drv);
  *
  * Return: 0 if both registrations succeeds, a negative error code otherwise.
  */
-static inline int i3c_i2c_driver_register(struct i3c_driver *i3cdrv,
+static __always_inline int i3c_i2c_driver_register(struct i3c_driver *i3cdrv,
                                          struct i2c_driver *i2cdrv)
 {
        int ret;
@@ -270,7 +270,7 @@ static inline int i3c_i2c_driver_register(struct i3c_driver *i3cdrv,
  * Note that when CONFIG_I3C is not enabled, this function only unregisters the
  * @i2cdrv.
  */
-static inline void i3c_i2c_driver_unregister(struct i3c_driver *i3cdrv,
+static __always_inline void i3c_i2c_driver_unregister(struct i3c_driver *i3cdrv,
                                             struct i2c_driver *i2cdrv)
 {
        if (IS_ENABLED(CONFIG_I3C))

As I understand, the underlying problem is less gcc inlining
being fragile, but more that gcc does not inline functions
when they have different __no_sanitize_coverage attributes.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f8bcf5ce-8b8b-4555-a210-14e1974eac92%40app.fastmail.com.
