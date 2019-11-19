Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6OI2HXAKGQEUAPFIXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id F2167102EAB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 22:54:02 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id i1sf15639103qtj.19
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 13:54:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574200441; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/stRHvL4qnA7nvKZ2OCK7wSmOMf+5EkhGmCx1QWnRVAtURrAAibu2M6a7pG3k4YER
         TH2xHrNiBGPnYMXZOqV7K6O8ZiEVA36C0ALFd0AM5cED4SpQiefN68UidW2HTW8s+7wr
         EfkAqR/M7owUwr2hvmluLjYCim9c14jVSs1wUSwgApXoT8mNeRMuP2lo1oLcUqisKjLu
         CSewVciEZqREec7aVU6JH4BmR2bWbfakkOgZvP8+qYMdXH6gY3Owrp6Ar5+oklXwslps
         GXzV43eoUF+MzlXuh+dw5T6MgRCVEWJJq9xQEyypYTNuUyvuRwZbkmKQloVaeMWJx8J4
         Tptg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=weQhbw63JXNplBHsCY+v0rUcYDDyKLnwJI2fXtaLOm4=;
        b=0iNpWMyosRsa3hw3mV9fZTmpixFxsuBQxo8gvuyhweesCqkkpoBeYDX5ua3fuoATde
         ZODp/+s6NPW74H32haEW4cv2QsnNMEhEPkoJtaodQXkakM7ccfm24/nxdSpRsZanCKSH
         1WlavticXnXR4cQHgB8uZjaXIsXZKpGvDNIocLbAkeQwZ5Yxl96KkPa/2mg0o0cYaDJT
         Hoog/eBCm7wo6gvUd7EjPJMZH7l6zfMhBcdTYBNHlnZW8nnGgjrwIb3i426zzQD7k9/C
         83XgxDVsPmsNc1tVMopDsHZ0xINFWK+CnGEX9Wxl2jAHNeRRrFHvHSg5H5em4gq2oUV9
         6H1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="os/9/wpF";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=weQhbw63JXNplBHsCY+v0rUcYDDyKLnwJI2fXtaLOm4=;
        b=BynGEI2QP5NDEdPZmu8aLFzLYVz7tL0sn3Qm8nfDaQI5z8Ez0BNQgCrZnHYdj5ACO2
         EI4QsFhlC0P8RoD7KpGlnyg5LAaniyFdz6S6k5dkH3HId9iGygt1CM5y16QKIW/Faudw
         +GDO2AqdViznP8/6lHTOMDUHyLESKKgCOBF8Ib5jkp19vQ+R/E9icVy+F+ZscrMK0AZj
         hR11hrOuYxKkxKxuBTF/oxEnEmtyO0oOdIEYL7PxPmZbzPm1+a+NtJgeK7vBQs51WgaR
         LDU/hOKDj2mLt8j3zVdnwAfj6trLtXjnHaEnTRP5uOWSG7y60dPG77CI0srksAFZdOv2
         D93Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=weQhbw63JXNplBHsCY+v0rUcYDDyKLnwJI2fXtaLOm4=;
        b=IUrir5SIS0Qp445tZfWkvJ3lyQXEJ9M9vR46cLzvfwxNUy2KwJeqDovLTl9SbSgFs8
         5cRYb7uH0WmCr24y7VI2kYejLgKnXBSXXR28aLNGJ6Q1jgve4UjFYjqt3BHcQFkTSSXt
         cJLGNMVayfts0ez4uMTg1rlH1ZgKwStaLn+C8S4Y21uNKTHvRXVEXMNcVNIKjVLQNi/K
         GIMgQEYHIitL1HMiRU3h95Ybh+Se3kioGEUdYdyIxsY2O4BnekLdrTwmBvzuPgxLop9q
         GwzCdwGlQzKcPdrShS9c+Wms582iyvsBsDEATrlqK+sKpWTbsRtY7iSXGGEhw218x0Yo
         B8Hg==
X-Gm-Message-State: APjAAAV7otFeoMVFEnjf6YXZPCKsky10r0lqjJVflF0hkc/JfHKs4wgU
	GqctcSqdua/j/4uMapcJHJQ=
X-Google-Smtp-Source: APXvYqzdzWStBPLY/nwEDKD1xPLQzCtTLQlSsDXLg6z91SGon7ol7W/81auqY5+VGVNALPo20ctaFw==
X-Received: by 2002:a37:b14:: with SMTP id 20mr30388300qkl.1.1574200441642;
        Tue, 19 Nov 2019 13:54:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:785:: with SMTP id 127ls10627qkh.8.gmail; Tue, 19 Nov
 2019 13:54:01 -0800 (PST)
X-Received: by 2002:ae9:ef0a:: with SMTP id d10mr18493421qkg.262.1574200441292;
        Tue, 19 Nov 2019 13:54:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574200441; cv=none;
        d=google.com; s=arc-20160816;
        b=WvPXBbzkJj2Q3pSQ8WJN09g4ghXZlCq0ROIH1jHRWBDNUuTKHAq0dg6ktXwzK8Ze+v
         Lah8jDzdz3SoFDf5F653I2h30miq/2GFb7bd8M6OjgJj2FODnqW31MmfOhMNyijpyR53
         bjy+RPU7sbSzPLAqmkDtPGWzzfRQS6nyyf1nU3snTMOXem+xJCk9tFTnkJA4eJdMS4PV
         pE6W2BFUa+p+oo7obA70CBOyW2R74f0jaL7t6UDehS6QLqFAkj3ovo0T8x9V6MfMFJjw
         TxheksYYked8AHC1xalAzGyr4woMHLM3+BKB3K8QI5/ZJmqu3T9BhjKHao96Cq1+Wusj
         YhaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xwQvEr0/UaVV1k90qxcSpFl3vFq94C3DTr9L5ipVOwI=;
        b=CZqpySIkeqdnkxLKOf2YeyJVM/xEJm/nvf58gTlL4QDCL4g+lm5XpHMhVStEBFk0QD
         05rKTX5VDHdRjjrc4kJaA1MQXVCjqcuTP2xpNLijr2W14lGzP8S1K47rabsOLasz1jMc
         WSI4Yq2lBTo/0zZwsoTwQLcnnMtORu5YdNKQ2ZvQV3N8jaWwzi0HdejHzV5Iiy4UWtdj
         5YtFHiyJ+m16WdNfEjbRrf+19lNT+FGS++YqvJK3akyQQj8II30ein9NAmjsc1+HtTnP
         m5istebAlef4vJcHTCHvEhWtwK1i9Pkvg9yyOcS5Tz8A61S52c1tocrMDGNO7wuJJdYg
         Jeqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="os/9/wpF";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id w140si1070538qka.6.2019.11.19.13.54.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 13:54:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id 94so19331331oty.8
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 13:54:01 -0800 (PST)
X-Received: by 2002:a9d:82e:: with SMTP id 43mr5680239oty.23.1574200440363;
 Tue, 19 Nov 2019 13:54:00 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPiKg++=QHUjD87dqiBU1pHHfZmGLAh1gOZ+4JKAQ4SAQ@mail.gmail.com>
 <A74F8151-F5E8-4532-BB67-6CFA32487D26@lca.pw>
In-Reply-To: <A74F8151-F5E8-4532-BB67-6CFA32487D26@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Nov 2019 22:53:48 +0100
Message-ID: <CANpmjNOJdWi6i+2Nn70UQDvF0a0pQTVVye7CTTJgqOHa3UmHMQ@mail.gmail.com>
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Qian Cai <cai@lca.pw>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <Mark.Rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="os/9/wpF";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Tue, 19 Nov 2019 at 22:42, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Nov 19, 2019, at 2:54 PM, Marco Elver <elver@google.com> wrote:
> >
> > Regardless of approach, my guess is that the complexity outweighs any
> > benefits this may provide in the end. Not only would a hypothetical
> > kernel that combines these be extremely slow, it'd also diminish the
> > practical value because testing and finding bugs would also be
> > impaired due to performance.
>
> On the other hand, it is valuable for distros to be able to select both for the debug kernel variant. Performance is usually not a major concern over there and could be migrated by other means like selecting powerful systems etc.

Fair enough. However, right now none of gcc nor clang would support
this. It is something to revisit in future, but is certainly not
something that can trivially be resolved.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOJdWi6i%2B2Nn70UQDvF0a0pQTVVye7CTTJgqOHa3UmHMQ%40mail.gmail.com.
