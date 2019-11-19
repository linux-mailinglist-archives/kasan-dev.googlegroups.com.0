Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBRWD2HXAKGQEHL6EGGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF018102E58
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 22:42:31 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 6sf12829256ota.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 13:42:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574199750; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Lk+VyRUo1kU8SYMosdFVV1R2KpV5GBA8DQdwhBRa8mVwpfDqHlD5chAD0R4deyKGf
         1ro4J0Nied6gGXKRQaYjKwGW6zgg/2/4papTEgXLrPBb+2AzLcGDnxVIphBiEs1KwvXN
         0Q2/uJMrP4iKvc6WXdtZChkQA93tcJ/VgeYIt6pH9pgWBu1zNu+ZZ2s2XmWUH4Uguhgf
         zrFDKYCtHQqB3AY4dxfuqeATimqgxkkak7akZPdgVMNl4pDkWV3cyqC7G6aU2trXMOIQ
         XzsQd9eHSi99mKcc8IykKsLfpp4NAsC+rpP5k/SwS3Z5qfPxdv7Y7pZjzVaaj3nHL72d
         b9eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=ug4BdgYm1IlISvywO9Y9pt7WQsG/RMhGML4zwhBE4v0=;
        b=dED1YnZ9mFRghieLv2ms7rGSbHnl/Ov6F5ehrISlu3CsASLGn1FKT/l7bt/YreGKJ2
         lpb+B6OH5wYddIsk/D1/lxcCJMbNp2HksHF7UMXRfgrYojWUATq1B0Bp95yDvJ5C9TMw
         TyeMBp9gYFrbgWVlBcY4Mf9T3ra+mQg4cl7UlDhLwrHzBsDiCdRihQvlq0VwKlcDEspZ
         iXBQyYnU0JQ5Vp1Rcdat1+we5I7+CPKgdhKj4SWYLpYLdcsdpN1bintORWcgrGebGKKN
         kUo7vVXbAJlFojImT7kmLGbQPNgvpDWqNoVgXkLabdq2DI9cp6YHyWhHb+PH8vaHgqUD
         RJ6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=fwZ3JQdG;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ug4BdgYm1IlISvywO9Y9pt7WQsG/RMhGML4zwhBE4v0=;
        b=pI9Q6zrMPpiGpMVdf1AFZEbhoMy7D2FJMigmodQjji4z1RJLukUMIjL76g0cqHdekW
         VQDdKQ3pL+KS/PHCJq9dT5P4CxcfdMg69TTlb/HclNKr6Sa2AY0f5LMbBNUeg+tkwqsj
         8wbrB9fc3s+6u7BjOMtqpgy5tZ8vOJSUt4mghg8pRL//MRd5oukM3LF1omAtMrpjKv9c
         R5R2uG6uFJyRxlsTdD+J1zYkiyBwFxEKU2UNe2zDtkJPaFrn1mphEiZ8D8KqqkOPLJvP
         XSSLwUTcgzFNLwLRXxyByqIuAwAKkXe4NEDATUT8cVLqUrCb6liWKYE57hHwCLseEmpN
         Uodw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ug4BdgYm1IlISvywO9Y9pt7WQsG/RMhGML4zwhBE4v0=;
        b=OgH9Gqocggov2BTbyvCf5QUTrOyFtbEPUMNEHN962anc5Ge2aVKS1c8Xcse91TWQCn
         GhpckLDys2ajihKIFyIsvZUzcjFKuooYruBUErSy1kILM2PFQuJqHLJUAm675Di5bBPI
         nZXlKwH/G1sZ7begvqwXVQNUAGZTSA6wjAqUD1aAFWa0t6zVM28oIGS/8QAWVR0erMuQ
         o3Caho4ec7ZodMMPkZEQK9V7K8VGj2/z193iNuZBuPVkE6FNzx2firUJJgOFshZ6Ps5N
         tp3bvqUyizllnP9lhBZ/FbXE8FruByWQZcSLxfyb8BxUU12nvI2IMU24r3WYr8cwkr2z
         ZTyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXobJp4/hlVOP5s7rsEVIU7MuAYXrd8exZs9ddiA87CsroeiMyx
	fMclYoSLbt+dft6CLx+G304=
X-Google-Smtp-Source: APXvYqz1oyYbc0f+EXVocNSzaV8rJ795bix/S49LnyXfpvhpAKJ89r+nuBHGw6XbTc5IbpcZABq6ZA==
X-Received: by 2002:aca:5786:: with SMTP id l128mr6154913oib.53.1574199750294;
        Tue, 19 Nov 2019 13:42:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2c1:: with SMTP id a1ls5235066oid.5.gmail; Tue, 19
 Nov 2019 13:42:29 -0800 (PST)
X-Received: by 2002:a54:4898:: with SMTP id r24mr6035290oic.143.1574199749769;
        Tue, 19 Nov 2019 13:42:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574199749; cv=none;
        d=google.com; s=arc-20160816;
        b=NHIJ6zNjdjJR5vfCO+CLk+RYMBGWAsyFkJPKqXpD0HDF5KF4z5/B0WntKAFyPUpLQQ
         yU8k9VFRioYFdtolbtacZxmZxgluuI5HDRHqd5VaJR609hk9mU6/uNtEBHeexOwDhCof
         X8QvfBCsbeYRU9Wpfka0I/cSZ7vGyG7YerENzy4lybPRBKdy5Kmlik1caP9L/9hZl3eH
         xPNFl+rdwT3Zrp6rUK4NTTeh7d6AtmhWHdy6ngGkrScDFnxiBeJd4gcFeeXHofrutrqQ
         hMT+FmV3jH0IHh08v68QqGkkFTiagxYUTBz1Nwzj5G2uQu6lMxv9R1p4GullDGsKZKcY
         T6ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=QB4SUVhpavfDd836jssG/dIvVknUQvs1rkhBHGx6mVo=;
        b=VX+6fr5LdKCH676zFkxVZDJkI6I4776QnCvZEZbzubOagcLCBX7whH4UFm34oH8WpK
         U4nMtUBZeC0vVoccDhtq1qzIS0Xc8ku+a8nqx/QnJEV05wPhdotJOz35BL+OrTp+fBkE
         vtrCx37bvTByfl1RjxYO53De8JS0zlzvNxoxyoUNa7HSSDC5DIxztQFUg420svz8vrb3
         4n+PTC8/q2uW9g34iousVcrzkfQZIsUZxO1a4PF2YlCxDZUMObhNkpS2987P/e6ocE/9
         82okt7W41b7HMBqwFK+Fsvnuqpcasc6WYbvmyWE9scHJhBSAFueNFO95ZB6hZt+nXLgi
         SvHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=fwZ3JQdG;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id j26si1095115otk.0.2019.11.19.13.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 13:42:29 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id 71so19363251qkl.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 13:42:29 -0800 (PST)
X-Received: by 2002:a37:6517:: with SMTP id z23mr32008271qkb.434.1574199749166;
        Tue, 19 Nov 2019 13:42:29 -0800 (PST)
Received: from ?IPv6:2600:1000:b079:1710:3c3b:2ce9:9489:b502? ([2600:1000:b079:1710:3c3b:2ce9:9489:b502])
        by smtp.gmail.com with ESMTPSA id a19sm13439465qtk.56.2019.11.19.13.42.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 13:42:28 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
Date: Tue, 19 Nov 2019 16:42:26 -0500
Message-Id: <A74F8151-F5E8-4532-BB67-6CFA32487D26@lca.pw>
References: <CANpmjNPiKg++=QHUjD87dqiBU1pHHfZmGLAh1gOZ+4JKAQ4SAQ@mail.gmail.com>
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
In-Reply-To: <CANpmjNPiKg++=QHUjD87dqiBU1pHHfZmGLAh1gOZ+4JKAQ4SAQ@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17A878)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=fwZ3JQdG;       spf=pass
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



> On Nov 19, 2019, at 2:54 PM, Marco Elver <elver@google.com> wrote:
> 
> Regardless of approach, my guess is that the complexity outweighs any
> benefits this may provide in the end. Not only would a hypothetical
> kernel that combines these be extremely slow, it'd also diminish the
> practical value because testing and finding bugs would also be
> impaired due to performance.

On the other hand, it is valuable for distros to be able to select both for the debug kernel variant. Performance is usually not a major concern over there and could be migrated by other means like selecting powerful systems etc.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/A74F8151-F5E8-4532-BB67-6CFA32487D26%40lca.pw.
