Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA6ETH3AKGQEUYK6QMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 012631DCBE8
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:12:05 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 67sf5036786pfe.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059523; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7HvOoIk1wQGJMTHqAoPOfKFfQ3O9CgfGfHm/k0vZovkWtoDcUqnl1cHRvpMvhdx/v
         jkt7Yh3sOE17/h9dRHRCm6kgRhtYib+8kOqovJBW0nKv421iEUmeOaM608XPuKM+n3/u
         tw9xogVc3zt+YYRPKJJKTu9mf1gtz0Z8F8HEyMDDKQUA7Xd4+37VZDXfPapo2+1qWPwk
         GqaGKhvT2EQ+qtMNHGOGZP713C0xXTcdoqZ8lPAmmElb5Y9dXmT175MHXJtI+EUq5xNV
         JiU4aMcBcdl+/7iqfbIZy9wPBBloqruYQ4m9Ijs1MdRFp21OvqFXRfrcIDhaWSZmGfvi
         1X0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wYkmDkKd1mMt3/RD/iTqLPMWo95X7bYwRqihVMeRJpY=;
        b=f49b4hUVd7voHXOjNNv4psSbgI5ICXq88DrSPlHnoaDq6L+p55ZBsMTHcImBXU0V6W
         9BODmkF+k2bSs6m7cBi2KsCOIGtjMwabcBJcPLTDofjP0T/68zvbPFRWm3ybayOrMUCV
         35FEA8C6+7VWBPnfNQ6Ur+DqLZvQ7OlRnUkVr1dIUBtoa+RxdFw81L1RIa4toUTo7ntB
         YzBaiFwNCGLTZxjmHK3eiE0jjrIgVvTUOEyTwpK+Q4ZddryZfaMyAC8T78Jw5pQtbd9z
         JMfVzq/IkgXuhj60klf9jne3JvbQook++S7kmx4ZIE8UyLz1ef445mxndASATM9EOBSl
         QS+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SToWnglh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wYkmDkKd1mMt3/RD/iTqLPMWo95X7bYwRqihVMeRJpY=;
        b=Zy4tZXR2uArOxz5tdGUtCd+yB7HDEsoUhhHEj33ZeAm+7dMsO/pNf8yKUwKiMIDkfo
         eK2iH9rL36e964vVDrRQi9GtbyMHFeU8rAdtJw44So+0TF1SBG1gVyY/X7Np2dlN+uqA
         lBD8mGHEdLvvAqF8Rhjte5v++qugpgH7izIVwIPiruk/APy9HiaZyuP6mRKFBFIvqIUT
         ZgNOLvpctMU4q/5UhXILRDuPAnqxxLgjbT9nLDo4OM7tdtkV0EG8iApwVO4/J1aP9aUq
         iPh+d8LwgbMyJQmYPpc21MvhsESqmRDGasUPu6S+KKhw/H6Rv4jvebnWvdhNab9lmt8k
         nCGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wYkmDkKd1mMt3/RD/iTqLPMWo95X7bYwRqihVMeRJpY=;
        b=QhFXlKA+0YmJYk/Qhu9qc/VCLfbCBCDCjgC0JeaceF2bWl+/LKKpNb//xnyms+KXfJ
         hlIZZxJWF6efUK2IsbJs08Y/H2E+0N6LzgzdfO6hzkyWFQ//N6cL7EInwy3PEKfyDr8H
         5focGf5itwNNip1mQWz4ytSe2bRPTckL1MWv73R5CxucEHyxX6cFK2xm2NRFs3oV8cLa
         hHDBG2/ADglXiJyXrkntCoep1gQljghfGBGX84m4G48UAzAZfSjZn+uMVo/sUSOfu1HZ
         DgG5eAvZCds7M6IIKd4gd4FD3U4weAH3Egf7+DooiTmpA0ONkwLhTqyqK4nMl/E7nW5G
         +qhw==
X-Gm-Message-State: AOAM53350ZtoJzIzVGdS0SOYp5gMOK7lmop90hk8mkm4LvmpB9QlXLBY
	+Fj2egYH/x5R1RQsN4EJmao=
X-Google-Smtp-Source: ABdhPJw8cEn5Yjwd1zABKwIPmcp7GRwVGxef06Jx8HKhHMCO7638+oBT0TOWb2Ajrkcz31x4ZUHogw==
X-Received: by 2002:a17:90a:35a7:: with SMTP id r36mr11479178pjb.117.1590059523681;
        Thu, 21 May 2020 04:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d95:: with SMTP id v21ls747610plo.3.gmail; Thu, 21
 May 2020 04:12:03 -0700 (PDT)
X-Received: by 2002:a17:90a:4495:: with SMTP id t21mr10738949pjg.185.1590059523273;
        Thu, 21 May 2020 04:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059523; cv=none;
        d=google.com; s=arc-20160816;
        b=Z3f5fIRID2BUYNaUbiA2zLHRYdHVzGGuH6PG9jmcyjXtrRPIMuSuy4psbbtRfk6Vs0
         hbDxzfr6OMkL9O1/WlTse75Op28hkIAo2qy4rW3fKzK2DAdeFfev3ym/wjQ7RGjM1afq
         ufglbUkIvluErZiQBNlZwRK8TygMohQk4yBOh+eak2BmWQUX/u70zaxVtpEqQL0qez/x
         Kio5iyPCdwPhRjGW7G2JvSZ2ss6MvyFh6C63UOaUqKvwISxRovZUUM1AOUaSAVMp/LOw
         PBZEFD871ULfjHVCUr4BLhgpS1KChRQ+FUTiyxleDTxSveczsa5Tj9ckukGAgubARPBi
         NhYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/oL7dAuaA62cBm7hAceUJOjBRK5rQp19BMPlUMceggo=;
        b=OCqY87tHs8g4LUGsJHm5ecuFscyGMHY1QuhTA9AMeHYzc0amA/U9bQqaLM96MFR5Yl
         8PG4F3QZuFzl5eGojIXyWMdeNKkKK87yKBYO/sevO3wnahP6K+SnYoTncTnfJDlKW4dx
         X6dbros+fBwDzu/TqdYAlF7oTVqxfG0j+iVEdWGIU0PFSFgW9A1fFLfv9Mw6yiys+m4U
         XPT5bB5wYCldARvEgmhUAZj4pbVcQf+ty5LtPuHpstFsXtWizfUvLYWbsAyzjPufrtj+
         KYrPbiJUJct8CNByGyCNDosPtEpNlVfINsLySJmoaIrnplFoBZuf45YpcKZJqwG9YYUM
         ngSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SToWnglh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id b5si138345pjn.0.2020.05.21.04.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id x22so5196299otq.4
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:12:03 -0700 (PDT)
X-Received: by 2002:a9d:27a3:: with SMTP id c32mr7112271otb.233.1590059522704;
 Thu, 21 May 2020 04:12:02 -0700 (PDT)
MIME-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
In-Reply-To: <20200515150338.190344-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 13:11:50 +0200
Message-ID: <CANpmjNP2GsUuHAfvBa6qhnAe1W=1Zo=0i2eB09V7GAdtRSjVfg@mail.gmail.com>
Subject: Re: [PATCH -tip 00/10] Fix KCSAN for new ONCE (require Clang 11)
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SToWnglh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Fri, 15 May 2020 at 17:03, Marco Elver <elver@google.com> wrote:
>
> This patch series is the conclusion to [1], where we determined that due
> to various interactions with no_sanitize attributes and the new
> {READ,WRITE}_ONCE(), KCSAN will require Clang 11 or later. Other
> sanitizers are largely untouched, and only KCSAN now has a hard
> dependency on Clang 11. To test, a recent Clang development version will
> suffice [2]. While a little inconvenient for now, it is hoped that in
> future we may be able to fix GCC and re-enable GCC support.
>
> The patch "kcsan: Restrict supported compilers" contains a detailed list
> of requirements that led to this decision.
>
> Most of the patches are related to KCSAN, however, the first patch also
> includes an UBSAN related fix and is a dependency for the remaining
> ones. The last 2 patches clean up the attributes by moving them to the
> right place, and fix KASAN's way of defining __no_kasan_or_inline,
> making it consistent with KCSAN.
>
> The series has been tested by running kcsan-test several times and
> completed successfully.
>
> [1] https://lkml.kernel.org/r/CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com
> [2] https://github.com/llvm/llvm-project
>


Superseded by v2:
https://lkml.kernel.org/r/20200521110854.114437-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP2GsUuHAfvBa6qhnAe1W%3D1Zo%3D0i2eB09V7GAdtRSjVfg%40mail.gmail.com.
