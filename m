Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4C7SCAMGQECDAXH3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DEAD381408
	for <lists+kasan-dev@lfdr.de>; Sat, 15 May 2021 01:01:39 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id r12-20020adfc10c0000b029010d83323601sf322084wre.22
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 16:01:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621033299; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwTiqvA+raP1xuECpHDO9RK9Taxd3erNCc3vBc5Qa6OIJ+DzbOsFmtrvti6guTbXU/
         W+IPXVbCsdj0Z8T7E07uuDFXN885icQaaNt9a4iqbgWX+84QKNhHOu7L4U9+u5Kryx1U
         xmK81vs2v9mwAG48qgKL/hgCQzCh2TjbEG0vc7EAYy9IASrei33wtDyG9coyx+YWnZwZ
         JXufILKzkJx4XSP4xwt4O6Wjjp02cRVQmVZ+ZCgfa370CaG2/g5olqZYvJC+mtqJj9wZ
         sltiLsFrmRE+NbEsFKN2mIoS12pvrBRMLhml24C7zWrCCxPCYAAulmy6ltPhaGZvO5PM
         xEew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jlZGLBnxSMp7IYQPhkfkEZUy/LBMbXStQeOdoJlMXfE=;
        b=Dwq5QPGXJOudQEDyRY3FdK7arHdWownNgNrCN26eUJJahKw6FgDMZZTVCc7devF9L5
         bhAO/LHNmdUCpedKTv7ysDg9nbd4ApEdJwFCRW54g+Okbl+TkA1hpVCIGWFYY8I1edTN
         KyZypciNKIXyrURBcg3BuAHcZLpGy6w1E6ilvwk7xz1l0fGQpAuJ7R1bkEcJZCWfyx0J
         /x9Y6VjEmc5LpZMxiha1daL4YsngIUjXf0gGzs/t+aDwwmASMus6WCqoN2WHTlyJuDtv
         wIvD3OJbLa+AMtTcksNfmkZPQjEIRl2arnqdWmE8oXf/4n2icPxKBSZYh/Vcw5Tvomzu
         bJAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ME8G7Ttr;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jlZGLBnxSMp7IYQPhkfkEZUy/LBMbXStQeOdoJlMXfE=;
        b=qzfeXoSaMcHn+bQNR1L/f2TEGYt8IdByiMYP498ZP4OCPg0o3J6d2D6iIxZhDvm4/u
         YiQ1c8t00EnhJtAxns/B6IyPlt2ucb17zYTqwSFJ7HxDoymmakcAnAOl0Uz53JRs437Q
         4SfwlZwyjFMgthHuubVZBhd2R6Oe9p4H6kGKxRY64HbqbaL7oo5/+BYIo+2KaNEd8cid
         Lwukloofc1DmCexy9jPe0s5H4uKkEGRURZT5x0vbigLEjS2ZriRJVSbTMcDipy6c7/Yr
         SqnIuwCGScC2j2JESE71E1wb+qRKAcC5p3TxOwBTBMzCkKF+hg7+ZT+NCkd3gOnNpV4X
         Hd5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jlZGLBnxSMp7IYQPhkfkEZUy/LBMbXStQeOdoJlMXfE=;
        b=Q7d6t94aOsiaxHSpF9+oXjtwH3E2HR7b7nowCQANWYHexw+5fT7Palxwe2SVslj9yx
         7AmksD1Rp5puYNAUR/aLALUGMZ4WcAUHQ0dP5bqUECQ1upHLfar1dwg++1Zr0UU2BZsl
         gjmxLjiPs77WtYVHUv/6Y+qEZu5a/WSqlHzQhNK/rp18OYOL8BsALQqfDs8rUbj6GZFe
         q0TJfUbYnivQI/Q4q6YFH8K/1QtmuLzEvkFR+S+16aQWAgh08SyTJ2eaL00ks3nG/Ye9
         atmkV15z81TsjbypPaJ4P6QoRNb+cnkvBm4nkiHv67ezCJtD6kVcV+vU5sBzyKKEJzgp
         eu4A==
X-Gm-Message-State: AOAM53134ZQjyXurTTzOEuEpJ8jd0ec7ySKiIP3gfquSPSEUpqzc4jzM
	N8Pza2uyIs1ThD2VfSvfwk0=
X-Google-Smtp-Source: ABdhPJxf/cgbQ/u/S2r6GAgdhZTNLCngTBoPGOb30VNBICis1gba9Rh0OvjGsMEo2W8YYg+T2K64Mw==
X-Received: by 2002:a1c:f614:: with SMTP id w20mr51528485wmc.70.1621033299175;
        Fri, 14 May 2021 16:01:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2051:: with SMTP id p17ls4495078wmg.1.gmail; Fri,
 14 May 2021 16:01:38 -0700 (PDT)
X-Received: by 2002:a05:600c:4a23:: with SMTP id c35mr3892051wmp.130.1621033298207;
        Fri, 14 May 2021 16:01:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621033298; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/Ipkm72p308vX2GglAvre5K6rtvP+yZtRq09r4iH8Ue8cAyli2dCaZ17lJYbu6arx
         007CpC2Kl5jW2iRxnSMl/BFVojUq2q3cftgxlRl27e9bA0plnyx8LESkhqCbrZxmWiQz
         2FEOS+HvFjqu8pA/VFEsec42ZLe5tlubRiwwHAXFmZTK+4P39O6LzGn1q9eaqGeG/vh2
         LSg/hCRmACm5mhU45eHObSafof3+FR9mmY5VBxozBeUc246nIM8jSol21QbYtW+RRMa3
         d+kDP5k/D9LW2BpRh/eGcTOxYCK99GjCR6z7bRDCcD5u3TULqM7fcte9FqAVk2LBgb0D
         Vc5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DLT6T+7ahT3h2bp+/MpRlemcgEcaSpw+T8SFb1iKTRY=;
        b=eGrFgNXzl5PDyoNkU+0ESz1+V2gocddQgHpOu5K/tOy0+ESnpFZ/db13D4mrBOu8TB
         2H/m04P0WFLgOXbLruAYYbDWurOhc6owdm3dOeRaN2T06b6ka/3M0szU4uF9fGlitF6L
         19hxECWW06LiymSLEZT34cJAHtfbKKjjcIt/JLZmut0K0dJwSTE9A+uWFfu24VDExFvU
         /HOfxRF40OoAd/9dt8GaCSYrZlU4m7KWLc6vTVOAc9SPpVhhk3R6fvTyPoNEY8OiwxZf
         wC6mfeBtVMtUXz5vXGJo+Q3CKbdpTMfwZCJ02eKP9gNWtMRGTzYP4H4S1WTxvd1pxuz1
         GAXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ME8G7Ttr;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id b5si198523wri.2.2021.05.14.16.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 16:01:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id s8so646242wrw.10
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 16:01:38 -0700 (PDT)
X-Received: by 2002:a5d:4886:: with SMTP id g6mr49446327wrq.225.1621033297714;
        Fri, 14 May 2021 16:01:37 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:9bfa:6490:ea29:a5dc])
        by smtp.gmail.com with ESMTPSA id h9sm6323784wmb.35.2021.05.14.16.01.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 May 2021 16:01:36 -0700 (PDT)
Date: Sat, 15 May 2021 01:01:31 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
Message-ID: <YJ8BS9fs5qrtQIzg@elver.google.com>
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
 <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
 <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ME8G7Ttr;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
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

On Fri, May 14, 2021 at 11:16PM +0200, Arnd Bergmann wrote:
> On Fri, May 14, 2021 at 10:18 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Fri, May 14, 2021 at 01:11:05PM -0700, Nathan Chancellor wrote:
> 
> > > You can see my response to Marco here:
> > >
> > > https://lore.kernel.org/r/ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org/
> > >
> > > Maybe some improved wording might look like
> > >
> > > clang with CONFIG_LTO_CLANG points out that an initcall function should
> > > return an 'int' due to the changes made to the initcall macros in commit
> > > 3578ad11f3fb ("init: lto: fix PREL32 relocations"):
> >
> > OK, so the naive reading was correct, thank you!
> >
> > > ...
> > >
> > > Arnd, do you have any objections?
> >
> > In the meantime, here is what I have.  Please let me know of any needed
> > updates.
> >
> 
> Looks good to me, thanks for the improvements!

FWIW, this prompted me to see if I can convince the compiler to complain
in all configs. The below is what I came up with and will send once the
fix here has landed. Need to check a few other config+arch combinations
(allyesconfig with gcc on x86_64 is good).

Thanks,
-- Marco

------ >8 ------

From 96c1c4e9902e96485268909d5ea8f91b9595e187 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Fri, 14 May 2021 21:08:50 +0200
Subject: [PATCH] init: verify that function is initcall_t at compile-time

In the spirit of making it hard to misuse an interface, add a
compile-time assertion in the CONFIG_HAVE_ARCH_PREL32_RELOCATIONS case
to verify the initcall function matches initcall_t, because the inline
asm bypasses any type-checking the compiler would otherwise do. This
will help developers catch incorrect API use in all configurations.

A recent example of this is:
https://lkml.kernel.org/r/20210514140015.2944744-1-arnd@kernel.org

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Joe Perches <joe@perches.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Miguel Ojeda <ojeda@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>
---
 include/linux/init.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/init.h b/include/linux/init.h
index 045ad1650ed1..d82b4b2e1d25 100644
--- a/include/linux/init.h
+++ b/include/linux/init.h
@@ -242,7 +242,8 @@ extern bool initcall_debug;
 	asm(".section	\"" __sec "\", \"a\"		\n"	\
 	    __stringify(__name) ":			\n"	\
 	    ".long	" __stringify(__stub) " - .	\n"	\
-	    ".previous					\n");
+	    ".previous					\n");	\
+	static_assert(__same_type(initcall_t, &fn));
 #else
 #define ____define_initcall(fn, __unused, __name, __sec)	\
 	static initcall_t __name __used 			\
-- 
2.31.1.751.gd2f1c929bd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YJ8BS9fs5qrtQIzg%40elver.google.com.
