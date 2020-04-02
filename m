Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB7ETSX2AKGQEG3EEFQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 437F919BA2E
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 04:12:13 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id i18sf747488wrx.17
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 19:12:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585793533; cv=pass;
        d=google.com; s=arc-20160816;
        b=PXye3UdYNIlBRsMlmtIa1vGRiWr/kSWSAsUmY/NsZ4R+gd/jInUAvlqOUSEia9zjMy
         Vian0OCxbbCkqeVMNwHIzfsBv2dWa7d2+aMkapHcYgc2FFuRnW8Nw6XLoHvVz0lGVRPG
         EoZjO6IgTqZxko3Qqtna9wvwBo4RVwaOA2nkg3k2kncyRHfYZ6I1Imt+eRH197Hgm13w
         QVvr8O1oQL4jGnhdYXLAPH4lNWJJBTaG9MLAtHZfp+RErR4cxP0EAFDM+zytJ82fXLRx
         7DgxSBMqLXxuexlWw2M8t4JiPvjgEDZOfTS3547gzwuLCPlTeAgqE0fIjClv11VSEBj3
         3zdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=q+Ahd7k1aLYNygLroVtxGvOTiou3XrqI4Wz6FJCwmqE=;
        b=LxrZ8vXCLBxMxElkEZtiip6NCCILXrPPwQFolktSgDuowLaofrlBRAGjjb/erARbsE
         P20pHdki4fwUEl8nIQxPu78bIU15IbEY2oAOlkBcJd8sDN+jQEwBbQLl9sYhHg55wbU9
         5DU3BOx8aOuidWgb7+EXHA6TAeWrHn2VWBgqSdoRORscHNOgx9c75cIdnnlX/MPSUq5S
         It/e9oC/EWoLdvBBp47NSGrr/CEFjXUMpgNIACG3LiVf1QuZn8r3lHlLBpSH+Q6w+jDS
         Tj+ARTXKm8Grw951sxsM9CHowO37/+wekFnDDwUMzfy11O+4UNWYOZMqVxXZRisQpuhV
         ZXtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="FEz92/cj";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q+Ahd7k1aLYNygLroVtxGvOTiou3XrqI4Wz6FJCwmqE=;
        b=pLTqwj4kspmhIYpsfLkHgoAlOdedgS6Kpq+8K1c3VRG1NLxdlxk+KvzBQ3YV8Y0+ym
         SqrH/2sMp6cncHO/lecU+ko5UuyHZr9xmzPFCB2G/faOwmXa+pJoNxIeAumG9MNWJYKp
         VQvytTcw1DdwUudnyfGkI/MiG2E26nV72LpIGoA7BOCzKKeAzqbAmN7HpGq7TvLEcSlL
         +fHFdbVoydvWn14P3Dm8jhrhjwvYs0gyUDOGsO2dFgTECbaiQJAZiExsutUuw/xJF+an
         IWHexW2ZFye2qkIkh7OsfsuHFBR3K/7C2srPG0/g6/WoYB/bcYJJVyqTb9LPdNVe5zL2
         ViDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q+Ahd7k1aLYNygLroVtxGvOTiou3XrqI4Wz6FJCwmqE=;
        b=Obu16kuFwr+m9bpewenS6vu0ItW6TdNV7/Kl8V2HX8Up4QvI9O2Nu9d4aGxmeRHjzs
         nzuZhBr+Ng/k/mroScS1m4zab0hFQwSMuzlJG6jy/Fd7RhQ3a0CvaFPIRNLPDGfQoz0v
         1+1nQZMwiUxzGXg2diuKDPdWdNV91vtotlbYs1uh8HIB26a6I2xNCIY3F8bF1bEWd5Cu
         n1lyWbo56GRMIVH5OpmdERa7MgqvMj7Cjcf5WpimOxz76IEwmjHbuDTTqJOZxn22pbRj
         FH05fH/B8eSNAnVXejP07/7L6AcYHozPFxmQaUQwgsDNRg8s+DHJYvl1i2sB2LZ2BDH2
         A0qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZhEjRrznWEo64w2tRjyzTS2WYSpMDIFgjt+o7p+dVYem3fvjwF
	B62J90mN0bplqdzsWlnzBas=
X-Google-Smtp-Source: APiQypLA2icA1Jesw7kOuyTdIRqxSgBDZMSdOnot+ydR9M4KFKlCL7xMGcYlnj2KUR8iwDXCHKyx3Q==
X-Received: by 2002:a5d:5141:: with SMTP id u1mr890630wrt.146.1585793533018;
        Wed, 01 Apr 2020 19:12:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e390:: with SMTP id e16ls414911wrm.9.gmail; Wed, 01 Apr
 2020 19:12:12 -0700 (PDT)
X-Received: by 2002:a05:6000:370:: with SMTP id f16mr953337wrf.9.1585793532426;
        Wed, 01 Apr 2020 19:12:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585793532; cv=none;
        d=google.com; s=arc-20160816;
        b=TokfnW3LJ7+P45HXJIpawQAA41DIRF9UEaj30qZOcR3IfqpsFmuMlCfYU6TY0xqE5O
         oxnfu03UwLUU4AcjgbY2+YWfaCWUHh/ZUNtbz0ZmMKzIlqSAkfeEYbn1Wo1MI9lWIadU
         0njoqNjY+/WN3z8o9fFR8H8JnvzCSjGB5naKeEHLKPZnaB38aaNIce4XI1DNPpMC+wkJ
         /tqYCQL8aMbwjRNygsjM2jSXp3Q0sfuvx7nxHCvOYYWLTPNsFigqJ1B+Gb2tZRBGl2kZ
         DJnsthjo5fpbRZ/w+AgOaBkw8lVMHquY3LijjX2KkbZgexjOd6cBQFjAC7gRzME8z58W
         7KuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xQMUHcx5ZJebHuFeNsiV5oTqPrmJdOW/j745+2PrxT0=;
        b=DedhKGLMox/jnIsL8CIrN6n0xnllh1EZZYE3r6iDXkjZLrh6bVV1b71Cb+68ghnCJf
         4HSt00KSqaBFMqUymtkYt3V6/Y7cRdAw4J78EPHXJq+g5rfKPETNDileXhHkFpPzdR1a
         sTWEhFkZoaBpqz9hJaUk/hVJR2ho7KpWtrdNpIV4f4RvIKfa98qUhQoZ8iqGx2vxMPkk
         6HIANNv6Rs7OzODYbrCr1JA2bIFySOXjDLQoV9eKgnHuyNTSafVzIEM9muusY+lFyESV
         gCaMIQn0dchYMPESOLT0NPvXLEtXPceW7AQ0owJlv4Ywvf7pTwVFUbI8gnDE643vf1OV
         i3BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="FEz92/cj";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id x204si366935wmb.3.2020.04.01.19.12.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 19:12:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id bd14so2251079edb.10
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 19:12:12 -0700 (PDT)
X-Received: by 2002:a50:b062:: with SMTP id i89mr784837edd.72.1585793531687;
        Wed, 01 Apr 2020 19:12:11 -0700 (PDT)
Received: from mail-ed1-f52.google.com (mail-ed1-f52.google.com. [209.85.208.52])
        by smtp.gmail.com with ESMTPSA id u61sm706029edc.13.2020.04.01.19.12.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 19:12:11 -0700 (PDT)
Received: by mail-ed1-f52.google.com with SMTP id de14so2300575edb.4
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 19:12:11 -0700 (PDT)
X-Received: by 2002:a19:7f96:: with SMTP id a144mr643180lfd.31.1585793175190;
 Wed, 01 Apr 2020 19:06:15 -0700 (PDT)
MIME-Version: 1.0
References: <20200324215049.GA3710@pi3.com.pl> <202003291528.730A329@keescook>
 <87zhbvlyq7.fsf_-_@x220.int.ebiederm.org> <CAG48ez3nYr7dj340Rk5-QbzhsFq0JTKPf2MvVJ1-oi1Zug1ftQ@mail.gmail.com>
 <CAHk-=wjz0LEi68oGJSQzZ--3JTFF+dX2yDaXDRKUpYxtBB=Zfw@mail.gmail.com>
 <CAHk-=wgM3qZeChs_1yFt8p8ye1pOaM_cX57BZ_0+qdEPcAiaCQ@mail.gmail.com> <CAG48ez1f82re_V=DzQuRHpy7wOWs1iixrah4GYYxngF1v-moZw@mail.gmail.com>
In-Reply-To: <CAG48ez1f82re_V=DzQuRHpy7wOWs1iixrah4GYYxngF1v-moZw@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Wed, 1 Apr 2020 19:05:59 -0700
X-Gmail-Original-Message-ID: <CAHk-=whks0iE1f=Ka0_vo2PYg774P7FA8Y30YrOdUBGRH-ch9A@mail.gmail.com>
Message-ID: <CAHk-=whks0iE1f=Ka0_vo2PYg774P7FA8Y30YrOdUBGRH-ch9A@mail.gmail.com>
Subject: Re: [PATCH] signal: Extend exec_id to 64bits
To: Jann Horn <jannh@google.com>
Cc: "Eric W. Biederman" <ebiederm@xmission.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Andrea Parri <parri.andrea@gmail.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Nicholas Piggin <npiggin@gmail.com>, David Howells <dhowells@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Luc Maranget <luc.maranget@inria.fr>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Akira Yokosawa <akiyks@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Adam Zabrocki <pi3@pi3.com.pl>, 
	kernel list <linux-kernel@vger.kernel.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, Oleg Nesterov <oleg@redhat.com>, 
	Andy Lutomirski <luto@amacapital.net>, Bernd Edlinger <bernd.edlinger@hotmail.de>, 
	Kees Cook <keescook@chromium.org>, Andrew Morton <akpm@linux-foundation.org>, 
	stable <stable@vger.kernel.org>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b="FEz92/cj";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Wed, Apr 1, 2020 at 6:36 PM Jann Horn <jannh@google.com> wrote:
>
> Since the read is already protected by the tasklist_lock, an
> alternative might be to let the execve path also take that lock to
> protect the sequence number update,

No.

tasklist_lock is aboue the hottest lock there is in all of the kernel.

We're not doing stupid things for theoretical issues.

Stop this crazy argument.

A comment - sure. 64-bit atomics or very expensive locks? Not a chance.

                   Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwhks0iE1f%3DKa0_vo2PYg774P7FA8Y30YrOdUBGRH-ch9A%40mail.gmail.com.
