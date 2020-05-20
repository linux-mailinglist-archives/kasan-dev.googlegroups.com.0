Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBE6CSL3AKGQEVX44ZIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 084531DA87D
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:16:36 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id u24sf758092ejg.9
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 20:16:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589944595; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kk+6g2Sk8WwLtQ7TR4o7tH2I5Z/NzmfHDm/0ZDzCe1TyICO8JVX3C8vfKyTrn3iqc2
         H5mA+bqsaLbYQGpUeLv2wOxBCBkc8HPlQ4nclXw+oIFciH8qbREIG0i7czNnTOwaTyHA
         v9i3FpGua7h/IQ6JFHEAK7lJsNnYVnOUbFZwnymr9j7SbnEhZ+8ciCJVQbBtvBzZDBCl
         nOfmKRPn4Ezdx4VBUQLyxWgeBVT3L4YLseEXQ7cJ2sAjooTU1R4RZcr9F5Kb5J4BV0ZQ
         H8Zmr8DDSreU+xhFSspz6JHlSC9kF1HruoEGn2AksCe9UY8ULnJ7dLaOnSm89asSvS0Y
         6tTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=rurKIvTcqwCxJssiOSYEBLGYKBrg6YYALl6xop3Inek=;
        b=wEMHQddcqyFPy740N/cupDO6L3nrJboBeMxHx2pmx8T53qDW1xuY4bl7FwqjFZ0Wkj
         mKpRiBGRDom0YOfVCfJijO3HOtiB66Kc+IDvqi7LC07n1x3mSX5jBlduv1ngNRDklESf
         4++BcH+brePDeVon6sPZ02yw3L4Lgx1ik/HhjJeTVQwOpDb6UQcZ3q3VGMkWxIL/Ev2q
         xxqB1LDTAd0QHNhpBWRCCzvvhPzhmM9QsZorVj+FmrU6Dts0ZvVGzuMy7xDNwM77Y7fA
         GGf2EH6cs1684o1exznJz+F4/ijxRwQhYLkO5FiBe193CW//FK4AroKc/vcv4ZWF78L1
         Y0jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=g05ihPzT;
       spf=pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rurKIvTcqwCxJssiOSYEBLGYKBrg6YYALl6xop3Inek=;
        b=EExRHJ4KIlD6zVIPug9QJcIjdQwEuwAuEfzeUHFJkR9nXfKlOzScaGiE75Jcm6NNTs
         IYK2ZdiBDP8ighiCmlkCCH1nmfou3n8CTNVVvLCjkr9tEQtS1Bz7dVuNGdVoKAFokrBW
         yAd2FkJKh5vZhC+POuQdtb1s3JoIoIdQUPGNe5OJgQRRuKND2c/S/EW0begg5uYIEhMr
         djFePPDKxDgMpij0q51F15sc82OEhEYx/uYqeXlwK7ZCOfph7dHt1lTN1eTaMkjE1UIZ
         uEXi7Rcj8T4VLbUy5D6vkBKTTqWHgrJJzr/FxyDTamUS9bCqlyLFDCduJ/2j2VV2XlFF
         Pm0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rurKIvTcqwCxJssiOSYEBLGYKBrg6YYALl6xop3Inek=;
        b=lExC0e5VCZVcF6NnofjTa2eqjV90eu4AnWNs+3V9mX/luWwUNSUW64SXEHhn537Ktc
         YyhNECryVPkt4Mx80IEYgRlEir/t2YUmi8XkFlbV24aVnW+gGdP+AC5arINzYS2wi/QM
         QzCrl+jcppcFPrZ85foLxGeO+3bqoD9wpev23kztoA3CWres2iuDD9K4iDPKps6h2jte
         CjziT3Snf16lU3BjaHkY/VzinGz1wzTk4qQcof7uzoHGqJI4qrI8/8e6OkccbhhNOzb3
         yC+KasNdUM8LDW7Avp88GuNi0be0anYXvlf0Sbfx3in/rrkIpYOlYNkkp/ezDcXiAb82
         cSag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QiUEzgRqAMbox4xMgMLcMgr2QrdOvpowLSS+K/sQ1ieqPVnJw
	P8ol3gT+LGDtSA92DQ6XT+4=
X-Google-Smtp-Source: ABdhPJzGni5Of6S9Or4F+Kc39HltRvYupFB8UIW3+PEP8E57VDLI2GFME5lBzTsyBzgbQtUCQRi6zA==
X-Received: by 2002:a05:6402:4c6:: with SMTP id n6mr1456552edw.264.1589944595807;
        Tue, 19 May 2020 20:16:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a413:: with SMTP id l19ls725756ejz.9.gmail; Tue, 19
 May 2020 20:16:35 -0700 (PDT)
X-Received: by 2002:a17:906:4088:: with SMTP id u8mr2212106ejj.500.1589944595348;
        Tue, 19 May 2020 20:16:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589944595; cv=none;
        d=google.com; s=arc-20160816;
        b=xtXZhG6BOLYGZXI1rVe67VpVUxQJmS8pBvxIv0ahfp6xC9eWHCU26DHXNtT6SP9Z8c
         tkfiT0hQZnWZ0VkoN05nHekE08lHzdp4e6l1bh1e/Po9dvbiCruJFWsxUkTHGUoj3V28
         hfoObpQB7N0T7hdT9hhuguLBe9SKnG1evHIgPwL95fWxZVoDCrwHf+y47JgBVi/qLHcI
         Bi7l26Ulb+SBxPfp1d8WEjYTgD8KBmIdTFdG+MP8mNJvbaZjbw+jUyS2II44JLCR5+L4
         jnYUW2ZJhTYnVLmyVV10o3qJ/KlODAYBYj0ZMvf5wt/gaC+2ld/vcqTIOlL/6Liy8NO/
         ivAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dsjqUKLAoPyWanOv8aTbF0H7d0vvqgBqr3qnWwKSiI0=;
        b=VUA0svVaNl+ygk96COH2W+9o7qO6ShbECWn97rkfbGE7xIkwEQ4J2FGipJRZOWr7Kz
         pQIxFCeHerAjpeBDdbwDyS8TRnDMzvPzOVsXuh0xSAEsxtd/RD9IGytRprSzFC4UUxrY
         8UevXAdw1x/lMcMmWE8pvqxUm9i0gANaxwIwwC47Rsa7nAMhnKnuRVJMd65PEgFrklfG
         gsZyIp72bXS90BaqnpNSMcckMLjR3Rob6aheWRxMEfg0/at6ZyHa1Y1JitpNSIfQGlhO
         3+L7JQ0rjQ8tF8ihbtUTFW/yxtPLdkq8yVdXWHa991a2qDP5Zdcqd502ji9laOpB6p8m
         Lxew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=g05ihPzT;
       spf=pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id bu18si55123edb.2.2020.05.19.20.16.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 20:16:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id g9so1192391edw.10
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 20:16:35 -0700 (PDT)
X-Received: by 2002:aa7:cc84:: with SMTP id p4mr1427232edt.157.1589944595021;
 Tue, 19 May 2020 20:16:35 -0700 (PDT)
MIME-Version: 1.0
References: <87y2pn60ob.fsf@nanos.tec.linutronix.de> <360AFD09-27EC-4133-A5E3-149B8C0C4232@lca.pw>
 <20200520024736.GA854786@ubuntu-s3-xlarge-x86>
In-Reply-To: <20200520024736.GA854786@ubuntu-s3-xlarge-x86>
From: Qian Cai <cai@lca.pw>
Date: Tue, 19 May 2020 23:16:24 -0400
Message-ID: <CAG=TAF4M5s1kQ98ys_YCgRS9WqjV_9KEbPCFiS71MA_QK8epdA@mail.gmail.com>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>, "Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=g05ihPzT;       spf=pass
 (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::544 as
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

On Tue, May 19, 2020 at 10:47 PM Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> On Tue, May 19, 2020 at 10:28:41PM -0400, Qian Cai wrote:
> >
> >
> > > On May 19, 2020, at 6:05 PM, Thomas Gleixner <tglx@linutronix.de> wro=
te:
> > >
> > > Yes, it's unfortunate, but we have to stop making major concessions j=
ust
> > > because tools are not up to the task.
> > >
> > > We've done that way too much in the past and this particular problem
> > > clearly demonstrates that there are limits.
> > >
> > > Making brand new technology depend on sane tools is not asked too
> > > much. And yes, it's inconvenient, but all of us have to build tools
> > > every now and then to get our job done. It's not the end of the world=
.
> > >
> > > Building clang is trivial enough and pointing the make to the right
> > > compiler is not rocket science either.
> >
> > Yes, it all make sense from that angle. On the other hand, I want to be=
 focus on kernel rather than compilers by using a stable and rocket-solid v=
ersion. Not mentioned the time lost by compiling and properly manage my own=
 toolchain in an automated environment, using such new version of compilers=
 means that I have to inevitably deal with compiler bugs occasionally. Anyw=
ay, it is just some other more bugs I have to deal with, and I don=E2=80=99=
t have a better solution to offer right now.
>
> Hi Qian,
>
> Shameless plug but I have made a Python script to efficiently configure
> then build clang specifically for building the kernel (turn off a lot of
> different things that the kernel does not need).
>
> https://github.com/ClangBuiltLinux/tc-build
>
> I added an option '--use-good-revision', which uses an older master
> version (basically somewhere between clang-10 and current master) that
> has been qualified against the kernel. I currently update it every
> Linux release but I am probably going to start doing it every month as
> I have written a pretty decent framework to ensure that nothing is
> breaking on either the LLVM or kernel side.
>
> $ ./build-llvm.py --use-good-revision
>
> should be all you need to get off the ground and running if you wanted
> to give it a shot. The script is completely self contained by default so
> it won't mess with the rest of your system. Additionally, leaving off
> '--use-good-revision' will just use the master branch, which can
> definitely be broken but not as often as you would think (although I
> totally understand wanting to focus on kernel regressions only).

Great, thanks. I'll try it in a bit.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG%3DTAF4M5s1kQ98ys_YCgRS9WqjV_9KEbPCFiS71MA_QK8epdA%40mail.gmai=
l.com.
