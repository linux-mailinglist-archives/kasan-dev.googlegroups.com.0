Return-Path: <kasan-dev+bncBDRZHGH43YJRBS6DQKFQMGQESWRX3IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F798427196
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 21:53:49 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id u2-20020a17090add4200b001a04c270354sf3285970pjv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 12:53:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633722827; cv=pass;
        d=google.com; s=arc-20160816;
        b=x028sd59B0AaaYeTiRMg/MGcqFTnYY1LlL/Ud8i+gk1wceCW7QGFzlu7LVggbf2OJz
         PdX+Aoi/hKc4aHAx/VyTDz8dE/MzdfspgW0xwx1cf7C2KaTPeDAbaN2DGiPl6q/VUtoe
         RzE5QBRDBqiUZpB2PFnJPKRnugXB2Dhmmd9UAYTbhrqK5pmqFGCf64dO59rHuwqk6seM
         mYrBE8TiCIhyyo8jWZApTa2bsMxHKC367jxgZ607JmwvsBlod+UJe8Y3hLR1q7bodm+l
         RV9I5iru8b6AjIZpMsvdvmoFAyo2hrIFhBGqty0M3yYijaOKS9a90ykQ43VPn5Gbq8fU
         x9/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tbrrCUXTGBkxxZ5ywKjGixLpVRlbb1/BEmRfmdtHNmU=;
        b=RTEuTexCabMfcBWacyD+PfsYMA0WAhWT3LgfmSyeQJM5XvVHaYnKUd2t316Rr03qtn
         +CDQzMV2Lms7acj2VXC8uYmiwIkEweK6WUexwp2BnFkjAeSldhq5+mWmq97T36IWZ+rq
         92XElpSk8S99kpmRIcIbSi/sRzOT/BGZGPDWtJHfFRVFI2oI3nJRS7174MDWfxgjg3to
         WSVtO4OOelzLfZYWJ4YDQ7Z1LgRQ9kbuyaM9LPg/XqPnGay3229BcczgcJo+CAl4Df4r
         CINMG2w5N6j28MX6F0d950F+Z09eqtD2/WQ4UBaMpiZ+fhxfQDFOTiAGjohHJmPT+vWU
         Dt2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q0cZY5sB;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbrrCUXTGBkxxZ5ywKjGixLpVRlbb1/BEmRfmdtHNmU=;
        b=TW6WnuczrT6NncgdK6qj/KU1NBzpBUEclESCj7Ql04hBg1J/khmNW1rX7aPPq6VhZY
         liD1/OUy2IQcpowA8rcWK0YwlaYH4agjzGXtLCO/90b1gptYoQDKAo5RO68gd/0I+h/3
         zk4XY5pGj22X12oXjJmrcpS/hu6LHCvR3zaKMRkg6eUmojkgr/4plFGdnB0B+dXPDNeu
         9BXFF2aRaMHFHGjqDxY2ktwySlmCSyMN6a/3hPK5Ygnp4uOCdOXevuRlxHy7voMTio7u
         eJ1wtieODjC7314knmVh+QLDQWDO/IQScGwaqNMeGQad1/zt01QFGZsrrfD68n4Uh1ze
         do0Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbrrCUXTGBkxxZ5ywKjGixLpVRlbb1/BEmRfmdtHNmU=;
        b=DKSevha2JQu2Z5C16VLprKYRHFy/Kn5zkWDyHvOw2cGx9gA4NE+x7O5EpmcQC8SuR8
         qohmP39QZ5WKgfIh5Tsqki5SZ63JYfBsJy51FH4/WkpmIfvoD191RReVbWzEA1S5EUSL
         Ex345l2n/Gsr6JeORFJfmHl+npcmBA2xGCZsSyrhdUm3AWW6xvrl0R75zShGmBiiMtzQ
         5TxDKc0b9Or50BUkkay5oWR6tphytzHJPU0cgWXKQgbGl1AKRedirG19DomMLxprG+q6
         tUL/ODRnQCPVFi8H3n+EwHZsDCiLU9cm9IAfjwLGMLIUakZOA2+BTldPcB5tB27I6K39
         dT4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbrrCUXTGBkxxZ5ywKjGixLpVRlbb1/BEmRfmdtHNmU=;
        b=O3MHKRiscJ3sMYDN/EPryYzNY28sjrg+ZV+eMWls5nr+32Dm+ZMaIPCJ5rv3QA11Rl
         85Avq1fcpt4yMTDotpVT86okGAu9Ocb1UM+BOgMNYYCURTcA0WZMS+kYMoYoWCZ/gqpb
         4Tz2HsEdR0Zw0qpMWkVet5VpD64Z30YRT3rukgcN9O2gbpVvfFCSJ+c4JQ2PKXFFkZCC
         sRVU3aZcHaYYaGtvyjMEXG90RhKaamq2z8qedua9bw0CgS49FRMq3MftGSxWzfXckOiP
         Y3bFmMEloNzNiULIYF+cMGZKU4jfkT3K9viIi04Gt0f2sJca0QmJ5RInTGfXzoY9JBPO
         VKnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326gUld3smc4RHWUeJRxBYJthF5QnCS6sWC1WV4LwmdWuzQzd8i
	eo6prbBOqYPz5BiELe7+sVc=
X-Google-Smtp-Source: ABdhPJzVMxBvWdfx5DyZ2cMreWWHHHugvMCO3r+59rYXiTRBol6gjuMA0bx058y9AwVmwnXX0RmwvA==
X-Received: by 2002:a17:902:6947:b0:13e:8e8d:cc34 with SMTP id k7-20020a170902694700b0013e8e8dcc34mr11137483plt.88.1633722827297;
        Fri, 08 Oct 2021 12:53:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:185:: with SMTP id z5ls2282007plg.9.gmail; Fri, 08
 Oct 2021 12:53:46 -0700 (PDT)
X-Received: by 2002:a17:90b:1c02:: with SMTP id oc2mr13899000pjb.128.1633722826163;
        Fri, 08 Oct 2021 12:53:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633722826; cv=none;
        d=google.com; s=arc-20160816;
        b=0XWz34yIEOagkr073TSEMjYWU6QSN5n4dzR4FsZa6/idbhH2e6pCfEbfkhN3T86nzq
         cCydzS/3OkvVa5SQP2kgJyVzAxjl8Vm9MB6N1YRWO4f6vRY+SujWSvgZ/5TBGur+hJNO
         OTNwSVxuNZkMN54L8bAWIuiu09PYyjsvPYYZySakG4oZBC0CHggyJcd1Ee9ehTgEyJv7
         Obx87mGoT7qGvVhV9Dwj+q6gx4d9J4C2P3kdQoou4+CSfMZw4jVgQFqAFykRDL7cPu32
         AB94JPdQIyw7LloA/9JFu5eqs4xUMLvf/Dq8viim0oYCtapAAEkLw3iMrE5RrYqRipEL
         BADQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OBX9dZSpmQcEMkNsFs72/snKGvpakQB3FBMD+xsLJgs=;
        b=XFtKfg3iRon1tY9MDUuX1u19SbildrlOmvWToMsHrAIQ3RTylDTRvkI6gAQfqdhy2r
         YViA2dBwOTAeIzSYyMCj9dYWhxKmhd94uCkyh7+Q2EwVYSs+WFv/UbNT1RqhPuc+TNcs
         k1gWMo0PlYPTQdsWKRhFFtP+hxdnnwzQLDijHHV4HhzZKqbE2CD0gnRTVK2duteqcaIq
         jau5q4noFqKJI+Z015JdgUII/BiU/BlUdMUQErQcjOC3gF37axMnTumKdPGRcin/XSI/
         zzdeATn71yWIbsICNhcAY/LYa3EqyYwYjvR07+IYBuUObcElLkWCesAaZSovqMexyaFS
         TEuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q0cZY5sB;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id j12si6695pgk.2.2021.10.08.12.53.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Oct 2021 12:53:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id q205so11951429iod.8
        for <kasan-dev@googlegroups.com>; Fri, 08 Oct 2021 12:53:46 -0700 (PDT)
X-Received: by 2002:a05:6638:297:: with SMTP id c23mr9231975jaq.131.1633722825542;
 Fri, 08 Oct 2021 12:53:45 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux> <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1> <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1> <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 8 Oct 2021 21:53:34 +0200
Message-ID: <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Q0cZY5sB;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Oct 8, 2021 at 1:42 AM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> OK, I now have this:
>
>         Both the unsafe Rust code and the C code can interfere with Rust
>         non-unsafe code, and furthermore safe code can violate unsafe
>         code's assumptions as long as it is in the same module. However,
>         please note that a Rust module is a syntactic construct vaguely
>         resembling a C++ namespace, and has nothing to do with a kernel
>         module or a translation unit.
>
> Is that better?

For someone new to Rust, I think the paragraph may be hard to make
sense of, and there are several ways to read it.

For instance, safe code "can" violate unsafe code's assumptions in the
same module, but then it just means the module is buggy/unsound.

But if we are talking about buggy/unsound modules, then even safe code
outside the module may be able to violate the module's assumptions
too.

Instead, it is easier to talk about what Rust aims to guarantee: that
if libraries containing unsafe code are sound, then outside safe code
cannot subvert them to introduce UB.

Thus it is a conditional promise. But it is a powerful one. The point
is not that libraries may be subverted if there is a bug in them, but
that they cannot be subverted if they are correct.

As an example, take `std::vector` from C++. Correct usage of
`std::vector` will not trigger UB (as long as `std::vector` is
non-buggy). Rust aims to guarantee something extra: that even
*incorrect* safe code using `Vec` will not be able to trigger UB (as
long as `Vec` and other abstractions are non-buggy).

As you see, the condition "as long as X is non-buggy" remains. But
that is OK -- it does not mean encapsulation is useless: it still
allows to effectively contain UB.

Put another way, C and C++ APIs are the trivial / reduced case for
what Rust aims to guarantee. For instance, we can think of C++
`std::vector` as a Rust type where every method is marked as `unsafe`.
As such, Rust would be able to provide its guarantee vacuously --
there are no safe APIs to call to begin with.

To be clear, this "incorrect" usage includes maliciously-written safe
code. So it even has some merits as an "extra layer of protection"
against Minnesota-style or "Underhanded C Contest"-style code (at
least regarding vulnerabilities that exploit UB).

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-%2BR7H2ecEw%40mail.gmail.com.
