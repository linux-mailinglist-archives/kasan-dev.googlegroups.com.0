Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5UC7WFAMGQELI53HZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 11945425B25
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 20:50:32 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id j26-20020a4a92da000000b002a80a30e964sf4142825ooh.13
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 11:50:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633632631; cv=pass;
        d=google.com; s=arc-20160816;
        b=tr1yfmFJEJOC4e3bJLIE9aDO9BbOO02Ph6Yn7c6yvTvhJLIv132NKr+Qftwbce99PX
         8A1KfZAMXLDx7MAR2fNj/ENJPRLrFbOwiDQ0jlnnf072HKhGyClS+eNrSYUo9aP79qau
         5X4JJebrcc1x4hMJ97ehVUZ5/cLrQj1vJjERbuf3+lzoWp+S9NFWJm0Q9GYjL6wJVdfH
         QMT/dYWcYBIop7QX3UTkE0tGktdT7If+Y90BJ2AkGdQ0K27GrG+VwCjuIPenh/2ysiqD
         vY9pKhMz2f6L9qq/l2oJ0MRX9HtvB6t/xmdQM+cyesSdChHliKsLUueM2ACdbHyTK8Sz
         YSLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=pAzEAtchXUtkS+MvpMCD6YSWGK/kmSJNCn7q93vuGwA=;
        b=Em8gnV1258+yIAX0UDFHEWzhngT1E16QcMd/rZ7AQ71AtlrM/eUU6RskL5IgU3bAfX
         DH+X+Z5U/GL1xReVW0MWe80Uz+VhyzPUSsKy6GxcHdyNKW7iM0S33Bn0OxAzdPsv/7pu
         Uqch7byZ9iRC/mueNVKdHmO0umR7R+Rns4xhRAcBH0dfj0iaD2cFt1hFsM3C2F6BAd3U
         HH/d1nBSPvvBHk00QC9JuNshPfAzlLl34oB+hYTKFuznrpPfqjuZmp9+ZxzLOObpMV0J
         CsqaITHQ+9ZcslTqU//oOQJsCroCN2BaToxeRpeW12BQ8d6TDRhSpa2LEl/SAT/UZwRp
         zFEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RYA3Fk9+;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pAzEAtchXUtkS+MvpMCD6YSWGK/kmSJNCn7q93vuGwA=;
        b=tQiXqf7rpDw3Dcd6JHk1TmbfGOROHEpLAmIhlyLB4iWoE9KNn+qD90OzQaf+g3UM8y
         Hx6M1/3w692mRsyMTSTIBdNdgFbr8o0CAxx5oHcK22OTz2rLELgIPtPh6hLjMH9mjXyH
         tE6hOlAs+2yPScVSM2F9mtj37i0ItF1TcHlMO1Uhzv64dSVsIGOqfyk1+buGDaONQr5w
         lxQHQbrD5YQyNii/+Zhs0qjx1oyS0xmrsPyeGGg5QWGQWdXaloiaxRDnMX5rvQFMZ2Bv
         t7Mw4hvRv4WW5PC/9Hb1tTQWoAD0z4clX96EXtQpWiWoY6Ygrx1pJqQ2fvb7iCn3CEpk
         Jnqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pAzEAtchXUtkS+MvpMCD6YSWGK/kmSJNCn7q93vuGwA=;
        b=WeUBnTSJVsGBN/cgGpb9OoE/G1CFzUK8udz7ygIuMZ6j1bD28Q9wVcFV5omBTnhldg
         3gKnpM7eSWBlmiPh0qDB+WWF3cQbIvg9b8E/yegFYZwBdKAclxx/pUQxnXXG3myljRe4
         EZvjqI+xaNo9D+Hn7wkW0uHr5tc0sKYLIY3etlJeWg15G7bE8lSOBx9rFCxTxUOSy+6j
         u3te+UKajF0OY7skOuKM/ao/CYaq9qfUI0JPpa9hv0ESdwgJ4w0OOpVT6HhFtow4Vyh0
         RNWVv1hO8nvYoA4SaTMZDbmXj2m6H8yTcf+iH2ZS+EhKeTgbVstQjo5NB5bNAG5mw2qq
         Itkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iCSMinE2K7cMu7F5z6pYmkcE7QmtlCC1OSRHVVs/utOx9rVCV
	naTr9ycoO0yBWxWElgJf9Oc=
X-Google-Smtp-Source: ABdhPJwxPQ38xy4K49a0lwiVOlHtCj9qPhzqIhfaj51MuwrlUpKVYTjXQ1EvrrnDzmjAQyhIktSa4A==
X-Received: by 2002:a05:6808:178b:: with SMTP id bg11mr4715493oib.160.1633632630970;
        Thu, 07 Oct 2021 11:50:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2f5:: with SMTP id r21ls278959ote.3.gmail; Thu, 07
 Oct 2021 11:50:30 -0700 (PDT)
X-Received: by 2002:a05:6830:44ab:: with SMTP id r43mr5082658otv.371.1633632630605;
        Thu, 07 Oct 2021 11:50:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633632630; cv=none;
        d=google.com; s=arc-20160816;
        b=swpkHXMIlNIxhInS5mFMzhg6Qzv6UaHxltdZoot1mFm6BPzoWXKxhv08Adw2IG9scg
         OYCWNBwyixP78s1HKi9vjrmzfIWYwAr6HstxDyx9iPQmC4oNcCycZv8DAJBCWGQ3+7vx
         1j943G6810rcYSeg+DfY12efD1BTsU9TXhUcl9mOG+qTbNZwhGSRPyGd9MGNP4RIjbZK
         xpeWhPvAbS8tV2FOlSNN5DVokJlc9iEa1BkqJTKmCHPfVapLugQAJSth4dOT5TLxCk8a
         fIUFWSTUjxyLukZsKkQt2xs15lXfiHxBVT/HgLcWDgYhzHsujK28fJfaZ/bSKekctFb0
         XGQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZsKp+EACnKz5MP1X0YE8UeP2eDSZ6e2aoiWOHKjSE0I=;
        b=tqEqLXcdZ3kcnVvu6cNQ9aEP7FEMX/xwMRq8F0JNUpbMRvqsvf9zKzEARtiHPOBu7c
         xWfrfEoKsD5w2FIn3V2dsZFpy+OJ5E5r1hIaQ9ZhdKdYAv1+uO/QwOCwV8r+MfsbDnPn
         R+qlHmz33heE9TgcXy4dp92P3Go487xilZblGS0ULgCtGpUOn3bFhVegtR+esgc7707t
         ceESnxjZ7g0yeK7u/eVPGdbE9fbSNO9KJGjB6Ixq9PC5fe96ADd4wiS/8CgHr9DTiVx+
         UXRxqsEuPgP5qit7MezbLBQMwNrDUgH/vpFD5pi9unNbK9QO3wVu43neCj5yGOhwgbxE
         fulQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RYA3Fk9+;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bi42si56632oib.4.2021.10.07.11.50.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 11:50:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F402C60F11;
	Thu,  7 Oct 2021 18:50:29 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id C62A55C0870; Thu,  7 Oct 2021 11:50:29 -0700 (PDT)
Date: Thu, 7 Oct 2021 11:50:29 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RYA3Fk9+;       spf=pass
 (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Oct 07, 2021 at 07:44:01PM +0200, Miguel Ojeda wrote:
> On Thu, Oct 7, 2021 at 5:47 PM Marco Elver <elver@google.com> wrote:
> >
> > So if rustc lowers core::ptr::{read,write}_volatile() to volatile in
> > LLVM IR (which I assume it does)
> 
> Yeah, it should, e.g. https://godbolt.org/z/hsnozhvc4

I have updated https://paulmck.livejournal.com/64970.html accordingly
(and hopefully correctly), so thank you both!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007185029.GK880162%40paulmck-ThinkPad-P17-Gen-1.
