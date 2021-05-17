Return-Path: <kasan-dev+bncBCJZRXGY5YJBBX7JRKCQMGQEHHCIKIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2908E383C2D
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 20:24:32 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id s10-20020a05620a030ab02902e061a1661fsf5352068qkm.12
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 11:24:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621275871; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ayma+tePd9s+qk1B2nLzwo8lfglDSgBr4XhhiKVx/NEOsSPU12DisjwoSdKDpUTA3o
         PoI5MjoZBLZp3r6oBqlN0qSDq/yClQl9p9y3ZqLqFWvh6kw6xrI8RoyXTnbiScCxbuBt
         Tdy0/WgMLMuT6mQFIbZZ2jsOpXKUvfM1C69ZfBCFcV9sFXAjSGRcROPJ49xM8oojAb44
         qkUIfleleCvouWzkByP6q4PqGK/M0dGG6Licbh7ESPh3L6KYU8AeKxxKHQRXu8KynkYR
         ns+ghf6DOzIefGXIX1DX45Oppwd0Ay2bgaClrDh40v5dnS5EIt9LRzHMSEE0Tp7FomI2
         mzqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=xB6+3NmFjiwXaH/kJ7KyaUUjhBgXlRQPvX/l6bOxbH8=;
        b=U7N4euMj64Aqnyby9xnW8TMFVaQgW9z2Qm7AQ6UbfePO3xpeHusweo0r/AiR65fz6x
         utTGCJ3bPgEhJYleuBWmgI5Zq1jelonUA1RKoR3711mtRXk2Ig6vACTpYr9v7Twu1lot
         IZ/CMLlS0usdpBmnIWXk/iZ+rM5bMCtU7NISEiJB5Le+M5qQKUraB5gsal2HClvxCyX4
         fCOOUzwpNhMBm4wvb/69Ts1c5DPKqRY5T+C07oWwZ0nfx0QtSyRkENfmBNNZ3BimsdQ7
         /CuvPNsrmu38PktWttvWFhkUtQv3d2rR7xi7vA+rH4HmX+8Ls1we42Igz/OygUjwXq7d
         6ACw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="WdgR/t2M";
       spf=pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xB6+3NmFjiwXaH/kJ7KyaUUjhBgXlRQPvX/l6bOxbH8=;
        b=siOMTkGcURM8QB7wj1dWdlb0q9XdlurgpFHuANhKh63k8BE2K2TtTXj7r0WNQCScUl
         B+Hutq1p0uKrRGVg+Mezm+ha42XWks+BCFcOK4BGWDKQi8qeL05MfLiTcLaEYIMWLGmH
         AC1qQA3+P27227J6T9GrZTFK2y+xlu1FwmSnHnPI+dH2htTQ2Di85566tsF7JY0ehaaP
         xgP33B6HZhD1t9utMt1GoFMv8LkjRbWio2hHqZ3qQ58Tgwyw5qQh2WDMeooz2J2kLxLl
         7fc68JH9NlBwekZspz3sGntSDX7tkIGynMaYTmV6PfJDoDC6IXx7ds5HShV++hQNF1A6
         IN2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xB6+3NmFjiwXaH/kJ7KyaUUjhBgXlRQPvX/l6bOxbH8=;
        b=EP4LGwlzgOEp80KPFQWTyYK8MFvE8B/TsFpPn8Sraj0C69b0FuFtCTjmR9eOVnXOi4
         yk+V/ibrR5gnteVAg36j1L76bPd+HwUdZL+1D1y8Y9icpIv9DvJ8PzGDU5bhZcx8NQZI
         Ey+8+PR4PJHshZSL16X0pG9SCNHkxPKqIiSgwHlYkDb6I7gS5gOGdL2oAxs3g7BQlmuL
         02EsHiVaQ8ycKGOa/01S0lkGzHZJPSL1vXonMfsu+cv+zVdQAO+Yq11ZQj6vFXxTVzno
         yclc4L2scSa2LkUO+xXMGYxOEfcH1rbUCr4b9VNPZPulkiNbj6Ob7dYeMp2V1NIYRrVZ
         PPew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UQ0oINjyk3YkhjcpdBpQHmZRsjCVKLEQ/8f2XFPATiZZMegdq
	wvhzTzdtQBrJETXg2n3vPD4=
X-Google-Smtp-Source: ABdhPJxVQh0b1NHU571Z9R4ogpkDSQbOTx0wFIl7CElv9hnmfxor1QE71CalcoEPpmKFFgfCZFHOvg==
X-Received: by 2002:a0c:ea2e:: with SMTP id t14mr1030602qvp.40.1621275871189;
        Mon, 17 May 2021 11:24:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:90d:: with SMTP id dj13ls3933663qvb.11.gmail; Mon,
 17 May 2021 11:24:30 -0700 (PDT)
X-Received: by 2002:a05:6214:18d:: with SMTP id q13mr1349759qvr.60.1621275870784;
        Mon, 17 May 2021 11:24:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621275870; cv=none;
        d=google.com; s=arc-20160816;
        b=NydCSQjhjGxJnDm8uBxci3Pne+5mIxTOgajZB/Goij+p+5YUfx44uOjv5wjdS6xhg0
         1ZbJLxvL3XfIV11DB/FCsNe29yOgXcxJ0eYTQtNJ0yF1cmyvJQfQWSGg2O9kC8PmGFjR
         BC1kwNV5KyHD9hSG5esfq0zlqwHlh/0xQWRh8831jphlgPkF3tYCDLcDQPI4worEfmh6
         pbrvthh4mmvAS6rle8iHVmqBsc8ayBew/38tcErkGepFKXcRREpqlwsZHaTSYZlSoSLe
         Bj2dHbBVEtH+ERN7RN9t3SbkKQf2XyH8TBLyTHkJG7GW0qdtSMr2jyOQ5fmyzwz/Ti3O
         w/Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2ChLCmCRjW4N24pxnrG3xchAhED4vI3Qc8c4bn/xBCw=;
        b=P3j15UDsIIM1EWk9eD31jjYajJ0k7hZMQlqNTks/k54MqeR+TluPebxagLATo7r1GM
         DQSo2bcaINeL/oweNUW3Aqy1uc8noRmV053oC+xgj34IsTcUjPshMDuX28jASZxRTdWF
         tGUbL+ZMq0FaPwdfXXt/7RmnE+bjAC5L+EjVDq0G9fz+6nBFBqynNRqNcq+M3dzJJyb1
         MMW/ePrEq9MLDbihqTVXfyfTUjaBz3670JXgYKoeQ5/j+wfRP5MWYvnMKFGqNhP6SaKV
         tflVJmRagp4QhtwmBmwAx5jXqN7HOZw0+f0i62czETaZN9JjJDgcZuT6QskP8NFVW8/h
         u1Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="WdgR/t2M";
       spf=pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x24si608335qkx.3.2021.05.17.11.24.30
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 May 2021 11:24:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A52D761004;
	Mon, 17 May 2021 18:24:29 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 5DF9B5C00C6; Mon, 17 May 2021 11:24:29 -0700 (PDT)
Date: Mon, 17 May 2021 11:24:29 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
Message-ID: <20210517182429.GK4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
 <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
 <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
 <YJ8BS9fs5qrtQIzg@elver.google.com>
 <CANiq72ms+RzVGE7WQ9YC+uWyhQVB9P64abxhOJ20cmcc84_w4A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72ms+RzVGE7WQ9YC+uWyhQVB9P64abxhOJ20cmcc84_w4A@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="WdgR/t2M";       spf=pass
 (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Sat, May 15, 2021 at 04:19:45PM +0200, Miguel Ojeda wrote:
> On Sat, May 15, 2021 at 1:01 AM 'Marco Elver' via Clang Built Linux
> <clang-built-linux@googlegroups.com> wrote:
> >
> > FWIW, this prompted me to see if I can convince the compiler to complain
> > in all configs. The below is what I came up with and will send once the
> > fix here has landed. Need to check a few other config+arch combinations
> > (allyesconfig with gcc on x86_64 is good).
> 
> +1 Works for LLVM=1 too (x86_64, small config).
> 
> Reviewed-by: Miguel Ojeda <ojeda@kernel.org>

I will applyon the next rebase, thank you!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517182429.GK4441%40paulmck-ThinkPad-P17-Gen-1.
