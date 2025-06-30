Return-Path: <kasan-dev+bncBDBK55H2UQKRBMMMRHBQMGQE62AVGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C5E77AED6BA
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 10:09:34 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-32b71af3b28sf6760651fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 01:09:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751270962; cv=pass;
        d=google.com; s=arc-20240605;
        b=VUmTMI25F9U1JIIwN3XUdvmpJ5xqDIwX+vUvSUl703709T9T7PZhHFDiRWoMZyj8Nw
         Aozetupk98EqdN0kA7Jgy9zHfNPy3XgmlIoF3gvh4RFr1v7dFanQB7xn+w7jNPCzYQTj
         COgZryW2W8Tuu5NOPLB5/2CpQGpciez0C6APd34vRT+k1hCUOphbhZ7y97dn3+aEv9GB
         D3lhe8roryJ5Sbs9PsgIsPKI2nLM6/ubzYOKl7n0DFNpW4YcOkCA9I+nRQuxEFce35Rl
         as5h4+zxS+p44IFQZEAHhqkMYB8gDges9Ca+PBs+zf0I0ayRYLHeb0OlqLdzCcq7fd43
         0lDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XTMTfq25l1ve2k1EdwRAQ0wyELzlgpCpfUdNivK81RY=;
        fh=Cls8OJRZFszk7TssWCKSvGTlHFz+GylRkQXAKYIOyeg=;
        b=U6uakkZ5cs1htO23gjgjjbva7N9y9aKwB7etaJCvGCHGtZT4kPKZ0ROvxyov356g0a
         lnudlD0yTf1fS49u0mYukkzO0f5lrXjPQnf/pvorE+De9RI0H61eTZxWaLoHOgHzklVg
         gwhxX14HblfPStSnGWr+f9osGW8ZEDiutG8jvH5CRo9hMbawzj26801cq6OeC5WkGecR
         HxeZDvzPuNTZ3NOCXxMH7yD3erxe4CfoCACnFM4/EhYB/hOmHeTLQXAkzv7lEeQwwacR
         gm78zwdlqKLIer01CRM8n1OVjRU2k6WybdKxv4SsgCpWO5XDQGXn7Grz5RNhFTzpTIWC
         14Ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="ANc6vgl/";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751270962; x=1751875762; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XTMTfq25l1ve2k1EdwRAQ0wyELzlgpCpfUdNivK81RY=;
        b=c3C6yKKYc14Tq5LexKdhswFLvuXMI2UXjsgAhQncRMGzpGkh9gDNxD+HDS2JtloEza
         9AeiTlw4AtpTL2D/3eizT1PS8LREUU3GhwBpeL9aziagT6o2JtiZrGBEwKIfX1heITM2
         6YRJcB3SHh0mjcxeipK0HFkqqurrappMIcyQCJQ714RpjgRm0WXNWhxyYdF1l5hhWrkj
         dZ3EZ/Zs+uMOdz1v1OUTbiW93KzWIyPwEIQ+sfUGlf/Sj0dMUQ5aktxz8aNZzSa1ULsf
         fXW6ZGUeYd5pt4/MdRpKepC/3KTuJYe7cRGh56VnJ/2u278QRjceYEnd1d9qSjFBLjhl
         HtFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751270962; x=1751875762;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XTMTfq25l1ve2k1EdwRAQ0wyELzlgpCpfUdNivK81RY=;
        b=TNCKjJqJXXfDZb4w+qhWq0ge4khuaJZrOS+rEcD5kFR9JNfp4b78IfmGVB0vU+Ggpj
         WKCQITBuZaiHuLHI51cokYUxH8eak6Y5XVzjbH6orjrM5nHHMZMO5TWNSRdHOa0T3MTa
         jWC0s4hem3dfqZUjMzk7VMW/O0BGpSTrg0WwFfpV+mgt9XA218dpQewC7dZydBvYCp5T
         14WvP6/+ADr4BwVpfmPZDtXF7uG6zdaythAITYpjp3r6ZwZt8TcsUpIFHkKhWQKuyVWT
         fIF7rypJboY5pASEqsNVycb7aoUHRivZ9ReHGxjotOME2B+wjufe2RdeZWDXyWJGql/k
         BhEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdl+rjFrrjwq4nn12/60/UOLPtMYtI9bCWiYoNrLyLteNqPrSVF1WQ6tcMD2ltf1dRRnTdmA==@lfdr.de
X-Gm-Message-State: AOJu0YyLaiiduIblyjfL3CJto4kcXNj9wPnYG8596b34+afWkXE63DDW
	uO/4VxcqxP/CSE/KyLrk8Ku+aW7nm+vdp/rBOvHGcFD4SaL6/c8Xf8ua
X-Google-Smtp-Source: AGHT+IH29N8ic5ARU5wH7ji16xHYsulFdAmUIwAixc2440skpkPszCKOqYh0hR5tIY5CCkNSMG/6PA==
X-Received: by 2002:a05:651c:4190:b0:32a:88a3:a98 with SMTP id 38308e7fff4ca-32cdc50f025mr28786931fa.38.1751270962194;
        Mon, 30 Jun 2025 01:09:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdfwehh4IbrVVRA76EGROt8+LBwIfP0IlGgn1CWJ5cGag==
Received: by 2002:a05:651c:382:b0:32a:e3cf:797f with SMTP id
 38308e7fff4ca-32cd03a4516ls8342371fa.1.-pod-prod-07-eu; Mon, 30 Jun 2025
 01:09:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1E4F1U8ESGlt/TejnTlSWz+S/6xKHY2JjUsCDRpOIzwsn/qpoOfkCFPn4qeVUNwNPeSPjW+EvAOY=@googlegroups.com
X-Received: by 2002:a2e:a37c:0:b0:32b:8045:7264 with SMTP id 38308e7fff4ca-32cdc446743mr24036811fa.12.1751270958730;
        Mon, 30 Jun 2025 01:09:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751270958; cv=none;
        d=google.com; s=arc-20240605;
        b=SW1ZdTfwo2avEvqrt9EXS9VeM/kFqAwo/ZjsgCgACwA1Je2p8xCR2AasxcfHq8pj+F
         vuKU4DepBBlessjLfPHjIFLcn7aGN/THgWLY7hQ2K476ySkl5/nifeA3SMk3MYHET1gX
         R1nZa/uq+dYX8rFDpgEv2xtioxLLJ5xyvifNJZ6NxEiYef4zmUNd45KaOXpEhxGho/Ue
         CLTjgLD7jXUleO50fDg1tpTdeXc+EkWI6SvjqybLrub3ZFsKCC2vdEZ5jPvp174wTSBr
         v9mzIMDO9M+NyFKUB3Iw+HWD4/mJ7XEwbQUGMFLofoiezqtoYMxsFyVUSKCKB1GrEoUs
         RcWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=g8duZxkPVS24hjNQcj3gCKwBgUqUfEF5TI3FylCBaP8=;
        fh=6CMZlTCQ6BelOc7tlGNkh1EOpzO7a/YWuZrugaOOFKA=;
        b=DiU+G3MNoSBZHzeEw3RV3Q6P/WpLlqCW14OCXS/spKdMB/p3QLiMnvwtR0RukOzjRf
         CuDWn4O1zaZNwPxkDYzmxVqnVyV59PqSoT2RqtqpG+Zt35YdCQB5nUVFa7BzKfRih400
         2JbIzTnPn9uNNFOlQ3ggFCkH5mIbYqXQtIIcMKTggckT5CN1piBE4b+BBZaKhFkJaiuv
         UYVu0G8eJDbqdpwxMjkB7xd0rtPASvv3+5lsu1yPgylfGEUc2kCfYyezFoXnuhudp7Lz
         kecTbdshS4CKX5ECXxZm4VOVobUkV02HlcgmRwvOsxs0+w4vaerBMzQRqa1GXn11831Q
         L9LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="ANc6vgl/";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2ead65csi4118611fa.5.2025.06.30.01.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jun 2025 01:09:18 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uW9Zg-00000003GM5-0OvX;
	Mon, 30 Jun 2025 08:09:12 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id F25AB300125; Mon, 30 Jun 2025 10:09:10 +0200 (CEST)
Date: Mon, 30 Jun 2025 10:09:10 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
	Miguel Ojeda <ojeda@kernel.org>, quic_jiangenj@quicinc.com,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
Message-ID: <20250630080910.GK1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-3-glider@google.com>
 <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
 <CANiq72mEMS+fmR+J2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72mEMS+fmR+J2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7=w@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="ANc6vgl/";
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Sun, Jun 29, 2025 at 09:25:34PM +0200, Miguel Ojeda wrote:

> > I think we can fix this by setting AllowShortFunctionsOnASingleLine:
> > Empty, SplitEmptyFunction: false in .clang-format
> >
> > Miguel, do you think this is a reasonable change?
> 
> I have a few changes in the backlog for clang-format that I hope to
> get to soon -- the usual constraints are that the options are
> supported in all LLVMs we support (there are some options that I have
> to take a look into that weren't available back when we added the
> config),

Since clang format is an entirely optional thing, I don't think we
should care about old versions when inconvenient. Perhaps stick to the
very latest version.

> and to try to match the style of as much as the kernel as
> possible (i.e. since different files in the kernel do different
> things).

You can have per directory .clang-format files to account for this. Eg.
net/ can have its own file that allows their silly comment style etc.

I suppose include/linux/ is going to be a wee problem..

Still, in general I don't like linters, they're too rigid, its either
all or nothing with those things.


And like I said, in my neovim-lsp adventures, I had to stomp hard on
clang-format, it got in the way far more than it was helpful.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250630080910.GK1613200%40noisy.programming.kicks-ass.net.
