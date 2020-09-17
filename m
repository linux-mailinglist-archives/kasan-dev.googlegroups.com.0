Return-Path: <kasan-dev+bncBCF5XGNWYQBRB7WCR75QKGQETXD3O5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 554E126E835
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 00:21:51 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id e190sf3498739ybf.18
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 15:21:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600381310; cv=pass;
        d=google.com; s=arc-20160816;
        b=E/27gcB8NtdYJog1fMXlkdgp1/rrezAjQnADe3mrY4DgbgA+x8dkTxCG8EFiFnQmPs
         ErymO3qksUMP7EuGioHAXp8Nsm0AXVq+uiic2nBSd7efeqUd6BoLYxGEgQTA9DKi1eHt
         84xH/Ps01Me9s3VX0/oQZev0V0kHtQ1vlgGiESgwMDOYxjlM4tyEAl+RLl1Suu+m8y5R
         HtCQqnS2JrIwSmAPZ340/r2dsDbU6LCs2d/2gDp7bs+4K1Q3GQdOVSXEkAi9QxuoeTCZ
         d2E1+W3bhLd/ouVBgEwScTDPGeiS3cq1lj77b3ZBl3cxLygWihV2oJThJgg7LCBEbID7
         mXFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nuqxzqXJCt4+BveSi/cjgDgUh0LAe/rqnmgwlhlUpM4=;
        b=D0y11Q8Ez4mFCSqTGEJk0EDw3Lw5Kz6i75Va+OVQpYDOcfjEK0QdOt2qdzuX/ARNbm
         MF9iZ4vzKQHfIedChsA+RXlaWktE74vv4FR+5l5BRd9o8OfpKtcWM0d7hRteFKmvwakq
         EvuouT5v09Ez8VFDRC5u1O3KbY8dUkbcF/psMHmZve1EtjMyt1ML8sh5vD216gSMmJB7
         63OStRx0F5G68O2gg23eY7yZtIMo0NBuZE4UNNdz5M+3n2aCAcLyUWeUbVtn50QTfmBZ
         Iw6LaAxlDabW+SYxRlN82RlSRGvusV+vpZyuPnTPiMVXYxe6sbnYQY39IQgQEt1pGvZm
         4P/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ciFNzf+h;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nuqxzqXJCt4+BveSi/cjgDgUh0LAe/rqnmgwlhlUpM4=;
        b=tedJrvxzlEtEv89bHlhyHt8bS71r3uDH0UJ8XwbYg9riCDozn1avLrxTFqtxbA+KKX
         PWK41+2IKtD7CSfmBOGt+Bjw/qPuSOpFOgd50BQPzX/BjqnksHWpUmFjs4RsbYWWggVl
         2aQ/YkEWK7bWKW3lszzZ8pV7ixlSl1dtmFSHTNDvEE5Iezs3U6Hf3RFf3AcyOwZ9GeXa
         mK0SwmlJjITTTtWgGyUCb8nlC2nJ8IPhhA7lzmgDX5+95Y7AZAhERLojsvzduWgk84Zv
         pUmmiaTYSi5+E9P0atXPrJnl70A0M2JmztjQToIBivx6+HKbrWZRkp+00f33raJS/KkH
         TEvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nuqxzqXJCt4+BveSi/cjgDgUh0LAe/rqnmgwlhlUpM4=;
        b=VYNX2xGV2ayQVOF7uiIOk70uJRqz8yrytulTZZ1D7QvJLSBArUt5rozXVS+yNAykXn
         KXC2J0K+zCLqwJAxKJATDoKtuZFbo+o8Ux0TFdQ75ExR6Be/SPe0EWgFhkt/kXWJIH1Y
         2QeDQrW5FmSENl15NCOf9Hbu6aB0xNrnOu+NTefOuBRtSNZOD1B3ev2MEreQoNqlTh1M
         eiRwrO4MBAYRlqQ/mKfckEo+bw1PM1o32kKYC/544+r0sTD2WAGC6QZlDg/SY/ebJzqk
         DubxOthSeJ33NgB0CXFIip8bOXU1+2UGOxmmuqyUdY+4Jv64EkmtEO9vBGT3g/tLCxJk
         FK0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530L0BW0vEkYdFIf2FWCfJgvoGi+SZmSC8eWlWXU6LqQBtihwJFz
	eMEYAt7U5FHkCCKcaEfz018=
X-Google-Smtp-Source: ABdhPJzhikEsVin02ui1jY4g8Y+1sClovwZGprxXNYQUzAhHdAthO4BLVUQMurvXvm8PHBB/IeQT5w==
X-Received: by 2002:a25:ce90:: with SMTP id x138mr25971717ybe.95.1600381310384;
        Thu, 17 Sep 2020 15:21:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c550:: with SMTP id v77ls1602150ybe.8.gmail; Thu, 17 Sep
 2020 15:21:49 -0700 (PDT)
X-Received: by 2002:a25:1fd5:: with SMTP id f204mr46221911ybf.236.1600381309926;
        Thu, 17 Sep 2020 15:21:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600381309; cv=none;
        d=google.com; s=arc-20160816;
        b=eLP6QPrbVMFoNcEl3VzytyJRo8Yh7qEClCECqZKVl9ApgeQi8s7H+tqyr10NeK/mq7
         FZlZF3Wm6EL9pNYQpDymswvP4rbTvncUBcbmk8FvqxFut+snZ1Sfz3fvySDeE6AwPbmX
         v2iL6oBn6UvSuJyUPT7ALoOg7riMTt2UjzNwmpHAlc0tRqjlhXsjSGxtVwYx9m90FZbo
         8Y2t/Tzhy77G9w+IH6v0PnqCW4AhOl7VfaIQr4P6sIWMBVgR2di5g3xPxskUZumIYKyb
         VF7IL3oD19vjOSjolNgdXZFH5ccSQMXNSGQrTNiroPzYlecwgw9bkdd9y4dxWeZknFsu
         2mKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9DPIpM4LW2/8oZNQwQFTEuyuoQvJ/tNgC5mR+LCoUuA=;
        b=sKwnLcfDm5/4Ys6N3PQKIbwngXyQYxx/t3m40nCvIILoIMY74p/+e121ht9ha1csUb
         gdgnYo8DTIEScn0Zs1oKVx17CxC/eLrVReL7+z5/IxfUa97B8M/RrJTBsPVaxb4H5qiM
         8g9mFpAz7C/5WWtODZMSMn0DZujYjvhHkoRZeBkEMQVgsMxmsILVxPQ0z+vGs5Gh+T5z
         Ih52YyrZaA18dZ/N+g6TOwV3IMkE+QH65OC0B86GbHkVpMYudLKig7loJUghCsRIoEPD
         1kgfkkFsq81RpkL0wIoYVlsGLo5U7c5rmkug+fCEzq8sXwjHKy3vYKJrSqeYzmdWbiWy
         yIHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ciFNzf+h;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id e17si128665ybp.1.2020.09.17.15.21.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 15:21:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id y6so1869825plt.9
        for <kasan-dev@googlegroups.com>; Thu, 17 Sep 2020 15:21:49 -0700 (PDT)
X-Received: by 2002:a17:902:c212:b029:d1:e629:92f4 with SMTP id 18-20020a170902c212b02900d1e62992f4mr12676668pll.75.1600381309149;
        Thu, 17 Sep 2020 15:21:49 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id m5sm627685pjn.19.2020.09.17.15.21.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Sep 2020 15:21:48 -0700 (PDT)
Date: Thu, 17 Sep 2020 15:21:47 -0700
From: Kees Cook <keescook@chromium.org>
To: George Popescu <georgepope@google.com>
Cc: Marco Elver <elver@google.com>, maz@kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	kvmarm@lists.cs.columbia.edu, LKML <linux-kernel@vger.kernel.org>,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	james.morse@arm.com, julien.thierry.kdev@gmail.com,
	suzuki.poulose@arm.com,
	Nathan Chancellor <natechancellor@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	David Brazdil <dbrazdil@google.com>, broonie@kernel.org,
	Fangrui Song <maskray@google.com>, Andrew Scull <ascull@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH 06/14] Fix CFLAGS for UBSAN_BOUNDS on Clang
Message-ID: <202009171519.951D26DB@keescook>
References: <20200915102458.GA1650630@google.com>
 <CANpmjNOTcS_vvZ1swh1iHYaRbTvGKnPAe4Q2DpR1MGhk_oZDeA@mail.gmail.com>
 <20200915120105.GA2294884@google.com>
 <CANpmjNPpq7LfTHYesz2wTVw6Pqv0FQ2gc-vmSB6Mdov+XWPZiw@mail.gmail.com>
 <20200916074027.GA2946587@google.com>
 <CANpmjNMT9-a8qKZSvGWBPAb9x9y1DkrZMSvHGq++_TcEv=7AuA@mail.gmail.com>
 <20200916121401.GA3362356@google.com>
 <20200916134029.GA1146904@elver.google.com>
 <CANpmjNOfgeR0zpL-4AtOt0FL56BFZ_sud-mR3CrYB7OCMg0PaA@mail.gmail.com>
 <20200917113540.GA1742660@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200917113540.GA1742660@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ciFNzf+h;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Sep 17, 2020 at 11:35:40AM +0000, George Popescu wrote:
> On Thu, Sep 17, 2020 at 08:37:07AM +0200, Marco Elver wrote:
> > So, it seems that local-bounds can still catch some rare OOB accesses,
> > where KASAN fails to catch it because the access might skip over the
> > redzone.
> > 
> > The other more interesting bit of history is that
> > -fsanitize=local-bounds used to be -fbounds-checking, and meant for
> > production use as a hardening feature:
> > http://lists.llvm.org/pipermail/llvm-dev/2012-May/049972.html
> > 
> > And local-bounds just does not behave like any other sanitizer as a
> > result, it just traps. The fact that it's enabled via
> > -fsanitize=local-bounds (or just bounds) but hasn't much changed in
> > behaviour is a little unfortunate.
> 
> > I suppose there are 3 options:
> > 
> > 1. George implements trap handling somehow. Is this feasible? If not,
> > why not? Maybe that should also have been explained in the commit
> > message.
> > 
> > 2. Only enable -fsanitize=local-bounds if UBSAN_TRAP was selected, at
> > least for as long as Clang traps for local-bounds. I think this makes
> > sense either way, because if we do not expect UBSAN to trap, it really
> > should not trap!
> > 
> > 3. Change the compiler. As always, this will take a while to implement
> > and then to reach whoever should have that updated compiler.
> > 
> > Preferences?
> Considering of what you said above, I find option 2 the most elegant.
> The first one doesn't sound doable for the moment, also the third.
> I will edit this patch considering your comments and resend it to the
> list.

I have a slightly different suggestion that is very nearly #2 above:
split local-bounds into a separate CONFIG that requires UBSAN_TRAP, and
then carefully document both:
- what does it catch that "bounds" doesn't
- why it only operates in trap mode

The rationale I have is that I don't like the coverage of some
mitigation or detection to "silently" vary between builds. e.g. someone
would build with/without UBSAN_TRAP and end up with unexpectedly
different coverage. I'd rather there be a separate CONFIG that appears.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202009171519.951D26DB%40keescook.
