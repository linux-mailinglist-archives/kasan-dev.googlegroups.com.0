Return-Path: <kasan-dev+bncBDEKVJM7XAHRBVWOWX3AKGQEQPX3ALY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF20C1E2AEA
	for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 21:00:38 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id bs5sf9319041edb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 12:00:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590519638; cv=pass;
        d=google.com; s=arc-20160816;
        b=BNxKbwywEeFPUypCy/eFv54EW+cbFnhGd1REsuNzxLCqvJsF5nd8k2Q/YEHFJVpL+b
         SjiqtC7AAsQ6dR7RXWM/vv+Ej2iF/V+yI2vKPF64bTnPyNW3TRzgQ7wYtdjVlLXOEX//
         rdTVA/FGkUVPPbafH12u7bx+yN0HZRJg71rHJqSr4uhR9D5rfgyaYa+ByEckuLqHVfBz
         Ir0WBWvXrdPFuwwG4NFsgLvEwlIq4AJ/oWWTI++lLm0SnZWF7Cu/9Du9K1o3Q/LUfgg5
         5LDl0k1SnURsdAkCrhg9Oi+w/b24RlKGDyAFYYVpG02Pkd8OY6NI1KvgmVnC96nEbHg2
         5B2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=FwS1XbATZUETraHtOgRM7Dfpjet+TclAtyoXPUtiIzk=;
        b=e3qIjP8LjglQduN6VlhvWQZHS/NhX88bcMhsU1+5Wuc24vce2gdJucijx3HOF0D/+C
         8cT42lUmHMevU0bkJL2ljz4tl/Zk9Tn/EdT7dyJFajOgmSQVW7/5aa9dHb/BZd+QJ0cy
         ipVLJYB6SzqWAA4JYSghxpiBSXZzrI5jCC1sNzAwyw5yWXj9WoMfCmvCv02YWibqhuca
         2xSyyA/c3I6IOIICgS7Do/EMeh6zaS5JQZCWvAvFEDUeq1hN0+I83L+GTX2aZjKLvU4U
         r72HvAzO269AEVHvqSSBhmtEpmRSaCSb4s6q6PICyGmL0FICu/YC4VwIae8SKhxt3QQ7
         SXGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FwS1XbATZUETraHtOgRM7Dfpjet+TclAtyoXPUtiIzk=;
        b=DnXyLE39KJa+BuPpIj60JqqUyntyqBwj+CSU/s+OzZTXfwJMMQ8Mw40A0DA/jj09hK
         ydNjsrXowVay1ouGjBaUYhro3JvuxyQh2j8uUtC9bfUKNoWr7gcnSF4vyno+dZdDM1zS
         I34+JClff/U+NIEHLXobfOERf8wTcrqbbLMqkOXvgR2b/yZt0LXn5yvhKwYSUG50/cMW
         KboR1eTCQYNI3R+XjrT9/LcZZNfiCyHs+QIg5FuclF0Jw+s50sMlkgFuyKEO1hduaAEp
         +hvRrnJdXxwvZn/B3plhh2sU8ZlhT40BMI5eme3GjgWJh0K+qDryadWXU0D43OsusFTN
         guWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FwS1XbATZUETraHtOgRM7Dfpjet+TclAtyoXPUtiIzk=;
        b=Y1CjQAFxl94sqWU8CLblAhBtiq6EyDiVCj9DcjEsjrgJRf0rk+mFXzqKw3+zwRhaQt
         dQen79KYEQGzKR7LkFvk8cftFOoJ+oMfkP8QTwaRTUYCANkaPEgo2QGquyrso958o9Lg
         hlqJWXtszYnoRm/+5gBUo7brUavXikcGAdn8mIRyAkuDo1GNiCLkrVfxWCP8GG7mRLm3
         J7wxJURXE2B5AJTk9qD43H/2lWgfbBEG2znojgaA9N9Ujyv/C3xOhdrzwTRmDkRsD3b7
         nVaT9pse8hadDoxFgh5nJ8K6f2UlCj0Mq9U07huthLPmdNPtf77v2Ru1tY1CpzXQclOk
         l7OQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W8jPfhxHs0mOlFG+hyyEXtoCq2vTUSlmGOU9ffF9uAdxPh/od
	wwR9zhqIpNTq7iJnvHjBnC0=
X-Google-Smtp-Source: ABdhPJzmU7WKhhlxBacg1UcBjsHTw3tZmGZ0fvcHpteNoNCCj3E+nKo/kMw02fPWojiWCVs3pq45KA==
X-Received: by 2002:a17:906:11c4:: with SMTP id o4mr2466285eja.163.1590519638726;
        Tue, 26 May 2020 12:00:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9f21:: with SMTP id b30ls13048735edf.1.gmail; Tue, 26
 May 2020 12:00:38 -0700 (PDT)
X-Received: by 2002:a50:81e6:: with SMTP id 93mr21858395ede.45.1590519638200;
        Tue, 26 May 2020 12:00:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590519638; cv=none;
        d=google.com; s=arc-20160816;
        b=APDpEmtcaMYxT2Mpf8TqzQY0IZUNZSzMPFTvgdIMIyXqX33v1+C66mMx8ANEDPO7qF
         /rHa7lEUg5JMfdJwSIFcI/Nv480GqGbgayhi7Yr/L9FnKoPe68EPgevTN9sbnPYL2oxu
         gDBdTQtsLyjutN9N8IJsnfXsf4XYB9Dca+38mpfxsMHpfnLN2qgEekZanEzfoTe5D3v/
         bHVfj1hUQ/OpmrztdjUA0WSQQMuLkc5ejBmolRrmQ1eIRyGxOVuYXyo1IncQrkQPumWN
         ZasmylbZpHxYu1bXDapTR+OecBbvIOOIxi/iuBbnTT3ypmRn++BGfvcvPoKjS4ziUKda
         k81A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=6a2oZxkItd9AGUyN44aak6tkm3BpLOq0hsKo8qlhGAc=;
        b=eiy6TNL33/vQgHvHjGZRiBYz9iiuFFzFZ9114Xrg0fZMngKCO8c/DX9pFwSmRpzLAh
         ojBPUzGQaJWC1QAH/pitsMpmFw1T3FdXYw89QTYKH9I+nYoDULgtPZJAGUr7Tg08r/qN
         66BMNjZc7RkPbpR8q134FYJKrNMITEhv+oRv+nnfMq8dG9sOh+qHBNpf1sKVoop7mSU4
         z7aMbhtjO8ACs69DGmub7Sh9yDcJfpIMaZNsT7DFfx+JRoY439eC0ngaBOAxbFgDiCTT
         r29rYPAcYGLYYyUbNEOXwg8CKwMVZxSudEF8R/NTmFnBb5lw9SP2i5H9IBIxgqPLFD2X
         fXPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.73])
        by gmr-mx.google.com with ESMTPS id r4si32251edl.0.2020.05.26.12.00.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 May 2020 12:00:38 -0700 (PDT)
Received-SPF: neutral (google.com: 217.72.192.73 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.73;
Received: from mail-qt1-f171.google.com ([209.85.160.171]) by
 mrelayeu.kundenserver.de (mreue109 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1M7auJ-1jeVDs2H7t-0084NB; Tue, 26 May 2020 21:00:37 +0200
Received: by mail-qt1-f171.google.com with SMTP id e16so11188961qtg.0;
        Tue, 26 May 2020 12:00:37 -0700 (PDT)
X-Received: by 2002:ac8:1844:: with SMTP id n4mr300518qtk.142.1590519636182;
 Tue, 26 May 2020 12:00:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck> <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
 <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com> <20200526173312.GA30240@google.com>
In-Reply-To: <20200526173312.GA30240@google.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Tue, 26 May 2020 21:00:20 +0200
X-Gmail-Original-Message-ID: <CAK8P3a3ZawPnzmzx4q58--M1h=v4X-1GtQLiwL1=G6rDK8=Wpg@mail.gmail.com>
Message-ID: <CAK8P3a3ZawPnzmzx4q58--M1h=v4X-1GtQLiwL1=G6rDK8=Wpg@mail.gmail.com>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement expression
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:uUX3wJdlDpht7240998zajIyQErWwYsmNrzsU0pa3bG+vnjnp1k
 Adi4CXZieyJbdy24+KQh0CGxya/WKwlzfL2/rCYWssdIoR1aK1D26tAISSqP4uj4Ulf2nVe
 qCeYlY2ezPFMZTRr2AWsfzAuYN8ScaXnie9q+dyaY/th5VWH4jZ21MSrGnHjvYjDBuFLhp8
 B/HWxqlKrZFzdubwo/FJw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:RtrXlh2KBTI=:ZudzcE1xW06e/bJADIsXvI
 FM8w9T+xeCEwEMeHZg1ZwWrKjBiljSxuUfFtl4HHWKSlq9elBu+ASEy+7y8eAMQE9d91tweYr
 /Wobcj5Vkz60gHrhSROTy+v6Fmbccu2O/i7ldvPdPKyjQukTEzFOEmF2KcPZXbyaPz3KBz+3h
 tbQABrUaFXXFRBBF0YYMl29c4/7d9DhPdvWwqQEt8bk1BhvL4Eb/VohAATb+ulqZWDXrOgumh
 Y8gMjM9BtLsk/v3Nftag4tGnlT7VlgifbSgOb0jwXCipNXfLWySRtIc3+68huEBvcPK1aNLOl
 XOCCv6nm0ZKcSpDuhNOLNb/4SxjdhNArPwrwExDkWz2DZ5hPUNRouXzoHjgTNek6fouSUSZ6f
 rZzcQEah0Qa4ykt6qutWy1TD2w3mr/8azGZ2KsY5/Ve9lG9Ex/PevhDblOuop8oi0NkuFJV88
 2jeHi3cFhywktDCtVIQEyYSpIcIcCnkiUqQ6Bnp5B3egn8jkGosMsgkWiwBAh8GB3yfmOTfK9
 RGiN8fywrkH3SvxClaKsyTRJctPKgNlTP+1nS8RqkMkUwyf2rGtdsPlaDYuRJrPRwibpsrISH
 yofNOVe8K3SlWBiOtHrdn0ao2efHQTeithPOzhWZ++0dZhU4VS7od3klyVFbmmfY+bNRam3lC
 aEHjlUOsdhXQ/Opkg2gHPvg7XeqBzsO0h69GE0HbpjAZaPyJHieqIFMXIwxVF/tb1Cfn/BgBC
 7lboWYea8lODWFofhUuPK6m4fXpDiO99FdfGPAfBoUwZSyjKqG9ZfQJpWQm6zXnL5Eu6ZPhWU
 M7Iy3hglWgM5myFpKzRq6vhqZoCpLdmbyRIUUXvp0ium3u+8sI=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.73 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Tue, May 26, 2020 at 7:33 PM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
> On Tue, 26 May 2020, Marco Elver wrote:
> > On Tue, 26 May 2020 at 14:19, Arnd Bergmann <arnd@arndb.de> wrote:
> > Note that an 'allyesconfig' selects KASAN and not KCSAN by default.
> > But I think that's not relevant, since KCSAN-specific code was removed
> > from ONCEs. In general though, it is entirely expected that we have a
> > bit longer compile times when we have the instrumentation passes
> > enabled.
> >
> > But as you pointed out, that's irrelevant, and the significant
> > overhead is from parsing and pre-processing. FWIW, we can probably
> > optimize Clang itself a bit:
> > https://github.com/ClangBuiltLinux/linux/issues/1032#issuecomment-633712667
>
> Found that optimizing __unqual_scalar_typeof makes a noticeable
> difference. We could use C11's _Generic if the compiler supports it (and
> all supported versions of Clang certainly do).
>
> Could you verify if the below patch improves compile-times for you? E.g.
> on fs/ocfs2/journal.c I was able to get ~40% compile-time speedup.

Yes, that brings both the preprocessed size and the time to preprocess it
with clang-11 back to where it is in mainline, and close to the speed with
gcc-10 for this particular file.

I also cross-checked with gcc-4.9 and gcc-10 and found that they do see
the same increase in the preprocessor output, but it makes little difference
for preprocessing performance on gcc.

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3ZawPnzmzx4q58--M1h%3Dv4X-1GtQLiwL1%3DG6rDK8%3DWpg%40mail.gmail.com.
