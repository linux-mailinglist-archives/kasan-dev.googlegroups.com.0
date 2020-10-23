Return-Path: <kasan-dev+bncBAABBGEQZX6AKGQE23BGVVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 970A32978BC
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 23:16:09 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id m62sf3386200ybb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 14:16:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603487768; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gmn+Qqd81kg1O3DafPvLM/3L80FhDC4bT6zL04KrkcAeTYi7+nfn/VAzghA/LmuFN8
         ZeWSwK1oUz+i9ItVqQp84pF0QOxv/Pz50ehWf11kf10pK0RqQc3FihVlDTdDU0D6Zgld
         fcNGz1YukGaWaQ8cglJJK1d4tYVX3MtiZQ0bNSaSjcFEjWEzahS9K0KABXnQ02SYQcSp
         l/jRjhYYwEf79wwiW8wqJ3eIGsOLWrrTUeELE6Cs1VdRfLQlhE3x0AfBRgnmHH0oVv02
         qZRddLdmGfmkuBOoUCCS7PqCQz7wLwshmhX9atbt3Gyus997vx2RPlVWmYPmX0JrAIIX
         wrwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=akMbGlOWOaw8fDuzcZSZzYbbLr+jrs/xl67XAh12944=;
        b=MOz5JAm1Ogg7mSFIzV5QBEOVyAUWMxu2SkLsV0e8mIFgT3LG9TT5Z54rdQBjMxd4rl
         tSM6lZwOVyqWpCAwrfSQLJpS4f345iykKr9yw1URSj8Q/mHpZpllYXywGLe0LJh69T4Z
         iPbGUInrK6WVdVz6NRpnqPHUM63AHEf0tV4xrawwazzXYcdyMPUQeYrDk43ObucU5JSl
         k4ap6BJ7r8oPZXITX/IQYRFkhU6IIo0SgV805iORJmOK23y1NjXb2fFuyZ0OvwUENlV3
         vt/CDUKmoIMtYiycAFtY0q2UpAUUqqbVxv0QUJ/srqEMkn0SqY1P8HNoWVgMmHjSWM4o
         eyuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ylYjv002;
       spf=pass (google.com: domain of song@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=akMbGlOWOaw8fDuzcZSZzYbbLr+jrs/xl67XAh12944=;
        b=BsL7g0VAaBwd45UxkHWoHZ/6Nz7Scjce3HJpIqTMtlpXOq9PuNaKxtXJG1CQbE19xS
         ZEcpA9HE1FRYRXVRBEQTF587Rk+dW7KtgBiHRrnsVx4J8+bd9yIiXsr9EBUSAH3w1W0J
         rDgoezjRz7jLJtzURslffIW+zWotaIsqMUSA5wOYf2O5/f+Mu0pvxNbCWc5+86bHlLGX
         VnVNBS5wP8WL7KmA95cphCLUUxpqaqXPTHcyow8CkqzCw0+7EQkemuWGi+2ZR5MMu+No
         UPIR2zX88NzGP1wVRJ3lFUPe/pKD2F2SCaJGXRyc9YgSJCgfPMJkYTOBO+Uay2F4QaCI
         6LNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=akMbGlOWOaw8fDuzcZSZzYbbLr+jrs/xl67XAh12944=;
        b=Ge3Ifyrg0XIYM3FBJ8U2TmMq5j+d7aK+XnTikvuatpnduV0PamQ6M7DG0pb1azAAgQ
         XEyuYxRaLhPcMVgxQHZb9Fwh6qAXKPDhPC7DwnY+1TsHkD0e5xvT8X/c1lUo7cxjulHv
         bcKt0UQDOTp88mtZVM+VawkuC4uKeBDxaCImFuHL6OhD8WyFKKjFojfp0Bs6nIR1TPgn
         givr+DkuYkPjANIez+GV8C4x9JrbJ7ZYXVKYGyjhQk/4PgimrNSA/6XjcDyJxrrjoqj2
         AvrOZIrh+j3oI1CC3j/gzZ99rEo7UaS6l83SswfmmBkiOzCSfqLXQKOAa93cU74Q+S9L
         fwEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y5ir+bK6IZF+VUK2axvKRlG5StB99rhaV1rxwCTUhwI1PyA/v
	CHgozXl3Lj/xBC/8bKtSsOA=
X-Google-Smtp-Source: ABdhPJyts1avfR9JwUbi7iuWVITgR3+Xh/qFtVjn1q+09yEW9Jm478bKAgQM5fJ8nHzwOF5K5hKspg==
X-Received: by 2002:a5b:b86:: with SMTP id l6mr6124083ybq.258.1603487768667;
        Fri, 23 Oct 2020 14:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2689:: with SMTP id m131ls1337212ybm.7.gmail; Fri, 23
 Oct 2020 14:16:08 -0700 (PDT)
X-Received: by 2002:a25:d08e:: with SMTP id h136mr6819610ybg.20.1603487768239;
        Fri, 23 Oct 2020 14:16:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603487768; cv=none;
        d=google.com; s=arc-20160816;
        b=ipFV8LB76Q/yu9fXK/9unGUDYQOYGn/rd/G2HtEZnQ5v2Y6mN4TYzDXauMk0LrzFm2
         E9b4jFpohXPibC9K2gdJKOBq+0PloD/iGUelLGIHWoL58Ym6HctS3CRI8xvylm0puWUC
         fgOI1Eo8qi2gWc6esfSXQ3UofBNUcSNDMEbOI02yf/xByP7pb/1xLgp7cpl3m1Gj7U83
         FT9b7s6/U+gHJriEqTe4t3mbGOppIobOKxKrUWjK0SSuhvaATrX9ljOeA1NqhEgtvo4c
         wYec1PewSQBqMSUEqM1HoaY06wEVc8bJUpC7S0uqa3dqnm444bHigwGOmGwJD5yGA3qp
         RvkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SIKXFbqTm+pSm6OfDyIbBjFu1rypT7X6yVZC0TmiM6w=;
        b=zRk0yb2IXfvjEJ9TgzWK+549iQBmPHQ9kBdgV3H49vQGQ/p0Gp3AfOY3+uXuLINHD0
         PoUnA7Ec29/dmc6NMZcdDTho8ITIIuacX9YV32CRZQfeHwmRPIt5pz0dw7Q52bknZvbF
         n4jewJonrX1pqK6M5uAeAYPCvBaHGgvFEhiPM/ocyYAEgxNeR5HjcsR9uTzfxj/rHkE+
         SaVu00LioWbS3E/iBat/ahglElOgZC9twSilAfTYpCunvejoFlJ/fcprO4smVGPgQTDU
         KaklNW2+z0gt/fdbl8oNIdb7HzWOn+0pf7nkD+/Wbch5hyQPuxRVdQ2g/8YDv0Jj8zKb
         AfwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ylYjv002;
       spf=pass (google.com: domain of song@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=song@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q4si178344ybk.3.2020.10.23.14.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Oct 2020 14:16:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of song@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-lj1-f174.google.com (mail-lj1-f174.google.com [209.85.208.174])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A49202466D
	for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 21:16:06 +0000 (UTC)
Received: by mail-lj1-f174.google.com with SMTP id m16so3016484ljo.6
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 14:16:06 -0700 (PDT)
X-Received: by 2002:a05:651c:cd:: with SMTP id 13mr1498277ljr.392.1603487764782;
 Fri, 23 Oct 2020 14:16:04 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
 <CA+G9fYu5aGbMHaR1tewV9dPwXrUR5cbGHJC1BT=GSLsYYwN6Nw@mail.gmail.com> <CAHk-=wjyp3Y_vXJwvoieBJpmmTrs46kc4GKbq5x_nvonHvPJBw@mail.gmail.com>
In-Reply-To: <CAHk-=wjyp3Y_vXJwvoieBJpmmTrs46kc4GKbq5x_nvonHvPJBw@mail.gmail.com>
From: Song Liu <song@kernel.org>
Date: Fri, 23 Oct 2020 14:15:53 -0700
X-Gmail-Original-Message-ID: <CAPhsuW6wZRVoT3Bu6YBVjWVm6JBz9n6_RoZKGM7KrVAXx89SFQ@mail.gmail.com>
Message-ID: <CAPhsuW6wZRVoT3Bu6YBVjWVm6JBz9n6_RoZKGM7KrVAXx89SFQ@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: song@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ylYjv002;       spf=pass
 (google.com: domain of song@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=song@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Oct 23, 2020 at 10:51 AM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Fri, Oct 23, 2020 at 10:00 AM Naresh Kamboju
> <naresh.kamboju@linaro.org> wrote:
> >
> > [Old patch from yesterday]
> >
> > After applying your patch on top on linux next tag 20201015
> > there are two observations,
> >   1) i386 build failed. please find build error build
>
> Yes, this was expected. That patch explicitly only works on x86-64,
> because 32-bit needs the double register handling for 64-bit values
> (mainly loff_t).
>
> >   2) x86_64 kasan test PASS and the reported error not found.
>
> Ok, good. That confirms that the problem you reported is indeed the
> register allocation.
>
> The patch I sent an hour ago (the one based on Rasmus' one from
> yesterday) should fix things too, and - unlike yesterday's - work on
> 32-bit.
>
> But I'll wait for confirmation (and hopefully a sign-off from Rasmus
> so that I can give him authorship) before actually committing it.
>
>               Linus

My test vm failed to boot since

commit d55564cfc222326e944893eff0c4118353e349ec
x86: Make __put_user() generate an out-of-line call

The patch also fixed it.

Thanks!
Song

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPhsuW6wZRVoT3Bu6YBVjWVm6JBz9n6_RoZKGM7KrVAXx89SFQ%40mail.gmail.com.
