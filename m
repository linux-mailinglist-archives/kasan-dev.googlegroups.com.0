Return-Path: <kasan-dev+bncBDRZHGH43YJRB77RQKFQMGQEMEA5T4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id D675842731A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 23:32:48 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id u13-20020a17090a4bcd00b00198e965f8f4sf8224579pjl.8
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 14:32:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633728767; cv=pass;
        d=google.com; s=arc-20160816;
        b=SXPfYkp0pQgL7DlFjI7piAuJZEeF8XHAk/jYT1m2EQdmCQi9o1ELGFurnFagfP0Ph0
         /vhFQ4j/ZvT9rDHdhz8W/3inJ4I/XW2xZlHKXZMsGylVaiSIDkNzYdylS83Jn8p3heL7
         llwSuNAZ36BWAMcbf9QaQ6e3/SHiUKPBOXMCWzO3Ri26QH8+n+HAsc8cKdeb0/jB2o+W
         48HhbNqr1pae3qtuUgXg98SI6wdBpnKTmVdwtRPENECIWAALZ4hgCqbxlkmmxhqPpKW9
         T5WgdYxfRkMrC4Zfk4zo+eWZi1IAXRsIZEqfOmWsdTVxqkfxvn8RG+0t8qDcOJfVh1ba
         ZSdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=iOe6YdfquFQjPODj1rWrvxhL+ysKckzBKTDD03jLHeM=;
        b=OmAmKTg48HAI+tQS4uPUI1uoYKYrk+Gnj1afxZWedMVPUlQcEOJOvTYFI2yoHASnfO
         K1O4mCWHON/Z7aj9kAGbjq3Lv2wqJ53GsRJYBIY8nH3L4J3o37PGyQDBlCGFWmovDjkA
         xFR10hfDBa8GrNt9D59JxQQzGYt/EQbRHqpSMzdmWltPoNPeJt+DkQGVCDS7qLhneAZX
         4Xl9ZMtfcv931E26uXdQlV9/5CqlEAgRSrxn65oNZua7R6L9IhVc9NbzD7c6MtLw7o13
         F4AMAYQdyA8uTAhXVk14djgnoEy8YrWokZC7Pxib/MeYaZ3unMYLwW7uz5r7RfvNrcub
         BafQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QGK2w5pf;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOe6YdfquFQjPODj1rWrvxhL+ysKckzBKTDD03jLHeM=;
        b=npYNuF31E5ZIhh+niShuFuZ8lDiz63SodIk7KlenR1+xqqi6cUpS51INDBFjgScflm
         GPs6QqQ/9c8oVD7FijgY1oR2K3IpARhxsknmVU0M1Ln78eKDvL0OyrSnbwkaB2Ub0pCm
         Ywv87mq81TwbWhxIEnjUQxZb+TSqz7W/5nfdiks6AhpPaO4X51wGe6JHGXOQLfEtTE5X
         9m4Kk5NvBZtiJXN98GhW0DvfB+0uHiFHBYgN5LYIclCFKwlMDB4e22WrB+sJ2AOZgwlF
         PLVN1SBTnaHkDbTwDZqr+chqFzgPPmU+MPRGnfcUDMa8g1+kDp2Imow0ZcaoDbK/eNCx
         n3vg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOe6YdfquFQjPODj1rWrvxhL+ysKckzBKTDD03jLHeM=;
        b=BZTtLqkxJOM0al9H733NFkAb8z4J3a5fjKvdVY9xcY09UrS45TKx3PSqEwJ7WMUl1I
         eQfjHOE+CPU85oQVqROrg6VcBu6twhrxsTt5wDtU8CH50n160l6bRdi8boasiQvoG9k1
         k6xkcNKqdlvAr8vty5pP7PFcf23ERaFULwvNyVfuNXRrr+loMDW9NB4JvWOkeB5rKEEL
         8hOlG6sWg+0Wq5K2AKwIKoLs8moP1hlkYzyB3TvgoAsoT0My0CR61fLuGWwIelPG4Lcv
         KUgimAsMhN8V6j69KI0q+S1sJx79RQVEVDabZ92mkAdQ1YCfFj+7dIc0k+XNt+edlZvF
         oS7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOe6YdfquFQjPODj1rWrvxhL+ysKckzBKTDD03jLHeM=;
        b=bu2e6VnCVj/6L6y4XEEwxjsflqkPUWvSfmhH0xov8hvVdwv1Gg5hYJeNE+uLH/ax/0
         Iu6+FSfhN+tkEe3htRMlSSiS405eV5lq1DtS0ENY+mS3hHqRqgjeXktWA0X3I0fVasOf
         GlQvnmUXhe8mi3x6ZpG1XRSx+XyMQ/o3Y+e4qT3QqQAW6HiHeTbZC85qYNWTfWDc7m5+
         qsqoFbr3kfReTupKhSxUfnOdGXMuvGLKm4BHrMn4iYCHjaR/9bFY1uEDcrj5TWMw53+z
         YuzwxMrbXXwchUlK3SbAJj1Su4lXZPwywS3CduYHWYD4lfOYncVy8gXvpLPqkme2khej
         l8Bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322K0kyC7TH93e6IETJNVtGZFioZKA0zfehVW9qCQcSvxJlB8BC
	8wwCi+3/v7UL6thB0IHZeTg=
X-Google-Smtp-Source: ABdhPJyLgmKNKzeZs602UGOs0YoogIQ2QIEDmy/IkO6gPkmwiXktsff4CqDU7Ef3+pLcdLnCY4rHuw==
X-Received: by 2002:a17:90a:4097:: with SMTP id l23mr15104822pjg.141.1633728767511;
        Fri, 08 Oct 2021 14:32:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1392:: with SMTP id t18ls1733160pfg.11.gmail; Fri,
 08 Oct 2021 14:32:46 -0700 (PDT)
X-Received: by 2002:a05:6a00:2284:b0:43d:fc72:e565 with SMTP id f4-20020a056a00228400b0043dfc72e565mr12631382pfe.84.1633728766699;
        Fri, 08 Oct 2021 14:32:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633728766; cv=none;
        d=google.com; s=arc-20160816;
        b=iGeV+X/fuAmiPlJNfSsKvsKmzKaONu4RshZbF3/IYrSjY3TVlyH25Kis8IzVntWeqS
         aXkNIbTw01hJeSD+rWqkz6wSGuFHmBgLUosXL5Xd7YgL3814AgO95bcIHoMeN7OIuX1V
         DjdS03KvVNAdhbTyWK0HTfe9ACalVYbUix1DPBJvdiA+J+dQIBFSTLJscciuoSXfaBxc
         t4buvekTFbilD7UwBciB/2q5nHzdFEGU0+5NE/9SWrivYFIYVRRJe8E9X1+7ged9JYOL
         f4I+GTrpWh00WeyrBnbab8Reri0CBn0yFsgAehxrVy7LqS+lnZJOuWJoAwOYVjHJcB8g
         zg3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LM9irX8xumxp4TIr9cZC8VWpmESQECbIIBoHRou9P3g=;
        b=QXG1r7Q9gL6z0luq7RxLNdoC27wlBgVHZEM25HLR9enhoUnPOPB9XVwLpxMcPHR7+q
         RPvyTwBlZ/rIEbw86exAQaA291cvymjL6UKb9iMMb+9NwCtlfbPbGm/Xy3UePu1t2OUU
         sVhJmBMaMqqcLQmHr7DT8AwNnfv7Ew4bqys0serGIInuBEIKN8fgdKanweX6543aSXo/
         3Oti2Xh9NkpZ5a5kcgdgyPXy0qCwWG/Bh1yWOp42XeRN8uJxfuLX0kZd+3aLNCkHypV5
         K0bmlCZHxjpD7Nzlpi8gwso3WBgjArNA7EuxkJvGYpljdbJuE5q/QZimIQNCGsKat0R/
         QSaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QGK2w5pf;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id u14si16431pgi.5.2021.10.08.14.32.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Oct 2021 14:32:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id x1so8266804iof.7
        for <kasan-dev@googlegroups.com>; Fri, 08 Oct 2021 14:32:46 -0700 (PDT)
X-Received: by 2002:a05:6638:14d0:: with SMTP id l16mr9287388jak.142.1633728766086;
 Fri, 08 Oct 2021 14:32:46 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux> <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1> <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1> <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1> <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 8 Oct 2021 23:32:34 +0200
Message-ID: <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QGK2w5pf;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Fri, Oct 8, 2021 at 7:40 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Just in case there is lingering confusion, my purpose in providing an
> example from the field of safety-critical systems was nothing more or
> less than to derive an extreme lower bound for the expected bug rate in

Yes, safety-critical systems usually have lower rate of bugs, but they
can actually be very buggy as long as they comply with requirements...
:P

> production software.  Believe me, there is no way that I am advocating
> use of Rust as it currently exists for use in safety-critical systems!
> Not that this will necessarily prevent such use, mind you!  ;-)

Well, people are already working on bringing Rust to safety-critical domains! :)

In any case, for example, DO-178 describes the software development
process, but does not require a particular language to be used even if
a particular project following that standard may do so.

> From what I have seen, people prevent unsafe Rust code from introducing
> UB by adding things, for example assertions and proofs of correctness.
> Each and every one of those added things have a non-zero probability
> of themselves containing bugs or mistakes.  Therefore, a Rust program
> containing a sufficiently large quantity of unsafe code will with high
> probability invoke UB.
>
> Hopefully, a much lower UB-invocation probability than a similar quantity
> of C code, but nevertheless, a decidedly non-zero probability.
>
> So what am I missing here?

Rust does not guarantee UB-freedom in an absolute way -- after all,
there is unsafe code in the standard library, we have unsafe code in
the kernel abstractions, the compiler may have bugs, the hardware may
misbehave, there may be a single-event upset, etc.

However, the key is to understand Rust as a way to minimize unsafe
code, and therefore minimize the chances of UB happening.

Let's take an example: we need to dereference a pointer 10 times in a
driver. And 10 more times in another driver. We may do it writing
`unsafe` many times in every driver, and checking that every single
usage does not trigger UB. This is fine, and we can write Rust code
like that, but is not buying us much. And, as you say, if we keep
accumulating those dereferences, the probability of a mistake grows
and grows.

Instead, we could write an abstraction that provides a safe way to do
the same thing. Then we can focus our efforts in checking the
abstraction, and reuse it everywhere, in all drivers.

That abstraction does not guarantee there is no UB -- after all, it
may have a bug, or someone else may corrupt our memory, or the
hardware may have a bug, etc. However, that abstraction is promising
that, as long as there is no other UB subverting it, then it will not
allow safe code to create UB.

Therefore, as a driver writer, as long as I keep writing only safe
code, I do not have to care about introducing UB. As a reviewer, if
the driver does not contain unsafe code, I don't need to worry about
any UB either. If UB is actually introduced, then the bug is in the
abstractions, not the safe driver.

Thus we are reducing the amount of places where we risk using a
potentially-UB operation.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72mOWV2SiF24E%3DNMB-zc2mK_UFH%3DCvDFxN%2Bvdtyjy-Wm0A%40mail.gmail.com.
