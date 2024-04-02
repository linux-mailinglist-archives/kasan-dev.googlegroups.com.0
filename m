Return-Path: <kasan-dev+bncBCMIZB7QWENRBZ4VV6YAMGQEBJLTLWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E77B894E55
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Apr 2024 11:07:52 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-515cddd7960sf2837010e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Apr 2024 02:07:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712048872; cv=pass;
        d=google.com; s=arc-20160816;
        b=GgBT5xNh9/9qJcibTeLCWWWL8WZg+qK9xUtYouMc3cJXZqvcs8Aeh/qMPV8mnMYdVR
         4RXVfiviNTSU091olHomgXNRQJMnoe/wojGpJ7KoHfwzIyzVOoUB09zR2wb6gkJKZ0U2
         mhM2NW+GhmjoZm1i3cvMor3OzX6Fvv8vGFJtcfYWCGIxNEyN6SDvsfJZWKBhC1b4aTxw
         UMiO2DZrRoBpN8ZZzD3VIw8ZGEj/J4rrcyxi+RCWEg7/tb++bx3f93PHVwnH7DIHQkIr
         Y9TFXbc/xVehVAPitdqchHFimvj9kzwdNcGMRVE8rqH3ZGiUanT7Q/2dRCOy/sr+FWiw
         fUPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yas60sHKkZRL/nVDSeCh23hfzUuTaTysVp1x5lnG44w=;
        fh=152qdpb197YvnA6q4ZYEQZjnwxtpGm3HlGUlu0/l70I=;
        b=xszehIL5GjB6RiF0x6gMgKZ+Pr4/ucrdhNOE9AW4oVTgXaiVmZBQ9lWcpFRJ0O5P10
         WDKY9bFztsGTpL8PX0+StdID9aAihh+n7wQ3ElErEkDfSy+CWq4Dwm1fToFuSm/FSZOw
         ZcVw/y/tkWhLqotwRQfKLZHcQT/+05H8laHAWiMiWofd0r7Fo8ZDo+N/bWGn3dAXsz21
         3L9X+HX+wIYJrT4/5olO0h1TfDfhdoj2ys+8m6MmsoJAWM3tOXDsj1dII5UNksYnVJJv
         auuUdEhowNzDUZ65je6XM/o28uzE9fdohQfPg3QlXhyN5+W/HIeGlp/6/Pmv+IWHKep+
         4sNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LIp8AlaL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712048872; x=1712653672; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yas60sHKkZRL/nVDSeCh23hfzUuTaTysVp1x5lnG44w=;
        b=kTyIbokQO0NaZoqEuOl0THYVc0j4LVDQFtupQN74LiEUEfsIzT6nm0binWf9iSpHpv
         oTEyNQctiQ55zI0+QG5Y9T5oS2uD0kZSsrffxzPGVVAwNu7lqHYb34y/RWRVb9/BsSow
         74y6iU5P7H3a1Wr0FRHIPBO2rdkYnrUQRj+26F61fDdRYY+yo6EFX/5BcqlCNih4D7mC
         IheZuImUa56KMlhOKq5+EJBLActB1VkJD/U9F5Oq1l4VQxxmMpDkN/+TdcN2Uy0mW/ZO
         R2R+r7INn3SsBBlurECQ4+LPyImkTPBRfzOsuMQCPA5vyJvNaWu32lYg5jIR6G7ungdr
         tmQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712048872; x=1712653672;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yas60sHKkZRL/nVDSeCh23hfzUuTaTysVp1x5lnG44w=;
        b=uzvYVdxaD7Ypj6oYUyN3H8tPgZWKIgRPfm/crq4fNYPVnVu67kZwJhtbjgOdt8qKQ6
         +yx91APAyS40Hdia59oBZ0UvZf7l4oTsLAPdmfuvricLfOKPL6W57VjIWPzcbMuN2l1T
         0lb1EwZWyhDsJhEPia7hUgP505pgv+bQ+Wr7mqeqxdW2XgffdCex+gVw6Z48bdEOqykv
         88FIha8gvl9u55BNHSRPNyl9dTHq4iaP25IeuQA9hjE2KOPAmCejVlGDapToUfCPpNoC
         0dZLsbXSbUsEAj0YZCbQOZTanFLD9lD1Raa4bQUgpTSmFRGShJ3rdCOmxVUFx4fv867k
         qBeg==
X-Forwarded-Encrypted: i=2; AJvYcCX3Yp1eymeDJqv9suOCvKiWQUbnF8P26Xl4vgGZzaVs0VbuIh4DiHEgaY14fLx91L23KYmQOzSI8qMuMSPLqqsO3CeJ+Plvqw==
X-Gm-Message-State: AOJu0YxGD2knntZucaAKaQSzGY5p+WFQ7ZYVeNXduokkpgmdUfx5I5wp
	nfibDBKD+QwkatNfWCrYFTXNDkBoobXlDTwsqDFKeYcpyzH2uO8u
X-Google-Smtp-Source: AGHT+IG5IU0irVAjG7XC7RtQrDsnPyMk4cd7TD9At1J/A08MbPsQArv5Bk1s13ZoPNJ/YVrhsIzk8Q==
X-Received: by 2002:ac2:514a:0:b0:515:c9a5:6abe with SMTP id q10-20020ac2514a000000b00515c9a56abemr6514345lfd.40.1712048871302;
        Tue, 02 Apr 2024 02:07:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac8:b0:513:5f27:9a68 with SMTP id
 n8-20020a0565120ac800b005135f279a68ls452713lfu.2.-pod-prod-09-eu; Tue, 02 Apr
 2024 02:07:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhlrflMUOYzjtwBzeOWZKWUyflP2GW+YjILmEHKGKdBfKPUs8hy4OtGULzPyGsh/BQmTQ0/ml5dVIuzk1D6E29C8GxdtmbThH3rg==
X-Received: by 2002:a05:6512:3d27:b0:516:9f03:6a9a with SMTP id d39-20020a0565123d2700b005169f036a9amr6433505lfv.25.1712048869035;
        Tue, 02 Apr 2024 02:07:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712048869; cv=none;
        d=google.com; s=arc-20160816;
        b=ACyfnVNUjgWsFqbQ2ZCi/SlpHT7Qv6df7vAyolSAikccrNJXgV+MKQ/oDT53s16DxB
         zle0ESbW6OpuzyvwcsYsoYwIgBtorHQH2ytvrMvme4M/DFh44FIo0cpgztAn+m3jKSYm
         Fwd5BNnd/a3EQvawIkihfy30vB3AlupYn4To+XDHVa9niD46MSvfoHUNxIgafJeWNepu
         7HQMy3AQlJnE9IO4jl/2hi41Sxm+wZ3QD7fwsFyDbVadk3MmlczqzZPUWgYny12e4Vgn
         6AELr1DmA0XInp84HrT0Y+VpUtr7jvahw7/Be1KdU6a4rLuYbEWz0WjgxCjEsmOFD4Xz
         7CUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Gj2lIs7j0qMeOLAI9CgIcyOVJL5/QjEQamjTy+gS40c=;
        fh=+s/U7zLdAazuFQDP1AT60Lb47IMypIdfAk/+l5hkxmk=;
        b=X3dVIlhK4+WxKjR75orGlrfSbuWBN3xzoG/AVS5S9x2ZDv/bW3pbHxc1otifk/73PP
         XRZ6yLUTnOPUGjuvH01012mC+geSsfZ3J7n5UIOLOdkIBAyy4CAxMeilLTz/Kd6GWVSI
         SAk1tqqDkDvGC9aapEDznKRnMplU/GBW50URFjJq4b72kPTjRMuL4r0URZqL4/UQ4mv5
         KuqwszvaeNGyjQht6lj22+sJZXtKJtGbPNuIRhD9glW8HKwqByu0RJY8vKKRZcAh+isz
         Nz51lmeor5U5eRtkQI71n2LPB464BKMdJHxz+Z4qrI1+riYhKiNj/xt0wDWhB+Ks11mD
         GWoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LIp8AlaL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id i6-20020a0565123e0600b00515d3383bfesi238899lfv.0.2024.04.02.02.07.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Apr 2024 02:07:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id 4fb4d7f45d1cf-56c2cfdd728so43472a12.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Apr 2024 02:07:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXlnTWDZgq7JadcxUESdVnphKLuHJDVE1mH+153W4YE7pxYmZcymVNenMktlMMheqnGQf3AY0wy1MZvHivEqPsY1UzDCxiHAbGPLA==
X-Received: by 2002:a05:6402:5253:b0:56d:eeb0:c76e with SMTP id
 t19-20020a056402525300b0056deeb0c76emr60307edd.7.1712048868331; Tue, 02 Apr
 2024 02:07:48 -0700 (PDT)
MIME-Version: 1.0
References: <20230316123028.2890338-1-elver@google.com> <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
In-Reply-To: <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Apr 2024 11:07:32 +0200
Message-ID: <CACT4Y+a6E8wg3PZhG_AoZtZwozhqUC+LPgMV3G_gQZXkr1rGzw@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: John Stultz <jstultz@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LIp8AlaL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 1 Apr 2024 at 22:17, John Stultz <jstultz@google.com> wrote:
>
> On Thu, Mar 16, 2023 at 5:30=E2=80=AFAM Marco Elver <elver@google.com> wr=
ote:
> >
> > From: Dmitry Vyukov <dvyukov@google.com>
> >
> > POSIX timers using the CLOCK_PROCESS_CPUTIME_ID clock prefer the main
> > thread of a thread group for signal delivery.     However, this has a
> > significant downside: it requires waking up a potentially idle thread.
> >
> > Instead, prefer to deliver signals to the current thread (in the same
> > thread group) if SIGEV_THREAD_ID is not set by the user. This does not
> > change guaranteed semantics, since POSIX process CPU time timers have
> > never guaranteed that signal delivery is to a specific thread (without
> > SIGEV_THREAD_ID set).
> >
> > The effect is that we no longer wake up potentially idle threads, and
> > the kernel is no longer biased towards delivering the timer signal to
> > any particular thread (which better distributes the timer signals esp.
> > when multiple timers fire concurrently).
> >
> > Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> > Suggested-by: Oleg Nesterov <oleg@redhat.com>
> > Reviewed-by: Oleg Nesterov <oleg@redhat.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Apologies for drudging up this old thread.
>
> I wanted to ask if anyone had objections to including this in the -stable=
 trees?
>
> After this and the follow-on patch e797203fb3ba
> ("selftests/timers/posix_timers: Test delivery of signals across
> threads") landed, folks testing older kernels with the latest
> selftests started to see the new test checking for this behavior to
> stall.  Thomas did submit an adjustment to the test here to avoid the
> stall: https://lore.kernel.org/lkml/20230606142031.071059989@linutronix.d=
e/,
> but it didn't seem to land, however that would just result in the test
> failing instead of hanging.
>
> This change does seem to cherry-pick cleanly back to at least
> stable/linux-5.10.y cleanly, so it looks simple to pull this change
> back. But I wanted to make sure there wasn't anything subtle I was
> missing before sending patches.

I don't have objections per se. But I wonder how other tests deal with
such situations. It should happen for any test for new functionality.
Can we do the same other tests are doing?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Ba6E8wg3PZhG_AoZtZwozhqUC%2BLPgMV3G_gQZXkr1rGzw%40mail.gm=
ail.com.
