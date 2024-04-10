Return-Path: <kasan-dev+bncBDQ6ZAEPEQIOVIO4WADBUBCNTYYHG@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DC79D8A0339
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 00:21:31 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-343e74dcf0bsf2849044f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 15:21:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712787691; cv=pass;
        d=google.com; s=arc-20160816;
        b=odT0RpxC6ebO+e9CYEBOtcvGV/mUDumMLk9yrmyykFkhnjXB2BEFGe4+X/nHRl2UuN
         I24uHWPx8vtQaFl4JRsaOYp2H2O2l/mjPpNa8/x+OWxJT1umy7QUgSbqIELx3JXhmNVB
         g/QL2ZEOuFon/1/WgBtxZf0m8FmtCta5LICOTw6Z/VlDvXjzilipdnmxeRKijGuvoX3V
         S1RQWXJzKVHSNirqk/cR8xjaeGBRa9jeg9EghXB6uuR14/F5jLvr81ps3w7+zPgGNqiH
         2fm1TPT0+0YBvZs0OSxSROYDeXDuwboTU+zQ0ZhQwxAg3XPumRc1byEO+Bs7sN3qT59J
         j/lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q0TZWmvzALVcRtoHHNrFULTzUBVWSA0CPPcwmM9x7mE=;
        fh=zXufKzyVIQTPEPpJG7j3fgJU/vn8CDrMHAdPzp7cKbQ=;
        b=Z1BcoMoffwas4RnXS1/zuJ/DXRa99xUoSgY4JJVmFZnixZgqivFPNg+UV7ifVqsVZ8
         wKkood6kh4jSbkGkp612spQbWVUGlG43A7wBn+z1lXtPjnsh6O7/DLYH6Ncl61gT4YN2
         bnR8f9z46AEGgw1HxWuZfSOOwIp7dl3S2YpWBCcSG2Y4IpimKOCM4e8TWZLfkPh+WiWt
         kR2IXlEP8he1/8fG+PYG9kHm6Z6nUu1m5vnE/y4+qKGrPkKkeaD2fiKwCyvzQ6ToDEai
         pKjGOa2SYK6/MHBpwpV2zVh81//Ych2BnbU2fH8Fm2C+lE8/Ruag2RLoo4POBaXHUyu2
         hG6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Z5Mvj4om;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712787691; x=1713392491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q0TZWmvzALVcRtoHHNrFULTzUBVWSA0CPPcwmM9x7mE=;
        b=rxYCyfFLEqQM4oRXmJqiU6bl6iblNOO6KhCFTFWKB2mh1OQLPsl018vskVmGZuy4lY
         NfT5e9QGR3Gb4Q1LVzUlxxkqtaLYlLCEbRVkWpjmq7FWQVFy7GRTR5BlYaINjnSFXB4W
         9GxQxG3vWkkpI8ofFfQOhg12qkDUA9l0Q8varjn8O30zNNMi1DEp1BxP72eEjf5ugF2Q
         cE9JVLBIN8jCxSuVYxizYQq3tlN22pdbMvcde8BMZk684V8zPcMFna2UsCu/YuFfSg2D
         i5tZXgdwMHgmhqcQeltbKFzGfPxPY522u6D58KYK8Iuob/JPElA3FNgRMnwnPm8KrhHq
         WXRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712787691; x=1713392491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Q0TZWmvzALVcRtoHHNrFULTzUBVWSA0CPPcwmM9x7mE=;
        b=V4LOP4BJ3w3xKHqXKFScMRxkBtNRjD3NLilNOvz9Qk6Yx/RXIa/j8AmAGgeQGHDlAD
         Uk9qWdx3PGZKSMIYBAjlXij7zgllSNlhlp+J0oe81ERTm0gl3ccnENcOdM/i6z0o2mwi
         u1bK52TEcPlVV+D0kaOz+QWA5iadGTP4Ju1sFb/2s53ytXJOUjj+ycAqEKfmQccM5u/a
         x4XRCcmXNsQsjDwFcBRkvBzSRiuNI6/x+RFeuMcN3WLhce/WeMuabKlIIUHkpd4Uwhim
         rx9BJMikmrdn+tEfudxZzQkLQL1LQhFioARABv7QV5HVV0qhkrL+q+6LB8fHM+C+bIOW
         kudw==
X-Forwarded-Encrypted: i=2; AJvYcCVZASVbX3lYeVsXYIxGCpy161myY+pCj0svWL51jOdgba41Bv98orv5SBGhA5Y3rsLEwd/IVaaAHoY5PE36ZEEPY0Uzvhm5jA==
X-Gm-Message-State: AOJu0YwJrcTwQR+kapFLQutQRKYowCNFlHWn4Gh6weou3dj4f/lnT/bg
	lLYwr2K/qjlqrAkaxO1LJXeTPVD8tjQjF4JwbK0Nx+SvStpdcOpe
X-Google-Smtp-Source: AGHT+IHO8O08bL/AqpNmch3BUKDTr2ga1QOIbm8UPgNgXcHwrjT0Qi72PfPpvWIgPLpy3UMHCScBEg==
X-Received: by 2002:a05:6000:2ad:b0:343:d35d:71d with SMTP id l13-20020a05600002ad00b00343d35d071dmr3106235wry.8.1712787690844;
        Wed, 10 Apr 2024 15:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:452d:0:b0:343:95b6:d75b with SMTP id j13-20020a5d452d000000b0034395b6d75bls2362792wra.0.-pod-prod-03-eu;
 Wed, 10 Apr 2024 15:21:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8F6wmV1fAmJNj1yyCXLnNo7OBx7lamd+Y4RqsiWfLMUM4EgRSfX7CVYeX5JdDzYdC20JjjBSH58nsufiVdCMqr4foTHwM2ZumNg==
X-Received: by 2002:a05:600c:54ee:b0:416:7500:31ae with SMTP id jb14-20020a05600c54ee00b00416750031aemr2622830wmb.15.1712787688820;
        Wed, 10 Apr 2024 15:21:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712787688; cv=none;
        d=google.com; s=arc-20160816;
        b=Vny0m7d4oeTW1JmAWplypGUCkMWkJH2b6TNJL6TBc4eso8YeIrAAsgv6Pqv6Dx8T/O
         tMaDV4syHzio8CIYlyM5rd3ygUQ4iFzRaX5ddTKGE+ta/mivjO4QC8DfscnIFPFTGeBo
         +J8NFuq/U1Dh33+i3akZ7C7O8K8gSloNR/eYtS0WTyNyGXBih2/nFIsOVssGdCULBsnx
         shl0qz/Z920s0+fOW+BD5Nu6iklLqmB+I87+kEg/cVEJbJshanX9GIqWdfwjpgsVclwA
         zIoiaXDwE3SK0jyoIwo9TT42UFaudpeNmVRPbqxiNyqbBJTtEOKU4wY2S6RK+6wZUlsr
         dRGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lH57B4VEUrPyB0pxiA08g9XOpVRgWubVTw/7AXbFYeE=;
        fh=E6hI7CjqQJIbjhvOPoLHtEC97rEkY5yIeG5u18OEhJk=;
        b=kPU6J0/w+gCahYqNMFOC1I5vCNQjRGGy7oZrf4kxgVjCIKyItB2rv4L1e6+OMQ4O6O
         myDylBPk09AgymwwxO4KhFKUrurkghfIW1DP2p/B2M0ZbtebpzksrrKJg04FeOC0q/JF
         HUvJHXZ/q7qAoZnmtpQQYA7eZ7o9mXf3WgfJ+4jO9rp1qFhCcB3VC9o2FavPpT/gvhQg
         Gh3bdiVXYRVuLVLeNEdGAVMAaL/tXU0QvukPGVoH0nFvzP9Hm0u6kwqZFj1w2qUW3Vq9
         agFTXFV6AN5SKKaLnAGiXmN+byubB40x4vKbKiucZFUplnSg+mnUjvsB7cJ66rtlhImg
         P/8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Z5Mvj4om;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id t6-20020a05600c328600b00417bd5d5484si180094wmp.1.2024.04.10.15.21.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Apr 2024 15:21:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-41699bbfb91so15315e9.0
        for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 15:21:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUm4xdnfArJVWkvkNsqYJuSTwzrr3BDTJnZApqns/iP21dOEyz2+Vu0oJ8mTZlGpBfsI+vfYKqm2O2mBkBrD2+uHoL4cM3IuyaO4w==
X-Received: by 2002:a05:600c:1d1a:b0:416:7385:b675 with SMTP id
 l26-20020a05600c1d1a00b004167385b675mr24064wms.7.1712787688267; Wed, 10 Apr
 2024 15:21:28 -0700 (PDT)
MIME-Version: 1.0
References: <20240404145408.GD7153@redhat.com> <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com> <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com> <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx> <20240409111051.GB29396@redhat.com> <877ch67nhb.ffs@tglx>
 <20240409133802.GD29396@redhat.com>
In-Reply-To: <20240409133802.GD29396@redhat.com>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Apr 2024 15:21:15 -0700
Message-ID: <CANDhNCrverCP+nB53XnMKFH4sTvxmtchiLWyGbNW6du=8xOSNg@mail.gmail.com>
Subject: Re: [PATCH v2] selftests/timers/posix_timers: reimplement check_timer_distribution()
To: Oleg Nesterov <oleg@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Z5Mvj4om;       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=jstultz@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: John Stultz <jstultz@google.com>
Reply-To: John Stultz <jstultz@google.com>
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

On Tue, Apr 9, 2024 at 6:39=E2=80=AFAM Oleg Nesterov <oleg@redhat.com> wrot=
e:
>
> Thomas says:
>
>         The signal distribution test has a tendency to hang for a long
>         time as the signal delivery is not really evenly distributed. In
>         fact it might never be distributed across all threads ever in
>         the way it is written.
>
> To me even the
>
>         This primarily tests that the kernel does not favour any one.
>
> comment doesn't look right. The kernel does favour a thread which hits
> the timer interrupt when CLOCK_PROCESS_CPUTIME_ID expires.
>
> The new version simply checks that the group leader sleeping in join()
> never receives SIGALRM, cpu_timer_fire() should always send the signal
> to the thread which burns cpu.
>
> Without the commit bcb7ee79029d ("posix-timers: Prefer delivery of signal=
s
> to the current thread") the test-case fails immediately, the very 1st tic=
k
> wakes the leader up. Otherwise it quickly succeeds after 100 ticks.
>
> As Thomas suggested, the new version doesn't report the failure on the
> pre v6.3 kernels that do not have the commit bcb7ee79029d; this is a
> feature that obviously fails on the older kernels. So the patch adds the
> new simple ksft_ck_kernel_version() helper and uses ksft_test_result_skip=
()
> if check_timer_distribution() fails on the older kernel.
>
> Signed-off-by: Oleg Nesterov <oleg@redhat.com>

This is working great here (on both 6.6 and the older 6.1)! Thanks so
much for fixing this!
One nit below, but otherwise:
  Tested-by: John Stultz <jstultz@google.com>

> +err:
> +       ksft_print_msg(errmsg);

This bit is causing the following warning:
posix_timers.c:250:2: warning: format not a string literal and no
format arguments [-Wformat-security]
  250 |  ksft_print_msg(errmsg);
      |  ^~~~~~~~~~~~~~

A simple fix is just to switch it to:
  ksft_print_msg("%s", errmsg);

thanks
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCrverCP%2BnB53XnMKFH4sTvxmtchiLWyGbNW6du%3D8xOSNg%40mail.gm=
ail.com.
