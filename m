Return-Path: <kasan-dev+bncBDAMN6NI5EERBW5G3SYAMGQE3LLVP3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E65328A0366
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 00:31:56 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-516d6c879c5sf2803991e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 15:31:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712788316; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqCTx5k3T4LCCTmdjbat8InkwcJAq/ZeK1dKRMMOQi19VrdFTTpWLFRdzUvNdMYpL/
         nShEk2lLoxHG4rn48N4QwnfOUbKwYUsGJEw72EeePlrsS6CyBjBVDRT83pCwIxmlTStW
         ZYYZ0ZAfb2Ds9vTMmZMuCTVrFxB4xoY0Q7hmpTTgmHxMelzGPGmSyAlzeHiHORZm8WsP
         P3h3gszHtGklStSdFFof1X4qZsz2Ar8mAUjIAEn44vfilMnVULevVD8ZLjBSxcExbGPM
         GArMaUnsytUv9W7W1KtXqQYBS+eE1nfLb0CDDLnDxsL23cSUviRwuFfGkFb/rsg/gJge
         YaUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=GlvP95z3AdNOJF5rzDQri3hfpvwkhN2CO9IfPHNCa6k=;
        fh=uXivG+Zfjv1PeUQh3HYH6tN6a1R8OtkZ0Otnc4Qjlhg=;
        b=i1zP2HpnXmeOordfvfkGfc1u0v4loB7oooH7CEaBTQTOmTcQinGt+YIG4N/6WCCK0O
         pdEf0k+Bx7nBZm3iYHLhNOReQESu8ITN03Hn3SmjTwEKckJ25adoM36P1CZPP+GTZIXj
         /HWBKYBdkf5c8kP9CElZwv4BXPz5HGiDGaBi3JQOlVcMi8Uv3TxB/CCSs+Iy+KgTh/G1
         F1P6tgGNMOiPJdYhOMrEIUyIg/qFEmNGomJrArdY5hAf4njv3R7XybitAe8Qw5NUUBw+
         uQW3cwDvcF//1l3uL/t/A4Ja6U8e226pdB3LA2bhDhWdgmrdKTIRts5LKJ6atxrx5bIw
         b8Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=0qpQ9mYn;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712788316; x=1713393116; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GlvP95z3AdNOJF5rzDQri3hfpvwkhN2CO9IfPHNCa6k=;
        b=UAFavn24KvvCkqJBp0nJ6hx0IgN4IMt7yxMeVWdQ1FSey7uKwdHYg3RXWx7DuvDApH
         hEqhFTzPCMN712bgnScYa1eiPBAM+ioBRCRHh2SFolNnjRsNBV5oZFtjMdI/VOs0TUQa
         4sBbFKiGoqu0us+JIXRc425wmUj9oHLsUNKkXz4ig2bvJxJui/u2JVAAMhoSoUhE/LKW
         yX068J0u5kPSC7r2HkwG9+l1wtSP8xHYnpeQK5/Eg72ZY0J0rFsCxOUDbQ9w9RK/oGRs
         GYq7d1xhmZExtUklldsEBQvZ7/gE5pHsKJPZZS8fhvkFKkE00iisUC45/oJWw/an9c6J
         ED4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712788316; x=1713393116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GlvP95z3AdNOJF5rzDQri3hfpvwkhN2CO9IfPHNCa6k=;
        b=nqySUu2usId4NQWLKDxP5EQHNfRl7cd+TO/z3NXHiKE7Ahz5DzuUcDg4DXK/Fbeaoz
         vyrniKIWUUb6eeWe4cSxu/+xEJ4mW3jN5GYJX+h5kFMV3YVVt0eeE5QloMwHi2pa1HtH
         3nrUxe3az/LHFjMjrRA6EgNxR8F4NS+shKdBiYP/KUvt/2Zg4PfUHPcRtFjbjmVrQm0k
         Y5XtoQbxGl2mq3ID3SioPkXrW5EY1mmrTR2nrxEKxSP6JYgSFgz/desr2ZcmYM0bqhPx
         CiWwzGUT9XEsnVtj0uFgymJvMgG008FaGnJe/d4zFjskQfxAlyx9PeNaTMWAQCp+FqUB
         odyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuEzfGY6O4DUn7TlvVeY3+Lm0IdyCez77SU5KEhb9hHF8VCaY8hNbqD8cooiKOWXWJE35xnlAITbhcPAbhaQ0X211Ss7MBKQ==
X-Gm-Message-State: AOJu0YwAxErE5oYyRrJ7OE7Ns371OSPhrmkV4GTNRLMBwt05eINVuhc1
	eSZEy6dPdNZ9XckS8MAIeFC4U8Ww4VK9t57RDSqpV9TQtllNgege
X-Google-Smtp-Source: AGHT+IGw8+kgEp27ZUe/DFWm8k6BqG8PEM3mbdkazapm0lG/3DpCXFilNIVm4q32k0aj9udzd6LSsg==
X-Received: by 2002:a05:6512:249:b0:516:d440:f303 with SMTP id b9-20020a056512024900b00516d440f303mr2832245lfo.24.1712788315775;
        Wed, 10 Apr 2024 15:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4475:0:b0:516:d667:808a with SMTP id y21-20020ac24475000000b00516d667808als1142675lfl.0.-pod-prod-07-eu;
 Wed, 10 Apr 2024 15:31:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxIaEKsyteqoUIczMqZZTje1IJvYPO9cnIEx8AiNdc4/pkdIeHXKbyrcPMpGO/7EVaMri4uCpD5rap5Hl4oskPjpvo46m2eUrT5Q==
X-Received: by 2002:a05:6512:33cb:b0:517:854e:2c91 with SMTP id d11-20020a05651233cb00b00517854e2c91mr1240233lfg.64.1712788313663;
        Wed, 10 Apr 2024 15:31:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712788313; cv=none;
        d=google.com; s=arc-20160816;
        b=S13UaI0sfe8Dn4FD4Bq3+7zOmjp4G2hGqVcjExJkw3vXmx55rkfPCkvBbYl6Qet2PF
         iLg7uiCLaecMa0fw4nGh+KEK4vyr6ZRDZ0gQEs5Mhz9KdYkQSouR+G9wJ7PGOjvqlpQL
         DltpFtdpFrhfj3hLFFa2zKbVf8phkW0yAzazDIpDxRahwEHZgBnZ213taK9Z4V61P43v
         EzGYlkkZf3xZrYjdD5gUK7RKIxIa2ICOxoimjzn1o6mU5xxvWRiVSWoGqo6XClmW1ad7
         cV9hNBdsJu4iEOH1nQI4jkO8OK9oZU5Wt90/V5DVl33OvJsBoZfaFOXjUnHNQPuIyFrj
         ItQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=JiCIrEt1XaB7glCHGKWy0bvbFt+bdOBFG+aYBovTWNY=;
        fh=hD+W1aAmzbULjc49TAo07a5Nb9fd2TGL8NPtj56k8sM=;
        b=pnn6Tb6+xRhf2niE4yCBl5o6CAJwZvmSk+ZGEnTmsCGrcucHqumwx0EaRP0jHsWnnZ
         pOTKY4WutO1XaNaibDMD3VGa7OVvZNODXQNBgqw6+iqjONJ6mdOCvUsExqVtnKeBTkIu
         bWTUsJnyTsCxjrP6H4htRKYpNoZdOCybJ/IIqFI9osQyRxLPDW+3HX7d5jVh0Yk3yjeA
         tAjMQv58njDbxRJqu22M4w8elHDmjcpyRaXUdcwSs7rtetRPGsbt4bTwkTj4BKXAy6oI
         36IKyyY8EoYg6cXVNGkTA0g32d/qjito3IGNheb4oCw+o83M3VhA30sBoK7Cr6RNdFSK
         I0YQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=0qpQ9mYn;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id dx5-20020a0565122c0500b00515d3383bfesi7835lfb.0.2024.04.10.15.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 15:31:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: John Stultz <jstultz@google.com>, Oleg Nesterov <oleg@redhat.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
 Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>,
 "Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, Edward Liaw
 <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v2] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
In-Reply-To: <CANDhNCrverCP+nB53XnMKFH4sTvxmtchiLWyGbNW6du=8xOSNg@mail.gmail.com>
References: <20240404145408.GD7153@redhat.com> <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com> <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com> <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx> <20240409111051.GB29396@redhat.com>
 <877ch67nhb.ffs@tglx> <20240409133802.GD29396@redhat.com>
 <CANDhNCrverCP+nB53XnMKFH4sTvxmtchiLWyGbNW6du=8xOSNg@mail.gmail.com>
Date: Thu, 11 Apr 2024 00:31:52 +0200
Message-ID: <871q7c3l47.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=0qpQ9mYn;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Wed, Apr 10 2024 at 15:21, John Stultz wrote:
> On Tue, Apr 9, 2024 at 6:39=E2=80=AFAM Oleg Nesterov <oleg@redhat.com> wr=
ote:
> This is working great here (on both 6.6 and the older 6.1)! Thanks so
> much for fixing this!
> One nit below, but otherwise:
>   Tested-by: John Stultz <jstultz@google.com>
>
>> +err:
>> +       ksft_print_msg(errmsg);
>
> This bit is causing the following warning:
> posix_timers.c:250:2: warning: format not a string literal and no
> format arguments [-Wformat-security]
>   250 |  ksft_print_msg(errmsg);
>       |  ^~~~~~~~~~~~~~
>
> A simple fix is just to switch it to:
>   ksft_print_msg("%s", errmsg);

Can you please send a delta patch against tip timers/urgent?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/871q7c3l47.ffs%40tglx.
