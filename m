Return-Path: <kasan-dev+bncBDAMN6NI5EERB5OYWXXAKGQEY3EMPSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB14DFC96A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 16:02:13 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id u14sf2059516lfk.7
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 07:02:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573743733; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cjuq4M8mfCjqIMGUWio2/8X9+nSAhyscdC6XPteRh+ARTGFfZA3/WE9csXV/4g4lx4
         qg3oenX6FErjLFxokIZ6m4d1ex71CpKLubIrvqyDxWszI2dmRMDEBDlViN+pfECGiT01
         4PW1VzqTJ5Wn0hsvDoomtPYdkZfeFaB2EtCgfgnK8B4vJ76yT8uptI4FsAZNTqxLh696
         4buSpZB7S7g7O9pQaTIAcAySSODS+a1sKH7+A/QGYuQIG2i9ZD+dIuUJrEmhxTDSPdAt
         ZiJ/en5BsS1MIJv4KbxGMXIGQePTm1/OrwuRvBUTQguYMuhA4ZavGuYkI/rwS1Fmw69Q
         CS3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RnODtK7Cs/GVEpbOIdMqCItJ8rUj2ShkpdGY9cXcjMo=;
        b=YfblLJkfXApUXzUtvg+6jEHVKW7fj4HRN3OQC1tAzxbBG8OI68PgJl2/uEjCcqKUaS
         RG7YSJye1kVF9XMEmEs85dns14DHZrd+I8VlmCvc6XuYIvErCp+XUeqfXWov+h9k58YO
         KzX2mpNJx6VQptd+u//CDiv52pSv4Q9Tti7A3DPtSvBxJ4v0PObIWAkhMmBUAFxsscoO
         fGTRQ+7LffyzoFzSr4v2OsJVzAJQemw562SwKxHiH+3rJsyNRNCT3TOL09ZPgxz17x9G
         B9r7ZEtOCxFIIBfhyNxLsMVNbWYAIodnh1+ybOhcaaMzCmLjkflSlAEOrE5fkJIM3Yh0
         xTOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RnODtK7Cs/GVEpbOIdMqCItJ8rUj2ShkpdGY9cXcjMo=;
        b=WJcOVy1HVmvj8Z/bHoKOj72QX60HAwkfJYDwDVmJufyPTJgzy8urAcJ6L4u6tPQDvz
         IbQumoG3+PTj6L/zRBaGRojcP0PTIWqjIkzliF9qgvylR7GBxwh83HKcXu/1A1KAdCdM
         DxxVLiErvEyAncdvoE0n4Cj6zpOMDS0veQE86Ij7SIWUwL50fSveQbdzmoZXYyaiXA66
         f7sMLF+RQnAJlzrOXCZJEhyaEhHVV8b8Yh0o71s8xzmUjP+kek8ir3YKTiw4OmWwrw+g
         YShJHbedr6cFIE7dsZ+V95z9Eo4bg+A897bBAEFzl/9x0d4EzBveE4XpsGg4Hv7f3VAS
         SXJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RnODtK7Cs/GVEpbOIdMqCItJ8rUj2ShkpdGY9cXcjMo=;
        b=gsx1FV9npCJNVQwORd9qZ0+scpBcLsVkPt2zbRjBj4KmWhfRbMHAoed72infZ/l6sW
         JUtrQGGfWfmPcpq6z48u0EKYiQ19312Z4Erlh8N1SEI0HJOQVcGpLqOz27qoqA7TgnO3
         44AG6T3DILJtuRdOvHNweDtWblS1y70JsX0Wm9JvatCeASB1DOfCTh+eD5mOGOC0AWfi
         2S/Y/z1w01GzmwHPa0H1OSUYYSGMv4/DbzH55s2i3YR7nBOVuFIdpxEnv6F3e1GmSo9m
         9sSWeK9XT5U3a5SNn/8k/gMbqEXd9JvzS83ZZykg0AFJMnDj/AlSBhntSlSt6orvuyga
         5Nbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXX0lNC3OmX7y+FLgHRCTBHaqMiYULoHRK7p4mlD7A4x3AEJLIC
	zMU2s61D3OjxbbTEpSevypg=
X-Google-Smtp-Source: APXvYqyEOPmQ7nZeQa/ARZ9WrIbAEslgHL6jypUd6eh0u5HrIDJJFFzSK+wBebpXHfmNI/cKMTC6iQ==
X-Received: by 2002:ac2:5f0a:: with SMTP id 10mr7094728lfq.57.1573743733536;
        Thu, 14 Nov 2019 07:02:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:289:: with SMTP id b9ls1250527ljo.10.gmail; Thu, 14
 Nov 2019 07:02:12 -0800 (PST)
X-Received: by 2002:a2e:2c1a:: with SMTP id s26mr3982632ljs.239.1573743732905;
        Thu, 14 Nov 2019 07:02:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573743732; cv=none;
        d=google.com; s=arc-20160816;
        b=nKWx6LhjMIxb30RDvzmm/S5OVnKK8ptcGi7SX3EnKIh3YpgywUsJhAuTuElhCXKb6J
         EPQvPDWyrb8c9LHSYXZSN/vPfwASGXfq9OzOyIGfrXGe/VCIaBFly/QshTw9H0gXRZJN
         A4RiUJGPdBQIfD5BVw8SRBpbfHUjwN6xQJylGnhpQGcC9EWJY4WXKVUlgNVVL3bPHtSz
         CZo2RqZkATOvgY29GNgF5tGgCcdqQpE6qWQkXk5SVGW1LXzn4IEvZ66bt/hLwZNYVQkf
         RoZV8BcNftgGnSi6nDWfSwvFzulmQPsEgt7DK+XeeFvWn6oUm/glVOucHCiAWtSs+OgJ
         S3bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date;
        bh=AglqcYYRLDCsCzp6kPuS4sck8i1uT4N/JciepFhF34s=;
        b=Fxc57UHboxWISplzagC+J7Obtbsq2mXHvleEBkvYfilcqwvCSE5dP35drvj4FIj0dg
         D4qlmPUPlKs7ZK6tJ9BvVqNibBIzoka8mLbE3puADORGeifCDwpzW89B/mwM4KjDrcFl
         Pwzj8uvYS1ZH9sON7ufbICeK0sDTkIH4bnZyaG9XJUD7tkM787m0KJvV6Ad2yY9LMdSe
         6GXSw1Y8KeqrAb75QlL1rIV0sAy0mTnREc6Cjw5OAAFsdpWp2b+Fv7+nCIuwa+NZzJYN
         Wel0tK8BppeavZZ8MC18sXyTn6/80QCYvIU2SRFAttANXrnB8Bcv0T/koac0I3QTNL8H
         xHmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id v82si280827lfa.3.2019.11.14.07.02.12
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Thu, 14 Nov 2019 07:02:12 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from [5.158.153.52] (helo=nanos.tec.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tglx@linutronix.de>)
	id 1iVGdN-0004oF-IU; Thu, 14 Nov 2019 16:02:09 +0100
Date: Thu, 14 Nov 2019 16:02:09 +0100 (CET)
From: Thomas Gleixner <tglx@linutronix.de>
To: Dmitry Vyukov <dvyukov@google.com>
cc: syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
    John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
    sboyd@kernel.org, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
    the arch/x86 maintainers <x86@kernel.org>, 
    kasan-dev <kasan-dev@googlegroups.com>, Jann Horn <jannh@google.com>
Subject: Re: linux-next boot error: general protection fault in
 __x64_sys_settimeofday
In-Reply-To: <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
Message-ID: <alpine.DEB.2.21.1911141601040.2507@nanos.tec.linutronix.de>
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de> <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
User-Agent: Alpine 2.21 (DEB 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
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

On Thu, 14 Nov 2019, Dmitry Vyukov wrote:
> On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> 
> Looks like a plain user memory access:
> 
> SYSCALL_DEFINE2(settimeofday, struct __kernel_old_timeval __user *, tv,
> struct timezone __user *, tz)
> {
> ....
> if (tv->tv_usec > USEC_PER_SEC)  // <==== HERE
> return -EINVAL;

Bah, I looked at a stale next ....

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.1911141601040.2507%40nanos.tec.linutronix.de.
