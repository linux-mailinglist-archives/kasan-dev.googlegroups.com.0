Return-Path: <kasan-dev+bncBDL4HU7KXIMRBLFV4WXAMGQEZ4LJYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 978A2862263
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 03:55:41 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40e53200380sf9315645e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 18:55:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708743341; cv=pass;
        d=google.com; s=arc-20160816;
        b=SXGsRrTwYT3VjiY6qTseIlkwOWmJe6+oJH+MPZVBa2VTUswGFw3spH/fybEu+qUM3S
         Yxf1YWczwBZrCNbuFEX1fm+5JX7OWtE6PKlFX55YkhByGvmqZIXMJ3GZIRhvV35/UCxi
         J0I67U4pjMFr3wQE6QVFPDH4SU8QK03REvwQec0xRYt4WlCSjJYCzf1BfqSSC/7lyRnp
         +j3bgrtV/bUZr+V93b9qBpw0y+KSNatD2MC1u1uqEsy8jZJiCgDkBWqGwrZFIa0kujXr
         7ajqVFtwRlUEZhS8Hi7UyvJbWCf+nH4EAcdQQve7rsDE7YoQdBdMaTvKYw48PphKAWTv
         A7Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2X5izx8Fkh6a3x5wjpxoaQnYAvZeIPY6r2nEwtLi6bQ=;
        fh=R5DChMvS5YhdZN8E/wNkoaGL4mFD2Yfk2b3aHlaibWY=;
        b=m5uh+P4Nh0dQ3I5Kt80bmeoINbYeXXjqi3fFWPCYSzFCzlGhGncYQx2yAQUqglQn76
         jl3kx9uWDdhKhqdwP/rzt7DjoUDfzv0jd1OJLEnmJfRTUBfzz0MvAVyrhXV/nyUXMnwI
         Xv10CyTMZq2p9Hlck7DxFxdmP3vnK2I36Hp3oa9ZgiyOy3nwm22m7IBA7g5Z+aisXuHe
         IF1D3j5hnbpyXhX5QysoqQWVoZ9rL0mZWBehfjomdaSkh0yk4zTDSxTcTheSXU2YF00b
         kQ7QY8zhg8DoUDgfaVKVl/eypsxhEBF2OXrFpvejWT+vE691p/RsF/+VA0yd4ZA3bMIA
         Snnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VpU7Fl85;
       spf=pass (google.com: domain of neeraj.iitr10@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=neeraj.iitr10@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708743341; x=1709348141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2X5izx8Fkh6a3x5wjpxoaQnYAvZeIPY6r2nEwtLi6bQ=;
        b=bK1uyjmM8Wh6Wge2o/2HUwvdgXinsOuPqZfamfhI5ASNF053OecoQc2cQUtfBnj12a
         TWeZ4LAPNDTKpVwRwVC3m2e05wEptUU82hMQ6bLtKihd30lRhZt4ZbX530MrDFYaPwCB
         a2A1gq+j0iFktEB9NNxIWqdhh3t1Z2QYnLWtpBXZv3YSBsMAIdePlMZn59c5m13QEszr
         YyySDX+j3XS2m8UrlQQApnFSVdaumABWHcrVbKpzwqUw/VEV8CExGrFxTHV8xlNe9t+r
         WQ2mgRe5QHjBGCizuOQD0OlP5iu/F4um6AXOcNvHBRODKQbuCIM2OW/nPZBhB1DTRMiB
         AzQw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1708743341; x=1709348141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2X5izx8Fkh6a3x5wjpxoaQnYAvZeIPY6r2nEwtLi6bQ=;
        b=JgNRXmhfEHLGGVceX1w9wfOoNHHbx1UYdHZN4Fs39xFolNtOoOVaX7wTERHpzyYTLH
         xwcWramFJ17hEKsmr5pMXLnoWMLrMsYadJH9LHwv2NeQ1jMV9br8IVUy38qXmhWfenv0
         GWzbafrjw0gVXI9PZIZZaIubpaYPTqeMm2wx1i9sihZ1ghda8mQGFw7TEflKgf4niPl4
         Jj0RhaGNLN/C3znXrQ3vBteT/S2uCkOAQ5mQekCekB/libgfNi/O/wrtsEgOX9ERb3lV
         muB4GVxVr1ri+k4yfa0C2mSM1tlXcHnbqwME27da+AuNXnBX1FvGNhJPsblp7Hlo/wi5
         752w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708743341; x=1709348141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2X5izx8Fkh6a3x5wjpxoaQnYAvZeIPY6r2nEwtLi6bQ=;
        b=YZeEf30RbVWn9ZsEI23KhNRND3QopRggJKk9v4vV+ntBpLST3b8GpOvsC3bp4RwfpX
         EHPER6a0C35plhnz1nnKtn/G2iMSZ+EFjUzwQ4E8YMmqq51rFd5n3YWTpbvCN1By3IKp
         6ybA9PypeMjG2GMl0ysfwbqXw5vin304/Ny26YWbHmgCwuESki9VrBLUPtegyBT3RY4m
         r4uxRkN7DLv1ouvkegtR62znXER3hEeldVoqpUV8APmDgFdZqEo2JV/KDqMOZ/QQsjXh
         CXpA5keEuY7t3HFVxlpfr7Lt70LZjFr+/o8DGvjVQTgIdw8Nu5kPqiMHNNXT7zsSjpah
         hpkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUXif8boJQgsUgXkIyA8edS3YgbndIEcEb0MiazYDV3z7Z39mlw7oaqTnfK6b+VWBmySpjYXgnxUDEhz/Sw0KSAmTIgbyqJlA==
X-Gm-Message-State: AOJu0Yw/TZ9FHuFx2wjlFPFIld4MIm4NZsfP/wbgbIPsxa1HuhXOmQCU
	S4JFuuq8ur5Vh/NgBriIukA8cC2GypbvDunHXK5kiubGlK9WNaQb
X-Google-Smtp-Source: AGHT+IEjB2N8kGFG8gzKl/PlSzo8jWZVd7+TLoiNyXyW86zWb0YFYAVfktS+7ZNZCvlfQ9ntRxeeBQ==
X-Received: by 2002:a05:600c:384e:b0:412:7585:bea7 with SMTP id s14-20020a05600c384e00b004127585bea7mr926732wmr.5.1708743340645;
        Fri, 23 Feb 2024 18:55:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e16:b0:412:9833:dd55 with SMTP id
 ay22-20020a05600c1e1600b004129833dd55ls272998wmb.2.-pod-prod-06-eu; Fri, 23
 Feb 2024 18:55:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV44gC2h5gRNe/4W7acPzqD79BOLV+PdUXrOUnEKhKQddM9LyKQhKeRSbJZ7UKzdBY6DJXFp8lXE95AL7dtM5se5apdTOn+PN8Lkw==
X-Received: by 2002:a05:600c:1d1e:b0:411:dd34:1d5f with SMTP id l30-20020a05600c1d1e00b00411dd341d5fmr887010wms.26.1708743338627;
        Fri, 23 Feb 2024 18:55:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708743338; cv=none;
        d=google.com; s=arc-20160816;
        b=i7LM/J2s0CGbF+kHHtbc9V8sT2bx78uFNNQhhBrS6mbtz7hX8HOGdjy1gsq3dnnSf7
         gIuYCGOL3jRcUdD0f3x6s8BScJTE6zW9PYnHk3FbTMXHa2VIob8hVBj/IqwuWZxsg0LC
         pwvecbCyHb9oVxztHd66wVJCAF81wPPzZe/xkuvxsrIgx8cyx1UXvt7X5aWx+DoVyUaC
         DJJxNJJDbWeF4kBlggNBjaXq6XTMQc4fBwr4m0a+EsJh5WCLiZYkYQBr/dhFIcXuBemP
         kwe7E4R7k1MZiZq8YxZ9yzPPz0S6t78Q+mZTi2vcjRr2x5275slLBXQ6xZ/TwQ7YZJua
         iVxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dKSTnM2v+jmLIpYPi1kbD+Pb1Qc9BSBN4XGZJPjFFPc=;
        fh=ELboU6Bs7qjqLxvk5CQV7kt4WTzBAcyvwAUU8ejy7E0=;
        b=kcOQfXgk87HKb5GfFSltytRR2aeHU4lzAip7RrvtYKYBFXB5YxOq1RfAwnaGfQHbRi
         b9f63rNRKRrerlIEJrvhvOSNT8U3ru8mhWKJXxiVEzIK/nTLmOmC88pfZtaIAKiqD9IK
         OICdG2esKInrbhNsdJIQNacJdhATVQlhmweDMc3MZQwjadlfaAMvQQjsHf7eyNU9RMkB
         W63DrIppi4mKYbax5bIvVZtm310UrK3Z2Oet39/yXDMOz+E0jTeFWKcSO0iEwO8+U0g/
         fWZmcjRVoBpjmb4Ro/BgdqDKWVZ9W2v/3wYE0237P6QGXOZcTq5QjfOjfgzX4Y7Uhvlu
         2+LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VpU7Fl85;
       spf=pass (google.com: domain of neeraj.iitr10@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) smtp.mailfrom=neeraj.iitr10@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52b.google.com (mail-ed1-x52b.google.com. [2a00:1450:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id a12-20020a05600c224c00b00412684b960csi75331wmm.1.2024.02.23.18.55.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Feb 2024 18:55:38 -0800 (PST)
Received-SPF: pass (google.com: domain of neeraj.iitr10@gmail.com designates 2a00:1450:4864:20::52b as permitted sender) client-ip=2a00:1450:4864:20::52b;
Received: by mail-ed1-x52b.google.com with SMTP id 4fb4d7f45d1cf-563c595f968so1840196a12.0
        for <kasan-dev@googlegroups.com>; Fri, 23 Feb 2024 18:55:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVQBwtEsrrui0eTeAR/7im61uid7dqxiYM+wU6Ud9sA2UfSYHCGoERUE1RBGgH3qY9L4fZu6CbAoAdRnNQpTUhj4M06kngCKMlK+A==
X-Received: by 2002:a05:6402:5201:b0:565:a5e1:3a10 with SMTP id
 s1-20020a056402520100b00565a5e13a10mr183414edd.36.1708743337653; Fri, 23 Feb
 2024 18:55:37 -0800 (PST)
MIME-Version: 1.0
References: <202402201506.b7e4b9b6-oliver.sang@intel.com> <CANpmjNNGCkfFBNiSsc+DOm1EDzXZoNLQy_jnEZjt9WuxP5aayw@mail.gmail.com>
In-Reply-To: <CANpmjNNGCkfFBNiSsc+DOm1EDzXZoNLQy_jnEZjt9WuxP5aayw@mail.gmail.com>
From: Neeraj upadhyay <neeraj.iitr10@gmail.com>
Date: Sat, 24 Feb 2024 08:25:24 +0530
Message-ID: <CAFwiDX-tVTsNcbrzd63oCCat5DqzhouA_HQv4sd4xS=c-C01yQ@mail.gmail.com>
Subject: Re: [linux-next:master] [kasan] 187292be96: WARNING:suspicious_RCU_usage
To: Marco Elver <elver@google.com>
Cc: kernel test robot <oliver.sang@intel.com>, "Paul E. McKenney" <paulmck@kernel.org>, RCU <rcu@vger.kernel.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Neeraj Upadhyay <quic_neeraju@quicinc.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Josh Triplett <josh@joshtriplett.org>, 
	Boqun Feng <boqun.feng@gmail.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: neeraj.iitr10@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VpU7Fl85;       spf=pass
 (google.com: domain of neeraj.iitr10@gmail.com designates 2a00:1450:4864:20::52b
 as permitted sender) smtp.mailfrom=neeraj.iitr10@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi,

On Tue, Feb 20, 2024 at 1:33=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Tue, 20 Feb 2024 at 08:35, kernel test robot <oliver.sang@intel.com> w=
rote:
> >
> >
> >
> > Hello,
> >
> > we noticed this is a revert commit, below report is for an issue we obs=
erved
> > on this commit but not on its parent. just FYI.
> >
> > 113edefd366346b3 187292be96ae2be247807fac1c3
> > ---------------- ---------------------------
> >        fail:runs  %reproduction    fail:runs
> >            |             |             |
> >            :6          100%           6:6     dmesg.WARNING:suspicious_=
RCU_usage
> >
> >
> > kernel test robot noticed "WARNING:suspicious_RCU_usage" on:
> >
> > commit: 187292be96ae2be247807fac1c3a6d89a7cc2a84 ("kasan: revert evicti=
on of stack traces in generic mode")
> > https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
>
> This commit didn't touch rcutorture or the rcu subsystem in any way,
> so I currently don't understand how rcutorture would be affected.
> While stackdepot has started to use RCU, this already happened in a
> previous commit, and this particular commit actually reduced RCU usage
> (no more evictions and re-allocations of stacktraces).
>
> The only explanation I have is that it improved performance of a
> KASAN-enabled kernel (which the config here has enabled) so much that
> previously undiscovered issues have now become much more likely to
> occur.
>
> [+Cc rcu folks]
>
> > in testcase: rcutorture

The rcutorture test type executed here is busted_srcud (torture_type:
busted_srcud). The busted_srcud torture test creates bad reader critical
section usages - in this case the rcu reader lock acquired was not
srcu lock, which subsequently resulted in rcu_dereference_check() to
cause a splat due to srcu read lock not being held.

 So, this is expected behavior, and not a problem in either KASAN or RCU.



Thanks
Neeraj

> > version:
> > with following parameters:
> >
> >         runtime: 300s
> >         test: cpuhotplug
> >         torture_type: busted_srcud
> >
> >
> >
> > compiler: clang-17
> > test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m=
 16G
> >
> > (please refer to attached dmesg/kmsg for entire log/backtrace)
> >
> >
> >
> > If you fix the issue in a separate patch/commit (i.e. not just a new ve=
rsion of
> > the same patch/commit), kindly add following tags
> > | Reported-by: kernel test robot <oliver.sang@intel.com>
> > | Closes: https://lore.kernel.org/oe-lkp/202402201506.b7e4b9b6-oliver.s=
ang@intel.com
> >
> >
> > [  292.513535][  T653] WARNING: suspicious RCU usage
> > [  292.514923][  T653] 6.8.0-rc4-00126-g187292be96ae #1 Not tainted
> > [  292.516369][  T653] -----------------------------
> > [  292.517743][  T653] kernel/rcu/rcutorture.c:1983 suspicious rcu_dere=
ference_check() usage!
> > [  292.519310][  T653]
> > [  292.519310][  T653] other info that might help us debug this:
> > [  292.519310][  T653]
> > [  292.523130][  T653]
> > [  292.523130][  T653] rcu_scheduler_active =3D 2, debug_locks =3D 1
> > [  292.525644][  T653] no locks held by rcu_torture_rea/653.
> > [  292.526974][  T653]
> > [  292.526974][  T653] stack backtrace:
> > [  292.529271][  T653] CPU: 0 PID: 653 Comm: rcu_torture_rea Not tainte=
d 6.8.0-rc4-00126-g187292be96ae #1
> > [  292.530780][  T653] Hardware name: QEMU Standard PC (i440FX + PIIX, =
1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> > [  292.532329][  T653] Call Trace:
> > [  292.533524][  T653]  <TASK>
> > [ 292.534696][ T653] dump_stack_lvl (lib/dump_stack.c:?)
> > [ 292.535941][ T653] ? __cfi_dump_stack_lvl (lib/dump_stack.c:98)
> > [ 292.537221][ T653] ? lockdep_rcu_suspicious (kernel/locking/lockdep.c=
:6712)
> > [ 292.538523][ T653] rcu_torture_one_read (kernel/rcu/rcutorture.c:?) r=
cutorture
> > [ 292.539887][ T653] ? __cfi_lockdep_hardirqs_on_prepare (kernel/lockin=
g/lockdep.c:4312)
> > [ 292.541226][ T653] ? rcu_torture_timer (kernel/rcu/rcutorture.c:1955)=
 rcutorture
> > [ 292.542621][ T653] ? __cfi_rcu_torture_timer (kernel/rcu/rcutorture.c=
:2055) rcutorture
> > [ 292.544012][ T653] ? init_timer_key (include/linux/lockdep.h:135 incl=
ude/linux/lockdep.h:142 include/linux/lockdep.h:148 kernel/time/timer.c:847=
 kernel/time/timer.c:867)
> > [ 292.545262][ T653] rcu_torture_reader (kernel/rcu/rcutorture.c:2093) =
rcutorture
> > [ 292.546579][ T653] ? __cfi_rcu_torture_reader (kernel/rcu/rcutorture.=
c:2076) rcutorture
> > [ 292.547872][ T653] ? __cfi__raw_spin_unlock_irqrestore (kernel/lockin=
g/spinlock.c:193)
> > [ 292.549108][ T653] ? __cfi_rcu_torture_timer (kernel/rcu/rcutorture.c=
:2055) rcutorture
> > [ 292.550341][ T653] ? __kthread_parkme (kernel/kthread.c:?)
> > [ 292.551425][ T653] ? __kthread_parkme (include/linux/instrumented.h:?=
 include/asm-generic/bitops/instrumented-non-atomic.h:141 kernel/kthread.c:=
280)
> > [ 292.552489][ T653] kthread (kernel/kthread.c:390)
> > [ 292.553504][ T653] ? __cfi_rcu_torture_reader (kernel/rcu/rcutorture.=
c:2076) rcutorture
> > [ 292.554689][ T653] ? __cfi_kthread (kernel/kthread.c:341)
> > [ 292.555749][ T653] ret_from_fork (arch/x86/kernel/process.c:153)
> > [ 292.556792][ T653] ? __cfi_kthread (kernel/kthread.c:341)
> > [ 292.557852][ T653] ret_from_fork_asm (arch/x86/entry/entry_64.S:250)
> > [  292.558920][  T653]  </TASK>
> >
> >
> >
> > The kernel config and materials to reproduce are available at:
> > https://download.01.org/0day-ci/archive/20240220/202402201506.b7e4b9b6-=
oliver.sang@intel.com
> >
> >
> >
> > --
> > 0-DAY CI Kernel Test Service
> > https://github.com/intel/lkp-tests/wiki
> >
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFwiDX-tVTsNcbrzd63oCCat5DqzhouA_HQv4sd4xS%3Dc-C01yQ%40mail.gmai=
l.com.
