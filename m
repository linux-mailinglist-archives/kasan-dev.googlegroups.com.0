Return-Path: <kasan-dev+bncBDAMN6NI5EERBCXC36YAMGQEXTKTULI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C12D8A16F4
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 16:17:48 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4147faf154csf36435305e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 07:17:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712845067; cv=pass;
        d=google.com; s=arc-20160816;
        b=eq3SfY2Ndt/sOqmgummlI/gxB63pqKRJ+KHOCBc4v/QhvDLgLkXN4LbGurf0cbnWX8
         Em89wlyiB8VoyNGGo8FaERXMpUsdUUkuLtRWqGSeYJoavGY+Ndl0veGZyo29chkZNsUp
         dzbuxQO9Hr7Jboe79bdnHNAVKZPND9kqnO3ygSOjjU/tCXkxeTBPfh5dicDc139U2RiF
         6oQ/VKgm2n4ceCCXR6fBD8jcYUCCcHeBcpSUUMfTttFX4BOLLBp9zxbHPbxMpGmId/gR
         EZUFbjkbj3vOFOrxOAbKyFcBcK26yIJ1huvIMitrQyADUcok+nxEmWW2t4J4gR8E+ZPo
         VSuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=f0WYOIB3MZBuWXBEt9fx03IWu5HbWfWEYj2yl8S2EFQ=;
        fh=3u9T6yUx+xKaxjFizNLaiyj6E0VWAtOquPkOXvU874A=;
        b=xbD0sjFyFEYGB4mvIDe5r1rB1cc/MIF9l0RO/lw7ozG29BqKG0xS3qmj7JFaWFJU3C
         nU8QH5Gt2r21GKdnCPgiY/H3cZpWkcIg/m/ml5pJ01vRBCLjxnteMuvPP6IuAmSvfmNM
         /bdu6RRTir+KTmONrc+wNr61xx5gvEv+MJrtG4k33ZISl/fKZBq33IKNg3QpkxaHr4qU
         NXw9DNH9mhoqTjzkNBGWV39xdYo93PVJoADGWvKvHTlmBzcz11Jo4fJ6Qm7ybNADkPgC
         scjUBXo8/s7qXvF4nQOQRnMU28g4867rVpI1k7f0sdssSJqZhBYkT+/4HUo0hg3kCSyK
         v+qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=4kjBAKBi;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=YYbHCtpq;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712845067; x=1713449867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f0WYOIB3MZBuWXBEt9fx03IWu5HbWfWEYj2yl8S2EFQ=;
        b=UkI+I+87PITGQrl/ipCkm8EBtuWFpL6TxmOVFByU8lL1IxvN7h6WLlWv35njlh3fPf
         zWrrmBMBHFQR6LdfQQKe6pf+DjhL+4fGWtmh8wKI14dxvNF0TUO8TFy/jjNAWz0b+FlT
         qyQopsnkGYbSeE/Pm6kb1/M5pwS2qJYQR92bql81X7ObbeMkZcRBhHfgOQRESy1Lm1kr
         P9Fd2EHGHpxzZJQrhhyqDG07tORrzvQJE3X8PWusuD2Teb+/6nYk3UPYCYdF/yY/3AA4
         qJuWYnJIl3X1BPmu/qcsqP679+4BhxT0VMZB8KUj8uGwY5Fx7R3vb9rW3Br5rfnctORk
         cl/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712845067; x=1713449867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f0WYOIB3MZBuWXBEt9fx03IWu5HbWfWEYj2yl8S2EFQ=;
        b=mzfvOtJih5Wh+vk0hsB9ZmQzcEUJZKA4KP8MsSNGbtHLKzPd34T5X8qexxkhfAyw/r
         7zIuQJHANM13tKcDTJrsKh3fvOihDxxUy6vwlYoChCuhUZcSPPL/l1aBOeyo/jLJMlDG
         DlMYXe1N42y7mhTCw4oBTUlYkZsUog59I9rNYV7ZeQIQYL0NXGbW7kO2fkdfqbnf3G2G
         makwSOZtw50/0cp0ACEAoDDIXuKalsVDXvmdmkN9DH4YgdgmuS+1T05ple9ydopcws6F
         Qx7e/ZOQeGWjWR65PYoSYeqihbYPaFuhXC/MxS8FZ5G0dYzndbIFKmTyZK1bbAvMYNS7
         pqOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5WkCbTAtf+tYxBgH+nQaAvlNVF+m3C3ozWSATC0t+VG/JePTjq+9pSRCGmjxHgACn/eQY6297ltxLVr5pOMXVNTn55Zrb+g==
X-Gm-Message-State: AOJu0Yzc69NjvpGEKBzhtl36Xf8APgnpcrEut456DbnJXeDYq7hoP6bz
	xpmZ5nVT9na0tl/mH/rC4t7tJPAH6Ft35gSRbsWm9IXdq+Kj6rPd
X-Google-Smtp-Source: AGHT+IFa08WGTEx2RpRtB8IsPzEdYDWJn+mcX1cXtVa6qHm0znxOJED3M0s1MWLP8etOSM0fahALfA==
X-Received: by 2002:a05:600c:198f:b0:414:cbd:1ee2 with SMTP id t15-20020a05600c198f00b004140cbd1ee2mr5468274wmq.35.1712845066468;
        Thu, 11 Apr 2024 07:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c27:b0:416:abf1:3c33 with SMTP id
 j39-20020a05600c1c2700b00416abf13c33ls1147024wms.0.-pod-prod-08-eu; Thu, 11
 Apr 2024 07:17:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJJxAT+t2A6qDPcNoMO/qqGQuVtLo2ky2kcsvS8Rb1lChC5V6vc6f1XuL60ebFw2ZurMFKhDpwYRGXib/0xMmMBb9YW+lj2FTLdw==
X-Received: by 2002:a05:600c:4e07:b0:417:ca54:e9de with SMTP id b7-20020a05600c4e0700b00417ca54e9demr2723376wmq.41.1712845064525;
        Thu, 11 Apr 2024 07:17:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712845064; cv=none;
        d=google.com; s=arc-20160816;
        b=Ucl5mmQdAt5sCVlsH6HElEh8Eysd2qw18IbhA6L352ItBkKW1hi+BXBQ328z/Sn3OH
         qIHmYIBEviJ+G2JgbO5grCCs3zRuNDtnRbImQWVNs1+Joqs7y6gFBzVY3qSdFA5cb73u
         0yGQ144DUXh1avxw3lWj6ozN0FSBjfJu+zYHZh9B6thfUyfnbmOs61P/fwZ4HofdIfUy
         6/ESaSvrEcESnFeGymRKexG3UWfCC997LFwQJsuV2ulGmHFbvDG8EyG5jSapiWl1kOLb
         Vmo+EDwtxrax7r/E4Hyg8+MlNEwRaKs6Dn+1RhnKz5mCpyETdU357PP/s9hvUhs6TsYD
         9Wcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=MuXafFQRttff2dvLyAB+pKNoH9ktNnb1Y8CD+U2h2iw=;
        fh=pR/XyCVIQetuTJjDccYIM9BYrd9ZaxzWnEgqdgahuZQ=;
        b=s0ZnR6kHRCVW71Vjd5febg2a2lOdXIKJVf1hAjOdyGOzFeZzG9prfkK2CLjZaxp7d1
         atVNn8eLXgrlLeMxZoeVre4XoFTL0OnGf76cL+p92kIjZgoJuc3Q7rWSy/EF6OEiqzaO
         BuBb+IM2k2qvH1oAW01rv+KDdgljY+Ps6gy+DLiOxHtE4B7JeIPV+M4NH3mttiDBhik5
         7edUWGJiiuM9hM3M3z8uC/nVouKLDazanjnIDVoxePEWIEJFgXG6ZNd/WKhtQvnlHnCq
         DrrSAk3VkUQL4KBRLRV6VlI+1wP7WeCPkuFoTxEV3PqXhk5cyOcdu3A954+TdLCpIyKs
         4yeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=4kjBAKBi;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=YYbHCtpq;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id t20-20020a05600c199400b004166a35d7e4si349758wmq.1.2024.04.11.07.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Apr 2024 07:17:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Mark Brown <broonie@kernel.org>, Oleg Nesterov <oleg@redhat.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
In-Reply-To: <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx> <20240406150950.GA3060@redhat.com>
 <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
Date: Thu, 11 Apr 2024 16:17:43 +0200
Message-ID: <87il0o0yrc.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=4kjBAKBi;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=YYbHCtpq;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Thu, Apr 11 2024 at 13:44, Mark Brown wrote:
> On Sat, Apr 06, 2024 at 05:09:51PM +0200, Oleg Nesterov wrote:
>> Thomas says:
>> 
>> 	The signal distribution test has a tendency to hang for a long
>> 	time as the signal delivery is not really evenly distributed. In
>> 	fact it might never be distributed across all threads ever in
>> 	the way it is written.
>> 
>> To me even the
>> 
>> 	This primarily tests that the kernel does not favour any one.
>
> Further to my previous mail it's also broken the arm64 selftest builds,
> they use kselftest.h with nolibc in order to test low level
> functionality mainly used by libc implementations and nolibc doesn't
> implement uname():
>
> In file included from za-fork.c:12:
> ../../kselftest.h:433:17: error: variable has incomplete type 'struct utsname'
>         struct utsname info;
>                        ^
> ../../kselftest.h:433:9: note: forward declaration of 'struct utsname'
>         struct utsname info;
>                ^
> ../../kselftest.h:435:6: error: call to undeclared function 'uname'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>         if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
>             ^
> ../../kselftest.h:435:22: error: call to undeclared function 'sscanf'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
>         if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)

Grrr. Let me stare at this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87il0o0yrc.ffs%40tglx.
