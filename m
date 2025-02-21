Return-Path: <kasan-dev+bncBCKLNNXAXYFBBHMB4G6QMGQEVZHAI5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B7DAA3EF4C
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 10:00:16 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30a4506714fsf10815101fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 01:00:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740128415; cv=pass;
        d=google.com; s=arc-20240605;
        b=hGLXKlu+1woZBy3NjepVvUPjm9I6fHMiClVSw+nAPBeIOE4yNGE0GG6Dj7D3Fe9PwN
         OQPOxjChhsqZpYEjFThHWgQsREAmLFdkn4TzrrRQ8q6JQhIWku7xm7InXSjdt7yPxzQS
         sgVshFYX0QIzIwV8dQeV32u3Tp4VVUoimNqSgbcCNgUlvyvxcZ+b/+te7ZwI7JBNrl+I
         M4sseLUU9eoz0mTDzy0jRtiFtLPWJx2XJIQR5VTzrhZsUkyGAo53LL/1/tW+Jz6vSW4C
         kT8QBbEpEMOiQCfEu4UxL7+YzvzkdFlpbRFLTJmoLbDPAOCSh/gfHbyxp3WngLyzWNNJ
         kegQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+l3xhG61Gkk5Fr/HlhQRJ1jYZkdTuu1PBg8bxDKhtXM=;
        fh=etvBrK7tAFuMybmjOer8pAcUGqVMFmNkSsGTly2WIqk=;
        b=XcfmmHPwX8RfKV8Hr4aYS9UYbByvxuOEauVx8qYZ3ORCWhlk4XWttJds+TOFvIUdik
         /b/qK8JR+hjNOw5LbVxPPZhU83hLMS6cy2h7JGKaMORBKcWN/+KycLESTUPyUyi47PBE
         1BKqaqUfRmKPn6u1ALGMXEekK6MXsrkQJbhj+6dShm9T4Hnj67qmC9N2QWg8t/z9CwpC
         Da30o0dKX5X608zWGlUP6CxzH724PGPERFhu3VaySBdZ4j8xAFzzY63xs7CK86pRA18u
         FIyypk0+wSHVQZPerQyo6OZVleCyHj5YS0tZ6D9BX/3qVdHyJ/Bmi47Yz565fiwYDawY
         jMkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fjFRHyE+;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740128415; x=1740733215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+l3xhG61Gkk5Fr/HlhQRJ1jYZkdTuu1PBg8bxDKhtXM=;
        b=ZUI56oRc9tIt/K5oFsZ7wRaTa0YMUvD/2VmE8cjp09ac0IO+PBl1iWON55egArb71r
         w3gny+Io4qwrq2KLwvsZkR142KQJZqHXmiAmQFaGWKj+OEqL3eDn0G9JWl0Zxgk4yLvA
         Bc7zTQb87OYNo4sgez3tpC3kLFum+TWv//yP8/WMYVipidPX30dLhU9iW0CNCpTAVJad
         CR7fJ8lazb61ns0otODB+0Hi7eHY/WsvQcxAtp9RwA93kPSzk2CoEsalYiKHsEASzkvQ
         ph33p13FasgswQadFQex/jDlsyHvVhHSFzCfDMVH/dqYv7cRrqof9knFSrMiEMRiICdC
         iG0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740128415; x=1740733215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+l3xhG61Gkk5Fr/HlhQRJ1jYZkdTuu1PBg8bxDKhtXM=;
        b=HbQUi/79N5WZPbq52erM63TM3c7qidgJD/elzhRTEVxi0bWFOQspl5qEVcUrxaXb4y
         MDEeoszgIVaNsaA1Np3Y/d6pa18P5Uceigx7lIJiFsdLobuPDHHmaNPic2H6LVHOC3ra
         v+4JLA7XW1uN38oKAJzoJEArVvJfAAyXyKR4UTomKlsj4UfuPTJx/wu9/RFzqkAiESPs
         kat6OPBnAiofFU0HDL3bgxJGRTrj4XKIfZ5ufSQtfeU3tfQXRMZChiIMmJdSPnAi16dp
         R6kGVnKxObQF5pv6fxd0C2C8z6uHyOxUwj4+anEhEic6s9DcY8/SyZkWrsXAX3Tpmoyy
         CwNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrwj77zA+cwXodACh2vrXgKy+9ob8y+nu0cFYvrT1f182y1phAYHf1CcK2m3lNxWBotcpmTA==@lfdr.de
X-Gm-Message-State: AOJu0YxbgbDBGk5Tw5tdM5+V2ZssA1ZD2tKY+m6kYNFArt4QByweKtjl
	mdJd3JcjmzkZj7HI8Rbk9cYF7dKKboP21LTX3tk7+rK0hmOyxrTk
X-Google-Smtp-Source: AGHT+IFglRyEt9+Vo0TRIqZ2Lx266aINWgJwm1FINjlNWfHeEYx/WJRVWLpOQMg8UmsSjsqSiF280Q==
X-Received: by 2002:a2e:b4a3:0:b0:30a:24bf:898d with SMTP id 38308e7fff4ca-30a5065136bmr25509191fa.18.1740128414369;
        Fri, 21 Feb 2025 01:00:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEPhKlVNXRah7Q5ZtORWmwAwDSSvNaBYMAbIOktnxXkMw==
Received: by 2002:a05:651c:2126:b0:309:1c03:d2f5 with SMTP id
 38308e7fff4ca-30a50010f4cls4645981fa.2.-pod-prod-00-eu; Fri, 21 Feb 2025
 01:00:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWR3zQ6Tv5jtWCm7D3eatt+4J144tYWNJU2xIFrZlse7Q5WyWp2/aOCTSu67xKHxDKZKxP6X1o9rDI=@googlegroups.com
X-Received: by 2002:a05:6512:3d25:b0:545:a70:74c5 with SMTP id 2adb3069b0e04-54838c7375cmr833620e87.13.1740128411134;
        Fri, 21 Feb 2025 01:00:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740128411; cv=none;
        d=google.com; s=arc-20240605;
        b=cUYgRYcbPKV+ZKdERUiImI5QE7w49XpoZ0L6vKpT6OKHjd6andEr+ly8dNdJZW6M3Z
         PUxhHy8BV1IqGtp1SpPI1gnKSvXmL17RaW3uXfyYCEs1iW5D1tPpI5zfm1Cywboc8+11
         VW8mgD7gLNfOrhesmpL9fzDyfGcpJSzDAMlWiYFSVZYyPsDSyseT8JHOdxRR+uROAaeV
         zyxSY7/yZE6q97cOkJ4zxc4iPwajj754j1A2NXsDw/43f2E/59NoxAwj46WWRYj9Nn+k
         aHQ7Jwn0wE1TI6NnBBmGGmvJiYCxwijsAO8kpyRhUzFgcaVI/hUabLpkzGc0J73Yw63y
         Q8ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=/G8u2w8Nz/6LNRqOihn9/E0oO4aWnl10a49dAoNX2lw=;
        fh=pchnQSBITUhZAZCYJ7QJTcg29zOA9pAQtPw2VWXoruw=;
        b=D7pKNYrrX8W3zlX9Y9uXWVirgV5CSIU82ZIFgGYivvMZxaBrMMNquCB6vlWIQkx0If
         /1rjBjKtd2DzFlguuuepCEuOBQtEUSj3PwfHncEXHzXtisQ9mj9Kjvjj11Hk/HgA6tL0
         Ox44gsDAtWk7I/w910KGMJxSS/ZGl4avsfj2OHSNLDGsqVZRtvzw0NeSd+SkPBfBBJ7v
         viy14Ek2wY+G4xizdAvqIoNQBXIqsrbOufsenyZafSFOdAWoVk1+hqfiBDf9hmh0PE5c
         p5QH7Nj9QW6X55GNYRvCSp7n+zuZ/4QWqPvictM6jJg2FZegrXa3Uk/TYZXnofbwVsBb
         nMqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fjFRHyE+;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5461abf4dabsi401417e87.9.2025.02.21.01.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 01:00:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Fri, 21 Feb 2025 10:00:08 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Oliver Sang <oliver.sang@intel.com>, oe-lkp@lists.linux.dev,
	lkp@intel.com, Petr Pavlu <petr.pavlu@suse.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Kees Cook <kees@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Waiman Long <longman@redhat.com>
Subject: Re: [linux-next:master] [x86] 66fbf67705:
 kernel-selftests.kvm.hardware_disable_test.fail
Message-ID: <20250221090008.5aWGygvI@linutronix.de>
References: <Z7bUC9QY815Cv6nb@xsang-OptiPlex-9020>
 <20250220155722.2Z2a-3z0@linutronix.de>
 <CANpmjNN9zpcPa4S+Zq+vJWJ3EcO0zCZJ=Z4FgNzDRXdi0YQA9g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN9zpcPa4S+Zq+vJWJ3EcO0zCZJ=Z4FgNzDRXdi0YQA9g@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=fjFRHyE+;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2025-02-20 17:30:22 [+0100], Marco Elver wrote:
> > How much do we care here? Is this something that makes UBSAN + KASAN
> > folks uncomfortable? Or is lockdep slowing things down anyway?
> 
> Does this series from Waiman help?
> https://lore.kernel.org/all/20250213200228.1993588-4-longman@redhat.com/

I have applied

| locking/lock_events: Add locking events for rtmutex slow paths
| locking/lock_events: Add locking events for lockdep
| locking/lockdep: Disable KASAN instrumentation of lockdep.c
| locking/lockdep: Add kasan_check_byte() check in lock_acquire()

and with this I am down to:

| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
| 
| real    0m29.517s
| user    0m0.493s
| sys     0m10.891s

Which is the pre-RCU case. Yes, the series from Waiman helps. This is my
favorite solution.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250221090008.5aWGygvI%40linutronix.de.
