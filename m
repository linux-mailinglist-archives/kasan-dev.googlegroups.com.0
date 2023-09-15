Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBYG3SGUAMGQELB3E36Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A90D7A2145
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 16:44:50 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2bcba79cedcsf28478221fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 07:44:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694789089; cv=pass;
        d=google.com; s=arc-20160816;
        b=iuzOj9GG12f7N9gU+8hYQPeYDan347gG9QwsgQaMXwQlga92w7PGihjn/lsZ+4Wnwv
         PxX6sAuIbaDoW/3dcSB0Jb2RXpxNB1VgK1n/Ck7lx4NeTM2zeTHiGGKLzl8NEu5J8a0l
         WugIAuxqtSHa6thXsbRAwUIU8+AoOpzqBf/UgNJ+z8GqZXbPo5lqLZjHmxVkEn5nTLSK
         a9GDjzbg/ViiRyryTXmaT8cRgd+2BHRS8UndHZNjLfPiH+P7eMdC1olbVfCi0cA4UhPB
         JFY2VNwPDLdeeklXz99a1AbYuzRfZmObjhCPmum5VLVEfDI1NnfOrVIo4Thb9sK2uqvF
         +Ivw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=llJeQN+MzXs9NZedJcn91cFApnVu4o7DAhgECRvgKEI=;
        fh=2FACerJjZ6Zqpe78/ckgS/B1U2+5wfj/3V9c0FtkGuU=;
        b=llmuCrEMR7MtPTJ5Qja3xPmDMWN6fgCBoMztNdcj+R8C7FJkQc2fOBUyzpT+YChah1
         sm43qDhP9CiMsMxYEz2aIOx419JfdP7OO/SGCEeJkjlKC7QS6b5HJqA0xyeAzuBhHb6s
         bQaeui9Z6Jmtl4vKmoJzF3+A2R+6ktUpQ92mMvA+4ob7ZrSadpme3xBciWuYBcCsnVH/
         YsROEEfhOgWSWa91aOYZADeEjPDxaVWNLj6mgWw5haNMMmN9QfPhQgupQTvDamPtqSBw
         h9zCVFQS9wZjKdUDanbCkpeydfJD4BIRqK9UQuMOaRvUwejpcFKHbYJ02Y3plULWXAa7
         fo5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=e3SulKit;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694789089; x=1695393889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=llJeQN+MzXs9NZedJcn91cFApnVu4o7DAhgECRvgKEI=;
        b=tbQSvZsTzfI/gXnBbbvaEkOYsKa9mav9xfQZZW22eRUf4xhLXfo56SEjV9Wt3x5L4O
         edymqSuUmWC+eLkGKFnRes7yp5+GBh+1uZw/yd0Ew8qg9ovvmdsQ2bkiivmpXhHcQ0gM
         5ndEeY2eURx6VwLwRML2i0Dg2RZDGD6nPM1eV9hAQ1KxlKP3Ml3uD9O3i4WxxCjyFBSp
         3DLXl5LFrCLrGjpLdXy71sxPgahWETQk/FboQbFR7+/7Ld1SuhgyOqh/WadfhrdM8COs
         lbijZdcxmQHQX8KEqRtGHqzU0Dm5m3bkoYG/8FkIxqIanAKsMhCnKdmdc+ecmYbCntNE
         TiXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694789089; x=1695393889;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=llJeQN+MzXs9NZedJcn91cFApnVu4o7DAhgECRvgKEI=;
        b=uYWvi83Y/sbLj/4JA8riQTHpuScAKLJDmAF+rJUB9X6/KWxB8Kdp3Ba5k5sDiIt4EO
         HJvVC3jjRw2AMGSl1Qlc+QNNPEi3i6dGTZkCDWyMfdfQok39+RJjRHC/0zhTDW8DzFdJ
         X2QH3kNAR/3ZbDDuPbGgC13qpwDC/Ayc4/GmlC02kjgow/2AMsOROF8klOWZ9gdfv6q0
         wjhZmdx6HP0FsFUKa4q7L+dVhJ/qk2E9kifGSKX6A6Gd8TgQfTNQeEZbZO8gppyEoM/a
         wAGrC8QpKxmobiUeXa7g8Cy5YV7ECaYD6Dl5Tpeht1PTkzRWD32jk1j5mJyZZ3oJvm8u
         CqYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywg+ZxlkRQubu0F2VqxidzhVGxHWz33mfc8n6ggspbDr2LTq05Q
	sCu5Dg+/sHO1yjacPAno6Cs=
X-Google-Smtp-Source: AGHT+IFvLffcyTexWY1dXKDpwb0QvRCoJ6Fi1yNjNoQb8bwSJpmr6OugKW6TQdhqBKGRv+YJI3OJ5A==
X-Received: by 2002:a2e:8315:0:b0:2ba:18e5:1063 with SMTP id a21-20020a2e8315000000b002ba18e51063mr1576781ljh.50.1694789088532;
        Fri, 15 Sep 2023 07:44:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c91:b0:2b9:5184:f05f with SMTP id
 bz17-20020a05651c0c9100b002b95184f05fls1600136ljb.1.-pod-prod-01-eu; Fri, 15
 Sep 2023 07:44:46 -0700 (PDT)
X-Received: by 2002:ac2:5470:0:b0:4fb:77d6:89c3 with SMTP id e16-20020ac25470000000b004fb77d689c3mr1706634lfn.12.1694789086796;
        Fri, 15 Sep 2023 07:44:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694789086; cv=none;
        d=google.com; s=arc-20160816;
        b=i3wme7smVl8Al2TJ9RHNOKpwzUdnN3lLOosWtbquVjPaOJIikPBTHV2V5AXrkzPMO4
         g2HnNFYk038XF6oRsJM+EA9kJx8vJjQU3aQMbAIVrTJwRt4oDFXEbgwbdMd8eE4r0r4j
         696c2hQaVmoplkY4ogYk6t1KAttWnwrKgYC9ekT0vr98xljIFCw/41EgtTBfBN/oTJvr
         MmJYY/RRWvHW7R/WohoQsrQUGREHmH4Xm8BTBYL4lf/3mDY3x90hPlFPSWEdxmOm1UKq
         ox0TBSxREWb3Iu3xzyr9V3sQRQAKQt8n9NlAntAJ6e3mQZRbIGHx0rl3Yb0zQFIsnPOy
         SFeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=H8PZLMZCU0PDXbXjCCzMXnQDN3Es4h4xOXOxp4F6e+E=;
        fh=2FACerJjZ6Zqpe78/ckgS/B1U2+5wfj/3V9c0FtkGuU=;
        b=j5e7ON/CXhgFiBHX6GyRrLSXVOXHVqzL8LXwZ4Op82n7bwuxXAPZljzQnVBwrLSa7C
         a4tuGC51nDXGVPKeq1uzcWcM28f8MCvGQzcHnhRnpTlKPgxhc+vaJldi5+K5esbtKsSW
         DQlyO2o5NELlKf9Cd5BE2qmkD/07D6aeU1nRqMgFrA7KqVZHizHG1UnHt1F8lt2pPaTD
         PHzPphgDBWd5xwJNSMUEPoIbLrRHZA8dkESmio/JBuZXXmIjEqiced3bzlyODwDpryqb
         o1c3K/YsLzBPU9Yr1nUDPJTMkhYpC+dYlWhVadmJitB5Skl4/Co9pSmEnLe4uVXRkGQh
         qWQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=e3SulKit;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id d7-20020a056512368700b004ff9d6b6cb0si284507lfs.2.2023.09.15.07.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Sep 2023 07:44:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.96)
	(envelope-from <johannes@sipsolutions.net>)
	id 1qhA39-001WIR-0N;
	Fri, 15 Sep 2023 16:44:03 +0200
Message-ID: <115822422e97aac5ccd651681d74a2a4ae3cff89.camel@sipsolutions.net>
Subject: Re: [PATCH v2] x86: Fix build of UML with KASAN
From: Johannes Berg <johannes@sipsolutions.net>
To: Ingo Molnar <mingo@kernel.org>, Vincent Whitchurch
	 <vincent.whitchurch@axis.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Frederic Weisbecker
 <frederic@kernel.org>, "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>,
 Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
 linux-um@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>,  kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, kernel@axis.com
Date: Fri, 15 Sep 2023 16:44:01 +0200
In-Reply-To: <ZQQkthfNuV3dOhZe@gmail.com>
References: <20230915-uml-kasan-v2-1-ef3f3ff4f144@axis.com>
	 <ZQQkthfNuV3dOhZe@gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=e3SulKit;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2023-09-15 at 11:32 +0200, Ingo Molnar wrote:
> 
> >  ld: mm/kasan/shadow.o: in function `memset':
> >  shadow.c:(.text+0x40): multiple definition of `memset';
> >  arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
> >  ld: mm/kasan/shadow.o: in function `memmove':
> >  shadow.c:(.text+0x90): multiple definition of `memmove';
> >  arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
> >  ld: mm/kasan/shadow.o: in function `memcpy':
> >  shadow.c:(.text+0x110): multiple definition of `memcpy';
> >  arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here
> 
> So the breakage was ~9 months ago, and apparently nobody build-tested UML?

Well, first of all, it's only with KASAN, and then I think we probably
all did and applied a similar fix or this one ... I have a in my tree
that simplies marks the three symbols as weak again, for instance,
dating back to March 27th. Didn't publish it at the time, it probably
got lost in the shuffle, don't remember.


Also, a variant of this patch has been around for three months too.

> Does UML boot with the fix?

Sure, works fine as long as the symbols are marked weak _somehow_.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/115822422e97aac5ccd651681d74a2a4ae3cff89.camel%40sipsolutions.net.
