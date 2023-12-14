Return-Path: <kasan-dev+bncBDW2JDUY5AORBWU65GVQMGQEWAA5K2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 60BF78123FE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:42:03 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35f7c1f00ffsf4113895ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514522; cv=pass;
        d=google.com; s=arc-20160816;
        b=D8lTl7kIBc+6H5FPUDtI5/SnvJuqLeYXM5/RIahRu7Rua2MsCeRjHV2P5iw6Cbg0Uk
         YHXOMK4NjiZheLt/rG8Gts6Opgnyf0YUsxvzKGhuSV28URsH0vFimRHrkl1SsQP6yh75
         iQqlg41oMdzoulSY4tNI4uWLMysHDNyvINt20oFepRIbO44eS67PLiExCnfME7FQ0FCz
         iCWS4IF1SyMY0+4QkGiZ5EsXBSXoiJxR5Do4YtkvW7OsZxksRxE18hxLfNhf4KhM1im2
         JRTjC+nHemBvlT7ma6mjxx62ivG1pSvLYPTww98xH7Hi9pX/KydUEYirVdIITiElc3iI
         kPUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=K25tFVZa4kByi+FI9zTshdgWTp5Q8GPn2j2fpNNglfU=;
        fh=F6+FGML87yHqRev/l5aFDmOtQouYoX3HLtF8iNVpDI4=;
        b=humCo1E7Y4RIk05dUHbGyrvrc3yEnOT56BeGjNeq22MySE4tZqN4+4m255gujfeCYi
         r7WAFUfChYOfuzE1kf7pqpXn8p0AXRiPCuhZFyzlYN6z8MUX6SEUKD6tVjVBA0iE4mLj
         dm2TvsmUfAPkt4uU8IWf5xU7BlmKCXY+Vcr4Z2961dzV9K6ipjr3z1JIjFIEjqPS1l3b
         aZpEn3/3gvygOWV0Gb2QiiAX3aDgztxfjY14eXib7Y56BXBxjIF24HckBoL7Io7O+fCW
         URMkRgvR45CBZr31A7v49ew/xE405y/9Mh3TLyoFvjG8m9oD8AaywzJm9fStu0BULcQk
         KeJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=f80c2EQk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514522; x=1703119322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=K25tFVZa4kByi+FI9zTshdgWTp5Q8GPn2j2fpNNglfU=;
        b=Q8Nf/4qagH5OqoiQIoD4dQ03UAAQi5unvlP6MjCsGR/9DW/k6CYfK8ruWN2eTKsdH4
         gYU4TtbVRGk9w6WPGXKasnPoEXv+NajN6hQXrysy/xA/PjDGSCXCIPgc0CLSB64/2hcQ
         6/LslUEUQoOrB0Mso1MG2Q5APwF6yWZ0LuNvlDMhWOZ/qFGEaI2Vy40hrY4nerWTqQfw
         Xl1dvJmFf1UetFSUJR7lRQ3DsbhbxGUKtL5zFsia43fS+SOnl4o2fSp1cxaJQQYqVfyF
         plLHSHrmpNVxGM9C0ce1QclMQXXVZ0hUvPRVq+ShicnVOTL7bSbv55+1oC18VPBNNz3k
         ry/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702514522; x=1703119322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K25tFVZa4kByi+FI9zTshdgWTp5Q8GPn2j2fpNNglfU=;
        b=eNrR1wkATZhC0M03y2caJfK0WEeHQFpQvBnTtu3MAKJh2bCLsHLC56azOvP26dFRyh
         sUQJ9piXQYQJIIVoUEVAzjlLlRjqTMcQLLOWdDHCtmsu1pEfki6KjzAqra01/kHHS6vS
         vs3MfNdevUFOPFK7QW6Ta9XK1bh3AZVgdDXsm6Gtp49V6SnzuV3i9x5tiGKl+PclvAWq
         yUmhH0fjI/Zlq75rW2Le79YT1GEYqUXc9+I3aMneD/yvPl+Dun9fM+KYiDBMRhgwGt/a
         xrjU93SJOWwWYHU6KyisAbUIMUgcvKXLPOoBMdV08qF1RVfC9kiWDxXJ3M17Fd6OWqVC
         Bltg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514522; x=1703119322;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=K25tFVZa4kByi+FI9zTshdgWTp5Q8GPn2j2fpNNglfU=;
        b=llYnOq8tcMWYYP0taoBKuenPmVjl4jgiBOt9A7CMsEzgIyYN5ZfjYBktu+QBruZUIQ
         7wNAC1b/bCYk6R4lfyDuR+E+avqnGrr4NJVSdkAGe9l8BoIq3xoF824S4AMa53N2kc/m
         gyZTz+Y54QvFqySfAWu7JAdneglmeqgcYmiWU1iDuqoT8T6oekDYMeZJU79A4R/JCoWf
         tdWBg60C2gdcktqRm2bZfKZdir1DCItL011Kl0kMr2lIt5oVFphHTXBDjiGz3fFXa5B4
         LU3Kmw1hjZgKI4WKEu00aFdM8hqrRGr4sBQ32oJKlY7sLHPAVPyHAiFW7lYZafxWUHwR
         Y3AA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyjhlw9kbdQKZgXwoqxyhQdaxv2SyMKCKC9z6wpsqayu/A82Ro5
	gHReoABZClACwLILtqdxINA=
X-Google-Smtp-Source: AGHT+IF0+s9jV7CRPxGmcsjS3F1r/Zc0PSb2GBv9kB23EzMs2O5yi1nX/Q9btvQ6UQdXAbuD5mTQvw==
X-Received: by 2002:a05:6e02:1bc6:b0:35f:6a4a:cbb0 with SMTP id x6-20020a056e021bc600b0035f6a4acbb0mr3676930ilv.25.1702514522118;
        Wed, 13 Dec 2023 16:42:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:523:b0:35e:7419:884 with SMTP id
 h3-20020a056e02052300b0035e74190884ls769311ils.2.-pod-prod-01-us; Wed, 13 Dec
 2023 16:42:01 -0800 (PST)
X-Received: by 2002:a05:6e02:12eb:b0:35d:591f:861 with SMTP id l11-20020a056e0212eb00b0035d591f0861mr14107650iln.8.1702514521233;
        Wed, 13 Dec 2023 16:42:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514521; cv=none;
        d=google.com; s=arc-20160816;
        b=rhrhm0RFRQZwKsVqoza9rL3bvtXSK/gbbL2E9Fr3t1MpPVXCjFK01cJSYJJUkl4Qnm
         5/k/Ni65LouGwHSCzIQD3QUka1j1HUKIVhJOs0mOnITSI0V4xTasNyl4AN6bEuCqmRZ+
         AxUFIxsoHT7qRJsjWnuZTKf1uTdEIZ1Ngz/GM51O3t5KAbVjtKI4omYr8dl/T5uRJuQ/
         QcUZ4ClAHqUsD8NPHfOf6j4vTyyrwiYS7siIVF8Fq035eUqeng8cY5wvRYl6tmeSBK/M
         5VlsSUt+H2UXEPFlebjjllgIk6/G7fDABduuV0j0vhywedbpwF4RkjbNlGomLfFFITOC
         3/Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lzK45zb0LxFLrNRkOxquQyQenMKLSRC3JhAeRqUtSRE=;
        fh=F6+FGML87yHqRev/l5aFDmOtQouYoX3HLtF8iNVpDI4=;
        b=KJVNmO3mKaPHQmiZC8Jlo9hyCkZw071CFvSJct0/hrhXlmT4NnQOpVYMt/bRfP4OIc
         I3lKByAmUUPwNo0xsqP3IvvzuXt/42vyMTdjNVkLzWVtI5hpGUcF1nf7cSiX9m8DFULr
         G4zB7F9vSnymkLyb2LEJ1XO58YBr8NgqQETHfjkmbXBq25GZAeE9hDh7Wu3/sVo58K1k
         kCy6z+f8z8Ljk1vJI3UtVJLsyVCgpa7gPHYr7RIoDjpfTkBz3cAA0105Cji0Ace1EGVy
         A65m/iCZxwzSCeTtcXiuHwL3TYHY3ZkZACMtiVle7CFjjivLJwFrmdjISdUk8wECMobC
         nIpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=f80c2EQk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id x18-20020a92de12000000b0035e6c380435si980009ilm.1.2023.12.13.16.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 16:42:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 46e09a7af769-6d9f069e9b0so4948593a34.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 16:42:01 -0800 (PST)
X-Received: by 2002:a05:6830:4423:b0:6d8:7ba7:c8b4 with SMTP id
 q35-20020a056830442300b006d87ba7c8b4mr11075778otv.6.1702514520732; Wed, 13
 Dec 2023 16:42:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl@google.com>
 <CANpmjNM9Kq9C4f9AMYE9U3JrqofbsrC7cmrP28ZP4ep1CZTWaA@mail.gmail.com>
 <CA+fCnZcGWXbpwCxk5eoBEMr2_4+8hhEpTefE2h4QQ-9fRv-2Uw@mail.gmail.com> <CANpmjNPEofU4wkmuqYegjDZgmP84yrf7Bmfc-t4Wp7UyYvDc7A@mail.gmail.com>
In-Reply-To: <CANpmjNPEofU4wkmuqYegjDZgmP84yrf7Bmfc-t4Wp7UyYvDc7A@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Dec 2023 01:41:49 +0100
Message-ID: <CA+fCnZd8_iOgf6HzDSemHJgs8S6doMJJK4YhcwT1M-oBePe7HA@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=f80c2EQk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::331
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Wed, Dec 13, 2023 at 5:51=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> > > [1]: Since a depot stack handle is just an u32, we can have a
> > >
> > >  union {
> > >    depot_stack_handle_t handles[2];
> > >    atomic64_t atomic_handle;
> > >   } aux_stack;
> > > (BUILD_BUG_ON somewhere if sizeof handles and atomic_handle mismatch.=
)
> > >
> > > Then in the code here create the same union and load atomic_handle.
> > > Swap handle[1] into handle[0] and write the new one in handles[1].
> > > Then do a cmpxchg loop to store the new atomic_handle.
> >
> > This approach should work. If you prefer, I can do this instead of a sp=
inlock.
> >
> > But we do need some kind of atomicity while rotating the aux handles
> > to make sure nothing gets lost.
>
> Yes, I think that'd be preferable. Although note that not all 32-bit
> architectures have 64-bit atomics, so that may be an issue. Another
> alternative is to have a spinlock next to the aux_stack (it needs to
> be initialized properly). It'll use up a little more space, but that's
> for KASAN configs only, so I think it's ok. Certainly better than a
> global lock.

Ah, hm, actually this is what I indented to do with this change. But
somehow my brain glitched out and decided to use a global lock :)

I'll change this into a local spinlock in v2.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd8_iOgf6HzDSemHJgs8S6doMJJK4YhcwT1M-oBePe7HA%40mail.gmai=
l.com.
