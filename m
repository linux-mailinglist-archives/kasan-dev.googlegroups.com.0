Return-Path: <kasan-dev+bncBD4LX4523YGBBG7TR7FAMGQE6EQXMQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04D9DCCBDA8
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 13:54:53 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ee21a0d326sf8761351cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 04:54:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766062492; cv=pass;
        d=google.com; s=arc-20240605;
        b=Owuo7owiL7FF28p7A7E291LijPXpEwa4TWczN2b/ePHELD1v4Yz38FE8QithZtdT51
         JGgmCBB7NgybUMhw0nm4ApFSVA6nI/dOTr2SyP89UwEUwI5OB0WQWZflZ0N+UEce93Km
         9rKOvXqNObIMX73laO759wrKAj8OFshLCs6ozzLaqSemsnec9My/8uzlwa4w3oUcyGG9
         F844Jxfi3C76/DM8JyJG1zgOT7q7p1nKO1efb4MJohuLstKClvvhHwMLH7+mM3c7tYo3
         2wI8sHPSrFxqurTRGQdCGe4ry1WR9teVR7zri3PNLfIwnVj0ECkIkXXmSsNXYeCK6J+q
         BjXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uB1C6Ts6G7kpi/x8fM6vOsSGg1/8Q7iC/D5sUp1buMU=;
        fh=aes5jMqhmiAD31WkUx10VYsAhRHpoZX/hu7y7v/LlhI=;
        b=YPulJjdM87aQMa7hw2XTJYuhYkyWoBXJc9CFvqodrBrRM3oP9zDauyy6QZ7bieeH/1
         ibbmIqgFZI9qRxAUhXW5KFmIq5+qEECa1C5jSNWrI4ne6nG3ZTp52QsfsDiIlqbA51g3
         JTKj+qpEwzksE/u9roK30T/+YJYBdWrp3uLLytuDHsg4stSgE9M2QT43s7f4LNCwHiWC
         UC0xfOF4wLMXIkuY8+x8rDObKXkCAkGlYIDtQvzfVbg1o56HH3uMYgy0OOKINl1/wH8E
         xXBVK+L82TIjmbzQxKGRlgxLA670FjkqME3Aw655W6n0q3GhjPWsJoVC623rw4lkNhsh
         58Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766062492; x=1766667292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uB1C6Ts6G7kpi/x8fM6vOsSGg1/8Q7iC/D5sUp1buMU=;
        b=svtvbGA1Tem8K0rVxVqV6MNUa+c/XVj+tK5MhmwWaQoRRNBac1mpku4RmJpNJR3tWj
         H8E2hng0XQntf151MhRG7kdxZrinnG2NFBZ/ABjKOJJ1SZ5IytQPpIO7czjvuq2Lhpvt
         r6RHtEBwvyr7ZDKaQdhMEcX6T5NwDiBFFakdlv6m4NaRhVh9b6O6NEeFQURv7l3JV4UK
         KOf+OWnxzsgBehPU4ok0kZg8oL6GTFoTF4C8+lRnRFJKHres37riP1vVc7p882T1ljk0
         s69wKJo29e6CGVVWXp/20Dacb7DDR8aQA0I3nM/7p6KgpShHTHxojr5ORhqqz79T5EAA
         JE3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766062492; x=1766667292;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uB1C6Ts6G7kpi/x8fM6vOsSGg1/8Q7iC/D5sUp1buMU=;
        b=AxGDQ8WvcQH4fJsN9ppq+CZrgfGi6MKmQ3wDMWU/spkNidXvu4OFK37l7vLCysv8V9
         36OmTz7/VeGy0506WF32g+lJ1h/ksw7yQqpt1PBMAsQCcjW2Ev4XgG3m3ndVOduRbXjj
         pe9zp5QWseECQEs4IUWWxuRFzRRxB7CyYr3/LeM54FL9mYagu8YMjN+Ilupz14EHG/H4
         KF3Eh1GvYjJ996RzyDHVeaDWArzcsRfsEldnWea+NzTWCytXN8PAEXXiUcncNtOH+xf/
         IhUabtJ6VYwAw5y14+1WtHx9s+vabOKnGx4iyabLdrIJQKKObeuJ3jWZPvS/fWCE10jM
         1idw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrRQg6hrk45NCH9LljxEk0fYbIN4ZQPzqPgSnKTO+84PLbMBKK1YbIZciRAM7IQFLsw4llHQ==@lfdr.de
X-Gm-Message-State: AOJu0YzjePcpFL5KQfWxgyVcFhpW4D+BHaCDAlFkjNYr2jN7Jiw+uQx5
	XyY8bp5bXn2bhHy1J6GgF9TW6Ti03WZ72mNv5+5vdzgVvpYV3bsfVQMv
X-Google-Smtp-Source: AGHT+IF3VRGLjHOeya8BzLN0ONnrIaibvcf8HRg8m/X7WA92BLeScJCxzGOOShJa72hMm0K/p8s1lQ==
X-Received: by 2002:a05:622a:c8:b0:4ed:e337:2e52 with SMTP id d75a77b69052e-4f1d04c0086mr294107321cf.30.1766062491789;
        Thu, 18 Dec 2025 04:54:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY0+bsGwM836d8qwkkzDINVOir8khGRZ7sPFiTbimsrFA=="
Received: by 2002:a05:622a:1391:b0:4ed:3036:f1ac with SMTP id
 d75a77b69052e-4f1ce95a346ls154165421cf.0.-pod-prod-01-us; Thu, 18 Dec 2025
 04:54:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUdv7I2iF68sK9PUkN652KVuOQlpxEko56EjOvV1IMO1xfc9t9TcfCA4RqNrY5AZLD37sLh1Kq9pOQ=@googlegroups.com
X-Received: by 2002:a05:6102:a48:b0:5e5:6360:1f63 with SMTP id ada2fe7eead31-5e8278508c7mr6036375137.40.1766062490981;
        Thu, 18 Dec 2025 04:54:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766062490; cv=none;
        d=google.com; s=arc-20240605;
        b=beMjfhaC+YciNPv/Dlj8opYSVCcGS3WVAr1SCm1Frt7xB5EwL8qXNoCqT48KPfhRGe
         zbBiDlAspUg7/Aruq5njR2M38TZyNkMRaC9kBwI6QaAd27kZ5kSuImvfdDYzHnvUufYd
         HS+kl0AnaJ4LTXFHPjlRMA8Ai7W7+/Qtn5ebdhrlMDf/C32hZ+rPabSHWCZ/87TKKhE3
         iw3ua90lSlPFZ8xNQbyJDQfP/DajPtCKEFf3zg3+7yuNKekf2SFd7FlEg5VqABDg+JdZ
         rYxgc0twVSJU2vzynwtyVnT7Q2D8HJhbRC5S9OSAduyeGj5ICFR6JKr0mHr9rXZIXHrc
         maQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=4LMdjhvdH1sCdTDlt7KNAhLnnS1N7j7PPQ+5bMTb7xA=;
        fh=d0nEaoMMqeNaBrTxc4ov22bFW4S1UooNq37rfuTuczE=;
        b=HPPiwNhAMrq0liYzHPOlCV/qEHpTWKqWrGX7XU5+2H5ArpivFo03AKcYkQXjG4jnHY
         DIVO3jMd2xHxVztWPSmiprnCl5/Il4kmOkNwZ3n9YrRoGVnVws1pJUskheBs8DyfiSO/
         K0SrNN7U753itSDRXFSXFJb8XtbUmIuTIKpKd7vX7qTMG+2zL9owRF/beH3zOxOAboyw
         vbcFck7U+TnaHsV/u5dAG54RHQy4oPGDrLyCA0bFcjZo3b0jzE9nAZhQ3sTQVTpwK5yN
         46dGZ5/peqSlsUrh7kTlhjeBvXkK3SEBDV7FvGQbBYqvqbljvbdmdoVgDyjvD08LnSgq
         8eCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id ada2fe7eead31-5eb05963411si36028137.2.2025.12.18.04.54.50
        for <kasan-dev@googlegroups.com>;
        Thu, 18 Dec 2025 04:54:50 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost [127.0.0.1])
	by gate.crashing.org (8.18.1/8.18.1/Debian-2) with ESMTP id 5BICsdLc454691;
	Thu, 18 Dec 2025 06:54:40 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.18.1/8.18.1/Submit) id 5BICsdqL454690;
	Thu, 18 Dec 2025 06:54:39 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 18 Dec 2025 06:54:39 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>,
        Kees Cook <kees@kernel.org>, Brendan Jackman <jackmanb@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        linux-toolchains@vger.kernel.org
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
Message-ID: <aUP5j7W8S7koM13M@gate>
References: <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com>
 <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
 <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
 <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
 <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
 <CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC+4BdXgLLf22Rjg@mail.gmail.com>
 <aUPsdDY09Jzn3ILf@gate>
 <20251218121813.GA2378051@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251218121813.GA2378051@noisy.programming.kicks-ass.net>
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

Hi!

On Thu, Dec 18, 2025 at 01:18:13PM +0100, Peter Zijlstra wrote:
> On Thu, Dec 18, 2025 at 05:58:44AM -0600, Segher Boessenkool wrote:
> 
> > You might have more success getting the stuff backported to some
> > distro(s) you care about?  Or get people to use newer compilers more
> > quickly of course, "five years" before people have it is pretty
> > ridiculous, two years is at the tail end of things already.
> 
> There is a difference between having and requiring it :/ Our current
> minimum compiler version is gcc-8 or clang-15 (IIRC).

Very much so.  If you have good reasons for requiring it, make sure you
voice that with your backport request!

Nothing we (again, GCC) do is *only* motivated by procedures.  We can do
unusual things in unusual situations.  But you need extraordinary
evidence for why extraordinary things would be needed, of course.  Does
that apply here, you think?

> On the bright side, I think we can be more aggressively with compiler
> versions for debug builds vs regular builds. Not being able to build a
> KASAN/UBSAN/whateverSAN kernel isn't too big of a problem (IMO).

Absolutely.  Just document the feature as needing a recent compiler!


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUP5j7W8S7koM13M%40gate.
