Return-Path: <kasan-dev+bncBD4LX4523YGBBAHJQSBAMGQEOS3TIEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B76B732DA59
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 20:26:57 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id a18sf4771458pfi.17
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 11:26:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614886016; cv=pass;
        d=google.com; s=arc-20160816;
        b=FBA9KIs++My0FuuKpSix7rHftWulbQ/4qzd2i3r7vui+Al+1ThkK5V350YQ1l8teTn
         TYhB6Y5b3jEMDkNnj2WQOklZx33Ix+lUY488WYnACgT7UGy0kxct5j1QI/Jud+xsm44N
         X3qJH1yRNNBl6wfXxVgkkLFqMlsa27PpO+6lwZ8mRXagUUdIwh6NlocvGWLDzmZ0yU9k
         bwAHGQjE4uq29Ho1xa5XtJpm87BFhCgjuWLbRkED5axVVA9ICgV9FF0B9JbJFbpuuTu+
         FcktS6Ks/o4XZfqoG6hOUCNKbfAAkldeIqA7mHFCpfFAxeuELSx8cD7PC5m9MvupYICA
         HAwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=mte9J34wMMIbMnd5grEZx5Ly8QzwJCkBpaTfOXjtBhA=;
        b=hvzJL0qpEVaCpkgSmmfGfyX/LHxQCgVl1CBZjtWD59ms2K8PL8gEgqA3tVYTzBtOcO
         DgFQ0PMTt16zg7r6GIJsNZvBYqWBgE2E6fGYbgYyOsV79MzITRWtYFvP1qVCxKbJDsPV
         dEEGtpzRfH6WMfqsBElOzHcmUPQ5SYl3qkqj0ZdOjHoT+Pc6tFSJiCPxdyaHuNUI0yRc
         iP6QbcjuQy4UPYcLeeYml8m1gFqu5PFWKIAJNYwjvWAqNKKU9ClQ/qKDuF9B6fU/Sc+X
         fhcp7AagzmIdETdrtdqu3oSVzrhlH8tMdoUtSmkB6QejGHfHEOAU43C1McK1a1Z+irDT
         RMRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mte9J34wMMIbMnd5grEZx5Ly8QzwJCkBpaTfOXjtBhA=;
        b=YgeRiO8fpRA4UkEJpbnthXMdRQWNEd8ozOtcSqBJ3//ceFkTVe8A6wG8IzYmZkUIi9
         4O4sT1O36VxkA92Bl/80UD5k1BG28RYT5uiz0HIzqtV0oXkz1tU90+O8eBBdRX3QXUhY
         cGuemFp+nPykwikJd3Hih1demsJq3uD6AngAc6gINdCFSbl6FmB7W9uBmsTEu3aAnBQm
         d5gBpt400A+vgHkE7p/CoY++13P3q9lDNidRvnpx1N4doujsTb/242oBt4J/34cy45iq
         c4/3vvv/eSqJz1joff38cfniFGB/5cjOblqTEviDCWGLHRr6G+2J/Rv0yAAs/C6FEA1c
         00Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mte9J34wMMIbMnd5grEZx5Ly8QzwJCkBpaTfOXjtBhA=;
        b=RxyOTFhnR0r33xOaq3JsuO2aTYElhbNdCSiQuAvmV2rwyOgY9Iz5nSu493iJsLgfFu
         NvrZfAZhNugA2oYv8MU5djoxOzAIw4JuM9JkjWgFbWTPQE/MewxlinpbbQov9KMVlCQt
         myO9HDN2Iw5z3LYKM7OYBv9WW1L9Nq9srvKO5mAze1ryUd2S5Jc3XlJOOifziUMltAjB
         TEtghnqNxKhigA7ojQVSM2C7WL230+R+XEK02ijEaTZPv+/5nUDcHVAZQo74mYN+3wkk
         z9LsiJB+q+u7QNEnPbbJdIkxsI3twnu6hSZe/YxHYee1FiKtz96u5hBWWc1aik4FS/ib
         cWHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ITZJvm2utAybywGY1fIhcNLmUVpKMAkvH05CtIyU3MY1kta4N
	gz7N1fY09WVGspN248ql5Lw=
X-Google-Smtp-Source: ABdhPJwTuteVItxvOm6rUA90U16m7KqDQp1gSKEvBGiKlVpNCMmVtlEd1ora94um2w4ObCnOKjMSKA==
X-Received: by 2002:a17:90a:f010:: with SMTP id bt16mr6168206pjb.116.1614886016360;
        Thu, 04 Mar 2021 11:26:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9106:: with SMTP id k6ls3864430pjo.0.canary-gmail;
 Thu, 04 Mar 2021 11:26:55 -0800 (PST)
X-Received: by 2002:a17:90a:654a:: with SMTP id f10mr6011002pjs.202.1614886015659;
        Thu, 04 Mar 2021 11:26:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614886015; cv=none;
        d=google.com; s=arc-20160816;
        b=d0jGq8tC6qIClmE21o9BbKHTPUfEDZBrfsIKjgKeYRu/hkeKmC7Q7MAFktS7sLVz5d
         ufSW6Lu+bpKL7ju7Zu6jy7UWJqoVMBwDGw2sXTjamO67i6g/7hO43bcHnOKr8uqGhHNX
         Huyjl7hdfsyZcgxOCnl2ltqU1UgAH4oDTtoEVRqUGUg2etU6Gf4QWHGUZYut1SRO5Ali
         +HSLCCys0PpJWMkVyIAXcdNHCq1evrnTZS9QW44w9ky/yt/gLg3yAlfwWqjhsdLEqnOQ
         IF9LE0XAz2lZi6vQvG5djggzoOWDNuC1LbZWSu/bT7mdRZgQseL1nJ7StbAs90yCdp2W
         DsHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=cXONi2N9A93eZ0DU3c70s17ZhKfjNIGPqAU4S8KvLU8=;
        b=C7Rwd0eW+1XXmpOZYOdeekwRo/EHv8Shhw71Tt6RR8syxGgmTErfMMZImZNt44AYAE
         PBbO7YdQp2pNZjGU+egv2aKYwFbtcKgm9LyJswG/9AaFvAsXRJ8YVpPyWhKwmlIx0l8c
         XsknhIw1UKlvYj8JOaI7Y31SkXZOzVYdhBkqzfUC4sJFOgm/7gnZQN7iTT+KyEvGDnwj
         gGhDccPDJeS7f0JjUD46/TnmLGyR72LALNo9qxuFiXhMO2Q5eIBbH+4UC8T6oSEauahA
         5nP2hwQ1n3R9lgagQRc4oYS0twmOqH5FuZDmSaeZm2MBNjGZf2NIY0YS1p8fCaCiBle+
         n+rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id x3si34838pjo.1.2021.03.04.11.26.54
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Mar 2021 11:26:54 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 124JOm06007417;
	Thu, 4 Mar 2021 13:24:48 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 124JOlBd007416;
	Thu, 4 Mar 2021 13:24:47 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 4 Mar 2021 13:24:47 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
        Mark Brown <broonie@kernel.org>, Paul Mackerras <paulus@samba.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        linux-toolchains@vger.kernel.org,
        linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in save_stack_trace() and friends
Message-ID: <20210304192447.GT29191@gate.crashing.org>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu> <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com> <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com> <20210304145730.GC54534@C02TD0UTHF1T.local> <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com> <20210304165923.GA60457@C02TD0UTHF1T.local> <YEEYDSJeLPvqRAHZ@elver.google.com> <CAKwvOd=wBArMwvtDC8zV-QjQa5UuwWoxksQ8j+hUCZzbEAn+Fw@mail.gmail.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKwvOd=wBArMwvtDC8zV-QjQa5UuwWoxksQ8j+hUCZzbEAn+Fw@mail.gmail.com>
User-Agent: Mutt/1.4.2.3i
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

On Thu, Mar 04, 2021 at 09:54:44AM -0800, Nick Desaulniers wrote:
> On Thu, Mar 4, 2021 at 9:42 AM Marco Elver <elver@google.com> wrote:
> include/linux/compiler.h:246:
> prevent_tail_call_optimization
> 
> commit a9a3ed1eff36 ("x86: Fix early boot crash on gcc-10, third try")

That is much heavier than needed (an mb()).  You can just put an empty
inline asm after a call before a return, and that call cannot be
optimised to a sibling call: (the end of a function is an implicit
return:)

Instead of:

void g(void);
void f(int x)
	if (x)
		g();
}

Do:

void g(void);
void f(int x)
	if (x)
		g();
	asm("");
}

This costs no extra instructions, and certainly not something as heavy
as an mb()!  It works without the "if" as well, of course, but with it
it is a more interesting example of a tail call.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304192447.GT29191%40gate.crashing.org.
