Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVKT27AMGQE6VBKZHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EFF7A4F206
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 01:04:32 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e60b75f87ffsf8174824276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 16:04:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741133071; cv=pass;
        d=google.com; s=arc-20240605;
        b=BCGX0+ofgNycuvk41BWH9U0ZqFIINZlYTaaAoyMeMWkvUUCaRpfHFTJlCOaHnpRBfC
         4ACzkyviNrmF4b/x3rburMNnMayMXxOQCYoJR1x+shjpYlcCRbsggrYR1f137/Kh1DfF
         mKOHYN3EWg++6iOh+kFtSHyaZYw8hM/dXO0YUiOLFG6BOEZJR8ls5xowbyfSZBhNzSeB
         SzvX5NMH1ttBOPJ1yV3RZN8o/pn3qAWkeJ36NN+1hLZtH5aIU7wkxZMXBUk6dAmhPjrs
         X4qf50DLiDzs5SxZ/dAwq1rDGo220f5VgYLlxjdSENUo6T8pf8X9cqOaExLIsi1HmiMy
         4/rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=S5IPU0aPSE9AbzktXJb5ywgBjjWvJNOj+i9uy4x7xOw=;
        fh=9qFfTvNYP4uXXM+Bh2DM68r2Ln3tW6AizJ7JCrWBTU8=;
        b=h3xpUSeBuynAOjK7E9j6As0yEkxEe2QtZZwewAESkAyHXtqA1xaPdF50XMPwFuwd4v
         nRT7TcGTdagFd0KVLQVy8xgIvkLlDh1DoH6s7Bgj2ZUjq8MxhWUgkZlfDelsdE67C0mI
         EAF66LM5+q9G7aOawP3sgoqjHjMDT7c69PlYnIexief7I/AzpM8CL1rdreh5xrTAtlj/
         OOPZeKj2aSxq1VUoZ4CV6VM+wR8OGG/O1/N7ZxLU9VWAWAWZP4jbfa3hREaFROTKpWVN
         cD5ubWNWHB7/24rbQ1N2g8F6OVCgY4j0s51wG9HuHyuC3oOru6Nmk8/pHt+ylZOKdj2z
         +Ang==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RmFdCE2T;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741133071; x=1741737871; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S5IPU0aPSE9AbzktXJb5ywgBjjWvJNOj+i9uy4x7xOw=;
        b=naTBYuoAoi1a3x14c77NcgnTxoIJLRVwRAuuptrRVJo5/EkV3sYgFULlqla3SV3ESV
         pHmW1L9akMtQ1arbGlHGomUVLDiCzsjskUb6kjAuq1pU6rDBkALAF7t4PFt0s/d8W0i0
         V0/27q/P31GKaU+7OFPzfoNK9rXN7yu94B73B3/e3dfFEHQsgGZ+JwA8Q0QTgZDcyi2Z
         08r2K0tsnJW5mgRO9yyyvLIS1Pi3sPW2Oruddr5Fys3/2K4SqJmKmIkP5bVPfTC17hS5
         osX2lXmzPvN5IogMPZfpyLsfBm7oQoI3H7pBRwept+JWZQmOusKS10AcwcE30kh5Xt56
         KCTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741133071; x=1741737871;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S5IPU0aPSE9AbzktXJb5ywgBjjWvJNOj+i9uy4x7xOw=;
        b=KReA0MUwuFJNb5s6BBjLK1PFSFWW3420Y0RXKXEd2ETdcrRlxd0MMWkNeV3RvVIjl9
         9a1Sz8RCcT6gVcZSs/dehirP9JQnOERYua7EvsTppYORtxa/wE8dv4UW3zxHxgDBjNL8
         yHMZruUeTHN4Uuo/9X1vKUF/MmMC5Ym1V1ekrQ/oAd/74JhfVX2e+xFF8EgCzmHbkYzX
         Wbl+30GPfJbvhyfzZWlNUCvPemexGSmPkN/pMTWDGXHCJCI45+i49TDeUUYjP4IDDG8j
         IYbj/D+glZdgVjdjkpSFLcgnA7BvtObWVyi0/rBXZT6hOsRCkhQIaqkBOaw2gvfX1NBC
         2U9Q==
X-Forwarded-Encrypted: i=2; AJvYcCWz10GG/YusRV8BGXy37fEbepPMXDQXpRi8N4D9+aV/ffV00j6ietp4vyQxIAjAoueXItQWpA==@lfdr.de
X-Gm-Message-State: AOJu0YxIRA9L9p6jS4I7uxa15NfmoeyaXMgQ4YPICxeM2T2MX7Cx1e5y
	VpFhmCktZiCrM4Ul2V59gDz0sBiyTWPA+TZMCc58VPab+zELNJJX
X-Google-Smtp-Source: AGHT+IHHHJshJO5nAHa+Yn+GW4seQ9myXCJ4hUkqlahwrGBgjW2Se6GVYxFfUQRBD8jRGhY0qujntA==
X-Received: by 2002:a05:6902:722:b0:e60:a068:a14b with SMTP id 3f1490d57ef6-e611e19a2f2mr1480605276.4.1741133070854;
        Tue, 04 Mar 2025 16:04:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFKXC8W0xdI2SwwFMzOV7syPdUnCp5kkRgrqWgxCXNBGA==
Received: by 2002:a25:abec:0:b0:e5b:3877:6d59 with SMTP id 3f1490d57ef6-e609ef3e767ls1320433276.0.-pod-prod-05-us;
 Tue, 04 Mar 2025 16:04:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVdRjm4iJPxY1zCsuX4QrkwJ1S/hCnpC0/YS2CUrgZLGoog3rogz9A90a1TLSsnGU18O9C0fr8gqSU=@googlegroups.com
X-Received: by 2002:a05:6902:1002:b0:e5b:2a51:deb7 with SMTP id 3f1490d57ef6-e611e1b9f12mr1484089276.14.1741133069654;
        Tue, 04 Mar 2025 16:04:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741133069; cv=none;
        d=google.com; s=arc-20240605;
        b=Rk8QlwqPXK7MdZ467mOLCoOgkoeEYoYBzvdQ00oAoGeyRh4Vrsa0wYfuRbEiQrOXXO
         kAwNLNfDjVQ84c1Ve3g8mzfF2D1vq2fOdf9gcbXmy+sxlgXLukmwDqxLwBaNrMXPBHhc
         ylMYCSjpAw2BzjILpL971Or1WiTYikV4hiTb6vhch+DEHbnIIcdD4br8B4cJLlN/r2by
         ByKhknIeQjPC7HOgLAhqXrsJkJ7s3dM20mrwmxxayE5HHsqIGq0fHQr6npJkm97HRswe
         j/KnWnYE3rLmsmdRCT8xZKX/debrjhlPeURSNYXZ6+Z8/IhCAyLvth04q9vFcADmUdkL
         mBzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LM4+VbDeQgzb/55NI3t+9R4dHqP/5jKcZhBFBtOBqBA=;
        fh=S4hnlfZV4yJpcUZXEmm9bs6S6oIx/8YpQj4cmcTdrHk=;
        b=kHUez3VF0iweOfBd93JyO/1Z6O0YF/8jONxML85fQKbKwj0FFEvOREa4D98i8dQ1az
         MxDL+Wziitm9EXZsWLmDJMpHfNk4jCp3JHR/9Y5P+vLOUfQHrHsXHz5YwdDa04UduzkL
         I0pQZ9KLFl50Y164m0ihcRhDRnj1ukSvWLPJqI29Ax/7/ITVMkMEsHVeiNYla40Lv3+v
         +oPD21Ra0Wve3ZWZUt3TWhz/Vb7vPjTKf18c401SmxsAyTwDNaroe82iLCXV4xqz5Hkt
         zIP7qlSYK0+5rWVb8KTiLvKcCjbbufJf9y1oxf9DMPHmc5ge2RUWxsMjbPv+uDfowGo0
         v0hg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RmFdCE2T;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e60a3ab62d0si760270276.4.2025.03.04.16.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 16:04:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2fef5c978ccso4787205a91.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 16:04:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXKxYkdqk+kcLAeuP/AHofW+AMWaxCAntzTCuIdDrMbEXy1hK0DGc7fvtzbG1tUMRxOqJAIV2W5ljA=@googlegroups.com
X-Gm-Gg: ASbGncsCNFrwFkGSMGUJuIE0fUaTxG5NDpkGrpfDJIIBH8zsKR9gFCturPpxzlskPHd
	vEHWrZGtr5sTC4NI88tLhLjT0vSnKbHM9QgNqO9fVK1CMTkzv//tcEayJS4VkMqEaJJOfO3Gllm
	glzecj+NHdy2DviHZu9xxnqzlO9Y+7iyfe6sFTwvV7P2ZO59NUwNeHNk17
X-Received: by 2002:a17:90b:4ad1:b0:2f4:423a:8fb2 with SMTP id
 98e67ed59e1d1-2ff497cce8emr1999183a91.20.1741133068525; Tue, 04 Mar 2025
 16:04:28 -0800 (PST)
MIME-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com> <20250304092417.2873893-4-elver@google.com>
 <41a14b09-9f09-4abe-8caa-89cfe2687562@acm.org>
In-Reply-To: <41a14b09-9f09-4abe-8caa-89cfe2687562@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Mar 2025 01:03:51 +0100
X-Gm-Features: AQ5f1Jpv14gcn7aAs4yWXHhRLBF4i5EQTdXxL-iYYKY2gY0B-tX3E5j-KtDZzBU
Message-ID: <CANpmjNMYoRTj3F1L9UCp2gHVbVZw0ieNnk0xPZ8Q--BhFCy7Ww@mail.gmail.com>
Subject: Re: [PATCH v2 03/34] compiler-capability-analysis: Add test stub
To: Bart Van Assche <bvanassche@acm.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RmFdCE2T;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 5 Mar 2025 at 00:52, Bart Van Assche <bvanassche@acm.org> wrote:
>
> On 3/4/25 1:21 AM, Marco Elver wrote:
> > +#include <linux/build_bug.h>
> > +
> > +/*
> > + * Test that helper macros work as expected.
> > + */
> > +static void __used test_common_helpers(void)
> > +{
> > +     BUILD_BUG_ON(capability_unsafe(3) != 3); /* plain expression */
> > +     BUILD_BUG_ON(capability_unsafe((void)2; 3;) != 3); /* does not swallow semi-colon */
> > +     BUILD_BUG_ON(capability_unsafe((void)2, 3) != 3); /* does not swallow commas */
> > +     capability_unsafe(do { } while (0)); /* works with void statements */
> > +}
>
> Is it guaranteed that <linux/build_bug.h> includes the header file that
> defines capability_unsafe() or should that header file perhaps be
> included explicitly?

It doesn't come in via build_bug.h, but via:

  scripts/Makefile.lib -> "-include
$(srctree)/include/linux/compiler_types.h" (all TUs) ->
compiler-capability-analysis.h.

The things pulled in via compiler_types.h are treated a bit like
builtins available everywhere implicitly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMYoRTj3F1L9UCp2gHVbVZw0ieNnk0xPZ8Q--BhFCy7Ww%40mail.gmail.com.
