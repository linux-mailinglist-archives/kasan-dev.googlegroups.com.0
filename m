Return-Path: <kasan-dev+bncBD3JNNMDTMEBB6W2WDDAMGQEIUQTIGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F0F0B85DED
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 18:04:19 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-7459d4431b2sf1161997a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 09:04:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758211451; cv=pass;
        d=google.com; s=arc-20240605;
        b=HXCqgOMwonux8uR7fC3fDyvSo9eXgvuh+vGis7UNi9jI9Vq2S4RtKXHoMEOcRYbhu6
         W2uZWIO4SF11B2RIxCikbnKyXahJGFjJ480WMkOqAbJLhiyAy9EbJqy97hFX1PUuPKTy
         OZ66O2FRyU68Ra2YC0g59CpmXPKb76K4vVsQSH4FYMX18UYGTflmBl/wdOn7S4W3mVvz
         Cp5wTJOpf6bIcXQ1bArJsbjoddds4zwIz9/3Jc1M7MU1jbEd03RW30ZOibdBlZu1ToZK
         Olz/x4z1uL3nBYlTJV2mTvYxLNKdTwbiBjXHjp6t4GEu1Qf0uI5wwJkD7AmQ1hGB1Z7+
         BrFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=y7uackCKyKrERQ7L3zY1tjyjUSy+u9E56u5fCrHy++I=;
        fh=A1FNCPp5c563oadgR9nEOjnlwBWbGzb2nfpJluOhZyk=;
        b=juwdE2lGAwIjVuLQNc7decsBd3jhR6JohYaodFrMTGKDIBuaHwoLko2tTn2wIsSxDb
         ijrrAB+TamSI37YDvs0/tRYRel3PE6QMTwCoVS1QDnDaF/jphCyk16+EcZANIlijWvXj
         gYzB8omJbjL9LIXnsOOAxuFyBhGppmBXjFdJ9MrbQVG4LmdkRUw6t0Hf66KPexPBlCUC
         re1HFTMujGn9wlJpzSb/TJS/tyfmx/HX+GxW9x3XBpBTBeIHb0SPzd6DdhNJvHW1KfrR
         IAdVGRj0Sp0FSim7naz2N6v4vdViBonKTQnl1Aq6mykmj/ssMUBT/9DXl7pesdXMEe+z
         E2tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=Mf0M1J8U;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758211451; x=1758816251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=y7uackCKyKrERQ7L3zY1tjyjUSy+u9E56u5fCrHy++I=;
        b=PL/SsJGir3Ooi8Op8JdZJw0cfl6p5hdIUGj2gz4gUR3oTKOiOssPfNcQlGZuqL5Cd2
         I3XCFdXH7w2zSSlqO78CKluXS0t8eAsFGGtiNT2WT13RHNa9guAGZ4DMHWNheOM4reOn
         Xf7+2UGVooYjRwY42G9i89USHIUOBPYAL2rdkxLbviU8eWSgkBfw6CSTGNM/r6g71DvK
         pVINdpXarodzVu0tBro+Jn8ZtdaNKTE51MUzA2pI2F0gncMYR4/LRa6AMc9eSNUpaxnh
         cPwHBWkfc46rIj8u1KUptVSuY6ygEOiAKe2uENlzJINn0m2yQX2e8+SGpul6iNPmYmTQ
         b1Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758211451; x=1758816251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y7uackCKyKrERQ7L3zY1tjyjUSy+u9E56u5fCrHy++I=;
        b=loh5wEdPHH71Ts+4tzLSftTPDbS6AYBXyteMatnkAcAdVuhimB8TKnozxQNnLidY1U
         sOUgGwf2eVHfr7jU56bU/h/IQBs4xg/+iEq1MXxaGxetkT8OBtNe51ybSydezSTnjjKr
         4D7TGDLESwk0vKlmyMLaPyBAeawyuf0j/ErA5/gfrKXUXFyRfScRKFmI7YTOutE4z9UE
         YQ5OFP2m21oD4PtD99RP/ZUiocnaJoYXOKnPGjAbX/JB8tOwgwThu0bZQ51juVmOPEJB
         tsNEDSVl6QfQuKIKungFNHmXEQ2lt7tFvU5ShRMIGW9gfv6y7l1/Iq3oU+AOVKINjWSe
         BAGQ==
X-Forwarded-Encrypted: i=2; AJvYcCW5G3ElrS3Ee79+exYYSeG9P9Ft3DCxmAKVpeHR47OychpywM5eMEwzbCNdc9m04lYKvLzBpA==@lfdr.de
X-Gm-Message-State: AOJu0Yx6VnkTYprZTZo7p2tmoBr/zccQGjuqjPdQRKbNFZVW3kLSIdsy
	6pa4slT987nYgTLcTGIRhDJubbUFCkan8GKxd8DbK19k1zwE9BuLcWT+
X-Google-Smtp-Source: AGHT+IE0OyzJOd1N+/ZM0+T7yrH3xd0S4aQPhA3Au/K+yZa6WrGrftc7Mcf9WAt1n9ZxJzhGw/VX1A==
X-Received: by 2002:a05:6830:6f87:b0:74a:1f03:db5e with SMTP id 46e09a7af769-76f7bd9497bmr121086a34.21.1758211450643;
        Thu, 18 Sep 2025 09:04:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5mIi/KuRiSBbCB2rHscJksIWeVboTJ2D4svFNTdhOjyg==
Received: by 2002:a05:6820:c08a:10b0:623:4d59:817b with SMTP id
 006d021491bc7-625dfabf7d3ls290092eaf.2.-pod-prod-09-us; Thu, 18 Sep 2025
 09:04:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWP8uwM5VFJSlJ093SQt0t+E3PpDay02SSHxYmn6UD00Op9bFisp/8iMZOtiNXAoVVsdqBdJKzR7M4=@googlegroups.com
X-Received: by 2002:a05:6808:1528:b0:43d:2218:5e3b with SMTP id 5614622812f47-43d50b0a1b3mr2830401b6e.4.1758211449457;
        Thu, 18 Sep 2025 09:04:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758211449; cv=none;
        d=google.com; s=arc-20240605;
        b=lj50yIazJkv5hSFSr0miQ79ndSN8gDAtcQ4Xa9+A92i3Tc4l1XRCugVr5/wplg4uyq
         fhCHNM2rR64NinKhAmU/aoU4BHt6/epRNEv/2Lz1CY1gF7iBTDEA4Zy1v0AjIIMIx5V4
         m1mZgpauJ1zEdp1vnUaiLOxRs7veIR6ib89NZ6x4++RPbxxvBgo5/0VwjKnZgnGmsFfR
         wc55yQM5DSOz6gdzYTKV7MGtW/I7trjQtBsIgQK78iwzWwFTL3ZNU3nDJwJWlYNiopuW
         AQ0ggv5uGOE6ehwoatv2hX5ZDXkPpw/9ycNy/rU5F0ZXaAoOXNuUjmrZi6DXYFj9w4rJ
         6DJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=4wzWm6RSRc1tNocFJFpFoox7GYZLGguM76hcy5QnMFw=;
        fh=rtDfM/8UKfqIdLSvC2M7G9S6POR45SemDPs2YvrtnaA=;
        b=f54YSXjwLfGeJl4TDOJl/ywUbfYd9RcjR15BdoPaB8j7+0CBOf88rMEjHqeI5iqw4B
         BQDiP176C1ziCFZwLU4uMRyUdNy7cIik2bjquEjseOyUuIyH8BoV3VD+YgNbXFP/xUpg
         zPWD3SFC8HDVhVcGBl/QIqiO9xuNVNmoaaqDM3EDSOBmYyCv0hJgYazBAI1N08KAEm6y
         BXJlfo8CIq+Sx3t7v8/WHTrDwgslJ3s6ZQaBBVAM1k9YLEbzf/VguqRqv71wQxU6kxMm
         pYJGtcDKlyw65Cb5UqCaj1vsJ3sLUKUJxkZ3d5sCWaSoVDgT8I3THn05OYNRTH5JRtwQ
         0sdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=Mf0M1J8U;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 003.mia.mailroute.net (003.mia.mailroute.net. [199.89.3.6])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-53d1f1f2b6esi93563173.0.2025.09.18.09.04.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 09:04:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted sender) client-ip=199.89.3.6;
Received: from localhost (localhost [127.0.0.1])
	by 003.mia.mailroute.net (Postfix) with ESMTP id 4cSL6c3snqzlgn8k;
	Thu, 18 Sep 2025 16:04:08 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 003.mia.mailroute.net ([127.0.0.1])
 by localhost (003.mia [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id 6L6n7UbPW0mK; Thu, 18 Sep 2025 16:03:59 +0000 (UTC)
Received: from [100.66.154.22] (unknown [104.135.204.82])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 003.mia.mailroute.net (Postfix) with ESMTPSA id 4cSL5g10BTzltKG9;
	Thu, 18 Sep 2025 16:03:18 +0000 (UTC)
Message-ID: <1ca90ba0-7bdc-43d1-af12-bba73dd3234a@acm.org>
Date: Thu, 18 Sep 2025 09:03:17 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 02/35] compiler-capability-analysis: Add infrastructure
 for Clang's capability analysis
To: Ian Rogers <irogers@google.com>, Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>,
 Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
 "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>,
 Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>,
 Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Jann Horn <jannh@google.com>,
 Joel Fernandes <joelagnelf@nvidia.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 llvm@lists.linux.dev, rcu@vger.kernel.org,
 Steven Rostedt <rostedt@goodmis.org>
References: <20250918140451.1289454-1-elver@google.com>
 <20250918140451.1289454-3-elver@google.com>
 <CAP-5=fUfbMAKrLC_z04o9r0kGZ02tpHfv8cOecQAQaYPx44awA@mail.gmail.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAP-5=fUfbMAKrLC_z04o9r0kGZ02tpHfv8cOecQAQaYPx44awA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=Mf0M1J8U;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.3.6 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 9/18/25 8:58 AM, Ian Rogers wrote:
> On Thu, Sep 18, 2025 at 7:05=E2=80=AFAM Marco Elver <elver@google.com> wr=
ote:
>> +config WARN_CAPABILITY_ANALYSIS
>> +       bool "Compiler capability-analysis warnings"
>> +       depends on CC_IS_CLANG && CLANG_VERSION >=3D 220000
>> +       # Branch profiling re-defines "if", which messes with the compil=
er's
>> +       # ability to analyze __cond_acquires(..), resulting in false pos=
itives.
>> +       depends on !TRACE_BRANCH_PROFILING
>=20
> Err, wow! What and huh, and why? Crikes. I'm amazed you found such an
> option exists. I must be very naive to have never heard of it and now
> I wonder if it is needed and load bearing?

(+Steven)

This is an old option. I think this commit introduced it:

commit 52f232cb720a7babb752849cbc2cab2d24021209
Author: Steven Rostedt <rostedt@goodmis.org>
Date:   Wed Nov 12 00:14:40 2008 -0500

     tracing: likely/unlikely branch annotation tracer

Bart.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
ca90ba0-7bdc-43d1-af12-bba73dd3234a%40acm.org.
