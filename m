Return-Path: <kasan-dev+bncBD63B2HX4EPBBD4YUOVQMGQEZ5TMWDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 91A147FF8D7
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 18:53:21 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-35c73e80782sf10231845ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 09:53:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701366800; cv=pass;
        d=google.com; s=arc-20160816;
        b=absUa0ytV+UFjzHFmCO9oMACvqatM+OxY+AVi8r1AFDjzkFAm0rUyiF/ot9RX6eWRj
         0N+pBV22C1/1cDJKBatQbfjMPlxH/S0BZW3F22MQfSYQR7WJs1pXVUKY/OViBpi8G0RZ
         JjzHXww5AhWJZiv4kNHVff27xP9I1f5Q0Mc1tojdmVQLxYBTQ0DNrvurzqZsYgQhNVDc
         fQqiBN/WoioMv64nrq6xXpI+OCVYDxmASol+RslhbsuFE0wZqOA2We5jKWxrmg/faM/0
         +rtrz7ce5Pol6CZdxysd2QMXV1S7jyRg0RMEI5eSMWPaoIOnsh3riLBkPfJLBSK76gbm
         Ozww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=8/ZMDgMB5KYhOXIkJIa+h8qiZHHhnPclwpk8mSTgt5Q=;
        fh=BCL3G4/EB/6E43qIQvqiTmSskf1MQ2+iKF4M83YUI6k=;
        b=KOjvDUtfpiHNMpw72ct0FFBYb3zZ/P6oPyD+2WyppT2gk0kw+fj2SSHDhp5IiUY80t
         kG7t3ruRn0ROv1lk9WCywyAvJya5ZeFnqNfzRazQyUvGlm5LxNh+R/GSjgtTSnv82AEX
         lbjShWyrA2Gxbb2ZhuqNo3hmL7wFlNDR/A+nfOjPbAQ5xUJ1EAjR4VtWBcr1bYhnzOcy
         74TmIZwrd3W1ChZFJx+cFQDqsQs1EWSUf9cAYJ5Do6CI67yB85AwIjatAXyy6KS/Wsn+
         GHvfOIY70wN7ejs8WFmN06sUq7sFWs2YNTcVMF94VDjx8AdApAG7ozN3nwbsCiPhghjY
         DZwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google2022 header.b=ZUH7LDpZ;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701366800; x=1701971600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8/ZMDgMB5KYhOXIkJIa+h8qiZHHhnPclwpk8mSTgt5Q=;
        b=tBez9Md6JnndWNhybXivn4oRzGrF8HF9Mzo86yFRurliOGHk+p46Rj/0wBR/OaWkf4
         7U7Bz/N2j7wvirLmqtn/F5YfRd5Zg5smF4G1MGYrzcQGRLZWhM9sGKz5h9zDknuwEIDG
         ODZn/t9ymzjG++aoBUj9PxA1mgiYN/SWwoqOnwBmyXiGs+ChBECYFeaoIb0Ioj9SlGT1
         sWkzg23bFOs8eiJbgwWixd3Y5sk3GINVDyblAhBQ1rtPHPc3O9397MO3BHxfNRVW+gdr
         jO/HbRKld3EDGkm1/NJ2n8lzHEOjEyH01Vwepy6BVu2A5uamp36FdbzwubpWiuRMqSSA
         JjrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701366800; x=1701971600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=8/ZMDgMB5KYhOXIkJIa+h8qiZHHhnPclwpk8mSTgt5Q=;
        b=t68n+aBda9eRqh1A+iJX/SWVmfCJ0js2Wi9CG1UwVs/lxFk6oGMS+rjndoWTIw85r0
         KhPNFcolcpsqpbJxrxviMFTZwLTFjzrq25MwXjz0Df6KS5EgT5qZ70wfAnlUR5wuDPdT
         tVWaVX6dt9945yObE8oU58mHWyxygjmTY2Wy9Ahb0WDaESr0H019H/8U0ftoPZzqwcKd
         jLcoGm0Xo9t+xKzYEQpFJfJK5TRCExVeY0gE405cDqPUd8UZDjL7hugcFZ6RYlppVqum
         hfo3gKjixKL1g4LY1DB+cAC3zwMbHtvBUK6aiwVSoEDOmve4dfY+dNMXgHXIKM8/GVZz
         xlrg==
X-Gm-Message-State: AOJu0Ywhy6oKiNWmqx6SrlSIzmEFf1vnz5JR5Mplb+ZXJR9JHRBma+q1
	BX4eoNIbjJIJW4FCovRjhaM=
X-Google-Smtp-Source: AGHT+IFLGHre6yIS8nxCQf0CYd4EP5CU5cKERaCycGJMxihVf+pY3Bmo5tBOn+oIuJOZjrJZGfQZ/g==
X-Received: by 2002:a92:d141:0:b0:35c:50f6:b57c with SMTP id t1-20020a92d141000000b0035c50f6b57cmr21871208ilg.8.1701366800060;
        Thu, 30 Nov 2023 09:53:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2182:b0:35b:fcb:3f04 with SMTP id
 j2-20020a056e02218200b0035b0fcb3f04ls711386ila.1.-pod-prod-03-us; Thu, 30 Nov
 2023 09:53:19 -0800 (PST)
X-Received: by 2002:a05:6e02:1e04:b0:35c:8410:84ee with SMTP id g4-20020a056e021e0400b0035c841084eemr21259111ila.24.1701366799323;
        Thu, 30 Nov 2023 09:53:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701366799; cv=none;
        d=google.com; s=arc-20160816;
        b=qOKP9ve4NPouykIO9IuNbClDLFtE5+bz+wKTQchiVz6mF6Fep61TtSM556d+QSVJvp
         2H4XE1eVxc6dTF3m8ovffaPtnCWTp7EJlsX/cEWjBtUYkfLGMkwOOgxOmfWcYLBthL65
         t6NvOwuW7w9j4h5ggKqBx85EMexXLkxkXpaXJHZqaNSUieIq2ehPn55sipSKGyjijSma
         i1gHicSvJqV7K6VbO67WeGf3FXC74bXprhGoM/hy+JG/P+jfwZd1FaA1OOwqr6/MH/MJ
         oRdJXLCUbCHk+/lgsk/xrYhZlpHsoNnm8n3YEB5NNhTUCSwjiJsNj6TgrTQXZ5S0gjSS
         MlfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qL+itczn3HPThVSLzcVj75fGWS5itqBGFZ6hUHZlR5Q=;
        fh=BCL3G4/EB/6E43qIQvqiTmSskf1MQ2+iKF4M83YUI6k=;
        b=mGn2jzC3NpHXaLn8IKASA/SOFwdJwEntUVGo6KxNl2wnq8Zima7ccjlM2n1Or5DTwz
         AlH/V+0DoPgGpdMw4huDiBUjwv5vj9kHtO8br0w+dXF9OIcqe1Nwv3c2Wgo7lY7H6fIP
         pvwpnU/Juu/G2IfkcStNEgUhckvROpMGN4YHBFtxbuSw8/tlntn/PiDGUHI1Kzcfq5pc
         IS89U/oxF3xh0PzC4bYMaEOU7v5x2b5VTbN5u08s4T3w+yxfwh4bupx0FuaJWQYzQ9T8
         3FA/+Yx5XLMdGhp61KPYw8zPlGm84eO2CYgjC/saL0uOMu9SsamqSlfaSkVRoMAVJ8Vg
         SBQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google2022 header.b=ZUH7LDpZ;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id g10-20020a056e021e0a00b0035c8cf634b9si497198ila.0.2023.11.30.09.53.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Nov 2023 09:53:19 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-6cb90b33c1dso271630b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 30 Nov 2023 09:53:19 -0800 (PST)
X-Received: by 2002:a62:cfc1:0:b0:6cd:d6eb:2f29 with SMTP id b184-20020a62cfc1000000b006cdd6eb2f29mr5585810pfg.3.1701366798540;
        Thu, 30 Nov 2023 09:53:18 -0800 (PST)
Received: from cork ([208.88.152.253])
        by smtp.gmail.com with ESMTPSA id hy7-20020a056a006a0700b0068790c41ca2sm1508783pfb.27.2023.11.30.09.53.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Nov 2023 09:53:17 -0800 (PST)
Date: Thu, 30 Nov 2023 09:53:15 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: dynamic kfence scaling
Message-ID: <ZWjMC9FXSEXZjNw9@cork>
References: <ZWgml3PCpk1kWcEg@cork>
 <CANpmjNMpty5+g76RLy5uZARZAfx+Uzr+z5uAKMp-om9__2O77Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMpty5+g76RLy5uZARZAfx+Uzr+z5uAKMp-om9__2O77Q@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google2022 header.b=ZUH7LDpZ;
       spf=pass (google.com: domain of joern@purestorage.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Thu, Nov 30, 2023 at 12:09:14PM +0100, Marco Elver wrote:
> On Thu, 30 Nov 2023 at 07:07, J=C3=B6rn Engel <joern@purestorage.com> wro=
te:
> >
> > That works for the instrumentation frequency.  But it doesn't work for
> > the amount of memory reserved for kfence.  We should be able to scale
> > that dynamically as well.
>=20
> Yeah, that's been requested before. The main problem is that it'd add
> a few more instructions to the allocator fast path (in the simplest
> version). Discussed previously here:
>=20
> https://lore.kernel.org/lkml/Ye5hKItk3j7arjaI@elver.google.com/
>=20
> Maybe it's possible to add a config option and if you can live with a
> few more instructions in the allocator fast path, then maybe that
> could work.

Ah!  I think my scheme wouldn't add instructions to the fast path.
Let's say we grab 1TB of virtual memory for our pool.  But we only use a
small fraction of that range.  Then the fast path would be


	static __always_inline bool is_kfence_address(const void *addr)
	{
		/*
		 * The __kfence_pool !=3D NULL check is required to deal with the case
		 * where __kfence_pool =3D=3D NULL && addr < KFENCE_POOL_SIZE. Keep it in
		 * the slow-path after the range-check!
		 */
		return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_VI=
RTUAL_POOL_SIZE && __kfence_pool);
	}

Notice that we check for KFENCE_VIRTUAL_POOL_SIZE, not KFENCE_POOL_SIZE.
Any address inside the 1TB range would return true.  Once that happens
we can check whether the address is within the much smaller range backed
by physical pages.

We probably want to avoid having a single contiguous range, as it makes
shrinking problematic.  But whatever we do, the more interesting check
can happen in the slow path.

> From this I infer you mean an effectively unbounded pool, or just
> having a soft upper limit, right? That looks rather tricky.

There would still be a bound, but something like 1TB will appear
unbounded to most people while still easily fitting inside a 64bit
address space.  Even if we only get 47bit effective address space.

The tricky bit is that you currently seem to allocate physical memory
ahead of time (contiguous physical memory?  I should check).  Then you
mark pages PROT_NONE or PROT_RW.  There are two states for any page.  In
my scheme there would be three states, with UNMAPPED being the dominant
state.  Supporting lots of unmapped pages requires a hashmap or
something similar.  So yeah, 98% of the work is building infrastructure.


> Looking at the problem space from a higher level, we're hoping that
> Arm MTE and whatever the equivalent will be on x86 systems will be the
> long-term solution to this.

Hmm.

> Logically, every 16 bytes of memory now contain an extra 4 bits of metada=
ta in addition to 128 bits of data.

That sounds rather expensive.  Which makes it more than just an
implementation detail.  If the cost is too high, people will choose to
avoid it.  The beauty of kfence is that it is cheap enough to avoid
such problems.  And a software solution today always beats a hardware
solution promised to arrive in the future.  Plus 5-10 years before
existing hardware gets replaced.

We'll see if MTE works out in the long run.

J=C3=B6rn

--
Squeezing microseconds is a very addictive and even destructive activity.
It ruins your evenings, destroys your ability to converse with human beings
and typically leaves your code in a mess.
-- Bert Hubert

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZWjMC9FXSEXZjNw9%40cork.
