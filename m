Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3PUZPBAMGQEOACSD3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E803CADF44D
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jun 2025 19:42:07 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b26e33ae9d5sf7958057a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jun 2025 10:42:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750268526; cv=pass;
        d=google.com; s=arc-20240605;
        b=MqztFtlcoglqxWOs/14HE/N7+5mujcnhTIFhK9xaksLx3qsH3/GNP2e7Y+pIdIntW6
         iVk2yI8hCP7jcYYPiCQLFzibN5nP38f3FT1/UJ9jvh5ui8BoPfrXgV5aAk0Pp5jDu9sE
         gf150Ilg8sP6DARwmCclk8MTgDUh0E3l7EUi82mXC8CkNhEN+Q2DU0ONgaj0sjpQk8Sd
         XwnDywYJNwBR52wCwJdsj3AKk86z9PbIaVXsRfqwTUDvL6MwsJ9YYz4nCNZduZz2lG2D
         hR6PErnnoXEEWhF3FbALRH5M54hxpRv1OVIGnGhIPlCoRUgDBGSDBpPCcFnnBTyhl2yb
         YTiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3kdJdfEac9N7CFL+bIdxUs/t8NAKAugVO9PPZG16HMk=;
        fh=4cb0MU1x7vMpOramTowPq9GoNpjAdf6xQHS6akyUz7s=;
        b=BigFqTMxp2tAm5kWmjKjDOyfSlasjXqgmsg5Oyh499DhW86vBTQYDZ5VkbNFA+Xj6F
         fRFuorcRPIiNerRRVaXflGActzNK3sg+aKGP767usmRsZe2xINUbkxbk2NRdh6eB8wlP
         i6Mlec+v6vt8cMLnvFsjqi9Id32EQobGrUxKehWnREniS9lwBgw9ZVtWi5i8I/wdtdk4
         BH5vtpmLbZE4h65VXRrjQI2iKndRUbTxSrP8o40MbRHgWLxRn2slPHGgLL0XddN1vUdi
         H4M1a3ADehPtVtUitK7Ha3lwQtWs/tGR6UvnQcAhkfMc+8Ua0+lZ/BkYu2Mar5RH4fvH
         SaDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3URY6+A7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750268526; x=1750873326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3kdJdfEac9N7CFL+bIdxUs/t8NAKAugVO9PPZG16HMk=;
        b=kxFtdzc7RTC7Nc/y8IJzEHzkcpABaDpQXqtwCwbBmxQc5vl5s2euYY7+yKm8uIiGkq
         5qFjDNTvhiwqhs2LnxRdQK3Je7fxYQHPuc/Cwpg3pclZaHieeDyv0X3DM0xWHtyXVC1K
         4aeaLPBrG/fEorVLnYlk6whIvoVWUMOa1QpjpvYYkvZM94Q4dSJtqaQJUKZrZMSznJ2J
         6PhRkJGYfltLdlgcktrpjyw3fDk0au2q4JBa1q9jSOEN4tOA5M7siwlXKTVoA0ZhPPbb
         t4dI6Ih0pY5RUxcld8LN/7Ex3ioaVFLs30R3ApeOK+8+XUI7Jq7TiFkohsVZf8UKEx/K
         dkCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750268526; x=1750873326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3kdJdfEac9N7CFL+bIdxUs/t8NAKAugVO9PPZG16HMk=;
        b=qLjMhi+VKuKbPKTdir+s30/hbZVh1flsJlbOowYa/L0pbwvF7UE+oMC8zQ/BYvBEso
         MLcfQ2/GGZ4H9eP2uetnIMwanGR0ud5hrCJ7iYOzXDMUCfZjToSHsBc0bgdsztWGfrt9
         h+hFtlFaK7c88q5+BxkAIwVlzoSgEOL1gQ9045NhDSBx/s2fh89WIU74Mg1fxE0BpuNA
         eZdhcbAmIAK6i63wouzS6Q/blEizz8oNmv9rWXRE2PwLpEaTfVQxaQ/BcEuOfKSQtyvh
         XS//Pz1hpywdnBbevXWeccvnDl6/iXIXV5UhGuQdkYQFkT792SR+qSb0mVgnm7OBqD87
         +qhA==
X-Forwarded-Encrypted: i=2; AJvYcCXKjnJx8GWWebswXhNqhjtTcq0crcoWV1qQAL3TCn9u5VmnXiyuPtVy1xfX6WKtoOUDXO9G0g==@lfdr.de
X-Gm-Message-State: AOJu0YzSqCxn4Tk+pQRh6964hEpBmwVkKfO3TC11TEiU/5ImSdL1pxdz
	r+aXJJ1kaapbxD2cxbKZgo/oZnuI13rkPF2Lvq0raIKB18n4+dBcS/b2
X-Google-Smtp-Source: AGHT+IHLaUKqDcdyRiyfym+C/49i4oDiykH80S6d+s9KhsMITyaIkobQsudauuSlpk+i4cIPCInYAA==
X-Received: by 2002:a17:90b:274d:b0:311:9e59:7aba with SMTP id 98e67ed59e1d1-313f1be899bmr28651023a91.2.1750268525807;
        Wed, 18 Jun 2025 10:42:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdihJ+vV+Uimspt7sUlQ/PYw37SWmWTN7EZmZDbr83h+g==
Received: by 2002:a17:90a:ba8c:b0:312:f2f1:3aaf with SMTP id
 98e67ed59e1d1-313bf91681fls5293637a91.0.-pod-prod-06-us; Wed, 18 Jun 2025
 10:42:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZV/5IANVcZtiC+6s6qYryUCU0yZlh8xx3ZIz5JU7ZRUhUuuwhDa8IzLAV+a9I/xSrfhdFXzsxtAc=@googlegroups.com
X-Received: by 2002:a17:90b:4d11:b0:312:ea46:3e66 with SMTP id 98e67ed59e1d1-313f1cd67bdmr23810012a91.21.1750268524439;
        Wed, 18 Jun 2025 10:42:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750268524; cv=none;
        d=google.com; s=arc-20240605;
        b=QG73/Ji8Fe4XCX9QPx+PXH+4ww/I6ZoQd46Pe4NZuOiswUZ3DlONrOp6xXzLN1HlLW
         xAidrnP427o3muuvM1/DkdkGZU8Z8yzNESnSoHVqvgGHWcokPzGuhcXyBs9juGjz2Z0u
         hcrBHADm5sEKt1Ce6z2BcUjEGbtkYCX5Vf+pa4thvLLX8Xl0jiBRnk/kxdLvMrGPfrv4
         fbJxXSFtVe6biOOBHTxg1ySKMtjqfS+mHeV1xFkEfzdaYSU1zRE4Q11O8gIvIx2DToNQ
         Zsgup+xJqKEGT3lzGTHjk9vabaCuuSMCsewvbxg6fSc6ZU755NU7Y4vAOYAdn9bwM8+U
         zBHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4KtsacfCH4ompyndjxAxteo2uJlXhUngPXY36wLIt+Q=;
        fh=UPOmXyhDiWBnZ8bOWVexpiAg4tMIfKrkcRCIMtgjb10=;
        b=kW0OqiJ68Da7ha0LxVgJLk9w7rPK8sMedMEYDqB250pArQKrW0xmPSCLkanq4UaecL
         ipENA6GcR+VW9qYSE2Ifq7BS56Br2LTBHPQoDMRGupOqPIB4iFweqdn5VrWFa7qGD83h
         EXsqif849Xzm150C9HEu35zyyZlo4s6pJHISW/q567WrZdVe4cIPv2fH7TR/69qUW6mY
         eLemXItl9p9upketExNpz3bLCL41UzcEbN8dynCFpHwfzmj8RQSSvSNZgMfojsfozZmE
         Qc9RvoyToSihVUt0JIzqb0u0Y2Ms5LDkdNUDPICQJugi9H65RKyolgfQIjltzu0sXS0q
         5vFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3URY6+A7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3157c9da648si98133a91.1.2025.06.18.10.42.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jun 2025 10:42:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-6fafd3cc8f9so95142946d6.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Jun 2025 10:42:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhymYOd81HdOyo+dANBzvitM6ehUaklIHtAcBQB3QiFctyZEEFhLjbpV7k/C9ZOqqCofFSMsjhDUA=@googlegroups.com
X-Gm-Gg: ASbGncvcintmntSXM13/PH6LbupGNSvFyfKJPG20tKPL1qRJbqmfvCB3wvJS0D6a1lJ
	2DweVZtwB9Ho5CKFgigCS47bvYbJbcfhnLaodIv1PIpkAmvidyhU4Egdy3dC2GG2mofRyd92Vqw
	Tmdjp2J5C7feqSO8Rzij8KcaxV2kihqfbFP4PAXodgE/xgr0HChmcCUuNn9ANiNN/8S/vfaqbE
X-Received: by 2002:a05:6214:2f82:b0:6fa:c81a:6234 with SMTP id
 6a1803df08f44-6fb47786b3fmr291387006d6.10.1750268523147; Wed, 18 Jun 2025
 10:42:03 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-3-glider@google.com>
 <CANpmjNNCf+ep-1-jZV9GURy7UkVX5CJF7sE_sGXV8KWoL6QPtQ@mail.gmail.com>
In-Reply-To: <CANpmjNNCf+ep-1-jZV9GURy7UkVX5CJF7sE_sGXV8KWoL6QPtQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Jun 2025 19:41:26 +0200
X-Gm-Features: Ac12FXwkIZeCxG1skmZP_wQUq_V6XjEjYDn0jhV__bms-J4s-zMDCJE6vbE-kG4
Message-ID: <CAG_fn=W9_QEhwoSwc9efY9cEFkagBTC=Q6u=wtf1rA+aJqa-Zg@mail.gmail.com>
Subject: Re: [PATCH 2/7] kcov: factor out struct kcov_state
To: Marco Elver <elver@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3URY6+A7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > ---
> >  MAINTAINERS                |   1 +
> >  include/linux/kcov-state.h |  31 ++++++++
>
> Looking at <linux/sched.h>, a lot of the headers introduced to factor
> out types are called "foo_types.h", so this probably should be
> "kcov_types.h".

Yeah, it makes sense, thank you!


> > +
> > +#ifdef CONFIG_KCOV
> > +struct kcov_state {
> > +       /* See kernel/kcov.c for more details. */
> > +       /*
> > +        * Coverage collection mode enabled for this task (0 if disabled).
> > +        * This field is used for synchronization, so it is kept outside of
> > +        * the below struct.
> > +        */
> > +       unsigned int mode;
> > +
>
> It'd be nice to have a comment why the below is in an anon struct "s"
Ack

> - AFAIK it's to be able to copy it around easily.
Yes, correct.

> However, thinking about it more, why does "mode" have to be in
> "kcov_state"? Does it logically make sense?

You might be right. Almost everywhere we are accessing mode and
kcov_state independently, so there isn't too much profit in keeping
them in the same struct.
Logically, they are protected by the same lock, but that lock protects
other members of struct kcov anyway.

> We also have this inconsistency where before we had the instance in
> "struct kcov" be "enum kcov_mode", and the one in task_struct be
> "unsigned int". Now they're both unsigned int - which I'm not sure is
> better.

You are right, this slipped my mind.

> Could we instead do this:
> - keep "mode" outside the struct (a bit more duplication, but I think
> it's clearer)
Ack

> - move enum kcov_mode to kcov_types.h
Ack

> - define all instances of "mode" consistently as "enum kcov_mode"

There is one tricky place where kcov_get_mode() handily returns either
an enum, or an error value. Not sure we want to change that (and the
declaration of "mode" in kcov_ioctl_locked()).
Or otherwise we could define two modes corresponding to -EINVAL and
-ENOTSUPP to preserve the existing behavior.

> - make kcov_state just contain what is now in "kcov_state::s", and
> effectively get rid of the nested "s"

Yeah, this is doable.


> > @@ -54,24 +55,16 @@ struct kcov {
> >          *  - each code section for remote coverage collection
> >          */
> >         refcount_t refcount;
> > -       /* The lock protects mode, size, area and t. */
> > +       /* The lock protects state and t. */
>
> Unlike previously, this implies it also protects "s.sequence" now.
> (Aside: as-is this will also make annotating it with __guarded_by
> rather difficult.)

As far as I can see, s.sequence is accessed under the same lock
anyway, so it is not too late to make it part of the protected state.
Or am I missing something?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW9_QEhwoSwc9efY9cEFkagBTC%3DQ6u%3Dwtf1rA%2BaJqa-Zg%40mail.gmail.com.
