Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75573GAMGQEURENTPI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wBzjFwKfn2nucwQAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBB75573GAMGQEURENTPI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Feb 2026 02:16:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 005E919FC35
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Feb 2026 02:16:49 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b630753cc38sf1191986a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 17:16:49 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772068608; cv=pass;
        d=google.com; s=arc-20240605;
        b=MdLcWEA1hybAKol44Yn1WmEHDxZG6h3XI4OKWZwUBD/n1r6Ue+7uh/g3B0uPOVjo4I
         JiAyKUxURPHHEpDU4do9YdVzGBX9JLqz12zchzRpgRH/9I6VPe2uLJISialVwyi30/9E
         rw09RSWKI1Qq/oGFdgG9Cawv3oac3iC3zcCt3WoRokudQb+URL0BN/X4ySQZ2qp5x3c7
         o3O7GjZ+HwV9W5dqsHut56wrhiK/YQzwd9UZH89QWVTU1kwld/zqSm0vQqwlktTgrXat
         BJgvDxvLyjMygCl0WPlqbAC1mCd9FDdxPVC3x0Q1eSPaLje/3QasrgVhpYarvwVP9pQ+
         4FHg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DBl9Kmn7mtsMdk7Pr18JOwTxg2hZs9IKWXBgnj15zHo=;
        fh=qSrz/0nTnUCMH3TCvAoT0eRPBL0IC9HoGc97K0vmTzE=;
        b=ZUdJ7mMTIYsdTVx982F8ld+SvVQxPPU3B9RErf7gs3b1zlapplCLwRaAIx6l3v7NBz
         iBu4rp7OmeNGgax2ohtNlFYQgNimZD8Uts0ngQNznCtKcWEo1VYvMJqY4OQG2MXkxISE
         3ECe1L2p3QBiEircqM/U50q0XAo8hdLAgCe+8dt4ikHYCOf8o5NVeVe1oC3TR0Yry7v6
         IqGEokr+u4qor/hJ/txNMHr1UYPcNQ931vdI5ypyJ6erU9gahJjiW8PJUoI85EcRz7I9
         lJYb+IIxwSMOQyhh1btaL5yLCdrBjrwluLFLYfFWsLSTzE43EANqmR7KgRtWm2frDkxU
         niuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=183wRxBB;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772068608; x=1772673408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DBl9Kmn7mtsMdk7Pr18JOwTxg2hZs9IKWXBgnj15zHo=;
        b=upo1YRak19lweOyKD5NnDFg6txMe3yq6bwoLtPx8p4zH+wpwYOpK018to5naHa/Bi8
         6P2tjKIlJa9CUBHob31N4jshSqvZbc1ER3NntCO3k5kTFepZtYilDaUwwfBEE4DOcLL2
         BJgDmkCGmlAbGfQXD6dltUriENEgE5g+q4Vj9fxs4iTC9EVWjpq//ecDeBrm4fM/XSVw
         boxkXAU4meFNRB1g4jvnvoQnS3MjmwiXejd6qxAGnfqW94OC+e28lBYGdNrvfHDeSAVw
         yOJnxWiKj2Ap4X5j+q2G/CnzB9fcDSccgfRKna5wNFUbUJGoA3oue0zxsFyNc0vcSWF/
         WR+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772068608; x=1772673408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DBl9Kmn7mtsMdk7Pr18JOwTxg2hZs9IKWXBgnj15zHo=;
        b=UQAZZnrKlv1i3x3mlJqYJkAsmpne1EQfWKVcgAC96II1p4CvJXBUYYGwEZPWOBzG3G
         it0QNAHg3/WGrv8iLXzUMhl6z89XNp9YXD6oE6l9UOFKRENqI//Gz0tb+qlg2zvQcb62
         bwGFa6A2XoCq7qOuSDkEON2U8qd6QovvRkiX0YYxvuPnk1Xu1m1ih0ZJwBrduPz1tH/M
         qIKsgbOm/AW4wIk6t0kYjqkvl3947Vpx+yhFOAfbIJ0QaUmU+GEfGKFGx9nrDvYzNf55
         6yEShGSAStRINhDIwNVZDCA1rEmD0DOMYrVWcUa9WXV2nD/jHx1idIKLAkUDBSevGJwb
         FB+Q==
X-Forwarded-Encrypted: i=3; AJvYcCX1yF6DiNPsY0WKgJi7pytsjSAIlsOmx8C0Yq54BthcD/56N9V8l1mASqsvZKYGGpmIvzRnLA==@lfdr.de
X-Gm-Message-State: AOJu0YyPm1jkvQMJnriaVva7gYcaVqN2DGrPFGHmVJqW/KE8bng1Cn8z
	5FBQPYS6+i+dHIehtPcxqbsq4ihXpjouxQ9LlNNcfBDZZy79l9qQ3pDD
X-Received: by 2002:a05:6a00:6f21:b0:827:3307:170 with SMTP id d2e1a72fcca58-82733070ebemr2046039b3a.37.1772068607454;
        Wed, 25 Feb 2026 17:16:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eb/61bfc+ceWUEb/FOX2r2jZjeyvSFNMLHtuYGAsIeSw=="
Received: by 2002:a05:6a00:3409:b0:824:af5e:5adc with SMTP id
 d2e1a72fcca58-8272788f61als1373323b3a.1.-pod-prod-03-us; Wed, 25 Feb 2026
 17:16:45 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCULS+qGowc0L7yOn9u5UENH6mdo5rkka0uv+xzIX61D+yKqsOPZzD104iVDKyB0FeGAVrWUXcqVqxw=@googlegroups.com
X-Received: by 2002:a05:6a00:4216:b0:821:81ef:5dec with SMTP id d2e1a72fcca58-826da8c1176mr14942723b3a.8.1772068605607;
        Wed, 25 Feb 2026 17:16:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772068605; cv=pass;
        d=google.com; s=arc-20240605;
        b=WiiW1N9uAPAnRcd18xdt4xRjBHikSqSUG4jAyELp05JKvgHE7mjCr4xtSRa16noXKe
         9geK9Tkm9tcf2Ok3ZjQsZ8o45VK4AE6aizwX/HLQ/POMlgXO0ofyPs1W7s6V9oEr+Qdd
         TyL5bgy71cg7wHTFQq8G7boNaLhsDthq31IOaqCAJxJsfvcVRqC8v+eN3kA9b2id1sxU
         YWCgLBWhITfpFp+ZTPhxhXFdju1I7jmEThuJDqqlUnw/a5Quf6vdu0EjKZDmprAOfxWB
         D1vbFokhW8KvRbo0bL7i/39hWEuG3hIPoMKEGocwGvupJfS32WfDqBvtpOHg6Mv+cnJJ
         OjbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vRCpYCv9LhOitz1IfzI25VOPlvd9PoDqej+x+FrWu+Q=;
        fh=D+feFOiQgIKETsJcdZDbrg6n4EpEUjDZK02wE8PhWjE=;
        b=EaOrwGx/CYX6pPHXPCo5pZzYtz98AWa4mBuJPLibZYiwp9cpKYa6IKhMQsTRFL0Bvw
         lRKUhFOVmy5lGp/1wvF/DWxfthZQAgk+pnXFo4An+trT6jl4APDhba5fDJH8GRSMb+vA
         VPL+10715l6d5ANChW5EDtHsfoKfuttp2R1aCXy46IhE6CtUW1mSoYFykx2gu5J292y0
         Q+3MqFMx0ImmxNHwnjEeWa+KEwHtqPlTwvJmkxkbcPs3i0KardiE4fjr76ERsHYJMIJZ
         23baw9xkHkloQ5L/W7Iv2trVy2KtuNnRQlcKg36tsRPhWZ/k86PjzJb8fgV/7q/zRyup
         RKpg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=183wRxBB;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1230.google.com (mail-dl1-x1230.google.com. [2607:f8b0:4864:20::1230])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-8273a123ebesi27455b3a.3.2026.02.25.17.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Feb 2026 17:16:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) client-ip=2607:f8b0:4864:20::1230;
Received: by mail-dl1-x1230.google.com with SMTP id a92af1059eb24-1275750cf9cso257818c88.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Feb 2026 17:16:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772068605; cv=none;
        d=google.com; s=arc-20240605;
        b=VI6wosUi5kkEnE89xtFIBNcpse5Y1zc8JafBwscxMLt+pGi6621Upg9HRgRzNXTznO
         Bc2AVIVVpQFTr1LcWNj7A4uToGnuzlO8rw4u+k3FFpukzEJhHzqs8uyVKOoKZ0IHaE4u
         wmgVbicCLM+/s6dISkuF7hRfEyV58Jzk9H7iJ0LzGJcTrSKaado1PewGH3v2d4GvbErz
         5bgqWl8UbqSXlMSB1ywdtuDRqu6FY1hMV7BHEHlJRZfWByx13nb041O43w3Rso4udUNw
         YTwt63ONrPW5HxJgp4pNGReeYdAi/jA/4GkEtzDzF2rWrm9gtuNkzAMczwQCvN+PvH8/
         6fPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vRCpYCv9LhOitz1IfzI25VOPlvd9PoDqej+x+FrWu+Q=;
        fh=D+feFOiQgIKETsJcdZDbrg6n4EpEUjDZK02wE8PhWjE=;
        b=MKr39tsi5ugkPwZiZK2iUbEz/CTE7Nz48nI/iO8pCSbFev/WSIYSUN3yvFM5ZDCMao
         obafM+OeeZV7MobVvgrp/6vKJszrCvT6G5AJmqyKZq1RZqU4QVcj+PRExciqWQXMnaWy
         ZGZi9YdxRK7nrExpxjeV4IIt9ZYOu8m2s3bkevo2uIkXLzwKDOAKcdnRaS0r9GBVbTy4
         pjj93xs3Dnb0jqwtNE03ZXm/53H3vTE1RT012vWceT3ZWtZIgETqiKTTyIguG1L10/tr
         u8InqByIGrPUzssOVDftXTSDlvZsqOMfzOIzm1vgIKy0DR7SfmJ3+aMIzObwV0fkJD9k
         c3IA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXZuJ2C5u9I0fS6O0PwzsSpnzeon81LgjX+kT1gT4S1JNqCmrWBURQekgVRVT61gho5wKRtSsfF8Z4=@googlegroups.com
X-Gm-Gg: ATEYQzythWSZAcxzitePvIV8rBUc2FyvHH+qVRPlClWuEnpIv8cEHfKLRcObGDnDl62
	xCK03WejygQoN3KwLjiWtbgTvFK9Wg0d1JXn/w7I3nXXqEL4I2oBD1VUb6iZLWvclbu/OuiEMef
	PezH6/zSJ055kkXsVLAoPHpFLKla35GSTgi3jRhhfQvtKfoTGFteTnc/3P7uy9UdMsFJhVJaq2c
	qkP7l3ZAw1m/ITgB+s8+7QR5Qg5QCrJPEXEaGJiJNjslztTXTxvEWFUaz1GXyTyFx/UvUV9c5Im
	sZQZgpv/MiSxu+Lpo7EMvDDkucs702vXLpm1D3Y=
X-Received: by 2002:a05:7022:48c:b0:124:9fd8:4b99 with SMTP id
 a92af1059eb24-1276acbdfbfmr8853747c88.14.1772068604514; Wed, 25 Feb 2026
 17:16:44 -0800 (PST)
MIME-Version: 1.0
References: <20260225203639.3159463-1-elver@google.com> <9476ab2ff783c77ff4f1d323fad3e356bb172fcd.camel@surriel.com>
In-Reply-To: <9476ab2ff783c77ff4f1d323fad3e356bb172fcd.camel@surriel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Feb 2026 02:16:08 +0100
X-Gm-Features: AaiRm52Q6kRNA7CHrMLsOWSgdbnXUE5vCnkOPGyFzwQOTRVlJEfjChemViCldxw
Message-ID: <CANpmjNM4kwRGU7mxZPtPnD2-Q2u2E5K9bLuHiZYkPkB4JETeJg@mail.gmail.com>
Subject: Re: [PATCH] kfence: add kfence.fault parameter
To: Rik van Riel <riel@surriel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Shuah Khan <skhan@linuxfoundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-mm@kvack.org, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=183wRxBB;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBB75573GAMGQEURENTPI];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[elver@google.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid]
X-Rspamd-Queue-Id: 005E919FC35
X-Rspamd-Action: no action

On Wed, 25 Feb 2026 at 23:26, Rik van Riel <riel@surriel.com> wrote:
>
> On Wed, 2026-02-25 at 21:36 +0100, Marco Elver wrote:
> >
> > +static int __init early_kfence_fault(char *arg)
> > +{
> > +     if (!arg)
> > +             return -EINVAL;
> > +
> > +     if (!strcmp(arg, "report"))
> > +             kfence_fault = KFENCE_FAULT_REPORT;
> > +     else if (!strcmp(arg, "oops"))
> > +             kfence_fault = KFENCE_FAULT_OOPS;
> > +     else if (!strcmp(arg, "panic"))
> > +             kfence_fault = KFENCE_FAULT_PANIC;
> > +     else
> > +             return -EINVAL;
> > +
> > +     return 0;
> > +}
> > +early_param("kfence.fault", early_kfence_fault);
>
> The other parameters in mm/kfence/ seem to be module_param,
> which make them tunable at run time through
> /sys/module/kfence/parameters/*
>
> Why is this one different?

That was my first thought too, but after much thought we should not
make this changeable after init, see below ...

> And, does this one show up as /sys/module/kfence/parameters/fault?
>
> Having the ability to tweak this behavior at run time, without
> requiring a system reboot, could be really useful for people
> unexpectedly triggering kernel panics across a fleet of servers,
> and deciding they would rather not.

It's intentional - having the ability to switch it after init means
we'd have to remove __ro_after_init from the kfence_fault setting. We
risk having the system administrator's choice being overridden by
accident in the exact situation where we do not want it to happen:
either through memory corruption overwriting that global flag, or it
might give an attacker the ability to circumvent the oops/panic
setting, if they manage to reset it. KFENCE is not a mitigation, but
this setting is meant to give a knob to reduce the risk that someone
takes advantage of KFENCE's heap layout - until now, KFENCE only
reports and continues - the actual buggy access happily proceeds.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM4kwRGU7mxZPtPnD2-Q2u2E5K9bLuHiZYkPkB4JETeJg%40mail.gmail.com.
