Return-Path: <kasan-dev+bncBD63B2HX4EPBBPWDX37AKGQEDIVK25Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CF0BF2D2EA5
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 16:54:39 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id c9sf22612610ybs.8
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 07:54:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607442879; cv=pass;
        d=google.com; s=arc-20160816;
        b=DV4Sio7+UDpQX5JJfMoM7eTBVSYXBhK7QmyxRNuDxaCeJfTpsIVUqrW5ZgW5xzcSOs
         OkvJY4zmwYrJB1sPXrKzJ971TKkg16zLbvWQi9oKbN3ytGQv3zRRwU83O9vQaYLfc/CY
         8amm6X9OnrHEdOJl5AjoRapFn5sgP4AZNfBJOuluX1wVOtRnJJm4rVWGguAZ/Lin5nO7
         TL26veDWDYXkA81mg0UUs12L+E8c7LDUmT+PJXje/C4GMfrydModNGVtBBxmQLL1+kTO
         jD7Xeq7/ogVB0KBfqCG7ndSk5gqk0KLhX9nbu5xZYhzPQlDJp5D/HuWyzowP5CG1argw
         qJ0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pS5PcIcczZeVNLWOYeR/KnurhoWRk6jMgXj4kjllhfo=;
        b=Up/2pvZ1+4sVCksJYANEqHZNjRwcsGJqVAJVg6953yERuaHVt2jIVLJQL3MHSdrow8
         6LX+i5txXdtvUGxrg1SF2Kwuo2RX6G3k2/2yvB/0kWDvpFIAriraWuy1X7gCw3G0oeS8
         y5TlFgG2fkshk5YMF8o7ppPKzcQKzPONI2SIxKW0JWFuWzUz7nPTRteSK2F7zBbrh6Lu
         MCIMIo5ulk4VHhq+QSi/YlBrsde2FdJPpE7XPOMCqM3bztLofzzxup87XENF5AO4d6zx
         IAluscWPRmWC5p8Conkor6LrDDnRY31W31zz+DkTnOrde+JqU/WzHC3Dg7jWjNTGWG7D
         yslg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=AcU3VAgG;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pS5PcIcczZeVNLWOYeR/KnurhoWRk6jMgXj4kjllhfo=;
        b=Kgy9QDTulVIAAl+s70N+icW1INAZ+/h6BMZgqRoGfJ3lKO9O9/zx0QMKqLf/UrYXhv
         6slcDVsR9wJbQoqqsZFBpn7RfcXfSOuVmniciAO4PexQcV9FYUHBNib2YVxSSO+0+te6
         2NrNfGFD+nVuUIEe9EU8SVN2POoeujpwYikzcV+N6YoejLlrNf9Lsw2ZEKNySINTPTJw
         AXY2E1kfUFMF2H71D1O6WsUW2ik5kq3POg1p+5GBEyVc7g0urDMLKzZibJgOQbhmZXUk
         woUZ5uhoeo+nVCGZRsNwu8wVbp6i8SQnYZur0/ksuquGs6WexgmUbQe6BRnp5aqqPaYf
         YZbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pS5PcIcczZeVNLWOYeR/KnurhoWRk6jMgXj4kjllhfo=;
        b=aa0YjK4ezo1I1ksdOLutLS0lEaur/xAlPENJPd/CuAig7LdWfnuWVLZjliylu2i39w
         p/iS/tOUw+DVeUBROACCFAfSqwIZ/6zSvQ0IgrfTxtgLzgxZXohyXAmERhIYCo2tj+il
         Ei6Hmh9NxBQeKfoZ+khCJUcrHLPsiv0UkKac+eETSEmhnxbQTDiOMximd42FxFNMSn34
         hw61e9s3t0RoJqctPi4MlJlKyiiDSWUENfq8pcakeLy3NlyhcGmuY19OdCkbU24NiJAa
         ljTHs6FSBAaqJMBSLWr2ANLCoV0UOraLEYHaP9oJIVr5B6cEMYEHI7wMeoq8lwpEdLcS
         5o0w==
X-Gm-Message-State: AOAM531NMEeURxWxYIwUkYb0yYKz+Eh1oXSZabBO298QaGU5f9/9JNWg
	9AkSaG/cMHAtqvT2g9Keu/8=
X-Google-Smtp-Source: ABdhPJzk+SqZhCMPZ7CxGbfwmJ1w0puMlxztRu4HHxDixDfe0y3mewyEBUuREPRVRfig07qAtO5aTg==
X-Received: by 2002:a25:168b:: with SMTP id 133mr30920190ybw.219.1607442878906;
        Tue, 08 Dec 2020 07:54:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ce49:: with SMTP id x70ls9987902ybe.4.gmail; Tue, 08 Dec
 2020 07:54:38 -0800 (PST)
X-Received: by 2002:a25:ac1f:: with SMTP id w31mr408114ybi.87.1607442878501;
        Tue, 08 Dec 2020 07:54:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607442878; cv=none;
        d=google.com; s=arc-20160816;
        b=NKRTy7NSpGlkBYD+Gx0gnGGRMYlBbj+xuMCJSF7P6ws2m5uDm8RLaigV78K2S42SKl
         y9fiiBdRs8ay2IRey0p4NviSR046D0REKcpt4Kx0zqU6E4cqXS0C9rpd2kekvZpddsbJ
         V9PbOmZu9N6wOiCjQ9rORntH2UJOHzvARQN0ZIb/tqQohHTSbnRtYyAswhvqxFYZB/mp
         qe0NOR9rwXG9ErWwpA7ZvZM27n7gTcUK0W4fSnufbSJWdPt2EFzpCIddzWnhnbXgM7bS
         VCdx+0plJCcFKPhIdYJYPJNxBo9cJ+IPip8/WWc2ZaopCREX2utONdW7vUf8bO4uX9/q
         G+Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=L+tIIhc/8G8VIdHvs+okuvpL+OQZog1Jo2lg6EAZ+ZQ=;
        b=aoVdfwzetOXiX0f9preD9v2UFRVTU/xvCVlVlF5f7/j904hzkuw9OpnT9479uUwd/l
         0FvaqNmVv5HG91rpxIg6rle49wQ3UIrItcV/WnsmzG8EWzdUwuvU15ygDU92TZnA/j0Z
         Tc3Q8yU022dKuhHaQOHsxzcBJhQXLedn+T5VObNHqZb1UNLbkyt1sU5RR+s/fzDeZSJL
         Z4LVj7RxaEiDDzTFgBOblhB6Ssz7RQz5nrrMaCLumv0PBrEXnFEKZNe1dB/5eW7qXvv0
         MpCEs1qgeL1H2FDN0rCaSDM6gQIX3t3Va8Puh+m34++Pk5a2+P7Syhqp9R7+w1tmLRTD
         GeEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=AcU3VAgG;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id k6si297322ybd.5.2020.12.08.07.54.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Dec 2020 07:54:38 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id m9so12535498pgb.4
        for <kasan-dev@googlegroups.com>; Tue, 08 Dec 2020 07:54:38 -0800 (PST)
X-Received: by 2002:a63:1d55:: with SMTP id d21mr22772957pgm.324.1607442878139;
        Tue, 08 Dec 2020 07:54:38 -0800 (PST)
Received: from cork (dyndsl-091-248-004-182.ewe-ip-backbone.de. [91.248.4.182])
        by smtp.gmail.com with ESMTPSA id c6sm3584918pjr.55.2020.12.08.07.54.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Dec 2020 07:54:37 -0800 (PST)
Date: Tue, 8 Dec 2020 07:54:33 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201208155433.GF2140704@cork>
References: <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
 <X83y/etcPKUnPxeD@elver.google.com>
 <20201208153632.GB2140704@cork>
 <CANpmjNPvRg6UfjX0=hW2LabqpNY6o8FGANex4yFtkvikDJvR_w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPvRg6UfjX0=hW2LabqpNY6o8FGANex4yFtkvikDJvR_w@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=AcU3VAgG;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
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

On Tue, Dec 08, 2020 at 04:43:51PM +0100, Marco Elver wrote:
>=20
> Cool, do share some perf numbers if you have them.
>=20
> > Patch is a mess, you definitely don't want it as-is.  But it allows me
> > to go more extreme and test the limits of kfence.  If it works for me a=
t
> > 10kHz, it should work for you at 10Hz. :)
>=20
> Fair enough, of course it's fine if you keep this in your tree if it
> suits your needs. But the hrtimer won't work with static keys, because
> the IPIs can't run from interrupt context. And I imagine your KFENCE
> pool must be huge, otherwise you'll exhaust it immediately (this is
> another non-starter for us).

500MB for now, probably 16MB in production.  Haven't decided on the
final number yet.  Frequency will also go down for production.

> To bridge the gap, does it make sense to send the
> KFENCE_STATIC_KEYS=3D[yn] patch at all, or would you just not bother,
> given that you're running with hrtimers anyway?

I think it does.  For me it will reduce the patch size on the next
upgrade.  And I suspect others may also decide that the online patching
is worse than the extra conditional.

J=C3=B6rn

--
The trouble with the world is that the stupid are cocksure and
the intelligent are full of doubt.
-- Bertrand Russell

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201208155433.GF2140704%40cork.
