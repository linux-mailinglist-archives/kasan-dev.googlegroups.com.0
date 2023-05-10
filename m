Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5UC56RAMGQE4DWSEBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF2C6FE223
	for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 18:08:24 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1ac7c726067sf39648245ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 09:08:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683734903; cv=pass;
        d=google.com; s=arc-20160816;
        b=kCksDlbMXSm+Skitb/oHVmNexgiQgtaLTEvSPKGaOdytBAr64CbMmsylc2+s11R19p
         fGESV9kzkekjwgyjzDsYRo7k428Xg0G2KfSVTDN9UH6URDF6DATqqv7wMoTE/bRwhc7H
         8kMoJ7VKsTYoCOYpK/pfP7fYgQGNnATa2XIvW92YZlMwiDvzyAJd6ePqK5LEyyN4PRIl
         uuCtxYzmAMpurrpFggoQZFMj8zA9fBLIIYMkFbCmwtZILM8KyGp92fe/9scnUGSrBVAL
         vo2PzgbN8YRb+6YvTNv/Zy6aEdBbiZw1RnWsrpnhVQ7lEowEXGM7RCccbTIxlkbIcmeI
         SFtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JOjrgnRw8maRklky51sikcmjDcXO4vUz6vCvwlIddC4=;
        b=x0yMxqjqbVyVbI/VuciAXPHGUrrH18CHF60iK5s+sr0fesz+D7bFa0iTC6iIi0SqHL
         nSBIXgwy0ULKFOiuTAWqyjq0YO4gZ6tJz8U/L5DKtyRiArWD78GnPvb+MvVms78n56DF
         IjW66hUQ9LyxVhPTq4y87xx9rjp7+9YP5UA5r25TzirSv+dCTq5EMoVs1ozk38fVYWdV
         JvaK41/jl+ftGKBUSi2wIq8eU2O3aQ3GUWp9bYhxdYXTTNvR+c8/4xGcsP1HzvbG5PSx
         6znpaX/Y0y4KLAhpfnQE5ph8iJtsY60ydNbH0zDHdGsPaZkjzq/UmnvMN6EIXRm7KhnB
         SNnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ObkmmUWr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683734903; x=1686326903;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JOjrgnRw8maRklky51sikcmjDcXO4vUz6vCvwlIddC4=;
        b=ruJ1t5tDeKP/aEkk/VfChNvhFgS2piad/5bJOEH2iqrPBKFVsfp/L1OgOMqNTQByQ3
         elhPmv7MFlWjoZ25Mv1EVztGxMm6Ry8t3635SfbugXoVJLLUnehR5oi6lOQMon6AZmI3
         Uc3R3sSNJIpnYHgqHLu25DZTpDbkYGoLcPYZTAhhFsYPznWBorebRGx+Q63ieVAidCJH
         VY7XTP1+zN9ZxDiLUZij8hkrqLHYCZyLI1kIDN3oXRocPGjwSpr7IBRE940XAGacq7SF
         mBjWrhtrViRE6vLjxnOr1G9Z4Iw82UjQWmXiflfN/7Eqm14ClG537EMQrVbl1EZC3Ten
         0w5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683734903; x=1686326903;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JOjrgnRw8maRklky51sikcmjDcXO4vUz6vCvwlIddC4=;
        b=LWi8PefdBxXtKcJnnjxdz8B2TslNmgAiUio22Rp70xAtNAhXN05775TvWUHOc/7SCQ
         5aHFGMCIpiAembSd2XGzT5WN6xbjlzKuwrp14ZoBGAr5mC4i7EB8v/S6Ky7ZGpcc5Fsw
         vS2FG0UGjWqpz1obDlw4o2GSKxSeZpTJ6wiSKVywTf5D5WO1hSQ7M93Lsm6ZEmMLxfuA
         7HD1j6Oci+YudRAp6KdWNgsIjT9wvC8OvIeoBI4ywCrWvtZjPCwzPaRPqjo1O5IvimUa
         w7+yvkzHWh/2igEQRtlp2nc0AUYnsV/NM3EgdidKCKaAG/z9jmpNH9q6a/0uSV5RRiUl
         NwFA==
X-Gm-Message-State: AC+VfDzu5efXWpgV6WQ1TAt10lVhkJtw9LVYJuTJWGOOMPToAFM5LmFy
	uApv+K3U3Hx1i4/vmsx9zLY=
X-Google-Smtp-Source: ACHHUZ72cV/s/C2kg8qsZRGw+ZhJYPwbWynoqIkQIXMYC6NTPA36MXew2sJPdh1q9wuy+vNm5OyhqA==
X-Received: by 2002:a17:902:ecd1:b0:1aa:c676:8508 with SMTP id a17-20020a170902ecd100b001aac6768508mr6736198plh.7.1683734903072;
        Wed, 10 May 2023 09:08:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c8f:b0:250:8ab4:e7ea with SMTP id
 pv15-20020a17090b3c8f00b002508ab4e7eals1930307pjb.0.-pod-prod-04-us; Wed, 10
 May 2023 09:08:22 -0700 (PDT)
X-Received: by 2002:a17:902:d2c7:b0:1a9:90bc:c3c6 with SMTP id n7-20020a170902d2c700b001a990bcc3c6mr24085695plc.16.1683734902139;
        Wed, 10 May 2023 09:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683734902; cv=none;
        d=google.com; s=arc-20160816;
        b=aFw15YEAob10vZ/gdJ07Lj4yyNhdSPKmndlH83AScCtRvg2S+zQlsEINYCBzfIT/kW
         iS/bFJrXqSYEwLMj5+xFLQEnWteTrU3goZypCXPP3DgcC7Sh3wTS5d7wItPtQG9SZdG/
         8X1VKcCckIp0B+WeuZgqYjlYV5cnAJ/gLerzjawI3xxtKUstCaw+4gXpvYe+Jsnxw7eL
         6tEJdF+zewewRMaHKI3MLO0o+mfmlHBYnEpfIAOeswMexntqwi3WQnOMKzMRwarEMC9k
         wq0DW690FVO2E/uKr7y0LAjNVOn81tIXZXKmpEq/g92UH5r9Yr7tg3EQqHTevywuKKtT
         gvVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=n/UqHIj3pp0KBOJJJHffNhpQw/fXZC/Mr36vwvvthqY=;
        b=QsVS1wbFBykBpCZIHSePrFOSTR6QKxvTnm1/sygh1PjjA3gDoDTgp5EQ+cV7yUiLb/
         2LNLWp5N3DtZgu7vk9oGaLPFtzddI+3reJCzCqWuT2AC2mhk8/lpCFYL9dlwS84Z5wog
         pfrozkB8Hi++NeisdeBmmHlcqfw5Cb94dhSYfKqr4RIMzrM4KA6dXWxsFWwHUVksFxZH
         oKDfO3LovHpJpt8HeQLLSBXHwhV5N3PYk7cP8DvKBj83Hr9XsVmNfBaAO6yVm7G8FDkV
         R6EfuBLDd1HrSI/qYsPNuXe2TC54j8UploocNG/vLYQlkn3rqtWhCQlnMdFqxW1gKcNx
         2jHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ObkmmUWr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id kx5-20020a170902f94500b001aaf7c46645si203991plb.11.2023.05.10.09.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 May 2023 09:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 3f1490d57ef6-b9246a5f3feso11039194276.1
        for <kasan-dev@googlegroups.com>; Wed, 10 May 2023 09:08:22 -0700 (PDT)
X-Received: by 2002:a25:d2ca:0:b0:b8f:469a:cb9b with SMTP id
 j193-20020a25d2ca000000b00b8f469acb9bmr18089016ybg.52.1683734901243; Wed, 10
 May 2023 09:08:21 -0700 (PDT)
MIME-Version: 1.0
References: <20230424112313.3408363-1-glider@google.com> <6446ad55.170a0220.c82cd.cedc@mx.google.com>
 <CAG_fn=UzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg@mail.gmail.com> <CAG_fn=XmSbaMQQAwCWVmZ8UYDrsmeQWiqi92Vi4CQqy4GK+0ug@mail.gmail.com>
In-Reply-To: <CAG_fn=XmSbaMQQAwCWVmZ8UYDrsmeQWiqi92Vi4CQqy4GK+0ug@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 May 2023 18:07:44 +0200
Message-ID: <CAG_fn=VgkA0OdjqJg1FCBX5FcXtm96h9PTTTwAt3qWa0n0oNyw@mail.gmail.com>
Subject: Re: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
To: Kees Cook <keescook@chromium.org>, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, andy@kernel.org, 
	ndesaulniers@google.com, nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ObkmmUWr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, May 10, 2023 at 9:48=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
>
>
>
> On Fri, Apr 28, 2023 at 3:48=E2=80=AFPM Alexander Potapenko <glider@googl=
e.com> wrote:
>>

>> > I *think* this isn't a problem for CONFIG_FORTIFY, since these will be
>> > replaced and checked separately -- but it still seems strange that you
>> > need to explicitly use __builtin_memcpy.
>>
>
> Or did you mean we'd better use __underlying_memcpy() here instead? I am =
a bit puzzled.

Kees told me offline that the patch in question is fine.
@Andrew, would it be possible to queue it for 6.4?

--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVgkA0OdjqJg1FCBX5FcXtm96h9PTTTwAt3qWa0n0oNyw%40mail.gmai=
l.com.
