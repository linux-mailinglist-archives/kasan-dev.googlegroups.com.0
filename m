Return-Path: <kasan-dev+bncBDRZHGH43YJRBDGZW6TAMGQENFJZB5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 271F0770E1A
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 08:30:38 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-40ff512f8a8sf18078771cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 23:30:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691217037; cv=pass;
        d=google.com; s=arc-20160816;
        b=w9S7SfTYNWZbfDEVkPckoOL0Wth7iRSpx5X17MCA/teAl8cJ8+27azR5uTlubCxP7x
         D2mTgoOQlNIZ4Bt23onweAn/F6cRSSIQRTVXTwPZTs773crsef85pnfFOp5pffi4R2hz
         RTSUboHvewppN5d5EBBeUBEJwkwmmcpl4FS/rbK5QxcwFgOAHyNq+tVIGeGcPIZFsDi6
         2FU5ecQxAgq92iwPDm1eHNcEZoqn3tfKYyL8lvsflDXhbokokJazjNIT9svtDlf0nioE
         wmOmbqokA83/IPNkSoz9j2SQQHG46VS9e0aq3WDpRAz8pl/YTcxSGqkl4P7xOtePC02j
         /nug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NNEtFourcIZfR6TBwpkh/lEHeEvJL4ugk06PI3ANqI8=;
        fh=FMRLi3ztUxhnltCnsnJwJ9zgLZOjmh0a3Fg56oY3FwQ=;
        b=L4larRkfYroDt448aek5EnDZG1Lpud99gmsD203yGqBp2wXt41N/FN3XSQleVduJTj
         kon62fp34bNHXarTcrXXN5a+Rg8fEhVOk5lQ3f48IwD6FvMyUADereueE7+f+m3U4TyY
         WgG2wd2PwXrlmkdFl0S3PPdd8lr5l5SbzDWqbgANaWirnLyjl05bwWQxn4SMAY9Jmd4e
         66pN8EXNu+Bt4yW1Xsd9LDiAujOzPFiwI1u6nMmHdbgvKCtNzTbXY7oUJlNSxEJebmmJ
         5v6Md1Chq+NkraazgXcfz3pFtvQTlXUJRQG9US9xvsKU5Tz7FSuPrFulhD/DA4ZTtIb0
         Pa5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=hocI5qRh;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691217037; x=1691821837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NNEtFourcIZfR6TBwpkh/lEHeEvJL4ugk06PI3ANqI8=;
        b=sNlfop478/aVkCMQeoKyedKi1mdPXmvelsPTxXq0EjyOxbh6LqRlUHjbICVI8oOMv8
         sfbQxy299IdMgXz/fgsI6BJ3RKK2+3cwDhT0N1hVPxm0dx1CO9r+DeG1XtR76/Q4UwdW
         aHUvLXws4yvQbJE5rqrwWvgK5lbmmWKpdinKre+YIqdZjFNccGUP4nrxs0tNhOEZ8+VF
         aS8f88GgngxL47xd57FE+x/EejlmWND5MzYI5OnNkvT6zGSFs6LEixYpUGMa2mMB71LF
         JWKAxBP1CH3WKisM0DAOw/xC1rJ9cIGXrxUj8C9f6/umK3FNl9QXnRFsbccXVooCqMKe
         5NHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1691217037; x=1691821837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NNEtFourcIZfR6TBwpkh/lEHeEvJL4ugk06PI3ANqI8=;
        b=G5hDG71dQKAgdhTv5y0QJ+IyU8atf/TOncq3e81p9PmIcQzLp4ccDK79tRG2ua8xnN
         AaQEBhUSIToUGrHDjIjvOJHOuGw28yDWOZ1IkixDy3uJnEIHYyGjPjqDzDKJf0qax69u
         mjLx+kFVpGxxRJzpKKrTPwfl0LoVZiODzAsXB5kq5VuDqhEIUIJq5pHtPOmsNcX+5mD3
         pF6Zm9+t/nXeHehbCXOFxECAmkinxpfGaO3wLwVhV8FWVJHND80CS48C9Hg4YJbuh1J2
         kc+JreLcotZPr4WUAD/USc2RHh0RfMFvpHUWOj35Z9QP5Q06UWzJE9IpDVBwxwSzsVYf
         72Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691217037; x=1691821837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NNEtFourcIZfR6TBwpkh/lEHeEvJL4ugk06PI3ANqI8=;
        b=eXhPdinC4tLtnB3EQTio8Esg+mJ91YNoDQn2nW4fzUQq9RNllKGrt8W1QVeqgp3XKd
         r16jJzG45CufP2HZ1hp4itV4/RCSTYkAINRmxFz3WHgdODxuEXt8BbJjnAESmAXI254J
         ds+vimTI1EWZDSVJQ5maOJLk5JZtz/OOgsw8O3SzzaOM5P9j36EhephCulGANYZ9Nlsv
         PW3cYKVn/ZtjBRruw7+LXexu2tMosr/Ovgp4XRsoBeVBiu7eUZGWfkG+APro+YlhjY7E
         59l1Mz+ZlxlYPJ6rlvW9beuMZMPYMATK4xcOilYeU8k7EAXb27vHTBjJTJtwZE/SkMMm
         VFWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywz/HxNLER5anL5rUg+rrjwjxxlUsrjaG8Ro8E20EOZCyTcFKOy
	5QT7+9aE9jrYCnkAYkhsUrE=
X-Google-Smtp-Source: AGHT+IEPcMJFB0RfySJVxsGV4ZfsMB+StX3DKO5yKhPZPiKQyoNNc6ixvIYiyf16Gmp8fVoseQz53w==
X-Received: by 2002:ac8:5715:0:b0:40f:e493:534d with SMTP id 21-20020ac85715000000b0040fe493534dmr5205883qtw.43.1691217037050;
        Fri, 04 Aug 2023 23:30:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:528e:0:b0:3ff:302c:4437 with SMTP id s14-20020ac8528e000000b003ff302c4437ls978585qtn.2.-pod-prod-01-us;
 Fri, 04 Aug 2023 23:30:36 -0700 (PDT)
X-Received: by 2002:ac8:5dd2:0:b0:40f:e176:ddc5 with SMTP id e18-20020ac85dd2000000b0040fe176ddc5mr5215275qtx.34.1691217036313;
        Fri, 04 Aug 2023 23:30:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691217036; cv=none;
        d=google.com; s=arc-20160816;
        b=RvDaVvZAg4lVqmuSINRPBAf/ztXwJJRbD5F5cy+XOrPlzcfsJG4a53RCmiEIQst7fn
         bM2mj7kia1maxT6AAKRQp9jMK3dDgrYmcnysd9dTdb3GYXBbvcg1c2W2pV2eujANIzjV
         ldz/mjAPy/5SOQHtOTNTAY/zFUhLqHFb4ErFfBl+a7Fg+yrJ1OeOkz+3eLFuzIj2bLHV
         vWrf/llX0EFbApxPHOMLpb1C4wIoFfno5f2CUR1snkisJsTSRuMTUcOd/x6ZA7SIhrcW
         cYY6Pp73Vx8UuQj9co3xJTrBVGplpMF/Di2VtiAxtZ4twZBZiUMOmPVjLSL39WP8QVTR
         L3jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1deVdX+LzYEoDf7vsg6ItDydaxzW1rpkypTtAc77Ldo=;
        fh=FMRLi3ztUxhnltCnsnJwJ9zgLZOjmh0a3Fg56oY3FwQ=;
        b=zgbZFoumlX1PAO4s87lBfsQ95J2e6kZWtSU0VGRQwEqbU90Uz6rhmCJgRdPWrY3Ivk
         DYAd3ltFQ7Hm7b7FeCvggnYfcTBwnJbphAGz7FRE8/Bk+zi9v45zd4IrbHTI8eNT2o/8
         Lp0QyX4tx9iatdqoY0QJSyT8g9WqywEVb4ei9cgw+ipfBM8pAwgVCD14A1Oly7GawCFg
         tgeKqu7ciLy2vc8T90fQcSWBo7AkFhTT7Itnw6U3ESZEACe0Rn3AQoQsj3G93eUCt+lA
         LyaU82VIn45TWR0J9zBZp5wJyeZP9yK/GKI6UvHPOrKSp7jUUK3aWw6iiVaS0WxJfvwX
         G5Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=hocI5qRh;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id gc3-20020a05622a59c300b0040fd9cedc86si712025qtb.5.2023.08.04.23.30.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 23:30:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-583f036d50bso31911667b3.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 23:30:36 -0700 (PDT)
X-Received: by 2002:a0d:d655:0:b0:586:9f60:72f6 with SMTP id
 y82-20020a0dd655000000b005869f6072f6mr5332389ywd.39.1691217035955; Fri, 04
 Aug 2023 23:30:35 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com> <20230804090621.400-2-elver@google.com>
 <20230804120308.253c5521@gandalf.local.home>
In-Reply-To: <20230804120308.253c5521@gandalf.local.home>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sat, 5 Aug 2023 08:30:24 +0200
Message-ID: <CANiq72k_=aPidmk-BRVeKfsU=5FLkDxZN5iQKtHn3O1wZi2MUA@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] list_debug: Introduce inline wrappers for debug checks
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>, Guenter Roeck <linux@roeck-us.net>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=hocI5qRh;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Aug 4, 2023 at 6:03=E2=80=AFPM Steven Rostedt <rostedt@goodmis.org>=
 wrote:
>
> Can we give actual real names to why the function is "special" besides th=
at
> it now has another underscore added to it?

+1, some docs on top of that can also help a lot to explain the
intended difference quickly to a reader.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72k_%3DaPidmk-BRVeKfsU%3D5FLkDxZN5iQKtHn3O1wZi2MUA%40mail.gm=
ail.com.
