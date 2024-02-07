Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7EESCXAMGQENZX5LUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id BE94584D5BD
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 23:21:49 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-6049f6b7406sf12621367b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 14:21:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707344508; cv=pass;
        d=google.com; s=arc-20160816;
        b=W4d3JQLqUP3EdIGkEZZb5t5VrpUuY8u7SPANG01sCfdFCmwI1qbMsp7oJL6B39/PsR
         WsMoPlJOIAE2T0LY6c29CJ0CKlTvNLDbtDtqBwfPR37mhdETTBdEFibf8lIOjeurlppQ
         ayEDC/RDZJILsR6oGhvFZIf9xYVsOQZ2UiymlPAKVNwJ4IvlYCc4EAUxDP2Vkxleq3kg
         4e2QtZErOU3Yuf0XyS0o3VbeXRH04pRuBMMo3zYBjOlqHvU6mKhptGUrUXUauAMfDTRa
         VqF1+0lI5YIObvKsq8XMf6Erte/MswnUTKN2XOlDkVGeBg7SbLX766/LFM6YTX2PQc+c
         pHag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WYTbZ4vZ/Y8FWh70j8gy8O+9Y718xMXt44QZ4EmW0Yg=;
        fh=lGUuwhiDncjpVAlZ34kV0muROS31xGNsnLq3ABBK2FU=;
        b=uvOsVV4ykEWJyZlXFaBgKEGiOpbX1g4hqPK1PfSFvsSWix44tSptsV/nLd4VgkHa0t
         TlbXZf2K4FVm15PmU/EpOS/P0BAwqHM/h9YPJDhxq/53+5kj4+bweiZ9MoaRSV0URLob
         wXtWd9dQ4fqIkBSJVBN5QjwPVbvE1eXorl4V+Kfxx/Fqm3GtNyXdZBQlUdblC02SCONn
         vIZHQqSSfOKKzMuREH/dr21NIzUzWhpa9K5OE5iC9lPzNayskYNfEso1dte0aNQdAfjL
         09MdV6CIETmnA+B+xdLXfxqBukq/62NkD26hvIHolEgJ+xKLJ6XqVEA2K2J2xgjxvT4f
         9O/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UlTi4oZA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707344508; x=1707949308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WYTbZ4vZ/Y8FWh70j8gy8O+9Y718xMXt44QZ4EmW0Yg=;
        b=Mo+sOEbxQERc3uqY+px6TZth8vz7ZS6JuR5rUMiYyVBOl9piYFBGhAWumLWE1J/Mea
         0hIbd5utTJLp23CM8eJsCfAIBQOktM7xNONeh8/TXvt8Jk3rB3HADCkslVZfbelggbq1
         TT1eVKQmzeUP11qM3HP3XnmGZRUwdwlYyuVkc13uA57H5B9mp4DikZC14ma28M0SfF5x
         R3NTQA9LSt/zWCvHzrQWaINT6sbMNBjoU0uPdv2B4PRrxsyX68RG7gVft3bgGLRDxxH+
         uJtlk8SrJnNCKw0GQAfLxi/BrCFVbF5kIaoHf0FLF3DuCQ8uMOJqv8ypLeu56d5FDDob
         iEuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707344508; x=1707949308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WYTbZ4vZ/Y8FWh70j8gy8O+9Y718xMXt44QZ4EmW0Yg=;
        b=A+UcdaNWqsHPn0yIoZMvUO2mJ5piu2lcqGJnzwe5tFDXUX0vpkyf6YAn0JrseS1nnX
         Ak4C4znyvenvRUmFgq+05YdG/xKJpaqQ0KxApw9yLpaFKv8si38rgKTMKcqJQAUnXHpL
         KO/ZkFMxVEeJ/doPnb7gG53TFmie1P5gjY6/qqtuDhIY96SpXoUdqReGzL9DeCqltyM3
         G7OjKSYvWl6ztmFDQCpywDPu0MeVNiKe3gfRLAomEOG1xSTrkbji4kiWy+m/ePP4BLeT
         b5L8fHb0M7RLBh2zdrJPS2s18QOPS0Z1TJ4JUaftLnuiDT4RqucWjfUmb8RUP9jm2Ppd
         fmLQ==
X-Forwarded-Encrypted: i=2; AJvYcCW8DZAWVTG4TCnyP8QoIJe9haJecUdaDWMZ0bcXMIDzYZFKAXXPzWh+soirzWbSzeE1fbZkHtWN7o0J2QWa+2j4IdfxP2rCAA==
X-Gm-Message-State: AOJu0YzJz5uNaeqMPtkkz2eOOKQP1VgFKwGbpMkvrSRL5EgOvi69BB+R
	41VlFXmOloYdfagXw4wLUuvoWoyt6UnbnNrbs9lC4w48zlUFXm4A
X-Google-Smtp-Source: AGHT+IE0Gyv0R2BYpRfTyHgE3ZMpUdZoNAGOy0b3MYTggEUKyxwp02X6fjlosd+ssuUT2rkzan0c/g==
X-Received: by 2002:a0d:d484:0:b0:5ff:a09d:b3d5 with SMTP id w126-20020a0dd484000000b005ffa09db3d5mr6839477ywd.45.1707344508257;
        Wed, 07 Feb 2024 14:21:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:452c:0:b0:68c:c08c:bee1 with SMTP id l12-20020ad4452c000000b0068cc08cbee1ls898722qvu.0.-pod-prod-06-us;
 Wed, 07 Feb 2024 14:21:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWaklv++D66drjkDQ8wMjqkNaIMp5QZ27ujvyf2TcauSFBcIrKR6n5+Ywle+jfOB3BoSZ8QL5KsaD62erdPJGG9ZPdeDhgkZQnZZw==
X-Received: by 2002:a05:620a:146b:b0:783:bd6c:90cd with SMTP id j11-20020a05620a146b00b00783bd6c90cdmr7020845qkl.19.1707344507228;
        Wed, 07 Feb 2024 14:21:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707344507; cv=none;
        d=google.com; s=arc-20160816;
        b=Hs2ImWhL2upph5WlN67q1c+u7+2+/rAQFTUAtqy9v9lqxyvdb2o3S0dSZ+sEYw16gO
         aRdUJiNKpICeyGmM3scwRCpoHF6uCgTS9sE4HQjcjtFnswiDayzpihqHELEU2Lr0bn0q
         fejiu+GBqmggzNDUaJAMMPSj9E74d++uKo6wKeXjYme/iOVqQFAip9RAHJg5sY7+gGcj
         XN42Qr35YnEysovbCUjOw59YU4a2KHXksP9KulDwvSubow30IhG3dMcXw2c5UDcK58c1
         FyJWOam3/tZV2fJyHiEJxsPrXpsBvisK3grJwFo8Elmxw4l5y0ZPZKx1384pZ86PQ8ra
         kOOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q+dKiZCAx2K5MWCLf8Rta07KqHdenFew9tjW2b/jNYE=;
        fh=bjcyxiYY34YINziB3JUR3l0lBeSAj7j3wfjc/GHdauA=;
        b=z2AyHhJ5wqLO37b9Fxda4gRFbkUJrHcf7pfXFdzGzQVPSlZAj7GgjP2QxMg/uRMmKX
         NMJFMpxxmoKAciksMzowWoPbTK/Gko02P/yzCSj7siP49GRgvfcbJfNaYl/6yoS7zAER
         pPpd9nKDI1XX/jcx/t3u4Np0ZG1VAZuj2vfgQDj4aKfH9+eyQ7zHyJR9yUz2FAii6h1B
         HU+wjIB3lDGjC8polBi3Y219UXIuKKBv7YomEQuoJADgisaDo8Vl71Dfx2m7iCBA7icN
         aRYvEDxvXK0Eo6zc8mbLg9AfR4Qyg17a4rvnz/NWkEdNfrv++sKwxSKJhCIEBx1RHnIL
         UW3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UlTi4oZA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWtfr/m0WaKZ/qRtQpRcP8F13cls2cYZRCSv6q3U3oigFozkXJ/IHCDI0dhy2qvFcqRoCOcunjVOVqnoUImFdlc0FihtUttkL4lkQ==
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id p14-20020a05620a056e00b00785600632b0si196869qkp.3.2024.02.07.14.21.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Feb 2024 14:21:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4c01ac04569so485093e0c.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Feb 2024 14:21:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX1stcqggRymTPE9fZ9iRdgUa8TorkbwxsGTarHGVxMwOmXikeOt5SBJqOtyqHW5gg4OptYYzJLvaLiEOr7FkwtQXRRtiFe8An/hA==
X-Received: by 2002:a05:6122:31a1:b0:4c0:d43:f8a0 with SMTP id
 ch33-20020a05612231a100b004c00d43f8a0mr4899395vkb.13.1707344506661; Wed, 07
 Feb 2024 14:21:46 -0800 (PST)
MIME-Version: 1.0
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local> <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local> <7a3d2c33-74ce-45fb-bddc-9eceb6dd928b@kernel.org>
In-Reply-To: <7a3d2c33-74ce-45fb-bddc-9eceb6dd928b@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Feb 2024 23:21:09 +0100
Message-ID: <CANpmjNOEhyW7xnaQ2gk0XXrdLSR6DgyWD96CBb-cxUJT+wgMXQ@mail.gmail.com>
Subject: Re: KFENCE: included in x86 defconfig?
To: Matthieu Baerts <matttbe@kernel.org>
Cc: Borislav Petkov <bp@alien8.de>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Netdev <netdev@vger.kernel.org>, 
	Jakub Kicinski <kuba@kernel.org>, linux-hardening@vger.kernel.org, 
	Kees Cook <keescook@chromium.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UlTi4oZA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 7 Feb 2024 at 23:12, Matthieu Baerts <matttbe@kernel.org> wrote:
>
> On 07/02/2024 20:04, Borislav Petkov wrote:
> > On Wed, Feb 07, 2024 at 07:35:53PM +0100, Matthieu Baerts wrote:
> >> Sorry, I'm sure I understand your suggestion: do you mean not including
> >> KFENCE in hardening.config either, but in another one?
> >>
> >> For the networking tests, we are already merging .config files, e.g. the
> >> debug.config one. We are not pushing to have KFENCE in x86 defconfig, it
> >> can be elsewhere, and we don't mind merging other .config files if they
> >> are maintained.
> >
> > Well, depends on where should KFENCE be enabled? Do you want people to
> > run their tests with it too, or only the networking tests? If so, then
> > hardening.config probably makes sense.
> >
> > Judging by what Documentation/dev-tools/kfence.rst says:
> >
> > "KFENCE is designed to be enabled in production kernels, and has near zero
> > performance overhead."
> >
> > this reads like it should be enabled *everywhere* - not only in some
> > hardening config.
> >
> > But then again I've never played with it so I don't really know.
> >
> > If only the networking tests should enable it, then it should be a local
> > .config snippet which is not part of the kernel.
> >
> > Makes more sense?
>
> Yes, thank you!
>
> On my side, KFENCE is currently in local .config snippet, not part of
> the kernel. If it has near zero performance overhead and can be used in
> productions kernel, maybe it can be set elsewhere to be used by more
> people? But not everywhere, according to Marco.

At the moment we still think this decision is to be made by the
distribution, system administrator, or whoever decides on kernel
config. I'm aware that several major Linux distributions enable KFENCE
in their kernels. The tool was designed for in-production use - we use
it in production [1] - but I'm not sure we can and should make this
decision for _every_ production kernel. The hardening config seems
like a good place, and I've put that on the TODO list.

Thanks,
-- Marco

[1] https://arxiv.org/abs/2311.09394 (see Linux section)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOEhyW7xnaQ2gk0XXrdLSR6DgyWD96CBb-cxUJT%2BwgMXQ%40mail.gmail.com.
