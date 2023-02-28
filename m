Return-Path: <kasan-dev+bncBDW2JDUY5AORBCN37GPQMGQEYKTCRCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D9B6A6014
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 21:01:14 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id i2-20020a5d9e42000000b0074cfcc4ed07sf4541338ioi.22
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 12:01:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677614473; cv=pass;
        d=google.com; s=arc-20160816;
        b=MghpoCDlule/0xGkELreUcTOQwvNdkxOEJJG0j3iU2P/27+52vsQer7/JLuYsPY4EW
         JqtN/HWrpLFcOSak1+gzrGgGivWEAQLKOzBzGOq1jdSudixB+PcpRbCzMuB9k3JsX12U
         c6iD9vwJdAyccnH1YUDjf11SIj6VEgkjDwbtA0R6oreMKF9TeJoNCqLeq3FrHfdUPynZ
         AkeUe7Vl7tlarEayMSU99ky5/AiqXnEdFmp12s5rnH0pGe97y299WQK8D9RtLEDrbjgg
         tmLtukpQrLg/Rj4JaXlADhURd/DEnU9mUZvKiRPdUhlQCTyl8kYemkvbKWwoc/jJXOFq
         A69Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=nTDDWGX5jnVR6eiCVdPmtGWvgB/PHne3k27JWsMXme4=;
        b=rGnEw7ocjrEcPjhRTZ8yt/lxHO+BZwM2FocUfHbcpMb/YDhotzl3Q4DbcRSesed7J6
         WGbuBukOHDUslKKKMESxuGMYWbXuxl1NZ+1tpnyW5T4MU1FI3YxX+kGLv19NadYhuiMp
         vgavm2fJs2jTpfFvu+euNqQXrm7aLoHrzvsUfXKGVaIgIjUy5U1jHynjycj4tco9ST+q
         xM63klC/wdmvcichMnZC4dC3ExVunZE7QHbM8uMZxNa2HjGA+bAWCbyml6gifQipZ9SN
         BeswYV0OLWmzMlLllG+Y1hUEowbCpxLrnnkzyax41NsvmMm5OohDucGEIIUTQbXpNVB3
         ve6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=B9lAkxeF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nTDDWGX5jnVR6eiCVdPmtGWvgB/PHne3k27JWsMXme4=;
        b=m0T4vuZyp88WQE8+4h8trfg/rUpqhDLNciGMR4JBEZnVEVGi+Q9VwilARCWp4GvMLA
         N6k5+kjMPLJCu8ZdQi5mjJmhBnWrGaRMIM4bXb9eGFbkcerleqmNGI1RRN8KU83E2JrY
         JdNTBDhhjm6lVhYcre2P99fHgI0fjkSRrZQWZxVf+FaDyfKn/tupOo1eTpj2rW4W7Smk
         GevA+kLOCGe+cr01vPDVsqC3+P2ZxEvi2OsO+VqqfmtKGDeuibku92BoCfigkoPkdjb3
         5rgjTSMYNvYt2QzZFS6RTinucPwGI7wj+UKmiPgaoWs3tfeRbk85vYU2VupV7MQ6P31L
         WJtA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nTDDWGX5jnVR6eiCVdPmtGWvgB/PHne3k27JWsMXme4=;
        b=PZUw0hJJ21Zwd2mqiSJz81OQ4qTmRuLvWZbt/fUjw+fSN90MyKCGuUBGXuUJJ9toUL
         14/sj4c8k1Rj0SeBbxaF9/ikmnnzugQycOcTgQSEulFE4UjlrPB1rgJCONPfwC8tEDmG
         icjFKEPzDb4NObmgl7TrXOuIogfmP6GhUe3rYDA3/XtKwJVx12llo6T2ZNebLnrP+Z3r
         pV/3aGv3R/CJ3RHQ2ga7Ksf2RmpRCp20fRWh9o5LJ3SORW3/0KpHv+0QrVqIUkGvVkwX
         Ab9iAoLG0QjKpr43hMX2yK38G/qVnizMl0sBFFAhkVK/oX9dOLQU0R/maf7q9XYzkyD5
         aljw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=nTDDWGX5jnVR6eiCVdPmtGWvgB/PHne3k27JWsMXme4=;
        b=2Evx6jxr8IZ3BtG103zLnPwI3ZMdFvC0TZB3pnZ7yvXzhpRmLegMbYLFd9Vxn0O9lc
         M366X9NTN3juNY/yiF5VPmF4utmRClv6ogTyGURcQmcFNXMpDWEwXIEkmaUFXZAihSfP
         7bG6E56Kl3fmuZf8S69G5mhFh226bxBQSknr4gz3fN4FpUtPysyzmS6wO4Q+BELmTDvt
         oB8TZhYLpLaiP3TNrrsVuKrJPP5jqs1tT841QWzEWYPfJb4d3xglmvsD9XsBByrwUblJ
         F5xSL/6P8Z8CzkClyjWsk/0U04ERtMAne7up1E8U9gR0cHgDmHD4VGH3o0+4qBq+nVCV
         EttQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVU1L+0KQG3E/lGbCUVhKxZeMkZxJnSJHtN0q8ZpIlsi5fKFI30
	QnFCkSDvJW6Mp1VLfTjExAo=
X-Google-Smtp-Source: AK7set9bUuoiLOSLA3IwkmHlCa3fiq1iJhMMXOnj/fXHF4cX8wPVXhqfJOUkrehdEDUjwTlmeGJ9Xw==
X-Received: by 2002:a05:6602:2d89:b0:74c:a82e:eed1 with SMTP id k9-20020a0566022d8900b0074ca82eeed1mr9458182iow.0.1677614473453;
        Tue, 28 Feb 2023 12:01:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0c:b0:315:e39c:90ef with SMTP id
 i12-20020a056e021d0c00b00315e39c90efls5899131ila.6.-pod-prod-gmail; Tue, 28
 Feb 2023 12:01:12 -0800 (PST)
X-Received: by 2002:a05:6e02:1542:b0:315:5141:339a with SMTP id j2-20020a056e02154200b003155141339amr3884056ilu.7.1677614472884;
        Tue, 28 Feb 2023 12:01:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677614472; cv=none;
        d=google.com; s=arc-20160816;
        b=qA3YBflebScAmH4ntljiORGXcHld9Zzn+JT80yL0yP7Af0zJjR0W7UDtPafsh4etg4
         2I/p2nE/zocKF62OPmN88ZCO7xiI0msQznwrKKP5nY3VBVpiq4bYtkGQzgWRUUpgaR88
         nQOqZqVaUj7OwqaumOkRHr5LSF+a7QdxUJrKLTwg/ZF/ra3ZJA3KovZZj5hedPAeVCjU
         tM2D+M9EccAPgRNMQzOCntjzLfSZKoH4o5+NxwtTPU688ksmQYt3MuF2K43B+RrxsbiA
         BmQH+bwrxVgOWwWDNTtzReYioVvs2BWjH9NgHPVSeWH5+8kcrYIC2dBsoqJvGgs2+41l
         gg6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+UfcMv5b3nEqDwC1e7v3pq9dQo0t54UUGukhaiaf8Ow=;
        b=YeHqCzIgcv7PC0yp3hCgtjx4dxPeljC/L9fzNXq6wf6iCZXos/keJYQje/dxLiWUB3
         PvVuFjJ2RqsxoMon4tgra/RXqXMaPiGrCs2SsB9E9eycu8r6MxZteD8yn5I9EURLy6on
         R6a+KhsevSS8I/P90r7PsnmgQWeKybqSNL/FJQqWhW5/mgYMy/ugqhfA4JfCj87RlIMu
         gXjfYkldH38qfvkbkETnKf/SJWp0h13X4yllCnT1p14LgoCdlt5WUk8fA2NVUbrsJuHt
         BSpDzQLGtQQVih28GxWW6OxpClvGTfMcwvW7OQLx19IUxda+yniI7IbFByjIs0kBSAmB
         znmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=B9lAkxeF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id u18-20020a056638135200b003de9c6a747dsi1163945jad.4.2023.02.28.12.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 12:01:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id ce7so6538278pfb.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 12:01:12 -0800 (PST)
X-Received: by 2002:a62:824c:0:b0:606:a48f:c211 with SMTP id
 w73-20020a62824c000000b00606a48fc211mr348879pfd.1.1677614472313; Tue, 28 Feb
 2023 12:01:12 -0800 (PST)
MIME-Version: 1.0
References: <0b5efd70e31bba7912cf9a6c951f0e76a8df27df.1677517724.git.andreyknvl@google.com>
 <CACT4Y+Z4GvK-XCbrLp8cuH-xHYsCdh1f0948ZgkU2D0apfGG5w@mail.gmail.com>
In-Reply-To: <CACT4Y+Z4GvK-XCbrLp8cuH-xHYsCdh1f0948ZgkU2D0apfGG5w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 28 Feb 2023 21:01:01 +0100
Message-ID: <CA+fCnZdn+3LuzDP0f=kc9Pgt6i63cQbXieP1gJRYOS8WnVJKQA@mail.gmail.com>
Subject: Re: [PATCH] kcov: improve documentation
To: Dmitry Vyukov <dvyukov@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=B9lAkxeF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Feb 28, 2023 at 10:37=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com>=
 wrote:
>
> On Mon, 27 Feb 2023 at 18:17, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Improve KCOV documentation:
> >
> > - Use KCOV instead of kcov, as the former is more widely-used.
> >
> > - Mention Clang in compiler requirements.
> >
> > - Use ``annotations`` for inline code.
> >
> > - Rework remote coverage collection documentation for better clarity.
> >
> > - Various smaller changes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  Documentation/dev-tools/kcov.rst | 169 +++++++++++++++++++------------
> >  1 file changed, 102 insertions(+), 67 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools=
/kcov.rst
> > index d83c9ab49427..a113a03a475f 100644
> > --- a/Documentation/dev-tools/kcov.rst
> > +++ b/Documentation/dev-tools/kcov.rst
> > @@ -1,42 +1,50 @@
> > -kcov: code coverage for fuzzing
> > +KCOV: code coverage for fuzzing
> >  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
> >
> > -kcov exposes kernel code coverage information in a form suitable for c=
overage-
> > -guided fuzzing (randomized testing). Coverage data of a running kernel=
 is
> > -exported via the "kcov" debugfs file. Coverage collection is enabled o=
n a task
> > -basis, and thus it can capture precise coverage of a single system cal=
l.
> > +KCOV collects and exposes kernel code coverage information in a form s=
uitable
> > +for coverage-guided fuzzing. Coverage data of a running kernel is expo=
rted via
> > +the ``kcov`` debugfs file. Coverage collection is enabled on a task ba=
sis, and
> > +thus KCOV can capture precise coverage of a single system call.
> >
> > -Note that kcov does not aim to collect as much coverage as possible. I=
t aims
> > -to collect more or less stable coverage that is function of syscall in=
puts.
> > -To achieve this goal it does not collect coverage in soft/hard interru=
pts
> > -and instrumentation of some inherently non-deterministic parts of kern=
el is
> > -disabled (e.g. scheduler, locking).
> > +Note that KCOV does not aim to collect as much coverage as possible. I=
t aims
> > +to collect more or less stable coverage that is a function of syscall =
inputs.
> > +To achieve this goal, it does not collect coverage in soft/hard interr=
upts
> > +(unless remove coverage collection is enabled, see below) and from som=
e
> > +inherently non-deterministic parts of the kernel (e.g. scheduler, lock=
ing).
> >
> > -kcov is also able to collect comparison operands from the instrumented=
 code
> > -(this feature currently requires that the kernel is compiled with clan=
g).
> > +Besides collecting code coverage, KCOV can also collect comparison ope=
rands.
> > +See the "Comparison operands collection" section for details.
> > +
> > +Besides collecting coverage data from syscall handlers, KCOV can also =
collect
> > +coverage for annotated parts of the kernel executing in background ker=
nel
> > +tasks or soft interrupts. See the "Remote coverage collection" section=
 for
> > +details.
> >
> >  Prerequisites
> >  -------------
> >
> > -Configure the kernel with::
> > +KCOV relies on compiler instrumentation and requires GCC 6.1.0 or late=
r
> > +or any Clang version supported by the kernel.
> >
> > -        CONFIG_KCOV=3Dy
> > +Collecting comparison operands is only supported with Clang.
>
> Are you sure?
> I see -fsanitize-coverage=3Dtrace-cmp in gcc sources and man page.

Right, supported too starting with version 8.

Will fix in v2.

> Otherwise looks good to me.

I'll add your Reviewed-by to v2 then.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdn%2B3LuzDP0f%3Dkc9Pgt6i63cQbXieP1gJRYOS8WnVJKQA%40mail.=
gmail.com.
