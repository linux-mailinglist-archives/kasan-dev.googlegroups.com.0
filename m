Return-Path: <kasan-dev+bncBDRZHGH43YJRBJNTUG3QMGQEIMH63KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B107E97A5CC
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 18:15:36 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2d877d2ad3fsf6899201a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 09:15:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726503334; cv=pass;
        d=google.com; s=arc-20240605;
        b=RDCqBcC8w38Pp8/5ZTUsFheyS9QCbk2vVtFjIab9UBMvemZpoVaL9CJm2vBnlAi/e/
         LVBed2isyj9y5JxmZpe4G6Ln0AcQjHOsxErGdnrDDc+SfNuU1eSnvdW+N+g6MrkYn/k9
         F9m7e/zpJCZwVIRXn46mzLiR2qMTcSIsKn/fOMlpBKhncMlQA4nLkKYqwmQT3/vW/8aY
         vgxsAtVxyPUtBFPHVTrwfzKFygXm+zONuzga0dA5+W046O8sJGJfjYscvsdKmgn1eXtv
         NKc72DapESa2ZdAbnBxgVMKPnqMXg49/k1/vYfl+A3lrYLkQD5pPqD6UawO4ImwcqvVJ
         rzXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+cGc3mT9MRmons/KIWoFlm27Z+6p0DPohpFd5QZunNI=;
        fh=wZ3SUnC/0ubBoLVeoaTqsIkBJEqdKaF9kMY0UiRPRFw=;
        b=LG0AA09OJca5JV2wpSYSj6BFtGI7w7/CIRHjy3yvMfmuEr7aEzkcM3dWzha49QsoAQ
         JhBuNivRfnd81pXGnmq9hnHJC3hvwIOa8zfx6mgfeK4VYYL3IMS22ZmAR//RTUeSotfF
         ORkIIp0gFEx1FClSgzHvE5rYenTqX1Vbk8g6eBtJnONY4a1ClDLlncxH7x3ZpdLMasl8
         DciQRDHDnXp3s9NCtOtmfImvU2HTar+X8yq6BnJhYEWuo1KWfqvSvcnma6lP52DKjs8c
         wY5n7e6gE8u2EMwg1qVhRTFXlbExKA2HFKcDdreZ9OMxUxKwWBIqqFefZYHgZ7j1+VzK
         sQKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AM60K5zA;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726503334; x=1727108134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+cGc3mT9MRmons/KIWoFlm27Z+6p0DPohpFd5QZunNI=;
        b=TAOrQ4hyqbcJHonBAOG2d7VQ3Ee+C6ZryRBzq8eMM8WP++QNrBa534CUxC51NR+3RN
         dL2MmApi446KMAggF4HzY9ZOE7ptQ2xg95vUYFOFLzYSAbLU1N7QJmJ2C8J08VMLrrby
         tgATc1BN/mHvRYYXHZofnU7OgIlsH29hNQnhDyxrfcy1c/BmADYxOAOy9uPRD+arvkKw
         jI4pW65JtGFFvQkOJEwic9jk/EvMhBzUYJCM+PAvdUXSZreSSWSuDBM/YrRtcCP7JZ/W
         PQq8jTaWIZC/PcqK138OUcgOMtC4eOZcNRoxbSvQG1Xu8CIPQcSi4zN/d9taLNm1Qe9T
         F/GA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726503334; x=1727108134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+cGc3mT9MRmons/KIWoFlm27Z+6p0DPohpFd5QZunNI=;
        b=kfo8sbpdWXBh3vASpYTISNP03S+WlaxHPdM4kbFkrm3t/XDtaIeN2rujgX8SuC7jGd
         2rM8fHuoibe8tpnzaUwh9lzNtiu3H2LWdl83W1ymCAnUhJ1L16alGixKFMRjnuP7Z1Ua
         //1bytetXlq0+IoT1p0LA/Qh+3IIpr9eubyJlzMxtspwyWk/H+K7zuZMTmzelNfOCh1l
         6y/DXE+l1JPdV9waFYJze6TPbmhYwz3ZAk7JnUcglRLQ7BQDM7CUUjcN/rR/FW4FW2Si
         YsA3LRLsU3DZoPmdXhTzuBsPteOVKnFGyf1EQL9KeEvmYFzrtnQc+t/z0WUYq49ayXjz
         eJYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726503334; x=1727108134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+cGc3mT9MRmons/KIWoFlm27Z+6p0DPohpFd5QZunNI=;
        b=VkjZNqZlA+g2qqr1mKyol6XTCJfVnq+2izDwGKT9hWFG4ThvE6aPUyFVZmDW2QLW6e
         VFIq2mEXfOMyLhm+mqpbL6WNAF2mfC7xyIgf12lAyijhJ+FREzflzfJaCXWKmsW9AOOU
         AHIvGml3PNS/JuVHZFYYCm/NAm4NfmOwKnWxib5LgaEakEp/wZ9AEnnuUxKI/zszED47
         SG56nkdKx7dHCw7fHOQz6FBqXkYVxEozzDFUOuwoWiV6NnpWVltapr7BDOtavhzEdViD
         lnjNs/6FsTqAXmiHk5GDh4mebMcLsAjmhbmITFlm/ltXIrLC2cDhLuOZWbqXt5253vXP
         cvwA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzUkDRMkVQHuwYHwzqEoMfpKHDpS0/mg+iiDfuiSZtyZWQSUjeMOB/vqj0dg3S1GgirVgXoA==@lfdr.de
X-Gm-Message-State: AOJu0YyNFyCdX+UXeWkB/Bfvjac2FtMHUhRjXqNT8j7SF6aF94IX0IxL
	V0hcNC5WDLxUqQq3BU2A3LvExDwsr98rbfVRn040GzBh5kTnxjCx
X-Google-Smtp-Source: AGHT+IGBX7ox1QGkFhKMCTSRwPYygWeOyiIRk0XWI+MZLb6AQOPm9Ed3fBHXXJPE1cZ4mwYcGqj0TQ==
X-Received: by 2002:a17:90a:740e:b0:2d3:d8b0:967b with SMTP id 98e67ed59e1d1-2dba00269d3mr18909113a91.27.1726503334033;
        Mon, 16 Sep 2024 09:15:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:158e:b0:2d8:7c42:a28d with SMTP id
 98e67ed59e1d1-2db9ed426a6ls1341296a91.0.-pod-prod-08-us; Mon, 16 Sep 2024
 09:15:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzi+3cKA4uDDcLKmZgV0bxOyMpEvu/ttqOC2/yW3l32oxWra9D6PNSpzLQezfpAto1rVrvehSpXUM=@googlegroups.com
X-Received: by 2002:a17:902:da82:b0:201:f70a:7492 with SMTP id d9443c01a7336-2076e423c5amr257040865ad.53.1726503332592;
        Mon, 16 Sep 2024 09:15:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726503332; cv=none;
        d=google.com; s=arc-20240605;
        b=fra5yhE2xquqyotITr0Oit6136cVwKLUAlU2ppZkMBTVqMzP+9wOM6QMZL7f6kMRzD
         bRLWLlUki4/d3hINqfnqnfJygROPTl4UMJ/2UJRAZD8qgne12LXq3R/V78li4MVZstRj
         sHtKLasG5WffDCdtEhtLfYuazZJ7wdcCabyv5YOfrJXbXuV4+aKHbqK9quPTyaWGGuMm
         C1y2zqq7H7AzITrlzrkf7m8hN12TgtId5pRImRt9qeOgnOS++P+KyHwXVCmttmV7LVrz
         fBYN3SamkyjM1+7Nk2ESAHWOojQWWnvC/51XGv418m9EW5cTVV15u0xM6dlQIcBbQ6Oo
         YkCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UdCaaZaGAuNxnOSLC5REDzZqrguiE6BbNpi1q+AVJDM=;
        fh=sbOtbfW9Q5CZ0D6oJQTP+HdEKS80JbnqCIO3diJ2GAc=;
        b=EDIurcAMO7FL7KveaLAEVpZOgsOe9dEiwfmruSaAfpDSBTnDwspyb4QrDQ5dEevX1f
         4OyYI+lU3eKKhAvXKUf9PNGdtQIkKPvnxTMlV2FnfLIH+gqiz/uLegeXJBRzHBttYUFE
         zuAS9Pow87lUC1AVs4u/kvCGX3hWbPvllvDnqe9b4PDDalv5K2ADMWJOg/YgN5w41ayt
         dSQWFChOD0/ZoUxo40JAl6wuo4PkBdY7grgog8ButdSCrhCGVk12LtPTtH66X95T8L/g
         StW7ay04tmdO1JM0TpnvopO2fbvv12OSwfug81o84+Mp+v8Iu6vuVe84Vjzhp1miY3la
         RXfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AM60K5zA;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-207945fb457si1765045ad.3.2024.09.16.09.15.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Sep 2024 09:15:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id 98e67ed59e1d1-2da516e6940so859207a91.3
        for <kasan-dev@googlegroups.com>; Mon, 16 Sep 2024 09:15:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWCsFUWw8KaLgEbzDsDQWDD/2MIrM2UO7+Rdr0rfmxpBSVxKx6Y0Q3Oa8UxspOIieFTlIdZCWKx0mo=@googlegroups.com
X-Received: by 2002:a17:90a:f308:b0:2db:60b:9be4 with SMTP id
 98e67ed59e1d1-2dba007b059mr7383255a91.7.1726503332118; Mon, 16 Sep 2024
 09:15:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com>
In-Reply-To: <20240820194910.187826-1-mmaurer@google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 16 Sep 2024 18:15:19 +0200
Message-ID: <CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA@mail.gmail.com>
Subject: Re: [PATCH v4 0/4] Rust KASAN Support
To: Matthew Maurer <mmaurer@google.com>
Cc: andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, aliceryhl@google.com, 
	samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AM60K5zA;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 20, 2024 at 9:49=E2=80=AFPM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Right now, if we turn on KASAN, Rust code will cause violations because
> it's not enabled properly.
>
> This series:
> 1. Adds flag probe macros for Rust - now that we're setting a minimum rus=
tc
>    version instead of an exact one, these could be useful in general. We =
need
>    them in this patch because we don't set a restriction on which LLVM ru=
stc
>    is using, which is what KASAN actually cares about.
> 2. Makes `rustc` enable the relevant KASAN sanitizer flags when C does.
> 3. Adds a smoke test to the `kasan_test` KUnit suite to check basic
>    integration.
>
> This patch series requires the target.json array support patch [1] as
> the x86_64 target.json file currently produced does not mark itself as KA=
SAN
> capable, and is rebased on top of the KASAN Makefile rewrite [2].

Applied to `rust-next` -- thanks everyone!

    [ Applied empty line nit, removed double empty line,
      applied `rustfmt` and formatted crate comment. - Miguel ]

    [ Applied "SW_TAGS KASAN" nit. - Miguel ]

I think `TMPOUT` needs to be passed though, i.e. like I did in
https://github.com/Rust-for-Linux/linux/pull/1087#issuecomment-2218445303:

diff --git a/scripts/Makefile.compiler b/scripts/Makefile.compiler
index 057305eae85c..0ac8679095f4 100644
--- a/scripts/Makefile.compiler
+++ b/scripts/Makefile.compiler
@@ -20,6 +20,7 @@ TMPOUT =3D $(if $(KBUILD_EXTMOD),$(firstword
$(KBUILD_EXTMOD))/).tmp_$$$$
 # Exit code chooses option. "$$TMP" serves as a temporary file and is
 # automatically cleaned up.
 try-run =3D $(shell set -e;              \
+       TMPOUT=3D$(TMPOUT);               \
        TMP=3D$(TMPOUT)/tmp;              \
        trap "rm -rf $(TMPOUT)" EXIT;   \
        mkdir -p $(TMPOUT);             \

Or is there something I am missing?

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA%40mail.gmail.=
com.
