Return-Path: <kasan-dev+bncBD52JJ7JXILRBDXOYCRAMGQEDRVKRQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BF9F6F3A3E
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 00:02:55 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-559d36a91a9sf30535707b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 15:02:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682978574; cv=pass;
        d=google.com; s=arc-20160816;
        b=aYNWUbZgYhdUbp9J9HQ+NlGHFUFG8kxwZeGHX3vmStt8Pyz/aHlu2+4wxuM3TmuGIx
         g43bZmZiDxsX9NwCBwrZLlvEXgQT8b5uK3qBcqy13ZKkvH1AvotOsVxXIHyc0TksAk9E
         uB6KRJ6Lvnm7Bbaix84pVmu2EcNG60jS4sVNzfwWIP7qAyTFMUEoSJ2ZHcw7/swv/u6L
         Ql3Ff78mhJfCVBpxU4nfW6RFtlKalJAgwCMdTuT/qVR1ZDlLd8u1fs7P/VCrgYwDQ/Kb
         eqpfPGEJAV+2dYffGbfEXUezCZg0jH4MaOAZBbHilVsoCsrhUgnxKd7ZgyWjmYZhJ3Ra
         5WKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t5WKWIo3QJN6BfBOt+hSpWVzHLeEEogOAJMHwb985ls=;
        b=SG3wrA80lI+wgyX1eTU8YqNIX0PHs4wAmJlIVdUmrBHwUIuueGXbfV6z/AhvfXhgfB
         Zr9ut13tacmflo40yVOKfkE2D9fzf4p5L3YIgtzoEn1oOvsreDKkw0uLcxWKeEyLNhAp
         /VtVJZC8Z3HS2Q7NEoAsPwZOik/x11AXM+5cZn1sSP5P0n424MSRIJb3bdfVY7uXTVPC
         K5sEE6QM7dKr9ZddTgkxo8YJr0gykRJjkhPZDSMf0JNf51PGIOJMsPmrMODdPPM0+lvj
         oV9d5XACNJ+8E/f+Qq2OUms0HcPnEzpax9qA0GKoXhiTab7BeEvTPO+j6A1OaBzVKofw
         486Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UaAEagmy;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682978574; x=1685570574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t5WKWIo3QJN6BfBOt+hSpWVzHLeEEogOAJMHwb985ls=;
        b=eg+mYfkH/J4TsQoUQ+p3zWONeJhpfUueuBCTImdvuNm91bq1rOwWODlLEckyma/x1z
         F5SCF24lUjg+D4f3gy1JdghovDEGHF9zc34EeZe+B7RuPBFpqIKa3RVHg7m3QtvxP1XF
         BMft/4aUaN4YXlYd2dm+iR/K286V1jvQ8DH3s7Z4fU2xiLmkitokhOh9svcPbpOwQdaL
         Q2r5WKILneLUBrs/d04FAg3m2jQ5YcqoeA86uJ8hD4t/KjeifLuq8iQQEcEqyAL2uFqM
         lvoldEP7tP50x4A5HBOPWkPsxi5otZfPQ4aspwb+Ge1M2qDOnvpgF7MKbzBvyIUvh7AH
         L7AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682978574; x=1685570574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=t5WKWIo3QJN6BfBOt+hSpWVzHLeEEogOAJMHwb985ls=;
        b=dbYmlt+ZVlnC+xlOX8q90GWujvccwNNZdHKmwOeWjn27x+otVtiCni1TqfdWW7fQiA
         6VE6ITvrJbNmRx4RGAzUOLuKX+dp2pCxIjtSNAnPJG+iPIzeo637+ECEfqw6xD4ukCq+
         OHTWRPWsbvqiZ2+j2LOBGqYaP2aVk/GkLtKEd9DWOK9pezjAWna6gZwS4L0+XrspwTy7
         NNJ4BChxHxyMYUp+wf6jGfVYPrtLN6nuO/iW8nq97JajQCTk3LaIRv5aBk3ar81qKGM5
         xCjmanWxxfmutDkFZKYYlDPHzJvF3ZWU8j0+TsmPd+wnnD4SocjIdHNap6pue6J1vaNt
         8DEw==
X-Gm-Message-State: AC+VfDyIiJ9HgYtmi3NCXSnLNKBIm7ikGlMfJMC4NWM3r1ZMsTtnjS5g
	D/bFBOuM+uBQOLOeXM0aEFA=
X-Google-Smtp-Source: ACHHUZ7rP/9ELLcq7/yo+ucIR0H+3X9vJSc6QfUkkVT1zR/834y3UON2SkxlytRzvI7/bcbsmhvwig==
X-Received: by 2002:a81:ef04:0:b0:543:bbdb:8c2b with SMTP id o4-20020a81ef04000000b00543bbdb8c2bmr9200866ywm.10.1682978574532;
        Mon, 01 May 2023 15:02:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:58e:0:b0:b8f:5ff4:69ae with SMTP id 136-20020a25058e000000b00b8f5ff469aels7250862ybf.3.-pod-prod-gmail;
 Mon, 01 May 2023 15:02:53 -0700 (PDT)
X-Received: by 2002:a05:6902:1504:b0:b8f:40de:e4c3 with SMTP id q4-20020a056902150400b00b8f40dee4c3mr17435262ybu.1.1682978573875;
        Mon, 01 May 2023 15:02:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682978573; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0payiDzSBEUMaU9sJ/sSq/ILNC7geaWEbbdhpTUVTYBAAjgi+yLI8DW3pzBuvuPUM
         aSoi+UCC7Teez8bdAixqf6+u1rmudGNJ+aEJavg126WgNI7Q21KNu9YLjxaAbfVaBLzo
         aNRYGrB8DQIWWui8xEKkO1JrVlKufMIx3cSwc5AsZjfwj4pLojtdci9EQXdBGq0wmBrb
         DU0Z8IfbEm2qasK53MeoM3sm1pSLQSxEfWRWkpB9JG9vKD2BH6H8XHMZwEoIgPxNZm/Z
         KU4hd8y5M4TaTBMwkPjMRxSKAlUFlJCb4IZT2W3JGx1Kw0dC3K5cGVDwBD5eksq1PrPK
         u+6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uUoPyEclplnbQ5nsG5OgNwVF48A7g0Micb2U/fMXHNA=;
        b=F/leR8g8b8Tmr4KPaxbN7GHZBfIuIC21NAJk/BGkpUKa2+BUZHO0RjjSleKFsEHQTg
         F+4KbDEWJQ/qxDHRGLdX9UltBKdxyEN8HNimaSts6IVfG662vWoqcJS8urKphBFx6YbG
         e8AbpgNITbqLSfILOpxyeC/2EW40radWRu+5IwiMKYjycWVBSC7nTGLxWy1mOTcmB2bH
         XDzNKgIc8VzMiKbcEX0LLOdLhJ9xX1vWepMo5yFPmacNwvRjzAEXU2ZBHnbu9V/bHGDK
         IRUtMWHoNTufhKECHsszi1iRRQaTzgYjMkYYlbelQtrH9z1CNJm3e/QdFheNcuHGp5sv
         v8dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UaAEagmy;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id x6-20020a25e006000000b00b9a4f329f28si1097288ybg.4.2023.05.01.15.02.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 15:02:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d75a77b69052e-3ef36d814a5so21431cf.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 15:02:53 -0700 (PDT)
X-Received: by 2002:ac8:7f47:0:b0:3ef:62f2:52df with SMTP id
 g7-20020ac87f47000000b003ef62f252dfmr21723qtk.9.1682978568636; Mon, 01 May
 2023 15:02:48 -0700 (PDT)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home> <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
In-Reply-To: <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 May 2023 15:02:37 -0700
Message-ID: <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, linux-trace-kernel@vger.kernel.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=UaAEagmy;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Thu, Feb 23, 2023 at 10:45=E2=80=AFPM Peter Collingbourne <pcc@google.co=
m> wrote:
>
> On Wed, Feb 15, 2023 at 11:33 AM Steven Rostedt <rostedt@goodmis.org> wro=
te:
> >
> > On Wed, 15 Feb 2023 09:57:40 +0100
> > Marco Elver <elver@google.com> wrote:
> >
> > > Yes, you are right, and it's something I've wondered how to do better
> > > as well. Let's try to consult tracing maintainers on what the right
> > > approach is.
> >
> > I have to go and revisit the config options for CONFIG_FTRACE and
> > CONFIG_TRACING, as they were added when this all started (back in
> > 2008), and the naming was rather all misnomers back then.
> >
> > "ftrace" is really for just the function tracing, but CONFIG_FTRACE
> > really should just be for the function tracing infrastructure, and
> > perhaps not even include trace events :-/ But at the time it was
> > created, it was for all the "tracers" (this was added before trace
> > events).
>
> It would be great to see this cleaned up. I found this aspect of how
> tracing works rather confusing.
>
> So do you think it makes sense for the KASAN tests to "select TRACING"
> for now if the code depends on the trace event infrastructure?

Any thoughts? It looks like someone else got tripped up by this:
https://reviews.llvm.org/D144057

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw%40mail.gmail.=
com.
