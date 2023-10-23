Return-Path: <kasan-dev+bncBDW2JDUY5AORBIVZ3KUQMGQEPFBLNAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D20CA7D3C18
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:17:39 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6ce346991cdsf5745599a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:17:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077858; cv=pass;
        d=google.com; s=arc-20160816;
        b=HT53IG3Z6OylVNmpd/rKyhAgAbBFS29AH5TbmaTdfnKf3w7P1IQgs+AmswNco+iDHb
         sD/6K/BZYc4rR06qyMQ8wS0DiKXx8uAyHnrMXCrO2711+0RrsSy0P3MUkYDqTkXPn56u
         m4Zbn7lSgZRrMIw7LKHmkeo9VRbHpImyirKSFKogs3ypCzcGpdj3f9rZ3RHIuSGPwKy7
         nWo6+Zkwij0YfUU4Q/8P8F1SYd/+afjna2ot5IhCZNZnFL6vlztsTZsS59igRUJG1F1N
         TRnD7GkWU/Hbc9YSCmh1cGFaiUTO7NfktntBxGu8yqNz+Naph2S1anxKhF6BuS1iRGQI
         c99Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9QUF8RakFNM1yHiSCFn4C5nTfv4Ly+plyB3wextHnjc=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=scoZsD6raAWGRu0IgjeUmfm7ZmwLbhaLwBzqeT2k/ymjrq3/PZDnFyLo6AjdSG2LNv
         eD+Byqtz05pT6Ph9Y15azhA+L6vuGPKlDq4D1LXFmEYjuGhBD4DQW99dbv4et4Oz0+jn
         e+N/OkOyb8fqgBeUwI0ENJszd8wa+oSG/3kyCsmNOxNfUaRKKJ954vnoHlPkl7DeZmTu
         G9VhRIF6u5P24miIUGb86mfXwhSMPXJupintq2u9MXEBcOJCyhqdmJmJFS11Rv8JIiT7
         cClOfQIdjfn5gwepEcNhQqGl0uEC7sXzWwfv+DAuJ/41Nc74aWZPfk4QVL3HLKBxdaN8
         yJdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=elKdqsy6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077858; x=1698682658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9QUF8RakFNM1yHiSCFn4C5nTfv4Ly+plyB3wextHnjc=;
        b=SC/CqHoHRlnRMHkF7dMoIB759d3sEWAMdwtp6yZ4EPZASC8FGyRa2Z04K/cFSQnLZS
         9/80+mHeuSBB49+hyVDRj/a74806UNWfTtudy0WQE8VSy74d7Yg8/Fe1CEPZiG3FSoyQ
         46ktPczhJLJzfWBCIiC3/ZlgaYG09agR3I1SBLvymiIIK2OVeOhbj15aEMq7BQ4h6ZsL
         warnc1FBokHaEAB9gQ9TNEONPCt3E3m2QdMIqP+oi4vc7dXuFylQmbd/ydMWkpzlF4sb
         HoTKgXbq80zOEq/fEG8tpbKM82mA/84NearB92r/qwaP/V5mtLPizkE7MCA0v6+DclKw
         91JQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077858; x=1698682658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9QUF8RakFNM1yHiSCFn4C5nTfv4Ly+plyB3wextHnjc=;
        b=MBuhL8PLyMNM4+J/BCNtK798B1NZjIRMiNqJTs1S+47Y/ctqcbsaUMdfv0KbDZAMfz
         8Rj6+A51REXg9mw0nOZMpQTepJ6MjYBrKAdW+kf4OFHItb+6WrHcagnf7UDp5GW9yxPr
         vCQSSwwtexLp1JMW7GU8ey1+HGNNUOyB9jp0ua/W47diXatQ/WVtaXtaAQDJ26IDLTt5
         POHdU11nybxRONIoyuavtA3nZv/gLIde5IYRxuCPggvCECvZn2ihTQMSJiKwY5mdD30w
         FVp8tC741gtSAlRYVz8aMk5Nv/XgUlxfsL2ZQockMbWDwMoeA7ZOg5vLIN/B5ISZ7s/K
         Jrdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077858; x=1698682658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9QUF8RakFNM1yHiSCFn4C5nTfv4Ly+plyB3wextHnjc=;
        b=Ml1QdpCEM/97XBdzrZOiwFbYjxu40o5oxCcK99NuQ5Q6UK8rnQpWDVD0bJfHFmYmET
         fxChaaizWDDfUO/j93Xh5Z8/L4eQMwIxYdMgFi1ZXd/dk6N6QGxVA6ejr8IOeVIzQxb9
         AAJ0LM6+2IqM5iYSjwQAIY+Q7sI6CA0wbPtD9EeJwiwvnT74kmr8dDbZ7rJfrmw5TKZ7
         LSWL/kJQaD3tmBLDh9FER2gTVql7RVxlqvtLd+t2skFt71b3tHuhHIe1eEmq5DiuRnKD
         JDni1RnZek6W894dPrDurdwdm/pB6QUYbHm3WKo9cjpsLA+uznXItudMWYXyUmR4EOJp
         O3+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzdXr5Wz++QQV7qZZ9H0mM4FSg4esUZ0zQ8pHtPJEW7YXkkM96O
	5a+YKSFOe9vxOYGQe3s0N8s=
X-Google-Smtp-Source: AGHT+IHUmBkr/U3eHaZ37xcA2pIud0ySZuTxTL8sxGXSAL3jCnHzNdXZVN/c1hcMjA5LGXBJ/P7Nug==
X-Received: by 2002:a05:6870:4c02:b0:1be:ceca:c666 with SMTP id pk2-20020a0568704c0200b001bececac666mr14350796oab.14.1698077858587;
        Mon, 23 Oct 2023 09:17:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f609:b0:1e1:5fe1:87e with SMTP id
 ek9-20020a056870f60900b001e15fe1087els626662oab.0.-pod-prod-02-us; Mon, 23
 Oct 2023 09:17:38 -0700 (PDT)
X-Received: by 2002:a05:6870:13d8:b0:1e9:a713:7ada with SMTP id 24-20020a05687013d800b001e9a7137adamr5424016oat.6.1698077858033;
        Mon, 23 Oct 2023 09:17:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077858; cv=none;
        d=google.com; s=arc-20160816;
        b=kDfUy/HIS9WJuGYS4NWC1HJpCItR5Yc0hwqUmNcSik+O+I6SBRXcabZpx794fVl0x6
         cbPCF0wDfZ5/nmxm2yi9uTe3BdbP+z8jTaVjFW2jvPk0KmGMB24+PhNCd9PaKN9GZTec
         vuAt/rmsaLmY4u/o6+XarC3Xs4ESfplwD/Z9Pds8Q1/Up9BoZLF715TFJ06P9Xa3HG2P
         vKKSADCOVmBFvPEe5R9qrZURrp4rIbxXrYYrhChKSk4kT4GsF8s77c1qJsHRFgY/154y
         amy6FNQE0oylIDUn0LKPUXPQhH7SmeumDTdR2VepKxHkU3bZK0ifw2/s6MwuinaRprdP
         lb7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wZyP39z6xvoSIY5Cv54i5pfq0RfQpmz8NTDav/yNwTk=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=cER+LV49Lj46PveMfFROm/rL0apHlqqLZWAIAIoiq64lV6ZdDNs/zJm8BrwvHRYwrE
         M/cbMH76f1VClokWlxZehKK4UjERbupatuJTJkIBUrj+UM8/g7iUEIfb7mydfdXiMC6P
         r+Mf92NFdzxjD1XoDmXmmptWuLIs2KkOms1l9QyLg+XCSNCblEQv9Zp0ppciXskJzV8N
         pV/r1SptBa+ZLwGWKL/mCsKEInYOqbE5dvKFzpwj9lc2Xq2PenXeGv72agvRAC83NBj5
         YePHA9kI1WKF5nyzUdTT8b3gEdcooIVU83ii9AbdNISXkq5PsE4PDVmHTp6WiPblfEaI
         YqDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=elKdqsy6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id fi3-20020a05622a58c300b0041ce9eb6295si394659qtb.1.2023.10.23.09.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:17:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-27d129e2e7cso2468838a91.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:17:37 -0700 (PDT)
X-Received: by 2002:a17:90a:f315:b0:27d:1f5c:22cb with SMTP id
 ca21-20020a17090af31500b0027d1f5c22cbmr6881409pjb.20.1698077857064; Mon, 23
 Oct 2023 09:17:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <556085476eb7d2e3703d62dc2fa920931aadf459.1694625260.git.andreyknvl@google.com>
 <CAG_fn=VJtzkvrMu84BuNtbjkmRuQx7aLLSsew-Hns5bAdSnm2Q@mail.gmail.com>
In-Reply-To: <CAG_fn=VJtzkvrMu84BuNtbjkmRuQx7aLLSsew-Hns5bAdSnm2Q@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:17:26 +0200
Message-ID: <CA+fCnZcLL9vapkMv292FnQdxbUY=_q8-r6aQ+9=okjk8ua7JLg@mail.gmail.com>
Subject: Re: [PATCH v2 17/19] kasan: remove atomic accesses to stack ring entries
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=elKdqsy6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f
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

On Mon, Oct 9, 2023 at 2:05=E2=80=AFPM Alexander Potapenko <glider@google.c=
om> wrote:
>
> On Wed, Sep 13, 2023 at 7:17=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Remove the atomic accesses to entry fields in save_stack_info and
> > kasan_complete_mode_report_info for tag-based KASAN modes.
> >
> > These atomics are not required, as the read/write lock prevents the
> > entries from being read (in kasan_complete_mode_report_info) while bein=
g
> > written (in save_stack_info) and the try_cmpxchg prevents the same entr=
y
> > from being rewritten (in save_stack_info) in the unlikely case of wrapp=
ing
> > during writing.
>
> Given that you removed all atomic accesses, it should be fine to
> remove the inclusion of atomic.h as well.

Not all of them are removed: stack_ring.pos is still accessed via atomics.

> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcLL9vapkMv292FnQdxbUY%3D_q8-r6aQ%2B9%3Dokjk8ua7JLg%40mai=
l.gmail.com.
