Return-Path: <kasan-dev+bncBDEKVJM7XAHRBYPBYGFQMGQEKKVWBUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D50D54353F4
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 21:41:21 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id s18-20020adfbc12000000b00160b2d4d5ebsf10437679wrg.7
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 12:41:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634758881; cv=pass;
        d=google.com; s=arc-20160816;
        b=GSQsu4WwVrz/RzIh9BskboKShXGPItoTg7gE4uMdiPAN8W4tx5qE9yXTkFQDsBtmIL
         4f5qiCqpfj8fsXf6BGg4eD+67leI/xjz/1W/NtUOLa2GGacUkhXTXR7anZJ7gbI3lKGt
         nuu+pbW7IRNg/Ou6Os/LHEdEJ6aXuTCIvDsgoZ7hSqIvaUzOgT3DiIMAtSNBft1U6vQy
         D9dHOrmXrhdpW0tCQ0pzj1gyISoB7mOl+T7kS+eBHV8s4Kgp0iuo++I1+SYbEMqT/rxN
         tUGv5w0++jFXDp3Cuk/rXSvc8t/4OQJtxecP27Huou108LO1Zp6FTRpXdtzgVe8dNG9j
         Z1Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Pai2o7YrwT/z9nXpHSMFkM0qvS+3ZrhQcjuWmPQhXq4=;
        b=PDV1ZI52Lvy5cZd3lJAXF0d4djZYT5r3HbuYwpKzTpOj3sHHM7R1K9QbYxLjscSmaN
         1h5HXxdZXn1qh+rBS2EmF2+f9zzN3QkPWO3k6GnNhPXrnRcsJjfxuXTwAf9qhXiYav0g
         6+iLPvFmZJiy+llspteq5fGiXRtODPrsbJm0VRYNXLLIRX7aptxuvAHhenQl9yCirwGi
         eOAfBA9AKJ5e7OxgRrYge6/BfQuVT+/UbpX0gwG++jFQBQLj5ay53KMIg43d4qXiBDHf
         nhcy2DB/m45djIBpKTR5dMPU2uFJICfgKUqoolKvLRVP8e9fteiH5xurkvA9sSVXOcvI
         orCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.24 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pai2o7YrwT/z9nXpHSMFkM0qvS+3ZrhQcjuWmPQhXq4=;
        b=VfqwV+R6IrQWf5FrR+v+fbRxyINANd73M/4S4IxvfnzVyaoSMGQLg2ndqa0qVcPM11
         +TTi/frR+SQtfw6TOPY3MLoHDCwBDlhkNK44k7rvYt6otBjrq1uDhQH4PyO3mZ5qhQV+
         CTIU5KNgL5/G3pCeFn+8A9h9INFjyjvGx53o0wa3ElgjsFGTgkm5pXuW6OaBiUfPDH+I
         jSq+n/caEVMnAzclChVwY7hav37mhNtL6nixg/W9nK8b4x0oJBhWlKOhsN/9oOqvWeDw
         UukWSKfJ1PEhSa6mYgfWgPK14MxQqbf61OfD4R3VexvlUgg+ZF+AVVL/r4wQ8mOLCPQN
         6wSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pai2o7YrwT/z9nXpHSMFkM0qvS+3ZrhQcjuWmPQhXq4=;
        b=DbTRpJoRcF+2miELVLFRkL4HFgMPi/itMyriUY1TmgsOzEeSzN0oqDH8DjFTjRMm5x
         AP6RBlrMutjyWq4NScZsac4Mi9kAziO6n7MGum1ZJ/pPznhr/eXfVNOURqlW4V3TFlpz
         UuqrmlxhplqVpaV/cmqZdhntrOXvZNYR+ZSGHrxIz2PSC70yZXJOfe4zW+CzJnZMVBdJ
         SVDqP9SvGM9Fa/8zaJDoGqPWzr879ZD1DIEqoYYqFTD1/oGa2qu7cSwbW0kJYjHjkR6/
         2pRWyuRy8t7l1G2FyKRULPbcSDlhz5qRqO6bAs16F3VEAC6AtuPRGEo7ks/4BVpfDv7J
         yCaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306xZ5QJtiuxp3Qg9MkGg9SBR4hYU/3QeZcWM5kgTIZRi7KioqE
	fgk8vSYSrYeeKtkZwnI7b/M=
X-Google-Smtp-Source: ABdhPJx020NW7UE7w/bvddqaDsVBHZ0Va03n1CGcg17IBMjSDLCYPUHESzuJ/miFonGzzofZkZKI4A==
X-Received: by 2002:adf:bb88:: with SMTP id q8mr1490479wrg.390.1634758881622;
        Wed, 20 Oct 2021 12:41:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ef8b:: with SMTP id d11ls3890754wro.2.gmail; Wed, 20 Oct
 2021 12:41:20 -0700 (PDT)
X-Received: by 2002:adf:a319:: with SMTP id c25mr1455001wrb.307.1634758880720;
        Wed, 20 Oct 2021 12:41:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634758880; cv=none;
        d=google.com; s=arc-20160816;
        b=YCZDMJb4XsB1rTR2PFJXTslEnnbvd+pLwJtZ3Bi4xVcYBtkPy0cMXA6ec/UpkS3M0a
         3BXzuwRt4cWsPUdRFdxJ4L/OMiWiI5UIlSUSxiYStrzQV6NbF24yhenf/DCf9oIplH0O
         ORA2oji+kOC96KZoZZsv/CtCDK5Z181rn0z1J723pYM2ub+bN4QJxKaNOIbDG1YoL6b6
         EODOdpBnANwFLnUkL+vaPiLZmpVfw3Q+stRBsyIuAINsEvajSYN/7lD4bI7fh0gqSG1S
         4YZuabOnaHp3jo/dQI+WFccmGfZLcJ9fdfE/DwoW1AEMY0NwrxURfqDqaQ6XpY/gnfse
         9nJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=9LXJcG28nxuAq2jQztVTZFEZkXj9h+lTk7fxWJXKUJs=;
        b=X8j5QOEivnAuo4zCd1cco1cTgYZGWyPAcGU04hm7CZTrRVYeeLHpJ8dyBMqkmg5DE9
         pSsFReZSd5X05Yuyg9bj7+kFtXa8/nuncP1puyA8K94tr7jB8P4lsabSLy04RKI48q7z
         FaXV2kOS2BS3VLOW1xO9eZfABquAylgZ8UFQs60dZpr4g8PMb5RkTWj3CH8Yoxv7qHiq
         QXpv9sFMF7r1nUieA2ui65w6cTgQS50dIL4NhOdr8qTaOEp4kjsMN3PPC1q0lSn+0Y9e
         vw7HLlv25V06+mdfCcMisPSVUaD9LCafX8+S21PvqKsNtScMlDfWmO0s4az8iLudGAmx
         DIlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.24 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.17.24])
        by gmr-mx.google.com with ESMTPS id d197si399931wmd.1.2021.10.20.12.41.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Oct 2021 12:41:20 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.17.24 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.17.24;
Received: from mail-wm1-f54.google.com ([209.85.128.54]) by
 mrelayeu.kundenserver.de (mreue107 [213.165.67.113]) with ESMTPSA (Nemesis)
 id 1MowbA-1n3EHm0teo-00qOae for <kasan-dev@googlegroups.com>; Wed, 20 Oct
 2021 21:41:20 +0200
Received: by mail-wm1-f54.google.com with SMTP id b189-20020a1c1bc6000000b0030da052dd4fso12075438wmb.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Oct 2021 12:41:20 -0700 (PDT)
X-Received: by 2002:a05:600c:1548:: with SMTP id f8mr1373091wmg.35.1634758879800;
 Wed, 20 Oct 2021 12:41:19 -0700 (PDT)
MIME-Version: 1.0
References: <20211020193807.40684-1-keescook@chromium.org>
In-Reply-To: <20211020193807.40684-1-keescook@chromium.org>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 20 Oct 2021 21:41:03 +0200
X-Gmail-Original-Message-ID: <CAK8P3a0jCxafw2mM8uDGXuZM7PsJa6mBpuHTc7+CkEDcDfeqSQ@mail.gmail.com>
Message-ID: <CAK8P3a0jCxafw2mM8uDGXuZM7PsJa6mBpuHTc7+CkEDcDfeqSQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Consolidate workarounds for unwanted
 __alloc_size() protection
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:DRhl+JkE4fKU6+Oe9TdFvoI5mKOjW8rPbty77NSInJYH0sZnWbF
 AdLI10E7do59LlZLCFWYW8p694RN2WxUo6//FUuuQ4hOmMvNT/Ooc21t5kbwX/J22LvtXV4
 Swm4XVTO6vjjLw3rObd17g02qrnTcowpuflaZWd7sGf3SQylXxOynqVhWLYEQsvF39xm0Pw
 d5Ti1gNIqAs6JkuqG8hHg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:wjIVc57XJcw=:weo0u/kZhJCbytgHl8EwwV
 ZhwORO57w3czsRHYy4ZiU+Qfhbu0He0yk16wT0kyq8p9ZRl2pU2phtvr3HtjYq0QKxyg8NUg8
 r9aptaMWBLNFwcwmKfD5RtKk8lxaapSAz+XVBobct9stLRLdyo48TcSyZq9QOyEl3r3roapgQ
 nsQpXMj14axIi0kwG8THaYGQzj404280EvH7iVRz8mD1QjuwkbzxHqmK92SNB1tvDqVj32+zL
 DNz0vX04qV1r0QLr8dFuUZJz8NsafjGaNWEoX4Mie3IFEv7qnWMLMVT6sA3m1R4pUzVN25MZd
 nkZy5sLGX8kzr2Jei73PmJi2HSW/DOfL1kAPH31fg8mWgsvHdQkL6dK9uIMxBa/bc3DGpovE2
 GYBpaUDzNEbTDtEZRwrEk3mrjD4QVHDbQbwscA0DZaAkHdd5RU5ZYlX13ixuvMoUegKUCQso6
 IBdIT88jNWMf9d1BQYbumGWsMcNy4qRtS4OvZMOXvSIpViD7LLm7mBXZKeAlZix7nKcHlmqSx
 RungUl8Nq0iJ8iWUA2ZqZ/ENSmTMdQrm0IEjBHknbShhEcajRgwHKoD7yz6k0uPbK8w+EEjst
 +21eKgOVYAT6deK6/7sDR601DB/m79nXDTkdaExCspSx50sPfFcICyvVj1vbaaVAgMoAKgYsy
 nD16sDs7RB55cUOUkanaF3K5363DaEgPtWvi4OSeorXdNoB0cSk+G0Cfz5GJ5dtonnO65zr4B
 KhXArh1J+YslBZ7R7jJAwnfBdCx9icLG4x9oP0BjURTjGlQODQ53OKTkAw62D01MLz0k6R3So
 15YoNQDTfOma4wMRUIeGlXZRxuR49bc1l5H/dqnNNY/pxzXtsU=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.17.24 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, Oct 20, 2021 at 9:38 PM Kees Cook <keescook@chromium.org> wrote:
>
> This fixes kasan-test-use-underlying-string-helpers.patch to avoid needing
> new helpers. As done in kasan-test-bypass-__alloc_size-checks.patch,
> just use OPTIMIZER_HIDE_VAR(). Additionally converts a use of
> "volatile", which was trying to work around similar detection.
>
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Kees Cook <keescook@chromium.org>

Yes, that's much better than my version

Acked-by: Arnd Bergmann <arnd@arndb.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a0jCxafw2mM8uDGXuZM7PsJa6mBpuHTc7%2BCkEDcDfeqSQ%40mail.gmail.com.
