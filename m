Return-Path: <kasan-dev+bncBDW2JDUY5AORBDOQRWJAMGQEVW5X7MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E154EB47F
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 22:11:58 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id q4-20020a0cf5c4000000b0044346ee3627sf6429524qvm.16
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 13:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648584717; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGPpZenAA8TaWXAHZM8yvuUNgmid+L1L+Xj7wuBff1sIRmL2M4aGGtvby9Z3EfDrwh
         p/YCJ7/EL8/LChz2s8Dpz/Cgb+LZwbCDjxzxNuRfdJD4RI23lRZejpCBQN8ZF5b20orR
         CUC+bh2yDjdy7fUfIgOhVnGyUXziokRlU7f3HeKaAVTFtsdd11Dd6D4n38OxS1AUXbsk
         alsW0XMQMpCPoNgJv2UOF8YmUrQzhdw2zMkk/G6pLotMhNhEJe0KKUEmKp51KhxmRC58
         XqdDoDP1KX9jAXEy2bd6IOxO0urSXMf7jAFkX+y+Pakw3LbQBu+TFM06EvlMiK+rIw9t
         Pi6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TzNB8RuyAZwANKPrQ2HkocaA1dMQ5knya1vumxDnZvI=;
        b=Nw7hUwysFZ4p25G8D9B4PRxf4xdw0NrKXuYy4S21ZrEDFimeVhx1ZANQj/oeb7bLy0
         Gt3NVcfu7YfHu0bekdPjTqlcch7/sIeQ7I5e0xcDM6+g8YsXrLRSMMTnKwWUkIzdyLyW
         m/u3RM8mxoif9/21koemgLwxHfCQrw+vKHr2tLsa7Ypt0niXZCiQaJ52mOlm2w63dxx3
         8atm6TV/YxLMf1NvyRToNeshBE913H5KSeEvoHtF/NqwE/WJ4btX7Tr9rfsXu9eD6F5b
         RTktYWyptpt1TVHhHUz+V1c+HYMyxInK+Gjv8gGmRwTH7gF7UxNUI9aMjgprQ44LCFVd
         jYlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RCfMNSku;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TzNB8RuyAZwANKPrQ2HkocaA1dMQ5knya1vumxDnZvI=;
        b=jsVUJRorV1zD0Nwa0nW6TA/vW5mHA/QzNbg0lhgJsx7sP5dCZVf2X60DW4UbBUwzf7
         58mU/mrbu+eDwZxbeVDBYdyTuzrF6v728Pa+t/G2aX5bJJw+vczZpWj7W8IvuQ/7A6Dj
         k6Demp250jk0aqmLJxYxNyDSCq6dtdoJfSJ9WPWRU2BKsiVf9/vtq45d83MxzBJugzP8
         39/VeTdC3KybywPQVgpZvFErKN7x9ai70usBmNCa+m+fiz3EFAKLna9a0rWavTfbYxce
         ckndzxd33qqCj2v28qWqVTLzhSsVPXXCTx0qVkdxhXKJP/UuoquR0LMHj+RZjZllpKNo
         jXLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TzNB8RuyAZwANKPrQ2HkocaA1dMQ5knya1vumxDnZvI=;
        b=na/YC4OAp1vk54CZBVvzf40JmQmpJuBBSXs/F1T3CPjxMHdT2tdzHCiU6R0GJ7iJ21
         boupBAd+jAdL+PqK6rTH/59UEoulJlW7WCiqTbWSNFTk3u77KJhua4l4qaUFHnvI/oDh
         29xqVtknuy2oBUcO95TPB3CwBxGHAgJsuUrZKt8jmPIvwX6tt0nJVAihhiv6HadFTAB4
         HKNxuixZe46fDlTmnzyYbhsXmVyTzeHB4Ro0LbhR96qI0Mok7OtleiUz87xVL3vWIp70
         LPuJOpXweEKP+5R0hZbS/0zZKHE2kNSDalEktLrGE2mQ0F1uPxI1QEMhgycO+u6UwMlV
         HPWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TzNB8RuyAZwANKPrQ2HkocaA1dMQ5knya1vumxDnZvI=;
        b=yJnkLR/ZSNJhBo6HHwYSt8DS0ukgWmhnDyJg5ekkbg1hhiGIsNJRWZFtK5QD+keWe4
         7eKKQMjIDrpDIjjMFeGSX+lAvEIeotzh+pLb6RNHjFEMWXJSE+3IqvxxneRTxW1HIvtb
         HlRlo1GMTgWXS8delB2J9unSeNV7kT+/2f0UQ5llL4gAKxAgndAzJPlIyVu6DnIYYXzQ
         c69WB1RkHF36gNmBfbQnnkyXsSo7ei8XhtE2WTwQYlJG7YAQ99IDkNVyKyYTsJFH46F2
         938rqBjtJ9iju3rY4Ce+ZLYtqhCD8vNX79BEK6pWEkn+nQ5NtacI+EAIN1OmEGDJ0U0T
         aiLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317jG6CgHE74EJDrcHA6DRvuX5owjKyxRzHZdX3cXUI2NE7FxsE
	AVhwgdBdp9unMiaPaIgKQKc=
X-Google-Smtp-Source: ABdhPJylIAHG4h8pi4I7mNpETvGx8ud+qxLaPznH4D1vDW5CKw3n7dsC/TGyxN4u0xKNAJ/0Wr2MiQ==
X-Received: by 2002:ad4:5389:0:b0:42d:a3cf:1b67 with SMTP id i9-20020ad45389000000b0042da3cf1b67mr28451952qvv.129.1648584717262;
        Tue, 29 Mar 2022 13:11:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1f95:b0:2dc:915a:9d81 with SMTP id
 cb21-20020a05622a1f9500b002dc915a9d81ls77174qtb.11.gmail; Tue, 29 Mar 2022
 13:11:56 -0700 (PDT)
X-Received: by 2002:a05:622a:594:b0:2e1:d59e:68ed with SMTP id c20-20020a05622a059400b002e1d59e68edmr30107353qtb.204.1648584716809;
        Tue, 29 Mar 2022 13:11:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648584716; cv=none;
        d=google.com; s=arc-20160816;
        b=Lz79CYLx12/vcyPe4eMBvCSk9WcwRReyPnqFODajKqlURAqDGi2efiSRiVbx3Trk8N
         5WCNTcA059+nalanXwoWCoFcOrKwagN84Rgc2+une6BFOsGRTaLZkPC0MG9/jYOvbgmt
         U+AN2ZRkgfZ7foVXsBPZK/lsbNwqlzLg+SI0ltsi6sr01nZpwlPE9Rjh9DuOx+PxWgVL
         +LauFTg7izzTc/kn6Rp+yal3JXo4W6D9n0FWYODyYeEwh/rHMkTWd032UZQB3/ITib0/
         LZyVlOq2yVxzUE1nXXSnlgmnZRiG5s0OoBuKAtc4gMVKibAQJ1IkHLv6qAb3y8yphtSE
         230g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Hh0vVsE5NsIgTehOa3nlosmMfHWGMN9c6MMyMO5zeA=;
        b=ELJDk5qPerzI6fa69q6qXQVYBXnRJuKp2rl04u0WC3sI+rrJilPLvGJhUcl5PEU7DB
         JttUviE1UDRYjKXROB9BrQAMm3YeiwauKmKbnut4LeZjCl/HjX5PzF9APhU/9tgkIlxU
         aVoMS6gU21l58w8aoIP788ajjJ3UmJz3mcpNrGaE65jxCK7IqAhOnOmA7r8CWb0/Rob6
         ebZRF20W3qod8eLTP6HKh+znbfwLINBUkgLuzsm5qxSCAJjaZKAETUBXcdJ6kY/Lvv3C
         aTKum3RZm0eyUwOhvzmW8eJ1o5Ip60wn4RuIOK+ki0xYsh3ENpxaMGX6UG9foLB4dU7q
         7L8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RCfMNSku;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id j6-20020a05620a146600b0067d1ceb0c68si927002qkl.0.2022.03.29.13.11.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Mar 2022 13:11:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id g21so9183641iom.13
        for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 13:11:56 -0700 (PDT)
X-Received: by 2002:a05:6638:2113:b0:321:4e19:b04d with SMTP id
 n19-20020a056638211300b003214e19b04dmr18181370jaj.71.1648584716304; Tue, 29
 Mar 2022 13:11:56 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <CANpmjNP_bWMzSkW=Q8Lc7yRWw8as_FoBpD-zwcweAiSBVn-Fsw@mail.gmail.com>
 <CA+fCnZeiR4v72P1fbF1AP=RqViCnkdtES0NtcmN6-R-_9NS4kQ@mail.gmail.com>
In-Reply-To: <CA+fCnZeiR4v72P1fbF1AP=RqViCnkdtES0NtcmN6-R-_9NS4kQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 29 Mar 2022 22:11:45 +0200
Message-ID: <CA+fCnZcPOfBuOMiXsaQzWMYxG=L_QGVgLDAdNWmYciA0JT+Deg@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RCfMNSku;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32
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

On Tue, Mar 29, 2022 at 8:36 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Mon, Mar 28, 2022 at 2:36 PM Marco Elver <elver@google.com> wrote:
> >
> > > Changes v1->v2:
> > > - Provide a kernel-wide stack_trace_save_shadow() interface for collecting
> > >   stack traces from shadow stack.
> > > - Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
> > > - Get SCS pointer from x18, as per-task value is meant to save the SCS
> > >   value on CPU switches.
> > > - Collect stack frames from SDEI and IRQ contexts.
> >
> > Do any of these new changes introduce new (noticeable) overhead (in
> > particular patch 2)?
>
> I'll measure the overheads and include the results into v3. Thanks!

Hm, looks like the overhead is overly significant: ~5%. I'll explore a
different approach in v3 instead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcPOfBuOMiXsaQzWMYxG%3DL_QGVgLDAdNWmYciA0JT%2BDeg%40mail.gmail.com.
