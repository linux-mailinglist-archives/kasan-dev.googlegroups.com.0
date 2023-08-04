Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMX5WSTAMGQEZGFTUKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 18CDD770792
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 20:08:52 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2b9cd6a555asf23608961fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 11:08:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691172531; cv=pass;
        d=google.com; s=arc-20160816;
        b=xBG2D4EW4ht5E9gTuHp+KZ34ls5c5Rn2dhEg9B902OVnTKob4uazYtOOZMPPVPmKqF
         JfOYXdB4f4GXpOyH7ORo4QC5gSMkOdXJ8J0OLRYq1Bf4noqlJGL4nxYDT8O8ohxlZ6Pd
         E/0ljCV5Ts+IL8BHsrT5+9tYG5eQdWXZaCej1NVB2Q7GXBi6l7HarXm2WWKC6UABIHgx
         pfa73XWscJXInH6bJlcF1CAi0W/awRw6q2WYyHe7aHDrqpRQzhbYUaUnm5/Xb+ovVDNo
         jZrInazqH3iTlRgYPS1PkkAw7El+pAktTIAKg7hd+Eu0WKgsOQhM70Ro9cUmlZsuimpe
         tBxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zh0AA1OSgkRL8G66sza9A+8zkcLcaj6z+gzZ3ltCpBs=;
        fh=3t+9JX4h1FMuCtHxMGExtCnzfKANoxWceyd8tNamNYs=;
        b=tXUxiu6gHTLJhSAjqs46F6+n7VcHteQGRx3w4FFWr11RIULcNvnDXbx2x516qt7p9o
         bVTtRzUFXU9ndtiud0bZxqwL1LzXlICaujDxM0nk4uOXyq+HNaCaQyI/yXAwYtljmc2V
         7YzhhIxqPiPG/OwrDiMmmIW8jncUYnF50iafOFZdxUj24W4DlwuNgyYWfL3HsTtq5dp3
         VCfqq6lIZiqsjRnWMIoSSEwj0kNdUFuq026WE/hvXBDvMQ4PXWkiJWO19DYg+vQzFH8p
         I8OrVduwgJ0D6iJ5ur7Rfku5LETe7wivEv7oLp1NobMHBYrBTpcoGw5ea78tEDQu0ay0
         GaUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=X23tQDKF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691172531; x=1691777331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zh0AA1OSgkRL8G66sza9A+8zkcLcaj6z+gzZ3ltCpBs=;
        b=myS7uuYDeMqNYvhdluY/IB3pllo0L8ScO8F1c28YHYl87eg1YuOkwgE18iuoAY93yK
         0ieQRfARwBuxevqZ82hHwSSwOmVvDT2+ICC8CdY25tWVAQkE6g34SdtRlBsud0HDb7aU
         2h8qvfDOvY+hK5uScFkQP/CJYi/hj5LnsBw1lVEodPbjEhQEVIuP6V4UuRMriBMNesNG
         NaX/X0C2jbjJKf+T+5EFmJ0iJ0XKaO0XR47PvIL5bLyvpD/JHygMyHIy+hGiM0crlYLK
         kLriAP2I72KOKcHgfvUbUSMfkz2a+ebMUXMZBj0KzSq2lTMxmcxUJcZEReXyRV3tNVVk
         jnxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691172531; x=1691777331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zh0AA1OSgkRL8G66sza9A+8zkcLcaj6z+gzZ3ltCpBs=;
        b=XHma0uu5FOeI7JzY61skeo40e6oika5NWsxosELwHS9TxJeSTWHZanZMFdiv37nflY
         XS2TkQUw/1dzyONt3BJaF7sutAm/gBAM/3kvV0Qm0hiPYY/c0UcQBbcG1pgZdzZ9rOLu
         geAPajAoRjFSkWNZh5i+aqmzhLlcFqxDhkPx+PRgc0Z+XuafJY08/pHjuIl04QSDOIJN
         lr046qibtd0zs/+u7s4nQp0Qlg/O2Qy3qOPm4DBJzK2s84UL2tzyMVv/2Afp0axovmvk
         ab2Hdvdj0n8CRssOcPIFK7X52ccn+0lC2Jz/RySBajj3jg/qqa73J3IuDMcbZ/IKV5MU
         g/sg==
X-Gm-Message-State: AOJu0Ywt4hA7h9SVCWvfeeZY0eRdz5401DZqy4LWfoRrjQYLH3tbf9ab
	vRhuPNE1tT6OFnIhPgjyW8k=
X-Google-Smtp-Source: AGHT+IG9J5+ghOzQfi5/mHJ83HeSTvdOSBYfQZXcsc3oaxHMsgP7qYRQ0mMS2jKsSwXFZ7ymocJF4w==
X-Received: by 2002:a2e:964e:0:b0:2b9:edcd:8770 with SMTP id z14-20020a2e964e000000b002b9edcd8770mr2391340ljh.43.1691172530745;
        Fri, 04 Aug 2023 11:08:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2127:b0:2b9:aac2:6927 with SMTP id
 a39-20020a05651c212700b002b9aac26927ls142335ljq.2.-pod-prod-01-eu; Fri, 04
 Aug 2023 11:08:48 -0700 (PDT)
X-Received: by 2002:a05:6512:525:b0:4f8:62a6:8b2 with SMTP id o5-20020a056512052500b004f862a608b2mr1829796lfc.46.1691172528632;
        Fri, 04 Aug 2023 11:08:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691172528; cv=none;
        d=google.com; s=arc-20160816;
        b=aVLr1fKms7HlnGjLdnqPduhvXmF6h+RdFD+pinI5WoOwiiYTu6qVpT7w4TuNgsYA63
         sydvd8RB8MKol77cyzLFaaI2i4OvJRzbEHRiL5xgqQlULPg8d84ZsKPagOkoRMb8X3RL
         zWrroUGNK04Eg2lG6ltb/NwB9GKASZcZl2umAwwzrERNfER104W3JeYiMO8OXgbs6f+E
         znobEJBxKEuttIIT1YCFImCwS5Zq1x0LMzjZunaStUCswJk+UTmgFYHBXYXRRKcgxWW3
         NyNMsRKP/ir1jvSdmDKwDAfQZ3zUT18Xn+/9mAIOgT6tG7Dj7V73zKuRKp+pKv2W5ahu
         fcIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fsI9PvVRlWWAw6F53JK6JF21HssLhBf6Wzr398dkifg=;
        fh=DLrPBd7o2oKP6cyzmVjIsB/4ChRHo+XNiPNmjSWnA/g=;
        b=NSWUE5/rhl2rMyurd0H2r1SH1OAdY3ieXwa4yQiOjbLN4Zn6JS4FK6D8nSg7y1+/Mi
         YCZa0QfmRpXHdEvXuZBSruqYU6QB53U/x+A95Ot/ZlDtuUZqfQGaQdYvEeKE2peuAHUw
         cWeeZnWfo4PL43w+t+kF9m9K0oJuZpZr7iNYdR8UjG5MCmeJyCAehTFttluwDWxPUP+o
         5w8CbfjRWdLw1auM9XL8DcONPz68+JkW5z3HwGhvbCDurUUVyj4fpfyl6c90dOdedr1J
         PF2LXbANNcVZXPlMXGTh9bXcHdlTyVEgdhYGFfUXgDgU/fZCaaDqOGZht4sNA3sVfraG
         +5RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=X23tQDKF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id q18-20020a056512211200b004f8621b17fasi189588lfr.3.2023.08.04.11.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 11:08:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-4fe28e4671dso4157517e87.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 11:08:48 -0700 (PDT)
X-Received: by 2002:a05:6512:3297:b0:4fb:9446:598b with SMTP id
 p23-20020a056512329700b004fb9446598bmr1882858lfe.27.1691172528068; Fri, 04
 Aug 2023 11:08:48 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com> <20230804090621.400-2-elver@google.com>
 <20230804120308.253c5521@gandalf.local.home> <CANpmjNNN6b9L72DoLzu5usGGjLw5Li8rnfu0VuaCsL-p2iKTgg@mail.gmail.com>
 <20230804135757.400eab72@gandalf.local.home> <20230804135902.7925ebb6@gandalf.local.home>
In-Reply-To: <20230804135902.7925ebb6@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Aug 2023 20:08:10 +0200
Message-ID: <CANpmjNPqfucNx7NdPOGSjjYgiZHntaBozGY1_rOSC4Wn4YCF1Q@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] list_debug: Introduce inline wrappers for debug checks
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=X23tQDKF;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as
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

On Fri, 4 Aug 2023 at 19:59, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Fri, 4 Aug 2023 13:57:57 -0400
> Steven Rostedt <rostedt@goodmis.org> wrote:
>
> > On Fri, 4 Aug 2023 19:49:48 +0200
> > Marco Elver <elver@google.com> wrote:
> >
> > > > I've been guilty of this madness myself, but I have learned the errors of
> > > > my ways, and have been avoiding doing so in any new code I write.
> > >
> > > That's fair. We can call them __list_*_valid() (inline), and
> > > __list_*_valid_or_report() ?
> >
> > __list_*_valid_check() ?

Well, in patch 3/3, the inline function will also do a reduced set of
checking, so "valid_check" is also misleading because both will do
checks.

The key distinguishing thing between the inline and non-inline version
is that the non-inline version will check more things, and also
produce reports.

So I can see

 1. __list_*_valid_or_report()
 2. __list_*_full_valid()

To be appropriate. Preference?

> I have to admit, I think the main reason kernel developers default to using
> these useless underscores is because kernel developers are notoriously
> lousy at naming. ;-)

Heh, naming is hard. ;-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPqfucNx7NdPOGSjjYgiZHntaBozGY1_rOSC4Wn4YCF1Q%40mail.gmail.com.
