Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2UHQ2CAMGQEAAECJLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BD2C36822E
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 16:10:51 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id g185-20020a1f20c20000b02901e083517917sf6847832vkg.18
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 07:10:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619100650; cv=pass;
        d=google.com; s=arc-20160816;
        b=ATeias7KPaXwXkoK59yWYqdOkT5Ael0556AMnUxtmdaxbbCCLX6uF6RZKYSoQAp6l/
         BD6MOHrDIcdUi7Bt54VY9SXJI3ob8uiR78iAoEbAi88xcIt3GkbocfqJwK9m+h/L4TsQ
         5/RMmfANc+2lQlVNkAtCBddQy02pcFSOEp7xxYTYgB7AG1W+rmcnfIbPedQKVR9+j2oS
         lxwtfFkLDf2oklmypiU/0OCPMm7TPecajhVYFQszx6ZlYtxt4OZwgVC14pfEbD/KiKyW
         19I4yiSiQht29qRdQw+07m+YyOH59CHp48eII4O1NYY7ZK1ITAZ4unTv3o3mEzKFkuAu
         F5Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0C3eGqvykcuyDH+sgJrh50iEbfkuxo1BETjM/r5tPdA=;
        b=uLQO0l2akEbCBjvKJHDtKwidVbBlo6kcR7sHEV+jZAOPrfaIxilROcfTA8cYGWfEXe
         lXwvHySA0T3DhIF3RL0UJUP5AL1JcBdh+VF1Ty5ekm/HsV5DAo32jOl/otw03Hsl6EKz
         bd9MlvMNZYQh+x1+XrH9WRbB/yyINLfK5fNMzhe6Gnlwv+BUcrFAwiwkGnkY8osU6x4l
         OtFR3Oja2O3JmAPURt6PELUqZV0J9PHofNxjetOBF5BwHF8I3UiRWtVwjCSdEeLxJZI4
         rRuVSQWSWgrPJ9qI7CDD3p84iEfBjgKQv23n6zK4RDwU1H2PdW2M7Zq8d0FBeijz5AIz
         quOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l0At3nLZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0C3eGqvykcuyDH+sgJrh50iEbfkuxo1BETjM/r5tPdA=;
        b=eUN5y2j6qjYUgOfr9TDsAjw+iAbyOlZsXsV5RyJJ6jx48iXVW3GHJo9XkdhWrLWWPv
         vdylev5HYK+txjwJvthzAwpM6pf54EyWU7cxPJ/Fjk8QXQD2S4Ab8HydHen6xvCFwfRo
         mjHyc53/EhvgHMOhSG7zhebZPgEAqICO3Ic6UTpPWo1Str4RWF7NoJ4gYspWnzc0eyPu
         e896AtvSXGsA1irmtzDjnWGNktoDNjEWfhE9tHLQsXMaBqcGU0tldaQLzKmxFSTAAYGI
         tJde8yxf7/muLdxZEJnW8S3t1vMfWszThOKIngwTynxQvzW8AE3gIf69maZucur1pI3w
         oblQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0C3eGqvykcuyDH+sgJrh50iEbfkuxo1BETjM/r5tPdA=;
        b=RSEwFJp6zJWtTpkpTaM/9q1kMW8rgNIG9yqMDhW9c7++mhxU1aP0l1P8ZmfoDFkNxj
         9QxPTUEBFkLVeC9BKfOmmj6x3ukD+bAPU0koqYB5L9VMSRwTjkVQb9jvzhs/0Ew/HxWq
         MGXStfH12Ziow0uKduVoH6vy27E1m5eDSj7B2eK3SFGtqdIv/xApQUeiG+mQ6CHpZdoT
         ak/t/HlqV8H1I+Q/VRuxwIyl5ddOQ2id5L8r3IYvCzyUksIC5ZWeeQdq4MnxpyCZzSCG
         rH1+Fb3DjXLiO7VmZP4DadSbdCDlakbwkG2mR+oi0XkT3AUTFHB7dYKlLQvx607RMx4c
         A2Ug==
X-Gm-Message-State: AOAM530b70//3CyioViL4vnIiSc9+TZdKPkY9csWxpeWdo+3/C5Ur/mE
	R3EIxE6riDyOQ74xfs2eMpU=
X-Google-Smtp-Source: ABdhPJx/OQ/cEIzyWrOE+XV5WmCtPNmnCniblg+nHJCIz9XP4Cygvul5WZQ/aFcz7B8uL0kCd5tnEA==
X-Received: by 2002:ab0:1d06:: with SMTP id j6mr2647085uak.137.1619100650226;
        Thu, 22 Apr 2021 07:10:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:555a:: with SMTP id u26ls560133uaa.1.gmail; Thu, 22 Apr
 2021 07:10:49 -0700 (PDT)
X-Received: by 2002:a9f:2422:: with SMTP id 31mr2725707uaq.68.1619100649614;
        Thu, 22 Apr 2021 07:10:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619100649; cv=none;
        d=google.com; s=arc-20160816;
        b=l694d8f4P2KP2eUPfAywhyZSL4NXGUFahskcSBOfnIqLE3sauEWoCksxsIvAKYxtGu
         6JkrIXuEA/K9sGpSYH8zlqa6/DyC45qt2ceK2McC8FcI1qIecZ8+sedtnPDsJrpLACgW
         OprlfzDpRg5qXG+Hn7YUUVF2jM4Q1KRWiQvbZn3r5q8E5Pk/hfd0bMIMqeYRhKJm4DTw
         WY4tJNt76b0iF4NEoXcCKQwhrvUeRRrA3RUHuXoTfGWyCiWIOCZZ5Kt3+9a7DRr1Y1SI
         02VpiDZW1oBVqOO82FOYTp5V/qX8mgqVTvCYAqbdNqMplp95id/55ujI2+3xSucGbrpW
         ez4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=600yFqdvLD6QPDeXvLbZtVFaRxpf+lbCpMUSy9z+aew=;
        b=Or3Xa81pZKdKBP7DHrx57173oVDMTZI5z3sfhSVBo4bOg3EnX2/Vb7mX4TSuRNZvZa
         cJUAc0Bpx9kwKpXy3e+J9ENSD1ZXHEp4ISAgK+142HIvDk0arjjWiaehXS+gaamOxcqM
         1Ln2GD0QlL0VbKOYBHGjyYM9gPxMHfDL6uU7z+4kZkFink03C1Lo5jPnbh94AVYKSthQ
         /khlL+UBxc2TfoxJ1ywoIlLQfSGA3XIa52Wpz9emno2J40mMhNNz8eXI+ljYXLYHCMT7
         esd4yd+0r9WTJzqR7Ns0fSWwEdUSxIV3zQ/J31S05U3n1JIgALCLG624VMJT4nSj4jgu
         UjLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l0At3nLZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id h7si577934uad.1.2021.04.22.07.10.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 07:10:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id u80so12322791oia.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 07:10:49 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr2377466oif.121.1619100648941;
 Thu, 22 Apr 2021 07:10:48 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa@epcas5p2.samsung.com>
 <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
In-Reply-To: <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 16:10:37 +0200
Message-ID: <CANpmjNOT7xVbv4P1n3X24-HH8VMBs7Ny33DFYbzjO6Gqza2mZA@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/kasan: avoid duplicate KASAN issues from reporting
To: Maninder Singh <maninder1.s@samsung.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	a.sahrawat@samsung.com, Vaneet Narang <v.narang@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l0At3nLZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Thu, 22 Apr 2021 at 11:17, Maninder Singh <maninder1.s@samsung.com> wrote:
>
> when KASAN multishot is ON and some buggy code hits same code path
> of KASAN issue repetetively, it can flood logs on console.
>
> Check for allocaton, free and backtrace path at time of KASAN error,
> if these are same then it is duplicate error and avoid these prints
> from KASAN.

On a more fundamental level, I think this sort of filtering is the
wrong solution to your problem. One reason why it's good that
multishot is off by default is, because _every_ KASAN report is
critical and can destabilize the system. Therefore, any report after
the first one might be completely bogus, because the system is in a
potentially bad state and its behaviour might be completely random.

The correct solution is to not leave the system running, fix the first
bug found, continue; rinse and repeat. Therefore, this patch adds a
lot of code for little benefit.

The much simpler solution that will likely yield a similar result is
to simply define an upper bound on the number of reports if multishot
is on. Because if I've seen 1000 reports, I already know the system is
completely trashed and whatever else it's reporting might just be
random.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOT7xVbv4P1n3X24-HH8VMBs7Ny33DFYbzjO6Gqza2mZA%40mail.gmail.com.
