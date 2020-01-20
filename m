Return-Path: <kasan-dev+bncBCMIZB7QWENRBMEAS7YQKGQEVBEJJ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07A11142E3A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:58:58 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 62sf13843043ybt.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:58:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579532337; cv=pass;
        d=google.com; s=arc-20160816;
        b=kM7D1GKeoEStF+B42ySlYe6lr5UkCNHKr6y/0U0BcW4+oecJ5MYgd2pyOq97iOWMTw
         rO+EVqnVsPe3tef4UOsfNpT9h2ouBa+PvSixS/7MxM1yxotSMxzXQxBOgci8qgaacK1V
         hxZ5B3JN+WdE7N2UcPbpoqHz9/g2hWRktBjw0qxay4ma/lSMmHfUE7bkCo8jxlY8LRmr
         9u60zTISFOOxyi6EXVWOOMexIvV3I31tUi9mT2AZXukMlzPwqpOQCHQZ/kSCkchGw3DW
         U+X5aw5SyDNo4Evo0bn993RbLdNVuFPPUHXJE5GfpsA0TtQU0MWCcOz+y7J5ovdylzhS
         E12Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kqlRXzv7kJViMK+GbkZwTR8A2MPs0DMi0NrUf0tOEks=;
        b=j/8tQoj45xckFd9UgQLsRiEd+zsFAjar20C5CcKdOQqbaYcrFjojk14h5NZgelV+MZ
         8OCj/6zxLEoq21rlKkmZyeyexcrRRwfaVRyeIE4Git3q1RNhmIRY4Z8adgbd9CwxQuOo
         FgaNwqFccAo9O7L9n7nmPJcB7JasL1jLRmyMRVK6oSY/Gz+Ly/gjDyjzZSRdv5Z051uk
         sgG7+yKYDZRczVJfe9mPsX0+Tc0OPXljzfudCG2miPcLsXNTmwPJdQNj6vFNTQUPFsad
         oghJj/g0ropb1DPvr6mAL45jQhPHfU1v/f9dVVJkCfG82ZN/RTO5/B8VPjZzV1MLmeFZ
         QpcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uKQkn4nh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kqlRXzv7kJViMK+GbkZwTR8A2MPs0DMi0NrUf0tOEks=;
        b=mHswQtNMLrBuRwRsPJSKYMlry4yx1XFpBWNHIhFmFwquH3dh3iQ2fWXM20bVRX3lF9
         +Ca6XXPDNkRvPl0AzTPIPtv4fab2zk3zaEKZj7OOm1Q++X1bIInfi1p5h2Td0Jjd9PED
         3RJtUqKp3Nv0B0mdcVq9bIxCvG9r+VibDqu6Gbxok56UuGZWFxHy6f3WCaht/K7EeCeu
         /BPcEZ6kfABDB1ofdggAeQ3RL7d1WKUbCskMBOTte5SwOmQtlhDvWC8Qm01+3+cLtsfT
         OssmoMEbPipYzyVKmn36CYEFbpH5At9ax+S3htuhjU55u8teUiqQgKw5xJDGy+/BlB31
         GNHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kqlRXzv7kJViMK+GbkZwTR8A2MPs0DMi0NrUf0tOEks=;
        b=XyBkvd33n/mcxtPVzYrvnrVZYIhbV/QbkGmL+1lLX3C/brLepGwMUZj7hTYarvh5Yw
         0cVtsbwnd/W4mKHnDEmd8bC1Dn5K34+682QgPNbss4meztM9MgCM2CBvyG6dEf/rIneC
         sgytsimT9cps2oYkGLDktU6tmMcN6l2AMSOD7ILHWFx4ljTGJXxa7ybv7bgO3NmLppma
         LEuDVT5za1FVLnx2NypIA/8xr92vM6MLiKhxpqhiMoDDtWZn4Y1UQXqw74w8s7MHDl6U
         9NrUZON4+zlOLGbH3roZwf15SIrAD8Rp4ejVOP+uIevEV6K89+p/i7xz3adCPS60AaDV
         y2xg==
X-Gm-Message-State: APjAAAU1Hj19/zHDKPnE9xiZBjqV42kA1690Cj36dYGymr5uD8mRgiqW
	CMkubMCVwwdnWpobG1yawx0=
X-Google-Smtp-Source: APXvYqz4x+7ju9P9v/QE4xlRketTtSt04TgpKtmM4UlU1yXMkae1Z02k210RBO5KOICCF97XF/V1KQ==
X-Received: by 2002:a0d:df10:: with SMTP id i16mr36220574ywe.478.1579532336994;
        Mon, 20 Jan 2020 06:58:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7184:: with SMTP id m126ls2029824ybc.12.gmail; Mon, 20
 Jan 2020 06:58:56 -0800 (PST)
X-Received: by 2002:a25:8510:: with SMTP id w16mr118006ybk.406.1579532336678;
        Mon, 20 Jan 2020 06:58:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579532336; cv=none;
        d=google.com; s=arc-20160816;
        b=j5StiUD/AEss1PJO3dQPdf6Uyu0WHsWcnE1igbHpoCukrMfpxWc8eVd7I3yNzVutLG
         xVW8az1mIom8+YJO0pdBPxZphWH3Lt0T+gNxBGqJrjNvJfESeRzpjUwIdkDkVk2SLGRk
         dEz9THCMgYZW+NXV3DWiFZj7BTzsPt7oir+nGeBL2T7uLFWMnKpA6/tINni+t5Zpmt7v
         2Z2n1MJEianXRqpeI6TY0oBOPhv7ryWvCaP5T7guAgdi05mc77/1HajFz4+/nNRUR7uV
         BTmVpiW6h8KoC4sqol6brZZoEAa3J/s1mk/ahuDeRTXoCicvYq4yGAvUyfZ1wKUFiDIV
         chig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eRQ0+UJNHKW1NOT+X9Ptz3p1mfuoK3ob/c2NaAESbjw=;
        b=ofDNEWZkx9Arz/ym9chIS5VHJ5idkgbpDPM5/Cf2G2GA1aXSH5+b9SSQmMxdn0BWxR
         E0zJwzvqUGGhu6OCPRQXZUESu5/zWfKev9/vsZE8PlGMmGBtU5u/Pv14R0e9gVdByE+O
         mniQdQBnB2Crq6lggq+4ZcGKFL/68ajW6aYIqBsp6eYKJQNGkCCDJda0OrSmiqNbCeKv
         PR9vwS9we9CGRYu70bV3SGI9/8TTsh8VXnyvXv7c/Orq0dt9ANFbghHlmQDsrax1j36Z
         wC1Uxo2/cy6J6zIlDUwsff/mSJ4kfwpN48ukthJzOwazWA5xuK9FgiTZ9kixslnearVW
         gSfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uKQkn4nh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id p187si1516194ywe.1.2020.01.20.06.58.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:58:56 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id r14so30294528qke.13
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:58:56 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr52465723qkk.8.1579532336048;
 Mon, 20 Jan 2020 06:58:56 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
In-Reply-To: <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 15:58:45 +0100
Message-ID: <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uKQkn4nh;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Jan 20, 2020 at 3:45 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
> >
> > This adds instrumented.h, which provides generic wrappers for memory
> > access instrumentation that the compiler cannot emit for various
> > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > future this will also include KMSAN instrumentation.
> >
> > Note that, copy_{to,from}_user require special instrumentation,
> > providing hooks before and after the access, since we may need to know
> > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > also relevant in future for KMSAN).
> >
> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> >  1 file changed, 153 insertions(+)
> >  create mode 100644 include/linux/instrumented.h
> >
> > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > new file mode 100644
> > index 000000000000..9f83c8520223
> > --- /dev/null
> > +++ b/include/linux/instrumented.h
> > @@ -0,0 +1,153 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +/*
> > + * This header provides generic wrappers for memory access instrumentation that
> > + * the compiler cannot emit for: KASAN, KCSAN.
> > + */
> > +#ifndef _LINUX_INSTRUMENTED_H
> > +#define _LINUX_INSTRUMENTED_H
> > +
> > +#include <linux/compiler.h>
> > +#include <linux/kasan-checks.h>
> > +#include <linux/kcsan-checks.h>
> > +#include <linux/types.h>
> > +
> > +/**
> > + * instrument_read - instrument regular read access
> > + *
> > + * Instrument a regular read access. The instrumentation should be inserted
> > + * before the actual read happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
>
> Based on offline discussion, that's what we add for KMSAN:
>
> > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_read(v, size);
> > +       kcsan_check_read(v, size);
>
> KMSAN: nothing

KMSAN also has instrumentation in
copy_to_user_page/copy_from_user_page. Do we need to do anything for
KASAN/KCSAN for these functions?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA%40mail.gmail.com.
