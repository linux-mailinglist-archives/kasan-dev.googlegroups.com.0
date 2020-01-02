Return-Path: <kasan-dev+bncBD42DY67RYARB36DW3YAKGQERQJERWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A22812E386
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jan 2020 08:55:29 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id e128sf15080011ywc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2020 23:55:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577951728; cv=pass;
        d=google.com; s=arc-20160816;
        b=S1qNPLOfeUQ0aKeqz7mvDuyZ+WNObd/VRmGOGgHlYsyymvir350LxTLaU4q37wEi7w
         D2qhRNALyEtWNLvBbYzXziEL80uWsNdK999+jVXzSRF/jrbL2gqgT6Hb6caIDxdvS5i8
         WCBjnfVDweAu/1ooYuQkPcNz7KFS4I3rG4Q44uhLy2PBKfgNHkabc63dMKcTNDbh4wjy
         sfo+O6AjC1Bkab2i2mN2jFbMm1I+jrzvzcTkALLUUU9tsch7/+MuDMOTizpOS3XODqFy
         UmsL8PR7TMD9/UQo48P+33VhkTCo8IWprq+XVnRtnLdA7E9SlzcdryTomg/BNG3ExHBp
         ccUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=2DqIc7CekwdZY5qhi45XNfOfuGGJOZLJbLB1coFPXCQ=;
        b=hTReNIgUJMAB87DtUKkfaB7JAOHKq0CpuEDmJEfHwlNfauppwe1eLv8c7al3UK2xEX
         7x3NVAeYufoTvqKXHN77mQcSWXR5bWr5Es5ubKvRnM2e4nsoU2N8rUiJdDOLgu0JX2uv
         GZCoT9f1+njbTwJAOVtNM3m9NNWxeq8PybKRuhbpKbX6iyZeWFUg/BLdOaW86UAeBiof
         aYvZfJrtpRnEuQsJOmDv1ivxkd1HA0M7mQUGQY7MZys0HT6D+YUx5xBS6lePtgGQR3M8
         5xt4Oe2+cAJ8O7MOBy6hVYcTiJCaQlw/dWZKsQWvQ7snyjlflOfDMsbnHg9dJVLWKh+O
         EQMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=d85ZQ8Qf;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2DqIc7CekwdZY5qhi45XNfOfuGGJOZLJbLB1coFPXCQ=;
        b=ZhmXzR6ZPYY2vTHhXHH8L+1inBsge0+czNB2TISdDcSTXsIc8ooJya82HG/QWF+Xg0
         TadWRf0UhGylkIxAe0YqVyjUa7DqjsalNzQwsSscqw91RCH/RWh+7maKqGeEoPobFfXi
         NXU54ITMEp9RwYDmahzG25HMLkOuM3I2xMvphoSXN6Tm3TIqky+mjj+iEuUyp2C9XWmZ
         sot4amA6LL6EpdDRW+uP0G4f7Gk+uDdzRWAOznMlnQz0ti4v/ICsaGMcCqpHxIhmq3wH
         Du6M1k7xqLv12KXd7UC1wr9lUMDxC8rC0nQj+t/TobI+tnB1q8F4Fcqv/uMRcG2r35ZZ
         a8kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2DqIc7CekwdZY5qhi45XNfOfuGGJOZLJbLB1coFPXCQ=;
        b=cQFpJxTSLKUnA3JqhBd6JKFISis4qvTeOw635BurcexDkK7occcv4D9dhvgCu3JK/i
         c1TnNdYHtAF12Fxr74yr6xkBVjkvXRfJ6QfgzPp3r01K+4mhmqgIWDJ0/q9JMibb//Xq
         qt3rQGfmAKttvbbaDyM4jv7IbARhdpGiVCWy/n8viezonJja8IqSx5NipvBK2MD3a4oX
         KBIhs/1CdrdfzUhyVw3i89tEzZIeRWL2PCQW2DovoBXW8FLQ6ApsYpcy3NOBaprGSSJF
         iHmBqiWuQM9eyS5pg8V4D2nTu9Y89jMZh5pP1NfGIZ+85xhgfhLDrkdJyoIMbiFhHXct
         XHYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW8i67caJjYF3LUAUzPchAgNCTI//UGV4MqKtSHsPn72OQeoOZx
	7PIKcOV3mvLcppIhm9Ld2m4=
X-Google-Smtp-Source: APXvYqyTcIPHp2VF0UlCFbWKBDzYc/qb8LrSZC8sgTRQbdDem0zsUJPFlp9OJMc4Zzade2XOPnraaQ==
X-Received: by 2002:a25:6887:: with SMTP id d129mr58146760ybc.345.1577951727793;
        Wed, 01 Jan 2020 23:55:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:66c6:: with SMTP id a189ls5939830ywc.8.gmail; Wed, 01
 Jan 2020 23:55:27 -0800 (PST)
X-Received: by 2002:a81:f50:: with SMTP id 77mr63111539ywp.340.1577951727409;
        Wed, 01 Jan 2020 23:55:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577951727; cv=none;
        d=google.com; s=arc-20160816;
        b=NDgwPnLAt3PvQLOelzjlRpd/EYfU46SGz+D/dWwM9zrQn12uFL/1h+VNgzR0VI0a6O
         X8RtbSQjrdTQAY6EmxojUibxpvhcQkDOmwgtMj+7ePNzvPOPREiNf5+pi7bB5q/vmMW5
         CtgWLoJFHu0fBFmlCmEk2l+URF1lWtYTrVTKTkxtKbBtPCHu6x9WgUQmy4YwNr0riVj4
         LVS9B4IyDTRC48FdLzN0rEztwC6GUt5b7PBx1qMhdLBr4Acm+2IuVXnfZi+hKQUs+gIT
         HroLZYvDT74xEiMAPlJVuZCIiVCqT9fxRn+uzRsDJYhONMINHmDRFJFHfM+CgM/uHsSD
         7Hjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=sJ16jnOhr3QUr3TB0LIZMFGSCmwDcNlgrayZJgkHF8s=;
        b=EP09IaoDIB8lMgBRHUiHsfsR/7o00vY0VzStO7u41+wGXh4F2R+ZZwwbhVcI2yYOw/
         5NCknJe99StaE/jvG68F/50zFdN8tM4oq2roum0k+AKBflNNdhzdxM+W9N/ZSyjZu1X4
         uCTDeoZ7+9RddETf/MVUQNshmxmQ+Fxx8QfHVJJ+0m2OJK06la2Pb4KYMF5Am6ACqdFU
         woLNJa0isDkFs4/nzPcB5RENm1W+R2yUrQUrtnzx02PPvPO+QVEWVWgUWrNhE9hiIy5Y
         67LrRhcd2WFY1BwhA0nUnIWsrqPTjOAjcHWXGTfcm8l1iXooOeDcIOj0QagFp+8ivyEK
         PsIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=d85ZQ8Qf;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id s64si2300111ywf.0.2020.01.01.23.55.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jan 2020 23:55:27 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id p9so17536021plk.9
        for <kasan-dev@googlegroups.com>; Wed, 01 Jan 2020 23:55:27 -0800 (PST)
X-Received: by 2002:a17:90a:8a98:: with SMTP id x24mr18878530pjn.113.1577951726559;
        Wed, 01 Jan 2020 23:55:26 -0800 (PST)
Received: from [10.145.97.154] ([203.129.124.82])
        by smtp.gmail.com with ESMTPSA id j14sm57009728pgs.57.2020.01.01.23.55.25
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jan 2020 23:55:25 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Andy Lutomirski <luto@amacapital.net>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v7 1/4] x86/insn-eval: Add support for 64-bit kernel mode
Date: Thu, 2 Jan 2020 16:55:22 +0900
Message-Id: <498AAA9C-4779-4557-BBF5-A05C55563204@amacapital.net>
References: <20200102074705.n6cnvxrcojhlxqr5@box.shutemov.name>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 "H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>,
 Sean Christopherson <sean.j.christopherson@intel.com>
In-Reply-To: <20200102074705.n6cnvxrcojhlxqr5@box.shutemov.name>
To: "Kirill A. Shutemov" <kirill@shutemov.name>
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=d85ZQ8Qf;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=luto@amacapital.net
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



> On Jan 2, 2020, at 4:47 PM, Kirill A. Shutemov <kirill@shutemov.name> wro=
te:
>=20
> =EF=BB=BFOn Thu, Dec 19, 2019 at 12:11:47AM +0100, Jann Horn wrote:
>> To support evaluating 64-bit kernel mode instructions:
>>=20
>> Replace existing checks for user_64bit_mode() with a new helper that
>> checks whether code is being executed in either 64-bit kernel mode or
>> 64-bit user mode.
>>=20
>> Select the GS base depending on whether the instruction is being
>> evaluated in kernel mode.
>>=20
>> Signed-off-by: Jann Horn <jannh@google.com>
>=20
> In most cases you have struct insn around (or can easily pass it down to
> the place). Why not use insn->x86_64?
>=20
>=20

What populates that?

FWIW, this code is a bit buggy: it gets EFI mixed mode wrong. I=E2=80=99m n=
ot entirely sure we care.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/498AAA9C-4779-4557-BBF5-A05C55563204%40amacapital.net.
