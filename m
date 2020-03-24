Return-Path: <kasan-dev+bncBCA2BG6MWAHBBFE35HZQKGQEMZ4MIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 16C201918A7
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 19:12:37 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id z19sf16994714ils.20
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 11:12:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585073556; cv=pass;
        d=google.com; s=arc-20160816;
        b=icY/q0MDWizPVH2kRIu0OAAkE/irV9cunuxG/QVbfc5r0GDu/nSijWbS2F62f3kLxa
         dWDDgsmg3Xsm9POaj3nFhauWz3S8b5chaeTIuhYQrDgLhjU9kQMshcWey4ae2gt8XGo+
         TKwfoYijf9nowEixZXWoP21VlPZ83R1eFgwhelzeNVk4RcJVHH9GVoR/xVgpjmNzIyNh
         QrOT573bUHV/CmHwTyviFbHL+iOnmygm3SfmGT1E1PaHLF8LaMAg1grBgI7kj1rBD3vj
         X4ffSfKBYtfDJ83bh4A6KGRS+hbo1BeXB96VUOeTtK+7k2yi9s9kQAV8t6Q7t6rU4tWj
         CP1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VVUUQjwKhqRIghZmo0VkHIfGpKKbsBW5b1v6c9yqvtE=;
        b=X1LjiASIvoVvSw7hPMIL4OYMKK9TBI5xOYy+uszs8zs+jPjO3Uh5+YtWlSLPUaNhe0
         B13vycsGURVjYdb4GY+eo/ZpOhc50ssn9U4JInwzSM2adnOe/Aljqg73bUznC42dKQLO
         8i7bzGZSkfZc+pEutZgOhuQKsUksS1ZRrZ7/ReI1q7mJ+rS0N3AVHdiEA7SHwTnvDKDi
         FQ5bXqQtMxNSFV2vCH+050gmysLglA4IuJaPX5USdX9GtaNqtHSmGolpbtbTKdSNW8HT
         Swtp1JHTG1+oo49EvFJdsffc5mDn1Hauu+D+gjhDDg9RaJamVTJMpY+jPzQSZ0P2yIE5
         k+ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vCq7M3Tc;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVUUQjwKhqRIghZmo0VkHIfGpKKbsBW5b1v6c9yqvtE=;
        b=rYVnGOcdUzZVn8AP92H5VPaCMKOjg8Hcv03SuPrHommQJMm88eQilzlhLLTz44HGnX
         iKS1GfYXf8M4W8U0G+LmWdJvFj/jl5EtnKAavpmun7du1kXCOGoA6kY8W8V1/RHf044q
         suXers1FhYzEuG2Ql1w0xxkrxmNV4uo/bzyRqcOuikYNeUOkGPDquOfwP5VdtsPtNr2P
         o6a4Fbp6eHreFNoYp7XB0Pt9VfAHyTCzPqKcqeo3ljCcw9c3n9PpiKquqHRfBpaF+ksS
         XvENF9/KWawS4vbjBD3Wlq0ds1NlYcJo9K0aEavaPBAzqjy/aFEb04e3tFvfFAf7tNA3
         dZ+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVUUQjwKhqRIghZmo0VkHIfGpKKbsBW5b1v6c9yqvtE=;
        b=eBVREwuOe5zNu+0DwWgGCbp5XR0LLDFW2FT+B3J7am0Yi5cGF+Q5CUUjp5ycnTUPjJ
         FXFHynfMsc3eY2kJwfC/ccWRNVD1o2EW9l5YmOahVL4HeVFNPI0cuLgO1K9pQE6WhXqG
         LJ2rR5lsMIJvHUQDWX6SHpX8SVFjTSDmnGRXu6qCjpD0ksKRkXO3OZDJoqW1NKh7euKt
         TFUCm66rL+iA6Lpj/ISbwWcOw7s7VwqdsAbtc31wZNn3wWwOlKZxWaGMSaaxev2xoNCZ
         tV0iAWnENxjMT1AYrS39+FS6O1l1pkUMAJGn3OA5hNvQfjwdJ3YA6hLZULpXDVBwuzE7
         /C8g==
X-Gm-Message-State: ANhLgQ0CHZakZXLGyklpIG+akOiCTVO3toMHE1C17s4LAqNOsguCsDcH
	ZkWtJjM2coARVkRK6yP8u8Y=
X-Google-Smtp-Source: ADFU+vvbgKODpa70V4CGUxC0hAn+HFmCDYGnA6vG75IpjvFmAkiHkcE8vr+amYqBcTj3XBCDs5E0Cg==
X-Received: by 2002:a92:c790:: with SMTP id c16mr5150149ilk.206.1585073556076;
        Tue, 24 Mar 2020 11:12:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:770b:: with SMTP id g11ls2372412jac.5.gmail; Tue, 24 Mar
 2020 11:12:35 -0700 (PDT)
X-Received: by 2002:a02:998f:: with SMTP id a15mr10002892jal.24.1585073555728;
        Tue, 24 Mar 2020 11:12:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585073555; cv=none;
        d=google.com; s=arc-20160816;
        b=b3JEMhVJdmkLqZMBCTHkGiupdeH1VjAn77jZvUaYx5e6KHhKsL2yXUy7sroEr4I5tx
         vJ7+k5S5TqHViuPTiBdtjbD1xk9elG4J6iHCAfbc5pNIA5CT3YOerg+c1qC3h0NHfpwI
         KCnXv8UNFISvFLs6IvPZecGo/SUntl5IxewroXHU8uGJK4Ob3XgmBEa/tTY4qHIaTPlt
         uyPIhnOCemhdnb9EZn5uk5Mepfjps8DiJI2rP5SJZ7PfnSbrp8BLRVOd4uSIaqH/MlUm
         IX8uNLOiAyv9AicqdFLAyu3WhFGI28efAt8NK/mT3mwCXH8+WSaNTb9f7i09JoGaVl/L
         hTGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/d+L7ssZFGD9dUL+ow/dGUzskuUeNpi5SPqcS5kNRuo=;
        b=ZAvJwrPjAqCq8djkkBpY1JAE6IzEhzCzahsHHLxDB8B9DlzQtctBjWrpgtOijZCjrA
         gcsJ3D2i0sknZZqdqO4JG2ervYkNjNSK58ngCt5cRAAiDFMP5zbONIa7P64dPoqIBPwz
         HUm4fdTt5fVcUeUQHu9w0ki3R2hw0rEU7lk9kqUItPiPj9bfmoMKS0baLVY9bMGiSjpF
         hsnCS9OzaBZKbzi5pvGRVZJJMsY0QZhgn54BNUOFS24iq+whr7ECfi75sB5OgWTIveaR
         bJ0KRmBEC4hOl4/+6+qIKrRWq2+hzn/k9ZJUfxg0CW0xTq+cTJ3qxjbbgjLyQey0zf6S
         iMRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vCq7M3Tc;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id a3si1504827iog.2.2020.03.24.11.12.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 11:12:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id 22so6105486pfa.9
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 11:12:35 -0700 (PDT)
X-Received: by 2002:a63:ff59:: with SMTP id s25mr12612787pgk.159.1585073554861;
 Tue, 24 Mar 2020 11:12:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com> <20200319164227.87419-2-trishalfonso@google.com>
In-Reply-To: <20200319164227.87419-2-trishalfonso@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 11:12:23 -0700
Message-ID: <CAFd5g44XDamNNib1=a2Zxm7R3WUbbAF4u0jiWZoYMSQbPKKOyw@mail.gmail.com>
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vCq7M3Tc;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Thu, Mar 19, 2020 at 9:42 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> In order to integrate debugging tools like KASAN into the KUnit
> framework, add KUnit struct to the current task to keep track of the
> current KUnit test.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44XDamNNib1%3Da2Zxm7R3WUbbAF4u0jiWZoYMSQbPKKOyw%40mail.gmail.com.
