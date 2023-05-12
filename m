Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4GP7GRAMGQE7QFMFNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AA50700CE8
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 18:23:14 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-52cb479e4d8sf4865945a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 09:23:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683908593; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKnslc+8YOQPlXj5m5BBq4UxdWC2uNzgAWKJlBWsyO4dP6pf4XVDTtPa/zq7vAD88N
         RCx3KU/Z+1ZvW3Q1iZr7ccWZDTqt9haoi7n+NzQli+TrlG5HF9lff5alD1Gtmq3J4VyL
         MbBMFSe0SkeWMx6h1Aanc/rajZTlzXurnN3d4t1TKIwqR/hGAwj9CYB4PIe5PPYeVKGa
         G/DReA14bx3Yq99CmiWo0mdGFiCvgf4Ih0z8mjqdzMMjB5KqYkco9HCNrZGhBHgq0OjW
         +/W/Tk7uolQZZUxRNlQ0ddRBdhTGad3LDqz4y5SwRbikQi2eR3FiqefaFUkn2dZahxmz
         tsRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=a6zIo6frDyH3OEnDb8RooSW9VRLbHOfoZ1VWjnw1KY8=;
        b=uFAqb6w27DwaMZuOm6IMgT6FXz/UDS3jB665+D2UFkvWlzz4JxmPhpk7jD2bGkgR7y
         TICXfH7EPvXPLYNflobGjBSAICCzaDd5jq0LettmDRZPU70Wh3K4uctMmKHRr7mCllgp
         u7x0TZzW8u9Qpc/MP49JAn0xBzj1y6T6Pvm37tIxgHaMcBqTtg5MQzQhD8ENbhIukoci
         WDb/aeBUvRhrO9hBf249doLbInOZczY/ltx1WApSXkotHGQ63b26EyGS65ehiG2t6Iky
         6u5BlrW/T0nLXr/lEZRZBpPAt5oo+6fsW4UTZRg7MKT+uSRnTuc8XCTaysfLo4dxqdVQ
         o5Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=d0YxE8gG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683908592; x=1686500592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a6zIo6frDyH3OEnDb8RooSW9VRLbHOfoZ1VWjnw1KY8=;
        b=YmbJOZk/jeEYK0iHP3JFyOLLEk/8WNk1KLg4jJAc7r3cY7faQL/2M2P46SH/frUVt+
         vLNami1mF9OTdnirC+76flJPO+HB6ny+8J6dAHJjiirahw/znUq139FXrKLlY7QOPgW4
         J3uy1ftlSAkq8XYnuUEumkwzkgcCGRSS3oYCfi0D6XUUjfeU0zFcDknzjaY1sdJqdjpk
         evKuKgEaSknh2Ldyt6w2G4h+ex1hC8fxeoOslrmUy+8bko2QzgsNaQG/mEdN+JSnu4q8
         5U+aNC5K0VJFrGK7EXyaAzJ/+uHqtvZMiQtJQpvAE/5Wr1jaNsvfPYsikCR1Jm5+LSMi
         qAAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683908593; x=1686500593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a6zIo6frDyH3OEnDb8RooSW9VRLbHOfoZ1VWjnw1KY8=;
        b=XPaFKg2N6H+FMXrD7eJEokJtmBB+241oNL/1pCFOhoXABEHxz9uqBEXLzQmzX/FD+1
         IOb8cLVjhUU62rKQF0Ll03Amqq/LqW/8qRos9P8+h0NqoEwBcD2AT4TOrrpo5VkVggly
         Rh2UYzQ2iq0xVFPSN/kEJbhe24XIJajiPymWENh0BqbO3nNxfL1hSu3EnzRW/2e+Nwgp
         LnXe7ULP2yZ6Z/S+0gL1vlSo3f0R3iQyZvemnMXJrIcjovB4+jGI8G2JndIVxO1P5og8
         Xd351TX07H2tXGvjgu/9KkoEuG6P/1aVtDkTJoE4SvErU5sUYXUF9/qGsnevJAb5w8QL
         wrAw==
X-Gm-Message-State: AC+VfDwDteVq2MNBX1SuCURkNCyZjUeqGUhBKJvUAuNdDlgP8gyEXCSL
	K+8xo4i8eGktw2hcA5vD238=
X-Google-Smtp-Source: ACHHUZ5jNywNzIFDdPCj+LY6+XXmyRauZT+/cHIZcI9HzC84o9YncVMGJvk0wJ1+RV0KyalP4QLNjw==
X-Received: by 2002:a63:2c92:0:b0:51b:500e:55d3 with SMTP id s140-20020a632c92000000b0051b500e55d3mr6945676pgs.6.1683908592796;
        Fri, 12 May 2023 09:23:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:df16:b0:23c:1f9b:df20 with SMTP id
 gp22-20020a17090adf1600b0023c1f9bdf20ls12392979pjb.1.-pod-control-gmail; Fri,
 12 May 2023 09:23:12 -0700 (PDT)
X-Received: by 2002:a17:90a:fa96:b0:24e:1093:c8c0 with SMTP id cu22-20020a17090afa9600b0024e1093c8c0mr24175302pjb.7.1683908591953;
        Fri, 12 May 2023 09:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683908591; cv=none;
        d=google.com; s=arc-20160816;
        b=EpNXeiKvdvCtwE5qdpVpKBbdN5XgpACdXO7o2sEly0yoQJPEsshsvcyQxt1gUPioL0
         pZ+cQIWpPi5na/0YedqnDXQ2S9l2O0EV9V54N52FLUFE/65ocLvscLNjkawKkKqHOef5
         TPCUz8cI3Hs0wkQ6FYFLGQBVNSeYiJ17VkiCrquQFfuzx2hZaxUC2FqRFyCv3nh4d4P4
         1UVrk2Ict29FIVuktsPhBH8l6wKe0H7Z6b/SmEGtuFSZTfbsFG8GNdZTVf03u2a+IWkb
         QKKVCLvahkhMMREdMhUvJ5cJ2rfCXO2DnaSt/F275nLWlBm1hB1TOHNuzAMHDm6bG3iA
         +r1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jYqg+LEPkZJcqO4f+OyWQdzbx/fRQEMeMqiumF1ATe4=;
        b=YeeRoOcMm24PxmjS3PChN9ea+Jr3WEfPPITktPsCfE/Sci45w0IxECnx3L5JRrfpfz
         Gml26/mj2uitOXuilEZCYHJEtp2GknOP1ph9quMiTnokvHNqySfqsfTnkzWPJApsExJv
         e+nx4UNQubDdxsW52+gVn3HcwjHwTe0A3EvFMvc39JPRc7R4w950duzHIv9kfgC4YE9d
         3XMdzlClr5tu9AmUcT4o89/YQvM6vDn1920o37UgQr33ldF8mw0XL6l25fIs76RVU98G
         co5/cb6dXytm+DKjiPi57FFYi/miLGDlFjfQYY0oUKlk7eEVxkGMI/XqsAiD0Y2vP70V
         HBQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=d0YxE8gG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id bk3-20020a17090b080300b0024de50e3455si1861937pjb.3.2023.05.12.09.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 09:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-763c3429a8cso266735539f.2
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 09:23:11 -0700 (PDT)
X-Received: by 2002:a6b:6513:0:b0:76c:76ea:3e8d with SMTP id
 z19-20020a6b6513000000b0076c76ea3e8dmr5441027iob.7.1683908591252; Fri, 12 May
 2023 09:23:11 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
In-Reply-To: <cover.1683892665.git.christophe.leroy@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 May 2023 18:22:32 +0200
Message-ID: <CANpmjNNLaA6TQnjwfhwd_=4o6S14vX5AAm4Az_bDaCb7zgNO_w@mail.gmail.com>
Subject: Re: [PATCH 0/3] Extend KCSAN to all powerpc
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Chris Zankel <chris@zankel.net>, 
	Max Filippov <jcmvbkbc@gmail.com>, linux-kernel@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	Rohan McLure <rmclure@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=d0YxE8gG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as
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

On Fri, 12 May 2023 at 17:31, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> This series enables KCSAN on all powerpc.
>
> To do this, a fix is required to KCSAN core.
>
> Once that fix is done, the stubs can also be removed from xtensa.
>
> It would be nice if patch 1 could go in v6.4 as a fix, then patches 2 and 3
> could be handled separately in each architecture in next cycle.
>
> Christophe Leroy (2):
>   kcsan: Don't expect 64 bits atomic builtins from 32 bits architectures
>   xtensa: Remove 64 bits atomic builtins stubs
>
> Rohan McLure (1):
>   powerpc/{32,book3e}: kcsan: Extend KCSAN Support

Acked-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNLaA6TQnjwfhwd_%3D4o6S14vX5AAm4Az_bDaCb7zgNO_w%40mail.gmail.com.
