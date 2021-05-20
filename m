Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXWS6CQMGQEWC4R24I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA27C389D72
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 08:01:19 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id bc3-20020ad456830000b02901f47dbd7ef6sf2426990qvb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 23:01:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621490478; cv=pass;
        d=google.com; s=arc-20160816;
        b=t3kmu59KLK7bR/b1TbhdUP8nCJ+apyIhY9d7cSrbGmdE8SG3rK9HxqHI6bjMdrWkEF
         faz8UM0Q1iCfswIyn1CRepdh1fc1snpsrBvNPiYl/q8BSJ4I1uQOH+JjolvBeSfvwhn+
         ELF94cfUQN6qvkS6xOTaT/V/bf0Eo66kQCwuX3/lMHcRpT1QSOeMTDoS6eAh1uxpK7Zz
         04vJ2tbiBinBKT618VnziOjSM4dP4ipHNzitXcDqKgP0qQd8Y/wY4mPJDvUAI0N0JRpG
         Bzhb3FynUrh7t46M17wl6D4WT10/szrTozy48+N4EnHw7O9Qzb5qJXCcfEX5xyQNhWWg
         +meg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=L8Fq2KN/lxxEzNnnio2QMrN0I+ItXLl4DYlCTLVnu4w=;
        b=jDftR7IlVkSXvvF3gXi/usF0Ayi3725hPrMt5elWjGUFT9nd0mNslVTadfJQKCrawZ
         I7U9qEHsdyko/Q4C4KZzThXCZwtn148Cn2Asx6lDO6ZXxnjfAh4MS8A4eATpHCovCFxP
         yDEtXSDw+NYB4cDgyyCZaTyJgsvI9kc0NuiJXxlPKAnHuFhMgThpuqDZDJBl5eJoANf/
         Ijd6l6XoX3uUBxwxNX8qcrc1jiLYygzKl4tukHLghkIGMmxCFosWHzOFvawItaXM4kgB
         8DJLa+s8+RzeymijZcc1cKdFx4++J/7Hvbl4wAN2czBZHt+bK9+HWE+SfqRZwDM23HrD
         ssuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IluN2ERP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=L8Fq2KN/lxxEzNnnio2QMrN0I+ItXLl4DYlCTLVnu4w=;
        b=QlpXWXHtgMrHYFuzdLgS1rND+I+EtN+/KiUtiMSjj25fgQymu8XFhPVYF/jWObOsis
         PrEzwKxqSMepZAbJNL0tnjcjCqkBSZPaiOz9RjsZUqus5B8q86qfuNhLc/V6hGWFVi+w
         gG7JvfSyR6t49zF54OyN9OiSSxW9RkJYqSvicWbAJPoqhCBeiXsQ/bhHNs2RDOTrRpCz
         tNKWJ98EqT6nWqpdUKNXxcZRumRPI9oKD57NaXi0z6FJJ5MEg4qYuf4Jmp08elzNVNK4
         jO/cOQBonn6EvrLA8nPC5PEvNPQ4RHNtFvwJdhlU3Icq2enSHhVtDqd5OpPxaSFgrZhN
         7h+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L8Fq2KN/lxxEzNnnio2QMrN0I+ItXLl4DYlCTLVnu4w=;
        b=psfqZERxgraccE4FySRVV6eQ6Vhz0VLR0pNOiD9RS+JzwZ0V/vpovwLJMZ08HzH6P5
         ABkckWmffhRcebb/HZsQT+2PNeeEdbUAYvAWLN98EP9bUk2dI5ut97wPyZ/IAxY5P+5k
         ZqeQBtWVd2aVuI/w/siH/f6dvZ78gjS3vu3YR6tGScF3H/rZviRexxezlQpvYxIASzeO
         3u1eKCvIYYcj9fAWGpEAarOAIDqjfS0+Ia+CYACehYpoojx4ydn5ILPBccGHFdNNXChr
         feFUT7JVxAHVnD2jUTvdHbnqgfM7tYJENoEqtOJAvDZMxKrF34oIR5o1z2tbAnYTq027
         1a/Q==
X-Gm-Message-State: AOAM532Za7v97H7x/Virt3/HTxc0eU7fFLmTwEVkpKZ/p7mChIKZy6sV
	9oI0obIedu5Mmr/201OBmMU=
X-Google-Smtp-Source: ABdhPJzJ7nlaVA+xCnsGFzuzVvfo8ZWfNQXen0GcONTasalpQliwf87FEHyUdPsR1VD39cv6evfIAw==
X-Received: by 2002:a37:a4c6:: with SMTP id n189mr3245818qke.221.1621490478704;
        Wed, 19 May 2021 23:01:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:64c1:: with SMTP id y184ls1072787qkb.10.gmail; Wed, 19
 May 2021 23:01:18 -0700 (PDT)
X-Received: by 2002:a37:ef11:: with SMTP id j17mr1759815qkk.234.1621490478224;
        Wed, 19 May 2021 23:01:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621490478; cv=none;
        d=google.com; s=arc-20160816;
        b=ccMoIbhfOka3RpjwLRlLORsTFfcoGa4epnb76UHCTB4vB9HwbXxAymz1DFG2gRlRtw
         ZzynaNP9TKJuE6Ev3rcho20URg4gS6LB5fcGnt4d1Fz74BqXzIqamJD8b/vAL6zNMGwZ
         k4crtLbGkvL2++JVh8EOMk4KkjBdT6zEnu5ku4DuZSBr9zyycTyKr+IPJMv2EuneKYSR
         TMURdrM0+xSMFqzrgad7mA2TUGZSb/St9lfTkIpy+Y2O64pIS5PT0tJKrquV0AmQlbQM
         0YlB1TZRBCGIAsyb/ec91J7NnYHGBukduOwd2mD/2n8hY3LsykD8TUm72xtB066prn5q
         PhOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=fqOqf3vUyxHzuCYa4Y48AgRxNP9v/oddnAtwvz5ANJM=;
        b=khVzLEoNhziy2gLgRqdQywxDL8hKCbuDWTjLycRkjY+Ccx/gXlFqv1gXWA6BTvASl0
         JQ/Jwc71PUrPenKdR9MSC3lG8CuiOV1Ty7TD4R2JkB1xWY8C2VNzJQyY/TbyKLmd42J+
         5Jwaa+NB2Vg72olDLv0H3quDOPVYnhjW7UX7iPiz4kjns9TFU2bBoRstGl7x6ZxiZ64a
         HDV0BJw43B25tfBA/8XszNYh7+JmDz+//LuSIDgLj3bUr9l4M5RLXVhPe0EoB27454nD
         tR9reTLcKaGkL1u0zepRMcq/iMflcpTRT46/OiBFIbmtOVJEShhFv6ARAgLeKdaH5+Uc
         9NWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IluN2ERP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id p5si226039qkj.2.2021.05.19.23.01.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 May 2021 23:01:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id i23-20020a9d68d70000b02902dc19ed4c15so13935423oto.0
        for <kasan-dev@googlegroups.com>; Wed, 19 May 2021 23:01:18 -0700 (PDT)
X-Received: by 2002:a05:6830:349b:: with SMTP id c27mr2664013otu.251.1621490476935;
 Wed, 19 May 2021 23:01:16 -0700 (PDT)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 May 2021 08:00:00 +0200
Message-ID: <CANpmjNOHSRdZWYcGOZeURYUMuVoCJhrLgWaMLh6VpHahq+GFWw@mail.gmail.com>
Subject: Feedback on KFENCE
To: mkubecek@suse.cz, tiwai@suse.de
Cc: Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IluN2ERP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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

Hello, Michal, Takashi,

I found: https://github.com/openSUSE/kernel-source/commit/5d73dc73e62632289a04bfa6c6b60e2d3732c8ea
(via https://gitlab.freedesktop.org/drm/intel/-/issues/3450 which
mentions KFENCE was disabled).

In the interest of improving KFENCE based on feedback, we're wondering
if there's more to that story?

One thing we're aware of is an idle regression, for which a patch was
also added to stable (unfortunately the Cc: stable tag was missed, so
it was a bit late):
https://www.spinics.net/lists/stable-commits/msg198394.html
The full series is here:
https://lore.kernel.org/linux-mm/20210421105132.3965998-1-elver@google.com/

There's also the consideration to change the defaults. We've chosen
them to be reasonable defaults for a variety of use-cases, that
*should* deliver the promised ~zero overhead (if we see reports that's
not true, we should change the defaults!) but also allow testers in
small deployments to discover bugs. But depending on precise use-case,
there are better options.  For large-scale deployment we're currently
looking at 500 ms sample intervals.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHSRdZWYcGOZeURYUMuVoCJhrLgWaMLh6VpHahq%2BGFWw%40mail.gmail.com.
