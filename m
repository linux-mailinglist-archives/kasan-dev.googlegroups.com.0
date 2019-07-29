Return-Path: <kasan-dev+bncBDEPT3NHSUCBBZG37HUQKGQEAXQUCOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id C83B0783BD
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 05:54:13 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id n185sf26084567vkf.14
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2019 20:54:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564372452; cv=pass;
        d=google.com; s=arc-20160816;
        b=hpa+tm+VJwkP0MrHPrgDo2mEBIshMvxcRLSsM7+kk7yo1HGmKnJL3KmgkatFyU+2cq
         eEBAyAW+RhcU2JvSQACHpaU+OHpwSb3IM7xHD6RUnBeHvZzqvVWVz24cLi0iHJVZkn4a
         GTRxzrllvENJXq9m5ltihjqUbDLAKdaeNfsE8grYdptBBM7vOV9zIDjtPi7y0e+mUMYo
         2CzrJ9agbaNeeMFAms1BuWgzNdqzjA682Leq1P82BnpjObnZm+/78o8Vi0MiEYx326lY
         YWU2rmXxnLabmCYcQapcLDmuNRGwZZKO24MzXn8wRhACf/nKBA9nEoI4iv+AFXWp8nHG
         WeeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=soAazvNUHuq2OE2+U/SaumAOUdorIaIYHNGGBfOWGW0=;
        b=qmgM9x+2MxeuKbKO0fdaNNqi0ia/BwG8m9bPc9u7/97cCc3j8Da5FR89tj4iQficEl
         a492Rgs1yepP0ryVtVjYP/5B5qG9wpbJ9uwm5o4azfH/Y+mieZrgEFXuO4MZP49VhbEd
         M3HWALuMTcfEotQdD5ijzx+gxOi9vDPYDadkX7SDgsePWc2cuxhuWnRffbnqto/erdQQ
         dQWKGnM06+b8XByJO4Uqj39C0FfCYrPj830yCbEcR5w7VcJDdTDG82NeXpgwyeTogbLq
         OXP9G1mLjCr1e4zxWHspgFxe+o1EsEss8H3w+zqz0xqKJJhyFwKluAqAyum3eaefSb93
         1H2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LjpAREuK;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=soAazvNUHuq2OE2+U/SaumAOUdorIaIYHNGGBfOWGW0=;
        b=tX4v/AYf14Gx9XzHdiY+UrP61eimEdmFgfVQeRsShi4crDvr6mjpd/B8ocpdBCt76r
         2q8jjsqHKTPkfm6zu9hE11X2vYgzRfEF2PWrFQ149wX0LzdqeLQ8AwtkorBfNiCo8NDj
         keFmf7d07Ywf9Y9axw72KIBXlYI2TtKlYex+Rfhg5/kV7o6KXPxHGdQE1nIk03HXqCBV
         aDVDTccJpjppdAoUXIdOOoIGCA3aipntEyWBQ0G7nM2BWkSu2OLlWjN8t9/PUK5C1bv/
         M51DtSTpDGr961yd7TuX3cCF1+ldt3s3SwFb5X1Wrk0cfoQHVDt4oN0yrooS7ucRWiTP
         q+GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=soAazvNUHuq2OE2+U/SaumAOUdorIaIYHNGGBfOWGW0=;
        b=aqHmwpay5HGt5EcbrtbVTI3mRDK87B1gY7OgQyesk8AgWOGbF/vgRn9yPLliXCUm/D
         E1DNd/L/4fZ8p1qO8rUu07WD4whpsUkL0ai0aX4aZDjFf9s9cKT0+umqeFhTLRqK6Yig
         NPZT9F4j4VpqFi9lKlODkAJmeyGEiLPh3c3Lo8zzK/SY1tW3JHh3QmAlv4CLvz832cZi
         7+PdQoNLV1jko7J8vZB1p/EIGl5EizDNM636Kj+k5aCbIMlhkCgeedwBuOJv9fuMUx52
         wgjVclaEC0hKML8dChYDmP4TAEehXslfGSkWMerjgy5VuHwj626cHbKw60UszfJcDDI6
         Z0pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUerTFxQ/RWC6yIoX6YGWRzJKKLJtHxvwgyOkmWmzE53X0F0TC8
	18fXx8VGtwMXhuTPMnNpxaw=
X-Google-Smtp-Source: APXvYqymP13lQdwSBBjV2/FZlPEm/tue4NPGAO2+5gCZ0PBZfUOP3f4f50eSIvlQM1z0fild9DkwUw==
X-Received: by 2002:a67:fd13:: with SMTP id f19mr65663677vsr.25.1564372452714;
        Sun, 28 Jul 2019 20:54:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8cc8:: with SMTP id o191ls7545815vsd.15.gmail; Sun, 28
 Jul 2019 20:54:12 -0700 (PDT)
X-Received: by 2002:a05:6102:db:: with SMTP id u27mr68027051vsp.83.1564372452466;
        Sun, 28 Jul 2019 20:54:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564372452; cv=none;
        d=google.com; s=arc-20160816;
        b=fqcepQDgW0e7MPvk02QpF2qCAyWH7kS/OIjCPq42LWwzxjgCrWqFBhU7V2U+MjRnhh
         m48DU2CdoruLx6vAE5QmfIVJzykO2JBv3wWj8v2IE4zhIFu9rDOGd1YA6kjC0N2UDgA6
         F28L21q78c/7kE4snMniBtJoIaKnC+m78WvybPCQ/WRnbFshFPfjwbkIVwSsRpyquJYJ
         HuTuCFbYPmlj+oopNb6L4hCri3jtQ/43myXXO4gT0khThn4VA/f0Mx8Fdz6O79mt9FOp
         MBTq1vXy4DP4/RrR0RSdG7mke/sICULQmawqAJJhE7Rr8kOymSQKl+f9W0Gwj3uVOab3
         HAbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hTyFj3mJs7wqbIkui3my2WNAjVvxWJhnTzKzmJol7Bg=;
        b=N/blCQZhezmRX5IE3G9TUhyA/VLYJAbJw4+riHWq9ZCRc9yfxTKTeSiLkRVRTrhwGQ
         Ik3/yxkgtAv/h/vY9/F63c1B1tjDGsOTSNwN0veL9QBbxFdo/5/IxYa17Z9xhx/0Gaas
         AsgZQNkNZ66hBv2BAL5d22HWIlJYvjOFRWAAcSssVEZIZJkZuZynX5NG/H1jXm4x//xS
         yEBQJIZtnMC/XbGZPHbcJ3yqasmf6F8z8IPZGSjfphMaRGjsCYVW4vsqwEIrpbydSjhv
         eDK7//Wbo+VTa8qAoLp3lDy8HlQHTU+rRIbftkLzGbIrmFjrFfCc+5MJwFmR9zQMI3UC
         RjdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LjpAREuK;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 63si3092196vkn.0.2019.07.28.20.54.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 28 Jul 2019 20:54:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f46.google.com (mail-wr1-f46.google.com [209.85.221.46])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5B0352147A
	for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2019 03:54:11 +0000 (UTC)
Received: by mail-wr1-f46.google.com with SMTP id x1so10233140wrr.9
        for <kasan-dev@googlegroups.com>; Sun, 28 Jul 2019 20:54:11 -0700 (PDT)
X-Received: by 2002:adf:f28a:: with SMTP id k10mr39238424wro.343.1564372449880;
 Sun, 28 Jul 2019 20:54:09 -0700 (PDT)
MIME-Version: 1.0
References: <20190729015933.18049-1-dja@axtens.net>
In-Reply-To: <20190729015933.18049-1-dja@axtens.net>
From: Andy Lutomirski <luto@kernel.org>
Date: Sun, 28 Jul 2019 20:53:58 -0700
X-Gmail-Original-Message-ID: <CALCETrX_+_zT8iKp9QMpaN0+NPS9_rmhZvPgG=ejN-5KkBbfdQ@mail.gmail.com>
Message-ID: <CALCETrX_+_zT8iKp9QMpaN0+NPS9_rmhZvPgG=ejN-5KkBbfdQ@mail.gmail.com>
Subject: Re: [PATCH] x86: panic when a kernel stack overflow is detected
To: Daniel Axtens <dja@axtens.net>, Peter Zijlstra <peterz@infradead.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=LjpAREuK;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Sun, Jul 28, 2019 at 6:59 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Currently, when a kernel stack overflow is detected via VMAP_STACK,
> the task is killed with die().
>
> This isn't safe, because we don't know how that process has affected
> kernel state. In particular, we don't know what locks have been taken.
> For example, we can hit a case with lkdtm where a thread takes a
> stack overflow in printk() after taking the logbuf_lock. In that case,
> we deadlock when the kernel next does a printk.
>
> Do not attempt to kill the process when a kernel stack overflow is
> detected. The system state is unknown, the only safe thing to do is
> panic(). (panic() also prints without taking locks so a useful debug
> splat is printed even when logbuf_lock is held.)

The thing I don't like about this is that it reduces the chance that
we successfully log anything to disk.

PeterZ, do you have any useful input here?  I wonder if we could do
something like printk_oh_crap() that is just printk() except that it
panics if it fails to return after a few seconds.

--Andy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCETrX_%2B_zT8iKp9QMpaN0%2BNPS9_rmhZvPgG%3DejN-5KkBbfdQ%40mail.gmail.com.
