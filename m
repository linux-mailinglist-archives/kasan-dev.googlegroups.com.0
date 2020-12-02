Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKW5T37AKGQES3IBJ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 867862CC06C
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 16:11:39 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id g3sf556132vso.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 07:11:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606921898; cv=pass;
        d=google.com; s=arc-20160816;
        b=b+3TaEw+RD6MfTdB0Oxlifc2PhbH2zYf+RtzpeuwiDFQJV4XxyzBqlXzbm6Omn8ak4
         RRScI0Ub4QlFbzmbD+S31WPUaEoy4+pI7xMjnoTKMWmJviLjziM7H45X8xeWYcr3ljxC
         9CfQwZ8VNRwQG0sdTsXKBGDho+dR3gSsn+aa9fYGDXrgJITu9a10v4tm+j3GmARi0HMR
         SnrpIEjonVxdKgJI5x86R+bpAG718YcYLohphrwaj8lQMrsZxlZLSjBwAlKACYNO3f+W
         9m4u69I3KQOVXZFwvBeRrL31jPly2tYx7aACRyjZAhP/zLwW1j+D4creMESXMmP6Hk2M
         9uuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JSGkZhtYy6ahMz4UPMZWT2eJafN7lybkAe2x7DP0j1I=;
        b=VgKHk1DIT3Fln62Ud8f25S8yve8aXs5sSpOMo2r7iVUSE4J/QZvm8noPHYThei8/7F
         lSEwg8O1/ZsGArC5TyTuSsdlliXZ8SAM7RotwONf9337bY6i+0cKzXr2L75MeDiCc9dW
         Q/cnlsbi/PYNyOE1crZbxbe+OnIqG1QdclrRMTg4//+UgEx9OKpgrZ/d5eXUljC4CfRB
         SRdfyokCzpqET3K6/9i7RrXnS6dAg3ElylMMvLv0Rnc0SdRQTz5zkAT16PmC7UUe9Oo+
         ADaD2gJoCe+98geqE9mTtqlHrtZtSUjXgnk9uqeVtptfuySzp5DxEGxt1AA2of5qrElu
         3/4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KQx3tJgz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JSGkZhtYy6ahMz4UPMZWT2eJafN7lybkAe2x7DP0j1I=;
        b=U+ik/3eOam7C9nx3W9qaErCJgSU4WR6vcNcCRwCSs1AJL6yUPEh5JmEu4EruLe2GB/
         Bq0BJwUqryRNSkmUjUia6/0NWvP7xldHAwfCK8lSoEEu7/Ti3afHUSZWFOhexTxnhqbf
         EU2i6hjV54pvbViy+vlN6AedLA1zTMUXTm9ji2JWdzSek51GtwNHJNmzpzqEW44y2cfd
         O5b2+1Zo2ifAvkC5AFXFgaFqjB0ltgcx/LFQw44QgVcOl3wO48TUTdSBI4kfa2FrKIYA
         spv6AMWSjCes3llUoMJqROJqqiEv3vuJSz/3/eYziaZDqfJk9r3UeX82w30KQaTVkfo1
         Sy6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JSGkZhtYy6ahMz4UPMZWT2eJafN7lybkAe2x7DP0j1I=;
        b=EkpwoGogJSMzBnkYyiznuWPn05xpnBcd58EE7Nk5KIKYwt9Ol+xksjIvJRcwaHw6Tq
         WVJMjScO4VPnyzNIkpUVzXNzPlPBGznnN/C0zOkeV+1RbiCMHgxKXcjKR1Hgz5g10IlE
         G33vSMLoGb2o0SEXAuYFax1JpFTjxJdo0HZf98pkfIVLlF9BCXRmijapYZcUau/zxkZ4
         wH49fu0XpIxlazevsc6a2Y7NGgJVO6/v1daoODJqG1O4gMuh0BtzU6DGXePkmV5kmIN5
         +9vnoz4r+AveKU0HkrrKDqlKiHU05lUxxUexUstqyQhbGwh6uNCk3aUVj46sxUUsszH2
         BQzA==
X-Gm-Message-State: AOAM531DNjE+nweM9ptKhKq64fRFQVXluDrMpOxNRmo5Fafu2IsJbrdO
	edK54DGnmiurmzrSyZZ8f40=
X-Google-Smtp-Source: ABdhPJxYanYtTRWn9A8zX1WxKobpwXfMqh6t5cuOxXiGL3oFl1fZa7yWdBuSY0/eVqxolC7IyEqmZQ==
X-Received: by 2002:ab0:4d66:: with SMTP id k38mr1807283uag.61.1606921898452;
        Wed, 02 Dec 2020 07:11:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c9b2:: with SMTP id f18ls118227vkm.9.gmail; Wed, 02 Dec
 2020 07:11:38 -0800 (PST)
X-Received: by 2002:ac5:c88a:: with SMTP id n10mr1896131vkl.16.1606921897940;
        Wed, 02 Dec 2020 07:11:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606921897; cv=none;
        d=google.com; s=arc-20160816;
        b=Hs7ilUR6/ce1teponc7vRKZCglEqqa0jFJeTap/B6hAmA34Kqvr/r3Yx2zNjOlYEgf
         XlNAajcW5lV1/ndRTBGE1AkfccHzx6B6S9nroSGT2cS/F9FGCO9XYVL+9Av4lkzcs5LW
         6kVy8h2M4ETRkOj713UToIj3rtj+4uGFrzJNFF10vsBeiLqnZAsH7dJJOii+vLumomqh
         51YSuVtDS1jznpCG0aswMjU5Jadme8sfim/ZmklWuXz7LQof+G2A0L0H7tY5r7lCZxET
         okYBqO7O8xaRQrIycNYdpLu0/5daTiWC6SRJ1s81o534SDUDAXYVq9jNMJ+b1sL+C1TL
         F57Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2HsmIMcZJpe7tYpMj4NnnC0QPe3wNYiaDnh9WVgHhJ4=;
        b=vV4jvtJIL+XJsoACWAm2lCoCuBQRJrhGoEgeEnLJfqG66kcqvfXUGEkPBJqoUWl5n9
         6qHatTMU0UwhnpDM27B2cvIeM+qPqTYibVb4mRnRKGwmsENk9rLpDfy8xjKMnH1Np+z6
         18a7x6CKXTMOiS3L1uNsDfk9xudtPES1BEAGx8qjACRINcX5mwRZMuP3bodQUp1WiPV9
         7noFUnkXp15KHAKDEvsd5ETAz8hXu7rqQiQMOV3uTpVfVBC1WNfX7kzC9uH0ofEZNRKC
         APuZSCOKMCa8OR8XStCdEnwVtkB9jAlmxBfZ3q3UK9fCe8HSVGozeGqDYHSuCdMolyAU
         ZTQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KQx3tJgz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id y8si209301vko.4.2020.12.02.07.11.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 07:11:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id b12so1143404pjl.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 07:11:37 -0800 (PST)
X-Received: by 2002:a17:90a:6bc1:: with SMTP id w59mr319106pjj.136.1606921896689;
 Wed, 02 Dec 2020 07:11:36 -0800 (PST)
MIME-Version: 1.0
References: <20201201161632.1234753-1-dja@axtens.net>
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Dec 2020 16:11:25 +0100
Message-ID: <CAAeHK+znbFs6PRQNg0TVAB=diqnzo=uRg8-dFKcKuNUgJ_T2uw@mail.gmail.com>
Subject: Re: [PATCH v9 0/6] KASAN for powerpc64 radix
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, PowerPC <linuxppc-dev@lists.ozlabs.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	"Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KQx3tJgz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Dec 1, 2020 at 5:16 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>
> This is a significant reworking of the previous versions. Instead of
> the previous approach which supported inline instrumentation, this
> series provides only outline instrumentation.
>
> To get around the problem of accessing the shadow region inside code we run
> with translations off (in 'real mode'), we we restrict checking to when
> translations are enabled. This is done via a new hook in the kasan core and
> by excluding larger quantites of arch code from instrumentation. The upside
> is that we no longer require that you be able to specify the amount of
> physically contiguous memory on the system at compile time. Hopefully this
> is a better trade-off. More details in patch 6.
>
> kexec works. Both 64k and 4k pages work. Running as a KVM host works, but
> nothing in arch/powerpc/kvm is instrumented. It's also potentially a bit
> fragile - if any real mode code paths call out to instrumented code, things
> will go boom.
>
> There are 4 failing KUnit tests:
>
> kasan_stack_oob, kasan_alloca_oob_left & kasan_alloca_oob_right - these are
> due to not supporting inline instrumentation.
>
> kasan_global_oob - gcc puts the ASAN init code in a section called
> '.init_array'. Powerpc64 module loading code goes through and _renames_ any
> section beginning with '.init' to begin with '_init' in order to avoid some
> complexities around our 24-bit indirect jumps. This means it renames
> '.init_array' to '_init_array', and the generic module loading code then
> fails to recognise the section as a constructor and thus doesn't run
> it. This hack dates back to 2003 and so I'm not going to try to unpick it
> in this series. (I suspect this may have previously worked if the code
> ended up in .ctors rather than .init_array but I don't keep my old binaries
> around so I have no real way of checking.)

Hi Daniel,

Just FYI: there's a number of KASAN-related patches in the mm tree
right now, so this series will need to be rebased. Onto mm or onto
5.11-rc1 one it's been released.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BznbFs6PRQNg0TVAB%3Ddiqnzo%3DuRg8-dFKcKuNUgJ_T2uw%40mail.gmail.com.
