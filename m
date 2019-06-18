Return-Path: <kasan-dev+bncBDEKVJM7XAHRBQMHUTUAKGQERVGDAJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FB034A569
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 17:31:15 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id l5sf5019450oih.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 08:31:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560871874; cv=pass;
        d=google.com; s=arc-20160816;
        b=A4gP58FFE7ofLtL7gsfIF1neHz2JSl5neQP045dvprnEDQngJ8GlDx1lghucKvG3YA
         v2qhnjUnabu4y8OEW9OKMbsZ5QDGt6EFMez1muqQGMseARrnE9MDQB/3SkBuDN5QRaZw
         P26+P4EGzWWUMnrKVcVn4TUN2n3KAWnKlhsnecjAMT63o/7ZtW8w0pfK7Ghgd1qgxt+W
         e2+ehIT7aKyXAG6DGZjsh0yP1dL9GdK6JwnFAwA6gtVHBBQy2fmlFuz9xtlX6cGR3w3d
         RGpeHP1E0a3rb2BqzIPPzJRdD7dw1otkI0oESDcL8DmKG0w+mrmKQS6S7jkX+PU/PxoE
         tw1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HMz1UoBobzofrwLuXFCLUAhIwZqc8SOfBOspQmet/Rk=;
        b=uGzlRnjQjgD+hHOCnCCs1DCbvYR0c4xjAkZzFW8T6JJxxjCSjsU9kkrsydQ5rnQtMZ
         C0yDjQsN9LkNxAyW/KUq8stbFqAJLbBWpalUs65S8aIvUgV74Axh9n3aCKnHA9GjedYe
         /qMubcFehnYvWALD2wSZIyJ6x1bINyUA5pNLlCAEYExJmsMDVi8GFw7x8x2O4bCkWWx0
         iS8NGWWTi+fEWCoekK7p5brZPX0gkZX55rXUfem8kORtaO6o9+ZyxtO4GMDtudVLoQEr
         ZVa6XhfZc75XyC/6lD3ALbBdkjpWls/V58EPOQ/jJMlPYXyHEip3LA1HK7x7UM0+law0
         ITOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.181 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HMz1UoBobzofrwLuXFCLUAhIwZqc8SOfBOspQmet/Rk=;
        b=p/ghLjlu4s7WPNsiYDx77ZpMxw7cH6uZMAr8WE/fnsOb3X1Bck8dK0v5U8He+O3G8n
         v+Kk9xDp3DntKlyBa2Xx7TRTDPFxvG7GrOXz8OnwK5x/5idwyCZ+I3jD6Vnh8C5fMk4x
         jGZ3aXkaexbkiYOL8YLuiPSBVU5Ehy/JDaEggn8T8VKXbpBbPpPBQc6k9pg1vExpxIJy
         fGjEKm48w8eEB/T0fpuOq5C6Bp4k5OtA3K2DTGpvhljBU1XRv0/JNvz0mU/95OFKrab0
         bNq6r+Nzi0YIxi1CPwMpCYM6fidHZPRQZqvKB7GCQbwa5DiJ4l60uqIXACAzXCX6ikl0
         ZYCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HMz1UoBobzofrwLuXFCLUAhIwZqc8SOfBOspQmet/Rk=;
        b=RSB5ZN/3E9/Y+8ooPoSQSJsqjQ6sqYyDdD7gvhGi3SYCIV2xEuP+og4P5/5FIBM5Gl
         gc32nf75jYJTHggA/3b7/VFQfSuBq4Yypxj8gF1RpLLdFvAlKd5Jf4O4GJ3v+Mns/vVw
         Z2hVz/jK3ps/fEOzViNv5AoyLExv4jO9A3X+YfF66Fa/D/saEsT4GsIHPDYFbUYLXyPR
         NMnanHlLh2GJhzDZ5NT4NdkJWX4bb2XzgY640gZEEfKV2pWV2E73WIWysUzEA7Wu3z/5
         MCwiqKxFQUO4kwE7VAMK8L/CmHZj97ZqLpEk1b1d5VJJhZUcHaC0lheGre3QQdCJusPF
         rOBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXurO68bbkU/4AihI77pWFZ4FyW75XrTCLC3KbD9XSF7izQoB1Y
	yx6gLhFjj+ZToJzJ3paaClI=
X-Google-Smtp-Source: APXvYqzWVGEM9J4gw0yXwJyv7NGAmEHDtGIEkI/x47pbqRTNGOa06iDhY9NSffjcCwwMtH1tc+plWg==
X-Received: by 2002:a9d:6499:: with SMTP id g25mr1178142otl.184.1560871873781;
        Tue, 18 Jun 2019 08:31:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:764a:: with SMTP id o10ls1580514otl.13.gmail; Tue, 18
 Jun 2019 08:31:13 -0700 (PDT)
X-Received: by 2002:a9d:6644:: with SMTP id q4mr51626462otm.308.1560871873403;
        Tue, 18 Jun 2019 08:31:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560871873; cv=none;
        d=google.com; s=arc-20160816;
        b=E+DriShuh1U3d8aV53tUX9sPbMRn7krqgZ0mIt4FwDxhsZ2aFA1SNQBGCc4j76ngAB
         KUv+EP9W36kAsVRDk5aPax7now7SXoE+5Qvw2oGElq0PQvVbhdlajCY2cO7+BA/xnTEg
         VUrI8ZMxVCer1qX7dOJCvmZZmnDR/2SweS62A7zs1EZFxLC6EMoVWXfLyWgQp/cexE2I
         3K0SONCVGgkrpuFPDA5oBeRwL7VjNgUGefeF9MHdfIr0J1h1+yFhQTUEFCoSFmGUZaEN
         qltmIqfJ6qdN/l3G5tNt4yIqzvQXTo6yjMvLgb6KRbdtOG2viFBlUgp0AVoPwjLooYKB
         T03A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=enVeaDd9KA1FhkBFIcyRHmn1gPk9Dn42G5cz03oOzOw=;
        b=0xOMTMsnI9PYK0Xq80ZSQpvSqA0YzfoZjJUOZGAWjsnOim8njH0fhiyIn8RcjtOE9Q
         r98DVvUcdD+51iF8SfLTKAa7aqImMv/gZvCvJ2g8IBgDClFknhwm/gThLghWhJFOzWrH
         eJ85EEucP9kihwfhKOlrS0GMB04tdID2/+56uf2ebOQrU8uO9/r6DaEVUlTQf2oRfMoL
         HvrpGfoObMzNeybRLH0ed9YOwR4jAJWAAO5cXZqUzBmjKPf2gAnmR9YEzNkXuvpwFts8
         GasXMS/Bs0ugHlQI3xi1T7KN+YNsii+0FukiQxwrWjt4LUlPY9+7lscMDzm8qWqxAYQw
         yMnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.181 as permitted sender) smtp.mailfrom=arndbergmann@gmail.com
Received: from mail-qt1-f181.google.com (mail-qt1-f181.google.com. [209.85.160.181])
        by gmr-mx.google.com with ESMTPS id v141si629488oif.2.2019.06.18.08.31.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2019 08:31:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of arndbergmann@gmail.com designates 209.85.160.181 as permitted sender) client-ip=209.85.160.181;
Received: by mail-qt1-f181.google.com with SMTP id p15so15848741qtl.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2019 08:31:13 -0700 (PDT)
X-Received: by 2002:aed:33a4:: with SMTP id v33mr66076417qtd.18.1560871872815;
 Tue, 18 Jun 2019 08:31:12 -0700 (PDT)
MIME-Version: 1.0
References: <20190618095347.3850490-1-arnd@arndb.de> <5ac26e68-8b75-1b06-eecd-950987550451@virtuozzo.com>
In-Reply-To: <5ac26e68-8b75-1b06-eecd-950987550451@virtuozzo.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Tue, 18 Jun 2019 17:30:55 +0200
Message-ID: <CAK8P3a1CAKecyinhzG9Mc7UzZ9U15o6nacbcfSvb4EBSaWvCTw@mail.gmail.com>
Subject: Re: [PATCH] [v2] page flags: prioritize kasan bits over last-cpuid
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Will Deacon <will.deacon@arm.com>, Christoph Lameter <cl@linux.com>, Mark Rutland <mark.rutland@arm.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of arndbergmann@gmail.com designates 209.85.160.181 as
 permitted sender) smtp.mailfrom=arndbergmann@gmail.com
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

On Tue, Jun 18, 2019 at 4:30 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> On 6/18/19 12:53 PM, Arnd Bergmann wrote:
> > ARM64 randdconfig builds regularly run into a build error, especially
> > when NUMA_BALANCING and SPARSEMEM are enabled but not SPARSEMEM_VMEMMAP:
> >
> >  #error "KASAN: not enough bits in page flags for tag"
> >
> > The last-cpuid bits are already contitional on the available space,
> > so the result of the calculation is a bit random on whether they
> > were already left out or not.
> >
> > Adding the kasan tag bits before last-cpuid makes it much more likely
> > to end up with a successful build here, and should be reliable for
> > randconfig at least, as long as that does not randomize NR_CPUS
> > or NODES_SHIFT but uses the defaults.
> >
> > In order for the modified check to not trigger in the x86 vdso32 code
> > where all constants are wrong (building with -m32), enclose all the
> > definitions with an #ifdef.
> >
>
> Why not keep "#error "KASAN: not enough bits in page flags for tag"" under "#ifdef CONFIG_KASAN_SW_TAGS" ?

I think I had meant the #error to leave out the mention of KASAN, as there
might be other reasons for using up all the bits, but then I did not change
it in the end.

Should I remove the "KASAN" word or add the #ifdef when resending?

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1CAKecyinhzG9Mc7UzZ9U15o6nacbcfSvb4EBSaWvCTw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
