Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB5GEZD6AKGQEUNKLKGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 14E012967E7
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 02:23:17 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id r19sf1442628ljj.9
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 17:23:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603412596; cv=pass;
        d=google.com; s=arc-20160816;
        b=m0ALOOG6ZHxbJc2cLWY2FtOsPLx6I67qAfBL12kTb8GZd5XR/EOcJqZqK4HFaviKlL
         1lgQcTXw7tCaxKI+EVAOwk5FH2IquwWXsUVfqKsk0bYbxA44odlCZwyuiSY5G4CkYLqq
         2HaStFtRxOnuiKAumurbEMnyT0OhWQveQTOsgo/YDOCtXtYr2o+bqXthoBQj5r0+L5tM
         4dzV5HrMsf6Wg/Hkuo1tq3p5BHre6tClHOtHU6CUi/RMThVup9hOnveLvqXl5AU1sepz
         mr5NEI4S+0Zj0/3pO6SdQE0bta4yCfbqnHmywPe7zQaR3cCseXWLTaAFxX6xXaTXAjHB
         BN3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=tv80VCt/55cnfHgbkX6dxmgnHhOtjuJYy7u5MEW5G9c=;
        b=UkPJe7hfCRPiTLqt7vXKvwCX1T+Fp9v4Qoy9yERJd6/ZMOnWlFI8KENI4gE3CS4ELu
         UEUI066BTjnjfOQoVFVW9XIyG9VJrDjFIsftzzC5dIdNthwoqC/iZsBhQooda5T3qKeZ
         mpchXFD+8w8gBoeOMCDljHg0BSINXNooQGVp8GK1W+Jl7Ydqp9HroAiRYOQWs9Ay+Z9c
         MbfsDhVsaAs4WYZ+7RqP54HS8XvYurw7zl91NjrB7oPICJwW8Q8H28kqgpoBslJJV1nx
         iUcQ0DbLwBTcOztA84zHzLlDEQ/9H0qYuUCO2EJpuOthAVew4/JYUpPBtQg/fnI/YpOv
         b+ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=bS2jLvh7;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tv80VCt/55cnfHgbkX6dxmgnHhOtjuJYy7u5MEW5G9c=;
        b=YhUgPcKXn5b35AGpAP+pADPFQbEC9wYxl2fKtoqq63c/CkZldqTLzRhb4SjPfQQA2H
         65HGasJWYZgY2OhUowfXKc32ukzQtcKus77hkQOWm9ivQqnaqU1wwLwcYMfJjeodd0bz
         hAV+pq/Pxr3aysrgsum2cXgU1j31JLucADOmQUqZA/EAXRWSbCRLiR7GQYZ4SV91+6Jc
         YjIUIUWmxaaKYklwhxmm2XG/iR67W4BCMPy+NxNBjcq0ePEAiQqXDxZAO8WedrT/wF+0
         rktfdAnd+ORW/VrhLPT8X84qgyF8unDOVWiNcEc/1p6YnhO7aK1d0bvgMUslr5SX3inq
         GQJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tv80VCt/55cnfHgbkX6dxmgnHhOtjuJYy7u5MEW5G9c=;
        b=alK3PO4zBPjv7EbcBNwdh2rm/aYdWJQIO8yfeS5Oz4Q+iaRiLZ6GtBM1IeHlFaZ08c
         ATOpeYgedfcA52cxWu9eIfFe44H0CvroH2CD5hvJ5362XmODfWbU1ccGhYIq4YNxyDQ7
         4fAZHp+MVLVZuVqtB9dIP4RCxmzYCHROjab2cYwjlOVCyQ+5/Mvp4+4Gr0q/JukOlJDC
         FphQkZk/FWBTbG9r58NhTAXB5yNEmlddh4pD8xvo8topU9TZcP+fHF6CMVjeU06SvrX9
         xBHZjh5Wj8zgqax4br8yAGb6J97dNc9sjaVOF+MR4g7TvtFQ901v94hW5GN3jmBFobUY
         WbNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BtTUzm6Yewk5YCPpLNzpb6NM/cwwBwS8uzRlMVcFoqG2e2zxf
	MoxqyIcIVaB06JuBHqtIG60=
X-Google-Smtp-Source: ABdhPJxAHvrF8Yi/ZxUxvrVYrf9kyY2cjHzcoyOFiJjl1JzwAd1+UkutYxhR1YryKRCDvnbwi5XvnA==
X-Received: by 2002:a05:6512:78c:: with SMTP id x12mr1795004lfr.414.1603412596624;
        Thu, 22 Oct 2020 17:23:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls2190097lfd.3.gmail; Thu, 22
 Oct 2020 17:23:15 -0700 (PDT)
X-Received: by 2002:a05:6512:3089:: with SMTP id z9mr1563334lfd.275.1603412595420;
        Thu, 22 Oct 2020 17:23:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603412595; cv=none;
        d=google.com; s=arc-20160816;
        b=jgYhFXqZduPhWE2cYQtyKw+myhQvN6Bi81YKVvG9hLMB3fiMsywsaWu33to0lOB2Ah
         O3jHK+/KuFAF9u3MelT8KP+62kqU7wkSHiyzwUB8I8hslPB/HEFgtH1+0J6JQ4E09Lnm
         6ldokqMq9xNu17+8PjCT3gxNgXMCKF7BPYOAR8UJi2+oNFojUCwHES8O40+Vh94XM1AH
         7qbhK/pxhY0deu2RvaGqiZJEo+1HIokG/+hcTfhEcQUVzCKFdKEKFfj6O8Ih3xuXs+Dt
         +unzTi5HFUwjGUoPC5jg1u1GI4hjhnQt1ixys7jE/c5yJyMeDoV1312D8aHZ0giuUi5M
         hA0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EKRAxIo6c5FisvVeBU9yqsWIDr+qdhruysORLXOncrM=;
        b=VP3tZs6JwAiMD8JM6jr1PNNOkGA1itRmapSClaZX8axIXRhrbibkgYZrB2u20nGkqo
         KzB0zbkHbyCuVxYjcnQzYBFLLj/t50NmfXzQFOQsRVToRUl5bxPNroZ04UD4Zr567acz
         1JZJCRyR09SgJoB+mK0iIU2laVXUCFmWIZY+T0Mk0E8P2N3fxEcTMaW6/ABy8KOgo9kN
         yaz6MCSf5hmTshLzY99xQc6jsnhFAfm08MFwwaTvjZzaUva3JD4Ir6uMLJSssd6HNRra
         tNkrU9IKxjTpQ7LVE5wX3w2P/3rQwzaXBs7BzBqVOWOm6NsY7U3WH/9EKBzGCoYXquOc
         LhtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=bS2jLvh7;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id o4si144420lfn.12.2020.10.22.17.23.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 17:23:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id v6so4452630lfa.13
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 17:23:15 -0700 (PDT)
X-Received: by 2002:a19:48c6:: with SMTP id v189mr1539778lfa.284.1603412594681;
        Thu, 22 Oct 2020 17:23:14 -0700 (PDT)
Received: from mail-lj1-f169.google.com (mail-lj1-f169.google.com. [209.85.208.169])
        by smtp.gmail.com with ESMTPSA id b66sm418310lfg.153.2020.10.22.17.23.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 17:23:13 -0700 (PDT)
Received: by mail-lj1-f169.google.com with SMTP id a4so3866584lji.12
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 17:23:12 -0700 (PDT)
X-Received: by 2002:a05:651c:503:: with SMTP id o3mr1747084ljp.421.1603412592176;
 Thu, 22 Oct 2020 17:23:12 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com> <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
In-Reply-To: <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 22 Oct 2020 17:22:56 -0700
X-Gmail-Original-Message-ID: <CAHk-=wgeHE7AS2Q4kPrkC5dMqfx_6+E84+FcEDYJSTugxqivUA@mail.gmail.com>
Message-ID: <CAHk-=wgeHE7AS2Q4kPrkC5dMqfx_6+E84+FcEDYJSTugxqivUA@mail.gmail.com>
Subject: Re: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, X86 ML <x86@kernel.org>, 
	LTP List <ltp@lists.linux.it>, lkft-triage@lists.linaro.org, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Ingo Molnar <mingo@redhat.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Al Viro <viro@zeniv.linux.org.uk>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Viresh Kumar <viresh.kumar@linaro.org>, zenglg.jy@cn.fujitsu.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=bS2jLvh7;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Oct 22, 2020 at 5:11 PM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> In particular, I wonder if it's that KASAN causes some reload pattern,
> and the whole
>
>      register __typeof__(*(ptr)) __val_pu asm("%"_ASM_AX);
> ..
>      asm volatile(.. "r" (__val_pu) ..)
>
> thing causes problems.

That pattern isn't new (see the same pattern and the comment above get_user).

But our previous use of that pattern had it as an output of the asm,
and the new use is as an input. That obviously shouldn't matter, but
if it's some odd compiler code generation interaction, all bets are
off..

                Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwgeHE7AS2Q4kPrkC5dMqfx_6%2BE84%2BFcEDYJSTugxqivUA%40mail.gmail.com.
