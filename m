Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBZXYZP6AKGQEKEHMH5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DED942972EB
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 17:53:10 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id r15sf844968ljn.16
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 08:53:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603468390; cv=pass;
        d=google.com; s=arc-20160816;
        b=adW+ykMAv4ep4Gv0Q0LvTugCGMG+Ny7odcwbCzmUgGUJ6wHYyoRRglM40KrEyKv2Fl
         Mz9vADMZbl9U4M4Uk47vG0DMFNSp6kCuJbxjZgc45rMYRKwv9d+WuZq5t1ZKla6sk9+6
         m5NvS4eppqme47l2vY3n2sM020A5XWD748XiOZhcPDkn9ExzMiHUq4r0tGJ/puqX32nz
         x9dLG310idVIHlNJWO5ktTOJPEuh/UIfwyUOdwhWxOElnvShLAMK7oczEiiyyoXSAiLI
         J9E2EZU4iXJDwil6uk+OUCk+flx2zL0A3k/zMKXgoopdYzYgzpGXxyWgBM6xUpKuACni
         Hfcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=DMJCkRvAv4LFbbBAfCE+0yclhfgjRL0nDGJNhfedA8E=;
        b=0YFTiKUtsjEzp9XJisgOZ1V9ZKpZta2jarwX2IJaARd2gpk+0DFPZ5j9rFOGI3SOQc
         K56wsRYIcW8Y5xcP58RRN1HUPpqwkPM5xUgLRWuSEG6RenXwgnoR68LzdCQ8nk9JoeBi
         +7ba49eSGkcD6O4Vn9kA8QPciyVbPiKORJCVL8Wp4KQappFK/wGu8h9kBaaMaKmiFoDM
         aaZfsN8h2EpFEvlNve+eyoYzSStNNonmuTcfCKE1ggDxPLOA+jciCrS+PHPkxSrBwbJG
         +Hdj0z6u4C5oEKXfJBldKU0vAERU7qXOj2crLnSwe5kLChe6VToIEgaFSAA4Q/HiL9ek
         7cSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=TzWUN3CT;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DMJCkRvAv4LFbbBAfCE+0yclhfgjRL0nDGJNhfedA8E=;
        b=fNp7ZWp32zinhNYFFFZPtI7SbtfKsdxhzOJrMoNPpTAntvfRr+ZlOSATQ5p/MnF3/y
         UNp2o3W0CH5iWuy1vWl1SRu9k3/6Se0SgXKjPhq0PRxjaQrof1xPw5V8xMg8dzCmfMwz
         kKdzKVpsx6wLmRGq7sfmUNTaZGAELURAb85ZVEKdnh/XYVUfzN4JRGMF/6DptUVnEOyt
         33qVMxZNfJx60ytxqimFV1a2WS53FOMJQvH4V05j9KOojdcbcx/Ri4xj540hbDNyASLf
         6un9i8ual0ykAvxHZ0rfFFzjOYLj3YuXcFaw+lsJUIobfipUAOQfG4dnPVu8G0oKl8mr
         JrwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DMJCkRvAv4LFbbBAfCE+0yclhfgjRL0nDGJNhfedA8E=;
        b=gZZT5oLmQb6ttTYQpN9CyPSe5BSWUhQqc87Oh27Gzn4d8IU05rax3vo7RJCR1uFid3
         hggqtBVmWoIhFt+hxooq71aiWm+E8FeQftY0M2GhHoA36qRJF0SW56xZxA0YgkX1Fjqd
         UtQwHfZb44lxOnbED6XFfJ9xY2GMZEeugFTZc51auGHsJIKmiJOkhl1juLuTPUSrNgaT
         j/2MgdBzXU3D29R1r4odNtOHDCbvI/kaITaFF1kZtEBYFe5SI7yRPmhW+vS/X56+BO+n
         b4AWw3e6h9IlIDh5qg4SLdKSv2Wq2fGPoRSv9dv3RKAyH644BZmkiQAxotfVtSrnBu88
         OibQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sFWddcYt6XrEsEEm2lcJv9xrthXpRTh6DJXJodwppPoqWhMdg
	1/H2E1VSY1BjWV5p+25lZT4=
X-Google-Smtp-Source: ABdhPJyYKRLTEZsQmp5theNBSvVqM1bUD8AdZJshLd+2FI2e+QH3lafwq2XUwtNc9a0mVmoLK9QQlw==
X-Received: by 2002:a05:651c:336:: with SMTP id b22mr1197028ljp.75.1603468390411;
        Fri, 23 Oct 2020 08:53:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls1310453lff.1.gmail; Fri, 23 Oct
 2020 08:53:09 -0700 (PDT)
X-Received: by 2002:a19:8ad4:: with SMTP id m203mr1106076lfd.183.1603468389140;
        Fri, 23 Oct 2020 08:53:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603468389; cv=none;
        d=google.com; s=arc-20160816;
        b=qLPBleCKy6njIFFf2hA4J6l8TFy5JCLIDr/owgu7YMmysLDyOEQH72aDrxr+znEL8K
         rdzL4H8O3c77JoaspfLpBty5KDoWFQAeot2wLh4e7TngL03fcYRCN69JRE7rUL5j986L
         Xeae2jZN/9HJB3vEpdd9I0RtZpXgDIKZhu1HLtLoUsnKGWy9FXh16W2ctfrBSgz3uGFk
         U4bA5hUPd/aEL2U3Sslkm4TJmw2j2ztcvhYoRAxoQSdhcQI22jOkTbcIT/OqfRjW8lG7
         2ytxGzunmyxdJ2Z27QddUtZrO2N+pJO4tafo9Fq2XtnyAcTxPdi6PNs5t0/lfRqdpsc9
         Mp7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=So975owvkkTFfYXQ470Q4DlssmIVIFu2QdqnJrTF8xg=;
        b=I3Jf/H+3tiY4M3nWsxwxolPI7/EMGNj+iIMIT7ViwlH0amX9NPYYtrzzvp8ZoNSDGr
         5XWEreuGGVojTsA6WwmiG7jRuFZIG0w68MhyNPxzBl4bLIYymzAUnHltfZny+G8H8dPC
         H2RhoJvObQPtWc4AIeOYLGhnKeIosIlClDl7D1ugnw/UEcD6aExe21dNvjy0I+qOBgjh
         bSskttrYCBTyKkps1ZWkvjK54lfIWBWFg+ZtibXqt6Oxw3CkYO7RahFK0if2DzXqwKrH
         AgEgk82pIv6wxx0efb+0N0BthnuU45Mm+QPKmCQOoVWugvzBp+9WMQo0VlEWPBhUX5B+
         uxwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=TzWUN3CT;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id h4si65458ljl.1.2020.10.23.08.53.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 08:53:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id d24so2657369lfa.8
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 08:53:08 -0700 (PDT)
X-Received: by 2002:ac2:4c12:: with SMTP id t18mr924074lfq.285.1603468388371;
        Fri, 23 Oct 2020 08:53:08 -0700 (PDT)
Received: from mail-lj1-f169.google.com (mail-lj1-f169.google.com. [209.85.208.169])
        by smtp.gmail.com with ESMTPSA id m4sm202295ljg.137.2020.10.23.08.53.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 08:53:07 -0700 (PDT)
Received: by mail-lj1-f169.google.com with SMTP id 23so2080260ljv.7
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 08:53:06 -0700 (PDT)
X-Received: by 2002:a2e:898c:: with SMTP id c12mr1248002lji.285.1603468386475;
 Fri, 23 Oct 2020 08:53:06 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com> <20201023050214.GG23681@linux.intel.com>
In-Reply-To: <20201023050214.GG23681@linux.intel.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 23 Oct 2020 08:52:50 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjBjUvjN_Mw2Oo5XMUJFSREi3d9AHTSFmgp-a42ZH_K_w@mail.gmail.com>
Message-ID: <CAHk-=wjBjUvjN_Mw2Oo5XMUJFSREi3d9AHTSFmgp-a42ZH_K_w@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	"Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=TzWUN3CT;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Oct 22, 2020 at 10:02 PM Sean Christopherson
<sean.j.christopherson@intel.com> wrote:
>
> I haven't reproduced the crash, but I did find a smoking gun that confirms the
> "register shenanigans are evil shenanigans" theory.  I ran into a similar thing
> recently where a seemingly innocuous line of code after loading a value into a
> register variable wreaked havoc because it clobbered the input register.

Yup, that certainly looks like the smoking gun.

Thanks for finding an example of this, clearly I'll have to either go
back to the "conditionally use 'A' or 'a' depending on size" model, or
perhaps try Rasmus' patch.

              Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjBjUvjN_Mw2Oo5XMUJFSREi3d9AHTSFmgp-a42ZH_K_w%40mail.gmail.com.
