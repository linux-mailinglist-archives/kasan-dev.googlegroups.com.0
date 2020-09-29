Return-Path: <kasan-dev+bncBDX4HWEMTEBRBN7WZT5QKGQEAGXSOLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id BFD9527CFC6
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:48:40 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id t3sf2094576ood.7
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:48:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601387319; cv=pass;
        d=google.com; s=arc-20160816;
        b=XnCqsfh/BDPFd+zp80c5WIcFN2u+23LC1qQo8Q/WaD6djFNJ/AfhflRAe9rgQf5eqj
         Ts2SPM0rWzRwo37lNc41uXqvAAl78dlPZmjlaFQAL9dxJglT2ycddwOH8bJh7HpRYPdW
         9pqzzZSNAtjEAiNfaU2WD/DOSS/Y96K9TCj5vBcUwwb5k8EXjAcTOkyZr/J+soue01a6
         EN87MUBLplOdajxtaPzGHMHLfKBgYgyJLLs2b+spbYTgUZAv2sXInxCRwXAMHZs3WN65
         A8W010yXIQQYxcCTW/zHLGzWYR9qE+yd23COQwfzniJO6bMDdz9FCxq6NDMDX7THpOGo
         QbAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qMfGBkjymIerllDhWJ40VluUBNRrwKtomBWTjW/ifXU=;
        b=f+vHjaFzbNO+W3F6Itp7jxnVpJElb5QjWq1+rML8o+isGZiRWp1RZffRNhpGAVjSO0
         wGX6i6RYH70EZBcIRe+oorHJFydCDo/TxgtlILptjfSBOuMI/hLL29dI3zS2WMxrt9/r
         yc6PHnKVEFg82NmRzkO+rDSVSoVgH6adlFwrGPzBatoo0vp7S3tSkSDzJ2ahWsMHxqoW
         CwL48foePmbnvIp/RHlWg188G2tjeSmBdrTl36ljllMjqTJEr+fRatZ2ol057Xlpi3K8
         BePJriF+809hMRm5XLR+Q0DTyEvlo0vryT47nS2o9uXRktHMOK4mbP67J8JmgeUNxtI4
         /+Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bSfQ00UY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qMfGBkjymIerllDhWJ40VluUBNRrwKtomBWTjW/ifXU=;
        b=GfSeEWINDCHyI89ONrJJMtOVzn6X89Sup6P1at/T0ixtO3HTRjn17HPBvuAatUsBRk
         WyFAgTaEgpY8KAtdi8U9LfX5vlcti3SAt3DNDTEsFcC8cdIEuNClIstczZKSaHw3mYZX
         WOw7OZwcJAi5YsuLEH4Eu/d65bUyohNK4krdS7DDPCHPrZPWnwyf6KR+AqUEv8RufYCj
         LEfsNwoGHxqGiqTLzYRbpCPkc2Defo8KckrmHrXkMmRTLuI8kI/okmpBkgwMh03PKFNQ
         MwGaQunXFSGcBiSSZBgSTDu2TvoRv8ga5c/ChLh7NkybRF+cXQDE/CSyDASbmNQZhPRF
         AF/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qMfGBkjymIerllDhWJ40VluUBNRrwKtomBWTjW/ifXU=;
        b=f47asddRHtajGD5WZQ4+sPASVY77v9lCMmgLF6wNw9UtiUB9eAlmkeBXzekB9P4hTF
         mDBy7t9w02m1mhRxWXi5ZKGD6fE/5oWmRl3x3mIGRdvZuSbuWUFnA3i8/1GnEA1ER2Ae
         V5lM89ko+Q+vOxTyXCwhkUPYD4VbXNQ/xznl/M8jEYaFzEJaXFtTk90FG3YEwp3+6PPE
         09gxlzTa81q4T7eG4pWOZvlkgHMhoPIQtEk9GbS9u0VNrvZM32S7XDyQOmv0+48fBFke
         XbOEUUhQFadpNY1ushHACqth/uOUaymn9wzRtejHCGDlL8yMRqkV7rIXfzFrq6uxnkLY
         yfWg==
X-Gm-Message-State: AOAM533YeOFRnwKXA7b8p615rQGBvjUPDTwE2vq1Ud1H/oT6piX38APV
	IS700cyAMONyng0w4bC2T6E=
X-Google-Smtp-Source: ABdhPJwavuBRTN4mskO4vNM760zGKP2kzvOvw5B8aI44gQNXcz3dLc8yceL9IjFnors5hHnmPa9EAQ==
X-Received: by 2002:a05:6830:2096:: with SMTP id y22mr2859483otq.158.1601387319707;
        Tue, 29 Sep 2020 06:48:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3e51:: with SMTP id h17ls1122284otg.5.gmail; Tue, 29 Sep
 2020 06:48:39 -0700 (PDT)
X-Received: by 2002:a9d:6250:: with SMTP id i16mr2997838otk.77.1601387319355;
        Tue, 29 Sep 2020 06:48:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601387319; cv=none;
        d=google.com; s=arc-20160816;
        b=CFLosvuTpjZsR26+k2sthH7ryYEXkJrLdJU6L0YDWfgqvfu3AORphDFPT+XiiWgmj4
         G5o8ZE2Aqjhv6UmjSYQRMnue0lQTlj3alrU+W7jcJ4H7SfS7zYPFg8BvhUIWeLwy8Wr9
         Gy8C/IlY41JA+TKCMmqxY///E8cxMKa72/g/J3POa2W6d4DZ3T5Gv46SP1gm8B8WjuNF
         k7d2FydWB3QHG7icCnq0HAzu5ezd1RSl/pacQZl/gGXLiH2EujM/rfDSiY6j5Ts4UuCc
         jSnMUIdmPuBTAtXxeR7l+J3CQOrzLq3pZuBr8ObGtMHTMfv7l0jNrskFUwUOLrFbJJE0
         lVuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IPm4tw86pN2WUua3zyIf+UMu5higdStDKbiJez1ULJI=;
        b=C6YpGeNkVwMJbHqVIBzDt03oyvAUQTKlYGpKO27umIAwKlVB2uU2NOiSYjfbvsH6rO
         lqYZ7D3eOFXdSxqzdfrQwUJhcRP48VdqwpajhRSN6bJKZ+9Yxkvj6KaU1mDg7dmNYhZ7
         Ti5X9et7Igjsu3mievc9X7T3hwj0dyh+pH/g9FNd4SdDvpIttS3ZFFa09W0N2eX6glMF
         anuieoI7imIpZmOJB61ngWwBbPvq+IE298oMceJM0vnrN+fHO7dau04qBSaQnSImbUkr
         HEuh64eLxeNoLTzp6p06/b3UNsXpSn00JvB0knzv/TpGHjsiMrp31/UdYKF3WGseMSau
         dLHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bSfQ00UY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id o22si360952otk.2.2020.09.29.06.48.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:48:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id q4so2692730pjh.5
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:48:39 -0700 (PDT)
X-Received: by 2002:a17:90a:81:: with SMTP id a1mr3910753pja.136.1601387318512;
 Tue, 29 Sep 2020 06:48:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <CAAeHK+zYP6xhAEcv75zdSt03V2wAOTed6vNBYReV_U7EsRmUBw@mail.gmail.com> <20200929131135.GA2822082@elver.google.com>
In-Reply-To: <20200929131135.GA2822082@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 15:48:27 +0200
Message-ID: <CAAeHK+y0aPAZ8zheD5vWFDR-9YCTR251i0F1pZ9QfXuiaW0r8w@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bSfQ00UY;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
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

On Tue, Sep 29, 2020 at 3:11 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 29, 2020 at 02:42PM +0200, Andrey Konovalov wrote:
> [...]
> > > +        */
> > > +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> >
> > Why do we subtract 1 here? We do have the metadata entry reserved for something?
>
> Above the declaration of __kfence_pool it says:
>
>         * We allocate an even number of pages, as it simplifies calculations to map
>         * address to metadata indices; effectively, the very first page serves as an
>         * extended guard page, but otherwise has no special purpose.
>
> Hopefully that clarifies the `- 1` here.

So there are two guard pages at the beginning and only then a page
that holds an object?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By0aPAZ8zheD5vWFDR-9YCTR251i0F1pZ9QfXuiaW0r8w%40mail.gmail.com.
