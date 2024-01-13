Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVFQRGWQMGQEDVS254I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 3600182CACD
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 10:31:02 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-28d4ec3bf5bsf5555618a91.1
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 01:31:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705138260; cv=pass;
        d=google.com; s=arc-20160816;
        b=I29bu9qRbR2QTfEqQMCFt5lLt3XPAVC2kOmBuL1Be2OVmOO3ZpyrgF1lhYLJ45meah
         03XpRkeixKXtxN5RqwmVcIkLVm2LvTcEZkNo3tFkBMVW9BxotGTKfpZ2EPG43OTpshbH
         7X8kUKhdp5wFMosjXDE96KK0RicV00XgqLxyysKtOX/cH8+L8fvu/jlsvUShCahVeJ0y
         9oajyAFqgfrag4MfnDwB4LZJMylkKhvDFzQ4fGKDP+ua4aRURPKa6Up/Xcvz2xnLRI21
         dlbjQFlNbOwQzt9WmcZTFYfJlybMM5G8d/dlN8S+pYCC9kluAoIzUTKMI9bdO+iVQRwK
         PuQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bGsJjShi15liOXkPFv1EYQCEMThPrpLnLLduY95rACQ=;
        fh=KtmuM4t+2D/0bgkLGSGV2OTdmeV3Sg+Pwv69Xxa5wIY=;
        b=w/3z6SydEYTb3BrbwgJ0567n3A1xGLLSsslg3LGPu4znKGD4FnJMMNmTswFSev81pf
         rCGgv7Tv6cwmPtcxoHeqdBTsmLKlP6GI3y80ifFY3oYsyB+JyHWGYrTAPy2j0XJt9Krj
         xAzBGdtsUQ9M8ikAdsZ1uXyA6AmFmQOLTiqZa9W7lU9tWV1+2D7BeH/1j/4G/ghGwIDl
         IjyDOauCa4GAVW9Kyt4ogJZSVzGmy9xD2O7thkHQBppj0OuExBNPGgxhqkV80eFPcL5U
         xDONgWakv936WLlNSDgIZVfhBjKXdR/PK5+sYrLkSwgHR2aZOpg2L2lJG0gBZu/jivDf
         1tWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SBU9I7H7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705138260; x=1705743060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bGsJjShi15liOXkPFv1EYQCEMThPrpLnLLduY95rACQ=;
        b=kpFCXgCm1xSp3RcSosdA5ZC+S52B5VniSTXTpWiBqFLkj73zt3+ppRUf8Ler3p7RC8
         WFp6CZ3AURyADKwFDZBU//wc6v/ptwfE5waVSRE+0VUT9nk3aAUPCw70gBp4iIdI4lEd
         u/kL8QdyRgu1h4mkfqyEeQ+iOnmmDbn0zNz0TIcCxlrRpam+NCuII1dp+FkScNUj4Vcj
         AmgvgPlJ2VVjHhKQUU8OQ5urAKPhavAC6HyfPxCfBDUqL3oP9HBweNnmFZ5OVT3pemLg
         JqtCrDGtVHQUAL+YENf97Tt2jwAjrD+GNIXDt9Acomm817MgDrqfGJdDyPTI+vy2cZWP
         zCKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705138260; x=1705743060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bGsJjShi15liOXkPFv1EYQCEMThPrpLnLLduY95rACQ=;
        b=GDCNrgsCECLPp6WUwWdUEgH8k8UrS3xGENq5DUkERn7uEJ29MZDEROefpsIkem9SIP
         6dcLULRrrHs97qGOGlPdKPFJeOYKFLWxz3f3qlU8AtVwkJytd5UH+26w06Tx5dbuzXPq
         55JqwUK5Lh6JPyeAK262slieZTym/dqM5ysmiEDf5mhzvyJW0D4qzV0/8uSjidq7RyZJ
         6cYJTm5G62espCmvvUf0yw9wANf3l/A16T7GmQGFzsX12nmZ/JUA0nNhj6cnQrRvgCgI
         UI5dlKKMWCWk+4qSnSR0wSeJUKP8BR6Rj0v/mKrVaFL+zDy1va6aXMCY0rXWXad2ksQF
         OTZg==
X-Gm-Message-State: AOJu0YwIapSDdKdknHo26+b2mzQTaBX8mhmRrs/mK0cL1cnTBG2XB+zj
	0T1ZFUu5NaF5QoECLpzovt8=
X-Google-Smtp-Source: AGHT+IFunFPYXu8IB+paKCPqf/jIJEpv9Guss4cBGlw8sU9NpKezlqCrkMtZUYGyVmK8eOM8qa/R1g==
X-Received: by 2002:a17:90b:4f90:b0:28d:44cc:5de2 with SMTP id qe16-20020a17090b4f9000b0028d44cc5de2mr5718112pjb.33.1705138260471;
        Sat, 13 Jan 2024 01:31:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3610:b0:28c:f8db:26db with SMTP id
 ml16-20020a17090b361000b0028cf8db26dbls3836832pjb.0.-pod-prod-00-us-canary;
 Sat, 13 Jan 2024 01:30:59 -0800 (PST)
X-Received: by 2002:a17:902:a503:b0:1d5:7524:6d21 with SMTP id s3-20020a170902a50300b001d575246d21mr3311174plq.42.1705138259262;
        Sat, 13 Jan 2024 01:30:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705138259; cv=none;
        d=google.com; s=arc-20160816;
        b=xnnz5+JF0wH7mgsg5P0BdV3rcXkHKQ4fDfVbSnZ3N9Jnma9+ljB4Ho64J4b3AIMFuD
         gVjw58qEiCy+UxLuVGKsp9Xr3T1Ck8pY8u9KDivfXYeslIbQoBefhGbw0stbl/rzAvgj
         ryNrkDi6JRk1b6F48g6GMYcfxuRmqntPa6qSf+N+1qhOmTnV1pdmxBq/6YMQp6oWJkhL
         Vy0aSSfpoAtpBLXxdDV/ZJuCCRlhmH1ZAe+YLOBoF+BcvbrHLyZhlRWAHKOMkaydgdeu
         DSoukiGAPpzDSD3nbcuJi6RjYXl5rT45nRBgGUW2BisS1/f8yPbqN0/CtVsKXGx14Ku8
         V2OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bs8F5F/gFkaaibZRS33VN3FkQujN/mSOo0oKKTFy/VY=;
        fh=KtmuM4t+2D/0bgkLGSGV2OTdmeV3Sg+Pwv69Xxa5wIY=;
        b=C1q/fN5xEO9PumI2niJwXDnqwG2JcGKrFAzgNemiTkiO3j8akuzHjCDQedH339XLCt
         w5YbAGnqe+yj2KxElzdn9BN3+6nVX3d8qq29iCGvB+zuwcNpnSbLdF99g2zCnPN0bMmO
         U8fahMVFuqpmlXLC3ThPWs5uajh88zebBBLDRrkAciEuMPQr5E1R9kjibBfJ+AO//+MF
         6lJkqny7eynhqz6bwtarwXBGMwacibfGAehEkOWFIohzX9vAehZy5ghz4wrIpoRpdpvT
         ZTBIzZBpYZ4TjOBUpagjwLk9B9sSS56ifnak6QrNYVeECXb5FnvV0hwhVV4Sr11DfW4N
         NRvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SBU9I7H7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2e.google.com (mail-vk1-xa2e.google.com. [2607:f8b0:4864:20::a2e])
        by gmr-mx.google.com with ESMTPS id d186-20020a6336c3000000b005c622d1ef04si261930pga.2.2024.01.13.01.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jan 2024 01:30:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as permitted sender) client-ip=2607:f8b0:4864:20::a2e;
Received: by mail-vk1-xa2e.google.com with SMTP id 71dfb90a1353d-4b739b29686so4032758e0c.0
        for <kasan-dev@googlegroups.com>; Sat, 13 Jan 2024 01:30:59 -0800 (PST)
X-Received: by 2002:ac5:c98c:0:b0:4b6:e3b6:41ea with SMTP id
 e12-20020ac5c98c000000b004b6e3b641eamr1766273vkm.4.1705138258316; Sat, 13 Jan
 2024 01:30:58 -0800 (PST)
MIME-Version: 1.0
References: <ZZUlgs69iTTlG8Lh@localhost.localdomain> <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo> <ZaA8oQG-stLAVTbM@elver.google.com>
 <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
 <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
 <ZaG56XTDwPfkqkJb@elver.google.com> <ZaHmQU5DouedI9kS@tassilo>
 <CANpmjNO-q4pjS4z=W8xVLHTs72FNq+TR+-=QBmkP=HOQy6UHmg@mail.gmail.com>
 <ZaJVqF-_fJ_O3pJK@tassilo> <CANpmjNOz7tBMK-HoyZNVR2KcgxEBY1Qym=DRa9gHLFkaNHLmVw@mail.gmail.com>
In-Reply-To: <CANpmjNOz7tBMK-HoyZNVR2KcgxEBY1Qym=DRa9gHLFkaNHLmVw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 13 Jan 2024 10:30:22 +0100
Message-ID: <CANpmjNNi=JqTsfZAWDg-e4ee2v3rXmHCg7UL7ZvN92yr2Y2vUg@mail.gmail.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
To: Andi Kleen <ak@linux.intel.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=SBU9I7H7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2e as
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

On Sat, 13 Jan 2024 at 10:23, Marco Elver <elver@google.com> wrote:
>
> On Sat, 13 Jan 2024 at 10:19, Andi Kleen <ak@linux.intel.com> wrote:
> >
> > On Sat, Jan 13, 2024 at 10:12:21AM +0100, Marco Elver wrote:
> > > On Sat, 13 Jan 2024 at 02:24, Andi Kleen <ak@linux.intel.com> wrote:
> > > >
> > > > On Fri, Jan 12, 2024 at 11:15:05PM +0100, Marco Elver wrote:
> > > > > +             /*
> > > > > +              * Stack traces of size 0 are never saved, and we can simply use
> > > > > +              * the size field as an indicator if this is a new unused stack
> > > > > +              * record in the freelist.
> > > > > +              */
> > > > > +             stack->size = 0;
> > > >
> > > > I would use WRITE_ONCE here too, at least for TSan.
> > >
> > > This is written with the pool_lock held.
> >
> > ...which doesn't help because the readers don't take it?
>
> This function is only refilling the freelist. Readers don't see it yet
> because it's in none of the hash table buckets. The freelist is only
> ever accessed under the lock.
>
> Once an entry is allocated from the freelist, its size is overwritten
> with something non-zero (since it then contains a stack trace). Those
> updates are released into the right hash table bucket with
> list_add_rcu() (which implies a release).
>
> Am I missing something else?

FWIW, the current version (draft) of this can be found here:
https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=kasan/dev
I'll send the 2 patches next week - they should apply cleanly on
current mainline.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNi%3DJqTsfZAWDg-e4ee2v3rXmHCg7UL7ZvN92yr2Y2vUg%40mail.gmail.com.
