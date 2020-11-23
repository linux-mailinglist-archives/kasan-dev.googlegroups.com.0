Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOH5536QKGQEFH3GXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F21A62C0A98
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 14:52:57 +0100 (CET)
Received: by mail-vs1-xe3f.google.com with SMTP id c25sf2885197vsh.18
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 05:52:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606139577; cv=pass;
        d=google.com; s=arc-20160816;
        b=EvOY0T0iCyY9xF7mXbm1BT4gw8pl4vW1+W4sRD1uHK9t4U0YwsJ8ayvqIeKirg77Ul
         /Gh6VaklYRx5I22wqN477Y08HCFGo8sr1DsTvqJiXOxGOow5Z5rOoBsF2w3WRWK30UZI
         9DCPWEpplVxwfxMDy9+P5al7jvNftg1ewonGLNDMHvoApW3APK9ba6o+mw1ASuu8H3zl
         b3wsCQDUofifcTG8Zo2kdtiUOr5asC6uUp/yUfduTH+cFxzPg3AOoi9GKu14J+DLfplP
         Z13/z6WsCVrcN3nrLdo7AjiGkUfDrsPvzGGoilwz5tGMBtoWJo8cai+3cdp52yDIsmmz
         ErLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cMq8A7UCQyx2Zj4x9aeTmD/KjyjeC2iQoJy2/QN26dg=;
        b=INjELjRn9crgCGMqUs2slCXcpyqOmZ50/no5ne6wIVPwDrxKrfY5zLyYtuSWcMyb8N
         UllMB1BKc5jldNWIHv8rrGTSn769iD6uWK3TjrqPcweetAZBlGXcqSqO43Ncxgg1jeBx
         eq/k5zZkiV2kOhzEAV298mYFmi9b0X8imyHSoP+P3UJ3WcyYDZUMSEkcEH1ArxCBeBrG
         lkS/RBF4SgGG9ixsMtj+A8QogRm163jKW26+iGzXIcno3s8LfTbOc9lCNXQo8uCIRt0H
         XSnZt6ZEAS6Obl/k8luawHCY4rPrnw4KSt54uFWMoaLyDGcNYyjiKQsT+wyJcUarwZpl
         sabA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WwhwzWGg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cMq8A7UCQyx2Zj4x9aeTmD/KjyjeC2iQoJy2/QN26dg=;
        b=OY957NwcbhascGBKhsZcF6OE8ao9jE/w43shK7XpF44QpEdc3t1pY5B92o4VBGVZLg
         N/AcdspDkLuLGYirqgr19GHS+BiNvHDkpSqDvfuenxPEbZh+XdXeqCLm1H22Zv51pBPB
         IHwbwMCYMzi/77JV2dhKh2/cSVTRTkEcb+JFO8ogZeE6CK1d6DKPLATwuFLTbCUpfk3z
         nqhFZYmKqpGDnIsNnosrQfSUfAu62SsHODZ6pVmu0vimM5wC68WBGBLtbp+j/NMi9d0W
         PWmLukFFPqrqzW2YpQjocZG67ClQAw4McCTQLyqRo+5huLTOciRI0TEFp8XIfDllQN7o
         7O+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cMq8A7UCQyx2Zj4x9aeTmD/KjyjeC2iQoJy2/QN26dg=;
        b=LcgrRwL4QVsj57x+b0w0ksD7Vi9aT/VLbZ7boQ3uWfHD1t9a7dFviIpWj/aTyJ/2xw
         nN+iKuxwrWkavUGbkFZgzkxFK5OIS8IpH3znM/ziXhOA1exsxjzCeZsjaP3X+HnzaerU
         5X1nJtc96GfHVPbP0mfz9OUqx4TeoFhAdZsuQSPwY7csjKSODJO/ao/ffvzwLm7b66K4
         U2sTgNhZA8UkDYnlgrc4otKb4clbiyXgwIC97yyDxfoBiJHGBtYP57PEj1A9giSsMAKb
         jVLwKkekKSNnR19nkynnSZwwB1JzF+gPb9ToLU0h8W0OBKdBJXR2vOLyGrZDPmvBnHJ0
         k0fQ==
X-Gm-Message-State: AOAM530n0B/91ywo3ynHmSF4DBFnkPUxqnpB7f5T5Of9g0uZz1nQTE7o
	x4cPcOTTeiX2KwiWoTdAyME=
X-Google-Smtp-Source: ABdhPJy21ktmypbMEY32Awftgnr1rIGFfCvOlHBQHx/+9VAjyOYzBWM9XlywzIjCip4U93mb+X2Myw==
X-Received: by 2002:a67:fb87:: with SMTP id n7mr19737745vsr.58.1606139577051;
        Mon, 23 Nov 2020 05:52:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:784b:: with SMTP id y11ls922761uaq.8.gmail; Mon, 23 Nov
 2020 05:52:56 -0800 (PST)
X-Received: by 2002:ab0:6dd1:: with SMTP id r17mr19060234uaf.108.1606139576453;
        Mon, 23 Nov 2020 05:52:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606139576; cv=none;
        d=google.com; s=arc-20160816;
        b=THh6ox+2FMZD57KyHj/9ba7L0Ddd03gUrXKR/c2ZZziueqYPVlu1WUZv9a8cZBuCYL
         HcCIAvCX1Zado8PhXhSIsRkmhr1/cEzjbi08IUW69LgQ74rna0GFReEV1JeSnVmXl3d7
         VdINcofIN6ZZlm920q2OIGSvdWemSQp/0ELX+8fwY52jgxXnCipU/OCKq1MvQu859Pq9
         znzWRYPVWnSrkunH578WvsUsBX5S/kwoNS6BduaBvakyhcdhz/fmd2IVgRGtxsf7PapG
         Pn5FIuURcLAEaugcUO6SwDVpx4gOxJZnbybnmZ75iPKi3Zq6ceTnVtMxC+57/Fcei9c2
         4asQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=088zmG11B7ENQeStfIt/hKr66YTpt35vQc34h9N/mec=;
        b=vtp1v8SOMfqomOMGVnHNny5ud8KJ5sW0ykZjvZN200gHdbjh3e7vIP0md7yMQ4t7io
         OE3ccf8YpUGIVaJUEzm1chCzRDt7qFzQmot5uZUFysaJoGhGFXRIyL6LK6yep48s1bTP
         ExMm9HbuO07SudnIvinOQrQYocE9CmHezmQzOV2PbtmzGI3EXgfRWHgD3q40VfB6jLzB
         MhhXbSUz0yyAbHSgTGCy8oRK4+OLklp3w4dSjHNZxZ3DDguumb8ipaQRQkMtsOvMTmTj
         8BHZHhG43tVu+MGunHTht//SGhdKv0IXmE3CGjjlR9k1/ySzbrMZjcN8ZPN/nfw+JHKa
         Olpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WwhwzWGg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id f26si515025uao.0.2020.11.23.05.52.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 05:52:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id t3so473756pgi.11
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 05:52:56 -0800 (PST)
X-Received: by 2002:a63:f20:: with SMTP id e32mr27452713pgl.130.1606139575373;
 Mon, 23 Nov 2020 05:52:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl@google.com>
 <CACT4Y+azmp-xczEt5rQmejtrnQ=e9PFC15tOHTjA3nHfgQ5gpg@mail.gmail.com>
In-Reply-To: <CACT4Y+azmp-xczEt5rQmejtrnQ=e9PFC15tOHTjA3nHfgQ5gpg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 14:52:44 +0100
Message-ID: <CAAeHK+xc5zgoaPsE9Xg5H6ZTHhBfbPFAygOxSeoJoTAqc8SH5Q@mail.gmail.com>
Subject: Re: [PATCH mm v3 18/19] kasan, mm: allow cache merging with no metadata
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WwhwzWGg;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Tue, Nov 17, 2020 at 2:25 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, Nov 13, 2020 at 11:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > The reason cache merging is disabled with KASAN is because KASAN puts its
> > metadata right after the allocated object. When the merged caches have
> > slightly different sizes, the metadata ends up in different places, which
> > KASAN doesn't support.
> >
> > It might be possible to adjust the metadata allocation algorithm and make
> > it friendly to the cache merging code. Instead this change takes a simpler
> > approach and allows merging caches when no metadata is present. Which is
> > the case for hardware tag-based KASAN with kasan.mode=prod.
> >
> > Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> > Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
>
> Somehow gerrit contains an old version... so I was going to
> independently propose what Marco already proposed as simplification...
> until I looked at the patch in the email :)

Ah, this is because I couldn't push next/mm-based changes into Gerrit
without manually adding tags to all of the yet-out-of-tree patches. So
the Gerrit doesn't have the last version of the patchset.

> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxc5zgoaPsE9Xg5H6ZTHhBfbPFAygOxSeoJoTAqc8SH5Q%40mail.gmail.com.
