Return-Path: <kasan-dev+bncBDW2JDUY5AORBIGN4WPAMGQEQEVE7TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DC6C683607
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 20:06:09 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id c5-20020a544e85000000b00361126f6443sf6654028oiy.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:06:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191968; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3IhnSxgpXnxzeW+C0+6FFqRxhde5icEatASgEYUKNOfp338RRv5zk7fXXczkn54dZ
         OaB8X247hMyqhKrDQ0os/19G4ATueTXeoEVW+ydORLyMlkht01r/GRrJPRO0MnOIJ1jz
         EnPkkDkF//Ky7vYq1XHukJZD3qg3KeiVi66DDacpccCzmcot4jzTxIzosLN4RZRIpPAH
         UfGGC9XLiCC/4YwNHpagrhcEKNbnJcRfSygoZ0kXWECs/EEdeb5m/2xy8K7uHqcf+vLf
         jZEoLdAPRa739OIyFXFG5RE8tJ5RXBn2XpbMpxijFhgOoDPG7vMLRRXYNo9Ds0oIRa/T
         Ps1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=FnorJ/hiHYXEGblnNTCbFBsvv1Vh1ptjn+HYfxMy8UU=;
        b=XsLqnOaX4WdvFxA8Laz1m6UkkkxbOBw0yptwkFFgWRpO9PrAAJ1A9lW+OAxPOFbZ/g
         fnmuDZP8vLx5UpbGGgCaqsagYYRk4nUEjjwufIDbtYt9BdEQCYM9ptfdCa9oi+uUs4k8
         KMai/bO1XROP4Km25I4bRfYnD9P/dlB2GNIzoj3QcnGELbjOwVYr65b9zLcx20KtRFEM
         yQZyScf46k7p0L+DqSD3hiaYmHcwh8HpTd/3OokExkr2UGET/vHeEJugApzUbIJgb20F
         irSxvYpjVx1H8j9LIvSqeB5T88vK28dB7nTLoM4C9MaXTC4GI83qtRp/cWCElsl3E8PQ
         5JJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RFEEyNFB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FnorJ/hiHYXEGblnNTCbFBsvv1Vh1ptjn+HYfxMy8UU=;
        b=Exxj6cWZY2U+un9L+uT8+Xh0xivIPnv139riRCv4bECwKZaRapWoEJmxLPQEhF9Swa
         rQA5rgy9fOQrQek3Sb6x50KrQPyH4PQNdo5YXg3+SM2zMsckKlmO+mx47nM0JZLIQUFg
         6H33UnCKilTWfOh6VpIPX1pgmfQpKE/SnClK45GnKDrspzd/NYWSjXIhPQpIweihuuMP
         P9pYFDuR37c/Ao5zjDGLEejz+3/oKi9VwaRdsbtTxyoDv8cq/gVXzgiptQmBRJ08VUHO
         q58H8aYyOLeaEL12nH0rhaGVzO7iB0rcH4jy3OC+IDNvmxeWu5zjHnNRCukh4mkR3VJs
         +Ghg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=FnorJ/hiHYXEGblnNTCbFBsvv1Vh1ptjn+HYfxMy8UU=;
        b=NMjfBKKMTeOoNCcwmijowktwtHHDWhLc3XDS5L/vddTK6BDQ7eCpCkdY/flULZ6SmT
         0bmApCmOSLJ+w5riWCORMEo4yeA8BbpSeTWGmmj6H3yvAvLxQKPI5rI6VQWNt7QzRfpp
         k03uRH8UMjKbeyYgYW2YiyjcwL1Goypu3BBR9jvRpgEHfMQaFvGVUhOm9cy+bucM6dy5
         8RDil+jVCSGl3eS898v0orZlE3di5TdALgoB69KLrJBwH229jo6VsP5XHohjxd4aF4zZ
         AGviQ0zsLXy+XKObsTK0t6MQwIqFGuvIJRLTt/jAwfHtVXSnrD40KTdiJf9NYFyrLadL
         2sXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FnorJ/hiHYXEGblnNTCbFBsvv1Vh1ptjn+HYfxMy8UU=;
        b=0PrZDrySEorJc9Iybvm2SKDVAihYdpPL6wRs/SLSfUkZJK6G8ApDn3gCRV3URtZm42
         DO9zhqFiGeFmqtxjDXzLUuWa+cCRD7tiT1SOXfoV5ifO1XvXMW98PbDxaUXsv6ugE53v
         B80qY4zG+4MYwouhB9vqJckzdV24yyPS9rSPDnJqs0RGoOoiEDgWrJCGaXEUwAXJLtdP
         lZb8V+imaocXbGREOYGlH2YTw+/fzS3bDjV5rrC9Ya9Cxj2W0mCszHFLJ21xbPeYlvXW
         KidXSDqnzLLsnHjaL+rY1pumXf79F1F9p0MD6PDL4cvd0v3jrj0b3B45Xv73//q1nTnF
         ODOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUwI6Q77JYY6RkPL5eZITmhn1ayr8Y3K/5WCqbTv9JrMolQf3OR
	uKT3QMB8gHESDoOkV4Ch1gY=
X-Google-Smtp-Source: AK7set+JgwBwxLF6NSamCeW//9dNhtT6OZVhQsbDqz6+zbWY+H/2Lnrw6VOFebGNJT6Dbmad2pFxQg==
X-Received: by 2002:a05:6808:1390:b0:375:7bce:3201 with SMTP id c16-20020a056808139000b003757bce3201mr938959oiw.202.1675191968189;
        Tue, 31 Jan 2023 11:06:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1cf:b0:13d:173c:e583 with SMTP id
 n15-20020a05687001cf00b0013d173ce583ls7107143oad.0.-pod-prod-gmail; Tue, 31
 Jan 2023 11:06:07 -0800 (PST)
X-Received: by 2002:a05:6871:212:b0:14f:c8ca:df03 with SMTP id t18-20020a056871021200b0014fc8cadf03mr533075oad.44.1675191967798;
        Tue, 31 Jan 2023 11:06:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191967; cv=none;
        d=google.com; s=arc-20160816;
        b=votYEGV7fgfeUQc4dcF8zJVGBcRd7yoytGFZpIjYdqzO5vcHnM2fPFIC6YYCTCLs76
         n/eR79fLboNTIirmjUopvAY59uB5vAEPh2Qiyi92LWFFFbqHRiA1fjP8SC22v0xyQfkk
         Ygn9pUb4Tj02pDdwabSrX2xosMTIqywzWHq1ljx2NjZ0zaMR2o7qDJ2CVSV1KgdGVJ8H
         Hj+REP1D6UJ+me7CZKNN+tNDubZG12rG6iSUioVkC0H2/q/LiVsNvLD99zlltRC27Dn3
         +vNyFNbJfBxbYDTVlbfIplBfBO/kJdQAqE8jKr0jhlctbMQ8aZZEpvq2Jvnxpk7N8bj6
         ckCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k3nPPwIeG38k9HpNI9M5BUtMRo8jsnar37fO5F7Z5gc=;
        b=FEXIcBc3tF9JQFf98PKza4p/9ho2b1X1ZmvOjQY43DxanDruKsGEqmZx7V9449KVCe
         zteWVmQWU9Tjq96dH01QBRdQLRLuUqTSFLGcLkoArG53UsZFeKn8+5sbUzW1tH9phlIQ
         EEvxW7kFKNTRg+H+A0nEIde7Bn5EgSFyx5iHxXfwVXCp3szI58Tetow21QGrvuXcFONh
         VeUcmaKdGuF/MzNZwZwKbUoXMrnV//vRAVN/F8M4iDag10fN1ybgpf1OLb7f+3a0Flao
         4j6uaew/j+gTV4t3OawyXDCXG/qgQ1dxmlwV5ikntx76dHKNYgRU+W/v06dGc2HpwDpa
         J6IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RFEEyNFB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id sc15-20020a056871220f00b001480308ea6csi964014oab.0.2023.01.31.11.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 11:06:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id c10-20020a17090a1d0a00b0022e63a94799so5203220pjd.2
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 11:06:07 -0800 (PST)
X-Received: by 2002:a17:90a:9316:b0:226:e191:4417 with SMTP id
 p22-20020a17090a931600b00226e1914417mr64670pjo.16.1675191967117; Tue, 31 Jan
 2023 11:06:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl@google.com>
 <CAG_fn=WxZf_kfn8-G8hvoxvUT8-NKNkXuP5Tg2bZp=zzMXOByw@mail.gmail.com>
In-Reply-To: <CAG_fn=WxZf_kfn8-G8hvoxvUT8-NKNkXuP5Tg2bZp=zzMXOByw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 20:05:56 +0100
Message-ID: <CA+fCnZdOFOUF6FEPkg2aU46rKYz8L9UAos4sRhcvfXKi26_MUw@mail.gmail.com>
Subject: Re: [PATCH 11/18] lib/stackdepot: rename slab variables
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RFEEyNFB;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jan 31, 2023 at 12:59 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Give better names to slab-related global variables: change "depot_"
> > prefix to "slab_" to point out that these variables are related to
> > stack depot slabs.
>
> I started asking myself if the word "slab" is applicable here at all.
> The concept of preallocating big chunks of memory to amortize the
> costs belongs to the original slab allocator, but "slab" has a special
> meaning in Linux, and we might be confusing people by using it in a
> different sense.
> What do you think?

Yes, I agree that using this word is a bit confusing.

Not sure what be a good alternative though. "Region", "block",
"collection", and "chunk" come to mind, but they don't reflect the
purpose/usage of these allocations as good as "slab". Although it's
possible that my perception as affected by overly frequently looking
at the slab allocator internals :)

Do you have a suggestion of a better word?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdOFOUF6FEPkg2aU46rKYz8L9UAos4sRhcvfXKi26_MUw%40mail.gmail.com.
