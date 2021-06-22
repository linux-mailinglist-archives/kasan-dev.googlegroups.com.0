Return-Path: <kasan-dev+bncBC72VC6I3MMBBSG3ZCDAMGQEI4XESEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3996C3B0D00
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 20:36:57 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id x3-20020a0561020c03b0290275a44fa036sf12311vss.15
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 11:36:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624387016; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y7l4v0om+9YZQ8tDMJUy4Qfu70UiQWGc0W6/L+lIcK1mlz4ozwnI+2odeREmrBboK3
         j31NFgnlaJ8HlHlLXgZfMjVJ9Nnmdqc+fF8w8IXhiR2MSgjA4unczY8TTKy82gbxn8h5
         XqvCO2QGKl6gEv08dYxUGJq/XxGqxa+f0sbO10PeAtP1VE1oHIlGRSqBazkkT2MNtQee
         /8flzTlrS8v4nOpMOpiIz42SHwIUbopjjDG8Sr8uprQc2s48EM8DZZthzlwxWaOjJ0A0
         88CwRUgRD9hgMimbp88jxIMo2ISod9C1neEwELqgGAP0dYnWJOXEUBp2gwAog7OfyU0Q
         +ojg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=nbZuKQIQbKn5SLXDYG5Jaa+aFEwClF1hOFdb60od5aY=;
        b=jUFB213FYgCxNJoGEfLtNQrjSRxt+nsHTGeMMpsWYp9ZbbGQtDp8fGaXmrnLDcZjJ6
         6eCNdYP92/rJ9dfJwYvnG7f8X2DX50lACSwDXz1siA3KHy+mX2zUnOSp4K49vPa9OK7s
         IqQBvwPDGrC2/TNKGZ0qo0JQXVOgrXRuZHlp9Jam4P434Lrg3ImeOA55UZCOBgkpCgi3
         T5NgFjmZWogdlcWw6C1XxlJo3LFyzIOzy6fIxNq/8K9pEikdQh1F9YTDW50WQGqDQSKk
         kEtaabbthyQUKajGY7wI3W7XrNbCNVOZAyWFIbXg6SPV7M2b9YVyyF/EwYnWTFPe8ox9
         r5Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=o1jHn6o+;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nbZuKQIQbKn5SLXDYG5Jaa+aFEwClF1hOFdb60od5aY=;
        b=IDdo0/WvuKUohtqmXN0FpQ5LtCQBR0xPzw7NqwTusXtI8L4Oy72Vx+NFGfigpK29x4
         9+cUvrmA0+0VRy2GK8uJHRRbmY8W3JROq9DP7JrZQ68lD7HKYC7xg5FScSiD5F/NgP+i
         dfSHfBeuz8BfKetVYhaSBj34sipf20/FMjyelOo+SrjOxXxZSZ+AHG6iPk6/IJDYY/Gi
         BLMcgbQavTV5TMMHyVpV/3yiVqya4hd8qUVFr/rsEhz/31M8xQRGT3CfOWDQqcHdDzr0
         sN3MORe+dJFdd9kMZX9huqrVDBupeMdzRFRfSZldSKtfb8rQgjAPnJiBSgnXYV7eONIr
         zFGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nbZuKQIQbKn5SLXDYG5Jaa+aFEwClF1hOFdb60od5aY=;
        b=rQ9z5k6lJIJ0+vzSf2H2G0RUfJ1a4kbMHx8BxHrfF17/3LIaG5dD5OYQsaCDlE2JPp
         i/QQZ/nboMJWn4O4fXdAeJafcziLoPURNoF7tFGSXTMBIGjHGt8IX9FftqO4duYDmjxA
         hDRqSIm94nl2lkaksBNR6gTPmxwZfTNhpKwz6zuS/LttZvxoEJmMQ4+u/7YQEPe7hC/m
         RfELluX6SIJTJZxHG/IODlOKLdPqtOXs0rGDWcbn6TPd7a/ovxs/Pt1Z3qz/mg6FwXE+
         LbgCQorOzCTfpuQJbOTmHcaCuz71VVrdYeZxoR9PGCF6GduIF7O+7FjKU2WX0qSwvxit
         azDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nbZuKQIQbKn5SLXDYG5Jaa+aFEwClF1hOFdb60od5aY=;
        b=bL3UTZHwZMj27vOi5YxH8ngMS15IW3IDWaaMrZzk6SUBhuXydGDfH6INqyfkc2DgNy
         SKPyj9qR4LDwJC1XqZBoKiGC6Lrz96O8gqL1ugFsODEOeckwXAIIHrRVvPcglTWOzsL8
         wA08bGHrQR71oMQntNkDn6Mx2LXMGiIzr7LodtnQITdcXYxCGm34fo/yWJYQWAtxJOqX
         cCHD0gx/C+TI4kp+0j0mEAYgcNdYE71sAknRaGZnZB6Gc+dn3UvZAjafGJKY3JiRIJZK
         LQWPxBlselO415mqaNmtFTNrPwOLBAWq95XzNaboGp6r5F0SMiqcwwow0rALT04Nfl52
         945g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332vESHa3ysjfRSBsiuITSifHbZDaPggF6pymC3ea4taAVm/eI2
	UN8biC6LV8/u3UseHR1RmhE=
X-Google-Smtp-Source: ABdhPJy7WBpTVSpAxsbdfRZ3WcltjBRdL1hxmEe9mYz8tBLq6HmoDqwl0HXvmPsz8rqjRqTbKDw4pg==
X-Received: by 2002:a05:6102:3097:: with SMTP id l23mr24464124vsb.19.1624387016338;
        Tue, 22 Jun 2021 11:36:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2fc3:: with SMTP id v186ls1450008vsv.10.gmail; Tue, 22
 Jun 2021 11:36:55 -0700 (PDT)
X-Received: by 2002:a05:6102:e92:: with SMTP id l18mr3840887vst.19.1624387015884;
        Tue, 22 Jun 2021 11:36:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624387015; cv=none;
        d=google.com; s=arc-20160816;
        b=enSIZJhWpjrvSiaZcK22LxYMbjiEH1CF5KG7NGLXY1XnEf7H/hlb6gAS6lyAPxzpxa
         /jySNxvTEURFcyMfp24fhrbN2J2X+9UhmHPxQeFh1P2RHZgrnuM4DxJnEj8aSGqJMQUO
         02yFfznQZBnvse6+NIQO18yTWIYKHNGkvFLI1k2QO9rlyXb8Ymx5znTb4XLxorfNaCIJ
         gLf/Jcuh8K1vsc94C/VCnAd3Aa7y0SGBfpvZYxYPK/eMLv27O7Rjw/WSV1QuyPXdb7Aw
         AGAlea1CNnzSGQPInkm7g63HPuWIwntUGTiAUB50bWAEgbVnFTTUqr+KDPfiYkaDr0ZL
         xHRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X582ckIshWor1vloajSsyeHfuFh3jfQXUW3m4Q8smqI=;
        b=xBoOKiociAc6vMuDCwnjf7aFmyZCkaeI6bENn3pvsvplOlcMO5GsZxRxgAGaNzmeIY
         Yeg9+gVslgmEYbffg1TT1QJpxctF4pRNtgc25sy0B+UWE1T9xPELQEy+V/FIqWv2UtSY
         Dzl2sU70+PHMnY4qI11oSsu3D2Z64leg19ReT0nlnrPTUqDByuWMD5PwCmuLErxK8ymh
         PSFL4Wq04wPihCpWG+WGwCmHztCTY+0nCs2ACzTv2LcoehIO71sJlON76o6t3vnkdQt5
         PWPpPgBpI7zJspfFKzA8pr4zqkbN/BLSI8wRjqwCcVy4OV1gGc5L0YVLmHdznql2ISgZ
         RLWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=o1jHn6o+;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe29.google.com (mail-vs1-xe29.google.com. [2607:f8b0:4864:20::e29])
        by gmr-mx.google.com with ESMTPS id 78si147343vkc.0.2021.06.22.11.36.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 11:36:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) client-ip=2607:f8b0:4864:20::e29;
Received: by mail-vs1-xe29.google.com with SMTP id z7so51092vso.3
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 11:36:55 -0700 (PDT)
X-Received: by 2002:a05:6102:22e7:: with SMTP id b7mr24640330vsh.14.1624387015578;
 Tue, 22 Jun 2021 11:36:55 -0700 (PDT)
MIME-Version: 1.0
References: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
 <YNIaFnfnZPGVd1t3@codewreck.org>
In-Reply-To: <YNIaFnfnZPGVd1t3@codewreck.org>
From: jim.cromie@gmail.com
Date: Tue, 22 Jun 2021 12:36:29 -0600
Message-ID: <CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E+4qKA@mail.gmail.com>
Subject: Re: [V9fs-developer] KCSAN BUG report on p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: kasan-dev@googlegroups.com, v9fs-developer@lists.sourceforge.net, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jim.cromie@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=o1jHn6o+;       spf=pass
 (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e29
 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;       dmarc=pass
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

On Tue, Jun 22, 2021 at 11:13 AM Dominique Martinet
<asmadeus@codewreck.org> wrote:
>
> jim.cromie@gmail.com wrote on Tue, Jun 22, 2021 at 10:42:58AM -0600:
> > I got this on rc7 + my hacks ( not near p9 )
> > ISTM someone here will know what it means.
> > If theres anything else i can do to help,
> > (configs, drop my patches and retry)
> >  please let me know
>
> Thanks for the report!
>
> > [   14.904783] ==================================================================
> > [   14.905848] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
>
> hm, this code hasn't changed in ages (unless someone merged code behind
> my back :D)
>
> I had assumed the p9_req_put() in p9_client_cb would protect the tag,
> but that doesn't appear to be true -- could you try this patch if this
> is reproductible to you?
>

I applied your patch on top of my triggering case, it fixes the report  !
you have my tested-by

> The tag is actually reclaimed in the woken up p9_client_rpc thread so
> that would be a good match (reset in the other thread vs. read here),
> caching the value is good enough but that is definitely not obvious...
>
> --
> Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E%2B4qKA%40mail.gmail.com.
