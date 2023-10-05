Return-Path: <kasan-dev+bncBDW2JDUY5AORBLN47SUAMGQEZ6SKDUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF66B7BAB7B
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Oct 2023 22:35:59 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6c4f69456aesf1796918a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Oct 2023 13:35:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696538158; cv=pass;
        d=google.com; s=arc-20160816;
        b=dwMZI32PX184rtpZf/YQp0EukEeO8uSAzkXA1+igJYJL1C3gLtrN3iFTLGcbHzuOK+
         tjp0ybfr0ibGtYsy37THzfYoI5frNAjTrbbqnTdZgbSnUyb6D6Wv4t6WnJsc7X4x8q+c
         3XBSZj0HQwsthAhucroyYKIIeTAQzdaW6FEvO1zVvzk3n5DLhjAN9N2wyJMB50wRo7jn
         lgxJ35oykM1nMoHD62gFWNIRYKlAvoIzTsbiyyuMkG2LwebSB1aWlMxBgizE//Xt9Fkq
         wMbtatG49Vnc4ZUq61rn5NPxZGE/wTMWAefjhoDHare/FzToMi0dodCPDXEHqaI3sqBM
         kgnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=AvV4MNw6/Xl6u7VDGh1FQhQxOBUyKtAhB6bIZ9/6VSk=;
        fh=TIa2X87mE4UHMKDAmhIRCmKTwDakJ0nJjDODmaarSK4=;
        b=N5gAQUiJy+0su2gavQtMdImWCXXher2frWfntjO6K8yTQvs2mOnzMeEDI3eCDRFqf8
         NF/RcuValjHh2RfrBDBLBWhFyZ0pCPIVFy6XbBYwb+X+NawWmPOVKAFSCUJD/Qlwo9KJ
         DgaUgtVoEYfsI5Pp8m4RyzrpMf23G0huqS8TFwrEtp3+eYYoZYwCmo23E1dqaCJlDI5W
         LBQhhX+mEK2axdKBvo4EU4wIdINi9HNuqI0XzwE/2b15lISGOyjl9djhYv6Al4haWznO
         JYS48q1j2e+FVTafYBMgGwhPXPF0zY3dmlwLWUf8MbJlJO/a6j1s2cGAA3weagLhrnuJ
         oOzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QwHSdvCl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696538158; x=1697142958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AvV4MNw6/Xl6u7VDGh1FQhQxOBUyKtAhB6bIZ9/6VSk=;
        b=NjOxjAVsuKFSfoNmkyliQPYg4gZfzls/4SV+f35WWCFu9iBVGdIlVU/XruoYxhmKOe
         bt4Yobg26SG/lX0Dzyku4WKY2sZwXZPifPMBzHaIUX5Yi61vf/HCY4HZEB4qz+ocIBBi
         dojxT6rn4Hhqmet2U+eLfRpw+NbU5wjTVwOQiEiNr1VmpuCVh1TK4cy9jR/QPCWsGf+w
         3AayXQS4V2Rr4RUDAQn81JxYRX1NQdkq/hKMduqkuLUZuHVfNMLmIqFyAqY9ggkIYDqj
         HISarIPc9Dz5r+cr4/0XbRAELdssSX/2k02PGHXyxdKp3DlsGnL6PkB2mnMl0OdHzcmE
         x1Sg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696538158; x=1697142958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AvV4MNw6/Xl6u7VDGh1FQhQxOBUyKtAhB6bIZ9/6VSk=;
        b=esvBY/mCYITAc7y4TrMv7sZf7BFrxkzRJn56V6+LlQkN20xmF2JJwwzBkQsWxNf2yU
         LZQ4VLBbRrwaBQjv0pzdk0AFuui3VUI2Np1lFjGO9l2KbR9mO/9ofSzffevT5dLpt5G4
         N3vebMhqV4Ldj9OAZmmjNZL8VT3AY3nxYvzzOvL4FkxSBSUFvDaMsLKXjPB8dX06NE9a
         b65d+rbtspSUmOxnzDnOI0pei+84W1frJD/ikTqrGvTDqIUgcgy2fj/vfIxoPBjxSfDy
         Wa7dO8x1LGJzKxdTHaBeAkJ1cQNoauPzr00dSDETfpVOlvXdxo1WmlqBJjGQ0NHhbYc6
         K7QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696538158; x=1697142958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AvV4MNw6/Xl6u7VDGh1FQhQxOBUyKtAhB6bIZ9/6VSk=;
        b=DNVVRtT6j5Oz1b2siqXMdeh27b8yJVYUwNDRJ24D//wbJpCWMo/ZY0kBxxRQHBu0P7
         w1kxvCgTW+nOEBc6YPLvwUcuNtKfxWH8hfoghzCNtxJw5TCBnn2RRR3DPW4SMw9H90ZV
         mMoQpPQf+wJ3zLAF8V+avZh7p58dH/xi8qcUK84YShIz4EbKso8Ku+GM9uYVVGfvZDjJ
         W5oqOQSVM3pbeQLngySbt+Sc81GVpve7Zeb/sDCpWo9snh3E3ivA1HwZsdUsywRxBoY0
         8YtZg6ZNHK+2V9PnClY0HDH98P3ViDTrCJU8jBSX/y9GxqLikXKwLBWbsaME9VlNKUKW
         2eOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwnrJ2aW0B0F+AkOT5tWGsEA0u0kmKlGJgGJGwrgtCyD518qWZY
	DyBIeoWpJoidQfcS/i1XZYI=
X-Google-Smtp-Source: AGHT+IHYUE5j+ttRAIFhD33bHpN04JSo6W6ahHvcE0M/JQWXNo+ZgRmgfN1fx4U6Knwg8SjJerYSHw==
X-Received: by 2002:a05:6870:d0d5:b0:1d6:439d:d04e with SMTP id k21-20020a056870d0d500b001d6439dd04emr6600411oaa.53.1696538157759;
        Thu, 05 Oct 2023 13:35:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f594:0:b0:646:f0a7:568f with SMTP id k20-20020a0cf594000000b00646f0a7568fls1237121qvm.1.-pod-prod-08-us;
 Thu, 05 Oct 2023 13:35:57 -0700 (PDT)
X-Received: by 2002:a1f:e2c3:0:b0:496:1f95:209a with SMTP id z186-20020a1fe2c3000000b004961f95209amr5217209vkg.15.1696538156895;
        Thu, 05 Oct 2023 13:35:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696538156; cv=none;
        d=google.com; s=arc-20160816;
        b=nrQ2aPH749mTutsmfmUiywANoFB4773mcWDg0BA3y2QWlg1O5gB/EDfGLZVTA6OvCo
         me18IOVXKR6My0fJuIepNuZeI+JhXHLOBx2eA9Ph7uvehk3B+vXnYe68XlQ8aZDQfoag
         4L2cOLErBxR2RZ3sAv96VHeofqCQgF1q27A5IpAmM115rVEXnfEA00FeLF88O+xJv1R/
         dSoE1uM9qr4ZQcAQydKNQxWRrqhU0FZ/BWhsmTcy+c0zOXI5ZxB4JyQ9NqzAckIJQQVB
         Q3JATHLlIe1NFp9rxQyu1wXiHh6lDydHAQCln2/HFUHb4cR9+odc2WfSmHiVyrTigPH7
         elhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fshyiHld1iaT92zV4X7OYvw4ri66Z9VzIvd68VZWy7U=;
        fh=TIa2X87mE4UHMKDAmhIRCmKTwDakJ0nJjDODmaarSK4=;
        b=Tsj1PlmVLd2LfqN0wVAqq05QHUH4milhHPwibVGVfW3qjYmGpPWZCPj//VIJWZrY4o
         VOlVIq/jh7RmrvQtAOus67fKSiimN2C99OaSKFnpWSKE7yJVcIS2qoAtssMiFPU69tYq
         zUAt5oudJi0P2ZgruV8RbvyHWtb3RXlgo3FsqVK+PnahErFDPWCG3/c6T0QSCio2fJMX
         g3cy5m7zlYVGbu1At5+wi9a6wiwUWN+pbyztfswCEhoXkANURISOMSbxEZS01z0PsZ1d
         /lL+ksSpbUhaQ8p4Xf8r/VnR18y9Q1eLpXSQdjLrSC3ZUnl4dtr55CWTHwSxRL/wl6UI
         QFFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QwHSdvCl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id di1-20020a056122468100b0049362af6c50si71243vkb.5.2023.10.05.13.35.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Oct 2023 13:35:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-5859b1c92a0so1008232a12.2
        for <kasan-dev@googlegroups.com>; Thu, 05 Oct 2023 13:35:56 -0700 (PDT)
X-Received: by 2002:a05:6a21:6d9b:b0:14b:8023:33cb with SMTP id
 wl27-20020a056a216d9b00b0014b802333cbmr7689179pzb.11.1696538156295; Thu, 05
 Oct 2023 13:35:56 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 5 Oct 2023 22:35:45 +0200
Message-ID: <CA+fCnZckOM0ycja3-=08=B3jwoWrYgn1w91eT=b6no9EN0UWLw@mail.gmail.com>
Subject: Re: [PATCH v2 00/19] stackdepot: allow evicting stack traces
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QwHSdvCl;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c
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

On Wed, Sep 13, 2023 at 7:14=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Currently, the stack depot grows indefinitely until it reaches its
> capacity. Once that happens, the stack depot stops saving new stack
> traces.
>
> This creates a problem for using the stack depot for in-field testing
> and in production.
>
> For such uses, an ideal stack trace storage should:
>
> 1. Allow saving fresh stack traces on systems with a large uptime while
>    limiting the amount of memory used to store the traces;
> 2. Have a low performance impact.
>
> Implementing #1 in the stack depot is impossible with the current
> keep-forever approach. This series targets to address that. Issue #2 is
> left to be addressed in a future series.
>
> This series changes the stack depot implementation to allow evicting
> unneeded stack traces from the stack depot. The users of the stack depot
> can do that via new stack_depot_save_flags(STACK_DEPOT_FLAG_GET) and
> stack_depot_put APIs.
>
> Internal changes to the stack depot code include:
>
> 1. Storing stack traces in fixed-frame-sized slots; the slot size is
>    controlled via CONFIG_STACKDEPOT_MAX_FRAMES (vs precisely-sized
>    slots in the current implementation);
> 2. Keeping available slots in a freelist (vs keeping an offset to the nex=
t
>    free slot);
> 3. Using a read/write lock for synchronization (vs a lock-free approach
>    combined with a spinlock).
>
> This series also integrates the eviction functionality in the tag-based
> KASAN modes.
>
> Despite wasting some space on rounding up the size of each stack record,
> with CONFIG_STACKDEPOT_MAX_FRAMES=3D32, the tag-based KASAN modes end up
> consuming ~5% less memory in stack depot during boot (with the default
> stack ring size of 32k entries). The reason for this is the eviction of
> irrelevant stack traces from the stack depot, which frees up space for
> other stack traces.
>
> For other tools that heavily rely on the stack depot, like Generic KASAN
> and KMSAN, this change leads to the stack depot capacity being reached
> sooner than before. However, as these tools are mainly used in fuzzing
> scenarios where the kernel is frequently rebooted, this outcome should
> be acceptable.
>
> There is no measurable boot time performance impact of these changes for
> KASAN on x86-64. I haven't done any tests for arm64 modes (the stack
> depot without performance optimizations is not suitable for intended use
> of those anyway), but I expect a similar result. Obtaining and copying
> stack trace frames when saving them into stack depot is what takes the
> most time.
>
> This series does not yet provide a way to configure the maximum size of
> the stack depot externally (e.g. via a command-line parameter). This will
> be added in a separate series, possibly together with the performance
> improvement changes.

Hi Marco and Alex,

Could you PTAL at the not-yet-reviewed patches in this series when you
get a chance?

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZckOM0ycja3-%3D08%3DB3jwoWrYgn1w91eT%3Db6no9EN0UWLw%40mai=
l.gmail.com.
