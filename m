Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX5HRWBQMGQE5NQZR6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 402E534EE08
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 18:37:53 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id m1sf14518776ilu.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 09:37:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617122272; cv=pass;
        d=google.com; s=arc-20160816;
        b=zDbIEvXPlsft90xx1c6jtcEJMZZeV2yKv/qIrArYtpyHHS9A8CqbkfXn5MGX+L3wSn
         Uuv1RoH6umgu2ti2V5SONBXgiFnhDkcebSSNSocN+yRgI13JBnl0rfYO9z3+CUtp3u3M
         DOtcBv5w48qL6wErCHQXTEsPJwJ70xIIlAuzH3WXnntWnrudlu5DMoIEmcJ7PAaTqsNs
         Blu5cIM2IJ7sqbGGChHL8uInirOYkeGogfpzgyRALjKmKawB6JT/7yFdNlGZdtF5mntm
         kL+Gwd6DHSxNPZZfnUQ12Iv6Hf56P2yThCJKR6lBje9P9Is+JjdY7wNchoTqlFhK3nNJ
         8gKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hyX7E5PIXCTVMJzkDaVOmsBCWCfkhZBBtUBWP29F6j8=;
        b=cC5LOYEGN9p22els9FeXwTNX5i3wnuKQaThpqGlAxoBarxtuI8I5F11Q0T6QeWyUCF
         rcHIZgngZHs5J9jzTQEMsZK9msOBs2W1tvdOWzscM9se4GcA0QaUQcsd0RjqbSawGhB2
         Vd4++Tuikg3v+utSKjRsOiCRtZF5lQaRudloobfm+iDS9gjLTRFXF3XyO1MnRl10zUO4
         1curQW9dv1Nkh3Mn9goEZdRzRzaV2JOBHXwgBOMbbHATCBi5MOMl1GttI1XtzzlUX+pn
         xWCpjfmhh+u6rg78Xc8Sgr2nf/b7M2B96GEJeIifzwcuT+Fh9qzgKjM6dVIP3T5pHMVb
         244Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JEpuv7is;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hyX7E5PIXCTVMJzkDaVOmsBCWCfkhZBBtUBWP29F6j8=;
        b=oezpi1xS6FYvJlB8ezM1k7jnyUwET05EzpfUjNCfjQE8wP7rbS/ztkUL1YidKd1gmv
         CGjQg8fHuRneTIKOh3Tqnqr0fHsKqQnWHP04Cp+C3WccSadGVzGLjDJ730My7zgc4L0c
         1DxX38GD3fxle+6Gs10RvAON6ASCNeR5Wa4wn0rW6PgRR6DAyjH7H+1RBS1FqvZ2xbSJ
         7Y1GHezTFi3yxUPyR5kVYJjSLpEYfBDCTRFIkQlmUMffgV6gH6xPgM0FOUxjyKiBtpg9
         1NxBjIDpC80+7xBHqQ93SsuqA3SWlox4bqn//Atq4/Rn4dHnz1X+uaayDAu0EY3y/xE1
         XBcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hyX7E5PIXCTVMJzkDaVOmsBCWCfkhZBBtUBWP29F6j8=;
        b=EyDDXIQ88jAZtNs9Hm8ChxhfJPBOm63jSfSJ59YZIXsc+XUDGRDT+X9+M4Vky04RxM
         ymBI9/bUXCXDozGzm7DNo2GHBWp+l4/NAfw2Xbn538SFqHTflVn3JXo6I1P3YbOF19lC
         hQi/c5bxoFpOSGEfRw1OJ0DT4sgdimQtEDdTVG/R0efn+D4NtJThc4XOCWQAGeAuZuGD
         y3oRrdq19PWgdJSuG5PILdB7M8FDdv9VBQ9in7fp930jB09pXf3ZUIg2GuQJCh1JWma/
         1pxL5gnVw7tNHk6Xva5HyzLEK5gpW0ViwSblWohj+7kQLellZ9I8ChcZ/pBYjSdbgVMK
         PeiA==
X-Gm-Message-State: AOAM531ejrjpsL0xfNi8ZJrBTHyFFHDQoMlhsVv0NbO7AivXM0IIQQ9G
	aClxFnTAK7GUErfdDuTpOeQ=
X-Google-Smtp-Source: ABdhPJyPbHbU3L6Sv6deQnjauJHAqLmCTYLV+ENAROTUBqH1AHv0DQwVRKWme5/uRhcBkJ9ew6nrdQ==
X-Received: by 2002:a5e:990f:: with SMTP id t15mr18090120ioj.180.1617122272037;
        Tue, 30 Mar 2021 09:37:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d40a:: with SMTP id q10ls4595614ilm.6.gmail; Tue, 30 Mar
 2021 09:37:51 -0700 (PDT)
X-Received: by 2002:a05:6e02:20cd:: with SMTP id 13mr9186217ilq.126.1617122271769;
        Tue, 30 Mar 2021 09:37:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617122271; cv=none;
        d=google.com; s=arc-20160816;
        b=MJdZ3BCNMwWfTBmlU7clYDGkyqBwNNx1Cmiqa7/yHJYtPgReZDBUdyWfPquB1PDKEM
         Hy5ZZbwD1cDqnJ9G5Lup9dP6bBHi3dvnoXmNkRR7KetmcYyQmDp97qklmTOPRHsRjTYU
         +7CYsgxDBfKOYbm8YcHA+GDkjaYvZ8d/I2b+9dRDRHo0oDXESkEprLinalSLi9ek2GGt
         3B9kl9tYTKWINBKuyvff8eeWKzph0Lkr97rYG5ELaKZaISaoXHBKfEVbIH9KPpcuPoci
         BgFZtmGebsIlcWnadAgCCZ3YA8m6wLDaiKPiZCbQaRwzOyfGzD32d765SOZFWNZejo5H
         xpMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2bFDTkH9JcEDOzccCJHbuAcdTPMMRb2IauyOAtWvukU=;
        b=fi9czZIqR4xjZ3ZB0HMZETOTRjxDKfyohIRgzgNjxU48o1w+qGwmHfqjb63dBrKSXE
         1zwluzQUOZK6TZKKVLJ2oLPv9vEBUYtoCOP55JK5nhwWn9TOPCJ2oRbbsFoeNmnC9VLM
         ouHuqmomvbCMMW2XHbbi7GTt6Yx3iPAj2Q55B2c2vUOw6IiDjWEOLd5rJVJ/FPW3XWmT
         wt5kYS3mQ4f2Obnl+u3u7PlauExl17Gf12J6qOn9kGyx5YBCvdd6NKSuEZMgw0r7z+sM
         C/9bxN8qQ5kJQe23rxQmM7OKoUOBj9WXH9zb39ux+cpuvUtax9G35lv/sJVqyHTcpXXS
         SAfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JEpuv7is;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id r19si828006iov.3.2021.03.30.09.37.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 09:37:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id g15so12542144pfq.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Mar 2021 09:37:51 -0700 (PDT)
X-Received: by 2002:a63:4e47:: with SMTP id o7mr16220027pgl.286.1617122271157;
 Tue, 30 Mar 2021 09:37:51 -0700 (PDT)
MIME-Version: 1.0
References: <2e5e80481533e73876d5d187d1f278f9656df73a.1617118134.git.andreyknvl@google.com>
 <115c3cd4-a5ec-ea4c-fdc8-a17a0990bd30@suse.cz>
In-Reply-To: <115c3cd4-a5ec-ea4c-fdc8-a17a0990bd30@suse.cz>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Mar 2021 18:37:39 +0200
Message-ID: <CAAeHK+yHcPQFP83p7-gPS4zC0NmhSWasxtoQU+Lz+py=QvKV-g@mail.gmail.com>
Subject: Re: [PATCH mm] mm, kasan: fix for "integrate page_alloc init with HW_TAGS"
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Sergei Trofimovich <slyfox@gentoo.org>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JEpuv7is;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::436
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

On Tue, Mar 30, 2021 at 5:54 PM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 3/30/21 5:31 PM, Andrey Konovalov wrote:
> > My commit "integrate page_alloc init with HW_TAGS" changed the order of
> > kernel_unpoison_pages() and kernel_init_free_pages() calls. This leads
> > to __GFP_ZERO allocations being incorrectly poisoned when page poisoning
> > is enabled.
>
> Correction: This leads to check_poison_mem() complain about memory corruption
> because the poison pattern has already been overwritten by zeroes.

Ah, indeed. Will send v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByHcPQFP83p7-gPS4zC0NmhSWasxtoQU%2BLz%2Bpy%3DQvKV-g%40mail.gmail.com.
