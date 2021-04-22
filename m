Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOFEQWCAMGQEHCDJTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 711EB367ED6
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 12:38:49 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id a1-20020a92c5410000b02901689a5cd3bdsf17975478ilj.21
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 03:38:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619087928; cv=pass;
        d=google.com; s=arc-20160816;
        b=AEerluRZzNWqzlM//+Gd9ba+G3jRZbw2cRASY0hBzmTnvWzNJRJM/Yb2uL+w5SgDAL
         7Wu52u86wVqOKJs8tbAOMiEzUDoYfs/AYSTK7Ls5IYaV+NV5ZPgs0CmNztUdgYLOXCZT
         Qr3JO5iRs9Rt6guA94QwIxeqjdhuyNnWiLj+0DgWz6huUfxPtVvhv8J3EPIi93R5hO1A
         31xR9c1lC6oUVQQkMj+XrpHDFFF3u+aePeWXSQF5LLsPAzxBOxiClx6fNYgQNW87JHVR
         JKOXux3X4hMkpje8mvnfDAkYV8ZMmtj23ki/+AwJ+b5uI5fANKLJEH3iBY8B/cQhGNS7
         1Eaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c/QVEMSAOkYiQuM7Jr6h+HcKqCJfy3BeGjH8Tz8IqCY=;
        b=UYrtqeO8IqO7qGc4q9CQ2m+2i3D0mJsA2YuAms00ROhQReighPRerR70KBZ/Gdfb0X
         hUo1qFGQeOxDL2ILhmAchleYmlgSR7FBn8X0R06dafaMY9hVbzdkj0iwhbiOolJhWvLh
         z6to2AHIG1GTp0wu4eaaGQrMZ/xg/Hubl2APXZanMQzwGwYZ5h31oL+tezpyUwkHcWn5
         gw4fzE+/XjTWB1xzMyjTlJYW4Dodi5WNym7ULmkcmQYUMxF/02Y0o5o0LYHFwFn5Q9yp
         8/bm3SaMhaImtf0hLwmcOzEpKQkVM+GA3fxroPrPFWemhHINRncey2q4PWIu0KZougES
         /0jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y6LzoE9M;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c/QVEMSAOkYiQuM7Jr6h+HcKqCJfy3BeGjH8Tz8IqCY=;
        b=LLY97OJKDIYoYm4JQnZHqhom5AcFPulHB+pqjCSHmpF2gmitI47SHi6MOlV2j3n/Ko
         UNkSb/y2Ki3QcrWmvUtgOD40ycfiO9MZH0sa8E6Vl3xd0BxJAcqvEhxjUJbpAKNB7Ab8
         Vwrk/Md3qD4Jns/YkeQb7pohVDeS9Q465KayScv7ATLaGz1Vcmf+dIGenJ9WssLGWEie
         WdMux4Ci3LR2pIVQ75XmpJUogbF6EeoOXfFfzLeyGxL3/1e1QAwrNitCOdQMe4+CCgjH
         /94BTBT0TGnkTQsdxai8LisyqWSjiOtoRxA5napFkWInAYRWd/5VcYLzqr1HVRpsLkwe
         IWtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c/QVEMSAOkYiQuM7Jr6h+HcKqCJfy3BeGjH8Tz8IqCY=;
        b=HcLrz0F32Uy2WJ5K/CKO6oPRKj0KnZZTG0pEnZBeBxY4GrDQTBfPO2Oxz7vGm91UU1
         /nRgPL8S40t+hGaZNF4lsyfdHt/gDUH8gs2heb1lfuXRlE3XysUrdfoOOv6ewctbD0uP
         8f4GOxas7oXRF30uHvsYAQAbBfJ5PVtKtmz/X4moIpzgqToa6zW1JTaSDH0zV9ikfUJ6
         y3piTyodlKoU+Q2HLD+4bTqfqQPT9rBkGIef2upshoO+N76FHrLXpb6TmTtMVCdaN/DM
         bs3N7iM6rxHSfeOo9gP43lwg+BoBw9AQ6fT742fdFQOkDjhXpyINvdFReGGN9GIXxydr
         fmVA==
X-Gm-Message-State: AOAM53272TWdUGu/5A88GpWOYCpveHK/vO1Ct7c6zXJnU6jXIwbd1Kp2
	wyUHCMNn1CCihENQeB1NzQc=
X-Google-Smtp-Source: ABdhPJx70SiYBl0cerhMsjhK7sxewxY2MZeg+X1Aw9pVNTnJYMc50OijlOeD1WBZr06u2E0d8k0JsA==
X-Received: by 2002:a5d:97cb:: with SMTP id k11mr2211761ios.204.1619087928296;
        Thu, 22 Apr 2021 03:38:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9382:: with SMTP id c2ls942555iol.9.gmail; Thu, 22 Apr
 2021 03:38:48 -0700 (PDT)
X-Received: by 2002:a6b:d213:: with SMTP id q19mr2154051iob.203.1619087927968;
        Thu, 22 Apr 2021 03:38:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619087927; cv=none;
        d=google.com; s=arc-20160816;
        b=ejl+EZI5ijJOIxgTKTIy8mLZIeUyADFet3L3qwKbR5J3EqJi+NaqnUpTNaXAOtTf8o
         f7cisgBuM2fwGPlpcuPdkpks0+PNqp/T5rC/k1fFqcPAQrafk66d8fS3uFi+vMq3c1UV
         UEgLpoWPwj9CICQsf5U5Xwcng2m0ZkmkSShTfAUsb6vQ/GnfZnVd67HyIincUYX8eIkZ
         5JEHETkWiruHToZh3YPHC+LzeDObkdcrAXpDlMCW58yWqoxCDyb7mf54FLbEVBsuWlor
         NVrtDOv5Wd+XYHIdME9n1ZsfOpE7A56zKC9CqI4EEbFTjev3ufZu/Mm/ikjZzaH41xnr
         4KwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+J6itTyY+KkRgMA362LXOYaefIx+9LEyUZfAGr8mPwo=;
        b=rbAS9k2Xqg/pI2opT2NUs1pZKq0sJt2NxxHULJUQnmOLHmMkJkmm41di18WFHRr9q6
         50i8NjnbA2WQQ++QaL4q53+EhnBf8eODEQyMS7bNCkrsQnyvOSlehTrFesP+sbKPARSi
         uL5m5OqKlxWXTCK7jcEmMZ/ifSHHjCCNyskmIb+AxwpsqtPFF2R3vvOuJFuuFZYvjetF
         FW6B8S3g9NfOHdn1q7m/kiG3Cl7qMT26Y5QJhR2AKC5ThYtuxW4sXIx/cSPZccwABwct
         zO2KKHxz66c7Uft3QuXe4B3UBEueqmmv7kqEn7xljbHmdKW9Xm5LP4ShKSo0jfhPbW3C
         Fy1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y6LzoE9M;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id d10si356804ioi.0.2021.04.22.03.38.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 03:38:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id y136so13660524qkb.1
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 03:38:47 -0700 (PDT)
X-Received: by 2002:a37:42c3:: with SMTP id p186mr2972199qka.352.1619087927256;
 Thu, 22 Apr 2021 03:38:47 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a@epcas5p4.samsung.com>
 <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
 <1619079317-1131-2-git-send-email-maninder1.s@samsung.com> <CACT4Y+ZJ95KiFNHeT9k0p6ezDz-apkJVp586UBSdJeHtCYR_Qg@mail.gmail.com>
In-Reply-To: <CACT4Y+ZJ95KiFNHeT9k0p6ezDz-apkJVp586UBSdJeHtCYR_Qg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 12:38:11 +0200
Message-ID: <CAG_fn=Xdx-hEna_S4u4nRXYXW+HrJCcyPPiGqQoU8Ri1UYZu0g@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm/kasan: proc interface to read KASAN errors at any time
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Maninder Singh <maninder1.s@samsung.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	AMIT SAHRAWAT <a.sahrawat@samsung.com>, Vaneet Narang <v.narang@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y6LzoE9M;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> Alex, Marco, can the recently added error_report_notify interface be
> used for this? Looks like they are doing roughly the same thing with
> the same intentions.

We've recently attempted to build a universal library capturing every
error report, but then were pointed to tracefs, which was just enough
for our purpose (https://lkml.org/lkml/2021/1/15/609).
Greg also stated that procfs is a bad place for storing reports:
https://lkml.org/lkml/2021/1/15/929.

Maninder, which exactly problem are you trying to solve?
Note that KASAN already triggers a trace_error_report_end tracepoint
on every error report:
https://elixir.bootlin.com/linux/v5.12-rc8/source/mm/kasan/report.c#L90
Would it help if you used that one? It could probably be extended with
more parameters.

Another option if you want verbatim reports is to use the console
tracepoints, as this is done in
https://elixir.bootlin.com/linux/v5.12-rc8/source/mm/kfence/kfence_test.c
Note that there are many caveats with error report collection (see the
links above), but for testing purpose it might be enough.

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXdx-hEna_S4u4nRXYXW%2BHrJCcyPPiGqQoU8Ri1UYZu0g%40mail.gmail.com.
