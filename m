Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6PR5T7AKGQE3VUQV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A9F282DCFCC
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 11:54:51 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d6sf15231541plr.17
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 02:54:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608202490; cv=pass;
        d=google.com; s=arc-20160816;
        b=JZixACP76XbGj1HdI9Mx2ta5+nPGiIfx97cpIRAk4CANe14W3zFtt4EHEsnL8OjH5U
         PpEEl6oevUaa8HRAi//l+gbGVVpSv9OexIoJ/HqDxgmRAJpKPVjGiaefrM7jFXciyMVH
         6g7Xq4t9RnU7p7Pt5+2Pfd8hvxHlQW/Q1v/TSkwYJme5NUGzU+4T8q/pxPPNKARao1U1
         gTGAx/7wZ0SluRHU9MbZc5mcNh8lAjmb8lz+9rMlr/5KVzUpcGjA/pJXZ5NVV4NOpUFX
         Hue+YJYHO+kA6QzYdy02roszcMEQq2vCi8li/3HQqg8tBDYNI0fAXwWSCVEqkmmdaICH
         Ciww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9rTuFHGEvIc0/ptsxgQiCV0AqYzp8XEoFI/wKoNU6W0=;
        b=YEYwjNfA3xKVgHJ1Qs21rGE3n1/60D48qiBJ9FJpDDI15M0SxSh4MmSq4bh6Lz8/Jc
         zzNAMVvGNs8sSk0oWK6PoYk09DfE7WCypzpOnstDAaP8KeT8jETuTsPa4VtG7SRaHx6/
         smA1m+NT7OFBz+lMHkGZtxrPaOnps9BxprO8aXZwu9NBzUPfQ6B09Z8TcgJvWJ2CQlpT
         yCJGXltfbItvxlDb0osjo92+hP8aUQ2dR91XDot5f8jFlklkU2rIQQi7MGU1sAwZu2fI
         nd0so261HLa69/f6rkO68AzSE9q8TIpNCGr0bZdFk49T6Gq6DX+h3wR5E/2lSxRuhmXP
         XylA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cktvz8iy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9rTuFHGEvIc0/ptsxgQiCV0AqYzp8XEoFI/wKoNU6W0=;
        b=WGgmD43Tywn6IwXUfAuKlaD6CT+AdAcXLyWAzxuSW/gnayijZ18jhZ55wArSZnJ8rg
         etNid9KBzCjBbbEbLZmWlNiVkBqDWJX3FTucvUMkcqKCu4mnN+U/flp+m++B2sZumguv
         VOyxzllsYji35sbMgIMJb4qWZOqjVjFPxiotWWNEopqAWDVjoKlZgT4yDOLsPcyUjY0v
         ScFpopdyngnoaczsJLa9KBD/83+5GaiMkaHIeaY0hkvW0yshWwWljsVNZwahow6lph3V
         Xp5sOP0w/Pj6A6WsOvsMpcJSTAF71JyeIA8yVWSqfhyfoFjWCfRWqC2/Z6dGdqSrQEfX
         w11A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9rTuFHGEvIc0/ptsxgQiCV0AqYzp8XEoFI/wKoNU6W0=;
        b=qn0aA4nxpJhjSYoxiHSBVCMY3CzY9UGXqP8DMhEtwfyugh/jJyMBYjGhzZa1MYWDhu
         fIlZXbX5N5gwWhK4HQTOUaCwwZbm31FBsKSVqwlKsuUzrhGDosFr5P0FREB+9cLjhrT3
         yy5TiPqkLXTOdtJwLBMaynn4pmwQASbDNiZ01JlaSbUe4JkokBxQTaC2p9n4WrKriiCX
         ZOm0V/8lPTxqMyeRJBAIdFJUHQTZqkLNFZht7If6Ze96ZCUBgIa1mIe/4zkScw9s3qmJ
         xA9h1TjUOgvNQIZto1iWHpcfqFLg1Fyi8mLKeFfcApqNNjE0vBo6LaeMH6iPezBzqKsq
         sWoQ==
X-Gm-Message-State: AOAM533A7wUW+vMcLsOAIXu11edm4vDUVOSssR3TwDp0PxLn5t+AnI9z
	i4zz41eI3HOcvXwahOI08H4=
X-Google-Smtp-Source: ABdhPJzh4iBzp94TLKqvL5SOhoRWiZ1myem5/AHxBKYzyqTss/Lizshu+po0Qk4cFR2yewqGQBz/Lw==
X-Received: by 2002:a63:4912:: with SMTP id w18mr37555348pga.9.1608202489920;
        Thu, 17 Dec 2020 02:54:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4704:: with SMTP id u4ls2308785pga.0.gmail; Thu, 17 Dec
 2020 02:54:49 -0800 (PST)
X-Received: by 2002:a63:4083:: with SMTP id n125mr37576231pga.356.1608202489378;
        Thu, 17 Dec 2020 02:54:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608202489; cv=none;
        d=google.com; s=arc-20160816;
        b=KZ1ueQwAsCOJaf19Jf+18u6lOZixNakhGn0Q4Hm8B/1clbxshKiqiIa31lrv/Vu8ap
         2nhqJhb3DKp6buXk+HNIgiXTuS9WpJQmompkPyYp75CHaw6j2uOk5qh3gylZVcbKI6F5
         QzL/vBC+NAQFhqiGU20cc+dXNS9vJrLnRZieJ2shxb/5aHnXmn/3lgoJlVfPzpjGvhiq
         HK4f3yGUP+Kjzk+eIAtEZAOJ0igOLxnMK5M4svGAvbhg9graOVgxJtK41WpTUxGdPLL7
         sp+F7y37yBuycEea/Qusy5rRK9UBmjKRfeY1gsD3TSR32HGH7UrWy+mfOd1Oojt2jM1f
         WFcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sh6ZnsaNRvH6fFObdqzFfNsJfBDLItS7EZc+yZ7OoyM=;
        b=XFdVRxzIaPy+cbhbaJT/Y/Huleod+ctuzXUrC05/93Ue6zVC++cQsSpR3TbT3KoBUQ
         cyAd71CCw6uX3le6UggByW65L7svV8/1bQpu9oNQE7aBPWWJwZ5rYdIJxyP/nCH3Ps4F
         mTGIOcjL+TxUJb+RosG8n20dhw3nb70IgTWYSINrQ6EVoKIkIIWfs4UEhgQf0YgEYS0h
         v6Ntc8+3Z1rSP6Y1n6DwwHzt1eWhLaTepBv902/0yKEFIpELM3esyjvZazoGp+EZNZiM
         BHEtCFPLlhdug6qtXDkqnqalUJV1iVfCjtuhbBUN5/PjRL/xRPmH2ADqd/atCdY31q/C
         29ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cktvz8iy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id c3si390481pll.0.2020.12.17.02.54.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Dec 2020 02:54:49 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id z9so19760132qtn.4
        for <kasan-dev@googlegroups.com>; Thu, 17 Dec 2020 02:54:49 -0800 (PST)
X-Received: by 2002:ac8:6f3c:: with SMTP id i28mr46368743qtv.8.1608202488317;
 Thu, 17 Dec 2020 02:54:48 -0800 (PST)
MIME-Version: 1.0
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
 <CAG_fn=VKsrYx+YOGPnZw_Q5t6Fx7B59FSUuphj7Ou+DDFKQ+8Q@mail.gmail.com>
 <77e98f0b-c9c3-9380-9a57-ff1cd4022502@codeaurora.org> <CAG_fn=WbN6unD3ASkLUcEmZvALOj=dvC0yp6CcJFkV+3mmhwxw@mail.gmail.com>
 <6cc89f7b-bf40-2fd3-96ce-2a02d7535c91@codeaurora.org> <CAG_fn=VOHag5AUwFbOj_cV+7RDAk8UnjjqEtv2xmkSDb_iTYcQ@mail.gmail.com>
 <255400db-67d5-7f42-8dcb-9a440e006b9d@codeaurora.org> <f901afa5-7c46-ceba-2ae9-6186afdd99c0@codeaurora.org>
 <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org> <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org> <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
In-Reply-To: <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Dec 2020 11:54:36 +0100
Message-ID: <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure STACK_HASH_SIZE
To: Vijayanand Jitta <vjitta@codeaurora.org>
Cc: Minchan Kim <minchan@kernel.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	dan.j.williams@intel.com, broonie@kernel.org, 
	Masami Hiramatsu <mhiramat@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com, 
	ylal@codeaurora.org, vinmenon@codeaurora.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cktvz8iy;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as
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

> > Can you provide an example of a use case in which the user wants to
> > use the stack depot of a smaller size without disabling it completely,
> > and that size cannot be configured statically?
> > As far as I understand, for the page owner example you gave it's
> > sufficient to provide a switch that can disable the stack depot if
> > page_owner=off.
> >
> There are two use cases here,
>
> 1. We don't want to consume memory when page_owner=off ,boolean flag
> would work here.
>
> 2. We would want to enable page_owner on low ram devices but we don't
> want stack depot to consume 8 MB of memory, so for this case we would
> need a configurable stack_hash_size so that we can still use page_owner
> with lower memory consumption.
>
> So, a configurable stack_hash_size would work for both these use cases,
> we can set it to '0' for first case and set the required size for the
> second case.

Will a combined solution with a boolean boot-time flag and a static
CONFIG_STACKDEPOT_HASH_SIZE work for these cases?
I suppose low-memory devices have a separate kernel config anyway?

My concern is that exposing yet another knob to users won't really
solve their problems, because the hash size alone doesn't give enough
control over stackdepot memory footprint (we also have stack_slabs,
which may get way bigger than 8Mb).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUXQUGiDqmChqD-xX-yF5Jp%2B7K%2BoHwKPrO9DZL-zW_4KQ%40mail.gmail.com.
