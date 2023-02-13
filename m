Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYXVVCPQMGQE62LJNQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FC826946FD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 14:28:04 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id t185-20020a6bc3c2000000b00733ef3dabe3sf8374858iof.14
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 05:28:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676294883; cv=pass;
        d=google.com; s=arc-20160816;
        b=AMLOZLmDPV/Guv9mCT6WXKBZRuvBFjnatYbBNYkI/N7IUyDoecQt+mC5LmM/yspk0U
         H2K96GRI67DjT3ym9gNBWjPA8lXumaNc4d/RaVYK1hLECsfYwlWU4YVwDkZqjWyNkYyC
         VFb1Ug5sFZPR4hS9wQTsufC/C5pugR83XgcRpnPWK+f4FgTQgrLF3bVB8cyEXmmA1Rj6
         17qHYgO3Qveg/iP3xqIst2C/XJ1vuStUUKkS9vfqtH908F5wlY0lq4uUtdaAFIuyaT6e
         OWm2K75RLAmjLO7NE6w8ugcHwO1OVYPlX0U6VRU9Cx90jPIvGSYecu5ul/g0aqukA3zY
         sW7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ntJdNhBh+BykClk4zFYbSjW/GTWKdvddWjq+yRM/MZ0=;
        b=myJo3KiOTPEgkMEk+Tac3GWRbrAop9hPRa6XDrTxgY8mQgEBpud7y5lelosifIfxXf
         y3pu7PVKlbnFD2PAExJs2CWQcK9Q7fELZN/pkaPCIU5oTMxUhIGQMa1gODZMvf1yxg3V
         w67dBY7O5G2XrrKra5TVL8DOFPwzNt27yUmtU0BlSLq0IVgBFyJxVeAk0fDGTnPHqLh0
         4RghtXq83Zd3UTakxbyyhQbCNkdErdBqRfcOiZH03Mpx6vRl3gicJzOfLtMKIcj0DPz2
         DNfifuifLElfUApNsagxBPrWVUyP6pVK3LCnGJOGJ1q9ijxIaGITswL6Xq9TrWATG+be
         NPIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E1gJIgM6;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ntJdNhBh+BykClk4zFYbSjW/GTWKdvddWjq+yRM/MZ0=;
        b=geAHgbP/nJtaelAoe0wRDbCR/ID0gDhO3eKTDbzCZAl9jaJ01xZO+85cirO9DZHZvc
         ihqq+gyrywv22la/ZngT1RI5XPPgCEckKtsPAmBgnif6Z47CUaUoTImaNF4u5blrRzbv
         xrWR+XAbuM1I37R8QZ5bHqLcp20NRzCmfqq21NZhUMHzpxcs0RqeB74edaY3SDABucgY
         OE1eApUzw9QAuR7GelpGf9EIBWjdaRcJMYarApeMppkvo3GT9Ryp2gnJgjMi58vq6imk
         7VFtGf77885DF5vTHlt2MfBL6SVth812ybXWdNjYxX0/wDAewXlqjDBj0xVwXC4L0HoP
         UWlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ntJdNhBh+BykClk4zFYbSjW/GTWKdvddWjq+yRM/MZ0=;
        b=qC0I8u3y36ECPjVIkBJVnR1EvSW+oPFfo19L+7jtJFmBNaodd1jlffFV8tfSdwnEqs
         xoL6r+DZZOYrlepKxC+zFlcLT6gvqfJyzZmWZG4YjBrH85Vb7H6bJ4DRjHnLgTjcZZOp
         JFhel+qFUWh1Qm6JJf3nkrIi2oan5ru7XpKnn4LfUqD99jq53ZyzS1X749lgJdo2lz+q
         OnCBKVq0MQ2d4nIKtPiG6u9DFr4eUY0pZNkZfiRkOZI6n0evkD+3qixNP77WNnO/v8IZ
         AKM/ZCg+gnCYlUOa8SXR4aLUyccrzXFKYxFsTpSKl8y3CjhK7Scr34OQIXnQ9du47vxL
         9mWg==
X-Gm-Message-State: AO0yUKVfwh1fwL25SG6ZI8eHHdGANLbae/YS9WZ48q7irpVrEqRKknTE
	c9o+mGxwzidUNk4AIXBU+84=
X-Google-Smtp-Source: AK7set8WJ7MjnEBTVBUyFXEZGu5y887NjViyrPHexxFYl/RIHXkXQ9oxCAerOtx5nBDy4OUnfv40vw==
X-Received: by 2002:a05:6e02:1105:b0:314:5db:e148 with SMTP id u5-20020a056e02110500b0031405dbe148mr7535237ilk.96.1676294882740;
        Mon, 13 Feb 2023 05:28:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2c53:b0:71e:5d17:7fe5 with SMTP id
 x19-20020a0566022c5300b0071e5d177fe5ls2789563iov.1.-pod-prod-gmail; Mon, 13
 Feb 2023 05:28:02 -0800 (PST)
X-Received: by 2002:a6b:7b04:0:b0:73a:4134:aba8 with SMTP id l4-20020a6b7b04000000b0073a4134aba8mr13914394iop.3.1676294882275;
        Mon, 13 Feb 2023 05:28:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676294882; cv=none;
        d=google.com; s=arc-20160816;
        b=RA4hfj4tPe4iCEKc2GywOtLBmSboMQVRQzTEUplGKoO5Z/kPwJCrOcXAaEocsCwJEI
         dxSgszuGKwpq96QULDZlc7NbIz8pzPl2ohkRZzCK1tG77b7XhDW1HM3ULaDpf4rZm6d3
         la9oeTIAVwr6qTX4bjamDKlJFBUjiHje7zBbSs/bCHn+s3lH3KSl+mgAOLoQd6q0/xCs
         tjE1PVxEGOIxmup2/DhEFlq1GGr+1Lxe5dEMHSjbYnEX0W6npCCMbp3UlxZfWPqPC8g8
         OY907nn0gCkMr536IPHQvWUH5AB5E32A53sX3FtdeT7YFd9eS4FIIns7kFaet9w1Xinf
         MDEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8Gb42UgzE9IFoAhtdlpi/Pyg3SPeN3v0rXrGEsBRa7g=;
        b=aZAU3P/WPiiznC1B/yoryJk6FlEj9M8HVh6znu3r9lOGNb/9LKXfILPN3N0OgqCX/9
         2GNVce8k5svr7Q339YM+24A7pjDTy5QciLTjkXhFUagFIpRp7cjamM+7OCOG5/wO3exF
         Ut/rkflW7+0zGMCRgs7K3l7jG6JSbsGNEXXSW6K4y7XQ1Wg8wKeJG9ewPJtHvP0wh8L3
         /Oou7yzt6i5TXylnCA4u9o9MDntZgw3lwd0SvKFgbxiANXQXTSkZUyPRIkM+207fzNaM
         tFiPsUQywTiiMG8vcK0DNLO/7U/QshmDKthKZrtamgADi+rs1zMLymGJYkP+TzpT57hB
         6EYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E1gJIgM6;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id y8-20020a05663824c800b003b8b7635cb2si1825515jat.0.2023.02.13.05.28.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 05:28:02 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id z5so1734071iow.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 05:28:02 -0800 (PST)
X-Received: by 2002:a02:a794:0:b0:3ad:3cae:6378 with SMTP id
 e20-20020a02a794000000b003ad3cae6378mr12315762jaj.16.1676294881849; Mon, 13
 Feb 2023 05:28:01 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <fbfee41495b306dd8881f9b1c1b80999c885e82f.1676063693.git.andreyknvl@google.com>
In-Reply-To: <fbfee41495b306dd8881f9b1c1b80999c885e82f.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 14:27:22 +0100
Message-ID: <CAG_fn=XEP2ETd5c8Pz2Eri2mHpDzewnBLWoQC=_Z3VKke9w_0g@mail.gmail.com>
Subject: Re: [PATCH v2 18/18] lib/stackdepot: move documentation comments to stackdepot.h
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E1gJIgM6;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d31 as
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

On Fri, Feb 10, 2023 at 10:19 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Move all interface- and usage-related documentation comments to
> include/linux/stackdepot.h.
>
> It makes sense to have them in the header where they are available to
> the interface users.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> + * For example, KASAN needs to save allocation and free stack traces for each
> + * object. Storing two stack traces per object requires a lot of memory (e.g.
> + * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
> + * stack traces often repeat, using stack depot allows to save about 100x space.
> + *
> + * Stack traces are never removed from stack depot.
... from the stack depot?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXEP2ETd5c8Pz2Eri2mHpDzewnBLWoQC%3D_Z3VKke9w_0g%40mail.gmail.com.
