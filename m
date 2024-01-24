Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDV2YSWQMGQEVPRUHWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76AF483AB95
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 15:22:08 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-20486eac97fsf7070456fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 06:22:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706106127; cv=pass;
        d=google.com; s=arc-20160816;
        b=SYSXGeTUOw8qS/h0ecrVBIWa6kEtdYju3+qS+4UxjXvu34LtznZeriIyBo5IHhqLsZ
         q7J6IAcxHhfshgjLLAlPgpyKBBMhWo2oXXCaUlHpKbbbYIk8lzkBssjKsXWDz/koG32V
         lw83fcJ17n3hHvYoy5Q4G8m3JshSUUVxzg816Cw9THKA6CINLg+/fXfMZbgQ7vUm/1er
         hnImY/H585tK0ySRHZ2B7Cq9hic3Ej4y2flgl6fOp4wkoE5G1dEBja4ssmDMkRm0b4ut
         WtvcUIo9xc02MlpwbGf4hvN3yRTIhKpaWUD0i5bVA+wgP8VIcJE7dGPVT4JN2ahysnym
         raZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=V9CFcjxHQnfoQK9mt4/QBn6InydmZoVjzEwjV15wqTY=;
        fh=8GRYvtF3nnnNcU0c5Jk1Zc1oIZsIghYIA3w5nN24Cjc=;
        b=0zXPdIAuMXICEvzETj24rbNUe2Jd9yX0NHJN2/D3ubPGpe4TsjOJ45nYThYncIw12H
         Yg0diawPhp4PbWlxH/981y/a/dNfKzOXPMD29s10YqFxG+agIvwU2/KkCH+6B7ztQpZx
         VCjJ95718Tw94f+1FDTXOlbf4hFBIxVfTwHVe7tb6JRhTTjTIBpwTXobZU9eCHML0TIB
         ItewyWXxHHpZDGdTPidqPkPwYvM4Iy4PH6zFbsXw0kr64IjKNzUStLB3r2I+guOl+8cZ
         OcZT/ReMkSK71cLhKnPWk1M481I6JV7XSYl0kUnouJb/XEI6XtyO5IG7exSSqrrzz797
         jdqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wl3Te28D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706106127; x=1706710927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V9CFcjxHQnfoQK9mt4/QBn6InydmZoVjzEwjV15wqTY=;
        b=nymhPPPRMYvv5eUDMFs8Mbh8WrhHUrDwpHoG6prbnzSodEyY/wWPge+nTIFYgL3g9A
         7KgU7mNz9L/OgCelWG/G7MeW7DZ5sFZO0yqkISCg16XZY3pgl+T0jmdiULzqYr9FmJHq
         VB+jB11fsz4iF3ZDZKoylLVExQVqSI8/fsHjEYe+nFla8/9YNItTAApa2/Ptcsl/k0o1
         681bpZWAgfWqI4tvjSehfRkj82Zqo82R2JsJjLcQkpXGV1tn/hhURDWWzJTcGJbtALdA
         t1EvXnBbPpDqMQKeNnp9egnlX0lRTtnPgxViHyE+NUlMsU2YK9VLuGjYPzN0s7OoiTps
         p/Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706106127; x=1706710927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V9CFcjxHQnfoQK9mt4/QBn6InydmZoVjzEwjV15wqTY=;
        b=gWNeETKIAusC+/kwqbUTk2tFbgNv65Kyjw57adAwMl/1PD1ChoBcEolf8RZ0UJLulj
         xsjIo7HpPkuy813/FoiIIx7AgWPRZEujqya8bW1YnzTgMa8fL0OEpQoVrgNAY3z/LChT
         rKECi6/kF3KntlPh3O1FXfhO7JiIF5mQzWCIL5/YlzEuutw2onHUEJLqL+G5ZcEd1Mg1
         r/rLMpMbWYzj+J7ewUZ29TrZMt9UnnkPmIqiJZOGHsQJ4cNYpXowgLZRq1FscxSrwbTR
         2CFOlAxTwMKi7FfiTRCFZBp8qQsXpuJ1TfFlT6DUCs6enMmHi8y94kPGnLLvLOPdR9rV
         b9+A==
X-Gm-Message-State: AOJu0YzlViMkw18j0s7xk4mI7ZWh/IkTeKgiYKAjZXTM8RfJl6xtje5E
	9/nqW/9EA11JOHOHTpNhhGM8bzaDoiiiWqls0H/ArAwm5ziFQ1Q9
X-Google-Smtp-Source: AGHT+IFBXVfOzriP32A/CUWMdWfnb3z3pDRQxa2zSAU0Tl2HRj9/w86GK4Qj/31PG8sZ0JqWKqknZQ==
X-Received: by 2002:a05:6870:1712:b0:214:85da:c254 with SMTP id h18-20020a056870171200b0021485dac254mr3111066oae.11.1706106126824;
        Wed, 24 Jan 2024 06:22:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1708:b0:210:a510:cc1b with SMTP id
 h8-20020a056870170800b00210a510cc1bls2555939oae.1.-pod-prod-09-us; Wed, 24
 Jan 2024 06:22:06 -0800 (PST)
X-Received: by 2002:a05:6871:88c:b0:210:a19a:ae3d with SMTP id r12-20020a056871088c00b00210a19aae3dmr3667908oaq.80.1706106125952;
        Wed, 24 Jan 2024 06:22:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706106125; cv=none;
        d=google.com; s=arc-20160816;
        b=TmL/QUqRYQF4qkSOQuL3ZLSgkIaiO9zwpdzfSJ7iqeE9x+GaQOA2f+RucV7uu4Q52/
         NFRQRBjJqnPKBM7NiwGzKOecwgLf5NIlo5bdzKzwiwucwruD5vpzm0DkIv23DBpmECXm
         pz60tIe9P+QOXC/f+cojLov9EHHXWeUAQmD2oGohwaiwHmCf1vw7J9vM18N47sOY9Kj/
         uUDU+qvmB9SuzzblghthYvsZpGr3wjcAsDr4VUtA5tK6KwolH79hdtl9esMQbcrz20i7
         dM2LE5sXAxaukrp7kldd8CkTrLuBW/YFFs3qTS3FLm/Rq+A+c2bWy/6PSPDK57QD3ft6
         tARw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y2Ickior11wnkNoXoIh8jyoa5DElGtPsGaiZ6/joupA=;
        fh=8GRYvtF3nnnNcU0c5Jk1Zc1oIZsIghYIA3w5nN24Cjc=;
        b=j3yAaJezv6VBlraJTYc4jcb+jQaSJM+ZsubjwBuHPnj6DAqRUQ1Yav6d8ZV21eoVuB
         IxfLZGu0enlAzzAeuG6bSAI+OY4pqVzmEDQlwVzCYdLI6mVq0EYMJy4eo2n8W8QNxtkQ
         7Wc7G0H+uceyXbYRq40CyRIdeB1YeZK7rtz40nMyxTJOWfe1h4pVC1GBmE0/ewfdi7id
         uKgkc8D0btdJCIh5ptQLq3KjqY/VyPMh0GwZ7tAVyUYn9NrSCz42GdROFWLfV06wxpqH
         CuXQHu37jHPol1dR1kch/mC6V76HhzCrt0xeqMrGci21eHhZZcQfXJWFn3hDXfBZFMO1
         tBGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wl3Te28D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id hb9-20020a056870780900b002149b52ee93si371118oab.3.2024.01.24.06.22.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jan 2024 06:22:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id 71dfb90a1353d-4bd54e5d30eso305795e0c.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Jan 2024 06:22:05 -0800 (PST)
X-Received: by 2002:a05:6122:9d:b0:4b6:bfae:3285 with SMTP id
 r29-20020a056122009d00b004b6bfae3285mr3899127vka.4.1706106125184; Wed, 24 Jan
 2024 06:22:05 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZbEbmyszaK9tYobe@gmail.com>
In-Reply-To: <ZbEbmyszaK9tYobe@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Jan 2024 15:21:26 +0100
Message-ID: <CANpmjNNnrKYKkV74rcBUkpA09KqwHOjse9J9aCHPRFuYKCQM2w@mail.gmail.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
To: Breno Leitao <leitao@debian.org>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Wl3Te28D;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as
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

On Wed, 24 Jan 2024 at 15:16, Breno Leitao <leitao@debian.org> wrote:
>
> Hello Andrey,
>
> On Mon, Nov 20, 2023 at 06:47:10PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Currently, stack depot uses the following locking scheme:
> >
> > 1. Lock-free accesses when looking up a stack record, which allows to
> >    have multiple users to look up records in parallel;
> > 2. Spinlock for protecting the stack depot pools and the hash table
> >    when adding a new record.
> >
> > For implementing the eviction of stack traces from stack depot, the
> > lock-free approach is not going to work anymore, as we will need to be
> > able to also remove records from the hash table.
> >
> > Convert the spinlock into a read/write lock, and drop the atomic accesses,
> > as they are no longer required.
> >
> > Looking up stack traces is now protected by the read lock and adding new
> > records - by the write lock. One of the following patches will add a new
> > function for evicting stack records, which will be protected by the write
> > lock as well.
> >
> > With this change, multiple users can still look up records in parallel.
> >
> > This is preparatory patch for implementing the eviction of stack records
> > from the stack depot.
>
> I am testing quite recent "debug" kernel (with KASAN, Lockdep, etc
> enabled). This kernel is based on
> 9f8413c4a66f2fb776d3dc3c9ed20bf435eb305e, and I found the following

This version predates this series, as far as I can tell. Can you try linux-next?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNnrKYKkV74rcBUkpA09KqwHOjse9J9aCHPRFuYKCQM2w%40mail.gmail.com.
