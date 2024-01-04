Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7T3GWAMGQEHBCA3EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9145C823E95
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jan 2024 10:26:21 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59487ced981sf340069eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 01:26:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704360380; cv=pass;
        d=google.com; s=arc-20160816;
        b=lci+PzmUnHJ/X1/0woA58LW6KU+8gfgjEdafwPTzsNqeUwDf/qW04qWWGrObBBuE/O
         nnKG2N98OQcBOwKk2JNExVIN7uVBKNNwH4WbKKC7GkGCVFeR363V4sKmGVzVFdK/MjjG
         U6i31vd0fB/dBj7WOe0Vo2GBNiOnr3GEU//c0M16zCOF1PBy/wRxNLIEm6xSjBsEN6UJ
         cy68sqzlkKj/apmxMx5fSlYHWrUB/DTdUpQCH+ChTjaMndrt4kZllM6bFOSRN0kvc8vV
         WxD59AH38LJ9gmSKaCnj+MzvAacTaAYXER0Lv+yO45KhQJfonPB+dIbkh29Pv15KA6gO
         UzMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/NFNXZ0oV5HW6cgBczUqqY5+Be6jttoPBjugsOqhWCQ=;
        fh=AnoIy5yXpmYRAA/ZJLVC0D5vdVMFCXYVFmK8go1Xijw=;
        b=YFeBJgIADWu7zLbKxvE4+muwordsL6m3UZ/ZmINZHiBC0xv/ABmyyw79OuawVpGQ/Z
         G800IT5lIY0w0mG9rI/D2sbQnZKIf5kyciXec+1S/Tu2ZUIxX2sX2PVPx+bZ4mkX1DEO
         thpsuwUex0WzOux49STNskceC0f/zc/5LHoQEy8MRNlgkNfZKPR7+mT0WWWj3K+DuhOU
         qNE9hFtSnGH8ouKQKNwOADKWk/VMFodYlsRb8yjAitoH8g1xafTGbcR4Bz8BnFrBk3D3
         HfTsa5DJb4xijxnWZE5d7b0YcKyRtd5AQhCpMePjBZaSMS9g8vsPCVryiyjvrkrpjcbz
         ZnfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="t5ySfb/R";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704360380; x=1704965180; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/NFNXZ0oV5HW6cgBczUqqY5+Be6jttoPBjugsOqhWCQ=;
        b=xw2Kb/d+JILYBQHjXHteHgzDP+48UnJz3OXrTK+FaNlxXPwZteTFl5Xrw7nKNdeg1i
         TPqp8yAcUUFKS4J0YC5GOda1WGTKNccfYsRB7y2CMeDNkCvcp8CO6mS2XfZx1GgGcKRb
         uYuYVvhPTs5q1rif82EBn3zzLfbvsihMAZnlvJ+6beIrEoZCCW/CXJ6cHAMHDSqC5U2D
         tjbFKKzkHrTNkFGUEDkdoVDYNtKH0N7OuWxETaEH2d9C6EnfLOMfRPO5DGX8cPqJon6I
         DjxhQCm1IOXk4vtre5Nh5ymhPyn62qOQRKpjp4n/AkZIbjTSgWMFrYAWljP6lhLGAO3d
         /tZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704360380; x=1704965180;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/NFNXZ0oV5HW6cgBczUqqY5+Be6jttoPBjugsOqhWCQ=;
        b=q0ijkK573igcML+lvBS+iFU6QQbcqjZP1iD+XvUoNXessahkmSYxAxAReXjGhcJNne
         3+7tshtDFWeGzVqD744yRBPef8KJE4MBKzFIE5hVprkctt0KRaiStKrFC+6C8LL59Xy9
         sSeBK1hgKLgxxSygI6nTgZuuNlDHklBdIwswAMQ+H1luumA4RBTwBbDommtwOz8L23xm
         nHH4T3Z8IcMyVlkUrh1uoPzJ+8G/4UVUXXATV0eSfBmod6m1p9HO0rAOX6WhKdy23UTc
         ZYalOAbZEeQh4/sE4ZtU20q3EMkK2WWbZbHpU0BiNfcHVcHrdGRAih6dAtj0PaF7eBmD
         GzoQ==
X-Gm-Message-State: AOJu0YxDjAMYFEYArK3Cao5L+5OK0a4j4nK4BXBZZ5II8CTbO9veJqEQ
	mmjFCBeHs0CxAdFVkzPyCJk=
X-Google-Smtp-Source: AGHT+IHiOm1BYfOodIjJn0uLkc4/JZ7EtHWj/OY4KKNIRG3JtBymJMVAqCRQkHkJA3jYydUcc9A2eQ==
X-Received: by 2002:a05:6820:22a4:b0:595:b7ec:2acb with SMTP id ck36-20020a05682022a400b00595b7ec2acbmr430432oob.18.1704360380019;
        Thu, 04 Jan 2024 01:26:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1aa5:b0:594:cfde:39ab with SMTP id
 bt37-20020a0568201aa500b00594cfde39abls4776554oob.1.-pod-prod-04-us; Thu, 04
 Jan 2024 01:26:19 -0800 (PST)
X-Received: by 2002:a05:6808:255:b0:3bb:c698:76d8 with SMTP id m21-20020a056808025500b003bbc69876d8mr266797oie.110.1704360379304;
        Thu, 04 Jan 2024 01:26:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704360379; cv=none;
        d=google.com; s=arc-20160816;
        b=o1Oxb++6KEqEK6o4FwOFstF3spQimtdbZNMk+j2dTT1cZ8wfao5qck4utBctSYTtKi
         1O/dnaytGEJsp4/AWywJV0ThtFbcc/u7H5QmFqLsiXIbZvPDxRcrFz7xh37RL5MIW0Hu
         AtoD8CNdJxfqpIudV+0B4sj4CA2ta/ySbTGgtJXtqE5TiTmTGUhi4ti4oxsc2lUNVhza
         anZkiL8ShClFto+y5VUQNiyqHExzGlDZTIxEYJBONk6GqPSPoUrQzlaqTT65NxKjesd4
         BcXO4sdHu4o8asge0va4SpYpE40XhQbVVNGd77Yg2kyv4/3JDghSROwhoKf1YckmPvRk
         xu8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JGeZ8w8hYuhNSoX/scf5I633EqoYMFGVRc1Mgn4PFeU=;
        fh=AnoIy5yXpmYRAA/ZJLVC0D5vdVMFCXYVFmK8go1Xijw=;
        b=E1gdEepLW6/G0IrWi0aGjUfNCj528ss0+9GRhaC9gIjqmgU36Iq873LdUM71nMAL1k
         kxSibl3VkI424QkVpariCAVX0u3ao6kGkn9WoZg02SqKxTCnkPT+BngHiaHwu68MhO8O
         bzXy9Itv1OPYun8xdRXVlg5YHciCTf70XIAAy5BfJUb7ZmoEYvc/8Tt0cbPFlyP060zc
         /I0GqRBhBOJu58qo0RjwNs91veeGkqG/E4z69V0Pqi+wU+iSAM1xCEmBiqv/utWnUW1k
         JQ+6KCcNNgFy0V9nliuet3IGsWrn3ksa8kpO69c7k2iZiryOlZIMenhwAfFVk9dXdV++
         3Okw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="t5ySfb/R";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2d.google.com (mail-vk1-xa2d.google.com. [2607:f8b0:4864:20::a2d])
        by gmr-mx.google.com with ESMTPS id jc18-20020a056a006c9200b006d9b1734f65si1409065pfb.0.2024.01.04.01.26.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jan 2024 01:26:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as permitted sender) client-ip=2607:f8b0:4864:20::a2d;
Received: by mail-vk1-xa2d.google.com with SMTP id 71dfb90a1353d-4affeacaff9so96580e0c.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Jan 2024 01:26:19 -0800 (PST)
X-Received: by 2002:a05:6122:45aa:b0:4b6:d5f1:7c8a with SMTP id
 de42-20020a05612245aa00b004b6d5f17c8amr245659vkb.4.1704360378266; Thu, 04 Jan
 2024 01:26:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl@google.com>
 <ZZZx5TpqioairIMP@localhost.localdomain>
In-Reply-To: <ZZZx5TpqioairIMP@localhost.localdomain>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jan 2024 10:25:40 +0100
Message-ID: <CANpmjNMWyVOvni-w-2Lx6WyEUnP+G_cLVELJv_-B4W1fMrQpnw@mail.gmail.com>
Subject: Re: [PATCH v4 17/22] lib/stackdepot: allow users to evict stack traces
To: Oscar Salvador <osalvador@suse.de>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="t5ySfb/R";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2d as
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

On Thu, 4 Jan 2024 at 09:52, Oscar Salvador <osalvador@suse.de> wrote:
>
> On Mon, Nov 20, 2023 at 06:47:15PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add stack_depot_put, a function that decrements the reference counter
> > on a stack record and removes it from the stack depot once the counter
> > reaches 0.
> >
> > Internally, when removing a stack record, the function unlinks it from
> > the hash table bucket and returns to the freelist.
> >
> > With this change, the users of stack depot can call stack_depot_put
> > when keeping a stack trace in the stack depot is not needed anymore.
> > This allows avoiding polluting the stack depot with irrelevant stack
> > traces and thus have more space to store the relevant ones before the
> > stack depot reaches its capacity.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> I yet have to review the final bits of this series, but I'd like to
> comment on something below
>
>
> > +void stack_depot_put(depot_stack_handle_t handle)
> > +{
> > +     struct stack_record *stack;
> > +     unsigned long flags;
> > +
> > +     if (!handle || stack_depot_disabled)
> > +             return;
> > +
> > +     write_lock_irqsave(&pool_rwlock, flags);
> > +
> > +     stack = depot_fetch_stack(handle);
> > +     if (WARN_ON(!stack))
> > +             goto out;
> > +
> > +     if (refcount_dec_and_test(&stack->count)) {
> > +             /* Unlink stack from the hash table. */
> > +             list_del(&stack->list);
> > +
> > +             /* Free stack. */
> > +             depot_free_stack(stack);
>
> It would be great if stack_depot_put would also accept a boolean,
> which would determine whether we want to erase the stack or not.

I think a boolean makes the interface more confusing for everyone
else. At that point stack_depot_put merely decrements the refcount and
becomes a wrapper around refcount_dec, right?

I think you want to expose the stack_record struct anyway for your
series, so why not simply avoid calling stack_depot_put and decrement
the refcount with your own helper (there needs to be a new stackdepot
function to return a stack_record under the pool_rwlock held as
reader).

Also, you need to ensure noone else calls stack_depot_put on the stack
traces you want to keep. If there is a risk someone else may call
stack_depot_put on them, it obviously won't work (I think the only
option then is to introduce a way to pin stacks).


> For the feature I'm working on page_ower [1], I need to keep track
> of how many times we allocated/freed from a certain path, which may
> expose a potential leak, and I was using the refcount to do that,
> but I don't want the record to be erased, because this new
> functionality won't be exclusive with the existing one.
>
> e.g:  you can check /sys/kernel/debug/page_owner AND
> /sys/kernel/debug/page_owner_stacks
>
> So, while the new functionaliy won't care if a record has been erased,
> the old one will, so information will be lost.
>
> [1] https://patchwork.kernel.org/project/linux-mm/cover/20231120084300.4368-1-osalvador@suse.de/
>
>
>
> --
> Oscar Salvador
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMWyVOvni-w-2Lx6WyEUnP%2BG_cLVELJv_-B4W1fMrQpnw%40mail.gmail.com.
