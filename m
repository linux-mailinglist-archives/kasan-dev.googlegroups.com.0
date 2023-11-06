Return-Path: <kasan-dev+bncBDW2JDUY5AORBVGKUSVAMGQECU36ITY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B66E7E2B61
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 18:41:42 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-1ef4f8d294esf6067095fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 09:41:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699292501; cv=pass;
        d=google.com; s=arc-20160816;
        b=nJyylejzPZ35IpSFoh5QB1Ic4rPN7CxrorQN5ocH5yd5cun4oA1LDso0G/FgpCqTkL
         1ANIei00la4drYFcdzD54qFuyAWZlSnhTHeu24kz6sqUtiLNiCUnAe0Dk8PvfwlRllJk
         ad3x/Wyb6iXjXUu8GmOHBdY8IjaIOiCIj275yMvWfJZcySvbbFfEJ/45zUgPkAOBhSJu
         N8vLtoLcFVJfDYYjNf0xNKmx75QGMDr7qZW0NllPeymMPxfYd04bTFUW5jgXXtCuCxjY
         nSJT4zjxtOzfvSodc+gP0pe5JIZOWj9dE+kJqESihFFeKlIP7lvDyagfLdbv1yevRxCA
         B/ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ZcOOQkpNa/poLQ+PFHbpnFU1nEjr8PcQwSw63Dtrqv8=;
        fh=5+L7uDpD4jkJrN4RKVrHhQN237X0qFSnK7EFFw/OBkI=;
        b=qYAYMTLLlBPhIGuI8+AwavTXhlozDO6EKcWi4va+ao/X7DfCjzBGWRWCCoq4HRloV+
         mkj/CoQucFv6QNjoj+/jRiC3wQG61y3r/YzUB5l1QP9uXE4U94NlVN0AlWqJzxIpOgZN
         y1D/yzGA8VXgaR0x+/iEj0Qxrk0KhApavCP/xYFBeDcXPhwaLUsDfWgA23Y2oKf/wy6e
         /AKk/cORWqQ8Jigex//75j1myNGVRSue1toOvih3SHdIjg/UfpbMaJNm2JDn3KRKwpxN
         CTvcKBe4H656SjYQFyHKzR1LfzOxZXgFMWaw0PWpZklLlQeOwuBO+m8xbL9uT5AdfxJ6
         kPSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=i21HTIAL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699292501; x=1699897301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZcOOQkpNa/poLQ+PFHbpnFU1nEjr8PcQwSw63Dtrqv8=;
        b=sYurFgXbO7gKY5T9tm8yvW+mo4QIgLzIVmKEC87TFte+4UmePM1CSYQYDn2UE/oWr8
         aIcwgjiBJaW/bjwcLIhdlg3SI8CfCQf0jhUFA/HJiRqvX+qCoQQ1TwDivQ95LAVt+DDk
         th8shRxM3jorz0NRwl8gyuaAxMEo1QEe7VzkQIYgDEbWbNZwQ9hJhOrUL98GtF25XSK1
         nxEHTv4JWEWfLQ7br+EMBwBgPOnmouZpALVQgPctc8QBvj6NZBlc4mJ8NenJgg4a8tAH
         /vGFRdH5ng7e6d2XwYddBrgI7v6mH6R4Jl0EiTe2azzMuv5qUvoE6XnrA5wghVZfUjK1
         oLBA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1699292501; x=1699897301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZcOOQkpNa/poLQ+PFHbpnFU1nEjr8PcQwSw63Dtrqv8=;
        b=c+G7TSPaa0SlhQinomEpM4WWPtuTcGCMpLtbe5EvQTsCismaqxrd8hc93nNVjw7AZo
         craH38b9M/HIMNaxwsE0wtbpPOqFaLjZ7JE+pntnjlA1WG6PUdArJWN38O+Vitgt87XP
         YluBQacEIZhFebl5U4AhmpbCR1BmL7cVrB5/RtEzdL6ghpsjN2WBSyeBurBNGZfW4/m+
         Kpif3Qz4r2PzlVNpBCuubABd7NciFuHFeyJlzBFs1daCR5Se+KmLMKTnrGd4+jgfhKPY
         cSZLng5FjV39rIwCxtUfhmyBQu2BDOBaQuwHhkGMlYpU6wI8mVBWguRJzJAgcrJevmk9
         azlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699292501; x=1699897301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZcOOQkpNa/poLQ+PFHbpnFU1nEjr8PcQwSw63Dtrqv8=;
        b=W6a1f7BMuU32o3d7/hj7Ls79GTg63uISTqsLR1D21DeKzgJL8LrtlRP/dQeYnO7Euv
         wOL0tUzdij7P25jP3noJuT/zWt1Nrh6toJnRR6RMyUapO+j9Ewxwn+X4NabKakL8k8kF
         eOEn4oIsGmiY5Ey+orkJpPyhqwAGIttso5e6S9E0SJHZfO7MA36QDjEo307myIIRE3zy
         9yGrahFYW2r8LpBTPtYTw4wdt7yHrO77Z/6RU/xzEsbv2X8itX7hicjzvhn6cd379UoL
         NeAhxNnu27244k2q+iRHrZRk8P3btuXtFrK7uRwNpYNAJmQCZ/hl32hKarNRdLKQF9z4
         IOFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yymcy5FIyQWUJEgfTP9bWHhy6Wirm8VpmLbuHvox8aFkBTcj+o+
	+AJnWcoq0mhb4OHAmxRgxnI=
X-Google-Smtp-Source: AGHT+IE8K7XbHjSXkJovZ0WCj8rHp74QSNlJa4bBXJ/yPQWywnE43MjgIfHToiyS3EyagsqMpx4gIA==
X-Received: by 2002:a05:6870:449:b0:1e9:f69a:1302 with SMTP id i9-20020a056870044900b001e9f69a1302mr406348oak.48.1699292500986;
        Mon, 06 Nov 2023 09:41:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:458d:b0:1e1:371:c3f8 with SMTP id
 nl13-20020a056871458d00b001e10371c3f8ls2802204oab.2.-pod-prod-02-us; Mon, 06
 Nov 2023 09:41:40 -0800 (PST)
X-Received: by 2002:a05:6870:be8f:b0:1e9:f73e:636c with SMTP id nx15-20020a056870be8f00b001e9f73e636cmr416102oab.43.1699292500081;
        Mon, 06 Nov 2023 09:41:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699292500; cv=none;
        d=google.com; s=arc-20160816;
        b=eLwxjSacbcFgh3gKcaSmv45uEwNhxOSRrlbo9xG1nr293oQ2bZw13SP5Be8//zF/qs
         4/DjWAHn1lRVNTATSWutRtIywHtDUmwM/4O0LXQzjS1XPoBU3KgaF1MGhmEwWaoBWTFb
         AmWjluRvGCET+ZW55ZtRdJHgHL0NvLaFvnPLKJGQwisaCJWTwvq3T4sYoGdnkOp8/a/G
         tJbXYXUf61+GdMHF6mS5Se85BlSktctjY+/gtD3RzQIPk1NnQxox72ksLiTXNouNRGV2
         LDKpzVYX7y2i9ad8yN+cv5LWzDxScOhM/1a29mzjGHpuf4jur3XsUXZdIRy5xjHhzIhs
         1GPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PQokn8UoRY8iyQHlIyiff09+YQ846OAlOmMikNVi4QE=;
        fh=5+L7uDpD4jkJrN4RKVrHhQN237X0qFSnK7EFFw/OBkI=;
        b=IKAzuRPb5DnamUjznShxoY6HU/LkdGOtIZT9NDmGvr3aObYtpQuKzrjW0wMyrYylU0
         G/zw1scWk29I64iBNx2yHHfFApU2BEzNhKH6IrNlm0CV6hAoxchn+PgPGKDzbilP5N9r
         cElF3RxZxoFjyBHWw3oatjKG1ocsl3yuRfvLl45hgT2o2WUCSL2XAXOLwLFLj+bkU+I0
         ehFAIJDcAtVvKNKMfGGvDcqPgdRaOYehqcLC6QYX6WcxLKHKNBZxshV/f4Eg1hwpPjmO
         Y5OZsq412Ui/Q/l+ViyGwdjbGo+6nm86DwQneIP6IKxtOZXHXB53kQ/nsrfEyD1ebu6a
         kmQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=i21HTIAL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id f13-20020a056870858d00b001c8bbdda1a5si662996oal.1.2023.11.06.09.41.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Nov 2023 09:41:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1cc9784dbc1so26292215ad.2
        for <kasan-dev@googlegroups.com>; Mon, 06 Nov 2023 09:41:40 -0800 (PST)
X-Received: by 2002:a17:90b:4a50:b0:26d:17da:5e9f with SMTP id
 lb16-20020a17090b4a5000b0026d17da5e9fmr10375032pjb.1.1699292499209; Mon, 06
 Nov 2023 09:41:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1698077459.git.andreyknvl@google.com> <CANpmjNNoJQoWzODAbc4naq--b+LOfK76TCbx9MpL8+4x9=LTiw@mail.gmail.com>
 <CA+fCnZeQ6nkCbkOR4GqGQ9OzprGNNrXvrOqqsJP0Vr3uJKLdrQ@mail.gmail.com>
In-Reply-To: <CA+fCnZeQ6nkCbkOR4GqGQ9OzprGNNrXvrOqqsJP0Vr3uJKLdrQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Nov 2023 18:41:28 +0100
Message-ID: <CA+fCnZeEkj2TdZ37jFOcYcA-+2BwHta7thMZxPf7n2N4Rt--tw@mail.gmail.com>
Subject: Re: [PATCH v3 00/19] stackdepot: allow evicting stack traces
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=i21HTIAL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633
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

On Fri, Nov 3, 2023 at 10:37=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Tue, Oct 24, 2023 at 3:14=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > 1. I know fixed-sized slots are need for eviction to work, but have
> > you evaluated if this causes some excessive memory waste now? Or is it
> > negligible?
>
> With the current default stack depot slot size of 64 frames, a single
> stack trace takes up ~3-4x on average compared to precisely sized
> slots (KMSAN is closer to ~4x due to its 3-frame-sized linking
> records).
>
> However, as the tag-based KASAN modes evict old stack traces, the
> average total amount of memory used for stack traces is ~0.5 MB (with
> the default stack ring size of 32k entries).
>
> I also have just mailed an eviction implementation for Generic KASAN.
> With it, the stack traces take up ~1 MB per 1 GB of RAM while running
> syzkaller (stack traces are evicted when they are flushed from
> quarantine, and quarantine's size depends on the amount of RAM.)
>
> The only problem is KMSAN. Based on a discussion with Alexander, it
> might not be possible to implement the eviction for it. So I suspect,
> with this change, syzbot might run into the capacity WARNING from time
> to time.
>
> The simplest solution would be to bump the maximum size of stack depot
> storage to x4 if KMSAN is enabled (to 512 MB from the current 128 MB).
> KMSAN requires a significant amount of RAM for shadow anyway.
>
> Would that be acceptable?
>
> > If it turns out to be a problem, one way out would be to partition the
> > freelist into stack size classes; e.g. one for each of stack traces of
> > size 8, 16, 32, 64.
>
> This shouldn't be hard to implement.
>
> However, as one of the perf improvements, I'm thinking of saving a
> stack trace directly into a stack depot slot (to avoid copying it).
> With this, we won't know the stack trace size before it is saved. So
> this won't work together with the size classes.

On a second thought, saving stack traces directly into a stack depot
slot will require taking the write lock, which will badly affect
performance, or using some other elaborate locking scheme, which might
be an overkill.

> > 2. I still think switching to the percpu_rwsem right away is the right
> > thing, and not actually a downside. I mentioned this before, but you
> > promised a follow-up patch, so I trust that this will happen. ;-)
>
> First thing on my TODO list wrt perf improvements :)
>
> > Acked-by: Marco Elver <elver@google.com>
> >
> > The series looks good in its current state. However, see my 2
> > higher-level comments above.
>
> Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeEkj2TdZ37jFOcYcA-%2B2BwHta7thMZxPf7n2N4Rt--tw%40mail.gm=
ail.com.
