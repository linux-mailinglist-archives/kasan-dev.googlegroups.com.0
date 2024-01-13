Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGVIRGWQMGQEK3SKO7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8591B82CAB8
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 10:13:00 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1ef4f8d294esf8926339fac.1
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 01:13:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705137179; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxowS7QnRRW+uPx+mzCNu+psIzk7v6p0keAu3cXwDS84fRw42vCaZWbbn0A6M8lzrT
         dA3tZQzOF3uX+AcB775xu0sNTLWVTZsw5WGfNkx7d5UtnVKSjwmrtNK76E7X+MznciI+
         mR3i8BTGwGz+hM5L+nExfpNICouDhAUB9Pqyl2uaxjuHyUuAAuIUO1OgPKfzp2C8glEU
         bOmvo1JwZlFo1e6qskLmzr6g/MqNSzluThrWzOHDiJb9POlPVgXuC0bo3841M99Y92A9
         oIEnfZn+MuoOtmlhpZ2NNU+K+Ct7UyIi87tPk93u4yMfdv1DY96wt6Hw8Gll7dfNHS8+
         1YRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8GVuIeBgU+3hDDkpyRk9io/wLLEbXMcKR380PlZQdCM=;
        fh=KtmuM4t+2D/0bgkLGSGV2OTdmeV3Sg+Pwv69Xxa5wIY=;
        b=dcx/geth2s2kESFK51CLmj0ai9zO8lG4TCyaL228EE5XV1mXMRVExhiONjneF0o84Q
         2OGDESVswEO7X21mnkHp72g1egdhY+uZSU5CGTjgeH6T448XiYO8pOCPE/ECtMWJ1tzH
         cCJ+BDSlUsKLXhg5Ng1284pSJUXMxf/iY9vff7TG9cGLcQQpciX7/ZyV1+bTK1zCnG5a
         rMio1qdvnZVX4FKr1vZ0O6v6rBjSKPziVmO/bf4mkIp1m1SEjJzNDwh3rubIvapgJHp8
         2M+vK9Otc3vkrCNWyAYaV3IT+LCacL6juvfGt+spROd5roN9W66aFiHCKSmtmLi7zoJd
         vNbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=luDzygNz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705137179; x=1705741979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8GVuIeBgU+3hDDkpyRk9io/wLLEbXMcKR380PlZQdCM=;
        b=vim4pL3iatVENMUDMWwoAWTK7wB4NZjzzmfqwBGj3iXUYA8QGTz5qHS416pMgGaJ8g
         VZUA8yUPhQPRTRloQ8ubZBdRFbuQxhv8zk64FEf2uh4YzyiQ13D1kuu+/7OnXAVRCGOq
         HVeUdvFQiU2IckRlCuel4t7JuSrc+FWwJPY3NMNR67ykqqj2D2liJoHnJcxjyD8P1gpd
         R/scEcGza1k4E+2RgJ6rX9GwZ3kvf4Dl7tqYJ6xsM67SJAErHRd2jmImFY/lNXAIszqv
         Ad5HaCUFHn47JNQK1fVOp+hvoDmQ7niTSAHnZxx0buMxKxcbpe588QymjV1s2x3MGsQW
         LVmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705137179; x=1705741979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8GVuIeBgU+3hDDkpyRk9io/wLLEbXMcKR380PlZQdCM=;
        b=CZp7p+rT7U9hupP/GQ/Ryk0KsrhLDCZ8qZ0vvaejp6kZiQ/++9XBB2Fxg15HEyJwbM
         dtlROSQov2U8XGijfoWgCQexaZ9FK3vRJJYfJ8RWiQpUeZyrh+G9416ywIu7Aqata4DK
         38FT90jt5vq5+NhJ5yWRzKLOEbqo6aONunWSzqSel0tm/QwmhysDv4ywruNxPNTTjaqc
         bLRtVJEtBOvbpGDCtIcXNkte81Og1N7bwVPOwLP0i4UVFcnkxqar3B8wZYWb9GkHlX6t
         bp5mue7lLT6z3lVPLeoEuP25vmfNZtfDOh61i0Mo1rvphojIpSbEDGQo7MHl8mOSoeuk
         hGWg==
X-Gm-Message-State: AOJu0YyqAuN5pRvHVq4IT2s+b9ShPQd30uQpYKcaLhA2vmzmcoS4HMnh
	9W8oVNKPdJJBJ1uLCwGlqWs=
X-Google-Smtp-Source: AGHT+IHwcvXT5mx13RIUEIYZxZElCsYLvnTOPJvK6/cNDsjrXoBKxJ957v1Xpmk84oalFL6cfAL39Q==
X-Received: by 2002:a05:6871:a58a:b0:204:b2de:2f1 with SMTP id wd10-20020a056871a58a00b00204b2de02f1mr3030182oab.104.1705137178983;
        Sat, 13 Jan 2024 01:12:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ce96:b0:206:8f0:d532 with SMTP id
 xe22-20020a056870ce9600b0020608f0d532ls776824oab.1.-pod-prod-02-us; Sat, 13
 Jan 2024 01:12:58 -0800 (PST)
X-Received: by 2002:a05:6870:eca3:b0:206:8880:a9eb with SMTP id eo35-20020a056870eca300b002068880a9ebmr3350762oab.12.1705137178266;
        Sat, 13 Jan 2024 01:12:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705137178; cv=none;
        d=google.com; s=arc-20160816;
        b=Crdnx1XY4IfSUoxuF+mtDnah41PlWjnNlxabDdZp3DrdKQSdybxUhn7zrjaklY7Pwd
         6EfgtjLiNKcFWqMWEnAv8GHm8X4k2w8IPhcyk5D+8DwW8Xbc6ILwbJ0PJ3vdcnIbSa43
         FES/flQkRi4fiVZ7/cgpKTCyVlmkgyaJw/xz/6w4Cvlp3sLumufYhVGxa5YYqKZaiMFf
         JrvGJWgBhhcMCsnM+K4PdYoCWxRdn0aaKfmZptlQC1glF1rm6kBe10gXhHzU4O1ACfJY
         gZNBwklHOvzNk4TFnWXwRWu59hlnn8ZD1T8WwxtziCaBELXi90SyIenzR0IOnAqPnVwP
         zSDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yo3t4e6P0WumxGPjlAvUPSxdP7muYs1O7d3R9moE3Qk=;
        fh=KtmuM4t+2D/0bgkLGSGV2OTdmeV3Sg+Pwv69Xxa5wIY=;
        b=hOZ3jfyc7NoaECX1SVGbIrbAOq3JxXGeXjoUfAF5EUwG87yHD7YHd9UCZYnrSjCP2s
         a9XToBfqtdNmLDrtuvNK56afyaS3aDVLJ3A6yLlnACKBWY17fWZV0vuKEE38wxLndwx5
         PM/TeqfViuA8p1wCXBZhsN0GMo0usM9qgwLm8DL4CppjNIGnG4BIAQuApC7H8UhyzJM/
         0It9Rl6Ye9VcVzoYhL4IPEb91SvHh6BDj+u0Pwy2NCoQNl0zfk7T1ohIKZ27cBkSvlei
         a2e1lN/Mc+K/Y2Ov6WkXTodjvTNeCX3d9uEgMggxR6k+kfaSQy8u42bCsDmmZUpQO/3B
         qyFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=luDzygNz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x931.google.com (mail-ua1-x931.google.com. [2607:f8b0:4864:20::931])
        by gmr-mx.google.com with ESMTPS id pk14-20020a056871d20e00b002043bb5e02asi766367oac.1.2024.01.13.01.12.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jan 2024 01:12:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) client-ip=2607:f8b0:4864:20::931;
Received: by mail-ua1-x931.google.com with SMTP id a1e0cc1a2514c-7cdf4b99e7eso2257602241.0
        for <kasan-dev@googlegroups.com>; Sat, 13 Jan 2024 01:12:58 -0800 (PST)
X-Received: by 2002:a67:ea53:0:b0:468:e16:1cf9 with SMTP id
 r19-20020a67ea53000000b004680e161cf9mr1822608vso.60.1705137177555; Sat, 13
 Jan 2024 01:12:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZZUlgs69iTTlG8Lh@localhost.localdomain> <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo> <ZaA8oQG-stLAVTbM@elver.google.com>
 <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
 <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
 <ZaG56XTDwPfkqkJb@elver.google.com> <ZaHmQU5DouedI9kS@tassilo>
In-Reply-To: <ZaHmQU5DouedI9kS@tassilo>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 13 Jan 2024 10:12:21 +0100
Message-ID: <CANpmjNO-q4pjS4z=W8xVLHTs72FNq+TR+-=QBmkP=HOQy6UHmg@mail.gmail.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
To: Andi Kleen <ak@linux.intel.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=luDzygNz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as
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

On Sat, 13 Jan 2024 at 02:24, Andi Kleen <ak@linux.intel.com> wrote:
>
> On Fri, Jan 12, 2024 at 11:15:05PM +0100, Marco Elver wrote:
> > +             /*
> > +              * Stack traces of size 0 are never saved, and we can simply use
> > +              * the size field as an indicator if this is a new unused stack
> > +              * record in the freelist.
> > +              */
> > +             stack->size = 0;
>
> I would use WRITE_ONCE here too, at least for TSan.

This is written with the pool_lock held.

> > +             return NULL;
> > +
> > +     /*
> > +      * We maintain the invariant that the elements in front are least
> > +      * recently used, and are therefore more likely to be associated with an
> > +      * RCU grace period in the past. Consequently it is sufficient to only
> > +      * check the first entry.
> > +      */
> > +     stack = list_first_entry(&free_stacks, struct stack_record, free_list);
> > +     if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))
>
> READ_ONCE (also for TSan, and might be safer long term in case the
> compiler considers some fancy code transformation)

And this is also only read with the pool_lock held, so it's impossible
that there'd be a data race due to size. (And if there is a data race,
I'd want KCSAN to tell us because that'd be a bug then.)
depot_pop_free() can't be used w/o the lock because it's manipulating
the freelist.
To be sure, I'm adding a lockdep_assert_held() to depot_pop_free().

> > +             return NULL;
> >
> > +             stack = depot_pop_free();
> > +             if (WARN_ON(!stack))
>
> Won't you get nesting problems here if this triggers due to the print?
> I assume the nmi safe printk won't consider it like an NMI.
>
> >       counters[DEPOT_COUNTER_FREELIST_SIZE]++;
> >       counters[DEPOT_COUNTER_FREES]++;
> >       counters[DEPOT_COUNTER_INUSE]--;
> > +
> > +     printk_deferred_exit();
>
> Ah this handles the WARN_ON? Should be ok then.

Yes, the pool_lock critical sections are surrounded by printk_deferred.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO-q4pjS4z%3DW8xVLHTs72FNq%2BTR%2B-%3DQBmkP%3DHOQy6UHmg%40mail.gmail.com.
