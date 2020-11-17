Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNM3Z76QKGQESDNZSMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A7932B6168
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 14:18:47 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id v10sf453102pjg.5
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 05:18:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605619126; cv=pass;
        d=google.com; s=arc-20160816;
        b=NbxKdf+ansk5QVk4O+/WSssVrHJ2tAgup6/T1Fi03I7oFmysSdCks5vyJTuqJDm+V4
         QKO2VK/KR7UM705C45lj1VGFFlsAY0tEZ8WVySks5iBjjau6Y9fDCZdIVCyhq4DqT7mR
         1jwNlJ5bRXkY60D5Qa23tuT3x7OVVQh9Z6mSCXVbINIwO8QywUZ9Az7at5yA870uZWIq
         qDWc3QVhmGbC5LzlfjOysJT/elyNlEfHKVqsztcyUG/tbK8o5p29z5yZuQ5vDAwfMNZ9
         nYmnjyaIxJ3FBFPDBpclPaST4QCXnEONJYGrF6RPn+y4S+lmP0BkDCKn8G6DOePt0qd1
         yydg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fc1gTTvxaC/fF5RNg4GqEBJv2SyZ86gCY+GSK2HgniU=;
        b=F4nv0yu7zJcd4ZWNGVJ6qrBXMMY1Rq3oV2Cufi36B3pjVCEMdCxXGcAdNb02pWxfZB
         2Oh1nOAu5fYjDcHZflzl5xgUWLKx6ACp7KDolikPedrTU4bX/d07RrvoqgsdD4P+cOaH
         VizdaN35/Mlgvv284U7fBYkk26LCJJFyJZPXvJHjczD0FbnDr2Ef67S4rt8G3JGXfVFH
         4cZHNQMS1hcnXcU/aLRa6CUVdousgFLOqVSIj5dx/4RYDQ9gIXQEeQ0xVYPR6sZ7jvxm
         avtcgTJeFk6ChRha2cW6B5346gBRZQqTtgvrDg7GjdfGawtx2cSd1uKGbAg0bjCODKp0
         WfKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kHpe6Zac;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fc1gTTvxaC/fF5RNg4GqEBJv2SyZ86gCY+GSK2HgniU=;
        b=ZwV4XuFR2x6npgKSyvH+7SHl5hskdBFIrH72Un9HwmpfVjqHsqu4hBRdqAzXk9BqMB
         zhNXtT4CO7vp5Su5i7lW/lITFfDct+6JUYCVMBqkbdUMRK/77xZzc4IFoG1XyRW9BoQq
         AFK1NQHW8GowogW0Woa5IjrzNQzO3ao87Zgf7xI/RPctIUfA75cwkXwn1qGvO4l0azPz
         RSsAKO95jjNXjgR7UuZRthZMDEGrXcjzA7WIJSIZXrejwZ2WoMZiu3J2osFwekvROsJa
         QV/iYdKQT3c++R8u6WnxegxEvIxPO/2fQHZ+KayHjUbzPul402prmZcJzou5opfUZ9yz
         0AhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fc1gTTvxaC/fF5RNg4GqEBJv2SyZ86gCY+GSK2HgniU=;
        b=aBIeuruKC/YHWCcqc/3o+vMQpYKR1qeLxdgzaZuWEHcjDDEyx4kGb4rnMyOwi1aXhw
         K3tx7wHSnORgZ/41EopS7Xh8nTvxYI6zL6STXsXWYs6VkbLYHH1QN+NI/gIL/iTsq47+
         hGHGcoEOSoUSJglQBfVPrYX5DY0RDuE6+AtC9P/vgzxCePCecEH5tppRTBKqoSAmX13P
         IQM3ZwHKx7xkEpWiUscjU5IBNL1eGxs/lhlklUPyJiWLqWFQjp5xnwoWJPxUTe+3sCs5
         eMJW3EMniKrnlqF+7/AGnQlPfFIRJbiBGct4eS7StQcx93vPeIAeLvhcJFsNPO5JPKpY
         17Yw==
X-Gm-Message-State: AOAM5313mDEEccBq0OKMwYA2yjRih8FNCbJvC1whQIq1VwtPaXEFh+bg
	dEjV0T44kD8F0XZE724wt3o=
X-Google-Smtp-Source: ABdhPJxlIIdyVe/oNniCZve0vMqSN6VnxAQ1ToNj/Jt1CzBk2+zB+qN+gddMkTenTdXEhX/JqOAACw==
X-Received: by 2002:aa7:8a01:0:b029:18c:a1fa:8599 with SMTP id m1-20020aa78a010000b029018ca1fa8599mr18978030pfa.12.1605619125888;
        Tue, 17 Nov 2020 05:18:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8908:: with SMTP id u8ls725348pjn.0.canary-gmail;
 Tue, 17 Nov 2020 05:18:45 -0800 (PST)
X-Received: by 2002:a17:90b:1115:: with SMTP id gi21mr4620194pjb.58.1605619125218;
        Tue, 17 Nov 2020 05:18:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605619125; cv=none;
        d=google.com; s=arc-20160816;
        b=PgVtbblMN5spQNb4jD60uGNsLWploQ1TVaNACD1+AcgCu5+ZHw60EOrgi3d85ZJj5M
         ehPOJfoiOqnpSv/Lw6NgxF5GBvrcsltUbH3kM8zCJ0dFPB9w6qQP1ExoF1O6u/xTGCMI
         kXBBB8+O+0RNf56EF4Teaz3vlvoD8j8CLPJZTWVS6g8bogVSG+UohlRbK0uoGRJfFHbR
         u6jQjDDgluS6FlibQhBen+u8SeBVyLtoZoO2awWnWs/ZBudLdMFSBRC7kl0VVQSUaPs7
         zGX5L2uZT5K9L9zvecQnLD/GLWd+Kg/bE5vL2ikxKCR2IFE059giHzSZZDhEMYqp4xJG
         xbxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pa0dw+2YDpQA3Ip7yWMCpwDF+q2V8p/vPHE4K5vOsWU=;
        b=iJdXExs3urReEB1I3eMQ6kBurGI8HOf2/qjTt4usXVUqQOHDleQVxO7WdIITOZnXOk
         lMST3bIOeZUJxuQ9yTAQPXnDjk7p2EP1UubOgwAJ9PfSkysl0iYAIItqsNTH/Nov/ro7
         V6EUm8igDK4+AfDKnoYVGlM+Se3t7Yo80M/cYnm1C8V8uoxObCH1jSl8KVwaorMRScF7
         ekGKRKu11RhISrW28lnOY2efYRGuzYTlOq3w14p9HykXC883IC5Bn496SHMELm5FWFK5
         RcrZ9Bd9OOGM6bzMSlULMZz9iycRlDBJZu6ek/rDhhLbEPbh0siOJIlv/Sug3v3srLN2
         kxmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kHpe6Zac;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id o24si203318pjt.3.2020.11.17.05.18.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 05:18:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id h16so15211596otq.9
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 05:18:45 -0800 (PST)
X-Received: by 2002:a9d:f44:: with SMTP id 62mr3111227ott.17.1605619124327;
 Tue, 17 Nov 2020 05:18:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <52518837b34d607abbf30855b3ac4cb1a9486946.1605305978.git.andreyknvl@google.com>
 <CACT4Y+ZaRgqpgPRe5k5fVrhd_He5_6N55715YzwWcQyvxYUNRQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZaRgqpgPRe5k5fVrhd_He5_6N55715YzwWcQyvxYUNRQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 14:18:32 +0100
Message-ID: <CANpmjNN6=5Vy5puLbhOQxSNUNptFA9jKKqnU4RXRcLb4JT=hJg@mail.gmail.com>
Subject: Re: [PATCH mm v3 17/19] kasan: clean up metadata allocation and usage
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kHpe6Zac;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Tue, 17 Nov 2020 at 14:12, Dmitry Vyukov <dvyukov@google.com> wrote:

> > +        */
> >         *(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
> > +
> >         ___cache_free(cache, object, _THIS_IP_);
> >
> >         if (IS_ENABLED(CONFIG_SLAB))
> > @@ -168,6 +173,9 @@ void quarantine_put(struct kmem_cache *cache, void *object)
> >         struct qlist_head temp = QLIST_INIT;
> >         struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> >
> > +       if (!meta)
> > +               return;
>
> Humm... is this possible? If yes, we would be leaking the object here...
> Perhaps BUG_ON with a comment instead.

If this is possible in prod-mode KASAN, a WARN_ON() that returns would be safer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN6%3D5Vy5puLbhOQxSNUNptFA9jKKqnU4RXRcLb4JT%3DhJg%40mail.gmail.com.
