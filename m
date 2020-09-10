Return-Path: <kasan-dev+bncBCMIZB7QWENRBWN45H5AKGQEQ4LTXNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B9668264AC1
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 19:11:55 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id x21sf317382pjp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 10:11:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599757914; cv=pass;
        d=google.com; s=arc-20160816;
        b=e/rhbgiyB5pMwxKYEFuyEpvLzojJV1u29s+FLuS8cGnn1TUxhKSrBbvSIxaty4ygmh
         Jb3TPYInjrCvp4XkmwDWbnf14k8I21PHYdk2n9Q7u6UY6wtcpmIpJgNos5sJk2+0mNQD
         9dtjt6fGbehmWvJZqjNsWAYVEi4RwSU4wK6IMS/qtVwqLDq1BfQrB2A0fAk7hHqeyU2G
         szaWzPdZkJpDGFCs/+ZFoIp9IJXYmjzZXE/t4RKRfhmN6SgJ1TtHf+3n4NtvVm8vWr2N
         KymYelh/zUP0XZ8dyn0nyOaWI/D47NtI1uhMucIH3i2la52gNwLuSsEG/mf11PnbHr2v
         JcXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1d77IP7wy2mvkSWI7XKqDWrr3IZU0bYz3B21dCA6Q5o=;
        b=q0A5s6tbCfzyChIjozWU77CwnEgz2jSXRxw0/KR5YorJ/4293BBLKC3dlQEMtJZUA+
         dpLmrrtSkZExiYavTSSmBWenr79NU0GkxdkGey7CZdFyDxAsnjQwo9wBjbPaogw0iOQ5
         TMMBh6MaO1XYLV7uToCoRxcY/dan4GoDS0fZnC98ZPinGfDmor4Fq/W+vgp05uZ6adrK
         82C69MDYVUngLTf4JVoFZke2YwpZsAz+jhAQ+1XcWOuTbZEKf8KgCGqKVw5tdIwiqLn0
         XQMmK92xZyFyF2ADyfRyR0T/eKXvqQ0Ei3MP+Qlzif94h35MXdnebktuvwat1qP6aaar
         /llg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dJ2eDS6O;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1d77IP7wy2mvkSWI7XKqDWrr3IZU0bYz3B21dCA6Q5o=;
        b=e218k3/UeMTGgz3sH/7jCwd1C+tOd0bqXxk6CCp/wFw7NNNRomRQwj3Ouf6RggPGT5
         RJKXBo0kmbIJJiO2z4MyKSQe+WNtYiurfKLxXA55SOa8QgsKSdyKlBw7aTNiilt3fFJh
         FQaEYxtEU9DDx8wPUXrU0+9lN2CJDhmHgfCdrfwC8eDTqdPWOX3v0ZS1ySaqNzNgrFHq
         8oq5MtTjdsAdWeOUonvJLb5gBZ721NNS0AlVS9gqSXPvTc2q1KydRJJL4rD2D3TsF2h0
         tiVvjQaFsM+IO/00EHjD4W2XrEW7EYoq1EiVRWk8nhCnzSBWLO8XGO0jMCLLXp3irI8h
         gYoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1d77IP7wy2mvkSWI7XKqDWrr3IZU0bYz3B21dCA6Q5o=;
        b=JHhRp10xuE9RTdvnUGpJlgp4eXqoh7QaUSek9Ylm0h8HbEMNKrNp9+nvTwCAaLy02F
         wl75lgPLUil5T7R3mhm0qJ57Zki4vFomDQm8CvgAGV3qJ+v2R3kYv4tBofcpxbRpHBVi
         e+AnMfxdxk6EjKlYdck+/QV9r/L3tH8U5wuvf4aSK5JjVQfkaCHoBcBxfFveBFGjIF6d
         2UPnz+vbHJ1WcLLBxiEYf0UcmTAqo/bHssM1z1gyetUdHUimqhNc0KQRXdjpaok7plCg
         NBqkSsxW9jzXubiwzPVzDc4j3RL+B96JUAnfjDiNlPKetjSSdAA/EAZ7NhKr1mEoa+7i
         KusA==
X-Gm-Message-State: AOAM530zJTpCKKlc2sgqmjkBr3xSFKuj3MtNcPh0P19EDw2MMqWEBBcy
	DHpFUMwPd5llfiaZcOZRI3g=
X-Google-Smtp-Source: ABdhPJx1bJM1V0axDVpAtj5S0HOMubQYH1oyLcwPmv0C3mMwjZhI6LdWdAXcdUmep+R3NQW1i3uymw==
X-Received: by 2002:a17:90a:e093:: with SMTP id q19mr871476pjy.98.1599757914149;
        Thu, 10 Sep 2020 10:11:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e303:: with SMTP id x3ls1673552pjy.2.gmail; Thu, 10
 Sep 2020 10:11:53 -0700 (PDT)
X-Received: by 2002:a17:90a:13c7:: with SMTP id s7mr904807pjf.124.1599757913553;
        Thu, 10 Sep 2020 10:11:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599757913; cv=none;
        d=google.com; s=arc-20160816;
        b=YhPIE4g1dy4XT9vMCPqE91eDzZz2jS9nf1dBuhfu2AfoONm0JKxu6FNABr9ZB/rreH
         JYvVgTNI2dK2vs9unk+Q3nGLXWMoW29meAhZxlt7gPzNqziZGzTCW1YsIkC+x7cW2v6t
         f1CRsVGmeND9LofqwIjtD/JrXzPGl7RMbl5hjPIamBmFGQrWIylI+/s4AgA5ocx6uj30
         iMHgA8LajOjgeH4l4YhY4PDloNGR24EC2uO8nEa/TDRt8GYpPZCPeU69EJakpiru5jYy
         6xa4qmmZ2h4MWfguN3tKU9pCY5/88bwaMYH7eyJHjvd5YNzjy3Oqt69706I5yq5bHAd/
         WjRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8vk1P98X5wFislYUCmYAXFRXimxyGQmLmxtAeRXAYBI=;
        b=ePy6QP1u8crH7Q+Ky1wxeBAVKPVYpGzvNe+TAQ+3l+yrn3MdCJIElBKuJyELqDLk2S
         nuqlJw6aG6CZO4M+rjBXop352MhcoENK1viS6D3Wpy2oTO+M90cNn+98tm9WzQmyKnrJ
         GSfJcDjx8fRlXLTJBTCdmCs7hZe877VifBojAs2Y9QYgpsiy/vrw7ZPCvVo1IQkUzQo1
         rn0wBBBNgNvfWiqZGKER+wsg3ZRPrLoUZRAT02hFOJXEOGg5zj3EvGmae3TFXRpnr6U/
         n8TX6PVfJKZqthjNY02dTvT2dTVxy1Bh/vKYCSOlrokFv99tQjFu8ZbVZDWU608wnmCC
         tklA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dJ2eDS6O;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id bg1si460672plb.5.2020.09.10.10.11.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 10:11:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id cv8so3685484qvb.12
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 10:11:53 -0700 (PDT)
X-Received: by 2002:a0c:f984:: with SMTP id t4mr9654083qvn.18.1599757912407;
 Thu, 10 Sep 2020 10:11:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+bfp2ch2KbSMkUd3142aA4p2CiMOmdXrr0-muu6bQ5xXg@mail.gmail.com> <CAG_fn=W4es7jaTotDORt2SwspE4A804mdwAY1j4gcaSEKtRjiw@mail.gmail.com>
In-Reply-To: <CAG_fn=W4es7jaTotDORt2SwspE4A804mdwAY1j4gcaSEKtRjiw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 19:11:41 +0200
Message-ID: <CACT4Y+awrz-j8y5Qc8OS9qkov4doMnw1V=obwp3MB_LTvaUFXw@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dJ2eDS6O;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Sep 10, 2020 at 6:19 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Thu, Sep 10, 2020 at 5:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
>
> > > +       /* Calculate address for this allocation. */
> > > +       if (right)
> > > +               meta->addr += PAGE_SIZE - size;
> > > +       meta->addr = ALIGN_DOWN(meta->addr, cache->align);
> >
> > I would move this ALIGN_DOWN under the (right) if.
> > Do I understand it correctly that it will work, but we expect it to do
> > nothing for !right? If cache align is >PAGE_SIZE, nothing good will
> > happen anyway, right?
> > The previous 2 lines look like part of the same calculation -- "figure
> > out the addr for the right case".
>
> Yes, makes sense.
>
> > > +
> > > +       schedule_delayed_work(&kfence_timer, 0);
> > > +       WRITE_ONCE(kfence_enabled, true);
> >
> > Can toggle_allocation_gate run before we set kfence_enabled? If yes,
> > it can break. If not, it's still somewhat confusing.
>
> Correct, it should go after we enable KFENCE. We'll fix that in v2.
>
> > > +void __kfence_free(void *addr)
> > > +{
> > > +       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> > > +
> > > +       if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
> >
> > This may deserve a comment as to why we apply rcu on object level
> > whereas SLAB_TYPESAFE_BY_RCU means slab level only.
>
> Sorry, what do you mean by "slab level"?
> SLAB_TYPESAFE_BY_RCU means we have to wait for possible RCU accesses
> in flight before freeing objects from that slab - that's basically
> what we are doing here below:

Exactly! You see it is confusing :)
SLAB_TYPESAFE_BY_RCU does not mean that. rcu-freeing only applies to
whole pages, that's what I mean by "slab level" (whole slabs are freed
by rcu).

> > > +               call_rcu(&meta->rcu_head, rcu_guarded_free);
> > > +       else
> > > +               kfence_guarded_free(addr, meta);
> > > +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bawrz-j8y5Qc8OS9qkov4doMnw1V%3Dobwp3MB_LTvaUFXw%40mail.gmail.com.
