Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZPFWD6QKGQE4FOPFRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 79C972AF891
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:52:22 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id j10sf3219652ybl.19
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:52:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120741; cv=pass;
        d=google.com; s=arc-20160816;
        b=FVLfW3vCPUHeNj+kEbrvlXOOkHRX39riHoUnq2WlQHVgkPbmKLJc2UC0Wge0sfvVXL
         e2TwhI6kUUgIAbJPAwNHGy+14c23iEYk7MR77q3S9hNuwSF+RBlBmvemonniakMYQM5s
         bi1o5JADhm7/aiPjf0cX458EP93hJDyfXyy2Rh8GqUT875bjQFX9NM65/azw9I4jhkPg
         DoPgJdggpY/an2+Gr8cl04GJQClMyXqoNRtMMjENU2SWUf/f1hB3fPqu48BCoGs8Fxqv
         pHEK9w9RRQCQnTqYyAnwqaPkdwA9zkJXwahsR6EiZTNqx+nQL2r8jccwx9lCoGja6sT4
         i+Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EwuDhNbTpQzjrtcJNHQWzFbpS6M7H9GKNAO8U+Xx6qY=;
        b=lU4MCZ3YiV6hiOE09MhPgT5OqKqxpifDKpAbfVfv0DIRFcDalgRAyED2Qs+RwVS5u+
         6I2PULy0i6q7Utl/TXBH5vLclTuxkW05hzoTlGGnqt0r0PbeEszDgHB8A/XtWXQx1tZg
         uFfJS9FPVyWE3A5N5pnalEIJBj2OhBkIKldkkdjTdxQuuaO0Wb4yETwpkXYxX3tgSMw+
         vzOprDrVdYzv52zAmemBHrCet6DThByC8pJ+ZX+bsZUk2+9aAhwBJcbPzyMn435b+Dns
         PvzIrLjiGJ1Xkix30tkKjRPIago6HxFeRXueN2i1Mhzn/zoBRhIfjhNfvpoztQpDaK7/
         mTAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iNz4Bk2U;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EwuDhNbTpQzjrtcJNHQWzFbpS6M7H9GKNAO8U+Xx6qY=;
        b=agKycXD0Jlqqf9aowTqD9BLPJERCur6o3Gt6EvYcj9IvdStD8DlDR0PLaRXkhK/WLP
         /JX9oligPFd38aNWCcMSSyULj9LqDf37iJRCpRI6/NwV6U8Nyf9N88OeniiimhYy8aDf
         T6gtWWGD8lcNxiCBwcsXOwQoOo2J2zD9SpJUfkmPzeuxpcw3aPxRhxOf8WbPTyqhCtX9
         fIiDXHxBtq+2UYj2FlKo/rsmoekpFAw5EwmnUVV+jygn4PKUhkvPdnHHHktzlD+hKJvE
         YHSfP5L3sHk9ijZBJDmscxe3lKu1UXARydP5ihmF6F24TUN38qd4Nlj3Z6it2d0FOU1l
         0LcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EwuDhNbTpQzjrtcJNHQWzFbpS6M7H9GKNAO8U+Xx6qY=;
        b=imDgpwdcrT7KCLvPn57091Sd9YZv1kS8u3qIftWoU+Yx7UXqK6mC0NzjD4jnFtA2gB
         YiallN5V3f93xjL3X9HlBOf8h8xPwmi2K75+VWxaiTAhIsWJeJWHRn9WN+9SNLZuJjGc
         Z5IqdkW96JNNwTBF5+mW3dEgHgkEGSploEYGXdtWmrQNqPkufG/Vqi3uw7RRCTm4ShPI
         +CIX98dug2Jo5uzN11VwfKNmJlBJ4sFHi4PlqzSYIvz6ikdBAG/KedAi/iIuiAA9s6ay
         7m2rz3nz/Jk9eyAH/J/y7hFbgRHKnn64GEdv8NJTHKW0G77otEmT3QInFVqMKFNfWged
         b9mQ==
X-Gm-Message-State: AOAM531skX+pmtYL4OaI66XyRme8nmPayW3QRoB+sWMHM53wwLf5bZUe
	I8FFURsMeAMrUnNIqv83J40=
X-Google-Smtp-Source: ABdhPJyjqv0vQot8yKgz6fMJKSH4+X4zhzpgjfhyiAc00kn3vo0fPQ6t0pm+yA/mmg/ALbYOzP5m7Q==
X-Received: by 2002:a25:4004:: with SMTP id n4mr16625170yba.382.1605120741418;
        Wed, 11 Nov 2020 10:52:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a268:: with SMTP id b95ls355284ybi.10.gmail; Wed, 11 Nov
 2020 10:52:21 -0800 (PST)
X-Received: by 2002:a25:585:: with SMTP id 127mr24460087ybf.425.1605120740966;
        Wed, 11 Nov 2020 10:52:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120740; cv=none;
        d=google.com; s=arc-20160816;
        b=uHlo5ktjqvfYv2ZNhwu+rZcjWM8Vk4dXkOHqdMsxwj9ydIz3tjsN6ket62qKh0JeE+
         efrWAMC4NCbW7O1ARMYEX/NAazqgSI245BykbeRnZGmkpWw6X/q1qCUBpA9YTt5xROaP
         g7RbcZNG5TNjhOKatn5YTj6AqWmBMzPMfbD2JojD6roKR674Ofoge/NUE3mUqLXyamSE
         trn5W8gEa0Mlju+ms64jSYFUlL2tmrnvFr4ols7INeXOL+zSMcmN8FMdH39cTz4nC9Z8
         EoGAsSIwy2PtbLkU1ZTaj5aatrhKq9PTLJ713uRPSKexUj0NpBfhdjT/U0llTdInb88u
         cnCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e9me8OLCg9caFbPV5Uj2BdRlxnobSrjFoBA3jMpvquw=;
        b=C+OHZvhUrYYsqiR9wMh7RbdZ7+i9SVX2L3hVorQy8LwmXSDM66Zmikyn0VgwAQ8wJW
         hoJzxrhiitlduyqZaJDh4AAjcEZF/W+ZCY47HX458vtLIRHFnUT3w4+RTwcxusbiJRj1
         D/JA8ltQcZvy9q1sCoG2xwTbHR1O7FA3B1sZxEHSb+2Kr8rb53TMgSuTRf68X3comq0W
         e83dXUMNR0ucfvmR6yoyAccriVWTVoN+bOoGQyAAAnqGt8FcCRFO+puOuO2kiEZTrLn2
         zGJMnnuEyxKhO7VFoUIo1//3RRaiRZ0cfiTSWlS14HCnNyLBY89y9aOxtrfvYushw16A
         JQdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iNz4Bk2U;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id g36si142228ybj.5.2020.11.11.10.52.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:52:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id w4so1943555pgg.13
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:52:20 -0800 (PST)
X-Received: by 2002:a62:cec6:0:b029:18a:d620:6b86 with SMTP id
 y189-20020a62cec60000b029018ad6206b86mr23279253pfg.2.1605120740077; Wed, 11
 Nov 2020 10:52:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl@google.com>
 <CAG_fn=VXhK0d__FkNdhdquy9F4VmB64_6eJQOQBRecy2oL6huQ@mail.gmail.com>
In-Reply-To: <CAG_fn=VXhK0d__FkNdhdquy9F4VmB64_6eJQOQBRecy2oL6huQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 19:52:09 +0100
Message-ID: <CAAeHK+wX+JPyZm2A5mDdGFCqnH6kdSBLyOZ2TnWfZnZuq_V0Bw@mail.gmail.com>
Subject: Re: [PATCH v9 21/44] kasan: kasan_non_canonical_hook only for
 software modes
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iNz4Bk2U;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
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

On Wed, Nov 11, 2020 at 4:09 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > This is a preparatory commit for the upcoming addition of a new hardware
> > tag-based (MTE-based) KASAN mode.
> >
> > kasan_non_canonical_hook() is only applicable to KASAN modes that use
> > shadow memory, and won't be needed for hardware tag-based KASAN.
> >
> > No functional changes for software modes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Reviewed-by: Marco Elver <elver@google.com>
> > ---
> > Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
> > ---
> >  mm/kasan/report.c | 3 ++-
> >  1 file changed, 2 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 5d5733831ad7..594bad2a3a5e 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> >         return ret;
> >  }
> >
> > -#ifdef CONFIG_KASAN_INLINE
> > +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
> > +       defined(CONFIG_KASAN_INLINE)
> >  /*
> >   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> >   * canonical half of the address space) cause out-of-bounds shadow memory reads
>
> Perhaps this comment also needs to be updated.

In what way?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwX%2BJPyZm2A5mDdGFCqnH6kdSBLyOZ2TnWfZnZuq_V0Bw%40mail.gmail.com.
