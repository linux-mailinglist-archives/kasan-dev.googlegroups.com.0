Return-Path: <kasan-dev+bncBDW2JDUY5AORBLWEWGJAMGQEXHDHS3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id F3E9C4F3C5B
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 17:37:19 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id b18-20020a63d812000000b0037e1aa59c0bsf7561665pgh.12
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 08:37:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649173038; cv=pass;
        d=google.com; s=arc-20160816;
        b=MjOP8yL+AZXQYuph7SN+q7RvLlHNH4WPc7WB+oeRbvagqISnON2UFQJJVDLxmlu5ys
         NbxPkbr2s59aySbNqFkR/ZyNSz9f4oKM+iXubiBu0IrEP6KFBVYb9jKjAIuklrwVYl7i
         YtlYme9hdBwFIZoX0WgLcW9xbWMrdkvphrIQz2GSNdEyQCvt16pEVJGhuJNMMdFd2D9J
         t7e0M/R4VsNcz8yw2NthpqLC5bv1x/BDAwo2hwhhdKDH3/HX+xswoQ44+iLjNB+rY3VC
         UcRC4sf6k4Xv+m62PsMlfaKueLKAHXktzAF0urg4f4QW9d64Rhvwl2ZtviHC5eUCOLGQ
         dQxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=6hGHV1ZnJ2PuO+AOc2HKmBMEANEOfYtf5oLB8RbRPpw=;
        b=o1sZjwlzRY77sL5N5rShhj/WviPuBtHfxBfBGXcZkZB6vDbPgyCJl+c/eVFtjXu7q6
         wzdwnCHD70XSpYreKaeqdl7YBxYPQMF83ei1kx8GMb8iaJymg77fsoe7hT4cmsASNm5m
         U6uGF5GhfH4VCcp5vSFx3n9JOcoiXcFa/ENUVxtCs0FDZoIkvwYH5s1pIGSMEirH/Gf4
         TFrAXBNATJC8usnbKPeJ1TAAj4AIKxObMZjQaivGBDC2aW79Plv7PaSIC0JlZUsgdghf
         sASfdGW7DJsbjU8nzS5liosem9aWg6TA8/gfeSqg1dxwIGd319IX1EcBkRInzHq7PqD1
         iKnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dFZM9Jrm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6hGHV1ZnJ2PuO+AOc2HKmBMEANEOfYtf5oLB8RbRPpw=;
        b=AQUSY66cxotA7O1elhj3L3E4pXn0vjL+kLVVga+cCRB6MZ9n8xAHOvjuIYRr9igXEd
         A3GP+02OuWQibA+/hJns30bCe/P/FyYYpjoQ7mrCBKY/QL0q1GhyfzLcuQf4a56xT++I
         gP0cmDqGrk7WmLw5PNj5LbDw1jkjG9JXYOr3XfivtiYwUWI44/g8HpAOoOmiJgs0+65J
         DGY1vPYdKMciKXy1K5yczpKZwq5LylfKkFkeRKk4NoERdDsMlHJwqoQZ0buiB48K87Ne
         OEdy5tvZLHyiwFSwB3Kt9a/W3LSIkf+UHfZYoMwDDrZjFjepV2kHLpbNJ6RcD/D7VeE1
         meqg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6hGHV1ZnJ2PuO+AOc2HKmBMEANEOfYtf5oLB8RbRPpw=;
        b=d1kpMlqL18cpQbZoM2yTSpFIf/VPqqjsFNHJXVHCXHWqHY6zGAOYlWDth1MelC7Hms
         mgV3yBu4szB1HAiJoCq3EfXVxVqvktkVHiJBbN6B3Zm6rGE949PN38cFnRNBx5KTeQ0V
         Yy5Ccjuacfy2jjgAmD0f9fs9t725BQV3RVPDXyOa26MS5goHOmvlVsr9jQ8OZhZLJIa2
         Epuy5YyPJ7mWMgmEWDiXL5mji3fQE2aOG9++8WdosTgzQWjoYzbGk4Ov38yPCS3ENGwD
         f6Hv7Jb9sCw9nouAS9bB9vEIWJxKDJqQTxggWN9e8eZfUYhgyIbw+aOSjLWA/NfUCTpc
         FU+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6hGHV1ZnJ2PuO+AOc2HKmBMEANEOfYtf5oLB8RbRPpw=;
        b=K6CkkVpr9Uy0HW32pq4pDy8PNP0GLOjKdZRRl5iXJ3PHMQyBwEn0iWgVcW1Ctb1DlT
         LGAxdkSt9wn5MtLJ54zJHgbpZYdna+yrn4sXo+Y1lmQvcr0VXcg2b0Q+Ob+lt/jzTv/a
         BDVgvjTsLhJlwLStMwjV4qry2okkPgqKOx2zOfB6OaQ5+GR5D2iWS2uSoUBvdRY0Ho/B
         LUmr03nnbqrfpQgNclcl+d0CK/jF43yg06Sg0YtPL4w1tP/2y/4YaX8seaqocC5r+fz8
         sz9LJRtXz0QdmxoeNS6IXnkeQzE9EDlA+fqh+KOKeMxV8Fhgei1lXvN2aIQbM1HXlRNr
         UP4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530nV68UzCDnuhmVtGdYOx40l38g9EN2UYeFyCTnmy+GK5hexj/a
	KJHxPQwE6VWZGmx/p5jr/+U=
X-Google-Smtp-Source: ABdhPJzLI52BNprip5PU0x6pz8exsoExo1N+Vf7flEfe7pmjcKh3IjZLcfJW9OYy5hbS0dueT6vSGA==
X-Received: by 2002:a17:90a:bf85:b0:1ca:8a8e:bec3 with SMTP id d5-20020a17090abf8500b001ca8a8ebec3mr4774127pjs.127.1649173038711;
        Tue, 05 Apr 2022 08:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b49:b0:1c7:821f:8386 with SMTP id
 ot9-20020a17090b3b4900b001c7821f8386ls2869227pjb.0.canary-gmail; Tue, 05 Apr
 2022 08:37:18 -0700 (PDT)
X-Received: by 2002:a17:902:c1c5:b0:156:a185:97ce with SMTP id c5-20020a170902c1c500b00156a18597cemr3989582plc.133.1649173038164;
        Tue, 05 Apr 2022 08:37:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649173038; cv=none;
        d=google.com; s=arc-20160816;
        b=wY71sR+d/Nr4YuJhZ1snv2BitXdE8p6VW205Uyv+1orz3Ds/ukG+ern8dZAA6+7CZF
         kk9cMLQn7a6BIPwY1E1ICO+KprxKnt7K4szE3p5zt/EpNM1Xt9DEs3Utus9FvAN8g/xd
         IOKP7AEnDZG4WqI6W5jh3MTRXCmrBw7MjTYm/ZeWqemd0dkDaYkn0Qv36MvP4KKauDVK
         UJgIm84Zo8yHbAV95wgq/Xej8BDQmkTRhJJlKnzVI5ZTKo1KxOYtWaKyVkwzq1MWdtRy
         UDip0A/bXgNrubqc5yZD8zEFXJ4jRHx09QBkl3w0y12puKcDYke29RH1jHCV3JPqik7F
         nJWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FtaEgz69DQ819AKh/JUIG3OQ4Q+fmie3I0z6sDwsCCk=;
        b=l4t0HRDJML9v2MKMfbzrNKlvjkW8POthEWJSbFelghDLJStS0afmKnOJqZUY1XmO/P
         tLLiCMRZZkJo8Y/mYfB0YMQCHw1N82SEwJ6NO7mEC7wi4D2N9WfIHVigbsAKIh2fPNpb
         9I2yQiponl2X4Sd6B6If4IYi9+Ra10UMBepy7VLoyXp2e9s9ClzlzEJHIUbZ2PDZlW22
         4IXgbNYAWd7aVGSQlIGl9SYLSe76Yoa9zZA5mdRILwMSXjI/5vIJt9VZLSezg89/frvT
         JD/uZXDPBtAOQ3y25gvZTpaxydBKXkfEkybB/NVR+HeZ9/mrHhxqYh3c86p6xqrFZNMl
         n9cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dFZM9Jrm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id z15-20020a056a001d8f00b004fdca03b476si545567pfw.6.2022.04.05.08.37.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Apr 2022 08:37:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id r2so15564833iod.9
        for <kasan-dev@googlegroups.com>; Tue, 05 Apr 2022 08:37:18 -0700 (PDT)
X-Received: by 2002:a02:b687:0:b0:323:60e7:121a with SMTP id
 i7-20020a02b687000000b0032360e7121amr2473005jam.22.1649173037888; Tue, 05 Apr
 2022 08:37:17 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
 <YkVyGdniIBXf4t8/@FVFF77S0Q05N>
In-Reply-To: <YkVyGdniIBXf4t8/@FVFF77S0Q05N>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 5 Apr 2022 17:37:06 +0200
Message-ID: <CA+fCnZeVKv9iJknyHiKWF0QA3vx+SznJCDJ10Q_HmnzHmnpt=w@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] stacktrace: add interface based on shadow call stack
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dFZM9Jrm;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
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

On Thu, Mar 31, 2022 at 11:19 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> > Collecting stack traces this way is significantly faster: boot time
> > of a defconfig build with KASAN enabled gets descreased by ~30%.
>
> Hmm... just to check, do ou know if that's just because of hte linear copy, or
> because we're skipping other work we have to do in the regular stacktrace?

No, I haven't looked into this.

> > The implementation of the added interface is not meant to use
> > stack_trace_consume_fn to avoid making a function call for each
> > collected frame to further improve performance.
>
> ... because we could easily provide an inline-optimized stack copy *without*
> having to write a distinct unwinder, and I'd *really* like to avoid having a
> bunch of distinct unwinders for arm64, as it really hinders maintenance. We're
> working on fixing/improving the arm64 unwinder for things like
> RELIABLE_STACKTRACE, and I know that some of that work is non-trivial to make
> work with an SCS-based unwind rather than an FP-based unwind, and/or will
> undermine the saving anyway.

Responded on the cover letter wrt this.

> > +int stack_trace_save_shadow(unsigned long *store, unsigned int size,
> > +                         unsigned int skipnr)
> > +{
> > +     /*
> > +      * Do not use stack_trace_consume_fn to avoid making a function
> > +      * call for each collected frame to improve performance.
> > +      * Skip + 1 frame to skip stack_trace_save_shadow.
> > +      */
> > +     return arch_stack_walk_shadow(store, size, skipnr + 1);
> > +}
> > +#endif
>
> If we really need this, can we make it an __always_inline in a header so that
> we can avoid the skip? Generally the skipping is problematic due to
> inlining/outlining and LTO, and I'd like to avoid adding more of it
> unnecessarily.

Yes, I think this should work.

However, if we keep the implementation in mm/kasan, this integration
will not be required.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeVKv9iJknyHiKWF0QA3vx%2BSznJCDJ10Q_HmnzHmnpt%3Dw%40mail.gmail.com.
