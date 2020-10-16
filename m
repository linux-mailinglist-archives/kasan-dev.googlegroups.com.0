Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVUDU76AKGQE73LBG5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 023802908E4
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 17:52:56 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id c5sf1873114iok.12
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 08:52:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602863574; cv=pass;
        d=google.com; s=arc-20160816;
        b=PaMs5t9jAVy8ugCibXCqZCZVyTnlcGOuh3vAkUcl8vYuL8HugnN+9lvt/eHRgKSDH9
         Cija02XX7EL3qbaGZcMgAypklJGe4qu7I8e497XeatBkZMFxMwGjEwX2dskah7/Ivso/
         /JQlYkZ790nxknM/YTteK1EnIqp9fGpd5ZKbfqOXzZbntOPzIxNdqG0IerdZglsikk/m
         vLL6iIVCLo1TTfR2zPXdyQcGhKPSxWVEUewXlkoFhaoz+ZCy52nqOXE5XA9hz3MvCkmq
         ykwx6VdMgAOFEA5IkoXt1gUezAykqFB2OZkG9+EuNCoLu8f/5P2TqKoYptQg39Ajgg1L
         fzWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2QcY2mwHU7lOJNpYfbmW6ou+PMPydTV1m2o54CFhhDo=;
        b=ydEa0ahfWc76fU9V6Oy2dbwEUz8XaZ/ZiqN/TM6QXjNRXYh8ens3+EI63Ryi5iQ+Lm
         1R+/hZD7CgUqmsc00nWmfEejJP/jGjHr5InA2l41SYCWqGwKwUu8SF+FKtPDWpVUsIZi
         YNCOKRhht8wu+EKH0HEoVupV7X7HsZ0+Hw4+XoocDDCOhBjo6XjqNmajlDapxqupCTWD
         XCl5korxIaG8eSqsOr0+Z6t5MSqeXjtZ/x6ET4vZIOYTgEYWKVF2JLpxGdWaufEzAg3A
         x0ZwkUVubhXBSOYq1C4CqKrbQY9VFnF/QVnCU2TgNSZiTUzfWxfXsy/S3Kc66U81UGGW
         UPhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=odYcfxCn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2QcY2mwHU7lOJNpYfbmW6ou+PMPydTV1m2o54CFhhDo=;
        b=ZBbk/ajvTOFUEIQnKr55O8spgrtZftztVhA6hpdeOWmsXRT0GC7z108dAB/eNEPCbt
         rBudtl233ZXR+ZGGhrRA61Jx7++6F2BbXvmCD3kW5c+0tef6ZhTikbIywpdCNZZFry2Q
         2KrGBkrsii9f7zBhaVhEjwpifKqnf8NHSLpDw4/fnjHhRQxv8wVFFUy9rkLH8TAPJUGa
         0UnyQsAQm/nSeaF4H06SEQpLnCzkTPu8y/DjGl2RnPZFmMgqav/TJt3Qvy0Mc7S4wjcd
         6Z3X2bNNikHrLokU9HYiM1EvTe3eAHxtXWNl/yiWa60YYHsEN/zNBsL4JREUcpQ7Jsnz
         qdzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2QcY2mwHU7lOJNpYfbmW6ou+PMPydTV1m2o54CFhhDo=;
        b=VO3D9HCRlwBkJUXWyUbjDIY047fVqy8L/RZrOEdj5nB251nI9CaUaumFuw4Su4wXsm
         On+jF+z4o7E5jiaj8R2YX02VpJGFq0+g9z8OxK+9/Cjj2Hs7mtPbBio2m6/UvBmJZOF6
         abuA794JoNfg7DDAhzNq/uQ+1ecezsvF7eOMtAX+tg5R35jVKkJJukOyPBuU8MvMyBgz
         ncOqu/vTl0zsG5Y4I7NltadnCkHUJkQtr+7+JODPqJqwor7TcncrKkqSUzFo6lT/5L25
         WY6WjjEn1gLHRbk/aeIcv2uRJnuFyd3OAzsp8/8X4Mx9NZMLrkSEGZ+m3AUC85ASLJDu
         Nrng==
X-Gm-Message-State: AOAM53287FRCjPC5G6A9u+Lv5By74a0psACZ1Uc/5HXzpCca3TO0mgJW
	BO6USMRVUhFsFUvaAN+bLFE=
X-Google-Smtp-Source: ABdhPJzZl1oPSSYNwhJ0vdknS1bRIXDurwcw7kHBp+Xme1lpveIuFarD3+hRT+JPWsWSg9b2nl3s3Q==
X-Received: by 2002:a05:6e02:f90:: with SMTP id v16mr3260313ilo.290.1602863574684;
        Fri, 16 Oct 2020 08:52:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6612:: with SMTP id a18ls563276ilc.7.gmail; Fri, 16 Oct
 2020 08:52:54 -0700 (PDT)
X-Received: by 2002:a92:9944:: with SMTP id p65mr3073430ili.127.1602863574326;
        Fri, 16 Oct 2020 08:52:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602863574; cv=none;
        d=google.com; s=arc-20160816;
        b=bUoxIhSy0iOxW+XSRqd23B3jXLWKUZonEkfI6ncrDddKmSg2RSXHrq3KWkXoyYkZ0n
         iFmrC8OAH8nPCQ10UlEVomHmZNDM6j0l5Nt0+JR0BCK1yPQ1eKg273nNCfvQCqTlU6QY
         8RQ5iD4cfBpnlykPogZAnYNf1N5NgxDBtO5j9dyV++iNpCSFRg57xX7Af8lTiVmTo4ad
         EjDfgKwf2d/qUNM6jTIAMdVSUf2g8/akaTzKTpWnbPRqJBnUdhIiOqIcf1FnQvvDGezy
         JYqqnWFmBmS8Ybl/3boa8AErjIHVf3K/2VPSXKcOBSV9tHYQtGmhgaERDcoUOmfZdK92
         M0Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3kC6Vgkm0RSxbZXaUeBWqyQrYh34yUHxn1mWSex6aQg=;
        b=EcNoB4D+N5EW6UdQM/rG5YDvlgDfF3QzlI2xKaCpu4XZYfkWO+twbpyx7DXvO2TnSB
         ube8q6gZe4H90leytcnY4NnrUZb7NWhwSbweA+UbdsbcsADVHFzv+3jbeZ926Zovnfdz
         3IY2OX0BW8uLaHu6HrBjKNa3nZBpl5sjymAfLlP0xXfL7cWJtzID+eD7omVXytHb8RZv
         OaKcxJ9fAMxuiTu6ZcWoVJSzuvPbsCnZT0g2qhORQMJCAl7m2LXTpYsPYGSZ1LqL/Hac
         0F/g8obKDeNYbfJeOEwnTa7ugGUtWlXnAGa4Lucwa14A+KePDDvGI7qH9qecYr+md0Wd
         jq8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=odYcfxCn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id z85si180613ilk.1.2020.10.16.08.52.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 08:52:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id a17so1613447pju.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 08:52:54 -0700 (PDT)
X-Received: by 2002:a17:902:5992:b029:d5:c794:3595 with SMTP id
 p18-20020a1709025992b02900d5c7943595mr3319246pli.57.1602863573590; Fri, 16
 Oct 2020 08:52:53 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
 <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com> <CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A@mail.gmail.com>
In-Reply-To: <CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 17:52:42 +0200
Message-ID: <CAAeHK+yuUJFbQBCPyp7S+hVMzBM0m=tgrWLMCskELF6SXHXimw@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Kostya Serebryany <kcc@google.com>, Serban Constantinescu <serbanc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=odYcfxCn;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
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

On Fri, Oct 16, 2020 at 3:31 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 16 Oct 2020 at 15:17, 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> [...]
> > > > The intention with this kind of a high level switch is to hide the
> > > > implementation details. Arguably, we could add multiple switches that allow
> > > > to separately control each KASAN or MTE feature, but I'm not sure there's
> > > > much value in that.
> > > >
> > > > Does this make sense? Any preference regarding the name of the parameter
> > > > and its values?
> > >
> > > KASAN itself used to be a debugging tool only. So introducing an "on"
> > > mode which no longer follows this convention may be confusing.
> >
> > Yeah, perhaps "on" is not the best name here.
> >
> > > Instead, maybe the following might be less confusing:
> > >
> > > "full" - current "debug", normal KASAN, all debugging help available.
> > > "opt" - current "on", optimized mode for production.
> >
> > How about "prod" here?
>
> SGTM.
>
> [...]
> >
> > > > Should we somehow control whether to panic the kernel on a tag fault?
> > > > Another boot time parameter perhaps?
> > >
> > > It already respects panic_on_warn, correct?
> >
> > Yes, but Android is unlikely to enable panic_on_warn as they have
> > warnings happening all over. AFAIR Pixel 3/4 kernels actually have a
> > custom patch that enables kernel panic for KASAN crashes specifically
> > (even though they don't obviously use KASAN in production), and I
> > think it's better to provide a similar facility upstream. Maybe call
> > it panic_on_kasan or something?
>
> Best would be if kasan= can take another option, e.g.
> "kasan=prod,panic". I think you can change the strcmp() to a
> str_has_prefix() for the checks for full/prod/on/off, and then check
> if what comes after it is ",panic".
>
> Thanks,
> -- Marco

CC Kostya and Serban.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByuUJFbQBCPyp7S%2BhVMzBM0m%3DtgrWLMCskELF6SXHXimw%40mail.gmail.com.
