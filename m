Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFMZW36QKGQE4THJGHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CBD8E2B0E04
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 20:27:18 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id x6sf2017390ooq.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605209237; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qm+A9uaRevneZBO5fKUBwBgwZqeDNjVm0XYO714K9uRUgv9QArzF41Cemx7lD8o2yC
         jftwNgm8HkvfQUeqKm2cgkKFnIVPOgTIy4gV1XBWLez9H2DfRSIeXpYCp4gfqDuOL59J
         aQs/3ac5hlbfodK4aY2Rs03nf/lHxD5dqTDRArKXYgc3nqb2UbpF7E5argJX/yDxICXA
         VhtnKA+WcXxSQXR9sSUY/jVzMVh29n3YqgB6wPOXbweQqiw/GBm61se8EvqPIq4poiAR
         c/km5P7p/1DCUz8xWGa5Hfx+NaulXEMCWner4s+TeSX2yfUOKGqeEC5CJ+6opvtM3Cwl
         dC2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2EgrtqhNDeE2+3GI81WIMBJvrY3b5jjZv3TixEhoasU=;
        b=D6mHND1S+ZLhD23DwuHwsIUVOK2hoEOMRhGTsBeoSrwbs9wEQjnnzi9m/JLm7DLLgQ
         v9guS6GcsrVcOzGbHadtJDHkiuk0FdWG68Fm0mT+WH7GuBSJWEfmQS1AcsZ8VVxeYxQ2
         zRR180fVWzEaQr+ooYScOpc7h/F+YgklNBvcqfZIE+UI2nQVhT/aPrP8ImdEsaIDcVDy
         nFd5jYAUOmOEz8zSSP/Ov9iLFYsPl2oIAcvjhuT82xty3zRxq6k7+fSLwb+QcZV6XIDK
         09baQVgtlQdR/KBgVJJDRuDo+e8kETbFQtiMv9DIVbxy+k6UfO/llQxJvqSSEot6yOIM
         6mMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d77qtn8Y;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2EgrtqhNDeE2+3GI81WIMBJvrY3b5jjZv3TixEhoasU=;
        b=YnxEhqOBAX98KwVu1nYVYHbwoEsyMKs9H7ga0waTOLG/wrQQNUxtMtEiQ1GZD1IPwf
         Ecx3sK5ZO/EJa5GwnTBYSInxmNN1u9+cf65SZON8USl8hO9mEFf7JhoLv3HsqIQ3Y6VE
         rIFDXX5K8agsPqBJ+Tnn4fa+M8igdyBkI7AViXgtRKc/rfQjuJWT9WlVEiqlpvXE5kwQ
         osAW4jo1sTcUf3z+VnY4LFcSPAmqSfCdaYykXUhr6g3c2TJi3Lu5htjmRRT5V1H7VXAM
         PVOR0/MqMYa04RBu0EGC5Ytz1hviZBC1AGi8eLma9QrQqrDDKzK83Crwa0Wrj0DgGF/j
         ExTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2EgrtqhNDeE2+3GI81WIMBJvrY3b5jjZv3TixEhoasU=;
        b=YR9I70TNLzRgRV/oFyHlJO/NOUuMutBBEHjcu6MRqsEU9DsKMz1Kd01EuZA05yJcUJ
         Gsd2IjrfpyRB7fl+olJABn9OS/cCWPg6SQk7/GzY42PuEp6J3282FZT3colZKyZqM7Gl
         QAf+/0y6OlBgHvkDtvjcPrtt69PHQCfVqe+I2WIrW+oTuXKmQF8nZAAE6Tcf22BfnDQX
         ICKyksvXG8ajds7QEz+q7mV4uZo+LORx6/78hZrAqE4zXMxkgKjyyQQbsquZS8PYbSIq
         Hx+I4eOMIZjsVaggPi127krKlm5P1ipo7rbev3RbXqBriEyVg+S145OqzfDN/bxjToKq
         voFw==
X-Gm-Message-State: AOAM530R/62SbbfSCNu8Cb9UISt+c0CMf+ajWSkiF4a+0EIvmJWAOnZ1
	mDXjK6mA7unDrmS1ZhkCUIw=
X-Google-Smtp-Source: ABdhPJyrfO2QTZH/SvSYVtmfmUGMdPF9oJY+iLR7u0ehPCwalh+cAM999sm74E7eLv3t6AJ/pcaQWA==
X-Received: by 2002:a9d:76d7:: with SMTP id p23mr581731otl.180.1605209237806;
        Thu, 12 Nov 2020 11:27:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls935584oib.5.gmail; Thu, 12 Nov
 2020 11:27:17 -0800 (PST)
X-Received: by 2002:aca:c6ce:: with SMTP id w197mr876585oif.98.1605209237395;
        Thu, 12 Nov 2020 11:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605209237; cv=none;
        d=google.com; s=arc-20160816;
        b=pNiy0mzirIQXnOt9d5ILrSx4Arl31QwFvNhy6hF4UUyp6SSclO7DMLpBClXLuORpNv
         CmazPyP4bMfqwCr+v/4lFPy9MvW+8kL5ra7EbxqpGHpF1rTh4sYunrHGGELJRn55BvKC
         09Qz0idgxyJqVzK5RwindHafSYjODiBb9nZvyHoJqTUV7dEmK7F4X0qMWobHRq6yUnjk
         YJ5YDOmphOYxgR2gLxyO++O6am2DvSFYGhraNXJVysFbaECZq1pkj1Gar5j/rNv/+i0U
         i3T+C4qxxfwe81n5uV8L0E9eGSM2501l9RiMXncTlfxzZhmloG//GYjruw/phRa4d0l0
         rbMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xycyBHYzWiVaz+V9gLDQX6HE1E3HaoQ5YhnMfRsWwHI=;
        b=pMYbjv+BukH/7Il/tYSpvWbFq4UmHx3WC5HV9t89n5iIbKI19MI3OEADZUaO9OWUkp
         T0XnGth2IDI9EwtnHFHVvZfbbWA4HAROBFiTIg5T1Rw+CNY/1VZJiP3GnQ5rC9x6Z5DP
         X6KMPrmF5scFL9J44p08uuZ7VszlI3/aqr7JqoLGi+32n9wZQxHLQHmON9DJLOl5adb7
         Y/+sUzwYCacgfxpIZZwycr/JDDyKNqRJTzkkUoHueU7Afi444vuWl8c2i7W3rNJxWoNH
         PCA0J+1KdgbC6xC6SGn1iyu3OiuY77alN+mfStIZLLMzMupJ6ArggVKUoVpTntUgTBTv
         /1tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d77qtn8Y;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id r6si932124oth.4.2020.11.12.11.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 11:27:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id w6so5494672pfu.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 11:27:17 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr747894pjz.136.1605209236569;
 Thu, 12 Nov 2020 11:27:16 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl@google.com>
 <CAG_fn=VXhK0d__FkNdhdquy9F4VmB64_6eJQOQBRecy2oL6huQ@mail.gmail.com>
 <CAAeHK+wX+JPyZm2A5mDdGFCqnH6kdSBLyOZ2TnWfZnZuq_V0Bw@mail.gmail.com> <CAG_fn=VPEC4Lk+zaN25M8fygFKpvqLVzwYg-WHB9iXdY5JK1sg@mail.gmail.com>
In-Reply-To: <CAG_fn=VPEC4Lk+zaN25M8fygFKpvqLVzwYg-WHB9iXdY5JK1sg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 20:27:05 +0100
Message-ID: <CAAeHK+wc8Z-mYR=UeA3XwGjiUNr0f+bAoouKu1MP-vsKZ2+4bw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=d77qtn8Y;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Thu, Nov 12, 2020 at 4:16 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Wed, Nov 11, 2020 at 7:52 PM 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > On Wed, Nov 11, 2020 at 4:09 PM Alexander Potapenko <glider@google.com> wrote:
> > >
> > > On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > > >
> > > > This is a preparatory commit for the upcoming addition of a new hardware
> > > > tag-based (MTE-based) KASAN mode.
> > > >
> > > > kasan_non_canonical_hook() is only applicable to KASAN modes that use
> > > > shadow memory, and won't be needed for hardware tag-based KASAN.
> > > >
> > > > No functional changes for software modes.
> > > >
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > > > Reviewed-by: Marco Elver <elver@google.com>
> > > > ---
> > > > Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
> > > > ---
> > > >  mm/kasan/report.c | 3 ++-
> > > >  1 file changed, 2 insertions(+), 1 deletion(-)
> > > >
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 5d5733831ad7..594bad2a3a5e 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > > >         return ret;
> > > >  }
> > > >
> > > > -#ifdef CONFIG_KASAN_INLINE
> > > > +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
> > > > +       defined(CONFIG_KASAN_INLINE)
> > > >  /*
> > > >   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> > > >   * canonical half of the address space) cause out-of-bounds shadow memory reads
> > >
> > > Perhaps this comment also needs to be updated.
> >
> > In what way?
>
> Ok, maybe not. I thought you were restricting the set of configs under
> which this hook is used, so this should've been explained.
> But as far as I understand, CONFIG_KASAN_INLINE already implies
> "defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)",
> doesn't it?
> Maybe this change is not needed at all then?

Ah, yes, you're right. Will drop this patch, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwc8Z-mYR%3DUeA3XwGjiUNr0f%2BbAoouKu1MP-vsKZ2%2B4bw%40mail.gmail.com.
