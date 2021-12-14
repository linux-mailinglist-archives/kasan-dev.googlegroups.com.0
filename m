Return-Path: <kasan-dev+bncBDW2JDUY5AORB7FL4SGQMGQEVNYDC5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E4379474DB9
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:09:01 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id d4-20020a17090a2a4400b001b0f20e1ebesf1236721pjg.9
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:09:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519740; cv=pass;
        d=google.com; s=arc-20160816;
        b=SInJeuv4cOy+zVOOi5wsHOMbv6xqQPFEMwSD7idoMydwrNnUKolxQliv9/YYfkUTRk
         F/ba+RIsb/I1Ct98QnEWVPPMDH202z8X7I7CL5Z+TJ5V5p3sgnznlyuDJhPyZ27BlQTb
         kABq+R9lJPWLkq2vhvLW4+CxqK1paQm3kgnJpngSdWfZymZWz0W5liLHi7S8Cga0laAN
         Jq7hmrbx6SEx1n6wMDASTOGN9+TxOHfJn0uF3wz20OVAdgU6F+eS2lLMF+ZCdy7aoWcw
         Q4lgSaqrhLT8XfpzJ7YJOtfJs2LGWWAlG0hCh0qkswogZA2qZ09K0Tc9VpgVE9ZYr42H
         8rIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kKa8lRibfCiTkLTmzAfwI+6ccIq/5zy34A6UF+MAJIw=;
        b=OyjjYD7djEoYNowskmAcIJYtFc9vPg2jO2pzxDbHblGIYIA+B+dbG4ujHaoZIYQEJ+
         3rDTYw5TfEA8vxDghnu3SVa6XPOE3Ln7bCAHqhztUw355XMErDfUG+iJRJ0KEo8GIFac
         EiH5vdYs4eop3sCToLdITW36OlOrC6eeAT5m10HvufBEFG4gDTgX75wJ8ER8mgOo797u
         sTfvLMXlkoQjxQr3TA3xFYB78KBJxvEPj8X9ttXPwbLEA8J6yYvYp3AWDwDLFcCy1UgI
         qlO6zVrdFXMDoJZVm1xh/F4gKqRDbNG1e2k19O3yJpQNYLBWlgY4l0ScDwWI3BW8q9qt
         m8yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Cc38oMKW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kKa8lRibfCiTkLTmzAfwI+6ccIq/5zy34A6UF+MAJIw=;
        b=rr4mcMWBcvC/09OReXnH5wjS9tfmIDAyn/DQmqPzxx/Bo3isqZyiTyxACTyQfBSXCQ
         FLHm+HfTOQEDQUGEc1wpamAO4Fmhmgk40VaCH3Z4Coe6S0IWz53xJ76VmgoRKAV4aI4d
         zouF4uKeNoIabFQfYflNjA6fcBNwhPCQkwTq+2KZvr32kbcRpykwY9MX91Hjk/kd4mqX
         duGHOyt3zn+1v9EybFFCvSbLP6BzgtoBgiSy5qqCE72q61R60gnZlQ6ScH+8zNQ75IW6
         rjplKIwBvIUGjMCr4HpYJFXmjWwc+vWj6HuLKjCmILyXf70DlDrr/5s7FYq20UJaiRnH
         tdjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kKa8lRibfCiTkLTmzAfwI+6ccIq/5zy34A6UF+MAJIw=;
        b=SrYjOYtRjqG60/JnVBgtixexDc5/xHY+JM/LSg2v5KMiKAKBKwxTDShah3IyBq1vST
         KBiLWtJZVGBq5Byi8ekjN9K4q5b62Uf+g0ToiV7628GOlitxKtUAQaliQ8z0nkYnRD3A
         XBUzfWdt9r7O07+WA9GnSONvdmH5oQ7s2j8ZzsNyJE40db7Cw/DtuM9A6i6exC9JXDgY
         F5AnrSz0jBvr3OAZ5iQAhLdvv/Ahpnr+cwoesMte5c+N/BO78PwqYQ8N21tuB6KR9aTW
         SXyAVgSsEtb3cVelonWEYaWUdqEM891ptVrsGfvHpUBAZYZ0beNwdp7JUhf6scbyEgbn
         nrNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kKa8lRibfCiTkLTmzAfwI+6ccIq/5zy34A6UF+MAJIw=;
        b=snTBd0WrmOnZGL2K2xi6KKeVkpjDU1oJbOtIfommJzLBPsISblZyVkfeZyLnqQGHK1
         BFJXFT3ONi1PQ7jBkIb84c6Yhlqgf9tqC8f+/9RnNXe9PViffMxq/B7x2v2C2lupHgjo
         jd5LxgZZDo3DGJuGzZc7WdNHdELwB0CjADMvVIy0w53fs9hYx0cXoHFLKh4u+Cwyugt1
         JYslL99q0GBC89J60RmT+1wE7cULv2K+L2IMpOWyGANrM4w7W8q7qFr2Gcs01nmzQ8Sp
         KNVMlqeym/+Ek8QOT3BVedRS7Jp0WZjZzSTJl70DwIJgstLfEVtEzK8XYiOqcTsgZMgq
         7FRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KLCF6odKD8rrycHg70kSuR8wLapAGnjTCBj3BdjdODytZFDH3
	DOSMRZT/NsqxvcOZUZeS7NU=
X-Google-Smtp-Source: ABdhPJyd0F4t9SJ8nCMej7xcteboz8nOjld274YiS1ZT2VeR9BE6/sC2GAbWBUHcZEivUmxkM7/S2Q==
X-Received: by 2002:a17:902:ea03:b0:148:a2e7:fb31 with SMTP id s3-20020a170902ea0300b00148a2e7fb31mr1497991plg.114.1639519740459;
        Tue, 14 Dec 2021 14:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e297:: with SMTP id d23ls1373660pjz.3.canary-gmail;
 Tue, 14 Dec 2021 14:08:59 -0800 (PST)
X-Received: by 2002:a17:903:22ca:b0:148:a2f7:9d4e with SMTP id y10-20020a17090322ca00b00148a2f79d4emr1472690plg.109.1639519739884;
        Tue, 14 Dec 2021 14:08:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519739; cv=none;
        d=google.com; s=arc-20160816;
        b=pywlrzfG1o62M6FsnJsbcoiHshVPRykBi168xHIg9IzaJ3ruQDeW6cDvLBiuts1nHf
         LDtyMVd4ec6S3Q4FqTRTihYPHRe0jXzg4bRGATTvaq6AqcDYUn6Xd55XiYbSD8DYvk0+
         POO1dEA2KC/geKwE1K939FYQQhppNgOV/BH4rGvOgoKqtt2WsV4lH/naZhuFmSgyau8l
         5l293c16W5KQUKFB0xwwpYgIEP+fexEKNnJa+RiKfCaKJhMHZle5tcuzTtTpC+FH13tc
         S7GdwNFkeXf9XEy9SFY4akHA/Dup6UmI2W75ZDhjnM0NLUJcyhWHzbEYGZjgC+oetJj7
         lhlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tP6csCLv+Ba35Rqxl/QI5p1YOyxnicuG22GVHFYUF1U=;
        b=pDCtBLM0fVUXk81zra/Mm91jYUqn/61iDim7cEW4g9NnEnY9wDbJ6sRjYcdGKhuFym
         jk3eRQQTDOfjV9UzLTKBWSgvqlWxyRMYHVWDLzRncmLv1OV+lfnjnWWvMNzLdnqNpoDW
         XFA1nabDkwmAY2E/TS4dKAFUfd3WLSZosgRta1asvlaCOV+GIlEUVVB7Pr3z7xyzR0mS
         RuRBlgKEGkuBVmkn05HNh6dbJT4SRI9ggHK+QI9zQ3VMeJG8J0KQA3zwCEk6KMnvr8Ga
         nWLXfd+VeZ367/zmsg/4DdgVs4Me/PhgEHdYm0RP+/FhBnih0hOjRbVYjrdYlPR8qNr2
         h4ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Cc38oMKW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id d10si4322pgv.0.2021.12.14.14.08.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:08:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id m9so26918936iop.0
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 14:08:59 -0800 (PST)
X-Received: by 2002:a5e:d502:: with SMTP id e2mr5381245iom.118.1639519739580;
 Tue, 14 Dec 2021 14:08:59 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <af3819749624603ed5cb0cbd869d5e4b3ed116b3.1639432170.git.andreyknvl@google.com>
 <Ybj2zms+c6J3J/pf@elver.google.com>
In-Reply-To: <Ybj2zms+c6J3J/pf@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 14 Dec 2021 23:08:49 +0100
Message-ID: <CA+fCnZeY+AEXrPyuWjq9yQ+HOsDxqqp-gw9scvEdLqV5v7q2dA@mail.gmail.com>
Subject: Re: [PATCH mm v3 29/38] kasan, vmalloc: add vmalloc tagging for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Cc38oMKW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
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

On Tue, Dec 14, 2021 at 8:56 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Dec 13, 2021 at 10:54PM +0100, andrey.konovalov@linux.dev wrote:
> [...]
> >
> > +     /*
> > +      * Skip page_alloc poisoning and zeroing for pages backing VM_ALLOC
> > +      * mappings. Only effective in HW_TAGS mode.
> > +      */
> > +     gfp &= __GFP_SKIP_KASAN_UNPOISON & __GFP_SKIP_ZERO;
>
> This will turn gfp == 0 always. Should it have been
>
>         gfp |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO

Oh, this is bad. Thanks for noticing! Will fix in v4.

> Also, not sure it matters, but on non-KASAN builds, this will now always
> generate an extra instruction. You could conditionally define GFP_SKIP*
> only in the KASAN modes that need them, otherwise they become 0, so the
> compiler optimizes this out. (Although I think it does does complicate
> GFP_SHIFT a little?)

I can implement this, but I don't think a single extra instruction per
vmalloc() matters.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeY%2BAEXrPyuWjq9yQ%2BHOsDxqqp-gw9scvEdLqV5v7q2dA%40mail.gmail.com.
