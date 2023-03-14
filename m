Return-Path: <kasan-dev+bncBDW2JDUY5AORBS7KYKQAMGQEYJP4PPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FCBA6B9DA5
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 18:56:29 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id oa14-20020a17090b1bce00b0023d1b58d3basf2591849pjb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 10:56:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678816587; cv=pass;
        d=google.com; s=arc-20160816;
        b=jDFIFa+yJLh5nx4JBaQzotKySmn3T5QSIweHPQ7pzkzLtqZvamEHLaHFNITS76R35J
         ydxfnaMQPTfh+oI5DVXONvIzdVhRrHp4SMcNWb2+V42dDSKJ0w2qwpAgY7RqQ2c80p8J
         ng+6NYYTw4U1vqSkSBSEuqFOfig7D4sttvkXclSjqF8rO5eh9nZOXMeti2xpzYKwBXP9
         izv8w1/caiLIgcSRXDJASS3Oiwbifx0s5VvWW8nh4p5zzn5vika+PpT/k78cszcP52e6
         g99cI0f8phNnEA+L5QdUmWagep9INYIXF7OplRwE/xmOdj6eDrwZU9bRZoNgwkV+oVAI
         uKzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Bnz+0eEv5QvfBB7J92Z8TsskbmQlzPk2YyTYkijWeNg=;
        b=r4iWtVWJjxbht+H1wB3uvEP6iFpoyJWEDVeaP3txfcgiYGD3Xk+CPPUNVFgU65Uw8E
         ZDjuDgyVckidoxuKTTDDkfFAoThPc68nxF12ZSwouSNeoRgbJhoNvoMsfsXnb+uYkOBn
         civipVbscOIXaAYtaMhjSk0NTe0WlMavrfO+KdjngFGZVpKM3evhRVZjNNZE+ZZdhU+C
         gs8bKNykS+kB2fkeBufaea7F0g3mftg1Um0q2UBTWcU/gAaczEvBb8+0vTNT3m1GLEek
         89EL6QNk7A0kWkYyK8qDwDOhWwsxj5M/OetYUOa70hM+owS5WRilsBESh7YIbyEdRhBS
         IOww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mno7WqzX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678816587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Bnz+0eEv5QvfBB7J92Z8TsskbmQlzPk2YyTYkijWeNg=;
        b=bMtForWldi7XqdcVbU3EpIdQCEq+47ktgOLIAY0JvegMdfwTYJ8IRTslzmGjTeVO2j
         CCjvD/zIasvMoU0nQoGVMM+Tz2sWV7vaMtokC3EhVRPUEiowtogAX72K1H1TYI0F9Mzj
         s1FDTmTI2N3WCA8p5rmetS7vMRm7JHVnTnaN3zXyNVlQlccT3bMcbbwRsl7dqzLq9Fe8
         armmXegoaacO+PedtxbgFgqMIoqFIwzqt3TpGKil4DZBlh3FuRlr5pvGIujUww5cByM/
         9UzEjPtG6sNCWRwsjDRVA0fFfe7Bxq9+8WueuCx1qL5hBFB4JUyN+ox3Ag+XLeVrh0ss
         fGxw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1678816587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Bnz+0eEv5QvfBB7J92Z8TsskbmQlzPk2YyTYkijWeNg=;
        b=oB+zO+ZZlIjIqaXvZ7EFixxIAU28t3PBE5rXvjjSg+ZHs/7wgkoNqUrwKIGu46gsYW
         +5300w3Bj/gy+3hDhtRn4Cf7w5H3zK8jqOVUYO7IrzAbaflIaP64nitn0RoB3K+u5cYT
         fDaO833XQcZ/J7hCChQ7br5mJCqzsNghXEQ+GYbVDaE5eDZlww9OtcLQc3zbTi8bzyC0
         deqON1jXFnYdzOYWIqeD0nZJgxPIZDQjezyzc5mLM3J86KkOLlpAjY+TNiJKnZfqruKH
         yUkIBFkYZPqL+5+G/bpQ8FgKTCRjcBc+dMoqWXAkoWle0J4uRwtk6RJpZucLgVKiE6A1
         8tiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678816587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Bnz+0eEv5QvfBB7J92Z8TsskbmQlzPk2YyTYkijWeNg=;
        b=oN4xIagZ9CykHo0h483o2Cdask/4eqktTHUM+p4rfnXaQbGVocRqqx0jjiz5pLEJ4O
         8c49Nr4mNt1tBgfUeXIcRlSxWjavnE1SA7f07lQAN7WwubGL47Yid4fxmvy/njWaFtgI
         je07K+3ACVSi1RSkw6xAnqnDkQ2f69SZVB+NLhuQ9ew94QwY3eGRutlzauqMuyFnk/mU
         9Wqko5ptMGJdYFRfoXBOSlM+rMIfWYwkb8N+qJI0R+IUWrsAQ/z4Yr7JZTcrY9yon72E
         ccPQajb2y6wBxkb48dusDAIAsLptM66M+XGLTjbYcCEsfFJOHanpt0iWS+gTQZ6LSLmQ
         rM7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUiH+R4HC6sR8PZStl6LZ7AYzAdmmoDxqu34XV/O3DFMC8TZfrs
	K0B+9a4ozFg6TZ7yYwqFSHs=
X-Google-Smtp-Source: AK7set+ZuQnJ7yrENDTjJhbZO3egBo2ajE4DakF9khM8N8GkEXwrYHFCV1faPjsV4HP9+yowv8soCQ==
X-Received: by 2002:a17:902:f98c:b0:1a0:41ea:b9ba with SMTP id ky12-20020a170902f98c00b001a041eab9bamr3583562plb.8.1678816587191;
        Tue, 14 Mar 2023 10:56:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b60e:b0:19c:a86d:b340 with SMTP id
 b14-20020a170902b60e00b0019ca86db340ls16388760pls.9.-pod-prod-gmail; Tue, 14
 Mar 2023 10:56:26 -0700 (PDT)
X-Received: by 2002:a17:902:daca:b0:19a:aa0e:2d67 with SMTP id q10-20020a170902daca00b0019aaa0e2d67mr16261469plx.32.1678816586419;
        Tue, 14 Mar 2023 10:56:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678816586; cv=none;
        d=google.com; s=arc-20160816;
        b=rr6bgKRw4jv1neu70B0dLCrRLbqvIbb2WH3Cf36yXQgSs0yPKMk0t2wKH5zilSghU1
         1w9NVq8DYZemPityUix8+ac12gZp6b3CQ2pCkOCWgyoYjHmRrVDNr+ciswRY7yrf+nuX
         QOqW6TSfvTF9RI+n1hRw7rVzyI/rqJJLHWnquewjtfIylFNviZEdGmy9DuShcwwiHGBx
         oeerxy/rBtOnvcxax1/5kaN2X2HDYzuics6qWudUa+/y9PMqtq9dvJOvoczc1vNrXeak
         CmIPOEQmJQ+6vNN4X3DpfbGKRM63nuxpwmV/IBjTGpEDwJNCV5Gnqkuv3v2yeUn0W7vl
         UqSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gd+1sCvHMwOBO08sAoxbEvUITd9t9ya85GRQ8ebYZaE=;
        b=Umrm9o1Z0vrJtEYb46mZsUfF5mIJ5TVcVAGwQEzwdhiGvfPC7Fjnz69zZqWeynKLbF
         yajU20ZMRtqT3o0gpd/MEQVJVaEANPoI71OGRbPhGDjw/Jl8Y9e4HFiqpsz05WvbOP6u
         5jBtYrEWlAE5UE472QjUoRqlQIQ0v6PPv4zdyBMjZY0qnDIifs8Z4IrWEAfq0ASO2HBg
         aUscMxxTJUs+qWdw8bdQyzAj5drD/xKNYCsTZ39lV53Ep4fftzDDYnNCGsZKRaQK/eub
         CrAnJntyQAIZFAyuwgtFEtvBvL1z8njYz+WYPUGuYEnZs4iExqAXvEtb0VIQ10e07wPY
         LiuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mno7WqzX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id ja18-20020a170902efd200b0019cb7349e64si125708plb.8.2023.03.14.10.56.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Mar 2023 10:56:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id c10so10214796pfv.13
        for <kasan-dev@googlegroups.com>; Tue, 14 Mar 2023 10:56:26 -0700 (PDT)
X-Received: by 2002:a62:1d57:0:b0:623:c7ff:46d8 with SMTP id
 d84-20020a621d57000000b00623c7ff46d8mr2948536pfd.6.1678816586037; Tue, 14 Mar
 2023 10:56:26 -0700 (PDT)
MIME-Version: 1.0
References: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
 <59f433e00f7fa985e8bf9f7caf78574db16b67ab.1678491668.git.andreyknvl@google.com>
 <CANpmjNMpjREcMc2iUS2ycUih9SRbP93mUaNPXcDZAd-ZDT2d+g@mail.gmail.com>
In-Reply-To: <CANpmjNMpjREcMc2iUS2ycUih9SRbP93mUaNPXcDZAd-ZDT2d+g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 14 Mar 2023 18:56:15 +0100
Message-ID: <CA+fCnZf=t50u+5z-e9kHUqe=7aAWJpkNgt=aS0n_9R_r2jBSHA@mail.gmail.com>
Subject: Re: [PATCH 5/5] kasan: suppress recursive reports for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Catalin Marinas <catalin.marinas@arm.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Will Deacon <will@kernel.org>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Weizhao Ouyang <ouyangweizhao@zeku.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=mno7WqzX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::436
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

On Mon, Mar 13, 2023 at 12:20=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
>
> > + * Hardware Tag-Based KASAN instead relies on:
> > + * For #1: Resetting tags via kasan_reset_tag().
> > + * For #2: Supression of tag checks via CPU, see report_suppress_start=
/end().
>
> Typo: "Suppression"

Will fix in v2.

> > +static void report_suppress_start(void)
> > +{
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +       /*
> > +        * Disable migration for the duration of printing a KASAN repor=
t, as
> > +        * hw_suppress_tag_checks_start() disables checks on the curren=
t CPU.
> > +        */
> > +       migrate_disable();
>
> This still allows this task to be preempted by another task. If the
> other task is scheduled in right after hw_suppress_tag_checks_start()
> then there won't be any tag checking in that task. If HW-tags KASAN is
> used as a mitigation technique, that may unnecessarily weaken KASAN,
> because right after report_suppress_start(), it does
> spin_lock_irqsave() which disables interrupts (and thereby preemption)
> anyway.
>
> Why not just use preempt_disable()?

Ah, yes, I intended to do that but forgot to make the change.

I'll wait for comments from arm64 maintainers on the other patches and
then send v2 with a fix.

Thank you, Marco!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf%3Dt50u%2B5z-e9kHUqe%3D7aAWJpkNgt%3DaS0n_9R_r2jBSHA%40m=
ail.gmail.com.
