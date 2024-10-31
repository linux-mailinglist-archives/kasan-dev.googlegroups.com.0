Return-Path: <kasan-dev+bncBAABBRVTRO4QMGQEZQLDRRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A4EF9B7185
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 02:13:44 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a3c3ecaaabsf7097045ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 18:13:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730337223; cv=pass;
        d=google.com; s=arc-20240605;
        b=SQeRC5bKg0VXvegAvgMOpuoF03WqYluL/fvhB0fx4xk9Atqw5CIWhU45ocuTgV7vH0
         UPsnKA61YdnCGDkhcEPoszD2xUDnkbmo9dDHA66AX9v+I00U4+CWokqge81PS5HDvbMm
         RguNGtGcxikXJlS0740cMzmWabEnuXvll8d1pYBekBi7K4sTl4ry++kpr3o0+M/e/s9E
         dwsB5JbFZzYhRyNkpbtDwCyQN0WHog+w2BLGrTSXhjwroEHDtySHFLrvihia7inttfBZ
         CWbBY8WtXoXPe3UYQCFDkFNE2yMg9m4LTyC9rmavgqcPuzq5dizOurqTM/5zrWmIid+K
         JoVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=thctBgxHVFYdnk8y8Fulog2zr+2NGwggzknbcRPPHvg=;
        fh=g5KjYgHY7ffkmVRVDOjkaW9HvljfoHirDIqsznGoWV0=;
        b=dwxYnq5s6CDncnI/DzhSn1K/wxST69RM9zQm1tz13KJvaINo3qZr4SgNVbbCG+IKtg
         ty9K488xTVs0D9E3riRd7M7b32cv2UEZUbcvoGQcEqtAZXDH+nDTlNxstHn+5NFgqNQm
         R3I3oCWNsyCewtKJAS+IW+Sq6h0jmTJuGhcQRigIs9xmJQ/b2tGMQHa/81jsvwVsaqP+
         s2/JaoQ2xZayaPRBrpSik8Gpg+R4vkkouiWScA1i7VhSpezZcpCYEPTlTPt5S+rJu9fd
         LhwJILjmHKzH8q/qI1i0eiTfrEJsy7c+7B+pzRfvcp4M8IIOvob+/dj7AnKY9hSTe8qP
         /j+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CQFnaBIg;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730337223; x=1730942023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=thctBgxHVFYdnk8y8Fulog2zr+2NGwggzknbcRPPHvg=;
        b=Y1vfF/+pb48K5BfVfJDlJG+Wpo3OS8qqcLcXOo634/MvYA/IMB+tGhbqq2RFq7nwq8
         ejhvs7N1Q/DQSjTkiuwWzj/6y0ivMpdRvapvhAztHw1uYvFcegHYokTnVOsyuGEgtxeb
         kZuYtBQG+X9NoocJKztNFV7ngRhDzc3Qge4hLsWU4/MvYI8Y8+RtbarNCfIebfSV3PXR
         y5R/N51EZa0Cpoy5n7Zs5U0q48Z/PYq6mpvBG/KGaeahSAXjwMs0EDt9ld5XmH/cvLkz
         1VbPSc/5TQsqRCG/7bxLuBmCZatwyBENaSL8qq6KzBJUUhXOZ4yGXvYhV2fMAV9RC78W
         P++g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730337223; x=1730942023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=thctBgxHVFYdnk8y8Fulog2zr+2NGwggzknbcRPPHvg=;
        b=L4hzSQ1olu/J9wU94kXGQM1ghe5tldAfAjIGodFZZAL34G0aGOyXak2Kfe/meLzBSC
         6hoZMhrfSP/5yCCezi9wL4kqE9Y642PVtWZD7XhrIOYs6MW3GwB6xdk8mAVq5gcyM13a
         qfAKDfe9ZG9s1CrktQ0fWtQauLSmrcadqK5gcJcYeUzbgQnM2m+hXP0WXR3KIGPLJPO/
         6JLvKs/Kz8Wx7xGYETK2LOjMvl+6woqdqprj9lL8DiF97OV2iJ9hNTmXjHLWcgboZI3D
         SszZHJGJH3MU/2TbsIsj6Iwu5Wmyxf5phnMNGSoftQUoJdhBNr3kFZEsd9054j1tTodN
         RUOg==
X-Forwarded-Encrypted: i=2; AJvYcCUR4y8KldnxLETJnO1kMoJxa4aZ+3SIJqyEpKS7w+59rr7oTOT4NATbcUS++8imWrWK86v7kA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1w1wMbtaYSl8LjOSMuJH13rRgwgAOYFdwMHVQtoOIzLcnCyju
	AWEerBhSwr7PLQYHObOcR1ykNqQl6pbHVp7GHcKOQRpKTgXBVrHu
X-Google-Smtp-Source: AGHT+IF0xreSy0oASk8S5MpejtqUmVYA2Mdm21HRncSPAxfhFKtG+K6+WXQ9huu9Hvgp/Z6cbn9q3Q==
X-Received: by 2002:a05:6e02:144f:b0:3a3:4175:79da with SMTP id e9e14a558f8ab-3a5e24a0416mr66694435ab.13.1730337223091;
        Wed, 30 Oct 2024 18:13:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b0c:b0:3a1:a3bd:adc1 with SMTP id
 e9e14a558f8ab-3a62812bcb4ls3545515ab.2.-pod-prod-01-us; Wed, 30 Oct 2024
 18:13:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHx3OaKrvPaAND1jW98Xahuhu0Dyb0uwGNxceD3gZ3uYswCzirVYw7N9o9OKrRNUq26EHgdvr/jkE=@googlegroups.com
X-Received: by 2002:a05:6602:6d10:b0:83a:b98e:9240 with SMTP id ca18e2360f4ac-83b5676f807mr604142539f.10.1730337222262;
        Wed, 30 Oct 2024 18:13:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730337222; cv=none;
        d=google.com; s=arc-20240605;
        b=aKdZ2oc+esPnB/8KKCmLXfJ06NrypNmxaFejMO3wnAdugbxL5vDB3O4pqdpq5c6B2c
         /748ZHLZniCYa/DceyX9w/ujcJXEOR8esCGvX7tW+DLabzGEM4lzRUA1a/DZpejOCKEK
         tpDsxToHZYVyHblDLEsl4fIiRiK0ewfnZNzLydfRcjjnRu+ha3hENkdRikXNvRuGR+7F
         Kuz3iVpN6QfXMNsvdBmWWGOuWwGZXs8d2hEqGjS8+q6A+jJ3WZ/rYlS6nLg/qvbvRP37
         FGuiMHVo/rAHpXyj39o0a2GB9SZjbiRbiEyaFHll3y3lE+PggX5ZOb3jSHx25iyOeNRY
         9mag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZvnyMvVRMyJDazzHKZnXv86cYYSXYBn+vQp6fH3kQpA=;
        fh=q0phajW5+BXZ+ck/RhiNmQtELeAkZTApIcTXs+RlYfw=;
        b=KhNFo/EQ9KYsYJeZjWY1+SiC85VN/wGRFqfMTa08SVrDF1/LZL1x6YR27EcivgLNVP
         5OaQuVZtELbyRYe2ftviwWnuQz43Cmf3qBO3OUJ0XST43R7PQAVw+Ry4zo+t1XNifAeo
         xpAuQ+ppw+sbEhyxsxUgYnfnZc57RkFS8sRJEFH/1OupFyz34qM7es/VvQproTW01/OK
         M9NkJouK8ta5AETJUqTea8AY9CqOInVcnAxVxmABoWb8eFJUD0C2JmlYrz06/7+3inC+
         qhLbodUCTfkqrfvY5433oNk9X5hzRxRZW/V3JuxP4VoPYyJIqu1bPYg8WFgx+g+6B2TI
         PTzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CQFnaBIg;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-83b67df7dc3si1129839f.3.2024.10.30.18.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 18:13:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D460CA439A2
	for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2024 01:11:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4353AC4AF0B
	for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2024 01:13:41 +0000 (UTC)
Received: by mail-ej1-f53.google.com with SMTP id a640c23a62f3a-a99f629a7aaso68120266b.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2024 18:13:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/HDuaKqxJ9NvkYotSSlrlB8Q/w5ftG6nrbjPkzGcjlRMPyFNGYACwaaxnjavv6nIw3E0La7kdYNA=@googlegroups.com
X-Received: by 2002:a17:907:97d6:b0:a9a:c57f:964b with SMTP id
 a640c23a62f3a-a9e55a29239mr50707566b.8.1730337219900; Wed, 30 Oct 2024
 18:13:39 -0700 (PDT)
MIME-Version: 1.0
References: <20241030063905.2434824-1-maobibo@loongson.cn> <20241030164123.ff63a1c0e7666ad1a4f8944e@linux-foundation.org>
In-Reply-To: <20241030164123.ff63a1c0e7666ad1a4f8944e@linux-foundation.org>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 31 Oct 2024 09:13:27 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7AyjyGT=4pW9X-ZrdN3JThs8ukC3dnoZW_dOxZLQsQtQ@mail.gmail.com>
Message-ID: <CAAhV-H7AyjyGT=4pW9X-ZrdN3JThs8ukC3dnoZW_dOxZLQsQtQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm: define general function pXd_init()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Bibo Mao <maobibo@loongson.cn>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-mips@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CQFnaBIg;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:45d1:ec00::3
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Andrew,

On Thu, Oct 31, 2024 at 7:41=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Wed, 30 Oct 2024 14:39:05 +0800 Bibo Mao <maobibo@loongson.cn> wrote:
>
> > --- a/arch/loongarch/include/asm/pgtable.h
> > +++ b/arch/loongarch/include/asm/pgtable.h
> > @@ -267,8 +267,11 @@ extern void set_pmd_at(struct mm_struct *mm, unsig=
ned long addr, pmd_t *pmdp, pm
> >   * Initialize a new pgd / pud / pmd table with invalid pointers.
> >   */
> >  extern void pgd_init(void *addr);
> > +#define pud_init pud_init
> >  extern void pud_init(void *addr);
> > +#define pmd_init pmd_init
> >  extern void pmd_init(void *addr);
> > +#define kernel_pte_init kernel_pte_init
> >  extern void kernel_pte_init(void *addr);
>
> Nitlet: don't we usually put the #define *after* the definition?
>
> void foo(void);
> #define foo() foo()
Is there any convention or documents about this? In kernel code there
are both before definitions and after definitions.

Huacai

>
> ?
>
>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H7AyjyGT%3D4pW9X-ZrdN3JThs8ukC3dnoZW_dOxZLQsQtQ%40mail.gmail.com.
