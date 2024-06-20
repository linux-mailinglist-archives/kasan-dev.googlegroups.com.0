Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTPU2CZQMGQETYNJCBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 074529107F0
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 16:18:55 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3737b6fc28fsf17474905ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 07:18:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718893133; cv=pass;
        d=google.com; s=arc-20160816;
        b=0lPaJLH3jBvX/ICH1wV6Kh0RKSLhIU5rx0GvfENPuET1TLwPNlN5bK9Vj6X1HVb72E
         a8AyLlkChxECOw8zzn9Bu++jbY6SZ0VFLEF4PS/jGzeJbIcRnZ0+8cIX9lzuiKGySEg7
         7VVaJ667yYp0E6BxGnk86JExQgaIxKvtQrAuZ2dQbHdINwer2Vei4KPqU7gJ0MvBbabx
         JPPEHN+smrjNgO1g5Vf6d9cBovhDeUawzuF2z334OWm3+Mk/GwIJWZEdEPg4qjeVoD19
         uAqUbgtbQ0G96eM3h7RSlIUKI3rOHqSKoNQu+8ntpZ81PeRPu4vnMdUBGEo8H9jF82GV
         vvsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jRO2bPc+oyyrYOyf9onkHQPloaS+Z6WHOG0CAT+BH/I=;
        fh=uBKQSHQoxSYe4VkPywCjG/iNwqshfCVPDf/pFAVy1PE=;
        b=ZF3R5gV6o1vU9/o4766oRc1ufmcyhDm4jDiOvu/pWSXFXcKmtvOHDm+389KBJD7Gp1
         yqfyGNiTb0q+NvwVKejmJb4Dh4MTpV47isewO9LNTFjq7/PS49CVRgqS0Z1l2st2yn0n
         fLdpCtV3aOBpnUNf/rypvzk6js88ksYj5+YDohJ3/YgPxywjbPa1Wz3iHnegDFjAhvcf
         6bnBOrmZGj27uz/35IFnQXhaZMFnDWJBNDTMIy6zyJj8syYO8GmwqY1qny634mIiC/rW
         9RW6gwQIVR0QaitowZLpe7frjAEbp1eMPhaKobkrCmx9L7SKKARhV709IrlURibSOARP
         WluA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EE90TQio;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718893133; x=1719497933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jRO2bPc+oyyrYOyf9onkHQPloaS+Z6WHOG0CAT+BH/I=;
        b=l5xemnyY+lExhEpGU1lxYoyQfUwKy3WwLQxmjobZHr7z6oEISvmoCVq6iTGayiue1P
         a1dl6vgsdZxBGxQ87BqT6J1TUDGFgBBY3oiKpbTLB+J75ioHAwlCDPXTMPl3MouASv42
         Sd0DRq8XKiTiTZYXTCy/bra1i733MEUM6KUeSk4dTQ5NY3/Qts7GXQELcfvOCFBP2MlJ
         y0XAXjmvjeZuCXJBcuio3EatK9SIqO47hQZga2/HameP6hiuqXoZ23hoc5B8gyjZavXU
         obnsFGPhmE4l81rMAIgFKFgZZpNW16X37+0XX9aCYmeytvr9QD7P9l5nZxXDNoBfXklN
         akjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718893133; x=1719497933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jRO2bPc+oyyrYOyf9onkHQPloaS+Z6WHOG0CAT+BH/I=;
        b=ZV2MHmwDSjKbiMazOeqfPnNj5pO4k2U+qlpj5fI/n21kOZMdZO+RYdHcXbJY97bGIX
         0u0awlbpKjHQ157D2TyZDHWPWkdQb4BoADtRLsSetGVYZq1lLiqf0qmJT5u4MtIIzVIn
         86IgXaMqwnGMu443XMd43DGC06NoVvunmxRCIJngXbXkZG2C7cmbyG/7fewEgxqfV7TO
         7nE8cYrZdUIfNAUWNDcaNbq1krkTkqfYKfYDWiE+nGM5gzTwJ4MSFx+u2uPayQVuHCf+
         sU+qJi+CaPgNgjLvlU2iO85atVNjCA2WdbZp/yhxyPtyVJzwz2oxDtThZUoqnJ/AngAn
         HDbw==
X-Forwarded-Encrypted: i=2; AJvYcCU96spZNeB3nKg9ALrbbmdnxw+PCXTW1bfj1MGNUMgZRjaLUT0ipT590rBTUfGChshxhdVmdkbHC0gRkY+OMYor4g4ARfUAYg==
X-Gm-Message-State: AOJu0YykV0tZHGgTOYMjKXylcjMPiAuHKE2R2SG7B64lxMeVnEmDXkdb
	jquHF0qYuW+Fyo+RHTe1q7ktSx9iEPXGq9SJJ+kAKZB+3w14IKMy
X-Google-Smtp-Source: AGHT+IF0z4KTfPSQf258za+ZnBAtB/sTHxqyGqqGjaJQMEjIzugFhuC1b7yfrkIJ+D7LdNHNtnDHmQ==
X-Received: by 2002:a05:6e02:1d07:b0:375:a37c:14b8 with SMTP id e9e14a558f8ab-3761d11c0c9mr36982485ab.11.1718893133422;
        Thu, 20 Jun 2024 07:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ef:b0:375:93f4:7453 with SMTP id
 e9e14a558f8ab-37626ae011dls4599685ab.2.-pod-prod-00-us; Thu, 20 Jun 2024
 07:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+AoQum7UDab6V8UKEc8x30Ki1qnW/2cbia8eLMhsbBJtn2TTnB54KNWgrUgmvpg8MlN6i3iLRAGNVmbSJuVlX7qaN2pap4R8YiA==
X-Received: by 2002:a92:c90f:0:b0:375:dc04:378d with SMTP id e9e14a558f8ab-376094f54b1mr46592125ab.6.1718893132587;
        Thu, 20 Jun 2024 07:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718893132; cv=none;
        d=google.com; s=arc-20160816;
        b=F77ZaYqtFqfR1ZuOFMtTaQxFECJn4rRo/Tf00lyHQ3v3cepUFTZ4hKNnN1g+yO0irk
         3yPJt+6i4RZ4p+Cn/3vS5MoOjZcEecsjNWfxhznN0MUMINOVTTEtO3yL6+ycRF2WLI2Y
         p8ZtSCD7loIBP51wk+lHTMleyeZifQpM+HVx6BN49F5pm5k32VN2jc2ZkEWwuYCQq/Iy
         fCbCwA67+5cC1WL5N97pfq+KodUVNxyuLwvrJkINw94Jc/sdlI0xcjb6gpiQ7oXHRNo3
         o9p/+R+nmU92v4OZ8En0zaJRVjTMdNfdvmiedU+HunmNufnutDLj14rTDZzgsDvYfZhZ
         0qBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oVpLK2lHnHY7pIeS6zCf+0/9yVq/jqYVxmvNvh0uGr0=;
        fh=acRYKdxX8PkeOj70uc+919ussH+Dso3FW0kN664E/sE=;
        b=kzBWSDr3K4VnbTT3F/WVLSsOOTWLApzQdVAwJ+aCwBuVyYb6/ayNLYxjrLhNI1r37n
         7AIc0l7Qh0zyGPyWUVyhqg7DcgTrgpQiPc9aMStPHQ+TKvVs8Mq1So49XeprN5ewC2Fw
         tjI2/vfjPk5mo65fKrTP3Qal2VB6vYbDs1YIvru/FfrlcT1CRvfzcEHfPRy8vS5rjnqD
         lEwQ1T5xXYvweP/Tpm+fVuZX2rv6ubpHpXFYhhq/Hm4sXPNoxu3xEnoSGID5gTkm/3W4
         znI1an690e1Cqu9rMr3saUHdMq5LLmdxBN71yQn7zsmcSU/lcS+8eSLYqTWd7OMcEIpu
         W4cQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EE90TQio;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b956a0c5a5si182051173.3.2024.06.20.07.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 07:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id af79cd13be357-79bc769b014so40562285a.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 07:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWdHmkP1+kxMjlgKu/4+M+/zMKfXUfYfOogLjr0gQCYPl/6qtYtl28JXnfsNNT6bGWggBqZizTGeCoiF1G4Tr6OndlFwzq7MIPayA==
X-Received: by 2002:ad4:5969:0:b0:6b0:8ac1:26bc with SMTP id
 6a1803df08f44-6b2e2312207mr142468546d6.14.1718893131865; Thu, 20 Jun 2024
 07:18:51 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-37-iii@linux.ibm.com>
 <ZnP1dwNycehZyjkQ@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com> <f6ab5d6e0aa90ad85e239a2da9252930ca9a70c3.camel@linux.ibm.com>
In-Reply-To: <f6ab5d6e0aa90ad85e239a2da9252930ca9a70c3.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 16:18:15 +0200
Message-ID: <CAG_fn=V-_8q2FDEDtvcNmS3rizPEM-RX+vHPrus4ECNx6AZfGg@mail.gmail.com>
Subject: Re: [PATCH v5 36/37] s390/kmsan: Implement the architecture-specific functions
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EE90TQio;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 20, 2024 at 3:38=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> On Thu, 2024-06-20 at 11:25 +0200, Alexander Gordeev wrote:
> > On Wed, Jun 19, 2024 at 05:44:11PM +0200, Ilya Leoshkevich wrote:
> >
> > Hi Ilya,
> >
> > > +static inline bool is_lowcore_addr(void *addr)
> > > +{
> > > +   return addr >=3D (void *)&S390_lowcore &&
> > > +          addr < (void *)(&S390_lowcore + 1);
> > > +}
> > > +
> > > +static inline void *arch_kmsan_get_meta_or_null(void *addr, bool
> > > is_origin)
> > > +{
> > > +   if (is_lowcore_addr(addr)) {
> > > +           /*
> > > +            * Different lowcores accessed via S390_lowcore
> > > are described
> > > +            * by the same struct page. Resolve the prefix
> > > manually in
> > > +            * order to get a distinct struct page.
> > > +            */
> >
> > > +           addr +=3D (void
> > > *)lowcore_ptr[raw_smp_processor_id()] -
> > > +                   (void *)&S390_lowcore;
> >
> > If I am not mistaken neither raw_smp_processor_id() itself, nor
> > lowcore_ptr[raw_smp_processor_id()] are atomic. Should the preemption
> > be disabled while the addr is calculated?
> >
> > But then the question arises - how meaningful the returned value is?
> > AFAICT kmsan_get_metadata() is called from a preemptable context.
> > So if the CPU is changed - how useful the previous CPU lowcore meta
> > is?
>
> This code path will only be triggered by instrumented code that
> accesses lowcore. That code is supposed to disable preemption;
> if it didn't, it's a bug in that code and it should be fixed there.
>
> >
> > Is it a memory block that needs to be ignored instead?
> >
> > > +           if (WARN_ON_ONCE(is_lowcore_addr(addr)))
> > > +                   return NULL;
> >
> > lowcore_ptr[] pointing into S390_lowcore is rather a bug.
>
> Right, but AFAIK BUG() calls are discouraged. I guess in a debug tool
> the rules are more relaxed, but we can recover from this condition here
> easily, that's why I still went for WARN_ON_ONCE().

We have KMSAN_WARN_ON() for that, sorry for not pointing it out
earlier: https://elixir.bootlin.com/linux/latest/source/mm/kmsan/kmsan.h#L4=
6

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV-_8q2FDEDtvcNmS3rizPEM-RX%2BvHPrus4ECNx6AZfGg%40mail.gm=
ail.com.
