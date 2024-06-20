Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7XU2CZQMGQEM2GYDKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 731BA9107F5
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 16:19:44 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5bb02b38ea9sf950733eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 07:19:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718893183; cv=pass;
        d=google.com; s=arc-20160816;
        b=s1qL9bFGkkUTa5NAdBEqK621gNe69Pe2bHNf0rTP9PcUR8Xf5ZoBMPsnx1Z3aZv2E1
         MHYQXf0EWtLX/mMxhlEp6OIunUxwB2JXKsMSIV1d8qx9Yj3WQJbc6gHOgCIu+QKk58mh
         X7cjlKCOhoSFGdv5EaNMIhYY3wcIrDwmeTumhtksr+KBsm+f726dZvHz8YlP+DuYOtO2
         WVjx1cQ6chKWbzLZgyFdjc1o+F1m562SElPgaZasS9OVcksHte3BPPW33Vg4/L110Y0o
         93VgXWEJf4SNUcGfbami27uYHr/YL+kvfW8/DjmOG5OztsApmGl5pFDAU5QCyHpSGnWO
         I53g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rOp4AEhefiUb976HMLYBiMLPpMuVdAKRb/irKUZa3M8=;
        fh=CWj1hzK1AzuZFG+WufHv2po0CX6F2FuR0sGSBGyz+BU=;
        b=VaFS5Dg8E6EDXtXPga6cJGYvMRgkJAKdM/WaIuiTs9v3nwhn3OskIncjRzcPybABPn
         zvZWpY2ZkW/JaqlvATimGWuCdNe78VvxTkinQFIGle/VhcJITadPH0sIQ8O+710gAFnX
         a86UHlmmxORgjf+oSaUBj8jbTN2Y5iVye6TRaWFVt5EnIqDeJTs6GjUsLKH8X6B3TlFq
         pjsimxiT6AoWnP4+yTpiTJHM421enA0oVjZckJV/8VfEuSJQKp4+pL8j8Elby4NTXZiq
         4Fyk7U2tFAY4ZpeNUIQPtNcPF0dxz7JPhnzOPvjIVPOiLS+lp1vKhsTmA/qQZdbvUtgU
         EAcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ANA3Es7p;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718893183; x=1719497983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rOp4AEhefiUb976HMLYBiMLPpMuVdAKRb/irKUZa3M8=;
        b=UehGFiFy3vasTwHh5PCrmLBOZMkyaL2zNRVj3Xe15HHG4mY/V8lwmM4CsshY98Hr5r
         XvNGFhe7+8Su7Ir/t6XYrEP5QsgdGeuAHGu7SP7hrycysIDhbkUmHsVaxXE4gmh5dqmg
         Fss+QwTUMShEP//2dR4+zu4rE/7yUlLDCAc6kgQ4H0k2I0HHq2MoOuKfwYpCg+dw80Ll
         A+uc/zwyJTdaju/NbZsbpJ27OnOO/mkRFzM5uYI6Hga/n/bS2zt1mPuB+jX0OrpU3xbQ
         mOMQbJlkjJuemCgb0oxVwoItrvf/J9twU2DlQpNfxruUAg20j7/6Dld7z0jNrkWmN1hd
         thpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718893183; x=1719497983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rOp4AEhefiUb976HMLYBiMLPpMuVdAKRb/irKUZa3M8=;
        b=Lzvi9z+UdbgE+9oU+L5tsd0xdZ1+aBJn1PUzearsOTe6Cup7BaZoEeY0QmrXBsjo62
         WQ18+g1JWKh9BHTTOOLYkAUU7S1AwCjV007D7mN+4d0wwXVwdW5ZdjSNhGkEB/qHEysl
         vqvpJK8l6HX/NOzSFPcy+SOLGEyTnXRxFJi49DG6jz3xT+WscP/J3UTA8VBxqfDqhhon
         kr4m0NgSqgU+bnVMcoToxsyHbRvc1sSqutX1jSmnEediEEZ/TkPVThE7gd075sgMKw7S
         8Ri2mxLep7hzHWUuI17L8MxfMu5IT5kQavdB2xn1yZDlu/fp9rdL1ijYLW2Vqh8b4BGV
         bG8w==
X-Forwarded-Encrypted: i=2; AJvYcCWwody6xR6sxcQYywljrtRcsSqBPJeC1o/Tdk4whxY+NMUblNOohLQBtHDoCp2wQu6/gLSFzclzg8L9asmjkQBiWrIglT42Lw==
X-Gm-Message-State: AOJu0YxNJ6NdZ7vgwB9/BMERSiXMygvQlW5BtvsYw5CWHfPKSYzap7lh
	Uexpc3o2uSnWZEjyMMBnNUA1UB/M61D3PjhDNVQThVKv1kufBCP+
X-Google-Smtp-Source: AGHT+IFjm3RrItTVkEjb7yjd/8jS6Nyqneox0mAl+MfVFCnmRVbhijpQbnfP4+sJYDUnmeoLF7RaOQ==
X-Received: by 2002:a4a:380a:0:b0:5c1:a296:6b2f with SMTP id 006d021491bc7-5c1adbfa8d0mr5837887eaf.9.1718893183073;
        Thu, 20 Jun 2024 07:19:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:810a:0:b0:5bd:b810:a87e with SMTP id 006d021491bc7-5c1bfd0fe55ls878085eaf.0.-pod-prod-08-us;
 Thu, 20 Jun 2024 07:19:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4rspCIWgmJ0eK61bjx03/MMRgg0eteLkpwEQH3BmQGObpswFZx99HO5StjKUUKx9QeLTFLeGQ7Vud31xqojZKQXl+GUzNKnVADw==
X-Received: by 2002:a05:6808:238f:b0:3d2:231c:dcc1 with SMTP id 5614622812f47-3d51b966404mr6239697b6e.5.1718893182065;
        Thu, 20 Jun 2024 07:19:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718893182; cv=none;
        d=google.com; s=arc-20160816;
        b=Uasnx0/w9UroMH/X7JQCwvURvCXx0KKr6gpEtYtxPydbLmQJffrrmdfuuFiIMImV+c
         9tnur9CZkvaAD9GpkVKimt+2WDeMoKyf3+2/MSINManxLJCeK9kJGOvXQx6hDCXLWm1x
         ZfzAwIgbAInIAEt0FKiQhpI95UeoQ9PFZPBTmOjiAv7KKloBcU+ky4i82tbSxiHZOyGh
         fn58el7HGUX8agtEApd/ptZUB4g92GVusM5ebsGoUO8u4mYqUUN08IgBQtU7c4sDqijc
         sAa4b//CbF3G2c8GkPv5vWq708xJEB4J6mSY+qPdNqvHENH+nFZk6BUJKRgJpdQR5CTF
         vaZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bv+xOEqws+KjvoyS4k7q1BnMnYne+DLlcGkvkV1YXWI=;
        fh=lNbJPb/LVFUfks3kb7OtI1KWG04gDThPmumEo7okA9A=;
        b=QDShHE6mXvtVEBydO4NcTSts8JFGPBQYCvlx68hn6sgzTbJhv/tj8ZgL1QyEmbKqAk
         TJxMEplgU0Qrk0ihhHnuFd7d8Se79HSLgAvqsOHGOArD+WxkVahjMYBYtb9Xdevn9ySJ
         /fRXOTzRMLcSNAQaO0D6WczR3d7H6TgT1ok42uOnm7ip5/HYPosiSKMm9k430Z2+9PBG
         XcdWZ3dHxs00YU16npF8OURbVThXgIcXI/G3zxCVZl/1KrKYaOY53UZ3hjXp7Xk7Trxu
         jNvGh1HH1/mRwLf6IFgM0d487Hlx++yzgbzwKuyKV+CfnMQQul4vgBPdPY6CNb1s2PAr
         w6VQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ANA3Es7p;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d247786a0esi730970b6e.4.2024.06.20.07.19.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 07:19:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id 46e09a7af769-6f361af4cb6so394901a34.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 07:19:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUyt3w7O2X1pqi1pQI4/Qv68q7qPvFtIsGNLQfom5ckyRpUGg8rMLiFfvkK1b0mYZIkP+1ojXv/ROe6wPhpECXwjp27oUv0FO7/ww==
X-Received: by 2002:a9d:5f14:0:b0:6fd:591d:9e21 with SMTP id
 46e09a7af769-700771e7dc8mr6110157a34.33.1718893181456; Thu, 20 Jun 2024
 07:19:41 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-37-iii@linux.ibm.com>
 <ZnP1dwNycehZyjkQ@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
 <f6ab5d6e0aa90ad85e239a2da9252930ca9a70c3.camel@linux.ibm.com> <CAG_fn=V-_8q2FDEDtvcNmS3rizPEM-RX+vHPrus4ECNx6AZfGg@mail.gmail.com>
In-Reply-To: <CAG_fn=V-_8q2FDEDtvcNmS3rizPEM-RX+vHPrus4ECNx6AZfGg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 16:19:04 +0200
Message-ID: <CAG_fn=XcDDFBAxq_0pij0VFU7ODJ6cUKd3AqBD-EgkbfnSLJNg@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=ANA3Es7p;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32d as
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

On Thu, Jun 20, 2024 at 4:18=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Thu, Jun 20, 2024 at 3:38=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om> wrote:
> >
> > On Thu, 2024-06-20 at 11:25 +0200, Alexander Gordeev wrote:
> > > On Wed, Jun 19, 2024 at 05:44:11PM +0200, Ilya Leoshkevich wrote:
> > >
> > > Hi Ilya,
> > >
> > > > +static inline bool is_lowcore_addr(void *addr)
> > > > +{
> > > > +   return addr >=3D (void *)&S390_lowcore &&
> > > > +          addr < (void *)(&S390_lowcore + 1);
> > > > +}
> > > > +
> > > > +static inline void *arch_kmsan_get_meta_or_null(void *addr, bool
> > > > is_origin)
> > > > +{
> > > > +   if (is_lowcore_addr(addr)) {
> > > > +           /*
> > > > +            * Different lowcores accessed via S390_lowcore
> > > > are described
> > > > +            * by the same struct page. Resolve the prefix
> > > > manually in
> > > > +            * order to get a distinct struct page.
> > > > +            */
> > >
> > > > +           addr +=3D (void
> > > > *)lowcore_ptr[raw_smp_processor_id()] -
> > > > +                   (void *)&S390_lowcore;
> > >
> > > If I am not mistaken neither raw_smp_processor_id() itself, nor
> > > lowcore_ptr[raw_smp_processor_id()] are atomic. Should the preemption
> > > be disabled while the addr is calculated?
> > >
> > > But then the question arises - how meaningful the returned value is?
> > > AFAICT kmsan_get_metadata() is called from a preemptable context.
> > > So if the CPU is changed - how useful the previous CPU lowcore meta
> > > is?
> >
> > This code path will only be triggered by instrumented code that
> > accesses lowcore. That code is supposed to disable preemption;
> > if it didn't, it's a bug in that code and it should be fixed there.
> >
> > >
> > > Is it a memory block that needs to be ignored instead?
> > >
> > > > +           if (WARN_ON_ONCE(is_lowcore_addr(addr)))
> > > > +                   return NULL;
> > >
> > > lowcore_ptr[] pointing into S390_lowcore is rather a bug.
> >
> > Right, but AFAIK BUG() calls are discouraged. I guess in a debug tool
> > the rules are more relaxed, but we can recover from this condition here
> > easily, that's why I still went for WARN_ON_ONCE().
>
> We have KMSAN_WARN_ON() for that, sorry for not pointing it out
> earlier: https://elixir.bootlin.com/linux/latest/source/mm/kmsan/kmsan.h#=
L46

Apart from that:

Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXcDDFBAxq_0pij0VFU7ODJ6cUKd3AqBD-EgkbfnSLJNg%40mail.gmai=
l.com.
