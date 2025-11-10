Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGNLZDEAMGQEBWE5XPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 290ADC480AF
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:40:59 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-88236279bd9sf83612816d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:40:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792858; cv=pass;
        d=google.com; s=arc-20240605;
        b=dZ6r2tuY3OMM55kfhUi4S2zMn8vxqJo+U7KU4NWVKk0tQzXzgdRNYkMzcf1UVcRn5L
         +zM42J+RAxiqdtan/OGmLFK8IlThVxYY9cX5RZBna/dj8SKcETDju0V11Zx2P1UTstAB
         0O/YQ+IPAykmuIrfuVBk7T4PfQwCqpc8wHj46Ut3+2rsf0EIcZkgFAxqHrHo6JH3HWcC
         ABnnUqlICyUVAIJEK9lbRbZ2yowQN8YwyomhylTVi/ySziCgsVMf7Hpr/tjbR+bjH5YN
         V8jK1dGcLzFZyqWR4f9UJq8A15SghamMWQJpBEqdTujHfUZjHGSE4eanCrb/iGZFN9f2
         QL8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WYCfamCeRsZy4XhNyv1EkpI7fU3wQtyhP8+kuc/XVxc=;
        fh=cNfTHt4/METIfIetWKlEcUfU5sTwXr120VZl4Al4SSQ=;
        b=bddRGonjCpyHrIa20ia6lN/mseBjYG6fJXyD8+0LPIWZX7DchhZnTg3cbO5qkq5LIk
         xCB/h6j2YvXli0ovNr3nzSxXR7fsjJY7qfWclOuFCOe+CNA2QXQQTxYVcq/SlOnKU1wJ
         7uoush5y04LHHl+LRuVyjAkYSIhf5SIkHmIM2tmiWjTKI2QXvVGgQPHumiAqVY/KuDoZ
         zWmuki4xl2ZguFdTaSvM4Hc4+EGOr2SsfZNKTna9g4MVLi686HiAs3+3Laqrh0HU2t5a
         p5VzNnTKG1YOwFYWcXZ7XN6RzD9uYGuk7GcVIBJJBzdwRduZBHnwrUppkBxX/IcPLWBu
         xz0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iORCtSdG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792858; x=1763397658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WYCfamCeRsZy4XhNyv1EkpI7fU3wQtyhP8+kuc/XVxc=;
        b=froCEAhi76OYU6tZFjyytexa9uuXWy2SXJbLEZvDxA99YI3TtKqlcqjz8HAowK4pjE
         ZXDKbfGHqh6oaSsRjZ74luwVhdBJIckNrT5cNTr+uOz7/CG+gnvVQcYeD1xGKhHcLU5Z
         pK/vVFPJBO5oP4WPmMLIkb+e0NoTGJ+em4q/oTWUa3oFqwntMUqu6H8dsNgpnXy8lXUf
         3IrR6PA1JqzPXvi7LMGy1vstNNcHEhFf4fY6jhlzlOLAMfnclAiSIJF8/iL1Tfq+7E9V
         wbUyaJdB1j1+qUt8p0mgyG6DQsqL2yDLuk53lN5m9dNG/apbELpiIRBzcLTtv92TW5eI
         AjEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792858; x=1763397658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WYCfamCeRsZy4XhNyv1EkpI7fU3wQtyhP8+kuc/XVxc=;
        b=ejCR8nS5hL+y+GRdcpQvNWKvEwiSZMrXeH+PitS4/Hs4SZRMrlCiC7y851wPhJpaXO
         XMHQv2EbSa3fSGcTRwJsYxd5hz87qo8HtJFBTDrFeAiPiSe0P3MSEyQNgDObkbb4NHGl
         TZP9Rbc+ev5LaJcCd4bwWCk+wE3SlkH8s213iwJQ6M3DpOzJU1cTDtJ2FU0C95NlOAxf
         FKTKTCpTq2hkRZooo7dlLQcnAknb37DPH+Vw4JcOOpniu4cRU/8cv07dMQyJChc8PSDb
         iEUPYBtFOP/knkDsXCN68fwWfQou3Hk9TzMiV4u4uEGacIb9ToamDeLCqK+igYk0kC9x
         gh7w==
X-Forwarded-Encrypted: i=2; AJvYcCWcX4PCsA+7CXhna9ET8a/Unahy6Xl8Vr+wTmAyCppbDFn353kxpIZujJOXTgwoFdJGqHhtdg==@lfdr.de
X-Gm-Message-State: AOJu0YzhfVnqx9/BdTmWspCPL+z1dSoF9Me2rrGxL/AVKk2xbv9nsY35
	JUQg46JMYmyS20Vv6TkrYhDQw+CnXgWt6A9VxKkwPvEiGmV/OIdTm2Lf
X-Google-Smtp-Source: AGHT+IH5UUnct9AO5WekKdZnVBtOghLrTTmTU2ScxfeaGHN61UMeSfNuFpCThNkj7S1B46QBLB1ADQ==
X-Received: by 2002:a05:6214:2503:b0:72b:5e10:55bb with SMTP id 6a1803df08f44-88238749531mr127944676d6.48.1762792858044;
        Mon, 10 Nov 2025 08:40:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y/sCBXzIKB/WcttEO46Wc8wTZLmxJMkNtxLnABBny6Gw=="
Received: by 2002:a05:6214:5183:b0:779:d180:7e3f with SMTP id
 6a1803df08f44-88082eb8352ls75551956d6.1.-pod-prod-01-us; Mon, 10 Nov 2025
 08:40:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDN09IKB3KvqBkt+pcXVXpj5L2PS+uhMLGt1digEGsavP51RKBnd5IxJPrGdzGum6fk7ep6j8cwFI=@googlegroups.com
X-Received: by 2002:a05:6214:124f:b0:880:5813:1551 with SMTP id 6a1803df08f44-8823861233bmr126860376d6.30.1762792857240;
        Mon, 10 Nov 2025 08:40:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792857; cv=none;
        d=google.com; s=arc-20240605;
        b=YxAMVqv5MRqXaKA585fhEAmqlWSTfzOD6WWivOQLIJu4HvrCmITtjRGHf50vHQqRZ2
         cqp2MxNJOAjMH6y+S3WvwUBu0lu1faFr+0AxM8d4Msgy3wZviczC5pDAqEWCKyTOSq3z
         QYLuxOx7G38HOltm1WNvFmn6wUoFiplExT7AkiWwRYnExNoYJOxhq8q4jIKd8iXUWkF/
         hXeJsehpKGHX8Enkk8hdNRMAABaTOej5eiKh3pOEEGMgMpoyEEWKGvwy0QyujbkJaOxY
         N/BmGhp6Xfu64QxEqHzN+XV4FLVBrGkhshyptrsnMtKh5ymtrJu3h19d+dPLuU8N/RWY
         TuNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ARP0s0P8t6lHLXGPK7oqG4hn2hPk4JBv7/AQ4HrLq7Y=;
        fh=ZxHopgpsmtVYgCEcEW+A9h9qf5wzTotnuDrRZfDTLOU=;
        b=YJMF5l5H1vf1xqvW5VE3EyILrWO/5pw0IArdhTUbUc3ZYzTmqKTu/+EBRUxVmwvtSY
         7sW05nnThAZSUGowjm7TGoQkMs4wm7sgLLyMGkn7j91MRPel44ih+/OiLlyHe7U9zNmu
         UvhoN4XgFWOGcrEwbBOvlvJFedqJDm5SLtQbpsNh7ARqlybXhISw+fAZpcTrl5Hc4zP9
         ngtIBNH3CQmwfQ+xdzosWvqX0ZMU7SHU5xgu2exwxVxR6N40jpE82t5UtWumIvQ6n4yG
         09c60c4ypkRQq5zVeS0Vhuv3adLVwQrAuxR3wN2Sc6tpP/7CLxLQgzpPYRb8xOFT66CC
         Ktxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iORCtSdG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88238a165fcsi6495296d6.5.2025.11.10.08.40.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:40:57 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-4edaeb11634so15344301cf.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:40:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXZ4pTLPcNecGpFHTu3GCHZ3C6cAlZYp43lLPUyJL0YAw2EtOgnHZrCsVcAmXW4ptj8K7Hp9+g5RCk=@googlegroups.com
X-Gm-Gg: ASbGncv5C5WuvhlJtWj9c16Q1Lohq9vOiLq0AHVV4quQSCxWTJTmNeHBJXK/ErHVm3n
	IrRM8TBnwjZip21ey6CNVe7roqlRNlQaznqzA2IkAg5AmrL6XC+QfHEX5QNcfK1puN36Z/hhMlE
	BHsD9iANxjjRzFQkbhyjFZs5WiM2bRFyTyETthrXEMWalY1V/NgIsfeagreIZwi0GSIWbKghzxg
	gB8lsCByei3VewUFBQ/ofLTXH/Z6L4iBn+nZRvlrHJymSDRcOgswCdlIwOJm+FjxJxDYTAgADAM
	58HT5I35p5V0tHXzr9rfiiPO4w==
X-Received: by 2002:ac8:5d05:0:b0:4e8:aa15:c96d with SMTP id
 d75a77b69052e-4eda4fec971mr97364671cf.55.1762792856275; Mon, 10 Nov 2025
 08:40:56 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <932121edc75be8e2038d64ecb4853df2e2b258df.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <932121edc75be8e2038d64ecb4853df2e2b258df.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Nov 2025 17:40:19 +0100
X-Gm-Features: AWmQ_bmi0ifqdxD1pRga8rXt1izLseEvw-FOTscdlGLXMffgSbt_R_kuG7tm2tc
Message-ID: <CAG_fn=V6pbNdN3w0Jr5rCL=M27-bOBt4AK8rB7UvvwT=3g4m7g@mail.gmail.com>
Subject: Re: [PATCH v6 02/18] kasan: Unpoison vms[area] addresses with a
 common tag
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org, stable@vger.kernel.org, 
	Baoquan He <bhe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iORCtSdG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

>  void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>  {
>         int area;
>
>         for (area = 0 ; area < nr_vms ; area++) {
>                 kasan_poison(vms[area]->addr, vms[area]->size,
> -                            arch_kasan_get_tag(vms[area]->addr), false);
> +                            arch_kasan_get_tag(vms[0]->addr), false);
> +               arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vms[0]->addr));

Like set_tag(), arch_kasan_set_tag() does not set the tag value in
place, so this line is a no-op.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV6pbNdN3w0Jr5rCL%3DM27-bOBt4AK8rB7UvvwT%3D3g4m7g%40mail.gmail.com.
