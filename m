Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBR777KVAMGQEBCXAPTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 042607F56A6
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 03:58:17 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-7b34d2f6e07sf42876339f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 18:58:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700708295; cv=pass;
        d=google.com; s=arc-20160816;
        b=xXDDWljhj/Bzt1UuI7BCmjIxAY0w3QfMTmGYSgokYl8pnlJUpZ3dBfKQG82Nenpd0K
         R+LVraWUJJW2KDGWnZu0upWoABDbM3dUPzQOLeICOZOiH8OQ9OpX80n01StMn8rXMkkM
         WgOCRPP5YdVQf6DZC8/kFISpePbh6zAjrHTN6TY921EaI2ExjqIe5h1ypSasZrvg2A4d
         akc4TRSkJS7DYq3eLpyZWeIaRR4c5+4U5mSAETkn1f9vLHu0dECqSPpJPgsTYS45O1Uq
         fb59gHkMXiHfHU7Iuj0iHhVAhDXY+kJTVUzbAV4mFbujd0JB7Of/Vqlkfsavkl0qHcde
         vfCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=doAKtI6SKNlDNWhczPPmc73tf61VNNcKyrNAQ4Bxh1s=;
        fh=eQ3tmEpMl1bhz7wzJ6U1QYJhLcA51CamE1Xf+NHyjgo=;
        b=iJFRs4jAAK4Jet5ZvZmYxr0mCR3PNFoPl0E4K1b/V7TKKyUA8XON/GE2foZS6TEUWz
         pGn6XDjNVaanT9weGlRdfnKz7gF16WQ6xeh4q7NqfrGG3+R/JbKZnC57qc51W8YAJ5LI
         pUxYOYqbuTUh34iTbDHhoGDwZHq4/cspIJjLpE/jjJy5R1p6Yv33GDISrz9v0KVsS9ud
         vsgYTf4flgft1V/CfQ+qAEOHeUSujrf416i9kY18dUF61X4GvVOvY++RNappv8/hqIDT
         /jzzxVSVnXCirxp7WhIPlnXqga7+KxRWeFOM+Z6xtJlIMFgiDYQhifqwEPJDaQR909cZ
         SbGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GSvu1LW0;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700708295; x=1701313095; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=doAKtI6SKNlDNWhczPPmc73tf61VNNcKyrNAQ4Bxh1s=;
        b=jxuPY0wK3Mj6ZOlEBjfm2Y8nNsrXR6vtPocqGGfu3e7RSdAncDLU5zImqGdMpoRwXz
         pQnEDnyC9TYHGw43CKmyVZxS938T+//CRBqowF7FMYJ3Q/B91qPpqMf170Syqk4tKXjd
         XqIZ0D9MrYuQTyUC71hubvvEqgQdb491bBAay+Hd+NSTCAegh2Qskfzm1McJcmtBW2Px
         5RuWOgGyNTwAAIpypjztjnVRyaC+8SwpG/RZTOqsZYJSekEXAAXWJhhvhDBBMuJSFS1p
         bfZkfGlCOArCQ4ZW5/wgNl7No5j1KtD0ddp6QnlXW2ztboNJHZQd/WztlX8VC2CDz9xm
         JhPw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700708295; x=1701313095; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=doAKtI6SKNlDNWhczPPmc73tf61VNNcKyrNAQ4Bxh1s=;
        b=W9s9XrlLS2AZL5nc3ciCMslc9q6dglPOd65wHuk2OnCMcN0wE9M9FBfOCxY/6vbwfM
         mtdyY8wBEE6S3hBoIgv88+UoGDspJkqvcw8dW6kTastGD6efWp/wsJrNBciEqlfl1tEu
         nFrDkjPIRouXSUdOG21UPZ0C+fCF29ifOB615xoJVhOsmapru9a65gUqThmM7xA2idel
         WnWluGioMuAeQfAE0y+7AVYwGaZOCVUvoZc6gLhuMpMMpIMXXCdJ6PliL7aV16g95+5Z
         i0qexErpEtX8irrIys7RZbBVzkWh0eHBRj2UvW76khRHzxqbyOeYN6/mbns/Y2HJKPPv
         oHIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700708295; x=1701313095;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=doAKtI6SKNlDNWhczPPmc73tf61VNNcKyrNAQ4Bxh1s=;
        b=ETBLRSZj0mEvI8M/Uhg6JcQswwpf0h4UyxPX/rJYAqRkJn02yX69E8hJQyreXwzlo+
         Ih2IZmJ7W/yUMgv9Rwf5T4r1vxeGg8wTSJBegl0yVFCDlltGVp+5dkuyqUaDlo9NBwJy
         QLwyy3G1O6ryP4MC0xdmsYuhos0Mqzp7N9J/9RBB7FAU/7jmztkFCPIviRDcWmcGURZ1
         u/HnHthAKm4c0RY5oHAK5v+Qq9e5Wu2wNNbRRSvA7rrT7A33xI6s59oZKfMFCVe+Q1Nx
         /sZXxfkz2hOUQttZ+AQhX2LoONSaE7AkUVIxqntC3YzYVcknB5pSqYRXlrjTWd3mxH6F
         W7hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywcoi2UJRmLG+XDAgTYTLfEkwmbYfWWb/MEm6lMMpTz9MUuAU2H
	99ia9nmUpPAh6WlHBfuG/7U=
X-Google-Smtp-Source: AGHT+IEssngPCBDHPOvPKEjCuZIqn9aT+lTy8bBzrSC7sok2I8aUbsI94PK3ApbccDiGASoopw9e/g==
X-Received: by 2002:a05:6e02:14b:b0:35b:ad85:df2b with SMTP id j11-20020a056e02014b00b0035bad85df2bmr4233639ilr.18.1700708295297;
        Wed, 22 Nov 2023 18:58:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3410:0:b0:35b:3847:627f with SMTP id b16-20020a923410000000b0035b3847627fls226862ila.1.-pod-prod-05-us;
 Wed, 22 Nov 2023 18:58:14 -0800 (PST)
X-Received: by 2002:a05:6602:36c6:b0:795:fa0:c15 with SMTP id bg6-20020a05660236c600b007950fa00c15mr5732552iob.6.1700708294568;
        Wed, 22 Nov 2023 18:58:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700708294; cv=none;
        d=google.com; s=arc-20160816;
        b=vIWxNlW04RvNHCHygEzhF4nCNRwmbCdReK/7FQC1+5dQlmwNpbfGixOTi6G+8CSJVi
         kXIQoZSDvuMzbs6eZvk1s5GIkvUXFaTeyN2Otwm8Z9w5yXogyHz+Rt1DTiFxteaR7Gqz
         JaxYQKOEYXGp/wk3LKei1g54mO02YYl0KDIzp03Z4jE6CiIitAQzYtqTOMVF+SyNEk1B
         mbKsej6zTTZJ6miZ7W7Z+ooKcnDelt+jqetemd0tZWcHcd4Iaxz+fduahFlFTMkJ8csz
         a0LC8SWwM50pGPCP1tpl3QF6IOBBl++k1hpAWngpmlfhxFc8goNViETsfYYsKFsNDAWG
         Tb6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KNqhJS4E6ntiOthoCCp30Dce98FPuWbxjBUizuT5qHE=;
        fh=eQ3tmEpMl1bhz7wzJ6U1QYJhLcA51CamE1Xf+NHyjgo=;
        b=qmP6teC4rLRZqPtbi/crdMJMTxydBGCLsL4C0L71Zi3ru53YOuiIvubeQsLW3VxcZX
         Kdv5PwsOKc9VuG40NNMoA+5H/Ah+Amc9JIQG62R/0h9vkvUdj3cE+cR9ZswtoShPBNXK
         Eiy7n57lI24ypLAuED+0onB36gjqU+ULiueOfKHA2l3nffwYRZ10hYUHfSj5i0k/FV2s
         phmBVw6Xf5djH6b4YIbInnJqPWR8nr5CrCcuGZXOkxZxpL5YvIskZIyiHg2FAHihTLnU
         6ZvwMbW/DWgda6Kt3+Yq7FlaxgKWqcN/hwS0PMQf0md91K0XGEpI93iQDOcGwHA1iBr1
         koiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GSvu1LW0;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id bk24-20020a056602401800b007a692b26f2bsi23628iob.3.2023.11.22.18.58.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 18:58:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id 71dfb90a1353d-4ac20a9bb28so161328e0c.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 18:58:14 -0800 (PST)
X-Received: by 2002:a67:f546:0:b0:462:877d:7d05 with SMTP id
 z6-20020a67f546000000b00462877d7d05mr4431612vsn.24.1700708293822; Wed, 22 Nov
 2023 18:58:13 -0800 (PST)
MIME-Version: 1.0
References: <20231122231202.121277-1-andrey.konovalov@linux.dev>
 <CAB=+i9QFeQqSAhwY_BF-DZvZ9TL_rWz7nMOBhDWhXecamsn=dw@mail.gmail.com> <CA+fCnZdp4+2u8a6mhj_SbdmfQ4dWsXBS8O2W3gygzkctekUivw@mail.gmail.com>
In-Reply-To: <CA+fCnZdp4+2u8a6mhj_SbdmfQ4dWsXBS8O2W3gygzkctekUivw@mail.gmail.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Thu, 23 Nov 2023 11:58:02 +0900
Message-ID: <CAB=+i9RnOz0jDockOfw3oNageCUF5gmF+nzOzPpoTxtr7eqn7g@mail.gmail.com>
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, Feng Tang <feng.tang@intel.com>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GSvu1LW0;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Thu, Nov 23, 2023 at 11:31=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
>
> On Thu, Nov 23, 2023 at 1:39=E2=80=AFAM Hyeonggon Yoo <42.hyeyoo@gmail.co=
m> wrote:
> >
> > On Thu, Nov 23, 2023 at 8:12=E2=80=AFAM <andrey.konovalov@linux.dev> wr=
ote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > When both KASAN and slub_debug are enabled, when a free object is bei=
ng
> > > prepared in setup_object, slub_debug poisons the object data before K=
ASAN
> > > initializes its per-object metadata.
> > >
> > > Right now, in setup_object, KASAN only initializes the alloc metadata=
,
> > > which is always stored outside of the object. slub_debug is aware of
> > > this and it skips poisoning and checking that memory area.
> > >
> > > However, with the following patch in this series, KASAN also starts
> > > initializing its free medata in setup_object. As this metadata might =
be
> > > stored within the object, this initialization might overwrite the
> > > slub_debug poisoning. This leads to slub_debug reports.
> > >
> > > Thus, skip checking slub_debug poisoning of the object data area that
> > > overlaps with the in-object KASAN free metadata.
> > >
> > > Also make slub_debug poisoning of tail kmalloc redzones more precise =
when
> > > KASAN is enabled: slub_debug can still poison and check the tail kmal=
loc
> > > allocation area that comes after the KASAN free metadata.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > Thank you for looking at this quickly!
> > Unfortunately the problem isn't fixed yet with the patch.
> >
> > I applied this on top of linux-next and built a kernel with the same co=
nfig,
> > it is still stuck at boot.
>
> Ah, this is caused by a buggy version of "kasan: improve free meta
> storage in Generic KASAN", which made its way into linux-next.
> Reverting that patch should fix the issue. My patch that you bisected
> to exposes the buggy behavior.

1. I reverted the commit "kasan: improve free meta storage in Generic KASAN=
",
    on top of linux-next (next-20231122), and it is still stuck at boot.

2. I reverted the commit "kasan: improve free meta storage in Generic KASAN=
",
    on top of linux-next (next-20231122),
   _and_ applied this patch on top of it, now it boots fine!

--
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9RnOz0jDockOfw3oNageCUF5gmF%2BnzOzPpoTxtr7eqn7g%40mail.=
gmail.com.
