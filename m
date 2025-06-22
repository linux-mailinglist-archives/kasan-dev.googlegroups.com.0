Return-Path: <kasan-dev+bncBDEKVJM7XAHRBE4C4HBAMGQESRAPIBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F62AAE3137
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 19:44:53 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2eb585690dcsf2800956fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 10:44:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750614292; cv=pass;
        d=google.com; s=arc-20240605;
        b=VW0/vgv6rBFlRVnPF9soVl0fhqC4Si09iM5LOebj7ifOmLTTPWjzM5/AsAI9iD9SoH
         3xi47laHrDKoQvXkkQuULlVnfaZ0RpTPhaT6jTJ3FT/+yFk4M66AXTCVVon2my33KcOd
         Lr/HsXwdlw6+owfYt7RHQkVGFxDZjMGPMwD9ibjlpJnOc6tXb5qvzGxiPCLyJh4+t9ky
         zYLQM3fSTwDJgcvyHVT6X+W+kCoCKlwp97qXIeGJdsgYrusUmD20a9zlQu3/s/BBagbW
         1rOyAN+TbFCZmSJ2/TGEblGcfwnwXQMSrSkd6hOcnyA2/M/spRE/tnMkYDOoDjN7KAWT
         2Fnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:sender:dkim-signature;
        bh=elJqDii02C3zpjewLjegugxFY0ESaauYGsEfzhA2Lno=;
        fh=x+0OGoyZnV3JGFlHFuxVoxv1SHeQJ27/Jfm9ngnd0ow=;
        b=XQtsAuWnYZR9Cog0/wqEFaxvZ8LEYuscbIj7WY+FbGi8JiiAA+w/xDCKvmVCuA1/Ny
         ceTUEUuI0wAJSwzWvIvwvfq30XWZy2xl9Nxr4zzs84Hnm9mNkQ3a66vgBeRqiMkbRgBd
         PaEIXd9F5oY1coJVATemlRSBwuR5odGOTGE3F3gYgjpHQZZld1U/TCYspF3boncSupGG
         TeOv6BO1FxW3NALtLEAg9lgLZ+Zj2WViYBUuAnlsD/6UIkrqL5CZoiDbTYUmNJCQeOYF
         fsDiDiBui8K3Vx3RI2DTZ1vnTMJceREqoT3YROp9Xjf26wLui7LtklRy4hCXlfBE8KId
         Mb+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=Yahs6+cj;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=pA2tFXjT;
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.150 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750614292; x=1751219092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:subject:references
         :in-reply-to:message-id:cc:to:from:date:mime-version:feedback-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=elJqDii02C3zpjewLjegugxFY0ESaauYGsEfzhA2Lno=;
        b=DXFJbrnYWuT2P3UoJWf5rTQ2Lt7FyKFlPA7+Gd+BTfSnMtlJhiPnJpLTVzcMiqBom9
         yTtVJqcNLTF+3Lr0Pr7ktICebzWYdPejjQzh9gy1IZbpuwan3coAVl5OHZBG+dcKNWon
         IqZIX1+PpEhJoRWYD0JM7QJktsedVMAIPylQwVtGB2tu+HKKYC4WYhgfPeqa4Hc+sY2j
         gzT5BQOYscewYBqnipm0Vlsm6gkM/RUHFxu1RdszyUHg+BsC30qATrOl39fHlXRbud7i
         Rcbt+gFEcLcnkHtrqclSwBqzMpPHejI4DZwaYFWF8IlPczLmdWpyqiB4XJvuru1MRIO5
         Bobw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750614292; x=1751219092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=elJqDii02C3zpjewLjegugxFY0ESaauYGsEfzhA2Lno=;
        b=qUEtoSWEqvKYKMQT8qsGcs1m+HZxPJw45TzHf5SbQNSPUc8of8uZZp5x/hTSsJR9xq
         rQgY7FjuNmc3ZidBv7NHHwASO/+uDwWcruwuaGmdyTs/vAnVFck12SS20T/AY4efihWa
         ow0qZ7frpznBLQJ+WPw2KgkcpqQJ8xWntxpK+Eb69yGohYrHfMSFKVyEXJVUPlF8bvFy
         swxrwmlovF46lgqhIAAYgdfLmnm28O20z23LEnvKRN7YgSwANbVanguZVTPNUZaQkv6h
         101OVIFW8zL0QlbiI5PzZoPJ25QffWL2p3Fa7SRCbXH+5zdRSeyI3bDjnr1O6Mv+9lph
         tOMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSWl46vk2CNuPZiOKpbWrO5nv2D2F2C88Rf4abQrdKgSHDlxfW2SD4dN+Mj223CTFbHW+1Eg==@lfdr.de
X-Gm-Message-State: AOJu0YyBEwviz+gDqqbTNM1Rb2rfhVvj8OXiT8aaiBPkYsCom3VWcugD
	Q/H3UeIxPgeCC10AoNLJ5NRp6lpBdZGaIsimsNECx72aX6PRYopjVYgc
X-Google-Smtp-Source: AGHT+IG/WLQFRapf63USGaGPj8NggAQo99ylMVqPtyt9vemnjJce+ackhu5BQonG8LN1zNwWXiRu0g==
X-Received: by 2002:a05:6871:42cf:b0:2d6:49df:a649 with SMTP id 586e51a60fabf-2eeee59be8bmr6373639fac.31.1750614291902;
        Sun, 22 Jun 2025 10:44:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZedsCuHOVg01olggLqU1+UfJ2+2YkDMGthyl0xakg1UkQ==
Received: by 2002:a05:6870:ed95:b0:2ea:7154:1841 with SMTP id
 586e51a60fabf-2ebacabeff6ls1440919fac.2.-pod-prod-03-us; Sun, 22 Jun 2025
 10:44:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUb+0I5MUye9BzyWUqjGiyld5xpiM7lLQUnqDRw6aNba2WhurYgU0kvY8mEgn3vyushPwsq4TSuYE=@googlegroups.com
X-Received: by 2002:a05:6870:b619:b0:29d:c832:7ef6 with SMTP id 586e51a60fabf-2eeee64197cmr6117145fac.39.1750614291091;
        Sun, 22 Jun 2025 10:44:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750614291; cv=none;
        d=google.com; s=arc-20240605;
        b=DD4rqs4SjNk1SxGJ7Uv9zY0hgUSFgX/zKcT3XmZ/ycuIgEaOr4zBgzDpG6E0XOw19m
         3CIEuwic5ajZcoN7uMgUt1dx0uUawo4VVZUegDvIdOA6+flR1s+Ej01nV052H2IaIKto
         YWjRwTNtbhVR4jTTvOeWUvuu09VBNEmj0Wvy+uVWoOSEJ2j645sfwrBdu3YeotIdFJmu
         Wr8yLm7vlCCy2qJvCPHempqaOlGCebk0JjS6tDb4WHyNHZJhkTdnOce+Fg36V9+Pkb82
         wGFvTU5CqA3eC0r/D9agIsv22veW1jmrtR3bSgY6oO6BCdPSUVYwFC/jfQAQcyhNuaRm
         sSpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=wX0xhtUiNaavlvoeqLUK7VU9fCulEKaVWdquJFUErSQ=;
        fh=yprIIBYavQ/B0jFPn74CAhb8VG1FmJOMf3cwnEecz/g=;
        b=MrrpQAowMY/GGcogeRR2gwMvJxmjRriAWkPqq6CWid/pysA/6GmikD+K3V9tGltfnl
         AMiu7KBBK6/plkp9MpqnmXkHw7ft2aQxQsLuXKvwbPWBXkl1ctAR0fsorUWgmUhtQ1fP
         AbBlwJmKbBkhwhZ4cIKlDStVNBpj6WJgZIp7/jRWRB+f+IzeW+RGXmrj16R36GnBTuUb
         K5LJZifp7beffQe2pUsPvAZnqtPIJvt9DZJX+Cfh+h90EV06oGtY6EmCMdRD4Gviy1UG
         XsnoW+sAGylSUdtKbfkC8WCouZ1sr5te7go5V84YPDUnHpmXpllMxArMj2rZ0RdBQg5C
         pxKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=Yahs6+cj;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=pA2tFXjT;
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.150 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fout-a7-smtp.messagingengine.com (fout-a7-smtp.messagingengine.com. [103.168.172.150])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ee58bfe510si204378fac.0.2025.06.22.10.44.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Jun 2025 10:44:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 103.168.172.150 as permitted sender) client-ip=103.168.172.150;
Received: from phl-compute-05.internal (phl-compute-05.phl.internal [10.202.2.45])
	by mailfout.phl.internal (Postfix) with ESMTP id 43CE51380CEA;
	Sun, 22 Jun 2025 13:44:50 -0400 (EDT)
Received: from phl-imap-02 ([10.202.2.81])
  by phl-compute-05.internal (MEProxy); Sun, 22 Jun 2025 13:44:50 -0400
X-ME-Sender: <xms:EUFYaLI15FDYsQS_9YA_AGNAOkUxG9n1PjIyDb3T-akdbs_ukV1wFQ>
    <xme:EUFYaPLkdp1VRe6DT2650DeklDieDyeiRfTY15rvL8JxndxC8o7BjalG1U4JfUHIR
    wf2uKBWj7Usx4q81qE>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtddvgddugeejlecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpuffrtefokffrpgfnqfghnecuuegr
    ihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenucfjug
    hrpefoggffhffvvefkjghfufgtgfesthhqredtredtjeenucfhrhhomhepfdetrhhnugcu
    uegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrghtthgvrh
    hnpedvhfdvkeeuudevfffftefgvdevfedvleehvddvgeejvdefhedtgeegveehfeeljeen
    ucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegrrhhnug
    esrghrnhgusgdruggvpdhnsggprhgtphhtthhopedufedpmhhouggvpehsmhhtphhouhht
    pdhrtghpthhtohepvhhinhgtvghniihordhfrhgrshgtihhnohesrghrmhdrtghomhdprh
    gtphhtthhopegrnhgurhgvhihknhhvlhesghhmrghilhdrtghomhdprhgtphhtthhopehr
    higrsghinhhinhdrrgdrrgesghhmrghilhdrtghomhdprhgtphhtthhopehsnhhovhhith
    holhhlsehgmhgrihhlrdgtohhmpdhrtghpthhtohepughvhihukhhovhesghhoohhglhgv
    rdgtohhmpdhrtghpthhtohepvghlvhgvrhesghhoohhglhgvrdgtohhmpdhrtghpthhtoh
    epghhlihguvghrsehgohhoghhlvgdrtghomhdprhgtphhtthhopehkrghsrghnqdguvghv
    sehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhopehhtghhsehinhhfrhgrug
    gvrggurdhorhhg
X-ME-Proxy: <xmx:EUFYaDs_yb9YFppfCv4c0fskz0zJ80kVkvXwz9b6-c0fgPIMRlITFQ>
    <xmx:EUFYaEZaxjCB4hzPBWCwWBzNtdz8WB5Jk4UT_ekkDfHwLxYiu_fukQ>
    <xmx:EUFYaCYYWyKk4C_a-XKuBCE-IqJ_PCRyQQvJSwWIWNjq94sohS8LEQ>
    <xmx:EUFYaIAIajDN9wOSOu1jvmX001tICAPRn9_fb3Mjcsyl5fl1-lw2YA>
    <xmx:EkFYaEKIkb_SD1ArJAQy6hGxH0Xj0HCI--J_JMKLhqffgDVI5lmO1Cqg>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 5CC9C700062; Sun, 22 Jun 2025 13:44:49 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: Ta22caa133d9fa1a8
Date: Sun, 22 Jun 2025 19:44:29 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Sabyrzhan Tasbolatov" <snovitoll@gmail.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>
Cc: "Andrew Morton" <akpm@linux-foundation.org>,
 "David Hildenbrand" <david@redhat.com>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Marco Elver" <elver@google.com>, "Alexander Potapenko" <glider@google.com>,
 "Christoph Hellwig" <hch@infradead.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>
Message-Id: <8ab6c624-28a1-47b9-93fc-190719c06727@app.fastmail.com>
In-Reply-To: <20250622141142.79332-1-snovitoll@gmail.com>
References: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
 <20250622141142.79332-1-snovitoll@gmail.com>
Subject: Re: [PATCH v2] mm: unexport globally copy_to_kernel_nofault
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=Yahs6+cj;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=pA2tFXjT;       spf=pass
 (google.com: domain of arnd@arndb.de designates 103.168.172.150 as permitted
 sender) smtp.mailfrom=arnd@arndb.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=arndb.de
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

On Sun, Jun 22, 2025, at 16:11, Sabyrzhan Tasbolatov wrote:
> `copy_to_kernel_nofault()` is an internal helper which should not be
> visible to loadable modules =E2=80=93 exporting it would give exploit cod=
e a
> cheap oracle to probe kernel addresses.  Instead, keep the helper
> un-exported and compile the kunit case that exercises it only when
> `mm/kasan/kasan_test.o` is linked into vmlinux.
>
> Fixes: ca79a00bb9a8 ("kasan: migrate copy_user_test to kunit")
> Suggested-by: Christoph Hellwig <hch@infradead.org>
> Suggested-by: Marco Elver <elver@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

Acked-by: Arnd Bergmann <arnd@arndb.de>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
ab6c624-28a1-47b9-93fc-190719c06727%40app.fastmail.com.
