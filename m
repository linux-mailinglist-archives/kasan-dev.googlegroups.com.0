Return-Path: <kasan-dev+bncBCT4XGV33UIBBAXQTO4AMGQEMWD6B6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 4163999779F
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2024 23:39:16 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-7b0f73c8935sf203420385a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 14:39:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728509954; cv=pass;
        d=google.com; s=arc-20240605;
        b=T15VsIVF2FDwritKll7hWkezc4mFBC5B6RwXx8+MLz97+6yfcDhIYdDNLVItnXH4YS
         Y/xRQB3uwFpy0nJ5l4Fc2Fjkgw2ZA4hyGFbWtxEqEQP+A0DHhgzoMsfyrIVIUPe0x6Rd
         T0WOz1qD7LwgaxLJdonre3Wte2YIHiJOV4nEtnbn4XBveK6qsUrCDt5nIh6A9tmb2VMH
         2Q5HMpiE+77DOqsB+ViCjZFup3McNcqYk9By5T1fikepfZ7+uvMfCzV11oRG9771zgTA
         DEeb5LVz2eMGjGJ+6jOL4yYtlq62X4EaC/LEYc8dTtxumzJ/VSYrKtDA5XZOQTG5ClpQ
         C2UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=foDAkGec+/y/r5eBB1mcye60F5rKUuue/3cIT3o7eJo=;
        fh=EIbeUHFQS8RNdqr27PwJ7CeBgjCnwJrPEweVBbPt3To=;
        b=CKbmUC6ydWNCN9DdpmZjvijqrgKW8U8wTHlMqKYl/gr6A3udJrou/fNRWonClm/nE/
         Tw9OqV9nVXmhh6EfGCw2bUF9vURbfue7+qTsImq90O9Wn9YBuQ7qjQ/wy0fxSssZtHrB
         06qS2FvvDYMiPKsji4ENCAz7FViV7Q8nfvAhg6R2ZnO6PJKx6WmabHbWqIQdijrLyXWp
         pABSf4y5Dk/+X+lfVWGIBxnBMpVJugLgmzcIfp9+hjiTXCfbq3jh+zKTiNuISq9Bq8Hn
         rznMqZNTs89ec42bBdvARmedjKDKrkbyYupd1djFfSvAGczhIdPtbR82fnYmpd51EMEL
         uJgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=c4fjM8mh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728509954; x=1729114754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=foDAkGec+/y/r5eBB1mcye60F5rKUuue/3cIT3o7eJo=;
        b=xbzCg9YuzTVfSI6m38oJzJndaQ0jIyp6ldESI4ZjIK9krU3V7AWrVUq+1uJwEg0Jo8
         2SwT/4VqZ7VG0CJDdDOTPv/zMLCq5qvE4sfjxazbOuh4KcIaQjtxQF2VbItg/TnmZqkU
         msoC/2P1+dE0lJqCx0nlIg9Ov1IUvn5pKwkCk6NRrwBG8HsH9zbpCww/aL9RwAgy3NsF
         1CPJRYHA5Z2T5i3YTCFy9UQKMbpa5cDI8YIYHlAoT9AyhgCzGfdK9ak9aJ/rnlRI6/7R
         o8meD7YSWeP1h7R4qBomhcpTg9iTv9DYjiRSKJrJDLtR5MCIk78WliZQG6qKnbCMwWI+
         ZeSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728509954; x=1729114754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=foDAkGec+/y/r5eBB1mcye60F5rKUuue/3cIT3o7eJo=;
        b=N5f6B8OgIFvZrESJlzL1WCBMbt1VWBPJfLvi/kysXKgCpVtfnnYr6fDpal6a6Gi0vc
         CgHSlji6AQ5spWloZa5GxJL+I37HLuGR1JEFwPA9ZneA5EV60pX2S5zcias2GNoFp5IR
         7YXcfXJKv3+MgmR+Zvwz/YuZYAyLBvWpWkn3ekQ2VceJLdHFUJeLcfrlUpjtvpgPRo3R
         sJuugDpluKFUhjyedMtVE4r+/42hBhoztMDJPKraqY7pjXFiqxm19vrx43bZ1Sun05D6
         WQ1gnb66ZPt4uxcUYWz8jI8l1rTXtQ74d1GhZPokOpq6altZ6WsTbPDqP8c8HyRzk8dl
         JmTA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2vAWW2+0paS4kiHbEgrpzT+VnNKIuuqDARjNGX1M1uk9jo6syR4TQctafAxtdJ3sFby/TLA==@lfdr.de
X-Gm-Message-State: AOJu0YwI8n6563cZiK7IwrWqsaBiqtquQfNkx43Lklk0AxT2ujU+V1ip
	KFrotNg8pFwIEWbRJy/dznueVrNh2S0jp5nMIs+49x+JtpsT9+sN
X-Google-Smtp-Source: AGHT+IE585VzvLB6VYAMng+0JBAMY7PnhImqZfDIOaSqDJFnnBjlFs+N7BaIrmtA4Fcsmy4FOorHMg==
X-Received: by 2002:a05:6214:4197:b0:6cb:c661:49ce with SMTP id 6a1803df08f44-6cbe5278577mr16173876d6.23.1728509954448;
        Wed, 09 Oct 2024 14:39:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d03:b0:6c5:1cfa:1e03 with SMTP id
 6a1803df08f44-6cbe56639cdls5233936d6.1.-pod-prod-00-us; Wed, 09 Oct 2024
 14:39:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUO29ojql9ZDIGubLp2zMpvE36T3pOeYFXVnKPIhs3CO+oLK/ujdKrHvWAKJYzy+PIhkaNouBlPcqo=@googlegroups.com
X-Received: by 2002:a05:620a:4053:b0:7a2:e2e:31c6 with SMTP id af79cd13be357-7b1124f3f93mr163960685a.21.1728509953756;
        Wed, 09 Oct 2024 14:39:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728509953; cv=none;
        d=google.com; s=arc-20240605;
        b=D1OQLmsocdyEdqxr7zetj6Ebu2+ydOMqPyPmFjzvEk77mBHsUS1q/Vr6wk6NmJj/pp
         MShouXMND1WGGn1VtMd1UgpkHWq3NxG6piZIJ2BMcQucwfmlVWjHKXpLAmL0hfgCgPar
         Reb5CY2wgMPJ9ReR7wI6ex5u+WhGdw3EI2jIPoITbdJHVbt2nz2eHX49gqo5nD6PcIDx
         MqdcHHE5hGWhhbrRxJM3qXE/tfTRJgxUFJr5hdjodFvLWjy+Owb80sSZV/l/ZLi806tb
         HFOug2BaMiPcwNq5dItsLcRvmdASWUP9EN8KHGMujYdM5auSPt1ph9M3UpKLoAhlGx6S
         T5cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8U4CFzeDbIm+H39sSJH/+CCEIzOuTKEt+8YbQcA7QVM=;
        fh=3GxtzfdtrbMSr0vj9tQY4edKA5cfksCjtVwgLDDFH+Y=;
        b=Tsim9iLM2r77p+1GbRC1YFtUv9DfnXQkxeT5UPvPjORQAofZenvmtM2gm/OTL3evqo
         aekihmDIAJQLTqIWAheI+/aS+dIKJkUsqxQ7vCGneLhadJwF1SQ99lSFlQmB1BZuO1Ya
         ZBfpzVnmWaTjBVxI4e5FUBHvhrGSNztzQL0wsUb0+8bC0mLR8AC7z9UaG9BNWyW2g2kK
         iIDZwhfpRn92AHBZgDw8mWzd5nrs5zso1fmbCsSX7TfwpTyR4gtjDNJFkFRo8PjiRsTJ
         X3Nu2RCHGLPnVrBgUDLUC9oa8nQXTRrKjbb20EbvLwFhj2cF7smbOImJ02OcU2RmJXab
         J9qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=c4fjM8mh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b06f444e51si7707585a.5.2024.10.09.14.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Oct 2024 14:39:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id ED0885C5E06;
	Wed,  9 Oct 2024 21:39:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E030C4CECC;
	Wed,  9 Oct 2024 21:39:12 +0000 (UTC)
Date: Wed, 9 Oct 2024 14:39:11 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: Marco Elver <elver@google.com>, andreyknvl@gmail.com,
 bpf@vger.kernel.org, dvyukov@google.com, glider@google.com,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, ryabinin.a.a@gmail.com,
 syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com,
 vincenzo.frascino@arm.com
Subject: Re: [PATCH v4] mm, kasan, kmsan: copy_from/to_kernel_nofault
Message-Id: <20241009143911.3c394e1bc598f59ce764a67c@linux-foundation.org>
In-Reply-To: <CACzwLxhJTHJ-rjwrvw5ni6jRfCG5euzN73EcckTSuM6jhoNvXA@mail.gmail.com>
References: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
	<20241008192910.2823726-1-snovitoll@gmail.com>
	<CANpmjNO9js1Ncb9b=wQQCJi4K8XZEDf_Z9E29yw2LmXkOdH0Xw@mail.gmail.com>
	<CACzwLxhJTHJ-rjwrvw5ni6jRfCG5euzN73EcckTSuM6jhoNvXA@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=c4fjM8mh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 9 Oct 2024 00:42:25 +0500 Sabyrzhan Tasbolatov <snovitoll@gmail.com> wrote:

> > > v4:
> > > - replaced Suggested-By with Reviewed-By: Marco Elver
> >
> > For future reference: No need to send v+1 just for this tag. Usually
> > maintainers pick up tags from the last round without the original
> > author having to send out a v+1 with the tags. Of course, if you make
> > other corrections and need to send a v+1, then it is appropriate to
> > collect tags where those tags would remain valid (such as on unchanged
> > patches part of the series, or for simpler corrections).
> 
> Thanks! Will do it next time.
> 
> Please advise if Andrew should need to be notified in the separate cover letter
> to remove the prev. merged  to -mm tree patch and use this v4:
> https://lore.kernel.org/all/20241008020150.4795AC4CEC6@smtp.kernel.org/

I've updated v3's changelog, thanks.

I kept Marco's Suggested-by:, as that's still relevant even with the
Reviewed-by:.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241009143911.3c394e1bc598f59ce764a67c%40linux-foundation.org.
