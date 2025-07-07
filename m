Return-Path: <kasan-dev+bncBAABBZ5ZV7BQMGQEYCNENXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 120BFAFB647
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 16:42:50 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-60f0ceb968fsf2875869eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 07:42:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751899368; cv=pass;
        d=google.com; s=arc-20240605;
        b=YEPXkZj9mjlcZL1lW06Qrslm+YZEKjxyX6NvJvmZNa4DAA5hQbjyaWrOzksUeWMKyF
         7jHJ/Jce+dagYDuu7WIkZAaq7I+qkLQC7+0fa2OmkOWURD1yyqcSrIMO+aX1g1kgwr7+
         Vp1dJF2HXZKU5vrhaFTk9N7t1Lqt7tZmaT0veDRjeJuHN8cS4Ui9G1964q9u3Us6C+Tl
         ZTNUoFKKcGnbzER7AqbZco//ualAUpPxRRPIh5npL0KTKFnRjQgzhHyCOrxvY1frUfLG
         4FYhe6/wJC8+QvlMeQ2NCH7iZwNOfy+A1PUKCjGWGeYTS+aqd4fKCV+ObJcYu6NU3YFg
         sHuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jM7AvULbi9HpCYLo343FZDkm60FRJUnzu8BXMKbNGqs=;
        fh=/ggcsewzjdUma31ruaDwh7Ljw9T/CzZIOswN48ifbi4=;
        b=Q44IB1IA7QweZKTfYIRQ1gQvEUycryVEBRrqcTiOgZ1rmnPCVJ/D9pyYGHReIXXR4u
         owv/2/mVw7LEINXJ4g3rG6lb7sSlrNOQG09dPZbIJu26iqUJ5K5sDMdu3X4/H1PN+4u8
         DzREt8VgsWAu688KBx3Qz2uC/zy2bfQwvDJIrM4ClT6o0aWSZP1MifcLflGud198pLk1
         P5Q7zh1crGzAVRBTbvKK7enEt0vPPkCVzoZW34KjvGCO/63PPb1fW41QcjZL/1ucZdF7
         buPtBIiDyoe/jjfaFEHpZpdrPu/HX2DzFJMcXtPO4v+GhHHvqoGmhhkiJizb1JUGKqaw
         AJ0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V4OaCflZ;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751899368; x=1752504168; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=jM7AvULbi9HpCYLo343FZDkm60FRJUnzu8BXMKbNGqs=;
        b=lC7IN9M0LLIxrisPbu30ZRydxc63wcDr+6niIwQ8hvi1FrXQFInCm8bA8Jzp4f2xWj
         jxobAn3+MV/BK2watEdvFKqcE/iPn1cdQWLhdjjpbrkdeWWfbdLFt6BnKNf2CM6gJ6Yt
         Gj0qABu8OR3L5yp4a+jToASZOPg4Kqq1dMcTV0I/8di5I9ZBYPlKjniy3JHm4wSGBaqJ
         9va57vBCf6hzBjeOdNbNmKJv9XdWTFR4c7DVmyqTVzFvOKS2b9r2DkYQk1Pbp2F67u62
         VJN4gz7bkOzjumlD5jdttwpXDqTp0GGI5LXSwIyD1y6TLGkkKc92+VnXvTG5btrjHgNm
         VmSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751899368; x=1752504168;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jM7AvULbi9HpCYLo343FZDkm60FRJUnzu8BXMKbNGqs=;
        b=sTkiK1iO8SYU/Id83B4JRh9G04Ivrsjj9Wx+4u9GTMnRDxJNZIGiEnn2qTOzWJMh6d
         0XAF+fpkfPmEx5wQu/CtCaUk1Hh25/2S7M0+UHOhXYie8CaPklDAuSdn5+TIwhUX2JD2
         gZ5U7NsJ1abltC2dUZxJh0N5KTvz1zftSC+7mS3KojcOcbqaBUhCHJanAdR6pznSaSji
         7CEacYWNV50j4/S/AShCCUijEHB9EcOm14ZjvwS0grWM1IhhZ1y3mZocsArapzsQZS1F
         +ff/D/Uptr4LpDCIUa/P8twgwgRukW0ay4EO5YWvxXyKzMopCANTwxQWH4jxI6tn27DY
         YH7g==
X-Forwarded-Encrypted: i=2; AJvYcCVjt8ZLXTbIUFym9/L0HDQiVPp0h1NlffdD9F1+n6O1xQaV5KAMutMCbV75ZCEkV8OicaVLZA==@lfdr.de
X-Gm-Message-State: AOJu0YyoM8x+GVlEWacSF2vTPIOye0yjG7G5DLFQ5h3HkfqgfMkv6/Os
	QYs7+XN5QkwUBsg64AJ8OuZhaH/455vWrKS1BrPOHJp/TEGTMXPlyVvh
X-Google-Smtp-Source: AGHT+IEFlIRz5UqWcv5Yb+TdczfMMhRIF5oDtIlGRr8kXveCXbbgIEfxBC3S2gnrugsCyyhHZDLlZQ==
X-Received: by 2002:a05:6870:459f:b0:296:e698:3227 with SMTP id 586e51a60fabf-2f79203e102mr11127470fac.36.1751899367964;
        Mon, 07 Jul 2025 07:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZco0xzwUY+90TOEl7tpv1POui8WwalL+tDQciVuoEXESQ==
Received: by 2002:a05:6870:2805:b0:2ef:17ae:f2b8 with SMTP id
 586e51a60fabf-2f79b14891als1533910fac.0.-pod-prod-05-us; Mon, 07 Jul 2025
 07:42:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3hv/AJ80+4SlNGdZFei1UIO1GjiVtisc3ArnJZKQ0fROr+R9bAzteqt7wsr85z8psZ0vs3pGtr4M=@googlegroups.com
X-Received: by 2002:a05:6870:1b0b:b0:2e9:96f6:1795 with SMTP id 586e51a60fabf-2f792029479mr10897469fac.33.1751899366950;
        Mon, 07 Jul 2025 07:42:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751899366; cv=none;
        d=google.com; s=arc-20240605;
        b=CZP52+ywtypTMazcl/TsI8iDB9RYbgIHt7SMhqSjHkGu4M5439Nrq8f9MaorIVt3MA
         kJ7w7+ALIxyJEpfzpZmaw3Dl487p+f47z4/n8seWWcvuwjHkpj/rC+h4nAaoEucNml7c
         Xv+up0rpRBphixnRZeeoUR8QCZH/AO2IWObFyxef0BsIdORVfz8NHxqQWoO7IBfdhXI7
         g560M4zXzoOBR7X96vsEgccwBoNbT2bWbLE3yGQCiEbbnLEshhuenbO5iD74zrkP/ORV
         6Vv2H6haQz4Sy5wS2Fo3Woho6YXUvRcgR/AGPgxrIk+/JjbOtIxsDnGjMfemguJr2Ddp
         NJrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1A+i7aMcf5ReW7LkDyYrEnwRq+3f66ir16xsIi4HmOM=;
        fh=1sxG5E/nygP/ZsLVCLHKsEzOAX3ljbg+Iz5HceMNGFI=;
        b=DmDVraM9D9EVctr8VVz+bovzVEY/zOFSc6Qu0xBYBCF9JHpB1ZS+FVzmnT5fKFql5p
         nGzQX9m7rcGt9xc0k8vlEyIMWo6yLkOiJiEBtG6Y79pBCky3VtyI9BNDJuOyAyhbbnvj
         dzPzkrMbT8REvDAMhgywuN9pJyz+wnWr/wTv70Ig2X/U/91rjSKwv4WkRPc09IEFwwLn
         O/z1K4Q96BCk/9UCM8diUWMpCEtvrLA6TZg20gHmBrLlP/m3MuxDXF2oDc6t/haOUe/V
         lUvXcrb0Pf41CU7N3U0+4FXipdURoAqT7OqHpTF5PCt740VxrLax8ka9Qxp/rpp8mj88
         d+SA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V4OaCflZ;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73c9f936b9bsi360580a34.5.2025.07.07.07.42.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 07:42:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AFD755C5462;
	Mon,  7 Jul 2025 14:42:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0DCBDC4CEE3;
	Mon,  7 Jul 2025 14:42:45 +0000 (UTC)
Date: Mon, 7 Jul 2025 16:42:43 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Michal Hocko <mhocko@suse.com>
Cc: Marco Elver <elver@google.com>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Jann Horn <jannh@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
Message-ID: <g6kp4vwuh7allqnbky6wcic4lbmnlctjldo4nins7ifn3633u7@lwuenzur5d4u>
References: <cover.1751862634.git.alx@kernel.org>
 <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
 <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
 <aGt8-4Dbgb-XmreV@tiehlicka>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="tmiwotmrfmdi6oyz"
Content-Disposition: inline
In-Reply-To: <aGt8-4Dbgb-XmreV@tiehlicka>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V4OaCflZ;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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


--tmiwotmrfmdi6oyz
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Michal Hocko <mhocko@suse.com>
Cc: Marco Elver <elver@google.com>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Jann Horn <jannh@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
References: <cover.1751862634.git.alx@kernel.org>
 <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
 <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
 <aGt8-4Dbgb-XmreV@tiehlicka>
MIME-Version: 1.0
In-Reply-To: <aGt8-4Dbgb-XmreV@tiehlicka>

Hi Michal,

On Mon, Jul 07, 2025 at 09:53:31AM +0200, Michal Hocko wrote:
> On Mon 07-07-25 09:46:12, Marco Elver wrote:
> > On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
> > >
> > > We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
> > > doesn't write more than $2 bytes including the null byte, so trying to
> > > pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
> > > the situation isn't different: seprintf() will stop writing *before*
> > > 'end' --that is, at most the terminating null byte will be written at
> > > 'end-1'--.
> > >
> > > Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
> > > Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")
> > 
> > Not sure about the Fixes - this means it's likely going to be
> > backported to stable kernels, which is not appropriate. There's no
> > functional problem, and these are tests only, so not worth the churn.
> 
> As long as there is no actual bug fixed then I believe those Fixes tags
> are more confusing than actually helpful. And that applies to other
> patches in this series as well.

For the dead code, I can remove the fixes tags, and even the changes
themselves, since there are good reasons to keep the dead code
(consistency, and avoiding a future programmer forgetting to add it back
when adding a subsequent seprintf() call).

For the fixes to UB, do you prefer the Fixes tags to be removed too?


Have a lovely day!
Alex

> -- 
> Michal Hocko
> SUSE Labs

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/g6kp4vwuh7allqnbky6wcic4lbmnlctjldo4nins7ifn3633u7%40lwuenzur5d4u.

--tmiwotmrfmdi6oyz
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhr3OMACgkQ64mZXMKQ
wqmhQhAAs+ekX9398aALI01OsOZ18qRcUwUGAgNGOEKzODVWKq+ZfCv5kpLjB8Rx
mz7WZld1t7roGUyTkEE6qInFFtJ9EB2Oc0WqZCBNEHvS7hRiWLbJdaYv3vdT5hl6
++tJ/HhXTGChathW1i4KfKiu5iZdre5B0h36dXQJvU70Xewnca8uY7Vq4u4mfpwU
POUiVLo1FPMx5PfJYILFFMhI8PRWrAwx6wlkbjHBmVaRqG4z286j4FonO8wwwwNt
8E8KmyNt2a8wsc0+ezpmDJ7lgsWpxr3qTp3FGIby9yokzHBUrc4IAlzj9agSPmlT
qWLcFUwdFPzKb4bQCX2zVfjidlbO14g6iS71wINotWZvKhy8e9Wtza78qUFhpGV4
77u0tXXT1dVd3K2P0HYz8AmXtgawUDUA/8DAF25SxfHIodsdJq35OsSGPzfrbIfC
BuT+K4OhfWoODvzcOYFpEyrz2a+YgXRep4GfRDc69PrGhmQk8S68V9vcMft/tzvy
k+ggvc9f1Y1Y1MtXFKV91pGhD5//TnJA1UYduI/HOz+2DeTFk+s62nHjiy/zXdzE
fvsiLzgRkXT8geMyrGRtKxnKKWqWEXrt0kmfr8h6FwjrBjL3hRzsrCCSyqCgmKyJ
isD88CxA4o8wntqCuOxhMtsOVK5jXG6pN56W+eZ/LOfzfz1MSRE=
=mTHU
-----END PGP SIGNATURE-----

--tmiwotmrfmdi6oyz--
