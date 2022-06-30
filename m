Return-Path: <kasan-dev+bncBDW2JDUY5AORBIGK62KQMGQE3FQSK4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E3422561B4A
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 15:29:05 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id z5-20020a170903018500b0016a561649absf10365569plg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 06:29:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656595744; cv=pass;
        d=google.com; s=arc-20160816;
        b=RBnaEEZY25vK3YVHZOoppW4+XOPAmoVLthVciMYeOMsidFrGzqKYuj4VPuur+tfPtR
         bFTOIgM87VgoFUjLDKCWfdAfLoyXteba3nHOj/GkZcLUVLYZMB1d8ec6zpGSx4qc7n2F
         e7wyxgUVHHdo5qB5Q2XEZ7iiEFwFYjC8BSUi3/WgCoFIHfQaPN0jAxQu0ghCn6k2EeiV
         /DHLSWXQ2pS93XlwOEPRGM9DwcTFnD92yCfgQmJ2mqHXhNKFY00NcTRmSifGw8hZR+Ap
         XkUsRgGbIXfsjOifkkYCEi8UxXnONeoWGbF968lWxuzrxsqLVEBR/UyOI8RTdqZHielN
         3Gig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=k3fmnhZaGfibQACtwBUOcX/UIyZKZNU5hK9W5kZFTy4=;
        b=cA67kkPlivHeK1Lj3UWKN3cflc2E1OKb6BC8sA9G8nYzZBIzRTZnsaRA/auT34FN7N
         nBd6mbEHSYqo13Hbbj2XUIUZcKcmD/3wAJI+czM4my4O3smMJUsHcDag3JTuIukrTZvc
         rlkDbPfuM9ixsXBcSWXS+GXKXj3pInVOs7p6BE+1wyL4kG7f2t39Dz7/jSFTQqXV2LOy
         mF/nM/qDcmOu8KAauYPr1o7X5fsRsHUtmhPJ412C4UEVFuixyYZ15B+zKTCWPJFZgFrD
         dG8101KL2P6xsP4OaoZDl2vXXKe3uYW5rMQH7JyQKnJlnlfrkt7zopqmb44UtZSKugsU
         K8VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=LLapPG0y;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k3fmnhZaGfibQACtwBUOcX/UIyZKZNU5hK9W5kZFTy4=;
        b=k/le9HZaQZkLjbskiCZ717Pxlags95jnwIU0Djz9Voa2RfUpysIFvV0WEXQdisaUn5
         xs4iQWd0PkP6855CAUmtAoI6SaR3O6Z0sbiaum/WE9IOSDXpjLoKRdO/o6RlAV5mxniB
         g3QfzSuLlCURuzzcKUILm71XFUTxaqt80trGMs9j+BlYY61sLQL6jpRdfOw9Oxh6sV5L
         cDOoASkn+7RSlXZoTQBqXRRvewXU+6O/pqB2tRBas6zXeF/ASrlwSyA7fBSb/67aL4GK
         JJGcxvS7wNM5NcsaLP5BBymZ3BgwVlBWtFVQe5e/1ig40QkdEmHaYsxNkYkk4xqqRpMT
         QVbw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k3fmnhZaGfibQACtwBUOcX/UIyZKZNU5hK9W5kZFTy4=;
        b=MLd1qTDl+yNZZK7+e1lXwdWGhEM5sjQJX3NZFaJuxMEZoSOBv29ZOqtFjz10G8AGqQ
         myGhECxkn9LShEFk87kw6lpMwlNDkVdJo9XJD6sl8UADG1UuU8iCjqALVDWN4fL+FMSb
         iZ/LM8TALXtbizfTNOaLVFQ6xhAYa+qfUNIP0n67RfoaGCYSVsgdDBMczI45wfO0nc3K
         dc4V01EiggxatP5lxWArOM0JrEC3t+2o7lr35CwSY9lsbQ8x0NIR1IrUMVrfFfNSatXt
         pHMJAsGRy92pEp+ViIb58wKW95xbHargw3LjG5REyzupqRjY0YHf+1/c6vKIzNl/b0tC
         JHsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k3fmnhZaGfibQACtwBUOcX/UIyZKZNU5hK9W5kZFTy4=;
        b=ObEV5VNX5qNnWxgfsbFgVWCpzF3MXN1rVJHX5aoHF7afZonuzaKUZ8rSJTi/0NEhIN
         +C/27Hg/vxi0s8Ej+OamX4IDRhD3OedB2LcO06Ym7enwilK9Mgzg62K1TiarDeaUaEkT
         eCyzSqSC1P9BQv/peXAglXrB8o9G7QbNy1PakcP1Xet2JGxMQqcuGpO8zSEFMxQ9WVhx
         lmo/ylKnL8zLZx7ZaQus9Oe+4Clz1OJQRxLs1Vqw/2rWZZAmnQnhsunVePfVLGNMi5lp
         4tTKhPntT9vkj1tbvP1dJDgrof1yI05Ib20GtTNlUmQuCzuY+fR0WHz+Lv1RsNLGLiZg
         b/4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9oKlnKliV3Wa0x0pD3TctjLf7CUJUbr/aZ/3QJfsDDn3oHrC7L
	c+hcEml0H0FaQdVQOlYSATw=
X-Google-Smtp-Source: AGRyM1t3efekpUWDwSwYRcfXWuT8wKzYwERuQ605sef/ceopx9zFgDerzDKi1Y0fkU9IM3V+sfeJ2A==
X-Received: by 2002:a17:902:d58a:b0:16a:3139:5ff7 with SMTP id k10-20020a170902d58a00b0016a31395ff7mr16362606plh.118.1656595744438;
        Thu, 30 Jun 2022 06:29:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:179d:b0:505:9501:adc5 with SMTP id
 s29-20020a056a00179d00b005059501adc5ls17783090pfg.2.gmail; Thu, 30 Jun 2022
 06:29:03 -0700 (PDT)
X-Received: by 2002:a63:68c4:0:b0:3fb:984f:6779 with SMTP id d187-20020a6368c4000000b003fb984f6779mr7654380pgc.444.1656595743811;
        Thu, 30 Jun 2022 06:29:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656595743; cv=none;
        d=google.com; s=arc-20160816;
        b=n8ArREb4i9PgQmHTcrsxdT+DUWephwZXow/+QdykbAdUkCZSnJCqzfWUWEANskcJ4a
         tI4uVMiEzGgra+97FWepCy0jfCG4e1myiLKxmO159ExpAoj9KMuigR+Dy7zmj7zJvMMj
         Rux//nfP3nPOga0r2iG72iITYXT/SrwKtAMeOSHrQh0bJg2fpsnL62SBbSZTmoUWd/Lk
         nnWINohDwmkBqPEOmchaMNtXJdnP18lSHZM2EtRVlxPaC/puTpe35Bd46xQZMwAjM5+M
         XnU33a+Av0PumATX1ejj9jn9uraaQaT9/u/nb+QYId+A9Onhy/slKFOIeQEVwVOHQHs+
         tAPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kpBSxRjyWissqpsLZxu6rDb8LTkx6HPCXFAIhKQadlM=;
        b=n4E9T/HCZruTms1R2gAgMdGcV8AmrnenQyR5AtaId17p/cLgpskhH1OR0iiBmR1mzU
         6+K4HDNlMXkO7ID4p+rdfow5z/mM75YnqNtezdxaaDx/7cybHbB1BsQtmAY2WMtX2xR4
         Wghw26zrdNGLIE961T5FmK6bT7j/ZFAl8xn4uzB3xTUYyN66td9iO+Wfxg+6YyYbZ5Qk
         KzJAQNZ9ZTrbv3SGWsT+4SbtlOX+RNZ1nH/v6TmydIpg72XWCLeiVGGeuZ+QIW1/bLPW
         ycoxaiiTc6zSTS0FWacwH5ILshLMtK0Xyz4UkA0B6ENj10w2tgIxoOkA3gDSjN8ZDr25
         ixZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=LLapPG0y;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id w11-20020a63934b000000b0040d1b0de0d1si883351pgm.2.2022.06.30.06.29.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 06:29:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id f15so11912168ilj.11;
        Thu, 30 Jun 2022 06:29:03 -0700 (PDT)
X-Received: by 2002:a05:6e02:1c2a:b0:2d9:45ef:75c2 with SMTP id
 m10-20020a056e021c2a00b002d945ef75c2mr4984281ilh.235.1656595743231; Thu, 30
 Jun 2022 06:29:03 -0700 (PDT)
MIME-Version: 1.0
References: <20220630080834.2742777-1-davidgow@google.com> <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com> <20220630125434.GA20153@axis.com>
In-Reply-To: <20220630125434.GA20153@axis.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Jun 2022 15:28:52 +0200
Message-ID: <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, 
	"anton.ivanov@cambridgegreys.com" <anton.ivanov@cambridgegreys.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=LLapPG0y;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131
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

On Thu, Jun 30, 2022 at 2:54 PM Vincent Whitchurch
<vincent.whitchurch@axis.com> wrote:
>
> On Thu, Jun 30, 2022 at 11:41:04AM +0200, Dmitry Vyukov wrote:
> > On Thu, 30 Jun 2022 at 10:08, David Gow <davidgow@google.com> wrote:
> > > diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> > > index 1c2d4b29a3d4..a089217e2f0e 100644
> > > --- a/arch/um/kernel/Makefile
> > > +++ b/arch/um/kernel/Makefile
> > > @@ -27,6 +27,9 @@ obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
> > >  obj-$(CONFIG_STACKTRACE) += stacktrace.o
> > >  obj-$(CONFIG_GENERIC_PCI_IOMAP) += ioport.o
> > >
> > > +KASAN_SANITIZE_stacktrace.o := n
> > > +KASAN_SANITIZE_sysrq.o := n
> >
> > Why are these needed?
> > It's helpful to leave some comments for any of *_SANITIZE:=n.
> > Otherwise later it's unclear if it's due to some latent bugs, some
> > inherent incompatibility, something that can be fixed, etc.
>
> I believe I saw the stacktrace code itself triggering KASAN splats and
> causing recursion when sanitization was not disabled on it.  I noticed
> that other architectures disabled sanitization of their stacktrace code,
> eg. ARM in commit 4d576cab16f57e1f87978f ("ARM: 9028/1: disable KASAN in
> call stack capturing routines"), so I did not investigate it further.
>
> (Note that despite the name, sysrq.c is also just stacktrace code.)

Stack trace collection code might trigger KASAN splats when walking
stack frames, but this can be resolved by using unchecked accesses.
The main reason to disable instrumentation here is for performance
reasons, see the upcoming patch for arm64 [1] for some details.

[1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=802b91118d11

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe6zk8WQ7FkCsnMPLpDW2%2BwJcjdcrs5fxJRh%2BT%3DFvFDVA%40mail.gmail.com.
