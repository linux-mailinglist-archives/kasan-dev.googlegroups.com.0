Return-Path: <kasan-dev+bncBDQ27FVWWUFRBIMF4WBAMGQEFRDVNHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D64AA3454E7
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 02:21:38 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id i1sf538528pgg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 18:21:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616462497; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tu0fmJEf1y92PqmWHF3PQVU/cJd8VbBy2KVyAvkcMynAorU/0ZLJI2uiDnKL1+ppnH
         zoLEcNWWozOhbcRrOZKiHwZOA0gQjOD11r0cywFxEXpEJrXahDw8cZRK1sqGeV/54zJm
         NAZfSr/V1Gb/dJDaD35LJja9bTCwmYDF/b4XgfUwcZpGwJPHK403qbH3KScygn2mCfoe
         kWSJJTROnx7Ds0EJT/Cnfsr9KRM0MgWRfTLqYle3i47hy5ghk/sOeRkjSnHh5wzPCtp/
         cRVHu/mdP9ahmHv9LAl15tPPxSF94RITiEf90ysHLX4L4i9gKCwYP3JxkWpcK8iN1rp7
         gMxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=4reb0DzoiL915K+XEyD0p0ZvNvHUZiSEh2i8+kKT7hk=;
        b=y5esu36XHF7+32hoGx0KBdRVmR8zuaOeiFEDd0jVshF2kJzVH/0NDXJ2OpmC/X+2yp
         4AbJWxTdyrhwu0qISB/qy+QTn1aD83YCDHr/6xcYG06Cwfcskkc30E5kj/ksxIid5XnQ
         oSTmRoKVxSbRKgWXXLmwLUR+/GHIB3omjoPPFLOaDWfSuXiZduZmrKqAjomz4oine8/U
         HC3W03MkVzFPKP9ZkiPAr6jP0EgQHd1BBdWHwpwlWUJZ1N5BBo7xzM97yEf/xWa1vP1x
         8t36EZAwyL5MKH6xBd9G+nuHpNANNKWlqhOHjOzeZ8XdwukbKrmCPvKGt6iITd/LIeZJ
         5vIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=VliLkGKl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4reb0DzoiL915K+XEyD0p0ZvNvHUZiSEh2i8+kKT7hk=;
        b=I0f/znWVxdjwfX7rCTzdAosRnsOiX/Ip68YfDkVYAveIpt06inQnCN3enILPzeMCTf
         cXp0y9hmfl1Dv0zKV2e7ESUTwCP+8rRbexPXjaOC4gBD+2CDLV+Z6trX4vYPQoBLx2IM
         QyrRwqMN0UbhA1ZtMVV27Rik6llPQs90l25BOmkG4npv8B/uASRKGYR3Wv6eoI0GATtk
         aYT8wGak+uN6vW+Fi5TeuprheHP+GSdjw7XxbQ7ansOwUZlgBcioKn5n6OkBLU1CqRMP
         +nwVg6vJ7sejP0m9UorKWpH9Wn/BKakZybN5CUcuuagVeCXUpVrWKccqUajlcdncqwqY
         y2bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4reb0DzoiL915K+XEyD0p0ZvNvHUZiSEh2i8+kKT7hk=;
        b=JI+7ig6erxmzra6AYA2cbbJw6uXYae5xZUHIBZsSh10MYFsXQg9ax9OKf7tkRzqnrp
         szPeCrSIJxG6/uInx/SP5RbFzAPpuiRcP0fXfwyqj8lDNUXh9Jc4P5DEqgZ7Hhx1P9EM
         zM2lByPgX/eZr3+lJ7c+GSPClv/ghBDl0VVUklXlaXi3H1s6LxrbympfMRZaNnmz9aXz
         qMwKoBETuQjju4bNzU0CkgAq+Gpx3Y+2tuayfgP0tDktWMUHl4tPT5+aP4uM2mdX7kwp
         XVi0zYPuINmKLKA9R7fybnDM1BscgTKAtoTOk0G6Ucjk43h4o0rh4CMTjtSOP7yOKr7r
         JecA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lL5K/UBIGjLIH1WrtxB/6iKy531VIjCIkjQE2J5lxGPY4qrYQ
	oizWRqyYb0Un5Imfk26AGRw=
X-Google-Smtp-Source: ABdhPJyD5UJF9nTmbpMM/iSDtvEJ8rMY/g6ejjojZNK2/sgIyGtU4RAkz6nl9Darij1pRLPVigJOHQ==
X-Received: by 2002:a17:90b:a01:: with SMTP id gg1mr1845324pjb.22.1616462497538;
        Mon, 22 Mar 2021 18:21:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ab81:: with SMTP id n1ls606543pjq.3.gmail; Mon, 22
 Mar 2021 18:21:37 -0700 (PDT)
X-Received: by 2002:a17:90b:291:: with SMTP id az17mr1764623pjb.206.1616462497022;
        Mon, 22 Mar 2021 18:21:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616462497; cv=none;
        d=google.com; s=arc-20160816;
        b=pyfn4Nygw0WQ4ohs+csnnlHzCvRmeeTq5VT7SsHnNn7XswxnYUogNQBZySDkiKCWFk
         MnjRslLkrRntLZykd9d8xpH68F4HF0VU+unHGv216/zFYrGGQL47zJw8Cc01ZeUwga6E
         BIJKgFOC+GzT+13qMLYypj44mrMR/7FHIITx8ZE3tE1iQZUU8GAO2m6lLcrzF1th+dn3
         n0AZDPXOy+dT78tR/nttmNkQC0gg2SVZXOqEQy34tffpSvl8pbqXoBXKlq/kXKSQib49
         yAcp/X/0r+SsFc4Yzm+CAZGFiSQgoyGDuMSFUQXhSVxDrrfmbSiZeBEGKhqeVIF8ZXt2
         KrVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=D6/t64GWTSvYj3tg/pZ5Ic42OSmLCS9eM7+HxTJh7bY=;
        b=HkAPVph9YB4yADkpElJLLZNIW9td9WprnMmTlG5AufPCrvvcQGrVmNcsdkQntWWA7A
         VPqVH4g6aMsB7vkQzrscczS5eA66VSYXfKG63oW+tBnupsL4tDA0Mv3L2sRcTQkEC4Lv
         nQT3k6/8YU1xYXol44avmFYG/hmHJ0l67rNi0Nk90N4khhick92PpeKCu+oKTQVCyyIG
         ekDYm10qoy7KIrRQzY0bfwtHX6Unctn36RF2i0txnWe1cUGl/eBzzH903iH36Vard4OS
         12stqHmlJnjtZ+p9BY5CcSq45ycWR3puTcLn4tlxSfVjzD20Jcz8CwaUc/O9SXQWBNP9
         q5Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=VliLkGKl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id r23si770812pfr.6.2021.03.22.18.21.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 18:21:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id j25so12556365pfe.2
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 18:21:36 -0700 (PDT)
X-Received: by 2002:a17:902:6ac3:b029:e6:c6a3:a697 with SMTP id i3-20020a1709026ac3b02900e6c6a3a697mr2657330plt.2.1616462496621;
        Mon, 22 Mar 2021 18:21:36 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-ab57-754e-edac-e091.static.ipv6.internode.on.net. [2001:44b8:1113:6700:ab57:754e:edac:e091])
        by smtp.gmail.com with ESMTPSA id j188sm15051642pfd.64.2021.03.22.18.21.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 18:21:36 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v11 0/6] KASAN for powerpc64 radix
In-Reply-To: <5a3b5952-b31f-42bf-eaf4-ea24444f8df6@csgroup.eu>
References: <20210319144058.772525-1-dja@axtens.net> <5a3b5952-b31f-42bf-eaf4-ea24444f8df6@csgroup.eu>
Date: Tue, 23 Mar 2021 12:21:32 +1100
Message-ID: <87ft0mbr6r.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=VliLkGKl;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::434 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Christophe,

> In the discussion we had long time ago, 
> https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20190806233827.16454-5-dja@axtens.net/#2321067 
> , I challenged you on why it was not possible to implement things the same way as other 
> architectures, in extenso with an early mapping.
>
> Your first answer was that too many things were done in real mode at startup. After some discussion 
> you said that finally there was not that much things at startup but the issue was KVM.
>
> Now you say that instrumentation on KVM is fully disabled.
>
> So my question is, if KVM is not a problem anymore, why not go the standard way with an early shadow 
> ? Then you could also support inline instrumentation.

Fair enough, I've had some trouble both understanding the problem myself
and clearly articulating it. Let me try again.

We need translations on to access the shadow area.

We reach setup_64.c::early_setup() with translations off. At this point
we don't know what MMU we're running under, or our CPU features.

To determine our MMU and CPU features, early_setup() calls functions
(dt_cpu_ftrs_init, early_init_devtree) that call out to generic code
like of_scan_flat_dt. We need to do this before we turn on translations
because we can't set up the MMU until we know what MMU we have.

So this puts us in a bind:

 - We can't set up an early shadow until we have translations on, which
   requires that the MMU is set up.

 - We can't set up an MMU until we call out to generic code for FDT
   parsing.

So there will be calls to generic FDT parsing code that happen before the
early shadow is set up.

The setup code also prints a bunch of information about the platform
with printk() while translations are off, so it wouldn't even be enough
to disable instrumentation for bits of the generic DT code on ppc64.

Does that make sense? If you can figure out how to 'square the circle'
here I'm all ears.

Other notes:

 - There's a comment about printk() being 'safe' in early_setup(), that
   refers to having a valid PACA, it doesn't mean that it's safe in any
   other sense.

 - KVM does indeed also run stuff with translations off but we can catch
   all of that by disabling instrumentation on the real-mode handlers:
   it doesn't seem to leak out to generic code. So you are right that
   KVM is no longer an issue.

Kind regards,
Daniel


>
> Christophe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ft0mbr6r.fsf%40dja-thinkpad.axtens.net.
