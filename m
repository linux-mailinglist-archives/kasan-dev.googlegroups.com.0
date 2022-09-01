Return-Path: <kasan-dev+bncBCKMR55PYIGBB4UFYKMAMGQEW6OIKLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C25825A93C6
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 12:01:23 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id bp7-20020a056512158700b00492d0a98377sf4269961lfb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 03:01:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662026483; cv=pass;
        d=google.com; s=arc-20160816;
        b=sfxXBygMbHtcbOvFbA21DX5oxnieWSKhk8fFvjizPdheNPf+dnMDTRot/bmIAPfcI9
         d/f73V1FouWIqPq700TPIaJby7RP80cq9IzD0daCHpsLU1ntx59W8/mapWN46tba/7Zm
         mJkn1fisgGLHU35FK4ESoqcSOLxBxeY5bdpz9nH3xDMiAhYw+YDgTOAtyfyiDGl/E8B3
         V7egWpCADvi+6xE/FagXeNEgYiLMfVX//4mpDIMG4T046dsAVtfMJJmUCoQdcAzM5ydT
         pABg3UsKFQidmuWN4jYiCfJcoWyAlGXY8SwM9dxjtrcFjzNukqlphhQ8H/Zi7AW2c0fF
         sniA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=sTHFHA3yNTqoIQZVJatIVLReGKMULJSiTw+hr2UV4Ys=;
        b=vNM3odNC6to8xPe8x4x1B1GCRJdIAYOMPepbL2rPLGvm0mgqJPsu7NdXY47eh43ykB
         +BM+NFexOUn3/4g8TtKDpExzfGE3QOJ/58+fBnBDGcwOcZHz0u+6WKa5RANhbzj/G4Ws
         jhaqElGGP8eF3FX3Hza5KICoFj6K7xgDl/ttKBNkO+58qgHl0ng0l+mCoWBn9+6qCfYg
         S1wbpxBr4GmzZmmcVBFCG83JbjeAgf7ItZ20NB5L4v0lenJ+yiepBClqmojV9by6t58z
         NA5x3+Zi5CrnzOJyC8Q1+4TEJVNgS6XhGNQ/dcOXAmXnCED7ctu4/s2TU1vUsLFMD2Lu
         78zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=qKa4+Slj;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=sTHFHA3yNTqoIQZVJatIVLReGKMULJSiTw+hr2UV4Ys=;
        b=p8poGSTzE1LUqlBQ/w2OvEmA23276Gi8t9n+xLpr0m/7yaNnhXSp+GRtk0gIGhXyFc
         AG9sQmXpCWVsFoOOlHJCMiCDRxmPwp4pc7vIwIFRJVAS2KwmYBpuQ0rRfyI74bZS18J7
         UWFx1WtM4wkpdpFxley28VF1plAkw7ePvqF8cypbdwsM+RfUJ7hTtOv/qiojzv4EY73M
         cQTsd15liOv00IaWU4uGheff32PsYuh8HfjV/E1lfp0JLXUPxCJnDiaql5Ib+th8QHyh
         BwDeFgO0woF02KqcTRLBvI0c4sPAmgioyVkF7gJpI1het2uFePxfmWOVenkFIfbMYFTZ
         LQUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=sTHFHA3yNTqoIQZVJatIVLReGKMULJSiTw+hr2UV4Ys=;
        b=vumNM/icslT3c2G292nv18itGNocmL5/Lo1F7supx+GTkYkrXvqibZgCRWx1ZCbDkQ
         NnDaIe0ArU3JHZqoEqVlxC5yCF5onFPQ710rsJEmBBH4eQebICUuYwqjArRe12Se1jv9
         i1EAGyRuwx8XqcjW/71MoiBWu+cNpEdOwh5F4hRMzFTxKSppZvqwI2cwmOJadA6uvPuh
         /gIWG58W6tbvy3nB5vjvbTSsuLSzuqLE+cu13wLxyNMcVm9Ode9UQgW2URONj48hndMP
         MCxU4KmbA9wB2u75+kdj00m+DCcFCtPd7JPPcisCu+e1af/qMaNs/e8O2xjJnr96VWbl
         Nt4g==
X-Gm-Message-State: ACgBeo2m9rxlZFvjqxceg4ypV0PBih1AGZVS7+yeXo95cOzJnJylEh89
	GtrjQXsyZexSuZdkGZ2n2d4=
X-Google-Smtp-Source: AA6agR5haQ7dhskhRY6CoxsHc8CSLTWxHlnTvMQQf/Z/a2M4qZTJimhE4JqmF+ux8ucW+6dS7RmOew==
X-Received: by 2002:a2e:a788:0:b0:268:d10f:355 with SMTP id c8-20020a2ea788000000b00268d10f0355mr93059ljf.159.1662026483044;
        Thu, 01 Sep 2022 03:01:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2016:b0:48b:2227:7787 with SMTP id
 a22-20020a056512201600b0048b22277787ls1063213lfb.3.-pod-prod-gmail; Thu, 01
 Sep 2022 03:01:21 -0700 (PDT)
X-Received: by 2002:a05:6512:b81:b0:494:78cc:ca9c with SMTP id b1-20020a0565120b8100b0049478ccca9cmr3617608lfv.564.1662026481495;
        Thu, 01 Sep 2022 03:01:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662026481; cv=none;
        d=google.com; s=arc-20160816;
        b=VNXhel1IoNu2y1cvBBCVX7qW/2XG81N8eNiBfWwtWazj10X8PhwPDmvADR0g+kt868
         Hh955Q4DgTEblBMnfPc46afwPqNId9o0iAAp10zRJGgoXWHKd9DOb2J0p21lnoP0v6Dr
         25dhCauTos9wyNgAp+cif9gORV91Wrr8UpcCyNOi+ryUHhFklRhYpwz1spriKwWLn5gj
         O0LP83NFKji1guiDe/CHu+8L5SGyVJh+/zjz3iH69/OrbOSs/x+irWrnQ8mHM07HE2Ie
         JVO8GjwmkPqU3RqSuPG0Esjltph6ZlufLfSYpioZe2DbLD0QkKtZawArTicfrykiexqy
         Bo0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pUkZJWp2nQ4dbOBqWBuaF5RJwLtyXngvDW9UF32VZDE=;
        b=t4n8Te/hxJp98XiU+jNpAcb6q/Txh8e7rgCZtXAfHZ+XIiYSbkOmPn/qtnKNtnW5rz
         RPk+EPumkwp5B8ZAsYNY2dpLRpQPlNrkApE1xaes0xRBHA4B6cZ0QZDaoPEF/gxqNSrC
         Ww6vum//J1ysr1rUYcenXaIKwYYzLg3d2Civi9RApTFyr8AQz6riTx0fZ7hIe6U7l1QI
         6yM6AEakqthFaPkUs6mt5x0Q1hQcAcnf7YPZw0dSFOo/Y7A4M9fTJWNl52dBzmfbEqAs
         KgWasYonRjMVgyGwi9ZOUWpfodlaBsi6L3o/WtKQQf+14ienbbUmHouDb2b7+8sCpvAM
         0X6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=qKa4+Slj;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id k22-20020a05651c10b600b0025e5351aa9bsi399718ljn.7.2022.09.01.03.01.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 03:01:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id C7512219F1;
	Thu,  1 Sep 2022 10:01:20 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A4B7D13A89;
	Thu,  1 Sep 2022 10:01:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id m67wJfCCEGMyXwAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 01 Sep 2022 10:01:20 +0000
Date: Thu, 1 Sep 2022 12:01:19 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Vlastimil Babka <vbabka@suse.cz>,
	Eric Dumazet <edumazet@google.com>,
	Waiman Long <longman@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
Message-ID: <YxCC7zoc3wX3ieMR@dhcp22.suse.cz>
References: <20220901044249.4624-1-osalvador@suse.de>
 <20220901044249.4624-2-osalvador@suse.de>
 <YxBsWu36eqUw03Dy@elver.google.com>
 <YxBvcDFSsLqn3i87@dhcp22.suse.cz>
 <CANpmjNNjkgibnBcp7ZOWGC5CcBJ=acgrRKo0cwZG0xOB5OCpLw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNjkgibnBcp7ZOWGC5CcBJ=acgrRKo0cwZG0xOB5OCpLw@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=qKa4+Slj;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Thu 01-09-22 11:18:19, Marco Elver wrote:
> On Thu, 1 Sept 2022 at 10:38, Michal Hocko <mhocko@suse.com> wrote:
> >
> > On Thu 01-09-22 10:24:58, Marco Elver wrote:
> > > On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
> > [...]
> > > > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > > > index 5ca0d086ef4a..aeb59d3557e2 100644
> > > > --- a/lib/stackdepot.c
> > > > +++ b/lib/stackdepot.c
> > > > @@ -63,6 +63,7 @@ struct stack_record {
> > > >     u32 hash;                       /* Hash in the hastable */
> > > >     u32 size;                       /* Number of frames in the stack */
> > > >     union handle_parts handle;
> > > > +   refcount_t count;               /* Number of the same repeated stacks */
> > >
> > > This will increase stack_record size for every user, even if they don't
> > > care about the count.
> >
> > Couldn't this be used for garbage collection?
> 
> Only if we can precisely figure out at which point a stack is no
> longer going to be needed.
> 
> But more realistically, stack depot was designed to be simple. Right
> now it can allocate new stacks (from an internal pool), but giving the
> memory back to that pool isn't supported. Doing garbage collection
> would effectively be a redesign of stack depot.

Fair argument. 

> And for the purpose
> for which stack depot was designed (debugging tools), memory has never
> been an issue (note that stack depot also has a fixed upper bound on
> memory usage).

Is the increased size really a blocker then? I see how it sucks to
maintain a counter when it is not used by anything but page_owner but
storing that counte externally would just add more complexity AFAICS
(more allocations, more tracking etc.).

Maybe the counter can be conditional on the page_owner which would add
some complexity as well (variable size structure) but at least the
external allocation stuff could be avoided.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxCC7zoc3wX3ieMR%40dhcp22.suse.cz.
