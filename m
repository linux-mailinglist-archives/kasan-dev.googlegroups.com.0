Return-Path: <kasan-dev+bncBD653A6W2MGBBB7X7KKQMGQESRIANCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id F0FBE562FA8
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 11:16:55 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id o21-20020adfa115000000b0021d3f78ebc2sf244504wro.11
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 02:16:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656667015; cv=pass;
        d=google.com; s=arc-20160816;
        b=APvmhpINmoafwsovPgJosdDSO4gcsoOWYJXZcbzu+/GvLvGOSHG2BzkzsnBohDvWZ0
         HnF45ZChDe3a6jgZ5wb0YCSmk/G5dn0tu5fWaoEZM7WWbFVk9CpMCgSZvqdrhu7dKxeV
         0RvhwUcPezVlNDQyfJ/uOG0WENX8DQqQJqaOEyHjESfy44XIyicowwZLncWFPNZtPU8C
         q+awVFEyMcL5LWT/pQtsSaTjNXALkKxVLaO9l3jElBPwMmXqn111WVssNCsY04BRPR8I
         ecWyxXrDf/6MdK7agAu7ZvJjLlQgf4lQROxPP026KwXwrUcb/3dIj+XvrsPxgW6ZPs96
         5tfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=q6YYk0kXYXP2BJlmue3WMnuRoyeNTj34mAti+9gx+x0=;
        b=AfXFCe6+moAZ84Klvbo3I+EElua504dFqB7Lq3KWnvgwVK4JBK6JZOSTTUzKlfMdkK
         iXTL8r9BnlPK6+NJu9X7a0R0wsODzRA7kRJ/xv2cQbmmjfuURYeHJAXr8P+A31X/VePW
         fPRQcRt86jkT0VjGRSmIMIQ4yDeqQG0DcPRqT4SUfAFQ+nWQkvA17Tp5ZIbvJm78slnu
         Qlfbt2s4dcgdbuFDwoGIgPQAl7lFfTxzbx+R2VdaiIFl6n0XRGluI9uL+H2lZkzctrQV
         Z969Po7V3+bjj60BuMG0D21rgq50AVIoAzg2tRdgC4xOMMgNOMgX8xLirxm0AexFkFIB
         LtdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=ADFivvq2;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q6YYk0kXYXP2BJlmue3WMnuRoyeNTj34mAti+9gx+x0=;
        b=Ac7IvHEhgScL24JLH2IMItJJQmlRsR97seNQUY7+TiOqEyFzBJPAOg3VXhqG+ucOO2
         9le9XNlIyJjmJ1e19CO+lIN93Rqy9bh/LPfV3poxOZCHcrfkS4AcFQVudsI4009PTxQ7
         kGP/PQfLKDsjwto6Lqq4lrChQHyZrxvz5VFcOerZotDwMWuKeGxDPPUfXT+qqQRFYG/k
         EoKCRWJJKysTtZhoWcg2tn1Qoq8S92wA0sjy0PJtrH3RBT/dI+5sW5jde5j/wphNp7Ei
         Bkwxg/I9CUIV32aDqxSZc02lY3WhotAbIYap6CTWauhCuQFJm2a/2G4rAMSP530znwN+
         hyNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q6YYk0kXYXP2BJlmue3WMnuRoyeNTj34mAti+9gx+x0=;
        b=wzIOYgseO0YCXiC6mTRzzxtl9RUdJ22fWU4hsi5oMi1w42mjkI+Tf9n+gQoJDG5+08
         Ik41OH/Yp7zQv+lVOQ+hmVOQW6rxEDFE8WYEU32r4GT+DvokrlVRIOwX8SwXyG1gzeFU
         5LKlF6SHoDZgOrthMBTkqNeUXn34UuH/FylzspWTNlyMfKI9SNcMpZufu2wcqA1aamCk
         n+DF4s2GwwxtTnMxA0f7Z3PrFeVoSC5wxZEaU7G5+E2nUMRjfxDfanOCMuAacZ0pbhrL
         Cro7wFEPPHjLAa0ZplWs67Nw1JaXWD0EbbTlB9S3jRJxvhFEzVLv7MuUjWn9D1ktMaqr
         qZyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8AZUgnn677GI8WDwGIsNurmspBITKJQlLEu1ubAw8MTHfx1qGC
	dUp2OQWrIl3E+LtYawbDvXg=
X-Google-Smtp-Source: AGRyM1u/XIEOXHe63iXntupTXAN+M71Y+Fs/CEDdqQiHlKRaw8cvIs7RqI7ZVpnqtHr1afSH0HwEJg==
X-Received: by 2002:a05:6000:15c1:b0:21b:ad5e:2798 with SMTP id y1-20020a05600015c100b0021bad5e2798mr12580264wry.237.1656667015434;
        Fri, 01 Jul 2022 02:16:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:178b:b0:21d:350e:23a6 with SMTP id
 e11-20020a056000178b00b0021d350e23a6ls7903076wrg.2.gmail; Fri, 01 Jul 2022
 02:16:54 -0700 (PDT)
X-Received: by 2002:a5d:4cc4:0:b0:21b:8a19:b8a6 with SMTP id c4-20020a5d4cc4000000b0021b8a19b8a6mr12540072wrt.590.1656667014454;
        Fri, 01 Jul 2022 02:16:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656667014; cv=none;
        d=google.com; s=arc-20160816;
        b=GqBVe5dI02n8LtY+Op7Vra+Cmc6qAeXEauX7NdFnCQfF5kfELyZwFTP35QK1292443
         cVEExOj4U8zFRlQbgxO28xXLh0ui0DQGBMEIFCDOiOa2afRwfMiY1500oyCt0RWeGYdN
         nqZexa/RhIh2Yx2p5VQ+W9QJcLTnddlgEi9jyARfANz4/E42jpCte+RJR6AO9VY2LbY/
         6sP6rlKLrCtjW8uN4fu8vsKU/i89S1+eqdGaSH2g/OBNHJv3mIr492ik6sKKwkJmLBVZ
         Fj5TWdsQdKHPe6QHljuz7zgBrjHdcrZvvSOhE0XTsSn+OOozvgoOC3+wG6HiQfUOWNt9
         I/fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yLWxJPfnToMyz/XrFhdVClGvwJBpxKEAR/Sl0m5JrbU=;
        b=a0G+h9kBDhRrkOMcgy+G08a/3bJVJHbd/l3Gn3U+MoVvS+gnD6ggGgIxxE+g/moQ1N
         UzHXDIpBCpvXqX2RLrY36LWA7wN9ej8Gd4lFErGlSkVsJJjhgmhTC0/bgy8EffRA6tii
         8dx3XHGYI0hg2fij/xKtznBz0DCYFbAEMmKdsTbbjU0h24DOW4hz4aMv672Zk8Sg/XAe
         OaOEXAVCwEEAJPnLDfOKIN9pYiXn5EJJrgzoBRQviUqxoxlELbAifnN3xpPTD6U/lPe2
         v+ZtEYopIUTaVgGzltMLFcX1CLgqmTm3k/TDjo/1IIUCtYCZzkbgMxqB/FnEJWU1Euna
         oeGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=ADFivvq2;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp2.axis.com (smtp2.axis.com. [195.60.68.18])
        by gmr-mx.google.com with ESMTPS id az26-20020a05600c601a00b003a033946319si318541wmb.0.2022.07.01.02.16.54
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Jul 2022 02:16:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) client-ip=195.60.68.18;
Date: Fri, 1 Jul 2022 11:16:53 +0200
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
To: David Gow <davidgow@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Johannes Berg <johannes@sipsolutions.net>, Patricia
 Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, Richard
 Weinberger <richard@nod.at>, "anton.ivanov@cambridgegreys.com"
	<anton.ivanov@cambridgegreys.com>, Brendan Higgins
	<brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, "linux-um@lists.infradead.org"
	<linux-um@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, Daniel
 Latypov <dlatypov@google.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
Message-ID: <20220701091653.GA7009@axis.com>
References: <20220630080834.2742777-1-davidgow@google.com>
 <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
 <20220630125434.GA20153@axis.com>
 <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
 <CABVgOSmxnTc31C-gbmbns+8YOkpppK77sdXLzASZ-hspFYDwfA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABVgOSmxnTc31C-gbmbns+8YOkpppK77sdXLzASZ-hspFYDwfA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=ADFivvq2;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

On Fri, Jul 01, 2022 at 11:08:27AM +0200, David Gow wrote:
> On Thu, Jun 30, 2022 at 9:29 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> > Stack trace collection code might trigger KASAN splats when walking
> > stack frames, but this can be resolved by using unchecked accesses.
> > The main reason to disable instrumentation here is for performance
> > reasons, see the upcoming patch for arm64 [1] for some details.
> >
> > [1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=802b91118d11
> 
> Ah -- that does it! Using READ_ONCE_NOCHECK() in dump_trace() gets rid
> of the nasty recursive KASAN failures we were getting in the tests.
> 
> I'll send out v5 with those files instrumented again.

Hmm, do we really want that?  In the patch Andrey linked to above he
removed the READ_ONCE_NOCHECK() and added the KASAN_SANITIZE on the
corresponding files for arm64, just like it's already the case in this
patch for UML.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701091653.GA7009%40axis.com.
