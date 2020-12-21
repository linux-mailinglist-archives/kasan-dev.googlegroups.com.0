Return-Path: <kasan-dev+bncBDO2DTMYRIMBBHMLQT7QKGQEDMR7DRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4499D2E0188
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 21:29:19 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id q12sf6298012plr.9
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 12:29:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608582558; cv=pass;
        d=google.com; s=arc-20160816;
        b=i3R2HjdPVYFUyU+xAyRA/opjcYSyNaiLEyfH1cXD3WVoFhtxM6g+4lhCY7ks9Q3rma
         TQ3BQz/ilXJuSUeEHfNUK0UucOge+dW175xmTsVVm7PlUEDfjMyTFlPZeo15npQ54eFN
         HgqYrsEGCMJ25I4wjGdg1zd0aWDTJI5cCdEdoxa6PU1o/dw+k2RdI9a67mv6cjpO0k28
         QZu7yrp8b3yd3D9HytvRInplv6QwZ+xvDXWSlRVo1JlcKyEZ0+hPnJTkPpUTLsr7PphU
         ECMKoH9iaoubYHkWQflhoO8Wt9Io+7Dt6wPzssEMwkSablxOzPJ2Xu4tivw5Nb8zqB1H
         bbww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7M1nw1UwjeAXbs6ngI3kNNTKUS0hU4rHsR9ryfkyoFE=;
        b=Wlvm1nh2VcKnYP7BT627GEE2040+236L7E53Rz8wiqxVYmkM3/NIPZEkXP4/Q7A/j8
         4ttEBw3Dgt0YdfKTEhwFZ0+6EFYBOk+JETpujxumQNYsySVTkFwhNH24GWwEOnZhPjyp
         jPBFMP4BnuVaO8Bi3XHXHDee09rZobtnzIZOwIUfOmx+R96+cr4Oo0WdA8jo04113sDp
         oN7jofc5Z+0N6xWsDF329Y3qYkzDZ+I4iigOUBQDHdbCcz0LrbsDv89/YPObFsvacO+v
         0A+oNFlkQc/95+CS2pGkBFbyDkPyBkw7c94XiT1+Mmjg5Y1bcuPPGQC3TkcjqQxs6mPe
         RBeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QcYIhsyz;
       spf=pass (google.com: domain of minchan.kim@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=minchan.kim@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7M1nw1UwjeAXbs6ngI3kNNTKUS0hU4rHsR9ryfkyoFE=;
        b=YLiiZgPQBz7qFi79qcocEcQc/Rvmo3lv84BFMi+WTUibVRDfU3PEa6kLhzae02UY+T
         FyjmY/r7uoR4gLA/lsmRYeCxz6balY93g7m1OWzSa8a0+9ZwV18xDZfQ18CwglDql2vj
         p3Zq0q++clE550TOYNZNHLYavZ4DrWLlbGLmuodm5B3xorl+JLS4yxkubmNCWpWzClSO
         i9FACkgkILg8XxRlsJmSP15LFiFRA0yuUJvADGJEF4xhPkdNo6k1WAC93oLKiwupHWCl
         4PlaW+E5m+stsxrt06WUklcIRd/U7Wyanj11+TQZljBTGhalI6KOn/RnRvaLCwbrOFpJ
         3Tsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7M1nw1UwjeAXbs6ngI3kNNTKUS0hU4rHsR9ryfkyoFE=;
        b=A7oFLAaK1NrZSGx3xQL6n4/ozX2YMgmJKzwSJCRRxRZ3EdNAGZZI35CXUwwt3VyTWv
         gLPmPvi9y9GVF310WGjEPLFZNh1Lgir5SYLs32LhCZEvGZmMosEKvzpMe/NyomjrubBz
         XUvtM4bWQOJ55G/PTpWVXD9pKPGAY4Mh21ejRyKWAXpRJUThPYakgHsJmmpe6TT4atiF
         YiTpCLRaqAhYYDWCDsmu6r959A5I6DFRr+77NNRwRmD14z7641esPwHPkv0EIHrnrZlF
         mw5xKrFJji1ZMoXHHGnGd2UT4N35wmSWcJOy90wNhsZBBksMHRvmyqy1zaCf4S9wR6Br
         afbA==
X-Gm-Message-State: AOAM533rT0vyNDzOVBjunCwXUs+QA8i8krDtWt8n44Ln6TebWeGpo/As
	fReZjMF8ZPYjqxyc2Qat+Xs=
X-Google-Smtp-Source: ABdhPJzD78vuVQVPDe62P5euh5HgvKF0+Wj9regX7thOaYN9wMzYsm56iVoBU1lec1Pf0hPA0HrHSA==
X-Received: by 2002:aa7:904b:0:b029:19e:c8a5:5154 with SMTP id n11-20020aa7904b0000b029019ec8a55154mr17200201pfo.41.1608582557802;
        Mon, 21 Dec 2020 12:29:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b893:: with SMTP id o19ls9662243pjr.2.canary-gmail;
 Mon, 21 Dec 2020 12:29:17 -0800 (PST)
X-Received: by 2002:a17:90a:1f01:: with SMTP id u1mr18648111pja.62.1608582557121;
        Mon, 21 Dec 2020 12:29:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608582557; cv=none;
        d=google.com; s=arc-20160816;
        b=azeNhEFfVlClcao/YqDFQ9+0F1+Max6dGiUOll8o45hzsNcEfBGOlJAqPeg+xxmxLh
         wmYXmloO01H3Q+L04hHPnUifJMxnP7IdzOrQVRF0UZ/xf1Gw10AgkrpN9uOX3FADYbQm
         cPgySycJlU8cfoikTZDDDKsUk2wGlRwoqS+f+ebDSxygHLS8SQGITp4/dN9xzGLYTrXe
         Kp7xe9um/ZiIJ6ApRqyG7iHPHFlqA/kjvGI/B1BYcpAKHWHuiXyOLD2nS7GFomq7HC2d
         uTATq8wgqzryKjLrwN+SBuD0rtzGFwVmaIch7Yx6Th+6KxYya2AcZiythaOZBEKG3Ha9
         RVSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=jxLW2pdUWD7RzC62LfDYxo1HOe4nc7nIXlrDQklPFuU=;
        b=NZ0x9rwrUzLB+QXTTAepC10guy2WaLsVMphr+YzIbSwsx42MzOOHLZKzWLTfuDFJR9
         /npztdIFAn/8j/rAEmT44SmDDrYFVpTanpl8EFtUgq+iq1e3aZ+BengOjrE3FYeprJWw
         9tMbpzIoyz4Y2WmltRTtCmjyUY/YnIfWfTkaytRiEzhm7dl+89AJ8vGaUuuP7PKW3Ymp
         dlVMBrmAFcHoSGybGFJ/v5hICAKNTzoJa+beUOYp/iN8dL4GQrFYduQROMBeRKdckFAB
         nDpScCTus/ePeWqGlWVUyNcNsoCn504KbJ+Bgur5W8cOqlHGxxK7EUq+66NGRWhqJRP/
         2v6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QcYIhsyz;
       spf=pass (google.com: domain of minchan.kim@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=minchan.kim@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id f14si976022pfe.3.2020.12.21.12.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Dec 2020 12:29:17 -0800 (PST)
Received-SPF: pass (google.com: domain of minchan.kim@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id 4so6201827plk.5
        for <kasan-dev@googlegroups.com>; Mon, 21 Dec 2020 12:29:17 -0800 (PST)
X-Received: by 2002:a17:90a:b110:: with SMTP id z16mr18441668pjq.167.1608582556811;
        Mon, 21 Dec 2020 12:29:16 -0800 (PST)
Received: from google.com ([2620:15c:211:201:7220:84ff:fe09:5e58])
        by smtp.gmail.com with ESMTPSA id f29sm17695810pfk.32.2020.12.21.12.29.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Dec 2020 12:29:15 -0800 (PST)
Sender: Minchan Kim <minchan.kim@gmail.com>
Date: Mon, 21 Dec 2020 12:29:13 -0800
From: Minchan Kim <minchan@kernel.org>
To: Alexander Potapenko <glider@google.com>
Cc: Vijayanand Jitta <vjitta@codeaurora.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	dan.j.williams@intel.com, broonie@kernel.org,
	Masami Hiramatsu <mhiramat@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com,
	ylal@codeaurora.org, vinmenon@codeaurora.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
Message-ID: <X+EFmQz6JKfpdswG@google.com>
References: <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org>
 <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org>
 <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
 <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
 <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org>
 <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
 <CAG_fn=VjejHtY8=cuuFkixpXd6A6q1C==6RAaUC3Vb5_4hZkcg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=VjejHtY8=cuuFkixpXd6A6q1C==6RAaUC3Vb5_4hZkcg@mail.gmail.com>
X-Original-Sender: minchan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=QcYIhsyz;       spf=pass
 (google.com: domain of minchan.kim@gmail.com designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=minchan.kim@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Dec 21, 2020 at 04:04:09PM +0100, Alexander Potapenko wrote:
> On Mon, Dec 21, 2020 at 12:15 PM Vijayanand Jitta <vjitta@codeaurora.org> wrote:
> >
> >
> >
> > On 12/18/2020 2:10 PM, Vijayanand Jitta wrote:
> > >
> > >
> > > On 12/17/2020 4:24 PM, Alexander Potapenko wrote:
> > >>>> Can you provide an example of a use case in which the user wants to
> > >>>> use the stack depot of a smaller size without disabling it completely,
> > >>>> and that size cannot be configured statically?
> > >>>> As far as I understand, for the page owner example you gave it's
> > >>>> sufficient to provide a switch that can disable the stack depot if
> > >>>> page_owner=off.
> > >>>>
> > >>> There are two use cases here,
> > >>>
> > >>> 1. We don't want to consume memory when page_owner=off ,boolean flag
> > >>> would work here.
> > >>>
> > >>> 2. We would want to enable page_owner on low ram devices but we don't
> > >>> want stack depot to consume 8 MB of memory, so for this case we would
> > >>> need a configurable stack_hash_size so that we can still use page_owner
> > >>> with lower memory consumption.
> > >>>
> > >>> So, a configurable stack_hash_size would work for both these use cases,
> > >>> we can set it to '0' for first case and set the required size for the
> > >>> second case.
> > >>
> > >> Will a combined solution with a boolean boot-time flag and a static
> > >> CONFIG_STACKDEPOT_HASH_SIZE work for these cases?
> > >> I suppose low-memory devices have a separate kernel config anyway?
> > >>
> > >
> > > Yes, the combined solution will also work but i think having a single
> > > run time config is simpler instead of having two things to configure.
> > >
> >
> > To add to it we started of with a CONFIG first, after the comments from
> > Minchan (https://lkml.org/lkml/2020/11/3/2121) we decided to switch to
> > run time param.
> >
> > Quoting Minchan's comments below:
> >
> > "
> > 1. When we don't use page_owner, we don't want to waste any memory for
> > stackdepot hash array.
> > 2. When we use page_owner, we want to have reasonable stackdeport hash array
> >
> > With this configuration, it couldn't meet since we always need to
> > reserve a reasonable size for the array.
> > Can't we make the hash size as a kernel parameter?
> > With it, we could use it like this.
> >
> > 1. page_owner=off, stackdepot_stack_hash=0 -> no more wasted memory
> > when we don't use page_owner
> > 2. page_owner=on, stackdepot_stack_hash=8M -> reasonable hash size
> > when we use page_owner.
> > "
> 
> Minchan, what do you think about making the hash size itself a static
> parameter, while letting the user disable stackdepot completely at
> runtime?
> As noted before, I am concerned that moving a low-level configuration
> bit (which essentially means "save 8Mb - (1 << stackdepot_stack_hash)
> of static memory") to the boot parameters will be unused by most
> admins and may actually trick them into thinking they reduce the
> overall stackdepot memory consumption noticeably.
> I also suppose device vendors may prefer setting a fixed (maybe
> non-default) hash size for low-memory devices rather than letting the
> admins increase it.

I am totally fine if we could save the static memory alloation when
the page_owner is not used.

IOW, page_owner=disable, stackdepot=disable will not consume the 8M
memory.
When we want to use page_owner, we could just do like this

	page_owner=enable, stackdepot=enable

(Maybe we need something to make warning if stackdepot is disabled
but someone want to use it, for example, KASAN?)

Vijayanand, If we could work this this, should we still need the
config option, then? 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X%2BEFmQz6JKfpdswG%40google.com.
