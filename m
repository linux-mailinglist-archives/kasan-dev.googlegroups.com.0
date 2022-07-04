Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBAU4RWLAMGQE5ZOAAYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 56BBB565E79
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 22:30:59 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id r128-20020a1c4486000000b003a2b44d876asf1018485wma.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 13:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656966659; cv=pass;
        d=google.com; s=arc-20160816;
        b=GN7cl3vFSDNPTnVTOw5alJR72ihmyRADl2xNXdV4pnIJVvP5erVX0k+ZBHKU5H1E7l
         NKtPZ06hj1bvjbNkUfAErIEZ0OX709sueGE1Gct9CHS1DUe/hywJb9PVLBoAbZyq9M6u
         Qe4gzdxAzmv3V6m9k0UmXSZgmNcEtbBy76M1NSLwxT8frEpfSO8Lq5MscQl7Ep2gLkSM
         cq1O3Pgj20RV4NhyY7f8WjzB7JtVo/em+JLhVJwo9oSgpPbxWYJmRbrOmahMn04NwR8Q
         xpTV37mfiwHqQLIigTTvqUKu4M3871MiSxpD+R/4hIgD91mKwBPQ9ETd0toYUTeay4pA
         El2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ZCHMk1BKZnVa2Z39b6gMANbAhuVmfwgWOhg7jHPYIbY=;
        b=q1mi7AJmUoHo0KIza910jhxWEf10r3bIEOj9DferBrJEt9zi6Yv6zNyBWDrx4vDjHQ
         bMeQ9JoKTLAmcz6Y2jxgis/6yWyx0j7zqB7MFUtylVv0tI2yq4mRos7VMvCgIogUTXas
         hlbBBfk5LIBW2NTiKZZnKcWr2z+Nwu9W681aG5OcuT+HlyuOhOA8gTTWG5IH6ndCit6y
         RPgps5CZehpQMsUXGF3eEfqBy4UNkBrEDxpOte1IflakhaMWQY9+DHnYO1R7BzJsbhVX
         jGW071UMvK5BXGHD924S6z0alciihHN1F1UAoeeFfC8af2p4Rc2rmk3xOiGq6AZCLbWA
         7OhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=QhD7Fvbc;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCHMk1BKZnVa2Z39b6gMANbAhuVmfwgWOhg7jHPYIbY=;
        b=Na+mgE+Fn0URKmGju6F41ozTzW7DjY6JbKhO0Oo3L02s1Q+PPqYNnk0inHuHtQO96n
         hIyq+RTk/2OZfUEJm1X2WTdo0oODZGlUaimMk3ka9ntCFiEnl7+gUFvFq9goCGK3eNIf
         MEzHK/M+nI1E7MntiKD6IarH5pGDkFR4X8dQIHbQAmzjlMSA/1EQ+9kg9JBNW552+fxm
         oU5Rv7B8jn+0F/+VuCG6k3mDJafjSb7XyeHWtotmVi8yVUXXcwnllNx6yvHgprLPi1Mw
         BQeQrGBaK/YrS5WzKFdjzA5KylWhbCya7IAG/mlHPPhmVxufFRPRPFhh+jPTBUBpsXTp
         gKcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCHMk1BKZnVa2Z39b6gMANbAhuVmfwgWOhg7jHPYIbY=;
        b=vJ+/QPXOx3WBZeGcPZyORkSWS+duwVBY0rW3TOrVCIN9S6/RnUyC1ttkGE/TB94NjM
         C4QNSNbMBeIH0enzOitSQAOVWaF2dOQQydhNot0VmWMVHMn+ghoTD6tkMDcQnqQkbzzw
         DT3brTaOeYN8Ey/wtc1zx1JOm6Yb3qprDkv7fjBvy0kG/n+8xVYNaUYVvDaPA5Pwpu1R
         z1fNHtwHn912i1l/ijXGKDgng/GIiGC3IlVWcNwmk35zDKFLlS2evWPlcc0H7Orb6lhg
         DynvlMr+oM3gOJLHoPLLk8TAX0K2TGVZ3EqRO43X2h4S4FLTDbxY2wrH9ox+Nj0Y+J65
         DQ+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8UpQY/gSGmSeB6qMKNrEbSNDQgZLHex4DWOKJFveuuya8v2R2O
	lHXybYbKMWY4MBvKpAHxwnY=
X-Google-Smtp-Source: AGRyM1vXq/hKZmMWUJURqH3UKU7VDtj5ccFFx76zNy7oAPxquQA5hpOd+Y2Fiar9XJeTTM7EP34cpA==
X-Received: by 2002:a05:6000:1a88:b0:21b:ca70:f622 with SMTP id f8-20020a0560001a8800b0021bca70f622mr29790147wry.330.1656966658795;
        Mon, 04 Jul 2022 13:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls24049777wrz.3.gmail; Mon, 04 Jul 2022
 13:30:57 -0700 (PDT)
X-Received: by 2002:a5d:528e:0:b0:21b:b85b:5873 with SMTP id c14-20020a5d528e000000b0021bb85b5873mr28481286wrv.191.1656966657640;
        Mon, 04 Jul 2022 13:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656966657; cv=none;
        d=google.com; s=arc-20160816;
        b=W3p9Jn09EdnL/D8CWk3FQqrDbSvajcmcWlVf8G3v0/qaHQxmyW13XN2R+UtlsO8q4q
         LW8C0a9PgDGR4yMdjOjPNsTApp2O72/DPbo1XpS+QJQt9BL+4jNK7faDVb1P5h1M3i8r
         Orp3+1zoK4XpBz/8qnWtjmrDgwD0XcNyKUtXbw32DiRWaP+JUkvYqfQrtZW0MYlHY6un
         e3ZZETaXahiXSZIxutX9D6T96zAOxTU9EyVcacj4SN9T7/CN+nkePAavkoJK0URTn6rt
         g9jp4moGB+zigmr/uBEX2toguto4rAILkYK0YqceXXKzOLApxoaw9edlhab3AKs3ttKo
         cVyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8NHXRzMNJPY/okJiN7rxUFnMFdO+6UnOx+ybcPBWQtw=;
        b=NnIqbOy69xsSCvzRXWTidDulhogMDg+gWmn16CG4am31iCVjx2kodoCnJKS9y7DJPk
         G+L6PqTn1mzDZlG595yNggzVQ8m4nb/NiobsuooCyY/0p8l3epQNgKMGwpph0M8iBViK
         pyx4Iu0hGIY3WYT1+DRrKtXc42Mw68TRnV5m5rmSBkLchVtnuyvv7LC1quXIkzXgYQ67
         SFQQp/fz7lVqfe8aey4dVLygM0DMcxuU5duquJyaKZNRq9pqx/0lVnx9tCQSygxifwR2
         nFb23ixC38QNvx5Iel810HZyZMNMB607MI0SlREfLqd8iIxmVLZWWgNGSD0TxLzO+A+W
         H9dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=QhD7Fvbc;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id r68-20020a1c2b47000000b003a19123bf95si388708wmr.2.2022.07.04.13.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 13:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id o25so18410378ejm.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 13:30:57 -0700 (PDT)
X-Received: by 2002:a17:906:9b8b:b0:726:b6da:e570 with SMTP id dd11-20020a1709069b8b00b00726b6dae570mr30068110ejc.365.1656966657181;
        Mon, 04 Jul 2022 13:30:57 -0700 (PDT)
Received: from mail-ed1-f41.google.com (mail-ed1-f41.google.com. [209.85.208.41])
        by smtp.gmail.com with ESMTPSA id q2-20020a170906a08200b006fed93bf71fsm14798103ejy.18.2022.07.04.13.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 13:30:56 -0700 (PDT)
Received: by mail-ed1-f41.google.com with SMTP id r6so1515350edd.7
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 13:30:56 -0700 (PDT)
X-Received: by 2002:a5d:64e7:0:b0:21b:ad72:5401 with SMTP id
 g7-20020a5d64e7000000b0021bad725401mr27424083wri.442.1656966304591; Mon, 04
 Jul 2022 13:25:04 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV> <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV>
In-Reply-To: <YsNFoH0+N+KCt5kg@ZenIV>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 4 Jul 2022 13:24:48 -0700
X-Gmail-Original-Message-ID: <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
Message-ID: <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Al Viro <viro@zeniv.linux.org.uk>
Cc: Alexander Potapenko <glider@google.com>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=QhD7Fvbc;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Mon, Jul 4, 2022 at 12:55 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> You are checking the wrong thing here.  It's really about mount_lock -
> ->d_seq is *not* bumped when we or attach in some namespace.

I think we're talking past each other.

Yes, we need to check the mount sequence lock too, because we're doing
that mount traversal.

But I think we *also* need to check the dentry sequence count, because
the dentry itself could have been moved to another parent.

The two are entirely independent, aren't they?

And the dentry sequence point check should go along with the "we're
now updating the sequence point from the old dentry to the new".

The mount point check should go around the "check dentry mount point",
but it's a separate issue from the whole "we are now jumping to a
different dentry, we should check that the previous dentry hasn't
changed".

                    Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwhp8Npc%2BvMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA%40mail.gmail.com.
