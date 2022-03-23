Return-Path: <kasan-dev+bncBCM2HQW3QYHRBMHR5SIQMGQE6ZUCLNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 646234E54EF
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 16:11:45 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id x26-20020a056512131a00b00448708fa822sf711188lfu.6
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 08:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648048305; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPFp0S3q73Z9x2Etb8ZV849JB/uSxtflvpUQcrjZb42/tnRY0kbEb5DYAYEgk3ji2W
         SCM0Wplu1RVpSfd5BkEd280itpX0il+2s54JzIYXCGmfH+mynNKuGrZh39jJbYNGyXv/
         gxfBnANC5HKWakCNAGTSYvmzYMH5Tt2kP2cJ5j0QUS3XcWKoXaTWCdXdpZH0Y17T+uuQ
         ITtaqxmVXxUzepR+bbIU15QYW/xeRIqdxhKkrQVWoDrSHnr0jBzOp2RlwnyLPn/NuQSi
         Ut+tsb3XZbgsPGoIkQLMAY66TYCVbBVR/aMVigxQd+2DVA0yFu6fRG/a6baM3HEUQ1jt
         YCJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0F6QpVzyBXTzFppviuIcJTmPBapy3pawUDmufyRYMvc=;
        b=WcTXZ+g9FlWdkMEFM4RW3zGygZpyvnmj63d2RZKny3K3hH+oa8eLSLVVqSR5e1vSiD
         2nKywT+ZAWVpP4TZ7nqqzw0xxH8C68gTeRLWpLzG6zwpJxpZjVowT4MDrKnTigZGcq2C
         1+tcCsFlVAm2L5JhV5FT2hpoeM9ZUZwLCGEyiJMIRqY3RBuu+BiadHCrxgkDM71fbGzd
         3mPJl0tI9zgYi/Y2XjslAy2qnmgPylU0OC0yDwKrATamsDLSqS0ezj9+Fez39Ys/Lb6W
         doWslO2820I9nTdbZMp1BFBUIDxeZJTg7rNb+I2+t4Gif6Sh4ITabD8cDdOzbjhQligz
         bm4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="r/jOVR6M";
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0F6QpVzyBXTzFppviuIcJTmPBapy3pawUDmufyRYMvc=;
        b=PwB737CfSQFT5taQBVGXC1Lq6Wl1xhkS0z8ZX7OP4Ns1ae1juOhH4fCGfit1v48E7U
         C8RC6yhnCkRphQ82BvuIkO17SD2onlCIF3tdxBCe5YkCVI7aa8pGtXqdnqFaDQR5QNap
         m9RBN2jB+TJCTuwbI0BwAJ4N0nNmxfRsCzINKOtH4bw3Zi6B0GnjljDroWePwwGsbyNR
         TBFad2pPKim3hnf/e0E5Eb+8WY6g3veMG9E9BYdzvK6g99OcKZqOAh/O88d5+Dy/zFSw
         Wf23a4YwYlY13VCJ3zC//dF80Zm8zsFmf+YAGLd0fDPEDgZ5yYwA9s7G5qv9ghaM1dmw
         QxlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0F6QpVzyBXTzFppviuIcJTmPBapy3pawUDmufyRYMvc=;
        b=EGTj15noGxpiABgHZBrZLIR8fynYrYfAeKj7nz89v2ZKlVI5Nv6BMFH1Q+v9ouWQgf
         e0581IgdEHVSXHJcApw3CuW4DGgRbYjPMNK6Ti8Iu41pIW5soj0/Lt1tuQMQkZUWZmxU
         JRZXqpz7uf5VNgtE3YokqJLNQ92jatpp2IgEy54NUkEQmwjdiIyt4dm7Zso+Uwg1MvlO
         CdKxRFJ2sFKfLBGvDTe3XdYsvjmFSBPgi5wyW9XTR/eJlGBBPSen9eIltF9gKI4wAbYS
         fzUF2x7xeDlwhZmQUpTXB0Rv+xwNXuD/yRdHGBBf9KWyLb31E8u2mP2L3MOTr3RNY2e4
         Wl1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305oR/IJFRfj5TSVHekuCgjHrFI+JA+eUhwUJjVNUT4XK2fEl0Q
	/RCAA2toNWEe2Xs0fVvtEG0=
X-Google-Smtp-Source: ABdhPJwTsDFvHm2M7bEAejl/RQ1PqNVCDssjhBb+rovCgJxNMO2BYCRk5KVUlwNHA7RJuTuQzsI5pw==
X-Received: by 2002:a2e:a236:0:b0:249:2a4b:16f5 with SMTP id i22-20020a2ea236000000b002492a4b16f5mr357443ljm.384.1648048304834;
        Wed, 23 Mar 2022 08:11:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:880d:0:b0:249:6a0e:ce7 with SMTP id x13-20020a2e880d000000b002496a0e0ce7ls2944355ljh.5.gmail;
 Wed, 23 Mar 2022 08:11:43 -0700 (PDT)
X-Received: by 2002:a2e:8496:0:b0:249:7dbc:d81b with SMTP id b22-20020a2e8496000000b002497dbcd81bmr361766ljh.332.1648048303883;
        Wed, 23 Mar 2022 08:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648048303; cv=none;
        d=google.com; s=arc-20160816;
        b=E5SKTsFOa+EvAeG3XYd40KXL8UvyYpfMuec0vB5naibeoRM/QxFFa23igIvmtLDPb+
         5YlWdb5Dz7+efewdHxeY+NnTwKS7V6MGeSOFZ3yvPMrvNTweJIjEZXX7OaYLT/mivKtW
         kLm1k3jJupSvq4isyAHR2QPDKDEyMsc7+YLapLEQ7UtaCLp46vniM44odotsiK1Uu7u7
         Cn0/exBq/HkywHOwaVwZCQ4t996ul4XcWdPmGzipx7R5ohRTOYvXe0ELv+b/TD1772Vc
         tJrGVgiKPpJ7dCikU1i4ABm0qfLjYxm9eGvnySD92F0aVZsbVuoyRz8fyARmX1Ykawg+
         aY0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mbYKYLyioxmza+e6kvwBLRa+wBIGtShUFd+o0R6xiJk=;
        b=CwVrZNnyNpeF1r+6iIpgb9p7Bpyzfa+73rqn9/j8Pm2x9cy/JmZzYTD8luGLGbfr7c
         bvmMoneSOZ0hERGPV9W2lTF0Uzcuf47nTfqogENoTtqKRPMQjXnihu5NmI+fEzyCjfpK
         sjH3PHDUYDxuhmdK1mFP3EuqtT6PR2+Fx4ITj3PIQaKxIMYjrKcsvbkB+LifqUuEndQ6
         P5O4cu8i4GVQ8kAqfM8UhRUGAUmDznzcBokPABx+eMGQKYG/mqPW6l6lMKoj2QSkcmhb
         425DeQo/VRXf7uaZg17H2fIot2nabgLd2VewHFrAYRerUuiJJm7GvK1/OGyntHKVUQSV
         B3Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="r/jOVR6M";
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id d24-20020a0565123d1800b0044a28635947si17458lfv.6.2022.03.23.08.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Mar 2022 08:11:43 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nX2e5-00Ccu6-3N; Wed, 23 Mar 2022 15:11:33 +0000
Date: Wed, 23 Mar 2022 15:11:33 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON
 with HW_TAGS
Message-ID: <Yjs4pSGr/h9ChCQ3@casper.infradead.org>
References: <cover.1643047180.git.andreyknvl@google.com>
 <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
 <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
 <YjsaaQo5pqmGdBaY@linutronix.de>
 <CA+fCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g@mail.gmail.com>
 <b4d598ac-006e-1de3-21e5-8afa6aea0538@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b4d598ac-006e-1de3-21e5-8afa6aea0538@suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="r/jOVR6M";
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Wed, Mar 23, 2022 at 02:57:30PM +0100, Vlastimil Babka wrote:
> I guess it's the simplest thing to do for now. For the future we can
> still improve and handle all combinations of kasan/lockdep to occupy as
> few bits as possible and set the shift/mask appropriately. Or consider
> first if it's necessary anyway. I don't know if we really expect at any
> point to start triggering the BUILD_BUG_ON() in radix_tree_init() and
> then only some combination of configs will reduce the flags to a number
> that works. Or is there anything else that depends on __GFP_BITS_SHIFT?

The correct long-term solution is to transition all the radix tree
users to the XArray, which has the GFP flags specified in the correct
place (ie at the call site) instead of embedding the GFP flags in the
data structure.

I've paused work on that while I work on folios; by my count there are
about 60 users left.  What I really need is something which prevents
any attempt to add new users.  Maybe that's a job for checkpatch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yjs4pSGr/h9ChCQ3%40casper.infradead.org.
