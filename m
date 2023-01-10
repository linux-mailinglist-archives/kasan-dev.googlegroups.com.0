Return-Path: <kasan-dev+bncBCU73AEHRQBBBLUL62OQMGQEYDEGZWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 588356644F9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 16:35:12 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id l13-20020a056e021c0d00b003034e24b866sf8740280ilh.22
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 07:35:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673364911; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvlqKtXnxlPuecFx3GrJpy4nU7Z1Ybmal6Huu1WeOMZ/pc4GEC7Elc0QDJ5aBN9OIE
         6LUxV/1cccSUaqNY0+kS0XHrgQVGBbSk6aEEE7J9PM8qOCWtOCl2PuDha/aqz1Xy5z9b
         eBp7A0X2hdCrZjvmz+Ls0vW1WD+5TYtVNFh5tRaUKIYnLJwcB/ZRWcWQm+WqoHYJ1bg+
         wO74JGLkfG3/iB/s9onl+H+8njArYA3I7loqBGiW3ns8Wh2mIxWWbwUCgcT9hPN/zfb3
         XcSdt/uoOaocj31Y9voqBRckn9VGPQ5HGYhMqH9w/B3neko8OPDb7v4sRi/L23LoWgxx
         qijQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=OFD1NZT3ZiMNYJs1ZhlWE46Jj736OL4bCXZzqhhv4aU=;
        b=h8v0Rj4wmBpIrehmL1xAIv/DVYve+n2gAW+r3D2yz0/0WLJBFfvt4Z1qn1iWz/ge4z
         PVu0PyK1IKJVGulKQYvK2iJoacMJ2MlMQ+Bn7egMfVi4tpZHWhajZ2TSTQd//20DKIwa
         c8wx12JaJ0NnnbLNyJybBqbXwdyga6wAb2n8OCIAIx5JyNZiKmAWx3+XfwUM8h8PtdL+
         1N6qDTTtCMiQK6OSA11yM1vHaEmxFHw9nwWnyQFpOFuP4frFHlPVtgKY4KiOyVB8JtBw
         3dLbrWhJF8+Fha9bqy/KFnXHhzax4hX1Rdyl08l0auNl6pts3Fv9X1BjmwpuVfQ/p5hb
         ZOQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=qz25=5h=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=qz25=5H=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OFD1NZT3ZiMNYJs1ZhlWE46Jj736OL4bCXZzqhhv4aU=;
        b=mgyTMcO8LZiOO9JDR2yPm7teOklGlua1dHDODReuCsl9dQ5A7UWCWZRj2peqVLup7W
         29jdKx7KCP3sdAMCd3qppjKQx9w0cyDOS6Jyx6ACHHbzbyY4jJYT8el6yRtFFc6xRxRv
         ahaaf1ZmaYCpoWg2KwPT1rObQiFQFK9sBPGiCDSm4mikvtNvlLnzisYGbt4YfC0T2rwm
         bKFMBcoezoTep/yjJRbR7g/8wZ2sAfA9mp6VexHgQ+gTchZGkd6wMJoQnHQXeNxBwzA7
         2j+pt19com0TJ+2HOFAOkcTmIkyQXZrLHGvAU6kqPluMDN33hqKNKnglHYo3JML3LFxU
         1EJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OFD1NZT3ZiMNYJs1ZhlWE46Jj736OL4bCXZzqhhv4aU=;
        b=NXMM6DuaLU4nPF+QIczch2VHQz/1NvCLB0secAoUs733syfGweHPCtw+cwZMFs0cbX
         Wahtsi3F/YF3IhuQoKS98iEEa5lEDymejRyUWrOt99XvFUjH0jG+jerNyjWR7J8QFaBe
         9aQOzFRaI1cMLbioP5G3+2FIbbqAvzA4R+Sj1fiH4/EVAaxrClyifWp96v8Q6KeTuXK/
         y6CgjYvni9hp1uj4tFR/G2TEThTTEMiB3Mmi61mZyVD26kf4H9YsDh5gQmc65Cv84s1n
         UxGOF0TgHSSGZADlJS5aJhjPAX1hq1nmbIxFVL0+bUH2cO/etM5DQRCEGQ7j4MJsTo4j
         tiwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpjhYa1cCjkZ99+55MsU4nY1EMOiJEpBnR6/kA3xOpco546SlG2
	dmQ0Ju/6z7RDGZPLUMDcGwo=
X-Google-Smtp-Source: AMrXdXtUo3ubL8Llvg+ThBi8tiKdbprl67Bjsu+Vvb7qc/4M9b08rcIpnK2/x8jQZyZWqgooRrQ+RA==
X-Received: by 2002:a92:d943:0:b0:30c:21d5:5ce3 with SMTP id l3-20020a92d943000000b0030c21d55ce3mr5652706ilq.176.1673364910938;
        Tue, 10 Jan 2023 07:35:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:ef02:0:b0:6de:dad2:59ac with SMTP id k2-20020a6bef02000000b006dedad259acls1710805ioh.4.-pod-prod-gmail;
 Tue, 10 Jan 2023 07:35:10 -0800 (PST)
X-Received: by 2002:a6b:d60c:0:b0:6eb:68a1:78c with SMTP id w12-20020a6bd60c000000b006eb68a1078cmr46359249ioa.10.1673364910516;
        Tue, 10 Jan 2023 07:35:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673364910; cv=none;
        d=google.com; s=arc-20160816;
        b=sQZ/rKq0MsEIzSrWYKiNf59QSmjWjXYyN8QRhVUvh4f7M0gNmavKm6yrLk0YFLdOc0
         iuJu7oxPnHHRMp+RcV/PrlLi4bY9UXc3m4Cqdbzzso8azP3uW4UkqBzcIMNe4crc/b1D
         479q+4pQ3As2+c07/Zg8JO6vsfQn2iC4oYFqY1c7yQ6iBUp4CPEGtbTfftgCpFpUe8SW
         B4/csfeAzsDedT6z07N/SvRGnnabpjzyb0GcFk1khUWPFvwlpApNCYGJWK0pS8FqPpp0
         mLYuyX5M6f95JyhiCEfQh+G42fFr624R5qvi7Mg+Z5ViqCOkufrXgzW8+imEre+HQP8i
         CW5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=K/skfp/aMEhFUFPf1QhxF/xUvXlBDvhs1SLq6EdYTR8=;
        b=H0c8x4Lz0gXVEjCASRRXXiifx5a3GX72ez3fKmGZxUEv+/k7lA5dFDOfq27SR/regD
         HYyr42PqmkLifgLbwa78gL5YYnMtzfwbYqhkek2W574jcIBfTyPFvDvj8c9YkhzyxI4n
         5Ca8Hi5/u9iYMdfFn7xzcIZkBtPeoezJhJL16fyqY40t1fJkygNMx6/MvJmvNGkzs1G4
         hzM0UI5gf81n1BXBDeLE6qmndDnPpxMXf6akZhhTBmHPBBB2R95DM+ZQeMh/B5urhwKd
         7yMFVjYxAyuJZ6qjB+EAhXrHiEwVakNdTqjgyZe2ggkuxzwLncfMD08jH1rqwmPYWXh9
         SVfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=qz25=5h=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=qz25=5H=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id n13-20020a056e0208ed00b0030d885207eesi969737ilt.3.2023.01.10.07.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 07:35:10 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=qz25=5h=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 19D4E61799;
	Tue, 10 Jan 2023 15:35:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E4C42C433F0;
	Tue, 10 Jan 2023 15:35:05 +0000 (UTC)
Date: Tue, 10 Jan 2023 10:35:04 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Christoph Hellwig <hch@lst.de>
Cc: Eric Dumazet <edumazet@google.com>, Alexander Potapenko
 <glider@google.com>, Dan Williams <dan.j.williams@intel.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Andrey
 Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd
 Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, Ilya
 Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
 <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
 <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, Matthew
 Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka
 Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr
 Mladek <pmladek@suse.com>, Thomas Gleixner <tglx@linutronix.de>, Vasily
 Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch
 <linux-arch@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase
 MAX_STRUCT_PAGE_SIZE
Message-ID: <20230110103504.6ee5f783@gandalf.local.home>
In-Reply-To: <20230110085549.GA12778@lst.de>
References: <20220701142310.2188015-11-glider@google.com>
	<CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
	<CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
	<63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
	<CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
	<63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
	<Y7z99mf1M5edxV4A@kroah.com>
	<63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch>
	<CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com>
	<CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p=ygAH7QocyVh+DQ@mail.gmail.com>
	<20230110085549.GA12778@lst.de>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=qz25=5h=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=qz25=5H=goodmis.org=rostedt@kernel.org"
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

On Tue, 10 Jan 2023 09:55:49 +0100
Christoph Hellwig <hch@lst.de> wrote:

> Folks, can you please trim your quotes to what is relevant?  I've not
> actually beeng finding any relevant information in the last three mails
> before giving up the scrolling after multiple pages.

If I don't see a response after three scrolls, I ignore the email.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230110103504.6ee5f783%40gandalf.local.home.
