Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WH3OVQMGQEUHKKKGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0562380C673
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:27:00 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-1fb1f23d1bcsf7610752fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:26:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702290418; cv=pass;
        d=google.com; s=arc-20160816;
        b=NsY+Tt34jHeq7kvSiY2PAkZeSHOZpQfmVu6Agg8j/0Ih25vhRXF2U+U/t9X338fyaY
         eM0IacfvsZMKeJ3wi34FCN0ALrHke0wf2LhFf7UWSMSX/1WHqZTG5aRp7yfihv9iU0jr
         EVbzKdqNyiJUfs9G+5a/cVHjK0cDYHGD/j884eWmRhYN9h1iYPjBhtT5FKU737V4YeH6
         3IbsMs6tHVaHAESifMtsXErOjPcQ7n3mkTjwPlhBpc36xsNh8by9rOOOS3FRGeWU0m+x
         SNiAyZsOS9vxukDfsAzRi3cFOGvcQhdxkvro9qS5w+h6q1xu6gZvndh7ELRt5zPmrV+f
         S4rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+DaqSXlUgA+L4tjVrcCcnAkTqmKztIS3NdZ/hayqav4=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=korwriztUlYKObym86lJyBFBsFb+nQIeVKekOrfmtXANGoqJcQSNMK0pNthRrVDTTe
         3GI8MWE67Em/3axhYh2uWq9L2CoV4KB6fSU7i51T/ZZ39FF83EB8No67n/MiUIg2mOha
         ZxiyDS71aFebce0DbN0u16Z2lDtQ8qQB6hTk8eM1rCWHA9XvQOyfez8g26JHMPCzXd/k
         V6vmsoYx0ZgcFvRZEtm/9zJWkyUkWkSZHMuYlEZRMA7aWFS2vj+Wey+Ukg7A5E4ToLkI
         QeaFYLTJaRjdYlIALU+iArVBVJaHYQszztyrwxA+BzI156NJSsZmlxL7XmSL9UJGNPnP
         auqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=K3seUkTp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702290418; x=1702895218; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+DaqSXlUgA+L4tjVrcCcnAkTqmKztIS3NdZ/hayqav4=;
        b=blpRnYQeQYViv3nngovv/7AgLCM3Dw9LIE+laZUoi2pf8oqDFiTNBzOmrsUadfm0uy
         kh9P0qg6cKGXeVO3eSdqEpwdCMvp77juEwpEM+OsLYSUTvGbgRMkzwxLRKNMcC1G3kYO
         KL0kqdCt/+2THfPA0Ms6k7/uPN+N4H3T/qWzHkO2j5VUsR4d24e+YEyJhG5tw+AYK8R3
         sJaUVxqmFVcVLbb6jcV5VEcrhxTK/Zra8YSMaOgK5BEZek/9Nrg7VbqI0HhDGxFlRktF
         uy/pOb0DKVyBry4WTwL0tg/ErlnhwW98Ddz41y6lzy5e6ZTO2/JGCVm1EJQTTue+Tp9m
         EoEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702290418; x=1702895218;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+DaqSXlUgA+L4tjVrcCcnAkTqmKztIS3NdZ/hayqav4=;
        b=hPDrWwtAndNeDD1oaaad8/wpFoA/9WgBbOKLWdMoFQcD5DX/ShpTJM/5I1a/WETJkC
         qKNzgX8obibWr5Qm/u9EGpCJPkybbBF9DS/LWFE/OwoaDuvrNKiExRk+fOl4iXjnz4r2
         l+NMlC0aglTx8nfisZe5ZdA3yFDRRr/dNLpUY1b4Wwl3vl0wX6Zok5Esj7OQ5eLVu9O2
         RzAfNerGQ3rGUtQxH7B6BwEsCECaLxTAArcS3fpEaY9TBENcELfL4nzwBBTcV1te5DSu
         ivy07hiik9w6k5tYbKhIxZiMEjvxOuuJduzNv6xRyNHigY4KNql0KO1WHPT+Hh/iLT/y
         0ltw==
X-Gm-Message-State: AOJu0Yx2Rnq2fE4xAy7kp2nAn1+UjgTvql1LmvGkXgSpSuEsXUBRO+WL
	nBnTJg66YTnkKovvCxPh9OQ=
X-Google-Smtp-Source: AGHT+IHhiWsnllxJTmzUNnLfh9j+xcIoRDqlafok8/P8pmmRF7oyjO9mXsUQR6XSZvduA/dBaHjdtA==
X-Received: by 2002:a05:6870:a782:b0:1fa:a755:fb14 with SMTP id x2-20020a056870a78200b001faa755fb14mr3979585oao.44.1702290418669;
        Mon, 11 Dec 2023 02:26:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5a1b:b0:1fb:1b99:3a67 with SMTP id
 on27-20020a0568715a1b00b001fb1b993a67ls5238777oac.2.-pod-prod-03-us; Mon, 11
 Dec 2023 02:26:58 -0800 (PST)
X-Received: by 2002:a05:6870:9f07:b0:1fb:75a:c43f with SMTP id xl7-20020a0568709f0700b001fb075ac43fmr3844403oab.104.1702290418040;
        Mon, 11 Dec 2023 02:26:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702290418; cv=none;
        d=google.com; s=arc-20160816;
        b=MTRdlcEE6xx2s8OD1q1yJi4d8g0vmq2orzWfVekeF3GL8N5ELzUx7vUDmv6JaEcc46
         JArnjVidIP7SLmpMOflDm3qCAdAf4BwVeVbzhYaCA/Ga4Fspav+7N9e4YnnKxH4EBVDp
         VeK2TCUH/3Xn0/JDqMnUSwI5oJTRzjFhbKWBhbMj+I26qPL/HHM6OnUDWc0fysw+/6Tv
         eRMG4a5XFoEdQ11ZSYAsl0miDcHsHcPQYTGZ9wFZXR42xB2A298jNohaVUVVkvVj7hyn
         jDW588ZDCucs0G7QEE3iPSTG8Fl7OHJzAVWiH57daKSCxGJwliqKL5AUVs1EC5MGiujS
         VPBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=52MMj8qKTft0Rgk5cZkkhNA4qD9/n7KR5GYlCADI69M=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=m3JN9/O2KW3McnI5GmmjzwU+xPsy/IF5stb0Q6y1r1UHLUUGH3uYikofXhiAJALMwl
         jgKhuIKfo3E1gw5dQnKCLYkrJJtSrZrJVQCSJAc+cHWXN/YZnvqt3hs6h7w0RgCwX92c
         88JIRbBIM3u7ODNX3EbegELVNeMSOdXN4PIvGvJSOtWxA9VzirHioQRe3TXDIVM0JGTj
         P3hIHt7covAesnBYiq0OWASI24FqUqtjhcAgFo/A8yEidR3B/tpEbDr1ToqHkQfqbXK0
         Dsx4UQE81NFuSmrJ5/5G2+FNnQGDi6ikDmX5W/3aUPpJTCCQd+6aiithzbIypwBQrLVB
         qTwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=K3seUkTp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id lw12-20020a0568708e0c00b001fab154c144si768281oab.1.2023.12.11.02.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:26:58 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id af79cd13be357-77f3790a187so220165185a.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:26:58 -0800 (PST)
X-Received: by 2002:a05:6214:4c04:b0:67a:c4d9:dc10 with SMTP id
 qh4-20020a0562144c0400b0067ac4d9dc10mr3977857qvb.109.1702290417391; Mon, 11
 Dec 2023 02:26:57 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-33-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-33-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:26:16 +0100
Message-ID: <CAG_fn=V5zMxGUQ=KmJh-ghTUHa-AZYn1CPTQNbf3x7Lu0w=HvA@mail.gmail.com>
Subject: Re: [PATCH v2 32/33] s390: Implement the architecture-specific kmsan functions
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=K3seUkTp;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> +static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
> +{
> +       if (addr >= (void *)&S390_lowcore &&
> +           addr < (void *)(&S390_lowcore + 1)) {
> +               /*
> +                * Different lowcores accessed via S390_lowcore are described
> +                * by the same struct page. Resolve the prefix manually in
> +                * order to get a distinct struct page.
> +                */
> +               addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
> +                       (void *)&S390_lowcore;
> +               return kmsan_get_metadata(addr, is_origin);
> +       }
> +       return NULL;
> +}

Is there a possibility for infinite recursion here? E.g. can
`lowcore_ptr[raw_smp_processor_id()]` point somewhere in between
`(void *)&S390_lowcore` and `(void *)(&S390_lowcore + 1))`?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV5zMxGUQ%3DKmJh-ghTUHa-AZYn1CPTQNbf3x7Lu0w%3DHvA%40mail.gmail.com.
