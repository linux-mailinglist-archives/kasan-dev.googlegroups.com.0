Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZWYTH7AKGQEOZEXOII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 491622CA7EA
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:16:40 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id h2sf1376626pjs.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839398; cv=pass;
        d=google.com; s=arc-20160816;
        b=MDoMfBqZCJN1vWMeLzbZdxjbygZX/104HIFDhwLInS4H+W46hr3T+JbrpHHoSVMzA3
         8gylhbuApP+FiruIH/+g14ARaHyGdIgU50meASW66Hk8l7wAH8dQ3EGO0jfm42dtRqVv
         O2t9vQk6BlFWiS2Htyn0B77NCZr3Gdd7jpsv4ixHn/B8RswvCOvjGK8mrqcw4TJUr5rM
         JsQukOyV0cL+IZKT7SUxo00veuWxSLodKL57LGalhiZSbB4+f0nlGgoND6cAVAZMp5fv
         bwyK5oR/Fj0Vjcf+nXRyVJf83KvVgUnjbIdVz7m/UWTOHcKRqgQcDCirFf+8HH1KrwA1
         O9TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4qKUmD+vEZEqDcmrv4xQAu6t+xA3tYbzUVsWSlWi/Tk=;
        b=f7LKQ61rf1sE+gwXYGUgi8BVW+D+KDeW+zg6fYnSZdHNzAf8jc7FDx8frGPhB3M9VR
         YrXUZ6EsdvNLF9HEhytW8m3XZMr+FqpVoofLRBotCO7oDpGJP4eIvSPPp/QGBZ5+YZ6C
         gBmsHYl1fG609syT9sjgKAlxnml8YFCyZG6N0h5ZoJRkv5g6Ks68xxbGqX7Mk/tl/SGI
         hVQk40Z9HqmVvlmWZRMGlispqEGu1CdgMUo2JJeLctd4i0bCcaEXDyQomMVTksZpOAWt
         6ogPkYnxfZV0723KXSea55I8tOEH3H+ymoYUAcJtMrtnok9nnnMLuoodp6G+BfRkYbtV
         G72g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pOQ4NjzP;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4qKUmD+vEZEqDcmrv4xQAu6t+xA3tYbzUVsWSlWi/Tk=;
        b=qk3A56JMsK1t7d41CKcvJTcR4MAKgEr+NuV3u+vWxb6nHM+qwCO4QbiEpFdaFEXeYh
         5fu92TzoaELnAoPmnoVvl/bsRFDorVt5jXY75w/eTZN2cwthfW8ijccd6q4Dev8wDoY3
         +i1d9J+TfBc9USVssoOMHw0t51ezL3E+FFoQf5+ejk2ROnYHIPJv2U5bpR9f5GwLaAS7
         Z25+kHTDYxXkX7PkNMNT8nBFAKJYJphohy2AVhIFoVBfCbBmpOuU44O4+B/o/ee6Oeah
         cSYBC61GUMS1E3ml8aHDCogO/7UqfqeOYfmcCnWWbYaEcJSe/Ykp5yDSWBfPAYUhkIBl
         3SRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4qKUmD+vEZEqDcmrv4xQAu6t+xA3tYbzUVsWSlWi/Tk=;
        b=ET14AbhWS50j3lqg03CRQc3CMgHtlr2zOfP31TS3aqvUBxYRTh6NJGjzEkxTgtckg4
         U3CiMsf31LQ60W1n5XBE6YRGMFSJ1wMWjSYcQ77gx1kabUWXXIdKEV/qZlGgC0/m5aXV
         U8LSSjLiBLWHdIe0S29/Z+ibZS0YhKyJhfX0qyxgJe/3ncZBlXbxp7kEkQLdrdXBFSJj
         mTsdP4CSDNxTiBN+KKeW5uM+7UYUHQwuSYqBa2mWgWIk4hY+YKK/mF7594aQIN3FZOgs
         tbTI+PgyfZe19h7Ds0HClHs9uaDbsDCI75Of7kbiVnJ2hqzuB2cGTKOxb/EwZ38dy2Wq
         zovQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MF8iFIWjyjkd/VvAhWnlDH4QJHIxzPOz6AtNIx3SHSWeY5zPx
	Fd06YVOmsMa0EISU8YbiPqI=
X-Google-Smtp-Source: ABdhPJxnYFGblJFqZt6HJnN7I5qJABoJoWT/rhqxS2aw32XONo6EvBjxZlaW9SPL5Ej6kHWI2QlWfQ==
X-Received: by 2002:a63:4857:: with SMTP id x23mr2812064pgk.404.1606839398537;
        Tue, 01 Dec 2020 08:16:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8681:: with SMTP id g1ls1192251plo.9.gmail; Tue, 01
 Dec 2020 08:16:38 -0800 (PST)
X-Received: by 2002:a17:90a:2e8c:: with SMTP id r12mr3436919pjd.29.1606839398006;
        Tue, 01 Dec 2020 08:16:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839398; cv=none;
        d=google.com; s=arc-20160816;
        b=WSdrnA/dF1hktuz99UJNlQIVBNaCvKDsnQRYzS02hWARIuv8MP5BbzRzdaw0YYC3h9
         yLlAZ8lGhpa8oXhs5VzuUm2+UYBS6P/3iWVqydXwUM1vYRVi8e1IdKqyg1GEQLuQg7ZP
         2zvkpXzasfb1DC5m711WLOQoP6uFd9JD65rPd7w6BvtM1x5BQXENgjfUS2oGrXETObiv
         3+YP1xnVNctbzVtLxi4eGEhxf+xUyzIAwsXjXHw4CllgvPPffRszyPXQGxGrGMVh4jKa
         T7YxK9Y4IxwQfWqCBke4S1EYWLiudY/TJl9fnE/bDQo4JlIeBjClKfk1pEr/I9LD40kd
         9Hlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=keKgMbCkoGOXeTFvWr8odCNv42gYD1NHpH65Gpi3cCA=;
        b=O9NkuB8yByeNtxoGwIhTU0h9jrVVATsAqJihuW2im4cUPK4uuez/AmVtmTHeXgGTMa
         mwwagskWG7AFy+XUSa8vn7ggm/20RkjP8QO6LtQps1kDn5f+5wOgY7zngMg31llBFt1E
         2RiFAgr/KDtD6RGp3Xr2QAo13jPtqEAoDbFYoH2Yzfxgk7DFq/WNqD4nHi5Bxdi6itPZ
         P32Dcxtt+IGk2XgjUSoj87S0H75VOp+rNvrYRZTcI2GEq1KavsbVljpQkqZT58o5L/56
         +CMaoNFU9XVFH6yzjAFCSy1dEymCWxHaoNFcCXgioWp9B2kgZ5pWjK8Or5D0mTniWLPM
         V/pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pOQ4NjzP;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id z14si18435pjr.3.2020.12.01.08.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:16:37 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id hk16so1524648pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:16:37 -0800 (PST)
X-Received: by 2002:a17:90b:a14:: with SMTP id gg20mr3560478pjb.46.1606839397634;
        Tue, 01 Dec 2020 08:16:37 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id r11sm82914pgn.26.2020.12.01.08.16.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:16:37 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 0/6] KASAN for powerpc64 radix
Date: Wed,  2 Dec 2020 03:16:26 +1100
Message-Id: <20201201161632.1234753-1-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=pOQ4NjzP;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

This is a significant reworking of the previous versions. Instead of
the previous approach which supported inline instrumentation, this
series provides only outline instrumentation.

To get around the problem of accessing the shadow region inside code we run
with translations off (in 'real mode'), we we restrict checking to when
translations are enabled. This is done via a new hook in the kasan core and
by excluding larger quantites of arch code from instrumentation. The upside
is that we no longer require that you be able to specify the amount of
physically contiguous memory on the system at compile time. Hopefully this
is a better trade-off. More details in patch 6.

kexec works. Both 64k and 4k pages work. Running as a KVM host works, but
nothing in arch/powerpc/kvm is instrumented. It's also potentially a bit
fragile - if any real mode code paths call out to instrumented code, things
will go boom.

There are 4 failing KUnit tests:

kasan_stack_oob, kasan_alloca_oob_left & kasan_alloca_oob_right - these are
due to not supporting inline instrumentation.

kasan_global_oob - gcc puts the ASAN init code in a section called
'.init_array'. Powerpc64 module loading code goes through and _renames_ any
section beginning with '.init' to begin with '_init' in order to avoid some
complexities around our 24-bit indirect jumps. This means it renames
'.init_array' to '_init_array', and the generic module loading code then
fails to recognise the section as a constructor and thus doesn't run
it. This hack dates back to 2003 and so I'm not going to try to unpick it
in this series. (I suspect this may have previously worked if the code
ended up in .ctors rather than .init_array but I don't keep my old binaries
around so I have no real way of checking.)


Daniel Axtens (6):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  kasan: define and use MAX_PTRS_PER_* for early shadow tables
  kasan: Document support on 32-bit powerpc
  powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
  powerpc: Book3S 64-bit outline-only KASAN support


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-1-dja%40axtens.net.
