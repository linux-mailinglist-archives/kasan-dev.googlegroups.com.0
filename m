Return-Path: <kasan-dev+bncBD6ZP2WSRIFRBPHIZCNAMGQEBKRXTSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D286606FA7
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 07:55:09 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 2-20020a1c0202000000b003c6d73209b0sf992475wmc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 22:55:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666331708; cv=pass;
        d=google.com; s=arc-20160816;
        b=eImI2Id7tWra3MsekWDHNW0/NaGKlPDN6fqVn40aTKX+DKMGUYSaAkVZGisrEmGAP8
         wZ1Je/6BEZi1Fvdph8cyJCQ/fvJzQ/Yc3MA49zmtaFBimjLFIxq4sD1EimSk5X89iOpu
         8nEieuRCDC9VMslmkHNXd/PGj6fH5dbpQGW7jbVVe0hlO8os1OsVjYWDZFPPDsh7C0It
         Rjp2+PvsFiMVzjJ7Dnt3X3KNz1zkMHcpHV6om6FLVVZrdujbHVAb6lHisDWXRqmtXfow
         qb1SdVHlPYeS07ijymC15/7BObRm8KAa5uohGYGmBnwdXbxsrwLxvNBykxiO/ktbhmSL
         Fv+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:references:in-reply-to:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=i3qmzjUEtc/JErm5fBJstAKCAQ1Km1wzCcxYy0zK4TI=;
        b=vmW/78+Vmk2suJw3vUkXm1/QA6LJVdjcFVyz5VzMt2TexbcJwdXZZQFcG/vBK3TfIL
         DCVKQFr73I4b90eye5TEaQX+sd2R1KSCKffmpiDcuMzjbZC+IMtN+6LucWF0aFpwD4Te
         WDf0dR/Q7Ruv/0l2WLkwS78xhmjzg9XZ4q7a8P/z8OwXRWQQozWLHduUg773Wf+IQlDW
         /Z5qaq5lkCk/8VUE6FE6sZhW46rd4GQY4dR/RgnQknMzq/Vh8cqB845zX3EjGz+O3lwE
         J0R9ZKUmMzU3iLlQjqsPOd3mJ6ISwitrlphVSUD5CcsrxnNrJMhCLifpGpbpvX87C6sj
         NZOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I8UJNHQU;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=i3qmzjUEtc/JErm5fBJstAKCAQ1Km1wzCcxYy0zK4TI=;
        b=Jvpsu6sZ1cXOnANVnsiFkUaNI5vnWIsOWZEZz25hHhcuXNjK1JXU9JNrk5tbQu70BG
         4YMahBk1MYtGWAFkGtnDCk1+iZSymjG/2Xpb2T1RUGPRlFzSQHh2M2LohaXdPxM44+Rd
         hXzku9/Qa1aLwpzOFfWvcJiFBxs/HPdsZguQOzapiFbYO/yhRsP0TpVBrPxfG4qj+J9D
         wopLpqXY4Wtt9SmUOdnYauFjxMnhp/tTOJwQayeAGeGIRuxHOrXUCIuObZdBrfQzMjxp
         d5QL1sQ2T0DPvrDqYZZrb4KfdNd59rpLIpJaGqo0H/zcdmn0ysPFOvv73sWyupA0fDu0
         9Gpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i3qmzjUEtc/JErm5fBJstAKCAQ1Km1wzCcxYy0zK4TI=;
        b=T3/uxSZdnssK2+0Xax40ynhNtRHTur7xtgkEea3DvOLcQDjyQBIqHlEkNiuaW2kBF4
         WV+Eur2jZ13M2X/7ei4BeMg68Y6kGJedoN1SHA2fkDIy3r+BK/HKRSlVkmrFrc0VK9h+
         OHEf5rOzIDi0z07Jhn/RzuKLl164blkx0Bcf+MsL7CouEFMTLD0aKuf0WsRB3KiMWap/
         BNwnUxnoKFwA4P1QBTlLJzF4gmS5yYOS73k2NjQGZlfU3X+ev7f5IVq7ed3g+GBcEWic
         xDJuDAj/zr2Demk12m926VZHWzX9b0jXrsosODxZo5vR1vgxRo+YYshWgi0nEwgDWx0U
         G8xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=i3qmzjUEtc/JErm5fBJstAKCAQ1Km1wzCcxYy0zK4TI=;
        b=PWeFTq+UqpSaM4UqLlyxCu70trqK86ONkKRcGocc8zqkyxS18j5RQMMNnBcMbJA+LJ
         8uJBfZxZnSdP8KmAE1+YQ9BnizJDudLGIrLjydqcH/Im/EM3gtJzlEv/Ow1oSOqZ9M3j
         qwbud/F64OISnVj2fA31sSfCxTd5CmjOSeGURTkRxJQrpkBRj38aKor3/FpV43DFGw+j
         BmDnxvHUZ/0VoYcmBeuAUSiyjYSpB4ChW0Sz9npii/pyVQ6iGAnxVf+Z1xvpiRqBxAqk
         fzhhuYsxxatuUjgpgAJKQMlcN5NKEqiWKnMtCjOIgAr7CmPtqeyJaPqr1xOg4E7EboTC
         t6LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2sjrTRH0Mkw1h04Mf2o5mVU4zVHILCW5EShD6R1wfV2BqWN5K3
	Jlrdl0J6mbeVndMiTqu5byE=
X-Google-Smtp-Source: AMsMyM4BmUdz2vCt6m8fvckwPjMW0oiPWdX4guaEusOnU9WJJcJdrmAlmY6gtwYWP5CZsexV48Zh8w==
X-Received: by 2002:a05:600c:5119:b0:3c6:cae1:1512 with SMTP id o25-20020a05600c511900b003c6cae11512mr33285226wms.80.1666331708558;
        Thu, 20 Oct 2022 22:55:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2316:b0:3c6:efd6:9cd8 with SMTP id
 22-20020a05600c231600b003c6efd69cd8ls719637wmo.0.-pod-control-gmail; Thu, 20
 Oct 2022 22:55:07 -0700 (PDT)
X-Received: by 2002:a7b:c303:0:b0:3b4:6e89:e5d5 with SMTP id k3-20020a7bc303000000b003b46e89e5d5mr11793209wmj.111.1666331707546;
        Thu, 20 Oct 2022 22:55:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666331707; cv=none;
        d=google.com; s=arc-20160816;
        b=hTC83W8hCugnKPeOXCg8orQlzgh402lHIrC6PcIjBn3vKdghG2uCPDstYFN4IjH2+n
         p0bhD9CNiEcLUsggeWFhIfDI+VhXCj1BVvWNnm7J8vQQ5hovhS37RdPAus9KCM68Imov
         sSoOGXV9d4dDRuoknl4iltP3Nwwx611vHsBfRZquKlvwcN72N/yfOF4Rt8TSAuigbYQ1
         s4f5g+EsSx7mkKsUpetsVn3mo734dwQr8nwwjBE+/FLjqi+qejMboaIVhHvXYHyeo8pw
         RAjsdM22MX37gAA44ikKTMWgk6/G61qOcCgtAIx5/3EyV1JtxuVv0x6QFmIe8KxJPw/k
         phfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:dkim-signature;
        bh=sX2sT5yZY9mOxq1lGzGkC1hbjgjx4M2iR0i8Qt3Tyuw=;
        b=hiOXI4o04OdwH4ezAVEsCZd0UnLbMGOvZW6NbUxC9O7lROW3ED74Gx2gYk9BbvvM/y
         5ChjapW02KWd3aWbxg4fXQ9SHniNnVK/CWHF9thS+x9QxOgaks3PyCgFfuBH37QOeIPh
         0x2qKYEKAj79WOQ8vVxynbfCBK5uxUmEy9zA+g8DqCQht26UaaVVpRo393hqIdVkAmmC
         2tedNN3kAIsuVjyHmqSXJcLMYy7NwUsZq5DKJI8jyIXSI+g/NF3l29YkUfFnk02ssjIb
         s5JPfqLe9EkGkzTcFI1qWKwDL9oZF5L3jDYOX/IYZXtsBgEpitBOVfOJ3+SP5bh0mVqq
         MrCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I8UJNHQU;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id h15-20020a1ccc0f000000b003c5081829c4si184835wmb.0.2022.10.20.22.55.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Oct 2022 22:55:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id b18so2251251ljr.13
        for <kasan-dev@googlegroups.com>; Thu, 20 Oct 2022 22:55:07 -0700 (PDT)
X-Received: by 2002:a2e:8796:0:b0:26e:8b13:a29c with SMTP id
 n22-20020a2e8796000000b0026e8b13a29cmr6125379lji.210.1666331707003; Thu, 20
 Oct 2022 22:55:07 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab3:5411:0:b0:1f6:575a:5fb7 with HTTP; Thu, 20 Oct 2022
 22:55:06 -0700 (PDT)
In-Reply-To: <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
From: youling 257 <youling257@gmail.com>
Date: Fri, 21 Oct 2022 13:55:06 +0800
Message-ID: <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=I8UJNHQU;       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
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

How to use perf tool?
I use diff compare "nm -S vmlinux".
android_x86:/ $ su
android_x86:/ # diff /sdcard/with_vmlinux /sdcard/without_vmlinux
--- /sdcard/with_vmlinux
+++ /sdcard/without_vmlinux
@@ -12951,7 +12951,7 @@
 ffffffff81338400 00000000000000dc T compat_only_sysfs_link_entry_to_kobj
 ffffffff810884d0 00000000000002b7 T compat_ptrace_request
 ffffffff812b4e80 0000000000000025 T compat_ptr_ioctl
-ffffffff811380d0 000000000000008d T compat_put_bitmap
+ffffffff811380d0 000000000000008a T compat_put_bitmap
 ffffffff81a62180 000000000000000f t compat_raw_ioctl
 ffffffff81afa060 000000000000000f t compat_rawv6_ioctl
 ffffffff81090790 0000000000000018 T compat_restore_altstack
@@ -14260,7 +14260,7 @@
 ffffffff8167d380 00000000000000dd T cppc_set_enable
 ffffffff8167d460 0000000000000221 T cppc_set_perf
 ffffffff818cdbe0 000000000000004f t cppc_update_perf
-ffffffff8102bba0 000000000000012b t cp_stat64
+ffffffff8102bba0 000000000000012a t cp_stat64
 ffffffff81494810 0000000000000028 t cp_status_show
 ffffffff812a33e0 00000000000001b2 t cp_statx
 ffffffff82e1c934 0000000000000004 b cpu0_hotpluggable
@@ -26993,7 +26993,6 @@
 ffffffff821b8000 0000000000000038 d CSWTCH.102
 ffffffff821cd6c0 0000000000000048 d CSWTCH.107
 ffffffff821d4b80 0000000000000018 d CSWTCH.11
-ffffffff8203dd88 000000000000000c d CSWTCH.111
 ffffffff82152de0 00000000000000a0 d CSWTCH.111
 ffffffff82105ea0 0000000000000020 d CSWTCH.1116
 ffffffff82105e80 0000000000000020 d CSWTCH.1121
@@ -27002,6 +27001,7 @@
 ffffffff821d4b60 0000000000000018 d CSWTCH.12
 ffffffff821b2c60 0000000000000024 d CSWTCH.120
 ffffffff82033fc0 0000000000000068 d CSWTCH.123
+ffffffff8203dd88 000000000000000c d CSWTCH.123
 ffffffff82014b80 00000000000000a0 d CSWTCH.125
 ffffffff82014b40 0000000000000028 d CSWTCH.128
 ffffffff82033f40 0000000000000064 d CSWTCH.128
@@ -27026,7 +27026,6 @@
 ffffffff821c9b80 0000000000000018 d CSWTCH.189
 ffffffff821b39a0 0000000000000028 d CSWTCH.19
 ffffffff820055c0 0000000000000024 d CSWTCH.195
-ffffffff82208de0 0000000000000004 d CSWTCH.199
 ffffffff82146127 0000000000000006 d CSWTCH.2
 ffffffff82146380 0000000000000014 d CSWTCH.2
 ffffffff8219f770 0000000000000018 d CSWTCH.20
@@ -27033,5 +27032,6 @@
 ffffffff821d9c90 0000000000000018 d CSWTCH.20
 ffffffff821b7e60 0000000000000128 d CSWTCH.202
+ffffffff82208de0 0000000000000004 d CSWTCH.202
 ffffffff821b7cc0 0000000000000188 d CSWTCH.204
 ffffffff821b7c80 0000000000000038 d CSWTCH.206
 ffffffff821a4ac0 0000000000000006 d CSWTCH.207
@@ -27043,8 +27043,8 @@
 ffffffff821b7be0 0000000000000038 d CSWTCH.214
 ffffffff821c9940 0000000000000030 d CSWTCH.217
 ffffffff8219f750 0000000000000018 d CSWTCH.22
-ffffffff82033580 0000000000000023 d CSWTCH.221
 ffffffff8213de80 0000000000000028 d CSWTCH.222
+ffffffff82033580 0000000000000023 d CSWTCH.223
 ffffffff82216c10 0000000000000014 d CSWTCH.225
 ffffffff82216bf0 0000000000000014 d CSWTCH.232
 ffffffff82216be0 0000000000000010 d CSWTCH.234
@@ -27052,7 +27052,7 @@
 ffffffff821b3800 0000000000000188 d CSWTCH.24
 ffffffff821f3340 0000000000000058 d CSWTCH.242
 ffffffff82158c60 0000000000000030 d CSWTCH.244
-ffffffff821a9868 000000000000000a d CSWTCH.255
+ffffffff821a9868 000000000000000a d CSWTCH.258
 ffffffff82106a20 0000000000000010 d CSWTCH.261
 ffffffff821a42a0 0000000000000004 d CSWTCH.261
 ffffffff8203d9e0 0000000000000030 d CSWTCH.265
@@ -27059,12 +27059,12 @@
 ffffffff82126780 0000000000000028 d CSWTCH.27
 ffffffff8214d360 0000000000000040 d CSWTCH.278
 ffffffff82136f80 0000000000000024 d CSWTCH.28
-ffffffff821b3000 0000000000000024 d CSWTCH.281
-ffffffff821b2fc0 0000000000000024 d CSWTCH.282
-ffffffff8210ed40 000000000000002c d CSWTCH.289
-ffffffff8210ed00 000000000000002b d CSWTCH.290
-ffffffff8210ecc0 000000000000002c d CSWTCH.292
+ffffffff821b3000 0000000000000024 d CSWTCH.285
+ffffffff821b2fc0 0000000000000024 d CSWTCH.286
+ffffffff8210ed40 000000000000002c d CSWTCH.292
 ffffffff821b3ae0 0000000000000020 d CSWTCH.292
+ffffffff8210ed00 000000000000002b d CSWTCH.293
+ffffffff8210ecc0 000000000000002c d CSWTCH.295
 ffffffff8214d340 0000000000000020 d CSWTCH.296
 ffffffff82146121 0000000000000006 d CSWTCH.3
 ffffffff821b7ba0 0000000000000020 d CSWTCH.3
@@ -27075,17 +27075,17 @@
 ffffffff821d3c40 0000000000000020 d CSWTCH.31
 ffffffff820ff780 0000000000000004 d CSWTCH.318
 ffffffff821b5cc0 0000000000000038 d CSWTCH.33
-ffffffff8214efa0 0000000000000010 d CSWTCH.334
+ffffffff8214efa0 0000000000000010 d CSWTCH.346
 ffffffff8214a8c0 0000000000000018 d CSWTCH.35
-ffffffff8210ecb0 000000000000000c d CSWTCH.359
-ffffffff8202cae0 000000000000002c d CSWTCH.360
+ffffffff8210ecb0 000000000000000c d CSWTCH.362
 ffffffff82016300 0000000000000020 d CSWTCH.363
 ffffffff821fce00 0000000000000040 d CSWTCH.38
-ffffffff82032780 0000000000000074 d CSWTCH.387
+ffffffff8202cae0 000000000000002c d CSWTCH.381
+ffffffff82032780 0000000000000074 d CSWTCH.390
 ffffffff82118100 0000000000000018 d CSWTCH.40
 ffffffff821598a0 0000000000000020 d CSWTCH.41
-ffffffff82032760 0000000000000020 d CSWTCH.428
 ffffffff82139a20 0000000000000038 d CSWTCH.43
+ffffffff82032760 0000000000000020 d CSWTCH.431
 ffffffff82015d40 0000000000000040 d CSWTCH.45
 ffffffff821399e0 0000000000000040 d CSWTCH.45
 ffffffff822194e0 000000000000000c d CSWTCH.450
@@ -27092,5 +27092,5 @@
 ffffffff8214d2e0 0000000000000048 d CSWTCH.459
-ffffffff8210eca0 000000000000000c d CSWTCH.464
+ffffffff8210eca0 000000000000000c d CSWTCH.467
 ffffffff821399c0 0000000000000020 d CSWTCH.47
 ffffffff8214a8e0 00000000000000c8 d CSWTCH.48
 ffffffff82028ac0 0000000000000018 d CSWTCH.49
@@ -27097,8 +27097,8 @@
 ffffffff821399a0 0000000000000020 d CSWTCH.49
-ffffffff82032740 0000000000000018 d CSWTCH.507
-ffffffff82032730 000000000000000c d CSWTCH.508
-ffffffff82032720 000000000000000c d CSWTCH.509
 ffffffff82139960 0000000000000030 d CSWTCH.51
+ffffffff82032740 0000000000000018 d CSWTCH.510
+ffffffff82032730 000000000000000c d CSWTCH.511
+ffffffff82032720 000000000000000c d CSWTCH.512
 ffffffff821595c0 0000000000000100 d CSWTCH.52
 ffffffff821b6240 0000000000000018 d CSWTCH.52
 ffffffff821371c0 0000000000000024 d CSWTCH.523
@@ -27125,7 +27125,7 @@
 ffffffff82139680 0000000000000058 d CSWTCH.72
 ffffffff82139620 0000000000000048 d CSWTCH.74
 ffffffff8213c740 0000000000000020 d CSWTCH.74
-ffffffff821f04a0 0000000000000018 d CSWTCH.753
+ffffffff821f04a0 0000000000000018 d CSWTCH.766
 ffffffff8200e4e0 0000000000000020 d CSWTCH.77
 ffffffff821bffc0 0000000000000018 d CSWTCH.78
 ffffffff8200e4c0 0000000000000020 d CSWTCH.79
1|android_x86:/ #

2022-10-21 2:14 GMT+08:00, Alexander Potapenko <glider@google.com>:
> On Wed, Oct 19, 2022 at 2:37 PM 'Marco Elver' via kasan-dev <
> kasan-dev@googlegroups.com> wrote:
>
>> On Thu, Oct 20, 2022 at 04:07AM +0800, youling 257 wrote:
>> > That is i did,i already test, remove "u64 __tmp=E2=80=A6kmsan_unpoison=
_memory",
>> no help.
>> > i only remove kmsan_copy_to_user, fix my issue.
>>
>> Ok - does only the below work (without the reverts)?
>>
>> diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
>> index c4cae333deec..eb05caa8f523 100644
>> --- a/include/linux/kmsan-checks.h
>> +++ b/include/linux/kmsan-checks.h
>> @@ -73,8 +73,8 @@ static inline void kmsan_unpoison_memory(const void
>> *address, size_t size)
>>  static inline void kmsan_check_memory(const void *address, size_t size)
>>  {
>>  }
>> -static inline void kmsan_copy_to_user(void __user *to, const void *from=
,
>> -                                     size_t to_copy, size_t left)
>> +static __always_inline void kmsan_copy_to_user(void __user *to, const
>> void *from,
>> +                                              size_t to_copy, size_t
>> left)
>>  {
>>  }
>>
>>
>> ... because when you say only removing kmsan_copy_to_user() (from
>> instrument_put_user()) works, it really doesn't make any sense. The only
>> explanation would be if the compiler inlining is broken.
>>
>>
> If what Marco suggests does not help, could you post the output of `nm -S
> vmlinux` with and without your revert so that we can see which functions
> were affected by the change?
>
> Unfortunately the top results are of no help, do you have the `perf` tool
> available in your system?
>
>
>> --
>> You received this message because you are subscribed to the Google Group=
s
>> "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send a=
n
>> email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit
>> https://groups.google.com/d/msgid/kasan-dev/Y1Bt%2BIa93mVV/lT3%40elver.g=
oogle.com
>> .
>>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOzgRdb%2BW3_FuOB%2BP_HkeinDiJdgpQSsXMC4GArOSixL9K5avg%40mail.gm=
ail.com.
