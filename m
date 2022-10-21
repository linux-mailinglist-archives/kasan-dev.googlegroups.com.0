Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMEGZSNAMGQESL5AWEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3106F607FD7
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 22:38:10 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id bl11-20020a05620a1a8b00b006f107ab09dcsf1404711qkb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 13:38:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666384689; cv=pass;
        d=google.com; s=arc-20160816;
        b=y1TYsn7ICQvh8hjvpTetzJtlW9u9ARCd06AdgQzNH4rCKdTkpTOqgRUqt8sKyAkcmj
         ra1KBJp1W/Y/XoJrWhqqvNszzq+YaGdw4zfUv5TJKhkUIfi/EXVfAUA+SXT1ipT02CBQ
         w8TX3PEdwpyLYHhcLw5uvBlkKxKZyvyeREdU0IbOeVJMxH89bKHIkkI1Jb2KQeDIeUQ2
         UwuvPFxsvsAvt+Zi7CCJEnonZnap9E4KafvtlcOCeZFJolFKNKevcQmt3/janvXAG+WY
         kwE3/cgcUGda5z43nEiQEhhYqKEalk9VvdumRLKgCio1sQb+SWAqf+6YFHr8a4DYZ67f
         ll0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qTA8acs7gEKbBEfIhJcdm19wVffII1mEuFXNKuzEK7w=;
        b=UhjgdfztOAPyP1IZkePJLcbJA5FQGIkKrd4mg2N+frAMAgNDVI4F+1xmBudikhpq6P
         7nb7CBSDUnzr1SoJb+Pqh3gOVXudormrqxjM7YRcXmQv2DRbG1Wb1Il5w6a57jjr/TVT
         dNxh+2UvqGpbHxUEiqc+spxCA6Cb/xHlVl2LzM+kRuJIIF8LPYiCsIS/xsj+GiQ/UBr+
         bSwIlyKWyB1Tz1KQ0PYjXWN399thvG4b0EBLnahjC1f61Kan6Z/9yp+Poe++jgGozcfD
         h5x4UiqYHOK4PX7/t9Le3keHoObwb/rmTb26S2qE2rzvLnr1BdCLoeqFM+lr1ze6V223
         sf/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mnm0wh60;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qTA8acs7gEKbBEfIhJcdm19wVffII1mEuFXNKuzEK7w=;
        b=JrLBEJY2gHiV9Mp22SbJ9Gk4p3nYMedbt9TMES8l75zc3/hIYpNIUMYxX3bah33kDZ
         HiVXyywvUeTj3UGIZQTe1iwAq2gBIZYv7SQq3loaZpfGm8WvhdLcQkBSGbZxrzVMxFq2
         1tqJt/+4z4JMWGpiSOp2egFma7fXd1vqlUHtJ+EgjcDWjqMC70nloozNdaQ0RHc/AmAd
         NaWCZneqUWUieUzipne8e3yyiwS4EBw7V3w070u+olrXOTXbmc+QYVIrWNJ/C/KyLJCZ
         LuhaTeXJi0mZfRo2NlkvqWBEPREXN3NAIhDY22Uy3iangnQzFzUPnIYmuEuFVACY7GQq
         /btQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=qTA8acs7gEKbBEfIhJcdm19wVffII1mEuFXNKuzEK7w=;
        b=wkr72lH8jj063thLrOuUozbX7OIcZgjJhw5eSvUv8JQwIayD8LOnnw2xngBvJtohZ+
         isv7Vcj2ixvjZ7wo6TJ/JtnVbW2X7/LfqhN0eXedShWGc1TGmh15JeWRICGAw0W6buNF
         SAnCccXHdvzP70AcPq6F7PVLBBkMvI4mfQQo6tvnNTb/mpAdC2mMJMgw3TiPjzYA3gFD
         tbDssFowCGurEVwn/cQ5571oidiRfrCi733qjSwAXO9ZqsxfUAyflJDAhG6OIyVXrY1y
         Q2d37eQWu9dbchdykz8VdDuyC848XA66m44qVNJ4mwtZTOqYwkgrE3JnZX729luAKohb
         rrqg==
X-Gm-Message-State: ACrzQf268hykkaZNOHy/ZflQoT4n0MGBtOT4RtYSIW+DxGqX6JunYSjY
	bcmcc3C3M2iRYkmLJ4oH/WE=
X-Google-Smtp-Source: AMsMyM62ki297iruU2lxqO26devOg3cSVj818+cL6yafjItfqxqT2+sSWIKik2raaYeABVuRTtPeoQ==
X-Received: by 2002:ac8:7e94:0:b0:39c:f328:a925 with SMTP id w20-20020ac87e94000000b0039cf328a925mr17646844qtj.524.1666384688864;
        Fri, 21 Oct 2022 13:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b312:0:b0:4af:9d10:e2a6 with SMTP id s18-20020a0cb312000000b004af9d10e2a6ls1816167qve.3.-pod-prod-gmail;
 Fri, 21 Oct 2022 13:38:08 -0700 (PDT)
X-Received: by 2002:ad4:5b89:0:b0:4b1:a22e:7d7f with SMTP id 9-20020ad45b89000000b004b1a22e7d7fmr17816700qvp.26.1666384688391;
        Fri, 21 Oct 2022 13:38:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666384688; cv=none;
        d=google.com; s=arc-20160816;
        b=Ws1r3dHutmcJyQEGH6CixxvtGE4bUFZLoYBYeW9PJR8q4w9O9yUum/5sUyWlW636oc
         Zb0EIylz1Wr3ZZ+psBHMGRaeyZHKfPbqFpTS56NJsj7SmCb9rUursDSuMcYMtXchRU3r
         LJpSObBVySxzip4fxNmjoVnPVjGCjCjGu1mfbLq6E4dEDC9XpvaSXScv6RQ5Fh2p9tny
         q8A4uKaSxtoimLjKghLDKXZWeS1p+gtM+Wc/MazAMoMIeeOA1AM6nxtt+3MG1G+JV/wx
         4ggn9H3JdDzu47BJLtK9j9qW1VYvmj61zboxyzzDqO/1G8OBnBY3h6xlx4WjldWHMOnX
         JHlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4JZYQeLzr13t2F4XshvRm/E8oRVfIbIgJs1oHky0VEQ=;
        b=jG3d6xf/aJUR3yq0RzHkMA0UtSD55EAriTXRbZoYdYFWohL0U8JznrGp7aP/ODVWAn
         DfV6fuVQji9cWHCkRS1i/d+CEMBavhyGoe214pKqKwwHeALDRsJU6NHc74mPhK9+SKD9
         glGaEFWKswb2SzTGfUUOAKEyiJFxii4NfEpLguUedX5NqxaQ8HokF/IoLXVr8j4X0bhY
         i7U/oW2Bq2Gn/6rlK+P2/OrJOHAnu7xIpULKz0yexQ1BI5305UmzzY4VSZjpd0BT+X3h
         7hQKYJxab/GUKqFbDl0x+Idjiq6kCakZHC4zIAQjbFULs36FrJH3XnCJao0gkh7CASBW
         t5TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mnm0wh60;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id a23-20020a05620a125700b006ec80b54a06si1037811qkl.1.2022.10.21.13.38.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Oct 2022 13:38:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-367b8adf788so34551337b3.2
        for <kasan-dev@googlegroups.com>; Fri, 21 Oct 2022 13:38:08 -0700 (PDT)
X-Received: by 2002:a0d:d284:0:b0:352:fe85:536c with SMTP id
 u126-20020a0dd284000000b00352fe85536cmr18878497ywd.299.1666384687906; Fri, 21
 Oct 2022 13:38:07 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
 <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
 <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com>
 <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com> <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com>
In-Reply-To: <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Oct 2022 13:37:31 -0700
Message-ID: <CAG_fn=UVARRueXn4mU51TkzLTpZ=2fKNL7NAB3YH7mGP71ZhUQ@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: youling 257 <youling257@gmail.com>
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
Content-Type: multipart/alternative; boundary="000000000000621ccb05eb916b72"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mnm0wh60;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

--000000000000621ccb05eb916b72
Content-Type: text/plain; charset="UTF-8"

On Fri, Oct 21, 2022 at 8:19 AM youling 257 <youling257@gmail.com> wrote:

> CONFIG_DEBUG_INFO=y
> CONFIG_AS_HAS_NON_CONST_LEB128=y
> # CONFIG_DEBUG_INFO_NONE is not set
> CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
> # CONFIG_DEBUG_INFO_DWARF4 is not set
> # CONFIG_DEBUG_INFO_DWARF5 is not set
> # CONFIG_DEBUG_INFO_REDUCED is not set
> # CONFIG_DEBUG_INFO_COMPRESSED is not set
> # CONFIG_DEBUG_INFO_SPLIT is not set
> # CONFIG_DEBUG_INFO_BTF is not set
> # CONFIG_GDB_SCRIPTS is not set
>
> perf top still no function name.
>
> 12.90%  [kernel]              [k] 0xffffffff833dfa64
>

I think I know what's going on. The two functions that differ with and
without the patch were passing an incremented pointer to unsafe_put_user(),
which is a macro, e.g.:

   unsafe_put_user((compat_ulong_t)m, umask++, Efault);

Because that macro didn't evaluate its second parameter, "umask++" was
passed to a call to kmsan_copy_to_user(), which resulted in an extra
increment of umask.
This probably violated some expectations of the userspace app, which in
turn led to repetitive kernel calls.

Could you please check if the patch below fixes the problem for you?

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 8bc614cfe21b9..1cc756eafa447 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -254,24 +254,25 @@ extern void __put_user_nocheck_8(void);
 #define __put_user_size(x, ptr, size, label)                           \
 do {                                                                   \
        __typeof__(*(ptr)) __x = (x); /* eval x once */                 \
-       __chk_user_ptr(ptr);                                            \
+       __typeof__(ptr) __ptr = (ptr); /* eval ptr once */              \
+       __chk_user_ptr(__ptr);                                          \
        switch (size) {                                                 \
        case 1:                                                         \
-               __put_user_goto(__x, ptr, "b", "iq", label);            \
+               __put_user_goto(__x, __ptr, "b", "iq", label);          \
                break;                                                  \
        case 2:                                                         \
-               __put_user_goto(__x, ptr, "w", "ir", label);            \
+               __put_user_goto(__x, __ptr, "w", "ir", label);          \
                break;                                                  \
        case 4:                                                         \
-               __put_user_goto(__x, ptr, "l", "ir", label);            \
+               __put_user_goto(__x, __ptr, "l", "ir", label);          \
                break;                                                  \
        case 8:                                                         \
-               __put_user_goto_u64(__x, ptr, label);                   \
+               __put_user_goto_u64(__x, __ptr, label);                 \
                break;                                                  \
        default:                                                        \
                __put_user_bad();                                       \
        }                                                               \
-       instrument_put_user(__x, ptr, size);                            \
+       instrument_put_user(__x, __ptr, size);                          \
 } while (0)

 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUVARRueXn4mU51TkzLTpZ%3D2fKNL7NAB3YH7mGP71ZhUQ%40mail.gmail.com.

--000000000000621ccb05eb916b72
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBkaXI9Imx0ciI+PGRpdiBkaXI9Imx0ciI+PGJyPjwvZGl2Pjxicj48ZGl2IGNsYXNzPSJn
bWFpbF9xdW90ZSI+PGRpdiBkaXI9Imx0ciIgY2xhc3M9ImdtYWlsX2F0dHIiPk9uIEZyaSwgT2N0
IDIxLCAyMDIyIGF0IDg6MTkgQU0geW91bGluZyAyNTcgJmx0OzxhIGhyZWY9Im1haWx0bzp5b3Vs
aW5nMjU3QGdtYWlsLmNvbSI+eW91bGluZzI1N0BnbWFpbC5jb208L2E+Jmd0OyB3cm90ZTo8YnI+
PC9kaXY+PGJsb2NrcXVvdGUgY2xhc3M9ImdtYWlsX3F1b3RlIiBzdHlsZT0ibWFyZ2luOjBweCAw
cHggMHB4IDAuOGV4O2JvcmRlci1sZWZ0OjFweCBzb2xpZCByZ2IoMjA0LDIwNCwyMDQpO3BhZGRp
bmctbGVmdDoxZXgiPkNPTkZJR19ERUJVR19JTkZPPXk8YnI+DQpDT05GSUdfQVNfSEFTX05PTl9D
T05TVF9MRUIxMjg9eTxicj4NCiMgQ09ORklHX0RFQlVHX0lORk9fTk9ORSBpcyBub3Qgc2V0PGJy
Pg0KQ09ORklHX0RFQlVHX0lORk9fRFdBUkZfVE9PTENIQUlOX0RFRkFVTFQ9eTxicj4NCiMgQ09O
RklHX0RFQlVHX0lORk9fRFdBUkY0IGlzIG5vdCBzZXQ8YnI+DQojIENPTkZJR19ERUJVR19JTkZP
X0RXQVJGNSBpcyBub3Qgc2V0PGJyPg0KIyBDT05GSUdfREVCVUdfSU5GT19SRURVQ0VEIGlzIG5v
dCBzZXQ8YnI+DQojIENPTkZJR19ERUJVR19JTkZPX0NPTVBSRVNTRUQgaXMgbm90IHNldDxicj4N
CiMgQ09ORklHX0RFQlVHX0lORk9fU1BMSVQgaXMgbm90IHNldDxicj4NCiMgQ09ORklHX0RFQlVH
X0lORk9fQlRGIGlzIG5vdCBzZXQ8YnI+DQojIENPTkZJR19HREJfU0NSSVBUUyBpcyBub3Qgc2V0
PGJyPg0KPGJyPg0KcGVyZiB0b3Agc3RpbGwgbm8gZnVuY3Rpb24gbmFtZS48YnI+DQo8YnI+DQox
Mi45MCXCoCBba2VybmVsXcKgIMKgIMKgIMKgIMKgIMKgIMKgIFtrXSAweGZmZmZmZmZmODMzZGZh
NjQ8YnI+PC9ibG9ja3F1b3RlPjxkaXY+PGJyPjwvZGl2PjxkaXY+SSB0aGluayBJIGtub3cgd2hh
dCYjMzk7cyBnb2luZyBvbi4gVGhlIHR3byBmdW5jdGlvbnMgdGhhdCBkaWZmZXIgd2l0aCBhbmQg
d2l0aG91dCB0aGUgcGF0Y2ggd2VyZSBwYXNzaW5nIGFuIGluY3JlbWVudGVkIHBvaW50ZXIgdG8g
dW5zYWZlX3B1dF91c2VyKCksIHdoaWNoIGlzIGEgbWFjcm8sIGUuZy46PC9kaXY+PGRpdj48YnI+
PC9kaXY+PGRpdj7CoMKgwqB1bnNhZmVfcHV0X3VzZXIoKGNvbXBhdF91bG9uZ190KW0sIHVtYXNr
KyssIEVmYXVsdCk7PC9kaXY+PGRpdj48YnI+PC9kaXY+PGRpdj5CZWNhdXNlIHRoYXQgbWFjcm8g
ZGlkbiYjMzk7dCBldmFsdWF0ZSBpdHMgc2Vjb25kIHBhcmFtZXRlciwgJnF1b3Q7dW1hc2srKyZx
dW90OyB3YXMgcGFzc2VkIHRvIGEgY2FsbCB0byBrbXNhbl9jb3B5X3RvX3VzZXIoKSwgd2hpY2gg
cmVzdWx0ZWQgaW4gYW4gZXh0cmEgaW5jcmVtZW50IG9mIHVtYXNrLjwvZGl2PjxkaXY+VGhpcyBw
cm9iYWJseSB2aW9sYXRlZCBzb21lIGV4cGVjdGF0aW9ucyBvZiB0aGUgdXNlcnNwYWNlIGFwcCwg
d2hpY2ggaW4gdHVybiBsZWQgdG8gcmVwZXRpdGl2ZSBrZXJuZWwgY2FsbHMuPC9kaXY+PGRpdj48
YnI+PC9kaXY+PGRpdj5Db3VsZCB5b3UgcGxlYXNlIGNoZWNrIGlmIHRoZSBwYXRjaCBiZWxvdyBm
aXhlcyB0aGUgcHJvYmxlbSBmb3IgeW91PzwvZGl2PjxkaXY+PGJyPjwvZGl2PjxkaXY+ZGlmZiAt
LWdpdCBhL2FyY2gveDg2L2luY2x1ZGUvYXNtL3VhY2Nlc3MuaCBiL2FyY2gveDg2L2luY2x1ZGUv
YXNtL3VhY2Nlc3MuaDxicj5pbmRleCA4YmM2MTRjZmUyMWI5Li4xY2M3NTZlYWZhNDQ3IDEwMDY0
NDxicj4tLS0gYS9hcmNoL3g4Ni9pbmNsdWRlL2FzbS91YWNjZXNzLmg8YnI+KysrIGIvYXJjaC94
ODYvaW5jbHVkZS9hc20vdWFjY2Vzcy5oPGJyPkBAIC0yNTQsMjQgKzI1NCwyNSBAQCBleHRlcm4g
dm9pZCBfX3B1dF91c2VyX25vY2hlY2tfOCh2b2lkKTs8YnI+wqAjZGVmaW5lIF9fcHV0X3VzZXJf
c2l6ZSh4LCBwdHIsIHNpemUsIGxhYmVsKSDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCBcPGJyPsKgZG8geyDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCBcPGJyPsKgIMKgIMKgIMKgIF9fdHlwZW9mX18oKihwdHIpKSBfX3ggPSAoeCk7IC8qIGV2
YWwgeCBvbmNlICovIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIFw8YnI+LSDCoCDCoCDCoCBfX2No
a191c2VyX3B0cihwdHIpOyDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoFw8YnI+KyDCoCDCoCDCoCBfX3R5cGVvZl9fKHB0cikg
X19wdHIgPSAocHRyKTsgLyogZXZhbCBwdHIgb25jZSAqLyDCoCDCoCDCoCDCoCDCoCDCoCDCoFw8
YnI+KyDCoCDCoCDCoCBfX2Noa191c2VyX3B0cihfX3B0cik7IMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgXDxicj7CoCDCoCDCoCDC
oCBzd2l0Y2ggKHNpemUpIHsgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgXDxicj7CoCDCoCDCoCDCoCBjYXNlIDE6
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIFw8YnI+LSDCoCDCoCDCoCDCoCDCoCDCoCDCoCBf
X3B1dF91c2VyX2dvdG8oX194LCBwdHIsICZxdW90O2ImcXVvdDssICZxdW90O2lxJnF1b3Q7LCBs
YWJlbCk7IMKgIMKgIMKgIMKgIMKgIMKgXDxicj4rIMKgIMKgIMKgIMKgIMKgIMKgIMKgIF9fcHV0
X3VzZXJfZ290byhfX3gsIF9fcHRyLCAmcXVvdDtiJnF1b3Q7LCAmcXVvdDtpcSZxdW90OywgbGFi
ZWwpOyDCoCDCoCDCoCDCoCDCoFw8YnI+wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgYnJlYWs7IMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgXDxicj7CoCDCoCDCoCDCoCBjYXNlIDI6IMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIFw8YnI+LSDCoCDCoCDCoCDCoCDCoCDCoCDCoCBfX3B1dF91c2VyX2dvdG8oX194
LCBwdHIsICZxdW90O3cmcXVvdDssICZxdW90O2lyJnF1b3Q7LCBsYWJlbCk7IMKgIMKgIMKgIMKg
IMKgIMKgXDxicj4rIMKgIMKgIMKgIMKgIMKgIMKgIMKgIF9fcHV0X3VzZXJfZ290byhfX3gsIF9f
cHRyLCAmcXVvdDt3JnF1b3Q7LCAmcXVvdDtpciZxdW90OywgbGFiZWwpOyDCoCDCoCDCoCDCoCDC
oFw8YnI+wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgYnJlYWs7IMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgXDxi
cj7CoCDCoCDCoCDCoCBjYXNlIDQ6IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIFw8YnI+LSDC
oCDCoCDCoCDCoCDCoCDCoCDCoCBfX3B1dF91c2VyX2dvdG8oX194LCBwdHIsICZxdW90O2wmcXVv
dDssICZxdW90O2lyJnF1b3Q7LCBsYWJlbCk7IMKgIMKgIMKgIMKgIMKgIMKgXDxicj4rIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIF9fcHV0X3VzZXJfZ290byhfX3gsIF9fcHRyLCAmcXVvdDtsJnF1b3Q7
LCAmcXVvdDtpciZxdW90OywgbGFiZWwpOyDCoCDCoCDCoCDCoCDCoFw8YnI+wqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgYnJlYWs7IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgXDxicj48L2Rpdj48ZGl2PsKgIMKg
IMKgIMKgIGNhc2UgODogwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgXDxicj4tIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIF9fcHV0X3VzZXJfZ290b191NjQoX194LCBwdHIsIGxhYmVsKTsgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgXDxicj4rIMKgIMKgIMKgIMKgIMKgIMKgIMKgIF9fcHV0X3Vz
ZXJfZ290b191NjQoX194LCBfX3B0ciwgbGFiZWwpOyDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCBc
PGJyPsKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIGJyZWFrOyDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoFw8YnI+
wqAgwqAgwqAgwqAgZGVmYXVsdDogwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqBcPGJyPsKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIF9fcHV0X3VzZXJfYmFkKCk7IMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIFw8YnI+wqAgwqAgwqAgwqAgfSDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCBcPGJyPi0gwqAgwqAgwqAgaW5zdHJ1
bWVudF9wdXRfdXNlcihfX3gsIHB0ciwgc2l6ZSk7IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgXDxicj4rIMKgIMKgIMKgIGluc3RydW1lbnRfcHV0X3VzZXIoX194LCBf
X3B0ciwgc2l6ZSk7IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgXDxicj7C
oH0gd2hpbGUgKDApPGJyPsKgPGJyPsKgI2lmZGVmIENPTkZJR19DQ19IQVNfQVNNX0dPVE9fT1VU
UFVUPGJyPjwvZGl2PjwvZGl2PjxkaXYgZGlyPSJsdHIiIGNsYXNzPSJnbWFpbF9zaWduYXR1cmUi
PjxkaXYgZGlyPSJsdHIiPjxicj48L2Rpdj48L2Rpdj48L2Rpdj4NCg0KPHA+PC9wPgoKLS0gPGJy
IC8+CllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQg
dG8gdGhlIEdvb2dsZSBHcm91cHMgJnF1b3Q7a2FzYW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpU
byB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBm
cm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIDxhIGhyZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJz
Y3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbSI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vw
cy5jb208L2E+LjxiciAvPgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0
IDxhIGhyZWY9Imh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FH
X2ZuJTNEVVZBUlJ1ZVhuNG1VNTFUa3pMVHBaJTNEMmZLTkw3TkFCM1lIN21HUDcxWmhVUSU0MG1h
aWwuZ21haWwuY29tP3V0bV9tZWRpdW09ZW1haWwmdXRtX3NvdXJjZT1mb290ZXIiPmh0dHBzOi8v
Z3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FHX2ZuJTNEVVZBUlJ1ZVhuNG1V
NTFUa3pMVHBaJTNEMmZLTkw3TkFCM1lIN21HUDcxWmhVUSU0MG1haWwuZ21haWwuY29tPC9hPi48
YnIgLz4K
--000000000000621ccb05eb916b72--
