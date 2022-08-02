Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA56UWLQMGQEPKS7TPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EDB9588108
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 19:29:41 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-106a48f2df7sf5120049fac.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 10:29:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659461380; cv=pass;
        d=google.com; s=arc-20160816;
        b=giN53ggRYpXWz8ib9vebmA7cr5NGoNMF5B5RNqwZxS65f5CrM72/nKPB2x082LOqdm
         h93ofCp8Q92KoOVdCEht3yzdsvScwwlIgWGovnuNADsLxS53YeeM1+h1ZyFloK8uyGMD
         NnKdt32d9JhTN8UT6oRQjgBLw0C8Vetpd78+ooSdtC8um2jdg40DkYD16sxSfX30JIuX
         ER57jk7KdiNlW5kneQ3dB9Ac4cxtczV04wgKUVI8MaohoqjakJ1xNxE4K+c3GjZW+Fsc
         hC7A2sPnfMHiJ7HLPaoPjZCs7L4+TNl/hzrtJPwThX9aKFKYAdAE8Sns6AN46aDNcadL
         VviQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6ont/IT7/mhWj8LkswspptfbaRYOzsH4FLOKfW4m5kE=;
        b=qGTWE55Zu2eBQOIRhoubdgyFN82X+lxp5s+xUhQCroUCqE0EpSbzgPYi6u1vcmYsJ7
         RVbKjAE8+OUSDO2jBvsqT1RpqGCTPuufa8UqHHcTIhiqyof9DyNBhz6Ns6moDdHDzHMD
         DPbQFap9zediPQN2xBpGHMWPpL4USc5V+lFnk0v1DKOSDUMZCMs+aZf9VxBCG9+NL+zT
         /rN4v4j3pdi6zajo1XSOdKTCf1pzxBCY9pQSmMAm8mHTqyEQbkYlEw63H7ilh2tutIiv
         G0SVTNp2AA8W7F/lwEAbcxsHJdsi8KS3CKMQJ9BVqwMTSh+Il/+jJ0QH2SRjDJzSzc3r
         9hTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QRi9qghY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ont/IT7/mhWj8LkswspptfbaRYOzsH4FLOKfW4m5kE=;
        b=cbL9VsxUlS5PVeWOUORC2WxoJesdDhnsfG81Pg44vEh4D+WIGuXlPaZiVLwLAKz0K1
         eCG64X8RJg1f8666/uQZvoa68TM8ZSGwgOtUqE0V4NEl4BljyuGINNDrVxMUondRELIU
         MMUhWluC77xM4Ihi5aG/cqB0MW0FTXRIxeKvKx+Czbguw0iuXW8MBSW7ad/dVZmjv0jl
         hJaiCFOICV4eg41FWQUb5rYSVRZBwl+1T2hDmS6+j96VVDzee9xJBbR9xqjtOVMDoI1h
         f9w/E21nHKa6y8G7biEGBQ9+kAd0baMylEIhTlLQg9fkxeMy/MNI/1Fh8iwPiDtBPc3M
         Io1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ont/IT7/mhWj8LkswspptfbaRYOzsH4FLOKfW4m5kE=;
        b=dZ1/I+zNbfdrOTkCEqbwXIGUdwkmQRyXzTH3uVYiFUt73n/o2ll0VfrmUNxrxqNN9L
         zdNJPlc/6yoVZ2RWf7wCMeOednffV5aq40WvG60B36ugbClMYJdfm71z6F+1+iORjSxv
         n8lO6P9xp8Zt4bGqbFQR7asRlLnwWxT4y+4Im57ll5vkbEYoK7cegefKjDPu6Y5jhbTG
         z0o1xdjjdIfeBbhjBvrvJNayMlOxD8EyopFu95+TXU1o7yyTjWXcTxSMt31w0QSvyt1W
         BgxyzJnRdk7yXv2ak3bMpAk7FFHIUWypGpGiuZeaGclgNt4rt/Rn4AFQm3EhoMPH5NAM
         5Wzw==
X-Gm-Message-State: ACgBeo05NchgrcsxHm7n3LidTGhbqgqeqjPwHEvtmWmw4xTt21oNYEjg
	7q8+C35DFrQds6HfewLb7+U=
X-Google-Smtp-Source: AA6agR4FgfNguPh6g5lYNVLxBNfr07aEglbaaDcA4cjKrtV0V8kgIEB3hMO8LDAAXr6p2nOpis2yig==
X-Received: by 2002:a05:6871:1d0:b0:101:59af:c6b7 with SMTP id q16-20020a05687101d000b0010159afc6b7mr231103oad.89.1659461379840;
        Tue, 02 Aug 2022 10:29:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a8a8:b0:10e:6b7b:7dc6 with SMTP id
 eb40-20020a056870a8a800b0010e6b7b7dc6ls5445472oab.10.-pod-prod-gmail; Tue, 02
 Aug 2022 10:29:39 -0700 (PDT)
X-Received: by 2002:a05:6870:6314:b0:10b:9595:62db with SMTP id s20-20020a056870631400b0010b959562dbmr246102oao.128.1659461379494;
        Tue, 02 Aug 2022 10:29:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659461379; cv=none;
        d=google.com; s=arc-20160816;
        b=r1oY4MkbLSANZb5g7h1t35Qm6JxhbkRgzowtsf2SfuTIXjLWnxeot4GLNNExm0LYha
         sKdrVaasG7fgj6b82HYU37lnuKchTL0giwtLQwwHnKllhP5G8GO6cpcg6O/Hii66/ZMN
         ENxNwWj8wK8ADcqXp8+HSa75pT06HZvRaqhqJe5VCfgYgLeFX8J6cAJY6gUgeUGnsBfx
         V66mo+Wy0FEsKB+pUGZgH6rYggzLWG28bEdyH2y5FyfvftlXI/YctAN0GBynTC2yh62f
         m4Buf/kfo4j3n5twNc8sMrtMuF+LFGVrBobhHRBX0Xo/WlkJ3eNeEy5rfFKEFBBnS9Yc
         qa4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MvRBkFzdQaYaXfpQTRaszNRJA99lxIjSlE2BIJqxf/w=;
        b=f8PswvPVwmMF9fJ+SiMhXgqQR0Y+55QAdBvTk1mL9cVNiu/IE96R8IR9FUBEeMB06y
         kpaBlvsFbW3ILSfk8aCE1wWHj8tAzXIYv+w6vJPTaJRSxKi8ukzCXyP3914GsK7iSveo
         YBUlU5g0Qq5UnBAaTg7ee4jsvS3pooVpaocl21uiCtsjgV267/HmCz70CgHv0v37IlOl
         zyvvOfe8y2kclEAlj9bew7xqyiFsLGl2JFONs0h8REPwXjN0laWf3/e+CZiYiS6LWMfJ
         5u7szHXFh2RFqHx3b54F6I+L1p416VBduIMCOjcM8XIy5SX7XwFfYPheefFwVWoF0snJ
         zW3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QRi9qghY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id k22-20020a056870959600b000e217d47668si1442432oao.5.2022.08.02.10.29.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 10:29:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id 7so24693928ybw.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 10:29:39 -0700 (PDT)
X-Received: by 2002:a25:bc3:0:b0:673:bc78:c095 with SMTP id
 186-20020a250bc3000000b00673bc78c095mr15729538ybl.376.1659461379014; Tue, 02
 Aug 2022 10:29:39 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-26-glider@google.com>
 <CANpmjNPeW=pQ_rU5ACTpBX8W4TH4vdcDn=hqPhHGtYU96iHF0A@mail.gmail.com>
In-Reply-To: <CANpmjNPeW=pQ_rU5ACTpBX8W4TH4vdcDn=hqPhHGtYU96iHF0A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 19:29:02 +0200
Message-ID: <CAG_fn=V343yojjvuU6zxHKm+SgFJ2jAb7G_aKEwaqLqtqSeiYQ@mail.gmail.com>
Subject: Re: [PATCH v4 25/45] kmsan: add tests for KMSAN
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QRi9qghY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as
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

On Tue, Jul 12, 2022 at 4:17 PM Marco Elver <elver@google.com> wrote:
>

> > +static void test_params(struct kunit *test)
> > +{
> > +#ifdef CONFIG_KMSAN_CHECK_PARAM_RETVAL
>
> if (IS_ENABLED(...))
>
Not sure this is valid C, given that EXPECTATION_UNINIT_VALUE_FN
introduces a variable declaration.

> > +       if (vbuf)
> > +               vunmap(vbuf);
> > +       for (i = 0; i < npages; i++)
>
> add { }
>
Done.


> if (IS_ENABLED(CONFIG_KMSAN_CHECK_PARAM_RETVAL))
>
Same as above.

> > +static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
> > +{
> > +       if (!strcmp(tp->name, "console"))
> > +               tracepoint_probe_unregister(tp, probe_console, NULL);
> > +}
> > +
> > +/*
> > + * We only want to do tracepoints setup and teardown once, therefore we have to
> > + * customize the init and exit functions and cannot rely on kunit_test_suite().
> > + */
>
> This is no longer true. See a recent version of
> mm/kfence/kfence_test.c which uses the new suite_init/exit.

Done.

> > +late_initcall_sync(kmsan_test_init);
> > +module_exit(kmsan_test_exit);
> > +
> > +MODULE_LICENSE("GPL v2");
>
> A recent version of checkpatch should complain about this, wanting
> only "GPL" instead of "GPL v2".
>
Fixed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV343yojjvuU6zxHKm%2BSgFJ2jAb7G_aKEwaqLqtqSeiYQ%40mail.gmail.com.
