Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4YZGNAMGQEJYH25PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id DE3A7607140
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 09:38:04 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id n33-20020ab013e4000000b0039f1bede4c9sf1651848uae.4
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 00:38:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666337883; cv=pass;
        d=google.com; s=arc-20160816;
        b=JKdGA4xTl2FZ3As/A2Ft/TxBA0ECUvpOqD84n3qpsEL3esJXqjAKwbD+nUwlVZAuQR
         vhF1XENUEv0teNCy9TrlZnyuTWsFoFy7UaZ8mliO8/J3MVsqG1juHXizzSZYVNXa+Z+F
         9YTkum79tiEmeSNwSVod4GD9OkZtVLS3JahMlrd5iA1kj/M748VjRFjsy1bJJzARw3Yo
         xBzOdukTz4l3ct13vQIJO7JJ5iKavbwhjKXRYpy6MC5OxvAQvaQiG8PrLa0up1YjLCjV
         o43BgWmvdEmz/BJ+Qjqe22lBI/DDLVtS28CO0YYZtj8yzqCpiUbAMlE89WVCzOKQqT+m
         2j0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JKaBEG53shPA1Ad7p/WfhRRHNlfTcBBqyD0WEo6nokg=;
        b=gdBj1XYvy2T9ygHw9G3AOxzjFtUk24RfDlowTWT02Vn5YRGC2dkT4hXtE+j1RvVGQ8
         CtEiCTveRfY56NUc/SkbXcullM1MWbGiQ3k3FNyzBcx91ndp0HIz/RorB5UP3koWJIPt
         RlY8RJXy3p6hJ8sAOLIYut8Tlzice9vFnCXfgRohT4unKmFHQNVQubarVAtesUN18li7
         pRTN0/I6gFvIlYDMP3v8eJT6wKdHsbvJWpYSQSmGo1tLX+MnboKf3wW3uuH2AEqXz4/h
         JwxTKWAVHOowFw1Wprc82HwTvunFOuwMCJ3tw2wA/o71S+KxXyLKx8DRLlnuG5EUZZTe
         wlDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hdGApCLD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JKaBEG53shPA1Ad7p/WfhRRHNlfTcBBqyD0WEo6nokg=;
        b=gv0edH2DZ/AMCBITEHPYEHWrp47HP9JIhqxSI4vmIPfxz/1BqRQaLGtlNyhkjHIgp9
         dDuzjzhGNmzyZHQqaBSmdLETCKC1y+Jw5cc78CxCajKEna2Qprd/0blg+lpQe9lPSMVf
         4RzFnQF577Khp6i8JxYiXUOrFUkG1XeaM2uYF8rAYwLrPxyznHoEWCDKTe1rqEPLyPlG
         NijwCkKaM7MSyRzpiAHLhqqPelscYCIuPG6xBGyPBgCUoG/0AVt2Ivtz+MRUjHAyGXHR
         iHCpfzPp0gib/REaprkOR1+r+ba4mktD91BgyhZTqyMdvhEdt83ymB2guEaf2w4SETvy
         M4GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=JKaBEG53shPA1Ad7p/WfhRRHNlfTcBBqyD0WEo6nokg=;
        b=LHp/cRkUkDy/EOmYqjcM46ziZB9QUTtSro9dAPVQB+OpDY/To0p3pVV+UJbqOdU9zu
         ABDO3DPB6lZwmC+0Hu3fDgD6KWpkkRy3KZ1MG1i14siqIsjNXxEGX5jH4VR4Coq7EK1B
         t4vSCMbeT2+nu6puyKNuXhsRHWA2Y9ayxqEyPQgtBxXz1h0Lg1KeMs0LRKNUX1Nf8VvG
         fv6/BKDdFDLUAxHxR81mSvW/t/Qvd7/V9XcoTdjxPgzaUQqHW3IZoSTetmyzSYkejav/
         vqfWM5AnPEZNqCN2l0hAUkvIZbnnxTrCTvCiTNI9mobX01nKgMAmq4YkFZC0VN2g3unY
         bOvA==
X-Gm-Message-State: ACrzQf2XqrvcgXtGwau5aYTBggrUnGAmI8LsyGOimYESs0AxYX7+mr20
	W6z5zr9TDeULPaApPsLSiXg=
X-Google-Smtp-Source: AMsMyM7P9UnZfqkM4HKO5i9EI/3sKQ5w3Lt6Tp9RZPcRW6WZxEgTp2NaAiL7lnbfaMlcA6oT8OEkTg==
X-Received: by 2002:a05:6102:38c9:b0:3a9:7206:b99e with SMTP id k9-20020a05610238c900b003a97206b99emr11396164vst.65.1666337883667;
        Fri, 21 Oct 2022 00:38:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b84e:0:b0:3aa:42d:4833 with SMTP id o14-20020a67b84e000000b003aa042d4833ls106195vsh.5.-pod-prod-gmail;
 Fri, 21 Oct 2022 00:38:02 -0700 (PDT)
X-Received: by 2002:a67:b805:0:b0:3a7:a708:20a9 with SMTP id i5-20020a67b805000000b003a7a70820a9mr10031460vsf.64.1666337882869;
        Fri, 21 Oct 2022 00:38:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666337882; cv=none;
        d=google.com; s=arc-20160816;
        b=hioA+xsp7zAW/whZ1tK5hKL4pBGtPYF2zvhg/g36gSdKRz++bLBrAMSot+Vusz/u+w
         /tsDiVbYMmd0/Pw8PEIzwXg+UuRCji0iEOAYnqQiHW6B9RnuziJeCRt5wDrPCr1SFRuW
         beJm02OdTCB207Zi9XsMK1wqpPwoJ5sDdNeN90kDGe3d8j/9khzvDThArG6yI5skSgmr
         x0TBB0lgJmAMSVs/lNYFkMgjLj7OAYqljtm0o2A1UnPeaPtDaj8Kna9VqVhMt13vG24v
         0ll4yfnWzHgQ5TwX+WJcc+cI26l7+MAgDqzYm6gcDaBPTEqD87jWfZj4qTqc15cNVKQJ
         LGuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YqCI81aYTBUvq0AjF/BYw/CwZWDfTatRIRM86fy8mzM=;
        b=e93iB3hx8DFxQ5LVpXDI23rO0Mj+zgJW9GTXWQ8L+dMyv84VUSCB/wj6g9aJh8aPzG
         9oGQ+IYP1QzpDBQx9fmlGEwNmixvIlG9ZT71ysVZ7m3tkIJfXqNpLLD/5xGbd9RhfpmQ
         PR5hsfJPe01voC23YKVMmRfE+q9Wfc0TFmzDkoV1IbBnZPinIbKJH9Es9BdLKqtseThq
         5jncgS7B2s17XobptOK2V2woym+CKMOyirvLGtEnNE1jHezVCNNW6shClnXYSFGtJzCr
         aB+CW+yDCTdvvYq1EtC4RmxeBAdkYPDc+v+UJX83GhpUi/PxPyTtZAdCJsM049TICMKa
         7/xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hdGApCLD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id y4-20020a05610207c400b003a95a847876si739855vsg.1.2022.10.21.00.38.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Oct 2022 00:38:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id e83so2427040ybh.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Oct 2022 00:38:02 -0700 (PDT)
X-Received: by 2002:a25:7b42:0:b0:6ca:1d03:2254 with SMTP id
 w63-20020a257b42000000b006ca1d032254mr8096145ybc.584.1666337882424; Fri, 21
 Oct 2022 00:38:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
 <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com> <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com>
In-Reply-To: <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Oct 2022 00:37:26 -0700
Message-ID: <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: youling 257 <youling257@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hdGApCLD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 20 Oct 2022 at 23:39, youling 257 <youling257@gmail.com> wrote:
>
> PerfTop:    8253 irqs/sec  kernel:75.3%  exact: 100.0% lost: 0/0 drop:
> 0/17899 [4000Hz cycles],  (all, 8 CPUs)
> ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
>
>     14.87%  [kernel]              [k] 0xffffffff941d1f37
>      6.71%  [kernel]              [k] 0xffffffff942016cf
>
> what is 0xffffffff941d1f37?

You need to build with debug symbols:
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y

Then it'll show function names.

> 2022-10-21 14:16 GMT+08:00, Marco Elver <elver@google.com>:
> > On Thu, 20 Oct 2022 at 22:55, youling 257 <youling257@gmail.com> wrote:
> >>
> >> How to use perf tool?
> >
> > The simplest would be to try just "perf top" - and see which kernel
> > functions consume most CPU cycles. I would suggest you compare both
> > kernels, and see if you can spot a function which uses more cycles% in
> > the problematic kernel.
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPUqVwHLVg5weN3%2Bm7RJ7pCfDjBqJ2fBKueeMzKn%3DR%3DjA%40mail.gmail.com.
