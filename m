Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCUA5SMAMGQEA6ZYNHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D7E75B3270
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 10:57:48 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id f6-20020a4a9206000000b0044e001dc716sf539680ooh.20
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 01:57:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662713866; cv=pass;
        d=google.com; s=arc-20160816;
        b=ATE8XCvC/2mnB+g8/vbHGptoOHXN7iPi8iwwpeNgVTiZTIZZ/hTIJ2KTu+SMVHda70
         Ere96Dfj25YgIyWKIVvaYJrh+zNZnKAs/YvKgE1sS434qe0rubKx9eNGzeCvh1bbEDZT
         uUU2pB0TWuKBXpcoAfJbeaJTrhn7pJpb2BQ71OBvwqktnQcCPYtK6uWfo31UFJGgNWOv
         3FFIemSxMqA61uWFrUnJZk58WR1QQpDUSu1sNWimAtoqblo/P70d+C8DYJ8pvzr4dFm9
         2C3Rs2n45SmL+hFBK+kZ/xNXr7dtf7T3CzmDEvodMduVamGVRn+0kpdF37QbX8Ndni1h
         2A3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h+Vj4A/9Ibpv/L+I8DQqW8odd299TXy9HxWmf6+zNDo=;
        b=Ci8E0E48CWpz5+08mTZcsVkPhZiwdRvPNoxA+uKCZxS0Zu95jSLQUswkrToDeFul3h
         TXtKjkLbtPwR4DWKxnbG9czGrIu33RWuwF5thE9tQgQ2hBfJguiOw2tAvs4SbK7XCL9j
         Jy5CdU3jaYVfXR+FJtfLhNXV0LVMu7Q/2htrhB73FahtTd+bM72ZSqgrPVqYxC58n1d6
         JDb3cpy5ZXSVjWzjuMcuoEM9wk14E6vQUB6dioTF38rTWeywVjwZwVU7xFy+hIXwK2Xc
         0ERmOB7KkFrpdT2X3aPUxBLU7wCnlwCgHk38O/0rm54YTirKX6cOKrro4UkTIG2GhJ8+
         VRyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=goGwbFEz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=h+Vj4A/9Ibpv/L+I8DQqW8odd299TXy9HxWmf6+zNDo=;
        b=s4hqjDgd6uioQLO21IwjTn8lHeojTa/8Sbu4KIrHx1PZ/C8bEQBfpAsdK+tknIFdER
         BZ4/2i2PXfB38KMFDOQk8XYN3n5yvq5OdOdndETdFRwh7vtfEb426YVz/qW5mjoHFysk
         Fj/zQuFFj+0cGKG2UlfbnAhpi/9HEUP4/tLwy4piXuYQlU80lGydqX9HgWyoLwLKM3Qd
         EzuHkVyMoqN3fjE6kOA9QcRGJGS1VPdPgrQFcHDEErUY3gdLwV0+ySNBp+KJT1GxYWyJ
         tHRxLXWGY513shL4YXaxMOH/RzSO/fGh0TaFGK5Du3V34YtlJsPZrOEunwGra9F1A5gM
         hSuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=h+Vj4A/9Ibpv/L+I8DQqW8odd299TXy9HxWmf6+zNDo=;
        b=11fgLtyOJtVhWRMrVkb2f6R8kgoqVFCeILvGyYdsTSTwbup3gOgM2Xl3C19CeucnET
         5l/B95IpkT3c1bweFJ5jOYOPKuQt3LMMWMZdzhL2HqrwGTJ8OuZVafTEwFST2p8hoTYo
         axnoze4Ep/vbE+0k8vkX+QFxMPwH7t4fe5ULhBp2nWklV64CDwEr86MjCRP1hHgzLK6W
         Ui1GDetF4c9p7nGBwH3C6xSek+5Q+SyLFZ9lKoHkOCmjtgG/JH1IO73DcMcLnNJv78Qc
         ZPp0bNOBClHHOWcuddygPB1ZhR1zehIH+WNZ0l1vwxH5IqXcSZYJh+5h9Tw8wmkYUPae
         U0Mw==
X-Gm-Message-State: ACgBeo0ZSv+UgEYcg+EumlGuzdVDeCM6KYgMkl0aH2dS0Nuj5fNwpZmp
	lEj2cQoo+9aBgcx/he6fCv4=
X-Google-Smtp-Source: AA6agR72Lr0j5NdrmVBVUtTp78HAl/Ob32/v0mTjvjnh1rRVBr9jWQpn2sG3qSp+NQKayY6spq/0xQ==
X-Received: by 2002:a05:6808:1928:b0:345:3228:a797 with SMTP id bf40-20020a056808192800b003453228a797mr3033480oib.125.1662713866762;
        Fri, 09 Sep 2022 01:57:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:618a:b0:61c:ac06:86ce with SMTP id
 cb10-20020a056830618a00b0061cac0686cels712731otb.0.-pod-prod-gmail; Fri, 09
 Sep 2022 01:57:46 -0700 (PDT)
X-Received: by 2002:a05:6830:2645:b0:638:99a4:e483 with SMTP id f5-20020a056830264500b0063899a4e483mr4843494otu.38.1662713866339;
        Fri, 09 Sep 2022 01:57:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662713866; cv=none;
        d=google.com; s=arc-20160816;
        b=IV078LZoZiB/99B2x4f2P4nsx7qkRjhp7vNBaIkWhJrtAkbkw6xYzbQncWIQkhg3C+
         lRA2KFJNKo5EwztvZ75fbRaAx17dTCKxxbFXBLzCtwqHB9Qm521Aoz0Iopb/uGuebpZ0
         rjTHo+Ex7SVMZX8ZXF40vx9hpoM7IGsnDgDN6ArFKgmSG5wywIZ/K44s4VkzlS/vySIo
         7oPmq/kAB07Vzm0DVEcMHrzhOTqLot7C7OeylFRQi1Wj84owa9TZcRkmwjy5Clhg3SoS
         gOZHPKAF8DxipeaUZ78nPJz1Ugpt3XmPdE2QsOATxXE7zpSKjUgZq1ejcUJxFbVIHicv
         wruA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BA7v9By/PKm8Lb5EGh75hqx3B2NthlRyqEiydr+9MIw=;
        b=qf5RLLuwqyX61auEp/jG+fSuNFAKEoBfpUOg8wy6OK7bPmTjTMm7Ku4MHkVKoFosqO
         6/LI+6VXdhxdE55HnwBvXdHFAo+1mmh5PlmihZ6BYW8cKxw/6PTkXRMg7VO4YomiK6Uq
         jIvbRr/sz+RlclK5OZJF16B0WDjOq3GwNFqM5cIA9rQTYVR+wKY6O+cC3glEhvhhqO8S
         Sje8Ph4kvjKYsuv/w4v5veEMVaDXXk4hfZiGCdnve5jiUgjC+uh/kRLHPdpce+c0LeH/
         qGuPOyj8E/mV5W4i3a9/7ZDRRroWopMUNxGqyVrKk/iooTrVZqwt84RODOv4+g9tKjWs
         fzDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=goGwbFEz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id z20-20020a056871015400b001280826e23csi133734oab.5.2022.09.09.01.57.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 01:57:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-3457bc84d53so11980887b3.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 01:57:46 -0700 (PDT)
X-Received: by 2002:a0d:c7c3:0:b0:31e:9622:c4f6 with SMTP id
 j186-20020a0dc7c3000000b0031e9622c4f6mr10866606ywd.144.1662713865771; Fri, 09
 Sep 2022 01:57:45 -0700 (PDT)
MIME-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com> <20220905122452.2258262-41-glider@google.com>
In-Reply-To: <20220905122452.2258262-41-glider@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Sep 2022 10:57:09 +0200
Message-ID: <CAG_fn=Wz1b5nKTACGa_oPBuxXcn4Hb7hDT-3Fcx5P3ODY+ivpA@mail.gmail.com>
Subject: Re: [PATCH v6 40/44] x86: kmsan: don't instrument stack walking functions
To: Andrew Morton <akpm@linux-foundation.org>, Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
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
 header.i=@google.com header.s=20210112 header.b=goGwbFEz;       spf=pass
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

On Mon, Sep 5, 2022 at 2:26 PM Alexander Potapenko <glider@google.com> wrote:
>
> Upon function exit, KMSAN marks local variables as uninitialized.
> Further function calls may result in the compiler creating the stack
> frame where these local variables resided. This results in frame
> pointers being marked as uninitialized data, which is normally correct,
> because they are not stack-allocated.
>
> However stack unwinding functions are supposed to read and dereference
> the frame pointers, in which case KMSAN might be reporting uses of
> uninitialized values.
>
> To work around that, we mark update_stack_state(), unwind_next_frame()
> and show_trace_log_lvl() with __no_kmsan_checks, preventing all KMSAN
> reports inside those functions and making them return initialized
> values.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Hi Andrew, Stephen,

I've noticed this particular patch is missing in -mm (and, as a
result, in linux-next), which results in tons of false positives at
boot time.
Could you please add it as well?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWz1b5nKTACGa_oPBuxXcn4Hb7hDT-3Fcx5P3ODY%2BivpA%40mail.gmail.com.
