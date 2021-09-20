Return-Path: <kasan-dev+bncBDGIV3UHVAGBB7VSUGFAMGQEQQELHLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FA8241121A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 11:50:55 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id w18-20020ac25d520000b02903c5ff81b281sf11807335lfd.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 02:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632131454; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOnU+8+y3mhbE4KJXUTu3u+GXIvPdxqCR/XXq+ow3U4pridc8fJBVUOUZes/4ZlOdN
         +8hksxF/Q47k2iVDmTL6mMB9+/07w5LsWKJXf9+3SnCr95NeGC9pUY0Tm6aNQI9Phg8O
         29ojz072tJWzhI7l+Irof2SLcJPw+GjUiH0XZC9S9Adaawvcgn63+3rqUG6qDLkQniWR
         uN8Ic026bg0SiG/QaaR/c+Op3WWaCDUOdOEFleu+/7MmESmbq0UMxjF5KlrSivSeHY1/
         Ye3jBzK6WuSEUYCOv8wIEwoyoCjPa98jhsFn2bdfx3mVjCZl38cO41BFf307X6PTWhCr
         eYxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BsSZN+3QkkBWG/B+/zSb1mZSFV7ZYc7T9yhlr7hcAVA=;
        b=S0pJb4jXlAWaK7gxu9HB/QeOyJhqBNyytooVLa4fIns6W7LfLqLpyaas7teLWUum0C
         eEfnkWPtPEGqv2akKoURZHvAFglDklloLuLXrupSXaew/4WwOVziEpi7EFWsydK9odu/
         0ExNGHY5Ikpoix9O34dH/Rb6vPP/Iwi0/uJ6isXXsc5x5dJlqSfmj08uB5etcT892V1f
         vxvn7Ba8bRIRseTbVBfygREUy1UwLxOa8dQIrblPT+MZXXuQesJL1flO5FTAd5vYhqed
         BacQTMPhgHPc7q1rW0QJ2QMC+5ifTfkxvUfunqS3Saox9qPzMucMaMBvI7eI+BugRHl5
         CZUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=gOd6OlzP;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BsSZN+3QkkBWG/B+/zSb1mZSFV7ZYc7T9yhlr7hcAVA=;
        b=l0fgLSnDJjDueXD6fw3t7mh/ZrbDIRrg6TqMxocXPUujH8xi/eKR0G7WguniqN6572
         /sbqBUqa4wvgirbtInD7DvywfQTK+sVyVB3sK+0ZuUS/BKFEK6R55YfhA8RddjxuT+dB
         hng0QrCWcs01Po/2ZC2ODkR2beyk+L4fYw+CSUgLgbVtz61aLyTgPGjmMT4s6QVCIpFe
         Whr0NcWSjkJNcF1IyoMRI3//fNbeJdo6BI00l2xDdotThWp3I3vXOdMg3iKyTCNrK/l0
         IOBIlJShHPESDg2W66Bshn1otWADoHeidELmK4FWfw9FdoO/fRbEQXQY425BSOH+0MoN
         tfRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BsSZN+3QkkBWG/B+/zSb1mZSFV7ZYc7T9yhlr7hcAVA=;
        b=xCUdbDGG9zf1Qsi2DuO1OtDiWNiMoQeLNX5w+/i3b9UR3I4sR4HYLOuiPSpZDIJWUs
         l7bxAFkkeV0s9gMTdCvyJ8sJP9CQMrbj5UcKOu1bR8onVgLSYe1Nbk4FD7q/rs2Ux2Ml
         lr0BbdjJtliElQNSiV//ZlM4jVfSHSY8hY7isjyN0nR6fNra5XAoDfFC8npTSC1RHRlg
         78zJqYhIHvQz7F8JHM7fanlTlNK8zdpASrndC/d7LxEit+I09y+LpNW0PYYaqh8qpdN+
         Kh/nvOuo5+wBLdJdaDIzQa61TbNIZA+BxqBbtf0o//U71dccHaf00IPubnYGf31FreJm
         cm0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532VLH64GRbL3P4VHSgdR0Efvk5k47H6bO+/zwcBpkaJvjp+UkBl
	1xmNEckBxouJwweEqZ5UkeI=
X-Google-Smtp-Source: ABdhPJyQK+rfh03ObYgoTZQaXlGu10kLZnifSeRXyOVttVXqewwuHnEop7HNG/17m+TZo58BA/QkhA==
X-Received: by 2002:ac2:4acb:: with SMTP id m11mr17483961lfp.146.1632131454639;
        Mon, 20 Sep 2021 02:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:503:: with SMTP id o3ls2666738ljp.0.gmail; Mon, 20
 Sep 2021 02:50:53 -0700 (PDT)
X-Received: by 2002:a2e:bc1e:: with SMTP id b30mr22234132ljf.191.1632131453544;
        Mon, 20 Sep 2021 02:50:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632131453; cv=none;
        d=google.com; s=arc-20160816;
        b=QEyriOXnJra0+1RNOLBCAMp23Zb3T69orc95FxDeY/Qx14k3krMxoJQXVSxuEhktgF
         mBmIrjJr017Azi45XgUgJRynLoamDP/U8SKUGkrVKUG5Cd+BdXuG/F6/DfjNmBNENG+S
         gsnn0hYiAgPnwHUcHz4eNlnxYo+zQ2M6wbRJ9sqFHuIqxTEl6KIQWFe2IezfTKV/JYSn
         /Cg37sEOZMdfOVC0aeogYE8j06exOTMHPyPw4sqnFFt+rJnxoK9KFfDksSuLvWhERlGp
         iMgrqD8YLAYdUAM6x8v55HIui2nnTB8DJmtde8zZgoVJMyuX++ILUu2y85O1s7rU35Mp
         KRiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=ZxRILvmjy4ooem4+55x6inqqVZExJI1xLe5CwsVk4v4=;
        b=WnXX+PPHVFI8ZuvVah4S2l+tr2/FM1Z3RL3jQQNlaSnPuXPfJsE7QOQWKItCoKgfYU
         K/iUq25ViZ4s+ioE2+2W066VvQ/5x3zlsNy66/kl0WT1cmd18CnnFPTjYIh4rSg3mZJv
         Q2qopnDi5TfkMtzcY2BTV+6mEsNtz7eb2sNA/6MC0Pp5EVrGD13CvZD39Tx8lKQgUpcC
         FMYSl1kSpNwJOcqK2T8IZ7jxTLxr5EUWtFFtKi7dDBjsHCxksQzQZIFZ6YZG40VhzJO7
         UtatOKHxHRwlGXo072yoGDDIq15n1UGz9rSPv8tjazAAPVLyI7au5xmqA5IDbkyFqULe
         mjjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=gOd6OlzP;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id g11si883012lfr.3.2021.09.20.02.50.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Sep 2021 02:50:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Mon, 20 Sep 2021 11:50:51 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Clark Williams <williams@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH 0/5] kcov: PREEMPT_RT fixup + misc
Message-ID: <20210920095051.uaukljr5axkv4ctq@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
 <CANpmjNPZMVkr5BpywHTY_m+ndLTeWrMLTog=yGG=VLg_miqUvQ@mail.gmail.com>
 <20210906162824.3s7tmdqah5i7jnou@linutronix.de>
 <CANpmjNPn5rS7MyoDtzJNbs9Gxo=26H_z7CX4UDQcwLRtJfZa6A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPn5rS7MyoDtzJNbs9Gxo=26H_z7CX4UDQcwLRtJfZa6A@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=gOd6OlzP;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2021-09-20 11:26:38 [+0200], Marco Elver wrote:
> I saw Dmitry responded with Acks/comment. Did you have a tree in mind
> to take it through? Usually KCOV changes go through the -mm tree, in
> which case please Cc Andrew in the rest of the series.

Okay. In that case I'm going to repost it with all the tags and akpm in
Cc:.

> Thanks,
> -- Marco

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210920095051.uaukljr5axkv4ctq%40linutronix.de.
